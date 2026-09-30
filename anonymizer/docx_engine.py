from __future__ import annotations

import io
import unicodedata
import zipfile
import zlib
from dataclasses import dataclass

from lxml import etree

from anonymizer.errors import (
    DocumentProcessingError,
    InvalidDocumentError,
    ResourceLimitExceededError,
    UnsupportedDocumentFormatError,
)
from anonymizer.limits import DEFAULT_LIMITS, ResourceLimits
from anonymizer.models import (
    DocumentData,
    REDACTION_GLYPH,
    RedactionPlan,
    TextUnit,
    XmlCharRef,
)

W_NS = 'http://schemas.openxmlformats.org/wordprocessingml/2006/main'
CP_NS = 'http://schemas.openxmlformats.org/package/2006/metadata/core-properties'
DC_NS = 'http://purl.org/dc/elements/1.1/'
DCTERMS_NS = 'http://purl.org/dc/terms/'

NSMAP = {'w': W_NS}

# OPC package plumbing. A DOCX is a ZIP with a contract: [Content_Types].xml
# says what every part IS, _rels/.rels says which part is the DOCUMENT, and
# only then does word/document.xml mean anything. Checking that a file with the
# right NAME exists proves none of it.
CONTENT_TYPES_NS = 'http://schemas.openxmlformats.org/package/2006/content-types'
RELATIONSHIPS_NS = 'http://schemas.openxmlformats.org/package/2006/relationships'
OFFICE_DOCUMENT_REL_TYPE = (
    'http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument'
)

CONTENT_TYPES_PART = '[Content_Types].xml'
ROOT_RELS_PART = '_rels/.rels'
MAIN_DOCUMENT_PART = 'word/document.xml'

# The four main-part content types this service accepts, and what each one makes
# the package. Everything is normalised to the first before anything is read for
# content, so the engine below only ever works on a plain document.
DOCX_MAIN_CONTENT_TYPE = (
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml'
)
WORD_MAIN_CONTENT_TYPES: dict[str, str] = {
    DOCX_MAIN_CONTENT_TYPE: 'docx',
    'application/vnd.ms-word.document.macroEnabled.main+xml': 'docm',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.template.main+xml': 'dotx',
    'application/vnd.ms-word.template.macroEnabledTemplate.main+xml': 'dotm',
}

# Compression methods this service will decompress. Anything else is a file we
# cannot read rather than a file that is wrong, and it must be refused BEFORE
# zipfile raises NotImplementedError from somewhere deep in a read.
_SUPPORTED_COMPRESSION = frozenset({zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED})
_ENCRYPTED_FLAG = 0x1

XML_PARSER = etree.XMLParser(
    resolve_entities=False,
    no_network=True,
    recover=True,
    remove_blank_text=False,
)

# word/document.xml is the one part the whole pipeline depends on, so it is
# parsed WITHOUT recovery: a malformed main document must be rejected, never
# silently repaired into a document with no text. Other parts keep the
# recovering parser above — a damaged header should not fail a usable file.
STRICT_XML_PARSER = etree.XMLParser(
    resolve_entities=False,
    no_network=True,
    recover=False,
    remove_blank_text=False,
)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ZipPreflight:
    """What the archive says about itself, before anything is decompressed."""

    member_count: int
    total_expanded_bytes: int
    names: tuple[str, ...]


@dataclass(frozen=True)
class PackageInfo:
    """A package that passed strict validation, and what it turned out to be.

    Returned so the validation happens ONCE per document and its result is
    carried, rather than every stage re-opening the archive to ask the same
    questions.
    """

    main_part: str
    main_content_type: str
    kind: str
    preflight: ZipPreflight


def preflight_zip_package(
    data: bytes, limits: ResourceLimits = DEFAULT_LIMITS
) -> ZipPreflight:
    """Read the central directory and refuse anything out of bounds.

    DECOMPRESSES NOTHING. Every check here reads metadata the archive already
    carries — member count, declared sizes, compression method, the encryption
    flag — which is the only way to refuse a decompression bomb without first
    decompressing it.

    The declared sizes are not trusted afterwards: ``read_member`` caps what it
    actually reads and the CRC check catches a central directory that lied. This
    pass is the cheap bound, that one is the honest one, and the document needs
    both.
    """
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = archive.infolist()
    except (zipfile.BadZipFile, OSError) as exc:
        raise InvalidDocumentError('Not a valid DOCX package') from exc

    if len(infos) > limits.max_zip_members:
        raise ResourceLimitExceededError(
            f'package has {len(infos)} members; the limit is {limits.max_zip_members}',
            code='ZIP_MEMBER_COUNT_EXCEEDED',
        )

    names: list[str] = []
    seen: set[str] = set()
    total = 0
    for info in infos:
        name = info.filename
        if name in seen:
            raise InvalidDocumentError(
                f'package contains {name!r} more than once',
                code='DUPLICATE_MEMBER_NAME',
            )
        seen.add(name)

        normalised = name.replace('\\', '/')
        if normalised.startswith('/') or '..' in normalised.split('/'):
            raise InvalidDocumentError(
                'package contains a member name that escapes the package',
                code='UNSAFE_MEMBER_NAME',
            )

        if info.flag_bits & _ENCRYPTED_FLAG:
            # Refused here so it cannot reach zipfile, which answers an
            # encrypted member with a bare RuntimeError and would surface as a
            # 500 for what is plainly a problem with the upload.
            raise InvalidDocumentError(
                f'package member {name!r} is encrypted',
                code='ENCRYPTED_ZIP_MEMBER',
            )
        if info.compress_type not in _SUPPORTED_COMPRESSION:
            raise InvalidDocumentError(
                f'package member {name!r} uses unsupported compression method '
                f'{info.compress_type}',
                code='UNSUPPORTED_COMPRESSION_METHOD',
            )

        size = int(info.file_size)
        if size > limits.max_zip_member_bytes:
            raise ResourceLimitExceededError(
                f'package member expands to {size} bytes; the limit is '
                f'{limits.max_zip_member_bytes}',
                code='ZIP_MEMBER_TOO_LARGE',
            )
        total += size
        if total > limits.max_zip_total_bytes:
            raise ResourceLimitExceededError(
                f'package expands to more than {limits.max_zip_total_bytes} bytes',
                code='ZIP_TOTAL_TOO_LARGE',
            )

        if size > limits.compression_ratio_floor_bytes:
            # Only large members are judged on ratio. Small XML parts reach 30:1
            # legitimately — the styles and settings of an ordinary decision do —
            # so a ratio cap without this floor would refuse real documents.
            ratio = size / max(int(info.compress_size), 1)
            if ratio > limits.max_compression_ratio:
                raise ResourceLimitExceededError(
                    f'package member expands {ratio:.0f}:1; the limit is '
                    f'{limits.max_compression_ratio:.0f}:1',
                    code='ZIP_COMPRESSION_RATIO_EXCEEDED',
                )

        names.append(name)

    return ZipPreflight(
        member_count=len(infos), total_expanded_bytes=total, names=tuple(names)
    )


def read_member(
    archive: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    limits: ResourceLimits = DEFAULT_LIMITS,
) -> bytes:
    """Read one member, never more than it declared and never past the cap.

    The read stops at ``file_size + 1`` bytes, so a central directory that
    understates a member cannot make this allocate without bound. Reading to the
    declared end also runs zipfile's CRC check, which is what catches a
    directory that lied in the other direction.
    """
    cap = min(int(info.file_size), limits.max_zip_member_bytes)
    try:
        with archive.open(info) as handle:
            data = handle.read(cap + 1)
    except (zipfile.BadZipFile, EOFError, zlib.error, ValueError, OSError) as exc:
        # NOT RuntimeError or NotImplementedError: the preflight already refused
        # encrypted and unsupported members, so seeing one here would mean a bug
        # in this file rather than a problem with the upload, and dressing a bug
        # up as a 400 sends the caller to look at a document that is fine.
        raise InvalidDocumentError(
            f'package member {info.filename!r} could not be read',
            code='CORRUPT_ZIP_MEMBER',
        ) from exc
    if len(data) > cap:
        raise ResourceLimitExceededError(
            f'package member {info.filename!r} is larger than it declared',
            code='ZIP_MEMBER_TOO_LARGE',
        )
    return data


def read_members(
    archive: zipfile.ZipFile,
    infos: list[zipfile.ZipInfo],
    limits: ResourceLimits = DEFAULT_LIMITS,
) -> dict[str, bytes]:
    """Read every member into memory, bounded in total as well as per member."""
    package: dict[str, bytes] = {}
    total = 0
    for info in infos:
        blob = read_member(archive, info, limits)
        total += len(blob)
        if total > limits.max_zip_total_bytes:
            raise ResourceLimitExceededError(
                f'package expands to more than {limits.max_zip_total_bytes} bytes',
                code='ZIP_TOTAL_TOO_LARGE',
            )
        package[info.filename] = blob
    return package


def _strict_root(blob: bytes, part_name: str, expected_tag: str) -> etree._Element:
    """Strictly parse a required part and confirm its root element.

    Required parts get the NON-recovering parser. The recovering one turns
    rubbish into an empty tree, and an empty [Content_Types].xml would mean
    "this package declares nothing" rather than "this package is broken".
    """
    try:
        root = etree.fromstring(blob, parser=STRICT_XML_PARSER)
    except etree.XMLSyntaxError as exc:
        raise InvalidDocumentError(
            f'{part_name} is not valid XML: {exc}',
            code='MALFORMED_PACKAGE_XML',
        ) from exc
    if root is None or root.tag != expected_tag:
        raise InvalidDocumentError(
            f'{part_name} has an unexpected root element',
            code='MALFORMED_PACKAGE_XML',
        )
    return root


def _main_document_target(rels_root: etree._Element) -> str:
    """The part the root relationships name as the office document.

    Exactly one officeDocument relationship is required. None means the package
    never says which part is the document; several mean it says so twice and we
    would be choosing.
    """
    targets: list[str] = []
    for relationship in rels_root:
        if not isinstance(relationship.tag, str):
            continue
        if relationship.get('Type') != OFFICE_DOCUMENT_REL_TYPE:
            continue
        target = (relationship.get('Target') or '').strip()
        if target:
            targets.append(target.lstrip('/'))

    if not targets:
        raise InvalidDocumentError(
            'package has no officeDocument relationship',
            code='INVALID_ROOT_RELATIONSHIP',
        )
    if len(targets) > 1:
        raise InvalidDocumentError(
            'package declares more than one officeDocument relationship',
            code='INVALID_ROOT_RELATIONSHIP',
        )
    return targets[0]


def _override_content_type(content_types_root: etree._Element, part_name: str) -> str:
    """The content type [Content_Types].xml declares for one part."""
    wanted = '/' + part_name
    for override in content_types_root:
        if not isinstance(override.tag, str):
            continue
        if etree.QName(override).localname != 'Override':
            continue
        if (override.get('PartName') or '').strip() == wanted:
            return (override.get('ContentType') or '').strip()
    raise InvalidDocumentError(
        f'{CONTENT_TYPES_PART} declares no content type for {part_name}',
        code='MALFORMED_PACKAGE_XML',
    )


def _validate_main_document_xml(blob: bytes) -> None:
    """Strictly parse ``word/document.xml`` and confirm it really is a Word document.

    The package-level checks above prove the archive is a well-formed OPC
    package that says it contains a Word document. They do not prove the
    document PARSES: a file can carry every expected name and relationship while
    its main part is truncated, wrongly encoded, or not WordprocessingML at all
    — and the recovering parser used for the rest of the package would turn that
    into an empty document, i.e. an empty redaction plan and an "anonymized"
    file that was never read. Rejecting it here is the whole point of this
    function.

    Raises InvalidDocumentError when the XML does not parse, when its root is
    not ``w:document``, or when it has no ``w:body``. Returns None.
    """
    try:
        root = etree.fromstring(blob, parser=STRICT_XML_PARSER)
    except etree.XMLSyntaxError as exc:
        raise InvalidDocumentError(
            f'word/document.xml is not valid XML: {exc}'
        ) from exc

    if root is None or root.tag != f'{{{W_NS}}}document':
        found = getattr(root, 'tag', None)
        raise InvalidDocumentError(
            'word/document.xml is not a WordprocessingML document '
            f'(root element is {found!r}, expected w:document)'
        )

    if root.find(f'{{{W_NS}}}body') is None:
        raise InvalidDocumentError('word/document.xml has no w:body element')


def validate_docx_package(
    data: bytes,
    *,
    limits: ResourceLimits = DEFAULT_LIMITS,
    expect_main_content_type: str | None = DOCX_MAIN_CONTENT_TYPE,
) -> PackageInfo:
    """Validate an OOXML Word package strictly, and say what it is.

    In order: preflight the archive, confirm the three required parts exist,
    strictly parse ``[Content_Types].xml`` and ``_rels/.rels``, resolve the
    officeDocument relationship, check what the package says its main part IS,
    and only then parse the main part itself.

    ``expect_main_content_type`` is the type the caller requires. Pass None to
    accept any of the four Word kinds, which is what format sniffing needs
    before normalisation; the default requires a plain document, which is what
    everything after normalisation needs.
    """
    preflight = preflight_zip_package(data, limits)
    names = set(preflight.names)

    required = [CONTENT_TYPES_PART, ROOT_RELS_PART, MAIN_DOCUMENT_PART]
    missing = [name for name in required if name not in names]
    if missing:
        raise InvalidDocumentError(
            'Not a valid DOCX package: missing ' + ', '.join(missing)
        )

    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        by_name = {info.filename: info for info in archive.infolist()}
        content_types_blob = read_member(archive, by_name[CONTENT_TYPES_PART], limits)
        rels_blob = read_member(archive, by_name[ROOT_RELS_PART], limits)
        main_blob = read_member(archive, by_name[MAIN_DOCUMENT_PART], limits)

    content_types_root = _strict_root(
        content_types_blob, CONTENT_TYPES_PART, f'{{{CONTENT_TYPES_NS}}}Types'
    )
    rels_root = _strict_root(
        rels_blob, ROOT_RELS_PART, f'{{{RELATIONSHIPS_NS}}}Relationships'
    )

    main_part = _main_document_target(rels_root)
    if main_part not in names:
        raise InvalidDocumentError(
            'the officeDocument relationship points at a part that is not in '
            'the package',
            code='INVALID_ROOT_RELATIONSHIP',
        )
    content_type = _override_content_type(content_types_root, main_part)

    kind = WORD_MAIN_CONTENT_TYPES.get(content_type)
    if kind is None:
        # A well-formed OPC package that is not a Word document: a spreadsheet,
        # a presentation, something else entirely. Nothing is wrong with it, so
        # this is an unsupported format rather than a malformed one.
        raise UnsupportedDocumentFormatError(
            'the package is not a Word document'
        )
    if expect_main_content_type is not None and content_type != expect_main_content_type:
        raise InvalidDocumentError(
            f'expected the main document part to be {expect_main_content_type!r}',
            code='UNEXPECTED_MAIN_CONTENT_TYPE',
        )
    if main_part != MAIN_DOCUMENT_PART:
        # Word always writes word/document.xml, and five modules address it by
        # that literal name. Supporting an arbitrary target would mean threading
        # the resolved name through all of them for a case that does not occur.
        raise InvalidDocumentError(
            f'the main document part must be {MAIN_DOCUMENT_PART}',
            code='UNSUPPORTED_MAIN_PART_NAME',
        )

    _validate_main_document_xml(main_blob)
    return PackageInfo(
        main_part=main_part,
        main_content_type=content_type,
        kind=kind,
        preflight=preflight,
    )


def validate_docx_bytes(data: bytes) -> None:
    """Validate that ``data`` is a well-formed DOCX package. Raise InvalidDocumentError if not.

    Thin wrapper over :func:`validate_docx_package` for callers that only need
    the verdict, kept because it is the shape the rest of the package and the
    tests already use.
    """
    validate_docx_package(data)


# ---------------------------------------------------------------------------
# XML part parsing helpers
# ---------------------------------------------------------------------------

def _parse_xml_parts(package_data: dict[str, bytes]) -> dict[str, etree._Element]:
    """Parse every .xml/.rels member of ``package_data`` into an lxml tree, skipping unparseable blobs. Return a mapping of part name to root element."""
    parsed: dict[str, etree._Element] = {}
    for name, blob in package_data.items():
        if not (name.endswith('.xml') or name.endswith('.rels')):
            continue
        try:
            element = etree.fromstring(blob, parser=XML_PARSER)
        except etree.XMLSyntaxError:
            continue
        if element is not None:
            parsed[name] = element
    return parsed


def _serialize_xml(root: etree._Element) -> bytes:
    """Serialize an lxml root element to UTF-8 bytes with an XML declaration."""
    return etree.tostring(root, encoding='UTF-8', xml_declaration=True)


def _local_name(element: etree._Element) -> str:
    """Return the namespace-free local tag name of ``element``."""
    return etree.QName(element).localname


def _is_word_text_part(part_name: str) -> bool:
    """Return True if ``part_name`` is a Word part carrying body text (document, headers, footers, footnotes, endnotes)."""
    return (
        part_name == 'word/document.xml'
        or (part_name.startswith('word/header') and part_name.endswith('.xml'))
        or (part_name.startswith('word/footer') and part_name.endswith('.xml'))
        or part_name in {'word/footnotes.xml', 'word/endnotes.xml'}
    )


# ---------------------------------------------------------------------------
# Element-path addressing (round-trippable pointer into the parsed tree)
# ---------------------------------------------------------------------------

def _element_path(root: etree._Element, element: etree._Element) -> str:
    """Compute a slash-separated child-index path from ``root`` down to ``element``. Return the path string ('/' for the root itself)."""
    if element is root:
        return '/'
    parts: list[str] = []
    current: etree._Element | None = element
    while current is not None and current is not root:
        parent = current.getparent()
        if parent is None:
            break
        parts.append(str(parent.index(current)))
        current = parent
    return '/' + '/'.join(reversed(parts))


def _find_by_element_path(root: etree._Element, path: str) -> etree._Element | None:
    """Resolve a child-index path produced by _element_path back to an element under ``root``. Return the element, or None if the path is invalid."""
    if path == '/':
        return root
    if not path.startswith('/'):
        return None
    current = root
    for token in path.strip('/').split('/'):
        # An empty token only arises from a malformed path (e.g. "/3//1"); the
        # contract is to reject any invalid token, so return None rather than
        # silently repairing it. (_element_path never emits empty tokens.)
        if not token:
            return None
        try:
            index = int(token)
        except ValueError:
            return None
        children = list(current)
        if index < 0 or index >= len(children):
            return None
        current = children[index]
    return current


# ---------------------------------------------------------------------------
# Character extraction — builds the normalized-text <-> XML char map
# ---------------------------------------------------------------------------

def _extract_para_chars(
    root: etree._Element,
    paragraph: etree._Element,
    part_name: str,
) -> tuple[list[str], list[XmlCharRef]]:
    """Extract the visible characters of ``paragraph`` (NFC-normalized per character, with tabs and breaks) alongside per-character XmlCharRef pointers into ``root``. Return the character list and its parallel char map."""
    chars: list[str] = []
    char_map: list[XmlCharRef] = []
    for node in paragraph.iter():
        if not isinstance(node.tag, str):
            continue
        if node.tag == f'{{{W_NS}}}t':
            text = node.text or ''
            node_path = _element_path(root, node)
            for idx, ch in enumerate(text):
                # Per-character NFC — never whole-string, which would shift
                # offsets and desynchronize the char map from the node text.
                norm = unicodedata.normalize('NFC', ch)
                if len(norm) != 1:
                    # NFC of a single char can expand to several (rare,
                    # composition-excluded codepoints). The 1 char : 1 ref
                    # alignment outranks normalization — keep the original.
                    norm = ch
                chars.append(norm)
                char_map.append(XmlCharRef(part_name, node_path, idx))
        elif node.tag == f'{{{W_NS}}}tab':
            chars.append('\t')
            char_map.append(XmlCharRef(part_name, '<w:tab/>', 0))
        elif node.tag == f'{{{W_NS}}}br':
            chars.append('\n')
            char_map.append(XmlCharRef(part_name, '<w:br/>', 0))
        elif node.tag == f'{{{W_NS}}}cr':
            chars.append('\n')
            char_map.append(XmlCharRef(part_name, '<w:cr/>', 0))
    # Load-bearing invariant: index i of the extracted text must always map to
    # char_map[i], or every downstream span offset is wrong.
    assert len(chars) == len(char_map), "char/char_map desynchronized"
    return chars, char_map


# ---------------------------------------------------------------------------
# Parsing a DOCX into TextUnits
# ---------------------------------------------------------------------------

def parse_docx(
    data: bytes,
    document_id: str,
    *,
    package: PackageInfo | None = None,
    limits: ResourceLimits = DEFAULT_LIMITS,
) -> DocumentData:
    """Parse DOCX bytes into a DocumentData of TextUnits (table cells and paragraphs with per-character XML maps) for all Word text parts. Raise InvalidDocumentError on malformed packages.

    ``package`` is a validation this caller has already done. Passing it skips a
    second strict pass over the same bytes; omitting it validates here, which is
    what keeps every entry point safe by default — the postcheck in particular
    validates the output itself rather than trusting anything the pipeline says
    about it.
    """
    if package is None:
        validate_docx_package(data, limits=limits)

    with zipfile.ZipFile(io.BytesIO(data)) as zin:
        package_data = read_members(zin, list(zin.infolist()), limits)

    parsed_parts = _parse_xml_parts(package_data)
    if 'word/document.xml' not in parsed_parts:
        # validate_docx_bytes just parsed this part strictly, so the recovering
        # parser dropping it would mean the two disagree. Refuse rather than
        # build an empty plan from a document nothing actually read.
        raise InvalidDocumentError('word/document.xml could not be parsed')

    text_units: list[TextUnit] = []
    unit_counter = 0

    for part_name in sorted(parsed_parts):
        if not _is_word_text_part(part_name):
            continue
        root = parsed_parts[part_name]

        # Paragraphs consumed by table cells, so the paragraph pass skips them.
        table_cell_paragraphs: set[etree._Element] = set()
        table_index = 0

        for table in root.xpath('.//w:tbl', namespaces=NSMAP):
            # Direct-child rows only. Any nested table's paragraphs are absorbed
            # into this outer cell below (the cell's .//w:p descends into them);
            # keep that behavior — downstream relies on it.
            rows = table.xpath('w:tr', namespaces=NSMAP)
            if not rows:
                continue

            header_texts: list[str] = []
            for cell in rows[0].xpath('w:tc', namespaces=NSMAP):
                cell_text = ''.join(
                    (node.text or '')
                    for node in cell.iter()
                    if isinstance(node.tag, str) and node.tag == f'{{{W_NS}}}t'
                )
                header_texts.append(cell_text.strip())

            for row_idx, row in enumerate(rows):
                is_header_row = row_idx == 0
                for col_idx, cell in enumerate(row.xpath('w:tc', namespaces=NSMAP)):
                    col_header = header_texts[col_idx] if col_idx < len(header_texts) else ''
                    chars: list[str] = []
                    char_map: list[XmlCharRef] = []
                    for para in cell.xpath('.//w:p', namespaces=NSMAP):
                        table_cell_paragraphs.add(para)
                        para_chars, para_map = _extract_para_chars(root, para, part_name)
                        chars.extend(para_chars)
                        char_map.extend(para_map)
                    if chars:
                        joined = ''.join(chars)
                        text_units.append(TextUnit(
                            unit_id=f'u{unit_counter}',
                            part_name=part_name,
                            unit_type='table_cell',
                            text=joined,
                            normalized_text=joined,
                            char_map=char_map,
                            location={
                                'table_index': table_index,
                                'row_index': row_idx,
                                'col_index': col_idx,
                                'column_header': col_header if not is_header_row else '',
                                'is_header_row': is_header_row,
                            },
                        ))
                        unit_counter += 1

            table_index += 1

        for paragraph in root.xpath('.//w:p', namespaces=NSMAP):
            if paragraph in table_cell_paragraphs:
                continue
            chars, char_map = _extract_para_chars(root, paragraph, part_name)
            if chars:
                joined = ''.join(chars)
                text_units.append(TextUnit(
                    unit_id=f'u{unit_counter}',
                    part_name=part_name,
                    unit_type='paragraph',
                    text=joined,
                    normalized_text=joined,
                    char_map=char_map,
                    # Global counter that also counted table cells: downstream
                    # relies on document order, not the numeric value.
                    location={'paragraph_index': unit_counter},
                ))
                unit_counter += 1

    return DocumentData(
        document_id=document_id,
        text_units=text_units,
        parts_inventory=sorted(package_data),
        warnings=[],
    )


# ---------------------------------------------------------------------------
# Applying a redaction plan (1:1 character substitution only)
# ---------------------------------------------------------------------------

def _apply_node_edits(root: etree._Element, edits: list[tuple[str, int, str]]) -> None:
    """Apply per-character replacements to w:t nodes under ``root``, given (node path, char index, replacement) edits; synthetic '<...>' paths are skipped. Mutates the tree in place and returns None."""
    grouped: dict[str, list[tuple[int, str]]] = {}
    for text_node_path, char_index, replacement in edits:
        if text_node_path.startswith('<'):
            continue
        grouped.setdefault(text_node_path, []).append((char_index, replacement))

    for text_node_path, node_edits in grouped.items():
        node = _find_by_element_path(root, text_node_path)
        if node is None:
            continue
        chars = list(node.text or '')
        for char_index, replacement in sorted(node_edits, key=lambda item: item[0], reverse=True):
            if 0 <= char_index < len(chars):
                chars[char_index] = replacement
        node.text = ''.join(chars)


def apply_plan(
    parsed_parts: dict[str, etree._Element],
    document: DocumentData,
    plan: RedactionPlan,
) -> None:
    """Apply a RedactionPlan to the parsed parts, replacing each character of every REDACT span with the redaction glyph via the units' char maps. Mutates ``parsed_parts`` in place and returns None."""
    spans_by_unit: dict[str, list] = {}
    for span in plan.spans:
        spans_by_unit.setdefault(span.unit_id, []).append(span)

    for unit in document.text_units:
        part_root = parsed_parts.get(unit.part_name)
        if part_root is None:
            continue
        map_len = len(unit.char_map)
        for span in sorted(spans_by_unit.get(unit.unit_id, []), key=lambda s: int(s.start), reverse=True):
            if str(span.action).upper() != 'REDACT':
                continue
            start = min(max(0, int(span.start)), map_len)
            end = min(max(0, int(span.end)), map_len)
            edits: list[tuple[str, int, str]] = []
            for i in range(start, end):
                ref = unit.char_map[i]
                if ref.text_node_path.startswith('<'):
                    continue
                edits.append((ref.text_node_path, ref.char_index, REDACTION_GLYPH))
            if edits:
                _apply_node_edits(part_root, edits)


# ---------------------------------------------------------------------------
# Metadata / structural cleanup
# ---------------------------------------------------------------------------

def _first_child(root: etree._Element, qname: str) -> etree._Element | None:
    """Return the first direct child of ``root`` with the fully-qualified tag ``qname``, or None."""
    for child in root:
        if isinstance(child.tag, str) and child.tag == qname:
            return child
    return None


def _blank_children(root: etree._Element, qnames: list[str]) -> None:
    """Blank the text and remove subelements of each direct child of ``root`` matching a qname in ``qnames``. Returns None."""
    for qname in qnames:
        child = _first_child(root, qname)
        if child is not None:
            child.text = ''
            for sub in list(child):
                child.remove(sub)


def _set_child_text(root: etree._Element, qname: str, text: str) -> None:
    """Set the text of the first direct child of ``root`` matching ``qname`` to ``text``, removing its subelements. Returns None."""
    child = _first_child(root, qname)
    if child is not None:
        child.text = text
        for sub in list(child):
            child.remove(sub)


def _cleanup_core_properties(parsed_parts: dict[str, etree._Element]) -> None:
    """Blank identifying core properties in docProps/core.xml and reset the
    created/modified timestamps to a fixed epoch. Returns None.

    dc:creator AND cp:lastModifiedBy ARE DELIBERATELY LEFT ALONE, and this is a
    ΔΕΔ-COMPATIBILITY DECISION RATHER THAN A PRIVACY ONE. The published gold
    decisions keep both — ``dc:creator`` reads "user" and ``cp:lastModifiedBy``
    carries the name of the clerk who prepared the file — and matching that
    output byte for byte is the requirement this service is held to.

    It is NOT a general privacy guarantee, and nothing downstream makes it one:
    a future ``cp:lastModifiedBy`` can hold a person's real name, it is not text
    the detectors ever see, and the post-redaction scan no longer fails a
    document for it. A deployment that needs the stronger behaviour has to add
    these two names back to the list below AND restore the matching HIGH
    findings in anonymizer.postcheck.
    """
    root = parsed_parts.get('docProps/core.xml')
    if root is None:
        return
    _blank_children(root, [
        f'{{{DC_NS}}}title',
        f'{{{CP_NS}}}keywords',
        f'{{{CP_NS}}}category',
    ])
    _set_child_text(root, f'{{{DCTERMS_NS}}}created', '2000-01-01T00:00:00Z')
    _set_child_text(root, f'{{{DCTERMS_NS}}}modified', '2000-01-01T00:00:00Z')


def _cleanup_app_properties(parsed_parts: dict[str, etree._Element]) -> None:
    """Blank the Company, Manager, and Template fields in docProps/app.xml if present. Returns None."""
    root = parsed_parts.get('docProps/app.xml')
    if root is None:
        return
    for element in root.iter():
        if isinstance(element.tag, str) and _local_name(element) in {'Company', 'Manager', 'Template'}:
            element.text = ''
            for child in list(element):
                element.remove(child)


def _remove_custom_properties(parsed_parts: dict[str, etree._Element], removed_parts: set[str]) -> None:
    """Drop docProps/custom.xml from the package along with its relationship and content-type entries, recording it in ``removed_parts``. Returns None."""
    removed_parts.add('docProps/custom.xml')
    parsed_parts.pop('docProps/custom.xml', None)

    rels = parsed_parts.get('_rels/.rels')
    if rels is not None:
        for rel in list(rels):
            target = rel.get('Target', '')
            rel_type = rel.get('Type', '')
            if target in {'docProps/custom.xml', '/docProps/custom.xml'} or rel_type.endswith('/custom-properties'):
                rels.remove(rel)

    content_types = parsed_parts.get('[Content_Types].xml')
    if content_types is not None:
        for override in list(content_types):
            if override.get('PartName') == '/docProps/custom.xml':
                content_types.remove(override)


def _remove_elements(root: etree._Element, qnames: list[str]) -> None:
    """Remove every element under ``root`` whose tag matches one of ``qnames``. Returns None."""
    qname_set = set(qnames)
    for element in list(root.iter()):
        if not isinstance(element.tag, str) or element.tag not in qname_set:
            continue
        parent = element.getparent()
        if parent is not None:
            parent.remove(element)


def _cleanup_comments(parsed_parts: dict[str, etree._Element]) -> None:
    """Replace word/comments.xml with an empty comments part and strip comment range/reference markers from the document body. Returns None."""
    if 'word/comments.xml' in parsed_parts:
        parsed_parts['word/comments.xml'] = etree.Element(f'{{{W_NS}}}comments', nsmap={'w': W_NS})
    document = parsed_parts.get('word/document.xml')
    if document is not None:
        _remove_elements(document, [
            f'{{{W_NS}}}commentRangeStart',
            f'{{{W_NS}}}commentRangeEnd',
            f'{{{W_NS}}}commentReference',
        ])


def _append_tail(parent: etree._Element, index: int, tail: str | None) -> None:
    """Attach ``tail`` text at child position ``index`` of ``parent``, merging into the previous sibling's tail or the parent's text. Returns None."""
    if not tail:
        return
    if index > 0:
        previous = parent[index - 1]
        previous.tail = (previous.tail or '') + tail
    else:
        parent.text = (parent.text or '') + tail


def _unwrap_element(element: etree._Element) -> None:
    """Remove ``element`` from its parent while promoting its children and preserving surrounding text and tail. Returns None."""
    parent = element.getparent()
    if parent is None:
        return
    index = parent.index(element)
    children = list(element)
    leading_text = element.text
    tail = element.tail
    parent.remove(element)
    if leading_text:
        if index > 0:
            previous = parent[index - 1]
            previous.tail = (previous.tail or '') + leading_text
        else:
            parent.text = (parent.text or '') + leading_text
    for offset, child in enumerate(children):
        parent.insert(index + offset, child)
    _append_tail(parent, index + len(children), tail)


def _drop_element(element: etree._Element) -> None:
    """Remove ``element`` and its contents from its parent, preserving only its tail text. Returns None."""
    parent = element.getparent()
    if parent is None:
        return
    index = parent.index(element)
    tail = element.tail
    parent.remove(element)
    _append_tail(parent, index, tail)


def _cleanup_tracked_changes(root: etree._Element) -> None:
    """Accept all tracked changes under ``root``: unwrap insertions/move-tos and drop deletions/move-froms. Returns None."""
    tags = {f'{{{W_NS}}}ins', f'{{{W_NS}}}del', f'{{{W_NS}}}moveFrom', f'{{{W_NS}}}moveTo'}
    wrappers = [element for element in root.iter() if isinstance(element.tag, str) and element.tag in tags]
    # Reverse document order keeps nested wrappers consistent as we splice.
    for element in reversed(wrappers):
        if element.getparent() is None:
            continue
        if element.tag in {f'{{{W_NS}}}ins', f'{{{W_NS}}}moveTo'}:
            _unwrap_element(element)
        else:
            _drop_element(element)


def _cleanup_hidden_text(root: etree._Element) -> None:
    """Remove all runs under ``root`` marked hidden via w:vanish run properties. Returns None."""
    runs = [run for run in root.iter(f'{{{W_NS}}}r') if run.xpath('./w:rPr/w:vanish', namespaces=NSMAP)]
    for run in runs:
        if run.getparent() is not None:
            _drop_element(run)


def _cleanup_word_parts(parsed_parts: dict[str, etree._Element]) -> None:
    """Run tracked-change and hidden-text cleanup over every Word text part in ``parsed_parts``. Returns None."""
    for part_name, root in list(parsed_parts.items()):
        if _is_word_text_part(part_name):
            _cleanup_tracked_changes(root)
            _cleanup_hidden_text(root)


def clean_sensitive_parts(
    parsed_parts: dict[str, etree._Element],
    removed_parts: set[str] | None = None,
) -> set[str]:
    """Scrub metadata, custom properties, comments, tracked changes, and hidden text from the parsed package. Return the set of part names removed entirely."""
    # Only None triggers a fresh set; a caller-supplied set (even an empty one)
    # is populated in place and returned.
    if removed_parts is None:
        removed_parts = set()
    _cleanup_core_properties(parsed_parts)
    _cleanup_app_properties(parsed_parts)
    _remove_custom_properties(parsed_parts, removed_parts)
    _cleanup_comments(parsed_parts)
    _cleanup_word_parts(parsed_parts)
    return removed_parts


# ---------------------------------------------------------------------------
# Byte-verbatim write-back
# ---------------------------------------------------------------------------

def _copy_zipinfo(info: zipfile.ZipInfo) -> zipfile.ZipInfo:
    """Return a new ZipInfo copying the metadata (name, dates, attributes, compression) of ``info``."""
    copied = zipfile.ZipInfo(filename=info.filename, date_time=info.date_time)
    copied.comment = info.comment
    copied.extra = info.extra
    copied.internal_attr = info.internal_attr
    copied.external_attr = info.external_attr
    copied.create_system = info.create_system
    copied.compress_type = info.compress_type
    return copied


def write_redacted_docx(
    input_bytes: bytes,
    document: DocumentData,
    plan: RedactionPlan,
    *,
    package: PackageInfo | None = None,
    limits: ResourceLimits = DEFAULT_LIMITS,
) -> bytes:
    """Produce redacted DOCX bytes from ``input_bytes`` by applying the redaction plan and cleaning sensitive parts, copying untouched members verbatim. Return the new package bytes; raise DocumentProcessingError on failure."""
    if package is None:
        validate_docx_package(input_bytes, limits=limits)

    stage = 'read'
    try:
        with zipfile.ZipFile(io.BytesIO(input_bytes)) as zin:
            infos = list(zin.infolist())
            package_data = read_members(zin, infos, limits)

        stage = 'parse'
        parsed_parts = _parse_xml_parts(package_data)

        stage = 'apply_plan'
        apply_plan(parsed_parts, document, plan)

        stage = 'clean_sensitive_parts'
        removed_parts = clean_sensitive_parts(parsed_parts)

        stage = 'write'
        output = io.BytesIO()
        with zipfile.ZipFile(output, 'w') as zout:
            written: set[str] = set()
            for info in infos:
                name = info.filename
                if name in written or name in removed_parts:
                    continue
                written.add(name)
                if name in parsed_parts:
                    payload = _serialize_xml(parsed_parts[name])
                else:
                    payload = package_data[name]
                zout.writestr(_copy_zipinfo(info), payload)
        return output.getvalue()
    except (
        InvalidDocumentError,
        DocumentProcessingError,
        ResourceLimitExceededError,
        UnsupportedDocumentFormatError,
    ):
        raise
    except Exception as exc:
        raise DocumentProcessingError(f'failed during {stage}') from exc


__all__ = [
    'CONTENT_TYPES_PART',
    'DOCX_MAIN_CONTENT_TYPE',
    'MAIN_DOCUMENT_PART',
    'PackageInfo',
    'ROOT_RELS_PART',
    'WORD_MAIN_CONTENT_TYPES',
    'ZipPreflight',
    'apply_plan',
    'clean_sensitive_parts',
    'parse_docx',
    'preflight_zip_package',
    'read_member',
    'read_members',
    'validate_docx_bytes',
    'validate_docx_package',
    'write_redacted_docx',
]
