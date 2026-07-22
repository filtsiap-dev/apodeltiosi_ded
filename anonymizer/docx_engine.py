from __future__ import annotations

import io
import unicodedata
import zipfile

from lxml import etree

from anonymizer.errors import DocumentProcessingError, InvalidDocumentError
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

XML_PARSER = etree.XMLParser(
    resolve_entities=False,
    no_network=True,
    recover=True,
    remove_blank_text=False,
)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def validate_docx_bytes(data: bytes) -> None:
    """Validate that ``data`` is a well-formed DOCX ZIP package containing the required parts. Raise InvalidDocumentError if it is not; return None."""
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = set(zf.namelist())
            bad_member = zf.testzip()
    except (zipfile.BadZipFile, OSError) as exc:
        raise InvalidDocumentError('Not a valid DOCX package') from exc

    if bad_member is not None:
        raise InvalidDocumentError(f'Not a valid DOCX package: corrupt member {bad_member}')

    required = ['[Content_Types].xml', '_rels/.rels', 'word/document.xml']
    missing = [name for name in required if name not in names]
    if missing:
        raise InvalidDocumentError('Not a valid DOCX package: missing ' + ', '.join(missing))


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

def parse_docx(data: bytes, document_id: str) -> DocumentData:
    """Parse DOCX bytes into a DocumentData of TextUnits (table cells and paragraphs with per-character XML maps) for all Word text parts. Raise InvalidDocumentError on malformed packages."""
    validate_docx_bytes(data)

    with zipfile.ZipFile(io.BytesIO(data)) as zin:
        package_data = {info.filename: zin.read(info.filename) for info in zin.infolist()}

    parsed_parts = _parse_xml_parts(package_data)
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
    """Blank identifying core properties (creator, lastModifiedBy, title, keywords, category) in docProps/core.xml and reset created/modified timestamps to a fixed epoch. Returns None."""
    root = parsed_parts.get('docProps/core.xml')
    if root is None:
        return
    _blank_children(root, [
        f'{{{DC_NS}}}creator',
        f'{{{CP_NS}}}lastModifiedBy',
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


def write_redacted_docx(input_bytes: bytes, document: DocumentData, plan: RedactionPlan) -> bytes:
    """Produce redacted DOCX bytes from ``input_bytes`` by applying the redaction plan and cleaning sensitive parts, copying untouched members verbatim. Return the new package bytes; raise DocumentProcessingError on failure."""
    validate_docx_bytes(input_bytes)

    stage = 'read'
    try:
        with zipfile.ZipFile(io.BytesIO(input_bytes)) as zin:
            infos = list(zin.infolist())
            package_data = {info.filename: zin.read(info.filename) for info in infos}

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
    except (InvalidDocumentError, DocumentProcessingError):
        raise
    except Exception as exc:
        raise DocumentProcessingError(f'failed during {stage}') from exc


__all__ = [
    'validate_docx_bytes',
    'parse_docx',
    'write_redacted_docx',
    'apply_plan',
    'clean_sensitive_parts',
]
