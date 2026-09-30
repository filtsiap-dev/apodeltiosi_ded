"""What kind of Word document arrived, and turning it into a plain one.

The service accepts four OOXML formats — ``.docx``, ``.docm``, ``.dotx``,
``.dotm`` — and always returns a ``.docx``. Legacy binary Word (``.doc``,
``.dot``) is refused: it is not OOXML at all, and converting it would mean
running an office suite as a subprocess on attacker-supplied input, which is a
larger attack surface than the feature is worth.

THE HEADER IS A CLAIM; THE PACKAGE IS THE EVIDENCE. A caller can label anything
as anything, so the media type only decides whether the request is worth reading
and the CONTENT decides what is actually processed. A ``.doc`` renamed to
``.docx`` is caught by its OLE2 signature, and a ``.docm`` sent as a ``.docx`` is
processed as the macro-enabled package it is.

NORMALISATION IS NATIVE AND IN-PROCESS. The three non-``.docx`` kinds differ from
a document in exactly two ways that matter here: the content type their main
part declares, and the macro payload they may carry. Both are package plumbing,
so both are rewritten directly — no conversion, no subprocess, no temporary
files anywhere in this path. What comes out opens as a ``.docx`` and carries no
macro-execution capability, which is the guarantee the postcheck then verifies
independently on the finished output.

Scope, deliberately: this module removes macro parts and the settings that make
Word reach for an external template on open. It does NOT scrub metadata,
hyperlink targets, custom XML or field instructions for retained personal data —
that is audit finding F4, and it is accepted and out of scope here.
"""

from __future__ import annotations

import io
import zipfile
from typing import Iterable, Literal

from lxml import etree

from anonymizer.docx_engine import (
    CONTENT_TYPES_PART,
    DOCX_MAIN_CONTENT_TYPE,
    PackageInfo,
    XML_PARSER,
    _copy_zipinfo,
    _serialize_xml,
    read_members,
    validate_docx_package,
)
from anonymizer.errors import InvalidDocumentError, UnsupportedDocumentFormatError
from anonymizer.limits import DEFAULT_LIMITS, ResourceLimits

WordKind = Literal["docx", "docm", "dotx", "dotm"]

# Compound File Binary signature: every legacy .doc and .dot begins with it.
OLE2_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
# Local file header. An OOXML package is a ZIP, so it begins with one.
ZIP_MAGIC = b"PK\x03\x04"

W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
RELATIONSHIPS_NS = "http://schemas.openxmlformats.org/package/2006/relationships"

# The parts that carry macro code, and the relationships that point at them.
MACRO_PARTS = frozenset({"word/vbaProject.bin", "word/vbaData.xml"})
MACRO_REL_TYPE_SUFFIXES = ("/vbaProject", "/wordVbaData")

# Settings that make Word go looking for something outside the file when the
# document is opened: an attached template, its styles, and field recalculation.
_EXTERNAL_UPDATE_SETTINGS = (
    f"{{{W_NS}}}attachedTemplate",
    f"{{{W_NS}}}linkStyles",
    f"{{{W_NS}}}updateFields",
)

_SETTINGS_PART = "word/settings.xml"
_DOCUMENT_RELS_PART = "word/_rels/document.xml.rels"


def macro_artifacts(names: Iterable[str]) -> list[str]:
    """The macro-bearing members present in a package, by name.

    Used both to decide whether normalisation has work to do and, on the
    finished output, to verify that it did it.
    """
    return sorted(name for name in names if name in MACRO_PARTS)


def sniff_format(
    data: bytes, limits: ResourceLimits = DEFAULT_LIMITS
) -> PackageInfo:
    """Decide what ``data`` actually is, from its bytes rather than its label.

    Raises :class:`UnsupportedDocumentFormatError` (415) for a legacy binary
    Word file, for OOXML that is not a Word document, and for anything that is
    not a recognisable document at all; :class:`InvalidDocumentError` (400) for
    something that claims to be an OOXML package and is broken.
    """
    if data.startswith(OLE2_MAGIC):
        raise UnsupportedDocumentFormatError(
            "legacy binary Word documents (.doc/.dot) are not supported; "
            "save the file as .docx and send it again",
            code="UNSUPPORTED_LEGACY_WORD_FORMAT",
        )
    if not data.startswith(ZIP_MAGIC):
        # Not a ZIP and not a compound file: this is not a document in a format
        # we declined, it is bytes that are not a document. That is malformed
        # input (400), and the distinction matters to the caller — 415 tells
        # them to send a different format, 400 tells them to look at the file.
        raise InvalidDocumentError("Not a valid DOCX package")
    # Accepts any of the four Word main content types and reports which.
    return validate_docx_package(data, limits=limits, expect_main_content_type=None)


def needs_normalization(package: PackageInfo) -> bool:
    """Whether this package would change on its way to being a plain document."""
    if package.kind != "docx":
        return True
    return bool(macro_artifacts(package.preflight.names))


def normalize_to_docx(
    data: bytes,
    package: PackageInfo,
    limits: ResourceLimits = DEFAULT_LIMITS,
) -> bytes:
    """Return ``data`` as a plain ``.docx`` with no macro-execution capability.

    A package that is already a document and carries no macro payload is
    returned UNCHANGED — byte for byte, the same object. That fast path is not
    an optimisation: rewriting a package that needs no rewriting would rebuild
    every member and quietly end the byte-verbatim round trip the engine
    otherwise guarantees.

    Otherwise: the main part's declared content type becomes the document one,
    macro parts and the relationships and content-type entries that name them
    are removed, and the settings that reach for an external template on open
    are dropped. Everything else is copied through exactly as it arrived.
    """
    if not needs_normalization(package):
        return data

    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        infos = list(archive.infolist())
        members = read_members(archive, infos, limits)

    removed = set(macro_artifacts(members))
    remaining = [name for name in members if name not in removed]

    rewritten: dict[str, bytes] = {}

    # --- [Content_Types].xml: the main part becomes a document, and the macro
    #     declarations go with the macro parts.
    content_types = _parse(members[CONTENT_TYPES_PART], CONTENT_TYPES_PART)
    extensions_left = {
        name.rsplit(".", 1)[-1].casefold() for name in remaining if "." in name
    }
    for element in list(content_types):
        if not isinstance(element.tag, str):
            continue
        local = etree.QName(element).localname
        if local == "Override":
            part_name = (element.get("PartName") or "").lstrip("/")
            if part_name in removed:
                content_types.remove(element)
            elif part_name == package.main_part:
                element.set("ContentType", DOCX_MAIN_CONTENT_TYPE)
        elif local == "Default":
            extension = (element.get("Extension") or "").casefold()
            # A Default covers an EXTENSION, not a part: `bin` is shared with
            # embedded objects and printer settings, so it may only be dropped
            # when nothing left in the package still uses it.
            if extension and extension not in extensions_left:
                content_types.remove(element)
    rewritten[CONTENT_TYPES_PART] = _serialize_xml(content_types)

    # --- word/_rels/document.xml.rels: drop what pointed at the macro parts.
    if _DOCUMENT_RELS_PART in members:
        rels = _parse(members[_DOCUMENT_RELS_PART], _DOCUMENT_RELS_PART)
        for relationship in list(rels):
            if not isinstance(relationship.tag, str):
                continue
            rel_type = relationship.get("Type") or ""
            target = (relationship.get("Target") or "").lstrip("/")
            resolved = target if "/" in target else f"word/{target}"
            if rel_type.endswith(MACRO_REL_TYPE_SUFFIXES) or resolved in removed:
                rels.remove(relationship)
        rewritten[_DOCUMENT_RELS_PART] = _serialize_xml(rels)

    # --- word/settings.xml: stop the document reaching outside itself on open.
    if _SETTINGS_PART in members:
        settings = _parse(members[_SETTINGS_PART], _SETTINGS_PART)
        changed = False
        for element in list(settings):
            if isinstance(element.tag, str) and element.tag in _EXTERNAL_UPDATE_SETTINGS:
                settings.remove(element)
                changed = True
        if changed:
            rewritten[_SETTINGS_PART] = _serialize_xml(settings)

    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as target:
        written: set[str] = set()
        for info in infos:
            name = info.filename
            if name in removed or name in written:
                continue
            written.add(name)
            target.writestr(_copy_zipinfo(info), rewritten.get(name, members[name]))
    return output.getvalue()


def _parse(blob: bytes, part_name: str) -> etree._Element:
    """Parse a package part that normalisation has to rewrite."""
    try:
        root = etree.fromstring(blob, parser=XML_PARSER)
    except etree.XMLSyntaxError as exc:
        raise InvalidDocumentError(
            f"{part_name} is not valid XML", code="MALFORMED_PACKAGE_XML"
        ) from exc
    if root is None:
        raise InvalidDocumentError(
            f"{part_name} is empty", code="MALFORMED_PACKAGE_XML"
        )
    return root


__all__ = [
    "MACRO_PARTS",
    "OLE2_MAGIC",
    "WordKind",
    "ZIP_MAGIC",
    "macro_artifacts",
    "needs_normalization",
    "normalize_to_docx",
    "sniff_format",
]
