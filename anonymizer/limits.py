"""The finite bounds every document is processed within.

These exist because every other bound in the service is a consequence of the
input, and an attacker chooses the input. A 20 MB upload cap says nothing about
how much memory the file expands to, how many parts it contains, or how many
provider calls it will cost — a few kilobytes of well-chosen ZIP can become
gigabytes of XML, and a few hundred tiny tables can become a few hundred LLM
chunks. Each number below closes one of those gaps.

They live in their own module so the document engine can take them without
importing ``anonymizer.config``, which imports the postcheck, which imports the
engine. They are carried on ``RuntimeConfig.limits`` and overridable per
deployment through the ``ANON_*`` variables named beside each field.

THE DEFAULTS ARE CALIBRATED, NOT GUESSED. Measured against a real Greek tax
decision from this corpus: 166,064 bytes on the wire, 23 ZIP members, 1,133,152
bytes expanded (7.0:1 overall), 211 text units, 37,986 characters, 19 chunks at
the default 3000-character chunk size. Every default below leaves that document
between eight and sixty times of headroom.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ResourceLimits:
    """Finite caps on one document's size, expansion and processing cost."""

    # The wire limit, enforced while the body is read rather than after it.
    # Exactly 20,000,000 bytes, not 20 MiB: a round decimal number is what the
    # operator agreed to, and 20 * 1024 * 1024 is a different, larger number.
    max_upload_bytes: int = 20_000_000            # ANON_MAX_UPLOAD_BYTES

    # A Word package is tens of parts. Five hundred leaves room for a document
    # full of headers, footers and images without leaving room for an archive
    # whose part count is the attack.
    max_zip_members: int = 500                    # ANON_MAX_ZIP_MEMBERS

    # No single part may expand past this. Above the upload cap on purpose, so a
    # STORED member can never trip it — only a compressed one can, which is the
    # case worth refusing.
    max_zip_member_bytes: int = 25_000_000        # ANON_MAX_ZIP_MEMBER_BYTES

    # The whole package, expanded. This is the real memory bound: the engine
    # holds every member in a dict while it works.
    max_zip_total_bytes: int = 60_000_000         # ANON_MAX_ZIP_TOTAL_BYTES

    # Expansion ratio for one member, checked only above the floor below. The
    # floor is what makes a ratio cap safe: small XML parts legitimately reach
    # 30:1 and higher (the measured document has a 32.8:1 member), and judging
    # those would refuse ordinary files. A member that is both large AND wildly
    # compressible is the shape of a decompression bomb.
    max_compression_ratio: float = 50.0           # ANON_MAX_COMPRESSION_RATIO
    compression_ratio_floor_bytes: int = 1_000_000  # ANON_COMPRESSION_RATIO_FLOOR_BYTES

    # Extracted text, across every unit. Bounds the LLM stage's input and the
    # detector's regex work, neither of which the ZIP limits constrain.
    max_text_chars: int = 400_000                 # ANON_MAX_TEXT_CHARS

    # Chunks, after splitting. Bounds provider cost directly, and catches the
    # one shape the character cap does not: every table becomes its own chunk
    # regardless of size, so many tiny tables produce many chunks from very
    # little text.
    max_chunks: int = 150                         # ANON_MAX_CHUNKS


DEFAULT_LIMITS = ResourceLimits()


__all__ = ["ResourceLimits", "DEFAULT_LIMITS"]
