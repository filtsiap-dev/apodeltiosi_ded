"""Narrowing for REDACT spans the LLM produced.

The prompt asks pass 2 to quote the value and not the label that introduces it.
A prompt is a request, so this is the part that holds whatever comes back to
that rule.

ONLY EVER NARROWS, in the geometric sense: every function returns a sub-range of
the span it was given, or None. It cannot widen a span, cannot move one, and
cannot turn a REDACT into a PRESERVE.

THAT IS NOT THE SAME AS BEING SAFE, and an earlier version of this file claimed
it was. Narrowing a span that was already correct is under-redaction: when the
cue matcher had no word boundary, "Iban" matched the first four letters of the
surname "Ibanez" and this function published them. Geometry being monotone says
nothing about whether the characters it gave up were personal data.

Two guards, therefore, and both are load-bearing:

* a cue only counts as a whole word (the boundary lives in ``_TRIM_CUE_RE``), so
  it can never match the prefix of a longer one;
* and no cue is trimmed at all from a span in a NAME category — see
  ``_NAME_CATEGORIES`` below. "Ιβάν" is a first name and "ΙΒΑΝ" is a label, the
  two are one casefold apart, and the category is the only thing that
  distinguishes them.

Not the primary defence: ``FIELD_LABEL`` spans already win a label's characters
back at the resolver, per character, whatever geometry the model returned. What
this adds is that the PLAN says what actually happened — a span reported as
``PRIVATE_ADDRESS`` covers the address rather than the address plus "κατοίκου" —
so the summary counts and the postcheck's over-redaction report mean what they
say.

Applied to REDACT spans only. A PRESERVE span that is too wide is a different
question, settled by the resolver's ladder rather than by trimming.
"""

from __future__ import annotations

from anonymizer.detector_patterns import (
    _LEADING_PREPOSITION_RE,
    _NOTICE_CUE_BEFORE_RE,
    _TRAILING_REFERENCE_DATE_RE,
    _TRAILING_YEAR_RE,
    _TRIM_CUE_RE,
)

# Categories whose ΔΕΔ convention keeps a trailing "/YYYY" visible:
# "αριθμό πρωτοκόλλου ……/30-03-2026", "τη με αριθμό ……/2020 απόφαση".
# Deliberately a closed list rather than a rule about digits, because another
# identifier may carry a year as an integral component — Α.Χ.Κ. 76/19062 is a
# serial, not a reference to the year 19062, and nothing here should guess.
_YEAR_SUFFIX_CATEGORIES = frozenset({
    "PROTOCOL_NUMBER",
    "AUDIT_ORDER",
    "CHALLENGED_ACT_NUMBER",
    "CASE_REF_NUMBER",
    "CASE_COURT_REFERENCE",
})

# Trimmed from either end. Quotation marks and brackets are here because a model
# that quotes «Παπαδόπουλος» or (Α.Χ.Κ. 76/19062) has included punctuation that
# belongs to the sentence, not to the value.
_EDGE_CHARS = " \t\n\r.,;:·()[]{}«»\"'’‚“”/-–—"

# Spans whose content IS a name, and from which no cue is ever trimmed.
#
# The cue vocabulary is built for identifiers and addresses, where a label
# reliably precedes the value. Applied to a name it is actively wrong: "Ιβάν",
# "Ιβανίδης" and "Τράπεζα" as the first word of a company's registered name all
# begin with something the cue list recognises, and trimming it publishes part of
# the very thing the span exists to blank.
#
# Edge punctuation is still trimmed for these — «…» is quoting, not naming.
#
# A leading preposition is trimmed only when the source WROTE IT IN LOWER CASE.
# An earlier comment here claimed no name begins with "με" or "στο", and that is
# simply false: "Στο Σπίτι" is a company, "ΣΕ-ΛΙ" is a name, and trimming
# published "Σπίτι" and "ΛΙ" out of spans that had correctly claimed them.
# Case is the one signal available at this layer: a preposition doing its
# grammatical job in running prose is lower-case ("με Παπαδόπουλο"), while the
# first word of a name is capitalised. When it is capitalised this function
# keeps it, which costs one over-redacted function word — the cheap direction.
#
# The relational article of a patronymic is deliberately NOT in the preposition
# list, so "του ΔΗΜΗΤΡΙΟΥ" keeps its article here as it does everywhere else.
_NAME_CATEGORIES = frozenset({
    "POSSIBLE_PERSON",
    "POSSIBLE_COMPANY",
    "APPELLANT_NAME",
    "FATHER_NAME",
    "PRIVATE_BENEFICIARY",
    "PRIVATE_COMPANY_NAME",
    "OFFICIAL_SIGNATORY",
})


def _trailing_region(text: str, regions: frozenset[str]) -> int:
    """How many characters of ``text`` are a trailing administrative region.

    0 when it does not end in one. The comparison is case-insensitive and uses
    the ALLOWLIST'S OWN length to cut, never the folded length: Greek folds its
    final sigma (``ς`` -> ``σ``) and a length taken from the folded form would
    be right only by luck.

    Bounded to one region: "Χαλανδρίου Αττικής" gives up "Αττικής" and stops.
    """
    stripped = text.rstrip(" \t,")
    for region in regions:
        if not region or len(region) >= len(stripped):
            # `>=` deliberately: a span that is NOTHING BUT a region has no
            # municipality in it to redact, and giving the whole span back is
            # not this function's decision to make.
            continue
        tail = stripped[-len(region):]
        if tail.casefold() != region.casefold():
            continue
        head = stripped[: len(stripped) - len(region)]
        if head.strip(" \t,"):
            return len(text) - len(head.rstrip(" \t,"))
    return 0


def narrow_redaction(
    unit_text: str,
    start: int,
    end: int,
    category: str,
    regions: frozenset[str] = frozenset(),
) -> tuple[int, int] | None:
    """Return a narrowed ``(start, end)`` for a REDACT span, or None if empty.

    ``unit_text`` is the authority on what sits at the offsets; the model's own
    quote is never consulted here. Offsets are clamped, so a span that arrives
    out of range narrows to nothing rather than raising.

    Three passes, in this order:

    1. edge punctuation and whitespace;
    2. leading prepositions ("με", "και", "υπ'") and — except in a name
       category — structural cues ("Α.Φ.Μ.", "Τράπεζα", "κο") with their
       separators, repeatedly, since they stack;
    3. a trailing "/YYYY" or "/DD-MM-YYYY", for reference categories and for a
       notice number identified by the cue in front of it;
    4. a trailing administrative REGION from ``regions``.

    Step 2 runs after step 1 so that «Α.Φ.Μ. 037173570» reaches the cue matcher
    with its opening quote already gone, and step 1 runs again after it to clear
    the separator's leftovers.

    STEP 4 IS THE REGION CONVENTION, held for spans the rules did not draw. The
    address detectors already leave the region outside their capture — the gold
    blanks the municipality and keeps the region, because a region names an area
    of millions and identifies nobody — but that only governs what THEY propose.
    A span pass 2 drew for itself obeyed no such rule, and ΣΚΟΥΛΑ published
    "κατοίκου .................." where the gold keeps "Αττικής", because the
    model quoted "Χαλανδρίου Αττικής" as one span and its answer outranks the
    narrower rule span underneath.

    Applied whatever the category says, and that is deliberate: the reason a
    region may stay visible has nothing to do with what the span was called. The
    cost is that a private name ENDING in a region — a company trading as
    "… Αττικής" — gives that word back; the word is public geography either way.
    """
    start = max(0, min(len(unit_text), int(start)))
    end = max(0, min(len(unit_text), int(end)))
    if start >= end:
        return None

    text = unit_text[start:end]

    # 1. edges
    stripped = text.lstrip(_EDGE_CHARS)
    start += len(text) - len(stripped)
    text = stripped.rstrip(_EDGE_CHARS)
    end = start + len(text)
    if not text:
        return None

    # 2. leading prepositions and structural cues, until neither matches.
    #
    # ITERATIVE because they stack: "με Α.Φ.Μ. 037173570" is a preposition then
    # a label, and one pass would leave whichever came second. Bounded so a
    # pattern that can match empty cannot spin.
    is_name = category in _NAME_CATEGORIES
    for _ in range(4):
        match = _LEADING_PREPOSITION_RE.match(text)
        if match is not None and is_name:
            # Capitalised here means the word is not doing a preposition's job;
            # it is the first word of the name this span exists to blank.
            word = match.group(0).strip()
            if word and word != word.lower():
                match = None
        if match is None and not is_name:
            match = _TRIM_CUE_RE.match(text)
        if match is None or match.end() == 0:
            break
        if match.end() >= len(text):
            # The span is nothing BUT a cue. There is no value in it to redact,
            # so it claims nothing rather than blanking a label.
            return None
        start += match.end()
        text = text[match.end():]
        stripped = text.lstrip(_EDGE_CHARS)
        start += len(text) - len(stripped)
        text = stripped
        end = start + len(text)
        if not text:
            return None

    # 3. the date or year a reference number keeps.
    #
    # PROPERTY_ID is not in the category list and must not be — "Α.Χ.Κ. 76/19062"
    # is a serial, and its "/19062" is not a year to be spared. But ONE member of
    # that category, the notice number, follows the reference convention exactly:
    # the gold publishes "αριθμό ειδοποίησης ………/15-03-2026". The category
    # cannot tell them apart, so the cue in front of the span does — read after
    # step 2, which has already moved `start` past that cue if the model quoted
    # it. Fixing this only in the detector would not help: a pass-2 span that
    # quotes the whole reference owns the date at its own tier.
    keeps_suffix = category in _YEAR_SUFFIX_CATEGORIES or (
        category == "PROPERTY_ID"
        and _NOTICE_CUE_BEFORE_RE.search(unit_text[:start]) is not None
    )
    if keeps_suffix:
        for tail_re in (_TRAILING_REFERENCE_DATE_RE, _TRAILING_YEAR_RE):
            tail = tail_re.search(text)
            if tail and tail.start() > 0:
                end = start + tail.start()
                text = text[: tail.start()]

    # 4. the administrative region a span may not take with the municipality.
    give_back = _trailing_region(text, regions)
    if give_back:
        end -= give_back
        text = text[: len(text) - give_back]

    if start >= end:
        return None
    return start, end


__all__ = ["narrow_redaction"]
