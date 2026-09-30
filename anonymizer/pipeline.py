from __future__ import annotations

import logging
import time
from collections import Counter
from typing import Any

from anonymizer.config import FileConfig, PolicySettings, RuntimeConfig
from anonymizer.deadline import RunContext
from anonymizer.detectors import detect_all
from anonymizer.docx_engine import (
    parse_docx,
    validate_docx_package,
    write_redacted_docx,
)
from anonymizer.errors import (
    AnonymizerError,
    DocumentProcessingError,
    ResidualPIIError,
    ResourceLimitExceededError,
)
from anonymizer.injection_screen import screen_document
from anonymizer.word_formats import (
    needs_normalization,
    normalize_to_docx,
    sniff_format,
)
from anonymizer.llm.detector import run_llm_detection, run_pass2_remediation
from anonymizer.llm.prompts import PROMPTS_SHA256
from anonymizer.llm.usage import UsageRecorder
from anonymizer.models import (
    AnonymizeResult,
    DocumentData,
    RedactionPlan,
    Span,
    UnresolvedFinding,
)
from anonymizer.postcheck import PostcheckFinding, scan_redacted_docx_bytes
from anonymizer.resolver import is_hard_preserve, resolve_redactions
from anonymizer.summary import build_summary

logger = logging.getLogger(__name__)

_FINAL_ACTIONS = {"REDACT", "PRESERVE"}


def _carried_hard_preserves(
    source: DocumentData,
    redacted: DocumentData,
    spans: list[Span],
    policy: PolicySettings,
) -> list[Span]:
    """The hard preserves the FIRST resolve established, for the second one.

    A hard preserve is a policy DECISION about this text: pass 2 is never handed
    one to adjudicate and could not outrank one if it were. That is as true of
    the post-redaction re-ask as of the first adjudication, so the decisions
    travel with the document — and travelling is all they do. They are the ones
    the rule engine made ON THE SOURCE, carried over unchanged.

    WHAT THIS DELIBERATELY DOES NOT DO IS RUN THE RULE ENGINE AGAIN. Detecting
    on the redacted text does not retain an authority, it INVENTS one, because
    the mask is itself evidence to a rule that reads context:

        Με δικαιούχο τον ΙΒΑΝ ΠΕΤΡΟΦ.      ->  no label here; "ΙΒΑΝ" is a name
        Με δικαιούχο τον ΙΒΑΝ .........    ->  a label followed by a placeholder

    One redaction away, a surviving first name reads as the IBAN label, is
    hard-preserved at a tier no pass-2 answer can reach, and becomes
    unredactable — by the very stage whose job is to redact what survived. A
    preserve that was not established before the document was masked is not
    established.

    CARRIED ONLY WHEN THE COORDINATES STILL MEAN THE SAME THING. Redaction is
    1:1 character substitution, so offsets normally survive it exactly — but
    ``clean_sensitive_parts`` also drops tracked-change, hidden and comment
    content, which can resize or remove a unit. So the geometry is checked
    rather than assumed: same unit ids, same lengths, or nothing is carried and
    the remediation resolve runs on pass-2 spans alone. Failing that check costs
    the labels their protection, which is the safe direction — the alternative
    is writing a preserve at an offset that now holds something else.
    """
    source_lengths = {
        unit.unit_id: len(unit.normalized_text) for unit in source.text_units
    }
    unchanged = len(source_lengths) == len(redacted.text_units) and all(
        source_lengths.get(unit.unit_id) == len(unit.normalized_text)
        for unit in redacted.text_units
    )
    if not unchanged:
        logger.info(
            "postcheck_remediation: the redacted parse does not match the source "
            "unit for unit, so no hard preserve was carried into the second resolve"
        )
        return []
    return [span for span in spans if is_hard_preserve(span, policy)]


def _residual_review_spans(findings: list[PostcheckFinding]) -> list[Span]:
    """The audit's textual findings, as located proposals for the pass-2 queue.

    A residual is evidence WITH coordinates and WITHOUT a decision, which is
    precisely what a deterministic REVIEW hint already is — so it enters the
    queue as one, and the pass-2 machinery needs no special case to hold it. The
    coordinates are the scan's own, copied verbatim: nothing here searches the
    document for the matched string, so two identical values in two places stay
    two questions.

    ``confidence`` is 1.0 because the audit is certain it MATCHED; it says
    nothing whatever about whether the text should go, which is the question
    REVIEW asks and pass 2 answers. ``origin`` stays deterministic — these are
    not adjudications — and it costs nothing, because a REVIEW span is a queue
    entry and never reaches the resolver.
    """
    spans: list[Span] = []
    for finding in findings:
        residual = finding.span
        if residual is None:  # pragma: no cover - callers filter on this
            continue
        spans.append(
            Span(
                unit_id=residual.unit_id,
                start=residual.start,
                end=residual.end,
                text=residual.text,
                category=residual.category,
                detector=f"postcheck_{finding.kind}",
                confidence=1.0,
                action="REVIEW",
                reason=f"post-redaction scan: {finding.kind}",
            )
        )
    return spans


def anonymize_document(
    docx_bytes: bytes,
    *,
    config: RuntimeConfig,
    files: FileConfig,
    client: Any,
    document_id: str | None = None,
    ctx: RunContext | None = None,
) -> AnonymizeResult:
    """Transport-neutral anonymization pipeline over raw DOCX bytes.

    Runs normalize -> parse -> screen -> detect -> llm -> resolve -> apply ->
    scan, timing each stage,
    and returns the redacted bytes plus a counts-only summary.

    A result may come back NEEDING REVIEW: pass 2 can leave individual findings
    unresolved after its one corrective retry, and those are carried on
    ``result.unresolved`` rather than guessed at. Nothing is written for them —
    the text is left exactly as it was, covered by whatever ordinary
    deterministic evidence reaches it — and ``result.needs_review`` says so.
    That leniency is for individual findings only: a chunk pass 2 never managed
    to read still fails the document, as does a HIGH postcheck finding that
    names no slice of text (see below — one that names a slice is re-asked
    rather than fatal).

    The scan is MANDATORY and there is no flag to skip it: every caller (CLI and
    API alike) gets output that has been audited for residual personal
    information. It runs EXACTLY ONCE per document, and what happens to a
    finding depends on whether it points at document text:

    * a finding that names a slice — a surviving AFM, email, phone, name,
      property identifier — is a QUESTION, and the stage that answers questions
      about document text is pass 2. It is asked again, against the redacted
      document with the whole chunk in view, and its answer goes through the
      ordinary resolver and a second apply. That is the remediation path:
      ``scan -> pass 2 -> resolver -> apply -> return``;
    * a finding that names no slice is unchanged. A HIGH one — a surviving
      macro, tracked change, comment part, a placeholder or ellipsis run left by
      our own write path — still raises :class:`ResidualPIIError` and no
      document is returned. Nothing there is a decision a model could make, and
      the over-redaction reports cannot be repaired at all, because the text
      they are about is already gone.

    THE OUTPUT OF THE REMEDIATION IS NOT SCANNED AGAIN. There is one audit per
    document and no loop: the alternative is either an iteration with no proof
    it terminates, or a second gate that can fail a document after it has just
    been corrected. ``result.postcheck`` therefore describes the document as it
    was BEFORE the remediation, and ``result.warnings`` says so.

    Catches nothing; every callee exception propagates. The exceptions this
    function itself raises are the invariant-1 RuntimeError below,
    DocumentProcessingError and ResidualPIIError.
    """
    # The budget and the correlation ids for this document. A caller that has
    # its own — the HTTP endpoint, which starts the clock the moment a request
    # is authenticated — passes one in; anyone else gets a fresh one, so no
    # entry point can process a document without a deadline by forgetting to
    # ask for one.
    if ctx is None:
        ctx = RunContext.start(
            config.document_deadline_s, document_id=document_id
        )
    document_id = ctx.document_id
    deadline = ctx.deadline
    limits = config.limits

    timings: dict[str, float] = {}
    t_total = time.perf_counter()
    # This document's own token ledger. Created here and passed down, so
    # concurrent chunks share it while concurrent DOCUMENTS never can.
    usage = UsageRecorder()

    # Stage: normalize — what arrived, and turning it into a plain document.
    #
    # Everything downstream assumes a .docx: one main content type, no macro
    # payload. This is where a .docm, .dotx or .dotm becomes one, and where a
    # file that is not an OOXML Word document at all is refused. The ZIP
    # preflight runs inside the sniff, so nothing below has read an
    # unbounded archive.
    deadline.check("normalize")
    t0 = time.perf_counter()
    incoming = sniff_format(docx_bytes, limits)
    normalized = needs_normalization(incoming)
    if normalized:
        docx_bytes = normalize_to_docx(docx_bytes, incoming, limits)
    timings["normalize"] = time.perf_counter() - t0
    logger.info(
        "stage=normalize %s detected=%s normalized=%s elapsed=%.3fs",
        ctx.tag(),
        incoming.kind,
        normalized,
        timings["normalize"],
    )

    # Stage: parse
    deadline.check("parse")
    t0 = time.perf_counter()
    package = validate_docx_package(docx_bytes, limits=limits)
    document = parse_docx(docx_bytes, document_id, package=package, limits=limits)
    text_chars = sum(len(unit.normalized_text) for unit in document.text_units)
    if text_chars > limits.max_text_chars:
        # The ZIP limits bound what was decompressed; this bounds what is
        # actually processed, which is what the detectors and the LLM stage
        # are paid for.
        raise ResourceLimitExceededError(
            f"document holds {text_chars} characters of text; the limit is "
            f"{limits.max_text_chars}",
            code="TEXT_TOO_LARGE",
        )
    timings["parse"] = time.perf_counter() - t0
    logger.info(
        "stage=parse %s units=%d chars=%d elapsed=%.3fs",
        ctx.tag(),
        len(document.text_units),
        text_chars,
        timings["parse"],
    )

    # Stage: screen — deterministic prompt-injection check, before ANY LLM
    # call. The document is data, not instructions, and this is where a
    # document that tries to be instructions is refused.
    deadline.check("screen")
    t0 = time.perf_counter()
    screen_document(document, files.injection_rules)
    timings["screen"] = time.perf_counter() - t0
    logger.info(
        "stage=screen %s rules=%d elapsed=%.3fs",
        ctx.tag(),
        len(files.injection_rules),
        timings["screen"],
    )

    # Stage: detect
    deadline.check("detect")
    t0 = time.perf_counter()
    detection = detect_all(document, files.rules)
    timings["detect"] = time.perf_counter() - t0
    logger.info(
        "stage=detect %s candidate_spans=%d review_hints=%d elapsed=%.3fs",
        ctx.tag(),
        len(detection.resolver_spans),
        len(detection.review_hints),
        timings["detect"],
    )

    # Stage: llm
    deadline.check("llm")
    t0 = time.perf_counter()
    llm_result = run_llm_detection(
        document,
        deterministic_spans=detection.resolver_spans,
        review_hints=detection.review_hints,
        client=client,
        cfg=config,
        policy=files.policy,
        usage=usage,
        ctx=ctx,
        # The gold blanks the municipality and keeps the region. The detectors
        # already exclude it from their own captures; handing the allowlist down
        # is what holds the same line for a span pass 2 drew for itself.
        regions=files.rules.regions,
    )
    llm_spans = llm_result.spans
    timings["llm"] = time.perf_counter() - t0
    llm_usage = usage.snapshot()
    logger.info(
        "stage=llm %s llm_spans=%d calls=%d tokens_in=%d tokens_out=%d "
        "tokens_total=%d truncated=%d pass1_success=%d pass1_parse_failure=%d "
        "pass1_output_truncated=%d pass2_skipped=%d pass2_executed=%d "
        "pass2_failed=%d pass2_retried=%d pass2_incomplete_attempts=%d "
        "unresolved=%d elapsed=%.3fs",
        ctx.tag(),
        len(llm_spans),
        llm_usage.calls,
        llm_usage.input_tokens,
        llm_usage.output_tokens,
        llm_usage.total_tokens,
        len(llm_usage.truncated),
        llm_usage.pass1_success,
        llm_usage.pass1_parse_failure,
        llm_usage.pass1_output_truncated,
        llm_usage.pass2_skipped,
        llm_usage.pass2_executed,
        llm_usage.pass2_failed,
        llm_usage.pass2_retried,
        llm_usage.pass2_incomplete_attempts,
        len(llm_result.unresolved),
        timings["llm"],
    )
    if llm_usage.pass1_degraded:
        # Never fatal, and therefore easy to miss: pass 1 losing its output
        # costs recommendations, not coverage, because pass 2 reads the whole
        # chunk itself. Said once per document so a run where it happens
        # constantly cannot look like a run where it never does.
        logger.warning(
            "%s pass 1 was unusable on %d of %d chunk(s) "
            "(%d unparseable, %d truncated); pass 2 read the full text of every "
            "one of them, with an empty queue where the rules also found nothing",
            ctx.tag(),
            llm_usage.pass1_degraded,
            llm_usage.pass1_success + llm_usage.pass1_degraded,
            llm_usage.pass1_parse_failure,
            llm_usage.pass1_output_truncated,
        )
    for call in llm_usage.truncated:
        # The difference between "the model omitted a decision" and "the model
        # ran out of room to answer". Counts and positions only, no text.
        logger.warning(
            "%s chunk=%d pass=%d (%s attempt) stopped at the output "
            "limit: %d of %d completion tokens — raise ANON_MAX_COMPLETION_TOKENS "
            "if pass 2 also came back incomplete",
            ctx.tag(), call.chunk_number, call.pass_number, call.attempt,
            call.output_tokens, call.limit,
        )

    if llm_result.unresolved:
        # Never fatal, by design: the alternative to a person settling these is
        # a machine inventing answers for them. Said once per document, with
        # counts and kinds only, so a run where it happens constantly cannot
        # look like a run where it never does.
        kinds = Counter(finding.kind for finding in llm_result.unresolved)
        logger.warning(
            "%s needs_review=true unresolved_count=%d by_kind=%s — produced from validated evidence only; a person must settle these",
            ctx.tag(),
            len(llm_result.unresolved),
            dict(kinds),
        )

    # Stage: resolve — both authorities are handed to the resolver together, each
    # span declaring which it is through `Span.origin`, and the ladder in
    # anonymizer.resolver arbitrates:
    #
    #     hard policy (deterministic) > pass-2 decision > ordinary deterministic
    #
    # so a pass-2 answer settles the ordinary rule spans it was asked about,
    # while the rule spans it did not cover stay as fallback evidence. Nothing is
    # filtered here on the way in: dropping the adjudicated rule spans would let
    # a chunk that never reached pass 2 lose its detections silently, and the
    # ladder does not need the help.
    #
    # review_hints are LLM input only and never reach the resolver; hard
    # preserves take the opposite route, skipping the LLM's decision queue and
    # going straight to the resolver that honors them.
    deadline.check("resolve")
    t0 = time.perf_counter()
    plan = resolve_redactions(document, llm_spans + detection.resolver_spans, files.policy)
    timings["resolve"] = time.perf_counter() - t0
    if any(span.action not in _FINAL_ACTIONS for span in plan.spans):
        raise RuntimeError("plan contains a non-final action — programming bug")
    logger.info(
        "stage=resolve %s plan_spans=%d elapsed=%.3fs",
        ctx.tag(),
        len(plan.spans),
        timings["resolve"],
    )

    # Stage: apply
    deadline.check("apply")
    t0 = time.perf_counter()
    redacted = write_redacted_docx(
        docx_bytes, document, plan, package=package, limits=limits
    )
    try:
        # Kept, not discarded: the remediation path below re-parses these bytes,
        # and re-validating them a third time would cost a strict pass over a
        # package this line has just approved.
        redacted_package = validate_docx_package(redacted, limits=limits)
    except AnonymizerError as exc:
        # Valid input, invalid output: that is ours, not the caller's, and
        # saying it with a 4xx would send them to inspect a file that is
        # fine.
        raise DocumentProcessingError(
            "the redacted document is not a valid DOCX package",
            code="INVALID_OUTPUT_PACKAGE",
        ) from exc
    timings["apply"] = time.perf_counter() - t0
    logger.info(
        "stage=apply %s redacted_bytes=%d elapsed=%.3fs",
        ctx.tag(),
        len(redacted),
        timings["apply"],
    )

    # Stage: scan — the mandatory post-redaction audit of the produced file.
    # Runs on the bytes that are about to be handed back, after
    # write_redacted_docx and before any caller can save or return them.
    deadline.check("scan")
    t0 = time.perf_counter()
    # `document` is the PARSED INPUT. Handing it over is what lets the scan
    # report over-redaction as well as leaks: it can compare how many
    # structural labels went in against how many came out.
    postcheck = scan_redacted_docx_bytes(redacted, files, document)
    timings["scan"] = time.perf_counter() - t0
    high = postcheck.by_severity.get("HIGH", 0)
    logger.info(
        "stage=scan %s findings=%d high=%d by_kind=%s elapsed=%.3fs",
        ctx.tag(),
        postcheck.findings_total,
        high,
        postcheck.by_kind,
        timings["scan"],
    )
    # Fail closed on what nothing downstream can settle. The document is not
    # returned and not saved: a surviving macro, a tracked change, a comment
    # part or residue of our own write path has to be looked at by a person, and
    # none of them is a question about document text. Locations and kinds only —
    # the finding details are not echoed, so the error text carries no document
    # text.
    blocking = postcheck.blocking
    if blocking:
        locations = ", ".join(f"{f.kind}@{f.location}" for f in blocking)
        raise ResidualPIIError(
            f"post-redaction scan found {len(blocking)} HIGH-severity finding(s) "
            f"that no further redaction can settle; the document needs manual "
            f"review ({locations})"
        )

    # Stage: remediate — scan -> pass 2 -> resolver -> apply -> return.
    #
    # Everything the scan found that names a slice of text is put back to the
    # pass that decides about text. It is asked ONCE, and whatever it answers is
    # what the document goes out with: a REDACT is applied, a PRESERVE is
    # respected, and anything pass 2 still could not settle after its own
    # corrective retry is carried to the caller as an unresolved finding rather
    # than guessed at. NOTHING RE-SCANS THE RESULT — see the docstring.
    residual_findings = postcheck.remediable
    remediation_plan: RedactionPlan | None = None
    remediation_unresolved: tuple[UnresolvedFinding, ...] = ()
    applied = 0
    if residual_findings:
        deadline.check("remediate")
        t0 = time.perf_counter()
        # THE DOCUMENT THE REMEDIATION WORKS FROM IS THE ONE JUST PRODUCED,
        # re-parsed from its own bytes. The coordinates the scan reported are
        # coordinates in that parse, the redactions already written are already
        # in it, and none of them can be taken back — the glyphs replaced the
        # characters. Nothing restarts from the source DOCX.
        redacted_document = parse_docx(
            redacted, document_id, package=redacted_package, limits=limits
        )
        remediation = run_pass2_remediation(
            redacted_document,
            _residual_review_spans(residual_findings),
            client=client,
            cfg=config,
            usage=usage,
            ctx=ctx,
            regions=files.rules.regions,
        )
        remediation_unresolved = remediation.unresolved
        # The re-ask is over; writing its answer is a NEW stage, and no new
        # stage begins on a document that has run out of time. Checked here
        # rather than waived: a late result is discarded by the HTTP endpoint
        # anyway, so keeping one would buy nothing and would make the CLI and
        # the API disagree about the same document.
        deadline.check("remediate apply")
        if remediation.spans:
            # THE ORDINARY RESOLVER, not a shortcut around it. The spans carry
            # origin="llm_pass2", so they rank exactly where a pass-2 decision
            # ranks and can no more claim a hard-policy tier here than in the
            # first resolve.
            #
            # THE HARD PRESERVES COME WITH THEM, and they have to. Leaving
            # them out silently dropped a guarantee the first resolve gives: a
            # remediation REDACT in a NAME category quoting "κάτοικος
            # Χαλανδρίου" would blank the label, because span_trim deliberately
            # trims no cue from a name ("Ιβάν" is a first name and "ΙΒΑΝ" a
            # label) and says itself that it is not the primary defence. The
            # FIELD_LABEL span is, per character, here as there.
            #
            # They are CARRIED, not re-derived — see ``_carried_hard_preserves``
            # for why detecting them again on the masked text would invent
            # authority rather than retain it.
            #
            # The ordinary rule spans stay out: re-running them over the output
            # would resurrect recommendations pass 2 has already settled once,
            # and nothing in the redacted text says which of them were settled
            # which way. So the deterministic layer can only ever CONSTRAIN what
            # a remediation blanks, never widen it.
            remediation_plan = resolve_redactions(
                redacted_document,
                remediation.spans + _carried_hard_preserves(
                    document, redacted_document,
                    detection.resolver_spans, files.policy,
                ),
                files.policy,
            )
            if any(span.action not in _FINAL_ACTIONS for span in remediation_plan.spans):
                raise RuntimeError("plan contains a non-final action — programming bug")
            applied = sum(
                1 for span in remediation_plan.spans if span.action == "REDACT"
            )
            if applied:
                # Only when there is something to write. A queue answered
                # entirely with PRESERVE has decided that the document is
                # already correct, and rewriting the package to say so would
                # put a second serialisation between the audited bytes and the
                # caller for no change at all.
                #
                redacted = write_redacted_docx(
                    redacted, redacted_document, remediation_plan,
                    package=redacted_package, limits=limits,
                )
                try:
                    validate_docx_package(redacted, limits=limits)
                except AnonymizerError as exc:
                    raise DocumentProcessingError(
                        "the remediated document is not a valid DOCX package",
                        code="INVALID_OUTPUT_PACKAGE",
                    ) from exc
        timings["remediate"] = time.perf_counter() - t0
        # Counts and transient ids only. The residual text is what the whole
        # stage is about and it is in none of these fields, nor in any other
        # line this path writes.
        logger.info(
            "stage=remediate %s postcheck_remediation=true candidate_count=%d "
            "candidate_ids=%s pass2_calls=%d remediation_redactions=%d "
            "unresolved=%d elapsed=%.3fs",
            ctx.tag(),
            len(remediation.candidate_ids),
            list(remediation.candidate_ids),
            remediation.pass2_calls,
            applied,
            len(remediation_unresolved),
            timings["remediate"],
        )

    # Non-blocking findings travel with the result so a caller can surface them.
    warnings = list(plan.warnings)
    unresolved = llm_result.unresolved + remediation_unresolved
    if remediation_plan is not None:
        warnings.extend(remediation_plan.warnings)
    if unresolved:
        warnings.append(
            f"LLM pass 2 left {len(unresolved)} finding(s) unresolved "
            f"after its corrective retry; this document needs human review"
        )
    if postcheck.findings_total:
        warnings.append(
            f"post-redaction scan: {postcheck.findings_total} "
            f"finding(s) {postcheck.by_kind}"
        )
    if residual_findings:
        warnings.append(
            f"post-redaction remediation: {len(residual_findings)} residual "
            f"finding(s) were re-adjudicated by LLM pass 2 and {applied} further "
            f"redaction(s) applied; the scan counts above describe this document "
            f"BEFORE that correction, and it was not scanned again"
        )

    timings["total"] = time.perf_counter() - t_total

    # Reproducibility stamp: enough to answer "which rules, prompts, model and
    # package produced this published document?" after the fact.
    try:
        from importlib.metadata import version

        package_version = version("ded-anonymizer")
    except Exception:
        package_version = "unknown"
    provenance = {
        "provider": config.provider,
        "model": config.model_handle,
        "config_sha256": files.config_sha256,
        "prompts_sha256": PROMPTS_SHA256,
        "package_version": package_version,
    }

    # Every decision written into this document, counted together. The two
    # plans address different parses of the same file, which is exactly why they
    # are summed rather than merged: a summary is counts, not geometry.
    decided = plan if remediation_plan is None else RedactionPlan(
        document_id=plan.document_id,
        spans=plan.spans + remediation_plan.spans,
        warnings=plan.warnings + remediation_plan.warnings,
    )

    return AnonymizeResult(
        document_id=document_id,
        redacted_docx=redacted,
        summary=build_summary(decided),
        warnings=warnings,
        model=config.model_handle,
        timings=timings,
        postcheck=postcheck,
        # THE WHOLE LEDGER, not the snapshot the llm stage logged. The
        # remediation's pass-2 calls are booked against this same recorder, so
        # taking the snapshot here is what makes the number a caller reads the
        # number of calls the document actually cost.
        llm_usage=usage.snapshot(),
        provenance=provenance,
        unresolved=unresolved,
    )
