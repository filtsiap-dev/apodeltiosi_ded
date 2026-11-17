package dev.filtsiap.ded.anonymizer;

import dev.filtsiap.ded.anonymizer.llm.LlmClient;
import dev.filtsiap.ded.anonymizer.llm.LlmDetector;
import dev.filtsiap.ded.anonymizer.llm.LlmUsage;
import dev.filtsiap.ded.anonymizer.llm.Prompts;
import dev.filtsiap.ded.anonymizer.pycompat.PyFloat;
import dev.filtsiap.ded.anonymizer.pycompat.PyRepr;
import dev.filtsiap.ded.anonymizer.pycompat.PyStr;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Transport-neutral pipeline: parse, screen, detect, LLM, resolve, apply, scan, remediate (port of
 * {@code pipeline.py}).
 *
 * <p>The post-redaction scan is mandatory, with no flag to skip it. A finding that names a slice
 * of text (a surviving AFM, email, phone, name, company, bank, street, property identifier, or a
 * value redacted elsewhere in the document) is a question, put back to LLM pass 2 ONCE against the
 * redacted document; its answer goes through the ordinary resolver and a second apply. A HIGH
 * finding that names no slice (a macro, a tracked change, our own placeholder residue) raises
 * {@link ResidualPIIError}, and no document is returned. When that second apply rewrote the bytes
 * they are scanned once more, DETERMINISTICALLY: the final scan calls no model and starts no
 * remediation, so there is no scan/LLM loop. {@code result.postcheck()} describes the returned
 * bytes. What pass 2 cannot settle, and a HIGH value the final scan still sees, comes back as
 * unresolved: the result is then {@code needs-review}. Nothing is caught here; every callee
 * exception propagates.
 *
 * <p>THE POSTCHECK OUTCOME POLICY (a deliberate change from v2, where a PRESERVE closed any
 * finding): a HIGH textual finding is settled only by being REDACTED. Pass 2 may still answer
 * PRESERVE, and the document carries that answer, but the finding then stays in front of a person
 * ({@code HIGH_RESIDUAL_PRESERVED}, so the result is {@code needs-review}); so does a HIGH value a
 * REDACT answer did not cover whole. A MEDIUM finding is settled by pass 2's answer either way.
 * This is outcome policy, applied after the second resolve; the resolver's tiers are untouched.
 *
 * <p>Every stage runs inside the document's {@link RunContext}: the deadline is checked at each
 * stage boundary, so no new stage begins on a document that has run out of time, and every
 * package read is bounded by {@link RuntimeConfig#limits()}.
 */
public final class Pipeline {

    private static final Logger LOG = LoggerFactory.getLogger("anonymizer.pipeline");

    private Pipeline() {
    }

    /**
     * Runs the pipeline inside {@code ctx}, whose budget the caller has already started (the API
     * starts it before reading the upload; the CLI per document, with
     * {@code RunContext.start(config.documentDeadlineS())}).
     */
    public static AnonymizeResult anonymizeDocument(byte[] docxBytes, RuntimeConfig config, FileConfig files,
                                                    LlmClient client, RunContext ctx) {
        String documentId = ctx.documentId();
        String tag = ctx.tag();
        Deadline deadline = ctx.deadline();
        ResourceLimits limits = config.limits();
        Map<String, Double> timings = new LinkedHashMap<>();
        long tTotal = System.nanoTime();

        deadline.check("parse");
        long t0 = System.nanoTime();
        DocumentData document = admitted(docxBytes, limits, ctx,
                () -> DocxEngine.parseDocx(docxBytes, documentId, limits)); // parseDocx validates first
        long textChars = document.textUnits().stream().mapToLong(u -> PyStr.len(u.normalizedText())).sum();
        if (textChars > limits.maxTextChars()) {
            // The ZIP limits bound what was decompressed; this bounds what is actually processed,
            // which is what the detectors and the LLM stage are paid for.
            throw new ResourceLimitExceededError("document holds " + textChars + " characters of text; the limit is "
                    + limits.maxTextChars(), "TEXT_TOO_LARGE");
        }
        timings.put("parse", seconds(t0));
        LOG.info("stage=parse {} units={} chars={} elapsed={}s", tag, document.textUnits().size(), textChars,
                fixed3(timings.get("parse")));

        // Stage: screen. A deterministic prompt-injection check, before ANY LLM call: the document
        // is data, not instructions, and a document that tries to be instructions is refused here.
        deadline.check("screen");
        t0 = System.nanoTime();
        InjectionScreen.screenDocument(document, files.injectionRules());
        timings.put("screen", seconds(t0));
        LOG.info("stage=screen {} rules={} elapsed={}s", tag, files.injectionRules().size(),
                fixed3(timings.get("screen")));

        deadline.check("detect");
        t0 = System.nanoTime();
        Detectors.DetectionResult detection = Detectors.detectAll(document, files.rules());
        timings.put("detect", seconds(t0));
        LOG.info("stage=detect {} candidate_spans={} review_hints={} elapsed={}s", tag,
                detection.resolverSpans().size(), detection.reviewHints().size(), fixed3(timings.get("detect")));

        deadline.check("llm");
        t0 = System.nanoTime();
        // The gold blanks the municipality and keeps the region; handing the allowlist down holds that
        // line for a span pass 2 drew for itself, too.
        LlmDetector.Result llm = LlmDetector.runLlmDetection(document, detection.resolverSpans(),
                detection.reviewHints(), client, config, files.policy(), files.rules().regions(), ctx);
        List<Span> llmSpans = llm.spans();
        long llmNanos = System.nanoTime() - t0;
        timings.put("llm", seconds(t0));
        LlmUsage stageUsage = ctx.usage().snapshot();
        LOG.info("stage=llm {} llm_spans={} calls={} tokens_in={} tokens_out={} tokens_total={} truncated={} "
                        + "pass1_success={} pass1_parse_failure={} pass1_output_truncated={} pass2_skipped={} "
                        + "pass2_executed={} pass2_failed={} pass2_retried={} pass2_incomplete_attempts={} unresolved={} "
                        + "elapsed={}s", tag, llmSpans.size(), stageUsage.calls(), stageUsage.inputTokens(),
                stageUsage.outputTokens(), stageUsage.totalTokens(), stageUsage.truncated().size(),
                stageUsage.pass1Success(), stageUsage.pass1ParseFailure(), stageUsage.pass1OutputTruncated(),
                stageUsage.pass2Skipped(), stageUsage.pass2Executed(), stageUsage.pass2Failed(),
                stageUsage.pass2Retried(), stageUsage.pass2IncompleteAttempts(), llm.unresolved().size(),
                fixed3(timings.get("llm")));
        if (stageUsage.pass1Degraded() > 0) {
            // Never fatal, by design, and therefore easy to miss: those chunks had no discovery, and pass 2
            // only adjudicated what the rules proposed there.
            LOG.warn("{} pass 1 coverage is incomplete on {} of {} chunk(s) ({} malformed, {} truncated, {} provider "
                    + "failed); those chunks require human review", tag,
                    stageUsage.pass1Degraded(), stageUsage.pass1Success() + stageUsage.pass1Degraded(),
                    stageUsage.pass1ParseFailure(), stageUsage.pass1OutputTruncated(), stageUsage.pass1ProviderFailure());
        }
        if (!llm.unresolved().isEmpty()) {
            // Never fatal: the alternative to a person settling these is a machine inventing answers.
            // Counts and kinds only.
            Map<String, Integer> kinds = new LinkedHashMap<>();
            llm.unresolved().forEach(f -> kinds.merge(f.kind().wire(), 1, Integer::sum));
            boolean fallbackUsed = llm.unresolved().stream()
                    .anyMatch(f -> f.kind() == UnresolvedFinding.Kind.PASS2_UNAVAILABLE);
            LOG.warn("{} needs_review=true fallback_used={} unresolved_count={} by_kind={} — produced from validated "
                    + "evidence only; a person must settle these", tag, fallbackUsed, llm.unresolved().size(),
                    PyRepr.repr(kinds));
        }

        // Every authority goes to the resolver together, each span declaring itself through
        // Span.origin, and the ladder arbitrates: hard policy (deterministic) > pass-2 decision >
        // pass-1 REDACT > ordinary deterministic > pass-1 PRESERVE. Nothing is filtered on the way in,
        // so rule spans no LLM span covers stay as fallback evidence. Review hints are LLM input only
        // and never reach it.
        deadline.check("resolve");
        t0 = System.nanoTime();
        List<Span> candidates = new ArrayList<>(llmSpans);
        candidates.addAll(detection.resolverSpans());
        RedactionPlan plan = Resolver.resolveRedactions(document, candidates, files.policy());
        timings.put("resolve", seconds(t0));
        requireFinal(plan);
        LOG.info("stage=resolve {} plan_spans={} elapsed={}s", tag, plan.spans().size(),
                fixed3(timings.get("resolve")));

        deadline.check("apply");
        t0 = System.nanoTime();
        DocxEngine.WriteResult firstWrite = admitted(docxBytes, limits, ctx,
                () -> DocxEngine.writeRedactedDocxWithTrace(docxBytes, document, plan, limits));
        byte[] redacted = firstWrite.bytes();
        SourceCorrespondence finalCorrespondence = firstWrite.correspondence();
        SourceCorrespondence secondCorrespondence = null;
        byte[] firstRedacted = redacted;
        timings.put("apply", seconds(t0));
        LOG.info("stage=apply {} redacted_bytes={} elapsed={}s", tag, redacted.length,
                fixed3(timings.get("apply")));

        // Mandatory audit of exactly the bytes about to be handed back, ONCE. `document` is the
        // parsed input, which lets the scan report over-redaction as well as leaks.
        deadline.check("scan");
        t0 = System.nanoTime();
        PostcheckSummary postcheck = admitted(docxBytes, limits, ctx,
                () -> Postcheck.scanRedactedDocxBytes(firstRedacted, files, document, plan, limits,
                        firstWrite.correspondence()));
        timings.put("scan", seconds(t0));
        int high = postcheck.bySeverity().getOrDefault("HIGH", 0);
        LOG.info("stage=scan {} findings={} high={} by_kind={} elapsed={}s", tag,
                postcheck.findingsTotal(), high, PyRepr.repr(postcheck.byKind()), fixed3(timings.get("scan")));

        // Fail closed on what nothing downstream can settle: a surviving macro, tracked change,
        // comment part or residue of our own write path is not a question about document text.
        // Kinds and locations only, never finding details or document text.
        List<PostcheckFinding> blocking = postcheck.blocking();
        if (!blocking.isEmpty()) {
            String locations = blocking.stream().map(f -> f.kind() + "@" + f.location())
                    .collect(Collectors.joining(", "));
            throw new ResidualPIIError("post-redaction scan found " + blocking.size() + " HIGH-severity finding(s) "
                    + "that no further redaction can settle; the document needs manual review (" + locations + ")");
        }

        // Stage: remediate. scan -> pass 2 -> resolver -> apply -> return. Everything the scan
        // found that names a slice of text is put back to the pass that decides about text, ONCE:
        // a REDACT is applied, a PRESERVE is written as pass 2 decided it (and, on a HIGH finding,
        // kept in front of a person: see the class comment), and what pass 2 still cannot settle
        // after its corrective retry is carried out as unresolved. A deterministic final scan checks
        // any second write; it never starts another remediation round.
        List<LlmDetector.Residual> residuals = residualQuestions(postcheck.findings());
        RedactionPlan remediationPlan = null;
        List<UnresolvedFinding> remediationUnresolved = List.of();
        int applied = 0;
        if (!residuals.isEmpty()) {
            deadline.check("remediate");
            t0 = System.nanoTime();
            // The document the remediation works from is the one just produced, re-parsed from its
            // own bytes: the scan's coordinates are coordinates in that parse, and the redactions
            // already written cannot be taken back. Nothing restarts from the source DOCX.
            DocumentData redactedDocument = firstWrite.document();
            // What the rules and pass 1 recommended, at coordinates that still mean the same places.
            List<LlmDetector.Evidence> evidence = llm.evidence().stream().flatMap(e ->
                    firstWrite.correspondence().translate(e.location()).stream().map(at ->
                            new LlmDetector.Evidence(at, e.sources(), e.action(), e.category()))).toList();
            // The hard decisions the first resolve established, carried once and used throughout: by the
            // remediation's queue (the same policy the first adjudication applied), by the second resolve,
            // and by the outcome rule's coverage check.
            List<Span> hardRedacts = firstWrite.correspondence().translateSpans(plan.spans().stream()
                    .filter(sp -> Resolver.isHardRedact(sp, files.policy())).toList(), true);
            List<Span> hardPreserves = firstWrite.correspondence().translateSpans(plan.spans().stream()
                    .filter(sp -> Resolver.isHardPreserve(sp, files.policy())).toList(), false);
            long remediationStarted = System.nanoTime();
            LlmDetector.Remediation remediation = LlmDetector.runPass2Remediation(redactedDocument, residuals, evidence,
                    hardRedacts, hardPreserves, client, config, files.rules().regions(), ctx);
            llmNanos += System.nanoTime() - remediationStarted;
            // Writing the answer is a new stage, and no new stage begins on a document out of time.
            deadline.check("remediate apply");
            if (!remediation.spans().isEmpty()) {
                // THE ORDINARY RESOLVER. The spans carry origin LLM_PASS2, so they rank where a
                // pass-2 decision ranks and can no more claim a hard-policy tier here than in the
                // first resolve. The hard preserves the first resolve established come with them
                // (carried, never re-derived from the masked text); the ordinary rule spans stay
                // out, so the deterministic layer can only CONSTRAIN what a remediation blanks.
                List<Span> second = new ArrayList<>(remediation.spans());
                second.addAll(hardPreserves);
                remediationPlan = Resolver.resolveRedactions(redactedDocument, second, files.policy());
                requireFinal(remediationPlan);
                applied = (int) remediationPlan.spans().stream().filter(sp -> sp.action() == SpanAction.REDACT).count();
                if (applied > 0) {
                    // Only when there is something to write: a queue answered entirely with PRESERVE
                    // has decided the document is already correct.
                    RedactionPlan secondPlan = remediationPlan;
                    DocxEngine.WriteResult secondWrite = admitted(docxBytes, limits, ctx,
                            () -> DocxEngine.writeRedactedDocxWithTrace(firstRedacted, redactedDocument, secondPlan, limits));
                    redacted = secondWrite.bytes();
                    secondCorrespondence = secondWrite.correspondence();
                    finalCorrespondence = firstWrite.correspondence().then(secondCorrespondence);
                }
            }
            // The outcome policy: what pass 2 left open, plus every HIGH residual still visible.
            List<UnresolvedFinding> highStillVisible = unsettledHighResiduals(remediation.outcomes(), remediationPlan,
                    hardRedacts);
            remediationUnresolved = concat(remediation.unresolved(), highStillVisible);
            timings.put("remediate", seconds(t0));
            // Counts and transient ids only: the residual text is in none of these fields.
            LOG.info("stage=remediate {} postcheck_remediation=true candidate_count={} candidate_ids={} "
                            + "pass2_calls={} remediation_redactions={} unresolved={} high_residuals_open={} "
                            + "elapsed={}s", tag, remediation.candidateIds().size(),
                    PyRepr.repr(remediation.candidateIds()), remediation.pass2Calls(), applied,
                    remediationUnresolved.size(), highStillVisible.size(), fixed3(timings.get("remediate")));
        }

        // Every decision written into this document, counted together. The two plans address
        // different parses of the same file, which is why they are summed rather than merged.
        RedactionPlan decided = remediationPlan == null ? plan : new RedactionPlan(plan.documentId(),
                concat(plan.spans(), remediationPlan.spans()), concat(plan.warnings(), remediationPlan.warnings()));
        List<UnresolvedFinding> unresolved = new ArrayList<>(remap(llm.unresolved(), firstWrite.correspondence()));
        unresolved.addAll(remediationUnresolved);
        if (secondCorrespondence != null) {
            unresolved = new ArrayList<>(remap(unresolved, secondCorrespondence));
        }

        // Stage: final scan. DETERMINISTIC ONLY, of exactly the bytes about to be returned, run when the
        // remediation rewrote them (otherwise the scan above already audited these very bytes). It
        // calls no model and starts nothing: a blocking finding still stops the document, a HIGH
        // textual one no earlier finding covers is held for a person, the rest is reported.
        PostcheckSummary finalScan = postcheck;
        if (redacted != firstRedacted) {
            deadline.check("final scan");
            t0 = System.nanoTime();
            byte[] returned = redacted;
            SourceCorrespondence returnedTrace = finalCorrespondence;
            finalScan = admitted(docxBytes, limits, ctx,
                    () -> Postcheck.scanRedactedDocxBytes(returned, files, document, decided, limits, returnedTrace));
            timings.put("final_scan", seconds(t0));
            LOG.info("stage=final_scan {} findings={} high={} by_kind={} elapsed={}s", tag, finalScan.findingsTotal(),
                    finalScan.bySeverity().getOrDefault("HIGH", 0), PyRepr.repr(finalScan.byKind()),
                    fixed3(timings.get("final_scan")));
            List<PostcheckFinding> stillBlocking = finalScan.blocking();
            if (!stillBlocking.isEmpty()) {
                throw new ResidualPIIError("final scan found " + stillBlocking.size() + " HIGH-severity finding(s) that "
                        + "no further redaction can settle; the document needs manual review (" + stillBlocking.stream()
                        .map(f -> f.kind() + "@" + f.location()).collect(Collectors.joining(", ")) + ")");
            }
            unresolved.addAll(highResidualsNotYetOpen(finalScan.findings(), unresolved));
        }

        List<String> warnings = new ArrayList<>(plan.warnings());
        if (remediationPlan != null) {
            warnings.addAll(remediationPlan.warnings());
        }
        long highOpen = unresolved.stream().filter(f -> f.kind() == UnresolvedFinding.Kind.HIGH_RESIDUAL_PRESERVED
                || f.kind() == UnresolvedFinding.Kind.HIGH_RESIDUAL_UNREDACTED).count();
        long discoveryOpen = unresolved.stream().filter(f -> f.kind() == UnresolvedFinding.Kind.DISCOVERY_INCOMPLETE).count();
        long pass2Unavailable = unresolved.stream().filter(f -> f.kind() == UnresolvedFinding.Kind.PASS2_UNAVAILABLE).count();
        long pass1Unrepresentable = unresolved.stream()
                .filter(f -> f.kind() == UnresolvedFinding.Kind.PASS1_REDACT_UNREPRESENTABLE).count();
        if (discoveryOpen > 0) {
            warnings.add("LLM pass 1 discovery coverage is incomplete in " + discoveryOpen + " chunk(s); human review required");
        }
        if (pass2Unavailable > 0) {
            warnings.add("LLM pass 2 was unavailable for " + pass2Unavailable + " candidate(s) after its retries; the "
                    + "documented pass-1/deterministic fallback was applied where one exists (fallback_used); this "
                    + "document needs human review");
        }
        if (pass1Unrepresentable > 0) {
            warnings.add(pass1Unrepresentable + " pass-1 REDACT(s) narrow to no redactable value and were not "
                    + "applied; this document needs human review");
        }
        // A pass-1 quote that is not in its excerpt is pass 1's, never "left unresolved by pass 2": named as what it is.
        long unlocatable = unresolved.stream().filter(f -> f.kind() == UnresolvedFinding.Kind.DISCOVERY_UNLOCATABLE).count();
        if (unlocatable > 0) {
            warnings.add(unlocatable + " pass-1 finding(s) quote text that is not in their excerpt and could not be "
                    + "placed; this document needs human review");
        }
        long otherOpen = unresolved.size() - highOpen - discoveryOpen - pass2Unavailable - pass1Unrepresentable
                - unlocatable;
        if (otherOpen > 0) {
            warnings.add("LLM pass 2 left " + otherOpen + " finding(s) unresolved after its "
                    + "corrective retry; this document needs human review");
        }
        if (highOpen > 0) {
            warnings.add(highOpen + " HIGH post-redaction finding(s) are still visible after remediation (preserved "
                    + "by LLM pass 2, or not fully redacted); this document needs human review");
        }
        if (postcheck.findingsTotal() > 0) {
            warnings.add("post-redaction scan: " + postcheck.findingsTotal() + " finding(s) "
                    + PyRepr.repr(postcheck.byKind()));
        }
        if (!residuals.isEmpty()) {
            warnings.add("post-redaction remediation: " + residuals.size() + " residual finding(s) were "
                    + "re-adjudicated by LLM pass 2 and " + applied + " further redaction(s) applied" + (applied > 0
                    ? "; the returned document was scanned again, deterministically, and the result's scan "
                    + "describes it" : ""));
        }
        if (finalScan != postcheck && finalScan.findingsTotal() > 0) {
            warnings.add("final scan: " + finalScan.findingsTotal() + " finding(s) " + PyRepr.repr(finalScan.byKind()));
        }
        timings.put("total", seconds(tTotal));

        Map<String, String> provenance = new LinkedHashMap<>();
        provenance.put("provider", config.provider().wire());
        provenance.put("model", config.modelHandle());
        provenance.put("config_sha256", files.configSha256());
        provenance.put("prompts_sha256", Prompts.PROMPTS_SHA256);
        provenance.put("package_version", packageVersion());

        // THE WHOLE LEDGER, taken last: the remediation's calls are booked on the same recorder.
        DocumentAccounting accounting = DocumentAccounting.of(ctx.usage().snapshot(),
                deadline.elapsedMillis(), llmNanos / 1_000_000, config.pricing());
        // The CLI also uses this boundary: even the final scan/writeback must finish in time.
        deadline.check("finish");
        return new AnonymizeResult(documentId, redacted, Summary.buildSummary(decided), warnings, config.modelHandle(),
                timings, finalScan, provenance, unresolved, accounting);
    }

    /**
     * The final scan's HIGH textual findings that no finding already in front of a person covers, as
     * {@code HIGH_RESIDUAL_UNREDACTED}: a HIGH value in the returned bytes needs a redaction or a person,
     * and the final scan has no model to ask. Judged by the carried slices, never by text.
     */
    static List<UnresolvedFinding> highResidualsNotYetOpen(List<PostcheckFinding> findings,
                                                            List<UnresolvedFinding> open) {
        List<UnresolvedFinding> added = new ArrayList<>();
        for (int i = 0; i < findings.size(); i++) {
            PostcheckFinding finding = findings.get(i);
            ResidualSpan at = finding.span();
            if (finding.severity() != PostcheckFinding.Severity.HIGH || at == null || open.stream()
                    .filter(f -> f.audit().stream().anyMatch(a -> a.kind().equals(finding.kind())
                            && a.severity() == finding.severity()))
                    .flatMap(f -> f.locations().stream()).anyMatch(l -> l.unitId().equals(at.unitId())
                            && l.start() <= at.start() && l.end() >= at.end())) {
                continue;
            }
            String id = "F" + (i + 1);
            added.add(new UnresolvedFinding(-1, UnresolvedFinding.Kind.HIGH_RESIDUAL_UNREDACTED, at.category().wire(),
                    List.of(new UnitSlice(at.unitId(), at.start(), at.end())), null, "HIGH final-scan finding " + id
                    + " (" + finding.kind() + ") is still visible in the returned document",
                    List.of(new UnresolvedFinding.AuditRef(id, finding.severity(), finding.kind(), finding.location()))));
        }
        return added;
    }

    /**
     * The scan's textual findings as located REVIEW proposals for the pass-2 queue, each with its
     * provenance. A residual is evidence WITH coordinates and WITHOUT a decision, which is exactly
     * what a REVIEW hint is, so the queue needs no special case. Coordinates are copied verbatim
     * from the scan. Confidence 1.0 because the audit is certain it MATCHED, which says nothing
     * about whether the text should go; origin stays deterministic, which costs nothing, because a
     * REVIEW span never reaches the resolver.
     *
     * <p>{@code findings} is the scan's whole list, so a finding's id ({@code P<n>}) is its place in
     * INITIAL scan order. The self-contained reference is not an index into final-output {@code --qa}.
     */
    static List<LlmDetector.Residual> residualQuestions(List<PostcheckFinding> findings) {
        List<LlmDetector.Residual> residuals = new ArrayList<>();
        for (int i = 0; i < findings.size(); i++) {
            PostcheckFinding finding = findings.get(i);
            ResidualSpan residual = finding.span();
            if (residual == null) {
                continue;
            }
            residuals.add(new LlmDetector.Residual(
                    new UnresolvedFinding.AuditRef("P" + (i + 1), finding.severity(), finding.kind(), finding.location()),
                    new Span(residual.unitId(), residual.start(), residual.end(), residual.text(), residual.category(),
                            "postcheck_" + finding.kind(), 1.0, SpanAction.REVIEW,
                            "post-redaction scan: " + finding.kind(), SpanOrigin.DETERMINISTIC)));
        }
        return residuals;
    }

    /**
     * THE HIGH-RESIDUAL OUTCOME RULE: a HIGH textual finding requires either an actual redaction
     * or a person. One finding per HIGH residual still visible after the second resolve:
     *
     * <ul>
     *   <li>pass 2 kept any part of it: {@code HIGH_RESIDUAL_PRESERVED}. The document keeps the value,
     *       as pass 2 decided, and is {@code needs-review};
     *   <li>only hard policy kept it (a carried hard preserve covers a part of it whole, so that part
     *       was never a question): {@code HIGH_RESIDUAL_UNREDACTED}, recorded as that policy decision;
     *   <li>every part of it was answered REDACT (by pass 2, or already by a carried hard redaction)
     *       but those redactions together do not cover every character of the slice, or no part of
     *       it was ever put to pass 2 or settled by policy: {@code HIGH_RESIDUAL_UNREDACTED};
     *   <li>a part of it was left undecided: nothing more here, since the adjudication already
     *       reported it (with this residual's provenance).
     * </ul>
     *
     * <p>Judged from the residual's aggregated outcome, never by matching text. A residual masking
     * cut into fragments is ONE residual here, with one finding at its original slice and every
     * candidate id it was asked as. A MEDIUM residual is never reported here: its answer settles it
     * either way.
     *
     * @param hardRedacts the carried hard redactions, in the redacted parse's coordinates: what was
     *                    already redacted before the remediation, counted with what it redacted
     */
    static List<UnresolvedFinding> unsettledHighResiduals(List<LlmDetector.ResidualOutcome> outcomes,
                                                          RedactionPlan remediationPlan, List<Span> hardRedacts) {
        List<UnresolvedFinding> open = new ArrayList<>();
        for (LlmDetector.ResidualOutcome outcome : outcomes) {
            UnresolvedFinding.AuditRef ref = outcome.residual().ref();
            if (ref.severity() != PostcheckFinding.Severity.HIGH) {
                continue;
            }
            Span span = outcome.residual().span();
            String finding = "HIGH post-redaction finding " + ref.findingId() + " (" + ref.kind() + ")";
            UnresolvedFinding.Kind kind;
            String detail;
            if (outcome.decision() == SpanAction.PRESERVE && outcome.preservedByPolicy()) {
                // A policy decision, recorded as one: never asked, so neither preserved by pass 2 nor a
                // missing adjudication. Still visible and still HIGH, so still in front of a person.
                kind = UnresolvedFinding.Kind.HIGH_RESIDUAL_UNREDACTED;
                detail = finding + " is kept visible by hard policy; a person must confirm it may stay visible";
            } else if (outcome.decision() == SpanAction.PRESERVE) {
                kind = UnresolvedFinding.Kind.HIGH_RESIDUAL_PRESERVED;
                detail = finding + " was preserved by LLM pass 2; a person must confirm it may stay visible";
            } else if (outcome.decision() == SpanAction.REDACT) {
                if (redactsWhole(remediationPlan, hardRedacts, span)) {
                    continue;
                }
                kind = UnresolvedFinding.Kind.HIGH_RESIDUAL_UNREDACTED;
                detail = finding + " was answered REDACT by LLM pass 2, but the final plan does not redact the whole "
                        + "value";
            } else if (!outcome.considered()) {
                kind = UnresolvedFinding.Kind.HIGH_RESIDUAL_UNREDACTED;
                detail = finding + " could not be put to LLM pass 2";
            } else {
                continue; // undecided: already an unresolved finding of the adjudication
            }
            List<String> ids = outcome.candidateIds();
            open.add(new UnresolvedFinding(outcome.chunkIndex(), kind, span.category().wire(),
                    List.of(new UnitSlice(span.unitId(), span.start(), span.end())),
                    ids.isEmpty() ? null : String.join(",", ids), detail, List.of(ref)));
        }
        if (!open.isEmpty()) {
            LOG.warn("postcheck_remediation: {} HIGH residual(s) still visible after remediation; kept for human "
                    + "review", open.size());
        }
        return open;
    }

    /**
     * Whether every character of {@code span}'s slice is redacted: by a REDACT span of {@code plan}
     * (null: none) or by one of {@code alreadyRedacted}, the hard redactions written before.
     */
    static boolean redactsWhole(RedactionPlan plan, List<Span> alreadyRedacted, Span span) {
        boolean[] covered = new boolean[Math.max(0, span.end() - span.start())];
        List<Span> redactions = new ArrayList<>(alreadyRedacted);
        if (plan != null) {
            redactions.addAll(plan.spans());
        }
        for (Span s : redactions) {
            if (s.action() != SpanAction.REDACT || !s.unitId().equals(span.unitId())) {
                continue;
            }
            for (int i = Math.max(s.start(), span.start()); i < Math.min(s.end(), span.end()); i++) {
                covered[i - span.start()] = true;
            }
        }
        for (boolean c : covered) {
            if (!c) {
                return false;
            }
        }
        return covered.length > 0;
    }

    /**
     * The hard preserves the FIRST resolve established, for the remediation's queue and for the second
     * resolve. A hard preserve is a policy decision about this text, as true of the post-redaction
     * re-ask as of the first adjudication, so it travels with the document.
     *
     * <p>THE RULE ENGINE IS DELIBERATELY NOT RUN AGAIN: on the masked text the mask is itself
     * evidence to a rule that reads context ("τον ΙΒΑΝ ........." reads as a label and a
     * placeholder), so detecting again would invent an authority no pass-2 answer could reach.
     *
     * <p>CARRIED ONLY WHEN THE COORDINATES STILL MEAN THE SAME THING. Redaction is 1:1, but the
     * cleanup also drops tracked-change, hidden and comment content, which can resize or remove a
     * unit. Same unit ids with the same lengths, or nothing is carried; losing the labels'
     * protection is the safe direction, writing a preserve at an offset that now holds something
     * else is not.
     */
    static List<Span> carriedHardPreserves(DocumentData source, DocumentData redacted, List<Span> spans,
                                           PolicySettings policy) {
        if (!source.sameUnitGeometry(redacted)) {
            LOG.info("postcheck_remediation: the redacted parse does not match the source unit for unit, so no hard "
                    + "preserve was carried into the remediation or the second resolve");
            return List.of();
        }
        return spans.stream().filter(sp -> Resolver.isHardPreserve(sp, policy)).toList();
    }

    /**
     * The hard redactions the FIRST resolve established, for the remediation's masked view: the same
     * rule that blanked them in what the first adjudication was shown blanks them in what the re-ask
     * is shown. Normally a no-op, since a written redaction is a run of dots already. Carried under
     * the same condition as {@link #carriedHardPreserves}, and for the same reason: blanking at an
     * offset that now holds something else would show the model the wrong text.
     */
    static List<Span> carriedHardRedacts(DocumentData source, DocumentData redacted, List<Span> spans,
                                         PolicySettings policy) {
        if (!source.sameUnitGeometry(redacted)) {
            return List.of();
        }
        return spans.stream().filter(sp -> Resolver.isHardRedact(sp, policy)).toList();
    }

    private static void requireFinal(RedactionPlan plan) {
        if (plan.spans().stream().anyMatch(sp -> sp.action() != SpanAction.REDACT && sp.action() != SpanAction.PRESERVE)) {
            throw new IllegalStateException("plan contains a non-final action — programming bug");
        }
    }

    private static <T> List<T> concat(List<T> a, List<T> b) {
        List<T> out = new ArrayList<>(a);
        out.addAll(b);
        return out;
    }

    private static List<UnresolvedFinding> remap(List<UnresolvedFinding> findings, SourceCorrespondence trace) {
        return findings.stream().map(f -> new UnresolvedFinding(f.chunkIndex(), f.kind(), f.category(),
                f.locations().stream().flatMap(at -> trace.translate(at).stream()).toList(),
                f.candidateId(), f.detail(), f.audit())).toList();
    }

    /** JAR manifest {@code Implementation-Version} (equals pyproject's version), else "unknown". */
    static String packageVersion() {
        String v = Pipeline.class.getPackage().getImplementationVersion();
        return v == null ? "unknown" : v;
    }

    /**
     * Runs a stage that parses or writes the whole package inside a {@link MemoryGate} reservation.
     * Only these stages hold one: between them (the LLM stage above all, which can take minutes) a
     * document keeps only its extracted text. Every stage is sized from the INPUT: the redacted
     * output has the same parts, a few bytes larger each, and sized from it a document admitted
     * to parse could be refused at write, after its LLM calls were paid for.
     */
    private static <T> T admitted(byte[] docx, ResourceLimits limits, RunContext ctx, Supplier<T> stage) {
        try (MemoryGate.Permit permit = MemoryGate.admit(docx, limits, ctx.deadline(), ctx.tag())) {
            return stage.get();
        }
    }

    private static double seconds(long startNanos) {
        return (System.nanoTime() - startNanos) / 1e9;
    }

    private static String fixed3(double d) {
        return PyFloat.fixed(d, 3);
    }
}
