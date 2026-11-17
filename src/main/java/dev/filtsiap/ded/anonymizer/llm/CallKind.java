package dev.filtsiap.ded.anonymizer.llm;

/**
 * Which logical request a provider call was: the pass, and whether it was the first ask or the
 * one corrective retry. The post-redaction remediation is pass 2 again, booked under its own
 * kinds so a document's cost can be split between the first adjudication and the re-ask.
 */
public enum CallKind {
    PASS1("pass1", 1, "first"),
    PASS2("pass2", 2, "first"),
    PASS2_RETRY("pass2_retry", 2, "retry"),
    REMEDIATION("remediation", 2, "first"),
    REMEDIATION_RETRY("remediation_retry", 2, "retry");

    private final String wire;
    private final int passNumber;
    private final String attempt;

    CallKind(String wire, int passNumber, String attempt) {
        this.wire = wire;
        this.passNumber = passNumber;
        this.attempt = attempt;
    }

    /** The pass-2 call of a first or corrective attempt, in the main stage or the remediation. */
    static CallKind pass2(boolean retry, boolean remediation) {
        if (remediation) {
            return retry ? REMEDIATION_RETRY : REMEDIATION;
        }
        return retry ? PASS2_RETRY : PASS2;
    }

    public String wire() {
        return wire;
    }

    /** 1 or 2; the remediation is pass 2. */
    public int passNumber() {
        return passNumber;
    }

    /** "first" or "retry", as the log tags spell it. */
    public String attempt() {
        return attempt;
    }
}
