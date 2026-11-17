package dev.filtsiap.ded.anonymizer;

import java.util.Optional;

/**
 * Span categories (port of {@code SpanCategory} in {@code models.py}). Constant names equal
 * the wire strings used in prompts, LLM output, YAML and JSON.
 */
public enum SpanCategory {
    AFM, AMKA, IBAN, EMAIL,
        PHONE, PROTOCOL_NUMBER, ACT_NUMBER, AUDIT_ORDER,
        INVOICE_NUMBER, TRANSACTION_ID, PRIVATE_ADDRESS, DATE,
        DOU, PUBLIC_SERVICE, LEGAL_REF, ARTICLE_REF,
        COURT_DECISION, MONEY, TAX_YEAR, FISCAL_PERIOD,
        POSSIBLE_PERSON, POSSIBLE_COMPANY, POSSIBLE_PRIVATE_LOCATION, MEDICAL_TERM,
        CHALLENGED_ACT_NUMBER, CASE_REF_NUMBER, PUBLIC_AUTHORITY_HEADER, DECISION_METADATA,
        OFFICIAL_SIGNATORY, APPELLANT_NAME, FATHER_NAME, PRIVATE_COMPANY_NAME,
        BANK_ACCOUNT, PRIVATE_BENEFICIARY, FISCAL_DEVICE_ID, INVOICE_TABLE_ID,
        PERCENTAGE, BUSINESS_SEAT,
    /**
     * The structural label that introduces a value ("Α.Φ.Μ.", "ΑΤΑΚ", "οδός"), or a generic party role
     * ("η προσφεύγουσα εταιρεία"); never personal data.
     */
    FIELD_LABEL,
    /** Cadastral / property-register identifiers (ΑΤΑΚ, ΚΑΕΚ, Ο.Τ., Α.Χ.Κ., notice number); cue-anchored. */
    PROPERTY_ID,
    /** A date with an explicit procedural cue. Distinct from {@link #DATE}, which may be a date of birth. */
    PROCEDURAL_DATE,
    /** A court decision in this case's own history, as opposed to precedent ({@link #COURT_DECISION}). */
    CASE_COURT_REFERENCE,
    /**
     * A place name whose role the context does not settle (after a district/area cue, or as a
     * model reads it): an ordinary, context-dependent category with no hard status either way.
     */
    LOCALITY,
    /**
     * PUBLIC geography the deterministic layer has POSITIVELY identified: a municipality with its
     * administrative region after a residence cue ("κατοίκου Χ Αττικής"), or the region after an
     * authority's place. Hard-preserved by policy. Never emitted for a bare place or a street.
     */
    PUBLIC_LOCALITY;

    /** The wire string; equals {@link #name()}. */
    public String wire() {
        return name();
    }

    /** Parses a wire string; unknown values give empty, never an exception. */
    public static Optional<SpanCategory> fromWire(String value) {
        for (SpanCategory c : values()) {
            if (c.name().equals(value)) {
                return Optional.of(c);
            }
        }
        return Optional.empty();
    }
}
