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
        PERCENTAGE, BUSINESS_SEAT;

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
