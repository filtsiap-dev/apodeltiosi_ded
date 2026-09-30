package dev.filtsiap.ded.anonymizer;

import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

/** Module-level constants of {@code models.py}. */
public final class Models {

    /** Every character of a REDACT span is replaced by this one character (one per code point). */
    public static final String REDACTION_GLYPH = ".";

    public static final Set<SpanCategory> REDACT_CATEGORIES = Collections.unmodifiableSet(EnumSet.of(
            SpanCategory.AFM,
            SpanCategory.AMKA,
            SpanCategory.IBAN,
            SpanCategory.EMAIL,
            SpanCategory.PHONE,
            SpanCategory.PROTOCOL_NUMBER,
            SpanCategory.ACT_NUMBER,
            SpanCategory.AUDIT_ORDER,
            SpanCategory.INVOICE_NUMBER,
            SpanCategory.TRANSACTION_ID,
            SpanCategory.PRIVATE_ADDRESS,
            SpanCategory.CHALLENGED_ACT_NUMBER,
            SpanCategory.CASE_REF_NUMBER,
            SpanCategory.APPELLANT_NAME,
            SpanCategory.FATHER_NAME,
            SpanCategory.PRIVATE_COMPANY_NAME,
            SpanCategory.BANK_ACCOUNT,
            SpanCategory.PRIVATE_BENEFICIARY,
            SpanCategory.FISCAL_DEVICE_ID,
            SpanCategory.INVOICE_TABLE_ID,
            SpanCategory.BUSINESS_SEAT));

    public static final Set<SpanCategory> PRESERVE_CATEGORIES = Collections.unmodifiableSet(EnumSet.of(
            SpanCategory.DATE,
            SpanCategory.DOU,
            SpanCategory.PUBLIC_SERVICE,
            SpanCategory.LEGAL_REF,
            SpanCategory.ARTICLE_REF,
            SpanCategory.COURT_DECISION,
            SpanCategory.MONEY,
            SpanCategory.TAX_YEAR,
            SpanCategory.FISCAL_PERIOD,
            SpanCategory.PUBLIC_AUTHORITY_HEADER,
            SpanCategory.DECISION_METADATA,
            SpanCategory.OFFICIAL_SIGNATORY,
            SpanCategory.PERCENTAGE));

    public static final Set<SpanCategory> REVIEW_CATEGORIES = Collections.unmodifiableSet(EnumSet.of(
            SpanCategory.POSSIBLE_PERSON,
            SpanCategory.POSSIBLE_COMPANY,
            SpanCategory.POSSIBLE_PRIVATE_LOCATION,
            SpanCategory.MEDICAL_TERM));

    /** Every category in the schema. */
    public static final Set<SpanCategory> ALL_CATEGORIES =
            Collections.unmodifiableSet(EnumSet.allOf(SpanCategory.class));

    private Models() {
    }
}
