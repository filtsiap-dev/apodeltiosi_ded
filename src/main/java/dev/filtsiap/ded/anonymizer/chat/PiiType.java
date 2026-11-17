package dev.filtsiap.ded.anonymizer.chat;

/** What a masked span was. The names equal the {@code type} values of eval/chat-anonymization/dataset.jsonl. */
public enum PiiType {
    PERSON,
    AFM, AMKA, IBAN, BANK_ACCOUNT, PHONE, EMAIL,
    ID_CARD, PASSPORT, PLATE, GEMI, CARD, CUSTOMER_NO,
    DOB, ORG_PERSONAL,
    /** A residual digit run, or a NER label with no more specific type. */
    OTHER
}
