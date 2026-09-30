package dev.filtsiap.ded.anonymizer;

/**
 * Text unit types (port of {@code UnitType}). {@code parse_docx} emits only PARAGRAPH and
 * TABLE_CELL; the rest are reserved, as in Python.
 */
public enum UnitType {
    PARAGRAPH("paragraph"),
    TABLE_CELL("table_cell"),
    HEADER("header"),
    FOOTER("footer"),
    FOOTNOTE("footnote"),
    ENDNOTE("endnote"),
    COMMENT("comment"),
    TEXTBOX("textbox");

    private final String wire;

    UnitType(String wire) {
        this.wire = wire;
    }

    /** The Python string value, e.g. {@code "table_cell"}. */
    public String wire() {
        return wire;
    }
}
