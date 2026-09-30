package dev.filtsiap.ded.anonymizer;

import java.util.List;

/** A parsed DOCX (port of {@code DocumentData}). */
public record DocumentData(String documentId, List<TextUnit> textUnits, List<String> partsInventory,
                           List<String> warnings) {
    public DocumentData {
        textUnits = List.copyOf(textUnits);
        partsInventory = List.copyOf(partsInventory);
        warnings = List.copyOf(warnings);
    }
}
