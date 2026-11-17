package dev.filtsiap.ded.anonymizer;

import dev.filtsiap.ded.anonymizer.pycompat.PyStr;
import java.util.List;

/** A parsed DOCX (port of {@code DocumentData}). */
public record DocumentData(String documentId, List<TextUnit> textUnits, List<String> partsInventory,
                           List<String> warnings) {
    public DocumentData {
        textUnits = List.copyOf(textUnits);
        partsInventory = List.copyOf(partsInventory);
        warnings = List.copyOf(warnings);
    }

    /**
     * Whether {@code other} has the same units, in the same order, with the same lengths: then a
     * coordinate in one means the same place in the other. Redaction is one character for one, so a
     * redacted parse lines up with its source unless the cleanup dropped content.
     */
    public boolean sameUnitGeometry(DocumentData other) {
        if (textUnits.size() != other.textUnits().size()) {
            return false;
        }
        for (int i = 0; i < textUnits.size(); i++) {
            TextUnit a = textUnits.get(i);
            TextUnit b = other.textUnits().get(i);
            if (!a.unitId().equals(b.unitId()) || !a.partName().equals(b.partName()) || a.unitType() != b.unitType()
                    || !a.charMap().equals(b.charMap()) || PyStr.len(a.normalizedText()) != PyStr.len(b.normalizedText())) {
                return false;
            }
            int[] beforePoints = a.normalizedText().codePoints().toArray();
            int[] afterPoints = b.normalizedText().codePoints().toArray();
            for (int k = 0; k < beforePoints.length; k++) {
                int after = afterPoints[k];
                if (after != '.' && after != beforePoints[k]) {
                    return false;
                }
            }
        }
        return true;
    }
}
