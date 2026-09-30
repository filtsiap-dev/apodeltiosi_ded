package dev.filtsiap.ded.anonymizer;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * One paragraph or table cell of extracted text (port of {@code TextUnit}).
 *
 * <p>{@code normalizedText} and {@code charMap} are parallel: code point {@code i} of the text
 * maps to {@code charMap.get(i)}. Python's free-form {@code location} dict is typed here as
 * {@link Location}; {@link Location#asMap()} restores the Python dict for JSON output.
 */
public record TextUnit(
        String unitId,
        String partName,
        UnitType unitType,
        String text,
        String normalizedText,
        List<XmlCharRef> charMap,
        Location location) {

    public TextUnit {
        charMap = List.copyOf(charMap);
    }

    /** Where a unit sits in the document. */
    public sealed interface Location permits ParagraphLocation, TableCellLocation {
        /** Python {@code location.get("column_header", "")}. */
        default String columnHeader() {
            return "";
        }

        /** The Python {@code location} dict, keys in Python's order. */
        Map<String, Object> asMap();
    }

    /** Location of a body paragraph; {@code paragraphIndex} is the global unit counter. */
    public record ParagraphLocation(int paragraphIndex) implements Location {
        @Override
        public Map<String, Object> asMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("paragraph_index", paragraphIndex);
            return m;
        }
    }

    /** Location of a table cell; {@code columnHeader} is empty for header-row cells. */
    public record TableCellLocation(int tableIndex, int rowIndex, int colIndex, String columnHeader,
                                    boolean isHeaderRow) implements Location {
        @Override
        public Map<String, Object> asMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("table_index", tableIndex);
            m.put("row_index", rowIndex);
            m.put("col_index", colIndex);
            m.put("column_header", columnHeader);
            m.put("is_header_row", isHeaderRow);
            return m;
        }
    }
}
