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

    /**
     * Location of a table cell; {@code columnHeader} is empty for header-row cells. Header rows are the
     * table's leading rows Word repeats as headers ({@code w:tblHeader}), else its first row only when
     * that row is positively made of known column labels ({@code DocxEngine.labelRow}), else none; a body
     * cell's {@code columnHeader} is the last non-empty header text above the grid columns it covers, and
     * empty when those columns carry different labels (or some none). {@code titleUnitId} is the
     * paragraph unit just before the table (its title or section heading), or null: context only, used
     * by the LLM work items, and never part of {@link #asMap()}. {@code colIndex} is the cell's first
     * column in the table's LOGICAL grid ({@code w:gridBefore} and the {@code w:gridSpan} of the cells
     * before it), so a horizontally merged cell never shifts the cells after it; for a table whose grid
     * cannot be read it is the cell's position in its row, and no cell of it has a header.
     * {@code headerAligned} says the header's own cell covers exactly this cell's columns: false under a
     * group label spanning several sub-columns, where the label does not say which column this is. Only
     * an aligned header may PRESERVE a cell whole ({@code Detectors.detectTableSensitiveValues}). Not part
     * of {@link #asMap()} either.
     */
    public record TableCellLocation(int tableIndex, int rowIndex, int colIndex, String columnHeader,
                                    boolean isHeaderRow, String titleUnitId, boolean headerAligned)
            implements Location {

        /** A cell located without grid information: a header given here is taken to name its column exactly. */
        public TableCellLocation(int tableIndex, int rowIndex, int colIndex, String columnHeader, boolean isHeaderRow) {
            this(tableIndex, rowIndex, colIndex, columnHeader, isHeaderRow, null);
        }

        public TableCellLocation(int tableIndex, int rowIndex, int colIndex, String columnHeader, boolean isHeaderRow,
                                 String titleUnitId) {
            this(tableIndex, rowIndex, colIndex, columnHeader, isHeaderRow, titleUnitId, true);
        }

        /** The same cell with the table's title paragraph named. */
        public TableCellLocation withTitle(String unitId) {
            return new TableCellLocation(tableIndex, rowIndex, colIndex, columnHeader, isHeaderRow, unitId,
                    headerAligned);
        }

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
