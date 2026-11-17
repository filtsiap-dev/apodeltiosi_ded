package dev.filtsiap.ded.anonymizer.llm;

import dev.filtsiap.ded.anonymizer.DocumentData;
import dev.filtsiap.ded.anonymizer.TextUnit;
import dev.filtsiap.ded.anonymizer.UnitSlice;
import dev.filtsiap.ded.anonymizer.UnitType;
import dev.filtsiap.ded.anonymizer.pycompat.PyStr;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.stream.Collectors;

/**
 * One LLM work item: a run of paragraph units, or one or more TABLE GROUPS (port of {@code Chunk},
 * extended). A table group is a whole small table, or a bounded run of a large table's rows; several
 * small tables share one work item, each in its own block, and a large one is split into row groups.
 * {@code groups} is empty for a paragraph chunk; {@code tableIndex} is the first group's table.
 */
public record Chunk(List<TextUnit> units, boolean isTable, Integer tableIndex, List<TableGroup> groups) {

    /** The longest title shown before a table, in code points; a longer one is cut (it is context only). */
    static final int TITLE_CONTEXT_MAX = 160;
    /** The prefix of every read-only context line; the prompts explain it. */
    static final String CONTEXT_PREFIX = "[context] ";

    public Chunk {
        units = List.copyOf(units);
        groups = groups == null ? List.of() : List.copyOf(groups);
    }

    /** A chunk of one whole table (or of paragraphs), as before table groups existed. */
    public Chunk(List<TextUnit> units, boolean isTable, Integer tableIndex) {
        this(units, isTable, tableIndex, isTable ? wholeTables(units) : List.of());
    }

    /**
     * One table's part of a chunk. {@code cells} are its REAL cells, each written to its own place.
     * {@code title} (the paragraph before the table) and {@code headerCopy} (the marked header rows, or
     * the first row when none is marked, repeated in front of a later row group) are READ-ONLY context:
     * rendered for the model, mapped to nothing,
     * so no span can ever be written to them. A row whose cells are split across groups (a row longer
     * than a whole work item) keeps its column positions in every group: a later part of it starts with
     * the empty places of the columns rendered before.
     */
    public record TableGroup(String partName, int tableIndex, List<TextUnit> cells, TextUnit title,
                             List<TextUnit> headerCopy, boolean continued) {
        public TableGroup {
            cells = List.copyOf(cells);
            headerCopy = headerCopy == null ? List.of() : List.copyOf(headerCopy);
        }
    }

    private static List<TableGroup> wholeTables(List<TextUnit> units) {
        Map<List<Object>, List<TextUnit>> byTable = new LinkedHashMap<>();
        for (TextUnit u : units) {
            byTable.computeIfAbsent(List.of(u.partName(), cell(u).tableIndex()), k -> new ArrayList<>()).add(u);
        }
        List<TableGroup> groups = new ArrayList<>();
        byTable.forEach((key, cells) -> groups.add(new TableGroup((String) key.get(0), (Integer) key.get(1), cells, null,
                List.of(), false)));
        return groups;
    }

    Set<String> unitIds() {
        return units.stream().map(TextUnit::unitId).collect(Collectors.toSet());
    }

    /**
     * The chunk as the model sees it, and the map back to where it came from. {@code segments}
     * gives, per unit in text order, exactly the code points that unit contributed; everything
     * between them (the "TABLE:" banners, joining newlines, the " | " between cells, context lines) is
     * synthetic and belongs to no unit, so nothing may ever be written to it. {@code contexts} are the
     * read-only context lines (a table's title, a repeated header): a match that touches one maps to
     * nowhere, never to a partial source slice. {@code blocks} are the tables' blocks (the whole text for
     * paragraphs): a context window never crosses from one into another.
     */
    public record Rendered(String text, Map<String, Integer> offsets, List<Segment> segments, List<Range> contexts,
                           List<Range> blocks) {

        /** The code points {@code [start, end)} of the rendered text that {@code unitId} contributed. */
        public record Segment(int start, int end, String unitId) {
        }

        /** Code points {@code [start, end)} of the rendered text. */
        public record Range(int start, int end) {
            boolean overlaps(int s, int e) {
                return s < end && start < e;
            }

            boolean contains(int s, int e) {
                return start <= s && e <= end;
            }
        }

        public Rendered {
            offsets = Collections.unmodifiableMap(new HashMap<>(offsets));
            segments = List.copyOf(segments);
            contexts = List.copyOf(contexts);
            blocks = List.copyOf(blocks);
        }

        /** A rendering without context lines: one block, the whole text. */
        public Rendered(String text, Map<String, Integer> offsets, List<Segment> segments) {
            this(text, offsets, segments, List.of(), List.of(new Range(0, PyStr.len(text))));
        }

        /**
         * Maps the rendered slice {@code [start, end)} back to one slice per unit it touches, in
         * text order, synthetic characters dropped. Empty for a slice that lands only on synthetic
         * characters, or touches a read-only context line at all, which the caller must treat as
         * nowhere to write.
         */
        public List<UnitSlice> locate(int start, int end) {
            for (Range c : contexts) {
                if (c.overlaps(start, end)) {
                    return List.of();
                }
            }
            List<UnitSlice> found = new ArrayList<>();
            for (Segment s : segments) {
                int low = Math.max(start, s.start());
                int high = Math.min(end, s.end());
                if (low < high) {
                    found.add(new UnitSlice(s.unitId(), low - s.start(), high - s.start()));
                }
            }
            return found;
        }

        /** Whether {@code [start, end)} lies wholly inside one read-only context line. */
        public boolean inContext(int start, int end) {
            return contexts.stream().anyMatch(c -> c.contains(start, end));
        }

        /** The block holding {@code position}: its table's block, or the whole text. */
        public Range blockAt(int position) {
            for (Range b : blocks) {
                if (b.start() <= position && position <= b.end()) {
                    return b;
                }
            }
            return new Range(0, PyStr.len(text));
        }
    }

    /**
     * Renders the chunk once, with the map back to the source units. A paragraph chunk renders as its
     * newline-joined texts. A table group renders as a "TABLE:" banner ("TABLE (continued):" for a later
     * row group of the same table), its read-only context lines, then one pipe-joined line per row, every
     * cell in its column's place (an empty cell stays an empty place between two " | "). Groups are
     * separated by a blank line.
     */
    public Rendered render() {
        Map<String, Integer> offsets = new HashMap<>();
        List<Rendered.Segment> segments = new ArrayList<>();
        if (!isTable) {
            int cursor = 0;
            for (int position = 0; position < units.size(); position++) {
                if (position > 0) {
                    cursor += 1; // the newline joining it to the previous unit
                }
                cursor = place(units.get(position), cursor, offsets, segments);
            }
            return new Rendered(units.stream().map(TextUnit::normalizedText).collect(Collectors.joining("\n")),
                    offsets, segments);
        }
        StringBuilder text = new StringBuilder();
        int[] cursor = {0};
        List<Rendered.Range> contexts = new ArrayList<>();
        List<Rendered.Range> blocks = new ArrayList<>();
        for (int g = 0; g < groups.size(); g++) {
            TableGroup group = groups.get(g);
            if (g > 0) {
                synthetic(text, cursor, "\n\n");
            }
            int blockStart = cursor[0];
            synthetic(text, cursor, banner(group.continued()));
            String titleLine = titleLine(group.title());
            if (titleLine != null) {
                synthetic(text, cursor, "\n");
                int start = cursor[0];
                synthetic(text, cursor, titleLine);
                contexts.add(new Rendered.Range(start, cursor[0]));
            }
            for (List<TextUnit> row : rows(group.headerCopy()).values()) {
                synthetic(text, cursor, "\n");
                int start = cursor[0];
                synthetic(text, cursor, copyPrefix(row));
                List<String> cells = new ArrayList<>();
                columns(row).forEach(u -> cells.add(u == null ? "" : u.normalizedText()));
                synthetic(text, cursor, String.join(" | ", cells));
                contexts.add(new Rendered.Range(start, cursor[0]));
            }
            for (List<TextUnit> row : rows(group.cells()).values()) {
                synthetic(text, cursor, "\n");
                List<TextUnit> placed = columns(row);
                for (int column = 0; column < placed.size(); column++) {
                    if (column > 0) {
                        synthetic(text, cursor, " | ");
                    }
                    TextUnit unit = placed.get(column);
                    if (unit != null) {
                        text.append(unit.normalizedText());
                        cursor[0] = place(unit, cursor[0], offsets, segments);
                    }
                }
            }
            blocks.add(new Rendered.Range(blockStart, cursor[0]));
        }
        return new Rendered(text.toString(), offsets, segments, contexts, blocks);
    }

    /** The prefix of a read-only copy of a row the document marks as a header (Word's, or the rules' label row). */
    static final String HEADER_ROW_PREFIX = CONTEXT_PREFIX + "header row: ";
    /**
     * The prefix of a read-only copy of a table's first row when nothing marks a header: it is NOT said to
     * be a header (it may be data); the model decides whether the table has a header, and where.
     */
    static final String FIRST_ROW_PREFIX = CONTEXT_PREFIX + "first row: ";

    /** A copied row's prefix: "header row" only for a row marked as one, else the neutral "first row". */
    private static String copyPrefix(List<TextUnit> row) {
        return row.stream().anyMatch(u -> cell(u).isHeaderRow()) ? HEADER_ROW_PREFIX : FIRST_ROW_PREFIX;
    }

    private static String banner(boolean continued) {
        return continued ? "TABLE (continued):" : "TABLE:";
    }

    /** The read-only title line, or null when there is none: the paragraph before the table, collapsed and cut. */
    private static String titleLine(TextUnit title) {
        if (title == null || PyStr.strip(title.normalizedText()).isEmpty()) {
            return null;
        }
        String text = PyStr.collapseWhitespace(PyStr.strip(title.normalizedText()));
        if (PyStr.len(text) > TITLE_CONTEXT_MAX) {
            text = PyStr.slice(text, 0, TITLE_CONTEXT_MAX) + "…";
        }
        return CONTEXT_PREFIX + "text before the table: " + text;
    }

    /**
     * The code points one row, or a run of one row's cells, adds to its group's rendering: its newline, its
     * cells' text, and a " | " for every column after the first up to its last (rows render from column 0,
     * so this depends on the row alone).
     */
    private static int rowLength(List<TextUnit> row) {
        int last = 0;
        int text = 0;
        for (TextUnit u : row) {
            last = Math.max(last, cell(u).colIndex());
            text += PyStr.len(u.normalizedText());
        }
        return 1 + text + 3 * last;
    }

    /** The code points of a group's banner, title line and header copy: all of its rendering but its own rows. */
    private static int frameLength(boolean continued, String titleLine, List<TextUnit> headerCopy) {
        int length = PyStr.len(banner(continued));
        if (titleLine != null) {
            length += 1 + PyStr.len(titleLine);
        }
        for (List<TextUnit> row : rows(headerCopy).values()) {
            length += rowLength(row) + PyStr.len(copyPrefix(row));
        }
        return length;
    }

    private static void synthetic(StringBuilder text, int[] cursor, String s) {
        text.append(s);
        cursor[0] += PyStr.len(s);
    }

    /** Cells by row, rows in order. */
    private static TreeMap<Integer, List<TextUnit>> rows(List<TextUnit> cells) {
        TreeMap<Integer, List<TextUnit>> rows = new TreeMap<>();
        for (TextUnit unit : cells) {
            rows.computeIfAbsent(cell(unit).rowIndex(), k -> new ArrayList<>()).add(unit);
        }
        return rows;
    }

    /**
     * A row's cells in their columns, from the first column, null where a column has no cell (an empty
     * cell has no unit). Always from column 0, also for a later part of a split row, so a cell is in
     * its own column in every group and under its own header.
     */
    private static List<TextUnit> columns(List<TextUnit> row) {
        List<TextUnit> cells = new ArrayList<>(row);
        cells.sort(Comparator.comparingInt(u -> cell(u).colIndex()));
        int last = cell(cells.getLast()).colIndex();
        List<TextUnit> placed = new ArrayList<>();
        for (int column = 0; column <= last; column++) {
            placed.add(null);
        }
        for (TextUnit u : cells) {
            placed.set(cell(u).colIndex(), u);
        }
        return placed;
    }

    private static TextUnit.TableCellLocation cell(TextUnit unit) {
        return (TextUnit.TableCellLocation) unit.location();
    }

    private static int place(TextUnit unit, int cursor, Map<String, Integer> offsets,
                             List<Rendered.Segment> segments) {
        offsets.put(unit.unitId(), cursor);
        int end = cursor + PyStr.len(unit.normalizedText());
        if (end > cursor) {
            segments.add(new Rendered.Segment(cursor, end, unit.unitId()));
        }
        return end;
    }

    /** The rendered length of one table group on its own. */
    private static int length(TableGroup group) {
        return PyStr.len(new Chunk(group.cells(), true, group.tableIndex(), List.of(group)).render().text());
    }

    /**
     * Tables first, then non-empty paragraph units accumulated while the joined text fits
     * {@code chunkSizeChars}; a paragraph unit is never split, and an oversized one is its own chunk.
     *
     * <p>Tables (grouped by part and table index, first-seen order): a table that fits is one group; a
     * larger one is cut into row groups that fit, every later group carrying a read-only copy of the
     * table's marked header rows, or of its first row when none is marked (when that copy is short enough
     * to be worth repeating); a row longer than a
     * whole work item is cut between its cells. Every group also carries the table's title as read-only
     * context. Then consecutive groups are packed into one work item while they fit together. Every cell
     * is in exactly one group, at its own coordinates; no cell is ever cut.
     */
    public static List<Chunk> split(DocumentData document, int chunkSizeChars) {
        Map<String, TextUnit> byId = new HashMap<>();
        document.textUnits().forEach(u -> byId.put(u.unitId(), u));
        record TableKey(String partName, int tableIndex) {
        }
        Map<TableKey, List<TextUnit>> tables = new LinkedHashMap<>();
        for (TextUnit unit : document.textUnits()) {
            if (unit.unitType() == UnitType.TABLE_CELL) {
                tables.computeIfAbsent(new TableKey(unit.partName(), cell(unit).tableIndex()),
                        k -> new ArrayList<>()).add(unit);
            }
        }
        List<TableGroup> pieces = new ArrayList<>();
        tables.forEach((key, cells) -> pieces.addAll(tableGroups(key.partName(), key.tableIndex(), cells, byId,
                chunkSizeChars)));

        List<Chunk> chunks = new ArrayList<>();
        List<TableGroup> packed = new ArrayList<>();
        int packedLen = 0;
        for (TableGroup piece : pieces) {
            int len = length(piece);
            if (!packed.isEmpty() && packedLen + 2 + len > chunkSizeChars) {
                chunks.add(tableChunk(packed));
                packed = new ArrayList<>();
                packedLen = 0;
            }
            packedLen = packed.isEmpty() ? len : packedLen + 2 + len;
            packed.add(piece);
        }
        if (!packed.isEmpty()) {
            chunks.add(tableChunk(packed));
        }

        List<TextUnit> current = new ArrayList<>();
        int currentLen = 0;
        for (TextUnit unit : document.textUnits()) {
            if (unit.unitType() == UnitType.TABLE_CELL || unit.normalizedText().isEmpty()) {
                continue;
            }
            int unitLen = PyStr.len(unit.normalizedText());
            if (!current.isEmpty() && currentLen + 1 + unitLen > chunkSizeChars) {
                chunks.add(new Chunk(current, false, null));
                current = new ArrayList<>();
                currentLen = 0;
            }
            currentLen = current.isEmpty() ? unitLen : currentLen + 1 + unitLen;
            current.add(unit);
        }
        if (!current.isEmpty()) {
            chunks.add(new Chunk(current, false, null));
        }
        return chunks;
    }

    private static Chunk tableChunk(List<TableGroup> groups) {
        List<TextUnit> units = new ArrayList<>();
        groups.forEach(g -> units.addAll(g.cells()));
        return new Chunk(units, true, groups.getFirst().tableIndex(), groups);
    }

    /** One table as groups that fit {@code size}: the whole table, or its row groups (see {@link #split}). */
    private static List<TableGroup> tableGroups(String part, int index, List<TextUnit> cells, Map<String, TextUnit> byId,
                                                int size) {
        String titleId = cell(cells.getFirst()).titleUnitId();
        TextUnit title = titleId == null ? null : byId.get(titleId);
        String titleLine = titleLine(title);
        TreeMap<Integer, List<TextUnit>> rows = rows(cells);
        // Sizes are counted, not rendered: each row's line once, each group's frame once. The count is the
        // rendered length exactly (render() builds the same banner, title line, header copy and row lines).
        Map<Integer, Integer> rowLengths = new HashMap<>();
        int body = 0;
        for (Map.Entry<Integer, List<TextUnit>> row : rows.entrySet()) {
            int length = rowLength(row.getValue());
            rowLengths.put(row.getKey(), length);
            body += length;
        }
        int firstFrame = frameLength(false, titleLine, List.of());
        if (firstFrame + body <= size) {
            return List.of(new TableGroup(part, index, cells, title, List.of(), false));
        }
        // What a later group repeats: the rows marked as the table's header; with none marked, its first row,
        // shown neutrally ("first row", never "header row"): whether the table has a header, and where (first
        // row, first column, elsewhere), is the model's reading. Only when it costs at most a quarter of a
        // work item (measured as a table of its own).
        List<TextUnit> header = rows.values().stream().flatMap(List::stream).filter(u -> cell(u).isHeaderRow()).toList();
        List<TextUnit> lead = !header.isEmpty() ? header : rows.firstEntry().getValue();
        int leadLength = PyStr.len(banner(false));
        for (List<TextUnit> row : rows(lead).values()) {
            leadLength += rowLength(row);
        }
        List<TextUnit> headerCopy = leadLength <= size / 4 ? lead : List.of();
        Set<Integer> copiedRows = rows(headerCopy).keySet();
        // A later group repeats the copy unless it holds the copied rows itself (see group()).
        int laterFrameWithHeader = frameLength(true, titleLine, List.of());
        int laterFrameWithCopy = frameLength(true, titleLine, headerCopy);

        List<TableGroup> groups = new ArrayList<>();
        List<TextUnit> current = new ArrayList<>();
        int currentLength = 0;
        boolean currentHoldsCopy = false;
        for (Map.Entry<Integer, List<TextUnit>> entry : rows.entrySet()) {
            List<TextUnit> row = entry.getValue();
            int length = rowLengths.get(entry.getKey());
            boolean rowIsCopied = copiedRows.contains(entry.getKey());
            if (frame(groups.isEmpty(), currentHoldsCopy || rowIsCopied, firstFrame, laterFrameWithHeader,
                    laterFrameWithCopy) + currentLength + length <= size) {
                current.addAll(row);
                currentLength += length;
                currentHoldsCopy |= rowIsCopied;
                continue;
            }
            if (!current.isEmpty()) {
                groups.add(group(part, index, current, title, headerCopy, copiedRows, groups.isEmpty()));
                current = new ArrayList<>();
                currentLength = 0;
                currentHoldsCopy = false;
            }
            int frame = frame(groups.isEmpty(), rowIsCopied, firstFrame, laterFrameWithHeader, laterFrameWithCopy);
            if (frame + length <= size) {
                current = new ArrayList<>(row);
                currentLength = length;
                currentHoldsCopy = rowIsCopied;
                continue;
            }
            // A row longer than a whole work item: cut between its cells (a cell is never cut). A run of the
            // row's cells renders from column 0, so its line is 1 + its text + " | " up to its last column.
            List<TextUnit> rowCells = new ArrayList<>(row);
            rowCells.sort(Comparator.comparingInt(u -> cell(u).colIndex()));
            List<TextUnit> run = new ArrayList<>();
            int runText = 0;
            for (TextUnit u : rowCells) {
                int cellText = PyStr.len(u.normalizedText());
                int withCell = 1 + runText + cellText + 3 * cell(u).colIndex();
                if (!run.isEmpty() && frame(groups.isEmpty(), rowIsCopied, firstFrame, laterFrameWithHeader,
                        laterFrameWithCopy) + withCell > size) {
                    groups.add(group(part, index, run, title, headerCopy, copiedRows, groups.isEmpty()));
                    run = new ArrayList<>();
                    runText = 0;
                }
                run.add(u);
                runText += cellText;
            }
            current = run;
            currentLength = 1 + runText + 3 * cell(run.getLast()).colIndex();
            currentHoldsCopy = rowIsCopied;
        }
        if (!current.isEmpty()) {
            groups.add(group(part, index, current, title, headerCopy, copiedRows, groups.isEmpty()));
        }
        return groups;
    }

    /** The frame of a group: the first one's, or a later one's holding the copied rows itself or with the copy. */
    private static int frame(boolean first, boolean holdsCopiedRows, int firstFrame, int laterFrameWithHeader,
                             int laterFrameWithCopy) {
        return first ? firstFrame : holdsCopiedRows ? laterFrameWithHeader : laterFrameWithCopy;
    }

    /** A row group: the first holds the copied rows itself; every later one carries a read-only copy of them. */
    private static TableGroup group(String part, int index, List<TextUnit> cells, TextUnit title,
                                    List<TextUnit> headerCopy, Set<Integer> copiedRows, boolean first) {
        boolean holdsCopiedRows = cells.stream().anyMatch(u -> copiedRows.contains(cell(u).rowIndex()));
        return new TableGroup(part, index, cells, title, first || holdsCopiedRows ? List.of() : headerCopy, !first);
    }
}
