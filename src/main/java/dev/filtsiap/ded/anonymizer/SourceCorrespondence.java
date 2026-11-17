package dev.filtsiap.ded.anonymizer;

import dev.filtsiap.ded.anonymizer.pycompat.PyStr;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.w3c.dom.Element;

/** In-memory provenance of surviving characters. Never serialized into the DOCX or diagnostics. */
final class SourceCorrespondence {
    private record Point(String unit, int offset) { }
    private record Match(TextUnit source, TextUnit output, int[] offsets) { }
    private record Tracked(XmlCharRef ref, Element root, Element node, Point point) { }
    private final Map<String, Match> matches;
    private final Map<String, TextUnit> aligned = new HashMap<>();

    private SourceCorrespondence(Map<String, Match> matches) {
        this.matches = java.util.Collections.unmodifiableMap(new LinkedHashMap<>(matches));
    }

    /** Capture actual element identities BEFORE edits/cleanup can remove nodes or change paths. */
    static final class Capture {
        private final DocumentData source;
        private final List<Tracked> tracked = new ArrayList<>();

        Capture(DocumentData source, Map<String, Element> parts) {
            this.source = source;
            Map<String, Element> nodes = new HashMap<>();
            for (TextUnit unit : source.textUnits()) {
                for (int i = 0; i < unit.charMap().size(); i++) {
                    XmlCharRef ref = unit.charMap().get(i);
                    Element root = parts.get(ref.partName());
                    if (root == null || ref.textNodePath().startsWith("<")) {
                        continue;
                    }
                    Element node = nodes.computeIfAbsent(ref.partName() + ":" + ref.textNodePath(),
                            k -> LxmlDom.findByElementPath(root, ref.textNodePath()));
                    if (node != null) {
                        tracked.add(new Tracked(ref, root, node, new Point(unit.unitId(), i)));
                    }
                }
            }
        }

        SourceCorrespondence finish(DocumentData output) {
            Map<XmlCharRef, Point> origins = new HashMap<>();
            Map<Element, String> paths = new java.util.IdentityHashMap<>();
            for (Tracked t : tracked) {
                String path = paths.computeIfAbsent(t.node(), node -> {
                    Element top = node;
                    while (LxmlDom.parent(top) != null) {
                        top = LxmlDom.parent(top);
                    }
                    return top == t.root() ? LxmlDom.elementPath(t.root(), node) : "";
                });
                if (!path.isEmpty()) {
                    XmlCharRef moved = new XmlCharRef(t.ref().partName(), path, t.ref().charIndex());
                    if (origins.putIfAbsent(moved, t.point()) != null) {
                        throw new DocumentProcessingError("duplicate physical character ownership", "INVALID_TEXT_MAPPING", null);
                    }
                }
            }
            Map<String, TextUnit> byId = new HashMap<>();
            source.textUnits().forEach(u -> byId.put(u.unitId(), u));
            Map<String, Match> found = new LinkedHashMap<>();
            for (TextUnit unit : output.textUnits()) {
                int[] offsets = new int[unit.charMap().size()];
                TextUnit from = null;
                boolean valid = offsets.length == PyStr.len(unit.normalizedText()) && offsets.length > 0;
                for (int i = 0; valid && i < offsets.length; i++) {
                    Point point = origins.get(unit.charMap().get(i));
                    if (point == null || (from != null && !from.unitId().equals(point.unit()))) {
                        valid = false;
                        break;
                    }
                    from = byId.get(point.unit());
                    offsets[i] = point.offset();
                    valid = from != null && (i == 0 || offsets[i] > offsets[i - 1]);
                }
                if (valid && compatible(from, unit, offsets)) {
                    found.put(unit.unitId(), new Match(from, unit, offsets));
                }
            }
            return new SourceCorrespondence(found);
        }
    }

    private static boolean compatible(TextUnit source, TextUnit output, int[] offsets) {
        if (!source.partName().equals(output.partName()) || source.unitType() != output.unitType()) {
            return false;
        }
        int[] was = source.normalizedText().codePoints().toArray();
        int[] now = output.normalizedText().codePoints().toArray();
        for (int i = 0; i < now.length; i++) {
            if (offsets[i] >= was.length || (now[i] != was[offsets[i]] && now[i] != '.')) {
                return false;
            }
        }
        return true;
    }

    /** Conservative legacy scan fallback: no relocation is inferred without a writer trace. */
    static SourceCorrespondence sameLocations(DocumentData source, DocumentData output) {
        Map<String, Match> found = new LinkedHashMap<>();
        if (source == null) {
            return new SourceCorrespondence(found);
        }
        Map<String, TextUnit> byId = new HashMap<>();
        source.textUnits().forEach(u -> byId.put(u.unitId(), u));
        for (TextUnit unit : output.textUnits()) {
            TextUnit from = byId.get(unit.unitId());
            int n = PyStr.len(unit.normalizedText());
            int[] offsets = java.util.stream.IntStream.range(0, n).toArray();
            if (from != null && PyStr.len(from.normalizedText()) == n && from.charMap().equals(unit.charMap())
                    && compatible(from, unit, offsets)) {
                found.put(unit.unitId(), new Match(from, unit, offsets));
            }
        }
        return new SourceCorrespondence(found);
    }

    /** Compose a second write with this trace, keeping the original source as the authority. */
    SourceCorrespondence then(SourceCorrespondence next) {
        Map<String, Match> found = new LinkedHashMap<>();
        for (Match after : next.matches.values()) {
            Match before = matches.get(after.source().unitId());
            if (before == null || !before.output().equals(after.source())) {
                continue;
            }
            int[] offsets = new int[after.offsets().length];
            for (int i = 0; i < offsets.length; i++) {
                offsets[i] = before.offsets()[after.offsets()[i]];
            }
            if (compatible(before.source(), after.output(), offsets)) {
                found.put(after.output().unitId(), new Match(before.source(), after.output(), offsets));
            }
        }
        return new SourceCorrespondence(found);
    }

    /** Exact, contiguous unchanged source slice; dots elsewhere do not vouch for this match. */
    boolean unchanged(String outputUnit, int start, int end) {
        Match match = matches.get(outputUnit);
        if (match == null || start < 0 || end > match.offsets().length || start >= end) {
            return false;
        }
        for (int i = start; i < end; i++) {
            if ((i > start && match.offsets()[i] != match.offsets()[i - 1] + 1)
                    || PyStr.codePointAt(match.source().normalizedText(), match.offsets()[i])
                    != PyStr.codePointAt(match.output().normalizedText(), i)) {
                return false;
            }
        }
        return true;
    }

    /** Surviving pieces of a source slice, now in output coordinates. */
    List<UnitSlice> translate(UnitSlice slice) {
        List<UnitSlice> out = new ArrayList<>();
        for (Match match : matches.values()) {
            if (!match.source().unitId().equals(slice.unitId())) {
                continue;
            }
            int start = -1;
            for (int i = 0; i <= match.offsets().length; i++) {
                boolean inside = i < match.offsets().length && match.offsets()[i] >= slice.start()
                        && match.offsets()[i] < slice.end();
                if (inside && start < 0) {
                    start = i;
                } else if (!inside && start >= 0) {
                    out.add(new UnitSlice(match.output().unitId(), start, i));
                    start = -1;
                }
            }
        }
        return out;
    }

    List<Span> translateSpans(List<Span> spans, boolean requireWrittenDots) {
        List<Span> out = new ArrayList<>();
        for (Span span : spans) {
            for (UnitSlice slice : translate(new UnitSlice(span.unitId(), span.start(), span.end()))) {
                String text = PyStr.slice(matches.get(slice.unitId()).output().normalizedText(), slice.start(), slice.end());
                if (!requireWrittenDots || text.codePoints().allMatch(cp -> cp == '.')) {
                    out.add(new Span(slice.unitId(), slice.start(), slice.end(), text, span.category(), span.detector(),
                            span.confidence(), span.action(), span.reason(), span.origin()));
                }
            }
        }
        return out;
    }

    /** Source text aligned to output units for the deterministic consistency audit; unknown units omitted. */
    TextUnit alignedSource(TextUnit output) {
        Match match = matches.get(output.unitId());
        if (match == null) {
            return null;
        }
        return aligned.computeIfAbsent(output.unitId(), id -> {
        StringBuilder text = new StringBuilder();
        int[] sourcePoints = match.source().normalizedText().codePoints().toArray();
        for (int offset : match.offsets()) {
            text.appendCodePoint(sourcePoints[offset]);
        }
        return new TextUnit(output.unitId(), output.partName(), output.unitType(), text.toString(), text.toString(),
                output.charMap(), output.location());
        });
    }
}
