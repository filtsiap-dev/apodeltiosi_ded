# Chat Text Anonymizer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `POST /anonymize-text` to the existing Java service. It masks personal data in chatbot conversation text with `.` and uses no LLM.

**Architecture:** A new package, `dev.filtsiap.ded.anonymizer.chat`, holds independent detectors. Each detector returns code-point spans:
- the reused `.docx` ID detectors, plus new chat ID regexes;
- addresses and places;
- Greek names: a Wikidata name list, plus "uncommon word" checks against the Hunspell dictionaries;
- an optional NER slot that is off by default.

The spans are merged as a plain **union**, masked, and re-scanned with the existing post-check patterns. Word lists are generated offline by a Java tool into `config/chat/` and loaded once at startup. A 100-entry dataset in `eval/chat-anonymization/` scores the result.

**Tech Stack:** Java 21 (CI/Docker on 24), Maven, JUnit 6, SnakeYAML 2.4, Jackson (all already in `pom.xml`). There are no new runtime dependencies.

**Spec:** `docs/superpowers/specs/2026-10-09-chat-text-anonymizer-design.md`

## Deviations from the spec (decided while planning; confirm at review)

1. **Union instead of `Resolver`.** `Resolver.priority` drops any REDACT span below `redact_threshold` (0.7). An AFM that fails its checksum is proposed at 0.4. In the `.docx` flow, pass 2 adjudicates such spans; in chat there is no LLM, so the Resolver would let them leak. Chat therefore masks the union of every REDACT and REVIEW span. PRESERVE spans (public email domains) are dropped.
2. **Settings live in `config/chat/chat.yaml`, not `policy.yaml`.** `policy.yaml` is validated strictly and is part of the `.docx` provenance hash. For the same reason, chat regexes are code constants and are not overridable through `regex_patterns.yaml` (`Config.validatePatterns` only knows `DetectorPatterns.DEFAULT_PATTERNS`).
3. **`GreekFold` is length-preserving.** Each code point is folded on its own, so a folded offset is the original offset. No offset map is needed.
4. **The "names that are also common words" stoplist is computed at lookup time** (`isName && isCommonWord`) rather than written as a file.
5. **Package:** `dev.filtsiap.ded.anonymizer.chat`, mirroring `…anonymizer.llm`.
6. **Eval reports go to `target/chat-eval/`** (build output), not into the source tree.
7. **The list builder is Java, in test scope** (`src/test/java/…/chat/build/`), so the repo stays Java-only and the builder is unit-tested.

## Global Constraints

- `maven.compiler.release` stays **21**; no new dependencies in `pom.xml`.
- Mask character is **`.`**. Output has the **same code-point length** as the NFC-normalised input. Whitespace (spaces, tabs, `\r`, `\n`) inside a masked span stays as it is.
- Offsets are **code points**, never UTF-16 indices. Use `PyRegex`, whose `PyMatch.start()/end()` are code points, and `String.codePoints()`.
- **Never log, echo or put in a header any input text.** Headers carry only ids, enums and integers.
- `/anonymize-text` makes **no LLM calls**.
- **Recall first.** Spans are a union, and NER may only add spans.
- Licences: Wikidata **CC0**; LibreOffice Hunspell `el_GR` **MPL 1.1** (we take MPL from its MPL/GPL/LGPL tri-licence); LibreOffice `en_US` (SCOWL, permissive). **No non-commercial data.**
- Same bearer auth as `POST /anonymize` (`ANON_API_KEY`).
- Out of scope for v1: Greeklish, date of birth (dataset T094 is an expected leak), NER adapters (only the interface ships).

## Review Focus

1. **Emoji or other non-BMP characters before personal data:** a UTF-16 vs code-point mix-up would shift every mask to the wrong characters. Pinned in Task 1 (`MaskerTest`), Task 8 (`ChatPipelineTest.emojiDoesNotShiftMasks`) and Task 9 (`crlfAndEmojiSurviveTheRoundTrip`).
2. **Decomposed (NFD) Greek input** from some clients (`α` + U+0301): lexicon lookups would miss and names would leak. Pinned in Task 8 (`nfdInputIsNormalisedBeforeMatching`).
3. **Non-UTF-8 or wrongly declared bodies** (`charset=iso-8859-7`, invalid bytes) must get 415/400, never garbled masking. Pinned in Task 9.
4. **Huge or pathological input** (400k characters, long digit/space runs, one 50k-letter word) must finish in seconds. Pinned in Task 8 (`longInputStaysFast`).
5. **Windows CRLF transcripts** (`Χρήστης: …\r\nBot: …`): a speaker change ends a sentence, so a place cue on one line must not mask the next line, and `\r\n` must survive. Pinned in Task 6 (`aLineBreakEndsTheResidenceClause`) and Task 9.

---

## File map

| File | Responsibility |
|---|---|
| `src/main/java/dev/filtsiap/ded/anonymizer/chat/PiiType.java` | What a span is (names equal the dataset's `type` values) |
| `…/chat/ChatSpan.java` | `[start, end)` code-point range + type + detector name |
| `…/chat/Masker.java` | Union mask, per-type counts, counts header |
| `…/chat/GreekFold.java` | Length-preserving lowercase/accent/final-sigma fold |
| `…/chat/GreekInflection.java` | Name paradigms: `forms(nominative)`, `family(anyForm)` |
| `…/chat/WordSet.java` | Compact sorted word set; gz loading; one-edit lookup |
| `…/chat/ChatLists.java` | All lists for the name detector; `load(dir)` / `of(...)` |
| `…/chat/ChatSettings.java` | `config/chat/chat.yaml` (NER switch) |
| `…/chat/Checksums.java` | Luhn, AMKA, digits-only |
| `…/chat/IdDetector.java` | Reused `.docx` ID detectors + chat ID regexes |
| `…/chat/AddressDetector.java` | Street + number, km addresses, residence cues, postal codes |
| `…/chat/NameDetector.java` | Cues, name lists, uncommon words, neighbours, propagation |
| `…/chat/NerDetector.java`, `NerUnavailableException.java` | NER slot (interface + `NONE`) |
| `…/chat/ResidualCheck.java` | Post-mask scan with `PostcheckPatterns.QA_PATTERNS` |
| `…/chat/ChatPipeline.java` | Orchestration, modes, status |
| `src/main/java/dev/filtsiap/ded/api/ApiHandler.java` | Route, `readText`, `anonymizeText`, `textReply` |
| `src/main/java/dev/filtsiap/ded/api/ApiServer.java` | Load chat lists at startup, wire the pipeline |
| `src/main/java/dev/filtsiap/ded/anonymizer/DetectorSupport.java` | Make `validAfm`, `validAmkaBirthDate` public |
| `src/main/java/dev/filtsiap/ded/anonymizer/PostcheckPatterns.java` | Make class and `QA_PATTERNS` public |
| `src/test/java/dev/filtsiap/ded/anonymizer/chat/build/*` | Hunspell expander + list builder (dev tool) |
| `config/chat/*` | Generated lists, hand lists, `chat.yaml`, `README.md` |
| `src/test/java/dev/filtsiap/ded/anonymizer/chat/*Test.java` | Unit, dataset and eval tests |

Test helpers shared by several tasks are created in Task 1 (`ChatAsserts`) and Task 3 (`ChatFixtures`).

---

### Task 1: Spans, union masking and counts

**Files:**
- Create: `src/main/java/dev/filtsiap/ded/anonymizer/chat/PiiType.java`
- Create: `src/main/java/dev/filtsiap/ded/anonymizer/chat/ChatSpan.java`
- Create: `src/main/java/dev/filtsiap/ded/anonymizer/chat/Masker.java`
- Test: `src/test/java/dev/filtsiap/ded/anonymizer/chat/ChatAsserts.java`
- Test: `src/test/java/dev/filtsiap/ded/anonymizer/chat/MaskerTest.java`

**Interfaces:**
- Produces:
  - `enum PiiType { PERSON, LOCATION, ADDRESS, POSTAL_CODE, AFM, AMKA, IBAN, BANK_ACCOUNT, PHONE, EMAIL, ID_CARD, PASSPORT, PLATE, GEMI, CARD, CUSTOMER_NO, DOB, ORG_PERSONAL, OTHER }`
  - `record ChatSpan(int start, int end, PiiType type, String detector)`
  - `Masker.mask(String text, List<ChatSpan> spans) -> String`
  - `Masker.counts(List<ChatSpan>) -> Map<PiiType,Integer>` (an `EnumMap`)
  - `Masker.countsHeader(Map<PiiType,Integer>) -> String`
  - Test helpers: `ChatAsserts.dots(String)`, `ChatAsserts.expect(String text, String... maskedParts)`

- [ ] **Step 1: Write the test helper and the failing tests**

`src/test/java/dev/filtsiap/ded/anonymizer/chat/ChatAsserts.java`:
```java
package dev.filtsiap.ded.anonymizer.chat;

/** Builds expected masked strings without counting dots by hand. */
final class ChatAsserts {
    private ChatAsserts() {
    }

    /** {@code s} with every non-whitespace code point replaced by '.', as Masker does. */
    static String dots(String s) {
        StringBuilder b = new StringBuilder();
        s.codePoints().forEach(cp -> b.appendCodePoint(Character.isWhitespace(cp) ? cp : '.'));
        return b.toString();
    }

    /**
     * {@code text} with every occurrence of each part masked. List a longer part before a part it
     * contains ("γιώργος" before "γιώργο"), or the shorter one is replaced inside it first.
     */
    static String expect(String text, String... maskedParts) {
        String out = text;
        for (String part : maskedParts) {
            out = out.replace(part, dots(part));
        }
        return out;
    }
}
```

`src/test/java/dev/filtsiap/ded/anonymizer/chat/MaskerTest.java`:
```java
package dev.filtsiap.ded.anonymizer.chat;

import static dev.filtsiap.ded.anonymizer.chat.ChatAsserts.expect;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class MaskerTest {

    private static ChatSpan span(int start, int end, PiiType type) {
        return new ChatSpan(start, end, type, "test");
    }

    @Test
    void masksEveryNonWhitespaceCodePointInsideSpans() {
        String text = "με λένε Γιώργο Παπαδόπουλο";
        assertEquals(expect(text, "Γιώργο Παπαδόπουλο"), Masker.mask(text, List.of(span(8, 26, PiiType.PERSON))));
    }

    @Test
    void overlappingSpansAreAUnion() {
        String text = "abcdefgh";
        assertEquals("........", Masker.mask(text, List.of(span(0, 4, PiiType.PERSON), span(2, 6, PiiType.AFM),
                span(6, 8, PiiType.PHONE))));
        assertEquals("a...efgh", Masker.mask(text, List.of(span(1, 3, PiiType.PERSON), span(2, 4, PiiType.AFM))));
    }

    @Test
    void offsetsAreCodePointsSoEmojiDoNotShiftTheMask() {
        String text = "🙏 090000045";
        assertEquals("🙏 .........", Masker.mask(text, List.of(span(2, 11, PiiType.AFM))));
    }

    @Test
    void outputKeepsLineBreaksAndCodePointLength() {
        String text = "a\r\nb";
        String masked = Masker.mask(text, List.of(span(0, 4, PiiType.OTHER)));
        assertEquals(".\r\n.", masked);
        assertEquals(text.codePointCount(0, text.length()), masked.codePointCount(0, masked.length()));
    }

    @Test
    void spansPastTheEndAreClamped() {
        assertEquals("a..", Masker.mask("abc", List.of(span(1, 99, PiiType.OTHER))));
    }

    @Test
    void countsMergeOverlappingAndTouchingRegionsPerType() {
        Map<PiiType, Integer> counts = Masker.counts(List.of(span(0, 3, PiiType.PERSON), span(2, 5, PiiType.PERSON),
                span(5, 6, PiiType.PERSON), span(8, 9, PiiType.PERSON), span(0, 3, PiiType.AFM),
                span(4, 4, PiiType.PHONE)));
        assertEquals(Map.of(PiiType.PERSON, 2, PiiType.AFM, 1), counts);
        assertEquals("PERSON=2,AFM=1", Masker.countsHeader(counts));
    }

    @Test
    void noSpansGiveTheNoneHeader() {
        assertEquals("none", Masker.countsHeader(Masker.counts(List.of())));
    }

    @Test
    void aSpanMustBeAForwardRange() {
        assertThrows(IllegalArgumentException.class, () -> span(5, 4, PiiType.PERSON));
        assertThrows(IllegalArgumentException.class, () -> span(-1, 4, PiiType.PERSON));
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `mvn -q -Dtest=MaskerTest test`
Expected: compilation failure, `cannot find symbol: class ChatSpan`.

- [ ] **Step 3: Implement**

`src/main/java/dev/filtsiap/ded/anonymizer/chat/PiiType.java`:
```java
package dev.filtsiap.ded.anonymizer.chat;

/** What a masked span was. The names equal the {@code type} values of eval/chat-anonymization/dataset.jsonl. */
public enum PiiType {
    PERSON, LOCATION, ADDRESS, POSTAL_CODE,
    AFM, AMKA, IBAN, BANK_ACCOUNT, PHONE, EMAIL,
    ID_CARD, PASSPORT, PLATE, GEMI, CARD, CUSTOMER_NO,
    DOB, ORG_PERSONAL,
    /** A residual digit run, or a NER label with no more specific type. */
    OTHER
}
```

`src/main/java/dev/filtsiap/ded/anonymizer/chat/ChatSpan.java`:
```java
package dev.filtsiap.ded.anonymizer.chat;

import java.util.Objects;

/**
 * A half-open range {@code [start, end)} of CODE POINTS of the NFC-normalised input that must be
 * masked. {@code detector} is a diagnostic name only; nothing arbitrates on it.
 */
public record ChatSpan(int start, int end, PiiType type, String detector) {
    public ChatSpan {
        if (start < 0 || end < start) {
            throw new IllegalArgumentException("not a forward range: " + start + ".." + end);
        }
        Objects.requireNonNull(type, "type");
        Objects.requireNonNull(detector, "detector");
    }
}
```

`src/main/java/dev/filtsiap/ded/anonymizer/chat/Masker.java`:
```java
package dev.filtsiap.ded.anonymizer.chat;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.StringJoiner;

/**
 * Applies spans as a UNION: a code point inside any span is masked, whoever proposed it. There is
 * no arbitration here on purpose (see the plan's deviation 1): chat has no adjudicator, so every
 * proposal counts.
 */
public final class Masker {
    public static final int MASK = '.';

    private Masker() {
    }

    /** Every non-whitespace code point inside any span becomes '.'; the code-point length is unchanged. */
    public static String mask(String text, List<ChatSpan> spans) {
        int[] cps = text.codePoints().toArray();
        for (ChatSpan s : spans) {
            int end = Math.min(s.end(), cps.length);
            for (int i = s.start(); i < end; i++) {
                if (!Character.isWhitespace(cps[i])) {
                    cps[i] = MASK;
                }
            }
        }
        return new String(cps, 0, cps.length);
    }

    /** Per type, the number of separate regions: overlapping or touching spans of one type count once. */
    public static Map<PiiType, Integer> counts(List<ChatSpan> spans) {
        Map<PiiType, List<ChatSpan>> byType = new EnumMap<>(PiiType.class);
        for (ChatSpan s : spans) {
            if (s.end() > s.start()) {
                byType.computeIfAbsent(s.type(), k -> new ArrayList<>()).add(s);
            }
        }
        Map<PiiType, Integer> counts = new EnumMap<>(PiiType.class);
        byType.forEach((type, list) -> {
            list.sort(Comparator.comparingInt(ChatSpan::start));
            int regions = 0;
            int reach = -1;
            for (ChatSpan s : list) {
                if (s.start() > reach) {
                    regions++;
                }
                reach = Math.max(reach, s.end());
            }
            counts.put(type, regions);
        });
        return counts;
    }

    /** {@code PERSON=2,AFM=1} in {@link PiiType} declaration order, or {@code none}. */
    public static String countsHeader(Map<PiiType, Integer> counts) {
        if (counts.isEmpty()) {
            return "none";
        }
        StringJoiner joined = new StringJoiner(",");
        new EnumMap<>(counts).forEach((type, n) -> joined.add(type.name() + "=" + n));
        return joined.toString();
    }
}
```

`countsHeader` copies its argument into a new `EnumMap`. `new EnumMap<>(Map)` throws on an empty non-`EnumMap` map, which is why the empty case returns early. An `EnumMap` compares equal to a `Map.of` with the same entries.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `mvn -q -Dtest=MaskerTest test`
Expected: `Tests run: 8, Failures: 0, Errors: 0`.

- [ ] **Step 5: Commit**

```bash
git add src/main/java/dev/filtsiap/ded/anonymizer/chat src/test/java/dev/filtsiap/ded/anonymizer/chat
git commit -m "Add chat spans and union masking for /anonymize-text"
```

---

### Task 2: Greek folding and name inflection

**Files:**
- Create: `src/main/java/dev/filtsiap/ded/anonymizer/chat/GreekFold.java`
- Create: `src/main/java/dev/filtsiap/ded/anonymizer/chat/GreekInflection.java`
- Test: `src/test/java/dev/filtsiap/ded/anonymizer/chat/GreekFoldTest.java`
- Test: `src/test/java/dev/filtsiap/ded/anonymizer/chat/GreekInflectionTest.java`

**Interfaces:**
- Produces:
  - `GreekFold.fold(String) -> String`: same code-point length; lowercase, no accents, σ for ς.
  - `GreekInflection.forms(String foldedNominative) -> Set<String>`
  - `GreekInflection.family(String foldedAnyForm) -> Set<String>`

- [ ] **Step 1: Write the failing tests**

`src/test/java/dev/filtsiap/ded/anonymizer/chat/GreekFoldTest.java`:
```java
package dev.filtsiap.ded.anonymizer.chat;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class GreekFoldTest {

    private static int cpLen(String s) {
        return s.codePointCount(0, s.length());
    }

    @Test
    void lowercasesStripsAccentsAndFinalSigma() {
        assertEquals("γιωργοσ παπαδοπουλοσ", GreekFold.fold("Γιώργος ΠΑΠΑΔΌΠΟΥΛΟΣ"));
        assertEquals("ιι υυ", GreekFold.fold("ΐΪ ΰΫ"));
        assertEquals("john", GreekFold.fold("John"));
    }

    @Test
    void keepsCodePointLengthWithEmojiAndMarks() {
        for (String s : new String[] {"🙏 ΑΦΜ 090000045", "ά́x", "Ελένη\r\nBot", ""}) {
            assertEquals(cpLen(s), cpLen(GreekFold.fold(s)), s);
        }
        assertEquals("🙏 αφμ 090000045", GreekFold.fold("🙏 ΑΦΜ 090000045"));
    }
}
```

`src/test/java/dev/filtsiap/ded/anonymizer/chat/GreekInflectionTest.java`:
```java
package dev.filtsiap.ded.anonymizer.chat;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Set;
import org.junit.jupiter.api.Test;

class GreekInflectionTest {

    @Test
    void formsFollowTheNominativeParadigm() {
        assertEquals(Set.of("γιωργοσ", "γιωργου", "γιωργο", "γιωργε"), GreekInflection.forms("γιωργοσ"));
        assertEquals(Set.of("δημητρησ", "δημητρη"), GreekInflection.forms("δημητρησ"));
        assertEquals(Set.of("νικολασ", "νικολα"), GreekInflection.forms("νικολασ"));
        assertEquals(Set.of("μαρια", "μαριασ"), GreekInflection.forms("μαρια"));
        assertEquals(Set.of("ελενη", "ελενησ"), GreekInflection.forms("ελενη"));
    }

    @Test
    void invariantNamesHaveOneForm() {
        assertEquals(Set.of("παπαδοπουλου"), GreekInflection.forms("παπαδοπουλου"));
        assertEquals(Set.of("john"), GreekInflection.forms("john"));
    }

    @Test
    void familyRecoversEveryFormFromAnyForm() {
        assertTrue(GreekInflection.family("στελιο").containsAll(Set.of("στελιοσ", "στελιου", "στελιε")));
        assertTrue(GreekInflection.family("μανωλη").contains("μανωλησ"));
        assertTrue(GreekInflection.family("παπαδοπουλου").contains("παπαδοπουλοσ"));
        assertEquals(Set.of("ab"), GreekInflection.family("ab"));
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `mvn -q -Dtest="GreekFoldTest,GreekInflectionTest" test`
Expected: compilation failure, `cannot find symbol: class GreekFold`.

- [ ] **Step 3: Implement**

`src/main/java/dev/filtsiap/ded/anonymizer/chat/GreekFold.java`:
```java
package dev.filtsiap.ded.anonymizer.chat;

import java.text.Normalizer;

/**
 * The matching form of a text: lowercase, no accents or diaeresis, σ for ς. It has EXACTLY the
 * input's code-point length, so a match offset in the fold is the same offset in the input. Each
 * code point is folded alone: the first code point of its NFD decomposition, lowercased. A lone
 * combining mark (one NFC could not compose) is kept as it is. Like DetectorPatterns.foldGreek,
 * but length-preserving, and with Character.toLowerCase instead of casefold (which can expand).
 */
public final class GreekFold {
    private GreekFold() {
    }

    public static String fold(String text) {
        StringBuilder out = new StringBuilder(text.length());
        text.codePoints().forEach(cp -> out.appendCodePoint(foldCodePoint(cp)));
        return out.toString();
    }

    static int foldCodePoint(int cp) {
        if (cp < 0x80) {
            return Character.toLowerCase(cp);
        }
        if (Character.getType(cp) == Character.NON_SPACING_MARK) {
            return cp;
        }
        String nfd = Normalizer.normalize(new String(Character.toChars(cp)), Normalizer.Form.NFD);
        int base = Character.toLowerCase(nfd.codePointAt(0));
        return base == 'ς' ? 'σ' : base;
    }
}
```

`src/main/java/dev/filtsiap/ded/anonymizer/chat/GreekInflection.java`:
```java
package dev.filtsiap.ded.anonymizer.chat;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * The few paradigms Greek first names and surnames follow, on FOLDED forms (no accents, σ for ς).
 * Enough to expand a Wikidata nominative ("γιωργοσ") into what people type ("γιωργο", "γιωργου"),
 * and to find a confirmed name's other forms in the same text.
 */
public final class GreekInflection {
    /** Nominative ending, then every ending of its paradigm (the nominative first). */
    private static final List<Map.Entry<String, List<String>>> PARADIGMS = List.of(
            Map.entry("ουσ", List.of("ουσ", "ου")),
            Map.entry("οσ", List.of("οσ", "ου", "ο", "ε")),
            Map.entry("ησ", List.of("ησ", "η")),
            Map.entry("ασ", List.of("ασ", "α")),
            Map.entry("εσ", List.of("εσ", "ε")),
            Map.entry("α", List.of("α", "ασ")),
            Map.entry("η", List.of("η", "ησ")),
            Map.entry("ω", List.of("ω", "ωσ")));

    /** A stem shorter than this is not inflected ("ο", "η" are words, not stems). */
    private static final int MIN_STEM = 2;

    private GreekInflection() {
    }

    /** Every form of a nominative; an ending no paradigm knows ("-ου" surnames, foreign names) is invariant. */
    public static Set<String> forms(String foldedNominative) {
        Set<String> out = new TreeSet<>();
        out.add(foldedNominative);
        for (Map.Entry<String, List<String>> p : PARADIGMS) {
            String nominative = p.getKey();
            if (foldedNominative.endsWith(nominative)
                    && foldedNominative.length() - nominative.length() >= MIN_STEM) {
                String stem = foldedNominative.substring(0, foldedNominative.length() - nominative.length());
                p.getValue().forEach(e -> out.add(stem + e));
                return out;
            }
        }
        return out;
    }

    /** Every form of every nominative {@code foldedAnyForm} could be a form of. Over-generates on purpose. */
    public static Set<String> family(String foldedAnyForm) {
        Set<String> out = new TreeSet<>();
        out.add(foldedAnyForm);
        for (Map.Entry<String, List<String>> p : PARADIGMS) {
            for (String ending : p.getValue()) {
                if (foldedAnyForm.endsWith(ending) && foldedAnyForm.length() - ending.length() >= MIN_STEM) {
                    String stem = foldedAnyForm.substring(0, foldedAnyForm.length() - ending.length());
                    p.getValue().forEach(e -> out.add(stem + e));
                }
            }
        }
        return out;
    }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `mvn -q -Dtest="GreekFoldTest,GreekInflectionTest" test`
Expected: `Tests run: 5, Failures: 0, Errors: 0`.

- [ ] **Step 5: Commit**

```bash
git add src/main/java/dev/filtsiap/ded/anonymizer/chat src/test/java/dev/filtsiap/ded/anonymizer/chat
git commit -m "Add length-preserving Greek fold and name inflection"
```

---

### Task 3: Word sets, chat lists and chat settings

**Files:**
- Create: `src/main/java/dev/filtsiap/ded/anonymizer/chat/WordSet.java`
- Create: `src/main/java/dev/filtsiap/ded/anonymizer/chat/ChatLists.java`
- Create: `src/main/java/dev/filtsiap/ded/anonymizer/chat/ChatSettings.java`
- Create: `config/chat/chat.yaml`
- Test: `src/test/java/dev/filtsiap/ded/anonymizer/chat/WordSetTest.java`
- Test: `src/test/java/dev/filtsiap/ded/anonymizer/chat/ChatListsTest.java`
- Test: `src/test/java/dev/filtsiap/ded/anonymizer/chat/ChatSettingsTest.java`
- Test: `src/test/java/dev/filtsiap/ded/anonymizer/chat/ChatFixtures.java`

**Interfaces:**
- Consumes: `GreekFold.fold`, `GreekInflection.forms` (Task 2).
- Produces:
  - `WordSet.of(Collection<String>)`: folds, dedupes, sorts.
  - `WordSet.loadSorted(Path)`: a generated file; `.gz` allowed; must already be folded, sorted and unique.
  - `WordSet.loadList(Path)`: a hand file; `#` comments; any order; folded on load.
  - `contains(String folded)`, `containsWithinOneEdit(String folded)`, `size()`, `footprintBytes()`.
  - `record ChatLists(WordSet givenNames, WordSet surnames, WordSet greekCommon, WordSet greekProper, WordSet englishCommon, WordSet allow)`, with `load(Path chatDir)`, `of(...)`, `isName(f)`, `isCommonWord(f)` and `footprintBytes()`.
  - `record ChatSettings(boolean nerEnabled, String nerProvider, double nerMinConfidence, int nerTimeoutMs)` with `load(Path chatDir)` and `DEFAULTS`.
  - Test fixture: `ChatFixtures.LISTS` (a small hand-made `ChatLists`).

The generated file names under `config/chat/` are: `given_names.txt`, `surnames.txt`, `el_common.txt.gz`, `el_proper.txt.gz`, `en_common.txt.gz`. The hand-kept ones are `slang.txt` and `domain_allowlist.txt`.

- [ ] **Step 1: Write the failing tests**

`src/test/java/dev/filtsiap/ded/anonymizer/chat/WordSetTest.java`:
```java
package dev.filtsiap.ded.anonymizer.chat;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.filtsiap.ded.anonymizer.ConfigurationError;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.zip.GZIPOutputStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class WordSetTest {

    @TempDir
    Path dir;

    @Test
    void ofFoldsDedupesAndFinds() {
        WordSet set = WordSet.of(List.of("Λογαριασμός", "λογαριασμος", "πλάκα", " "));
        assertEquals(2, set.size());
        assertTrue(set.contains("λογαριασμοσ"));
        assertTrue(set.contains("πλακα"));
        assertFalse(set.contains("πλακ"));
        assertFalse(set.contains("πλακασ"));
        assertFalse(set.contains(""));
    }

    @Test
    void oneEditCoversSubstitutionInsertionDeletionAndTransposition() {
        WordSet set = WordSet.of(List.of("λογαριασμοσ"));
        assertTrue(set.containsWithinOneEdit("λογαριασμοσ"));
        assertTrue(set.containsWithinOneEdit("λογαριασμασ"));   // substitution
        assertTrue(set.containsWithinOneEdit("λογαριασμοοσ"));  // insertion
        assertTrue(set.containsWithinOneEdit("λογαριαμοσ"));    // deletion
        assertTrue(set.containsWithinOneEdit("λογαριασομσ"));   // transposition
        assertFalse(set.containsWithinOneEdit("λογαριαμασ"));   // two edits
    }

    @Test
    void loadsSortedPlainAndGzipFiles() throws Exception {
        Path plain = dir.resolve("a.txt");
        Files.writeString(plain, "αβγ\nδεζ\n", StandardCharsets.UTF_8);
        Path gz = dir.resolve("b.txt.gz");
        try (OutputStream out = new GZIPOutputStream(Files.newOutputStream(gz))) {
            out.write("αβγ\nδεζ\n".getBytes(StandardCharsets.UTF_8));
        }
        assertTrue(WordSet.loadSorted(plain).contains("δεζ"));
        assertTrue(WordSet.loadSorted(gz).contains("αβγ"));
    }

    @Test
    void anUnsortedOrUnfoldedGeneratedFileIsAConfigurationError() throws Exception {
        Path unsorted = dir.resolve("u.txt");
        Files.writeString(unsorted, "δεζ\nαβγ\n", StandardCharsets.UTF_8);
        assertThrows(ConfigurationError.class, () -> WordSet.loadSorted(unsorted));
        Path unfolded = dir.resolve("f.txt");
        Files.writeString(unfolded, "Άλφα\n", StandardCharsets.UTF_8);
        assertThrows(ConfigurationError.class, () -> WordSet.loadSorted(unfolded));
    }

    @Test
    void handListsSkipCommentsAndFold() throws Exception {
        Path list = dir.resolve("h.txt");
        Files.writeString(list, "# telecom words\nΔΕΗ\n\niPhone  # a phone\n", StandardCharsets.UTF_8);
        WordSet set = WordSet.loadList(list);
        assertTrue(set.contains("δεη"));
        assertTrue(set.contains("iphone"));
        assertEquals(2, set.size());
    }

    @Test
    void footprintIsCharsPlusOffsets() {
        WordSet set = WordSet.of(List.of("ab", "cde"));
        assertEquals(5 * 2 + 3 * 4, set.footprintBytes());
    }
}
```

`src/test/java/dev/filtsiap/ded/anonymizer/chat/ChatFixtures.java`:
```java
package dev.filtsiap.ded.anonymizer.chat;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

/**
 * A small, hand-made ChatLists for unit tests. Every ordinary word the unit tests use must be in
 * GREEK or ENGLISH below, or the uncommon-word rule masks it; that is the point of the rule.
 */
final class ChatFixtures {
    private ChatFixtures() {
    }

    static List<String> words(String spaceSeparated) {
        return Arrays.asList(spaceSeparated.trim().split("\\s+"));
    }

    /** Nominatives expanded through GreekInflection, as the list builder does. */
    static List<String> names(String nominatives) {
        return words(nominatives).stream().map(GreekFold::fold)
                .flatMap(n -> GreekInflection.forms(n).stream()).collect(Collectors.toList());
    }

    static final String GREEK = """
            καλησπέρα με λένε και θέλω να ακυρώσω τη συνδρομή η μου είπε ότι το πρόβλημα λύθηκε ομάδα
            πήρε νίκη χθες οπότε είμαι χαρούμενος δεν έχω καμία ελπίδα λυθεί αυτό θέμα σοφία της όμως
            βοηθά εδώ είναι μητέρα ήλιος σήμερα καίει ο στο γραφείο ευχαριστώ πολύ ήσουν εξυπηρετική γεια
            σας κύριε κυρία από τον την του τμήμα μίλησα λογιστήριο απαντά πελάτης χρόνια γιος πώς μπορώ
            βοηθήσω κόρη ονομάζομαι λέγομαι υπογραφή πλατεία πλάκα έχει που λογαριασμός ήρθε διπλός
            σούπερ μάρκετ κοντά μένω μένει στην κατάστημα έχετε δάφνη θα γιορτή πολλά για αγίου άγιος
            γιορτή εκκλησία απέναντι οδός οδό στη κατοικώ ζω δουλεύω αλλά νέα διεύθυνση ειρήνη ησυχία
            όχι άλλα τηλεφωνήματα φορές αριθμός
            """;

    static final String ENGLISH = "hi i m can you help me with my bill smith bot ok thanks for the";

    static final ChatLists LISTS = ChatLists.of(
            names("Γιώργος Μαρία Ελένη Νίκη Ελπίδα Σοφία Αναστασία Ηλίας Στέλιος Φωτεινή Δάφνη Αθηνά"),
            names("Παπαδόπουλος Παππάς"),
            words(GREEK),
            words("Αθήνα Αμερική Αμερικής Ιούνιος Ιουνίου Πάσχα Ελλάδα Λάρισα"),
            words(ENGLISH),
            words("κλπ τηλ αφμ αμκα δεη ευδαπ iphone android"));
}
```

`src/test/java/dev/filtsiap/ded/anonymizer/chat/ChatListsTest.java`:
```java
package dev.filtsiap.ded.anonymizer.chat;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.filtsiap.ded.anonymizer.ConfigurationError;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ChatListsTest {

    @TempDir
    Path dir;

    @Test
    void namesAndCommonWordsAreSeparateQuestions() {
        ChatLists lists = ChatFixtures.LISTS;
        assertTrue(lists.isName("γιωργο"));
        assertFalse(lists.isCommonWord("γιωργο"));
        assertTrue(lists.isName("νικη"));
        assertTrue(lists.isCommonWord("νικη"));   // a name that is also a word: needs a cue
        assertTrue(lists.isCommonWord("bill"));
        assertTrue(lists.isCommonWord("δεη"));    // allowlisted
        assertTrue(lists.greekProper().contains("αμερικησ"));
    }

    @Test
    void loadReadsEveryFile() throws Exception {
        writeAll(dir);
        ChatLists lists = ChatLists.load(dir);
        assertTrue(lists.isName("γιωργοσ"));
        assertTrue(lists.isCommonWord("πλακα"));
        assertTrue(lists.isCommonWord("viber"));
    }

    @Test
    void aMissingFileStopsStartup() throws Exception {
        writeAll(dir);
        Files.delete(dir.resolve("el_common.txt.gz"));
        ConfigurationError e = assertThrows(ConfigurationError.class, () -> ChatLists.load(dir));
        assertTrue(e.getMessage().contains("el_common.txt.gz"));
    }

    static void writeAll(Path dir) throws Exception {
        Files.writeString(dir.resolve("given_names.txt"), "γιωργο\nγιωργοσ\n", StandardCharsets.UTF_8);
        Files.writeString(dir.resolve("surnames.txt"), "παπαδοπουλοσ\n", StandardCharsets.UTF_8);
        gz(dir.resolve("el_common.txt.gz"), "πλακα\n");
        gz(dir.resolve("el_proper.txt.gz"), "αθηνα\n");
        gz(dir.resolve("en_common.txt.gz"), "bill\n");
        Files.writeString(dir.resolve("slang.txt"), "κλπ\n", StandardCharsets.UTF_8);
        Files.writeString(dir.resolve("domain_allowlist.txt"), "Viber\n", StandardCharsets.UTF_8);
    }

    static void gz(Path path, String content) throws Exception {
        try (var out = new java.util.zip.GZIPOutputStream(Files.newOutputStream(path))) {
            out.write(content.getBytes(StandardCharsets.UTF_8));
        }
    }
}
```

`src/test/java/dev/filtsiap/ded/anonymizer/chat/ChatSettingsTest.java`:
```java
package dev.filtsiap.ded.anonymizer.chat;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import dev.filtsiap.ded.anonymizer.ConfigurationError;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ChatSettingsTest {

    @TempDir
    Path dir;

    @Test
    void aMissingFileMeansDefaultsWithNerOff() {
        assertEquals(ChatSettings.DEFAULTS, ChatSettings.load(dir));
        assertFalse(ChatSettings.DEFAULTS.nerEnabled());
    }

    @Test
    void theShippedFileLoadsWithNerOff() {
        assertFalse(ChatSettings.load(Path.of("config", "chat")).nerEnabled());
    }

    @Test
    void enablingNerWithoutAProviderStopsStartup() throws Exception {
        Files.writeString(dir.resolve("chat.yaml"), "ner:\n  enabled: true\n  provider: none\n");
        assertThrows(ConfigurationError.class, () -> ChatSettings.load(dir));
    }

    @Test
    void aConfidenceOutsideZeroToOneIsRejected() throws Exception {
        Files.writeString(dir.resolve("chat.yaml"), "ner:\n  min_confidence: 1.5\n");
        assertThrows(ConfigurationError.class, () -> ChatSettings.load(dir));
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `mvn -q -Dtest="WordSetTest,ChatListsTest,ChatSettingsTest" test`
Expected: compilation failure, `cannot find symbol: class WordSet`.

- [ ] **Step 3: Implement**

`src/main/java/dev/filtsiap/ded/anonymizer/chat/WordSet.java`:
```java
package dev.filtsiap.ded.anonymizer.chat;

import dev.filtsiap.ded.anonymizer.ConfigurationError;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.TreeSet;
import java.util.zip.GZIPInputStream;

/**
 * An immutable set of FOLDED words in two flat arrays: every word's chars back to back, and each
 * word's start offset. Sorted in String order, so a lookup is a binary search, and a million words
 * cost about the characters they contain instead of a String object each.
 */
public final class WordSet {
    private static final String GREEK_LETTERS = "αβγδεζηθικλμνξοπρστυφχψω";

    private final char[] chars;
    /** Word i is chars[starts[i] .. starts[i + 1]); starts.length == size() + 1. */
    private final int[] starts;

    private WordSet(char[] chars, int[] starts) {
        this.chars = chars;
        this.starts = starts;
    }

    /** Folds, drops blanks, dedupes and sorts {@code words}. For small lists and tests. */
    public static WordSet of(Collection<String> words) {
        TreeSet<String> sorted = new TreeSet<>();
        for (String w : words) {
            String folded = GreekFold.fold(w.strip());
            if (!folded.isEmpty()) {
                sorted.add(folded);
            }
        }
        Builder b = new Builder();
        sorted.forEach(b::add);
        return b.build();
    }

    /**
     * A generated list: one word per line, already folded, strictly increasing in String order (so
     * no duplicates). Streams the file, so loading never holds a String per word. A violation is a
     * ConfigurationError: the file was edited by hand or built by an older builder.
     */
    public static WordSet loadSorted(Path path) {
        Builder b = new Builder();
        String previous = null;
        try (BufferedReader in = reader(path)) {
            String line;
            int lineNo = 0;
            while ((line = in.readLine()) != null) {
                lineNo++;
                if (line.isEmpty()) {
                    continue;
                }
                if (!GreekFold.fold(line).equals(line)) {
                    throw new ConfigurationError(path + ":" + lineNo + " is not folded; rebuild the chat lists");
                }
                if (previous != null && previous.compareTo(line) >= 0) {
                    throw new ConfigurationError(path + ":" + lineNo + " is out of order; rebuild the chat lists");
                }
                b.add(line);
                previous = line;
            }
        } catch (IOException e) {
            throw new ConfigurationError("cannot read " + path + ": " + e.getMessage(), e);
        }
        return b.build();
    }

    /** A hand-kept list: '#' starts a comment, blank lines are skipped, any order, folded on load. */
    public static WordSet loadList(Path path) {
        List<String> words = new ArrayList<>();
        try (BufferedReader in = reader(path)) {
            String line;
            while ((line = in.readLine()) != null) {
                int hash = line.indexOf('#');
                String word = (hash < 0 ? line : line.substring(0, hash)).strip();
                if (!word.isEmpty()) {
                    words.add(word);
                }
            }
        } catch (IOException e) {
            throw new ConfigurationError("cannot read " + path + ": " + e.getMessage(), e);
        }
        return of(words);
    }

    private static BufferedReader reader(Path path) throws IOException {
        InputStream raw = Files.newInputStream(path);
        InputStream in = path.getFileName().toString().endsWith(".gz") ? new GZIPInputStream(raw, 1 << 16) : raw;
        return new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8), 1 << 16);
    }

    public int size() {
        return starts.length - 1;
    }

    public boolean contains(String folded) {
        int lo = 0;
        int hi = size() - 1;
        while (lo <= hi) {
            int mid = (lo + hi) >>> 1;
            int c = compareAt(mid, folded);
            if (c < 0) {
                lo = mid + 1;
            } else if (c > 0) {
                hi = mid - 1;
            } else {
                return true;
            }
        }
        return false;
    }

    /** Sign of (word i − s) in String order. */
    private int compareAt(int i, String s) {
        int a = starts[i];
        int aEnd = starts[i + 1];
        int b = 0;
        while (a < aEnd && b < s.length()) {
            int d = chars[a++] - s.charAt(b++);
            if (d != 0) {
                return d;
            }
        }
        return (aEnd - a) - (s.length() - b);
    }

    /** Whether a word within one substitution, insertion, deletion or adjacent swap (Greek letters) is in the set. */
    public boolean containsWithinOneEdit(String w) {
        if (contains(w)) {
            return true;
        }
        for (int i = 0; i < w.length(); i++) {
            if (contains(w.substring(0, i) + w.substring(i + 1))) {
                return true;
            }
        }
        for (int i = 0; i + 1 < w.length(); i++) {
            char[] c = w.toCharArray();
            char t = c[i];
            c[i] = c[i + 1];
            c[i + 1] = t;
            if (contains(new String(c))) {
                return true;
            }
        }
        for (int i = 0; i <= w.length(); i++) {
            for (int k = 0; k < GREEK_LETTERS.length(); k++) {
                char ch = GREEK_LETTERS.charAt(k);
                if (contains(w.substring(0, i) + ch + w.substring(i))) {
                    return true;
                }
                if (i < w.length() && w.charAt(i) != ch && contains(w.substring(0, i) + ch + w.substring(i + 1))) {
                    return true;
                }
            }
        }
        return false;
    }

    /** Bytes held by the two arrays (object headers aside). */
    public long footprintBytes() {
        return chars.length * 2L + starts.length * 4L;
    }

    /** Appends words in order into growing arrays. */
    private static final class Builder {
        private char[] chars = new char[1 << 12];
        private int[] starts = new int[1 << 10];
        private int size;
        private int used;

        void add(String w) {
            if (used + w.length() > chars.length) {
                chars = Arrays.copyOf(chars, Math.max(chars.length * 2, used + w.length()));
            }
            if (size + 2 > starts.length) {
                starts = Arrays.copyOf(starts, starts.length * 2);
            }
            starts[size++] = used;
            w.getChars(0, w.length(), chars, used);
            used += w.length();
        }

        WordSet build() {
            starts[size] = used;
            return new WordSet(Arrays.copyOf(chars, used), Arrays.copyOf(starts, size + 1));
        }
    }
}
```

`src/main/java/dev/filtsiap/ded/anonymizer/chat/ChatLists.java`:
```java
package dev.filtsiap.ded.anonymizer.chat;

import dev.filtsiap.ded.anonymizer.ConfigurationError;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * The word lists of the name detector, loaded once at startup from config/chat. See
 * config/chat/README.md for each list's source and licence.
 *
 * @param givenNames    Wikidata given names, every inflected form, folded
 * @param surnames      Wikidata surnames of Greek citizens, every inflected form, folded
 * @param greekCommon   lowercase Hunspell el_GR entries, every form, folded: ordinary Greek words
 * @param greekProper   capitalised Hunspell el_GR entries minus the name lists: places, institutions, months
 * @param englishCommon lowercase Hunspell en_US entries, every form
 * @param allow         slang.txt + domain_allowlist.txt: hand-kept words that are never names
 */
public record ChatLists(WordSet givenNames, WordSet surnames, WordSet greekCommon, WordSet greekProper,
                        WordSet englishCommon, WordSet allow) {

    static final List<String> GENERATED = List.of("given_names.txt", "surnames.txt", "el_common.txt.gz",
            "el_proper.txt.gz", "en_common.txt.gz");
    static final List<String> HAND_KEPT = List.of("slang.txt", "domain_allowlist.txt");

    public static ChatLists load(Path chatDir) {
        for (String name : concat(GENERATED, HAND_KEPT)) {
            if (!Files.isRegularFile(chatDir.resolve(name))) {
                throw new ConfigurationError(chatDir.resolve(name) + " is missing; see config/chat/README.md "
                        + "for how to build the chat lists");
            }
        }
        WordSet slang = WordSet.loadList(chatDir.resolve("slang.txt"));
        WordSet domain = WordSet.loadList(chatDir.resolve("domain_allowlist.txt"));
        return new ChatLists(
                WordSet.loadSorted(chatDir.resolve("given_names.txt")),
                WordSet.loadSorted(chatDir.resolve("surnames.txt")),
                WordSet.loadSorted(chatDir.resolve("el_common.txt.gz")),
                WordSet.loadSorted(chatDir.resolve("el_proper.txt.gz")),
                WordSet.loadSorted(chatDir.resolve("en_common.txt.gz")),
                WordSet.of(concat(slang.words(), domain.words())));
    }

    /** From plain collections (folded here); for tests. */
    public static ChatLists of(Collection<String> givenNames, Collection<String> surnames,
                               Collection<String> greekCommon, Collection<String> greekProper,
                               Collection<String> englishCommon, Collection<String> allow) {
        return new ChatLists(WordSet.of(givenNames), WordSet.of(surnames), WordSet.of(greekCommon),
                WordSet.of(greekProper), WordSet.of(englishCommon), WordSet.of(allow));
    }

    public boolean isName(String folded) {
        return givenNames.contains(folded) || surnames.contains(folded);
    }

    public boolean isCommonWord(String folded) {
        return greekCommon.contains(folded) || englishCommon.contains(folded) || allow.contains(folded);
    }

    public long footprintBytes() {
        return givenNames.footprintBytes() + surnames.footprintBytes() + greekCommon.footprintBytes()
                + greekProper.footprintBytes() + englishCommon.footprintBytes() + allow.footprintBytes();
    }

    private static List<String> concat(Collection<String> a, Collection<String> b) {
        List<String> out = new ArrayList<>(a);
        out.addAll(b);
        return out;
    }
}
```

This calls `WordSet.words()`, so add it to `WordSet` (it is used only for the two small hand lists):
```java
    /** Every word, in order. Allocates a String per word: for small lists only. */
    List<String> words() {
        List<String> out = new ArrayList<>(size());
        for (int i = 0; i < size(); i++) {
            out.add(new String(chars, starts[i], starts[i + 1] - starts[i]));
        }
        return out;
    }
```

`src/main/java/dev/filtsiap/ded/anonymizer/chat/ChatSettings.java`:
```java
package dev.filtsiap.ded.anonymizer.chat;

import dev.filtsiap.ded.anonymizer.ConfigurationError;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

/** config/chat/chat.yaml. A missing file means {@link #DEFAULTS}: NER off. */
public record ChatSettings(boolean nerEnabled, String nerProvider, double nerMinConfidence, int nerTimeoutMs) {

    public static final ChatSettings DEFAULTS = new ChatSettings(false, "none", 0.6, 2000);

    public static ChatSettings load(Path chatDir) {
        Path path = chatDir.resolve("chat.yaml");
        if (!Files.isRegularFile(path)) {
            return DEFAULTS;
        }
        Object data;
        try {
            data = new Yaml(new SafeConstructor(new LoaderOptions())).load(Files.readString(path, StandardCharsets.UTF_8));
        } catch (IOException | RuntimeException e) {
            throw new ConfigurationError("cannot read " + path + ": " + e.getMessage(), e);
        }
        Map<?, ?> root = data instanceof Map<?, ?> m ? m : Map.of();
        Map<?, ?> ner = root.get("ner") instanceof Map<?, ?> m ? m : Map.of();
        boolean enabled = Boolean.TRUE.equals(ner.get("enabled"));
        String provider = String.valueOf(ner.containsKey("provider") ? ner.get("provider") : DEFAULTS.nerProvider());
        double minConfidence = ner.get("min_confidence") instanceof Number n ? n.doubleValue()
                : DEFAULTS.nerMinConfidence();
        int timeoutMs = ner.get("timeout_ms") instanceof Number n ? n.intValue() : DEFAULTS.nerTimeoutMs();
        if (minConfidence < 0 || minConfidence > 1) {
            throw new ConfigurationError(path + ": ner.min_confidence must be between 0 and 1");
        }
        if (enabled) {
            // v1 ships the slot, not a model: refusing to start beats silently running without NER.
            throw new ConfigurationError(path + ": ner.enabled is true but this build has no NER provider ('"
                    + provider + "'); see the spec's \"When NER is switched on\"");
        }
        return new ChatSettings(false, provider, minConfidence, timeoutMs);
    }
}
```

`config/chat/chat.yaml`:
```yaml
# Settings for POST /anonymize-text.
# Design: docs/superpowers/specs/2026-10-09-chat-text-anonymizer-design.md
ner:
  # v1 ships no NER model: setting this to true stops startup with a configuration error.
  enabled: false
  provider: none
  min_confidence: 0.6
  timeout_ms: 2000
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `mvn -q -Dtest="WordSetTest,ChatListsTest,ChatSettingsTest" test`
Expected: `Tests run: 13, Failures: 0, Errors: 0`.

- [ ] **Step 5: Commit**

```bash
git add src/main/java/dev/filtsiap/ded/anonymizer/chat src/test/java/dev/filtsiap/ded/anonymizer/chat config/chat/chat.yaml
git commit -m "Add compact word sets, chat list loading and chat settings"
```

---

### Task 4: Build the word lists (Hunspell + Wikidata)

**Files:**
- Create: `src/test/java/dev/filtsiap/ded/anonymizer/chat/build/HunspellAffixes.java`
- Create: `src/test/java/dev/filtsiap/ded/anonymizer/chat/build/BuildChatLists.java`
- Test: `src/test/java/dev/filtsiap/ded/anonymizer/chat/build/HunspellAffixesTest.java`
- Test: `src/test/java/dev/filtsiap/ded/anonymizer/chat/ChatListsRealConfigTest.java`
- Create (generated, committed): `config/chat/given_names.txt`, `surnames.txt`, `el_common.txt.gz`, `el_proper.txt.gz`, `en_common.txt.gz`
- Create (hand-kept): `config/chat/slang.txt`, `config/chat/domain_allowlist.txt`, `config/chat/README.md`
- Modify: `.gitignore` (add `.cache/`)

**Interfaces:**
- Consumes: `GreekFold.fold`, `GreekInflection.forms`, `ChatLists.load`.
- Produces: the files listed in Task 3, plus `config/chat/lists.properties` (sources, licences, fetch date, counts).

Facts about the sources (checked 2026-10-12):
- `el_GR.aff`: `SET ISO8859-7`, default single-character flags, 5 `PFX` groups, 35 `SFX` groups, no continuation classes and no compounding.
- Wikidata: 608 male + 346 female given names have a Greek `P1705` label, and about 1,098 surnames (`P734`) of people with `P27 = Q41` (Greece) have a Greek label.

- [ ] **Step 1: Write the failing expander test**

`src/test/java/dev/filtsiap/ded/anonymizer/chat/build/HunspellAffixesTest.java`:
```java
package dev.filtsiap.ded.anonymizer.chat.build;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import org.junit.jupiter.api.Test;

class HunspellAffixesTest {

    private static final String AFF = """
            SET UTF-8
            TRY αβγ
            PFX A Y 1
            PFX A 0 ξανα .
            SFX B Y 2
            SFX B ος ου ος    # δρόμος > δρόμου
            SFX B ος ο ος
            SFX C N 1
            SFX C 0 ς [αη]
            """;

    private static Set<String> expand(String dicLine) {
        HunspellAffixes affixes = HunspellAffixes.parse(AFF.getBytes(StandardCharsets.UTF_8));
        return new TreeSet<>(affixes.expand(dicLine));
    }

    @Test
    void suffixesApplyWhereTheConditionHolds() {
        assertEquals(Set.of("δρόμος", "δρόμου", "δρόμο"), expand("δρόμος/B"));
        assertEquals(Set.of("ώρα", "ώρας"), expand("ώρα/C"));
    }

    @Test
    void prefixesAndCrossProductCombine() {
        assertEquals(Set.of("δρόμος", "δρόμου", "δρόμο", "ξαναδρόμος", "ξαναδρόμου", "ξαναδρόμο"),
                expand("δρόμος/AB"));
    }

    @Test
    void wordsWithoutFlagsAndMorphologyFieldsAreKept() {
        assertEquals(Set.of("και"), expand("και"));
        assertEquals(Set.of("δρόμος", "δρόμου", "δρόμο"), expand("δρόμος/B po:noun"));
    }

    @Test
    void theEncodingComesFromTheSetLine() {
        byte[] aff = "SET ISO8859-7\nSFX B Y 1\nSFX B ος ου ος\n".getBytes(java.nio.charset.Charset.forName("ISO-8859-7"));
        HunspellAffixes affixes = HunspellAffixes.parse(aff);
        assertEquals("ISO-8859-7", affixes.charset().name());
        assertEquals(List.of("δρόμος", "δρόμου"), affixes.expand("δρόμος/B"));
    }

    @Test
    void anUnsupportedFlagTypeIsRefused() {
        assertThrows(IllegalArgumentException.class,
                () -> HunspellAffixes.parse("SET UTF-8\nFLAG long\n".getBytes(StandardCharsets.UTF_8)));
    }
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `mvn -q -Dtest=HunspellAffixesTest test`
Expected: compilation failure, `cannot find symbol: class HunspellAffixes`.

- [ ] **Step 3: Implement the expander**

`src/test/java/dev/filtsiap/ded/anonymizer/chat/build/HunspellAffixes.java`:
```java
package dev.filtsiap.ded.anonymizer.chat.build;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * The subset of Hunspell's .aff format the LibreOffice el_GR and en_US dictionaries use: SET,
 * single-character flags, PFX/SFX groups with cross-product. Continuation classes on an affix
 * ("add/flags") are dropped, which can only under-generate; any FLAG type other than the default
 * is refused rather than misread.
 */
final class HunspellAffixes {
    record Rule(String strip, String add, Pattern condition) {
    }

    record Group(boolean prefix, boolean crossProduct, List<Rule> rules) {
    }

    private final Charset charset;
    private final Map<Character, Group> groups;

    private HunspellAffixes(Charset charset, Map<Character, Group> groups) {
        this.charset = charset;
        this.groups = groups;
    }

    Charset charset() {
        return charset;
    }

    static HunspellAffixes parse(byte[] aff) {
        Charset charset = StandardCharsets.ISO_8859_1;
        for (String line : new String(aff, StandardCharsets.ISO_8859_1).split("\\R")) {
            String[] f = line.strip().split("\\s+");
            if (f.length >= 2 && f[0].equals("SET")) {
                charset = Charset.forName(f[1].equalsIgnoreCase("ISO8859-7") ? "ISO-8859-7" : f[1]);
            }
        }
        Map<Character, Group> groups = new LinkedHashMap<>();
        for (String line : new String(aff, charset).split("\\R")) {
            int hash = line.indexOf('#');
            String[] f = (hash < 0 ? line : line.substring(0, hash)).strip().split("\\s+");
            if (f[0].equals("FLAG")) {
                throw new IllegalArgumentException("unsupported FLAG type: " + (f.length > 1 ? f[1] : ""));
            }
            if (!f[0].equals("PFX") && !f[0].equals("SFX")) {
                continue;
            }
            boolean prefix = f[0].equals("PFX");
            char flag = f[1].charAt(0);
            if (f.length == 4 && !groups.containsKey(flag)) {          // header: PFX A Y 1
                groups.put(flag, new Group(prefix, f[2].equals("Y"), new ArrayList<>()));
            } else if (f.length >= 5) {                                // rule: SFX B strip add condition
                String strip = f[2].equals("0") ? "" : f[2];
                String add = f[3].equals("0") ? "" : f[3].split("/", 2)[0];
                String cond = f[4].equals(".") ? "" : f[4];
                Pattern condition = Pattern.compile(prefix ? "^" + cond : cond + "$");
                groups.get(flag).rules().add(new Rule(strip, add, condition));
            }
        }
        return new HunspellAffixes(charset, groups);
    }

    /** Every form of one .dic line ("word", "word/FLAGS", optionally followed by morphology fields). */
    List<String> expand(String dicLine) {
        String entry = dicLine.strip().split("\\s+", 2)[0];
        int slash = entry.indexOf('/');
        String word = slash < 0 ? entry : entry.substring(0, slash);
        String flags = slash < 0 ? "" : entry.substring(slash + 1);
        Set<String> out = new LinkedHashSet<>();
        out.add(word);
        List<String> prefixed = new ArrayList<>();
        for (char flag : flags.toCharArray()) {
            Group g = groups.get(flag);
            if (g == null || !g.prefix()) {
                continue;
            }
            for (Rule r : g.rules()) {
                if (r.condition().matcher(word).find() && word.startsWith(r.strip())) {
                    String form = r.add() + word.substring(r.strip().length());
                    out.add(form);
                    if (g.crossProduct()) {
                        prefixed.add(form);
                    }
                }
            }
        }
        for (char flag : flags.toCharArray()) {
            Group g = groups.get(flag);
            if (g == null || g.prefix()) {
                continue;
            }
            List<String> bases = new ArrayList<>();
            bases.add(word);
            if (g.crossProduct()) {
                bases.addAll(prefixed);
            }
            for (String base : bases) {
                for (Rule r : g.rules()) {
                    if (r.condition().matcher(base).find() && base.endsWith(r.strip())) {
                        out.add(base.substring(0, base.length() - r.strip().length()) + r.add());
                    }
                }
            }
        }
        return new ArrayList<>(out);
    }
}
```

The cross-product condition is checked on the prefixed base, and the strip is applied to its end. For a suffix condition that works the same on prefixed and unprefixed bases, as in the test.

- [ ] **Step 4: Run it to verify it passes**

Run: `mvn -q -Dtest=HunspellAffixesTest test`
Expected: `Tests run: 5, Failures: 0, Errors: 0`.

- [ ] **Step 5: Write the builder**

`src/test/java/dev/filtsiap/ded/anonymizer/chat/build/BuildChatLists.java`:
```java
package dev.filtsiap.ded.anonymizer.chat.build;

import dev.filtsiap.ded.anonymizer.chat.GreekFold;
import dev.filtsiap.ded.anonymizer.chat.GreekInflection;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.LocalDate;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Pattern;
import java.util.zip.GZIPOutputStream;

/**
 * Dev-time tool, never run by the service: downloads the sources into a cache, expands and folds
 * them, and writes config/chat. Usage (from the repo root, after `mvn -q test-compile`):
 *
 * <pre>java -Xmx2g -cp "target/test-classes;target/classes" \
 *     dev.filtsiap.ded.anonymizer.chat.build.BuildChatLists config/chat .cache/chat-lists</pre>
 *
 * (Use ':' instead of ';' in the classpath on Linux/macOS.)
 */
public final class BuildChatLists {
    static final String LO = "https://raw.githubusercontent.com/LibreOffice/dictionaries/master/";
    static final Map<String, String> DOWNLOADS = Map.of(
            "el_GR.aff", LO + "el_GR/el_GR.aff",
            "el_GR.dic", LO + "el_GR/el_GR.dic",
            "en_US.aff", LO + "en/en_US.aff",
            "en_US.dic", LO + "en/en_US.dic");
    static final String WDQS = "https://query.wikidata.org/sparql?query=";
    static final String GIVEN_QUERY = "SELECT DISTINCT ?l WHERE { VALUES ?t {wd:Q12308941 wd:Q11879590} "
            + "?n wdt:P31 ?t ; wdt:P1705 ?l . FILTER(LANG(?l)=\"el\") }";
    static final String SURNAME_QUERY = "SELECT DISTINCT ?l WHERE { ?p wdt:P27 wd:Q41 ; wdt:P734 ?f . "
            + "?f rdfs:label ?l . FILTER(LANG(?l)=\"el\") }";
    /** One Greek word, optionally hyphenated; labels with spaces or other scripts are skipped. */
    static final Pattern GREEK_NAME = Pattern.compile("[\\p{IsGreek}]+(?:-[\\p{IsGreek}]+)?");

    private static final HttpClient HTTP = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(30))
            .followRedirects(HttpClient.Redirect.NORMAL).build();

    private BuildChatLists() {
    }

    public static void main(String[] args) throws Exception {
        Path out = Path.of(args.length > 0 ? args[0] : "config/chat");
        Path cache = Path.of(args.length > 1 ? args[1] : ".cache/chat-lists");
        Files.createDirectories(cache);
        for (Map.Entry<String, String> d : DOWNLOADS.entrySet()) {
            fetch(d.getValue(), cache.resolve(d.getKey()), "*/*");
        }
        fetch(WDQS + URLEncoder.encode(GIVEN_QUERY, StandardCharsets.UTF_8), cache.resolve("given.csv"), "text/csv");
        fetch(WDQS + URLEncoder.encode(SURNAME_QUERY, StandardCharsets.UTF_8), cache.resolve("surnames.csv"), "text/csv");

        Set<String> given = names(cache.resolve("given.csv"));
        Set<String> surnames = names(cache.resolve("surnames.csv"));
        Set<String> elCommon = new TreeSet<>();
        Set<String> elProper = new TreeSet<>();
        expandDictionary(cache.resolve("el_GR.aff"), cache.resolve("el_GR.dic"), elCommon, elProper);
        Set<String> enCommon = new TreeSet<>();
        expandDictionary(cache.resolve("en_US.aff"), cache.resolve("en_US.dic"), enCommon, new TreeSet<>());
        elProper.removeAll(given);
        elProper.removeAll(surnames);

        Files.createDirectories(out);
        write(out.resolve("given_names.txt"), given, false);
        write(out.resolve("surnames.txt"), surnames, false);
        write(out.resolve("el_common.txt.gz"), elCommon, true);
        write(out.resolve("el_proper.txt.gz"), elProper, true);
        write(out.resolve("en_common.txt.gz"), enCommon, true);

        Properties p = new Properties();
        p.setProperty("built", LocalDate.now().toString());
        DOWNLOADS.forEach((k, v) -> p.setProperty("source." + k, v));
        p.setProperty("source.given_names", "Wikidata SPARQL: " + GIVEN_QUERY);
        p.setProperty("source.surnames", "Wikidata SPARQL: " + SURNAME_QUERY);
        p.setProperty("count.given_names", Integer.toString(given.size()));
        p.setProperty("count.surnames", Integer.toString(surnames.size()));
        p.setProperty("count.el_common", Integer.toString(elCommon.size()));
        p.setProperty("count.el_proper", Integer.toString(elProper.size()));
        p.setProperty("count.en_common", Integer.toString(enCommon.size()));
        try (OutputStream o = Files.newOutputStream(out.resolve("lists.properties"))) {
            p.store(o, "Generated by BuildChatLists; see config/chat/README.md");
        }
        System.out.println(p);
    }

    /** Downloads once; a cached file is reused, so a rebuild with the same cache is reproducible. */
    static void fetch(String url, Path target, String accept) throws IOException, InterruptedException {
        if (Files.isRegularFile(target) && Files.size(target) > 0) {
            return;
        }
        HttpRequest req = HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofMinutes(3))
                .header("Accept", accept)
                .header("User-Agent", "ded-anonymizer-list-builder/1.0 (internal build tool)").GET().build();
        HttpResponse<Path> resp = HTTP.send(req, HttpResponse.BodyHandlers.ofFile(target));
        if (resp.statusCode() != 200) {
            Files.deleteIfExists(target);
            throw new IOException("GET " + url + " -> HTTP " + resp.statusCode());
        }
    }

    /** CSV with header "l": each Greek single-word label, folded, expanded through GreekInflection. */
    static Set<String> names(Path csv) throws IOException {
        Set<String> out = new TreeSet<>();
        List<String> lines = Files.readAllLines(csv, StandardCharsets.UTF_8);
        for (String line : lines.subList(1, lines.size())) {
            String label = line.strip().replace("\"", "");
            if (GREEK_NAME.matcher(label).matches()) {
                for (String part : label.split("-")) {
                    out.addAll(GreekInflection.forms(GreekFold.fold(part)));
                }
            }
        }
        return out;
    }

    /** Lowercase-initial entries go to {@code common}, capitalised ones to {@code proper}; every form, folded. */
    static void expandDictionary(Path aff, Path dic, Collection<String> common, Collection<String> proper)
            throws IOException {
        HunspellAffixes affixes = HunspellAffixes.parse(Files.readAllBytes(aff));
        List<String> lines = Files.readAllLines(dic, affixes.charset());
        for (String line : lines.subList(1, lines.size())) {   // line 1 is the entry count
            if (line.isBlank()) {
                continue;
            }
            for (String form : affixes.expand(line)) {
                if (form.isEmpty() || !Character.isLetter(form.codePointAt(0))) {
                    continue;
                }
                (Character.isUpperCase(form.codePointAt(0)) ? proper : common).add(GreekFold.fold(form));
            }
        }
    }

    static void write(Path path, Collection<String> sortedFolded, boolean gzip) throws IOException {
        try (OutputStream raw = Files.newOutputStream(path);
             OutputStream o = gzip ? new GZIPOutputStream(raw, 1 << 16) : raw;
             BufferedWriter w = new BufferedWriter(new OutputStreamWriter(o, StandardCharsets.UTF_8))) {
            for (String word : sortedFolded) {
                w.write(word);
                w.write('\n');
            }
        }
    }
}
```

`TreeSet<String>` iterates in `String` natural order, which is the order `WordSet.loadSorted` checks. The lines from `expand` are folded before insertion, so every written line is folded.

- [ ] **Step 6: STOP — ask the user before downloading**

Tell the user, and wait for an explicit yes:
> The list builder downloads into `.cache/chat-lists/` (git-ignored):
> - `el_GR.aff` and `el_GR.dic` (Greek spell-check dictionary, MPL/GPL/LGPL) from github.com/LibreOffice/dictionaries.
> - `en_US.aff` and `en_US.dic` (English, SCOWL licence) from the same repository.
> - Two Wikidata SPARQL query results (CC0) from query.wikidata.org.
>
> These are data files only; nothing is executed. OK to download?

Then add `.cache/` to `.gitignore`:
```bash
printf '\n# list-builder downloads (BuildChatLists)\n.cache/\n' >> .gitignore
```

- [ ] **Step 7: Run the builder and check the output**

Run (Git Bash on Windows):
```bash
mvn -q test-compile
java -Xmx2g -cp "target/test-classes;target/classes" dev.filtsiap.ded.anonymizer.chat.build.BuildChatLists config/chat .cache/chat-lists
ls -la config/chat
```
Expected:
- `lists.properties` is printed with `count.given_names` in the low thousands (about 950 names × their forms), `count.surnames` in the low thousands, and `count.el_common` in the hundreds of thousands or more.
- All five generated files exist.

If `el_common.txt.gz` is over 25 MB, stop and ask the user whether to commit it or use Git LFS before going on.

Spot-check folded content:
```bash
zcat config/chat/el_common.txt.gz | grep -c '^λογαριασμοσ$'
grep -c '^γιωργο$' config/chat/given_names.txt
zcat config/chat/el_proper.txt.gz | grep -c '^αθηνα$'
```
Expected: `1`, `1`, `0`. "Αθηνά" (a given name) folds to the same string as the city "Αθήνα", so the city is removed from the proper list by design. It then reaches the name rules, and is treated as `may_mask` in the dataset.

- [ ] **Step 8: Write the hand-kept lists and the README**

`config/chat/slang.txt`:
```text
# Chat words that are not in the dictionaries and are never names. Folded on load.
# One entry per line; '#' starts a comment.
κλπ
κτλ
λπ
οκ
οκει
μπλα
χαχα
χαχαχα
λολ
ρε
βρε
μωρε
ντε
αντε
μερσι
σορυ
τηλ
αρ
κιν
ok
okay
lol
thx
pls
plz
hi
hello
bye
sorry
```

`config/chat/domain_allowlist.txt`:
```text
# Terms of OUR services and of the systems customers mention, which must never be masked.
# Grow this from reviewed output: a term masked by the uncommon-word rule belongs here.
# Folded on load (case and accents do not matter). '#' starts a comment.
# Public bodies and Greek acronyms
δεη
ευδαπ
εφκα
ααδε
δυπα
οαεδ
κεπ
δου
αφμ
αμκα
γεμη
αδτ
τκ
ικα
οτε
ελτα
ερτ
# Telecom and IT
cosmote
vodafone
nova
wind
email
mail
wifi
router
modem
app
android
iphone
ios
windows
viber
whatsapp
messenger
facebook
instagram
google
gmail
yahoo
outlook
sms
pin
puk
fiber
vdsl
adsl
ftth
mbps
online
chatbot
# Payments
iban
swift
bic
visa
mastercard
paypal
```

`config/chat/README.md`:
```markdown
# Chat anonymization lists

Loaded once at startup by `ChatLists.load` for `POST /anonymize-text`. Every word is FOLDED:
lowercase, no accents, σ for ς.

| File | Source | Licence | Kept by |
|---|---|---|---|
| `given_names.txt` | Wikidata: male (Q12308941) and female (Q11879590) given names with a Greek native label (P1705), expanded with Greek case endings | CC0 | generated |
| `surnames.txt` | Wikidata: family names (P734) of Greek citizens (P27 = Q41) with a Greek label, expanded with case endings | CC0 | generated |
| `el_common.txt.gz` | LibreOffice Hunspell `el_GR` (v0.9), lowercase entries, every affix form | MPL 1.1 (of MPL 1.1 / GPL 2.0 / LGPL 2.1) | generated |
| `el_proper.txt.gz` | Same dictionary, capitalised entries, minus the two name lists | MPL 1.1 | generated |
| `en_common.txt.gz` | LibreOffice Hunspell `en_US` (SCOWL), lowercase entries, every affix form | SCOWL (permissive; keep the copyright notice) | generated |
| `slang.txt` | Chat words not in the dictionaries | ours | by hand |
| `domain_allowlist.txt` | Our product and service terms, acronyms | ours | by hand |
| `lists.properties` | What was built, when, from where, and how many words | – | generated |
| `chat.yaml` | NER switch | – | by hand |

We use and keep the dictionaries unmodified inside this service. MPL 1.1 asks that its notice be
kept, and that changes to the dictionary FILES themselves be shared if we distributed them; we
distribute neither the files nor changes.

## Rebuilding the generated lists

From the repo root (downloads go to `.cache/chat-lists/`, which is git-ignored; delete it to fetch
fresh copies):

    mvn -q test-compile
    java -Xmx2g -cp "target/test-classes;target/classes" dev.filtsiap.ded.anonymizer.chat.build.BuildChatLists config/chat .cache/chat-lists

Use `:` instead of `;` in the classpath on Linux/macOS. Then run `mvn -B verify`: the chat eval
shows what the new lists changed.
```

- [ ] **Step 9: Write the real-config test**

`src/test/java/dev/filtsiap/ded/anonymizer/chat/ChatListsRealConfigTest.java`:
```java
package dev.filtsiap.ded.anonymizer.chat;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import org.junit.jupiter.api.Test;

/** The committed lists load, hold what the detectors rely on, and fit the memory budget. */
class ChatListsRealConfigTest {
    static final ChatLists LISTS = ChatLists.load(Path.of("config", "chat"));

    @Test
    void theCommittedListsLoad() {
        assertTrue(LISTS.isName("γιωργοσ"));
        assertTrue(LISTS.isName("γιωργο"));
        assertTrue(LISTS.isCommonWord("λογαριασμοσ"));
        assertTrue(LISTS.isCommonWord("bill"));
        assertTrue(LISTS.isCommonWord("δεη"));
        assertFalse(LISTS.isCommonWord("μπαλαμωτη"));
    }

    @Test
    void theListsStayUnderSixtyFourMegabytes() {
        // The JVM heap is shared with .docx processing (R-1); the lists are resident for the process's life.
        assertTrue(LISTS.footprintBytes() < 64L * 1024 * 1024, "footprint " + LISTS.footprintBytes());
    }
}
```

Run: `mvn -q -Dtest="ChatListsRealConfigTest,HunspellAffixesTest" test`
Expected: `Tests run: 7, Failures: 0, Errors: 0`.

- [ ] **Step 10: Commit**

```bash
git add .gitignore config/chat src/test/java/dev/filtsiap/ded/anonymizer/chat
git commit -m "Build and commit chat word lists from Wikidata and Hunspell"
```

---

### Task 5: Structured ID detector

**Files:**
- Create: `src/main/java/dev/filtsiap/ded/anonymizer/chat/Checksums.java`
- Create: `src/main/java/dev/filtsiap/ded/anonymizer/chat/IdDetector.java`
- Modify: `src/main/java/dev/filtsiap/ded/anonymizer/DetectorSupport.java`. Line 21 becomes `public final class DetectorSupport {`; lines 127 and 132 get `public static boolean validAfm(String value)` and `public static boolean validAmkaBirthDate(String value)`.
- Test: `src/test/java/dev/filtsiap/ded/anonymizer/chat/IdDetectorTest.java`

**Interfaces:**
- Consumes:
  - `Detectors.detectStructuredIds(TextUnit, DetectorRules)`, `Detectors.detectContacts(TextUnit, DetectorRules)`, `Detectors.detectBankPaymentIds(TextUnit)` (all public).
  - `DetectorSupport.validAfm(String)` and `validAmkaBirthDate(String)` (made public here).
  - `GreekFold.fold`, `ChatSpan`, `PiiType`.
- Produces:
  - `new IdDetector(DetectorRules rules)` and `List<ChatSpan> detect(String nfcText)`.
  - `Checksums.luhn(String)`, `Checksums.amka(String)`, `Checksums.digitsOnly(String)`.

- [ ] **Step 1: Write the failing tests**

`src/test/java/dev/filtsiap/ded/anonymizer/chat/IdDetectorTest.java`:
```java
package dev.filtsiap.ded.anonymizer.chat;

import static dev.filtsiap.ded.anonymizer.chat.ChatAsserts.expect;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.filtsiap.ded.anonymizer.Config;
import java.nio.file.Path;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.api.Test;

class IdDetectorTest {
    static final IdDetector IDS = new IdDetector(Config.loadFileConfig(Path.of("config")).rules());

    private static String masked(String text) {
        return Masker.mask(text, IDS.detect(text));
    }

    @ParameterizedTest(name = "{0}")
    @CsvSource(delimiter = '|', value = {
            "Καλησπέρα, το ΑΦΜ μου είναι 090000045.|090000045",
            "Σας στέλνω τον ΑΦΜ χωρίς κενά: 801 234 560|801 234 560",
            "ο αριθμός μου είναι 047112234, μπορείτε;|047112234",
            "ΑΜΚΑ: 15038501233|15038501233",
            "IBAN GR39 0110 1250 0000 0123 4567 890 για την επιστροφή|GR39 0110 1250 0000 0123 4567 890",
            "στείλτε τα χρήματα στο gr6801701230000000123456789|gr6801701230000000123456789",
            "Το κινητό μου είναι 6912345678, πάρτε με μετά τις 5.|6912345678",
            "Τηλέφωνο: +30 697 123 4567 ή αλλιώς|+30 697 123 4567",
            "σταθερό 210 6543210 το πρωί|210 6543210",
            "0030 6944 556677 είναι το νούμερο|0030 6944 556677",
            "Τ η λ: 6 9 1 2 3 4 5 6 7 8|6 9 1 2 3 4 5 6 7 8",
            "Το email μου είναι maria.papadopoulou82@gmail.com|maria.papadopoulou82@gmail.com",
            "γράψτε μου στο giorgos_k [at] yahoo.gr|giorgos_k [at] yahoo.gr",
            "Αριθμός ταυτότητας ΑΚ 123456|ΑΚ 123456",
            "η ταυτότητά μου είναι Χ-654321, παλιού τύπου|Χ-654321",
            "Ταυτότητα AB123456 (με λατινικά)|AB123456",
            "Αρ. διαβατηρίου AN1234567, λήγει τον Μάρτιο|AN1234567",
            "πινακίδα ΙΚΥ-4521 εδώ|ΙΚΥ-4521",
            "το μηχανάκι ΖΗΒ 318 εδώ|ΖΗΒ 318",
            "Πλήρωσα με την κάρτα 4111 1111 1111 1111 και χρεώθηκα 45,90 €|4111 1111 1111 1111",
            "Αριθμός παροχής 1 23456789-01 2, ευχαριστώ|1 23456789-01 2",
            "αριθμός ΓΕΜΗ 123456701000|123456701000",
            "και ο κωδικος πελατη 7788990011|7788990011"})
    void masksTheIdentifier(String text, String id) {
        assertEquals(expect(text, id), masked(text));
    }

    @Test
    void masksLabelValuePairsWithoutSpaces() {
        String text = "ΑΦΜ:998877666,ΑΜΚΑ:01016003111,ΤΗΛ:6900112233";
        assertEquals(expect(text, "998877666", "01016003111", "6900112233"), masked(text));
    }

    @ParameterizedTest(name = "{0}")
    @CsvSource(delimiter = '|', value = {
            "Πλήρωσα 123,45 € στις 15/06/2026 και δεν φαίνεται.",
            "Το τηλεφωνικό κέντρο 11888 δεν απαντά.",
            "Ο κωδικός σφάλματος είναι E-4021 στην εφαρμογή σας.",
            "Η εφαρμογή σας κολλάει σε Android 14 και iPhone 15.",
            "Ο λογαριασμός είναι 89,99 € για 30 ημέρες, δηλαδή 2,99 € την ημέρα.",
            "Το συμβόλαιο έχει διάρκεια 24 μήνες και λήγει στις 31/12/2027.",
            "Η κάρτα μου τελειώνει σε 1111"})
    void leavesOrdinaryNumbersAlone(String text) {
        assertEquals(text, masked(text));
    }

    @Test
    void checksums() {
        assertTrue(Checksums.luhn("4111111111111111"));
        assertTrue(Checksums.amka("15038501233"));
        assertEquals("801234560", Checksums.digitsOnly("801 234-560"));
    }
}
```

`@ParameterizedTest` needs `junit-jupiter-params`. The `junit-jupiter` aggregator in `pom.xml` already includes it. Check with `grep -n "junit-jupiter" pom.xml`; the artifact is `junit-jupiter`, which pulls in params.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `mvn -q -Dtest=IdDetectorTest test`
Expected: compilation failure, `cannot find symbol: class IdDetector`.

- [ ] **Step 3: Implement**

Apply the three visibility changes to `DetectorSupport.java` listed under **Files**.

`src/main/java/dev/filtsiap/ded/anonymizer/chat/Checksums.java`:
```java
package dev.filtsiap.ded.anonymizer.chat;

import dev.filtsiap.ded.anonymizer.DetectorSupport;

/** Check-digit tests for chat IDs; AFM and the AMKA date come from the .docx detectors' DetectorSupport. */
public final class Checksums {
    private Checksums() {
    }

    public static String digitsOnly(String s) {
        StringBuilder b = new StringBuilder();
        s.codePoints().filter(cp -> cp >= '0' && cp <= '9').forEach(b::appendCodePoint);
        return b.toString();
    }

    public static boolean luhn(String digits) {
        int total = 0;
        for (int i = 0; i < digits.length(); i++) {
            int n = digits.charAt(digits.length() - 1 - i) - '0';
            if (i % 2 == 1) {
                n = n * 2 > 9 ? n * 2 - 9 : n * 2;
            }
            total += n;
        }
        return !digits.isEmpty() && total % 10 == 0;
    }

    /** 11 digits, a plausible DDMMYY birth date, and a Luhn check digit. */
    public static boolean amka(String digits) {
        return digits.length() == 11 && DetectorSupport.validAmkaBirthDate(digits) && luhn(digits);
    }

    public static boolean afm(String digits) {
        return digits.length() == 9 && DetectorSupport.validAfm(digits);
    }
}
```

`src/main/java/dev/filtsiap/ded/anonymizer/chat/IdDetector.java`:
```java
package dev.filtsiap.ded.anonymizer.chat;

import dev.filtsiap.ded.anonymizer.DetectorRules;
import dev.filtsiap.ded.anonymizer.Detectors;
import dev.filtsiap.ded.anonymizer.Span;
import dev.filtsiap.ded.anonymizer.SpanAction;
import dev.filtsiap.ded.anonymizer.TextUnit;
import dev.filtsiap.ded.anonymizer.UnitType;
import dev.filtsiap.ded.anonymizer.pycompat.PyRegex;
import dev.filtsiap.ded.anonymizer.pycompat.PyRegex.PyMatch;
import dev.filtsiap.ded.anonymizer.pycompat.PyRegex.PyPattern;
import java.util.ArrayList;
import java.util.List;

/**
 * Structured identifiers. First the .docx detectors (AFM, AMKA, IBAN, email, phone, bank account),
 * every REDACT and REVIEW proposal kept whatever its confidence (no pass 2 here to settle a REVIEW
 * or a low-confidence REDACT). Then chat shapes the .docx rules do not need: spaced digits,
 * obfuscated emails, ID cards, passports, plates, ΓΕΜΗ, cards, customer numbers. Cue patterns run
 * on the GreekFold of the text, whose offsets are the text's.
 */
public final class IdDetector {
    private static final String ID_LETTERS = "ΑΒΕΖΗΙΚΜΝΟΡΤΥΧABEZHIKMNOPTYX";
    private static final String PLATE_LETTERS = "ΑΒΕΖΗΙΚΜΝΟΡΤΥΧ";

    /** 10 digits from 2 or 6, single separators allowed, optional +30 / 0030. */
    static final PyPattern PHONE = PyRegex.compile(
            "(?<![\\d+])(?:(?:\\+|00)\\s?30[\\s.\\-]?)?[26](?:[\\s.\\-]?\\d){9}(?!\\d)", 0);
    /** 9 to 11 digits with single separators: an AFM or AMKA only if its check passes. */
    static final PyPattern DIGIT_GROUP = PyRegex.compile("(?<!\\d)\\d(?:[\\s.\\-]?\\d){8,10}(?!\\d)", 0);
    static final PyPattern IBAN = PyRegex.compile("\\bGR\\d{2}(?:\\s?[0-9A-Z]){23}\\b", PyRegex.IGNORECASE);
    static final PyPattern CARD = PyRegex.compile("(?<!\\d)\\d(?:[\\s\\-]?\\d){12,18}(?!\\d)", 0);
    static final PyPattern EMAIL_OBFUSCATED = PyRegex.compile(
            "[\\w.+\\-]{1,64}\\s?(?:@|\\[at\\]|\\(at\\)|\\{at\\})\\s?[\\w\\-]{1,63}"
                    + "(?:\\s?(?:\\.|\\[dot\\]|\\(dot\\))\\s?[\\w\\-]{1,63}){1,4}", PyRegex.IGNORECASE);
    static final PyPattern ID_CARD_NEW = PyRegex.compile(
            "(?<!\\w)[" + ID_LETTERS + "]{2}[\\s\\-]?\\d{6}(?!\\w)", 0);
    static final PyPattern ID_CARD_OLD = PyRegex.compile("(?<!\\w)[" + ID_LETTERS + "]-\\d{6}(?!\\w)", 0);
    static final PyPattern PLATE = PyRegex.compile(
            "(?<!\\w)[" + PLATE_LETTERS + "]{3}[\\s\\-]?\\d{3,4}(?!\\w)", 0);
    // Cue patterns: matched on the FOLDED text.
    // Every cue starts with (?<!\w): "αρ" must not match inside "καθαρή".
    static final PyPattern ID_CARD_CUED = PyRegex.compile(
            "(?<!\\w)(?:ταυτοτητ\\w*|α\\.?δ\\.?τ\\.?)\\s*:?\\s*(?:αρ\\w*\\.?\\s*)?([a-zα-ω]{1,2}[\\s\\-]?\\d{6})(?!\\d)",
            0);
    static final PyPattern PASSPORT_CUED = PyRegex.compile(
            "(?<!\\w)διαβατηρ\\w*[^\\d\\n]{0,20}?([a-zα-ω]{2}\\d{7})(?!\\d)", 0);
    static final PyPattern GEMI_CUED = PyRegex.compile(
            "(?<!\\w)γ\\.?ε\\.?μ\\.?η\\.?\\s*:?\\s*(?:αρ\\w*\\.?\\s*)?(\\d{9,12})(?!\\d)", 0);
    static final PyPattern CUSTOMER_CUED = PyRegex.compile(
            "(?<!\\w)(?:αρ\\w*\\.?|κωδικ\\w*)\\s+(?:παροχ\\w*|πελατ\\w*|συμβασ\\w*|συμβολαι\\w*|μετρητ\\w*|συνδρομητ\\w*"
                    + "|λογαριασμ\\w*)\\s*:?\\s*(\\d(?:[\\d\\s\\-/]{3,24}\\d)?)", 0);

    private final DetectorRules rules;

    public IdDetector(DetectorRules rules) {
        this.rules = rules;
    }

    public List<ChatSpan> detect(String text) {
        List<ChatSpan> out = new ArrayList<>(reused(text));
        String folded = GreekFold.fold(text);
        for (PyMatch m : PHONE.finditer(text)) {
            out.add(new ChatSpan(m.start(), m.end(), PiiType.PHONE, "chat_phone"));
        }
        for (PyMatch m : DIGIT_GROUP.finditer(text)) {
            String digits = Checksums.digitsOnly(m.group());
            if (Checksums.afm(digits)) {
                out.add(new ChatSpan(m.start(), m.end(), PiiType.AFM, "chat_afm_checksum"));
            } else if (Checksums.amka(digits)) {
                out.add(new ChatSpan(m.start(), m.end(), PiiType.AMKA, "chat_amka_checksum"));
            }
        }
        add(out, IBAN, text, 0, PiiType.IBAN, "chat_iban");
        for (PyMatch m : CARD.finditer(text)) {
            if (Checksums.luhn(Checksums.digitsOnly(m.group()))) {
                out.add(new ChatSpan(m.start(), m.end(), PiiType.CARD, "chat_card_luhn"));
            }
        }
        add(out, EMAIL_OBFUSCATED, text, 0, PiiType.EMAIL, "chat_email");
        add(out, ID_CARD_NEW, text, 0, PiiType.ID_CARD, "chat_id_card");
        add(out, ID_CARD_OLD, text, 0, PiiType.ID_CARD, "chat_id_card_old");
        add(out, PLATE, text, 0, PiiType.PLATE, "chat_plate");
        add(out, ID_CARD_CUED, folded, 1, PiiType.ID_CARD, "chat_id_card_cue");
        add(out, PASSPORT_CUED, folded, 1, PiiType.PASSPORT, "chat_passport_cue");
        add(out, GEMI_CUED, folded, 1, PiiType.GEMI, "chat_gemi_cue");
        add(out, CUSTOMER_CUED, folded, 1, PiiType.CUSTOMER_NO, "chat_customer_cue");
        return out;
    }

    private static void add(List<ChatSpan> out, PyPattern p, String text, int group, PiiType type, String name) {
        for (PyMatch m : p.finditer(text)) {
            out.add(new ChatSpan(m.start(group), m.end(group), type, name));
        }
    }

    /** The .docx detectors over the text as one in-memory paragraph; PRESERVE proposals are dropped. */
    private List<ChatSpan> reused(String text) {
        TextUnit unit = new TextUnit("chat", "chat", UnitType.PARAGRAPH, text, text, List.of(),
                new TextUnit.ParagraphLocation(0));
        List<Span> spans = new ArrayList<>();
        spans.addAll(Detectors.detectStructuredIds(unit, rules));
        spans.addAll(Detectors.detectContacts(unit, rules));
        spans.addAll(Detectors.detectBankPaymentIds(unit));
        List<ChatSpan> out = new ArrayList<>();
        for (Span s : spans) {
            if (s.action() == SpanAction.PRESERVE) {
                continue;
            }
            PiiType type = switch (s.category()) {
                case AFM -> PiiType.AFM;
                case AMKA -> PiiType.AMKA;
                case IBAN -> PiiType.IBAN;
                case EMAIL -> PiiType.EMAIL;
                case PHONE -> PiiType.PHONE;
                case BANK_ACCOUNT -> PiiType.BANK_ACCOUNT;
                case PRIVATE_BENEFICIARY -> PiiType.PERSON;
                default -> null; // e.g. a bank's NAME after "Τράπεζα": public in chat
            };
            if (type != null) {
                out.add(new ChatSpan(s.start(), s.end(), type, s.detector()));
            }
        }
        return out;
    }
}
```

If `PyMatch.end(int)` is not public, check `PyRegex.java:300-360`. `start(int)` is public at :351, and `end(int)` sits next to it.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `mvn -q -Dtest=IdDetectorTest test`
Expected: all pass. If a positive case fails, print `IDS.detect(text)` in the failing test and fix the specific pattern; do not weaken the test. If a negative case fails, find which detector fired via `ChatSpan.detector()` and tighten that pattern.

- [ ] **Step 5: Run the whole suite (visibility change)**

Run: `mvn -q test`
Expected: the existing 271 tests plus the new ones all pass.

- [ ] **Step 6: Commit**

```bash
git add src/main/java/dev/filtsiap/ded/anonymizer src/test/java/dev/filtsiap/ded/anonymizer/chat
git commit -m "Add chat ID detector reusing the .docx ID rules"
```

---

### Task 6: Address and place detector

**Files:**
- Create: `src/main/java/dev/filtsiap/ded/anonymizer/chat/AddressDetector.java`
- Test: `src/test/java/dev/filtsiap/ded/anonymizer/chat/AddressDetectorTest.java`

**Interfaces:**
- Consumes: `GreekFold.fold`, `ChatSpan`, `PiiType`.
- Produces: `new AddressDetector()` and `List<ChatSpan> detect(String nfcText)`, which returns ADDRESS, LOCATION and POSTAL_CODE spans.

- [ ] **Step 1: Write the failing tests**

`src/test/java/dev/filtsiap/ded/anonymizer/chat/AddressDetectorTest.java`:
```java
package dev.filtsiap.ded.anonymizer.chat;

import static dev.filtsiap.ded.anonymizer.chat.ChatAsserts.expect;
import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class AddressDetectorTest {
    static final AddressDetector ADDRESSES = new AddressDetector();

    private static String masked(String text) {
        return Masker.mask(text, ADDRESSES.detect(text));
    }

    @Test
    void streetInTheGenitivePlusNumber() {
        String t = "Η διεύθυνσή μου είναι Ελευθερίου Βενιζέλου 45, Νέα Σμύρνη.";
        assertEquals(expect(t, "Ελευθερίου Βενιζέλου 45", "Νέα Σμύρνη"), masked(t));
        String t2 = "Πατησίων 112, 3ος όροφος";
        assertEquals(expect(t2, "Πατησίων 112"), masked(t2));
        String t3 = "στο κατάστημα της οδού Θηβών 120.";
        assertEquals(expect(t3, "Θηβών 120"), masked(t3));
    }

    @Test
    void kilometreAddress() {
        String t = "Το σπίτι μου είναι στο 3ο χιλιόμετρο Λεωφόρου Μαραθώνος, Πικέρμι.";
        assertEquals(expect(t, "3ο χιλιόμετρο Λεωφόρου Μαραθώνος", "Πικέρμι"), masked(t));
    }

    // Every row has three columns; an empty trailing column is passed as null.
    @ParameterizedTest(name = "{0}")
    @CsvSource(delimiter = '|', value = {
            "Μένω στην Πλατεία Αμερικής, κοντά στο σούπερ μάρκετ.|Πλατεία Αμερικής|",
            "Μένω στην Πλάκα, πάνω από ένα καφέ.|Πλάκα|",
            "Ζω στη Νίκαια με τους γονείς μου.|Νίκαια|",
            "Είμαι από τη Ζωγράφου αλλά δουλεύω στο Μαρούσι.|Ζωγράφου|Μαρούσι",
            "Μένω στο Σύνταγμα, Φιλελλήνων 7.|Σύνταγμα|Φιλελλήνων 7",
            "και μένει μόνη στο Μεταξουργείο.|Μεταξουργείο|",
            "Είμαι ο Μάνος από το Γαλάτσι, ο Μανώλης δηλαδή.|Γαλάτσι|"})
    void placesAfterAResidenceOrWorkCue(String text, String first, String second) {
        String actual = masked(text);
        // Other capitalised words after the cue may be masked too ("Μανώλης"): only check the places.
        for (String part : second == null ? new String[] {first} : new String[] {first, second}) {
            int at = text.indexOf(part);
            assertEquals(ChatAsserts.dots(part), actual.substring(at, at + part.length()), part);
        }
    }

    @Test
    void postalCodeAfterTk() {
        String t = "Η νέα μου διεύθυνση: Αγίου Δημητρίου 8, Τ.Κ. 17341, Άγιος Δημήτριος.";
        assertEquals(expect(t, "Αγίου Δημητρίου 8", "17341", "Άγιος Δημήτριος"), masked(t));
    }

    @ParameterizedTest(name = "{0}")
    @CsvSource(delimiter = '|', value = {
            "Έχετε κατάστημα κοντά στην Πλατεία Αμερικής;",
            "Έχει πλάκα που ο λογαριασμός ήρθε διπλός.",
            "Διάβασα το Σύνταγμα για τα δικαιώματά μου.",
            "Ο λογαριασμός του Ιουνίου 2026 ήρθε διπλός.",
            "Πλήρωσα στις 15 Ιουνίου 2026.",
            "Η εφαρμογή σας κολλάει σε Android 14 και iPhone 15.",
            "Ο πελάτης σας 10 χρόνια."})
    void leavesNonAddressesAlone(String text) {
        assertEquals(text, masked(text));
    }

    @Test
    void aLineBreakEndsTheResidenceClause() {
        String t = "Χρήστης: Μένω στην Πλάκα\r\nBot: Ευχαριστώ Γιώργο";
        assertEquals(expect(t, "Πλάκα"), masked(t));
    }
}
```

In `placesAfterAResidenceOrWorkCue`, a CSV row with only two columns passes `null` as `second`. That is JUnit's default for a missing trailing column.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `mvn -q -Dtest=AddressDetectorTest test`
Expected: compilation failure, `cannot find symbol: class AddressDetector`.

- [ ] **Step 3: Implement**

`src/main/java/dev/filtsiap/ded/anonymizer/chat/AddressDetector.java`:
```java
package dev.filtsiap.ded.anonymizer.chat;

import dev.filtsiap.ded.anonymizer.pycompat.PyRegex;
import dev.filtsiap.ded.anonymizer.pycompat.PyRegex.PyMatch;
import dev.filtsiap.ded.anonymizer.pycompat.PyRegex.PyPattern;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * Where someone lives or works. Three shapes:
 * <ul>
 *   <li>a street: Greek capitalised words IN THE GENITIVE (how Greek streets are named: "Πατησίων",
 *       "Ελευθερίου Βενιζέλου") followed by a house number, or "3ο χιλιόμετρο Λεωφόρου …";</li>
 *   <li>a place after a residence or work cue ("μένω", "κατοικώ", "δουλεύω", "είμαι από",
 *       "διεύθυνση"): every capitalised run from the cue to the end of the sentence;</li>
 *   <li>a postal code after "Τ.Κ.".</li>
 * </ul>
 * The same place mentioned without a cue ("κατάστημα κοντά στην Πλατεία Αμερικής") is kept.
 */
public final class AddressDetector {
    private static final String UPPER = "A-ZΑ-ΩΆΈΉΊΌΎΏΪΫ";
    private static final String LOWER = "a-zα-ωάέήίόύώϊϋΐΰ";
    private static final String CAP_WORD = "[" + UPPER + "][" + LOWER + UPPER + "]+";
    private static final String GENITIVE_WORD = "[Α-ΩΆΈΉΊΌΎΏΪΫ][α-ωάέήίόύώϊϋΐΰ]*"
            + "(?:[ωώ]ν|ο[υύ]|[ηή]ς|[αά]ς|εως|ο[υύ]ς|[οό]ς)";

    static final PyPattern STREET_NUMBER = PyRegex.compile(
            "(?<![" + LOWER + UPPER + "])((?:" + GENITIVE_WORD + "\\s+){0,2}" + GENITIVE_WORD
                    + ")\\s+\\d{1,4}[α-δΑ-Δ]?(?![\\d,.]?\\d)"
                    + "(?!\\s*(?:€|ευρώ|%|χρόνια|χρονών|ημέρες|μήνες|λεπτά|ώρες|φορές))", 0);
    static final PyPattern KM_ADDRESS = PyRegex.compile(
            "\\d{1,3}(?:ο|ου)\\s+(?:χλμ\\.?|χιλιόμετρο|χιλιομέτρου)(?:\\s+" + GENITIVE_WORD + "){1,3}", 0);
    static final PyPattern CAP_RUN = PyRegex.compile(
            "(?<![" + LOWER + UPPER + "])" + CAP_WORD + "(?:[ \\t\\-]+" + CAP_WORD + ")*", 0);
    /** On the FOLDED text. */
    static final PyPattern RESIDENCE_CUE = PyRegex.compile(
            "\\b(?:μενω|μενει|μενουμε|μενετε|μενουν|κατοικω|κατοικει|κατοικουμε|ζω|ζει|ζουμε|καταγομαι|"
                    + "καταγεται|δουλευω|δουλευει|εργαζομαι|εργαζεται|διευθυνση|διευθυνσεισ|ειμαι\\s+απο|"
                    + "ειναι\\s+απο|ειμαι\\s+[οη]\\s+[^\\s,.]+(?:\\s+[^\\s,.]+)?\\s+απο|"
                    + "η\\s+δουλεια\\s+μου\\s+ειναι|το\\s+σπιτι\\s+μου\\s+ειναι)\\b", 0);
    /** On the FOLDED text; group 1 is the code. */
    static final PyPattern POSTAL_CODE = PyRegex.compile(
            "(?:(?<!\\w)τ\\.?\\s?κ\\.?|ταχυδρομικ\\w*\\s+κωδικ\\w*)\\s*:?\\s*(\\d{3}\\s?\\d{2})(?!\\d)", 0);

    private static final Set<String> MONTHS_GENITIVE = Set.of("ιανουαριου", "φεβρουαριου", "μαρτιου",
            "απριλιου", "μαιου", "ιουνιου", "ιουλιου", "αυγουστου", "σεπτεμβριου", "οκτωβριου", "νοεμβριου",
            "δεκεμβριου");

    public List<ChatSpan> detect(String text) {
        List<ChatSpan> out = new ArrayList<>();
        String folded = GreekFold.fold(text);
        int[] cps = text.codePoints().toArray();
        for (PyMatch m : STREET_NUMBER.finditer(text)) {
            String[] words = GreekFold.fold(m.group(1)).split("\\s+");
            if (!MONTHS_GENITIVE.contains(words[words.length - 1])) {
                out.add(new ChatSpan(m.start(), m.end(), PiiType.ADDRESS, "chat_street_number"));
            }
        }
        for (PyMatch m : KM_ADDRESS.finditer(text)) {
            out.add(new ChatSpan(m.start(), m.end(), PiiType.ADDRESS, "chat_km_address"));
        }
        for (PyMatch cue : RESIDENCE_CUE.finditer(folded)) {
            int end = sentenceEnd(cps, cue.end());
            String clause = new String(cps, cue.end(), end - cue.end());
            for (PyMatch run : CAP_RUN.finditer(clause)) {
                out.add(new ChatSpan(cue.end() + run.start(), cue.end() + run.end(), PiiType.LOCATION,
                        "chat_residence_cue"));
            }
        }
        for (PyMatch m : POSTAL_CODE.finditer(folded)) {
            out.add(new ChatSpan(m.start(1), m.end(1), PiiType.POSTAL_CODE, "chat_postal_code"));
        }
        return out;
    }

    /**
     * The first sentence end at or after {@code from}: ; ! ? \r \n, or a '.' followed by whitespace
     * and a capital (so "Τ.Κ. 17341" and "κ. Ράλλη" do not end it), or the end of the text.
     */
    static int sentenceEnd(int[] cps, int from) {
        for (int i = from; i < cps.length; i++) {
            int c = cps[i];
            if (c == ';' || c == '!' || c == '?' || c == '\r' || c == '\n') {
                return i;
            }
            if (c == '.') {
                int j = i + 1;
                while (j < cps.length && (cps[j] == ' ' || cps[j] == '\t')) {
                    j++;
                }
                if (j == cps.length || (j > i + 1 && Character.isUpperCase(cps[j]))) {
                    return i;
                }
            }
        }
        return cps.length;
    }
}
```

The clause is built with `new String(cps, offset, count)`, so `run.start()` is a code-point offset within the clause. Adding `cue.end()` gives a code-point offset into the text.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `mvn -q -Dtest=AddressDetectorTest test`
Expected: all pass. If `leavesNonAddressesAlone` fails on "Ο πελάτης σας 10 χρόνια.", the culprit is `(?!\s*(?:…χρόνια…))`. Check that the lookahead sits after the number, not after the word.

- [ ] **Step 5: Commit**

```bash
git add src/main/java/dev/filtsiap/ded/anonymizer/chat/AddressDetector.java src/test/java/dev/filtsiap/ded/anonymizer/chat/AddressDetectorTest.java
git commit -m "Add chat address, residence-cue and postal-code detector"
```

---

### Task 7: Name detector

**Files:**
- Create: `src/main/java/dev/filtsiap/ded/anonymizer/chat/NameDetector.java`
- Test: `src/test/java/dev/filtsiap/ded/anonymizer/chat/NameDetectorTest.java`

**Interfaces:**
- Consumes:
  - `ChatLists` (`isName`, `isCommonWord`, `greekProper()`, `greekCommon().containsWithinOneEdit`)
  - `GreekFold.fold`, `GreekInflection.family`
  - `ChatFixtures.LISTS` (tests)
- Produces: `new NameDetector(ChatLists lists)` and `List<ChatSpan> detect(String nfcText)`, which returns PERSON spans whose detector is one of `name_cue`, `name_cue_initial`, `name_list`, `name_after_article`, `uncommon_word`, `name_adjacent` or `name_propagated`.

How each word is decided, in order:
1. **Cue:** after a name cue, up to 3 following tokens are captured, plus any initials. A token is captured if it is capitalised, a known name, or not a common word. Capture stops at the first ordinary lowercase word or at punctuation.
2. **Lists:**
   - Saint guard: a token right after Άγιος/Αγίου/Αγία/… is skipped.
   - Known name, not a common word, not a known place: mask (confident).
   - Known name that is capitalised, not sentence-initial, and right after an article (ο, η, του, της, τον, την, τη): mask (confident).
   - Neither a known name, a common word nor a known place: if it is a typo of a common word, keep it; otherwise mask (`uncommon_word`).
3. **Neighbours (repeated until nothing changes):** a capitalised, non-sentence-initial, not-all-caps token, or an initial, right next to a masked token is masked.
4. **Propagation:** every form (`GreekInflection.family`) of a confident name is masked anywhere in the text.

- [ ] **Step 1: Write the failing tests**

`src/test/java/dev/filtsiap/ded/anonymizer/chat/NameDetectorTest.java`:
```java
package dev.filtsiap.ded.anonymizer.chat;

import static dev.filtsiap.ded.anonymizer.chat.ChatAsserts.expect;
import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class NameDetectorTest {
    static final NameDetector NAMES = new NameDetector(ChatFixtures.LISTS);

    private static String masked(String text) {
        return Masker.mask(text, NAMES.detect(text));
    }

    @Test
    void aCueTakesANameEvenWhenItIsACommonWord() {
        String t = "με λένε νίκη και θέλω να ακυρώσω τη συνδρομή";
        assertEquals(expect(t, "νίκη"), masked(t));
    }

    @Test
    void aNameThatIsACommonWordIsKeptWithoutACue() {
        String t = "δεν έχω καμία ελπίδα";
        assertEquals(t, masked(t));
        String t2 = "η ομάδα πήρε τη νίκη χθες";
        assertEquals(t2, masked(t2));
    }

    @Test
    void aCapitalisedNameAfterAnArticleIsMasked() {
        String t = "Η Νίκη μου είπε ότι το πρόβλημα λύθηκε.";
        assertEquals(expect(t, "Νίκη"), masked(t));
    }

    @Test
    void aKnownNameThatIsNotAWordIsMasked() {
        String t = "μίλησα με Αναστασία χθες";
        assertEquals(expect(t, "Αναστασία"), masked(t));
    }

    @Test
    void anUncommonWordIsMasked() {
        String t = "μίλησα με Ξανθίππη Μπαλαμώτη χθες";
        assertEquals(expect(t, "Ξανθίππη", "Μπαλαμώτη"), masked(t));
    }

    @Test
    void aTypoOfACommonWordIsKept() {
        String t = "ο λογαριασμόός ήρθε διπλός";
        assertEquals(t, masked(t));
    }

    @Test
    void aCueOverridesTheTypoRule() {
        String t = "με λένε Γιορτώ";   // one edit from "γιορτή", but after a cue
        assertEquals(expect(t, "Γιορτώ"), masked(t));
    }

    @Test
    void aCapitalisedWordNextToANameIsMasked() {
        String t = "hi I'm John Smith can you help me";
        assertEquals(expect(t, "John Smith"), masked(t));
    }

    @Test
    void anInitialBetweenNamesIsMasked() {
        String t = "Υπογραφή: Γιώργος Μ. Παπαδόπουλος";
        assertEquals(expect(t, "Γιώργος Μ. Παπαδόπουλος"), masked(t));
    }

    @Test
    void aConfirmedNameIsMaskedInItsOtherFormsEverywhere() {
        String t = "με λένε στέλιο\nBot: γεια σας Στέλιε";
        assertEquals(expect(t, "στέλιο", "Στέλιε"), masked(t));
    }

    @Test
    void aSaintsNameIsNotAPerson() {
        String t = "πολλά για τη γιορτή του Αγίου Γεωργίου";
        assertEquals(t, masked(t));
    }

    @Test
    void englishWordsUseTheEnglishLexiconAndAllowlistedTermsStay() {
        String t = "ok thanks for the bill, το iphone και η ΔΕΗ";
        assertEquals(t, masked(t));
    }

    @Test
    void aKnownPlaceWithoutCueIsKept() {
        String t = "θα είμαι στην Αμερική";
        assertEquals(t, masked(t));
    }

    @Test
    void hyphenatedSurnamePiecesAreMasked() {
        String t = "λέγομαι Μαρία Παπαδάκη-Ντόκου";
        assertEquals(expect(t, "Μαρία", "Παπαδάκη", "Ντόκου"), masked(t));
    }

    @Test
    void allCapsTextUsesTheListsNotCapitals() {
        String t = "ΣΑΣ ΓΡΑΦΕΙ Ο ΓΙΩΡΓΟΣ ΜΠΑΛΑΜΩΤΗΣ ΑΠΟ ΤΗ ΛΑΡΙΣΑ";
        // "σας γραφει απο τη" must be common words for this test: they are added below.
        NameDetector names = new NameDetector(ChatLists.of(ChatFixtures.names("Γιώργος"), java.util.List.of(),
                ChatFixtures.words(ChatFixtures.GREEK + " γράφει"), ChatFixtures.words("Λάρισα"),
                java.util.List.of(), java.util.List.of()));
        assertEquals(expect(t, "ΓΙΩΡΓΟΣ ΜΠΑΛΑΜΩΤΗΣ"), Masker.mask(t, names.detect(t)));
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `mvn -q -Dtest=NameDetectorTest test`
Expected: compilation failure, `cannot find symbol: class NameDetector`.

- [ ] **Step 3: Implement**

`src/main/java/dev/filtsiap/ded/anonymizer/chat/NameDetector.java`:
```java
package dev.filtsiap.ded.anonymizer.chat;

import dev.filtsiap.ded.anonymizer.pycompat.PyRegex;
import dev.filtsiap.ded.anonymizer.pycompat.PyRegex.PyMatch;
import dev.filtsiap.ded.anonymizer.pycompat.PyRegex.PyPattern;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Person names in chat text, by four kinds of evidence, strongest first: a cue ("με λένε",
 * "κύριε", "Υπογραφή:"), the name lists, the lexicons (a word that is not ordinary Greek or English
 * is masked: that is how unusual names are caught), and position (next to a masked name, or after
 * an article). A confirmed name is then masked in all its forms across the text.
 */
public final class NameDetector {
    static final PyPattern TOKEN = PyRegex.compile(
            "[A-Za-zÀ-ÖØ-öø-ÿΑ-Ωα-ωΆΈΉΊΌΎΏάέήίόύώΪΫϊϋΐΰ]+", 0);
    /** On the FOLDED text. */
    static final PyPattern NAME_CUE = PyRegex.compile(
            "(?<!\\w)(?:με\\s+λενε|με\\s+λεν|λεγομαι|ονομαζομαι|το\\s+ονομα\\s+μου\\s+ειναι|ειμαι\\s+[οη]"
                    + "|κυριε|κυρια|κυριο|κυριου|κυριασ|κοσ|κα\\.?|κ\\.|υπογραφη\\s*:?|εκ\\s+μερουσ\\s+(?:του|τησ)"
                    + "|ευχαριστω|ευχαριστουμε|στο\\s+ονομα|κουδουνι|i'?m|my\\s+name\\s+is|mr\\.?|mrs\\.?|ms\\.?)"
                    + "(?=\\s|$)", 0);
    static final PyPattern SURNAME_ENDING = PyRegex.compile(
            "(?:οπουλοσ|οπουλου|οπουλο|ακησ|ακη|ιδησ|ιδη|ιδου|ιαδησ|ιαδη|αδησ|αδη|ογλου|ελλησ|ιωτησ|ιωτη"
                    + "|ουδησ|ουδη|αιοσ|αιου)$", 0);
    private static final Set<String> ARTICLES = Set.of("ο", "η", "του", "τησ", "τον", "την", "τη");
    private static final Set<String> SAINT_WORDS = Set.of("αγιοσ", "αγιου", "αγιο", "αγια", "αγιασ", "αγιων",
            "αγιε", "αγ");
    private static final int MAX_CUE_TOKENS = 3;
    private static final int TYPO_MIN_LENGTH = 6;
    /** Longer tokens are never typo-checked: the one-edit search is quadratic in the length. */
    private static final int TYPO_MAX_LENGTH = 30;
    private static final String CLAUSE_BREAKS = ",;:!?()«»\"\r\n";

    record Token(int start, int end, String folded, boolean capitalised, boolean allCaps,
                 boolean sentenceInitial, boolean greek) {
        int length() {
            return end - start;
        }
    }

    private final ChatLists lists;

    public NameDetector(ChatLists lists) {
        this.lists = lists;
    }

    public List<ChatSpan> detect(String text) {
        String folded = GreekFold.fold(text);
        int[] cps = text.codePoints().toArray();
        List<Token> tokens = tokenize(text, folded, cps);
        String[] verdict = new String[tokens.size()];
        boolean[] confident = new boolean[tokens.size()];

        applyCues(folded, cps, tokens, verdict, confident);
        applyLists(cps, tokens, verdict, confident);
        applyNeighbours(cps, tokens, verdict);
        applyPropagation(cps, tokens, verdict, confident);

        List<ChatSpan> out = new ArrayList<>();
        for (int i = 0; i < tokens.size(); i++) {
            if (verdict[i] != null) {
                out.add(new ChatSpan(tokens.get(i).start(), tokens.get(i).end(), PiiType.PERSON, verdict[i]));
            }
        }
        return out;
    }

    private static List<Token> tokenize(String text, String folded, int[] cps) {
        List<Token> tokens = new ArrayList<>();
        for (PyMatch m : TOKEN.finditer(text)) {
            int s = m.start();
            int e = m.end();
            boolean allCaps = true;
            boolean greek = false;
            for (int i = s; i < e; i++) {
                allCaps &= Character.isUpperCase(cps[i]);
                greek |= Character.UnicodeScript.of(cps[i]) == Character.UnicodeScript.GREEK;
            }
            tokens.add(new Token(s, e, new String(folded.codePoints().skip(s).limit(e - s).toArray(), 0, e - s),
                    Character.isUpperCase(cps[s]), allCaps && e - s > 1, sentenceInitial(cps, s), greek));
        }
        return tokens;
    }

    /** No letter or digit before {@code start} since the text began or since . ! ? : ; or a line break. */
    private static boolean sentenceInitial(int[] cps, int start) {
        for (int i = start - 1; i >= 0; i--) {
            int c = cps[i];
            if (c == '.' || c == '!' || c == '?' || c == ':' || c == ';' || c == '\n' || c == '\r') {
                return true;
            }
            if (Character.isLetterOrDigit(c)) {
                return false;
            }
        }
        return true;
    }

    private void applyCues(String folded, int[] cps, List<Token> tokens, String[] verdict, boolean[] confident) {
        for (PyMatch cue : NAME_CUE.finditer(folded)) {
            int k = firstTokenAtOrAfter(tokens, cue.end());
            int prevEnd = cue.end();
            Token prev = null;
            int taken = 0;
            while (k < tokens.size() && taken < MAX_CUE_TOKENS) {
                Token t = tokens.get(k);
                if (breaksBetween(cps, prevEnd, t.start(), prev)) {
                    break;
                }
                if (isInitial(t, cps)) {
                    verdict[k] = "name_cue_initial";
                } else if (t.capitalised() || lists.isName(t.folded()) || !lists.isCommonWord(t.folded())) {
                    verdict[k] = "name_cue";
                    confident[k] = true;
                    taken++;
                } else {
                    break;
                }
                prevEnd = t.end();
                prev = t;
                k++;
            }
        }
    }

    private void applyLists(int[] cps, List<Token> tokens, String[] verdict, boolean[] confident) {
        for (int i = 0; i < tokens.size(); i++) {
            Token t = tokens.get(i);
            if (verdict[i] != null || t.length() < 2 || afterSaintWord(cps, tokens, i)) {
                continue;
            }
            String f = t.folded();
            boolean name = lists.isName(f);
            boolean common = lists.isCommonWord(f);
            boolean place = lists.greekProper().contains(f);
            if (name && !common && !place) {
                verdict[i] = "name_list";
                confident[i] = true;
            } else if (name && t.capitalised() && !t.sentenceInitial() && i > 0
                    && ARTICLES.contains(tokens.get(i - 1).folded())
                    && onlySpaces(cps, tokens.get(i - 1).end(), t.start())) {
                verdict[i] = "name_after_article";
                confident[i] = true;
            } else if (!name && !common && !place && !isTypo(t)) {
                verdict[i] = "uncommon_word";
            }
        }
    }

    private boolean isTypo(Token t) {
        return t.greek() && t.length() >= TYPO_MIN_LENGTH && t.length() <= TYPO_MAX_LENGTH
                && SURNAME_ENDING.search(t.folded()) == null
                && lists.greekCommon().containsWithinOneEdit(t.folded());
    }

    private static void applyNeighbours(int[] cps, List<Token> tokens, String[] verdict) {
        boolean changed = true;
        while (changed) {
            changed = false;
            for (int i = 0; i < tokens.size(); i++) {
                Token t = tokens.get(i);
                if (verdict[i] != null || afterSaintWord(cps, tokens, i)) {
                    continue;
                }
                boolean eligible = isInitial(t, cps)
                        || (t.capitalised() && !t.allCaps() && !t.sentenceInitial() && t.length() >= 2);
                if (!eligible) {
                    continue;
                }
                boolean left = i > 0 && verdict[i - 1] != null && adjacent(cps, tokens.get(i - 1), t);
                boolean right = i + 1 < tokens.size() && verdict[i + 1] != null && adjacent(cps, t, tokens.get(i + 1));
                if (left || right) {
                    verdict[i] = "name_adjacent";
                    changed = true;
                }
            }
        }
    }

    private static void applyPropagation(int[] cps, List<Token> tokens, String[] verdict, boolean[] confident) {
        Set<String> family = new HashSet<>();
        for (int i = 0; i < tokens.size(); i++) {
            if (confident[i] && tokens.get(i).length() >= 3) {
                family.addAll(GreekInflection.family(tokens.get(i).folded()));
            }
        }
        for (int i = 0; i < tokens.size(); i++) {
            Token t = tokens.get(i);
            if (verdict[i] == null && t.length() >= 3 && family.contains(t.folded())
                    && !afterSaintWord(cps, tokens, i)) {
                verdict[i] = "name_propagated";
            }
        }
    }

    /** Binary search: tokens are in text order, so a text with thousands of cues stays linear-ish. */
    private static int firstTokenAtOrAfter(List<Token> tokens, int pos) {
        int lo = 0;
        int hi = tokens.size();
        while (lo < hi) {
            int mid = (lo + hi) >>> 1;
            if (tokens.get(mid).start() < pos) {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        return lo;
    }

    /** A single capital letter directly followed by '.': "Μ." in "Γιώργος Μ. Παπαδόπουλος". */
    private static boolean isInitial(Token t, int[] cps) {
        return t.length() == 1 && t.capitalised() && t.end() < cps.length && cps[t.end()] == '.';
    }

    /** Between two tokens: only spaces/tabs or one hyphen; or '.' and spaces after an initial. */
    private static boolean adjacent(int[] cps, Token a, Token b) {
        int dots = 0;
        int hyphens = 0;
        for (int i = a.end(); i < b.start(); i++) {
            int c = cps[i];
            if (c == '.') {
                dots++;
            } else if (c == '-') {
                hyphens++;
            } else if (c != ' ' && c != '\t') {
                return false;
            }
        }
        return hyphens <= 1 && (dots == 0 || (dots == 1 && isInitial(a, cps)));
    }

    /** Clause punctuation between {@code from} and {@code to}, or a '.' that does not follow an initial. */
    private static boolean breaksBetween(int[] cps, int from, int to, Token prev) {
        for (int i = from; i < to; i++) {
            int c = cps[i];
            if (CLAUSE_BREAKS.indexOf(c) >= 0) {
                return true;
            }
            if (c == '.' && !(prev != null && isInitial(prev, cps) && i == prev.end())) {
                return true;
            }
        }
        return false;
    }

    private static boolean onlySpaces(int[] cps, int from, int to) {
        for (int i = from; i < to; i++) {
            if (cps[i] != ' ' && cps[i] != '\t') {
                return false;
            }
        }
        return true;
    }

    private static boolean afterSaintWord(int[] cps, List<Token> tokens, int i) {
        if (i == 0 || !SAINT_WORDS.contains(tokens.get(i - 1).folded())) {
            return false;
        }
        for (int c = tokens.get(i - 1).end(); c < tokens.get(i).start(); c++) {
            if (cps[c] != ' ' && cps[c] != '.') {
                return false;
            }
        }
        return true;
    }
}
```

The `Token.folded` slice is taken from the folded string by code points. The `folded.codePoints().skip(s).limit(e - s)` expression rescans from the start for every token, which is O(n²) on a long text. Replace it with an `int[] foldedCps = folded.codePoints().toArray()`, computed once in `tokenize`, and `new String(foldedCps, s, e - s)`. Review-focus item 4 (`longInputStaysFast`) will catch the slow version.

Use this for `tokenize`:
```java
    private static List<Token> tokenize(String text, String folded, int[] cps) {
        int[] foldedCps = folded.codePoints().toArray();
        List<Token> tokens = new ArrayList<>();
        for (PyMatch m : TOKEN.finditer(text)) {
            int s = m.start();
            int e = m.end();
            boolean allCaps = true;
            boolean greek = false;
            for (int i = s; i < e; i++) {
                allCaps &= Character.isUpperCase(cps[i]);
                greek |= Character.UnicodeScript.of(cps[i]) == Character.UnicodeScript.GREEK;
            }
            tokens.add(new Token(s, e, new String(foldedCps, s, e - s), Character.isUpperCase(cps[s]),
                    allCaps && e - s > 1, sentenceInitial(cps, s), greek));
        }
        return tokens;
    }
```

`PyPattern.search` returns null on no match; it is used for `SURNAME_ENDING`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `mvn -q -Dtest=NameDetectorTest test`
Expected: all pass. When one fails, print `NAMES.detect(t)` and use each span's `detector` to see which rule fired or failed. The likely culprits:
- A fixture word missing from `ChatFixtures.GREEK`: add it to the fixture, not to the detector.
- A cue that `NAME_CUE` doesn't match on the folded text: print `GreekFold.fold(t)`.

- [ ] **Step 5: Commit**

```bash
git add src/main/java/dev/filtsiap/ded/anonymizer/chat/NameDetector.java src/test/java/dev/filtsiap/ded/anonymizer/chat/NameDetectorTest.java
git commit -m "Add chat name detector: cues, name lists, uncommon words, propagation"
```

---

### Task 8: NER slot, residual check and the chat pipeline

**Files:**
- Create: `src/main/java/dev/filtsiap/ded/anonymizer/chat/NerDetector.java`
- Create: `src/main/java/dev/filtsiap/ded/anonymizer/chat/NerUnavailableException.java`
- Create: `src/main/java/dev/filtsiap/ded/anonymizer/chat/ResidualCheck.java`
- Create: `src/main/java/dev/filtsiap/ded/anonymizer/chat/ChatPipeline.java`
- Modify: `src/main/java/dev/filtsiap/ded/anonymizer/PostcheckPatterns.java`. Line 14 becomes `public final class PostcheckPatterns {`, and line 17 becomes `public static final Map<String, PyPattern> QA_PATTERNS;`.
- Test: `src/test/java/dev/filtsiap/ded/anonymizer/chat/ChatPipelineTest.java`

**Interfaces:**
- Consumes: `IdDetector`, `AddressDetector`, `NameDetector`, `Masker`, `ChatLists`, `ChatSettings`, `FileConfig.rules()`, `Deadline.check(String)`, `PostcheckPatterns.QA_PATTERNS`.
- Produces:
  - `interface NerDetector { List<ChatSpan> detect(String text) throws NerUnavailableException; NerDetector NONE; }`
  - `ChatPipeline(DetectorRules rules, ChatLists lists, NerDetector ner, boolean rulesEnabled)`
  - `ChatPipeline.production(FileConfig files, ChatLists lists, ChatSettings settings)`
  - `ChatPipeline.TextResult anonymize(String text, Deadline deadline)`
  - `record TextResult(String masked, Status status, Map<PiiType,Integer> counts, List<String> reviewReasons)`
  - `enum Status { ANONYMIZED, NEEDS_REVIEW; String wire(); }`, where `wire()` returns `anonymized` / `needs-review`.

- [ ] **Step 1: Write the failing tests**

`src/test/java/dev/filtsiap/ded/anonymizer/chat/ChatPipelineTest.java`:
```java
package dev.filtsiap.ded.anonymizer.chat;

import static dev.filtsiap.ded.anonymizer.chat.ChatAsserts.expect;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.filtsiap.ded.anonymizer.Config;
import dev.filtsiap.ded.anonymizer.Deadline;
import dev.filtsiap.ded.anonymizer.DetectorRules;
import dev.filtsiap.ded.anonymizer.RunContext;
import java.nio.file.Path;
import java.text.Normalizer;
import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.Test;

class ChatPipelineTest {
    static final DetectorRules RULES = Config.loadFileConfig(Path.of("config")).rules();
    static final ChatPipeline PIPELINE = new ChatPipeline(RULES, ChatFixtures.LISTS, NerDetector.NONE, true);

    private static Deadline deadline() {
        return RunContext.start(60).deadline();
    }

    @Test
    void masksIdsAddressesAndNamesTogether() {
        String t = "Καλησπέρα, με λένε γιώργο παπαδόπουλο. ΑΦΜ 090000045. Ο γιώργος μένει στην Πατησίων 25, "
                + "τηλ 6912345678";
        ChatPipeline.TextResult r = PIPELINE.anonymize(t, deadline());
        assertEquals(expect(t, "γιώργος", "γιώργο", "παπαδόπουλο", "090000045", "Πατησίων 25", "6912345678"),
                r.masked());
        assertEquals(ChatPipeline.Status.ANONYMIZED, r.status());
        assertEquals(1, r.counts().get(PiiType.AFM));
        assertEquals(1, r.counts().get(PiiType.PHONE));
        assertEquals(1, r.counts().get(PiiType.ADDRESS));
        assertTrue(r.counts().get(PiiType.PERSON) >= 3);
    }

    @Test
    void emojiDoesNotShiftMasks() {
        String t = "🙏 ΑΦΜ 090000045";
        assertEquals(expect(t, "090000045"), PIPELINE.anonymize(t, deadline()).masked());
    }

    @Test
    void nfdInputIsNormalisedBeforeMatching() {
        String nfc = "μίλησα με Αναστασία χθες";
        String nfd = Normalizer.normalize(nfc, Normalizer.Form.NFD);
        assertEquals(expect(nfc, "Αναστασία"), PIPELINE.anonymize(nfd, deadline()).masked());
    }

    @Test
    void aResidualDigitRunIsMaskedAndAsksForReview() {
        String t = "ο αριθμός 1234567890 χθες";
        ChatPipeline.TextResult r = new ChatPipeline(RULES, ChatFixtures.LISTS, NerDetector.NONE, true)
                .anonymize(t, deadline());
        assertEquals(expect(t, "1234567890"), r.masked());
        assertEquals(ChatPipeline.Status.NEEDS_REVIEW, r.status());
        assertEquals(List.of("residual:DIGIT_RUN"), r.reviewReasons());
    }

    @Test
    void nerSpansOnlyAdd() {
        String t = "δεν έχω καμία ελπίδα";
        int at = t.indexOf("ελπίδα");
        NerDetector stub = text -> List.of(new ChatSpan(at, at + 6, PiiType.PERSON, "stub"));
        assertEquals(expect(t, "ελπίδα"),
                new ChatPipeline(RULES, ChatFixtures.LISTS, stub, true).anonymize(t, deadline()).masked());
        assertEquals(expect(t, "ελπίδα"),
                new ChatPipeline(RULES, ChatFixtures.LISTS, stub, false).anonymize(t, deadline()).masked());
    }

    @Test
    void anUnavailableNerFallsBackToTheRulesAndAsksForReview() {
        String t = "ΑΦΜ 090000045";
        NerDetector broken = text -> {
            throw new NerUnavailableException("model down", null);
        };
        ChatPipeline.TextResult r = new ChatPipeline(RULES, ChatFixtures.LISTS, broken, true).anonymize(t, deadline());
        assertEquals(expect(t, "090000045"), r.masked());
        assertEquals(ChatPipeline.Status.NEEDS_REVIEW, r.status());
        assertEquals(List.of("ner_unavailable"), r.reviewReasons());
    }

    @Test
    void longInputStaysFast() {
        String digits = "6 9 1 ".repeat(35_000);
        String word = "α".repeat(50_000);
        String mixed = "με λένε Ξανθίππη, ΑΦΜ 090000045. ".repeat(4_000);
        assertTimeoutPreemptively(Duration.ofSeconds(10), () -> {
            PIPELINE.anonymize(digits, deadline());
            PIPELINE.anonymize(word, deadline());
            PIPELINE.anonymize(mixed, deadline());
        });
    }

    @Test
    void emptyTextIsAnonymized() {
        ChatPipeline.TextResult r = PIPELINE.anonymize("", deadline());
        assertEquals("", r.masked());
        assertEquals(ChatPipeline.Status.ANONYMIZED, r.status());
    }
}
```

`RunContext.start(double seconds)` exists (`RunContext.java:23`). In `masksIdsAddressesAndNamesTogether`, "τηλ" and "ΑΦΜ" are kept because the fixture allowlist contains `τηλ` and `αφμ`.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `mvn -q -Dtest=ChatPipelineTest test`
Expected: compilation failure, `cannot find symbol: class ChatPipeline`.

- [ ] **Step 3: Implement**

Apply the two visibility changes to `PostcheckPatterns.java` listed under **Files**.

`src/main/java/dev/filtsiap/ded/anonymizer/chat/NerUnavailableException.java`:
```java
package dev.filtsiap.ded.anonymizer.chat;

/** The NER model could not answer (crash, timeout, sidecar down). The rules' result still goes out. */
public final class NerUnavailableException extends Exception {
    private static final long serialVersionUID = 1L;

    public NerUnavailableException(String message, Throwable cause) {
        super(message, cause);
    }
}
```

`src/main/java/dev/filtsiap/ded/anonymizer/chat/NerDetector.java`:
```java
package dev.filtsiap.ded.anonymizer.chat;

import java.util.List;

/**
 * The NER slot. A model's spans are ADDED to the rules' spans and never remove one, so turning a
 * model on can only mask more. v1 ships only {@link #NONE}; an ONNX or HTTP adapter implements this
 * interface later and is selected in config/chat/chat.yaml.
 */
@FunctionalInterface
public interface NerDetector {
    List<ChatSpan> detect(String text) throws NerUnavailableException;

    NerDetector NONE = text -> List.of();
}
```

`src/main/java/dev/filtsiap/ded/anonymizer/chat/ResidualCheck.java`:
```java
package dev.filtsiap.ded.anonymizer.chat;

import dev.filtsiap.ded.anonymizer.PostcheckPatterns;
import dev.filtsiap.ded.anonymizer.pycompat.PyRegex.PyMatch;
import dev.filtsiap.ded.anonymizer.pycompat.PyRegex.PyPattern;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** The .docx post-check's QA patterns over the MASKED text: anything still matching slipped past every detector. */
final class ResidualCheck {
    private static final Map<String, PiiType> TYPES = Map.of("AFM", PiiType.AFM, "AMKA", PiiType.AMKA,
            "IBAN_GR", PiiType.IBAN, "EMAIL", PiiType.EMAIL, "PHONE", PiiType.PHONE, "DIGIT_RUN", PiiType.OTHER);

    private ResidualCheck() {
    }

    /** Spans named "residual:<QA pattern key>". */
    static List<ChatSpan> find(String masked) {
        List<ChatSpan> out = new ArrayList<>();
        for (Map.Entry<String, PyPattern> e : PostcheckPatterns.QA_PATTERNS.entrySet()) {
            for (PyMatch m : e.getValue().finditer(masked)) {
                out.add(new ChatSpan(m.start(), m.end(), TYPES.getOrDefault(e.getKey(), PiiType.OTHER),
                        "residual:" + e.getKey()));
            }
        }
        return out;
    }
}
```

`src/main/java/dev/filtsiap/ded/anonymizer/chat/ChatPipeline.java`:
```java
package dev.filtsiap.ded.anonymizer.chat;

import dev.filtsiap.ded.anonymizer.Deadline;
import dev.filtsiap.ded.anonymizer.DetectorRules;
import dev.filtsiap.ded.anonymizer.FileConfig;
import java.text.Normalizer;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;

/**
 * POST /anonymize-text: NFC, every detector, union mask, residual re-scan. No LLM. The output is
 * the NFC text with masked code points, so its code-point length is the NFC input's.
 */
public final class ChatPipeline {

    public enum Status {
        ANONYMIZED("anonymized"), NEEDS_REVIEW("needs-review");

        private final String wire;

        Status(String wire) {
            this.wire = wire;
        }

        public String wire() {
            return wire;
        }
    }

    /** {@code reviewReasons}: fixed strings only ("ner_unavailable", "residual:AFM"), never text. */
    public record TextResult(String masked, Status status, Map<PiiType, Integer> counts, List<String> reviewReasons) {
    }

    private final IdDetector ids;
    private final AddressDetector addresses = new AddressDetector();
    private final NameDetector names;
    private final NerDetector ner;
    private final boolean rulesEnabled;

    /**
     * {@code rulesEnabled} false runs the NER alone (the eval's "ner" mode); production always runs
     * the rules. The residual re-scan belongs to the rules.
     */
    public ChatPipeline(DetectorRules rules, ChatLists lists, NerDetector ner, boolean rulesEnabled) {
        this.ids = new IdDetector(rules);
        this.names = new NameDetector(lists);
        this.ner = ner;
        this.rulesEnabled = rulesEnabled;
    }

    /** ChatSettings.load has already refused an enabled NER, so this is the rules with NER off. */
    public static ChatPipeline production(FileConfig files, ChatLists lists, ChatSettings settings) {
        return new ChatPipeline(files.rules(), lists, NerDetector.NONE, true);
    }

    public TextResult anonymize(String input, Deadline deadline) {
        String text = Normalizer.normalize(input, Normalizer.Form.NFC);
        List<ChatSpan> spans = new ArrayList<>();
        List<String> reasons = new ArrayList<>();
        if (rulesEnabled) {
            spans.addAll(ids.detect(text));
            deadline.check("chat_ids");
            spans.addAll(addresses.detect(text));
            spans.addAll(names.detect(text));
            deadline.check("chat_names");
        }
        try {
            spans.addAll(ner.detect(text));
        } catch (NerUnavailableException e) {
            reasons.add("ner_unavailable");
        }
        String masked = Masker.mask(text, spans);
        if (rulesEnabled) {
            List<ChatSpan> residual = ResidualCheck.find(masked);
            if (!residual.isEmpty()) {
                masked = Masker.mask(masked, residual);
                spans.addAll(residual);
                TreeSet<String> kinds = new TreeSet<>();
                residual.forEach(s -> kinds.add(s.detector()));
                reasons.addAll(kinds);
            }
        }
        Status status = reasons.isEmpty() ? Status.ANONYMIZED : Status.NEEDS_REVIEW;
        return new TextResult(masked, status, Masker.counts(spans), List.copyOf(reasons));
    }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `mvn -q -Dtest=ChatPipelineTest test`
Expected: all pass. If `longInputStaysFast` times out, profile which call is slow:
- `NameDetector.tokenize` must use the `foldedCps` array (Task 7 note).
- `AddressDetector.sentenceEnd` is linear per cue. If the text has thousands of cues, that is still fine.

- [ ] **Step 5: Run the whole suite (visibility change)**

Run: `mvn -q test`
Expected: everything passes.

- [ ] **Step 6: Commit**

```bash
git add src/main/java/dev/filtsiap/ded/anonymizer src/test/java/dev/filtsiap/ded/anonymizer/chat
git commit -m "Add chat pipeline with NER slot and residual re-scan"
```

---

### Task 9: `POST /anonymize-text`

**Files:**
- Modify: `src/main/java/dev/filtsiap/ded/api/ApiHandler.java`
  - `ROUTES` (line 109)
  - constructors (lines 122-149)
  - `route` (lines 212-240)
  - new methods next to `anonymize`
- Modify: `src/main/java/dev/filtsiap/ded/api/ApiServer.java`
  - `start` (lines 112-122)
  - `main` (lines 430-460)
- Test: `src/test/java/dev/filtsiap/ded/api/ApiTextEndpointTest.java`

**Interfaces:**
- Consumes: `ChatPipeline`, `ChatPipeline.TextResult`, `Masker.countsHeader`, `ChatLists.load`, `ChatSettings.load`, and the `ApiHandlerTest.serve`, `CFG`, `HTTP`, `SECRET` and `text` helpers (package-private statics in the same package).
- Produces:
  - `ApiHandler.TextProcessor` (`TextResult process(String text, RunContext ctx)`)
  - `ApiHandler(RuntimeConfig, LongSupplier, Processor, TextProcessor)` for tests
  - `ApiHandler(RuntimeConfig, FileConfig, LlmClient, ChatPipeline, BooleanSupplier)` for production
  - `ApiServer.start(RuntimeConfig, FileConfig, ChatPipeline, LlmClient, InetSocketAddress, int)`

Contract:
- Request: `Content-Type: text/plain`, charset absent or `utf-8`.
- Body limit: `ANON_MAX_TEXT_CHARS × 4` bytes.
- Response: `200 text/plain; charset=utf-8` with headers `x-document-id`, `x-anonymization-status`, `x-redaction-counts`, `x-review-reasons` (only when needs-review) and `x-processing-time-ms`.
- Errors: 401 (auth), 415 (type or charset), 400 (invalid UTF-8), 413 (too many characters), 503 (no chat pipeline configured).

- [ ] **Step 1: Write the failing tests**

`src/test/java/dev/filtsiap/ded/api/ApiTextEndpointTest.java`:
```java
package dev.filtsiap.ded.api;

import static dev.filtsiap.ded.api.ApiHandlerTest.CFG;
import static dev.filtsiap.ded.api.ApiHandlerTest.HTTP;
import static dev.filtsiap.ded.api.ApiHandlerTest.SECRET;
import static dev.filtsiap.ded.api.ApiHandlerTest.serve;
import static dev.filtsiap.ded.api.ApiHandlerTest.text;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import dev.filtsiap.ded.anonymizer.Config;
import dev.filtsiap.ded.anonymizer.RuntimeConfig;
import dev.filtsiap.ded.anonymizer.chat.ChatLists;
import dev.filtsiap.ded.anonymizer.chat.ChatPipeline;
import dev.filtsiap.ded.anonymizer.chat.NerDetector;
import dev.filtsiap.ded.anonymizer.chat.PiiType;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

class ApiTextEndpointTest {
    static final ChatPipeline CHAT = new ChatPipeline(Config.loadFileConfig(Path.of("config")).rules(),
            ChatLists.of(List.of("Αναστασία"), List.of(), List.of("μίλησα", "με", "χθες"), List.of(), List.of(),
                    List.of("αφμ")),
            NerDetector.NONE, true);

    static HttpRequest postText(ApiServer server, byte[] body, String contentType, boolean auth) {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + server.port() + "/anonymize-text"))
                .POST(HttpRequest.BodyPublishers.ofByteArray(body)).header("Content-Type", contentType);
        if (auth) {
            b.header("Authorization", "Bearer k3y");
        }
        return b.build();
    }

    static HttpResponse<byte[]> send(ApiHandler handler, byte[] body, String contentType, boolean auth) throws Exception {
        ApiServer server = serve(handler, 2);
        try {
            return HTTP.send(postText(server, body, contentType, auth), HttpResponse.BodyHandlers.ofByteArray());
        } finally {
            server.stop(0);
        }
    }

    static ApiHandler real(RuntimeConfig cfg) {
        return new ApiHandler(cfg, System::nanoTime, ApiHandlerTest::pipeline,
                (text, ctx) -> CHAT.anonymize(text, ctx.deadline()));
    }

    static byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    @Test
    void masksTheTextAndReportsStatusAndCounts() throws Exception {
        HttpResponse<byte[]> r = send(real(CFG), utf8("μίλησα με Αναστασία, ΑΦΜ 090000045"),
                "text/plain; charset=utf-8", true);
        assertEquals(200, r.statusCode());
        assertEquals("μίλησα με ........., ΑΦΜ .........", text(r));
        assertEquals("text/plain; charset=utf-8", r.headers().firstValue("Content-Type").orElse(""));
        assertEquals("anonymized", r.headers().firstValue("x-anonymization-status").orElse(""));
        assertEquals("PERSON=1,AFM=1", r.headers().firstValue("x-redaction-counts").orElse(""));
        assertTrue(r.headers().firstValue("x-document-id").isPresent());
        assertTrue(r.headers().firstValue("x-processing-time-ms").isPresent());
        assertFalse(r.headers().firstValue("x-review-reasons").isPresent());
    }

    @Test
    void aMissingCharsetMeansUtf8() throws Exception {
        assertEquals(200, send(real(CFG), utf8("χθες"), "text/plain", true).statusCode());
    }

    @Test
    void needsReviewCarriesItsReasons() throws Exception {
        ApiHandler handler = new ApiHandler(CFG, System::nanoTime, ApiHandlerTest::pipeline,
                (text, ctx) -> new ChatPipeline.TextResult("...", ChatPipeline.Status.NEEDS_REVIEW,
                        Map.of(PiiType.OTHER, 1), List.of("residual:DIGIT_RUN")));
        HttpResponse<byte[]> r = send(handler, utf8("abc"), "text/plain", true);
        assertEquals("needs-review", r.headers().firstValue("x-anonymization-status").orElse(""));
        assertEquals("residual:DIGIT_RUN", r.headers().firstValue("x-review-reasons").orElse(""));
    }

    @Test
    void crlfAndEmojiSurviveTheRoundTrip() throws Exception {
        HttpResponse<byte[]> r = send(real(CFG), utf8("🙏\r\nΑΦΜ 090000045"), "text/plain", true);
        assertEquals("🙏\r\nΑΦΜ .........", text(r));
    }

    @Test
    void anEmptyBodyIsAnEmptyAnswer() throws Exception {
        HttpResponse<byte[]> r = send(real(CFG), new byte[0], "text/plain", true);
        assertEquals(200, r.statusCode());
        assertEquals("", text(r));
    }

    @Test
    void requiresTheBearerToken() throws Exception {
        assertEquals(401, send(real(CFG), utf8("χθες"), "text/plain", false).statusCode());
    }

    @Test
    void refusesOtherMediaTypesAndCharsets() throws Exception {
        assertEquals(415, send(real(CFG), utf8("χθες"), "application/json", true).statusCode());
        assertEquals(415, send(real(CFG), "χθες".getBytes(java.nio.charset.Charset.forName("ISO-8859-7")),
                "text/plain; charset=iso-8859-7", true).statusCode());
    }

    @Test
    void refusesInvalidUtf8() throws Exception {
        HttpResponse<byte[]> r = send(real(CFG), new byte[] {(byte) 0xC3, (byte) 0x28}, "text/plain", true);
        assertEquals(400, r.statusCode());
        assertTrue(text(r).contains("INVALID_UTF8"));
    }

    @Test
    void refusesTextOverTheCharacterLimit() throws Exception {
        RuntimeConfig small = Config.loadRuntimeConfig(Map.of("ANON_PROVIDER", "openai", "OPENAI_API_KEY", "sk-test",
                "ANON_MODEL", "gpt-test", "ANON_API_KEY", "k3y", "ANON_MAX_TEXT_CHARS", "10"));
        assertEquals(413, send(real(small), utf8("αβγδεζηθικλ"), "text/plain", true).statusCode());
        assertEquals(200, send(real(small), utf8("αβγδεζηθικ"), "text/plain", true).statusCode());
    }

    @Test
    void anUnconfiguredChatPipelineIs503() throws Exception {
        ApiHandler docxOnly = new ApiHandler(CFG, System::nanoTime, ApiHandlerTest::pipeline);
        assertEquals(503, send(docxOnly, utf8("χθες"), "text/plain", true).statusCode());
    }

    @Test
    void logLinesNeverContainTheText() throws Exception {
        Logger api = (Logger) LoggerFactory.getLogger("anonymizer.api");
        ListAppender<ILoggingEvent> logs = new ListAppender<>();
        logs.start();
        api.addAppender(logs);
        try {
            send(real(CFG), utf8("με λένε " + SECRET), "text/plain", true);
            send(real(CFG), utf8(SECRET), "application/json", true);
        } finally {
            api.detachAppender(logs);
        }
        assertTrue(logs.list.stream().anyMatch(e -> e.getFormattedMessage().startsWith("text_finished")));
        assertTrue(logs.list.stream().noneMatch(e -> e.getFormattedMessage().contains("Παπαδόπουλος")));
    }
}
```

`refusesTextOverTheCharacterLimit` sets `ANON_MAX_TEXT_CHARS=10`. If `Config.validateLimits` (`Config.java:322`) rejects a value that small, use its smallest accepted value N and change the two strings to N+1 and N Greek letters.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `mvn -q -Dtest=ApiTextEndpointTest test`
Expected: compilation failure, `constructor ApiHandler … cannot be applied` / `cannot find symbol: TextProcessor`.

- [ ] **Step 3: Implement in `ApiHandler.java`**

Add the imports:
```java
import dev.filtsiap.ded.anonymizer.chat.ChatPipeline;
import dev.filtsiap.ded.anonymizer.chat.Masker;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
```

Replace `ROUTES` (line 109):
```java
    private static final Map<String, String> ROUTES = Map.of("/anonymize", "POST", "/anonymize-text", "POST",
            "/healthz", "GET");
```

Add, next to `interface Processor`:
```java
    /** One text's work: the chat pipeline, or a stand-in in tests. */
    @FunctionalInterface
    interface TextProcessor {
        ChatPipeline.TextResult process(String text, RunContext ctx);
    }

    /** A handler built without a chat pipeline answers /anonymize-text with 503, as a missing API key does. */
    static final TextProcessor NO_TEXT_PIPELINE = (text, ctx) -> {
        throw new ConfigurationError("POST /anonymize-text is not configured on this server");
    };

    static final String TEXT_MEDIA_TYPE = "text/plain";
```

Replace the field block and constructors (lines 128-149) with:
```java
    private final RuntimeConfig cfg;
    private final LongSupplier clock;
    private final Processor processor;
    private final TextProcessor textProcessor;
    private final BooleanSupplier cancelled;

    /** {@code cancelled}: the server's shutdown is cancelling the requests still running. */
    ApiHandler(RuntimeConfig cfg, FileConfig files, LlmClient client, ChatPipeline chat, BooleanSupplier cancelled) {
        this(cfg, System::nanoTime, (docx, ctx) -> Pipeline.anonymizeDocument(docx, cfg, files, client, ctx),
                chat == null ? NO_TEXT_PIPELINE : (text, ctx) -> chat.anonymize(text, ctx.deadline()), cancelled);
    }

    /** {@code clock} is the monotonic nanosecond clock every document's budget runs on. */
    ApiHandler(RuntimeConfig cfg, LongSupplier clock, Processor processor) {
        this(cfg, clock, processor, NO_TEXT_PIPELINE, () -> false);
    }

    ApiHandler(RuntimeConfig cfg, LongSupplier clock, Processor processor, TextProcessor textProcessor) {
        this(cfg, clock, processor, textProcessor, () -> false);
    }

    ApiHandler(RuntimeConfig cfg, LongSupplier clock, Processor processor, BooleanSupplier cancelled) {
        this(cfg, clock, processor, NO_TEXT_PIPELINE, cancelled);
    }

    ApiHandler(RuntimeConfig cfg, LongSupplier clock, Processor processor, TextProcessor textProcessor,
               BooleanSupplier cancelled) {
        this.cfg = cfg;
        this.clock = clock;
        this.processor = processor;
        this.textProcessor = textProcessor;
        this.cancelled = cancelled;
    }
```

Search for every `new ApiHandler(` with `grep -rn "new ApiHandler(" src`. Each existing call must still compile: the 3-argument and 4-argument `(…, BooleanSupplier)` forms are kept. The old production form `(cfg, files, client, cancelled)` is replaced, and its only caller, `ApiServer.start`, is updated below.

In `route`, replace the last line, `return anonymize(exchange);`, with:
```java
        if (path.equals("/anonymize-text")) {
            return anonymizeText(exchange);
        }
        return anonymize(exchange);
```

Add these methods after `anonymize`:
```java
    // ------------------------------------------------------------------ POST /anonymize-text

    /**
     * The one POST /anonymize-text flow: auth, read and decode, the chat pipeline, the reply. Exactly
     * one {@code text_finished} line per request with ids, codes, counts and timings, NEVER the
     * text. Errors are thrown for {@link #handle} to send, as on /anonymize.
     */
    private Reply anonymizeText(HttpExchange exchange) throws HttpError, IOException {
        requireApiKey(exchange.getRequestHeaders());
        RunContext ctx = RunContext.start(cfg.documentDeadlineS(), null, clock);
        exchange.getResponseHeaders().set("x-document-id", ctx.documentId());
        long started = clock.getAsLong();
        String outcome = "internal_error";
        int status = 500;
        String errorCode = "INTERNAL_ERROR";
        int chars = 0;
        try {
            String text = readText(exchange, ctx.deadline());
            chars = text.codePointCount(0, text.length());
            ChatPipeline.TextResult result = textProcessor.process(text, ctx);
            ctx.deadline().check("respond");
            long elapsedMs = (clock.getAsLong() - started) / 1_000_000;
            send(exchange, textReply(ctx.documentId(), result, elapsedMs));
            outcome = result.status() == ChatPipeline.Status.NEEDS_REVIEW ? "needs_review" : "success";
            status = 200;
            errorCode = "-";
            return null;
        } catch (AnonymizerError e) {
            outcome = e.outcome();
            status = statusFor(e);
            errorCode = e.code();
            throw e;
        } catch (IOException e) {
            outcome = "io_error";
            errorCode = "IO_ERROR";
            throw e;
        } catch (RuntimeException | Error e) {
            LOG.error("unhandled_exception {} error={} cause={}\n{}", ctx.tag(), e.getClass().getSimpleName(),
                    e.getCause() == null ? "-" : e.getCause().getClass().getSimpleName(), frames(e));
            throw new InternalError(e);
        } finally {
            String line = "text_finished {} outcome={} status={} elapsed_s={} chars={} error_code={}";
            Object[] fields = {ctx.tag(), outcome, status,
                    PyFloat.fixed((clock.getAsLong() - started) / 1e9, 2), chars, errorCode};
            if (errorCode.equals("-")) {
                LOG.info(line, fields);
            } else if (status < 500) {
                LOG.warn(line, fields);
            } else {
                LOG.error(line, fields);
            }
        }
    }

    /**
     * The body as text: text/plain, charset absent or UTF-8, valid UTF-8, at most
     * ANON_MAX_TEXT_CHARS code points (so at most four times that in bytes). A leading BOM is dropped.
     */
    private String readText(HttpExchange exchange, Deadline deadline) throws IOException {
        String contentType = headerValue(exchange.getRequestHeaders(), "Content-Type");
        if (!mediaType(contentType).equals(TEXT_MEDIA_TYPE) || !utf8Charset(contentType)) {
            throw new UnsupportedDocumentFormatError(
                    "send the text as the request body with Content-Type: text/plain; charset=utf-8");
        }
        long maxChars = cfg.limits().maxTextChars();
        long limit = maxChars * 4;
        checkDeclaredLength(exchange.getRequestHeaders().getFirst("Content-Length"), limit);
        byte[] data = readBody(exchange.getRequestBody(), limit, deadline);
        String text;
        try {
            text = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(data)).toString();
        } catch (CharacterCodingException e) {
            throw new InvalidDocumentError("request body is not valid UTF-8", "INVALID_UTF8");
        }
        if (text.startsWith("﻿")) {
            text = text.substring(1);
        }
        if (text.codePointCount(0, text.length()) > maxChars) {
            throw new ResourceLimitExceededError("text exceeds the " + maxChars + "-character limit",
                    "TEXT_TOO_LARGE");
        }
        return text;
    }

    /** True when the Content-Type has no charset parameter or says utf-8 / utf8. */
    static boolean utf8Charset(String contentType) {
        String[] parts = contentType.split(";");
        for (int i = 1; i < parts.length; i++) {
            String[] kv = parts[i].split("=", 2);
            if (kv.length == 2 && PyStr.casefold(PyStr.strip(kv[0])).equals("charset")) {
                String value = PyStr.casefold(PyStr.strip(kv[1]).replace("\"", ""));
                return value.equals("utf-8") || value.equals("utf8");
            }
        }
        return true;
    }

    /** Every header value is an id, an enum, a fixed reason string or an integer: never the text. */
    private static Reply textReply(String documentId, ChatPipeline.TextResult result, long elapsedMs) {
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("x-document-id", documentId);
        headers.put("x-anonymization-status", result.status().wire());
        headers.put("x-redaction-counts", Masker.countsHeader(result.counts()));
        if (!result.reviewReasons().isEmpty()) {
            headers.put("x-review-reasons", String.join(",", result.reviewReasons()));
        }
        headers.put("x-processing-time-ms", Long.toString(elapsedMs));
        return new Reply(200, "text/plain; charset=utf-8", result.masked().getBytes(StandardCharsets.UTF_8), headers);
    }
```

`InvalidDocumentError(String, String)` and `ResourceLimitExceededError(String, String)` exist. `UnsupportedDocumentFormatError` maps to 415, `InvalidDocumentError` to 400, `ResourceLimitExceededError` to 413 and `ConfigurationError` to 503 (`ERROR_STATUS`, lines 93-107). The error body already carries `code` (see `handle`), so `INVALID_UTF8` appears in the 400 body.

The existing code reads `readUpload`'s Content-Type through `headerValue`, which returns `""` when the header is absent. `mediaType("")` is `""`, which is not `text/plain`, so the request gets a 415.

- [ ] **Step 4: Implement in `ApiServer.java`**

Replace `start` (lines 112-122) with:
```java
    /** Starts serving; the caller owns the returned handle. {@code chat} null leaves /anonymize-text at 503. */
    public static ApiServer start(RuntimeConfig cfg, FileConfig files, ChatPipeline chat, LlmClient client,
                                  InetSocketAddress address, int maxConcurrentRequests) {
        if (cfg.anonApiKey() == null || cfg.anonApiKey().isEmpty()) {
            // Fail closed: there is no unauthenticated mode for the HTTP transport.
            throw new ConfigurationError("ANON_API_KEY is required to serve the HTTP API "
                    + "(POST /anonymize is bearer-authenticated)");
        }
        RequestTracker requests = new RequestTracker();
        return serve(new ApiHandler(cfg, files, client, chat, requests::cancelling), client, address,
                maxConcurrentRequests, requests);
    }

    /** As before /anonymize-text existed: no chat pipeline. */
    public static ApiServer start(RuntimeConfig cfg, FileConfig files, LlmClient client, InetSocketAddress address,
                                  int maxConcurrentRequests) {
        return start(cfg, files, null, client, address, maxConcurrentRequests);
    }
```

In `main`, after `FileConfig files = Config.loadFileConfig(Path.of("config"));`, add:
```java
            ChatLists chatLists = ChatLists.load(Path.of("config", "chat"));
            ChatPipeline chat = ChatPipeline.production(files, chatLists,
                    ChatSettings.load(Path.of("config", "chat")));
            log().info("chat lists loaded: {} MB", chatLists.footprintBytes() / 1_000_000);
```
Change the `start(...)` call in `main` to `start(cfg, files, chat, LlmClients.build(cfg), new InetSocketAddress(host, port), slots)`, and add these imports:
```java
import dev.filtsiap.ded.anonymizer.chat.ChatLists;
import dev.filtsiap.ded.anonymizer.chat.ChatPipeline;
import dev.filtsiap.ded.anonymizer.chat.ChatSettings;
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `mvn -q -Dtest="ApiTextEndpointTest,ApiHandlerTest" test`
Expected: all pass, including every existing `ApiHandlerTest` case.

- [ ] **Step 6: Run the whole suite**

Run: `mvn -q test`
Expected: everything passes.

- [ ] **Step 7: Commit**

```bash
git add src/main/java/dev/filtsiap/ded/api src/test/java/dev/filtsiap/ded/api/ApiTextEndpointTest.java
git commit -m "Add POST /anonymize-text endpoint"
```

---

### Task 10: Dataset check and three-mode evaluation

**Files:**
- Test: `src/test/java/dev/filtsiap/ded/anonymizer/chat/ChatDatasetTest.java`
- Test: `src/test/java/dev/filtsiap/ded/anonymizer/chat/ChatEval.java` (scorer)
- Test: `src/test/java/dev/filtsiap/ded/anonymizer/chat/ChatEvalTest.java`
- Delete: `eval/chat-anonymization/validate_dataset.py`
- Modify: `eval/chat-anonymization/README.md`

**Interfaces:**
- Consumes:
  - `ChatPipeline`, `NerDetector`, `ChatListsRealConfigTest.LISTS` (real lists)
  - `Checksums`
  - `DetectorSupport.validAfm` (via `Checksums.afm`)
  - Jackson `ObjectMapper` (already a dependency)
- Produces:
  - `ChatEval.load(Path) -> List<Entry>`
  - `ChatEval.run(String mode, ChatPipeline, List<Entry>) -> Report`
  - `Report.markdown()`
  - reports in `target/chat-eval/<mode>.md`

Scoring (also written into the README in Step 7):
- A `must_mask` item is **caught** only if every letter and digit of every occurrence is masked. Spaces and punctuation inside the item are not required.
- A `must_keep` item is **over-masked** if any of its characters is masked.
- `may_mask` items are not scored.

- [ ] **Step 1: Write the dataset test**

`src/test/java/dev/filtsiap/ded/anonymizer/chat/ChatDatasetTest.java`:
```java
package dev.filtsiap.ded.anonymizer.chat;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** The dataset itself is consistent: Java port of the former validate_dataset.py. */
class ChatDatasetTest {
    static final Set<String> GROUPS = Set.of("ids", "names_typical", "names_tricky", "locations_tricky",
            "overmask_traps", "multi_turn", "format_extremes", "controls");

    @Test
    void everyEntryIsConsistent() {
        List<ChatEval.Entry> entries = ChatEval.load(ChatEval.DATASET);
        List<String> problems = new ArrayList<>();
        for (int i = 0; i < entries.size(); i++) {
            ChatEval.Entry e = entries.get(i);
            if (!e.id().equals(String.format("T%03d", i + 1))) {
                problems.add(e.id() + ": ids must be T001..Tnnn in order");
            }
            if (!GROUPS.contains(e.group())) {
                problems.add(e.id() + ": unknown group " + e.group());
            }
            List<int[]> maskRanges = new ArrayList<>();
            for (ChatEval.Item item : e.mustMask()) {
                List<int[]> found = ChatEval.occurrences(e.text(), item.text());
                if (found.isEmpty()) {
                    problems.add(e.id() + ": must_mask '" + item.text() + "' not in text");
                }
                maskRanges.addAll(found);
                try {
                    PiiType.valueOf(item.type());
                } catch (IllegalArgumentException x) {
                    problems.add(e.id() + ": unknown type " + item.type());
                }
                String digits = Checksums.digitsOnly(item.text());
                boolean ok = switch (item.type()) {
                    case "AFM" -> Checksums.afm(digits);
                    case "AMKA" -> Checksums.amka(digits);
                    case "CARD" -> Checksums.luhn(digits);
                    case "IBAN" -> ibanValid(item.text());
                    default -> true;
                };
                if (!ok) {
                    problems.add(e.id() + ": " + item.type() + " '" + item.text() + "' fails its checksum");
                }
            }
            for (String keep : concat(e.mustKeep(), e.mayMask())) {
                if (ChatEval.occurrences(e.text(), keep).isEmpty()) {
                    problems.add(e.id() + ": '" + keep + "' not in text");
                }
            }
            for (String keep : e.mustKeep()) {
                for (int[] k : ChatEval.occurrences(e.text(), keep)) {
                    for (int[] m : maskRanges) {
                        if (k[0] < m[1] && m[0] < k[1]) {
                            problems.add(e.id() + ": must_keep '" + keep + "' overlaps a must_mask item");
                        }
                    }
                }
            }
        }
        assertEquals(List.of(), problems);
        assertEquals(100, entries.size());
    }

    static boolean ibanValid(String s) {
        String v = s.replaceAll("\\s", "").toUpperCase(java.util.Locale.ROOT);
        StringBuilder num = new StringBuilder();
        for (char c : (v.substring(4) + v.substring(0, 4)).toCharArray()) {
            num.append(Character.getNumericValue(c));
        }
        return v.matches("GR\\d{25}") && new java.math.BigInteger(num.toString()).mod(java.math.BigInteger.valueOf(97))
                .intValue() == 1;
    }

    private static List<String> concat(List<String> a, List<String> b) {
        List<String> out = new ArrayList<>(a);
        out.addAll(b);
        return out;
    }

    @Test
    void theDatasetPathExists() {
        assertTrue(java.nio.file.Files.isRegularFile(Path.of("eval", "chat-anonymization", "dataset.jsonl")));
    }
}
```

`ibanValid` is a local mod-97 check. `DetectorSupport.ibanIsValid` stays package-private, because the test only needs the dataset check.

- [ ] **Step 2: Write the scorer**

`src/test/java/dev/filtsiap/ded/anonymizer/chat/ChatEval.java`:
```java
package dev.filtsiap.ded.anonymizer.chat;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.filtsiap.ded.anonymizer.RunContext;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/** Loads eval/chat-anonymization/dataset.jsonl and scores a pipeline on it (README: "Scoring"). */
final class ChatEval {
    static final Path DATASET = Path.of("eval", "chat-anonymization", "dataset.jsonl");
    static final Path REPORT_DIR = Path.of("target", "chat-eval");

    record Item(String text, String type) {
    }

    record Entry(String id, String group, String text, List<Item> mustMask, List<String> mustKeep,
                 List<String> mayMask) {
    }

    record Leak(Entry entry, Item item) {
    }

    record OverMask(Entry entry, String keep) {
    }

    record Report(String mode, int mustMaskTotal, int mustKeepTotal, List<Leak> leaks, List<OverMask> overMasks,
                  long maskedChars, long maskedCharsExpected, Map<String, int[]> byType, Map<String, int[]> byGroup,
                  Map<String, String> outputs) {

        double leakRate() {
            return mustMaskTotal == 0 ? 0 : (double) leaks.size() / mustMaskTotal;
        }

        double overMaskRate() {
            return mustKeepTotal == 0 ? 0 : (double) overMasks.size() / mustKeepTotal;
        }

        double charPrecision() {
            return maskedChars == 0 ? 1 : (double) maskedCharsExpected / maskedChars;
        }

        String markdown() {
            StringBuilder b = new StringBuilder();
            b.append("# Chat eval: ").append(mode).append("\n\n");
            b.append(String.format("| Metric | Value |%n|---|---|%n| Leak rate | %d / %d (%.1f%%) |%n"
                            + "| Over-mask rate | %d / %d (%.1f%%) |%n| Character precision | %.1f%% |%n%n",
                    leaks.size(), mustMaskTotal, 100 * leakRate(), overMasks.size(), mustKeepTotal,
                    100 * overMaskRate(), 100 * charPrecision()));
            b.append("## Recall by type\n\n| Type | Caught | Total |\n|---|---|---|\n");
            byType.forEach((t, v) -> b.append("| ").append(t).append(" | ").append(v[0]).append(" | ")
                    .append(v[1]).append(" |\n"));
            b.append("\n## Recall by group\n\n| Group | Caught | Total |\n|---|---|---|\n");
            byGroup.forEach((g, v) -> b.append("| ").append(g).append(" | ").append(v[0]).append(" | ")
                    .append(v[1]).append(" |\n"));
            b.append("\n## Leaks\n\n");
            leaks.forEach(l -> b.append("- ").append(l.entry().id()).append(" ").append(l.item().type())
                    .append(" `").append(l.item().text()).append("` → `").append(outputs.get(l.entry().id()))
                    .append("`\n"));
            b.append("\n## Over-masked\n\n");
            overMasks.forEach(o -> b.append("- ").append(o.entry().id()).append(" `").append(o.keep())
                    .append("` → `").append(outputs.get(o.entry().id())).append("`\n"));
            return b.toString();
        }
    }

    private ChatEval() {
    }

    static List<Entry> load(Path path) {
        ObjectMapper json = new ObjectMapper();
        List<Entry> out = new ArrayList<>();
        try {
            for (String line : Files.readAllLines(path, StandardCharsets.UTF_8)) {
                if (line.isBlank()) {
                    continue;
                }
                JsonNode n = json.readTree(line);
                List<Item> mustMask = new ArrayList<>();
                n.get("must_mask").forEach(i -> mustMask.add(new Item(i.get("text").asText(), i.get("type").asText())));
                out.add(new Entry(n.get("id").asText(), n.get("group").asText(), n.get("text").asText(), mustMask,
                        strings(n.get("must_keep")), strings(n.get("may_mask"))));
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        return out;
    }

    private static List<String> strings(JsonNode array) {
        List<String> out = new ArrayList<>();
        array.forEach(s -> out.add(s.asText()));
        return out;
    }

    /** Code-point ranges of every occurrence of {@code needle} (case-sensitive). */
    static List<int[]> occurrences(String text, String needle) {
        List<int[]> out = new ArrayList<>();
        for (int at = text.indexOf(needle); at >= 0; at = text.indexOf(needle, at + 1)) {
            int start = text.codePointCount(0, at);
            out.add(new int[] {start, start + needle.codePointCount(0, needle.length())});
        }
        return out;
    }

    static Report run(String mode, ChatPipeline pipeline, List<Entry> entries) {
        List<Leak> leaks = new ArrayList<>();
        List<OverMask> overMasks = new ArrayList<>();
        Map<String, int[]> byType = new TreeMap<>();
        Map<String, int[]> byGroup = new TreeMap<>();
        Map<String, String> outputs = new TreeMap<>();
        int mustMaskTotal = 0;
        int mustKeepTotal = 0;
        long maskedChars = 0;
        long maskedExpected = 0;
        for (Entry e : entries) {
            String masked = pipeline.anonymize(e.text(), RunContext.start(60).deadline()).masked();
            outputs.put(e.id(), masked);
            int[] orig = e.text().codePoints().toArray();
            int[] out = masked.codePoints().toArray();
            if (orig.length != out.length) {
                throw new AssertionError(e.id() + ": output length differs from input");
            }
            boolean[] expected = new boolean[orig.length];
            for (Item item : e.mustMask()) {
                mustMaskTotal++;
                boolean caught = true;
                for (int[] r : occurrences(e.text(), item.text())) {
                    for (int i = r[0]; i < r[1]; i++) {
                        expected[i] = true;
                        if (Character.isLetterOrDigit(orig[i]) && out[i] != Masker.MASK) {
                            caught = false;
                        }
                    }
                }
                if (!caught) {
                    leaks.add(new Leak(e, item));
                }
                tally(byType, item.type(), caught);
                tally(byGroup, e.group(), caught);
            }
            for (String may : e.mayMask()) {
                for (int[] r : occurrences(e.text(), may)) {
                    for (int i = r[0]; i < r[1]; i++) {
                        expected[i] = true;
                    }
                }
            }
            for (String keep : e.mustKeep()) {
                mustKeepTotal++;
                boolean touched = false;
                for (int[] r : occurrences(e.text(), keep)) {
                    for (int i = r[0]; i < r[1]; i++) {
                        touched |= out[i] == Masker.MASK && orig[i] != Masker.MASK;
                    }
                }
                if (touched) {
                    overMasks.add(new OverMask(e, keep));
                }
            }
            for (int i = 0; i < orig.length; i++) {
                if (out[i] == Masker.MASK && orig[i] != Masker.MASK) {
                    maskedChars++;
                    if (expected[i]) {
                        maskedExpected++;
                    }
                }
            }
        }
        return new Report(mode, mustMaskTotal, mustKeepTotal, leaks, overMasks, maskedChars, maskedExpected,
                byType, byGroup, outputs);
    }

    private static void tally(Map<String, int[]> map, String key, boolean caught) {
        int[] v = map.computeIfAbsent(key, k -> new int[2]);
        v[1]++;
        if (caught) {
            v[0]++;
        }
    }

    static void write(Report report) {
        try {
            Files.createDirectories(REPORT_DIR);
            Files.writeString(REPORT_DIR.resolve(report.mode() + ".md"), report.markdown(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
```

- [ ] **Step 3: Write the eval test with an unpinned baseline**

`src/test/java/dev/filtsiap/ded/anonymizer/chat/ChatEvalTest.java`:
```java
package dev.filtsiap.ded.anonymizer.chat;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.filtsiap.ded.anonymizer.Config;
import dev.filtsiap.ded.anonymizer.DetectorRules;
import dev.filtsiap.ded.anonymizer.RunContext;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

/**
 * The dataset in three modes (eval/chat-anonymization/README.md). Only "rules" runs until a NER
 * model exists; the invariant that NER only adds is checked with a stub model.
 */
class ChatEvalTest {
    static final DetectorRules RULES = Config.loadFileConfig(Path.of("config")).rules();
    static final List<ChatEval.Entry> DATASET = ChatEval.load(ChatEval.DATASET);

    /** Pinned from the first full run (Task 10, Step 5). A change that leaks or over-masks more fails. */
    static final int MAX_RULES_LEAKS = Integer.MAX_VALUE;
    static final int MAX_RULES_OVER_MASKS = Integer.MAX_VALUE;

    /** These types are checksum- or shape-certain: the rules must catch every one in the dataset. */
    static final Set<String> MUST_NEVER_LEAK = Set.of("AFM", "AMKA", "IBAN", "CARD", "ID_CARD", "PASSPORT", "PLATE",
            "GEMI", "EMAIL");

    /** The NER model to evaluate; none in v1. */
    static NerDetector configuredNer() {
        return null;
    }

    @Test
    void rulesMode() {
        ChatEval.Report report = ChatEval.run("rules",
                new ChatPipeline(RULES, ChatListsRealConfigTest.LISTS, NerDetector.NONE, true), DATASET);
        ChatEval.write(report);
        System.out.println(report.markdown());
        List<String> certainLeaks = new ArrayList<>();
        report.leaks().stream().filter(l -> MUST_NEVER_LEAK.contains(l.item().type()))
                .forEach(l -> certainLeaks.add(l.entry().id() + " " + l.item().type()));
        assertEquals(List.of(), certainLeaks);
        assertTrue(report.leaks().size() <= MAX_RULES_LEAKS, "leaks " + report.leaks().size());
        assertTrue(report.overMasks().size() <= MAX_RULES_OVER_MASKS, "over-masks " + report.overMasks().size());
    }

    @Test
    void nerAndBothModes() {
        NerDetector ner = configuredNer();
        Assumptions.assumeTrue(ner != null, "no NER model configured: ner and both modes skipped");
        ChatEval.write(ChatEval.run("ner", new ChatPipeline(RULES, ChatListsRealConfigTest.LISTS, ner, false), DATASET));
        ChatEval.write(ChatEval.run("both", new ChatPipeline(RULES, ChatListsRealConfigTest.LISTS, ner, true), DATASET));
    }

    @Test
    void bothModeNeverMasksLessThanRulesMode() {
        // A stub "model" that flags every capitalised word: whatever it says, both ⊇ rules.
        NerDetector stub = text -> {
            List<ChatSpan> out = new ArrayList<>();
            int[] cps = text.codePoints().toArray();
            for (int i = 0; i < cps.length; i++) {
                if (Character.isUpperCase(cps[i]) && (i == 0 || !Character.isLetter(cps[i - 1]))) {
                    int j = i;
                    while (j < cps.length && Character.isLetter(cps[j])) {
                        j++;
                    }
                    out.add(new ChatSpan(i, j, PiiType.OTHER, "stub"));
                }
            }
            return out;
        };
        ChatPipeline rules = new ChatPipeline(RULES, ChatListsRealConfigTest.LISTS, NerDetector.NONE, true);
        ChatPipeline both = new ChatPipeline(RULES, ChatListsRealConfigTest.LISTS, stub, true);
        for (ChatEval.Entry e : DATASET) {
            int[] r = rules.anonymize(e.text(), RunContext.start(60).deadline()).masked().codePoints().toArray();
            int[] b = both.anonymize(e.text(), RunContext.start(60).deadline()).masked().codePoints().toArray();
            for (int i = 0; i < r.length; i++) {
                if (r[i] == Masker.MASK) {
                    assertEquals(Masker.MASK, b[i], e.id() + " position " + i);
                }
            }
        }
    }
}
```

- [ ] **Step 4: Run it and fix the certain-type leaks**

Run: `mvn -q -Dtest="ChatDatasetTest,ChatEvalTest" test`
Expected:
- `ChatDatasetTest` passes.
- `ChatEvalTest.rulesMode` prints the report.
- `rulesMode` may fail with a non-empty `certainLeaks` list.

For each entry in `certainLeaks`, read its row under "Leaks" in `target/chat-eval/rules.md`. Fix the detector pattern in `IdDetector`, and add that exact text as a new `@CsvSource` row in `IdDetectorTest`, so the unit test pins the fix. Repeat until `certainLeaks` is empty. Do not change the dataset to make a test pass.

- [ ] **Step 5: Pin the baseline**

Read the two numbers at the top of `target/chat-eval/rules.md`: the leaks count (`Leak rate | L / …`) and the over-masks count (`Over-mask rate | O / …`). Set them in `ChatEvalTest`:
```java
    static final int MAX_RULES_LEAKS = /* L, from target/chat-eval/rules.md on 2026-10-1x */ L;
    static final int MAX_RULES_OVER_MASKS = /* O */ O;
```
Write the actual integers in place of `L` and `O`, and the actual date in the comment.

The README lists entries expected to leak with rules: T032 (Νίκη), T048 (Βασιλική), T090 (phone in words) and T094 (date of birth). Check that they appear under "Leaks"; if they don't, that's a pleasant surprise worth one line in the commit message. Any **other** leak goes in the report to the user at the end of the task. Do not tune detectors to the dataset beyond the certain types without the user agreeing: tuning to the test set inflates the score.

Run: `mvn -q -Dtest=ChatEvalTest test`
Expected: `rulesMode` and `bothModeNeverMasksLessThanRulesMode` pass, and `nerAndBothModes` is skipped.

- [ ] **Step 6: Delete the Python validator**

```bash
git rm eval/chat-anonymization/validate_dataset.py
```

- [ ] **Step 7: Update the eval README**

In `eval/chat-anonymization/README.md`:

Replace the `validate_dataset.py` row of the Files table with:
```markdown
| `ChatDatasetTest` (JUnit) | Checks the dataset itself: every snippet occurs, keeps never overlap masks, IDs pass their checksums |
| `ChatEvalTest` (JUnit) | Scores the anonymizer; reports go to `target/chat-eval/<mode>.md` |
```

Replace the sentence that starts "Whitespace inside a `must_mask` item…" with:
```markdown
Only **letters and digits** inside a `must_mask` item must be masked: spaces, hyphens and dots
(`6 9 1 2…`, `Παπαδάκης-Ντόκου`, `Μ.`) may stay.
```

Add this section at the end:
```markdown
## Running it

    mvn -q -Dtest="ChatDatasetTest,ChatEvalTest" test

The `rules` report is written to `target/chat-eval/rules.md`. `ChatEvalTest` fails the build if:
- any AFM, AMKA, IBAN, card, ID card, passport, plate, ΓΕΜΗ or email leaks; or
- the leak or over-mask count rises above the pinned baseline.

The `ner` and `both` modes are skipped until a NER model is configured in
`ChatEvalTest.configuredNer()`.
```

- [ ] **Step 8: Run the whole build**

Run: `mvn -B verify`
Expected: `BUILD SUCCESS`.

- [ ] **Step 9: Commit**

```bash
git add src/test/java/dev/filtsiap/ded/anonymizer/chat eval/chat-anonymization
git commit -m "Score /anonymize-text on the chat dataset and pin the rules baseline"
```

---

### Task 11: Documentation

**Files:**
- Modify: `README.md` (add a section after the `POST /anonymize` API section)
- Modify: `docs/superpowers/specs/2026-10-09-chat-text-anonymizer-design.md` (append "Implementation notes")

- [ ] **Step 1: Add the endpoint to `README.md`**

Find the API section with `grep -n "POST /anonymize" README.md` and add after it:
````markdown
### POST /anonymize-text

Masks personal data in plain text (chatbot conversation logs). No LLM is called.

```bash
curl -s -X POST http://localhost:8000/anonymize-text \
  -H "Authorization: Bearer $ANON_API_KEY" \
  -H "Content-Type: text/plain; charset=utf-8" \
  --data-binary "Καλησπέρα, με λένε Γιώργο Παπαδόπουλο, ΑΦΜ 090000045"
```

The response is the same text with every masked character replaced by `.`. Its length (in
characters) is unchanged, and whitespace is kept.

| Header | Meaning |
|---|---|
| `x-anonymization-status` | `anonymized`, or `needs-review` when a safety net fired; check `x-review-reasons` |
| `x-redaction-counts` | `PERSON=2,AFM=1`, or `none` |
| `x-review-reasons` | Only on `needs-review`: `residual:<pattern>`, `ner_unavailable` |
| `x-document-id`, `x-processing-time-ms` | As on `/anonymize` |

Errors:
- 401: auth.
- 415: not `text/plain`, or a charset other than UTF-8.
- 400: invalid UTF-8.
- 413: more than `ANON_MAX_TEXT_CHARS` characters.

Word lists live in `config/chat/`; their sources, licences and how to rebuild them are in
`config/chat/README.md`. Detection quality is measured on `eval/chat-anonymization/`. Design:
`docs/superpowers/specs/2026-10-09-chat-text-anonymizer-design.md`.
````

- [ ] **Step 2: Append implementation notes to the spec**

At the end of `docs/superpowers/specs/2026-10-09-chat-text-anonymizer-design.md`, add a section `## Implementation notes (2026-10-12)` containing the seven items of this plan's "Deviations from the spec" section, copied verbatim.

- [ ] **Step 3: Commit**

```bash
git add README.md docs/superpowers/specs/2026-10-09-chat-text-anonymizer-design.md
git commit -m "Document POST /anonymize-text and the implementation notes"
```

---

## Verification (end to end)

1. `mvn -B verify` passes: the existing tests, the new unit tests, `ChatDatasetTest` and `ChatEvalTest` (with `nerAndBothModes` skipped).
2. Start the server, then run the example request:
   - Start it with `java -jar target/ded-anonymizer-2.0.0.jar` (or as `RUNNING.md` describes) with `ANON_API_KEY` set.
   - Check the log for `chat lists loaded: N MB`.
   - Run the `curl` from Task 11 Step 1.
   - Expect: the name and AFM come back as dots, plus `x-anonymization-status: anonymized` and `x-redaction-counts: PERSON=2,AFM=1`.
3. Open `target/chat-eval/rules.md` and share the leak and over-mask lists with the user.
