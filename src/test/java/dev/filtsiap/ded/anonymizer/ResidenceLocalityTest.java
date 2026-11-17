package dev.filtsiap.ded.anonymizer;

import static dev.filtsiap.ded.anonymizer.llm.ScriptedLlm.answer;
import static dev.filtsiap.ded.anonymizer.llm.ScriptedLlm.candidates;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.filtsiap.ded.anonymizer.llm.LlmCallException;
import dev.filtsiap.ded.anonymizer.llm.ScriptedLlm;
import dev.filtsiap.ded.anonymizer.pycompat.PyJson;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * A bare locality after a residence cue ("κατοίκου Λαμίας", "κάτοικος Λαμία") is kept by policy (a hard
 * PUBLIC_LOCALITY preserve, owner decision), while the street, its number and the postal code still go and the
 * labels stay, with or without a usable model decision. Every value is synthetic.
 */
class ResidenceLocalityTest {

    static final FileConfig FILES = Config.loadFileConfig(Path.of("config"));
    static final RuntimeConfig CFG = Config.loadRuntimeConfig(Map.of("ANON_PROVIDER", "openai",
            "OPENAI_API_KEY", "sk-test", "ANON_MODEL", "gpt-test"));

    static TextUnit unit(String text) {
        return new TextUnit("u0", "word/document.xml", UnitType.PARAGRAPH, text, text, List.of(),
                new TextUnit.ParagraphLocation(0));
    }

    static AnonymizeResult anonymize(String paragraph, ScriptedLlm llm) {
        return Pipeline.anonymizeDocument(TestDocx.paragraphs(paragraph).bytes(), CFG, FILES, llm,
                RunContext.start(300, "residence", System::nanoTime));
    }

    static String text(AnonymizeResult r) {
        return TestDocx.part(r.redactedDocx(), "word/document.xml");
    }

    static Map<String, Object> finding(String text, String action, String category) {
        Map<String, Object> f = new LinkedHashMap<>();
        f.put("text", text);
        f.put("action", action);
        f.put("category", category);
        return f;
    }

    /**
     * A model that reads the residence rule as the prompt now states it: pass 1 keeps the locality and
     * redacts the street and number; pass 2 keeps a candidate that is exactly the locality and redacts
     * everything else (a wider candidate holding a street is private).
     */
    static ScriptedLlm readsTheResidenceRule(String locality) {
        List<Map<String, Object>> findings = List.of(finding(locality, "PRESERVE", "PUBLIC_LOCALITY"),
                finding("Ερμού", "REDACT", "PRIVATE_ADDRESS"), finding("5", "REDACT", "PRIVATE_ADDRESS"));
        return new ScriptedLlm(r -> {
            if (ScriptedLlm.isPass1(r)) {
                return PyJson.dumps(findings);
            }
            List<Object> out = new ArrayList<>();
            for (Map<String, Object> c : candidates(r)) {
                String text = (String) c.get("text");
                out.add(answer((String) c.get("id"), text.equals(locality) ? "PRESERVE" : "REDACT",
                        text.equals(locality) ? "PUBLIC_LOCALITY" : "PRIVATE_ADDRESS"));
            }
            return PyJson.dumps(out);
        });
    }

    /** Pass 1 as above; pass 2 never answers (the provider stays unavailable). */
    static ScriptedLlm pass2Unavailable(String locality) {
        List<Map<String, Object>> findings = List.of(finding(locality, "PRESERVE", "PUBLIC_LOCALITY"),
                finding("Ερμού", "REDACT", "PRIVATE_ADDRESS"), finding("5", "REDACT", "PRIVATE_ADDRESS"));
        return ScriptedLlm.completions(r -> {
            if (ScriptedLlm.isPass1(r)) {
                return ScriptedLlm.finished(PyJson.dumps(findings));
            }
            throw LlmCallException.status(503, 0L, null);
        });
    }

    /** No model at all is usable: every call fails. */
    static ScriptedLlm nothingUsable() {
        return ScriptedLlm.completions(r -> {
            throw LlmCallException.status(503, 0L, null);
        });
    }

    static final String GENITIVE = "Ο προσφεύγων Νικόλαος Ιωάννου, κατοίκου Λαμίας, οδός Ερμού αρ. 5, Τ.Κ. 35100, άσκησε "
            + "ενδικοφανή προσφυγή.";
    static final String NOMINATIVE = "Ο προσφεύγων Νικόλαος Ιωάννου, κάτοικος Λαμία, οδός Ερμού αρ. 5, Τ.Κ. 35100, άσκησε "
            + "ενδικοφανή προσφυγή.";

    /** The document's visible text: every redacted code point is a dot. */
    static String plain(AnonymizeResult r) {
        return text(r).replaceAll("<[^>]+>", "").strip();
    }

    /**
     * L1: genitive cue with a street after it. The locality stays; the name, the street (with the space
     * a wider street proposal covers), the number and the postal code go; the labels stay ("αρ." keeps its
     * own dot: "αρ..." is that dot, then the space and the number blanked).
     */
    @Test
    void aUsableDecisionKeepsTheBareLocalityAfterTheGenitiveCue() {
        assertEquals("Ο προσφεύγων ................, κατοίκου Λαμίας, οδός ......αρ..., Τ.Κ. ....., άσκησε "
                + "ενδικοφανή προσφυγή.", plain(anonymize(GENITIVE, readsTheResidenceRule("Λαμίας"))));
    }

    /**
     * L2: nominative cue with a street after it. The bare town is kept by hard policy (owner decision), so it is
     * never a pass-2 question, and the street is proposed on its own (never one span over both).
     */
    @Test
    void aUsableDecisionKeepsTheBareLocalityAfterTheNominativeCue() {
        assertTrue(Detectors.detectAll(new DocumentData("d", List.of(unit(NOMINATIVE)), List.of(), List.of()),
                FILES.rules()).resolverSpans().stream().anyMatch(s -> s.text().equals("Λαμία")
                        && Resolver.isHardPreserve(s, FILES.policy())));
        ScriptedLlm llm = readsTheResidenceRule("Λαμία");
        assertEquals("Ο προσφεύγων ................, κάτοικος Λαμία, οδός ......αρ..., Τ.Κ. ....., άσκησε "
                + "ενδικοφανή προσφυγή.", plain(anonymize(NOMINATIVE, llm)));
        List<String> asked = llm.requests.stream().filter(r -> !ScriptedLlm.isPass1(r))
                .flatMap(r -> candidates(r).stream()).map(c -> (String) c.get("text")).toList();
        assertTrue(asked.stream().noneMatch(t -> t.contains("Λαμία")), asked.toString());
    }

    /** L3: a bare locality at the end of the sentence. */
    @Test
    void aUsableDecisionKeepsALocalityAtTheEndOfTheSentence() {
        String paragraph = "Ο προσφεύγων Νικόλαος Ιωάννου, κάτοικος Πατρών.";
        List<Map<String, Object>> findings = List.of(finding("Πατρών", "PRESERVE", "PUBLIC_LOCALITY"),
                finding("Νικόλαος Ιωάννου", "REDACT", "APPELLANT_NAME"));
        ScriptedLlm llm = new ScriptedLlm(r -> {
            if (ScriptedLlm.isPass1(r)) {
                return PyJson.dumps(findings);
            }
            List<Object> out = new ArrayList<>();
            for (Map<String, Object> c : candidates(r)) {
                out.add(answer((String) c.get("id"), c.get("text").equals("Πατρών") ? "PRESERVE" : "REDACT",
                        "PUBLIC_LOCALITY"));
            }
            return PyJson.dumps(out);
        });
        String xml = text(anonymize(paragraph, llm));
        assertTrue(xml.contains("κάτοικος Πατρών."), xml);
        assertFalse(xml.contains("Νικόλαος") || xml.contains("Ιωάννου"), xml);
    }

    /**
     * L5/L6: without a usable decision (pass 2 unavailable, or no model call usable at all) the bare town is
     * still kept, since policy keeps it whatever a model answers, and the street, number and postal code are
     * still redacted by the rules' fallback, the labels staying.
     */
    @Test
    void withoutAUsableDecisionTheTownIsStillKeptAndTheAddressRedacted() {
        String tail = ", οδός ..... αρ. ., Τ.Κ. ....., άσκησε ενδικοφανή προσφυγή.";
        for (ScriptedLlm llm : List.of(pass2Unavailable("Λαμίας"), nothingUsable())) {
            assertEquals("Ο προσφεύγων ................, κατοίκου Λαμίας" + tail, plain(anonymize(GENITIVE, llm)));
        }
        for (ScriptedLlm llm : List.of(pass2Unavailable("Λαμία"), nothingUsable())) {
            assertEquals("Ο προσφεύγων ................, κάτοικος Λαμία" + tail, plain(anonymize(NOMINATIVE, llm)));
        }
    }

    /**
     * The owner's explicit correction, "κάτοικος Χαλκίδας" keeps "Χαλκίδας", is met by the bare-town rule
     * above (no place is named in production code: {@code PublicLocalityTest.noGoldDocumentPlaceIsHardcodedInProduction}).
     * Whatever the model does, the town is a hard preserve and never a question; the name, the street, its
     * number and the postal code still go; the town inside a court's name stays with the court; and the same
     * word as a street name keeps nothing.
     */
    @Test
    void kátoikosChalkidasKeepsTheTownAndNothingOfTheAddress() {
        String paragraph = "Ο προσφεύγων Νικόλαος Ιωάννου, κάτοικος Χαλκίδας, οδός Ερμού αρ. 5, Τ.Κ. 34100, άσκησε "
                + "ενδικοφανή προσφυγή κατά της απόφασης του Διοικητικού Πρωτοδικείου Χαλκίδας.";
        assertTrue(Detectors.detectAll(new DocumentData("d", List.of(unit(paragraph)), List.of(), List.of()),
                FILES.rules()).resolverSpans().stream().anyMatch(s -> s.text().equals("Χαλκίδας")
                        && s.category() == SpanCategory.PUBLIC_LOCALITY && Resolver.isHardPreserve(s, FILES.policy())));
        for (ScriptedLlm llm : List.of(readsTheResidenceRule("Χαλκίδας"), pass2Unavailable("Χαλκίδας"), nothingUsable())) {
            String out = plain(anonymize(paragraph, llm));
            assertTrue(out.contains(", κάτοικος Χαλκίδας, οδός "), out);
            assertTrue(out.endsWith("του Διοικητικού Πρωτοδικείου Χαλκίδας."), out);
            for (String gone : List.of("Νικόλαος", "Ιωάννου", "Ερμού", "αρ. 5", "34100")) {
                assertFalse(out.contains(gone), gone + " / " + out);
            }
            List<String> asked = llm.requests.stream().filter(r -> !ScriptedLlm.isPass1(r))
                    .flatMap(r -> candidates(r).stream()).map(c -> (String) c.get("text")).toList();
            assertTrue(asked.stream().noneMatch(t -> t.equals("Χαλκίδας")), asked.toString());
        }
        // The same word as a street's name is the street, not a residence locality: never kept by this rule.
        String street = "Η επιχείρηση στεγάζεται επί της οδού Χαλκίδας 12 στο Περιστέρι.";
        int at = street.indexOf("Χαλκίδας");
        assertTrue(Detectors.detectAll(new DocumentData("d", List.of(unit(street)), List.of(), List.of()),
                FILES.rules()).resolverSpans().stream().noneMatch(s -> Resolver.isHardPreserve(s, FILES.policy())
                        && s.start() < at + 8 && at < s.end()));
    }

    /**
     * The confirmed over-reach: "κάτοικος Λαμίας, προσέφυγε κατά της πράξης" gave a REDACT proposal over the
     * place AND the clause. Now the town is kept by policy and the clause is never touched, with or without a
     * usable decision.
     */
    @Test
    void theClauseAfterAResidenceIsNeverRedacted() {
        String paragraph = "Ο Νικόλαος Ιωάννου, κάτοικος Λαμίας, προσέφυγε κατά της πράξης.";
        for (ScriptedLlm llm : List.of(readsTheResidenceRule("Λαμίας"), pass2Unavailable("Λαμίας"), nothingUsable())) {
            String out = plain(anonymize(paragraph, llm));
            assertTrue(out.endsWith(", κάτοικος Λαμίας, προσέφυγε κατά της πράξης."), out);
        }
    }

    /**
     * The confirmed short-document defect: with no title line, the authority header ran into the appellant's
     * paragraph and its confident PRESERVE outranked every address proposal there, so the fallback (pass 2
     * unavailable) left the street, the number and the postal code visible. The header now ends at that
     * paragraph; the authority's own contact line keeps its header recommendation.
     */
    @Test
    void theAppellantsParagraphIsNeverTheAuthorityHeaderEvenWithoutATitle() {
        byte[] docx = TestDocx.paragraphs("ΕΛΛΗΝΙΚΗ ΔΗΜΟΚΡΑΤΙΑ", "Τηλέφωνο: 2131312347",
                "Ο προσφεύγων, κάτοικος Λαμίας, οδός Ερμού αρ. 5, Τ.Κ. 35100, τηλέφωνο 6912345678, e-mail "
                        + "giorgos@example.com.").bytes();
        ScriptedLlm llm = ScriptedLlm.completions(r -> {
            if (ScriptedLlm.isPass1(r)) {
                return ScriptedLlm.finished("[]");
            }
            throw LlmCallException.status(503, 0L, null);
        });
        AnonymizeResult r = Pipeline.anonymizeDocument(docx, CFG, FILES, llm, RunContext.start(300, "short", System::nanoTime));
        String visible = plain(r);
        assertTrue(visible.contains("κάτοικος Λαμίας, οδός ..... αρ. ., Τ.Κ. ....., τηλέφωνο"), visible);
        assertFalse(visible.contains("giorgos"), visible);
        assertEquals("needs-review", r.status()); // pass 2 was unavailable and the phones are undecided
    }
}
