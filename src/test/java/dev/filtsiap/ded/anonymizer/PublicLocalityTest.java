package dev.filtsiap.ded.anonymizer;

import static dev.filtsiap.ded.anonymizer.llm.ScriptedLlm.answer;
import static dev.filtsiap.ded.anonymizer.llm.ScriptedLlm.candidates;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.filtsiap.ded.anonymizer.llm.ScriptedLlm;
import dev.filtsiap.ded.anonymizer.pycompat.PyJson;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

/**
 * Public geography under the new gold, decided by the ROLE of the words and never by which place
 * they name: a place inside a public institution's name, a court's chamber, a municipality with its
 * region after a residence cue, and an all-zero ΚΑΕΚ suffix stay; a private address and every
 * identifier go. Multi-word places, models that read the context correctly, and models that are
 * deliberately wrong. Every value is synthetic.
 */
class PublicLocalityTest {

    static final FileConfig FILES = Config.loadFileConfig(Path.of("config"));
    static final RuntimeConfig CFG = Config.loadRuntimeConfig(Map.of("ANON_PROVIDER", "openai",
            "OPENAI_API_KEY", "sk-test", "ANON_MODEL", "gpt-test"));
    static final String AFM = TestDocx.validAfm("24681357");
    static final String AMKA = "15078512345";
    static final String IBAN = TestDocx.validGreekIban("01101230000012345678901");
    static final String EMAIL = "g.p@example.com";
    static final String PHONE = "6912345678";

    static TextUnit unit(String text) {
        return new TextUnit("u0", "word/document.xml", UnitType.PARAGRAPH, text, text, List.of(),
                new TextUnit.ParagraphLocation(0));
    }

    /** The hard preserves the rules draw over one paragraph, as text. */
    static List<String> hardPreserves(String paragraph) {
        return Detectors.detectAll(new DocumentData("d", List.of(unit(paragraph)), List.of(), List.of()),
                FILES.rules()).resolverSpans().stream().filter(s -> Resolver.isHardPreserve(s, FILES.policy()))
                .map(Span::text).toList();
    }

    // ------------------------------------------------------------------ the deterministic layer

    @Test
    void aMultiWordPlaceInAnInstitutionsNameIsKeptWhole() {
        assertTrue(hardPreserves("της Διεύθυνσης ΥΔΟΜ του Δήμου Νέας Σμύρνης.").contains("Δήμου Νέας Σμύρνης"));
        assertTrue(hardPreserves("με τη βεβαίωση του Δήμου Αγίας Παρασκευής.").contains("Δήμου Αγίας Παρασκευής"));
        assertTrue(hardPreserves("απόφαση του Πρωτοδικείου Νέας Ιωνίας.").contains("Πρωτοδικείου Νέας Ιωνίας"));
        // Case and accents do not matter to the modifier: it is a class of words, compared folded.
        assertTrue(hardPreserves("του Δήμου ΝΕΑΣ ΣΜΥΡΝΗΣ.").contains("Δήμου ΝΕΑΣ ΣΜΥΡΝΗΣ"));
        // The court cues in the nominative too.
        assertTrue(hardPreserves("το Εφετείο Θεσσαλονίκης έκρινε.").contains("Εφετείο Θεσσαλονίκης"));
        assertTrue(hardPreserves("ενώπιον του Πρωτοδικείο Αθηνών.").contains("Πρωτοδικείο Αθηνών"));
        // Court structure: the chamber, its number and its composition.
        assertTrue(hardPreserves("(Τμήμα 1ο Τριμελές)").contains("1ο Τριμελές"));
        assertTrue(hardPreserves("Τμήμα 2ο Μονομελές").contains("2ο Μονομελές"));
    }

    @Test
    void aHardPreserveNeverReachesThePersonalNameThatFollowsThePlace() {
        String text = "Η βεβαίωση του Δήμου Νέας Σμύρνης Γεώργιος Παπαδόπουλος υπογράφηκε.";
        List<String> kept = hardPreserves(text);
        assertEquals(List.of("Δήμου Νέας Σμύρνης"), kept.stream().filter(t -> t.startsWith("Δήμου")).toList());
        int nameStart = text.indexOf("Γεώργιος");
        assertTrue(Detectors.detectAll(new DocumentData("d", List.of(unit(text)), List.of(), List.of()), FILES.rules())
                .resolverSpans().stream().filter(s -> Resolver.isHardPreserve(s, FILES.policy()))
                .noneMatch(s -> s.end() > nameStart), "a hard preserve reaches the name");
    }

    @Test
    void aMultiWordPlaceAllowsMultipleSpacesAndTabsWithoutProtectingTheNextName() {
        for (String gap : List.of("  ", "\t", " \t ")) {
            String place = "Δήμου Νέας" + gap + "Σμύρνης";
            List<String> kept = hardPreserves(place + " Γεώργιος Παπαδόπουλος.");
            assertTrue(kept.contains(place), kept.toString());
            assertTrue(kept.stream().noneMatch(t -> t.contains("Γεώργιος") || t.contains("Παπαδόπουλος")));
        }
    }

    @Test
    void aPlaceWhoseEndTheWordsCannotTellIsLeftToPass2BeyondItsFirstWord() {
        // No modifier opens it, so nothing says where this place's name ends: only its first word is a
        // decision; the rest is ordinary evidence, put to pass 2 with the context it needs.
        List<String> kept = hardPreserves("του Δήμου Ρήγα Φεραίου.");
        assertTrue(kept.contains("Δήμου Ρήγα"), kept.toString());
        assertTrue(kept.stream().noneMatch(t -> t.contains("Φεραίου")), kept.toString());
    }

    @Test
    void localityIsOrdinaryEvidenceAndOnlyPublicLocalityIsHard() {
        assertTrue(FILES.policy().hardPreserveCategories().contains("PUBLIC_LOCALITY"));
        assertFalse(FILES.policy().hardPreserveCategories().contains("LOCALITY"));
        assertFalse(FILES.policy().hardRedactCategories().contains("LOCALITY"));
        Span modelLocality = new Span("u0", 0, 5, "Λαμία", SpanCategory.LOCALITY, "llm", 0.95, SpanAction.PRESERVE, "",
                SpanOrigin.DETERMINISTIC);
        assertFalse(Resolver.isHardPreserve(modelLocality, FILES.policy())); // a LOCALITY PRESERVE is a proposal
    }

    @Test
    void theKaekRuleIsTheApprovedOneAndNoWider() {
        String text = "ΚΑΕΚ 050011122233/0/0 και ΚΑΕΚ 050011122234/1/2 και ΚΑΕΚ 050011122235/0/3.";
        List<Span> spans = Detectors.detectPropertyIds(unit(text), FILES.rules());
        // Only an ALL-ZERO suffix is kept (as a hard FIELD_LABEL); any other digit keeps the suffix with its root.
        assertEquals(List.of("PRESERVE:/0/0", "REDACT:050011122233", "REDACT:050011122234/1/2",
                "REDACT:050011122235/0/3"), spans.stream().map(s -> s.action() + ":" + s.text()).toList());
        assertTrue(Resolver.isHardPreserve(spans.get(0), FILES.policy()));
        assertTrue(spans.subList(1, 4).stream().allMatch(s -> Resolver.isHardRedact(s, FILES.policy())));
    }

    /**
     * The gold this policy was approved against names its own places; none of them may become a rule.
     * This trips if one ever reaches production code or the policy (comments included), so a
     * document-specific exception cannot be added quietly. The allowlists are gazetteers of every
     * tax office and region and are not checked.
     */
    @Test
    void noGoldDocumentPlaceIsHardcodedInProduction() throws IOException {
        List<Path> production = new ArrayList<>();
        try (Stream<Path> files = Files.walk(Path.of("src/main/java"))) {
            files.filter(p -> p.toString().endsWith(".java")).forEach(production::add);
        }
        production.add(Path.of("config/policy.yaml"));
        production.add(Path.of("config/regex_patterns.yaml"));
        List<String> hits = new ArrayList<>();
        for (Path file : production) {
            String folded = DetectorPatterns.foldGreek(Files.readString(file, StandardCharsets.UTF_8));
            // The later golds' bank, street and parties too: their fixes are rules, never these values.
            for (String place : List.of("χαλκιδ", "χαλανδρ", "eurobank", "ergasias", "ιερας", "monfroni", "huang")) {
                if (folded.contains(place)) {
                    hits.add(file + ": " + place);
                }
            }
        }
        assertEquals(List.of(), hits);
    }

    // ------------------------------------------------------------------ the whole pipeline

    static final List<String> PARAGRAPHS = List.of(
            "Η ενδικοφανής προσφυγή του Γεωργίου Παπαδόπουλου, με Α.Φ.Μ. " + AFM
                    + ", κατοίκου Χαλανδρίου Αττικής, οδός Διομήδους αρ. 12, Τ.Κ. 15231.",
            "Με τη βεβαίωση της Διεύθυνσης ΥΔΟΜ του Δήμου Νέας Σμύρνης και την πράξη του Δήμου Αγίας Παρασκευής.",
            "τη με αριθμό 231/2020 απόφαση του Διοικητικού Πρωτοδικείου Χαλκίδας (Τμήμα 1ο Τριμελές) και του "
                    + "Πρωτοδικείου Νέας Ιωνίας.",
            "ΑΜΚΑ " + AMKA + ", IBAN " + IBAN + ", email " + EMAIL + ", κινητό " + PHONE + ".",
            "ακίνητο με ΚΑΕΚ 050011122233/0/0 και ΚΑΕΚ 050011122234/1/2.",
            "Η βεβαίωση του Δήμου Νέας Σμύρνης Γεώργιος Παπαδόπουλος υπογράφηκε.");

    /**
     * What HARD POLICY keeps visible whatever any model says: public geography the rules identified,
     * court structure, the zero suffix, and the labels' own characters.
     */
    static final List<String> HARD_PUBLIC = List.of("κατοίκου Χαλανδρίου Αττικής,", "του Δήμου Νέας Σμύρνης και",
            "του Δήμου Αγίας Παρασκευής.", "Πρωτοδικείου Χαλκίδας (Τμήμα 1ο Τριμελές)", "του Πρωτοδικείου Νέας Ιωνίας.",
            "/0/0 και", "Η βεβαίωση του Δήμου Νέας Σμύρνης", "Α.Φ.Μ.", "ΑΜΚΑ", "IBAN", "οδός", "αρ.", "Τ.Κ.", "ΚΑΕΚ");
    /** What a model that reads the context also keeps: the rest of each public name, and the label spacing. */
    static final List<String> READ_PUBLIC = List.of("της Διεύθυνσης ΥΔΟΜ του Δήμου Νέας Σμύρνης και",
            "απόφαση του Διοικητικού Πρωτοδικείου Χαλκίδας (Τμήμα 1ο Τριμελές) και του Πρωτοδικείου Νέας Ιωνίας.",
            "κατοίκου Χαλανδρίου Αττικής, οδός ", "Τ.Κ. ", "με Α.Φ.Μ. ", "ΚΑΕΚ ............/0/0 και ΚΑΕΚ ");
    /** What is private: names, the street, its number, the postal code, every identifier, the KAEK root. */
    static final List<String> PRIVATE = List.of("Γεωργίου", "Παπαδόπουλου", AFM, "Διομήδους", "αρ. 12", "15231", AMKA,
            IBAN, EMAIL, PHONE, "050011122233", "050011122234", "/1/2", "Γεώργιος", "Παπαδόπουλος");
    /** The private values, as a model that read the excerpt would report them. */
    static final List<String> PRIVATE_SPANS = List.of("Γεωργίου Παπαδόπουλου", "Διομήδους", "15231",
            "Γεώργιος Παπαδόπουλος", PHONE);

    static String run(ScriptedLlm llm) {
        AnonymizeResult r = Pipeline.anonymizeDocument(TestDocx.paragraphs(PARAGRAPHS.toArray(String[]::new)).bytes(),
                CFG, FILES, llm, RunContext.start(300, "places", System::nanoTime));
        return TestDocx.part(r.redactedDocx(), "word/document.xml");
    }

    /** One pass-1 finding. */
    static Map<String, Object> finding(String text, String action, String category) {
        Map<String, Object> f = new LinkedHashMap<>();
        f.put("text", text);
        f.put("action", action);
        f.put("category", category);
        return f;
    }

    /**
     * A model whose pass 1 reports each of {@code findings} it can see in its (masked) excerpt, and
     * whose pass 2 answers every candidate with {@code decide}.
     */
    static ScriptedLlm pass2(Function<Map<String, Object>, String> decide, List<Map<String, Object>> findings) {
        return new ScriptedLlm(r -> {
            if (ScriptedLlm.isPass1(r)) {
                return PyJson.dumps(findings.stream().filter(f -> r.userMessage().contains((String) f.get("text")))
                        .toList());
            }
            List<Object> out = new ArrayList<>();
            for (Map<String, Object> c : candidates(r)) {
                // The category a model would give: the one recommended (the field is forgiving anyway).
                Object recommended = ((List<?>) c.get("recommendations")).isEmpty() ? null
                        : ((Map<?, ?>) ((List<?>) c.get("recommendations")).get(0)).get("category");
                out.add(answer((String) c.get("id"), decide.apply(c),
                        recommended == null ? "POSSIBLE_PERSON" : (String) recommended));
            }
            return PyJson.dumps(out);
        });
    }

    /**
     * A model that reads each candidate in its place, as the prompt teaches: anything holding a
     * private value goes; a place that is part of a public body's name, a court's structure, or a
     * municipality with its region after a residence cue stays; anything else goes (when uncertain,
     * redact). Its pass 1 reports the private values it reads, whether or not the rules did.
     */
    static ScriptedLlm contextReadingModel() {
        Function<Map<String, Object>, String> decide = c -> {
            String text = (String) c.get("text");
            String before = (String) c.get("before");
            if (PRIVATE.stream().anyMatch(text::contains)) {
                return "REDACT";
            }
            boolean institution = (before + text).matches("(?s).*(Δήμ(ου|ος)|Πρωτοδικεί(ου|ο)|Εφετεί(ου|ο)|Τμήμα)"
                    + "\\s+(Νέας\\s+|Αγίας\\s+)?\\S*$")
                    || text.matches("^(Δήμ|Πρωτοδικ|Εφετ|Τμήμα|Διοικητικ|Διεύθυνσ|ΥΔΟΜ).*");
            boolean residenceWithRegion = before.endsWith("κατοίκου ") && text.endsWith("Αττικής");
            return institution || residenceWithRegion ? "PRESERVE" : "REDACT";
        };
        List<Map<String, Object>> found = new ArrayList<>();
        PRIVATE_SPANS.forEach(t -> found.add(finding(t, "REDACT", "POSSIBLE_PERSON")));
        return pass2(decide, found);
    }

    @Test
    void aModelThatReadsTheContextKeepsThePublicAndRedactsThePrivate() {
        ScriptedLlm llm = contextReadingModel();
        String xml = run(llm);
        for (String kept : concat(HARD_PUBLIC, READ_PUBLIC)) {
            assertTrue(xml.contains(kept), kept + " lost: " + xml);
        }
        for (String secret : PRIVATE) {
            assertFalse(xml.contains(secret), secret + " survived: " + xml);
        }
        // What the model reasoned from is what it was shown: each candidate with the words around it.
        List<Map<String, Object>> asked = llm.requests.stream().filter(r -> !ScriptedLlm.isPass1(r))
                .flatMap(r -> candidates(r).stream()).toList();
        assertTrue(asked.stream().anyMatch(c -> ((String) c.get("before")).endsWith("του Δήμου Νέας ")),
                asked.toString());
    }

    /** Deliberately wrong: reports every public place for redaction in pass 1, and REDACTs every candidate. */
    @Test
    void aModelThatRedactsThePublicIsOverruledWhereHardPolicyKeepsIt() {
        List<Map<String, Object>> attack = new ArrayList<>();
        for (String t : List.of("Νέας Σμύρνης", "Αγίας Παρασκευής", "Χαλκίδας", "Νέας Ιωνίας", "1ο Τριμελές",
                "Χαλανδρίου Αττικής", "/0/0")) {
            attack.add(finding(t, "REDACT", "LOCALITY"));
        }
        PRIVATE_SPANS.forEach(t -> attack.add(finding(t, "REDACT", "POSSIBLE_PERSON")));
        String xml = run(pass2(c -> "REDACT", attack));
        for (String kept : HARD_PUBLIC) {
            assertTrue(xml.contains(kept), kept + " lost: " + xml);
        }
        // The name after the municipality was never shielded: it goes with everything else private.
        for (String secret : PRIVATE) {
            assertFalse(xml.contains(secret), secret + " survived: " + xml);
        }
    }

    /**
     * Deliberately wrong the other way: reports every identifier it can see as one to keep, and
     * PRESERVEs every candidate. (The hard-redacted ones it cannot see at all: they are masked.)
     */
    @Test
    void aModelThatPreservesTheIdentifiersIsOverruledWhereHardPolicyRedactsThem() {
        List<Map<String, Object>> keepAll = new ArrayList<>();
        for (String t : List.of(AFM, AMKA, IBAN, EMAIL, "050011122233/0/0", "050011122234/1/2")) {
            keepAll.add(finding(t, "PRESERVE", "PUBLIC_SERVICE"));
        }
        ScriptedLlm llm = pass2(c -> "PRESERVE", keepAll);
        String xml = run(llm);
        for (String secret : List.of(AFM, AMKA, IBAN, EMAIL, "050011122233", "050011122234")) {
            assertTrue(llm.requests.stream().noneMatch(r -> r.userMessage().contains(secret)), secret + " was shown");
        }
        for (String secret : List.of(AFM, AMKA, IBAN, EMAIL, "050011122233", "050011122234", "/1/2")) {
            assertFalse(xml.contains(secret), secret + " survived a model that kept it: " + xml);
        }
        for (String kept : HARD_PUBLIC) {
            assertTrue(xml.contains(kept), kept + " lost: " + xml);
        }
    }

    static List<String> concat(List<String> a, List<String> b) {
        List<String> out = new ArrayList<>(a);
        out.addAll(b);
        return out;
    }
}
