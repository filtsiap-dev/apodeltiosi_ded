package dev.filtsiap.ded.anonymizer;

import static dev.filtsiap.ded.anonymizer.llm.ScriptedLlm.answer;
import static dev.filtsiap.ded.anonymizer.llm.ScriptedLlm.candidates;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.filtsiap.ded.anonymizer.llm.ScriptedLlm;
import dev.filtsiap.ded.anonymizer.pycompat.PyJson;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * The new gold's five over-redaction corrections, and the sensitive data that must still go. All
 * text is synthetic; the shapes follow the published decisions.
 */
class NewGoldTest {

    static final FileConfig FILES = Config.loadFileConfig(Path.of("config"));
    static final RuntimeConfig CFG = Config.loadRuntimeConfig(Map.of("ANON_PROVIDER", "openai",
            "OPENAI_API_KEY", "sk-test", "ANON_MODEL", "gpt-test"));
    static final String AFM = TestDocx.validAfm("09401420");

    static String run(ScriptedLlm llm, String... paragraphs) {
        AnonymizeResult r = Pipeline.anonymizeDocument(TestDocx.paragraphs(paragraphs).bytes(), CFG, FILES, llm,
                RunContext.start(300, "gold", System::nanoTime));
        return TestDocx.part(r.redactedDocx(), "word/document.xml");
    }

    static int count(String haystack, String needle) {
        int n = 0;
        for (int i = haystack.indexOf(needle); i >= 0; i = haystack.indexOf(needle, i + 1)) {
            n++;
        }
        return n;
    }

    /**
     * What v2's prompt told the model to blank in these phrases (the Java prompt now teaches the
     * opposite, see PromptText), and the whole ΚΑΕΚ besides: hard policy must hold even against it.
     */
    static final List<String> TARGETS = List.of("Χαλανδρίου", "Χαλκιδέων", "Χαλκίδας", "1ο Τριμελές",
            "050011122233/0/0");

    /**
     * A model that does exactly that, by every route it has: pass 1 reports each target it can see
     * in its (masked) excerpt, and pass 2 REDACTs every candidate that contains one. Everything else
     * it PRESERVEs.
     */
    static ScriptedLlm promptFollowingModel() {
        return new ScriptedLlm(r -> {
            if (ScriptedLlm.isPass1(r)) {
                List<Object> findings = new ArrayList<>();
                for (String t : TARGETS) {
                    if (!r.userMessage().contains(t)) {
                        continue; // a model can only quote what it was shown
                    }
                    Map<String, Object> f = new LinkedHashMap<>();
                    f.put("text", t);
                    f.put("action", "REDACT");
                    f.put("category", "LOCALITY");
                    findings.add(f);
                }
                return PyJson.dumps(findings);
            }
            List<Object> out = new ArrayList<>();
            for (Map<String, Object> c : candidates(r)) {
                String text = (String) c.get("text");
                boolean target = TARGETS.stream().anyMatch(text::contains);
                out.add(answer((String) c.get("id"), target ? "REDACT" : "PRESERVE", "LOCALITY"));
            }
            return PyJson.dumps(out);
        });
    }

    @Test
    void theNewGoldPlacesChamberAndZeroKaekSuffixStayVisibleWhateverTheModelSays() {
        String xml = run(promptFollowingModel(),
                "Η ενδικοφανής προσφυγή, με Α.Φ.Μ. " + AFM + ", κατοίκου Χαλανδρίου Αττικής, οδός Διομήδους αρ. 12.",
                "Με τη βεβαίωση της Διεύθυνσης ΥΔΟΜ του Δήμου Χαλκιδέων και την πράξη του Δήμου Χαλκιδέων.",
                "τη με αριθμό 231/2020 απόφαση του Διοικητικού Πρωτοδικείου Χαλκίδας (Τμήμα 1ο Τριμελές).",
                "ακίνητο εμβαδού 120,50 τ.μ. και με ΚΑΕΚ 050011122233/0/0.");
        assertTrue(xml.contains("κατοίκου Χαλανδρίου Αττικής,"), xml);
        assertEquals(2, count(xml, "του Δήμου Χαλκιδέων"), xml);
        assertTrue(xml.contains("απόφαση του Διοικητικού Πρωτοδικείου Χαλκίδας (Τμήμα 1ο Τριμελές)."), xml);
        assertTrue(xml.contains("με ΚΑΕΚ ............/0/0."), xml); // the root goes, the suffix stays
        assertFalse(xml.contains(AFM) || xml.contains("050011122233"), xml);
    }

    @Test
    void sensitiveDataIsStillRedacted() {
        // The cooperative model follows every proposal: what the rules propose for redaction goes.
        String xml = run(ScriptedLlm.cooperative(),
                "Η ενδικοφανής προσφυγή του Νικολάου Δημητρίου, με Α.Φ.Μ. " + AFM
                        + ", κατοίκου Χαλανδρίου Αττικής, οδός Διομήδους αρ. 12.",
                "ΑΜΚΑ 15078512345, IBAN GR6401401230000000123456789, email n.d@example.com, κινητό 6912345678.",
                "με την εταιρεία με επωνυμία Αλφάδα Εμπορική Α.Ε. και δικαιούχο τον Γεώργιο Παπαδόπουλο.",
                "Η βεβαίωση του Δήμου Χαλκιδέων Σπυρίδων Αντωνίου υπογράφηκε.",
                "ακίνητο με ΚΑΕΚ 050011122234/1/2 και ΚΑΕΚ 050011122233/0/0 και αριθμό ειδοποίησης 1234/2026.");
        for (String secret : List.of("Νικολάου", "Δημητρίου", AFM, "Διομήδους", "αρ. 12", "15078512345",
                "GR6401401230000000123456789", "n.d@example.com", "6912345678", "Αλφάδα", "Παπαδόπουλο", "Σπυρίδων",
                "Αντωνίου", "050011122234", "/1/2", "050011122233", "1234/")) {
            assertFalse(xml.contains(secret), secret + " survived: " + xml);
        }
        // What the policy keeps, kept: the residence, the authority, the labels, the suffix, the year.
        for (String kept : List.of("κατοίκου Χαλανδρίου Αττικής", "του Δήμου Χαλκιδέων", "οδός", "αρ.",
                "Α.Φ.Μ.", "ΑΜΚΑ", "IBAN", "ΚΑΕΚ", "/0/0", "/2026")) {
            assertTrue(xml.contains(kept), kept + " lost: " + xml);
        }
    }

    // ------------------------------------------------------------------ later gold corrections (synthetic)

    /**
     * A model that reads a whole private value correctly in pass 1 and redacts it in pass 2, but answers
     * PRESERVE for every narrower name-shape question inside it ("not a person"): the answer to a
     * fragment may not carve the value it belongs to.
     */
    static ScriptedLlm fragmentPreservingModel(String whole, String category) {
        return new ScriptedLlm(r -> {
            if (ScriptedLlm.isPass1(r)) {
                Map<String, Object> f = new LinkedHashMap<>();
                f.put("text", whole);
                f.put("action", "REDACT");
                f.put("category", category);
                return PyJson.dumps(List.of(f));
            }
            List<Object> out = new ArrayList<>();
            for (Map<String, Object> c : candidates(r)) {
                out.add(answer((String) c.get("id"), whole.equals(c.get("text")) ? "REDACT" : "PRESERVE", category));
            }
            return PyJson.dumps(out);
        });
    }

    @Test
    void aPreserveOnAFragmentCannotExposeAPrivateCompanyOrStreet() {
        String company = "ΚΑΠΑ ΛΑΜΔΑ ΣΥΜΒΟΥΛΕΥΤΙΚΗ ΕΤΑΙΡΙΑ";
        String xml = run(fragmentPreservingModel(company, "PRIVATE_COMPANY_NAME"),
                "οι συναλλαγές με την " + company + " για το 2020.");
        assertTrue(xml.contains("οι συναλλαγές με την " + ".".repeat(company.length()) + " για το 2020."), xml);

        String street = "Αγίας Σοφίας Οδού 12, Πάτρα";
        xml = run(fragmentPreservingModel(street, "PRIVATE_ADDRESS"), "στη δηλωμένη έδρα της επί της " + street + ", όπου");
        assertTrue(xml.contains("επί της " + ".".repeat(street.length()) + ", όπου"), xml);
    }

    @Test
    void aGenericPartyRoleSurvivesAModelThatCallsItACompany() {
        String xml = run(fragmentPreservingModel("προσφεύγουσα εταιρία", "PRIVATE_COMPANY_NAME"),
                "οι πράξεις κοινοποιήθηκαν στην προσφεύγουσα εταιρία ηλεκτρονικά.");
        assertTrue(xml.contains("στην προσφεύγουσα εταιρία ηλεκτρονικά."), xml);
    }

    @Test
    void aCompositeProtocolReferenceQuotedWholeLosesOnlyItsSerial() {
        String reference = "ΔΕΔ 123456 ΕΞ 2Ο26 ΕΜΠ / 1Ο-06-2Ο26";
        String xml = run(fragmentPreservingModel(reference, "PROTOCOL_NUMBER"),
                "Το με αρ. πρ. " + reference + " έγγραφο της Υπηρεσίας μας.");
        assertTrue(xml.contains("Το με αρ. πρ. ΔΕΔ ...... ΕΞ 2Ο26 ΕΜΠ / 1Ο-06-2Ο26 έγγραφο"), xml);
    }

    @Test
    void aPartysBankNameIsKeptAndItsAccountIsRedacted() {
        // A model that follows the prompt's policy: a bank's name is kept, everything else as recommended. No rule
        // proposes the name (only a generic two-capitalised-words hint asks about "Τράπεζα ΔΕΛΤΑ").
        ScriptedLlm keepsBanks = new ScriptedLlm(r -> ScriptedLlm.isPass1(r) ? "[]" : PyJson.dumps(candidates(r).stream()
                .map(c -> ((String) c.get("text")).contains("ΔΕΛΤΑ") ? answer((String) c.get("id"), "PRESERVE",
                        "POSSIBLE_COMPANY") : ScriptedLlm.agreeWithEveryCandidate(r).get(candidates(r).indexOf(c)))
                .toList()));
        String xml = run(keepsBanks,
                "ζητήθηκε από την Τράπεζα ΔΕΛΤΑ BANK A.E. όπως μας γνωστοποιήσει",
                "το απόρρητο έγγραφο της τράπεζας ΔΕΛΤΑ, για τα έτη 2019 και 2020, στον λογαριασμό 1234567890.");
        assertTrue(xml.contains("από την Τράπεζα ΔΕΛΤΑ BANK A.E. όπως"), xml);
        assertTrue(xml.contains("της τράπεζας ΔΕΛΤΑ, για τα έτη"), xml);
        assertFalse(xml.contains("1234567890"), xml);
    }

    @Test
    void aBareResidenceIsKeptAndAStreetNumberAndAPostalCodeAreRedactedAndTheirLabelsAndTheLawStay() {
        String xml = run(ScriptedLlm.cooperative(),
                "Ο προσφεύγων, κατοίκου Λαμίας, οδός Διομήδους αρ. 12, Τ.Κ. 15231, του Γεωργίου Παπαδόπουλου με Α.Φ.Μ. "
                        + AFM + ".",
                "Παρών ο κ. Σπυρίδων Αντωνίου. Τιμολόγιο 4321, αρ. πρωτ. 1234/2026.",
                "Σύμφωνα με τις διατάξεις του αρ. 9 της ΠΟΛ 1234/2015.");
        for (String secret : List.of("Διομήδους", "12,", "15231", "Γεωργίου", "Παπαδόπουλου", "Σπυρίδων",
                "Αντωνίου", "4321", "1234/2026", AFM)) {
            assertFalse(xml.contains(secret), secret + " survived: " + xml);
        }
        for (String kept : List.of("κατοίκου Λαμίας, ", "οδός ", "αρ. ", "Τ.Κ. ", "Α.Φ.Μ. ", "ο κ. ", "Τιμολόγιο ", "/2026",
                "του αρ. 9 της ΠΟΛ 1234/2015")) {
            assertTrue(xml.contains(kept), kept + " lost: " + xml);
        }
    }
}
