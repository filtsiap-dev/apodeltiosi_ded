package dev.filtsiap.ded.anonymizer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import dev.filtsiap.ded.anonymizer.pycompat.PyStr;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** Narrowing a model's REDACT span to its value: v2's span_trim, with a word-boundary region rule. */
class SpanTrimTest {

    static final Set<String> REGIONS = DetectorsTest.RULES.regions();

    /** What is left of {@code quote} in {@code text} after narrowing, or null when nothing is. */
    static String narrowed(String text, String quote, SpanCategory category) {
        int start = PyStr.find(text, quote);
        int[] r = SpanTrim.narrowRedaction(text, start, start + PyStr.len(quote), category, REGIONS);
        return r == null ? null : PyStr.slice(text, r[0], r[1]);
    }

    /**
     * Found by the real-model run of 3127: pass 1 quoted "11010705" of "11010705/1/9871/15.09.2022 εντολής
     * ελέγχου", leaving "1/9871" of the audit order's serial visible (the gold blanks "11010705/1/9871").
     */
    @Test
    void aReferenceThatStopsInsideItsMultiPartSerialTakesTheRestOfItButNeverItsDate() {
        String order = "Κατόπιν της με αριθμό 11010705/1/9871/15.09.2022 εντολής ελέγχου του 1ου ΕΛΚΕ";
        assertEquals("11010705/1/9871", narrowed(order, "11010705", SpanCategory.AUDIT_ORDER));
        assertEquals("11010705/1/9871", narrowed(order, "11010705/1", SpanCategory.AUDIT_ORDER));
        assertEquals("11010705/1/9871", narrowed(order, "11010705/1/9871/15.09.2022", SpanCategory.AUDIT_ORDER));
        assertEquals("1/5696634", narrowed("με αριθ. 1/5696634/2026 Προσωρινό", "1", SpanCategory.CHALLENGED_ACT_NUMBER));
        assertEquals("3776/430", narrowed("πρωτοκόλλου 3776/430/10-02-2026 ( ορθή", "3776", SpanCategory.PROTOCOL_NUMBER));
        // A serial that simply ends (3096: "1" of "1/5696634 προσωρινό"), and one typed with a letter O for a zero
        // and a dash before its year (3096: "863/Ο/1109-2024").
        assertEquals("11010705/1/9871", narrowed("με αριθμό 11010705/1/9871 εντολής", "11010705", SpanCategory.AUDIT_ORDER));
        assertEquals("1/5696634", narrowed("στον υπ' αριθμό. 1/5696634 προσωρινό", "1", SpanCategory.ACT_NUMBER));
        assertEquals("863/Ο/1109", narrowed("(υπ'αριθ.863/Ο/1109-2024 Εντολή", "863", SpanCategory.AUDIT_ORDER));
        assertEquals("863/0", narrowed("υπ. αριθμ. 863/0/ 11/9/2024 εκδόθηκε", "863", SpanCategory.AUDIT_ORDER));
        // What follows is the reference's date or year alone, or a slash date: nothing to take.
        assertEquals("34519", narrowed("πρωτοκόλλου 34519/30-03-2026 ενδικοφανή", "34519", SpanCategory.PROTOCOL_NUMBER));
        assertEquals("988", narrowed("των 987 και 988/2024 Οριστικών", "988", SpanCategory.CHALLENGED_ACT_NUMBER));
        assertEquals("2.701", narrowed("υπ. αρ. 2.701/2007 Πληρεξούσιο", "2.701", SpanCategory.CASE_REF_NUMBER));
        assertEquals("1234", narrowed("η πράξη 1234/15/09/2022 της", "1234", SpanCategory.ACT_NUMBER));
        // The category is no reference: the span stays as quoted.
        assertEquals("5069", narrowed("Α.Χ.Κ. 5069/141/2020 πράξη", "5069", SpanCategory.PROPERTY_ID));
        assertEquals("11010705", narrowed(order, "11010705", SpanCategory.POSSIBLE_PERSON));
    }

    @Test
    void labelsPrepositionsAndEdgePunctuationComeOff() {
        assertEquals("037173570", narrowed("ο προσφεύγων με Α.Φ.Μ. 037173570 ζητά", "με Α.Φ.Μ. 037173570",
                SpanCategory.AFM));
        assertEquals("037173570", narrowed("«Α.Φ.Μ. 037173570»", "«Α.Φ.Μ. 037173570»", SpanCategory.AFM));
        assertEquals("15078512345", narrowed("ΑΜΚΑ: 15078512345.", "ΑΜΚΑ: 15078512345.", SpanCategory.AMKA));
        assertEquals("x@example.com", narrowed("E-mail: x@example.com", "E-mail: x@example.com", SpanCategory.EMAIL));
        assertNull(narrowed("Α.Φ.Μ.", "Α.Φ.Μ.", SpanCategory.AFM)); // nothing but a label claims nothing
        assertNull(narrowed("...", "...", SpanCategory.AFM));
    }

    @Test
    void aCueIsAWholeWordAndNeverTrimmedFromAName() {
        assertEquals("Ibanez Garcia", narrowed("Ibanez Garcia", "Ibanez Garcia", SpanCategory.BANK_ACCOUNT));
        assertEquals("Ιβάν Ιβανίδης", narrowed("Ιβάν Ιβανίδης", "Ιβάν Ιβανίδης", SpanCategory.POSSIBLE_PERSON));
        assertEquals("κ. Νικολάου", narrowed("του κ. Νικολάου", "κ. Νικολάου", SpanCategory.FATHER_NAME));
        assertEquals("του ΔΗΜΗΤΡΙΟΥ", narrowed("του ΔΗΜΗΤΡΙΟΥ", "του ΔΗΜΗΤΡΙΟΥ", SpanCategory.FATHER_NAME));
        // A lower-case preposition is grammar; a capitalised one begins the name.
        assertEquals("Παπαδόπουλο", narrowed("με Παπαδόπουλο", "με Παπαδόπουλο", SpanCategory.APPELLANT_NAME));
        assertEquals("Στο Σπίτι Ο.Ε", narrowed("Στο Σπίτι Ο.Ε.", "Στο Σπίτι Ο.Ε.", SpanCategory.PRIVATE_COMPANY_NAME));
    }

    @Test
    void aReferenceKeepsItsDateOrYearAndASerialKeepsItsSlash() {
        assertEquals("34519", narrowed("με αριθμό πρωτοκόλλου 34519/30-03-2026", "αριθμό πρωτοκόλλου 34519/30-03-2026",
                SpanCategory.PROTOCOL_NUMBER));
        assertEquals("1234", narrowed("αρ. πρωτ. 1234/2026", "αρ. πρωτ. 1234/2026", SpanCategory.PROTOCOL_NUMBER));
        assertEquals("231", narrowed("τη με αριθμό 231/2020 απόφαση", "231/2020", SpanCategory.CASE_COURT_REFERENCE));
        assertEquals("76/19062", narrowed("Α.Χ.Κ. 76/19062", "Α.Χ.Κ. 76/19062", SpanCategory.PROPERTY_ID));
        assertEquals("2221792", narrowed("αριθμό ειδοποίησης 2221792/15-03-2026", "2221792/15-03-2026",
                SpanCategory.PROPERTY_ID)); // a notice number, by the cue in front of it
        assertEquals("12345", narrowed("(αριθ. ειδοποίησης 12345/2026,", "12345/2026", SpanCategory.PROPERTY_ID));
    }

    @Test
    void aCompositeProtocolReferenceGivesUpOnlyItsSerial() {
        String[][] cases = {
            {"ΔΕΔ 123456 ΕΞ 2026 ΕΜΠ / 01-06-2026", "123456"},
            {"ΔΕΔ 123456 ΕΞ 2Ο26 ΕΜΠ / 1Ο-06-2Ο26", "123456"}, // a capital O typed for a zero
            {"ΕΛ.ΚΕ.3 ΑΤ 7654321 ΕΞ2023", "7654321"},
            {"ΕΛ.ΚΕ. 3 ΑΤ 765432 ΕΙ 2024 ΕΜΠ/26.Ο7.2024", "765432"},
            {"ΔΑ 4321/23-06-2026", "4321"},
            {"αρ. πρ. ΔΕΔ 654321 ΕΙ 2026/24-06-2026", "654321"},
            {"υπ. αριθμ. ΕΛ.ΚΕ.3 ΑΤ 7654321 ΕΞ2Ο23", "7654321"}};
        for (String[] c : cases) {
            assertEquals(c[1], narrowed("το με αρ. " + c[0] + " έγγραφο", c[0], SpanCategory.PROTOCOL_NUMBER), c[0]);
        }
        // Not a composite reference: a single token, two serials, or a word that is not a code stays whole.
        assertEquals("ΓΠ760", narrowed("ΓΠ760/10-05-2021", "ΓΠ760/10-05-2021", SpanCategory.PROTOCOL_NUMBER));
        assertEquals("987 και 988", narrowed("987 και 988/2024", "987 και 988/2024", SpanCategory.PROTOCOL_NUMBER));
        assertEquals("ΠΑΠΑΣ 123456", narrowed("ΠΑΠΑΣ 123456", "ΠΑΠΑΣ 123456", SpanCategory.PROTOCOL_NUMBER));
        assertEquals("2606.48151.1842", narrowed("2606.48151.1842", "2606.48151.1842", SpanCategory.CASE_REF_NUMBER));
        // Only reference categories: a name category never loses a word this way.
        assertEquals("ΔΕΔ 123456", narrowed("ΔΕΔ 123456", "ΔΕΔ 123456", SpanCategory.POSSIBLE_PERSON));
        // Letters alone are not a date or a year.
        assertEquals("1234/ΟΟ-ΟΟ-ΟΟΟΟ", narrowed("1234/ΟΟ-ΟΟ-ΟΟΟΟ", "1234/ΟΟ-ΟΟ-ΟΟΟΟ", SpanCategory.PROTOCOL_NUMBER));
    }

    @Test
    void anInvoiceOrActNumberKeepsItsDateLikeEveryReference() {
        assertEquals("1136", narrowed("ΔΑ 1136/23-06-2026", "1136/23-06-2026", SpanCategory.INVOICE_TABLE_ID));
        assertEquals("526", narrowed("Πράξη 526/26-02-2026", "526/26-02-2026", SpanCategory.ACT_NUMBER));
        // A date introduced by a word dates the document and stays, as a slashed one does.
        assertEquals("4321", narrowed("Καταστατικό με αριθμό 4321 της 18-3-2011 (συν. 2)", "4321 της 18-3-2011",
                SpanCategory.CASE_REF_NUMBER));
        assertEquals("4321", narrowed("με αριθμό 4321 από 26-9-2013", "4321 από 26-9-2013", SpanCategory.PROTOCOL_NUMBER));
        // Not after a name, and a date is not a date's own tail; a full date stays whatever else the model
        // called the value, but a bare year only after a reference.
        assertEquals("Νίκος της 18-3-2011", narrowed("Νίκος της 18-3-2011", "Νίκος της 18-3-2011",
                SpanCategory.POSSIBLE_PERSON));
        assertEquals("01/02/1980", narrowed("γέννησης 01/02/1980", "01/02/1980", SpanCategory.DATE));
        assertEquals("54321", narrowed("ως ΑΤΒ 54321/10.09.2Ο24.", "54321/10.09.2Ο24.", SpanCategory.TRANSACTION_ID));
        assertEquals("54321/2024", narrowed("κωδικός 54321/2024", "54321/2024", SpanCategory.TRANSACTION_ID));
    }

    @Test
    void aPrepositionWithItsArticleAndACompanyCueComeOffButNeverFromAPersonsName() {
        assertEquals("Ερμού 5", narrowed("με έδρα επί της Ερμού 5", "επί της Ερμού 5", SpanCategory.BUSINESS_SEAT));
        assertEquals("Ερμού 5", narrowed("στην οδό Ερμού 5", "στην οδό Ερμού 5", SpanCategory.PRIVATE_ADDRESS));
        assertEquals("ΔΕΛΤΑ BANK A.E", narrowed("προς την Τράπεζα ΔΕΛΤΑ BANK A.E.", "Τράπεζα ΔΕΛΤΑ BANK A.E.",
                SpanCategory.PRIVATE_COMPANY_NAME));
        assertEquals("ΑΛΦΑ Α.Ε", narrowed("με την επωνυμία ΑΛΦΑ Α.Ε.", "με την επωνυμία ΑΛΦΑ Α.Ε.",
                SpanCategory.PRIVATE_COMPANY_NAME));
        // The word that introduces a name is never its first word, whatever the category: a name-shape
        // question that took the cue word along gives it back. A structural label still never comes off
        // a name ("Ιβάν" above), and the patronymic keeps its article.
        assertEquals("ΔΕΛΤΑ", narrowed("από την Τράπεζα ΔΕΛΤΑ", "Τράπεζα ΔΕΛΤΑ", SpanCategory.POSSIBLE_PERSON));
        assertEquals("Τραπεζάς Νικόλαος", narrowed("ο Τραπεζάς Νικόλαος", "Τραπεζάς Νικόλαος",
                SpanCategory.POSSIBLE_PERSON)); // a surname, not the noun
        assertEquals("του ΔΗΜΗΤΡΙΟΥ", narrowed("επί του ΔΗΜΗΤΡΙΟΥ", "του ΔΗΜΗΤΡΙΟΥ", SpanCategory.FATHER_NAME));
    }

    @Test
    void aTrailingRegionIsGivenBackOnlyAsAWholeWord() {
        assertEquals("Χαλανδρίου", narrowed("κατοίκου Χαλανδρίου Αττικής", "κατοίκου Χαλανδρίου Αττικής",
                SpanCategory.PRIVATE_ADDRESS));
        assertEquals("Λαμία", narrowed("Λαμία, Αττικής", "Λαμία, Αττικής", SpanCategory.PRIVATE_ADDRESS));
        assertEquals("Κρήτης", narrowed("οδός Κρήτης", "Κρήτης", SpanCategory.PRIVATE_ADDRESS)); // only a region
        assertEquals("Αθηνών", narrowed("Αθηνών Ανατολικής Μακεδονίας και Θράκης",
                "Αθηνών Ανατολικής Μακεδονίας και Θράκης", SpanCategory.PRIVATE_ADDRESS)); // longest entry
        // v2 compares the tail with no boundary and publishes "κρήτης" and "αττικής" here.
        assertEquals("Παπακρήτης", narrowed("Ο Παπακρήτης", "Παπακρήτης", SpanCategory.FATHER_NAME));
        assertEquals("Γεώργιος Δελαττικής", narrowed("Ο Γεώργιος Δελαττικής", "Γεώργιος Δελαττικής",
                SpanCategory.APPELLANT_NAME));
    }

    @Test
    void offsetsAreClampedAndNeverWidened() {
        assertNull(SpanTrim.narrowRedaction("abc", 5, 9, SpanCategory.AFM, REGIONS));
        assertNull(SpanTrim.narrowRedaction("abc", 2, 2, SpanCategory.AFM, REGIONS));
        int[] r = SpanTrim.narrowRedaction("x😀 Αττικής", 0, 10, SpanCategory.PRIVATE_ADDRESS, REGIONS);
        assertEquals(0, r[0]);
        assertEquals(2, r[1]); // code points: the emoji is one
    }
}
