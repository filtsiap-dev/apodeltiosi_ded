package dev.filtsiap.ded.anonymizer.chat;

import static dev.filtsiap.ded.anonymizer.chat.ChatAsserts.expect;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

/** The name detector with the committed lists: what the small fixture lists cannot show. */
class NameDetectorRealListsTest {
    static final NameDetector NAMES = new NameDetector(ChatListsRealConfigTest.LISTS);

    private static String masked(String text) {
        return Masker.mask(text, NAMES.detect(text));
    }

    // A surname ending marks a surname even when the word is also a place-list entry (el_proper).
    @ParameterizedTest(name = "{0}")
    @CsvSource(delimiter = '|', value = {
            "Ο Αναγνωστόπουλος από το λογιστήριο δεν απαντά.|Αναγνωστόπουλος",
            "μίλησα με τον Αγγελάκη χθες|Αγγελάκη",
            "ΑΓΓΕΛΑΚΗΣ ΓΙΑΝΝΗΣ|ΑΓΓΕΛΑΚΗΣ ΓΙΑΝΝΗΣ",
            "Χρήστης: Βασιλάκης|Βασιλάκης",
            "μίλησα με τον αγγελάκη χθες|αγγελάκη"})
    void aSurnameEndingOverridesThePlaceList(String text, String name) {
        assertEquals(expect(text, name), masked(text));
    }

    @Test
    void aSurnameEndingOverridesACommonWordOnlyWhenCapitalised() {
        String t = "Μίλησα με τον Ραφτόπουλο χθες";
        assertEquals(expect(t, "Ραφτόπουλο"), masked(t));
        String lower = "ένα ραφτόπουλο της γειτονιάς";
        assertEquals(lower, masked(lower));
    }

    @Test
    void aSurnameFoundByItsEndingIsMaskedInItsOtherForms() {
        String t = "Ο Αναγνωστόπουλος δεν απαντά, πείτε στον αναγνωστόπουλο να πάρει τηλέφωνο.";
        assertEquals(expect(t, "Αναγνωστόπουλος", "αναγνωστόπουλο"), masked(t));
    }

    @Test
    void aSoftHyphenInsideASurnameDoesNotSplitIt() {
        String t = "μίλησα με τον Παπα­δόπουλο χθες";
        assertEquals(expect(t, "Παπα­δόπουλο"), masked(t));
    }

    @Test
    void aPolytonicNameIsFound() {
        String t = "μίλησα με τον Ἀθανάσιο χθες";
        assertEquals(expect(t, "Ἀθανάσιο"), masked(t));
    }

    @Test
    void taxAndDeviceTermsOfTheAllowlistAreNotNames() {
        String t = "Πληρώνω τον ΕΝΦΙΑ μέσω Taxisnet από ένα Samsung Galaxy.";
        assertEquals(t, masked(t));
    }

    @Test
    void oeidisAdjectivesAreNotSurnames() {
        String t = "Σφαιροειδής μορφή, σφαιροειδή σχήματα.";
        assertEquals(t, masked(t));
    }

    // H1: a first name that is also a common word, next to a surname, in any case or position.
    @ParameterizedTest(name = "{0}")
    @CsvSource(delimiter = '|', value = {
            "Σοφία Γεωργίου|Σοφία Γεωργίου",
            "Σταύρος Παπαδόπουλος|Σταύρος Παπαδόπουλος",
            "ΣΟΦΙΑ ΓΕΩΡΓΙΟΥ|ΣΟΦΙΑ ΓΕΩΡΓΙΟΥ",
            "σοφια γεωργιου|σοφια γεωργιου",
            "Ονοματεπώνυμο: Σοφία Γεωργίου|Σοφία Γεωργίου",
            "Ειρήνη Αναγνωστοπούλου|Ειρήνη Αναγνωστοπούλου"})
    void aCommonWordFirstNameNextToASurnameIsMasked(String text, String name) {
        assertEquals(expect(text, name), masked(text));
    }

    @Test
    void aCommonWordFirstNameAloneIsStillKept() {
        String t = "η ελπίδα πεθαίνει τελευταία";
        assertEquals(t, masked(t));
    }

    // M1: form labels and the third-person "λένε" are name cues.
    @ParameterizedTest(name = "{0}")
    @CsvSource(delimiter = '|', value = {
            "Όνομα: Ζωή|Ζωή",
            "Επώνυμο: Οικονόμου|Οικονόμου",
            "Τον λένε Χρήστο|Χρήστο",
            "Τη λένε Νίκη|Νίκη"})
    void aFormLabelOrThirdPersonLeneIsANameCue(String text, String name) {
        assertEquals(expect(text, name), masked(text));
    }

    // M2: an ordinary capitalised word with a weak surname ending is not forced to be a surname.
    @ParameterizedTest(name = "{0}")
    @CsvSource(delimiter = '|', value = {
            "Παλαιός κωδικός πρόσβασης",
            "Ιδιώτης πελάτης είμαι",
            "Περιφερειακή διεύθυνση",
            "Πανεπιστημιακή κλινική"})
    void anOrdinaryWordWithAWeakSurnameEndingIsKept(String text) {
        assertEquals(text, masked(text));
    }

    // Owner cases (2026-10-14): lowercase and unaccented full names are masked in every form.
    @Test
    void aSurnameAloneThenTheFullNameInALaterMessageAreMaskedEverywhere() {
        String t = "Χρήστης: είμαι ο παππάς\nΧρήστης: συγγνώμη, ηλίας παππάς";
        assertEquals(expect(t, "παππάς", "ηλίας"), masked(t));
    }

    @Test
    void anUnaccentedLowercaseFullNameAfterACueIsMasked() {
        String t = "ειμαι ο ηλιας παππας και θελω βοηθεια";
        assertEquals(expect(t, "ηλιας παππας"), masked(t));
    }

    // The benefits chatbot's own vocabulary: public bodies, systems and units are not names.
    @ParameterizedTest(name = "{0}")
    @CsvSource(delimiter = '|', value = {
            "πως κανω αιτηση για το ΕΚΑΣ",
            "ΟΠΕΚΑ πληρωμη επιδοματος παιδιου",
            "αναπηρικο επιδομα ΚΕΠΑ",
            "myAADE εφαρμογη",
            "ΑΣΕΠ προκηρυξη 3Κ/2025",
            "διαμέρισμα 70 τμ",
            "ΚΕΑ ελάχιστο εγγυημένο εισόδημα"})
    void publicBenefitVocabularyIsNeverMasked(String text) {
        assertEquals(text, masked(text));
    }

    @Test
    void theBenefitVocabularyDoesNotHideARealName() {
        String t = "με λένε Ελένη Κωνσταντίνου και ρωτάω για το ΕΚΑΣ";
        assertEquals(expect(t, "Ελένη", "Κωνσταντίνου"), masked(t));
    }

    // "ΚΩΝ/ΝΟΣ" and "ΚΩΝ/ΝΑ" abbreviate Κωνσταντίνος and Κωνσταντίνα. The '/' splits them into two words, one of
    // which ("ΚΩΝ", "ΝΑ") is not a name on any list, so a rule matches the whole abbreviation.
    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {"ΚΩΝ/ΝΟΣ", "ΚΩΝ/ΝΑ", "ΚΩΝ/ΝΟΥ", "ΚΩΝ/ΝΑΣ", "ΚΩΝ / ΝΟΣ", "κων/νος", "Κων/νου", "ΚΩΝ/ΝΕ",
            "ΚΩΝ/Ν\u0041", "\u004BΩΝ/ΝΟΣ"})
    void theAbbreviationOfConstantinosIsMaskedLetterByLetter(String abbreviation) {
        String text = "ραντεβού για τον " + abbreviation + " χθες";
        String expected = text.replace(abbreviation, abbreviation.replaceAll("\\p{L}", "."));
        assertEquals(expected, masked(text));
    }

    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {"ΚΩΝ/ΝΟΜΟΣ", "ΚΩΝ/ΝΟΣΤΙΜΟΣ", "ΚΩΝΣΤΑΝΤΙΝΟΣ/ΝΟΣ", "ΑΚΩΝ/ΝΟΣ"})
    void otherWordsAreNotReadAsTheAbbreviation(String text) {
        assertEquals(List.of(), NAMES.detect(text).stream()
                .filter(s -> s.detector().equals("name_abbreviation")).toList());
    }
}
