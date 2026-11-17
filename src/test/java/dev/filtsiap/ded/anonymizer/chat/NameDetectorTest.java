package dev.filtsiap.ded.anonymizer.chat;

import static dev.filtsiap.ded.anonymizer.chat.ChatAsserts.expect;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;

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

    @Test
    void longInputStaysFast() {
        String unit = "με λένε Νίκη και υπογραφή: Γιώργος Μ. Παπαδόπουλος    \n";
        String t = unit.repeat(5000) + " ".repeat(100_000) + "ξ".repeat(100_000);
        assertTimeoutPreemptively(java.time.Duration.ofSeconds(10), () -> NAMES.detect(t));
    }

    @Test
    void aLongCapitalisedRunBeforeANameStaysFast() {
        String t = "Θέλω ".repeat(60_000) + "Ξανθίππη";
        java.util.List<ChatSpan> spans = assertTimeoutPreemptively(java.time.Duration.ofSeconds(3),
                () -> NAMES.detect(t));
        int cpLen = (int) t.codePoints().count();
        ChatSpan last = spans.get(spans.size() - 1);
        ChatSpan secondLast = spans.get(spans.size() - 2);
        assertEquals(cpLen, last.end());
        assertEquals(cpLen - "Θέλω Ξανθίππη".length(), secondLast.start());
    }

    @Test
    void theCurlyApostropheCueIsAccepted() {
        String t = "hi I’m John Smith can you help me";
        assertEquals(expect(t, "John Smith"), masked(t));
    }

    @Test
    void namesInAnyScriptAreTokens() {
        String cyrillic = "με λένε Иван Петров";
        assertEquals(expect(cyrillic, "Иван Петров"), masked(cyrillic));
        String latinExtended = "μίλησα με Łukasz Dvořák χθες";
        assertEquals(expect(latinExtended, "Łukasz Dvořák"), masked(latinExtended));
    }

    @Test
    void polytonicLettersAreFoldedToTheirBase() {
        String name = "μίλησα με Ἀναστασία χθες";
        assertEquals(expect(name, "Ἀναστασία"), masked(name));
        String common = "Ἡ ὁμάδα πήρε τη νίκη χθες";
        assertEquals(common, masked(common));
    }

    @Test
    void formatCharactersStayInsideATokenAndAreIgnoredForLookup() {
        String common = "ο λογαρια​σμός ήρθε διπλός";
        assertEquals(common, masked(common));
        String name = "μίλησα με Αναστα­σία χθες";
        assertEquals(expect(name, "Αναστα­σία"), masked(name));
    }

    @Test
    void aCapitalisedCommonWordAfterACueIsMaskedButNotPropagated() {
        String t = "Ευχαριστώ Πολύ για τη βοήθεια, πολύ καλή";
        assertEquals(expect(t, "Πολύ"), masked(t));
    }
}
