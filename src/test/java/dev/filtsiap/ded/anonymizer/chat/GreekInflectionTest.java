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
