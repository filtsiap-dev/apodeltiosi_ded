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
        String source = "SET ISO8859-7\nSFX B Y 1\nSFX B ος ου ος\n";
        byte[] aff = source.getBytes(java.nio.charset.Charset.forName("ISO-8859-7"));
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
