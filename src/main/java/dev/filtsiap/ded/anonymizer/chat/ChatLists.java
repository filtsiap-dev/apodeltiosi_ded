package dev.filtsiap.ded.anonymizer.chat;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import dev.filtsiap.ded.anonymizer.ConfigurationError;

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

    /**
     * Loads every list from {@code chatDir}.
     *
     * @param chatDir the config/chat directory
     * @return the loaded lists
     * @throws ConfigurationError when a list file is missing or corrupt
     */
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

    /**
     * From plain collections (folded here); for tests.
     *
     * @param givenNames    given names
     * @param surnames      surnames
     * @param greekCommon   ordinary Greek words
     * @param greekProper   Greek proper nouns that are not names
     * @param englishCommon ordinary English words
     * @param allow         words that are never names
     * @return the lists
     */
    public static ChatLists of(Collection<String> givenNames, Collection<String> surnames,
                               Collection<String> greekCommon, Collection<String> greekProper,
                               Collection<String> englishCommon, Collection<String> allow) {
        return new ChatLists(WordSet.of(givenNames), WordSet.of(surnames), WordSet.of(greekCommon),
                WordSet.of(greekProper), WordSet.of(englishCommon), WordSet.of(allow));
    }

    /**
     * Whether the word is a given name or a surname.
     *
     * @param folded the word, folded
     * @return true when either name list has it
     */
    public boolean isName(String folded) {
        return givenNames.contains(folded) || surnames.contains(folded);
    }

    /**
     * Whether the word is an ordinary Greek or English word, or a hand-kept never-a-name word.
     *
     * @param folded the word, folded
     * @return true when it is
     */
    public boolean isCommonWord(String folded) {
        return greekCommon.contains(folded) || englishCommon.contains(folded) || allow.contains(folded);
    }

    /**
     * The approximate memory the lists use.
     *
     * @return bytes
     */
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
