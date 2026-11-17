# Chat anonymization lists

Loaded once at startup by `ChatLists.load` for `POST /anonymize-text`. Every word in the generated
lists is stored FOLDED (lowercase, no accents, σ for ς); `slang.txt` and `domain_allowlist.txt` are
written normally and folded on load.

| File | Source | Licence | Kept by |
|---|---|---|---|
| `given_names.txt` | Wikidata: male (Q12308941) and female (Q11879590) given names with a Greek native label (P1705), plus the given names (P735) of Greek citizens (P27 = Q41) with a Greek label, expanded with Greek case endings | CC0 | generated |
| `surnames.txt` | Wikidata: family names (P734) of Greek citizens (P27 = Q41) with a Greek label, expanded with case endings | CC0 | generated |
| `el_common.txt.gz` | LibreOffice Hunspell `el_GR` (v0.9), lowercase entries, every affix form | MPL 1.1 (of MPL 1.1 / GPL 2.0 / LGPL 2.1) | generated |
| `el_proper.txt.gz` | Same dictionary, capitalised entries, minus the two name lists | MPL 1.1 | generated |
| `en_common.txt.gz` | LibreOffice Hunspell `en_US` (SCOWL), lowercase entries, every affix form | SCOWL (permissive; keep the copyright notice) | generated |
| `slang.txt` | Chat words that are never names (some are also in the dictionaries) | ours | by hand |
| `domain_allowlist.txt` | Our product and service terms, acronyms | ours | by hand |
| `lists.properties` | What was built, when, from where, and how many words | – | generated |
| `chat.yaml` | NER switch | – | by hand |

Derived word lists are committed and shipped. `el_common.txt.gz`, `el_proper.txt.gz` and
`en_common.txt.gz` are generated from the el_GR dictionary (we use it under MPL 1.1, chosen from
its MPL 1.1 / GPL 2.0 / LGPL 2.1 tri-licence) and the en_US dictionary (SCOWL): every affix form
is expanded, folded and filtered, and the result is part of the repository and of the Docker
image. We do not ship the original `.dic` and `.aff` files. MPL 1.1 and SCOWL both ask that their
notices stay with what is distributed: see [NOTICE.md](NOTICE.md) for each source, its licence and
its copyright holder, and `licenses/` for the upstream README files that carry the licence texts.

## Rebuilding the generated lists

From the repo root (downloads go to `.cache/chat-lists/`, which is git-ignored; delete it to fetch
fresh copies):

    mvn -q test-compile
    java -Xmx2g -cp "target/test-classes;target/classes" \
        dev.filtsiap.ded.anonymizer.chat.build.BuildChatLists config/chat .cache/chat-lists

(The command is one line; it is wrapped here. Use `:` instead of `;` in the classpath on
Linux/macOS, and the line continuation of your shell.)

The builder also records the dictionaries' upstream commit (GitHub API, cached as
`dictionaries_commit.json`) and writes `lists.properties` sorted and without a timestamp, so a
rebuild changes only what changed. Then run `mvn -B verify`: the chat eval shows what the new lists
changed.
