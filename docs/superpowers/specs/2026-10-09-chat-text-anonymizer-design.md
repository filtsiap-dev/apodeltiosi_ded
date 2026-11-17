# Design: `POST /anonymize-text` — masking for chatbot conversation logs

Status: implemented (see Implementation notes) · Date: 2026-10-09 (updated 2026-10-13) · Branch: java-app-log-masking

## Context
Chatbots are going to production, and their conversation logs will be kept for analytics. For legal reasons those logs must be anonymised first. The existing service (`ded-anonymizer`, Java 21/24, Maven) only anonymises `.docx` tax decisions. Its regexes for structured IDs are strong: AFM, AMKA, IBAN, email and phone, with validators. Its name detection, however, relies on cues specific to tax decisions plus a "two capitalised words" shape, and chat text won't match those.

Decisions made during brainstorming:
- **Local only, no LLM.** Azure OpenAI is not used as the Greek NLP.
- **No licence-unclear NER model in v1.** spaCy Greek is non-commercial. gr-nlp-toolkit's NER was trained on the non-commercial elNER corpus, so legal must clear it first.
- **Approach A:** regex + a Greek name gazetteer + context cues, plus a pluggable NER slot that is off by default.
- **Output is a character mask with `.`**, length preserved, the same as today.
- **The input format is unknown**, so start with a plain-text endpoint: mask whatever text comes in.
- **In scope:** person names, addresses and locations, and other Greek IDs. **Out of scope:** Greeklish. (Since 2026-10-14 location information is no longer masked: Implementation notes 22.)
- **Low volume, async is fine.**
- **Names:**
  - Typical names come from a Wikidata list (CC0).
  - Uncommon names are any word that isn't in the Greek or English dictionary, isn't a typo, and isn't allowlisted. Such words are **always masked**.
  - A Wiktionary list is not used.
- **No evaluation data yet,** so build a synthetic gold set now and design it so real labelled turns can be added later.

## Process overview (readable summary)

### In one sentence
`/anonymize-text` uses the same building blocks as the `.docx` `/anonymize` endpoint: authentication, the ID detectors, a `.` mask and a final safety re-scan. It does not use the `Resolver`: the spans are a union (Implementation notes 1). The differences:
- **It reads and returns plain text.** No `.docx` parsing or writing.
- **It has no LLM passes.**
- **It adds three things:**
  1. New regexes for other Greek IDs (the address regexes were removed on 2026-10-14: Implementation notes 22).
  2. Name detection: a Wikidata name list plus the Hunspell "uncommon word" check.
  3. An optional Greek NER detector, off by default.

### Step by step, with an example
Input: `Καλησπέρα, με λένε γιώργο παπαδόπουλο. ΑΦΜ 090000045. Ο γιώργος μένει στην Πατησίων 25, τηλ 6912345678`

1. **Receive.** Decode UTF-8 and NFC-normalise. All later steps work on character positions in this string.
2. **Fold a copy for matching.** Lowercase it, strip accents and map ς→σ, one code point at a time, so a position in the copy is the same position in the original and no offset map is needed (Implementation notes 3). This way "Γιώργο", "γιωργο" and "ΓΙΩΡΓΟ" match the same entry. The folded copy is never output.
3. **Detectors run independently.** Each returns spans (start, end, category, confidence):

| Detector | Finds | Why |
|---|---|---|
| Existing ID regexes (reused) | `090000045` AFM, `6912345678` PHONE | label/shape + checksum |
| New chat regexes | nothing here; `Πατησίων 25` stays (Implementation notes 22) | location information is not masked |
| Name detector | `γιώργο παπαδόπουλο` PERSON | cue "με λένε"; γιωργο is in the name list; next word sits beside a given name |
| NER (if enabled) | more PERSON/LOC/ORG | context-aware model |

4. **Propagate names.** Every other form of a confirmed name, anywhere in the text, is marked too. `γιώργος` in the second sentence becomes PERSON.
5. **Combine.** There is no `Resolver`: the mask is the union of every span any detector proposed, so no proposal can be lost to an adjudication step (Implementation notes 1). The detectors already leave the label ("ΑΦΜ") out of the span.
6. **Mask.** Every non-whitespace character in a span becomes `.`; spaces and punctuation outside spans stay, so the length is unchanged:
   `Καλησπέρα, με λένε ...... ............ ΑΦΜ .......... Ο ....... μένει στην Πατησίων 25, τηλ ..........`
7. **Safety re-scan.** Look for anything in the output that still looks like an AFM, AMKA, IBAN, email, phone or a 9-11 digit run. Anything found is masked anyway, and the status becomes `needs-review`.
8. **Reply.** The body is the masked text. Headers carry `x-anonymization-status` and `x-redaction-counts`. Original text is never logged or stored.

### How the name detector decides (per word)
- **Known name**, from the Wikidata list in all its inflected forms: mask, unless it is also a place-list entry (then it needs a cue or a neighbour, like the next case).
- **Known name that is also a common word** (Νίκη, Ελπίδα, Άγγελος): mask after a cue ("με λένε", "τον/την λένε", "ονομάζομαι", "είμαι ο/η", "κύριε/κυρία", "κος/κα", "εκ μέρους", "υπογραφή", "ευχαριστώ", "στο όνομα", "κουδούνι", a form label such as "Όνομα:", "Επώνυμο:" or "Αιτών:", "I'm", "my name is", "Mr/Mrs/Ms"). Without a cue it is masked only when it is capitalised, not the first word of a sentence and right after an article (ο, η, του, της, τον, την, τη), or when it sits next to a name that was already masked with confidence ("Σοφία Γεωργίου").
- **Uncommon word** (not in the Greek or English dictionary, not a typo of a common word, not allowlisted): **always mask**. This is how unusual names are caught: "είμαι η Ξανθίππη Μπαλαμώτη" → "είμαι η ........ .........".
- **Surname ending** (-όπουλος, -άκης, -ίδης…): mask, with the conditions of the "Surname endings" bullet in the Core section.
- **Ordinary word, known place name** (Μαρούσι, Κηφισιάς) **or allowlisted domain term:** keep. No detector masks places, streets or postal codes any more, whatever the cue ("μένω", "δουλεύω", "ΔΟΥ"): Implementation notes 22. A place can still be masked by the cases above when it looks like a name ("Αθήνα" is also a given name, "Ζωγράφου" has a surname shape) or is not an ordinary word; the owner accepts that.

### Where the lists come from (all allow commercial use)

| List | Source | Licence | What it asks of us |
|---|---|---|---|
| Given names and surnames, expanded with inflections (2,685 and 2,250 forms as shipped; about 950 given names and 1.1k surnames before expansion) | Wikidata | CC0 (public domain) | nothing |
| Ordinary Greek words, all forms (794,707 as shipped) and Greek proper nouns (17,636) | LibreOffice Hunspell `el_GR` spell-check dictionary | MPL 1.1 (of a MPL/GPL/LGPL tri-licence) | keep the notice; the derived word lists are committed and shipped, so `config/chat/NOTICE.md` and the upstream READMEs in `config/chat/licenses/` travel with them |
| Ordinary English words (102,190 as shipped) | SCOWL / Hunspell `en_US` | permissive (BSD/MIT-style) | keep the notice |
| Slang/abbreviations, domain terms | hand-kept by us | ours | – |

- Hunspell is only used at **build time**: the list builder (`BuildChatLists`, Implementation notes 7) expands it into a plain word file.
- The service loads that file. It contains no Hunspell code.
- Avoided:
  - spaCy Greek, elNER, Greek Legal NER: CC BY-NC-SA, non-commercial.
  - gr-nlp-toolkit: trained on non-commercial data, so legal must decide.
  - Wiktionary: not needed.
  - Name-day sites: all rights reserved.

### When NER is switched on
- **Enabled by config** (`config/chat/chat.yaml`, Implementation notes 2):
  - `ner.enabled: true`
  - `provider`
  - `min_confidence`
  - `timeout_ms`
  - A future adapter adds its own keys (`model_path` or `url`). v1 refuses to start with `ner.enabled: true`, because it ships no adapter.
- **Two adapters behind one `NerDetector` interface:**
  - `OnnxNerDetector`: in-process ONNX Runtime, e.g. our own fine-tuned GREEK-BERT (MIT).
  - `HttpNerDetector`: a Python container on localhost, e.g. gr-nlp-toolkit if legal clears it. Text never leaves our infrastructure.
- **Input and output:** the model reads the original text, in pieces of about 512 tokens. Its PERSON/LOC/ORG spans above `min_confidence` become ordinary REDACT spans, and are propagated, resolved and masked like any other span.
- **NER only adds masks, never removes them.** Turning it on can only make output safer.
- **On failure** (crash, timeout, sidecar down), the regex/list result is still returned, with status `needs-review` and the `x-review-reasons` header. The request doesn't fail.
- **What it adds:**
  - Names that are common words with no cue ("μίλησα με τη νίκη").
  - Organisations.
  - Places with no address cue (designed before Implementation notes 22; an adapter must now drop LOC spans, since locations are not masked).
- **Measuring it:** `ChatEvalTest` runs the gold set with NER off and on, so the gain is measured before it's enabled.

## Design

### API (`src/main/java/dev/filtsiap/ded/api/ApiHandler.java`)
- Add `"/anonymize-text" -> "POST"` to `ROUTES` (the `ROUTES` map).
- Request: `text/plain; charset=utf-8`. Response: `200 text/plain; charset=utf-8`, the masked text.
- Headers:
  - `x-anonymization-status`: `anonymized` | `needs-review` (lowercase, as the docx route sends it).
  - `x-redaction-counts`: comma-separated `TYPE=n` in `PiiType` declaration order, e.g. `PERSON=2,AFM=1`; `none` when nothing was masked. Mirrors `x-postcheck-kinds`.
  - `x-review-reasons`: only when the status is `needs-review`; comma-separated fixed strings (`residual:<pattern>`, `ner_unavailable`), never text.
  - `x-processing-time-ms`, as on the docx route.
  - `x-document-id`.
- Reuse the `/anonymize` mechanics:
  - `requireApiKey`
  - `RunContext` deadline
  - `readUpload` size cap (its own text limit)
  - `ERROR_STATUS` mapping
  - the single `document_finished`-style log line, with counts only and never any text
- Add a `Processor`-like seam so tests can stub the pipeline, as for docx.
- Add 415 for other media types.

### Core (`src/main/java/dev/filtsiap/ded/anonymizer/chat/`, new; the names below are the original design, the names as built are in Implementation notes 15)
- **`ChatPipeline.anonymizeText(String, cfg, files, ctx) -> TextResult(masked, status, counts)`.** Steps:
  1. NFC-normalise, then wrap the text as one `TextUnit` (PARAGRAPH, synthetic charMap) in a `DocumentData`.
  2. Run the reused detectors from `Detectors.java`: `detectStructuredIds` (:113), `detectContacts` (:168), `detectBankPaymentIds` (:496). These are public and only need the text.
  3. Run `ChatDetectors` (new regexes), then `GreekNameDetector` (gazetteer + cues), then `NerDetector` (no-op unless enabled).
  4. **Propagate within the request:** every confident name hit masks all other occurrences of the same folded form and its inflected forms.
  5. Merge with `Resolver.resolveRedactions(DocumentData, spans, …)` (Resolver.java:268), then mask each redacted character with `.`. (Built as a plain union of the spans, without the `Resolver`: Implementation notes 1.)
  6. **Residual scan:** run `PostcheckPatterns.QA_PATTERNS` (PostcheckPatterns.java:21-29) over the masked text. Any hit (AFM, AMKA, IBAN, email, phone or a 9-11 digit run) gets force-masked and sets the status to `needs-review`.
- **`GreekFold`:** NFD, strip combining marks, lowercase, ς→σ, one code point at a time so that offsets stay the same (no offset map: Implementation notes 3). Reuse the logic of `DetectorPatterns.foldGreek`.
- **`ChatDetectorPatterns`:** chat regexes, each overridable by key in `config/regex_patterns.yaml`.
  - ID card (ΑΔΤ), new `ΑΒ 123456` and old `Α-123456`, Greek and Latin look-alike letters.
  - Passport behind a cue.
  - Plate, e.g. `ΙΚΥ-1234`.
  - ΓΕΜΗ behind a cue.
  - Payment card, 13–19 digits + Luhn.
  - Customer, supply or contract number behind a cue.
  - Street + number, "μένω/κατοικώ στ…" + place, and postal codes: built, then removed on 2026-10-14 (Implementation notes 22).
  - Bare 9- and 11-digit runs that pass the AFM/AMKA validators.
- **Name detection (`GreekNameDetector`), following the user's design.** Typical names come from a list. An uncommon name is any word that isn't ordinary Greek or English.
  - **Typical names, `config/gazetteer/given_names.txt` and `surnames.txt`:**
    - Source: Wikidata (CC0). About 950 given names (608 male + 346 female, verified 2026-10-09) and about 1.1k surnames of Greek people; with the P735 addition of note 8 and the inflected forms, the shipped lists hold 2,685 given-name and 2,250 surname forms.
    - Folded, then expanded with 8 inflection paradigms (-ος/-ου/-ο/-ε, -ης/-η, -ας/-α, -ους/-ου, -ες/-ε, -α/-ας, -η/-ης, -ω/-ως; an ending no paradigm knows, such as invariant -ου, is left as it is). There are no diminutive rules.
    - A hit is REDACT.
  - **Names that are also common words** (Νίκη, Ελπίδα, Άγγελος) need a cue before they are redacted.
    - This stoplist is computed automatically as gazetteer ∩ the common-word lexicon, so it isn't hand-maintained.
  - **Uncommon words: always REDACT** (user decision; recall first).
    - A token is uncommon if it is not in any of: the Greek lexicon, the English lexicon, the slang/abbreviation list, `domain_allowlist.txt`, or the known-proper-nouns list, and it is not a typo.
    - **Greek lexicon:** the LibreOffice Hunspell `el_GR` dictionary, tri-licensed MPL 1.1/GPL 2/LGPL 2.1 (we take MPL).
      - Expanded offline with the test-scope `HunspellAffixes` (not `unmunch`) into all forms, folded, and stored as `config/lexicon/el_common.txt`.
      - Only lowercase entries count as common words.
      - Capitalised entries, minus the name gazetteer, become `known_proper_nouns.txt`: cities, countries, institutions. These are preserved.
    - **English lexicon:** a permissively licensed English word list (SCOWL `en_US` word list, size 60 — the default spell-check size), stored as `config/lexicon/en_common.txt`.
    - **Typo rule:** a Greek-script token of 6 to 30 characters that is one edit away from a Greek lexicon word (a substitution, an insertion, a deletion or an adjacent swap) counts as a typo and is kept. This does not apply after a name cue or when the token has a surname ending.
    - Pure digits and punctuation are handled by the ID detectors, not here.
  - **Cues still matter:** "με λένε", "ονομάζομαι", "είμαι ο/η", "κ./κύριε/κυρία", "εκ μέρους", "υπογραφή".
    - After a cue, the next tokens (up to 3, not counting initials) are masked while each is capitalised, a known name, or not an ordinary word. The cue list in the code is longer: see "How the name detector decides".
  - **Surname endings** (`SURNAME_ENDING`: -όπουλος/-οπούλου/-όπουλο, -άκης/-άκη, -ίδης/-ίδη/-ίδου, -ιάδης/-ιάδη, -άδης/-άδη, -ογλου, -έλλης, -ιώτης/-ιώτη, -ούδης/-ούδη, -αίος/-αίου) mark a surname when the word is not an ordinary word, and also when it is a place-list entry. A capitalised or all-caps ordinary word counts only with a strong ending (-όπουλος/-οπούλου/-όπουλο, -ιάδης/-ιάδη, -ογλου), so "Ιδιώτης" or "Περιφερειακή" are kept; "-οειδής" adjectives and "είδη" are excepted. A lowercase ordinary word with such an ending is not masked by this rule.
  - **Memory:** the lexicons are large (0.9M folded forms in total as shipped).
    - Load them into a compact sorted structure rather than a `HashSet<String>`.
    - Check the result against the existing heap budget (R-1) in a test.
- **`NerDetector`:** interface `List<Span> detect(TextUnit)`.
  - The default is `NerDetector.NONE`, which finds nothing.
  - It is selected by the `config/chat/chat.yaml` key `ner.enabled: false` (+ `ner.provider`), so an ONNX GREEK-BERT or a gr-nlp-toolkit sidecar adapter can be added later without changing the design.
  - In v1 we ship only the interface, the no-op, the config keys, and the failure-to-`needs-review` path, tested with a stub detector.
  - The NER results only add spans. The ONNX and HTTP adapters themselves come later, once a model is chosen.
- **List build tool**, `tools/build-lists`. It runs at dev time, never at runtime.
  - Pulls Wikidata names via SPARQL: `P31 ∈ {Q12308941, Q11879590}` with a Greek `P1705` label; family names (`P734`) of people with `P27 = Q41`.
  - Applies the inflection rules.
  - Expands Hunspell `el_GR` and `en_US`.
  - Computes the stoplist and `known_proper_nouns`.
  - Writes `config/gazetteer/*` and `config/lexicon/*`.
  - The generated files are committed, together with a README recording each source, its licence, and the date it was fetched.
  - The hand-kept `slang.txt` and `domain_allowlist.txt` start small and grow as masked output is reviewed.
- **Out of scope for v1:** a Wiktionary surname list (the user judged it overkill), Greeklish, date of birth (added on 2026-10-14: Implementation notes 21), and phone numbers spelled in words.

### Testing (TDD, JUnit as in the repo)
- **Unit tests:**
  - `GreekFoldTest`
  - `ChatDetectorsTest`: per pattern, positives and look-alike negatives.
  - `GreekNameDetectorTest`: inflections, cues, stoplist, propagation, and uncommon-word masking. It also checks that typos, English words and allowlisted terms are kept.
  - `LexiconTest`: memory bound and lookup.
  - `ChatPipelineTest`
- **`ApiHandlerTest` cases for `/anonymize-text`:**
  - auth, 415, size cap, deadline, header contract
  - no text in log lines
- **Gold set: `eval/chat-anonymization/`. Already created** (2026-10-12): 120 entries (100 first, T101-T118 after the final review, T119-T120 on 2026-10-14), checksum-valid IDs, extreme cases (Πλατεία Αμερικής, Πλάκα, Σύνταγμα, Νίκη…), and word-vs-PII pairs.
  - The format and scoring rules are in its README.
  - `validate_dataset.py` was ported to the JUnit `ChatDatasetTest`, so the repo stays Java-only; the Python file is gone.
- **`ChatEvalTest`: three-mode comparison.**
  - Runs `ChatPipeline` over the dataset in three modes, chosen by the `rulesEnabled` flag of the `ChatPipeline` constructor and by the `NerDetector` passed to it (there are no config switches for this):
    - `rules`: regex + lists + lexicon.
    - `ner`: model only.
    - `both`: production.
  - Scores every mode with the same metrics: leak rate (primary), recall per type and group, over-mask rate, character precision.
  - Writes one report per mode to `target/chat-eval/<mode>.md` (Implementation notes 6). A diff of the entries whose outcome changes between modes is planned and not written yet.
  - **Gate:** the `rules` leak and over-mask counts must not exceed the pinned `MAX_RULES_LEAKS` and `MAX_RULES_OVER_MASKS`. A gate for `both` is added when a model exists; the `ner` mode is report-only.
  - When no model is configured, the `ner` and `both` modes are skipped with a clear message.
  - **User decision (2026-10-12):** run the `rules` mode only for now. The `ner` and `both` modes are wired and tested with a stub detector, and switch on once a model exists: gr-nlp-toolkit cleared by legal, or a fine-tuned GREEK-BERT.
  - Real labelled turns go into the same folder later.

## Verification
- `mvn -B verify` passes: the existing tests plus the new ones.
- Run `RunAnonymizer`/`ApiServer` locally and send a request:
  `curl -H "Authorization: Bearer …" -H "Content-Type: text/plain; charset=utf-8" --data-binary "Καλησπέρα, με λένε Γιώργο Παπαδόπουλο, ΑΦΜ 090000045, μένω Πατησίων 25" :8000/anonymize-text`
  - Expect the name and AFM to come back as dots, the address "Πατησίων 25" to stay (Implementation notes 22), and `x-anonymization-status: anonymized`.
- `ChatEvalTest` prints the recall/precision table, which is the baseline for comparing a future NER plug-in.

## Implementation notes (2026-10-12)

1. **Union instead of `Resolver`.** `Resolver.priority` drops any REDACT span below `redact_threshold` (0.7). An AFM that fails its checksum is proposed at 0.4. In the `.docx` flow, pass 2 adjudicates such spans; in chat there is no LLM, so the Resolver would let them leak. Chat therefore masks the union of every REDACT and REVIEW span. PRESERVE spans (public email domains) are dropped.
2. **Settings live in `config/chat/chat.yaml`, not `policy.yaml`.** `policy.yaml` is validated strictly and is part of the `.docx` provenance hash. For the same reason, chat regexes are code constants and are not overridable through `regex_patterns.yaml` (`Config.validatePatterns` only knows `DetectorPatterns.DEFAULT_PATTERNS`).
3. **`GreekFold` is length-preserving.** Each code point is folded on its own, so a folded offset is the original offset. No offset map is needed.
4. **The "names that are also common words" stoplist is computed at lookup time** (`isName && isCommonWord`) rather than written as a file.
5. **Package:** `dev.filtsiap.ded.anonymizer.chat`, mirroring `…anonymizer.llm`.
6. **Eval reports go to `target/chat-eval/`** (build output), not into the source tree.
7. **The list builder is Java, in test scope** (`src/test/java/…/chat/build/`), so the repo stays Java-only and the builder is unit-tested.
8. **Name lists also include the given names of Greek citizens** (Wikidata P735 of people with P27 = Q41, Greek label), merged with the P1705 query. Without them, common names such as Μαρία and Μιχάλης were missing and would have counted as "known places". Name forms containing letters outside α-ω (such as ϑ and ϰ in Wikidata labels) are dropped.
9. **Chat ID patterns differ from the plan text:**
   - Whitespace after the ID-card, ΓΕΜΗ and customer-number cues is bounded (`{0,8}`), so a long run of spaces cannot cause quadratic backtracking.
   - Cards and AFM/AMKA fall back to the longest checksum-valid prefix of a longer digit run, so "4111 1111 1111 1111 12/26" still masks the card.
   - Card spans are computed first; digit groups that overlap a card are skipped.
   - An obfuscated email no longer takes in the word after a sentence-ending email.
   - The postal-code cue has bounded whitespace too.
10. **Address detector** (removed on 2026-10-14, note 22):
    - The third-person "δουλεύει" is not a residence/work cue. Support chats say "δεν δουλεύει το …" ("… doesn't work").
    - A residence cue nested inside an earlier cue's clause is skipped only when it also ends inside that clause.
11. **Name detector:**
    - The neighbour rule runs as a linear worklist.
    - The "I'm" cue accepts the curly apostrophe (’).
    - A token captured after a cue is propagated to its other forms only if it is a known name or not a common word.
12. **`PyRegex.finditer` and `sub` are linear in the number of matches.** This is shared with the `.docx` path, and the offsets are unchanged. Before, every match re-scanned the whole text to convert offsets.
13. **Baseline on the 120-entry dataset (rules only, NER off; 100 first entries from 2026-10-12, T101-T118 added after the final review on 2026-10-13, T119-T120 on 2026-10-14; unchanged by the fixes of note 16; labels and counts updated 2026-10-14, notes 17, 18, 21 and 22):**
    - 3 / 99 must-mask items leak: T090 (phone spelled in words), T095 ("Maria" in English text without a cue) and T096 (the "ΟΕ" of a family business, masked until note 22 only by the work-cue place rule). T094 (date of birth) leaked until the rule of note 21. Before note 22 it was 2 / 131: the 32 ADDRESS, POSTAL_CODE and LOCATION items are now `may_mask`.
    - 2 / 98 must-keep items are over-masked: T036 and T047, where the lowercase noun shares a confirmed name's form.
    - Character precision is 98.4% (98.7% before note 22).
    - The first 100 entries alone gave 3 / 104 and 2 / 83 (measured 3 / 106 and 2 / 82 after the 2026-10-14 label decisions, before note 22). Run on the code before the fix wave, T101-T118 gave 21 / 125 leaks (18 new), so they do test what they were written for.
14. **Final-review fix wave:**
    - **Surname endings override the place list.** A match of `SURNAME_ENDING` marks a surname even when the token is an `el_proper` entry, and also when it is an ordinary word if it is capitalised or all caps (narrowed to strong endings in note 16). "-οειδής" adjectives and "είδη" are excepted. The token is confident, so its other forms are masked across the text. About 700 common surnames used to be kept as places.
    - **Tokens are runs of letters in any script**, with combining marks, and format characters (soft hyphen, ZWSP, ZWNJ/ZWJ) between two letters. The format characters are dropped from the folded lookup form only; masking covers the original code points. Cyrillic, Latin Extended and polytonic names are found.
    - **Lowercase addresses** (removed on 2026-10-14, note 22). `AddressDetector` took `ChatLists`. A street keyword (οδός, λεωφ., πλατεία…) in any case followed by 1-3 words and a house number is an ADDRESS. After a residence cue, the next 1-3 words that are place-list entries or not ordinary words are a LOCATION (an ADDRESS with a house number). A postal code right before or after an address is a POSTAL_CODE.
    - **Cards, AFM and AMKA at any group start.** A run of digit groups is checked at every group boundary (cards 19 to 13 digits, then AFM 9 / AMKA 11), longest first, so "κάρτα 1 4111 1111 1111 1111" and "cvv 123 4111 …" no longer leak. This replaces the prefix-only fallback of item 9. The scan is hand-written and linear.
    - **Spaced emails** ("maria.k @ gmail.com", "nick @ yahoo . gr") are masked again. The match must end in a TLD-shaped last label (2 to 6 Latin letters), so a Greek word after the sentence's full stop is not taken in; a following Latin word may be over-masked.
    - **Bounded runs.** Capitalised runs take at most 8 words per match and the bank-name and beneficiary patterns of the `.docx` flow take at most 31, so a 400k-character input of capitalised words no longer overflows the stack (it was a deterministic 500). No chat pattern repeats a group without a bound.
    - **Shutdown.** `/anonymize-text` handles a shutdown the way `/anonymize` does: a 503 whose body is `{"detail": ...}` only; the log line carries `error_code=SHUTTING_DOWN` and `outcome=cancelled`.
    - **Licences.** `config/chat/README.md` no longer says the dictionaries are not distributed; `config/chat/NOTICE.md` names each source, its licence and the author or copyright holder the upstream README gives, the upstream READMEs are stored in `config/chat/licenses/`, and `lists.properties` records the upstream commit and no longer carries a timestamp.
    - Latin look-alike letters are accepted in plates ("IKY-1234").
15. **Names as built** (the Core and Testing sections above keep the design-time names).
    - Package `dev.filtsiap.ded.anonymizer.chat`: `ChatPipeline.anonymize(String, Deadline)` returns `TextResult(masked, status, counts, reviewReasons)`. The detectors are `IdDetector` (the reused `.docx` detectors plus the chat ID shapes, in place of `ChatDetectors` and `ChatDetectorPatterns`), `BirthDateDetector` (note 21) and `NameDetector` (in place of `GreekNameDetector`). `NerDetector.NONE` is the no-op (there is no `NoopNerDetector`). Also `Masker`, `ResidualCheck`, `GreekFold`, `GreekInflection` and `WordSet` (compact sorted word lists).
    - Lists are in `config/chat/`: `given_names.txt`, `surnames.txt`, `el_common.txt.gz`, `el_proper.txt.gz` (in place of `known_proper_nouns.txt`), `en_common.txt.gz`, `slang.txt`, `domain_allowlist.txt`, `lists.properties` and `chat.yaml`, not `config/gazetteer/*` and `config/lexicon/*`.
    - The list builder is the test-scope `BuildChatLists` with `HunspellAffixes` (not `tools/build-lists` and `unmunch`).
    - Tests: `IdDetectorTest`, `BirthDateDetectorTest`, `NameDetectorTest`, `NameDetectorRealListsTest`, `ChatPipelineTest`, `WordSetTest`, `ChatListsTest`, `ChatDatasetTest`, `ChatEvalTest` and, for the endpoint, `ApiTextEndpointTest`. The route table is `ROUTES` in `ApiHandler`.
16. **Fixes from the owner review (2026-10-13).** The eval is unchanged (3 / 125 leaks, 2 / 97 over-masks); every item has a unit test.
    - A known name next to a confident name is masked whatever its case or position, so a first name that is also a common word is found in "Σοφία Γεωργίου", "ΣΟΦΙΑ ΓΕΩΡΓΙΟΥ" and at the start of a sentence.
    - "Όνομα:", "Επώνυμο:", "Ονοματεπώνυμο:", "Αιτών:", "Αιτούσα:" and "Τον/Την/Τη λένε" are name cues.
    - A capitalised ordinary word is a surname by its ending only with a strong ending (-όπουλος, -ιάδης, -ογλου), so "Ιδιώτης" and "Περιφερειακή" are kept. The weak endings still apply to words that are not ordinary words and to place-list entries.
    - A passport number may have a space or hyphen after its letters. A postal code after the city name ("Συγγρού 100, Αθήνα 17671") is masked; a five-digit number after an address and one word is now read as a code. (The postal-code part was removed by note 22.)
    - (Removed by note 22.) A street typed in all caps ("ΠΑΤΗΣΙΩΝ 25") was an address when the word was a genitive place-list entry. The same street in lowercase without a keyword or cue is not detected: the place list holds ordinary genitives too ("εβδομάδας 2"), and the eval has no negatives to show that it is safe.
    - The digit groups of an IBAN are no longer also reported as a card, and a shutdown-cancelled `/anonymize-text` request is logged at WARN as `/anonymize` does.
    - The domain allowlist has the tax terms ΕΝΦΙΑ, Taxisnet and myDATA, and a few device brands.
17. **Tax-office place and owner label decisions (2026-10-14).** The tax-office rule and the T002 decision were reversed later that day (note 22). The place after a ΔΟΥ, Δ.Ο.Υ. or εφορία cue (1 to 3 words, past an article; capitalised, a place-list entry or not an ordinary word; an ordinal such as "Α'" included) is a LOCATION and the cue word stays; the owner also decided T002 (that place is `must_mask`), T085 (the age "85 χρονών" is `may_mask`) and T088 ("Μανώλης" is `must_mask`). The note numbered 15 in the request is note 17 here because 15 and 16 were already taken.
18. **CVV after its cue (2026-10-14, owner decision).** 3 or 4 digits after cvv, cvc, cv2, cid or "κωδικός ασφαλείας" (optionally "είναι") are masked as CARD (`chat_cvv_cue`) and the cue stays; T114 now lists the CVV as `must_mask`, and `ChatDatasetTest` skips the Luhn check for a CARD item of 4 digits or fewer.
19. **Owner decisions (2026-10-14).** The place rules below were removed later that day (note 22). Places are masked only after a residence, work or tax-office cue, or as a street with a keyword; a street + number with no keyword or cue is intentionally not masked (this closes review item M5); T083's company phone may be masked; T096 is kept as labelled. T119 and T120 pin lowercase and unaccented full names.
20. **POST /anonymize-log (2026-10-14, owner decision).** One chatbot log entry (one JSON object) in; only the string value of the top-level `user_query` is masked, with the unchanged chat rules, and every other byte comes back identical. `LogBody` finds the token range with Jackson's streaming parser and splices the re-encoded masked text into the original string, so numbers, escapes, field order and unknown fields are never re-serialised; a value with nothing masked keeps its original token, even when it is not NFC, and a masked value is written as the pipeline's NFC output with unpaired surrogates escaped. A leading BOM is accepted and kept. A missing or null `user_query` is returned unchanged (`anonymized`, counts `none`); a non-string one is returned unchanged as `needs-review` with `user_query_not_a_string`; a duplicated key masks both values. The body is limited by `ANON_MAX_UPLOAD_BYTES`, each decoded query by `ANON_MAX_TEXT_CHARS`; headers describe the query result only; the `log_finished` line carries sizes, never content. The auth, deadline and logging lifecycle is shared with `/anonymize-text`.
21. **Date of birth (2026-10-14, owner decision).** Out of scope in v1; the owner added it on 2026-10-14. `BirthDateDetector` (wired into `ChatPipeline` after `IdDetector`) masks, as DOB (`chat_dob_cue`), the first date after a birth cue matched on the folded text: γεννήθηκα/γεννήθηκε/γεννηθήκαμε, γεννημένος/γεννημένη/γεννηθείς, ημερομηνία γέννησης, ημ. γέννησης, ημ/νία γέννησης, ημερ. γεν., ημ. γεν., έτος γέννησης, "date of birth", "born on", "born in", DOB, D.O.B. Between the cue and the date are up to 25 characters with no digit, '!', '?', ';' (the Greek question mark) or line break, and no '.' followed by a space and a capital (checked on the original text). The shapes are d/m/yyyy and dd/mm/yy with '/', '-' or '.', yyyy-mm-dd, a day with a Greek or English month name in any form or abbreviation and a 4-digit year ("27 Οκτωβρίου 1984", "27 Οκτ. 1984", "October 27, 1984", "27 Oct 1984"), and a bare year 1900-2099 right after the cue and an optional article ("γεννήθηκα το 1984"). Only the date is masked; a date without a cue (a payment, a deadline) is kept. Every repetition is bounded and a 400k-character input scales linearly (`BirthDateDetectorTest`). T094 no longer leaks (note 13).
22. **No location masking (2026-10-14, owner decision).** The owner decided that location information is not personal data for this service: areas of residence or work, the place of a tax office (ΔΟΥ, εφορία), street addresses (street + number, keyword streets such as οδός/λεωφ., km addresses, all-caps streets) and postal codes all stay visible. `AddressDetector` and `AddressDetectorTest` are deleted, `ChatPipeline` no longer runs it, and `PiiType` loses `LOCATION`, `ADDRESS` and `POSTAL_CODE`, so `x-redaction-counts` never names them. This reverses the T002 decision of note 17 and the place rules of notes 10, 14, 16, 17 and 19. In the dataset, every `must_mask` item of type ADDRESS, POSTAL_CODE or LOCATION (32 items in 21 entries) moved to `may_mask`, with the decision in each entry's note; `must_keep` is unchanged. The name rule may still mask a place incidentally, when it looks like a name ("Αθήνα" is also a given name, "Ζωγράφου" has a surname shape) or is not an ordinary word; the owner accepts that, so nothing special-cases places. Dropping the work-cue rule also unmasked the "ΟΕ" of T096's family-business name, which is now a third leak (note 13); `MAX_RULES_LEAKS` is re-pinned to 3.

23. **Benefit vocabulary and plate-like acronyms (2026-10-15, code review H1 and M2).** The uncommon-word rule masked the benefits chatbot's own vocabulary as names: ΕΚΑΣ, ΟΠΕΚΑ, ΚΕΠΑ, ΑΣΕΠ, myAADE and the unit "τμ" (6 of 16 benefit words in a probe). `config/chat/domain_allowlist.txt` now lists these public bodies, systems and units. Separately, the plate pattern (three look-alike capitals and 3-4 digits) masked "ΚΕΑ 2025" and "ΙΚΑ 2024": `IdDetector` now takes the allowlist (`new IdDetector(rules, lists.allow())`) and skips a plate-shaped match whose three letters are allowlisted. A real plate ("ΙΚΥ-4521") is still masked. The dataset is unchanged and the eval stays at 3 / 99 leaks and 2 / 98 over-masks. Review items M1 (the typo rule lets unlisted names escape) and M3 (the residual re-scan reads hyphenated dates as phone numbers) are not fixed yet.

24. **Dates are not phone numbers in the residual re-scan (2026-10-15, code review M3).** The QA PHONE pattern of the post-check (a leading 2 or 6, then 8 to 14 digits, spaces or hyphens) also matched hyphenated dates whose day is 20 to 29 ("27-10-2024", "2024-10-27"): `ResidualCheck` masked them and set `needs-review`, while the same date with slashes was kept. A PHONE match with fewer than ten digits is now ignored (a date has eight; a Greek phone has ten, twelve with +30). A 9 to 11 digit run is still caught by DIGIT_RUN, so an amount such as "1000000000" is still masked with `needs-review`. Review item M1 (the typo rule) is still open.

25. **Abbreviated Κωνσταντίνος and Κωνσταντίνα (2026-10-15, owner request).** Users write the name as "ΚΩΝ/ΝΟΣ" and "ΚΩΝ/ΝΑ". The "/" splits it into two words that no name list can hold ("ΚΩΝ" was kept as an ordinary word and "ΝΑ" is a common word), so a name-list entry could not match; `NameDetector.NAME_ABBREVIATION` matches the whole abbreviation instead (any case ending: -ΝΟΣ, -ΝΟΥ, -ΝΟ, -ΝΕ, -ΝΑ, -ΝΑΣ; optional spaces around the slash; Latin look-alikes accepted) and masks both words letter by letter while the "/" stays visible ("ΚΩΝ/ΝΟΣ" becomes ".../..."). The words are not propagated to other occurrences. The dataset is unchanged: the rule is pinned by unit tests in `NameDetectorRealListsTest`.
27. **Any number after an ID cue is masked (2026-10-27, owner request).** (Numbered 27 because note 26 is taken on `java-app-location-filters`.)
    - **Before:** every ID rule needed an exact shape and checksum. A cue only raised the confidence, so a wrong-length number after its cue leaked with status `anonymized`: «με αφμ 1212121», «ΑΜΚΑ 123456», «τηλ 69123456», the digits of «ΑΔΤ ΑΚ 12345». A 10-digit «ΑΜΚΑ 1989992121» was caught only by the residual DIGIT_RUN, so it got `needs-review`.
    - **The rule:** `IdDetector.CUED_NUMBER` has one pattern per type on the folded text, and masks the next number of any length after an ID's name.
      - Cues: ΑΦΜ, ΑΜΚΑ, ΑΔΤ/ταυτότητα, διαβατήριο, τηλ/τηλέφωνο/κινητό, IBAN, and their Latin forms.
      - Between the cue and the number there may be up to 25 characters with no digit and no line break.
      - The number may be digit groups joined by single spaces, '.', '-' or '/', with at most 32 groups, because `java.util.regex` recurses once per repeated group.
      - Also masked with the number: one or two letters before it for an id card or passport, a '+' for a phone, and a country code for an IBAN. The letters count only when typed in capitals («ΑΚ 12345»); in lowercase they are usually a word («η ταυτότητα λήγει το 2030», where only «2030» is masked), so the span starts at the digits.
      - The cue word stays visible.
      - A cue word must not be followed by a letter, so «τηλεόραση», «τηλεφωνικό κέντρο» and «κινητικότητα» are not cues.
    - **Which rule's span is used:** if another rule already found the number, its span is kept, so «ΑΦΜ 090000045 12 ετών» still leaves «12» visible. When two cues precede one number, the nearer cue names it.
    - **Accepted, owner's spec ("any length", recall first):** a number that is not an ID is masked when it follows a cue word («τηλ. στις 10:30» masks «10»). Numbers without a cue are unchanged.
    - **Eval and tests:** the eval is unchanged (3 / 99 leaks, 2 / 98 over-masks, 98.4 % precision). The rule is pinned by unit tests in `IdDetectorTest`, `ChatPipelineTest`, `ApiTextEndpointTest` and `ApiLogEndpointTest`.
    - **Found while testing, fixed on `java-app-bounded-prefixes` (merged here):** the shared .docx AFM prefix `\s*[:.]?\s*` backtracked quadratically, so «αφμ» followed by 200,000 spaces took more than 2 s. That prefix and the 23 other label patterns of the same shape now read `\s*(?:[:.]\s*)?`, which matches the same text in linear time. `RegexBacktrackingTest` rejects the shape anywhere in `src/main/java` and `config`, and `IdDetectorTest.aCuedNumberOfAnyShapeStaysFast` now uses real spaces.
