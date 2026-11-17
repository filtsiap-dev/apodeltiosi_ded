# Chat anonymization test set

These are 120 synthetic Greek and English chat messages for measuring how well `/anonymize-text` masks personal data. Every name, ID, phone number and address here is invented, apart from public figures, streets and places (T053, T054, T074). The structured IDs (AFM, AMKA, IBAN, card) are generated so that they **pass their checksums**. That way they look real to the validators, and a miss is a genuine miss.

## Files

| File | What it is |
|---|---|
| `dataset.jsonl` | The 120 entries, one JSON object per line |
| `ChatDatasetTest` (JUnit) | Checks the dataset itself: every snippet occurs, keeps never overlap masks, IDs pass their checksums |
| `ChatEvalTest` (JUnit) | Scores the anonymiser; reports go to `target/chat-eval/<mode>.md` |

## Entry format

```json
{"id":"T051","group":"locations_tricky",
 "text":"Μένω στην Πλάκα, πάνω από ένα καφέ.",
 "must_mask":[],
 "must_keep":["καφέ"],
 "may_mask":["Πλάκα"],
 "note":"Neighbourhood = common word ('slab', 'joke'). Location information ... (owner decision 2026-10-14)."}
```

- **`must_mask`:** personal data. **Every occurrence** of `text` in the message must be fully masked. Matching is case-sensitive, so `Άγγελος` and `άγγελος` are different strings.
- **`must_keep`:** words that look risky but are not personal. If any character of them is masked, that counts as over-masking.
- **`may_mask`:** borderline cases. They are not scored either way. Examples: any place or address, a public figure, the company's own phone number.

## Groups

| Group | # | What it tests |
|---|---|---|
| `ids` | 26 | AFM, AMKA, IBAN, phones, emails (also spaced), ID card, passport, plates (also Latin-typed), card or AFM after another number, ΓΕΜΗ, supply numbers, in many formats |
| `names_typical` | 10 | Ordinary Greek names with cues and inflections |
| `names_tricky` | 26 | Names that are also words (Νίκη, Ελπίδα, Σοφία, Ψαράς), lowercase or unaccented, all caps, typos, rare or foreign names, surnames found by their ending, Cyrillic, Latin Extended and polytonic names. Each "word" case is paired with a "name" case |
| `locations_tricky` | 22 | Πλατεία Αμερικής, Πλάκα, Σύνταγμα, Περιστέρι, Δάφνη, Νίκαια…, each paired with a sentence where the same words are *not* personal; lowercase addresses and places. Since 2026-10-14 the places and addresses are `may_mask`, so this group now scores the `must_keep` side only |
| `overmask_traps` | 14 | Months, amounts, dates, product names, public bodies, saints' days, error codes. Nothing should be masked |
| `multi_turn` | 10 | `Χρήστης:` / `Bot:` transcripts: the bot echoes names, labels and values sit in different turns |
| `format_extremes` | 8 | Spaced-out digits, phone spelled in words, no spaces, emoji, hyphenated surnames, English text, family business names |
| `controls` | 4 | No personal data at all |

### Labelling rules
- **Locations are not personal data here** (owner decision 2026-10-14). Areas of residence, origin or work, the place of a tax office ("ΔΟΥ Κηφισιάς", T002), street addresses (street + number, keyword streets, km addresses) and postal codes are `may_mask`: the service does not mask them, and they are not scored. The owner first labelled areas and street addresses personal (`must_mask`); every ADDRESS, POSTAL_CODE and LOCATION item moved to `may_mask` on 2026-10-14, with the decision in each entry's note. The name rule may still mask a place that looks like a name ("Αθήνα", "Ζωγράφου") or is not an ordinary word, which is why they are `may_mask` and not `must_keep`.
  - The same place mentioned with no link to a person (e.g. "do you have a shop in Πλατεία Αμερικής?") stays `must_keep`, and so do the cue words ("ΔΟΥ", "μένω"). A floor is `may_mask` (T084).
- **Employees' names** (the agent the user spoke to) are personal data, so `must_mask`.
- **A business named after its owners** (T096) is `ORG_PERSONAL`: the owners' names are personal, so the whole name is `must_mask`.
- **A ΓΕΜΗ number** (T020) is a business-registry identifier; it counts as personal because it can identify a sole trader.
- **Historical or public figures** in a general statement are `may_mask`.
- **Partial card digits and expiry** are `may_mask`. On their own they don't identify anyone.
- **Date of birth** (T094) is `must_mask`. It was out of v1 scope and showed the gap until the owner added the date-of-birth rule on 2026-10-14; rules now catch it.

## Scoring (the same for every mode)

| Metric | Definition | Why it matters |
|---|---|---|
| **Leak rate** | Share of `must_mask` items with at least one character left unmasked | **Legal metric: the main one.** One leaked character of a name is a leak. |
| Recall | 1 − leak rate, reported per type and per group | Where the gaps are |
| Over-mask rate | Share of `must_keep` items with any character masked | Analytics value lost |
| Character precision | Masked characters inside `must_mask` ∪ `may_mask` ÷ all masked characters | How much extra text is masked |

Only **letters and digits** inside a `must_mask` item must be masked: spaces, hyphens and dots
(`6 9 1 2…`, `Παπαδάκης-Ντόκου`, `Μ.`) may stay.

## Three modes to compare

The same scorer runs over the same 120 entries three times. Only the detectors that are switched on differ:

| Mode | Detectors on | Answers the question |
|---|---|---|
| `rules` | Regexes + name list + uncommon-word lexicon + cues + propagation | How far do rules alone get? |
| `ner` | The NER model only (no regex, no lists) | What does the model add, and what does it miss alone (likely: every structured ID)? |
| `both` | Everything (the production setup): NER can only add masks | Is the combination worth it? |

The output is one table per mode (leak rate, recall per type and group, over-mask rate, precision). A **diff list** is planned: entries that leak in `rules` but are caught in `both`, and entries over-masked only when NER is on. `ChatEvalTest` does not write it yet; it currently writes one report per mode. That diff is what will justify, or reject, switching NER on.

**Baseline (2026-10-14, rules only, 120 entries, after locations stopped being masked).** 3 / 99 must-mask items leak: T090 (phone spelled in words), T095 ("Maria" in English text without a cue) and T096 (the "ΟΕ" of the family-business name, which only the removed work-cue place rule masked). Before that change it was 2 / 131: the 32 ADDRESS, POSTAL_CODE and LOCATION items are now `may_mask`. T094 (date of birth) is caught since the date-of-birth rule (owner decision 2026-10-14). 2 / 98 must-keep items are over-masked: T036 and T047 (a lowercase noun with the same form as a confirmed name in the same message). Character precision is 98.4% (98.7% before). The CVV after its cue (T114) is caught by rules. T032 and T048 (names that are common words) and T013 (obfuscated email) are caught.

T101 to T118 were added after the final review, one or more per fix: surnames found by their ending, names in Cyrillic, Latin Extended and polytonic letters, lowercase addresses and places, a card or AFM after another number, spaced emails, a Latin-typed plate, and one negative ("η πλατεία ήταν γεμάτη κόσμο χθες"). On the code before that fix wave they gave 21 / 125 leaks; the first 100 entries alone are unchanged at 3 / 104 and 2 / 83 (measured 3 / 106 and 2 / 82 on 2026-10-14, after the owner's label decisions on T002, T085 and T088). T119 and T120 (2026-10-14) pin lowercase and unaccented full names; rules catch both. T001 to T100 are never edited except for owner label decisions: append new entries.

## Running it

    mvn -q -Dtest="ChatDatasetTest,ChatEvalTest" test

The `rules` report is written to `target/chat-eval/rules.md`. `ChatEvalTest` fails the build if:
- any AFM, AMKA, IBAN, card, ID card, passport, plate, ΓΕΜΗ or email leaks; or
- the leak or over-mask count rises above the pinned baseline.

The `ner` and `both` modes are skipped until a NER model is configured in
`ChatEvalTest.configuredNer()`.
