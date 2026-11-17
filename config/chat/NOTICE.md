# Third-party notices for config/chat

The word lists in this directory are derived from the sources below. The derived lists are shipped
in the Docker image. The upstream README files that carry each licence text are stored verbatim in
[`licenses/`](licenses/); the commit of the upstream repository they were taken from is recorded in
`lists.properties` (`source.dictionaries_commit`, `source.dictionaries_commit_date`).

## el_GR Greek dictionary (Hunspell), version 0.9

- Used for: `el_common.txt.gz`, `el_proper.txt.gz` (every affix form, folded; the capitalised
  entries minus the two name lists).
- Upstream: LibreOffice dictionaries, `el_GR/` (https://github.com/LibreOffice/dictionaries). Home
  page named in its README: http://elspell.math.upatras.gr
- Author and contact named in the README: Steve Stavropoulos (the README states no copyright line);
  it thanks Γιώργος Γέγος and Nick Demou for words, and credits the older v.003 dictionary by
  Evripidis Papakostas, based on the ispell Greek word list.
- Licence: tri-licence MPL 1.1 / GPL 2.0 / LGPL 2.1. **We use it under MPL 1.1.** Notice and licence
  statement: `licenses/README_el_GR.txt`, fetched verbatim from
  https://raw.githubusercontent.com/LibreOffice/dictionaries/master/el_GR/README_el_GR.txt. The
  file was UTF-8 as published, so it is stored as downloaded (no conversion).

## en_US English dictionary (Hunspell, derived from SCOWL)

- Used for: `en_common.txt.gz` (every affix form, folded).
- Upstream: LibreOffice dictionaries, `en/` (https://github.com/LibreOffice/dictionaries), which
  take it from SCOWL, http://wordlist.sourceforge.net
- Copyright holder: Kevin Atkinson and the contributors named in the README (2000-2018), plus the
  third-party notices it lists (among them Ispell, BSD, and a WordNet inflections database from
  Princeton University).
- Licence: the permissive SCOWL licence: copies may be used and distributed if the copyright notice
  and the permission notice come with them. Full text: `licenses/README_en_US.txt`, fetched verbatim
  from https://raw.githubusercontent.com/LibreOffice/dictionaries/master/en/README_en_US.txt (UTF-8
  as published, stored unchanged). Version stated in the README: 2020.12.07.

## Wikidata

- Used for: `given_names.txt`, `surnames.txt` (labels of given names and family names of Greek
  citizens, expanded with Greek case endings).
- Upstream: https://www.wikidata.org, via the SPARQL queries recorded in `lists.properties`.
- Licence: CC0 1.0 (public domain dedication). No notice is required.

## Our own lists

`slang.txt`, `domain_allowlist.txt` and `chat.yaml` are ours.

## Which upstream commit

`source.dictionaries_commit` is the head of the upstream `master` branch when the licence files
and the commit were fetched (2026-10-13). The lists were built from dictionary files downloaded on
2026-10-12 at about 12:00 UTC, nearly an hour before that head commit was made (12:58 UTC the same
day). The head commit only adds the Ligurian (lij_IT) dictionary and touches no `el_GR` or `en`
file, so that commit left the el_GR and en_US files unchanged. An upstream commit made between
the download and the head commit cannot be excluded without downloading the dictionaries again.
