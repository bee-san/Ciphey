# Plaintext detection

How Ciphey decides that a candidate is the plaintext, how to measure it, and where it
still goes wrong.

A search asks the checkers about tens of thousands of candidates per second: every output
of every decoder at every node. Almost all of them are junk. A false positive ends the
search on junk; a miss lets it run on, often until a false positive or the timeout. So
detection has to reject nearly everything, accept the plaintext, and do both in a few
microseconds.

## Where detection happens

1. **The input** (`check_if_input_text_is_plaintext` in `src/lib.rs`): Athena at Medium
   sensitivity. If the input already is plaintext Ciphey returns it unchanged ("Your input
   text is the plaintext"). A flag without a flag word in its prefix (`SEKAI{...}`) isn't
   taken: input shaped like that is more likely a Caesar shift of a flag.
2. **A cached answer** (`cached_result`): checked again by the current checkers (and the
   human checker), and forgotten if it fails.
3. **Decoders**: every decoder's `crack()` asks its checker, Athena, about its output, at the
   decoder's sensitivity (see [Sensitivity](#sensitivity)). Ciphers with many keys rank
   their candidates first and only ask about the best ones (see [Decoder-side
   rules](#decoder-side-rules)).
4. **The A\* search** (`src/searchers/astar.rs`): candidates a decoder's checker accepted
   become result nodes. When several turn up in one step, they are ordered by
   `result_confidence` (strict English hits and format hits first, then cheaper paths;
   results that still tie keep the order of the decoder list in
   `filter_and_get_decoders`, whose comments say why each decoder is where it is), and
   `result_passes_sanity` rejects results no answer could look like: under 3 characters,
   mostly unprintable, under 5% of the input's length, an English hit that is more than a
   third punctuation, or a flag without a flag word when the input was flag-shaped.
5. **The human checker** (`src/checkers/human_checker.rs`) has the last word: Ciphey shows
   the candidate and asks y/N. `-d` (and API mode) turns it off, so the first candidate the
   checkers accept is the answer. A candidate the human rejected is never asked about again.
6. **`--top-results`** runs WaitAthena instead of Athena: the same checkers in the same
   order, without the human checker, recording every accepted candidate until the timeout.

## Athena and WaitAthena

`src/checkers/athena.rs` and `src/checkers/wait_athena.rs` run the checkers in this order
and stop at the first that identifies the text (`identify_plaintext` in
`src/checkers/mod.rs`):

| # | Checker | Accepts | Reported as |
|---|---|---|---|
| | Regex (only with `--regex`) | a match of the crib; nothing else runs | Regex matched: *the crib* |
| 1 | Wordlist (only with a wordlist) | an exact line of the wordlist | Text matches an entry in the provided wordlist |
| 2 | LemmeKnow | known formats (URLs, emails, IPs, keys, …) and CTF flags | the format's name |
| 3 | JSON | a non-empty JSON object or array | JavaScript Object Notation (JSON) |
| 4 | Common passwords | a common password of 5+ characters | Common Password |
| 5 | English | English text, with or without spaces | Words |
| 6 | Code | source code, shell commands, query strings | Source code or shell command |

The order is cheapest and most specific first. English goes before code so that text that
reads as English is reported as words. The sub-checkers are built once, and nothing is
allocated until one of them accepts: almost every text is rejected, so the rejection path
is the one that has to be fast.

## The checkers

### LemmeKnow and CTF flags

`src/checkers/lemmeknow_checker.rs`. [LemmeKnow](https://github.com/swanandx/lemmeknow) 0.8
(the Rust port of pyWhat) matches the text against about 130 anchored regexes; those with
a rarity below 0.1, which match by chance (timestamps, `key:value` pairs), are skipped.
Many of the others only check which characters a string has and how long it is, so
decoder junk matches them. Ignored:

- every pattern tagged `Credit Card`, `Phone`, `Bitly`, `Visual Studio` or `Turkish`;
- by name: ASIN, the Bitcoin Cash, Litecoin, Ripple and Dogecoin wallets, the Google
  ReCaptcha key, and two letters followed by a character class of fixed length: Facebook
  Access Token (`EA` and 190+), Twilio Account and Application SIDs (`AC`/`AP` and 32) and
  the AWS Organization ID (`o-` and 10 to 32);
- URLs without `://` or a leading `www.`;
- EC2 instance IDs that aren't `i-` and 8 or 17 lower-case hex digits (the pattern is
  case-insensitive alphanumeric);
- ARNs that don't start with `arn:` and a lower-case partition and service;
- email addresses whose top-level domain isn't one of 112 common ones (`EMAIL_TLDS`), or
  an IP in brackets. A Caesar shift of an address is still shaped like one
  (`uryyb@jbeyq.pbz`);
- any text with a control character other than tab and line breaks: it isn't a format,
  and it is a fifth of what a search checks, so LemmeKnow's regexes are skipped for it;
- LemmeKnow's own flag formats (`flag{.*}`, `thm{.*}` …) with more braces inside, like
  `THM{UyLgUqMJU}LjUkM^U}` from a chain of wrong decoders: a flag has one pair.

LemmeKnow's patterns are ASCII-only, so the checker also identifies a **domain name or
email address with a non-ASCII letter** (`hello.müller.example.com`, `müller@example.com`),
what the Punycode decoder makes of `xn--` labels, if it ends in one of `EMAIL_TLDS`. The
DTMF decoder still takes keys that LemmeKnow's phone number pattern matches for the number
dialled (`18005551234`), with the human checker's agreement.

When LemmeKnow finds nothing, the checker looks for a **CTF flag** in any format,
`^[A-Za-z][A-Za-z0-9_]{1,19}\{[^{}\n]{1,200}\}$` (matched by hand: the regex crate compiles
the bounded repeat into hundreds of states). Caesar shifts, Atbash and Vigenère keep a
flag's shape, so:

- A prefix with a **flag word** (ending in `ctf` or `flag`, starting with `flag`, or `htb`,
  `thm`, `hackthebox`, `tryhackme`) makes any contents a flag: `picoCTF{7e1b9e3a}`.
- A prefix that is a shift or an Atbash of a flag word (`synt`, `uozt`, `cvpbPGS`) is an
  encoded flag, not a flag.
- A prefix without a flag word (`SEKAI`, `dice`, `ENO`) needs contents of letters, digits
  and `_-!?.@$#&+'` that **read as words** once leetspeak is undone (`y0u_f0und_m3`):
  half of their characters in words, one word of three letters or more, and no Caesar
  shift or Atbash of the contents reading better. Without that, wrong ROT47 and railfence
  keys made flag-shaped junk out of digit strings (`wyv{wxwwwyvvyzyvxvy}`) and shifts of
  `SEKAI{y0u_f0und_m3}` were accepted (`NZFVD{t0p_a0piy_h3}`). Such a flag is also not
  taken as the input itself, from Caesar, Atbash or Vigenère, or when the input was
  flag-shaped (see the A\* sanity check). Use a crib (`-r 'SEKAI\{'`) for flags with hex or
  random contents.

### JSON

`src/checkers/json_checker.rs`: a JSON object or array with at least one entry. Bare
values (`1`, `"x"`, `true`) are valid JSON but say nothing. Caesar, Atbash and Vigenère
don't ask the checkers about their output when their input is JSON: every key would pass.

### Common passwords

`src/checkers/password.rs`: an exact entry of gibberish-or-not's list of 10,714 common
passwords, if it has at least 5 characters (6 for digits only) and 3 different ones. The
list has a thousand four-character entries and hundreds of digit strings and repeated
letters, and wrong keys produce strings like `1130`, `geil` and `tttttttt` all the time.
Text longer than the longest entry (23 bytes) skips the lookup.

### English

`src/checkers/english.rs`. [gibberish-or-not](https://crates.io/crates/gibberish-or-not) 6
decides whether a text is natural language, with or without spaces, and in which
language. A search asks about tens of thousands of short candidates, nearly all of them
junk, and junk that happens to be language (a common word, two short words) is still junk
there, so the checker has rules of its own on top. Each was measured against
gibberish-or-not 6 deciding alone (see [What the English rules
do](#what-the-english-rules-do)); the rules that gibberish-or-not now does better are gone
(normalising the text before asking it, and a quadgram score and word split for text
without spaces).

The text is normalised for the word rules only (gibberish-or-not reads the text as written,
and the result keeps the original): lower case, ASCII punctuation becomes a space except
apostrophes inside words (`don't`), whitespace collapses. Text with a control character
other than tab and line breaks is rejected outright (`hello\u{17}world`). CTF flags and
secrets (16+ letters, digits and `+/=_-` with both letters and digits: passwords, keys,
hashes) between whitespace are left out when the rest has a word (two for a secret), like
numbers: `Well done! Flag: IW{N0_0ne_can_st0p_y0u}`, `The password is
IFukwKGsFW8MOq3IRFqrxE1hxTNEbUPR`. Then:

1. **Decoder output is rejected first** (`looks_like_decoder_output`, one pass):
   - *case*: more than a third of the words, or any of three words or fewer, cased like no
     written word: `hHeREoUtHo`, `baLL`, `NoNeININ`. Ciphers that only change letters keep
     the case of mixed-case input such as Base64. Written words are lower case, upper case,
     capitalised, or capitalised words run together (`GitHub`, `iPhone`, `URLs`);
   - *symbols*: more than a third of the characters are symbols, one of them
     `\^[]{}|~=<>%*+` or a backtick: `!%TOO(NO`;
   - *brackets*: square or curly brackets that don't balance: `[bede 'cab'  'ea`;
   - *NATO code words*: text the NATO phonetic decoder reads as letters
     (`Hotel-Echo-Lima-Lima-Oscar`) is words, but not the plaintext.

   Words of 12+ letters that change case only between runs of two letters or more are
   cased like writing too: alternating-case words run together, `hiTHEREwelcomeTOlinear`.
2. **Space-less letters** (no whitespace, only ASCII, 8+ letters, 90%+ letters), what
   classical ciphers leave plaintext as: gibberish-or-not decides (`MEETMEATNOON`,
   `HELLOWORLD`, not the railfence shuffle `HWORLDELLO`), unless the quadgram score is
   below -6.5 (-7.5 at High).
3. **Text with spaces** whose quadgram score is below -6.5 (-7.5 at High) over 12+ letters
   is far from any language: rejected (wrong Caesar shifts, reversed text).

   With gibberish-or-not 6 these two quadgram vetoes change no verdict on the data set:
   gibberish-or-not and the later rules reject the same texts. They are kept because they
   are much cheaper: gibberish-or-not takes a few microseconds over space-less text, and
   two thirds of the data set's space-less texts score below -6.5.
4. **Mostly words**: two or more words, one of three letters or more, more than 80% of
   them English words, accepted. Numbers don't count either way (`number 1 1 operation`).
   Without spaces the words must be separated by writing's punctuation or `_`
   (`Hello,world!How`, `beware_the_ides_of_march`, not `9=inn@on`), and numbers count
   against.
5. A **single word** must be a dictionary word of 4 to 9 letters, of 5+ letters at Low: one
   in 150 strings of four letters is a dictionary word, and the ciphers that check at Low
   ask about their most English-looking key, so they found `SHAG` and `MEAN` in junk. It
   doesn't label a number with more digits than its letters (`flag = 5093751751…`, Big
   integer's input).
6. **Two words** that aren't both words are rejected (`terces pot`, `peg knioge`).
7. **No English word at all** is rejected, and so are **fewer than half English words**
   (35% at High) unless two different common words of French, German, Spanish, Italian,
   Portuguese or Dutch are in the text (`is_other_language`): reversed text, wrong
   railfence keys and partly decrypted Vigenère are below half; English sentences hardly
   ever are.
8. Everything else goes to gibberish-or-not at the checker's sensitivity.

Text that rules 5 to 7 reject is still accepted if gibberish-or-not finds it is one of the
[other languages](#languages) Ciphey compiles in, and is then reported as `Words (French)`
and so on, in the result, the human checker's prompt and `--top-results`.

A **word** (`is_known_word`) is a word of 1 to 3 letters from `english_short_words.txt`
(`a`, `is`, `me`, `i'm`: gibberish-or-not's word list has many more short "words", 246 of
the 676 strings of two letters such as `bk` and `cx`, which wrong keys make all the time),
a word of 4 or more letters in
gibberish-or-not's English word list, or a word of 10+ letters it doesn't have that splits
into words (`understanding`) or scores -4.6 or better with varied letters
(`decompresses`, not `otstontnottr`).

#### What the English rules do

Each row is the English checker on gibberish-or-not 6 with one rule taken out, the others
as in the first row, measured with `cargo bench --bench plaintext` when Ciphey moved to
gibberish-or-not 6. F1 is Athena's, train / heldout; FP is false positives, train +
heldout; Caesar is `crack()` on the held-out plaintexts.

| taken out | Low F1 (train / heldout) | Low FP | Medium F1 (train / heldout) | Medium FP | Caesar right / wrong (heldout) | |
|---|---|---|---|---|---|---|
| none: every rule (MIGRATION.md's change 2 only) | 0.969 / 0.972 | 30 + 33 | 0.967 / 0.971 | 44 + 46 | 92.4% / 0.4% | baseline |
| normalising the text gibberish-or-not reads | 0.971 / 0.975 | 25 + 24 | 0.971 / 0.975 | 34 + 35 | 92.4% / 0.4% | removed |
| quadgram veto for text with spaces | 0.969 / 0.972 | 30 + 33 | 0.966 / 0.971 | 45 + 46 | 92.4% / 0.4% | kept: with the rules below, no verdict changes, and it is the cheapest reject |
| quadgram score and word split for space-less text | 0.967 / 0.973 | 31 + 30 | 0.963 / 0.972 | 48 + 48 | 92.2% / 0.2% | removed |
| long words (10+) by quadgram score or split, instead of gibberish-or-not's list | 0.969 / 0.972 | 30 + 32 | 0.967 / 0.972 | 43 + 43 | 92.4% / 0.4% | kept with the list (same numbers; the list misses rare words such as `decompresses`) |
| decoder-output vetoes (case, symbols, brackets) | 0.967 / 0.971 | 36 + 35 | 0.963 / 0.970 | 53 + 49 | 92.4% / 0.4% | kept |
| mostly English words: accepted | 0.937 / 0.937 | 29 + 32 | 0.935 / 0.937 | 43 + 45 | 88.2% / 0.4% | kept |
| other text without spaces: one dictionary word only | 0.969 / 0.971 | 31 + 34 | 0.967 / 0.971 | 45 + 47 | 92.4% / 0.4% | kept |
| one or two words: one dictionary word, or rejected | 0.969 / 0.971 | 30 + 34 | 0.967 / 0.973 | 44 + 47 | 92.4% / 0.4% | kept |
| no English word, or too few: rejected | 0.964 / 0.963 | 44 + 60 | 0.946 / 0.950 | 99 + 113 | 92.4% / 0.4% | kept |
| ... unless another language's common words are in it | 0.969 / 0.972 | 30 + 33 | 0.967 / 0.971 | 43 + 46 | 92.4% / 0.4% | kept |
| 1 to 3 letter words from Ciphey's list, not gibberish-or-not's | 0.962 / 0.965 | 49 + 57 | 0.957 / 0.963 | 72 + 77 | 92.4% / 0.4% | kept |
| single words: 5+ letters at Low | 0.971 / 0.974 | 30 + 33 | 0.967 / 0.971 | 44 + 46 | 93.5% / 0.7% | kept (Caesar's wrong answers) |
| single words: 4 to 9 letters | 0.969 / 0.972 | 30 + 33 | 0.968 / 0.974 | 51 + 54 | 92.4% / 0.4% | kept |
| flags and secrets in text left out | 0.969 / 0.972 | 30 + 33 | 0.967 / 0.971 | 44 + 46 | 92.4% / 0.4% | kept |
| control characters | 0.969 / 0.972 | 30 + 33 | 0.967 / 0.971 | 44 + 46 | 92.4% / 0.4% | kept (no sample in the data set) |
| NATO code words | 0.969 / 0.972 | 30 + 33 | 0.967 / 0.971 | 44 + 46 | 92.4% / 0.4% | kept (no sample in the data set) |
| all but control characters and NATO words (gibberish-or-not alone) | 0.972 / 0.976 | 29 + 31 | 0.967 / 0.973 | 50 + 56 | 93.7% / 0.0% | - |

End to end (`--e2e=3`, 296 searches, correct answers; each run is one pass, run-to-run
spread about ±1.5):

| English checker | runs |
|---|---|
| gibberish-or-not 5.0.7 (master) | 269 |
| gibberish-or-not 6, every rule ("none") | 271, 272 |
| without normalising, the spaced quadgram veto, and long words by the list only | 270, 272 |
| ... and without the space-less quadgram score | 273, 272, 274, 274 |
| **the checker**: the same, long words by the list or the old rule | 271, 273 |
| ... without the one-or-two-word rule | 268, 266 |
| ... without the 5+ letters at Low rule | 273, 273 |
| ... without leaving out flags and secrets | 271, 274 |
| ... without the other-language exemption | 271, 273 (#1031's French and German cases lost) |
| single words of any length (4 to 9 letters taken out) | 256, 259 |
| gibberish-or-not alone (all but control characters and NATO words) | 263, 264 |

Other languages (informational, 48 samples) are accepted 25% / 31% / 31% of the time at
Low / Medium / High with the exemption, 10% / 12% / 17% without it (master: 8% / 17% /
21%).

### Code

`src/checkers/code_checker.rs`, after English. Text of printable ASCII whose brackets and
double quotes balance, at least 60% letters, digits and spaces, and with a line that starts
like code:

- a keyword, function call or markup (`import `, `def `, `fn `, `#include `, `console.log(`,
  `SELECT `, `<?php`, `#!/bin/` …), with a bracket, `=`, `;`, `<`, `>`, `|`, `&`, `$`,
  `\`, `"`, `*`, `+` or a backtick somewhere in the text, since many keywords are English
  words (`from the river` isn't code);
- or a common command (`ls`, `curl`, `git`, `nc`, `python3` …) and an argument: an option,
  path, quoted string or variable after a two-letter command (`ls -la`, `cd /tmp`), any
  word after a longer one (`git commit`).

It also accepts **query strings and form data** with two or more fields
(`number_1=1&number_2=0&operation=/`): identifiers of two or more characters as names,
values of letters, digits and `._~:/+,@-` (no `%`, so the still URL-encoded form isn't
taken).

### Regex (crib) and wordlist

`--regex` (`-r`) turns every other checker off: only text matching the crib is accepted,
and the classical ciphers check every key instead of their best-ranked ones, so the crib
picks the key. `--wordlist FILE` accepts exact lines of the file before anything else.

## Sensitivity

gibberish-or-not's `Sensitivity` also selects Ciphey's thresholds (see `docs/sensitivity.md`):

| | Low | Medium | High |
|---|---|---|---|
| Used by | Caesar, ROT47, railfence, Vigenère and the other classical ciphers (Beaufort, Hill, Vigenère Autokey, …) | every other decoder, the input check | nothing in Ciphey |
| gibberish-or-not's minimum calibrated score | 0.9 (strictest) | 0.75 | 0.5 (most lenient) |
| Share of English words needed (3+ words) | 50% | 50% | 35% |
| Letters in a single word | 5+ | 4+ | 4+ |

## Decoder-side rules

The checkers can't tell junk that is shaped like plaintext from plaintext, so the
decoders that make most of it are careful about what they ask:

- **Caesar** ranks its 25 shifts by letter-pair fitness and asks about the best one (after
  any shift giving a flag with a flag word). **ROT47** asks about shift 47 and then the
  best-ranked shift; **railfence** about its best-ranked key. With a crib they ask about
  every key.
- **Vigenère** only tries keys of 3 letters up to a fifth of the text's letters
  (`MIN_LETTERS_PER_KEY_LETTER`): with fewer letters per key letter its key search found
  the right key for 22 of about 4,150 texts in the benchmark and wrong plaintext for 20
  (measured with `--vigenere-keys` before the limit), and on short junk it can make the
  text say almost anything. It
  only asks about candidates with spaces of which 75% of the words are words, or without
  spaces with 85% of their letters in words, because its key search maximises the letter
  statistics the other checks look at. It no longer asks the checker about its own input.
- Caesar, Atbash and Vigenère don't check their output when their input is JSON, and
  don't accept a flag without a flag word.

## Languages

gibberish-or-not has one Cargo feature per language pack, and Ciphey compiles in the ones
it accepts text in (`gibberish-or-not`'s `features` in `Cargo.toml`): English only, as
gibberish-or-not 6.0 ships English only. A pack is added when it is measured here: its
language's recall (the informational `non_english` category, and new categories of that
language) against the false positives it adds on the junk categories and end to end. The
English checker asks the other languages' packs only about text its English rules reject
(rules 5 to 7 above) and about text it leaves to gibberish-or-not, and reports their
language (`Words (Spanish)`).

French, German, Spanish and other Latin-script sentences are partly accepted already:
gibberish-or-not's English pack accepts many of them, labelled English, when the
other-language exemption (rule 7) lets them through.

## The quadgram model

`src/storage/ngrams/` holds the statistics the ciphers and the English checker's long-word
rule use:

- `english_quadgrams.bin`: 26⁴ bytes, one per letter quadgram `AAAA` to `ZZZZ`
  (index `((a·26 + b)·26 + c)·26 + d`). Byte `q` stores log₁₀ P = -q / 25, so 255 is
  -10.2; an unseen quadgram counts 0.01 times. Counted by `generate.py` over the letters
  of 85 public-domain Project Gutenberg books (English originals, mixed registers, no Jane
  Austen), with everything but letters removed and case folded, so quadgrams run across
  word boundaries the way space-less text does.
- `quadgram_score(text)` is the mean log₁₀ probability of the text's letter quadgrams:
  English scores about -4 to -5, other European languages -5 to -6.5, wrong shifts and
  random letters -7 and below. Ciphers rank their keys with it (Pollux, and the quadgram
  tables of Beaufort, Hill and substitution), the English checker scores words of 10+
  letters that aren't in gibberish-or-not's word list with it, and Vigenère's word-ratio
  rule (`has_mostly_words`) skips splitting text that scores below -5.6.
- `english_short_words.txt`: words of 1 to 3 characters from the same books (frequent, in
  20+ books, usually written in lower case, not Roman numerals).
- `english_bigrams.txt` and `bigram_fitness`: letter-pair statistics that Caesar, ROT47,
  railfence and Vigenère rank keys by.

Regenerate with `python3 src/storage/ngrams/generate.py` (it downloads the books once into
`target/gutenberg`); `--bench` writes the benchmark's book sentences instead.

## Configuration

| Key (`~/.ciphey/config.toml`) / flag | Effect on detection |
|---|---|
| `regex` / `-r`, `--regex` | only the crib decides; ciphers check every key; no cache |
| `wordlist_path` / `--wordlist` | exact wordlist lines are accepted first |
| `human_checker_on` / `-d` turns it off | the y/N prompt has the last word |
| `top_results` / `--top-results` | WaitAthena: collect every accepted candidate until the timeout |
| `timeout` / `-c` | how long a search may run when nothing is accepted |
| `api_mode` | no prompts or output (library use) |
| `enhanced_detection`, `model_path` | read and ignored (removed in #1031) |

The `lemmeknow_min_rarity`, `lemmeknow_max_rarity`, `lemmeknow_tags`,
`lemmeknow_exclude_tags` and `lemmeknow_boundaryless` keys are read into the config, but the
LemmeKnow checker uses its own settings (rarity 0.1 and the filters above), so they
currently have no effect.

## The benchmark

`benches/plaintext.rs`, a bench binary without criterion:

```sh
cargo bench --bench plaintext                      # checkers and decoders, both splits (~10 s)
cargo bench --bench plaintext -- --split=train     # one split in detail
cargo bench --bench plaintext -- --e2e             # also whole searches (a few minutes)
cargo bench --bench plaintext -- --e2e-only=5      # only whole searches, 5 s timeout
cargo bench --bench plaintext -- --examples=10     # misclassified samples per category
cargo bench --bench plaintext -- --tsv=after.tsv   # also write every number, for diffs
cargo bench --bench plaintext -- --dump=FILE       # every sample with every verdict
cargo bench --bench plaintext -- --check < FILE    # classify each line (\n, \t escaped)
cargo bench --bench plaintext -- --vigenere-keys   # the Vigenère key-length study
cargo bench --bench plaintext -- --no-captured     # leave out captured.tsv
cargo bench --bench plaintext -- --checkers='^Athena'          # only some checkers
cargo bench --bench plaintext -- --checkers=Athena@Medium --repeat=5  # run checks only
cargo bench --bench plaintext -- --capture=FILE    # re-capture search candidates
```

`cargo bench -- --test` and `cargo test --benches` run a quick smoke check of it.

### The data set

In `benches/data/plaintext/`, all checked in, so runs are comparable:

- `curated.tsv` (`category<TAB>split<TAB>text`): single words, short phrases, sentences in
  several registers (chat, technical, formal and news, CTF messages, verse), paragraphs,
  CTF flags in 35 formats, JSON, code and shell commands, URLs, emails and IPs, pyWhat's
  own examples of the formats LemmeKnow knows, common passwords, and the #1031 harness's
  lists. Also informational categories, reported but left out of every total because
  Ciphey doesn't claim to accept them: other languages, and formats ignored on purpose
  (card and phone numbers, URLs without a scheme).
- `gutenberg.tsv`: 760 sentences and short phrases from five public-domain books, written by
  `generate.py --bench`. The held-out ones (Pride and Prejudice, A Tale of Two Cities, The
  Great Gatsby) are not in the quadgram table's books; the train ones are.
- **Derived near misses**, made when the benchmark starts, the way decoders make them
  (fixed seed): two wrong Caesar shifts, ROT47, Atbash and the reverse of every positive,
  two wrong railfence keys, a wrong Vigenère key and one with its last letter off by one,
  one layer of a random encoding left (Base64, Base32, hex, binary, decimal, octal, URL,
  Morse, A1Z26, HTML entities, Unicode escapes, Base58, Z85), upper-case and space-less
  variants of half the sentences, random strings of many alphabets and mojibake (UTF-8 read
  as Latin-1, UTF-16 read as bytes). Each inherits its source's split.
- `captured.tsv`: texts the A\* search asked Athena about while searching the end-to-end
  corpora (1 s timeout each), which are not the answer: all of those Athena@High accepted
  when they were captured (`search_hard`, 579) and an even sample of the rest
  (`search_random`, 5,146). `--capture` rewrites it by recording Athena's trace log. They
  were captured with the checkers of #1031, so `search_hard` is, by construction, what
  those checkers got wrong: compare versions with `--no-captured` too.
- Formats that look like credentials (API keys, tokens, webhooks) are generated at
  start-up from random characters (`generated_formats`): GitHub's secret scanning blocks
  committed strings in those formats, even pyWhat's published examples.
- `e2e.tsv` (`set<TAB>name<TAB>input<TAB>expected`) and `benches/data/search.toml`: whole
  searches with the answer they should give, `=` for input that already is plaintext and
  `-` for input with no plaintext (any answer is wrong): the #1031 cases, the integration
  tests and README examples, 8 flags under 9 encodings, strings from CTF writeups (the
  validated cases of the closed CTF-corpus PR #848, picoCTF and OverTheWire), and 40
  inputs with no plaintext (digit strings, hex, hashes, random letters, Base64 of random
  bytes, card and phone numbers).

Every sample is in the **train** or the **heldout** split, by source or by a hash of its
text. Tune on train; held-out is the check that a change generalises.

### What it reports

- **Overall**, per checker and split: precision, recall and F1 over every counted sample,
  false positives and their rate. Negatives far outnumber positives, as in a search.
- **Per family** (english, flag, json, code, net, lemmeknow, password): F1 with precision
  and recall, counting the family's own near misses as its negatives.
- **Per category**: recall of each positive category, false-positive rate of each negative
  one, acceptance of the informational ones.
- **Time per check**: median, p99 and mean over samples, for negatives and positives
  separately. Checks under 2 µs are repeated and averaged. On a busy machine, count
  instructions instead: `perf stat -e instructions:u` on `--repeat=5` minus `--repeat=0`,
  divided by five times the number of samples, is the mean cost of one check.
- **What accepted negatives**: false positives by the checker and format that took them.
- **Decoders**: `crack()` with Athena on the data set's plaintexts encrypted with Caesar,
  ROT47, Atbash, railfence and Vigenère: right, wrong plaintext, nothing.
- **End to end** (`--e2e`): `perform_cracking` on every corpus input, as a fresh
  `ciphey -d -c 3` would run it: correct, wrong (stopped on a false positive), input
  returned unchanged, missed; and the time taken. Timings depend on the machine.

The criterion suites (`benches/checkers.rs`, `decoders.rs`, `search.rs`) time the same
code on fixed inputs; compare versions with alternating runs (see `benches/README.md`).

## Current numbers

From `cargo bench --bench plaintext -- --e2e=3` on a shared 64-core Linux host (load 50 to
70), with gibberish-or-not 6.0. Accuracy is deterministic; times depend on the machine.

**Checkers** (2,609 positives and 20,785 negatives; train 1,140 / 9,957, heldout 1,469 / 10,828):

| checker | train: precision / recall / F1 | heldout: precision / recall / F1 | false positives (train + heldout) |
|---|---|---|---|
| Athena@Low | 97.7% / 96.1% / 0.969 | 98.5% / 96.6% / 0.976 | 26 + 21 |
| Athena@Medium | 96.7% / 96.8% / 0.968 | 97.5% / 97.5% / 0.975 | 38 + 37 |
| Athena@High | 94.7% / 97.0% / 0.958 | 95.5% / 97.5% / 0.965 | 62 + 68 |
| English@Medium | 96.8% / 82.9% / 0.893 | 97.7% / 89.8% / 0.936 | 31 + 31 |
| gibberish-or-not@Medium (alone) | 95.6% / 84.8% / 0.899 | 96.3% / 91.1% / 0.936 | 45 + 51 |
| LemmeKnow | 99.2% / 11.3% / 0.203 | 94.2% / 6.7% / 0.125 | 1 + 6 |
| JSON | 100% / 1.9% | 100% / 0.5% | 0 |
| Password | 85.7% / 3.2% | 100% / 1.7% | 6 + 0 |
| Code | 100% / 2.2% | 100% / 1.3% | 0 |

The format checkers' recall is low by design: they only accept their own formats. Athena's
F1 per family at Medium: english 0.979, flag 1.000, json 1.000, code 0.947, net 0.932,
lemmeknow 0.910, password 0.884. Most remaining false positives are partly decrypted
Vigenère (4% of them are accepted at Medium; the Vigenère decoder itself filters them),
wrong railfence keys (0.5%) and reversed common passwords. Other languages are accepted 31%
of the time at Medium.

**Time per check** over all samples (median / p99 / mean, three runs): Athena@Medium
4.6–5.2 µs / 24–29 µs / 5.3–6.0 µs, the English checker 0.84–0.88 µs / 19–21 µs /
1.9–2.1 µs, gibberish-or-not alone 0.8 µs / 18 µs / 1.9 µs, LemmeKnow 2.4 µs / 7.0 µs /
2.7 µs, JSON 21 ns, the password list 26 ns, code 295 ns.

**Decoders** (`crack()` with Athena), held-out split, right / wrong plaintext / nothing:
Caesar 92% / 0.2% / 8%, ROT47 95% / 0% / 5%, Atbash 95% / 0% / 5%, railfence 86% / 0.9%
/ 13%, Vigenère 29% / 0.8% / 70% (its key search, not detection, is the limit).

**End to end** (3 s timeout, six runs: the range):

| set | cases | correct | wrong (false positive) | nothing found |
|---|---|---|---|---|
| regression | 18 | 18 | 0 | 0 |
| search.toml | 113 | 112–113 | 0–1 | 0 |
| issue1031 | 26 | 26 | 0 | 0 |
| flags | 72 | 68 | 3 | 1 |
| ctf | 17 | 16 | 1 | 0 |
| plaintext_input | 10 | 10 | 0 | 0 |
| no_answer | 40 | 20–24 | 16–20 | 0 |
| all | 296 | 271–275 | 20–24 | 1 |

The wrong answers: wrong decoders' output on 16 to 20 of the inputs with no plaintext
(which ones depends on how far a search gets in 3 s), three `SEKAI{...}` flags under shift
ciphers (they need a crib), and picoCTF's `l3arn_th3_r0p35` (leetspeak without a flag around
it). The one missed: `SEKAI{...}` under Caesar.

## Known weaknesses

- **Other languages** are mostly missed: French, German and Spanish sentences pass only
  when gibberish-or-not's English pack takes them (31% of the informational set at Medium),
  until their own packs are measured and compiled in ([Languages](#languages)).
- **Short plaintext** is ambiguous: four-letter words aren't accepted from Caesar, ROT47,
  railfence or Vigenère, single words of three letters (`yes`) never, and a Caesar shift of
  a five-letter word can be another word (`Lorry` and `Fills`).
- **Inputs with no plaintext** still often end on a wrong decoder's output that reads as
  words (`dolenisatirsifmatini`, `sway awed`), mostly from the newer decoders (Keyboard
  shift, Affine, Hill, T9) chained after ROT47 or railfence.
- **Partly decrypted Vigenère** (a key with one wrong letter) is accepted by the English
  checker 4% of the time at Medium; only the Vigenère decoder's own word-ratio rule keeps
  it out of results.
- **Flags without a flag word** whose contents aren't words (`SECCON{7e1b9e3a}`) and any
  such flag under Caesar, ROT13 or Atbash need a crib.
- **Formats**: IPv6, Bitcoin, JWT, dates of birth and social security numbers are among
  the patterns LemmeKnow 0.8 drops because the regex crate can't compile them; and the
  `lemmeknow_*` config keys have no effect.
- **Words**: rare words and names count as unknown unless gibberish-or-not's word list has
  them (`cryptography`) or, for 10+ letters, they score well (`decompresses`): `Ciphey
  rocks` is two words that aren't both words.

## Extending

- **A new checker**: implement `Check` for `Checker<YourChecker>` with an allocation-free
  `identify(text) -> Option<String>`, add a `CheckerTypes` variant and a `CHECKER_MAP`
  entry (cached results name their checker), put it in `identify_plaintext` where its
  specificity and cost fit, and add a `Probe` for it in `benches/plaintext.rs`.
- **More data**: add lines to `curated.tsv` (new categories also need a line in
  `tsv_category`), cases to `e2e.tsv`, or re-capture search candidates with `--capture`
  after changing the corpora. Keep text public domain or your own.
- **Tuning**: change one rule, run `--tsv` before and after and diff the files, look at
  `--examples` on train, and only then check heldout and `--e2e`. `--dump` writes every
  sample's verdicts for analysis outside Rust. A change that moves the criterion search
  benches by more than 5% needs alternating A/B runs and a reason.
