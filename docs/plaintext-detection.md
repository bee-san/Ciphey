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
| 2 | pyWhat | known formats (URLs, emails, IPs, keys, …) and CTF flags | the format's name |
| 3 | JSON | a non-empty JSON object or array | JavaScript Object Notation (JSON) |
| 4 | Common passwords | a common password of 5+ characters | Common Password |
| 5 | English | English text, with or without spaces | Words |
| 6 | Code | source code, shell commands, query strings | Source code or shell command |

The order is cheapest and most specific first. English goes before code so that text that
reads as English is reported as words. The sub-checkers are built once, and nothing is
allocated until one of them accepts: almost every text is rejected, so the rejection path
is the one that has to be fast.

## The checkers

### pyWhat and CTF flags

`src/checkers/pywhat_checker.rs`. [pyWhat](https://github.com/bee-san/pyWhat)'s `pywhat`
crate (6, the Rust port of pyWhat, which replaced LemmeKnow 0.8 in Ciphey 0.13.0) matches
the whole text against pyWhat's 150-odd regexes (`identify_whole`): a format inside a
sentence doesn't count. Regexes with a rarity below 0.1, which match by chance (timestamps,
`key:value` pairs), are not used, and neither are those pyWhat tags **Charset Only**: they
only check which characters a text has and how long it is (more than 1 in 1,000 random
strings of a common alphabet and the right length match them, after their checksum), so
decoder junk matches them: Bitly and Visual Studio keys (any SHA-1), ASINs, Twilio SIDs,
Turkish IDs, the AWS secret key, most card numbers. pyWhat checks the checksums of the
formats that have one (Luhn for card numbers, Base58Check and CashAddr for wallets), so
random Base58 isn't a Bitcoin or Litecoin address any more. On top of that, the checker
ignores:

- every card number (pyWhat's tag `Credit Card`), as before pyWhat: the card formats that
  aren't Charset Only (Maestro, Laser, Switch, Solo, ...) check a prefix, a length and the
  Luhn digit, which 1 in 2,000 to 1 in 20,000 random strings of 14 to 19 digits pass;

- by name: JSON Web Tokens (the JWT decoder decodes them: the payload is the plaintext),
  the Facebook Access Token (`EA` and 190+ letters and digits, which a Vigenère decryption
  of Base64 can be: pyWhat's validator only asks for a lower-case letter, an upper-case
  letter and a digit), the Google ReCaptcha key (`6L` and 38 letters and digits: wrong
  decoders on a SHA-1 hash make those) and the AWS Organization ID (`o-` and 10 to 32
  letters and digits);
- IPv6 addresses that don't parse as addresses or are outside the ranges IANA has
  assigned (global unicast `2000::/3`, unique local, link-local, multicast, NAT64, the
  loopback `::1`, and IPv4 addresses written as IPv6 such as `::ffff:192.0.2.1`): pyWhat
  takes any hex groups with colons, and a port after them without brackets, so decoder
  junk such as `DB:F::E9` and `::9861:13287` (to pyWhat, `::9861` and port 13287), and a
  reversed address, were IPv6 addresses to it;
- UK postcodes that don't start with one of the 124 postcode areas (`UK_POSTCODE_AREAS`):
  a Caesar shift of a postcode is still shaped like one (`TX1B 1BB` is ROT1 of `SW1A
  1AA`). Of the 67 Caesar shifts of pyWhat's seven example postcodes that its regex
  takes, 17 land on an area and stay postcodes (`WA1E 1EE`);
- URLs without `://` or a leading `www.`: pyWhat's URL regex takes bare domains
  (`example.com`). It is also by far pyWhat's slowest regex (18 KB, run by fancy-regex),
  so the checker only runs it on text that has one;
- email addresses whose top-level domain isn't one of 112 common ones (`EMAIL_TLDS`), or
  an IP in brackets. A Caesar shift of an address is still shaped like one
  (`uryyb@jbeyq.pbz`);
- any text with a control character other than tab and line breaks: it isn't a format,
  and it is a fifth of what a search checks, so pyWhat's regexes are skipped for it;
- pyWhat's own flag formats (`flag{.*}`, `thm{.*}` …) with more braces inside, like
  `THM{UyLgUqMJU}LjUkM^U}` from a chain of wrong decoders: a flag has one pair.

pyWhat's email regex is ASCII-only, so the checker also identifies a **domain name or
email address with a non-ASCII letter** (`hello.müller.example.com`, `müller@example.com`),
what the Punycode decoder makes of `xn--` labels, if it ends in one of `EMAIL_TLDS`; the
`pywhat_*` settings of the URL and email regexes apply to them. pyWhat takes phone numbers
written with a `+` and their country code (`+1 202 555 0156`) and North American numbers
written with separators (`202-555-0178`, `(202) 555-0178`), not bare runs of digits. The DTMF
decoder takes the keys of a number dialled on a keypad for a phone number, with the human
checker's agreement, when pyWhat does with a `+` in front (`18005551234`), or when they are
10 to 13 digits that start with a trunk prefix 0 (`07700900123`).

Ciphey uses pywhat without its default features (no file identification, no MAC address
vendors): `cargo tree -e features -i pywhat` shows the features. NOTICE lists pyWhat's data
files that are in Ciphey's binaries, and their licences.

When pyWhat finds nothing, the checker looks for a **CTF flag** in any format,
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

`src/checkers/english.rs`. The text is normalised for the decision only (the result keeps
the original): lower case, ASCII punctuation becomes a space except apostrophes inside
words (`don't`), whitespace collapses. Text with a control character other than tab and
line breaks is rejected outright (`hello\u{17}world`). CTF flags and secrets (16+
letters, digits and `+/=_-` with both letters and digits: passwords, keys, hashes)
between whitespace are left out when the rest has a word (two for a secret), like
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
2. **Space-less letters** (no whitespace, only ASCII, 8+ letters, 90%+ letters), what classical ciphers
   leave plaintext as: a single word (rule 5), or a mean quadgram score of at least -5.1 (Low),
   -5.3 (Medium) or -5.6 (High). Up to 12 letters it must also split into words
   (`HELLOWORLD`, not the railfence shuffle `HWORLDELLO`), unless it has 10+ letters scoring
   -4.4 or better.
3. **Text with spaces** whose quadgram score is below -6.5 (-7.5 at High) over 12+ letters
   is far from any language: rejected (wrong Caesar shifts, reversed text).
4. **Mostly words**: two or more words, one of three letters or more, more than 80% of
   them English words, accepted. Numbers don't count either way (`number 1 1 operation`).
   Without spaces the words must be separated by writing's punctuation or `_`
   (`Hello,world!How`, `beware_the_ides_of_march`, not `9=inn@on`), and numbers count
   against.
5. A **single word** must be a dictionary word, of 5+ letters at Low: one in 150 strings of
   four letters is a dictionary word, and the ciphers that check at Low ask about their
   most English-looking key, so they found `SHAG` and `MEAN` in junk. It doesn't label a
   number with more digits than its letters (`flag = 5093751751…`, Big integer's input).
6. **Two words** that aren't both words are rejected (`terces pot`, `peg knioge`).
7. **No English word at all** is rejected, and so are **fewer than half English words**
   (35% at High) unless two different common words of French, German, Spanish, Italian,
   Portuguese or Dutch are in the text (`is_other_language`): reversed text, wrong
   railfence keys and partly decrypted Vigenère are below half; English sentences hardly
   ever are.
8. Everything else goes to [gibberish-or-not](https://crates.io/crates/gibberish-or-not)'s
   `is_gibberish` at the checker's sensitivity.

A **word** (`is_known_word`) is a word of 1 to 3 letters from `english_short_words.txt`
(`a`, `is`, `me`, `i'm`; gibberish-or-not's dictionary lacks them), a 4 to 9 letter word in
gibberish-or-not's dictionary (it only answers for those lengths), or a word of 10+ letters
that splits into words (`understanding`) or scores -4.6 or better with varied letters
(`congratulations`, not `otstontnottr`).

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

gibberish-or-not's `Sensitivity` (its own docs have Low and High the wrong way round; see
`docs/sensitivity.md`) also selects Ciphey's thresholds:

| | Low | Medium | High |
|---|---|---|---|
| Used by | Caesar, ROT47, railfence, Vigenère and the other classical ciphers (Beaufort, Hill, Vigenère Autokey, …) | every other decoder, the input check | nothing in Ciphey |
| Space-less text, minimum quadgram score | -5.1 | -5.3 | -5.6 |
| Text with spaces, quadgram veto below | -6.5 | -6.5 | -7.5 |
| Share of English words needed (3+ words) | 50% | 50% | 35% |
| Letters in a single word | 5+ | 4+ | 4+ |
| gibberish-or-not threshold | strictest | | most lenient |

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

## The quadgram model

`src/storage/ngrams/` holds the statistics the English checker and the ciphers use:

- `english_quadgrams.bin`: 26⁴ bytes, one per letter quadgram `AAAA` to `ZZZZ`
  (index `((a·26 + b)·26 + c)·26 + d`). Byte `q` stores log₁₀ P = -q / 25, so 255 is
  -10.2; an unseen quadgram counts 0.01 times. Counted by `generate.py` over the letters
  of 85 public-domain Project Gutenberg books (English originals, mixed registers, no Jane
  Austen), with everything but letters removed and case folded, so quadgrams run across
  word boundaries the way space-less text does.
- `quadgram_score(text)` is the mean log₁₀ probability of the text's letter quadgrams:
  English scores about -4 to -5, other European languages -5 to -6.5, wrong shifts and
  random letters -7 and below.
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
| `pywhat_min_rarity` | the pyWhat checker only uses regexes at least this rare (default 0.1; lower values count as 0.1) |
| `pywhat_max_rarity` | ... and at most this rare (default 1; 0 means no maximum) |
| `pywhat_tags` | if not empty, only regexes with one of these tags or names (`["CTF Flag", "IP"]`) |
| `pywhat_exclude_tags` | no regexes with these tags or names; "Charset Only" ones are never used |
| `pywhat_boundaryless` | read and ignored: a format only counts as the whole text |
| `enhanced_detection`, `model_path` | read and ignored (removed in #1031) |

The `pywhat_*` keys can only make the checker stricter than the defaults. Leaving out pyWhat's
"Capture The Flag (CTF) Flag" regex (`pywhat_exclude_tags = ["CTF Flag"]`) also leaves out
the generic flag pattern, which reports under that name, and leaving out "Email Address"
the internationalised addresses. Config files written before 0.13.0 have the same keys
named `lemmeknow_*` (`lemmeknow_min_rarity` ...), with 0 for both rarities: they are read
as the `pywhat_*` keys, so those files keep the defaults.

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
  own examples of the formats it knows (category `lemmeknow`, from before pyWhat replaced
  LemmeKnow), common passwords, and the #1031 harness's
  lists. Also informational categories, reported but left out of every total because
  Ciphey doesn't claim to accept them: other languages, and formats ignored on purpose
  (`lemmeknow_ignored`: the formats LemmeKnow's filters ignored, such as card and phone
  numbers and URLs without a scheme; pyWhat accepts the ones whose checksum or prefix
  makes them more than a character set, such as international phone numbers and wallets
  with a valid checksum).
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
  separately. Checks under 2 µs are repeated and averaged. pyWhat's regexes are compiled
  first (each is compiled the first time a text could match it, and a search compiles them
  all in the background when it starts), so the compiling isn't counted per check. On a busy machine, count
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
70), with pywhat 6. Accuracy is deterministic; times depend on the machine.

**Checkers** (2,609 positives and 20,785 negatives; train 1,140 / 9,957, heldout 1,469 / 10,828):

| checker | train: precision / recall / F1 | heldout: precision / recall / F1 | false positives (train + heldout) |
|---|---|---|---|
| Athena@Low | 92.7% / 97.2% / 0.949 | 93.7% / 95.7% / 0.947 | 87 + 95 |
| Athena@Medium | 91.3% / 97.9% / 0.945 | 91.2% / 96.8% / 0.939 | 107 + 138 |
| Athena@High | 83.9% / 98.0% / 0.904 | 84.5% / 96.9% / 0.903 | 214 + 262 |
| English@Medium | 90.5% / 83.5% / 0.869 | 90.8% / 89.4% / 0.901 | 100 + 133 |
| pyWhat | 99.3% / 11.9% / 0.213 | 95.1% / 6.6% / 0.123 | 1 + 5 |
| JSON | 100% / 1.9% | 100% / 0.5% | 0 |
| Password | 85.7% / 3.2% | 100% / 1.7% | 6 + 0 |
| Code | 100% / 2.2% | 100% / 1.3% | 0 |

The format checkers' recall is low by design: they only accept their own formats. Athena's
F1 per family at Medium: english 0.942, flag 0.993, json 1.000, code 0.958, net 0.972,
lemmeknow (pyWhat's formats) 0.931, password 0.884. Most remaining false positives are partly decrypted
Vigenère (a quarter of them are accepted at Medium; the Vigenère decoder itself filters them), and a
few reversed texts (0.5%) and wrong railfence keys (0.3%). Other languages are accepted
17% of the time at Medium.

**Time per check** over all samples (median / p99 / mean, three runs): Athena@Medium
3.5–3.6 µs / 21–22 µs / 4.2–4.5 µs, the English checker 0.85 µs / 14 µs / 1.7 µs, pyWhat
0.81–0.84 µs / 5.8–5.9 µs / 1.17–1.19 µs (LemmeKnow 0.8 was 2.4–2.5 µs / 6.8–7.2 µs /
2.5–2.6 µs), JSON 24 ns, the password list 28 ns, code 305 ns.

**Decoders** (`crack()` with Athena), held-out split, right / wrong plaintext / nothing:
Caesar 91% / 0.4% / 8%, ROT47 93% / 0.2% / 7%, Atbash 94% / 0% / 6%, railfence 85% / 1.3%
/ 13%, Vigenère 29% / 0% / 71% (its key search, not detection, is the limit).

**End to end** (3 s timeout, five runs: the range):

| set | cases | correct | wrong (false positive) | input returned unchanged | nothing found |
|---|---|---|---|---|---|
| regression | 18 | 18 | 0 | 0 | 0 |
| search.toml | 113 | 113 | 0 | 0 | 0 |
| issue1031 | 26 | 25 | 1 | 0 | 0 |
| flags | 72 | 68 | 2–3 | 0 | 1–2 |
| ctf | 17 | 16 | 1 | 0 | 0 |
| plaintext_input | 10 | 10 | 0 | 0 | 0 |
| no_answer | 40 | 19–22 | 17–20 | 1 | 0 |
| all | 296 | 269–272 | 22–25 | 1 | 1–2 |

The wrong answers: wrong decoders' output on the inputs with no plaintext (which ones
depends on how far a search gets in 3 s), German base64 (`Wir treffen uns morgen am
Bahnhof` isn't found, and a wrong decoding is), `SEKAI{...}` under ROT13, Atbash and
railfence (they need a crib), and picoCTF's `l3arn_th3_r0p35` (leetspeak without a flag
around it). The no-answer input `+1 555 0100 2234` is a phone number to pyWhat, so the
search returns it unchanged. The missed: `SEKAI{...}` under Caesar (and sometimes ROT13).

## Known weaknesses

- **Other languages** are mostly missed: French, German and Spanish sentences pass only
  when gibberish-or-not takes them (17% of the informational set at Medium), and German
  base64 (`Wir treffen uns morgen am Bahnhof`) still finds nothing.
- **Short plaintext** is ambiguous: four-letter words aren't accepted from Caesar, ROT47,
  railfence or Vigenère, single words of three letters (`yes`) never, and a Caesar shift of
  a five-letter word can be another word (`Lorry` and `Fills`).
- **Space-less junk of 12 to 20 letters** from Vigenère and railfence keys on short inputs
  still sometimes reads as words (`seerienbashaneyr`): 5 of the 40 no-answer inputs end on
  junk. The words-in-text rules can't separate it from real space-less text of that
  length.
- **Partly decrypted Vigenère** (a key with one wrong letter) is accepted by the English
  checker a quarter of the time; only the Vigenère decoder's own word-ratio rule keeps it
  out of results.
- **Flags without a flag word** whose contents aren't words (`SECCON{7e1b9e3a}`) and any
  such flag under Caesar, ROT13 or Atbash need a crib.
- **Formats**: a reversed IPv4 address is an IPv4 address (`7.41.01.01`), so the Reverse
  decoder's output can end a search on one.
- **Words**: gibberish-or-not's dictionary only answers for words of 4 to 9 letters, so
  long rare words (`cryptography`) count as unknown unless they score well, and names
  count as unknown.

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
