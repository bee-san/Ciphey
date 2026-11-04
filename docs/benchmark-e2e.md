# End-to-end benchmark

How well and how fast the `ciphey` binary decodes, measured on a frozen corpus, with the same
corpus run through ciphey 0.12.0 (the last release), Python Ciphey 5.14.0 and CyberChef's
Magic. Decoder PRs use its quick subset to show they don't make Ciphey slower or worse
([benches/README.md](../benches/README.md#end-to-end-benchmark-the-check-for-decoder-prs)).

| Path | What |
|---|---|
| [`benches/e2e/run.py`](../benches/e2e/run.py) | the runner: one tool, or two interleaved (A/B); standard library only |
| [`benches/e2e/corpus.py`](../benches/e2e/corpus.py) | generates the corpus from the plaintexts and a fixed seed, `--check`s and `--verify`s it |
| [`benches/data/e2e/corpus-v1.tsv`](../benches/data/e2e/corpus-v1.tsv) | corpus v1, 376 cases (frozen) |
| [`benches/data/e2e/plaintexts.tsv`](../benches/data/e2e/plaintexts.tsv) | the plaintexts, with their sources |
| [`benches/e2e/setup.sh`](../benches/e2e/setup.sh) | installs ciphey 0.12.0, Python Ciphey, CyberChef and the generator's packages, pinned |
| `benches/e2e/python_ciphey.py`, `cyberchef.mjs`, `cyberchef.py` | the Python Ciphey and CyberChef adapters |
| `benches/e2e/verify.py` | `corpus.py --verify`: decodes the corpus again with other implementations |

## Running it

```sh
cargo build --release
python3 benches/e2e/run.py target/release/ciphey                        # every case, ~6 minutes
python3 benches/e2e/run.py --subset quick OLD/ciphey target/release/ciphey   # A/B, ~1 minute
python3 benches/e2e/run.py --category chain --ids '^chain5' target/release/ciphey
benches/e2e/setup.sh                                                    # the other tools, in .tools/
python3 benches/e2e/run.py v0.12.0=.tools/ciphey-0.12.0/bin/ciphey
python3 benches/e2e/run.py python-ciphey:.tools/pyciphey/bin/python
python3 benches/e2e/run.py cyberchef:.tools/node cyberchef-intensive:.tools/node
python3 benches/e2e/run.py --summarize target/e2e/*/results.tsv          # one table from saved runs
```

A tool is `[name=][adapter:]path`, the adapter one of `ciphey` (the default: any ciphey
binary), `python-ciphey` (the Python of a venv with Python Ciphey), `cyberchef` and
`cyberchef-intensive` (a directory with `node_modules/cyberchef`). Every run writes
`results.tsv` (one line per case and tool: status, verdict, seconds, decoder path, answer),
`summary.md` and `meta.json` (versions, sha256 of the binary and the corpus, timeout,
threads, `uptime` before and after) to `target/e2e/<time>/`, or `--out`. It reads and writes
only inside the repository and the temp directory.

## Method

Every run of a case:

* gets a fresh `HOME` with the default `~/.ciphey/config.toml`
  ([`benches/data/config.toml`](../benches/data/config.toml)), so nothing is cached and the
  first-run setup doesn't start;
* is `ciphey -d -c 5 --text=INPUT`: no human checker, a 5 second search timeout (Ciphey's
  default), the input on the command line, stdin from `/dev/null`, `RAYON_NUM_THREADS=4`;
* is killed after 6 seconds of wall-clock time (any tool), and its time is the wall-clock time
  of the whole process.

Cases run one at a time. With two tools, each case runs on both back to back, A first on even
cases and B first on odd ones, so the host's load affects both alike. The A/B report lists
every case whose verdict differs and the geometric mean of the per-case time ratios B/A, with
a 95% confidence interval from Student's t on the log ratios.

**Verdicts.** A case's answer is the text after `The plaintext is:`. It is **correct** if it
equals the expected plaintext after the case's match rule, **wrong** if it doesn't (a false
positive), and **nothing** if the tool found no plaintext or ran out of time. For an input
with no plaintext (`no_answer`) giving up is correct and any answer is wrong, including
"Your input text is the plaintext". The match rules, in the `match` column, are:

| Rule | Compares | Used for |
|---|---|---|
| `exact` | the text, trailing whitespace ignored | most cases |
| `fold` | case-folded, runs of whitespace as one space | encodings that lose case (Morse, Braille, T9, Baudot, ...) |
| `letters` | letters and digits only, case-folded | encodings that also lose spaces (A1Z26, Baconian, Polybius, tap code, Playfair, Hill, ...) |
| `json` | the parsed JSON | JWT payloads |

**Determinism.** Accuracy doesn't depend on the run, except for cases that finish close to the
timeout. `--repeat N`, or an A/B run of a binary against itself, lists every case whose
verdict changed. The baseline's own check is under [Determinism](#determinism).

### The other tools

They run on the same corpus, timeout and machine, and each is reported only on the cases it
is **comparable** on (the `tools` column): the cases whose every layer it has a decoder for.

* **ciphey 0.12.0**, `cargo install ciphey --version 0.12.0 --locked`, run exactly like
  master. Every case.
* **Python Ciphey 5.14.0** (the latest on PyPI, 2021-06-06), on CPython 3.9.25 because
  `cipheycore` has no wheels for later versions. [`python_ciphey.py`](../benches/e2e/python_ciphey.py)
  does what `ciphey -q -t TEXT` does (verbosity below zero turns its human checker off) and
  also prints the decoder path. Its decoders are the 37 modules it registers: no A1Z26,
  Base58 Flickr, URL-safe Base64, Base65536, Z85, DNA, DTMF, railfence or substitution, and
  only an English checker, so it isn't compared on other languages. Its hash cracker looks
  hashes up on web sites, so hashes aren't compared either. Its ~0.85 s start-up is in its
  times.
* **CyberChef 11.5.0** (npm `cyberchef`, Node.js API), the Magic operation with its default
  settings: depth 3, no intensive mode, no extensive language support, no crib. Magic
  doesn't give one answer but a ranked list; its answer here is its first suggestion, baked
  on the whole input (Magic keeps only the first 100 characters of each). When nothing ranks
  above the input itself, it counts as "nothing", which is correct for plaintext input.
  `cyberchef-intensive` is the same with intensive mode on, which also brute-forces
  single-byte XOR, bit rotations and 152 text encodings on the first 100 bytes. Magic only
  tries operations that have a detection pattern (46 of CyberChef's 505), so it has no
  Caesar, ROT13, Vigenère, Atbash or reversed text, and in intensive mode only those
  brute-forces on top. Both run in one warm Node process: CyberChef's 1.6 s start-up isn't
  in its times. The summary also says how often the answer was among Magic's first five
  suggestions.

## Corpus v1

376 cases, generated by `corpus.py` with seed 20261104 and frozen: re-running the generator
with the pinned packages reproduces the file byte for byte (`corpus.py --check`). A change to
the cases makes a corpus v2 next to it, so that results stay comparable; the runner records
the corpus's sha256 (v1: `412f2c61be13…`).

| Category | Cases | What | Python Ciphey | CyberChef (intensive) |
|---|---:|---|---:|---:|
| `encoding` | 119 | one layer (a few with Base64 or hex outside) of each of 87 encodings Ciphey decodes, some in two formats, and of 27 it doesn't decode yet | 31 | 41 (47) |
| `classical` | 59 | 42 ciphers and keys Ciphey cracks (Caesar, ROT13, ROT47, ROT18, Atbash, affine, Vigenère, Beaufort, autokey, railfence, route, substitution, Playfair, Hill, single-byte and repeating-key XOR, ASCII shift, reversed text) and 12 it doesn't have yet | 27 | 0 (3) |
| `hash` | 16 | MD5, SHA-1, SHA-256 and NTLM of four common passwords | - | - |
| `chain` | 40 | 2 to 5 layers, ten of each: half only base encodings, half with a classical cipher inside | 40 | 20 (20) |
| `flag` | 30 | CTF flags in 12 formats under 30 encodings and chains, 7 of them with random hex inside | 28 | 15 (16) |
| `short` | 15 | 2 to 11 characters (`go`, `yes`, `hi mom`) | 15 | 9 (9) |
| `long` | 12 | 713 to 2,445 characters of public-domain prose | 10 | 5 (5) |
| `language` | 36 | German, French, Spanish, Italian, Portuguese, Dutch, Polish, Turkish, Russian, Chinese, Japanese and Korean, as Base64, hex and plaintext | - | 36 (36) |
| `plaintext` | 10 | input that already is the plaintext: sentences, a URL, an email address, an IP address, JSON, a shell command, a flag, code | 10 | 10 (10) |
| `no_answer` | 39 | random letters, digits, hex and Base64 of random bytes, keyboard mashing, English letter-bigram gibberish, sentences with each word's letters shuffled, CJK, emoji, symbols | 39 | 39 (39) |

116 cases are comparable on all four tools: 77 with an answer and the 39 without one.

**Expected failures.** The `xfail` column marks cases Ciphey can't decode until something
lands, so that the decoder PRs' gains show up: 39 encodings and ciphers it has no decoder for
yet, each tagged with its issue from [#1030](https://github.com/bee-san/Ciphey/issues/1030)
(Base45 #923, Base62 #924, Bech32 #931, Modhex #932, xxencode #934, Bubble Babble #936,
UTF-7 #942, EBCDIC #944, Cisco type 7 #949, base-N codes #953, Chuck Norris #954, Manchester
#955, DNA 2-bit #967, upside-down #970, Zalgo #972, runes #974, Kenny #979, Pig Latin #980,
reversed words #983, Brainfuck dialects #985, Whitespace #986, ROT8000 #993, Trithemius #995,
skip #998, Redefence #999, Porta #1004, four-square #1008, Bifid #1009, Nihilist #1012,
ADFGX/ADFGVX #1013, columnar #1014, double transposition #1015, fractionated Morse #1016, bit
rotation #1019, Zstandard #1025, LZ4 #1026, LZ-String #1027), the hashes (#1029), and the other
languages (gibberish-or-not 6). The summary counts them on their own for Ciphey.

**How the ciphertexts were made.** Never with Ciphey's decoders, always with something
independent: Python's standard library (Base64/32/16/85, Ascii85, binascii, quopri,
email.header, idna, utf-7, cp037, gzip, zlib, bz2, lzma, hashlib, hmac), PyPI references
(base45, base58, base65536, base91, base92, pybase62, pycipher, pycryptodome's MD4, lz4,
zstandard, lzstring, cipheydists's galactic table), CyberChef's encoders (Citrix CTX1,
ROT8000, A1Z26, Bacon), the npm `jsfuck` reference encoder, or a few lines written from the
published definition and cited in the code (Z85 from ZeroMQ RFC 32, Bech32 from BIP-173,
Bubble Babble, Monero's Base58, ITA2, the standard genetic code, AAEncode ported from
Hasegawa's encoder, Delastelle's four-square, ...). `corpus.py` checks known answers of the
hand-written ones when it starts (`selftest`), and `corpus.py --verify` decodes the corpus
again with a second implementation, mostly CyberChef's decoders, plus PyPI and the standard
library, Node.js `eval` for JSFuck and AAEncode, and a Brainfuck interpreter: 267 of the 315
cases with layers check out and none disagree. The other 48 use one of 47 layers nothing
else here decodes (keypad and tap codes, NATO, Polybius, Pollux, 01248, DNA codons,
Baudot, keyboard shifts, Hill, Nihilist, ...).

**Plaintexts.** Written for this benchmark (sentences, short texts, the other languages, flag
contents, the plaintext inputs), and five paragraphs of public-domain books from Project
Gutenberg chosen to be outside both Ciphey's quadgram table and gibberish-or-not 6's training
books (its `en_test` list):

| Ebook | Title | sha256 of the file used |
|---|---|---|
| 1250 | Anthem | `73057e044f9d2b7db1904c55bcfc2233344fd497facb82092be3cf76ceb83f20` |
| 26184 | Simple Sabotage Field Manual | `c009a5c1f171ca1952456d477d328dfc4e4007c1bd05f17590bec37ee1d5b488` |
| 161 | Sense and Sensibility | `7bcd77c45cb32fb8d9f89402561270cc6a911c0a4e20667176d5be779fc3974a` |
| 67098 | Winnie-the-Pooh | `4bef0cc815e2c9f3188c3a0f992c817d1829139d77bbfaffb07b815d6175976c` |

## Baseline, 2026-11-04

On the Ciphey program's shared build host: an AMD EPYC 9R14 KVM guest with 64 vCPUs, Amazon
Linux 2023, kernel 6.12, with a load average of 44 to 62 from other jobs during every run. Corpus v1,
timeout 5 s, `RAYON_NUM_THREADS=4`.

| Tool | Version | Runs (UTC) |
|---|---|---|
| ciphey master | 9350174d, `cargo build --release`, rustc 1.99.1 | with 0.12.0, interleaved: 14:37 to 14:52 |
| ciphey 0.12.0 | crates.io, `cargo install --locked` | see master |
| Python Ciphey | 5.14.0 on CPython 3.9.25 | 14:52 to 15:02 |
| CyberChef Magic | npm `cyberchef` 11.5.0 on Node.js 24.21.0 | 15:24 to 15:25, intensive 15:25 to 15:32 |

The per-case results are in [`benches/data/e2e/baseline-2026-11-04.tsv`](../benches/data/e2e/baseline-2026-11-04.tsv)
(answers left out); `python3 benches/e2e/run.py --summarize benches/data/e2e/baseline-2026-11-04.tsv`
prints every table below. The commands were these, with master's release binary copied to
`.tools/ciphey-master-9350174d/` and the other tools installed by hand with the versions
`setup.sh` pins (it puts them in `.tools/pyciphey` and `.tools/node`):

```sh
python3 benches/e2e/run.py master=.tools/ciphey-master-9350174d/ciphey v0.12.0=.tools/ciphey-0.12.0/bin/ciphey
python3 benches/e2e/run.py python-ciphey:.venv-pyciphey/bin/python
python3 benches/e2e/run.py cyberchef:.tools/cyberchef
python3 benches/e2e/run.py cyberchef-intensive:.tools/cyberchef
python3 benches/e2e/run.py master=.tools/ciphey-master-9350174d/ciphey master=.tools/ciphey-master-9350174d/ciphey
```

### Accuracy

Correct answers of the cases each tool ran (for `no_answer`, giving up). The tools ran
different cases, the ones they are comparable on, so compare tools in the
[head-to-head table](#head-to-head) and read this one down its columns.

| Category | master | 0.12.0 | Python Ciphey 5.14.0 | CyberChef | CyberChef, intensive |
|---|---:|---:|---:|---:|---:|
| encoding | 87/119 (73%) | 25/119 (21%) | 27/31 (87%) | 36/41 (88%) | 35/47 (74%) |
| classical | 44/59 (75%) | 11/59 (19%) | 18/27 (67%) | - | 3/3 |
| hash | 0/16 | 0/16 | - | - | - |
| chain | 25/40 (62%) | 1/40 (2%) | 21/40 (52%) | 9/20 (45%) | 8/20 (40%) |
| flag | 28/30 (93%) | 7/30 (23%) | 17/28 (61%) | 11/15 (73%) | 0/16 (0%) |
| short | 9/15 (60%) | 9/15 (60%) | 7/15 (47%) | 4/9 (44%) | 2/9 (22%) |
| long | 11/12 (92%) | 4/12 (33%) | 7/10 (70%) | 4/5 (80%) | 3/5 (60%) |
| language | 8/36 (22%) | 11/36 (31%) | - | 36/36 (100%) | 34/36 (94%) |
| plaintext | 10/10 (100%) | 9/10 (90%) | 9/10 (90%) | 9/10 (90%) | 3/10 (30%) |
| no_answer | 12/39 (31%) | 2/39 (5%) | 37/39 (95%) | 35/39 (90%) | 6/39 (15%) |
| **all** | **234/376 (62.2%)** | **79/376 (21.0%)** | **143/200 (71.5%)** | **144/175 (82.3%)** | **94/185 (50.8%)** |

Without the 92 expected failures (no decoder yet, hashes, other languages), master gets
226 of 284 cases right (79.6%) and 0.12.0 68 (23.9%): encodings 87/92 against 25/92,
classical ciphers 44/47 against 11/47, flags 28/29 against 7/29. 8 of master's expected
failures pass already, all of them other languages (French and Spanish in every form, German
and Italian as hex), and 11 of 0.12.0's.

#### Head to head

The 116 cases every tool is comparable on: 77 with an answer (19 encodings, 20 chains of
base encodings, 14 flags, 9 short and 5 long texts, 10 plaintext inputs) and the 39 without.

| Tool | Correct of 77 | Wrong | Nothing | False positives of 39 | Median time | p90 time |
|---|---:|---:|---:|---:|---:|---:|
| master | 62 (80.5%) | 8 | 7 | 27 (69%) | 66 ms | 5.46 s |
| 0.12.0 | 33 (42.9%) | 24 | 20 | 37 (95%) | 0.18 s | 5.12 s |
| Python Ciphey 5.14.0 | 60 (77.9%) | 13 | 4 | 2 (5%) | 1.36 s | 6.04 s |
| CyberChef | 54 (70.1%) | 11 | 12 | 4 (10%) | 5 ms | 33 ms |
| CyberChef, intensive | 31 (40.3%) | 36 | 10 | 33 (85%) | 1.43 s | 5.30 s |

### Time

| Tool | All cases: median / p90 / p99 | Correct answers: median / p90 | No answer: time to give up, median |
|---|---|---|---|
| master | 62 ms / 5.48 s / 5.65 s | 50 ms / 73 ms (222) | 5.47 s (its 5 s timeout) |
| 0.12.0 | 0.15 s / 5.10 s / 6.04 s | 77 ms / 0.14 s (77) | 5.19 s |
| Python Ciphey 5.14.0 | 1.61 s / 6.05 s / 6.06 s | 1.24 s / 2.25 s (106) | 6.04 s (killed: it never gave up) |
| CyberChef | 5 ms / 21 ms / 6.22 s | 5 ms / 12 ms (109) | 2 ms |
| CyberChef, intensive | 1.81 s / 4.67 s / 6.22 s | 1.92 s / 4.09 s (88) | 0.15 s |

Ciphey's and Python Ciphey's times are whole processes, start-up included (under 50 ms for
Ciphey, about 0.85 s for Python Ciphey); CyberChef's are calls into a warm process.

### Determinism

Master against itself over the whole corpus, interleaved (`run.py master=… master=…`, 15:10
to 15:23 UTC), gave 234/376 correct in both runs, as in the baseline run, with one verdict
different: `lang.ru.base64`, a false positive found after 5.30 s in one run and nothing at the
5 s timeout in the other. The time ratio of the two runs was 0.997 (95% confidence interval
0.986 to 1.007). On the quick subset (76 cases), master against itself took 54 s, changed no
verdict and had a time ratio of 0.991 (0.956 to 1.027); master against 0.12.0 lists 43 changed
verdicts there and `--check` fails, as it should. CyberChef ran twice too (the first runs
counted the restart of the Node process after a timeout into the next timed-out case): the
same verdicts by default, and in intensive mode two cases that finish close to the timeout
changed places (`enc.bech32.1`, `flag.19`), 94 correct both times.

### What stands out

* Where it has decoders, master is far ahead of 0.12.0 (79.6% against 23.9%), mostly because
  0.12.0 accepts junk: 230 of its 297 misses are wrong answers, typically from long chains of
  Vigenère, railfence and ROT47.
* On the cases all tools can do, master answers 62 of 77 right, a little ahead of Python
  Ciphey (60) and CyberChef (54), and about 20 times faster than Python Ciphey (median 66 ms
  against 1.36 s).
* Master's weak spot is **inputs with no answer**: it returns junk for 27 of 39 (all six
  English-like letter strings, the keyboard mashing, the shuffled words, digit strings), where
  CyberChef gives up on 35 and Python Ciphey runs out of time on 37.
* Chains get harder with depth: master solves 9, 9, 5 and 2 of the ten chains of 2, 3, 4 and
  5 layers (Python Ciphey 5, 7, 5, 4).
* Hashes (0/16, #1029), other languages (8/36, gibberish-or-not 6) and short texts (9/15) are
  the other gaps. Of the 92 single encodings Ciphey has decoders for, master missed 5: Base58
  Monero, binary written with X and Y, T9 with a word outside its dictionary, and the
  zero-width and acrostic texts, where it takes the cover text for the plaintext. Of the 47
  classical ciphers it missed a substitution (one letter wrong), a Playfair and a Hill
  cipher of 18 letters.
* CyberChef's intensive mode makes Magic worse at first suggestions: its text-encoding
  brute force ranks CJK readings of Base64 above the right answer.

## Limitations

* One machine, shared and busy. Accuracy repeats (see [Determinism](#determinism)); times
  move with the load, so compare times only within an A/B run.
* Python Ciphey and CyberChef are reported on the cases they have decoders for, and "has a
  decoder" was decided from their source (registered modules, Magic's patterns), not from
  their results.
* CyberChef Magic suggests, it doesn't answer: counting only its first suggestion is strict.
  How often the answer was among its first five is in the summary (116 of 136 cases with
  an answer, 109 first).
* The corpus has one or two cases per encoding, so a single case moving is a large change in
  a small category. Categories, not single encodings, are the unit to compare.
* Corpus v1's plaintexts are English apart from the `language` category; most are one
  sentence.
