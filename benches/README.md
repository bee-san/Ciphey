# Benchmarks

Criterion benchmarks for the decoders, the checkers, the A* search and startup.
Baseline numbers and a profile are in [docs/benchmarks.md](../docs/benchmarks.md).

```sh
cargo bench                          # everything, about 10 minutes
cargo bench --bench decoders         # one suite
cargo bench --bench decoders -- caesar        # benchmarks whose id matches a regex
cargo bench --bench search -- search/multi
cargo bench -- --test                # run every benchmark once and check the fixtures
cargo bench --bench plaintext        # the plaintext-detection report (docs/plaintext-detection.md)
```

| Suite | What it measures | Ids |
|---|---|---|
| `decoders` | `Decoder::crack` with the Athena checker, for every decoder, on an 84 character text encoded with that decoder (`medium`), a 576 character one (`long`), and a gibberish string it rejects (`miss`, the common case during a search). Crackers that take hundreds of milliseconds per call (Playfair) are in a group of their own with 10 flat samples | `decoders/<decoder>/{medium,long,miss}`, `decoders_slow/<decoder>/{long,miss}` |
| `checkers` | English (gibberish detection), LemmeKnow, the password list, and Athena (all of them in turn), on hits and misses, at each sensitivity the decoders use | `checkers/<checker>[_<sensitivity>]/<input>` |
| `crib` | The regex and wordlist checkers, plus two end-to-end `--regex` searches | `crib/...`, `crib/search/...` |
| `search` | `perform_cracking` end to end: input that is already plaintext, single-layer and multi-layer encodings, and inputs with no solution, all with a 1 second timeout | `search/{plaintext,single,multi,no_solution}/<case>` |
| `startup` | Config defaults, loading `config.toml` and a wordlist, the SQLite cache, `perform_cracking` on a cache hit and miss, and the `ciphey` binary started as a subprocess (Unix only) | `startup/...` |
| `plaintext` | Plaintext-detection accuracy (precision, recall and F1 per checker, family and category, on train and held-out splits), time per check, decoder results and, with `-- --e2e`, whole searches. Not criterion: a report. See [docs/plaintext-detection.md](../docs/plaintext-detection.md) | - |

Criterion keeps results in `target/criterion` and compares each run with the previous
one. To compare against a named baseline:

```sh
cargo bench -- --save-baseline before
# ...change something...
cargo bench -- --baseline before
```

On a busy machine two full runs minutes apart can differ by more than the change you
are measuring. To compare two versions fairly, build both bench binaries (for example
from a `git worktree`, with a different `CARGO_TARGET_DIR`) and alternate between them
one benchmark at a time, sending each side's results to its own `CRITERION_HOME`:

```sh
for id in $(target/release/deps/search-<hash> --bench --list | sed -n 's/: benchmark$//p'); do
  CRITERION_HOME=/tmp/old /path/to/old/target/release/deps/search-<hash> --bench "^$id\$"
  CRITERION_HOME=/tmp/new target/release/deps/search-<hash> --bench "^$id\$"
done
```

## End-to-end benchmark: the check for decoder PRs

[`e2e/run.py`](e2e/run.py) runs whole `ciphey` binaries on a frozen corpus and reports
accuracy and time. Corpus v1 ([`data/e2e/corpus-v1.tsv`](data/e2e/corpus-v1.tsv), 376 cases)
has every encoding and cipher Ciphey decodes and 39 it doesn't yet, hashes, chains of
2 to 5 layers, CTF flags, short and long texts, other languages, plaintext input and inputs
with no answer. The method, the corpus and the baselines of master, 0.12.0, Python Ciphey
and CyberChef Magic are in [docs/benchmark-e2e.md](../docs/benchmark-e2e.md). The runner
needs only Python 3.9+ (Linux or macOS).

A PR that adds or changes a decoder or a checker runs the **quick subset** (76 cases, about
a minute) with master's binary as A and its own as B:

```sh
git worktree add ../ciphey-master origin/master
(cd ../ciphey-master && cargo build --release)    # master's binary, once
cargo build --release
python3 benches/e2e/run.py --subset quick --check ../ciphey-master/target/release/ciphey target/release/ciphey
```

Each case runs on both binaries back to back, A first on even cases and B first on odd
ones, each time with a fresh `HOME` (no cache), `-d` and a 5 second timeout. The report ends
with:

* **Verdicts that changed**: every case one binary got right and the other didn't, with the
  answers and the decoder paths. A decoder PR should have no line that goes from `correct`
  to `wrong` or `nothing`; `--check` exits 1 if there is one.
* **Time B/A**: the geometric mean of the per-case time ratios, with a 95% confidence
  interval (Student's t on the log ratios). Master against itself gave 0.991 (0.956 to 1.027)
  in 54 s on the busy shared host; an interval above 1.05 is a slowdown to explain.

Paste those lines and the `uptime` lines into the PR. To show what the new decoder gains, run
its own cases of the full corpus too (they are tagged with its issue as expected failures),
for example `--ids base45`, and drop `--subset quick` for the whole corpus (about 6 minutes
per binary) when the change touches the search or the checkers. CI runs `run.py --selftest`
and then `--subset smoke` (10 cases) on the debug binary.

## Inputs

All inputs are checked in under [`data/`](data) so runs are comparable:

* `decoders.toml`: one `medium` and one `long` input per decoder, plus the shared `miss` input.
* `checkers.toml`: named inputs and the checker runs over them.
* `search.toml`: the A* corpus. `layers` says how each input was built, innermost first.
* `config.toml`: the default `~/.ciphey/config.toml`, used by the startup benchmarks.
* `wordlist.txt`: 5,000 words for the wordlist checker and wordlist loading.

Every benchmark first runs its case once and panics if the result differs from the
fixture (`expected`, `success`, `identified`, `outcome`), so a behaviour change shows up
as a failure instead of as a different number. If you change behaviour on purpose,
update the fixture. Search results are only checked in optimised builds: under
`cargo test --benches` some searches don't finish within the 1 second timeout.

## Things to know

* Ciphey's config and database path are process-wide and can only be set once, so each
  suite picks one configuration when it starts. That is why the regex/wordlist
  checkers have their own suite.
* `decoders`, `checkers`, `crib` and `search` keep the cache database in memory, so
  every `perform_cracking` call is a cache miss and nothing under `~/.ciphey` is read or
  written. `startup` uses a scratch dir under `target/tmp` for its database and as
  `HOME` for the CLI.
* The A* search keeps per-decoder success statistics for the life of the process and
  uses them in its edge costs. The search benchmarks clear them before every
  iteration (`ciphey::reset_decoder_stats`), so each search explores in the same order
  as in a fresh `ciphey` process instead of depending on how many searches ran before.
* The no-solution searches end when the decoders run out of candidates, when the
  search settles on a false positive, or at the timeout. Which one happens can depend on
  machine speed, so only the "exhausted" and "timeout" outcomes are checked. Before
  [#1031](https://github.com/bee-san/Ciphey/issues/1031) both gibberish inputs ended
  early on a false positive (rot47 → Vigenere); now they run until the timeout.
* The search runs on rayon's thread pool, so its numbers depend on core count and on
  whatever else the machine is doing. Close other heavy work before comparing runs.

## Profiling

The bench profile inherits `strip = "symbols"` from the release profile. To profile,
build with symbols and use criterion's profile mode, which runs a benchmark for a fixed
time without analysis:

```sh
CARGO_PROFILE_BENCH_DEBUG=line-tables-only CARGO_PROFILE_BENCH_STRIP=none \
  cargo bench --bench search --no-run
perf record -F 999 -g target/release/deps/search-<hash> --bench --profile-time 10 'search/multi'
perf report --no-children --sort symbol
```

`cargo flamegraph --bench search -- --bench --profile-time 10 search/multi`, with the same
two environment variables set, works too if you have
[flamegraph](https://github.com/flamegraph-rs/flamegraph) installed.
