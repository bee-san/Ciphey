# Ciphey on WebAssembly

Ciphey's library is written to build for WebAssembly with its default features and no
flags:

```sh
rustup target add wasm32-unknown-unknown
cargo build --lib --target wasm32-unknown-unknown
```

Native builds don't change: `cargo install ciphey` builds the same command-line tool, with
the same defaults, and `--features mcp` the same MCP server.

**Status.** Ciphey's own code builds for wasm32, but two of its dependencies don't yet, so
the command above fails on `master` until they are replaced:

- gibberish-or-not 5.0.7 pulls in candle, tokenizers (whose `onig_sys` compiles C) and
  reqwest with OpenSSL, for a BERT model its `is_gibberish` never loads;
- lemmeknow 0.8.0's wasm32 `Identifier::identify` takes `&[String]` and hands the slice to
  `Regex::is_match`, so it doesn't compile.

gibberish-or-not 6 and pywhat 6, which replace them, are built for WebAssembly. Until then
the WebAssembly build is checked with both crates patched (gibberish-or-not without the
model, lemmeknow's wasm32 code fixed), and the browser API and a CI job come with the
switch to the new crates.

## What is different on WebAssembly

WebAssembly in a browser or in Node.js has no threads, no files, no terminal and no
clock that `std` can read (`std::time::Instant::now()` panics on wasm32-unknown-unknown).
Everything that needs them is left out of the WebAssembly build, and replaced where the
library needs it:

| Part | Native targets | WebAssembly |
| --- | --- | --- |
| The search | runs on its own thread; up to 10 nodes at a time and all decoders of a node in parallel (rayon) | runs on the caller's thread, one decoder after another (`src/parallel.rs`) |
| The timeout | a timer thread stops the search, prints the countdown and pauses while the human checker asks | the search checks a deadline before each step and before each decoder (`searchers::search_until`) |
| The clock | `std::time` | the JavaScript clock (`performance.now()`), through the `web-time` crate (`src/clock.rs`) |
| The cache | SQLite in `~/.ciphey/database.sqlite` | none |
| The human checker | asks on the terminal | accepts every candidate, as in API mode, whatever `human_checker_on` says |
| Config file, first-run setup, wordlist files | `~/.ciphey/config.toml`, `--wordlist` (read with memmap2) | none: set the `Config` fields, and pass a wordlist as a `HashSet` (`Config::wordlist`, `DetectOptions::wordlist`) |
| `top_results` mode | prints the results at the timeout | prints nothing (they are in `storage::wait_athena_storage`), and ends early when the search space is exhausted |
| LemmeKnow's regexes | compiled on rayon's pool before the first check | compiled when a check first needs them |
| Colours | ANSI escape codes | none |
| The `ciphey` binary | the CLI | prints that the CLI doesn't run on WebAssembly |
| `ciphey-mcp` (`--features mcp`) | the MCP server | not available |

The answers are the same: on WebAssembly, `tests/wasm.rs` runs every decoder on its
benchmark inputs and every search of the benchmark corpus that has a plaintext, and gets
what native builds get. Searches of input that has no plaintext are the exception: where a
native search ends (which false positive, if any, it settles on) can depend on thread
timing. The WebAssembly search is sequential: it tries candidates in the same order as a
native search on one thread (`RAYON_NUM_THREADS=1`).

## How it is gated, and why

The WebAssembly build is chosen by the target, with `cfg(target_family = "wasm")` and
`cfg(not(target_family = "wasm"))` in the code and target-specific dependency tables in
`Cargo.toml`:

```toml
# Native targets only: threads, files, the terminal and the SQLite cache
[target.'cfg(not(target_family = "wasm"))'.dependencies]
clap = ...
crossbeam = ...
dirs = ...
env_logger = ...
memmap2 = ...
rayon = ...
rusqlite = { version = "0.37", features = ["bundled"] }
text_io = ...
uuid = ...
```

Cargo features can't do this without a flag. Features only add to a build, so to keep
SQLite, threads and files out of the WebAssembly build they would have to sit behind a
default feature (say `native`) that WebAssembly builds turn off with
`--no-default-features`. That is the extra flag "WebAssembly by default" rules out. Every
crate that depends on Ciphey would have to pass it as well, and since Cargo unifies
features across a build, one dependent that left `native` on would break the WebAssembly
build for everyone. The target is known to every build, so nobody has to choose anything.
Features stay for optional extras: `mcp` (native only) and the browser API to come.

`target_family = "wasm"` rather than `target_arch = "wasm32"` so that wasm64 and every
WebAssembly OS (`wasm32-unknown-unknown`, `wasm32-wasip1`, ...) get the same build: WASI
preview 1 has no threads either, and SQLite's bundled C would need a WASI C toolchain.

Everything in `[dependencies]` is meant to build for WebAssembly, and everything does
except gibberish-or-not 5 and lemmeknow 0.8 (see Status); the native-only dependencies are
in the table above. Four dependencies no code used (`ansi_term`, `cipher_identifier`,
`human-panic` and `include_dir`) were removed instead of gated. `human-panic` was also what
turned on `uuid`'s `v4` feature, which the cache uses, so `uuid` asks for it itself now.

## Keeping it working

Decoders and checkers run on every target, so in them:

- use pure-Rust dependencies only: no `-sys` crates that compile C or C++
  (`ruzstd` and `lz4_flex` are pure-Rust choices for zstd and LZ4);
- don't use `std::thread`, `std::fs`, `std::net`, `std::process` or `std::env`;
- measure time limits with `crate::clock::Instant`, not `std::time::Instant`;
- don't call what reads std's clock inside: `Condvar::wait_timeout` and
  `wait_timeout_while`, `mpsc::Receiver::recv_timeout`, `thread::sleep`, and dependencies
  that call `std::time::Instant::now()` (brainfuck-exe does unless
  `with_bench_execution(false)`). On wasm32-unknown-unknown they panic with "time not
  implemented on this platform";
- run work in parallel with the iterators of `crate::parallel` (rayon's prelude on native
  targets, sequential on WebAssembly), not `rayon` directly;
- embed data with `include_str!`/`include_bytes!` instead of reading files at run time.

Check a new dependency in a scratch crate (`cargo new`, add it, then `cargo build --target
wasm32-unknown-unknown`). Once gibberish-or-not and lemmeknow are replaced, check every
change with

```sh
cargo build --lib --target wasm32-unknown-unknown
cargo test --target wasm32-unknown-unknown --test wasm
```

The build alone doesn't find a clock read: it compiles, and panics when it runs.

## Tests

`tests/wasm.rs` holds the core checks, written to run on every target: whole searches
(Base64, three layers, Caesar, input that is already plaintext, nothing to decode, an
invalid regex, the timeout), single decoders (including the Vigenère, Playfair and
substitution crackers, whose data, time limits and cache used to need files, `std::time`
and threads), plaintext detection and the built-in data. Two more run the benchmark
fixtures, which were recorded natively: every decoder on its inputs
(`benches/data/decoders.toml`) and every search of the corpus that has a plaintext
(`benches/data/search.toml`). Natively the file runs with the rest of `cargo test`, without
those two, which `cargo bench -- --test` checks there in optimised builds (or run them with
`cargo test --test wasm -- --include-ignored`). On
WebAssembly it runs under Node.js with `wasm-bindgen-test-runner`, which has to be the
same version as the `wasm-bindgen-test` crate in `Cargo.toml` (0.3.80, which is
wasm-bindgen 0.2.130):

```sh
cargo install wasm-bindgen-cli --version 0.2.130
export CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER=wasm-bindgen-test-runner
cargo test --target wasm32-unknown-unknown --test wasm
```

Only that file runs on WebAssembly. The other tests use what WebAssembly doesn't have
(threads, the database, files, the CLI binary), and wasm-bindgen-test-runner only runs
tests marked `wasm_bindgen_test`, which `tests/wasm.rs` makes `#[test]` mean on
wasm32-unknown-unknown.
