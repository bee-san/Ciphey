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
model, lemmeknow's wasm32 code fixed), and a CI job comes with the switch to the new
crates.

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
native search on one thread (`RAYON_NUM_THREADS=1`), except where two candidates' scores
differ only in the last bits of a logarithm or exponential, which WebAssembly's maths
library rounds differently. On the benchmark corpus the results are the same.

## The browser API

The crate in `wasm/`, `ciphey-wasm`, is Ciphey's JavaScript API, made with wasm-bindgen.
It's a member of Ciphey's workspace and isn't published to crates.io. It wraps the Rust
API `ciphey::search::Search`, which runs the search a step at a time with its own
options, and which works natively too.

It's a separate crate, not a `wasm` feature of `ciphey`, because the JavaScript module has
to be a `cdylib`. A `cdylib` in `ciphey`'s own `[lib]` would be built, natively too, by
everything that builds the library. The separate crate also keeps wasm-bindgen out of
`ciphey`'s dependencies.

### Building it

```sh
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version 0.2.130   # the version wasm/Cargo.toml pins
# and binaryen's wasm-opt: https://github.com/WebAssembly/binaryen/releases
wasm/build.sh            # or wasm/build.sh <out dir>; the default is wasm/pkg
```

The script builds the module with the `wasm` profile (release, `opt-level = "z"`, fat
LTO, one codegen unit, `panic = "abort"`), runs `wasm-bindgen --target web` and then
`wasm-opt -Oz`. It prints the module's size raw and gzipped, and fails above
`MAX_WASM_BYTES` or `MAX_WASM_GZIP_BYTES` if they are set. The out dir gets
`ciphey_wasm.js` (ES module), `ciphey_wasm_bg.wasm` and `ciphey_wasm.d.ts` (TypeScript
types for everything below).

### Exports

The names don't collide with pyWhat's and gibberish-or-not's WebAssembly bindings
(`identify`, `tags`, `version`, `detect`, `score`, `isGibberish`, ...), so one module can
link all three.

| Export | What it does |
| --- | --- |
| `new Search(input, options?)` | A search for the plaintext of `input`. Nothing runs until `step`; the timeout counts from here. Throws on bad options |
| `search.step(budgetMs)` | Searches for about `budgetMs` ms and returns a `SearchProgress`. `Infinity` runs it to its end |
| `search.status` | `"running"`, `"decoded"`, `"not_found"` (nothing left to try) or `"timed_out"` |
| `search.results()` | Every `SearchResult` so far |
| `search.free()` | Frees the search's memory in the module |
| `decode(input, options?)` | The whole search at once: the first `SearchResult`, or `null`. Blocks up to the timeout |
| `listDecoders()` | `[{name, id, aliases, tags, description, link, keyFormat}]` |
| `detectPlaintext(text, options?)` | What Ciphey's plaintext checkers take `text` for: `{checker, checkerName, description, confidence}` or `null`. Options: `checkers` (ids), `sensitivity`, `regex` |
| `cipheyVersion()` | The library's version, such as `"0.12.1"` |

The options of `new Search` and `decode`, all optional:

- `timeout` (seconds) or `timeoutMs`, default 5 s;
- `regex`: a crib, in Rust's regex syntax; only text it matches is plaintext;
- `topResults`: keep searching after the first plaintext, until the timeout or the end;
- `sensitivity`: `"low"`, `"medium"` or `"high"` for the English checker, where `"low"` is
  the strictest;
- `previewChars`: how much of each node's text to report, default 120.

Options must be a plain object, `undefined` or `null` (`null` fields are the defaults).
Unknown fields, numbers that are negative, `NaN` or infinite, and a regex that doesn't
compile throw an `Error` that says why. Lengths and `previewChars` count characters as
code points: an emoji is one, though its JavaScript `length` is 2.

`step` returns a `SearchProgress`:

| Field | |
| --- | --- |
| `status` | as `search.status` |
| `elapsedMs` | since `new Search` |
| `expanded`, `queued`, `seen` | nodes expanded so far, nodes waiting, texts seen (the search never queues a text twice) |
| `depth` | decoders in the deepest node expanded so far |
| `nodes` | the nodes this step expanded, in order: `{id, parent, depth, decoder, key, text, length, cost, children}`. The input is node 0 with `parent: null`. A node's parent is always reported before it, so the nodes make a tree. `text` is the start of the node's text and `length` its length in characters. `cost` is the search's priority, f = g + h (it expands the lowest first), and `children` is how many children expanding the node queued |
| `results` | the plaintexts this step found (more than one only with `topResults`) |
| `result` | the search's first plaintext, from this step or an earlier one, or `null` |

A `SearchResult` has:

- `plaintext`;
- `path`: one step per decoder, input first, `[{decoder, key, checker, checkerName,
  description, confidence}]`, where only the last step has the checker fields;
- `checker` (an id such as `"english"` or `"lemmeknow"`), `checkerName` (such as
  `"English Checker"`), `description` (such as `"Words"`) and `confidence` (pyWhat's
  rarity for its formats, else `null`);
- `elapsedMs`;
- `nodeId`: the node it was decoded from, the end of the winning branch, or `null` if
  the input was already plaintext.

A step returns between two batches of up to ten nodes once its budget has passed, so one
can run longer than the budget: as long as the slowest batch takes. Playfair's cracker
allows itself 1.5 s, and on long input the first step can take much longer: on 1 MB of
text, 11 to 14 s under Node.js, most of it in the Base58 decoders
([#1138](https://github.com/bee-san/Ciphey/issues/1138)). The search checks its own
timeout before every decoder. Searches never prompt, use no cache and print nothing. A
panic is logged to `console.error` before the module aborts; the instance is unusable
after that, so start a new one.

### Memory

A search keeps every node it hasn't expanded yet, so its memory grows for as long as it
runs: about 1 KB per queued node for short input, more for long input (a node holds its
text and its whole decoder path). A search with no plaintext queues hundreds of thousands
of nodes a minute: one measured in Chrome reached 4 GiB, all a wasm32 module can address,
after 27 s, and the module aborted. Running out of memory isn't a panic, so nothing is
logged. Keep timeouts short, or watch `queued` (or the module's memory) and stop the
search, as ciphey-web does. `search.free()` gives the memory back to the module for the
next search, though the module itself never shrinks. Bounding the queue is
[#1144](https://github.com/bee-san/Ciphey/issues/1144).

### In a Web Worker

A step blocks the thread it runs on, so run the search in a Worker and step it between
messages:

```js
// worker.js: new Worker(new URL("./worker.js", import.meta.url), { type: "module" })
import init, { Search } from "./pkg/ciphey_wasm.js";

const ready = init(); // fetches and compiles ciphey_wasm_bg.wasm once
let current = null;

onmessage = async ({ data }) => {
  await ready;
  if (data.type === "cancel") {
    current?.free();
    current = null;
    return;
  }
  // { type: "decode", input, options }
  current?.free();
  current = null;
  let search;
  try {
    search = new Search(data.input, data.options);
  } catch (error) {
    postMessage({ type: "error", message: error.message }); // a bad crib, say
    return;
  }
  current = search;
  let update;
  do {
    update = search.step(40);
    postMessage({ type: "progress", update }); // update.nodes: the tree's new nodes
    // Let a "cancel" or a new "decode" message in between steps
    await new Promise((resolve) => setTimeout(resolve, 0));
  } while (current === search && update.status === "running");
  if (current === search) {
    search.free();
    current = null;
  }
};
```

```js
// main.js
const worker = new Worker(new URL("./worker.js", import.meta.url), { type: "module" });
worker.onmessage = ({ data }) => {
  if (data.type !== "progress") return;
  const { update } = data;
  for (const node of update.nodes) drawNode(node); // node.parent was drawn before it
  if (update.status === "decoded") {
    showAnswer(update.result.plaintext, update.result.path, update.result.nodeId);
  }
};
worker.postMessage({ type: "decode", input: "aGVsbG8gdGhlcmUgZ2VuZXJhbA==", options: { timeout: 5 } });
```

To stop a search at once, even inside a long step, terminate the Worker and start a new
one.

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
- don't call what reads std's clock, sleeps or waits for another thread inside:
  `SystemTime::now()`, `Condvar::wait`, `wait_timeout` and `wait_timeout_while`,
  `mpsc::Receiver::recv_timeout`, `thread::sleep`, and dependencies that call
  `std::time::Instant::now()` (brainfuck-exe does unless `with_bench_execution(false)`).
  On wasm32-unknown-unknown they panic: "time not implemented on this platform", "can't
  sleep" (`thread::sleep`, `Condvar::wait_timeout`) or "condvar wait not supported";
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

`tests/search.rs` (the Rust `Search` API) runs the same way, and the browser API's own
tests under Node.js with

```sh
cargo test -p ciphey-wasm --target wasm32-unknown-unknown --test node
```

Only those files run on WebAssembly. The other tests use what WebAssembly doesn't have
(threads, the database, files, the CLI binary), and wasm-bindgen-test-runner only runs
tests marked `wasm_bindgen_test`, which `tests/wasm.rs` makes `#[test]` mean on
wasm32-unknown-unknown.
