# The Ciphey website

The site at <https://bee-san.github.io/Ciphey/>: Ciphey, pyWhat and gibberish-or-not in the
browser. It has three pages, one per tool:

| Page | Path | Runs |
| --- | --- | --- |
| Decode | `/Ciphey/` | Ciphey's search, through its browser API (`wasm/`, [docs/wasm.md](../docs/wasm.md)) |
| Identify | `/Ciphey/identify/` | [pyWhat](https://github.com/bee-san/pyWhat)'s `wasm` feature |
| Is it language? | `/Ciphey/language/` | [gibberish-or-not](https://github.com/bee-san/gibberish-or-not)'s `wasm` feature |

Everything runs in the browser. There's no server, no analytics, no cookies, and no request
to any other site: fonts are the system's, icons are inline SVG, and the Content Security
Policy only allows the site's own files.

## Working on it

You need Node.js 22.12 or later, and for the WebAssembly modules a Rust toolchain with the
`wasm32-unknown-unknown` target, `wasm-bindgen-cli` 0.2.130 (the version the crates pin) and
binaryen's `wasm-opt`:

```sh
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version 0.2.130 --locked
# wasm-opt: https://github.com/WebAssembly/binaryen/releases

cd web
npm ci                 # the dev dependencies, pinned in package-lock.json
npm run wasm           # builds the three modules into src/wasm/ (git-ignored)
npm run dev            # http://localhost:5173/Ciphey/, reloads as you edit
```

The dev server serves the pages without their Content Security Policy (it injects inline
scripts), so check changes in a production build too:

```sh
npm run build          # type-checks, then builds dist/
npm run preview        # serves dist/ as GitHub Pages does, at http://127.0.0.1:4173/Ciphey/
```

| Command | What it does |
| --- | --- |
| `npm test` | Unit tests (Vitest): the pages' logic in `src/lib/` and `src/decode/` |
| `npm run e2e` | End-to-end test in headless Chrome (see below). Needs `CHROME` and a build |
| `npm run measure` | Transfer sizes and load times on a cold cache, throttled. Needs `CHROME` and a build |
| `npm run screenshots` | The screenshots in `screenshots/`. Needs `CHROME` and a build |
| `npm run typecheck` | TypeScript, for the pages, the workers, the tests and the build config |

`CHROME` is the path to a Chrome or Chromium binary, for example
`CHROME=$(command -v google-chrome) npm run e2e`.

## How it fits together

```
index.html, identify/index.html, language/index.html   the pages; the header and footer come
                                                        from scripts/shell.ts at build time
src/decode/, src/identify/, src/language/               each page's code (main.ts)
src/workers/*.worker.ts                                  one Web Worker per page: loads its
                                                        WebAssembly module and does the work
src/lib/                                                 logic without the DOM (unit-tested)
src/shell/                                               what every page shares: theme, DOM
                                                        helpers, the worker client
src/styles/                                              one stylesheet; tokens in base.css
engine/                                                  the Rust crates for pyWhat's and
                                                        gibberish-or-not's modules
scripts/build-wasm.sh                                    builds the three modules
tests/unit/, tests/e2e/                                  the tests
```

- **The stack** is vanilla TypeScript and Vite, with no framework. Each page is a form, a
  result area and a worker, and the most involved part, the live search tree, draws hundreds
  of nodes a second, which is simplest as direct DOM updates batched per frame. A framework
  would add a dependency to keep up to date and kilobytes to load for little gain. Vite builds
  the three pages, bundles each worker with its module, and fingerprints every file.
- **Workers.** Every WebAssembly call runs in a worker, so the page never freezes. Decode
  runs Ciphey's `Search` a step (40 ms) at a time and posts the tree's new nodes after each,
  and the page draws them once per frame. Cancel tells the worker to stop between two steps;
  if a step doesn't end within 300 ms (a slow decoder on a big input), the page terminates
  the worker and starts a new one. Identify and Is it language? run as you type: one request
  is with the worker at a time, and only the newest text waits behind it
  (`LatestRequest` in `src/shell/engine.ts`).
- **One module per tool**, loaded only by its page's worker. Measured with `wasm-opt -Oz`:

  | Module | Raw | gzip -9 |
  | --- | ---: | ---: |
  | Decode (Ciphey) | 5,531,448 B | 2,249,691 B |
  | Identify (pyWhat) | 1,375,796 B | 482,045 B |
  | Is it language? (gibberish-or-not) | 1,246,561 B | 1,025,582 B |
  | One module for all three | 6,840,303 B | 3,244,570 B |

  With one module, Identify would load 3.2 MB instead of 0.5 MB, and every page would wait
  for the biggest one. (Ciphey links gibberish-or-not and pyWhat itself, so once it uses
  their version 6 a shared module will be smaller than this one, which has both versions,
  but still about Decode's size.) Separate modules cost a visitor who opens all three pages
  about 0.5 MB more in total.
- **The search tree.** Ciphey reports the nodes it *expands* (runs every decoder on), each
  with its parent, so the tree is always connected. The page draws the first 300 and every
  node on the way to a plaintext, folds a parent's outputs from one decoder (Caesar's 25
  shifts) into a group once there are three, and counts what it leaves out.
- **Highlights.** pyWhat returns each match's text but not where it is, so the page finds it
  again (`src/lib/spans.ts`). Its n-th match of a text gets the text's n-th occurrence, and
  a match pyWhat found after dropping control characters (as its Python version does) is
  mapped back across them. The marks sit in a layer behind the textarea, laid out exactly
  like it.
- **Share links** keep the input in the URL's fragment (`#input=...`), which browsers don't
  send to the server. The page only makes one when asked, shows a warning about secrets
  first, and removes the fragment from the address bar as soon as the input changes. Moving
  text between the tools (Identify the plaintext, Decode it with Ciphey) goes through
  `sessionStorage`, never the URL.

## Security and privacy

- The production pages carry this policy (in a `<meta>` tag: GitHub Pages can't send
  headers):
  `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; worker-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'none'`.
  There are no inline scripts or styles (`public/theme.js`, which applies the saved theme
  before the first paint, is a file for this reason), and nothing can be sent anywhere but
  the site itself, which only serves static files.
- Everything the engines return is data: the pages insert it with `textContent`, never as
  HTML. pyWhat's descriptions are Rich markup (`[link=...]`), parsed in `src/lib/markup.ts`,
  where only `http(s)` links become links. The links in pyWhat's results open in a new tab
  with `rel="noopener noreferrer"`, and every page sets `referrer: no-referrer`.
- The only storage is `localStorage["ciphey-theme"]` (the theme button's choice) and the
  hand-off between tools in `sessionStorage`.
- The end-to-end test fails if any request leaves the site's origin, if the policy blocks
  anything, or if the console shows an error.

## Accessibility

The target is WCAG 2.2 AA.

- Every control has a label; hints and errors are tied to their fields with
  `aria-describedby` and `aria-invalid`. Results, errors and status changes are announced
  through a polite live region; the Identify panel is `aria-busy` while a newer text is on
  its way.
- Keyboard: a skip link, a visible focus ring on everything (3 px, 5.6:1 or more against
  every surface), Ctrl+Enter (⌘+Enter) to decode and Escape to cancel. Focus stays on the
  Decode button through a search, and the share dialog is a native `<dialog>`.
- Colour: the tokens are in `src/styles/base.css`. Text is at least 4.5:1 on every surface
  it's used on, and borders and focus rings at least 3:1, in both themes:

  | Pair | Light | Dark |
  | --- | ---: | ---: |
  | text on page, panel, field | 15.6, 16.9, 14.8 | 15.5, 14.2, 15.9 |
  | muted text on page, panel, field | 6.2, 6.7, 5.9 | 7.9, 7.2, 8.1 |
  | links on page, panel | 6.2, 6.7 | 10.5, 9.7 |
  | text on highlights (lowest of six) | 12.0 | 7.1 |
  | field borders on panel | 3.5 | 3.5 |
  | focus ring on page, panel, field | 5.9, 6.4, 5.6 | 9.0, 8.3, 9.3 |

- `prefers-reduced-motion` turns animation off, and the layout works from 320 px wide.
- The end-to-end test runs axe-core with the WCAG 2.0 to 2.2 A and AA rules and the best
  practices, on every page and state it reaches (empty, searching, results, nothing found,
  the share dialog, the filters), in both themes, at 1280 and 390 px wide, and fails on any
  violation. It also tabs through the Decode page and checks each stop has a visible focus.

## The end-to-end test

`tests/e2e/e2e.mjs` serves `dist/` the way GitHub Pages does (or tests a live copy with
`--url https://bee-san.github.io/Ciphey/`) and checks that:

- every Decode example decodes to its plaintext (`src/decode/examples.ts`; an example that
  needs a decoder Ciphey doesn't have yet, such as #1029's hash cracker, is hidden);
- the tree grows while a search runs, a search without a plaintext ends with advice,
  Escape cancels, a crib that isn't a valid regex is reported at the crib, Ctrl+Enter
  decodes, and a share link opens and runs its search;
- Identify finds and highlights an email address, an IP address, a CTF flag, a Bitcoin
  wallet and a URL, and its filters and sorting work;
- Is it language? says a sentence is language and a keyboard mash and a Caesar shift aren't;
- and the accessibility and privacy checks above pass.

The examples' inputs were made without Ciphey (`python3 scripts/make-examples.py` makes
them with Python's standard library and checks `examples.ts`), and a unit test recomputes
each one in JavaScript.

## Deploying

`.github/workflows/pages.yml` builds the site, runs the unit and end-to-end tests, and on a
push to `master` deploys it to GitHub Pages. It runs when `web/`, `wasm/`, Ciphey's sources
or its manifests change, and on pull requests that change them (build and test only).

To update a module: pyWhat's and gibberish-or-not's versions are in `engine/Cargo.toml`
(then `cargo update --manifest-path engine/Cargo.toml`); Ciphey's is the repository itself.
