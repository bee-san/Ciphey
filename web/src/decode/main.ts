import "../styles/main.css";
import { count, duration, plural, preview } from "../lib/format";
import type { DecodeEvent, DecodeOptions, DecodeRequest, DecodeResult, SearchStatus, SearchUpdate, Sensitivity } from "../lib/protocol";
import { SENSITIVITIES } from "../lib/protocol";
import { choiceField, decodeHash, intField, MAX_SHARE_CHARS, shareUrl } from "../lib/share";
import { announce, byId, characterCount, copyButton, copyText, h, icon, readTextFile, responsiveLabel, wireFileInput } from "../shell/dom";
import { EngineClient } from "../shell/engine";
import { handOff, pickUp } from "../shell/handoff";
import { initPage } from "../shell/page";
import { EXAMPLES } from "./examples";
import { TreeView } from "./tree-view";
import {
  checkCrib,
  checkInput,
  checkTimeout,
  CRIB_INVALID,
  decoderName,
  MAX_INPUT_CHARS,
  optionsSummary,
  pathSpeech,
  pathText,
  stepLabel,
  verdictSentence,
} from "./words";

initPage();

const form = byId<HTMLFormElement>("decode-form");
const input = byId<HTMLTextAreaElement>("input");
const inputCount = byId("input-count");
const inputError = byId("input-error");
const examples = byId("examples");
const options = byId<HTMLDetailsElement>("options");
const optionsSummaryEl = byId("options-summary");
const timeout = byId<HTMLInputElement>("timeout");
const timeoutError = byId("timeout-error");
const regex = byId<HTMLInputElement>("regex");
const regexError = byId("regex-error");
const topResults = byId<HTMLInputElement>("top-results");
const decodeButton = byId<HTMLButtonElement>("decode");
const cancelButton = byId<HTMLButtonElement>("cancel");
const clearButton = byId<HTMLButtonElement>("clear");
const engineStatus = byId("engine-status");
const outputMeta = byId("output-meta");
const outputEmpty = byId("output-empty");
const searchBox = byId("search");
const searchText = byId("search-text");
const searchStats = byId("search-stats");
const searchSpinner = byId("search-spinner");
const progress = byId<HTMLProgressElement>("search-progress");
const resultBox = byId("result");
const treePanel = byId<HTMLDetailsElement>("tree-panel");
const treeSummary = byId("tree-summary");
const treeHint = byId("tree-hint");
const tree = new TreeView(byId<HTMLUListElement>("tree"));
const shareDialog = byId<HTMLDialogElement>("share-dialog");
const shareInput = byId<HTMLInputElement>("share-url");

// --- The engine ---------------------------------------------------------------------------

interface EngineInfo {
  version: string;
  decoders: string[];
  live: boolean;
  reusable: boolean;
}

const engine = new EngineClient<DecodeRequest, DecodeEvent>(
  () => new Worker(new URL("../workers/decode.worker.ts", import.meta.url), { type: "module", name: "ciphey" }),
  "Ciphey",
);
let info: EngineInfo | null = null;
let ready = false;
let loadError: string | null = null;

/** The search the page is showing. */
interface Search {
  id: number;
  input: string;
  options: DecodeOptions;
  started: number;
  results: DecodeResult[];
  expanded: number;
  queued: number;
  depth: number;
  memoryBytes: number;
  frame: number;
}

/**
 * After a search that left the module holding more than this, the worker is replaced:
 * WebAssembly memory is never given back, and a phone may close a tab that holds too much.
 */
const FRESH_WORKER_ABOVE = 512 * 1024 ** 2;
let search: Search | null = null;
let waiting: DecodeRequest | null = null;
let nextId = 1;
/** A search told to stop, and the timer that restarts the worker if it doesn't answer. */
let cancelling: number | null = null;
let cancelTimer = 0;
/** The decode request the running worker was given for the search shown, if any. */
let sent: DecodeRequest | null = null;

engine.on((event) => {
  switch (event.type) {
    case "ready":
      ready = true;
      loadError = null;
      info = {
        version: event.version,
        // Names and tags, for the examples that need a decoder
        decoders: event.decoders.map((d) => [d.name, ...d.tags].join(" ")),
        live: event.live,
        reusable: event.reusable,
      };
      showEngineReady();
      if (waiting) {
        const request = waiting;
        waiting = null;
        // The time limit starts when Ciphey starts searching, not while it downloads
        if (search && request.type === "decode" && request.id === search.id) search.started = performance.now();
        send(request);
      }
      return;
    case "update":
      if (search && event.id === search.id) onUpdate(event.update);
      return;
    case "cancelled":
      if (event.id === cancelling) {
        window.clearTimeout(cancelTimer);
        cancelling = null;
      }
      return;
    case "error":
      if (event.id === null && !ready) {
        // Ciphey didn't load: a search waiting for it can't run
        loadError = event.message;
        waiting = null;
        showEngineError();
        if (search) finish("error", event.message);
      } else if (search && (event.id === search.id || event.id === null)) {
        finish("error", event.message);
      }
      return;
  }
});
engine.start();

function showEngineReady(): void {
  engineStatus.replaceChildren(`Ciphey ${info?.version} is ready · ${plural(info?.decoders.length ?? 0, "decoder")}`);
  byId("decoder-count").textContent = String(info?.decoders.length ?? "over 80");
  renderExamples();
}

function showEngineError(): void {
  engineStatus.replaceChildren(
    h("span", { class: "field__error" }, loadError ?? "Couldn't load Ciphey."),
    " ",
    h("button", { type: "button", class: "link-button", onclick: () => restartEngine() }, "Try again"),
  );
}

/** Gives the worker a search, or keeps it until the worker is ready. */
function send(request: DecodeRequest): void {
  if (ready) {
    engine.post(request);
    if (request.type === "decode") sent = request;
  } else {
    waiting = request;
    if (loadError) restartEngine();
  }
}

/**
 * Starts a fresh worker. A search the old one had been given (behind a step that wouldn't
 * stop) starts again on the new one, from the beginning.
 */
function restartEngine(): void {
  ready = false;
  loadError = null;
  cancelling = null;
  window.clearTimeout(cancelTimer);
  if (search && sent?.type === "decode" && sent.id === search.id) {
    waiting = sent;
    search.started = performance.now();
    search.results = [];
    tree.reset();
  }
  sent = null;
  engineStatus.replaceChildren(h("span", { class: "spinner", "aria-hidden": "true" }), "Loading Ciphey…");
  engine.restart();
}

// --- Options --------------------------------------------------------------------------------

function sensitivity(): Sensitivity {
  const checked = form.querySelector<HTMLInputElement>('input[name="sensitivity"]:checked');
  return (checked?.value as Sensitivity | undefined) ?? "medium";
}

function setSensitivity(value: Sensitivity): void {
  const radio = form.querySelector<HTMLInputElement>(`input[name="sensitivity"][value="${value}"]`);
  if (radio) radio.checked = true;
}

function readOptions(): DecodeOptions | null {
  let ok = true;
  const t = checkTimeout(timeout.value);
  setFieldError(timeout, timeoutError, t.ok ? null : t.message);
  const c = checkCrib(regex.value);
  setFieldError(regex, regexError, c.ok ? null : c.message);
  if (!t.ok || !c.ok) {
    ok = false;
    options.open = true;
    (t.ok ? regex : timeout).focus();
  }
  return ok && t.ok ? { timeout: t.value, regex: regex.value, topResults: topResults.checked, sensitivity: sensitivity() } : null;
}

function updateOptionsSummary(): void {
  const t = checkTimeout(timeout.value);
  optionsSummaryEl.textContent = optionsSummary({
    timeout: t.ok ? t.value : 5,
    regex: regex.value,
    topResults: topResults.checked,
    sensitivity: sensitivity(),
  });
}

function setFieldError(field: HTMLElement, error: HTMLElement, message: string | null): void {
  error.textContent = message ?? "";
  error.hidden = message === null;
  if (message === null) field.removeAttribute("aria-invalid");
  else field.setAttribute("aria-invalid", "true");
}

for (const el of [timeout, regex, topResults, ...form.querySelectorAll<HTMLInputElement>('input[name="sensitivity"]')]) {
  el.addEventListener("input", () => {
    updateOptionsSummary();
    if (el === timeout && timeoutError.textContent) setFieldError(timeout, timeoutError, null);
    if (el === regex && regexError.textContent) setFieldError(regex, regexError, null);
  });
}

// --- Input ----------------------------------------------------------------------------------

let sharedHash = location.hash.length > 1;

function onInputChanged(): void {
  inputCount.textContent = characterCount(input.value);
  if (inputError.textContent) setFieldError(input, inputError, null);
  // A shared link's input stays in the address bar only until the input changes
  if (sharedHash) {
    history.replaceState(null, "", location.pathname + location.search);
    sharedHash = false;
  }
}
input.addEventListener("input", onInputChanged);

wireFileInput(byId("dropzone"), byId<HTMLInputElement>("file"), byId("open-file"), async (file) => {
  const read = await readTextFile(file, MAX_INPUT_CHARS);
  if ("error" in read) {
    setFieldError(input, inputError, read.error);
    announce(read.error);
    return;
  }
  input.value = read.text.replace(/\r?\n$/, "");
  onInputChanged();
  announce(`Opened ${file.name}`);
  input.focus();
});

let shownExamples = "";

/** Draws the example buttons, again only if the set changed (so a focused one stays focused). */
function renderExamples(): void {
  const available = EXAMPLES.filter((e) => !e.needs || (info?.decoders.some((d) => e.needs?.test(d)) ?? false));
  const key = available.map((e) => e.id).join(" ");
  if (key === shownExamples) return;
  shownExamples = key;
  examples.replaceChildren(
    ...available.map((example) =>
      h(
        "button",
        {
          type: "button",
          class: "chip",
          "data-example": example.id,
          onclick: () => {
            input.value = example.input;
            onInputChanged();
            start();
          },
        },
        example.label,
      ),
    ),
  );
}
renderExamples();

clearButton.addEventListener("click", () => {
  if (search) cancel();
  input.value = "";
  onInputChanged();
  showOnly(outputEmpty);
  treePanel.hidden = true;
  outputMeta.textContent = "";
  input.focus();
  announce("Cleared");
});

// --- Searching ------------------------------------------------------------------------------

form.addEventListener("submit", (event) => {
  event.preventDefault();
  start();
});

document.addEventListener("keydown", (event) => {
  if (event.key === "Enter" && (event.ctrlKey || event.metaKey) && !shareDialog.open) {
    event.preventDefault();
    start();
  } else if (event.key === "Escape" && search && !shareDialog.open) {
    event.preventDefault();
    cancel();
  }
});

cancelButton.addEventListener("click", () => cancel());

function showOnly(...shown: HTMLElement[]): void {
  for (const el of [outputEmpty, searchBox, resultBox]) el.hidden = !shown.includes(el);
}

function start(): void {
  const check = checkInput(input.value);
  if (!check.ok) {
    setFieldError(input, inputError, check.message);
    announce(check.message);
    input.focus();
    return;
  }
  setFieldError(input, inputError, null);
  const opts = readOptions();
  if (!opts) return;
  if (search) cancel(false);

  const request: DecodeRequest = { type: "decode", id: nextId++, input: input.value, options: opts };
  search = {
    id: request.id,
    input: request.input,
    options: opts,
    started: performance.now(),
    results: [],
    expanded: 0,
    queued: 0,
    depth: 0,
    memoryBytes: 0,
    frame: 0,
  };
  tree.reset();
  treePanel.hidden = false;
  treePanel.open = true;
  treeSummary.textContent = "";
  treeHint.textContent = "Each row is a text Ciphey ran every decoder on, under the text it came from.";
  outputMeta.textContent = "";
  resultBox.replaceChildren();
  showOnly(searchBox);
  searchSpinner.hidden = false;
  searchText.textContent = ready ? "Searching…" : "Loading Ciphey, then searching…";
  searchStats.textContent = "";
  progress.max = opts.timeout * 1000;
  progress.value = 0;
  cancelButton.hidden = false;
  if (window.matchMedia("(max-width: 959px)").matches) byId("output").scrollIntoView({ block: "start" });
  announce("Decoding…");

  send(request);
  tick();
}

/** Moves the clock and the progress bar on while the search runs. */
function tick(): void {
  if (!search) return;
  if (waiting) {
    // No time is used until Ciphey has loaded and starts searching
    searchText.textContent = "Loading Ciphey, then searching…";
    progress.removeAttribute("value");
  } else {
    const elapsed = performance.now() - search.started;
    progress.value = Math.min(elapsed, progress.max);
    const found = search.results.length ? ` · ${plural(search.results.length, "plaintext")} found` : "";
    // A decoder that has started finishes even if the time limit passes meanwhile
    const clock =
      elapsed < search.options.timeout * 1000 ? `${duration(elapsed)} of ${search.options.timeout} s` : "time's up, finishing the last step";
    searchText.textContent = `Searching… ${clock}${found}`;
  }
  searchStats.textContent = search.expanded
    ? `${plural(search.expanded, "text")} tried · up to ${plural(search.depth, "layer")} deep · ${count(search.queued)} more to try`
    : "";
  treeSummary.textContent = tree.drawn ? `${count(tree.drawn)} drawn` : "";
  search.frame = requestAnimationFrame(tick);
}

function onUpdate(update: SearchUpdate): void {
  if (!search) return;
  search.expanded = update.expanded;
  search.queued = update.queued;
  search.depth = update.depth ?? search.depth;
  search.memoryBytes = update.memoryBytes ?? search.memoryBytes;
  if (update.nodes.length) tree.add(update.nodes);
  for (const r of update.results) {
    search.results.push(r);
    tree.addResult(r);
  }
  if (update.status !== "running") finish(update.status, null, update.elapsedMs);
}

/**
 * Stops the search. The worker stops between two steps; a step can run long (a slow
 * decoder on a big input), so if the worker hasn't answered in 300 ms it's restarted.
 */
function cancel(say = true): void {
  if (!search) return;
  const s = search;
  const elapsed = performance.now() - s.started;
  if (waiting) waiting = null;
  else if (ready) {
    cancelling = s.id;
    sent = null;
    engine.post({ type: "cancel", id: s.id });
    window.clearTimeout(cancelTimer);
    cancelTimer = window.setTimeout(() => {
      if (cancelling !== s.id) return;
      cancelling = null;
      restartEngine();
    }, 300);
  }
  finish("cancelled", null, elapsed, say);
}

type Ending = SearchStatus | "cancelled" | "error";

function finish(status: Ending, message: string | null, elapsedMs?: number, speak = true): void {
  const s = search;
  if (!s) return;
  cancelAnimationFrame(s.frame);
  search = null;
  const hadFocus = document.activeElement === cancelButton;
  cancelButton.hidden = true;
  if (hadFocus) decodeButton.focus();
  const elapsed = elapsedMs ?? performance.now() - s.started;

  // A crashed module can't search again, and one that grew its memory can't give it back:
  // start a fresh one for the next search
  if (
    (status === "error" && /^Ciphey (crashed|ran out of memory)/.test(message ?? "")) ||
    status === "memory_full" ||
    (status !== "cancelled" && s.memoryBytes > FRESH_WORKER_ABOVE)
  ) {
    restartEngine();
  }

  tree.finish();
  treePanel.hidden = tree.size === 0;
  treeSummary.textContent = tree.size ? `${plural(s.expanded || tree.size, "text")} tried${tree.drawn < tree.size ? `, ${count(tree.drawn)} drawn` : ""}` : "";
  const found = s.results.length > 0 && status !== "error";
  treeHint.textContent = [
    "Each row is a text Ciphey ran every decoder on, under the text it came from.",
    tree.drawn < tree.size ? `The first ${count(tree.drawn)} rows are drawn${found ? ", and every row on the way to a plaintext" : ""}.` : null,
    found ? "The highlighted branch leads to the plaintext." : null,
  ]
    .filter(Boolean)
    .join(" ");

  showOnly(resultBox);
  outputMeta.textContent = `${duration(elapsed)}${s.expanded ? ` · ${plural(s.expanded, "text")} tried` : ""}`;
  // Plaintexts found before a cancel, the time limit or an error ("Find every plaintext")
  // still count
  if (s.results.length) {
    renderResults(s);
    const why =
      status === "cancelled"
        ? `Search cancelled after ${duration(elapsed)}`
        : status === "memory_full"
          ? `Ciphey stopped after ${duration(elapsed)} to stay within your browser's memory`
          : status === "timed_out"
            ? `The time limit (${s.options.timeout} s) ended the search`
            : status === "error"
              ? `The search stopped after ${duration(elapsed)}: ${message ?? "an error"}`
              : null;
    if (why) resultBox.prepend(h("p", { class: "field__hint" }, `${why}; these were found before it.`));
    const first = s.results[0] as DecodeResult;
    const how = first.path.length ? ` Path: ${pathSpeech(first.path)}.` : " The input is already plaintext.";
    if (speak) announce(`${why ? `${why}. ` : ""}Found the plaintext in ${duration(first.elapsedMs)}: ${preview(first.plaintext, 140)}.${how}`);
    return;
  }
  if (status === "error" && message && /regex|crib/i.test(message) && !loadError) {
    options.open = true;
    setFieldError(regex, regexError, CRIB_INVALID);
    resultBox.replaceChildren(
      h(
        "div",
        { class: "notice notice--error" },
        h("p", { class: "notice__title" }, "Check the crib."),
        h("p", {}, "It isn't a valid regular expression, so Ciphey didn't search. The fix is under Options."),
      ),
    );
    regex.focus(); // also scrolls it into view on a phone
    announce(CRIB_INVALID);
    return;
  }
  resultBox.replaceChildren(nothing(status, message, s, elapsed));
  // An error notice is an alert, which a screen reader says by itself
  if (speak && status !== "error") announce(resultBox.querySelector(".notice__title")?.textContent ?? "The search ended");
}

function nothing(status: Ending, message: string | null, s: Search, elapsed: number): HTMLElement {
  switch (status) {
    case "cancelled":
      return h(
        "div",
        { class: "notice" },
        h("p", { class: "notice__title" }, `Search cancelled after ${duration(elapsed)}.`),
        h("p", {}, "Press Decode to search again from the start."),
      );
    case "error":
      return h(
        "div",
        { class: "notice notice--error", role: "alert" },
        h("p", { class: "notice__title" }, loadError ? "Ciphey didn't load, so it couldn't search." : "Ciphey couldn't search this input."),
        h("p", {}, message ?? "Something went wrong."),
        // Downloads Ciphey again, then runs this search
        loadError ? h("div", {}, h("button", { type: "button", class: "button button--small", onclick: () => start() }, "Try again")) : null,
      );
    case "memory_full":
      return h(
        "div",
        { class: "notice" },
        h("p", { class: "notice__title" }, `Ciphey stopped after ${duration(elapsed)}, before your browser ran out of memory.`),
        h(
          "ul",
          {},
          h("li", {}, `It had found no plaintext, and ${plural(s.queued, "branch", "branches")} were still waiting to be tried.`),
          h("li", {}, s.options.regex ? "Check the crib: with one set, only text it matches is accepted." : "If you know part of the answer (a flag format, a word), set it as a crib under Options."),
          h("li", {}, "Plaintext that isn't English is often missed. A crib helps there too."),
        ),
      );
    default: {
      const title =
        status === "not_found"
          ? "Ciphey tried everything it knows and found no plaintext."
          : `No plaintext found in ${s.options.timeout} ${s.options.timeout === 1 ? "second" : "seconds"}.`;
      const tips = [
        status === "timed_out" && s.options.timeout < 60 ? "Give it more time: raise the time limit under Options." : null,
        s.options.regex
          ? "Check the crib: with one set, only text it matches is accepted."
          : "If you know part of the answer (a flag format, a word), set it as a crib under Options.",
        "Plaintext that isn't English is often missed. A crib helps there too.",
        h("span", {}, "Not sure it's encoded? ", identifyLink(s.input, "See what pyWhat identifies in it"), "."),
      ];
      return h(
        "div",
        { class: "notice" },
        h("p", { class: "notice__title" }, title),
        h("ul", {}, ...tips.filter((t) => t !== null).map((t) => h("li", {}, t))),
      );
    }
  }
}

function renderResults(s: Search): void {
  const [first, ...rest] = s.results as [DecodeResult, ...DecodeResult[]];
  const blocks: HTMLElement[] = [renderResult(first, s, true)];
  if (rest.length) {
    // Usually decoder output that a checker happened to accept: folded, and not as certain
    blocks.push(h("h3", { class: "result__more-title" }, `Ciphey's checkers also accepted ${rest.length === 1 ? "this" : `these ${rest.length}`}`));
    blocks.push(
      h(
        "ol",
        { class: "result__more" },
        ...rest.map((r) =>
          h(
            "li",
            {},
            h(
              "details",
              { class: "result__fold" },
              h("summary", {}, h("code", {}, preview(r.plaintext, 60)), h("span", { class: "field__meta" }, r.path.length ? pathText(r.path) : "the input")),
              renderResult(r, s, false),
            ),
          ),
        ),
      ),
    );
  }
  resultBox.replaceChildren(...blocks);
}

function renderResult(r: DecodeResult, s: Search, main: boolean): HTMLElement {
  const verdict = verdictSentence(r);
  const plaintextId = `plaintext-${s.id}-${Math.round(r.elapsedMs)}-${main ? "main" : "more"}`;
  const already = r.path.length === 0;
  const head = h(
    "div",
    { class: "result__head" },
    main
      ? h("span", { class: "badge badge--success" }, icon("check"), already ? "Already plaintext" : "Plaintext found")
      : h("span", { class: "badge" }, "Also accepted"),
    h("span", { class: "field__meta" }, already ? `checked in ${duration(r.elapsedMs)}` : `in ${duration(r.elapsedMs)} · ${plural(r.path.length, "layer")}`),
  );
  // Focusable, so a long plaintext can be scrolled with the keyboard
  const text = h("pre", { class: "plaintext", id: plaintextId, tabindex: 0, role: "group", "aria-label": "Plaintext" }, r.plaintext);
  const actions = h(
    "div",
    { class: "actions result__actions" },
    copyButton("Copy plaintext", () => r.plaintext, { spoken: "Plaintext copied", short: "Copy" }),
    already ? null : copyButton("Copy path", () => pathText(r.path), { spoken: "Path copied" }),
    main ? shareButton(s) : null,
    main ? identifyLink(r.plaintext, "Identify the plaintext", "button button--small", "Identify") : null,
  );
  const steps = h(
    "ol",
    { class: "path", "aria-label": "Path, from the input to the plaintext" },
    h(
      "li",
      { class: "path__step path__step--input" },
      h("div", { class: "path__head" }, h("span", { class: "path__decoder" }, "Input")),
      h("code", { class: "path__text" }, preview(s.input, 160)),
    ),
    ...r.path.map((step, i) => {
      const last = i === r.path.length - 1;
      return h(
        "li",
        { class: `path__step${last ? " path__step--last" : ""}` },
        h(
          "div",
          { class: "path__head" },
          h("span", { class: "path__decoder" }, decoderName(step.decoder)),
          step.key ? h("span", { class: "badge badge--accent" }, `key ${step.key}`) : null,
        ),
        h("code", { class: "path__text" }, preview(last ? r.plaintext : (step.text ?? ""), 160)),
      );
    }),
  );
  return h(
    "div",
    { class: main ? "result__main" : "result__other" },
    head,
    text,
    verdict ? h("p", { class: "result__verdict" }, verdict) : null,
    actions,
    already ? h("p", { class: "field__hint" }, "Ciphey's checkers accept the input as it is, so there was nothing to decode.") : null,
    already ? null : h("h3", { class: "result__path-title" }, "Path ", h("span", { class: "field__meta" }, r.path.map(stepLabel).join(" → "))),
    already ? null : steps,
  );
}

/** A link to the Identify page that takes `text` along (sessionStorage, not the URL). */
function identifyLink(text: string, label: string, cls = "", short?: string): HTMLAnchorElement {
  return h(
    "a",
    { href: "identify/", class: cls || null, "aria-label": short ? label : null, onclick: () => handOff(text) },
    cls ? icon("search") : null,
    responsiveLabel(label, short),
  );
}

// --- Sharing ----------------------------------------------------------------------------------

function shareFields(s: Search): Record<string, string | number | boolean | null> {
  return {
    input: s.input,
    timeout: s.options.timeout === 5 ? null : s.options.timeout,
    crib: s.options.regex || null,
    sensitivity: s.options.sensitivity === "medium" ? null : s.options.sensitivity,
    all: s.options.topResults,
  };
}

function shareButton(s: Search): HTMLElement {
  const tooLong = Array.from(s.input).length > MAX_SHARE_CHARS;
  const button = h(
    "button",
    {
      type: "button",
      class: "button button--small",
      disabled: tooLong,
      "aria-label": "Share link…",
      title: tooLong ? `Inputs over ${MAX_SHARE_CHARS.toLocaleString("en")} characters are too long for a link` : null,
    },
    icon("link"),
    responsiveLabel("Share link…", "Share…"),
  );
  button.addEventListener("click", () => {
    shareInput.value = shareUrl(location.href, shareFields(s));
    shareDialog.showModal();
    shareInput.select();
  });
  return button;
}

byId("share-close").addEventListener("click", () => shareDialog.close());
byId("share-copy").addEventListener("click", async () => {
  const ok = await copyText(shareInput.value);
  announce(ok ? "Link copied to the clipboard" : "Couldn't copy the link");
  if (ok) shareDialog.close();
});

// --- A shared link opened -----------------------------------------------------------------------

function openShared(): void {
  const fields = decodeHash(location.hash);
  const shared = fields.get("input");
  if (!shared) {
    sharedHash = false;
    return;
  }
  input.value = shared.slice(0, MAX_INPUT_CHARS);
  inputCount.textContent = characterCount(input.value);
  const t = intField(fields, "timeout", 1, 60);
  if (t) timeout.value = String(t);
  const crib = fields.get("crib");
  if (crib) regex.value = crib.slice(0, 1000);
  const sens = choiceField(fields, "sensitivity", SENSITIVITIES);
  if (sens) setSensitivity(sens);
  if (fields.get("all") === "1") topResults.checked = true;
  if (t || crib || sens || topResults.checked) options.open = true;
  updateOptionsSummary();
  start();
}

// ⌘ + Enter is the habit on a Mac (both work everywhere)
if (/Mac|iPhone|iPad/.test(navigator.userAgent)) byId("shortcut-hint").textContent = "⌘ + Enter decodes.";

updateOptionsSummary();
const handedOver = pickUp();
if (handedOver) input.value = handedOver.slice(0, MAX_INPUT_CHARS);
inputCount.textContent = characterCount(input.value);
openShared();
