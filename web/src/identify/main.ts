import "../styles/main.css";
import { count, fraction, plural } from "../lib/format";
import { parseMarkup } from "../lib/markup";
import type { IdentifyEvent, IdentifyMatch, IdentifyOptions, IdentifyRequest } from "../lib/protocol";
import { sortMatches, type SortKey } from "../lib/pywhat";
import { decodeHash } from "../lib/share";
import { assignRanges, segment } from "../lib/spans";
import { announce, byId, characterCount, copyButton, h, icon, readTextFile, wireFileInput } from "../shell/dom";
import { EngineClient, LatestRequest } from "../shell/engine";
import { handOff, pickUp } from "../shell/handoff";
import { initPage } from "../shell/page";
import { TokenField } from "./token-field";

initPage();

/** Larger texts are refused: identifying is as you type, and pyWhat checks every format. */
const MAX_TEXT_CHARS = 1_000_000;
/** The page draws this many cards at most (highlights cover every match up to MAX_RANGES). */
const MAX_CARDS = 200;
const MAX_RANGES = 5000;
const HIGHLIGHTS = 6;

const EXAMPLES: ReadonlyArray<{ label: string; text: string }> = [
  { label: "Email, IP and URL", text: "Email bee@skerritt.blog from 192.168.0.1 about https://github.com/bee-san/pyWhat" },
  { label: "CTF flag and coordinates", text: "52.6169586, -1.9779857 HTB{this is a flag} https://skerritt.blog" },
  { label: "Crypto wallets", text: "0x52908400098527886E0F7030069857D2E4169EE7 1KFHE7w8BhaENAswwryaoccDb6qcT6DbYY" },
  { label: "Network addresses", text: "Router 10.0.0.1 (00:1B:44:11:3A:B7)" },
  { label: "API key", text: "AIzaSyA00000000000000000000000000000000" },
];

const text = byId<HTMLTextAreaElement>("text");
const textCount = byId("text-count");
const textError = byId("text-error");
const backdrop = byId("backdrop");
const boundaryless = byId<HTMLInputElement>("boundaryless");
const minRarity = byId<HTMLInputElement>("min-rarity");
const maxRarity = byId<HTMLInputElement>("max-rarity");
const rarityError = byId("rarity-error");
const filtersSummary = byId("filters-summary");
const sort = byId<HTMLSelectElement>("sort");
const matchesList = byId<HTMLUListElement>("matches");
const matchCount = byId("match-count");
const emptyState = byId("matches-empty");
const noneState = byId("matches-none");
const engineStatus = byId("engine-status");
const filtersError = byId("filters-error");
const matchesPanel = byId("matches-panel");
const matchesError = byId("matches-error");

const include = new TokenField(byId("include-tokens"), byId<HTMLInputElement>("include-input"), "the tags to show", () => refresh());
const exclude = new TokenField(byId("exclude-tokens"), byId<HTMLInputElement>("exclude-input"), "the tags to hide", () => refresh());

// --- Engine ----------------------------------------------------------------------------------

const engine = new EngineClient<IdentifyRequest, IdentifyEvent>(
  () => new Worker(new URL("../workers/identify.worker.ts", import.meta.url), { type: "module", name: "pywhat" }),
  "pyWhat",
);
const latest = new LatestRequest<IdentifyRequest>((r) => engine.post(r));
let ready = false;
/** The text the shown matches are for. */
let shownText = "";
let matches: IdentifyMatch[] = [];
let ranges: ReturnType<typeof assignRanges> = [];
const marks = new Map<number, HTMLElement[]>();
let pendingText = "";

engine.on((event) => {
  switch (event.type) {
    case "ready": {
      ready = true;
      engineStatus.textContent = `pyWhat ${event.version} is ready · ${plural(event.tags.length, "tag")}`;
      byId("tag-list").replaceChildren(...event.tags.map((t) => h("option", { value: t })));
      refresh();
      return;
    }
    case "identified":
      if (latest.settle(event.id)) show(pendingText, event.matches);
      return;
    case "error":
      if (event.id === null) {
        engineStatus.replaceChildren(
          h("span", { class: "field__error" }, event.message),
          " ",
          h("button", { type: "button", class: "link-button", onclick: () => engine.restart() }, "Try again"),
        );
      } else if (latest.settle(event.id)) {
        showError(event.message);
      }
      return;
  }
});
engine.start();

// --- Filters ------------------------------------------------------------------------------------

function readFilters(): IdentifyOptions | null {
  const min = Number(minRarity.value);
  const max = Number(maxRarity.value);
  let message: string | null = null;
  if (minRarity.value.trim() === "" || maxRarity.value.trim() === "" || !Number.isFinite(min) || !Number.isFinite(max)) message = "Rarities are numbers from 0 to 1.";
  else if (min < 0 || max > 1 || min > 1 || max < 0) message = "Rarities are from 0 to 1.";
  else if (min > max) message = "The range starts above where it ends.";
  rarityError.textContent = message ?? "";
  rarityError.hidden = message === null;
  for (const el of [minRarity, maxRarity]) {
    if (message) el.setAttribute("aria-invalid", "true");
    else el.removeAttribute("aria-invalid");
  }
  if (message) return null;
  return { minRarity: min, maxRarity: max, include: include.values, exclude: exclude.values, boundaryless: boundaryless.checked };
}

function updateFiltersSummary(o: IdentifyOptions | null): void {
  if (!o) {
    filtersSummary.textContent = "Check the rarity range";
    return;
  }
  const parts = [`Rarity ${o.minRarity} to ${o.maxRarity}`];
  if (!o.boundaryless) parts.push("whole lines");
  if (o.include.length) parts.push(`only ${plural(o.include.length, "tag")}`);
  if (o.exclude.length) parts.push(`hiding ${count(o.exclude.length)}`);
  filtersSummary.textContent = parts.join(" · ");
}

for (const el of [boundaryless, minRarity, maxRarity]) el.addEventListener("input", () => refresh());
byId("reset-filters").addEventListener("click", () => {
  boundaryless.checked = true;
  minRarity.value = "0.1";
  maxRarity.value = "1";
  include.clear();
  exclude.clear();
  refresh();
  announce("Filters reset");
});
sort.addEventListener("change", () => render());

// --- Text -----------------------------------------------------------------------------------------

/**
 * While a newer text or filter is on its way to pyWhat, the matches shown are for the old
 * one: the panel says so (aria-busy, and the cards dim after a moment).
 */
function setBusy(busy: boolean): void {
  matchesPanel.setAttribute("aria-busy", String(busy));
}

let timer = 0;
text.addEventListener("input", () => {
  textCount.textContent = characterCount(text.value);
  syncBackdropText();
  setBusy(true);
  window.clearTimeout(timer);
  timer = window.setTimeout(refresh, 90);
});
text.addEventListener("scroll", () => {
  backdrop.scrollTop = text.scrollTop;
});
new ResizeObserver(() => {
  backdrop.scrollTop = text.scrollTop;
}).observe(text);

wireFileInput(byId("dropzone"), byId<HTMLInputElement>("file"), byId("open-file"), async (file) => {
  const read = await readTextFile(file, MAX_TEXT_CHARS);
  if ("error" in read) {
    showTextError(read.error);
    return;
  }
  setText(read.text);
  announce(`Opened ${file.name}`);
  text.focus();
});

byId("examples").replaceChildren(
  ...EXAMPLES.map((e) => h("button", { type: "button", class: "chip", onclick: () => setText(e.text) }, e.label)),
);

function setText(value: string): void {
  text.value = value;
  textCount.textContent = characterCount(value);
  syncBackdropText();
  refresh();
}

function showTextError(message: string | null): void {
  textError.textContent = message ?? "";
  textError.hidden = message === null;
  if (message) {
    text.setAttribute("aria-invalid", "true");
    announce(message);
  } else text.removeAttribute("aria-invalid");
}

/** Sends the current text and filters to pyWhat (the newest replaces any still waiting). */
function refresh(): void {
  const options = readFilters();
  updateFiltersSummary(options);
  if (!options) {
    setBusy(false);
    return;
  }
  const value = text.value;
  if (value.length > MAX_TEXT_CHARS) {
    showTextError(`That's ${count(value.length)} characters. pyWhat identifies up to ${count(MAX_TEXT_CHARS)} here.`);
    setBusy(false);
    return;
  }
  showTextError(null);
  if (value.trim() === "") {
    show("", []);
    return;
  }
  setBusy(true);
  if (!ready) return; // sent once pyWhat is ready
  pendingText = value;
  latest.request((id) => ({ type: "identify", id, text: value, options }));
}

// --- Results --------------------------------------------------------------------------------------

function show(forText: string, found: IdentifyMatch[]): void {
  setBusy(false);
  clearErrors();
  shownText = forText;
  matches = found;
  // Highlights are only right for the text they were found in
  ranges = forText === text.value ? assignRanges(forText, found, MAX_RANGES) : [];
  render();
  if (forText.trim() !== "") announce(found.length ? `${plural(found.length, "match", "matches")} found` : "Nothing found");
}

/**
 * pyWhat's errors: a tag or name it doesn't know goes under the filters (its message is
 * "Passed filter contains tags or names that are not used by 'what': {...}"), anything else
 * above the matches.
 */
function showError(message: string): void {
  setBusy(false);
  matches = [];
  ranges = [];
  shownText = "";
  render();
  emptyState.hidden = true;
  const unknown = /not used by 'what': \{?([^}]*)\}?/.exec(message);
  if (unknown) {
    // pyWhat names them in lower case: give the user's own spelling back
    const named = (unknown[1] ?? "").split(",").map((t) => t.trim().replace(/^'|'$/g, ""));
    const typed = [...include.values, ...exclude.values].filter((t) => named.includes(t.toLowerCase()));
    const list = typed.length ? typed.map((t) => `“${t}”`).join(", ") : named.join(", ");
    filtersError.textContent = `pyWhat has no tag or format called ${list}. Remove it to see matches.`;
    filtersError.hidden = false;
    byId<HTMLDetailsElement>("filters").open = true;
  } else {
    matchesError.replaceChildren(h("p", { class: "notice__title" }, "pyWhat couldn't identify this text."), h("p", {}, message));
    matchesError.hidden = false;
  }
}

function clearErrors(): void {
  filtersError.hidden = true;
  filtersError.textContent = "";
  matchesError.hidden = true;
  matchesError.replaceChildren();
}

const colour = (id: number) => `hl-${(id % HIGHLIGHTS) + 1}`;

function render(): void {
  const empty = shownText.trim() === "";
  emptyState.hidden = !empty;
  noneState.hidden = empty || matches.length > 0;
  matchesList.hidden = empty || matches.length === 0;
  matchCount.hidden = empty;
  matchCount.textContent = count(matches.length);

  const [key, reverse] = sortKey(sort.value);
  const sorted = sortMatches(matches, key, reverse);
  const cards = sorted.slice(0, MAX_CARDS).map(card);
  if (sorted.length > MAX_CARDS) {
    cards.push(h("li", { class: "field__hint" }, `The first ${MAX_CARDS} of ${count(sorted.length)} matches are shown. Filter by rarity or tag to narrow them down.`));
  }
  matchesList.replaceChildren(...cards);
  drawHighlights();
}

function sortKey(value: string): [SortKey, boolean] {
  switch (value) {
    case "rarity-reverse":
      return ["rarity", true];
    case "name":
      return ["name", false];
    case "matched":
      return ["matched", false];
    default:
      return ["rarity", false];
  }
}

function card(m: IdentifyMatch): HTMLLIElement {
  const nameId = `match-${m.id}`;
  const description = m.description
    ? h(
        "p",
        { class: "match__desc" },
        ...parseMarkup(m.description).map((p) =>
          p.kind === "link" ? h("a", { href: p.href, target: "_blank", rel: "noopener noreferrer" }, p.text) : p.text,
        ),
      )
    : null;
  const li = h(
    "li",
    { class: `match ${colour(m.id)}`, "data-id": m.id },
    h(
      "div",
      { class: "match__head" },
      h("h3", { class: "match__name", id: nameId }, m.name),
      h(
        "span",
        { class: "rarity", title: "Rarity: 1 for formats that little else looks like" },
        h("span", { class: "rarity__bar", "aria-hidden": "true" }, rarityFill(m.rarity)),
        `Rarity ${fraction(m.rarity)}`,
      ),
    ),
    h(
      "p",
      { class: "match__matched" },
      h("code", {}, m.matched),
      m.fragment ? h("span", { class: "badge", title: "This match is part of a longer word or match" }, "inside longer text") : null,
    ),
    description,
    m.tags.length ? h("ul", { class: "tags", "aria-label": "Tags" }, ...m.tags.map((t) => h("li", {}, t))) : null,
    m.exploit
      ? h("details", { class: "match__exploit" }, h("summary", {}, "How to use or check it"), h("pre", {}, m.exploit))
      : null,
    h(
      "div",
      { class: "match__actions" },
      copyButton("Copy", () => m.matched),
      m.link
        ? h("a", { href: m.link, target: "_blank", rel: "noopener noreferrer" }, "Look it up", icon("external"), h("span", { class: "visually-hidden" }, " (opens another site)"))
        : null,
      h(
        "button",
        {
          type: "button",
          class: "link-button",
          onclick: () => {
            exclude.add(m.name);
            byId<HTMLDetailsElement>("filters").open = true;
          },
        },
        "Hide this format",
      ),
    ),
  );
  li.setAttribute("aria-labelledby", nameId);
  const on = () => activate(m.id);
  const off = () => activate(null);
  li.addEventListener("mouseenter", on);
  li.addEventListener("mouseleave", off);
  li.addEventListener("focusin", on);
  li.addEventListener("focusout", off);
  return li;
}

function rarityFill(rarity: number): HTMLElement {
  const fill = h("span", { class: "rarity__fill" });
  fill.style.width = `${Math.round(Math.max(0, Math.min(1, rarity)) * 100)}%`;
  return fill;
}

// --- Highlights -------------------------------------------------------------------------------------

/** The backdrop's text without marks (while the next result is on its way). */
function syncBackdropText(): void {
  if (text.value !== shownText) {
    marks.clear();
    backdrop.replaceChildren(text.value + "\n");
  }
}

function drawHighlights(): void {
  marks.clear();
  if (shownText !== text.value) {
    syncBackdropText();
    return;
  }
  const pieces: Array<Node | string> = [];
  for (const s of segment(shownText.length, ranges)) {
    const piece = shownText.slice(s.start, s.end);
    if (s.ids.length === 0) {
      pieces.push(piece);
      continue;
    }
    const mark = h("mark", { class: colour(s.ids[0] as number) }, piece);
    for (const id of s.ids) {
      const list = marks.get(id) ?? [];
      list.push(mark);
      marks.set(id, list);
    }
    pieces.push(mark);
  }
  // A trailing newline keeps the backdrop's last line as tall as the textarea's
  pieces.push("\n");
  backdrop.replaceChildren(...pieces);
  backdrop.scrollTop = text.scrollTop;
}

function activate(id: number | null): void {
  for (const li of matchesList.querySelectorAll(".match.is-active")) li.classList.remove("is-active");
  for (const m of backdrop.querySelectorAll("mark")) {
    m.classList.remove("is-active", "is-dim");
    if (id !== null) m.classList.add("is-dim");
  }
  if (id === null) return;
  matchesList.querySelector(`.match[data-id="${id}"]`)?.classList.add("is-active");
  for (const m of marks.get(id) ?? []) {
    m.classList.remove("is-dim");
    m.classList.add("is-active");
  }
}

// --- A link with text -------------------------------------------------------------------------------

const shared = pickUp() ?? decodeHash(location.hash).get("text");
if (shared) setText(shared.slice(0, MAX_TEXT_CHARS));
byId("decode-link").addEventListener("click", () => handOff(text.value));
updateFiltersSummary(readFilters());
textCount.textContent = characterCount(text.value);
