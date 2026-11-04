import "../styles/main.css";
import { count, fraction, plural } from "../lib/format";
import { parseMarkup, safeHref } from "../lib/markup";
import { MAX_MATCHES } from "../lib/pieces";
import type { IdentifyEvent, IdentifyMatch, IdentifyOptions, IdentifyRequest } from "../lib/protocol";
import { type Card, formatColours, groupMatches, sortMatches, type SortKey } from "../lib/pywhat";
import { decodeHash } from "../lib/share";
import { assignRanges, segment } from "../lib/spans";
import { announce, byId, characterCount, copyButton, h, icon, readTextFile, wireFileInput } from "../shell/dom";
import { EngineClient, LatestRequest } from "../shell/engine";
import { handOff, pickUp } from "../shell/handoff";
import { initPage } from "../shell/page";
import { TokenField } from "./token-field";

initPage();

/**
 * Larger texts are refused: identifying runs as you type, and pyWhat's output is about 11 KB
 * of JSON per match (each carries its format's whole entry), so 100,000 characters dense
 * with identifiers already make 72 MB of it (0.7 s to identify, 0.2 s to parse, measured).
 */
const MAX_TEXT_CHARS = 100_000;
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
/** Each format's highlight colour (see formatColours). */
let colours = new Map<string, number>();
let lastSaid = "";
let sayTimer = 0;

engine.on((event) => {
  switch (event.type) {
    case "ready": {
      ready = true;
      engineStatus.textContent = `pyWhat ${event.version} is ready`;
      byId("tag-list").replaceChildren(...event.tags.map((t) => h("option", { value: t })));
      refresh();
      return;
    }
    case "identified":
      if (latest.settle(event.id)) show(pendingText, event.matches, event.capped);
      return;
    case "error":
      if (event.id === null) {
        ready = false;
        engineStatus.replaceChildren(h("span", { class: "field__error" }, event.message), " ", h("button", { type: "button", class: "link-button", onclick: () => restart() }, "Try again"));
      } else {
        const current = latest.settle(event.id);
        // A crashed module can't identify again: a new worker, and nothing left in flight
        if (event.crashed) restart();
        if (current || event.crashed) showError(event.message);
      }
      return;
  }
});
engine.start();

/** A fresh worker: after a crash, or Try again. Requests in flight are forgotten. */
function restart(): void {
  ready = false;
  latest.reset();
  engineStatus.replaceChildren(h("span", { class: "spinner", "aria-hidden": "true" }), "Loading pyWhat…");
  engine.restart();
}

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
  text.focus({ preventScroll: true });
  showMatchesPanel();
});

/** On a phone the matches are below the text: bring them into view. */
function showMatchesPanel(): void {
  if (window.matchMedia("(max-width: 959px)").matches) matchesPanel.scrollIntoView({ block: "start" });
}

byId("examples").replaceChildren(
  ...EXAMPLES.map((e) =>
    h(
      "button",
      {
        type: "button",
        class: "chip",
        onclick: () => {
          setText(e.text);
          showMatchesPanel();
        },
      },
      e.label,
    ),
  ),
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
    // A reply still on its way is for other filters
    latest.reset();
    setBusy(false);
    return;
  }
  const value = text.value;
  // Counted by character, as the counter does (an emoji is one)
  const chars = Array.from(value).length;
  if (chars > MAX_TEXT_CHARS) {
    latest.reset();
    const message = `That's ${count(chars)} characters. pyWhat identifies up to ${count(MAX_TEXT_CHARS)} here.`;
    showTextError(message);
    // The matches shown were for another text: take them away
    matches = [];
    ranges = [];
    shownText = "";
    render();
    emptyState.hidden = true;
    matchesError.replaceChildren(h("p", { class: "notice__title" }, "The text is too long to identify."), h("p", {}, message));
    matchesError.hidden = false;
    setBusy(false);
    return;
  }
  showTextError(null);
  if (value.trim() === "") {
    // A reply still on its way is for the text that was cleared
    latest.reset();
    show("", []);
    return;
  }
  setBusy(true);
  if (!ready) return; // sent once pyWhat is ready
  pendingText = value;
  latest.request((id) => ({ type: "identify", id, text: value, options }));
}

// --- Results --------------------------------------------------------------------------------------

let capped = false;

function show(forText: string, found: IdentifyMatch[], wasCapped = false): void {
  capped = wasCapped;
  setBusy(false);
  clearErrors();
  shownText = forText;
  matches = found;
  // Highlights are only right for the text they were found in
  ranges = forText === text.value ? assignRanges(forText, found, MAX_RANGES) : [];
  colours = formatColours(found, HIGHLIGHTS);
  render();
  // Said once typing pauses, and only when it changes, as the language panel does
  window.clearTimeout(sayTimer);
  if (forText.trim() === "") lastSaid = "";
  else {
    const said = found.length ? `${plural(found.length, "match", "matches")} found` : "Nothing found";
    sayTimer = window.setTimeout(() => {
      if (said !== lastSaid) announce(said);
      lastSaid = said;
    }, 900);
  }
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
    if (/Filters/.test(message)) byId<HTMLDetailsElement>("filters").open = true;
  }
}

function clearErrors(): void {
  filtersError.hidden = true;
  filtersError.textContent = "";
  matchesError.hidden = true;
  matchesError.replaceChildren();
}

/** The highlight colour of a format: one per kind of thing. */
const colourOf = (name: string) => `hl-${(colours.get(name) ?? 0) + 1}`;
const byIdMatch = new Map<number, IdentifyMatch>();

function render(): void {
  const empty = shownText.trim() === "";
  emptyState.hidden = !empty;
  noneState.hidden = empty || matches.length > 0;
  matchesList.hidden = empty || matches.length === 0;
  matchCount.hidden = empty;
  matchCount.textContent = count(matches.length);

  byIdMatch.clear();
  for (const m of matches) byIdMatch.set(m.id, m);
  const [key, reverse] = sortKey(sort.value);
  const all = groupMatches(sortMatches(matches, key, reverse));
  const cards = all.slice(0, MAX_CARDS).map(card);
  if (all.length > MAX_CARDS) {
    cards.push(h("li", { class: "field__hint" }, `The first ${MAX_CARDS} of ${count(all.length)} cards are shown. Filter by rarity or tag to narrow them down.`));
  }
  if (capped) {
    cards.unshift(
      h("li", { class: "notice" }, `pyWhat stopped at ${count(MAX_MATCHES)} matches: the text has more. Filter by rarity or tag, or identify a smaller part of the text, to see the rest.`),
    );
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

/** The most matched texts a format's card lists; the rest are counted. */
const MAX_CHIPS = 50;

function card(c: Card): HTMLLIElement {
  const members = c.kind === "single" ? [c.match] : c.matches;
  const m = members[0] as IdentifyMatch;
  const group = c.kind === "group";
  const nameId = `match-${m.id}`;
  // A group shows what its matches share; a description that differs per match (a processor
  // names a MAC address's vendor, say) is left out
  const description = members.every((x) => x.description === m.description) ? m.description : null;
  const desc = description
    ? h(
        "p",
        { class: "match__desc" },
        ...parseMarkup(description).map((p) =>
          p.kind === "link" ? h("a", { href: p.href, target: "_blank", rel: "noopener noreferrer" }, p.text) : p.text,
        ),
      )
    : null;
  const rarity = Math.max(...members.map((x) => x.rarity));
  // A lookup link sends the match to another site: never for credentials, and always named
  const secret = m.tags.some((t) => /credential|token|key/i.test(t));
  const lookup = (x: IdentifyMatch) => (secret || !x.link ? null : safeHref(x.link));
  const chips = group
    ? h(
        "ul",
        { class: "match__chips", "aria-label": "Matched text" },
        ...members.slice(0, MAX_CHIPS).map((x) => {
          const href = lookup(x);
          return h(
            "li",
            {},
            href
              ? h("a", { href, target: "_blank", rel: "noopener noreferrer", title: `Look it up on ${hostOf(href)} (sends ${x.matched} there)` }, h("code", {}, x.matched))
              : h("code", {}, x.matched),
          );
        }),
        members.length > MAX_CHIPS ? h("li", { class: "field__meta" }, `and ${count(members.length - MAX_CHIPS)} more`) : null,
      )
    : h(
        "p",
        { class: "match__matched" },
        h("code", {}, m.matched),
        m.fragment ? h("span", { class: "badge", title: "This match is part of a longer word or match" }, "inside longer text") : null,
      );
  const li = h(
    "li",
    { class: `match ${colourOf(m.name)}`, "data-ids": members.map((x) => x.id).join(" ") },
    h(
      "div",
      { class: "match__head" },
      h("h3", { class: "match__name", id: nameId }, m.name, group ? h("span", { class: "match__count" }, ` · ${count(members.length)}`) : null),
      h(
        "span",
        { class: "rarity", title: "Rarity: 1 for formats that little else looks like" },
        h("span", { class: "rarity__bar", "aria-hidden": "true" }, rarityFill(rarity)),
        `Rarity ${fraction(rarity)}`,
      ),
    ),
    chips,
    desc,
    m.tags.length ? h("ul", { class: "tags", "aria-label": "Tags" }, ...m.tags.map((t) => h("li", {}, t))) : null,
    m.exploit
      ? h(
          "details",
          { class: "match__exploit" },
          h("summary", {}, group ? "How to use or check it (for the first match)" : "How to use or check it"),
          h("pre", {}, m.exploit),
        )
      : null,
    h(
      "div",
      { class: "match__actions" },
      group
        ? copyButton("Copy all", () => members.map((x) => x.matched).join("\n"), { spoken: `${count(members.length)} matches copied` })
        : copyButton("Copy", () => m.matched, { spoken: `${m.name} copied` }),
      !group && lookup(m)
        ? h(
            "a",
            { href: lookup(m) as string, target: "_blank", rel: "noopener noreferrer" },
            `Look it up on ${hostOf(lookup(m) as string)}`,
            icon("external"),
            h("span", { class: "visually-hidden" }, ` (opens that site, and sends it ${m.matched})`),
          )
        : null,
      h(
        "button",
        {
          type: "button",
          class: "link-button",
          onclick: () => {
            exclude.add(m.name);
            byId<HTMLDetailsElement>("filters").open = true;
            // The card goes away: focus the field that now lists the hidden format
            byId("exclude-input").focus();
          },
        },
        "Hide this format",
      ),
    ),
  );
  li.setAttribute("aria-labelledby", nameId);
  const ids = members.map((x) => x.id);
  const on = () => activate(ids);
  const off = () => activate(null);
  li.addEventListener("mouseenter", on);
  li.addEventListener("mouseleave", off);
  li.addEventListener("focusin", on);
  li.addEventListener("focusout", off);
  return li;
}

/** "www.shodan.io" → "shodan.io" */
function hostOf(href: string): string {
  return new URL(href).hostname.replace(/^www\./, "");
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
    // Above the limit there are no highlights to line up: don't lay out a copy of the text
    if (text.value.length > MAX_TEXT_CHARS) backdrop.replaceChildren();
    else backdrop.replaceChildren(text.value + "\n");
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
    const mark = h("mark", { class: colourOf(byIdMatch.get(s.ids[0] as number)?.name ?? "") }, piece);
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

/** Rings the marks of `ids` (a card's matches) and dims the others; `null` puts all back. */
function activate(ids: readonly number[] | null): void {
  for (const li of matchesList.querySelectorAll(".match.is-active")) li.classList.remove("is-active");
  for (const m of backdrop.querySelectorAll("mark")) {
    m.classList.remove("is-active", "is-dim");
    if (ids !== null) m.classList.add("is-dim");
  }
  if (ids === null || ids.length === 0) return;
  matchesList.querySelector(`.match[data-ids~="${ids[0]}"]`)?.classList.add("is-active");
  for (const id of ids) {
    for (const m of marks.get(id) ?? []) {
      m.classList.remove("is-dim");
      m.classList.add("is-active");
    }
  }
}

// --- A link with text -------------------------------------------------------------------------------

// Text from another tool (sessionStorage), or from a link to identify/#text=...: like Decode's
// share links, the text leaves the address bar as soon as it's edited
const fromLink = decodeHash(location.hash).get("text");
const shared = pickUp() ?? fromLink;
if (shared) setText(Array.from(shared).slice(0, MAX_TEXT_CHARS).join(""));
if (fromLink) {
  text.addEventListener("input", () => history.replaceState(null, "", location.pathname + location.search), { once: true });
}
byId("decode-link").addEventListener("click", () => handOff(text.value));
updateFiltersSummary(readFilters());
textCount.textContent = characterCount(text.value);
