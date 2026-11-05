import "../styles/main.css";
import { duration, fraction } from "../lib/format";
import versions from "../wasm/versions.json";
import { capitalise } from "../decode/words";
import { isLanguageAt, languageName, listNames, THRESHOLDS } from "../lib/language";
import type { LanguageEvent, LanguageRequest, LanguageVerdict, Sensitivity } from "../lib/protocol";
import { announce, byId, characterCount, h, icon } from "../shell/dom";
import { EngineClient, LatestRequest } from "../shell/engine";
import { initPage } from "../shell/page";

initPage();

const MAX_TEXT_CHARS = 10_000;

const EXAMPLES: ReadonlyArray<{ label: string; text: string }> = [
  { label: "An English sentence", text: "The quick brown fox jumps over the lazy dog" },
  { label: "Caesar-shifted text", text: "Wkh txlfn eurzq ira mxpsv ryhu wkh odcb grj" },
  { label: "Keyboard mash", text: "asdkj qweoiu zxcmnb lkjqwe" },
  { label: "Base64", text: "aGVsbG8gdGhlcmUgZ2VuZXJhbA==" },
  { label: "A common password", text: "password123" },
];

const text = byId<HTMLTextAreaElement>("text");
const textCount = byId("text-count");
const verdictBox = byId("verdict");
const verdictTitle = byId("verdict-title");
const verdictDetail = byId("verdict-detail");
const verdictMeta = byId("verdict-meta");
const scoreBox = byId("score");
const scoreValue = byId("score-value");
const scoreFill = byId("score-fill");
const passwordNote = byId("password-note");
const languagesNote = byId("languages-note");
const engineStatus = byId("engine-status");

const engine = new EngineClient<LanguageRequest, LanguageEvent>(
  () => new Worker(new URL("../workers/language.worker.ts", import.meta.url), { type: "module", name: "gibberish-or-not" }),
  "gibberish-or-not",
);
const latest = new LatestRequest<LanguageRequest>((r) => engine.post(r));
let ready = false;
/** The text and sensitivity gibberish-or-not crashed on: not sent again until one changes. */
let crashedOn: string | null = null;
let pendingKey = "";
/** Why gibberish-or-not didn't load, if it didn't: shown where the verdict goes. */
let loadError: string | null = null;
let lastSaid = "";
let sayTimer = 0;

engine.on((event) => {
  switch (event.type) {
    case "ready": {
      ready = true;
      loadError = null;
      engineStatus.textContent = `gibberish-or-not ${versions.gibberish} is ready`;
      const names = event.languages.map(languageName);
      languagesNote.textContent = names.length
        ? `This version knows ${listNames(names)}. Text in another language may be called gibberish, or taken for one it knows.`
        : "";
      refresh();
      return;
    }
    case "detected":
      if (latest.settle(event.id)) show(event.verdict, event.elapsedMs);
      return;
    case "error":
      if (event.id === null) {
        ready = false;
        engineStatus.replaceChildren(h("span", { class: "field__error" }, event.message), " ", h("button", { type: "button", class: "link-button", onclick: () => restart() }, "Try again"));
        loadError = event.message;
        refresh();
      } else {
        const current = latest.settle(event.id);
        if (event.crashed) {
          crashedOn = pendingKey;
          restart();
        }
        if (current || event.crashed) verdictDetail.textContent = event.message;
      }
      return;
  }
});
engine.start();

/** A fresh worker: after a crash, or Try again. Requests in flight are forgotten. */
function restart(): void {
  ready = false;
  loadError = null;
  latest.reset();
  engineStatus.replaceChildren(h("span", { class: "spinner", "aria-hidden": "true" }), "Loading gibberish-or-not…");
  engine.restart();
}

function sensitivity(): Sensitivity {
  return (document.querySelector<HTMLInputElement>('input[name="sensitivity"]:checked')?.value as Sensitivity | undefined) ?? "medium";
}

const textHint = byId("text-hint");
const HINT = textHint.textContent ?? "";

function refresh(): void {
  textCount.textContent = characterCount(text.value);
  // By character, as the count does (an emoji is one)
  const chars = Array.from(text.value);
  const over = chars.length > MAX_TEXT_CHARS;
  textHint.textContent = over ? `Only the first ${MAX_TEXT_CHARS.toLocaleString("en")} characters are checked.` : HINT;
  const value = over ? chars.slice(0, MAX_TEXT_CHARS).join("") : text.value;
  if (value.trim() === "") {
    // A reply still on its way is for the text that was cleared
    latest.reset();
    showEmpty();
    return;
  }
  const key = JSON.stringify([value, sensitivity()]);
  if (key === crashedOn) {
    verdictTitle.textContent = "Not checked";
    verdictDetail.textContent = "gibberish-or-not crashed on this text. Change it to try again.";
    return;
  }
  if (!ready) {
    if (loadError) {
      verdictTitle.textContent = "Not checked";
      verdictDetail.textContent = loadError;
    }
    return;
  }
  pendingKey = key;
  latest.request((id) => ({ type: "detect", id, text: value, sensitivity: sensitivity() }));
}

text.addEventListener("input", refresh);
for (const radio of document.querySelectorAll<HTMLInputElement>('input[name="sensitivity"]')) radio.addEventListener("change", refresh);
byId("examples").replaceChildren(
  ...EXAMPLES.map((e) =>
    h(
      "button",
      {
        type: "button",
        class: "chip",
        onclick: () => {
          text.value = e.text;
          // A new text is said even if its verdict is the same as before
          lastSaid = "";
          refresh();
        },
      },
      e.label,
    ),
  ),
);

function showEmpty(): void {
  verdictBox.className = "verdict verdict--empty";
  verdictBox.querySelector(".verdict__mark")?.replaceChildren();
  verdictTitle.textContent = "Type some text";
  verdictDetail.textContent = "The verdict, the language and the score show up here.";
  verdictMeta.textContent = "";
  scoreValue.textContent = "–";
  scoreFill.style.width = "0";
  scoreBox.classList.remove("score--yes");
  passwordNote.hidden = true;
  markCurrent();
}

function show(v: LanguageVerdict, ms: number): void {
  const s = sensitivity();
  const yes = isLanguageAt(v.score, s) && v.isLanguage;
  verdictBox.className = `verdict ${yes ? "verdict--yes" : "verdict--no"}`;
  verdictBox.querySelector(".verdict__mark")?.replaceChildren(icon(yes ? "ok" : "no"));
  verdictTitle.textContent = yes ? "Language" : "Not language";
  // The more lenient sensitivities that would accept it, by name
  const lenient = (["high", "medium"] as const).filter((x) => THRESHOLDS[x] < THRESHOLDS[s] && v.score >= THRESHOLDS[x]).map(capitalise);
  verdictDetail.textContent = yes
    ? `${v.language ? languageName(v.language) : "A language it knows"}, at ${capitalise(s)} sensitivity`
    : lenient.length
      ? `Language at ${listNames(lenient)} sensitivity, not at ${capitalise(s)}`
      : "Gibberish, or a language it doesn't know";
  verdictMeta.textContent = `checked in ${duration(ms)}`;
  scoreValue.textContent = fraction(v.score);
  scoreFill.style.width = `${Math.round(Math.max(0, Math.min(1, v.score)) * 100)}%`;
  scoreBox.classList.toggle("score--yes", yes);
  passwordNote.hidden = !v.isPassword;
  markCurrent();
  // Say the verdict once typing pauses, and only when it changes
  window.clearTimeout(sayTimer);
  const said = `${verdictTitle.textContent}. ${verdictDetail.textContent}. Score ${fraction(v.score)}.`;
  sayTimer = window.setTimeout(() => {
    if (said !== lastSaid) announce(said);
    lastSaid = said;
  }, 900);
}

function markCurrent(): void {
  const s = sensitivity();
  for (const tick of document.querySelectorAll(".score__tick")) tick.classList.toggle("is-current", tick.classList.contains(`score__tick--${s}`));
}

markCurrent();
textCount.textContent = characterCount(text.value);
