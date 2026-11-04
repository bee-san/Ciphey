import "../styles/main.css";
import { duration, fraction } from "../lib/format";
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
let lastSaid = "";
let sayTimer = 0;

engine.on((event) => {
  switch (event.type) {
    case "ready": {
      ready = true;
      engineStatus.textContent = "gibberish-or-not is ready";
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
        engineStatus.replaceChildren(
          h("span", { class: "field__error" }, event.message),
          " ",
          h("button", { type: "button", class: "link-button", onclick: () => engine.restart() }, "Try again"),
        );
      } else if (latest.settle(event.id)) {
        verdictDetail.textContent = event.message;
      }
      return;
  }
});
engine.start();

function sensitivity(): Sensitivity {
  return (document.querySelector<HTMLInputElement>('input[name="sensitivity"]:checked')?.value as Sensitivity | undefined) ?? "medium";
}

function refresh(): void {
  textCount.textContent = characterCount(text.value);
  const value = text.value.slice(0, MAX_TEXT_CHARS);
  if (value.trim() === "") {
    showEmpty();
    return;
  }
  if (!ready) return;
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
  verdictDetail.textContent = yes
    ? `${v.language ? languageName(v.language) : "A language it knows"}, at ${s} sensitivity`
    : v.score >= THRESHOLDS.high
      ? `Language at a more lenient sensitivity, not at ${s}`
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
