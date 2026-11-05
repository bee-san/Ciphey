// The language page's worker: loads gibberish-or-not's WebAssembly module and scores text.

import init, { detect, isPassword, languages } from "../wasm/language/language.js";
import wasmUrl from "../wasm/language/language_bg.wasm?url";
import type { LanguageEvent, LanguageRequest } from "../lib/protocol";

declare const self: DedicatedWorkerGlobalScope;

/** Why the module didn't load, in words for the page. */
function loadFailure(error: unknown, name: string): string {
  return error instanceof WebAssembly.CompileError
    ? `This browser can't run ${name}. Try a recent Chrome, Firefox or Safari.`
    : `Couldn't download ${name}. Check your connection, then press Try again.`;
}
const post = (event: LanguageEvent) => self.postMessage(event);

const ready = init({ module_or_path: wasmUrl })
  .then(() => {
    post({ type: "ready", languages: languages() });
    return true;
  })
  .catch((error: unknown) => {
    // The detail (a URL, a status) is for the console; the page says what to do
    console.error(error);
    post({ type: "error", id: null, message: loadFailure(error, "gibberish-or-not") });
    return false;
  });

self.onmessage = async (event: MessageEvent<LanguageRequest>) => {
  if (!(await ready)) return;
  const { id, text, sensitivity } = event.data;
  const started = performance.now();
  try {
    const d = detect(text, sensitivity);
    const verdict = { isLanguage: d.isLanguage, language: d.language ?? null, score: d.score, isPassword: isPassword(text) };
    d.free();
    post({ type: "detected", id, verdict, elapsedMs: performance.now() - started });
  } catch (error) {
    // A panic aborts the module: the page starts a new worker
    const crashed = error instanceof WebAssembly.RuntimeError;
    post({ type: "error", id, message: crashed ? "gibberish-or-not crashed on this text." : `gibberish-or-not failed on this text: ${String(error)}`, crashed });
  }
};
