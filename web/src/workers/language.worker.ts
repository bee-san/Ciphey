// The language page's worker: loads gibberish-or-not's WebAssembly module and scores text.

import init, { detect, isPassword, languages } from "../wasm/language/language.js";
import wasmUrl from "../wasm/language/language_bg.wasm?url";
import type { LanguageEvent, LanguageRequest } from "../lib/protocol";

declare const self: DedicatedWorkerGlobalScope;
const post = (event: LanguageEvent) => self.postMessage(event);

const ready = init({ module_or_path: wasmUrl })
  .then(() => {
    post({ type: "ready", languages: languages() });
    return true;
  })
  .catch((error: unknown) => {
    post({ type: "error", id: null, message: `Couldn't load gibberish-or-not: ${String(error)}` });
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
    post({ type: "error", id, message: `gibberish-or-not failed on this text: ${String(error)}` });
  }
};
