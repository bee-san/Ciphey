// The Identify page's worker: loads pyWhat's WebAssembly module and identifies text in the
// background, so typing stays smooth on large texts.

import init, { identify, tags, version } from "../wasm/identify/identify.js";
import wasmUrl from "../wasm/identify/identify_bg.wasm?url";
import type { IdentifyEvent, IdentifyRequest } from "../lib/protocol";
import { flattenMatches, identifyOptionsJson } from "../lib/pywhat";

declare const self: DedicatedWorkerGlobalScope;
const post = (event: IdentifyEvent) => self.postMessage(event);

const ready = init({ module_or_path: wasmUrl })
  .then(() => {
    post({ type: "ready", version: version(), tags: JSON.parse(tags()) as string[] });
    return true;
  })
  .catch((error: unknown) => {
    post({ type: "error", id: null, message: `Couldn't load pyWhat: ${String(error)}` });
    return false;
  });

self.onmessage = async (event: MessageEvent<IdentifyRequest>) => {
  if (!(await ready)) return;
  const { id, text, options } = event.data;
  const started = performance.now();
  try {
    const matches = flattenMatches(identify(text, identifyOptionsJson(options)));
    if ("error" in matches) post({ type: "error", id, message: matches.error });
    else post({ type: "identified", id, matches, elapsedMs: performance.now() - started });
  } catch (error) {
    post({ type: "error", id, message: `pyWhat failed on this text: ${String(error)}` });
  }
};
