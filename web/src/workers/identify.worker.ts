// The Identify page's worker: loads pyWhat's WebAssembly module and identifies text in the
// background, so typing stays smooth on large texts.
//
// pyWhat's output repeats each format's whole entry for every match (its URL regex alone is
// 18,056 characters): about 11 KB of JSON per match on average and 41 KB per URL. One call on
// 100,000 characters dense with identifiers makes over 100 MB of it. So a long text goes to
// pyWhat in pieces of about 10,000 characters, cut at line ends (or spaces), and the worker
// stops at MAX_MATCHES. A match that would cross a cut is missed; with lines, rarely.

import init, { identify, tags, version } from "../wasm/identify/identify.js";
import wasmUrl from "../wasm/identify/identify_bg.wasm?url";
import type { IdentifyEvent, IdentifyMatch, IdentifyRequest } from "../lib/protocol";
import { MAX_MATCHES, pieces } from "../lib/pieces";
import { flattenMatches, identifyOptionsJson } from "../lib/pywhat";

declare const self: DedicatedWorkerGlobalScope;
const post = (event: IdentifyEvent) => self.postMessage(event);

/** Why the module didn't load, in words for the page. */
function loadFailure(error: unknown, name: string): string {
  return error instanceof WebAssembly.CompileError
    ? `This browser can't run ${name}. Try a recent Chrome, Firefox or Safari.`
    : `Couldn't download ${name}. Check your connection, then press Try again.`;
}

const PIECE = 10_000;

const ready = init({ module_or_path: wasmUrl })
  .then(() => {
    post({ type: "ready", version: version(), tags: JSON.parse(tags()) as string[] });
    return true;
  })
  .catch((error: unknown) => {
    // The detail (a URL, a status) is for the console; the page says what to do
    console.error(error);
    post({ type: "error", id: null, message: loadFailure(error, "pyWhat") });
    return false;
  });

self.onmessage = async (event: MessageEvent<IdentifyRequest>) => {
  if (!(await ready)) return;
  const { id, text, options } = event.data;
  const started = performance.now();
  const json = identifyOptionsJson(options);
  const matches: IdentifyMatch[] = [];
  let capped = false;
  try {
    for (const piece of pieces(text, PIECE, !options.boundaryless)) {
      const found = flattenMatches(identify(piece, json));
      if ("error" in found) {
        post({ type: "error", id, message: found.error });
        return;
      }
      for (const m of found) {
        matches.push({ ...m, id: matches.length });
        if (matches.length >= MAX_MATCHES) break;
      }
      if (matches.length >= MAX_MATCHES) {
        capped = true;
        break;
      }
    }
    post({ type: "identified", id, matches, capped, elapsedMs: performance.now() - started });
  } catch (error) {
    // A panic aborts the module: the page starts a new worker
    const crashed = error instanceof WebAssembly.RuntimeError;
    post({ type: "error", id, message: crashed ? "pyWhat crashed on this text. Try a smaller part of it." : `pyWhat failed on this text: ${String(error)}`, crashed });
  }
};
