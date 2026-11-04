// The Decode page's worker: loads Ciphey's WebAssembly module (the ciphey-wasm crate, see
// docs/wasm.md) and runs a search a step at a time, posting the tree's new nodes after each
// step, so the page draws the search as it happens and stays responsive. Between steps it
// reads its messages, so a "cancel" stops the search; the page terminates the worker if a
// step takes too long to get there.

import init, { cipheyVersion, listDecoders, Search, type SearchProgress, type SearchResult } from "../wasm/decode/ciphey_wasm.js";
import wasmUrl from "../wasm/decode/ciphey_wasm_bg.wasm?url";
import type { DecodeEvent, DecodeRequest, DecodeResult, DecoderInfo, TreeNode } from "../lib/protocol";

declare const self: DedicatedWorkerGlobalScope;

/** Why the module didn't load, in words for the page. */
function loadFailure(error: unknown, name: string): string {
  return error instanceof WebAssembly.CompileError
    ? `This browser can't run ${name}. Try a recent Chrome, Firefox or Safari.`
    : `Couldn't download ${name}. Check your connection, then press Try again.`;
}
const post = (event: DecodeEvent) => self.postMessage(event);

/** How long one step searches before it reports back: about 25 updates a second. */
const STEP_MS = 40;
/**
 * The search stops before Ciphey's WebAssembly memory passes this. Its queue of branches
 * grows by about 1 KB per branch (for a 56-character input), about 150 MB a second, and a
 * long search with no plaintext reached the 4 GiB a 32-bit module can have after 23 to 39 s,
 * which aborts the module. So: a quarter of the device's memory where the browser says how
 * much it has (Chromium, at most 8 GB), between 512 MiB and 2 GiB; else 2 GiB on desktops
 * and 512 MiB on phones.
 */
const MEMORY_LIMIT = (() => {
  const gib = 1024 ** 3;
  const device = (navigator as { deviceMemory?: number }).deviceMemory;
  if (device) return Math.min(2 * gib, Math.max(gib / 2, (device * gib) / 4));
  return /Mobi|Android|iPhone|iPad/.test(navigator.userAgent) ? gib / 2 : 2 * gib;
})();
/** Characters of each node's text the page gets (it shows up to 160). */
const PREVIEW_CHARS = 160;

type Message = DecodeRequest;
type Decode = Extract<DecodeRequest, { type: "decode" }>;

let current: { id: number; search: Search; texts: Map<number, { parent: number | null; text: string }> } | null = null;
let memory: WebAssembly.Memory | null = null;
let dead = false;
/** Searches cancelled before they started (the page doesn't send these, but be safe). */
const cancelled = new Set<number>();

const memoryBytes = () => memory?.buffer.byteLength ?? 0;

function describe(error: unknown): string {
  const text = error instanceof Error ? error.message : String(error);
  // A Rust panic or a failed allocation aborts the module: the call throws a RuntimeError
  // ("unreachable"), and the instance is unusable from then on
  if (error instanceof WebAssembly.RuntimeError || /unreachable|out of memory/i.test(text)) {
    dead = true;
    if (memoryBytes() > MEMORY_LIMIT / 2 || /out of memory/i.test(text)) {
      return "Ciphey ran out of memory. Try a shorter time limit, or a crib.";
    }
    return "Ciphey crashed on this input. That's a bug in Ciphey: please report it, with the input, at github.com/bee-san/Ciphey/issues.";
  }
  return text;
}

const ready = init({ module_or_path: wasmUrl })
  .then((output) => {
    memory = output.memory;
    const decoders = (listDecoders() as DecoderInfo[]).map((d) => ({ name: d.name, tags: d.tags }));
    post({ type: "ready", version: cipheyVersion(), decoders, live: true, reusable: true });
    return true;
  })
  .catch((error: unknown) => {
    // The detail (a URL, a status) is for the console; the page says what to do
    console.error(error);
    post({ type: "error", id: null, message: loadFailure(error, "Ciphey") });
    return false;
  });

/** The output of each step of a result's path, from the nodes on its branch. */
function withStepTexts(r: SearchResult, texts: Map<number, { parent: number | null; text: string }>): DecodeResult {
  // The branch from the input down to the node the plaintext was decoded from: node i on it
  // is the output of step i (node 0 is the input), and the last step's output is the plaintext
  const branch: string[] = [];
  for (let id = r.nodeId; id !== null && texts.has(id); id = texts.get(id)?.parent ?? null) {
    branch.unshift(texts.get(id)?.text ?? "");
  }
  const path = r.path.map((step, i) => ({
    decoder: step.decoder,
    key: step.key,
    text: i === r.path.length - 1 ? r.plaintext : (branch[i + 1] ?? null),
    checker: step.checker,
    checkerName: step.checkerName,
    description: step.description,
    confidence: step.confidence,
  }));
  return {
    plaintext: r.plaintext,
    path,
    checker: r.checker,
    checkerName: r.checkerName,
    description: r.description,
    confidence: r.confidence,
    elapsedMs: r.elapsedMs,
    nodeId: r.nodeId,
  };
}

async function run(request: Decode): Promise<void> {
  const { id, input, options } = request;
  let search: Search;
  try {
    search = new Search(input, {
      timeout: options.timeout,
      regex: options.regex === "" ? undefined : options.regex,
      topResults: options.topResults,
      sensitivity: options.sensitivity,
      previewChars: PREVIEW_CHARS,
    });
  } catch (error) {
    post({ type: "error", id, message: describe(error) });
    return;
  }
  const texts = new Map<number, { parent: number | null; text: string }>();
  current = { id, search, texts };
  try {
    for (;;) {
      const p: SearchProgress = search.step(STEP_MS);
      if (current?.search !== search) return; // cancelled or replaced while stepping
      // Stop before the module runs out of memory (it can't give memory back: the page
      // starts a new worker for the next search)
      const full = p.status === "running" && memoryBytes() > MEMORY_LIMIT;
      const nodes: TreeNode[] = p.nodes.map((n) => ({
        id: n.id,
        parent: n.parent,
        depth: n.depth,
        decoder: n.decoder,
        key: n.key,
        text: n.text,
        length: n.length,
        cost: n.cost,
        queuedChildren: n.children,
      }));
      for (const n of nodes) texts.set(n.id, { parent: n.parent, text: n.text });
      post({
        type: "update",
        id,
        update: {
          status: full ? "memory_full" : p.status,
          elapsedMs: p.elapsedMs,
          expanded: p.expanded,
          queued: p.queued,
          seen: p.seen,
          depth: p.depth,
          nodes,
          results: p.results.map((r) => withStepTexts(r, texts)),
          memoryBytes: memoryBytes(),
        },
      });
      if (p.status !== "running" || full) break;
      // Let a "cancel" (or a new search) in between two steps
      await new Promise((resolve) => setTimeout(resolve, 0));
      if (current?.search !== search) return;
    }
  } catch (error) {
    post({ type: "error", id, message: describe(error) });
  } finally {
    if (!dead) search.free();
    if (current?.search === search) current = null;
  }
}

self.onmessage = async (event: MessageEvent<Message>) => {
  const message = event.data;
  if (message.type === "cancel") {
    if (current?.id === message.id) current = null; // run() frees it after its step
    else cancelled.add(message.id);
    post({ type: "cancelled", id: message.id });
    return;
  }
  if (!(await ready)) return;
  if (dead) {
    post({ type: "error", id: message.id, message: "Ciphey has to restart after a crash." });
    return;
  }
  if (cancelled.delete(message.id)) return;
  current = null;
  void run(message);
};
