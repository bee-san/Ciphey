#!/usr/bin/env node
// End-to-end test of the site in headless Chrome (puppeteer-core):
//
//   CHROME=/path/to/chrome node tests/e2e/e2e.mjs                 # serves dist/ locally
//   CHROME=... node tests/e2e/e2e.mjs --url https://bee-san.github.io/Ciphey/
//
// Decode: every example decodes to its plaintext; the tree grows while a search runs; a
// search can be cancelled, and one with no plaintext ends with advice; a bad crib is
// reported at the crib; a share link opens and runs its search. Identify: a few strings are
// identified and highlighted, and the filters and sorting work. Is it language?: a sentence
// is language, a keyboard mash isn't. On every page: axe-core finds no WCAG 2.2 A/AA or
// best-practice violations, in both themes, at desktop and phone widths; keyboard focus is
// visible; nothing is requested from another origin; no CSP violations or console errors.
// Prints PASS/FAIL per check; exits 1 if any failed.
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRequire } from "node:module";
import puppeteer from "puppeteer-core";
import { EXAMPLES } from "../../src/decode/examples.ts";
import { serve } from "../../scripts/serve.mjs";
// The policy, written out: a test that imported it from scripts/shell.ts would follow a
// weakened one
const CSP =
  "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; worker-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'none'";

const require = createRequire(import.meta.url);
const AXE = readFileSync(require.resolve("axe-core/axe.min.js"), "utf8");
const AXE_TAGS = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa", "best-practice"];

const args = process.argv.slice(2);
const urlArg = args.includes("--url") ? args[args.indexOf("--url") + 1] : null;
const only = args.includes("--only") ? args[args.indexOf("--only") + 1] : null;
const chrome = process.env.CHROME;
if (!chrome) {
  console.error("e2e: set CHROME to a Chrome or Chromium binary");
  process.exit(2);
}

let server = null;
let base = urlArg;
if (!base) {
  // The base path the site was built for (vite.config.ts reads the same variable)
  const path = process.env.BASE_PATH ?? "/Ciphey/";
  server = await serve({ port: 0, root: new URL("../../dist", import.meta.url).pathname, base: path });
  base = `http://127.0.0.1:${server.address().port}${path}`;
}
if (!base.endsWith("/")) base += "/";
const origin = new URL(base).origin;

const browser = await puppeteer.launch({
  executablePath: chrome,
  headless: true,
  args: ["--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage"],
});

const results = [];
const problems = { foreign: new Set(), console: [], csp: [] };
let failed = 0;

function report(name, ok, detail = "") {
  results.push({ name, ok, detail });
  if (!ok) failed++;
  console.log(`${ok ? "PASS" : "FAIL"} ${name}${detail ? ` (${detail})` : ""}`);
}

async function check(name, fn) {
  if (only && !name.startsWith(only)) return;
  const t0 = Date.now();
  try {
    const detail = await fn();
    report(name, true, [detail, `${Date.now() - t0} ms`].filter(Boolean).join(", "));
  } catch (error) {
    report(name, false, String(error?.message ?? error).split("\n")[0]);
  }
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

/** A fresh page (own cache and storage), recording requests, console errors and CSP violations. */
async function open(path, { width = 1280, height = 900, theme = "light", reducedMotion = false, deviceMemory, userAgent, on = browser } = {}) {
  const context = await on.createBrowserContext();
  const page = await context.newPage();
  if (userAgent) await page.setUserAgent(userAgent);
  // The page reads navigator.deviceMemory to size a search's memory budget
  if (deviceMemory !== undefined) {
    await page.evaluateOnNewDocument((m) => Object.defineProperty(Navigator.prototype, "deviceMemory", { get: () => m ?? undefined }), deviceMemory);
  }
  await page.setViewport({ width, height, deviceScaleFactor: 1 });
  await page.emulateMediaFeatures([
    { name: "prefers-color-scheme", value: theme },
    { name: "prefers-reduced-motion", value: reducedMotion ? "reduce" : "no-preference" },
  ]);
  page.on("request", (r) => {
    const u = r.url();
    if (!u.startsWith("data:") && !u.startsWith("blob:") && new URL(u).origin !== origin) problems.foreign.add(u);
  });
  // WebSockets aren't requests to puppeteer: watch for them in the page and in every worker
  const watchSockets = async (session) => {
    await session.send("Network.enable").catch(() => {});
    session.on("Network.webSocketCreated", (e) => problems.foreign.add(`WebSocket ${e.url}`));
  };
  await watchSockets(await page.createCDPSession());
  page.on("workercreated", (worker) => void watchSockets(worker.client));
  page.on("console", (m) => {
    if (m.type() === "error") problems.console.push(`${path}: ${m.text()}`);
  });
  page.on("pageerror", (e) => problems.console.push(`${path}: ${e.message}`));
  await page.evaluateOnNewDocument(() => {
    window.__csp = [];
    document.addEventListener("securitypolicyviolation", (e) => window.__csp.push(`${e.violatedDirective} ${e.blockedURI}`));
  });
  page.closeAll = async () => {
    const csp = await page.evaluate(() => window.__csp).catch(() => []);
    problems.csp.push(...csp.map((c) => `${path}: ${c}`));
    await context.close();
  };
  await page.goto(base + path, { waitUntil: "load" });
  return page;
}

async function engineReady(page, timeout = 60_000) {
  await page.waitForFunction(() => /is ready/.test(document.getElementById("engine-status")?.textContent ?? ""), { timeout });
}

async function setValue(page, selector, value) {
  await page.$eval(
    selector,
    (el, v) => {
      el.value = v;
      el.dispatchEvent(new Event("input", { bubbles: true }));
    },
    value,
  );
}

const text = (page, selector) => page.$eval(selector, (el) => el.textContent.trim());
const texts = (page, selector) => page.$$eval(selector, (els) => els.map((el) => el.textContent.trim()));

async function decodeResult(page, timeout = 40_000) {
  await page.waitForFunction(
    () => {
      const r = document.getElementById("result");
      return r && !r.hidden && r.querySelector(".plaintext, .notice");
    },
    { timeout },
  );
  return page.evaluate(() => ({
    plaintext: document.querySelector("#result .plaintext")?.textContent ?? null,
    notice: document.querySelector("#result .notice__title")?.textContent ?? null,
    path: document.querySelector("#result .result__path-title .field__meta")?.textContent ?? "",
    meta: document.getElementById("output-meta")?.textContent ?? "",
  }));
}

async function axe(page, label) {
  await page.evaluate(AXE);
  const found = await page.evaluate(async (tags) => {
    const r = await window.axe.run(document, { runOnly: { type: "tag", values: tags }, resultTypes: ["violations"] });
    return r.violations.map((v) => `${v.id} [${v.impact}] ${v.nodes.map((n) => n.target.join(" ")).slice(0, 4).join(" | ")}`);
  }, AXE_TAGS);
  assert(found.length === 0, `${label}: ${found.join("; ")}`);
  return found.length;
}

/** How far the page scrolls sideways, and the elements that stick out (for the message). */
async function sideways(page) {
  return page.evaluate(() => {
    const w = window.innerWidth;
    const overflow = document.documentElement.scrollWidth - w;
    const out = [...document.querySelectorAll("body *")]
      .filter((el) => el.getBoundingClientRect().right > w + 0.5)
      // Only the outermost: an element whose parent sticks out is covered by its parent
      .filter((el) => !(el.parentElement && el.parentElement.getBoundingClientRect().right > w + 0.5))
      .slice(0, 4)
      .map((el) => `${el.tagName.toLowerCase()}${el.id ? `#${el.id}` : ""}${el.classList.length ? `.${[...el.classList].join(".")}` : ""}`);
    return { overflow, out: out.join(", ") };
  });
}

let axeRuns = 0;
async function axeEverywhere(name, path, prepare) {
  for (const theme of ["light", "dark"]) {
    for (const [width, height] of [
      [1280, 900],
      [390, 844],
    ]) {
      await check(`axe ${name} ${theme} ${width}px`, async () => {
        const page = await open(path, { theme, width, height });
        try {
          await prepare(page);
          await axe(page, `${name} ${theme} ${width}`);
          axeRuns++;
          const { overflow, out } = await sideways(page);
          assert(overflow <= 0, `the page scrolls sideways by ${overflow} px (${out})`);
          return "0 violations";
        } finally {
          await page.closeAll();
        }
      });
    }
  }
}

// --- Decode ---------------------------------------------------------------------------------

const decode = await open("");
await check("decode: Ciphey loads", async () => {
  await engineReady(decode);
  return await text(decode, "#engine-status");
});

const shown = await decode.$$eval("#examples [data-example]", (els) => els.map((el) => el.dataset.example));
for (const example of EXAMPLES) {
  await check(`decode example: ${example.label}`, async () => {
    if (!shown.includes(example.id)) {
      // Examples that need a decoder Ciphey doesn't have yet are hidden (#1029's hash cracker)
      assert(example.needs, `${example.id} isn't offered`);
      return "hidden: no decoder for it in this build";
    }
    await decode.click(`#examples [data-example="${example.id}"]`);
    const r = await decodeResult(decode);
    assert(r.plaintext === example.plaintext, `got ${JSON.stringify(r.plaintext ?? r.notice)}`);
    const onPath = await decode.$$eval("#tree .node--result", (els) => els.length);
    assert(onPath >= 1, "the tree doesn't mark the plaintext");
    return `${r.path} in ${r.meta}`;
  });
}

await check("decode: the path shows each layer's output", async () => {
  const example = EXAMPLES.find((e) => e.id === "base64x3");
  await decode.click(`#examples [data-example="${example.id}"]`);
  await decodeResult(decode);
  const layers = await texts(decode, "#result .path__text");
  const b64 = (t) => Buffer.from(t).toString("base64");
  const want = [example.input, b64(b64(example.plaintext)), b64(example.plaintext), example.plaintext];
  // Each is cut to 160 characters (with an ellipsis), so compare the starts
  assert(layers.length === 4, `${layers.length} layers`);
  layers.forEach((l, i) => assert(want[i].startsWith(l.replace(/…$/, "")), `layer ${i}: ${l.slice(0, 40)}`));
  return `${layers.length} layers`;
});

await check("decode: decoded HTML is shown as text, never run", async () => {
  const html = '<img src=x onerror="window.__xss=1"><b>Hello</b> there, this decoded text is plain English and harmless';
  await setValue(decode, "#input", Buffer.from(html).toString("base64"));
  await decode.click("#decode");
  const r = await decodeResult(decode);
  const state = await decode.evaluate(() => ({
    xss: window.__xss,
    elements: document.querySelector("#result .plaintext")?.children.length,
    images: document.querySelectorAll("#result img, #tree img").length,
  }));
  assert(r.plaintext === html, `got ${r.plaintext ?? r.notice}`);
  assert(state.xss === undefined && state.elements === 0 && state.images === 0, JSON.stringify(state));
  return "shown as text";
});

await check("decode: the tree grows while searching, then advice when nothing is found", async () => {
  await decode.click("#options summary");
  await setValue(decode, "#timeout", "3");
  await setValue(decode, "#regex", "^ZZZZ-no-such-plaintext$");
  await setValue(decode, "#input", "SGVsbG8gZnJvbSB0aGUgb3RoZXIgc2lkZSBvZiB0aGUgd29ybGQ=XqZ7");
  await decode.click("#decode");
  // At least 1.5 s in, and the tree has grown (up to 2.5 s on a slow machine)
  await new Promise((r) => setTimeout(r, 1500));
  await decode.waitForFunction(() => document.querySelectorAll("#tree .node").length > 10, { timeout: 1000 }).catch(() => {});
  const midway = await decode.evaluate(() => ({
    nodes: document.querySelectorAll("#tree .node").length,
    stats: document.getElementById("search-stats")?.textContent ?? "",
    searching: !document.getElementById("search").hidden,
  }));
  assert(midway.searching, "the search ended before 1.5 s");
  assert(midway.nodes > 10, `only ${midway.nodes} tree nodes after 1.5 s`);
  assert(/texts tried/.test(midway.stats), `no counters: ${midway.stats}`);
  const r = await decodeResult(decode, 15_000);
  assert(/No plaintext found in 3 seconds|tried everything/.test(r.notice ?? ""), `got ${r.notice}`);
  const tips = await texts(decode, "#result .notice li");
  assert(tips.length >= 2, "no advice");
  return `${midway.nodes} nodes drawn at 1.5 s; "${r.notice}"`;
});

await check("decode: the tree draws at most 300 rows, plus the way to a plaintext", async () => {
  const rows = await decode.$$eval("#tree .node:not(.node--more)", (els) => els.length);
  assert(rows <= 300 + 25, `${rows} rows drawn`);
  return `${rows} rows`;
});

/** Whether the engine status line shows "Loading" at any point in the next `ms`. */
async function restartsWithin(page, ms) {
  await page.evaluate(() => {
    window.__loading = false;
    window.__watch?.disconnect();
    window.__watch = new MutationObserver(() => {
      if (/Loading/.test(document.getElementById("engine-status").textContent)) window.__loading = true;
    });
    window.__watch.observe(document.getElementById("engine-status"), { childList: true, characterData: true, subtree: true });
  });
  await new Promise((r) => setTimeout(r, ms));
  return page.evaluate(() => window.__loading);
}

await check("decode: a cancel reaches the worker (no restart), and a stuck step gets a new worker", async () => {
  await setValue(decode, "#regex", "^ZZZZ-no-such-plaintext$");
  await setValue(decode, "#timeout", "30");
  await setValue(decode, "#input", "SGVsbG8gZnJvbSB0aGUgb3RoZXIgc2lkZSBvZiB0aGUgd29ybGQ=XqZ7");
  await decode.click("#decode");
  await new Promise((r) => setTimeout(r, 800));
  const watching = restartsWithin(decode, 1200);
  await decode.keyboard.press("Escape");
  assert(!(await watching), "a cancel between steps restarted the worker (the cancel didn't reach it)");
  // 65,536 characters: one step takes seconds, so the cancel can't get in
  await setValue(decode, "#input", "aGVsbG8gdGhlcmUgZ2VuZXJhbA".repeat(2521).slice(0, 65536));
  await decode.click("#decode");
  // Right after the first step's update the worker is in its second long step
  await decode.waitForFunction(() => / tried/.test(document.getElementById("search-stats").textContent), { timeout: 30_000 });
  const restarting = restartsWithin(decode, 1500);
  await decode.keyboard.press("Escape");
  assert(await restarting, "a cancel during a long step didn't replace the worker");
  await engineReady(decode);
  await setValue(decode, "#regex", "");
  await setValue(decode, "#timeout", "5");
  return "cancel between steps: same worker; during a long step: new worker";
});

await check("decode: Escape cancels a search, and the next search runs", async () => {
  await setValue(decode, "#timeout", "30");
  await decode.click("#decode");
  await new Promise((r) => setTimeout(r, 1000));
  await decode.keyboard.press("Escape");
  const r = await decodeResult(decode, 5_000);
  assert(/Search cancelled after/.test(r.notice ?? ""), `got ${r.notice}`);
  await setValue(decode, "#regex", "");
  await setValue(decode, "#timeout", "5");
  await decode.click('#examples [data-example="base64x3"]');
  const next = await decodeResult(decode);
  assert(next.plaintext === EXAMPLES[0].plaintext, `then got ${next.plaintext ?? next.notice}`);
  return r.notice;
});

await check("decode: a text file opens into the input, and a binary file is refused", async () => {
  const dir = mkdtempSync(join(tmpdir(), "ciphey-e2e-"));
  const textFile = join(dir, "secret.txt");
  writeFileSync(textFile, "aGVsbG8gdGhlcmUgZ2VuZXJhbA==\n");
  const binary = join(dir, "photo.png");
  writeFileSync(binary, Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 13, 0x49, 0x48, 0x44, 0x52, 0, 0, 1, 0]));
  const input = await decode.$("#file");
  await input.uploadFile(textFile);
  await decode.waitForFunction(() => document.getElementById("input").value === "aGVsbG8gdGhlcmUgZ2VuZXJhbA==", { timeout: 5_000 });
  await input.uploadFile(binary);
  await decode.waitForFunction(() => !document.getElementById("input-error").hidden, { timeout: 5_000 });
  const message = await text(decode, "#input-error");
  assert(/doesn't look like text/.test(message), `got ${message}`);
  return message;
});

await check("decode: input that is already plaintext says so", async () => {
  await setValue(decode, "#regex", "");
  await setValue(decode, "#input", "hello there general kenobi");
  await decode.click("#decode");
  const r = await decodeResult(decode);
  const badge = await text(decode, "#result .result__head .badge");
  assert(r.plaintext === "hello there general kenobi" && badge === "Already plaintext", `got ${badge}: ${r.plaintext}`);
  return badge;
});

await check("decode: Find every plaintext lists more than one", async () => {
  await setValue(decode, "#timeout", "2");
  await decode.$eval("#top-results", (el) => (el.checked = true));
  await setValue(decode, "#input", "aGVsbG8gdGhlcmUgZ2VuZXJhbA==");
  await decode.click("#decode");
  const r = await decodeResult(decode, 20_000);
  const more = await decode.$$eval("#result .result__more > li", (els) => els.length);
  await decode.$eval("#top-results", (el) => (el.checked = false));
  await setValue(decode, "#timeout", "5");
  assert(r.plaintext === "hello there general", `first ${r.plaintext ?? r.notice}`);
  assert(more >= 1, "only one plaintext listed");
  return `${more + 1} plaintexts`;
});

await check("decode: a crib that isn't a valid regex is explained at the crib, which gets focus", async () => {
  await setValue(decode, "#regex", "flag{");
  await decode.click("#decode");
  await decode.waitForFunction(() => !document.getElementById("regex-error").hidden, { timeout: 10_000 });
  const message = await text(decode, "#regex-error");
  const state = await decode.evaluate(() => [
    document.getElementById("regex").getAttribute("aria-invalid"),
    document.activeElement?.id,
    document.querySelector("#result .notice__title")?.textContent,
  ]);
  assert(state[0] === "true", "the crib isn't marked invalid");
  assert(state[1] === "regex", `focus is on ${state[1]}`);
  assert(state[2] === "Check the crib.", `result says ${state[2]}`);
  assert(/backslash/.test(message), `message: ${message}`);
  await setValue(decode, "#regex", "");
  return message.slice(0, 60);
});

await check("decode: Ctrl+Enter decodes, and the share dialog warns and links", async () => {
  await decode.focus("#input");
  await setValue(decode, "#input", "aGVsbG8gdGhlcmUgZ2VuZXJhbA==");
  await decode.keyboard.down("Control");
  await decode.keyboard.press("Enter");
  await decode.keyboard.up("Control");
  const r = await decodeResult(decode);
  assert(r.plaintext === "hello there general", `got ${r.plaintext ?? r.notice}`);
  const share = await decode.$$("xpath/.//button[contains(., 'Share link')]");
  assert(share.length === 1, "no Share link button");
  await share[0].click();
  await decode.waitForSelector("#share-dialog[open]");
  const url = await decode.$eval("#share-url", (el) => el.value);
  assert(url.includes("#input=aGVsbG8gdGhlcmUgZ2VuZXJhbA%3D%3D"), `link ${url}`);
  const warning = await text(decode, "#share-warning");
  assert(/secrets/.test(warning), "no warning about secrets");
  const display = await decode.$eval("#share-warning", (el) => getComputedStyle(el).display);
  assert(display === "block", `the warning is laid out as ${display} (one paragraph is block)`);
  await decode.keyboard.press("Escape");
  await decode.waitForFunction(() => !document.getElementById("share-dialog").open);
  return url.slice(url.indexOf("#"));
});
await check("decode: Identify the plaintext hands it over through sessionStorage, not the URL", async () => {
  const example = EXAMPLES.find((e) => e.id === "ctf-flag");
  await decode.click(`#examples [data-example="${example.id}"]`);
  await decodeResult(decode);
  const link = await decode.$('#result a[href="identify/"]');
  await Promise.all([decode.waitForNavigation({ waitUntil: "load" }), link.click()]);
  await engineReady(decode);
  const state = await decode.evaluate(() => ({
    url: location.href,
    text: document.getElementById("text").value,
    stored: sessionStorage.getItem("ciphey-handoff"),
  }));
  assert(state.text === example.plaintext, `Identify has ${state.text}`);
  assert(!state.url.includes("flag") && !state.url.includes("#"), `the URL carries it: ${state.url}`);
  assert(state.stored === null, "the hand-off stayed in sessionStorage");
  await decode.goBack({ waitUntil: "load" });
  await engineReady(decode);
  return "handed over, then removed";
});
await decode.closeAll();

await check("decode: a share link opens, runs its search, and leaves the address bar on edit", async () => {
  const example = EXAMPLES.find((e) => e.id === "ctf-flag");
  const page = await open(`#input=${encodeURIComponent(example.input)}&timeout=7&crib=${encodeURIComponent("flag\\{")}`);
  try {
    const r = await decodeResult(page, 60_000);
    assert(r.plaintext === example.plaintext, `got ${r.plaintext ?? r.notice}`);
    const options = await page.evaluate(() => [document.getElementById("timeout").value, document.getElementById("regex").value]);
    assert(options[0] === "7" && options[1] === "flag\\{", `options ${options}`);
    await page.type("#input", " ");
    const hash = await page.evaluate(() => location.hash);
    assert(hash === "", `the hash stayed: ${hash.slice(0, 40)}`);
    return r.path;
  } finally {
    await page.closeAll();
  }
});

await check("decode: the clock waits for Ciphey to load (a share link on a slow connection)", async () => {
  const context = await browser.createBrowserContext();
  const page = await context.newPage();
  try {
    const cdp = await page.createCDPSession();
    await cdp.send("Network.enable");
    await cdp.send("Network.emulateNetworkConditions", { offline: false, latency: 60, downloadThroughput: (3e6 / 8) | 0, uploadThroughput: (1e6 / 8) | 0 });
    const example = EXAMPLES.find((e) => e.id === "base64x3");
    await page.goto(`${base}#input=${encodeURIComponent(example.input)}&timeout=3`, { waitUntil: "load" });
    const seen = new Set();
    let over = null;
    let firstAfterLoad = null;
    for (let i = 0; i < 300; i++) {
      const s = await page.evaluate(() => [document.getElementById("search-text")?.textContent ?? "", !document.getElementById("result").hidden]);
      seen.add(s[0].replace(/[\d.]+ m?s of/, "N of"));
      const m = /([\d.]+) (ms|s) of (\d+) s/.exec(s[0]);
      const at = m ? (m[2] === "s" ? Number(m[1]) : Number(m[1]) / 1000) : null;
      if (at !== null && firstAfterLoad === null) firstAfterLoad = at;
      if (/time's up/.test(s[0]) && firstAfterLoad === null) firstAfterLoad = Infinity;
      if (at !== null && at > Number(m[3])) over = s[0];
      if (s[1]) break;
      await new Promise((r) => setTimeout(r, 50));
    }
    assert(!over, `the clock passed the limit: ${over}`);
    assert([...seen].some((x) => /Loading Ciphey, then searching/.test(x)), `never said it was loading: ${[...seen].join(" | ")}`);
    // Once loaded, the clock starts from nothing: its first reading is well under the limit
    assert(firstAfterLoad !== null && firstAfterLoad < 1.5, `first reading after loading: ${firstAfterLoad} s`);
    const r = await page.evaluate(() => document.querySelector("#result .plaintext")?.textContent);
    assert(r === example.plaintext, `got ${r}`);
    return [...seen].join(" | ").slice(0, 120);
  } finally {
    await context.close();
  }
});

await check("decode: a failed download says so, offers Try again, and recovers", async () => {
  const context = await browser.createBrowserContext();
  const page = await context.newPage();
  try {
    // The worker's requests go through the page's interception too
    let block = true;
    await page.setRequestInterception(true);
    page.on("request", (r) => (block && r.url().endsWith(".wasm") ? r.abort("failed") : r.continue()));
    await page.goto(base, { waitUntil: "load" });
    await page.waitForFunction(() => /Couldn't download Ciphey/.test(document.getElementById("engine-status").textContent), { timeout: 20_000 });
    await setValue(page, "#input", "aGVsbG8gdGhlcmUgZ2VuZXJhbA==");
    await page.click("#decode");
    await page.waitForFunction(() => /didn't load/.test(document.querySelector("#result .notice__title")?.textContent ?? ""), { timeout: 20_000 });
    const status = await text(page, "#engine-status");
    assert(/Try again/.test(status), `status: ${status}`);
    block = false;
    const [again] = await page.$$("xpath/.//div[@id='result']//button[contains(., 'Try again')]");
    assert(again, "no Try again in the result");
    await again.click();
    const r = await decodeResult(page, 30_000);
    assert(r.plaintext === "hello there general", `after Try again: ${r.plaintext ?? r.notice}`);
    return status.replace(/\s+/g, " ").slice(0, 80);
  } finally {
    await context.close();
  }
});

/**
 * Tabs through `path` from the skip link, and checks that every stop looks different focused
 * (a ring of 2 px or more, or another change) from how it looks unfocused.
 */
async function keyboardPass(path, tabs) {
  const page = await open(path);
  try {
    await engineReady(page);
    await page.keyboard.press("Tab");
    const first = await page.evaluate(() => document.activeElement?.className);
    assert(first === "skip-link", `first stop is ${first}`);
    await page.keyboard.press("Enter");
    const stops = [];
    for (let i = 0; i < tabs; i++) {
      await page.keyboard.press("Tab");
      stops.push(
        await page.evaluate(() => {
          const el = document.activeElement;
          const look = (s) => [s.outlineStyle, s.outlineWidth, s.outlineColor, s.boxShadow, s.borderColor].join("|");
          const focused = getComputedStyle(el);
          const ring = focused.outlineStyle !== "none" && parseFloat(focused.outlineWidth) >= 2;
          const label = el.id || el.dataset.example || el.textContent.trim().slice(0, 20) || el.tagName;
          const on = look(focused);
          // A segmented radio shows its ring on its label
          const shown = el.matches(".segmented input") ? getComputedStyle(el.nextElementSibling) : null;
          const labelRing = shown ? shown.outlineStyle !== "none" && parseFloat(shown.outlineWidth) >= 2 : false;
          el.blur();
          const off = look(getComputedStyle(el));
          el.focus({ focusVisible: true });
          return { label, visible: (ring && on !== off) || labelRing };
        }),
      );
    }
    const invisible = stops.filter((s) => !s.visible).map((s) => s.label);
    assert(invisible.length === 0, `no visible focus on ${invisible.join(", ")}`);
    return stops.map((s) => s.label);
  } finally {
    await page.closeAll();
  }
}

await check("decode: a search started while a step is stuck runs on the new worker", async () => {
  const page = await open("");
  try {
    await engineReady(page);
    await setValue(page, "#input", "aGVsbG8gdGhlcmUgZ2VuZXJhbA".repeat(2521).slice(0, 65536));
    await page.click("#decode");
    await page.waitForFunction(() => / tried/.test(document.getElementById("search-stats").textContent), { timeout: 30_000 });
    // The worker is in a long step: this search waits behind it until the page replaces it
    await setValue(page, "#input", "aGVsbG8gdGhlcmUgZ2VuZXJhbA==");
    await page.click("#decode");
    const r = await decodeResult(page, 30_000);
    assert(r.plaintext === "hello there general", `got ${r.plaintext ?? r.notice}`);
    return r.meta;
  } finally {
    await page.closeAll();
  }
});

/** A search that can only end on memory: a crib that never matches, a long limit. */
async function memorySearch(page, input = "kq8vZ2mXw!9tLr#", every = false) {
  await engineReady(page);
  await page.click("#options summary");
  await setValue(page, "#timeout", "60");
  if (!every) await setValue(page, "#regex", "^no-such-plaintext$");
  if (every) await page.$eval("#top-results", (el) => (el.checked = true));
  await setValue(page, "#input", input);
  await page.click("#decode");
}

await check("decode: on a small device the search stops on memory, keeps what it found, and gets a fresh worker", async () => {
  // A 2 GB device: a 512 MiB budget
  const page = await open("", { deviceMemory: 2 });
  try {
    const t0 = Date.now();
    await memorySearch(page, "aGVsbG8gdGhlcmUgZ2VuZXJhbA==", true);
    const watching = restartsWithin(page, 40_000);
    const r = await decodeResult(page, 40_000);
    const secs = (Date.now() - t0) / 1000;
    const hint = await page.$eval("#result", (el) => el.querySelector(".field__hint")?.textContent ?? "");
    assert(r.plaintext === "hello there general", `the plaintext found is gone: ${r.plaintext ?? r.notice}`);
    assert(/to stay within your browser's memory/.test(hint), `it didn't stop on memory: ${hint}`);
    assert(secs < 35, `took ${secs} s`);
    assert(await watching, "no fresh worker after the memory stop");
    return `${hint.slice(0, 70)} (${secs.toFixed(1)} s)`;
  } finally {
    await page.closeAll();
  }
});

await check("decode: a phone with no deviceMemory gets the small budget", async () => {
  const iphone = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1";
  const page = await open("", { deviceMemory: null, userAgent: iphone, width: 390, height: 844 });
  try {
    const hint = await page.$eval("#input-limit", (el) => el.textContent);
    assert(hint === "16,000", `input limit shown as ${hint}`);
    await memorySearch(page);
    const r = await decodeResult(page, 40_000);
    assert(/before your browser ran out of memory/.test(r.notice ?? ""), `got ${r.notice}`);
    return r.notice;
  } finally {
    await page.closeAll();
  }
});

await check("decode: when the browser refuses memory, it says so (not a crib, not a bug) and keeps the plaintexts", async () => {
  // V8 lets the module grow to 384 MiB only, under the page's 2 GiB budget
  const small = await puppeteer.launch({
    executablePath: chrome,
    headless: true,
    args: ["--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage", "--js-flags=--wasm-max-mem-pages=6144"],
  });
  try {
    const page = await open("", { on: small, deviceMemory: 8 });
    try {
      await memorySearch(page, "aGVsbG8gdGhlcmUgZ2VuZXJhbA==", true);
      const r = await decodeResult(page, 60_000);
      const said = await page.evaluate(() => [...document.querySelectorAll("#result .field__error, #result .notice__title, #result .field__hint")].map((e) => e.textContent).join(" | "));
      assert(r.plaintext === "hello there general", `the plaintexts are gone: ${said}`);
      assert(/ran out of memory/.test(said), `it says ${said}`);
      assert(!/crib/i.test(await text(page, "#regex-error").catch(() => "")), "it blamed the crib");
      return said.slice(0, 100);
    } finally {
      await page.closeAll();
    }
  } finally {
    await small.close();
  }
});

await check("decode: keyboard focus is visible on every stop, skip link first", async () => {
  const order = await keyboardPass("", 14);
  for (const id of ["input", "open-file", "base64x3", "decode"]) assert(order.includes(id), `${id} isn't reachable: ${order.join(" > ")}`);
  assert(order.indexOf("input") < order.indexOf("base64x3") && order.indexOf("base64x3") < order.indexOf("decode"), `order ${order.join(" > ")}`);
  return order.join(" > ");
});

await check("identify and language: keyboard focus is visible on every stop", async () => {
  const a = await keyboardPass("identify/", 12);
  const b = await keyboardPass("language/", 10);
  for (const id of ["text", "open-file"]) assert(a.includes(id), `identify: ${id} isn't reachable: ${a.join(" > ")}`);
  assert(b.includes("text") && b.includes("sens-medium"), `language: ${b.join(" > ")}`);
  return `${a.length} + ${b.length} stops`;
});

await check("theme: the button switches theme and the choice is remembered", async () => {
  const page = await open("identify/", { theme: "light" });
  try {
    await page.click("#theme-toggle");
    const after = await page.evaluate(() => [document.documentElement.dataset.theme, document.getElementById("theme-toggle").getAttribute("aria-pressed")]);
    assert(after[0] === "dark" && after[1] === "true", `after click ${after}`);
    await page.reload({ waitUntil: "load" });
    const kept = await page.evaluate(() => [document.documentElement.dataset.theme, getComputedStyle(document.body).backgroundColor]);
    assert(kept[0] === "dark", `after reload ${kept}`);
    return kept[1];
  } finally {
    await page.closeAll();
  }
});

await check("reduced motion: no animation", async () => {
  const page = await open("", { reducedMotion: true });
  try {
    const d = await page.$eval(".spinner", (el) => parseFloat(getComputedStyle(el).animationDuration));
    assert(d < 0.01, `spinner animates for ${d} s`);
    return `${d}s`;
  } finally {
    await page.closeAll();
  }
});

// --- Identify -------------------------------------------------------------------------------

const identify = await open("identify/");
await check("identify: pyWhat loads", async () => {
  await engineReady(identify);
  return await text(identify, "#engine-status");
});

async function identifyText(value) {
  await setValue(identify, "#text", value);
  // The panel is busy from the edit until pyWhat's answer for this text is drawn
  await identify.waitForFunction(
    (v) => {
      const busy = document.getElementById("matches-panel").getAttribute("aria-busy") === "true";
      const list = document.getElementById("matches");
      const none = document.getElementById("matches-none");
      return document.getElementById("text").value === v && !busy && (!list.hidden || !none.hidden);
    },
    { timeout: 20_000 },
    value,
  );
  return {
    names: await texts(identify, "#matches .match__name"),
    marks: await texts(identify, "#backdrop mark"),
  };
}

const IDENTIFY = [
  ["Email bee@skerritt.blog from 192.168.0.1", ["Email Address", "Internet Protocol (IP) Address Version 4"], ["bee@skerritt.blog", "192.168.0.1"]],
  ["HTB{this is a flag}", ["HackTheBox Flag Format"], ["HTB{this is a flag}"]],
  ["1KFHE7w8BhaENAswwryaoccDb6qcT6DbYY", ["Bitcoin (₿) Wallet Address"], ["1KFHE7w8BhaENAswwryaoccDb6qcT6DbYY"]],
  ["https://github.com/bee-san/pyWhat", ["Uniform Resource Locator (URL)"], ["https://github.com/bee-san/pyWhat"]],
];
for (const [input, names, marked] of IDENTIFY) {
  await check(`identify: ${input.slice(0, 40)}`, async () => {
    const r = await identifyText(input);
    for (const n of names) assert(r.names.includes(n), `no ${n} in ${r.names.join(", ")}`);
    const joined = r.marks.join("");
    for (const m of marked) assert(joined.includes(m), `${m} isn't highlighted (marks: ${r.marks.join(" | ")})`);
    return r.names.join(", ");
  });
}

await check("identify: a format with many matches gets one card", async () => {
  const r = await identifyText("10.0.0.1 10.0.0.2 10.0.0.3 10.0.0.4 10.0.0.5 and bee@skerritt.blog");
  const cards = await identify.$$eval("#matches .match", (els) =>
    els.map((el) => [el.querySelector(".match__name")?.textContent, el.querySelectorAll(".match__chips code").length]),
  );
  const ip = cards.find((c) => /Address Version 4/.test(c[0]));
  assert(ip && /· 5$/.test(ip[0]) && ip[1] === 5, `cards: ${JSON.stringify(cards)}`);
  // Its chips link to Shodan: the card says so on screen, and each link's name says where
  const said = await identify.$$eval("#matches .match", (els) => {
    const card = els.find((el) => /Address Version 4/.test(el.querySelector(".match__name")?.textContent ?? ""));
    return [card?.textContent ?? "", card?.querySelector(".match__chips a")?.textContent ?? ""];
  });
  assert(/links to shodan\.io/.test(said[0]), "the card doesn't name the site its chips open");
  assert(/opens shodan\.io/.test(said[1]), `a chip link is named ${said[1]}`);
  assert(r.marks.filter((m) => /^10\.0\.0\.\d$/.test(m)).length === 5, `marks: ${r.marks.join(" | ")}`);
  return cards.map((c) => c[0]).join("; ");
});

await check("identify: 100,000 dense characters stop at 5,000 matches, and say so", async () => {
  // 12,000 addresses in 96,000 characters: more than the cap
  const dense = "1.1.1.1 ".repeat(12_000);
  await setValue(identify, "#text", dense);
  await identify.waitForFunction(() => document.getElementById("matches-panel").getAttribute("aria-busy") === "false", { timeout: 60_000 });
  const state = await identify.evaluate(() => [document.getElementById("match-count").textContent, document.querySelector("#matches .notice")?.textContent ?? ""]);
  assert(state[0] === "5,000", `count ${state[0]}`);
  assert(/stopped at 5,000 matches/.test(state[1]), `notice: ${state[1]}`);
  return state[0];
});

await check("identify: credentials in a busy format get no lookup links", async () => {
  const tokens = Array.from({ length: 5 }, (_, i) => `12345678901234${i}|AbCdEfGhIjKlMnOpQrStUvWxYz${i}`).join(" ");
  await identifyText(tokens);
  const links = await identify.$$eval("#matches .match", (els) =>
    els.filter((el) => /Facebook/.test(el.querySelector(".match__name")?.textContent ?? "")).map((el) => el.querySelectorAll("a[target=_blank]").length),
  );
  assert(links.length > 0, "no Facebook card");
  assert(links.every((n) => n === 0), `links on credential cards: ${links}`);
  return `${links.length} card(s), no links`;
});

await check("identify: the limit counts characters, not UTF-16 units", async () => {
  await setValue(identify, "#text", "🙂".repeat(60_000));
  await identify.waitForFunction(() => document.getElementById("matches-panel").getAttribute("aria-busy") === "false", { timeout: 60_000 });
  const emoji = await identify.evaluate(() => document.getElementById("text-error").hidden);
  await setValue(identify, "#text", "a".repeat(100_001));
  await identify.waitForFunction(() => !document.getElementById("text-error").hidden, { timeout: 10_000 });
  assert(emoji, "60,000 emoji (120,000 UTF-16 units) were refused");
  return "60,000 emoji taken, 100,001 characters refused";
});

await check("identify: typing is announced once it pauses", async () => {
  await setValue(identify, "#text", "");
  await identify.evaluate(() => {
    window.__said = [];
    new MutationObserver(() => {
      const t = document.getElementById("announcer").textContent;
      if (t) window.__said.push(t);
    }).observe(document.getElementById("announcer"), { childList: true, characterData: true, subtree: true });
  });
  await identify.focus("#text");
  await identify.keyboard.type("mail bee@skerritt.blog now", { delay: 120 });
  await new Promise((r) => setTimeout(r, 2000));
  const said = await identify.evaluate(() => window.__said);
  assert(said.length >= 1 && said.length <= 2, `said ${said.length} times: ${said.join(" | ")}`);
  return said.join(" | ");
});

await check("identify: the default sort puts the most specific first", async () => {
  const page = await open("identify/");
  try {
    await engineReady(page);
    await setValue(page, "#text", "Email bee@skerritt.blog from 192.168.0.1");
    await page.waitForSelector("#matches:not([hidden]) .match", { timeout: 20_000 });
    const rarities = await page.$$eval("#matches .rarity", (els) => els.map((el) => Number(el.textContent.replace(/[^\d.]/g, ""))));
    assert(rarities.length > 1 && rarities.every((r, i) => i === 0 || r <= rarities[i - 1]), `rarities ${rarities}`);
    return rarities.join(" ≥ ");
  } finally {
    await page.closeAll();
  }
});

await check("identify: rarity, exclude and sorting", async () => {
  await identifyText("Email bee@skerritt.blog from 192.168.0.1 about https://github.com/bee-san/pyWhat");
  await identify.click("#filters summary");
  await setValue(identify, "#min-rarity", "0.6");
  await identify.waitForFunction(() => ![...document.querySelectorAll("#matches .match__name")].some((n) => n.textContent === "Email Address"), { timeout: 10_000 });
  await identify.type("#exclude-input", "URL");
  await identify.keyboard.press("Enter");
  await identify.waitForFunction(() => ![...document.querySelectorAll("#matches .match__name")].some((n) => /URL/.test(n.textContent)), { timeout: 10_000 });
  const left = await texts(identify, "#matches .match__name");
  assert(left.length === 1 && left[0] === "Internet Protocol (IP) Address Version 4", `left ${left}`);
  await identify.click("#reset-filters");
  await identify.select("#sort", "name");
  await identify.waitForFunction(() => document.querySelectorAll("#matches .match").length >= 4, { timeout: 10_000 });
  const sorted = await texts(identify, "#matches .match__name");
  const expected = [...sorted].sort((a, b) => a.localeCompare(b, "en", { sensitivity: "base" }));
  assert(JSON.stringify(sorted) === JSON.stringify(expected), `not sorted: ${sorted}`);
  return `${left[0]} at 0.6 without URL; sorted ${sorted.length}`;
});

await check("identify: lookup links name their site, and credentials get none", async () => {
  await identifyText("192.168.0.1 123456789012345|AbCdEfGhIjKlMnOpQrStUvWxYz0");
  const links = await identify.$$eval("#matches .match", (els) =>
    els.map((el) => [el.querySelector(".match__name")?.textContent, el.querySelector(".match__actions a")?.textContent ?? null]),
  );
  const ip = links.find((l) => /Address Version 4/.test(l[0]));
  assert(ip && /^Look it up on shodan\.io/.test(ip[1]), `IP: ${JSON.stringify(ip)}`);
  const token = links.find((l) => /Facebook/.test(l[0]));
  assert(!token || token[1] === null, `token: ${JSON.stringify(token)}`);
  return links.map((l) => `${l[0]}: ${l[1] ?? "no link"}`).join("; ");
});

await check("identify: hostile text stays text", async () => {
  await identifyText('<img src=x onerror="window.__xss=1"> bee@skerritt.blog <script>window.__xss=2</script> [link=javascript:alert(1)]x[/link]');
  const state = await identify.evaluate(() => ({
    xss: window.__xss,
    injected: document.querySelectorAll("#matches img, #matches script, #backdrop img, #backdrop script, #backdrop *:not(mark)").length,
    jsLinks: [...document.querySelectorAll("a")].filter((a) => !/^https?:/.test(a.href)).length,
  }));
  assert(state.xss === undefined && state.injected === 0 && state.jsLinks === 0, JSON.stringify(state));
  return "no markup, no script";
});

await check("identify: results for a text that was cleared never come back", async () => {
  const big = "Email bee@skerritt.blog from 192.168.0.1 about https://github.com/bee-san/pyWhat\n".repeat(1100);
  await setValue(identify, "#text", big);
  await new Promise((r) => setTimeout(r, 300));
  await setValue(identify, "#text", "");
  await new Promise((r) => setTimeout(r, 4000));
  const state = await identify.evaluate(() => ({
    cards: document.querySelectorAll("#matches .match").length,
    listHidden: document.getElementById("matches").hidden,
    marks: document.querySelectorAll("#backdrop mark").length,
  }));
  assert(state.cards === 0 || state.listHidden, `stale results: ${JSON.stringify(state)}`);
  assert(state.marks === 0, `${state.marks} stale highlights`);
  return JSON.stringify(state);
});

await check("identify: an unknown tag is explained, not a crash", async () => {
  await identifyText("bee@skerritt.blog");
  await identify.$eval("#filters", (d) => (d.open = true));
  await identify.type("#include-input", "NoSuchTagAtAll");
  await identify.keyboard.press("Enter");
  await identify.waitForFunction(() => !document.getElementById("filters-error").hidden, { timeout: 10_000 });
  const message = await text(identify, "#filters-error");
  await identify.click("#reset-filters");
  return message;
});
await identify.closeAll();

await check("identify: an identify/#text= link opens its text, which leaves the address bar on edit", async () => {
  const page = await open(`identify/#text=${encodeURIComponent("bee@skerritt.blog")}`);
  try {
    await engineReady(page);
    await page.waitForSelector("#matches:not([hidden]) .match", { timeout: 20_000 });
    await page.type("#text", " ");
    const hash = await page.evaluate(() => location.hash);
    assert(hash === "", `the hash stayed: ${hash}`);
    return "text opened, hash gone";
  } finally {
    await page.closeAll();
  }
});

await check("hostile text in the language panel stays text", async () => {
  const page = await open("language/");
  try {
    await engineReady(page);
    await setValue(page, "#text", '<img src=x onerror="window.__xss=1"><script>window.__xss=2</script> hello there');
    await page.waitForFunction(() => document.getElementById("verdict-title").textContent !== "Type some text");
    const xss = await page.evaluate(() => [typeof window.__xss, document.querySelectorAll("main img, main script").length]);
    assert(xss[0] === "undefined" && xss[1] === 0, JSON.stringify(xss));
    return "no markup, no script";
  } finally {
    await page.closeAll();
  }
});

// --- Is it language? -----------------------------------------------------------------------

const language = await open("language/");
await check("language: gibberish-or-not loads", async () => {
  await engineReady(language);
  return await text(language, "#engine-status");
});
for (const [input, verdict] of [
  ["The quick brown fox jumps over the lazy dog", "Language"],
  ["asdkj qweoiu zxcmnb lkjqwe", "Not language"],
  ["Wkh txlfn eurzq ira mxpsv ryhu wkh odcb grj", "Not language"],
]) {
  await check(`language: ${input.slice(0, 30)}`, async () => {
    await setValue(language, "#text", input);
    await language.waitForFunction((v) => document.getElementById("verdict-title").textContent === v, { timeout: 10_000 }, verdict);
    return `${verdict}, ${await text(language, "#verdict-detail")}, score ${await text(language, "#score-value")}`;
  });
}
await check("language: over 10,000 characters it says only the first are checked", async () => {
  await setValue(language, "#text", "The quick brown fox jumps over the lazy dog. ".repeat(230));
  const hint = await text(language, "#text-hint");
  assert(/Only the first 10,000 characters are checked/.test(hint), `hint: ${hint}`);
  return hint;
});

await check("language: the verdict follows the sensitivity", async () => {
  // Scores 0.835: language at High (0.5) and Medium (0.75), not at Low (0.9)
  await setValue(language, "#text", "the quick brwn fx");
  const at = async (level) => {
    await language.click(`label[for="sens-${level}"]`);
    await new Promise((r) => setTimeout(r, 200));
    return [await text(language, "#verdict-title"), await text(language, "#verdict-detail")];
  };
  const high = await at("high");
  const low = await at("low");
  assert(high[0] === "Language" && low[0] === "Not language", `High: ${high}; Low: ${low}`);
  assert(/High and Medium sensitivity, not at Low/.test(low[1]), `Low says ${low[1]}`);
  await at("medium");
  return `High: ${high[0]}; Low: ${low[1]}`;
});
await language.closeAll();

// --- The pages' policy ----------------------------------------------------------------------

for (const path of ["", "identify/", "language/"]) {
  await check(`csp: ${path || "decode"} carries exactly the policy, as its first element after the charset`, async () => {
    const html = await (await fetch(base + path)).text();
    const head = html.slice(0, html.indexOf("</head>"));
    const tags = [...head.matchAll(/<(meta|script|link|style|title|base)\b[^>]*>/gi)].map((m) => m[0]);
    assert(/^<meta charset=/i.test(tags[0] ?? ""), `first tag ${tags[0]}`);
    assert(tags[1] === `<meta http-equiv="Content-Security-Policy" content="${CSP}">`, `second tag ${tags[1]}`);
    assert(!/<script(?![^>]*\bsrc=)[^>]*>/i.test(html), "an inline script");
    assert(!/<style\b|\sstyle=|\son[a-z]+=/i.test(html), "an inline style or handler");
    assert((html.match(/Content-Security-Policy/g) ?? []).length === 1, "more than one policy");
    return "exact, first";
  });
}

await check("decode: a 20 s search with no plaintext ends without a crash", async () => {
  const page = await open("");
  try {
    await engineReady(page);
    await page.click("#options summary");
    await setValue(page, "#timeout", "20");
    await setValue(page, "#regex", "^no-such-plaintext$");
    await setValue(page, "#input", "kq8vZ2mXw!9tLr#");
    await page.click("#decode");
    const r = await decodeResult(page, 60_000);
    assert(/No plaintext found in 20 seconds|tried everything|before your browser ran out of memory/.test(r.notice ?? ""), `got ${r.notice}`);
    return r.notice;
  } finally {
    await page.closeAll();
  }
});

// --- Accessibility --------------------------------------------------------------------------

await axeEverywhere("decode (empty)", "", async (page) => {
  await engineReady(page);
});
await axeEverywhere("decode (result, options open)", "", async (page) => {
  await engineReady(page);
  await page.click("#options summary");
  await page.click('#examples [data-example="rot13-base64"]');
  await decodeResult(page);
});
await axeEverywhere("decode (searching)", "", async (page) => {
  await engineReady(page);
  await setValue(page, "#input", "SGVsbG8gZnJvbSB0aGUgb3RoZXIgc2lkZSBvZiB0aGUgd29ybGQ=XqZ7");
  await page.$eval("#regex", (el) => (el.value = "^no$"));
  await page.click("#decode");
  await new Promise((r) => setTimeout(r, 1200));
});
await axeEverywhere("decode (share dialog)", "", async (page) => {
  await engineReady(page);
  await page.click('#examples [data-example="morse"]');
  await decodeResult(page);
  const [share] = await page.$$("xpath/.//button[contains(., 'Share link')]");
  await share.click();
  await page.waitForSelector("#share-dialog[open]");
});
await axeEverywhere("identify (matches, filters open)", "identify/", async (page) => {
  await engineReady(page);
  await page.click("#filters summary");
  await page.click("#examples .chip");
  await page.waitForSelector("#matches:not([hidden]) .match");
});
await axeEverywhere("identify (nothing found)", "identify/", async (page) => {
  await engineReady(page);
  await setValue(page, "#text", "zzzz");
  await page.waitForSelector("#matches-none:not([hidden])");
});
await axeEverywhere("language (verdict)", "language/", async (page) => {
  await engineReady(page);
  await page.click("#examples .chip");
  await page.waitForFunction(() => document.getElementById("verdict-title").textContent !== "Type some text");
});

await check("narrow screens: no page scrolls sideways at 320 px", async () => {
  const widths = [];
  for (const [path, fill] of [
    ["", async (p) => {
      await p.click('#examples [data-example="vigenere"]');
      await decodeResult(p);
    }],
    ["identify/", async (p) => {
      await p.click("#examples .chip");
      await p.waitForSelector("#matches:not([hidden]) .match");
    }],
    ["language/", async (p) => {
      await p.click("#examples .chip");
      await p.waitForFunction(() => document.getElementById("verdict-title").textContent !== "Type some text");
    }],
  ]) {
    const page = await open(path, { width: 320, height: 640 });
    try {
      await engineReady(page);
      await fill(page);
      const { overflow, out } = await sideways(page);
      assert(overflow <= 0, `${path || "decode"} scrolls sideways by ${overflow} px (${out})`);
      widths.push(`${path || "decode"} ok`);
    } finally {
      await page.closeAll();
    }
  }
  return widths.join(", ");
});

// --- What the pages asked for ---------------------------------------------------------------

await check("every page's footer states the privacy promise and its one exception", async () => {
  for (const path of ["", "identify/", "language/"]) {
    const html = await (await fetch(base + path)).text();
    assert(/What you paste stays on this page, unless you open one of Identify's lookup links/.test(html), `${path || "decode"}: footer`);
    assert(/Tatoeba/.test(html) && /CC BY-SA 4\.0/.test(html), `${path || "decode"}: data credits`);
  }
  return "3 pages";
});

if (!only) {
  report("privacy: no request left the site's origin", problems.foreign.size === 0, [...problems.foreign].slice(0, 5).join(", "));
  report("no CSP violations", problems.csp.length === 0, problems.csp.slice(0, 5).join("; "));
  report("no console errors", problems.console.length === 0, problems.console.slice(0, 5).join("; "));
}

await browser.close();
server?.close();
const passed = results.filter((r) => r.ok).length;
console.log(`\n${passed}/${results.length} checks passed, ${axeRuns} axe runs (${AXE_TAGS.join(", ")}) against ${base}`);
console.log(failed ? "E2E_FAIL" : "E2E_OK");
process.exit(failed ? 1 : 0);
