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
async function open(path, { width = 1280, height = 900, theme = "light", reducedMotion = false } = {}) {
  const context = await browser.createBrowserContext();
  const page = await context.newPage();
  await page.setViewport({ width, height, deviceScaleFactor: 1 });
  await page.emulateMediaFeatures([
    { name: "prefers-color-scheme", value: theme },
    { name: "prefers-reduced-motion", value: reducedMotion ? "reduce" : "no-preference" },
  ]);
  page.on("request", (r) => {
    const u = r.url();
    if (!u.startsWith("data:") && !u.startsWith("blob:") && new URL(u).origin !== origin) problems.foreign.add(u);
  });
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

await check("decode: the tree grows while searching, then advice when nothing is found", async () => {
  await decode.click("#options summary");
  await setValue(decode, "#timeout", "3");
  await setValue(decode, "#regex", "^ZZZZ-no-such-plaintext$");
  await setValue(decode, "#input", "SGVsbG8gZnJvbSB0aGUgb3RoZXIgc2lkZSBvZiB0aGUgd29ybGQ=XqZ7");
  await decode.click("#decode");
  await new Promise((r) => setTimeout(r, 1500));
  const midway = await decode.evaluate(() => ({
    nodes: document.querySelectorAll("#tree .node").length,
    stats: document.getElementById("search-stats")?.textContent ?? "",
    searching: !document.getElementById("search").hidden,
  }));
  assert(midway.searching, "the search ended before 1.5 s");
  assert(midway.nodes > 10, `only ${midway.nodes} tree nodes after 1.5 s`);
  assert(/nodes explored/.test(midway.stats), `no counters: ${midway.stats}`);
  const r = await decodeResult(decode, 15_000);
  assert(/No plaintext found in 3 seconds|tried everything/.test(r.notice ?? ""), `got ${r.notice}`);
  const tips = await texts(decode, "#result .notice li");
  assert(tips.length >= 2, "no advice");
  return `${midway.nodes} nodes drawn at 1.5 s; "${r.notice}"`;
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

await check("decode: a crib that isn't a valid regex is reported at the crib", async () => {
  await setValue(decode, "#regex", "flag{(");
  await decode.click("#decode");
  await decode.waitForFunction(() => !document.getElementById("regex-error").hidden, { timeout: 10_000 });
  const message = await text(decode, "#regex-error");
  const invalid = await decode.$eval("#regex", (el) => el.getAttribute("aria-invalid"));
  assert(invalid === "true", "the crib isn't marked invalid");
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
  await decode.keyboard.press("Escape");
  await decode.waitForFunction(() => !document.getElementById("share-dialog").open);
  return url.slice(url.indexOf("#"));
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

await check("decode: keyboard focus is visible on every stop, skip link first", async () => {
  const page = await open("");
  try {
    await engineReady(page);
    await page.keyboard.press("Tab");
    const first = await page.evaluate(() => document.activeElement?.className);
    assert(first === "skip-link", `first stop is ${first}`);
    await page.keyboard.press("Enter");
    const stops = [];
    for (let i = 0; i < 14; i++) {
      await page.keyboard.press("Tab");
      stops.push(
        await page.evaluate(() => {
          const el = document.activeElement;
          const s = getComputedStyle(el);
          const visible = (s.outlineStyle !== "none" && parseFloat(s.outlineWidth) >= 2) || s.boxShadow !== "none";
          const label = el.id || el.dataset.example || el.textContent.trim().slice(0, 20) || el.tagName;
          return { label, visible };
        }),
      );
    }
    const invisible = stops.filter((s) => !s.visible).map((s) => s.label);
    assert(invisible.length === 0, `no visible focus on ${invisible.join(", ")}`);
    const order = stops.map((s) => s.label);
    for (const id of ["input", "open-file", "base64x3", "decode"]) assert(order.includes(id), `${id} isn't reachable: ${order.join(" > ")}`);
    assert(order.indexOf("input") < order.indexOf("base64x3") && order.indexOf("base64x3") < order.indexOf("decode"), `order ${order.join(" > ")}`);
    return order.join(" > ");
  } finally {
    await page.closeAll();
  }
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

await check("identify: an unknown tag is explained, not a crash", async () => {
  await identify.click("#filters summary").catch(() => {});
  await identify.$eval("#filters", (d) => (d.open = true));
  await identify.type("#include-input", "NoSuchTagAtAll");
  await identify.keyboard.press("Enter");
  await identify.waitForFunction(() => !document.getElementById("filters-error").hidden, { timeout: 10_000 });
  const message = await text(identify, "#filters-error");
  await identify.click("#reset-filters");
  return message;
});
await identify.closeAll();

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
await language.closeAll();

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
