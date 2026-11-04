#!/usr/bin/env node
// Measures what each page transfers and how long it takes to be usable, on a cold cache, in
// headless Chrome with the network throttled:
//
//   CHROME=/path/to/chrome node scripts/measure.mjs [--url https://bee-san.github.io/Ciphey/] [--runs 5]
//
// Without --url it serves dist/ like GitHub Pages does (scripts/serve.mjs: gzip, no brotli).
// Each run is a new browser context (empty cache). Per page it reports the bytes transferred
// (compressed, as sent over the network) by kind, the first contentful paint, and "ready":
// when the page's engine has loaded and the tool can be used (the status line says so).
// Prints a Markdown table of the medians.
import puppeteer from "puppeteer-core";
import { serve } from "./serve.mjs";

const args = process.argv.slice(2);
const arg = (name, fallback) => (args.includes(`--${name}`) ? args[args.indexOf(`--${name}`) + 1] : fallback);
const runs = Number(arg("runs", "5"));
const PROFILES = {
  // Cable or fibre
  fast: { latency: 20, downloadThroughput: (50e6 / 8) | 0, uploadThroughput: (10e6 / 8) | 0 },
  // A good mobile connection
  "4g": { latency: 60, downloadThroughput: (12e6 / 8) | 0, uploadThroughput: (4e6 / 8) | 0 },
};
const profiles = arg("profiles", "fast,4g").split(",");

let server = null;
let base = arg("url", null);
if (!base) {
  const path = process.env.BASE_PATH ?? "/Ciphey/";
  server = await serve({ port: 0, root: new URL("../dist", import.meta.url).pathname, base: path });
  base = `http://127.0.0.1:${server.address().port}${path}`;
}
const browser = await puppeteer.launch({ executablePath: process.env.CHROME, headless: true, args: ["--no-sandbox", "--disable-gpu"] });

async function once(path, profile) {
  const context = await browser.createBrowserContext();
  const page = await context.newPage();
  await page.setViewport({ width: 1280, height: 900 });
  // A new context has an empty cache; the conditions also apply to the workers' requests
  const cdp = await page.createCDPSession();
  await cdp.send("Network.enable");
  await cdp.send("Network.emulateNetworkConditions", { offline: false, ...PROFILES[profile] });
  const t0 = Date.now();
  await page.goto(base + path, { waitUntil: "load" });
  await page.waitForFunction(() => /is ready/.test(document.getElementById("engine-status")?.textContent ?? ""), {
    timeout: 120_000,
    polling: "mutation",
  });
  const ready = await page.evaluate(() => performance.now());
  const fcp = await page.evaluate(() => performance.getEntriesByName("first-contentful-paint")[0]?.startTime ?? null);
  // Bytes from Resource Timing (transferSize: compressed body plus headers), in the page and
  // in its workers, which fetch the WebAssembly
  const entries = () => [
    ...performance.getEntriesByType("navigation").map((e) => [e.name, "Document", e.transferSize]),
    ...performance.getEntriesByType("resource").map((e) => [e.name, e.initiatorType, e.transferSize]),
  ];
  const all = [...(await page.evaluate(entries))];
  for (const worker of page.workers()) all.push(...(await worker.evaluate(entries)));
  const bytes = { html: 0, css: 0, js: 0, wasm: 0, other: 0 };
  for (const [url, type, size] of all) {
    const k = url.endsWith(".wasm") ? "wasm" : type === "Document" ? "html" : url.endsWith(".css") ? "css" : url.endsWith(".js") ? "js" : "other";
    bytes[k] += size;
  }
  await context.close();
  return { ready, fcp, bytes, wall: Date.now() - t0 };
}

const median = (xs) => {
  const s = [...xs].sort((a, b) => a - b);
  return s.length % 2 ? s[(s.length - 1) / 2] : (s[s.length / 2 - 1] + s[s.length / 2]) / 2;
};
const kb = (n) => `${Math.round(n / 1000).toLocaleString("en")} KB`;

console.log(`Cold cache, ${runs} runs each, median; ${base}`);
for (const profile of profiles) {
  const p = PROFILES[profile];
  console.log(`\n**${profile}**: ${Math.round((p.downloadThroughput * 8) / 1e6)} Mbit/s down, ${p.latency} ms latency\n`);
  console.log("| Page | Transferred | HTML | CSS | JS | WebAssembly | First paint | Ready |");
  console.log("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |");
  for (const [name, path] of [
    ["Decode", ""],
    ["Identify", "identify/"],
    ["Is it language?", "language/"],
  ]) {
    const all = [];
    for (let i = 0; i < runs; i++) all.push(await once(path, profile));
    const total = (r) => Object.values(r.bytes).reduce((a, b) => a + b, 0);
    const m = (f) => median(all.map(f));
    console.log(
      `| ${name} | ${kb(m(total))} | ${kb(m((r) => r.bytes.html))} | ${kb(m((r) => r.bytes.css))} | ${kb(m((r) => r.bytes.js))} | ${kb(m((r) => r.bytes.wasm))} | ${Math.round(m((r) => r.fcp ?? 0))} ms | ${(m((r) => r.ready) / 1000).toFixed(2)} s |`,
    );
  }
}
await browser.close();
server?.close();
