#!/usr/bin/env node
// The screenshots in web/screenshots/, for the pull request and the README: each page in
// both themes, at desktop and phone sizes, the live tree mid-search, Identify's highlights
// and the language panel. Viewport shots, at most 1280 px on each side.
//
//   CHROME=/path/to/chrome node scripts/screenshots.mjs        # needs a build in dist/
import { mkdirSync, statSync } from "node:fs";
import puppeteer from "puppeteer-core";
import { serve } from "./serve.mjs";

const out = new URL("../screenshots/", import.meta.url).pathname;
mkdirSync(out, { recursive: true });
const path = process.env.BASE_PATH ?? "/Ciphey/";
const server = await serve({ port: 0, root: new URL("../dist", import.meta.url).pathname, base: path });
const base = `http://127.0.0.1:${server.address().port}${path}`;
const browser = await puppeteer.launch({ executablePath: process.env.CHROME, headless: true, args: ["--no-sandbox", "--disable-gpu"] });

const DESKTOP = { width: 1280, height: 900, deviceScaleFactor: 1 };
// A phone at 2x: 390 x 640 CSS px, 780 x 1280 image px
const PHONE = { width: 390, height: 640, deviceScaleFactor: 2, isMobile: true, hasTouch: true };

async function shot(name, path, viewport, theme, prepare) {
  const context = await browser.createBrowserContext();
  const page = await context.newPage();
  await page.setViewport(viewport);
  await page.emulateMediaFeatures([{ name: "prefers-color-scheme", value: theme }]);
  await page.goto(base + path, { waitUntil: "load" });
  await page.waitForFunction(() => /is ready/.test(document.getElementById("engine-status")?.textContent ?? ""), { timeout: 60_000 });
  await prepare(page);
  // Settle: animations, the tree's last frame
  await new Promise((r) => setTimeout(r, 400));
  const file = `${out}${name}.png`;
  await page.screenshot({ path: file });
  await context.close();
  console.log(`${name}.png ${Math.round(statSync(file).size / 1000)} KB`);
}

const setValue = (page, selector, value) =>
  page.$eval(
    selector,
    (el, v) => {
      el.value = v;
      el.dispatchEvent(new Event("input", { bubbles: true }));
    },
    value,
  );

const decoded = async (page, example = "rot13-base64") => {
  await page.click(`#examples [data-example="${example}"]`);
  await page.waitForSelector("#result:not([hidden]) .plaintext", { timeout: 30_000 });
};

const scrollTo = (page, selector) => page.$eval(selector, (el) => el.scrollIntoView({ block: "start" }));

for (const theme of ["dark", "light"]) {
  await shot(`decode-${theme}-desktop`, "", DESKTOP, theme, (p) => decoded(p));
  await shot(`decode-${theme}-mobile`, "", PHONE, theme, async (p) => {
    await decoded(p, "base64x3");
    await scrollTo(p, "#output");
  });
}
await shot("decode-empty-light-desktop", "", DESKTOP, "light", async () => {});
await shot("decode-live-tree-dark", "", DESKTOP, "dark", async (p) => {
  await p.click("#options summary");
  await setValue(p, "#timeout", "20");
  await setValue(p, "#regex", "^no-such-plaintext$");
  await setValue(p, "#input", "SGVsbG8gZnJvbSB0aGUgb3RoZXIgc2lkZSBvZiB0aGUgd29ybGQ=XqZ7");
  await p.click("#options summary");
  await p.click("#decode");
  await new Promise((r) => setTimeout(r, 2500));
  await scrollTo(p, "#output");
});
await shot("decode-nothing-found-light", "", DESKTOP, "light", async (p) => {
  await p.click("#options summary");
  await setValue(p, "#timeout", "2");
  await setValue(p, "#input", "kq8vZ2mXw!9tLr#");
  await p.click("#options summary");
  await p.click("#decode");
  await p.waitForSelector("#result:not([hidden]) .notice", { timeout: 30_000 });
  await scrollTo(p, "#output");
});
for (const theme of ["light", "dark"]) {
  await shot(`identify-${theme}-desktop`, "identify/", DESKTOP, theme, async (p) => {
    await p.click("#examples .chip");
    await p.waitForSelector("#matches:not([hidden]) .match");
    await p.hover("#matches .match:nth-child(3)");
  });
}
await shot("identify-light-mobile", "identify/", PHONE, "light", async (p) => {
  await p.click("#examples .chip:nth-child(2)");
  await p.waitForSelector("#matches:not([hidden]) .match");
});
for (const theme of ["dark", "light"]) {
  await shot(`language-${theme}-desktop`, "language/", DESKTOP, theme, async (p) => {
    await p.click(theme === "dark" ? "#examples .chip" : "#examples .chip:nth-child(2)");
    await p.waitForFunction(() => document.getElementById("verdict-title").textContent !== "Type some text");
  });
}

await browser.close();
server.close();
