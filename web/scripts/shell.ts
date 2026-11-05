// Build-time HTML for the three pages: the shared header and footer, and the Content Security
// Policy. The pages are plain HTML files with <!--shell:header--> and <!--shell:footer-->
// placeholders, so the shell is in the HTML from the first byte (no JavaScript needed to see
// it) and written once, here.

import { existsSync, readFileSync } from "node:fs";
import type { Plugin } from "vite";

export type PageId = "decode" | "identify" | "language";

const PAGES: ReadonlyArray<{ id: PageId; path: string; label: string }> = [
  { id: "decode", path: "", label: "Decode" },
  { id: "identify", path: "identify/", label: "Identify" },
  { id: "language", path: "language/", label: "Is it language?" },
];

/**
 * GitHub Pages can't send headers, so the policy is a <meta> tag (which can't set
 * frame-ancestors or report-uri). Scripts, styles, workers and fetches are same-origin only,
 * nothing is inline, and there's no connect-src beyond 'self': the page has nowhere to send
 * what you type. WebAssembly runs in the workers, which the page's policy doesn't cover;
 * their code is ours and only fetches its own .wasm file.
 */
export const CSP = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self'",
  "font-src 'self'",
  "connect-src 'self'",
  "worker-src 'self'",
  "manifest-src 'self'",
  "base-uri 'none'",
  "form-action 'none'",
].join("; ");

interface Versions {
  ciphey: string;
  pywhat: string;
  gibberish: string;
}

function readVersions(file: string): Versions {
  if (!existsSync(file)) return { ciphey: "dev", pywhat: "dev", gibberish: "dev" };
  return JSON.parse(readFileSync(file, "utf8")) as Versions;
}

const esc = (s: string) => s.replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c] as string);

const MARK = `<svg class="brand__mark" viewBox="0 0 32 32" width="28" height="28" aria-hidden="true" focusable="false"><rect width="32" height="32" rx="8" class="brand__tile"/><path class="brand__layers" d="M22.5 9.2a9.5 9.5 0 1 0 0 13.6M19.6 12.3a5.3 5.3 0 1 0 0 7.4" fill="none" stroke-width="2.6" stroke-linecap="round"/><circle class="brand__core" cx="15.6" cy="16" r="1.9"/></svg>`;

const SUN = `<svg class="icon icon--sun" viewBox="0 0 24 24" width="20" height="20" aria-hidden="true" focusable="false"><circle cx="12" cy="12" r="4.2"/><path d="M12 2.5v2.2M12 19.3v2.2M2.5 12h2.2M19.3 12h2.2M5.3 5.3l1.6 1.6M17.1 17.1l1.6 1.6M5.3 18.7l1.6-1.6M17.1 6.9l1.6-1.6"/></svg>`;
const MOON = `<svg class="icon icon--moon" viewBox="0 0 24 24" width="20" height="20" aria-hidden="true" focusable="false"><path d="M20 14.6A8.5 8.5 0 0 1 9.4 4a8.5 8.5 0 1 0 10.6 10.6z"/></svg>`;
const CODE = `<svg class="icon" viewBox="0 0 24 24" width="20" height="20" aria-hidden="true" focusable="false"><path d="M8.5 7 3.5 12l5 5M15.5 7l5 5-5 5"/></svg>`;

export function header(base: string, page: PageId): string {
  const links = PAGES.map(
    (p) => `<li><a href="${base}${p.path}"${p.id === page ? ' aria-current="page"' : ""}>${esc(p.label)}</a></li>`,
  ).join("");
  return `<a class="skip-link" href="#main">Skip to main content</a>
<header class="site-header">
  <div class="site-header__inner">
    <a class="brand" href="${base}">${MARK}<span class="brand__name">Ciphey</span></a>
    <nav class="tools-nav" aria-label="Tools"><ul>${links}</ul></nav>
    <div class="site-header__actions">
      <button type="button" class="icon-button" id="theme-toggle" aria-pressed="false" title="Dark theme">${SUN}${MOON}<span class="visually-hidden">Dark theme</span></button>
      <a class="icon-button" href="https://github.com/bee-san/Ciphey" title="Source code on GitHub">${CODE}<span class="visually-hidden">Source code on GitHub</span></a>
    </div>
  </div>
</header>`;
}

export function footer(v: Versions, commit: string | undefined): string {
  const built = commit
    ? ` · built from <a href="https://github.com/bee-san/Ciphey/commit/${esc(commit)}"><code>${esc(commit.slice(0, 8))}</code></a>`
    : "";
  return `<footer class="site-footer">
  <div class="site-footer__inner">
    <p class="site-footer__privacy">Everything runs in your browser: no server, no analytics, no cookies. What you paste stays on this page, unless you open one of Identify's lookup links, which sends that match to the site it names.</p>
    <p class="site-footer__meta"><a href="https://github.com/bee-san/Ciphey">Ciphey</a> ${esc(v.ciphey)} · <a href="https://github.com/bee-san/pyWhat">pyWhat</a> ${esc(v.pywhat)} · <a href="https://github.com/bee-san/gibberish-or-not">gibberish-or-not</a> ${esc(v.gibberish)} · MIT licence${built}</p>
    <details class="site-footer__credits">
      <summary>Credits and data licences</summary>
      <ul>
        <li>Formats identified with <a href="https://github.com/bee-san/pyWhat">pyWhat</a> (MIT). Some of its regexes are based on <a href="https://regex101.com/library">regex101</a> community library entries, and on Dora (Siddharth Dushantha, MIT) and gf (Tom Hudson, MIT).</li>
        <li>pyWhat's file signatures come from Wikipedia's <a href="https://en.wikipedia.org/wiki/List_of_file_signatures">List of file signatures</a> (CC BY-SA 4.0).</li>
        <li>gibberish-or-not's English model is built from <a href="https://tatoeba.org">Tatoeba</a> sentences (CC BY 2.0 FR, by the Tatoeba contributors), public-domain Project Gutenberg books and the public-domain Moby word lists.</li>
        <li>The rest is in pyWhat's <a href="https://github.com/bee-san/pyWhat/blob/main/docs/data-sources.md">data sources</a> and gibberish-or-not's <a href="https://github.com/bee-san/gibberish-or-not/blob/main/NOTICE">NOTICE</a>.</li>
      </ul>
    </details>
  </div>
</footer>`;
}

/** Fills the placeholders of each page, and adds the CSP to production builds. */
export function shell(options: { versionsFile: string; commit?: string }): Plugin {
  let base = "/";
  let build = false;
  return {
    name: "ciphey-shell",
    configResolved(config) {
      base = config.base;
      build = config.command === "build";
    },
    transformIndexHtml(html, ctx) {
      const page: PageId = ctx.path.includes("/identify/") ? "identify" : ctx.path.includes("/language/") ? "language" : "decode";
      const versions = readVersions(options.versionsFile);
      let out = html
        .replace("<!--shell:header-->", header(base, page))
        .replace("<!--shell:footer-->", footer(versions, options.commit));
      // Vite's dev server injects inline scripts, which the policy (rightly) forbids
      if (build) out = out.replace("<!--shell:csp-->", `<meta http-equiv="Content-Security-Policy" content="${CSP}">`);
      else out = out.replace("<!--shell:csp-->", "");
      return out;
    },
  };
}
