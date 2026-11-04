#!/usr/bin/env node
// Serves web/dist the way GitHub Pages serves the site: under /Ciphey/, directories as their
// index.html, gzip when the browser accepts it, .wasm as application/wasm, 404 otherwise.
// For `npm run preview`, the end-to-end test and the measurements; no dependencies.
//
//   node scripts/serve.mjs [--port 4173] [--root dist] [--base /Ciphey/]
import { createReadStream, existsSync, statSync } from "node:fs";
import { createServer } from "node:http";
import { extname, join, normalize, resolve } from "node:path";
import { pipeline } from "node:stream";
import { fileURLToPath } from "node:url";
import { createGzip } from "node:zlib";

const TYPES = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".wasm": "application/wasm",
  ".svg": "image/svg+xml",
  ".json": "application/json",
  ".png": "image/png",
  ".txt": "text/plain; charset=utf-8",
};
const COMPRESSIBLE = new Set([".html", ".js", ".mjs", ".css", ".wasm", ".svg", ".json", ".txt"]);

export function serve({ port = 4173, root = "dist", base = "/Ciphey/", host = "127.0.0.1" } = {}) {
  const dir = resolve(root);
  const server = createServer((req, res) => {
    const url = new URL(req.url ?? "/", "http://localhost");
    if (url.pathname === "/" && base !== "/") {
      res.writeHead(302, { location: base }).end();
      return;
    }
    if (!url.pathname.startsWith(base)) {
      res.writeHead(404, { "content-type": TYPES[".txt"] }).end("404: not under the site's base path\n");
      return;
    }
    let file = normalize(join(dir, decodeURIComponent(url.pathname.slice(base.length))));
    if (!file.startsWith(dir)) {
      res.writeHead(403).end();
      return;
    }
    if (existsSync(file) && statSync(file).isDirectory()) {
      if (!url.pathname.endsWith("/")) {
        res.writeHead(301, { location: `${url.pathname}/` }).end();
        return;
      }
      file = join(file, "index.html");
    }
    if (!existsSync(file) || !statSync(file).isFile()) {
      res.writeHead(404, { "content-type": TYPES[".txt"] }).end("404\n");
      return;
    }
    const ext = extname(file);
    const headers = { "content-type": TYPES[ext] ?? "application/octet-stream", "cache-control": "max-age=600" };
    const gzip = COMPRESSIBLE.has(ext) && /\bgzip\b/.test(req.headers["accept-encoding"] ?? "");
    if (gzip) {
      res.writeHead(200, { ...headers, "content-encoding": "gzip", vary: "Accept-Encoding" });
      if (req.method === "HEAD") return res.end();
      pipeline(createReadStream(file), createGzip({ level: 6 }), res, () => {});
    } else {
      res.writeHead(200, { ...headers, "content-length": statSync(file).size });
      if (req.method === "HEAD") return res.end();
      pipeline(createReadStream(file), res, () => {});
    }
  });
  return new Promise((done) => server.listen(port, host, () => done(server)));
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const arg = (name, fallback) => {
    const i = process.argv.indexOf(`--${name}`);
    return i > 0 ? process.argv[i + 1] : fallback;
  };
  const port = Number(arg("port", "4173"));
  const base = arg("base", "/Ciphey/");
  await serve({ port, root: arg("root", "dist"), base });
  console.log(`Serving dist at http://127.0.0.1:${port}${base}`);
}
