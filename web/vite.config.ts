import { resolve } from "node:path";
import { defineConfig } from "vite";
import { shell } from "./scripts/shell.ts";

// The site lives at https://bee-san.github.io/Ciphey/. BASE_PATH overrides it, e.g. "/" to
// serve dist/ at the root of another host.
const base = process.env.BASE_PATH ?? "/Ciphey/";

export default defineConfig({
  base,
  plugins: [shell({ versionsFile: resolve(import.meta.dirname, "src/wasm/versions.json"), commit: process.env.GITHUB_SHA })],
  build: {
    target: "es2022",
    // Three pages, each a tool with its own worker and WebAssembly module, loaded only there
    rollupOptions: {
      input: {
        decode: resolve(import.meta.dirname, "index.html"),
        identify: resolve(import.meta.dirname, "identify/index.html"),
        language: resolve(import.meta.dirname, "language/index.html"),
      },
    },
    // No data: URLs (the CSP has no data: source); every asset is a file
    assetsInlineLimit: 0,
    reportCompressedSize: false,
  },
  worker: { format: "es" },
  server: { fs: { allow: [".."] } },
});
