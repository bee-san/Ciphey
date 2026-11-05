import { defineConfig } from "vitest/config";

// The unit tests cover the pages' logic (src/lib, the Decode words, the tree), which doesn't
// need a DOM; the end-to-end test (tests/e2e) drives the real pages in Chrome.
export default defineConfig({
  test: {
    include: ["tests/unit/**/*.test.ts"],
    environment: "node",
  },
});
