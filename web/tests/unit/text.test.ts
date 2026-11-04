import { describe, expect, it } from "vitest";
import { parseMarkup, plainText, safeHref } from "../../src/lib/markup";
import { pieces } from "../../src/lib/pieces";
import { choiceField, decodeHash, encodeHash, intField, shareUrl } from "../../src/lib/share";
import { assignRanges, findAll, locate, segment } from "../../src/lib/spans";

describe("findAll", () => {
  it("finds every non-overlapping occurrence, left to right", () => {
    expect(findAll("abcabcab", "ab")).toEqual([
      [0, 2],
      [3, 5],
      [6, 8],
    ]);
    expect(findAll("aaaa", "aa")).toEqual([
      [0, 2],
      [2, 4],
    ]);
  });
  it("finds nothing for an empty needle or a missing one", () => {
    expect(findAll("abc", "")).toEqual([]);
    expect(findAll("abc", "d")).toEqual([]);
  });
});

describe("locate", () => {
  it("uses UTF-16 offsets, as the textarea does", () => {
    const text = "🙂 bee@skerritt.blog";
    expect(locate(text, "bee@skerritt.blog")).toEqual([[3, 20]]);
  });
  it("maps a match pyWhat cleaned of control characters back onto the input", () => {
    // pyWhat drops U+0000-U+001F and U+007F-U+009F before matching, so "Matched" has no tab
    const text = "x 192.168.\t0.1 y";
    expect(locate(text, "192.168.0.1")).toEqual([[2, 14]]);
    expect(text.slice(2, 14)).toBe("192.168.\t0.1");
  });
  it("prefers a match as it is", () => {
    expect(locate("a\tb ab", "ab")).toEqual([[4, 6]]);
  });
});

describe("assignRanges", () => {
  it("gives a format's n-th match of a text that text's n-th occurrence", () => {
    const text = "1.1.1.1 and 1.1.1.1";
    const ranges = assignRanges(text, [
      { id: 0, name: "IPv4", matched: "1.1.1.1" },
      { id: 1, name: "IPv4", matched: "1.1.1.1" },
    ]);
    expect(ranges).toEqual([
      { start: 0, end: 7, id: 0 },
      { start: 12, end: 19, id: 1 },
    ]);
  });
  it("lets two formats share one occurrence, and skips text it can't find", () => {
    const ranges = assignRanges("AIzaKEY", [
      { id: 0, name: "Google Cloud", matched: "AIzaKEY" },
      { id: 1, name: "Google API", matched: "AIzaKEY" },
      { id: 2, name: "Gone", matched: "nowhere" },
    ]);
    expect(ranges).toEqual([
      { start: 0, end: 7, id: 0 },
      { start: 0, end: 7, id: 1 },
    ]);
  });
  it("stops at the limit", () => {
    const matches = Array.from({ length: 10 }, (_, id) => ({ id, name: "x", matched: "a" }));
    expect(assignRanges("a".repeat(10), matches, 3)).toHaveLength(3);
  });
});

describe("segment", () => {
  it("returns the whole text as one plain segment without ranges", () => {
    expect(segment(5, [])).toEqual([{ start: 0, end: 5, ids: [] }]);
  });
  it("splits at every boundary, with nested and overlapping ranges", () => {
    // 0123456789
    //   [0---)      id 0: 2..6
    //     [1---)    id 1: 4..8
    //     [2)       id 2: 4..5
    expect(
      segment(10, [
        { start: 2, end: 6, id: 0 },
        { start: 4, end: 8, id: 1 },
        { start: 4, end: 5, id: 2 },
      ]),
    ).toEqual([
      { start: 0, end: 2, ids: [] },
      { start: 2, end: 4, ids: [0] },
      { start: 4, end: 5, ids: [0, 1, 2] },
      { start: 5, end: 6, ids: [0, 1] },
      { start: 6, end: 8, ids: [1] },
      { start: 8, end: 10, ids: [] },
    ]);
  });
  it("merges touching ranges of the same match and clips ranges to the text", () => {
    expect(
      segment(6, [
        { start: -3, end: 2, id: 7 },
        { start: 2, end: 4, id: 7 },
        { start: 5, end: 99, id: 8 },
        { start: 3, end: 3, id: 9 },
      ]),
    ).toEqual([
      { start: 0, end: 4, ids: [7] },
      { start: 4, end: 5, ids: [] },
      { start: 5, end: 6, ids: [8] },
    ]);
  });
  it("covers every character exactly once", () => {
    const ranges = [
      { start: 1, end: 9, id: 0 },
      { start: 3, end: 4, id: 1 },
      { start: 8, end: 12, id: 2 },
    ];
    const segs = segment(12, ranges);
    expect(segs[0]?.start).toBe(0);
    expect(segs[segs.length - 1]?.end).toBe(12);
    for (let i = 1; i < segs.length; i++) expect(segs[i]?.start).toBe(segs[i - 1]?.end);
  });
});

describe("parseMarkup", () => {
  it("turns pyWhat's Rich markup into text and links, dropping colours", () => {
    expect(
      parseMarkup("An [#CAE4F1][link=https://en.wikipedia.org/wiki/Social_Security_number]American Identification Number[/link][/#CAE4F1]"),
    ).toEqual([
      { kind: "text", text: "An " },
      { kind: "link", text: "American Identification Number", href: "https://en.wikipedia.org/wiki/Social_Security_number" },
    ]);
  });
  it("keeps placeholders such as [ACCESS_KEY] as text", () => {
    expect(plainText("aws configure set [ACCESS_KEY] [SECRET_KEY]")).toBe("aws configure set [ACCESS_KEY] [SECRET_KEY]");
  });
  it("never makes a link of anything but http(s)", () => {
    expect(parseMarkup("[link=javascript:alert(1)]click[/link]")).toEqual([{ kind: "text", text: "click" }]);
    expect(parseMarkup("[link=data:text/html,x]x[/link]")).toEqual([{ kind: "text", text: "x" }]);
    expect(safeHref("not a url")).toBeNull();
    expect(safeHref("http://example.com/a b")).toBe("http://example.com/a%20b");
  });
  it("closes a link left open, and ignores a stray [/link]", () => {
    expect(parseMarkup("[link=https://a.example/]open")).toEqual([{ kind: "link", text: "open", href: "https://a.example/" }]);
    expect(parseMarkup("a[/link]b")).toEqual([{ kind: "text", text: "ab" }]);
  });
});

describe("share links", () => {
  it("round-trips any input through the fragment", () => {
    const input = "a&b=c #d %e\n🙂 \u0000 +";
    const url = shareUrl("https://bee-san.github.io/Ciphey/#old", { input, timeout: 10, crib: null, all: true, off: false });
    expect(url.startsWith("https://bee-san.github.io/Ciphey/#input=")).toBe(true);
    const fields = decodeHash(new URL(url).hash);
    expect(fields.get("input")).toBe(input);
    expect(fields.get("timeout")).toBe("10");
    expect(fields.get("all")).toBe("1");
    expect(fields.has("crib")).toBe(false);
    expect(fields.has("off")).toBe(false);
  });
  it("writes nothing for no fields", () => {
    expect(encodeHash({ a: "", b: null, c: undefined, d: false })).toBe("");
  });
  it("only accepts numbers and choices in range", () => {
    const fields = decodeHash("#t=30&big=99&neg=-1&f=1.5&s=high&bad=extreme");
    expect(intField(fields, "t", 1, 60)).toBe(30);
    expect(intField(fields, "big", 1, 60)).toBeUndefined();
    expect(intField(fields, "neg", 1, 60)).toBeUndefined();
    expect(intField(fields, "f", 1, 60)).toBeUndefined();
    expect(choiceField(fields, "s", ["low", "medium", "high"] as const)).toBe("high");
    expect(choiceField(fields, "bad", ["low", "medium", "high"] as const)).toBeUndefined();
  });
});

describe("pieces", () => {
  const lines = Array.from({ length: 50 }, (_, i) => `line ${i} 10.0.0.${i} bee@skerritt.blog`).join("\n");
  it("keeps short texts whole, and joins back to the text", () => {
    expect(pieces("short", 100, false)).toEqual(["short"]);
    for (const whole of [false, true]) expect(pieces(lines, 200, whole).join("")).toBe(lines);
  });
  it("cuts after line ends, so no line is cut in anchored mode", () => {
    const parts = pieces(lines, 200, true);
    expect(parts.length).toBeGreaterThan(5);
    for (const p of parts.slice(0, -1)) expect(p.endsWith("\n")).toBe(true);
    for (const p of parts) expect(p.length).toBeLessThanOrEqual(200);
  });
  it("cuts a long line at a space when matches may sit inside text", () => {
    const words = Array.from({ length: 300 }, (_, i) => `word${i}`).join(" ");
    const parts = pieces(words, 100, false);
    for (const p of parts.slice(0, -1)) expect(p.endsWith(" ")).toBe(true);
    expect(parts.join("")).toBe(words);
  });
  it("never cuts a line in anchored mode, however long", () => {
    const long = "x".repeat(500);
    expect(pieces(long, 100, true)).toEqual([long]);
    const mixed = `a\n${long}\nb`;
    expect(pieces(mixed, 100, true)).toEqual(["a\n", `${long}\n`, "b"]);
  });
});
