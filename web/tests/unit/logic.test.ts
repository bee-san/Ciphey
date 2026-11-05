import { describe, expect, it } from "vitest";
import { printable } from "../../src/decode/tree-view";
import { checkCrib, checkerLabel, checkInput, checkTimeout, decoderName, inputLimit, memoryBudget, optionsSummary, pathSpeech, pathText, verdictSentence } from "../../src/decode/words";
import { bytes, count, duration, plural, preview } from "../../src/lib/format";
import { isLanguageAt, languageName, listNames, THRESHOLDS } from "../../src/lib/language";
import type { IdentifyMatch, Step } from "../../src/lib/protocol";
import { flattenMatches, formatColours, groupMatches, identifyOptionsJson, lookupHref, sortMatches } from "../../src/lib/pywhat";
import { SearchTree } from "../../src/lib/tree";
import { LatestRequest } from "../../src/shell/engine";

describe("identifyOptionsJson", () => {
  it("leaves out an empty include list, which would include nothing", () => {
    const json = JSON.parse(identifyOptionsJson({ minRarity: 0.1, maxRarity: 1, include: [], exclude: ["Charset Only"], boundaryless: true }));
    expect(json).toEqual({ min_rarity: 0.1, max_rarity: 1, exclude: ["Charset Only"], boundaryless: true });
    const only = JSON.parse(identifyOptionsJson({ minRarity: 0, maxRarity: 0.5, include: ["Credentials"], exclude: [], boundaryless: false }));
    expect(only.include).toEqual(["Credentials"]);
    expect(only.boundaryless).toBe(false);
  });
});

describe("flattenMatches", () => {
  const output = JSON.stringify({
    "File Signatures": null,
    Regexes: {
      text: [
        {
          Matched: "192.168.0.1",
          "Regex Pattern": { Name: "Internet Protocol (IP) Address Version 4", Rarity: 0.7, Tags: ["Identifiers", "IP"], URL: "https://www.shodan.io/host/", Description: null, Exploit: null },
          Fragment: false,
        },
        {
          Matched: "a b",
          "Regex Pattern": { Name: "Has a processor link", Rarity: 1, Tags: [], URL: "https://x.example/", Link: "https://y.example/z" },
          Fragment: true,
        },
      ],
    },
  });
  it("lists pyWhat's matches with their links", () => {
    const matches = flattenMatches(output) as IdentifyMatch[];
    expect(matches.map((m) => [m.id, m.name, m.rarity, m.link, m.fragment])).toEqual([
      [0, "Internet Protocol (IP) Address Version 4", 0.7, "https://www.shodan.io/host/192.168.0.1", false],
      [1, "Has a processor link", 1, "https://y.example/z", true],
    ]);
    expect(matches[0]?.tags).toEqual(["Identifiers", "IP"]);
  });
  it("reports pyWhat's errors and empty results", () => {
    expect(flattenMatches('{"error": "options: bad"}')).toEqual({ error: "options: bad" });
    expect(flattenMatches('{"File Signatures": null, "Regexes": null}')).toEqual([]);
    expect((flattenMatches("not json") as { error: string }).error).toMatch(/Filters/);
  });
  it("builds a link from the URL and the match without spaces", () => {
    const one = JSON.stringify({ Regexes: { text: [{ Matched: "1 2 3", "Regex Pattern": { Name: "n", URL: "https://u.example/?q=" } }] } });
    expect((flattenMatches(one) as IdentifyMatch[])[0]?.link).toBe("https://u.example/?q=123");
  });
});

describe("sortMatches", () => {
  const m = (id: number, name: string, rarity: number, matched: string): IdentifyMatch => ({
    id, name, rarity, matched, description: null, tags: [], link: null, exploit: null, fragment: false,
  });
  const list = [m(0, "URL", 0.7, "b.example"), m(1, "Email Address", 0.5, "a@b.example"), m(2, "AWS Key", 1, "AKIA"), m(3, "IPv4", 0.7, "10.0.0.2")];
  it("puts the most specific first, keeping pyWhat's order for ties", () => {
    expect(sortMatches(list, "rarity").map((x) => x.id)).toEqual([2, 0, 3, 1]);
    expect(sortMatches(list, "rarity", true).map((x) => x.id)).toEqual([1, 0, 3, 2]);
  });
  it("sorts names and matched text from A to Z, ignoring case", () => {
    expect(sortMatches(list, "name").map((x) => x.name)).toEqual(["AWS Key", "Email Address", "IPv4", "URL"]);
    expect(sortMatches(list, "matched").map((x) => x.matched)).toEqual(["10.0.0.2", "a@b.example", "AKIA", "b.example"]);
  });
  it("doesn't change its input", () => {
    sortMatches(list, "name");
    expect(list.map((x) => x.id)).toEqual([0, 1, 2, 3]);
  });
});

describe("lookupHref", () => {
  it("gives http(s) lookup links, and none for credentials, tokens or keys", () => {
    expect(lookupHref({ link: "https://www.shodan.io/host/1.2.3.4", tags: ["Identifiers", "IP"] })).toBe("https://www.shodan.io/host/1.2.3.4");
    expect(lookupHref({ link: "https://developers.facebook.com/tools/debug/accesstoken/?access_token=x", tags: ["Credentials"] })).toBeNull();
    expect(lookupHref({ link: "https://x.example/", tags: ["API Keys"] })).toBeNull();
    expect(lookupHref({ link: "https://x.example/", tags: ["JWT Token"] })).toBeNull();
    expect(lookupHref({ link: "javascript:alert(1)", tags: [] })).toBeNull();
    expect(lookupHref({ link: null, tags: [] })).toBeNull();
  });
});

describe("groupMatches", () => {
  const m = (id: number, name: string, matched = `m${id}`): IdentifyMatch => ({
    id, name, matched, rarity: 0.5, description: null, tags: [], link: null, exploit: null, fragment: false,
  });
  it("keeps formats with up to three matches as single cards, in order", () => {
    const cards = groupMatches([m(0, "IP"), m(1, "Email"), m(2, "IP"), m(3, "IP")]);
    expect(cards.map((c) => (c.kind === "single" ? c.match.id : c.name))).toEqual([0, 1, 2, 3]);
  });
  it("makes one card of a format with more than three, where its first match was", () => {
    const sorted = [m(5, "URL"), m(0, "IP"), m(1, "IP"), m(9, "Email"), m(2, "IP"), m(3, "IP")];
    const cards = groupMatches(sorted);
    expect(cards.map((c) => c.kind)).toEqual(["single", "group", "single"]);
    const group = cards[1] as { kind: "group"; name: string; matches: IdentifyMatch[] };
    expect(group.name).toBe("IP");
    expect(group.matches.map((x) => x.id)).toEqual([0, 1, 2, 3]);
  });
  it("gives each format one colour, by pyWhat's order, whatever the sort", () => {
    const colours = formatColours([m(3, "Email"), m(0, "URL"), m(1, "IP"), m(2, "URL")], 6);
    expect([...colours.entries()]).toEqual([
      ["URL", 0],
      ["IP", 1],
      ["Email", 2],
    ]);
    const many = formatColours(Array.from({ length: 8 }, (_, i) => m(i, `F${i}`)), 6);
    expect(many.get("F6")).toBe(0);
  });
});

describe("SearchTree", () => {
  const node = (id: number, parent: number | null, decoder: string | null = "Base64") => ({ id, parent, depth: parent === null ? 0 : 1, decoder, key: null, text: `t${id}`, length: 2 });
  it("keeps children in arrival order and finds the path to a node", () => {
    const tree = new SearchTree();
    expect(tree.add([node(0, null), node(5, 0), node(9, 0), node(12, 9)])).toHaveLength(4);
    expect(tree.add([node(5, 0)])).toHaveLength(0);
    expect(tree.get(0)?.children).toEqual([5, 9]);
    expect(tree.pathTo(12).map((n) => n.id)).toEqual([0, 9, 12]);
    expect(tree.pathTo(77)).toEqual([]);
    expect(tree.roots().map((n) => n.id)).toEqual([0]);
  });
  it("draws the first nodes, plus the path to a pinned one", () => {
    const tree = new SearchTree();
    tree.add([node(0, null), node(1, 0), node(2, 0), node(3, 2), node(4, 3)]);
    expect([...tree.visible(2)].sort()).toEqual([0, 1]);
    expect([...tree.visible(2, [4])].sort()).toEqual([0, 1, 2, 3, 4]);
    expect(tree.hiddenChildren(0, tree.visible(2))).toBe(1);
  });
});

describe("Decode's words", () => {
  const path: Step[] = [
    { decoder: "Base64", key: null, text: "x", checker: null, checkerName: null, description: null, confidence: null },
    { decoder: "caesar", key: "13", text: "y", checker: "english", checkerName: "English Checker", description: "Words", confidence: null },
  ];
  it("writes paths for copying and for screen readers", () => {
    expect(pathText(path)).toBe("Base64 → Caesar (key 13)");
    expect(pathSpeech(path)).toBe("Base64, then Caesar with key 13");
    expect(decoderName("Vigenere")).toBe("Vigenère");
    expect(decoderName("railfence")).toBe("Rail fence");
    expect(decoderName("Base64")).toBe("Base64");
  });
  it("names checkers by id, falling back to the name", () => {
    expect(checkerLabel("english")).toBe("the English checker");
    expect(checkerLabel("lemmeknow")).toBe("pyWhat");
    expect(checkerLabel("pywhat")).toBe("pyWhat");
    expect(checkerLabel(null, "Regex Checker")).toBe("your crib");
    expect(checkerLabel("new_one", "Shiny Checker")).toBe("Shiny checker");
    expect(checkerLabel(null, null)).toBeNull();
  });
  it("says what accepted the plaintext", () => {
    expect(verdictSentence({ checker: "english", checkerName: "English Checker", description: "Words", confidence: null })).toBe(
      "The English checker accepted it as English words.",
    );
    expect(verdictSentence({ checker: "json", checkerName: "JSON Checker", description: "JSON object", confidence: null })).toBe(
      "Accepted by the JSON checker as JSON object.",
    );
    expect(verdictSentence({ checker: "lemmeknow", checkerName: "LemmeKnow Checker", description: "Email Address", confidence: 0.5 })).toBe(
      "pyWhat identified it as Email Address (rarity 0.50).",
    );
    expect(verdictSentence({ checker: "regex", checkerName: "Regex Checker", description: "Regex matched: flag", confidence: null })).toBe(
      "It matches your crib.",
    );
    expect(verdictSentence({ checker: null, checkerName: null, description: null, confidence: null })).toBeNull();
  });
  it("summarises the options", () => {
    expect(optionsSummary({ timeout: 5, regex: "", topResults: false, sensitivity: "medium" })).toBe("5 s · Medium sensitivity");
    expect(optionsSummary({ timeout: 30, regex: "flag", topResults: true, sensitivity: "low" })).toBe("30 s · Low sensitivity · crib · every plaintext");
  });
  it("checks the input and the options", () => {
    expect(checkInput("   ").ok).toBe(false);
    expect(checkInput("abc").ok).toBe(true);
    expect(checkInput("a".repeat(65_537)).ok).toBe(false);
    expect(checkInput("🙂".repeat(65_536)).ok).toBe(true); // counted in characters, not UTF-16 units
    expect(checkTimeout("5")).toEqual({ ok: true, value: 5 });
    expect(checkTimeout(" 60 ")).toEqual({ ok: true, value: 60 });
    for (const bad of ["0", "61", "1.5", "", "-3", "five"]) expect(checkTimeout(bad).ok).toBe(false);
    expect(checkCrib("x".repeat(1001)).ok).toBe(false);
  });
});

describe("memory budget", () => {
  const GiB = 1024 ** 3;
  const desktop = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0 Safari/537.36";
  const iphone = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148";
  const ipad = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15";
  it("is a quarter of the device's memory, from 512 MiB to 2 GiB", () => {
    expect(memoryBudget({ deviceMemory: 8, userAgent: desktop })).toBe(2 * GiB);
    expect(memoryBudget({ deviceMemory: 4, userAgent: desktop })).toBe(GiB);
    expect(memoryBudget({ deviceMemory: 2, userAgent: iphone })).toBe(GiB / 2);
    expect(memoryBudget({ deviceMemory: 0.5, userAgent: desktop })).toBe(GiB / 2);
  });
  it("without deviceMemory: 2 GiB on desktops, 512 MiB on phones and iPads", () => {
    expect(memoryBudget({ userAgent: desktop })).toBe(2 * GiB);
    expect(memoryBudget({ userAgent: ipad, maxTouchPoints: 0 })).toBe(2 * GiB); // a Mac
    expect(memoryBudget({ userAgent: iphone })).toBe(GiB / 2);
    expect(memoryBudget({ userAgent: ipad, maxTouchPoints: 5 })).toBe(GiB / 2); // an iPad says it's a Mac
  });
  it("takes a smaller input on a small budget, and says why", () => {
    expect(inputLimit(2 * GiB)).toBe(65_536);
    expect(inputLimit(GiB)).toBe(16_000);
    const small = checkInput("a".repeat(16_001), inputLimit(GiB / 2));
    expect(small.ok).toBe(false);
    expect(small.ok ? "" : small.message).toMatch(/On this device Ciphey decodes up to 16,000/);
    expect(checkInput("a".repeat(16_001), inputLimit(2 * GiB)).ok).toBe(true);
  });
});

describe("format", () => {
  it("formats durations, counts and sizes", () => {
    expect(duration(85.4)).toBe("85 ms");
    expect(duration(1234)).toBe("1.2 s");
    expect(duration(12_345)).toBe("12 s");
    expect(duration(Number.NaN)).toBe("–");
    expect(count(1234567)).toBe("1,234,567");
    expect(plural(1, "node")).toBe("1 node");
    expect(plural(2, "branch", "branches")).toBe("2 branches");
    expect(bytes(950)).toBe("950 B");
    expect(bytes(12_345)).toBe("12 KB");
    expect(bytes(2_249_691)).toBe("2.2 MB");
  });
  it("cuts previews by character and shows line breaks", () => {
    expect(preview("a\nb\tc", 10)).toBe("a↵b→c");
    expect(preview("🙂🙂🙂", 2)).toBe("🙂🙂…");
    expect(preview("short", 120)).toBe("short");
  });
  it("keeps control and direction characters out of tree rows", () => {
    expect(printable("a\u0000b\u202ec\u2066d\u0085e")).toBe("a·b·c·d·e");
    expect(printable("tab\tnew\nline")).toBe("tab\tnew\nline");
  });
});

describe("language", () => {
  it("uses gibberish-or-not's thresholds: Low is the strictest", () => {
    expect(THRESHOLDS.low).toBeGreaterThan(THRESHOLDS.medium);
    expect(THRESHOLDS.medium).toBeGreaterThan(THRESHOLDS.high);
    expect(isLanguageAt(0.8, "medium")).toBe(true);
    expect(isLanguageAt(0.8, "low")).toBe(false);
    expect(isLanguageAt(0.5, "high")).toBe(true);
  });
  it("names languages", () => {
    expect(languageName("en")).toBe("English");
    expect(languageName("fr")).toBe("French");
    expect(listNames(["English", "French", "German"])).toBe("English, French, and German");
  });
});

describe("LatestRequest", () => {
  it("keeps one request in flight and sends only the newest after it", () => {
    const sent: number[] = [];
    const latest = new LatestRequest<{ id: number; text: string }>((r) => sent.push(r.id));
    const a = latest.request((id) => ({ id, text: "a" }));
    const b = latest.request((id) => ({ id, text: "ab" }));
    const c = latest.request((id) => ({ id, text: "abc" }));
    expect(sent).toEqual([a]);
    expect(latest.settle(a)).toBe(false); // stale: c is sent instead, b is dropped
    expect(sent).toEqual([a, c]);
    expect(latest.settle(b)).toBe(false);
    expect(latest.settle(c)).toBe(true);
    latest.request((id) => ({ id, text: "abcd" }));
    expect(sent).toHaveLength(3);
  });
  it("forgets everything after a reset", () => {
    const sent: number[] = [];
    const latest = new LatestRequest<{ id: number }>((r) => sent.push(r.id));
    latest.request((id) => ({ id }));
    latest.reset();
    const next = latest.request((id) => ({ id }));
    expect(sent).toEqual([1, next]);
  });
});
