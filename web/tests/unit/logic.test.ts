import { describe, expect, it } from "vitest";
import { printable } from "../../src/decode/tree-view";
import { checkCrib, checkerLabel, checkInput, checkTimeout, optionsSummary, pathSpeech, pathText, verdictSentence } from "../../src/decode/words";
import { bytes, count, duration, plural, preview } from "../../src/lib/format";
import { isLanguageAt, languageName, listNames, THRESHOLDS } from "../../src/lib/language";
import type { IdentifyMatch, Step } from "../../src/lib/protocol";
import { flattenMatches, identifyOptionsJson, sortMatches } from "../../src/lib/pywhat";
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
    expect(flattenMatches("not json")).toHaveProperty("error");
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
    expect(pathText(path)).toBe("Base64 → caesar (key 13)");
    expect(pathSpeech(path)).toBe("Base64, then caesar with key 13");
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
      "Accepted by the English checker as Words.",
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
    expect(optionsSummary({ timeout: 5, regex: "", topResults: false, sensitivity: "medium" })).toBe("5 s · Medium");
    expect(optionsSummary({ timeout: 30, regex: "flag", topResults: true, sensitivity: "low" })).toBe("30 s · Low · crib · every plaintext");
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
