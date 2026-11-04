// Every Decode example is recomputed here from its plaintext with Node's own Buffer and
// crypto (and a few lines for ROT13, Morse and Vigenère), so an edit to examples.ts that
// breaks one fails here, not only in the browser. scripts/make-examples.py does the same in
// Python.
import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { EXAMPLES } from "../../src/decode/examples";

const b64 = (s: string) => Buffer.from(s, "utf8").toString("base64");
const rot13 = (s: string) =>
  s.replace(/[a-z]/gi, (c) => {
    const base = c <= "Z" ? 65 : 97;
    return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base);
  });
const MORSE: Record<string, string> = {
  A: ".-", B: "-...", C: "-.-.", D: "-..", E: ".", F: "..-.", G: "--.", H: "....", I: "..", J: ".---", K: "-.-", L: ".-..", M: "--",
  N: "-.", O: "---", P: ".--.", Q: "--.-", R: ".-.", S: "...", T: "-", U: "..-", V: "...-", W: ".--", X: "-..-", Y: "-.--", Z: "--..",
};
const morse = (s: string) =>
  s
    .toUpperCase()
    .split(" ")
    .map((w) => [...w].map((c) => MORSE[c]).join(" "))
    .join(" / ");
const vigenere = (s: string, key: string) => {
  let i = 0;
  return s.replace(/[a-z]/gi, (c) => {
    const base = c <= "Z" ? 65 : 97;
    const shift = (key.toUpperCase().charCodeAt(i++ % key.length) - 65) % 26;
    return String.fromCharCode(((c.charCodeAt(0) - base + shift) % 26) + base);
  });
};

const make: Record<string, (plaintext: string) => string> = {
  base64x3: (p) => b64(b64(b64(p))),
  "rot13-base64": (p) => b64(rot13(p)),
  morse: (p) => morse(p),
  vigenere: (p) => vigenere(p, "BROWSER"),
  "ctf-flag": (p) => b64(Buffer.from(p).toString("hex")),
  md5: (p) => createHash("md5").update(p).digest("hex"),
  french: (p) => b64(p),
};

describe("Decode's examples", () => {
  it("has a check for each example", () => {
    expect(EXAMPLES.map((e) => e.id).sort()).toEqual(Object.keys(make).sort());
  });
  for (const example of EXAMPLES) {
    it(`${example.label}: the input is the plaintext encoded as the label says`, () => {
      const encode = make[example.id] as (p: string) => string;
      // (Morse has no lower case, and its plaintext is the upper case Ciphey prints)
      expect(encode(example.plaintext)).toBe(example.input);
    });
  }
  it("covers the formats the site promises", () => {
    expect(EXAMPLES.map((e) => e.label)).toEqual(["Base64 ×3", "ROT13 → Base64", "Morse code", "Vigenère", "CTF flag", "MD5 hash", "French text"]);
  });
});
