// Words and text for Decode's results, kept apart from the DOM so they can be tested.

import type { DecodeOptions, DecodeResult, Step } from "../lib/protocol";

/**
 * Who accepted a plaintext, as the page says it: from the checker's id ("english",
 * "lemmeknow", ...), else its name ("English Checker").
 */
export function checkerLabel(id: string | null, name: string | null = null): string | null {
  const byId: Record<string, string> = {
    english: "the English checker",
    lemmeknow: "pyWhat",
    pywhat: "pyWhat",
    regex: "your crib",
    wordlist: "your wordlist",
    json: "the JSON checker",
    password: "the password checker",
    code: "the code checker",
    jwt_structure: "the JWT checker",
  };
  const byName: Record<string, string> = {
    "English Checker": "the English checker",
    "LemmeKnow Checker": "pyWhat",
    "pyWhat Checker": "pyWhat",
    "Regex Checker": "your crib",
    "Wordlist Checker": "your wordlist",
  };
  if (id && byId[id]) return byId[id] as string;
  if (name) return byName[name] ?? name.replace(/ Checker$/, " checker");
  return id;
}

/**
 * Ciphey names some decoders in lower case (`caesar`, `atbash`) and writes Vigenère without
 * its accent; the page shows them as the README writes them. Other names pass through.
 */
const NAMES: Readonly<Record<string, string>> = {
  a1z26: "A1Z26",
  atbash: "Atbash",
  caesar: "Caesar",
  railfence: "Rail fence",
  rot18: "ROT18",
  rot47: "ROT47",
  simplesubstitution: "Simple substitution",
  Vigenere: "Vigenère",
  "Vigenere Autokey": "Vigenère autokey",
};

export function decoderName(name: string): string {
  return NAMES[name] ?? name;
}

/** A step as one phrase: `Caesar (key 13)`. */
export function stepLabel(step: Pick<Step, "decoder" | "key">): string {
  const name = decoderName(step.decoder);
  return step.key ? `${name} (key ${step.key})` : name;
}

/** The path as one line, for copying: `Base64 → Hexadecimal → Caesar (key 13)`. */
export function pathText(path: readonly Step[]): string {
  return path.map(stepLabel).join(" → ");
}

/** The path for a screen reader: `Base64, then Hexadecimal, then Caesar with key 13`. */
export function pathSpeech(path: readonly Step[]): string {
  return path.map((s) => (s.key ? `${decoderName(s.decoder)} with key ${s.key}` : decoderName(s.decoder))).join(", then ");
}

/** What the crib field says when Ciphey can't read the crib as a regular expression. */
export const CRIB_INVALID =
  "This crib isn't a valid regular expression. To match a symbol such as { ( [ . * + ? as itself, put a backslash before it: flag\\{ matches flag{.";

/** What accepted the plaintext, as a sentence: "pyWhat identified it as Email Address (rarity 0.50)." */
export function verdictSentence(result: Pick<DecodeResult, "checker" | "checkerName" | "description" | "confidence">): string | null {
  const who = checkerLabel(result.checker, result.checkerName);
  const what = result.description;
  if (!who && !what) return null;
  const sure = result.confidence !== null && result.confidence !== undefined ? ` (rarity ${result.confidence.toFixed(2)})` : "";
  if (who === "pyWhat" && what) return `pyWhat identified it as ${what}${sure}.`;
  if (who === "the English checker" && (!what || what === "Words")) return "The English checker accepted it as English words.";
  if (who === "your crib") return "It matches your crib.";
  if (who && what) return `Accepted by ${who} as ${what}${sure}.`;
  return who ? `Accepted by ${who}.` : `Identified as ${what}${sure}.`;
}

/** The options as the Options disclosure's summary: `5 s · Medium · crib · every plaintext`. */
export function optionsSummary(o: DecodeOptions): string {
  const parts = [`${o.timeout} s`, `${capitalise(o.sensitivity)} sensitivity`];
  if (o.regex) parts.push("crib");
  if (o.topResults) parts.push("every plaintext");
  return parts.join(" · ");
}

/** The most characters Ciphey's search takes here (the MCP server's limit too). */
export const MAX_INPUT_CHARS = 65_536;
/**
 * On a device with a small memory budget, less: one step of the search on a 65,536-character
 * input can grow the module by 0.5 to 0.8 GiB, more than such a budget; 16,000 characters
 * overshoot it by under 50 MiB (audit-ciphey-web-b, F14).
 */
export const SMALL_DEVICE_INPUT_CHARS = 16_000;

const GIB = 1024 ** 3;

/**
 * The WebAssembly memory a search may use before the worker stops it: a quarter of the
 * device's memory where the browser says (Chromium's `navigator.deviceMemory`, at most 8 GB),
 * between 512 MiB and 2 GiB; else 2 GiB on desktops and 512 MiB on phones and tablets.
 * iPadOS Safari says it's a Mac, but a Mac has no touch screen.
 */
export function memoryBudget(nav: { deviceMemory?: number; userAgent: string; maxTouchPoints?: number }): number {
  if (nav.deviceMemory) return Math.min(2 * GIB, Math.max(GIB / 2, (nav.deviceMemory * GIB) / 4));
  const tablet = /Macintosh/.test(nav.userAgent) && (nav.maxTouchPoints ?? 0) > 1;
  return /Mobi|Android|iPhone|iPad/.test(nav.userAgent) || tablet ? GIB / 2 : 2 * GIB;
}

/** The input limit for a memory budget. */
export function inputLimit(budget: number): number {
  return budget <= GIB ? SMALL_DEVICE_INPUT_CHARS : MAX_INPUT_CHARS;
}

export type InputCheck = { ok: true } | { ok: false; message: string };

export function checkInput(text: string, max = MAX_INPUT_CHARS): InputCheck {
  if (text.trim() === "") return { ok: false, message: "Paste or type the text to decode first." };
  const n = Array.from(text).length;
  if (n > max) {
    const where =
      max < MAX_INPUT_CHARS
        ? `On this device Ciphey decodes up to ${max.toLocaleString("en")}, to stay within its memory; a computer takes up to ${MAX_INPUT_CHARS.toLocaleString("en")}.`
        : `Ciphey decodes up to ${max.toLocaleString("en")} here.`;
    return { ok: false, message: `That's ${n.toLocaleString("en")} characters. ${where}` };
  }
  return { ok: true };
}

export function checkTimeout(raw: string): { ok: true; value: number } | { ok: false; message: string } {
  if (!/^\s*\d+\s*$/.test(raw)) return { ok: false, message: "The time limit is a whole number of seconds, from 1 to 60." };
  const value = Number(raw);
  if (value < 1 || value > 60) return { ok: false, message: "The time limit is from 1 to 60 seconds." };
  return { ok: true, value };
}

export function checkCrib(raw: string): InputCheck {
  if (raw.length > 1000) return { ok: false, message: "The crib is limited to 1,000 characters." };
  return { ok: true };
}

/** "medium" → "Medium" */
export function capitalise(word: string): string {
  return word.charAt(0).toUpperCase() + word.slice(1);
}
