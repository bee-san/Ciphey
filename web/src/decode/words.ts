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

/** A step as one phrase: `Caesar (key 13)`. */
export function stepLabel(step: Pick<Step, "decoder" | "key">): string {
  return step.key ? `${step.decoder} (key ${step.key})` : step.decoder;
}

/** The path as one line, for copying: `Base64 → Hexadecimal → Caesar (key 13)`. */
export function pathText(path: readonly Step[]): string {
  return path.map(stepLabel).join(" → ");
}

/** The path for a screen reader: `Base64, then Hexadecimal, then Caesar with key 13`. */
export function pathSpeech(path: readonly Step[]): string {
  return path.map((s) => (s.key ? `${s.decoder} with key ${s.key}` : s.decoder)).join(", then ");
}

/** What accepted the plaintext, as a sentence: "pyWhat identified it as Email Address (rarity 0.50)." */
export function verdictSentence(result: Pick<DecodeResult, "checker" | "checkerName" | "description" | "confidence">): string | null {
  const who = checkerLabel(result.checker, result.checkerName);
  const what = result.description;
  if (!who && !what) return null;
  const sure = result.confidence !== null && result.confidence !== undefined ? ` (rarity ${result.confidence.toFixed(2)})` : "";
  if (who === "pyWhat" && what) return `pyWhat identified it as ${what}${sure}.`;
  if (who === "your crib") return "It matches your crib.";
  if (who && what) return `Accepted by ${who} as ${what}${sure}.`;
  return who ? `Accepted by ${who}.` : `Identified as ${what}${sure}.`;
}

/** The options as the Options disclosure's summary: `5 s · Medium · crib · every plaintext`. */
export function optionsSummary(o: DecodeOptions): string {
  const parts = [`${o.timeout} s`, o.sensitivity[0]?.toUpperCase() + o.sensitivity.slice(1)];
  if (o.regex) parts.push("crib");
  if (o.topResults) parts.push("every plaintext");
  return parts.join(" · ");
}

/** The most characters Ciphey's search takes here (the MCP server's limit too). */
export const MAX_INPUT_CHARS = 65_536;

export type InputCheck = { ok: true } | { ok: false; message: string };

export function checkInput(text: string): InputCheck {
  if (text.trim() === "") return { ok: false, message: "Paste or type the text to decode first." };
  const n = Array.from(text).length;
  if (n > MAX_INPUT_CHARS)
    return { ok: false, message: `That's ${n.toLocaleString("en")} characters. Ciphey decodes up to ${MAX_INPUT_CHARS.toLocaleString("en")} here.` };
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
