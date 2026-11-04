// The messages between the pages and their engine workers. Everything WebAssembly runs in a
// worker, so the page stays responsive while Ciphey searches or pyWhat scans a large text.

export type Sensitivity = "low" | "medium" | "high";
export const SENSITIVITIES: readonly Sensitivity[] = ["low", "medium", "high"];

// --- Decode (Ciphey) ---------------------------------------------------------------------

export interface DecodeOptions {
  /** Seconds the search may take. */
  timeout: number;
  /** A crib: only plaintext this regular expression (Rust syntax) matches is accepted. */
  regex: string;
  /** Keep searching after the first plaintext, until the timeout. */
  topResults: boolean;
  /** How lenient the English checker is (Low is the strictest). */
  sensitivity: Sensitivity;
}

/** One decoder of a path. */
export interface Step {
  decoder: string;
  key: string | null;
  /** The start of this step's output. */
  text: string | null;
  /** The id of the checker that accepted this step's output ("english", "lemmeknow", ...), for the last step. */
  checker: string | null;
  /** Its name, such as "English Checker". */
  checkerName: string | null;
  /** What that checker took the text for: "Words", "Email Address", ... */
  description: string | null;
  /** How sure it is, in [0, 1], if the checker measures it (pyWhat's rarity). */
  confidence: number | null;
}

export interface DecodeResult {
  plaintext: string;
  /** The decoders from the input to the plaintext, in order. */
  path: Step[];
  /** The id of the checker that accepted it, and its name. */
  checker: string | null;
  checkerName: string | null;
  description: string | null;
  confidence: number | null;
  /** When the search found it. */
  elapsedMs: number;
  /** The tree node it came from, if the engine reports the tree. */
  nodeId: number | null;
}

/** A node of the search tree: the input (id 0) or the output of a decoder. */
export interface TreeNode {
  id: number;
  parent: number | null;
  depth: number;
  decoder: string | null;
  key: string | null;
  /** The start of the node's text. */
  text: string;
  /** The length of the whole text, in characters. */
  length: number;
  /** The search's priority for it (f = g + h, lowest first), if the engine reports it. */
  cost?: number;
  /** How many children expanding it queued. */
  queuedChildren?: number;
}

/**
 * Where a search is. Ciphey reports the first four; "memory_full" is the page's own: the
 * worker stopped the search before it ran out of WebAssembly memory (see the worker).
 */
export type SearchStatus = "running" | "decoded" | "not_found" | "timed_out" | "memory_full";

export interface SearchUpdate {
  status: SearchStatus;
  elapsedMs: number;
  /** Nodes expanded (run through every decoder) so far. */
  expanded: number;
  /** Nodes waiting to be expanded. */
  queued: number;
  /** Texts seen (none is searched twice). */
  seen?: number;
  /** Decoders in the deepest node expanded so far. */
  depth?: number;
  /** Nodes new since the last update, parents first. */
  nodes: TreeNode[];
  /** Plaintexts new since the last update. */
  results: DecodeResult[];
}

export interface DecoderInfo {
  name: string;
  tags: string[];
}

export type DecodeRequest =
  | { type: "decode"; id: number; input: string; options: DecodeOptions }
  | { type: "cancel"; id: number };

export type DecodeEvent =
  | {
      type: "ready";
      version: string;
      decoders: DecoderInfo[];
      /** Whether the engine streams the tree as it searches (else only the result's path). */
      live: boolean;
      /** Whether the worker can run another search (else the page starts a new worker). */
      reusable: boolean;
    }
  | { type: "update"; id: number; update: SearchUpdate }
  | { type: "cancelled"; id: number }
  | { type: "error"; id: number | null; message: string };

// --- Identify (pyWhat) -------------------------------------------------------------------

export interface IdentifyOptions {
  minRarity: number;
  maxRarity: number;
  /** Only regexes with one of these tags (or names); empty for all. */
  include: string[];
  /** No regexes with any of these tags (or names). */
  exclude: string[];
  /** Find matches inside longer text, not only whole lines. */
  boundaryless: boolean;
}

export interface IdentifyMatch {
  /** The match's index in the results, for highlights. */
  id: number;
  matched: string;
  name: string;
  /** Rich markup: see lib/markup.ts. */
  description: string | null;
  rarity: number;
  tags: string[];
  /** Where to look the match up, if the format has a place. */
  link: string | null;
  /** How to use or check it (a command), if the format has one. */
  exploit: string | null;
  /** Part of a longer word or match. */
  fragment: boolean;
}

export type IdentifyRequest = { type: "identify"; id: number; text: string; options: IdentifyOptions };

export type IdentifyEvent =
  | { type: "ready"; version: string; tags: string[] }
  | { type: "identified"; id: number; matches: IdentifyMatch[]; elapsedMs: number }
  | { type: "error"; id: number | null; message: string };

// --- Is it language? (gibberish-or-not) ---------------------------------------------------

export interface LanguageVerdict {
  isLanguage: boolean;
  /** ISO 639-1 code, when it is language. */
  language: string | null;
  /** Calibrated score in [0, 1]. */
  score: number;
  isPassword: boolean;
}

export type LanguageRequest = { type: "detect"; id: number; text: string; sensitivity: Sensitivity };

export type LanguageEvent =
  | { type: "ready"; languages: string[] }
  | { type: "detected"; id: number; verdict: LanguageVerdict; elapsedMs: number }
  | { type: "error"; id: number | null; message: string };
