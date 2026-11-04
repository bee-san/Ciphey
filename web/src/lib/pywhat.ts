// pyWhat's WebAssembly API takes its options as JSON and returns what `pywhat --json`
// prints. These turn the page's filters into those options and the output into a flat list.

import type { IdentifyMatch, IdentifyOptions } from "./protocol";

/** The options JSON for pywhat's `identify(text, options)`. */
export function identifyOptionsJson(o: IdentifyOptions): string {
  const options: Record<string, unknown> = {
    min_rarity: o.minRarity,
    max_rarity: o.maxRarity,
    exclude: o.exclude,
    boundaryless: o.boundaryless,
  };
  // An empty include list would include nothing: leave it out for "all"
  if (o.include.length > 0) options.include = o.include;
  return JSON.stringify(options);
}

interface RawPattern {
  Name?: unknown;
  Description?: unknown;
  Rarity?: unknown;
  Tags?: unknown;
  URL?: unknown;
  Link?: unknown;
  Exploit?: unknown;
}

interface RawMatch {
  Matched?: unknown;
  "Regex Pattern"?: RawPattern;
  Fragment?: unknown;
}

const str = (v: unknown): string | null => (typeof v === "string" && v !== "" ? v : null);

/**
 * The matches in pywhat's JSON output, in its order, or the error it reported. A match's link
 * is the one a processor gave it, else the format's URL followed by the match without spaces
 * (pyWhat's `get_link`).
 */
export function flattenMatches(json: string): IdentifyMatch[] | { error: string } {
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch (e) {
    return { error: `pyWhat returned something that isn't JSON: ${String(e)}` };
  }
  if (typeof parsed !== "object" || parsed === null) return { error: "pyWhat returned no result" };
  const root = parsed as { error?: unknown; Regexes?: unknown };
  if (typeof root.error === "string") return { error: root.error };
  const matches: IdentifyMatch[] = [];
  if (typeof root.Regexes !== "object" || root.Regexes === null) return matches;
  for (const list of Object.values(root.Regexes as Record<string, unknown>)) {
    if (!Array.isArray(list)) continue;
    for (const raw of list as RawMatch[]) {
      const p = raw["Regex Pattern"] ?? {};
      const matched = typeof raw.Matched === "string" ? raw.Matched : "";
      const url = str(p.URL);
      matches.push({
        id: matches.length,
        matched,
        name: str(p.Name) ?? "Unknown format",
        description: str(p.Description),
        rarity: typeof p.Rarity === "number" ? p.Rarity : 0,
        tags: Array.isArray(p.Tags) ? p.Tags.filter((t): t is string => typeof t === "string") : [],
        link: str(p.Link) ?? (url ? url + matched.replace(/ /g, "") : null),
        exploit: str(p.Exploit),
        fragment: raw.Fragment === true,
      });
    }
  }
  return matches;
}

export type SortKey = "rarity" | "name" | "matched";

/**
 * The matches sorted by `key`: rarity from the rarest (1) down, names and matched text from
 * A to Z; `reverse` flips that. Ties keep pyWhat's order.
 */
export function sortMatches(matches: readonly IdentifyMatch[], key: SortKey, reverse = false): IdentifyMatch[] {
  const collator = new Intl.Collator("en", { sensitivity: "base", numeric: true });
  const compare = (a: IdentifyMatch, b: IdentifyMatch): number => {
    switch (key) {
      case "rarity":
        return b.rarity - a.rarity;
      case "name":
        return collator.compare(a.name, b.name);
      case "matched":
        return collator.compare(a.matched, b.matched);
    }
  };
  // Array.prototype.sort is stable, so ties stay in pyWhat's order either way
  return [...matches].sort((a, b) => (reverse ? -compare(a, b) : compare(a, b)) || a.id - b.id);
}
