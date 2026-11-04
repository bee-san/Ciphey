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
    // pyWhat's output for tens of thousands of matches can be cut short
    void e;
    return {
      error:
        "This text has more matches than pyWhat can list here. Narrow them down with Filters (raise the rarity's start, or hide tags), or identify a smaller part of the text.",
    };
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

/** A card: one match, or every match of a format that has more than `GROUP_ABOVE`. */
export type Card = { kind: "single"; match: IdentifyMatch } | { kind: "group"; name: string; matches: IdentifyMatch[] };

/** A format with more matches than this gets one card for all of them. */
export const GROUP_ABOVE = 3;

/**
 * The cards for `sorted` matches: a format with more than `GROUP_ABOVE` matches becomes one
 * card, where its first match in `sorted` was, holding its matches in that order.
 */
export function groupMatches(sorted: readonly IdentifyMatch[], above = GROUP_ABOVE): Card[] {
  const byName = new Map<string, IdentifyMatch[]>();
  for (const m of sorted) {
    const list = byName.get(m.name);
    if (list) list.push(m);
    else byName.set(m.name, [m]);
  }
  const cards: Card[] = [];
  const placed = new Set<string>();
  for (const m of sorted) {
    const list = byName.get(m.name) as IdentifyMatch[];
    if (list.length <= above) cards.push({ kind: "single", match: m });
    else if (!placed.has(m.name)) {
      placed.add(m.name);
      cards.push({ kind: "group", name: m.name, matches: list });
    }
  }
  return cards;
}

/**
 * Each format's colour index, in the order pyWhat first reports it (match ids), so a colour
 * means a kind of thing and stays put when the sort changes.
 */
export function formatColours(matches: readonly IdentifyMatch[], colours: number): Map<string, number> {
  const order = new Map<string, number>();
  for (const m of [...matches].sort((a, b) => a.id - b.id)) {
    if (!order.has(m.name)) order.set(m.name, order.size % colours);
  }
  return order;
}
