// Where pyWhat's matches are in the input, for the highlights.
//
// pyWhat's JSON gives each match's text ("Matched") but not its offsets, and that text has
// had its control characters removed (U+0000 to U+001F and U+007F to U+009F, like Python's
// `clean_text`). So the matches are found again here: first as they are, then in the text
// without its control characters, mapped back to the input. Offsets are UTF-16 code units,
// as JavaScript strings index them.

/** A half-open range `[start, end)` of the input that match `id` covers. */
export interface Range {
  start: number;
  end: number;
  id: number;
}

/** A piece of the input, and the matches that cover it (none for plain text). */
export interface Segment {
  start: number;
  end: number;
  ids: number[];
}

const CONTROL = /[\u0000-\u001f\u007f-\u009f]/;

/** Every non-overlapping occurrence of `needle` in `text`, left to right. */
export function findAll(text: string, needle: string): Array<[number, number]> {
  const found: Array<[number, number]> = [];
  if (needle.length === 0) return found;
  let from = 0;
  for (;;) {
    const at = text.indexOf(needle, from);
    if (at < 0) return found;
    found.push([at, at + needle.length]);
    from = at + needle.length;
  }
}

/**
 * Where `matched` occurs in `text`. If it doesn't occur as it is, it is looked for in `text`
 * without its control characters, and each occurrence is mapped back to a range of `text`
 * (which then spans the control characters inside it).
 */
export function locate(text: string, matched: string): Array<[number, number]> {
  const direct = findAll(text, matched);
  if (direct.length > 0 || !CONTROL.test(text)) return direct;
  // `kept[i]` is the index in `text` of the i-th character that isn't a control character.
  const kept: number[] = [];
  let cleaned = "";
  for (let i = 0; i < text.length; i++) {
    const c = text[i] as string;
    if (!CONTROL.test(c)) {
      kept.push(i);
      cleaned += c;
    }
  }
  return findAll(cleaned, matched).map(([s, e]) => [kept[s] as number, (kept[e - 1] as number) + 1]);
}

/**
 * The ranges of `matches` in `text`. pyWhat reports a text that occurs twice as two matches,
 * so a format's n-th match of a text gets that text's n-th occurrence (and a match whose text
 * isn't found gets none). At most `limit` ranges.
 */
export function assignRanges(
  text: string,
  matches: ReadonlyArray<{ id: number; name: string; matched: string }>,
  limit = 5000,
): Range[] {
  const occurrences = new Map<string, Array<[number, number]>>();
  const used = new Map<string, number>();
  const ranges: Range[] = [];
  for (const m of matches) {
    if (ranges.length >= limit) break;
    let spots = occurrences.get(m.matched);
    if (!spots) {
      spots = locate(text, m.matched);
      occurrences.set(m.matched, spots);
    }
    const key = `${m.name}\u0000${m.matched}`;
    const n = used.get(key) ?? 0;
    used.set(key, n + 1);
    const spot = spots[n];
    if (spot) ranges.push({ start: spot[0], end: spot[1], id: m.id });
  }
  return ranges;
}

/**
 * Splits `[0, length)` at every range boundary. Each segment lists the ids of the ranges that
 * cover it, in the order of `ranges`; segments between ranges have none. Ranges may overlap or
 * nest. Empty ranges, and the parts of ranges outside `[0, length)`, are ignored.
 */
export function segment(length: number, ranges: readonly Range[]): Segment[] {
  // Sweep: at each boundary, ranges start or end; between boundaries the cover is constant
  const events = new Map<number, { open: number[]; close: number[] }>();
  const at = (p: number) => {
    let e = events.get(p);
    if (!e) events.set(p, (e = { open: [], close: [] }));
    return e;
  };
  ranges.forEach((r, order) => {
    const start = Math.max(0, r.start);
    const end = Math.min(length, r.end);
    if (end <= start) return;
    at(start).open.push(order);
    at(end).close.push(order);
  });
  at(0);
  at(length);
  const points = [...events.keys()].sort((a, b) => a - b);
  const active = new Set<number>();
  const segments: Segment[] = [];
  for (let i = 0; i + 1 < points.length; i++) {
    const p = points[i] as number;
    const e = events.get(p) as { open: number[]; close: number[] };
    for (const o of e.close) active.delete(o);
    for (const o of e.open) active.add(o);
    const next = points[i + 1] as number;
    if (next <= p) continue;
    const ids = [...active].sort((a, b) => a - b).map((o) => (ranges[o] as Range).id);
    const last = segments[segments.length - 1];
    if (last && last.end === p && sameIds(last.ids, ids)) last.end = next;
    else segments.push({ start: p, end: next, ids });
  }
  return segments;
}

function sameIds(a: readonly number[], b: readonly number[]): boolean {
  return a.length === b.length && a.every((id, i) => id === b[i]);
}
