// Numbers as the page shows them.

const COUNT = new Intl.NumberFormat("en", { maximumFractionDigits: 0 });

/** `1,234` */
export function count(n: number): string {
  return COUNT.format(n);
}

/** `1 node`, `2 nodes` */
export function plural(n: number, one: string, many = `${one}s`): string {
  return `${count(n)} ${n === 1 ? one : many}`;
}

/** `85 ms` under a second, then `1.2 s` (`12 s` from ten seconds on). */
export function duration(ms: number): string {
  if (!Number.isFinite(ms) || ms < 0) return "–";
  if (ms < 1000) return `${Math.round(ms)} ms`;
  const s = ms / 1000;
  return s < 10 ? `${s.toFixed(1)} s` : `${Math.round(s)} s`;
}

/** `950 B`, `12 KB`, `2.1 MB` (powers of 1000, like the PR's measurements). */
export function bytes(n: number): string {
  if (n < 1000) return `${n} B`;
  if (n < 1e6) return `${Math.round(n / 1000)} KB`;
  return `${(n / 1e6).toFixed(1)} MB`;
}

/** A score or rarity in [0, 1] with two decimals, `0.70`. */
export function fraction(x: number): string {
  return Number.isFinite(x) ? x.toFixed(2) : "–";
}

/**
 * The first `max` characters of `text` (by code point, so emoji aren't cut in half) on one
 * line, with an ellipsis if it was cut. Line breaks and tabs show as `↵` and `→`.
 */
export function preview(text: string, max = 120): string {
  const chars = Array.from(text);
  const cut = chars.length > max;
  const shown = (cut ? chars.slice(0, max) : chars).join("").replace(/\r\n|\r|\n/g, "↵").replace(/\t/g, "→");
  return cut ? `${shown}…` : shown;
}
