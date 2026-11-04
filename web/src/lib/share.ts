// Share links keep the input in the URL's fragment (#...), which browsers never send to the
// server. They are opt-in: the page only writes one when asked, and drops it from the address
// bar once the input changes, so a secret doesn't linger in the URL.

/** Longer inputs don't make a usable link (chat apps and some browsers cut long URLs). */
export const MAX_SHARE_CHARS = 16_000;

/** `#a=1&b=2` from the fields that have a value, in the order given. */
export function encodeHash(fields: Record<string, string | number | boolean | null | undefined>): string {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(fields)) {
    if (value === undefined || value === null || value === "" || value === false) continue;
    params.set(key, value === true ? "1" : String(value));
  }
  const query = params.toString();
  return query ? `#${query}` : "";
}

/** The fields of a `#a=1&b=2` fragment (with or without the `#`). */
export function decodeHash(hash: string): Map<string, string> {
  const params = new URLSearchParams(hash.startsWith("#") ? hash.slice(1) : hash);
  return new Map(params.entries());
}

/** A whole share URL: `base` (the page's URL without its fragment) and the fields. */
export function shareUrl(base: string, fields: Record<string, string | number | boolean | null | undefined>): string {
  const at = base.indexOf("#");
  return (at < 0 ? base : base.slice(0, at)) + encodeHash(fields);
}

/** A number from a share link, if it is an integer within `[min, max]`. */
export function intField(fields: Map<string, string>, key: string, min: number, max: number): number | undefined {
  const raw = fields.get(key);
  if (raw === undefined || !/^\d+$/.test(raw)) return undefined;
  const n = Number(raw);
  return n >= min && n <= max ? n : undefined;
}

/** One of `choices` from a share link. */
export function choiceField<T extends string>(fields: Map<string, string>, key: string, choices: readonly T[]): T | undefined {
  const raw = fields.get(key);
  return choices.find((c) => c === raw);
}
