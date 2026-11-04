// Long texts go to pyWhat in pieces (see workers/identify.worker.ts for why).

/** The page highlights at most this many matches; the worker stops there. */
export const MAX_MATCHES = 5_000;

/**
 * `text` in pieces of about `size` characters, each ending at a line end if there is one in
 * its second half, else at a space (or, with `wholeLines`, at the piece's last line end, or
 * the end of a line longer than the piece). With `wholeLines` (pyWhat's anchored mode, where
 * a regex must match a whole line) no line is ever cut, and a text with no line ends stays
 * whole. The pieces joined are `text`.
 */
export function pieces(text: string, size: number, wholeLines: boolean): string[] {
  if (text.length <= size || (wholeLines && !text.includes("\n"))) return [text];
  const out: string[] = [];
  let start = 0;
  while (start < text.length) {
    let end = Math.min(text.length, start + size);
    if (end < text.length) {
      const half = start + Math.floor(size / 2);
      const line = text.lastIndexOf("\n", end - 1);
      const space = text.lastIndexOf(" ", end - 1);
      if (line >= half) end = line + 1;
      else if (!wholeLines && space >= half) end = space + 1;
      else if (wholeLines && line >= start) end = line + 1;
      else if (wholeLines) {
        const next = text.indexOf("\n", end);
        end = next < 0 ? text.length : next + 1;
      }
    }
    out.push(text.slice(start, end));
    start = end;
  }
  return out;
}
