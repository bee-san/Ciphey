// Long texts go to pyWhat in pieces (see workers/identify.worker.ts for why).

/** The page highlights at most this many matches; the worker stops there. */
export const MAX_MATCHES = 5_000;

/**
 * `text` in pieces of about `size` characters. A piece ends at a line end if there is one in
 * its second half; else (matches may sit inside text) at a space, then at punctuation that no
 * identifier contains; else at `size`. With `wholeLines` (pyWhat's anchored mode, where a
 * regex must match a whole line) no line is ever cut, and a text with no line ends stays
 * whole. No piece ends inside a PEM or PGP block (`-----BEGIN …` to `-----END …-----`):
 * pyWhat's key formats span many lines. The pieces joined are `text`.
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
      if (line >= half) end = line + 1;
      else if (!wholeLines) {
        const cut = lastCut(text, half, end);
        if (cut >= 0) end = cut + 1;
      } else if (line >= start) end = line + 1;
      else {
        const next = text.indexOf("\n", end);
        end = next < 0 ? text.length : next + 1;
      }
      end = afterBlock(text, start, end);
    }
    out.push(text.slice(start, end));
    start = end;
  }
  return out;
}

/** The last space in `[from, to)`, else the last punctuation no identifier has; -1 if none. */
function lastCut(text: string, from: number, to: number): number {
  const space = text.lastIndexOf(" ", to - 1);
  if (space >= from) return space;
  for (let i = to - 1; i >= from; i--) if (/[\s,;|<>"'()[\]{}]/.test(text[i] as string)) return i;
  return -1;
}

const BEGIN = /-----BEGIN [A-Z0-9 ]+-----/g;

/**
 * `end`, or the end of the line where a PEM/PGP block that starts in `[start, end)` and isn't
 * closed there is closed (if it isn't closed at all, the text's end).
 */
function afterBlock(text: string, start: number, end: number): number {
  BEGIN.lastIndex = start;
  let last: RegExpExecArray | null = null;
  for (let m = BEGIN.exec(text); m && m.index < end; m = BEGIN.exec(text)) last = m;
  if (!last) return end;
  const close = text.indexOf("-----END ", last.index);
  if (close >= 0 && close < end) {
    // Closed inside the piece: unless the closing line runs past the cut
    const lineEnd = text.indexOf("\n", close);
    const closeEnd = lineEnd < 0 ? text.length : lineEnd + 1;
    return Math.max(end, closeEnd);
  }
  if (close < 0) return text.length;
  const lineEnd = text.indexOf("\n", close);
  return lineEnd < 0 ? text.length : lineEnd + 1;
}
