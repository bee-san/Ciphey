// pyWhat's descriptions are written for Rich, the terminal library its CLI prints with:
// "An [#CAE4F1][link=https://en.wikipedia.org/wiki/...]American Identification Number[/link][/#CAE4F1]".
// This turns them into text and links, never HTML. Colour tags are dropped; any other
// bracketed text ("[ACCESS_KEY]" in an exploit) stays as it is.

export type Piece = { kind: "text"; text: string } | { kind: "link"; text: string; href: string };

const TAG = /\[(\/?#[0-9a-fA-F]{3,8}|link=[^\]]*|\/link)\]/g;

/** Only http(s) links become links; anything else (javascript:, data:) stays text. */
export function safeHref(href: string): string | null {
  try {
    const url = new URL(href);
    return url.protocol === "https:" || url.protocol === "http:" ? url.href : null;
  } catch {
    return null;
  }
}

/** The text and links of a Rich-marked-up string, with neighbouring text merged. */
export function parseMarkup(source: string): Piece[] {
  const pieces: Piece[] = [];
  const push = (piece: Piece) => {
    if (piece.text === "") return;
    const last = pieces[pieces.length - 1];
    if (piece.kind === "text" && last?.kind === "text") last.text += piece.text;
    else pieces.push(piece);
  };
  let href: string | null = null;
  let linkText = "";
  let at = 0;
  for (const m of source.matchAll(TAG)) {
    const before = source.slice(at, m.index);
    if (href === null) push({ kind: "text", text: before });
    else linkText += before;
    at = m.index + m[0].length;
    const tag = m[1] as string;
    if (tag.startsWith("link=")) {
      if (href !== null) push(linkPiece(linkText, href)); // a link inside a link: close the first
      href = tag.slice(5);
      linkText = "";
    } else if (tag === "/link" && href !== null) {
      push(linkPiece(linkText, href));
      href = null;
    }
    // Colour tags, and a [/link] without a [link=], are dropped
  }
  const rest = source.slice(at);
  if (href === null) push({ kind: "text", text: rest });
  else push(linkPiece(linkText + rest, href));
  return pieces;
}

function linkPiece(text: string, href: string): Piece {
  const safe = safeHref(href);
  return safe ? { kind: "link", text, href: safe } : { kind: "text", text };
}

/** The plain text of a marked-up string: what a screen reader or a copy gets. */
export function plainText(source: string): string {
  return parseMarkup(source)
    .map((p) => p.text)
    .join("");
}
