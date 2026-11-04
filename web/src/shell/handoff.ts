// Hands text from one tool to another, through sessionStorage: it stays in this tab and is
// never in a URL, so it doesn't end up in the browser's history or a server's logs.

const KEY = "ciphey-handoff";

/** Leaves `text` for the next page this tab opens to pick up. */
export function handOff(text: string): void {
  try {
    sessionStorage.setItem(KEY, text);
  } catch {
    // Storage blocked: the other page starts empty
  }
}

/** The text another page left for this one, once (it's removed as it's read). */
export function pickUp(): string | null {
  try {
    const text = sessionStorage.getItem(KEY);
    sessionStorage.removeItem(KEY);
    return text;
  } catch {
    return null;
  }
}
