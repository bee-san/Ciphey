// Small DOM helpers shared by the pages. Text always goes in through textContent (h() and
// text nodes), never as HTML: everything the engines return is data.

type Child = Node | string | null | undefined | false;
type Attrs = Record<string, string | number | boolean | null | undefined | EventListener>;

/** An element: `h("a", { href, class: "x" }, "text", child)`. `on…` attributes add listeners. */
export function h<K extends keyof HTMLElementTagNameMap>(tag: K, attrs: Attrs = {}, ...children: Child[]): HTMLElementTagNameMap[K] {
  const el = document.createElement(tag);
  for (const [name, value] of Object.entries(attrs)) {
    if (value === null || value === undefined || value === false) continue;
    if (typeof value === "function") el.addEventListener(name.slice(2).toLowerCase(), value);
    else if (value === true) el.setAttribute(name, "");
    else el.setAttribute(name, String(value));
  }
  append(el, ...children);
  return el;
}

export function append(parent: Element, ...children: Child[]): void {
  for (const c of children) {
    if (c === null || c === undefined || c === false) continue;
    parent.append(typeof c === "string" ? document.createTextNode(c) : c);
  }
}

/** The element with `id`, or an error naming it (the HTML and the code disagree). */
export function byId<T extends HTMLElement = HTMLElement>(id: string): T {
  const el = document.getElementById(id);
  if (!el) throw new Error(`#${id} is missing from the page`);
  return el as T;
}

/** Inline SVG icons, drawn on a 24-unit grid with the .icon stroke style. */
const ICONS = {
  copy: '<rect x="8.5" y="8.5" width="11" height="11" rx="2"/><path d="M15.5 8.5V6a1.5 1.5 0 0 0-1.5-1.5H6A1.5 1.5 0 0 0 4.5 6v8A1.5 1.5 0 0 0 6 15.5h2.5"/>',
  check: '<path d="m5 12.5 4.5 4.5L19 7.5"/>',
  link: '<path d="M10 14a4.5 4.5 0 0 0 6.4 0l3-3a4.5 4.5 0 0 0-6.4-6.4l-1 1"/><path d="M14 10a4.5 4.5 0 0 0-6.4 0l-3 3a4.5 4.5 0 0 0 6.4 6.4l1-1"/>',
  external: '<path d="M14 4.5h5.5V10M19.5 4.5 11 13M10 6H6a1.5 1.5 0 0 0-1.5 1.5v10.5A1.5 1.5 0 0 0 6 19.5h10.5A1.5 1.5 0 0 0 18 18v-4"/>',
  x: '<path d="m7 7 10 10M17 7 7 17"/>',
  ok: '<circle cx="12" cy="12" r="8.5"/><path d="m8.2 12.3 2.6 2.6 5-5.4"/>',
  no: '<circle cx="12" cy="12" r="8.5"/><path d="m9 9 6 6M15 9l-6 6"/>',
  arrow: '<path d="M12 5v14M6.5 13.5 12 19l5.5-5.5"/>',
} as const;

export function icon(name: keyof typeof ICONS): SVGSVGElement {
  const tpl = document.createElement("template");
  // A fixed string from ICONS above, never data
  tpl.innerHTML = `<svg class="icon" viewBox="0 0 24 24" width="16" height="16" aria-hidden="true" focusable="false">${ICONS[name]}</svg>`;
  return tpl.content.firstElementChild as SVGSVGElement;
}

/**
 * Says `message` through the page's polite live region. Repeating the same message still
 * announces it: the region is emptied first.
 */
export function announce(message: string): void {
  const region = document.getElementById("announcer");
  if (!region) return;
  region.textContent = "";
  window.setTimeout(() => {
    region.textContent = message;
  }, 50);
}

/** Copies `text`, with the old way as a fallback where the Clipboard API isn't allowed. */
export async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    const area = h("textarea", { class: "visually-hidden", "aria-hidden": "true", tabindex: -1 });
    area.value = text;
    document.body.append(area);
    area.select();
    let ok = false;
    try {
      ok = document.execCommand("copy");
    } catch {
      ok = false;
    }
    area.remove();
    return ok;
  }
}

/** A button that copies what `get()` returns and says so on itself for a moment. */
export function copyButton(label: string, get: () => string, extraClass = ""): HTMLButtonElement {
  const text = h("span", {}, label);
  const button = h("button", { type: "button", class: `button button--small ${extraClass}`.trim() }, icon("copy"), text);
  let timer = 0;
  button.addEventListener("click", async () => {
    const ok = await copyText(get());
    text.textContent = ok ? "Copied" : "Couldn't copy";
    announce(ok ? `${label}: copied to the clipboard` : "Couldn't copy to the clipboard");
    window.clearTimeout(timer);
    timer = window.setTimeout(() => (text.textContent = label), 2000);
  });
  return button;
}

/** Reads a file as UTF-8 text, refusing files over `maxBytes`. */
export async function readTextFile(file: File, maxBytes: number): Promise<{ text: string } | { error: string }> {
  if (file.size > maxBytes) {
    const kb = Math.round(maxBytes / 1024);
    return { error: `${file.name} is ${Math.ceil(file.size / 1024).toLocaleString("en")} KB. Files up to ${kb} KB can be read here.` };
  }
  const text = new TextDecoder("utf-8", { fatal: false }).decode(await file.arrayBuffer());
  if (text.includes("\u0000") || (text.match(/\uFFFD/g)?.length ?? 0) > text.length / 20) {
    return { error: `${file.name} doesn't look like text. Ciphey and pyWhat read text, such as a .txt file.` };
  }
  return { text };
}

/**
 * Makes `zone` accept dropped files and `button` open the file picker `input`; `onFile` gets
 * the chosen file. Dropping is a shortcut: the button does the same with a click or a key.
 */
export function wireFileInput(zone: HTMLElement, input: HTMLInputElement, button: HTMLElement, onFile: (file: File) => void): void {
  button.addEventListener("click", () => input.click());
  input.addEventListener("change", () => {
    const file = input.files?.[0];
    if (file) onFile(file);
    input.value = "";
  });
  let depth = 0;
  const hasFiles = (e: DragEvent) => Array.from(e.dataTransfer?.types ?? []).includes("Files");
  zone.addEventListener("dragenter", (e) => {
    if (!hasFiles(e)) return;
    e.preventDefault();
    depth++;
    zone.classList.add("is-dragging");
  });
  zone.addEventListener("dragover", (e) => {
    if (hasFiles(e)) e.preventDefault();
  });
  zone.addEventListener("dragleave", () => {
    depth = Math.max(0, depth - 1);
    if (depth === 0) zone.classList.remove("is-dragging");
  });
  zone.addEventListener("drop", (e) => {
    if (!hasFiles(e)) return;
    e.preventDefault();
    depth = 0;
    zone.classList.remove("is-dragging");
    const file = e.dataTransfer?.files[0];
    if (file) onFile(file);
  });
}

/** `0 characters`, `1 character`, `1,234 characters` (code points, as Ciphey counts). */
export function characterCount(text: string): string {
  let n = 0;
  for (const _ of text) n++;
  return `${n.toLocaleString("en")} ${n === 1 ? "character" : "characters"}`;
}
