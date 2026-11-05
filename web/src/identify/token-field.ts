// A text field that collects tokens: type a tag and press Enter (or a comma) to add it; each
// token has a remove button; Backspace in the empty field removes the last one. Suggestions
// come from the field's <datalist>.

import { announce, h, icon } from "../shell/dom";

export class TokenField {
  private tokens: string[] = [];
  private readonly list: HTMLUListElement;

  constructor(
    private readonly root: HTMLElement,
    private readonly input: HTMLInputElement,
    private readonly noun: string,
    private readonly onChange: () => void,
  ) {
    this.list = root.querySelector("ul") as HTMLUListElement;
    input.addEventListener("keydown", (e) => {
      if ((e.key === "Enter" || e.key === ",") && input.value.trim()) {
        e.preventDefault();
        this.add(input.value);
        input.value = "";
      } else if (e.key === "Enter") {
        e.preventDefault();
      } else if (e.key === "Backspace" && input.value === "" && this.tokens.length) {
        this.remove(this.tokens[this.tokens.length - 1] as string);
      }
    });
    // Picking a suggestion from the datalist fires "input" with the whole value (an
    // insertReplacementText input, or a plain Event in some browsers); typing doesn't add
    input.addEventListener("input", (e) => {
      const picked = !(e instanceof InputEvent) || e.inputType === "insertReplacementText";
      const options = input.list ? Array.from(input.list.options).map((o) => o.value) : [];
      if (picked && options.includes(input.value)) {
        this.add(input.value);
        input.value = "";
      }
    });
    root.addEventListener("click", (e) => {
      if (e.target === root) input.focus();
    });
  }

  get values(): string[] {
    return [...this.tokens];
  }

  add(raw: string): void {
    const value = raw.replace(/,/g, " ").trim();
    if (!value || this.tokens.some((t) => t.toLowerCase() === value.toLowerCase())) return;
    this.tokens.push(value);
    this.render();
    announce(`${value} added to ${this.noun}`);
    this.onChange();
  }

  remove(value: string): void {
    this.tokens = this.tokens.filter((t) => t !== value);
    this.render();
    announce(`${value} removed from ${this.noun}`);
    this.input.focus();
    this.onChange();
  }

  clear(): void {
    this.tokens = [];
    this.render();
  }

  private render(): void {
    this.list.replaceChildren(
      ...this.tokens.map((t) =>
        h(
          "li",
          { class: "token" },
          h("span", {}, t),
          h("button", { type: "button", "aria-label": `Remove ${t}`, title: `Remove ${t}`, onclick: () => this.remove(t) }, icon("x")),
        ),
      ),
    );
  }
}
