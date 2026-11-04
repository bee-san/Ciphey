// Draws the search tree into a <ul>, as nested lists: one item per node, its children in a
// list under it. Nodes arrive in bursts while Ciphey searches; they're drawn once per frame,
// the first TREE_CAP of them, with "+N more" under parents whose other children aren't drawn.
// A parent's children from one decoder (Caesar's 25 shifts, say) fold into a group once there
// are GROUP_AT of them, so the tree's shape stays readable. The path to a plaintext is always
// drawn, its groups opened, and marked.

import { count, plural, preview } from "../lib/format";
import type { DecodeResult, TreeNode } from "../lib/protocol";
import { SearchTree } from "../lib/tree";
import { h, icon } from "../shell/dom";
import { decoderName } from "./words";

export const TREE_CAP = 300;
export const GROUP_AT = 3;

interface Group {
  li: HTMLLIElement;
  details: HTMLDetailsElement;
  list: HTMLUListElement;
  label: HTMLElement;
  members: number[];
}

/**
 * Text for a one-line preview: control characters, and the characters that reorder text
 * (bidirectional overrides and isolates), show as "·", so decoder junk can't garble the row.
 */
export function printable(text: string): string {
  return text.replace(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u200e\u200f\u202a-\u202e\u2066-\u2069]/g, "·");
}

export class TreeView {
  private tree = new SearchTree();
  private readonly items = new Map<number, HTMLLIElement>();
  private readonly lists = new Map<number, HTMLUListElement>();
  private readonly more = new Map<number, HTMLLIElement>();
  /** parent id → decoder → the parent's drawn children from that decoder, or their group */
  private readonly singles = new Map<number, Map<string, number[]>>();
  private readonly groups = new Map<number, Map<string, Group>>();
  private readonly groupOf = new Map<number, Group>();
  private pinned = new Set<number>();
  private results = new Set<number>();
  private queued = false;
  private dirty = false;

  constructor(private readonly root: HTMLUListElement) {}

  get size(): number {
    return this.tree.size;
  }

  get drawn(): number {
    return this.items.size;
  }

  reset(): void {
    this.tree = new SearchTree();
    for (const map of [this.items, this.lists, this.more, this.singles, this.groups, this.groupOf]) map.clear();
    this.pinned = new Set();
    this.results = new Set();
    this.root.replaceChildren();
    this.root.classList.remove("tree--done");
  }

  add(nodes: readonly TreeNode[]): void {
    if (this.tree.add(nodes).length > 0) this.schedule();
  }

  /** Marks `id` as a plaintext and draws the path to it. */
  markResult(id: number): void {
    this.results.add(id);
    this.pinned.add(id);
    this.schedule();
  }

  /**
   * Adds a result's plaintext as a leaf under the node it was decoded from (the engine
   * reports expanded nodes, and the plaintext isn't expanded), and marks it. A result of the
   * input itself marks the input.
   */
  addResult(result: DecodeResult): void {
    if (result.nodeId === null) {
      this.markResult(0);
      return;
    }
    const parent = this.tree.get(result.nodeId);
    const last = result.path[result.path.length - 1];
    const id = -1 - this.results.size;
    this.tree.add([
      {
        id,
        parent: result.nodeId,
        depth: (parent?.depth ?? 0) + 1,
        decoder: last?.decoder ?? null,
        key: last?.key ?? null,
        text: result.plaintext,
        length: Array.from(result.plaintext).length,
      },
    ]);
    this.markResult(id);
  }

  /** The search ended: nodes off the plaintext's path are drawn quieter. */
  finish(): void {
    this.flush();
    if (this.results.size > 0) this.root.classList.add("tree--done");
  }

  private schedule(): void {
    this.dirty = true;
    if (this.queued) return;
    this.queued = true;
    requestAnimationFrame(() => {
      this.queued = false;
      this.flush();
    });
  }

  flush(): void {
    if (!this.dirty) return;
    this.dirty = false;
    const shown = this.tree.visible(TREE_CAP, this.pinned);
    // Parents before children: by depth, then in the order they arrived
    const order = [...shown].sort((a, b) => (this.tree.get(a)?.depth ?? 0) - (this.tree.get(b)?.depth ?? 0));
    for (const id of order) if (!this.items.has(id)) this.draw(id);

    const onPath = new Set<number>();
    for (const r of this.results) for (const n of this.tree.pathTo(r)) onPath.add(n.id);
    for (const [id, li] of this.items) {
      const path = onPath.has(id);
      li.classList.toggle("node--path", path);
      li.classList.toggle("node--result", this.results.has(id));
      if (this.results.has(id) && !li.querySelector(":scope > .node__row > .node__found")) {
        li.querySelector(":scope > .node__row")?.append(h("span", { class: "badge badge--success node__found" }, icon("check"), "plaintext"));
      }
      const group = this.groupOf.get(id);
      if (group && path && !group.li.classList.contains("node-group--path")) {
        group.li.classList.add("node-group--path");
        group.details.open = true;
      }
    }
    for (const [parent, byDecoder] of this.groups) {
      for (const [decoder, g] of byDecoder) {
        const all = this.tree.get(parent)?.children.filter((c) => this.tree.get(c)?.decoder === decoder).length ?? g.members.length;
        g.label.textContent = all > g.members.length ? `${count(g.members.length)} of ${plural(all, "output")} drawn` : plural(all, "output");
      }
    }
    for (const id of this.items.keys()) this.updateMore(id, shown);
  }

  private row(id: number, isRoot: boolean): HTMLElement {
    const node = this.tree.get(id) as TreeNode;
    return h(
      "div",
      { class: "node__row" },
      h("span", { class: "node__decoder" }, isRoot ? "Input" : decoderName(node.decoder ?? "?")),
      node.key ? h("span", { class: "node__key" }, `key ${node.key}`) : null,
      h("code", { class: "node__text" }, printable(preview(node.text, 80)) || "(empty)"),
      h("span", { class: "node__len" }, plural(node.length, "character")),
    );
  }

  private draw(id: number): void {
    const node = this.tree.get(id);
    if (!node) return;
    const parentLi = node.parent === null ? undefined : this.items.get(node.parent);
    const isRoot = !parentLi;
    const li = h("li", { class: "node" }, this.row(id, isRoot));
    this.items.set(id, li);
    if (isRoot) {
      li.classList.add("node--root");
      this.root.append(li);
      return;
    }
    const parent = node.parent as number;
    const decoder = node.decoder ?? "?";
    const group = this.groups.get(parent)?.get(decoder);
    if (group) {
      group.members.push(id);
      group.list.append(li);
      this.groupOf.set(id, group);
      return;
    }
    const byDecoder = this.singles.get(parent) ?? new Map<string, number[]>();
    this.singles.set(parent, byDecoder);
    const same = byDecoder.get(decoder) ?? [];
    same.push(id);
    byDecoder.set(decoder, same);
    const list = this.childList(parent);
    if (same.length < GROUP_AT) {
      this.insert(list, parent, li);
      return;
    }
    // The GROUP_AT-th child from this decoder: fold them all into a group where the first was
    const first = this.items.get(same[0] as number) as HTMLLIElement;
    const label = h("span", { class: "node__count" });
    const summary = h("summary", { class: "node__row node__row--group" }, h("span", { class: "node__decoder" }, decoderName(decoder)), label);
    const groupList = h("ul");
    const details = h("details", {}, summary, groupList);
    const groupLi = h("li", { class: "node-group" }, details);
    list.insertBefore(groupLi, first);
    const g: Group = { li: groupLi, details, list: groupList, label, members: [] };
    for (const member of same) {
      const memberLi = member === id ? li : (this.items.get(member) as HTMLLIElement);
      g.members.push(member);
      groupList.append(memberLi);
      this.groupOf.set(member, g);
    }
    byDecoder.delete(decoder);
    const groups = this.groups.get(parent) ?? new Map<string, Group>();
    groups.set(decoder, g);
    this.groups.set(parent, groups);
  }

  private childList(parent: number): HTMLUListElement {
    let list = this.lists.get(parent);
    if (!list) {
      list = h("ul");
      this.items.get(parent)?.append(list);
      this.lists.set(parent, list);
    }
    return list;
  }

  /** Appends `li` to a parent's list, before its "+N more" line if it has one. */
  private insert(list: HTMLUListElement, parent: number, li: HTMLLIElement): void {
    const more = this.more.get(parent);
    if (more && more.parentElement === list) list.insertBefore(li, more);
    else list.append(li);
  }

  private updateMore(id: number, shown: ReadonlySet<number>): void {
    const hidden = this.tree.hiddenChildren(id, shown);
    let more = this.more.get(id);
    if (hidden === 0) {
      more?.remove();
      this.more.delete(id);
      return;
    }
    if (!more) {
      more = h("li", { class: "node node--more" });
      this.more.set(id, more);
    }
    more.textContent = `+ ${count(hidden)} more not drawn`;
    this.childList(id).append(more);
  }
}
