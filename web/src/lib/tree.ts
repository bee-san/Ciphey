// The search tree the Decode page draws as Ciphey searches: the input at the root, and under
// each node the outputs of the decoders that ran on it. A 5-second search can expand
// thousands of nodes, so the page draws the first `cap` and counts the rest, but always draws
// the path to a plaintext.

import type { TreeNode } from "./protocol";

export interface Node extends TreeNode {
  /** Ids of the node's children, in the order they arrived. */
  children: number[];
}

export class SearchTree {
  private readonly byId = new Map<number, Node>();
  private readonly order: number[] = [];

  /** The number of nodes. */
  get size(): number {
    return this.order.length;
  }

  get(id: number): Node | undefined {
    return this.byId.get(id);
  }

  /** The nodes without a parent in the tree (normally just the input). */
  roots(): Node[] {
    return this.order.map((id) => this.byId.get(id) as Node).filter((n) => n.parent === null || !this.byId.has(n.parent));
  }

  /** Adds nodes (parents before children); returns the ones that weren't there yet. */
  add(nodes: readonly TreeNode[]): Node[] {
    const added: Node[] = [];
    for (const n of nodes) {
      if (this.byId.has(n.id)) continue;
      const node: Node = { ...n, children: [] };
      this.byId.set(n.id, node);
      this.order.push(n.id);
      if (n.parent !== null) this.byId.get(n.parent)?.children.push(n.id);
      added.push(node);
    }
    return added;
  }

  /** The nodes from the root down to `id` (empty if `id` isn't in the tree). */
  pathTo(id: number): Node[] {
    const path: Node[] = [];
    const seen = new Set<number>();
    let node = this.byId.get(id);
    while (node && !seen.has(node.id)) {
      seen.add(node.id);
      path.unshift(node);
      node = node.parent === null ? undefined : this.byId.get(node.parent);
    }
    return path;
  }

  /** The ids to draw: the first `cap` nodes to arrive, and every node on the paths to `pinned`. */
  visible(cap: number, pinned: Iterable<number> = []): Set<number> {
    const shown = new Set(this.order.slice(0, cap));
    for (const id of pinned) for (const n of this.pathTo(id)) shown.add(n.id);
    return shown;
  }

  /** How many of `id`'s children `shown` leaves out. */
  hiddenChildren(id: number, shown: ReadonlySet<number>): number {
    return this.byId.get(id)?.children.filter((c) => !shown.has(c)).length ?? 0;
  }
}
