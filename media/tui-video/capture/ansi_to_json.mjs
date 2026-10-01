#!/usr/bin/env node
// Convert the tmux snapshots written by capture.py into ../video/captures.js.
//
// Every snapshot is a full `tmux capture-pane -e` dump (scrollback + screen).
// We parse each one into a cell grid (char + colour/bold), then work out the
// first snapshot in which every cell of the final screen appeared ("birth").
// The composition replays the session by revealing cells at the time of
// their birth snapshot, so what you see is exactly what the terminal showed.
//
// Usage: node ansi_to_json.mjs [captureOutDir] [outFile]

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const capDir = process.argv[2] ?? path.join(here, "out");
const outFile = process.argv[3] ?? path.join(here, "..", "video", "captures.js");
const demos = JSON.parse(fs.readFileSync(path.join(here, "demos.json"), "utf8"));

// 16-colour palette used for plain SGR 30-37 / 90-97 (Catppuccin Mocha).
const PALETTE = [
  "#45475a", "#f38ba8", "#a6e3a1", "#f9e2af", "#89b4fa", "#f5c2e7", "#94e2d5", "#bac2de",
  "#585b70", "#f38ba8", "#a6e3a1", "#f9e2af", "#89b4fa", "#f5c2e7", "#94e2d5", "#a6adc8",
];
const hex = (r, g, b) => "#" + [r, g, b].map((v) => v.toString(16).padStart(2, "0")).join("");

function xterm256(n) {
  if (n < 16) return PALETTE[n];
  if (n < 232) {
    const i = n - 16, steps = [0, 95, 135, 175, 215, 255];
    return hex(steps[Math.floor(i / 36)], steps[Math.floor(i / 6) % 6], steps[i % 6]);
  }
  const v = 8 + (n - 232) * 10;
  return hex(v, v, v);
}

// Display width as tmux computes it for the characters ciphey prints.
const ZERO = /[\u200d\ufe0e\ufe0f\p{Mn}\p{Me}]/u;
const WIDE = /[\p{Emoji_Presentation}\u1100-\u115f\u2e80-\ua4cf\uac00-\ud7a3\uf900-\ufaff\ufe30-\ufe4f\uff00-\uff60\uffe0-\uffe6]/u;

function applySgr(style, params) {
  const p = params.length ? params : [0];
  for (let i = 0; i < p.length; i++) {
    const c = p[i];
    if (c === 0) Object.assign(style, { fg: null, bg: null, bold: false, dim: false, italic: false, underline: false });
    else if (c === 1) style.bold = true;
    else if (c === 2) style.dim = true;
    else if (c === 3) style.italic = true;
    else if (c === 4) style.underline = true;
    else if (c === 22) { style.bold = false; style.dim = false; }
    else if (c === 23) style.italic = false;
    else if (c === 24) style.underline = false;
    else if (c >= 30 && c <= 37) style.fg = PALETTE[c - 30];
    else if (c >= 90 && c <= 97) style.fg = PALETTE[c - 90 + 8];
    else if (c === 39) style.fg = null;
    else if (c >= 40 && c <= 47) style.bg = PALETTE[c - 40];
    else if (c >= 100 && c <= 107) style.bg = PALETTE[c - 100 + 8];
    else if (c === 49) style.bg = null;
    else if (c === 38 || c === 48) {
      const key = c === 38 ? "fg" : "bg";
      if (p[i + 1] === 2) { style[key] = hex(p[i + 2], p[i + 3], p[i + 4]); i += 4; }
      else if (p[i + 1] === 5) { style[key] = xterm256(p[i + 2]); i += 2; }
    }
  }
}

const styleKey = (s) => `${s.fg ?? ""}|${s.bg ?? ""}|${s.bold ? 1 : 0}${s.dim ? 1 : 0}${s.italic ? 1 : 0}${s.underline ? 1 : 0}`;

// Parse one capture into rows of cells: {ch, w, style}. Wide chars are followed
// by a {pad:true} cell so column indices line up with the terminal grid.
function parseCapture(text) {
  const style = { fg: null, bg: null, bold: false, dim: false, italic: false, underline: false };
  const rows = [];
  let row = [];
  const chars = Array.from(text);
  for (let i = 0; i < chars.length; i++) {
    const ch = chars[i];
    if (ch === "\x1b" && chars[i + 1] === "[") {
      let j = i + 2, body = "";
      while (j < chars.length && !/[A-Za-z]/.test(chars[j])) body += chars[j++];
      if (chars[j] === "m") applySgr(style, body.split(";").filter((x) => x !== "").map(Number));
      i = j;
      continue;
    }
    if (ch === "\n") { rows.push(row); row = []; continue; }
    if (ZERO.test(ch)) {
      const prev = [...row].reverse().find((c) => !c.pad);
      if (prev) {
        prev.ch += ch;
        if (ch === "\ufe0f" && prev.w === 1) { prev.w = 2; row.push({ pad: true }); }
      }
      continue;
    }
    const w = WIDE.test(ch) ? 2 : 1;
    row.push({ ch, w, style: { ...style } });
    if (w === 2) row.push({ pad: true });
  }
  if (row.length) rows.push(row);
  return rows;
}

const cellId = (c) => (c && !c.pad ? c.ch + "\u0000" + styleKey(c.style) : null);

const result = {};
for (const [name, demo] of Object.entries(demos.demos)) {
  const meta = JSON.parse(fs.readFileSync(path.join(capDir, name, "frames.json"), "utf8"));
  const snaps = meta.frames.map((f) => parseCapture(fs.readFileSync(path.join(capDir, name, f.file), "utf8")));
  const final = snaps[snaps.length - 1];
  const styles = [], styleIndex = new Map();
  const internStyle = (s) => {
    const k = styleKey(s);
    if (!styleIndex.has(k)) {
      styleIndex.set(k, styles.length);
      styles.push({ fg: s.fg, bg: s.bg, b: s.bold ? 1 : 0 });
    }
    return styleIndex.get(k);
  };

  // Trim trailing empty rows of the final screen.
  let lastRow = final.length - 1;
  while (lastRow > 0 && final[lastRow].every((c) => c.pad || c.ch === " ")) lastRow--;

  const lines = [];
  for (let r = 0; r <= lastRow; r++) {
    const runs = [];
    final[r].forEach((cell, col) => {
      if (cell.pad) return;
      const id = cellId(cell);
      let birth = snaps.length - 1;
      while (birth > 0 && cellId(snaps[birth - 1][r]?.[col]) === id) birth--;
      const st = internStyle(cell.style);
      const typed = meta.frames[birth].kind === "type";
      const last = runs[runs.length - 1];
      // Typed text is split per character so it can be revealed keystroke by keystroke;
      // wide glyphs get their own run so they can be pinned to two cells.
      if (last && !typed && cell.w === 1 && last.w === 1 && last.s === st && last.b === birth && last.c + last.t.length === col) {
        last.t += cell.ch;
      } else {
        runs.push({ t: cell.ch, s: st, b: birth, c: col, w: cell.w });
      }
    });
    // Drop runs of plain spaces that only pad the line.
    lines.push(runs.filter((run) => run.t.trim() !== "" || styles[run.s].bg).map(({ t, s, b, c, w }) => (w === 2 ? [t, s, b, c, 2] : [t, s, b, c])));
  }

  result[name] = {
    title: demo.title,
    cols: meta.cols,
    rows: meta.rows,
    styles,
    frames: meta.frames.map((f) => ({
      kind: f.kind, label: f.label, top: f.history,
      cursor: [f.history + f.cursor_y, f.cursor_x],
      ...(f.typed ? { typed: f.typed } : {}),
    })),
    lines,
  };
}

const banner = `// GENERATED by capture/ansi_to_json.mjs from real tmux captures of target/release/ciphey.
// Line runs are [text, styleIndex, birthFrame, column(, width)]. Do not edit by hand.\n`;
fs.writeFileSync(outFile, banner + "window.CIPHEY_CAPTURES = " + JSON.stringify(result) + ";\n");
for (const [k, v] of Object.entries(result)) {
  console.log(`${k}: ${v.lines.length} rows, ${v.frames.length} frames, ${v.styles.length} styles`);
}
console.log("wrote", outFile, fs.statSync(outFile).size, "bytes");
