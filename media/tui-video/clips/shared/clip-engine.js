// Shared engine for the short feature clips (fast.html, lemmeknow.html, crib.html).
//
// It is the replay code from index.html (the TUI promo) made reusable: every terminal
// cell comes from window.CIPHEY_CAPTURES (real tmux recordings of target/release/ciphey,
// see ../capture/) and is revealed at the snapshot in which it first appeared.
// A clip page supplies the timing (scenes, captions, highlight boxes) and its title and
// end cards as plain HTML with data-in / data-out attributes (seconds).
(function () {
  const CW = 15.6; // JetBrains Mono advance at 26px (0.6em)
  const LH = 35;
  const COLS = 88;
  const VIEW_ROWS = 13; // rows visible in the compact window (#winWrap 539px tall)
  const ROW_STAGGER = 0.014;

  function mulberry32(seed) {
    return function () {
      seed |= 0; seed = (seed + 0x6d2b79f5) | 0;
      let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }
  function make(tag, cls, parent, text) {
    const node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text != null) node.textContent = text;
    if (parent) parent.appendChild(node);
    return node;
  }
  // Rebuild a row as an array of column cells (wide glyphs take two).
  function rowCells(lines, r) {
    const cells = [];
    for (const [t, , , c, w] of lines[r] || []) {
      if (w === 2) { cells[c] = t; cells[c + 1] = ""; continue; }
      Array.from(t).forEach((ch, i) => { cells[c + i] = ch; });
    }
    return cells;
  }
  // Plain text of a capture's final screen, used to quote real output in captions.
  function captureText(id) {
    const cap = window.CIPHEY_CAPTURES[id];
    return cap.lines.map((_, r) => Array.from(rowCells(cap.lines, r), (ch) => ch ?? " ").join("")).join("\n");
  }
  function findText(cap, text, last) {
    const order = [...cap.lines.keys()];
    if (last) order.reverse();
    for (const r of order) {
      const cells = rowCells(cap.lines, r);
      let str = "";
      const map = [];
      for (let col = 0; col < cells.length; col++) {
        const ch = cells[col] ?? " ";
        if (ch === "") continue;
        for (const cp of Array.from(ch)) { map.push(col); str += cp; }
      }
      const idx = str.indexOf(text);
      if (idx < 0) continue;
      const first = Array.from(str.slice(0, idx)).length;
      const lastCp = Array.from(str.slice(0, idx + text.length)).length - 1;
      const startCol = map[first];
      const endCol = map[lastCp] + (cells[map[lastCp] + 1] === "" ? 2 : 1);
      return { row: r, col: startCol, width: endCol - startCol };
    }
    throw new Error("text not found in capture: " + text);
  }

  function run(cfg) {
    const CAP = window.CIPHEY_CAPTURES;
    const DUR = cfg.duration;
    const tl = gsap.timeline({ paused: true });
    // bgDrift=false freezes the faint background rows. build.sh renders the GIF previews that
    // way: the drifting rows change every pixel of the frame, which makes GIFs ~4x larger.
    const vars = (window.__hyperframes && window.__hyperframes.getVariables && window.__hyperframes.getVariables()) || {};
    const drift = vars.bgDrift !== false;

    // ---------- background glyph rows (the clip's real ciphertexts) ----------
    const glyphHost = document.getElementById("glyphs");
    const typed = cfg.scenes.map((s) => {
      const cmd = CAP[s.id].frames.find((f) => f.typed).typed;
      return cmd.slice(cmd.indexOf("'") + 1, cmd.indexOf("'", cmd.indexOf("'") + 1));
    });
    const rnd = mulberry32(cfg.seed || 42);
    for (let i = 0; i < 16; i++) {
      const src = typed[i % typed.length];
      const row = make("div", "grow", glyphHost, (src + "  ").repeat(Math.ceil(300 / src.length)));
      row.setAttribute("data-layout-allow-overflow", "");
      row.setAttribute("data-layout-allow-occlusion", "");
      row.style.top = 18 + i * 66 + "px";
      row.style.opacity = (0.035 + rnd() * 0.05).toFixed(3);
      const dir = i % 2 ? 1 : -1;
      const x0 = -rnd() * 600;
      const dx = dir * (110 + rnd() * 90) * (DUR / 20);
      if (drift) tl.fromTo(row, { x: x0 }, { x: x0 + dx, duration: DUR, ease: "none" }, 0);
      else tl.set(row, { x: x0 + dx / 2 }, 0);
    }

    // ---------- title / end card elements: data-in reveals, data-out fades ----------
    document.querySelectorAll("[data-in]").forEach((el) => {
      const dy = el.dataset.dy ? parseFloat(el.dataset.dy) : 20;
      tl.fromTo(el, { opacity: 0, y: dy }, { opacity: 1, y: 0, duration: 0.55, ease: "power3.out" }, parseFloat(el.dataset.in));
    });
    document.querySelectorAll("[data-out]").forEach((el) => {
      tl.to(el, { opacity: 0, y: -40, scale: 0.98, duration: 0.45, ease: "power2.in" }, parseFloat(el.dataset.out));
    });

    // ---------- terminal window ----------
    tl.fromTo("#winWrap", { opacity: 0, y: 70, scale: 0.94 }, { opacity: 1, y: 0, scale: 1, duration: 0.75, ease: "power3.out" }, cfg.window.in);
    tl.fromTo("#watermark", { opacity: 0 }, { opacity: 1, duration: 0.6 }, cfg.window.in + 0.4);
    tl.to("#winWrap", { opacity: 0, y: -156, scale: 0.92, duration: 0.45, ease: "power2.in" }, cfg.window.out);
    tl.to("#captions", { opacity: 0, duration: 0.4 }, cfg.window.out);
    tl.to("#watermark", { opacity: 0, duration: 0.4 }, cfg.window.out);

    const screen = document.getElementById("screen");
    const captionsHost = document.getElementById("captions");

    cfg.scenes.forEach((scene) => {
      const cap = CAP[scene.id];
      const demo = make("div", "demo", screen);
      demo.id = "demo-" + scene.id;
      const rowsEl = make("div", "rows", demo);
      rowsEl.style.height = Math.max(20, cap.lines.length) * LH + "px";
      rowsEl.setAttribute("data-layout-allow-overflow", "");
      if (scene.frames.length !== cap.frames.length) {
        throw new Error(`${scene.id}: ${scene.frames.length} frame times for ${cap.frames.length} snapshots`);
      }
      const T = (k) => scene.start + scene.frames[k].at;

      const byFrame = cap.frames.map(() => []);
      cap.lines.forEach((runs, r) => {
        runs.forEach(([t, s, b, c, w]) => {
          const st = cap.styles[s];
          const span = make("span", "run" + (st.b ? " b" : "") + (w === 2 ? " w2" : ""), rowsEl, t);
          span.style.left = c * CW + "px";
          span.style.top = r * LH + "px";
          if (st.fg) span.style.color = st.fg;
          if (st.bg) span.style.background = st.bg;
          byFrame[b].push({ el: span, r, c, len: w === 2 ? 2 : Array.from(t).length });
        });
      });
      const cursor = make("div", "cursor", rowsEl);

      tl.set(demo, { opacity: 1 }, scene.start);
      tl.to(demo, { opacity: 0, duration: 0.3, ease: "power1.in" }, scene.end - 0.3);

      const cursorEvents = [];
      let top = 0;
      const scrollTo = (newTop, t) => {
        if (newTop <= top) return;
        tl.fromTo(rowsEl, { y: -top * LH }, { y: -newTop * LH, duration: 0.12, ease: "power2.out", immediateRender: false }, t);
        top = newTop;
      };

      cap.frames.forEach((frame, k) => {
        const t0 = T(k);
        const cells = byFrame[k].sort((a, b) => a.r - b.r || a.c - b.c);
        if (frame.kind === "type") {
          // typing: [[chars, secondsPerChar], ...]; the last segment applies to the rest.
          const plan = scene.frames[k].typing || [[Infinity, 0.07]];
          let t = t0, seg = 0, used = 0;
          cells.forEach((cell) => {
            tl.set(cell.el, { opacity: 1 }, t);
            if (cell.r - VIEW_ROWS + 1 > top) scrollTo(cell.r - VIEW_ROWS + 1, t);
            const next = cell.c + cell.len >= COLS ? [cell.r + 1, 0] : [cell.r, cell.c + cell.len];
            cursorEvents.push([t, next[0], next[1]]);
            used++;
            if (used >= plan[seg][0] && seg < plan.length - 1) { seg++; used = 0; }
            t += plan[seg][1];
          });
        } else {
          const rows = [...new Set(cells.map((c) => c.r))];
          rows.forEach((r, j) => {
            const t = t0 + j * ROW_STAGGER;
            cells.filter((c) => c.r === r).forEach((c) => tl.set(c.el, { opacity: 1 }, t));
            if (r - VIEW_ROWS + 1 > top) scrollTo(r - VIEW_ROWS + 1, t);
          });
          const tEnd = t0 + Math.max(0, rows.length - 1) * ROW_STAGGER;
          cursorEvents.push([k === 0 ? scene.start : tEnd, frame.cursor[0], frame.cursor[1]]);
        }
      });

      // Cursor: follow events, blink while idle (finite, seek-safe).
      cursorEvents.sort((a, b) => a[0] - b[0]);
      cursorEvents.forEach(([t, r, c], i) => {
        tl.set(cursor, { x: c * CW, y: r * LH, opacity: 1 }, t);
        const next = i + 1 < cursorEvents.length ? cursorEvents[i + 1][0] : scene.end - 0.3;
        for (let b = t + 0.55, on = false; b < next - 0.12; b += 0.5, on = !on) {
          tl.set(cursor, { opacity: on ? 1 : 0 }, b);
        }
      });

      (scene.highlights || []).forEach((h) => {
        const pos = findText(cap, h.text, h.last);
        const box = make("div", "hl", rowsEl);
        const width = Math.max(pos.width, h.minWidth || 0) * CW;
        box.style.left = pos.col * CW - 5 + "px";
        box.style.top = pos.row * LH - 1 + "px";
        box.style.width = width + 10 + "px";
        box.style.height = (h.rows || 1) * LH + 2 + "px";
        tl.fromTo(box, { opacity: 0, scale: 0.97 }, { opacity: 1, scale: 1, duration: 0.3, ease: "power2.out" }, scene.start + h.at);
        tl.to(box, { opacity: 0, duration: 0.25 }, scene.start + h.end);
      });

      const eyebrow = make("div", "cap-eyebrow", captionsHost, scene.eyebrow);
      tl.fromTo(eyebrow, { opacity: 0, y: 10 }, { opacity: 1, y: 0, duration: 0.35, ease: "power2.out" }, scene.start);
      tl.to(eyebrow, { opacity: 0, duration: 0.25 }, scene.end - 0.3);
      scene.captions.forEach((c) => {
        const node = make("div", "cap", captionsHost);
        node.innerHTML = c.html;
        tl.fromTo(node, { opacity: 0, y: 18 }, { opacity: 1, y: 0, duration: 0.35, ease: "power3.out" }, scene.start + c.at);
        tl.to(node, { opacity: 0, y: -10, duration: 0.25, ease: "power1.in" }, scene.start + c.end - 0.25);
      });
    });

    if (cfg.extra) cfg.extra(tl);

    // The page registers `tl` on window.__timelines once `ready` resolves, so the
    // first frame is drawn with the real fonts.
    const faces = [
      '400 26px "JetBrains Mono"', '700 26px "JetBrains Mono"', '500 22px "Inter"', '600 42px "Inter"',
      '700 54px "Inter Display"', '800 118px "Inter Display"', '22px "Noto Color Emoji"',
    ];
    const ready = Promise.all(faces.map((f) => document.fonts.load(f, f.includes("Emoji") ? "🕵🥳" : "Ciphey")))
      .catch(() => {})
      .then(() => document.fonts.ready);
    return { tl, ready };
  }

  window.CipheyClip = { run, captureText };
})();
