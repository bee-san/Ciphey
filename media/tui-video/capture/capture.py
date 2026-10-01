#!/usr/bin/env python3
"""Drive the real `ciphey` binary inside tmux and record what the terminal shows.

For every demo in demos.json this script:
  1. creates a throw-away $HOME (optionally seeded with a config.toml),
  2. starts bash in a fixed-size tmux pane (COLS x ROWS),
  3. types the scripted keystrokes, waiting for ciphey's real prompts,
  4. after each step saves `tmux capture-pane -e` output (ANSI colours included,
     full scrollback) plus cursor/scroll position.

The snapshots in out/<demo>/ are the single source of truth for the video:
ansi_to_json.mjs turns them into captures.js, which the HyperFrames
composition replays. Nothing in the video's terminal is typed by hand.

Usage:  python3 capture.py [--bin path/to/ciphey] [demo ...]
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SOCK = "ciphey-video-capture"
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def tmux(*args, check=True):
    cmd = ["tmux", "-u", "-L", SOCK, "-f", os.path.join(HERE, "tmux.conf"), *args]
    res = subprocess.run(cmd, check=check, capture_output=True, text=True)
    return res.stdout


def pane_state(target):
    fmt = "#{history_size} #{cursor_x} #{cursor_y} #{pane_width} #{pane_height}"
    hist, cx, cy, w, h = map(int, tmux("display-message", "-p", "-t", target, fmt).split())
    return {"history": hist, "cursor_x": cx, "cursor_y": cy, "cols": w, "rows": h}


def capture(target, escapes=True):
    args = ["capture-pane", "-p", "-S", "-", "-E", "-", "-t", target]
    if escapes:
        args.insert(2, "-e")
    return tmux(*args)


def last_line(text):
    lines = [ln for ln in text.splitlines() if ln.strip()]
    return lines[-1] if lines else ""


def wait_settled(target, pattern=None, timeout=20.0, settle=0.6):
    """Wait until the last non-empty line matches `pattern` and the pane stops changing."""
    deadline = time.monotonic() + timeout
    rx = re.compile(pattern) if pattern else None
    last, last_change = None, time.monotonic()
    while time.monotonic() < deadline:
        text = capture(target, escapes=False)
        if text != last:
            last, last_change = text, time.monotonic()
        matched = rx is None or rx.search(last_line(text))
        if matched and time.monotonic() - last_change >= settle:
            return text
        time.sleep(0.05)
    raise TimeoutError(f"timed out waiting for {pattern!r}; last screen:\n{last}")


def run_demo(name, demo, ciphey_bin, out_root, cols, rows):
    out_dir = os.path.join(out_root, name)
    shutil.rmtree(out_dir, ignore_errors=True)
    os.makedirs(out_dir)

    work = tempfile.mkdtemp(prefix=f"ciphey-{name}-")
    home = os.path.join(work, "home")
    bindir = os.path.join(work, "bin")
    os.makedirs(os.path.join(home, ".ciphey"))
    os.makedirs(bindir)
    # `ciphey` on the session's PATH is the real binary capped at 60 s, so a run that never
    # finishes can't outlive the capture. --foreground keeps the y/N prompts readable from the
    # tmux pane; the wrapper adds a few milliseconds to the `time` shown in the Fast clip.
    wrapper = os.path.join(bindir, "ciphey")
    with open(wrapper, "w", encoding="utf-8") as fh:
        fh.write(f"#!/bin/sh\nexec timeout --foreground 60 '{os.path.abspath(ciphey_bin)}' \"$@\"\n")
    os.chmod(wrapper, 0o755)
    if demo.get("config"):
        shutil.copy(os.path.join(HERE, demo["config"]), os.path.join(home, ".ciphey", "config.toml"))
    else:
        os.rmdir(os.path.join(home, ".ciphey"))  # truly fresh: triggers first-run wizard

    ps1 = demo.get("ps1", r"\[\e[1;38;2;166;227;161m\]❯\[\e[0m\] ")
    env = [
        "env", "-i", f"HOME={home}", f"PATH={bindir}:/usr/bin:/bin",
        "TERM=tmux-256color", "LANG=C.UTF-8", "LC_ALL=C.UTF-8", f"PS1={ps1}",
        "bash", "--norc", "--noprofile",
    ]
    session = f"demo-{name}"
    tmux("kill-session", "-t", session, check=False)
    tmux("new-session", "-d", "-s", session, "-x", str(cols), "-y", str(rows), "--", *env)
    target = f"{session}:0.0"
    tmux("pipe-pane", "-t", target, "-o", f"cat >> {os.path.join(out_dir, 'raw.log')}")

    frames = []
    t0 = time.monotonic()

    def snap(kind, label, extra=None):
        idx = len(frames)
        path = os.path.join(out_dir, f"{idx:02d}.ansi")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(capture(target))
        state = pane_state(target)
        frame = {"index": idx, "kind": kind, "label": label, "file": os.path.basename(path),
                 "elapsed": round(time.monotonic() - t0, 3), **state}
        if extra:
            frame.update(extra)
        frames.append(frame)

    wait_settled(target, r"^❯\s*$")
    snap("output", "shell prompt")
    for step in demo["steps"]:
        if step.get("type"):
            tmux("send-keys", "-t", target, "-l", step["type"])
            wait_settled(target, settle=0.3)
            snap("type", step.get("label", "type"), {"typed": step["type"]})
        if step.get("enter", True):
            tmux("send-keys", "-t", target, "Enter")
            wait_settled(target, step.get("expect"), timeout=step.get("timeout", 20))
            snap("output", step.get("label", "output"))

    with open(os.path.join(out_dir, "frames.json"), "w", encoding="utf-8") as fh:
        json.dump({"demo": name, "cols": cols, "rows": rows, "title": demo.get("title", name),
                   "frames": frames}, fh, indent=1, ensure_ascii=False)
    plain = ANSI_RE.sub("", capture(target)).rstrip() + "\n"
    with open(os.path.join(out_dir, "final.txt"), "w", encoding="utf-8") as fh:
        fh.write(plain)
    tmux("kill-session", "-t", session, check=False)
    shutil.rmtree(work, ignore_errors=True)
    if "panicked" in plain:
        raise RuntimeError(f"{name}: ciphey panicked during capture; see {out_dir}/final.txt")
    print(f"[{name}] {len(frames)} snapshots -> {out_dir}")
    return plain


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", default=os.path.join(HERE, "../../../target/release/ciphey"))
    ap.add_argument("--demos", default=os.path.join(HERE, "demos.json"))
    ap.add_argument("--out", default=os.path.join(HERE, "out"))
    ap.add_argument("names", nargs="*")
    args = ap.parse_args()
    if not os.access(args.bin, os.X_OK):
        sys.exit(f"ciphey binary not found at {args.bin}; run `cargo build --release` first")
    spec = json.load(open(args.demos, encoding="utf-8"))
    names = args.names or list(spec["demos"].keys())
    try:
        for name in names:
            print(run_demo(name, spec["demos"][name], args.bin, args.out, spec["cols"], spec["rows"]))
    finally:
        tmux("kill-server", check=False)


if __name__ == "__main__":
    main()
