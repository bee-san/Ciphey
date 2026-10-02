#!/usr/bin/env bash
# Renders the before/after screenshots in media/tui/screenshots from real runs.
#
#   media/tui/screenshots.sh BEFORE_BINARY
#
# BEFORE_BINARY is a `ciphey` built from master before the terminal UI redesign, for
# the before-* shots. The after-* shots use target/release/ciphey, built here.
#
# Each shot records one run with asciinema in a detached tmux pane, presses keys the
# way a user would and renders one frame with agg: the same pinned tools, font and
# colours as record.sh, which downloads them into target/media-tools. Every ciphey
# runs under `timeout -k`, and everything left in the pane is killed afterwards.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd "$here/../.." && pwd)
tools=$repo/target/media-tools
out=$here/screenshots
old=$(realpath "${1:?usage: media/tui/screenshots.sh BEFORE_BINARY}")
new=$repo/target/release/ciphey
THEME=1e1e2e,cdd6f4,45475a,f38ba8,a6e3a1,f9e2af,89b4fa,f5c2e7,94e2d5,bac2de,585b70,f38ba8,a6e3a1,f9e2af,89b4fa,f5c2e7,94e2d5,a6adc8

if [ ! -x "$tools/agg" ] || [ ! -x "$tools/asciinema" ]; then
  echo "run media/tui/record.sh first: it downloads and checks the pinned tools" >&2
  exit 1
fi
command -v convert > /dev/null || { echo "needs ImageMagick (convert)" >&2; exit 1; }
(cd "$repo" && cargo build --release --quiet)
mkdir -p "$out"

# Kills every descendant of $1, deepest first
kill_tree() {
  local child
  for child in $(pgrep -P "$1"); do
    kill_tree "$child"
    kill -KILL "$child" 2> /dev/null || true
  done
}

# shot NAME BINARY ROWS ARGS KEYS UNTIL [AT]
# Runs `ciphey ARGS` in an 80xROWS terminal, presses each of KEYS 2.5 s apart, waits
# until the screen shows UNTIL and renders the last frame, or the one at AT seconds.
shot() {
  local name=$1 bin=$2 rows=$3 args=$4 keys=$5 until=$6 at=${7:-}
  local work sock pane_pid key cast deadline
  work=$(mktemp -d)
  sock=$work/tmux.sock
  cast=$work/$name.cast
  mkdir -p "$work/home/.ciphey" "$work/bin" "$work/frames"
  : > "$work/home/.ciphey/config.toml"
  printf '#!/bin/sh\nexec timeout --foreground -k 3 60 %q "$@"\n' "$bin" > "$work/bin/ciphey"
  chmod +x "$work/bin/ciphey"
  printf "PS1='\$ '\n" > "$work/.bashrc"
  tmux -S "$sock" -f /dev/null new-session -d -s s -x 80 -y "$rows" -c "$work" \
    env -i HOME="$work/home" PATH="$work/bin:/usr/bin:/bin" TERM=xterm-256color LANG=C.UTF-8 \
    "$tools/asciinema" rec --quiet --window-size "80x$rows" \
    --command 'bash --noprofile --rcfile .bashrc' "$cast"
  sleep 0.8
  tmux -S "$sock" send-keys -t s -l -- "ciphey $args"
  tmux -S "$sock" send-keys -t s Enter
  for key in $keys; do
    sleep 2.5
    tmux -S "$sock" send-keys -t s "$key"
  done
  deadline=$((SECONDS + 40))
  until tmux -S "$sock" capture-pane -p -t s | grep -qF -- "$until"; do
    if ((SECONDS > deadline)); then
      echo "$name: timed out waiting for: $until" >&2
      break
    fi
    sleep 0.1
  done
  sleep 0.6
  pane_pid=$(tmux -S "$sock" display-message -p -t s '#{pane_pid}' 2> /dev/null || true)
  if [ -n "$pane_pid" ]; then
    kill_tree "$pane_pid"
  fi
  tmux -S "$sock" kill-server 2> /dev/null || true

  local select=()
  if [ -n "$at" ]; then
    select=(--select "$at")
  fi
  "$tools/agg" --quiet --theme "$THEME" --font-dir "$tools/fonts" --font-family 'JetBrains Mono' \
    --font-size 18 --line-height 1.35 --idle-time-limit 2 --last-frame-duration 1 "${select[@]}" \
    "$cast" "$work/$name.gif"
  convert "$work/$name.gif" -coalesce "$work/frames/%03d.png"
  cp "$(ls "$work"/frames/*.png | tail -1)" "$out/$name.png"
  rm -rf "$work"
  echo "wrote $out/$name.png"
}

three='NTA3NjYzNzU3MjZjMjA3NjY2MjA2OTcyNjU2YzIwNzM2ZTY2Njc='
# A plaintext found three layers down, the question answered y
shot before-success "$old" 14 "-t '$three'" "y Enter" 'the decoders used are'
shot after-success "$new" 14 "-t '$three'" "y" 'Searched'
# A crib that nothing matches, so the 3 s time limit runs out
shot before-failure "$old" 12 "-c 3 -r '^xyz' -t 'aGVsbG8gd29ybGQ='" "" 'Timed out after'
shot after-failure "$new" 14 "-c 3 -r '^xyz' -t 'aGVsbG8gd29ybGQ='" "" 'discord.skerritt.blog'
# What the search looks like while it runs (the old output shows nothing), and with ?
shot after-searching "$new" 9 "-d -c 6 -r '^xyz' -t 'aGVsbG8gd29ybGQ='" "" 'discord.skerritt.blog' 2.5
shot after-help "$new" 16 "-d -c 6 -r '^xyz' -t 'aGVsbG8gd29ybGQ='" "?" 'discord.skerritt.blog' 4
