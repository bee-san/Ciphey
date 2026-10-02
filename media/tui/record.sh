#!/usr/bin/env bash
# Records the terminal UI GIF in this folder from a real ciphey run.
#
#   media/tui/record.sh            build ciphey, record ciphey-tui.cast, render ciphey-tui.gif
#   media/tui/record.sh --render   only render ciphey-tui.gif from the committed cast
#
# A detached 80x18 tmux pane runs asciinema, which records an interactive bash. The
# script types the command into it one key at a time (the ciphertext is pasted in one
# go, as you would), waits for ciphey's real question, leaves it on screen for a few
# seconds, answers y and waits for the result. Nothing is drawn by hand: the GIF is
# what ciphey printed, with its real timing.
#
# The input is the README's sentence under four layers, innermost first:
# hex, Base64, Base32, Base64. It was picked because ciphey's first question about
# it is the right answer, after a search long enough to watch.
#
# Needs Linux on x86_64, tmux, curl, unzip, sha256sum and python3. The pinned tools
# are downloaded into target/media-tools and checked against the checksums below:
#   asciinema 3.2.1 and agg 1.9.0, the static musl builds from github.com/asciinema
#   JetBrains Mono 2.304 (SIL OFL 1.1), the font the README videos use
# The colours are Catppuccin Mocha, the palette of the README videos. The default
# ciphey colour scheme uses the terminal's own colours, so these are what it shows.
set -euo pipefail

ASCIINEMA_URL=https://github.com/asciinema/asciinema/releases/download/v3.2.1/asciinema-x86_64-unknown-linux-musl
ASCIINEMA_SHA256=bec9781bc8f297a9d3d74ff60205599507f2abba1183578b8b2f22be4c999214
AGG_URL=https://github.com/asciinema/agg/releases/download/v1.9.0/agg-x86_64-unknown-linux-musl
AGG_SHA256=ddcbf6ca044c8ac3a434dcb9ee89fb9e3be87209982b7c2adb55f782e8f0f390
FONT_URL=https://github.com/JetBrains/JetBrainsMono/releases/download/v2.304/JetBrainsMono-2.304.zip
FONT_SHA256=6f6376c6ed2960ea8a963cd7387ec9d76e3f629125bc33d1fdcd7eb7012f7bbf
# Background, foreground, then the 16 terminal colours
THEME=1e1e2e,cdd6f4,45475a,f38ba8,a6e3a1,f9e2af,89b4fa,f5c2e7,94e2d5,bac2de,585b70,f38ba8,a6e3a1,f9e2af,89b4fa,f5c2e7,94e2d5,a6adc8

COLS=80
ROWS=18
PLAINTEXT='Ciphey peels back every layer of encoding'
SECRET='SlpDRTJNU1BLUlJYT1RUS000WkU0VkRER1ZHV1VRSlRKVkNGU01LT05KS1RFV0wyTU41RTIyU0JHSkdXVVdMWUpaVkUyTVNaTkpFWE9UVEtLVVpVNDJTWkdGSEhVU0pUSjVLRVM1Mk9OVkdURVRLVU1NMlU0MlNWR05HV1VTTFhKWldWU01TT05KRVhPVFRLS1VaRlVWQ1pQSkhHMldKU0paQ0ZTTktPTlZLVEVUVFhIVTZRPT09PQ=='

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd "$here/../.." && pwd)
tools=$repo/target/media-tools
cast=$here/ciphey-tui.cast
gif=$here/ciphey-tui.gif

# Downloads $1 to $2 unless it is already there, and checks it against $3
fetch() {
  if [ ! -f "$2" ]; then
    curl -sSfL -o "$2.part" "$1"
    mv "$2.part" "$2"
  fi
  if ! echo "$3  $2" | sha256sum -c --quiet -; then
    echo "checksum mismatch for $2, delete it and try again" >&2
    exit 1
  fi
}

mkdir -p "$tools/fonts"
fetch "$AGG_URL" "$tools/agg" "$AGG_SHA256"
fetch "$FONT_URL" "$tools/JetBrainsMono-2.304.zip" "$FONT_SHA256"
chmod +x "$tools/agg"
unzip -o -q -j "$tools/JetBrainsMono-2.304.zip" \
  fonts/ttf/JetBrainsMono-Regular.ttf fonts/ttf/JetBrainsMono-Bold.ttf -d "$tools/fonts"

if [ "${1:-}" != "--render" ]; then
  fetch "$ASCIINEMA_URL" "$tools/asciinema" "$ASCIINEMA_SHA256"
  chmod +x "$tools/asciinema"

  # The input really is the sentence under those four layers
  python3 - "$SECRET" "$PLAINTEXT" <<'EOF'
import base64, sys
secret, plaintext = sys.argv[1:]
layer = plaintext.encode().hex()
for encode in (base64.b64encode, base64.b32encode, base64.b64encode):
    layer = encode(layer.encode()).decode()
assert layer == secret, "SECRET is not hex -> Base64 -> Base32 -> Base64 of PLAINTEXT"
EOF

  (cd "$repo" && cargo build --release --quiet)

  work=$(mktemp -d)
  sock=$work/tmux.sock
  # Kills every descendant of $1, deepest first
  kill_tree() {
    local child
    for child in $(pgrep -P "$1"); do
      kill_tree "$child"
      kill -KILL "$child" 2>/dev/null || true
    done
  }
  # Whatever happens, nothing started for the recording is left running
  cleanup() {
    local pane_pid
    pane_pid=$(tmux -S "$sock" display-message -p -t rec '#{pane_pid}' 2>/dev/null || true)
    if [ -n "$pane_pid" ]; then
      kill_tree "$pane_pid"
    fi
    tmux -S "$sock" kill-server 2>/dev/null || true
    rm -rf "$work"
  }
  trap cleanup EXIT

  # A fresh home: an empty config (the default colour scheme) and no cache
  mkdir -p "$work/home/.ciphey" "$work/bin"
  : > "$work/home/.ciphey/config.toml"
  # `ciphey` on the recorded shell's PATH, so no run can outlive the recording
  printf '#!/bin/sh\nexec timeout --foreground -k 5 120 %q "$@"\n' "$repo/target/release/ciphey" \
    > "$work/bin/ciphey"
  chmod +x "$work/bin/ciphey"

  pane() { tmux -S "$sock" "$@"; }
  # Types $1 one key at a time
  type_keys() {
    local i
    for ((i = 0; i < ${#1}; i++)); do
      pane send-keys -t rec -l -- "${1:i:1}"
      sleep 0.08
    done
  }
  # Waits until the pane shows $1
  wait_for() {
    local deadline=$((SECONDS + 60))
    until pane capture-pane -p -t rec | grep -qF -- "$1"; do
      if ((SECONDS > deadline)); then
        echo "timed out waiting for: $1" >&2
        pane capture-pane -p -t rec >&2
        exit 1
      fi
      sleep 0.05
    done
  }

  rm -f "$cast"
  # asciinema drops PS1 from the environment, so the prompt comes from an rc file
  printf "PS1='\$ '\n" > "$work/.bashrc"
  pane -f /dev/null new-session -d -s rec -x "$COLS" -y "$ROWS" -c "$work" \
    env -i HOME="$work/home" PATH="$work/bin:/usr/bin:/bin" TERM=xterm-256color \
    LANG=C.UTF-8 \
    "$tools/asciinema" rec --quiet --capture-env TERM --window-size "${COLS}x${ROWS}" \
    --command 'bash --noprofile --rcfile .bashrc' "$cast"
  pane set-option -t rec status off > /dev/null
  wait_for '$'
  sleep 1

  type_keys "ciphey -t '"
  sleep 0.3
  pane send-keys -t rec -l -- "$SECRET"
  sleep 0.5
  type_keys "'"
  sleep 0.6
  pane send-keys -t rec Enter

  wait_for 'Is this the plaintext?'
  if ! pane capture-pane -p -t rec | grep -qF -- "$PLAINTEXT"; then
    echo "ciphey asked about a different candidate first; run the script again" >&2
    pane capture-pane -p -t rec >&2
    exit 1
  fi
  # Long enough to read the question
  sleep 3
  pane send-keys -t rec -l y
  wait_for 'Searched'
  sleep 1
  # ciphey has exited; closing the pane ends the recording (asciinema writes every
  # event as it happens, so nothing is lost)
  pane kill-server
fi

# The last frame stays up for 6 seconds before the GIF loops
"$tools/agg" --quiet --theme "$THEME" --font-dir "$tools/fonts" --font-family 'JetBrains Mono' \
  --font-size 20 --line-height 1.35 --idle-time-limit 3 --last-frame-duration 6 \
  "$cast" "$gif"
echo "wrote $gif ($(du -k "$gif" | cut -f1) KB)"
