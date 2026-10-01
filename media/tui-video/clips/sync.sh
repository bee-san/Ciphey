#!/usr/bin/env bash
# Copy the files the clip projects share into each of them (the copies are gitignored).
# Sources of truth: ../video/assets/fonts, ../video/captures.js, ../video/bench.js, shared/.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
for clip in fast lemmeknow crib; do
  dst="$HERE/$clip"
  rm -rf "$dst/assets"
  mkdir -p "$dst/assets"
  cp -R "$HERE/../video/assets/fonts" "$dst/assets/fonts"
  cp "$HERE/../video/captures.js" "$HERE/../video/bench.js" "$HERE/shared/clip-engine.js" "$HERE/shared/clip.css" "$dst/"
done
echo "synced shared files into: fast lemmeknow crib"
