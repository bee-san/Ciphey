#!/usr/bin/env bash
# Rebuild the Ciphey TUI promo video from scratch:
#   1. build ciphey, 2. record real sessions in tmux, 3. convert them for the composition,
#   4. check + render with HyperFrames, 5. make the GIF/JPEG previews used in the GitHub issue.
#
# Needs: Rust toolchain, tmux >= 3.2, python3, Node.js >= 22, ffmpeg + ffprobe on PATH.
# Usage: media/tui-video/build.sh [--skip-capture]
#   --skip-capture   reuse capture/out/ instead of re-recording the tmux sessions
#   OUT_DIR=...      write the MP4 and previews somewhere other than media/tui-video/out
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
HF="hyperframes@0.8.103"
OUT="${OUT_DIR:-$HERE/out}"
MP4="$OUT/ciphey-tui-promo.mp4"
# Anonymous HyperFrames usage telemetry is off unless you opt back in.
export HYPERFRAMES_NO_TELEMETRY="${HYPERFRAMES_NO_TELEMETRY:-1}"

if [[ "${1:-}" != "--skip-capture" ]]; then
  (cd "$ROOT" && cargo build --release)
  python3 "$HERE/capture/capture.py" --bin "$ROOT/target/release/ciphey"
fi
node "$HERE/capture/ansi_to_json.mjs"

mkdir -p "$OUT"
cd "$HERE/video"
npx --yes "$HF" browser ensure
npx --yes "$HF" check
npx --yes "$HF" render --crf 20 --output "$MP4"

# Inline previews: GIF excerpt (title -> demo 1), poster frame, 2x2 stills.
ffmpeg -v error -y -ss 2.4 -t 11.5 -i "$MP4" \
  -vf "fps=10,scale=800:-1:flags=lanczos,split[a][b];[a]palettegen=max_colors=128:stats_mode=full[p];[b][p]paletteuse=dither=none:diff_mode=rectangle" \
  -loop 0 "$OUT/preview.gif"
ffmpeg -v error -y -ss 12.5 -i "$MP4" -frames:v 1 -q:v 3 "$OUT/poster.jpg"
ffmpeg -v error -y -ss 12.5 -i "$MP4" -ss 17.5 -i "$MP4" -ss 26.6 -i "$MP4" -ss 40.9 -i "$MP4" \
  -filter_complex "[0]scale=960:540[a];[1]scale=960:540[b];[2]scale=960:540[c];[3]scale=960:540[d];[a][b]hstack[t];[c][d]hstack[u];[t][u]vstack" \
  -frames:v 1 -q:v 3 "$OUT/stills.jpg"

ffprobe -v error -show_entries format=duration,size:stream=codec_name,width,height,r_frame_rate -of compact "$MP4"
ls -l "$OUT"
