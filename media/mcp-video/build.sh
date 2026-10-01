#!/usr/bin/env bash
# Rebuild the ciphey-mcp video:
#   1. build ciphey-mcp, 2. record a scripted JSON-RPC session with it (and, with --kiro, a new
#   Kiro CLI session), 3. turn the recordings into video/session.js, 4. check + render with
#   HyperFrames, 5. make the GIF and JPEG previews.
#
# Needs: Rust toolchain, python3, Node.js >= 22, ffmpeg + ffprobe on PATH; kiro-cli (logged in)
# only for --kiro.
# Usage: media/mcp-video/build.sh [--skip-capture] [--kiro]
#   --skip-capture   reuse capture/out/ (no cargo build, no new recordings)
#   --kiro           also re-record the Kiro CLI session. Its reply is written by a language
#                    model, so the chat in the video will be worded differently.
#   OUT_DIR=...      write the MP4 and previews somewhere other than media/mcp-video/out
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
HF="hyperframes@0.8.103"
OUT="${OUT_DIR:-$HERE/out}"
BIN="$ROOT/target/release/ciphey-mcp"
# Anonymous HyperFrames usage telemetry is off unless you opt back in.
export HYPERFRAMES_NO_TELEMETRY="${HYPERFRAMES_NO_TELEMETRY:-1}"
export PYTHONDONTWRITEBYTECODE=1

CAPTURE=1 KIRO=0
for arg in "$@"; do
  case "$arg" in
    --skip-capture) CAPTURE=0 ;;
    --kiro) KIRO=1 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

if [[ $CAPTURE == 1 ]]; then
  (cd "$ROOT" && cargo build --release --features mcp --bin ciphey-mcp)
  python3 "$HERE/capture/mcp_session.py" --bin "$BIN"
  if [[ $KIRO == 1 ]]; then "$HERE/capture/kiro_session.sh" "$BIN"; fi
fi
python3 "$HERE/capture/to_session_js.py"

mkdir -p "$OUT"
npx --yes "$HF" browser ensure
TMPV="$(mktemp -d)"
trap 'rm -rf "$TMPV"' EXIT

mp4="$OUT/ciphey-mcp.mp4"
(cd "$HERE/video" && npx --yes "$HF" check && npx --yes "$HF" render --crf 20 --output "$mp4")
# The GIF comes from a second render with the faint background rows frozen (bgDrift=false):
# drifting rows change every pixel of every frame and make the GIF several times larger.
(cd "$HERE/video" && npx --yes "$HF" render --crf 18 --strict-variables --variables '{"bgDrift":false}' --output "$TMPV/still.mp4")

# GIF: the chat scene, cropped to the window and captions and scaled to 60 %. It starts at
# 10.7 s, once the question and its caption are fully in, because GitHub shows the first frame
# as the still preview when animated images don't autoplay; it ends as the chat exits (24.0 s).
ffmpeg -v error -y -ss 10.7 -t 13.3 -i "$TMPV/still.mp4" \
  -vf "crop=1600:900:160:30,fps=10,scale=960:-1:flags=lanczos,split[a][b];[a]palettegen=max_colors=128:stats_mode=diff[p];[b][p]paletteuse=dither=none:diff_mode=rectangle" \
  -loop 0 "$OUT/ciphey-mcp.gif"
# Poster: the tool result, with the plaintext and the decoder path highlighted.
ffmpeg -v error -y -ss 16.5 -i "$mp4" -frames:v 1 -q:v 3 "$OUT/ciphey-mcp-poster.jpg"
# 2x2 contact sheet: setup, tool result, reply, end card.
ffmpeg -v error -y -ss 8.2 -i "$mp4" -ss 16.5 -i "$mp4" -ss 22.5 -i "$mp4" -ss 27.5 -i "$mp4" \
  -filter_complex "[0]scale=960:540[a];[1]scale=960:540[b];[2]scale=960:540[c];[3]scale=960:540[d];[a][b]hstack[t];[c][d]hstack[u];[t][u]vstack" \
  -frames:v 1 -q:v 3 "$OUT/ciphey-mcp-stills.jpg"

ffprobe -v error -show_entries format=duration,size:stream=codec_name,profile,pix_fmt,width,height,r_frame_rate -of compact "$mp4"
ls -l "$OUT"
