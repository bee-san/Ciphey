#!/usr/bin/env bash
# Rebuild every README video from scratch:
#   1. build ciphey, 2. record real sessions in tmux, 3. convert them for the compositions,
#   4. check + render with HyperFrames, 5. make the GIF/JPEG previews the README embeds.
#
# Needs: Rust toolchain, tmux >= 3.2, python3, Node.js >= 22, ffmpeg + ffprobe on PATH.
# Usage: media/tui-video/build.sh [--skip-capture] [--bench] [promo|fast|lemmeknow|crib ...]
#   --skip-capture   reuse capture/out/ instead of re-recording the tmux sessions
#   --bench          re-run bench/bench_compare.py (needs Python Ciphey 5.14.0, see that file);
#                    otherwise the Fast clip uses the numbers already in bench/results.json
#   names            render only these videos (default: all four)
#   OUT_DIR=...      write the MP4s and previews somewhere other than media/tui-video/out
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
HF="hyperframes@0.8.103"
OUT="${OUT_DIR:-$HERE/out}"
# Anonymous HyperFrames usage telemetry is off unless you opt back in.
export HYPERFRAMES_NO_TELEMETRY="${HYPERFRAMES_NO_TELEMETRY:-1}"

CAPTURE=1 BENCH=0 NAMES=()
for arg in "$@"; do
  case "$arg" in
    --skip-capture) CAPTURE=0 ;;
    --bench) BENCH=1 ;;
    promo|fast|lemmeknow|crib) NAMES+=("$arg") ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done
[[ ${#NAMES[@]} -gt 0 ]] || NAMES=(promo fast lemmeknow crib)

if [[ $CAPTURE == 1 ]]; then
  (cd "$ROOT" && cargo build --release)
  python3 "$HERE/capture/capture.py" --bin "$ROOT/target/release/ciphey"
fi
if [[ $BENCH == 1 ]]; then
  RUST_CIPHEY="$ROOT/target/release/ciphey" python3 "$HERE/bench/bench_compare.py"
else
  python3 "$HERE/bench/bench_compare.py" --js-only
fi
node "$HERE/capture/ansi_to_json.mjs"
"$HERE/clips/sync.sh"

mkdir -p "$OUT"
npx --yes "$HF" browser ensure

# GIF previews come from a second render with the faint background rows frozen
# (bgDrift=false): drifting rows change every pixel and make the GIFs ~4x larger.
# They crop to the terminal window and captions (by default 1600x880 from 160,140, scaled to
# 800 px, i.e. half size) so the terminal text stays readable.
TMPV="$(mktemp -d)"
trap 'rm -rf "$TMPV"' EXIT
gif() { # mp4 start duration fps out.gif [crop] [width]
  ffmpeg -v error -y -ss "$2" -t "$3" -i "$1" \
    -vf "crop=${6:-1600:880:160:140},fps=$4,scale=${7:-800}:-1:flags=lanczos,split[a][b];[a]palettegen=max_colors=128:stats_mode=diff[p];[b][p]paletteuse=dither=none:diff_mode=rectangle" \
    -loop 0 "$5"
}
poster() { # mp4 time out.jpg
  ffmpeg -v error -y -ss "$2" -i "$1" -frames:v 1 -q:v 3 "$3"
}
stills() { # mp4 t1 t2 t3 t4 out.jpg  (2x2 contact sheet)
  ffmpeg -v error -y -ss "$2" -i "$1" -ss "$3" -i "$1" -ss "$4" -i "$1" -ss "$5" -i "$1" \
    -filter_complex "[0]scale=960:540[a];[1]scale=960:540[b];[2]scale=960:540[c];[3]scale=960:540[d];[a][b]hstack[t];[c][d]hstack[u];[t][u]vstack" \
    -frames:v 1 -q:v 3 "$6"
}
render() { # project-dir mp4 crf
  (cd "$1" && npx --yes "$HF" check && npx --yes "$HF" render --crf "$3" --output "$2")
}
still() { # project-dir mp4
  (cd "$1" && npx --yes "$HF" render --crf 18 --strict-variables --variables '{"bgDrift":false}' --output "$2")
}

for name in "${NAMES[@]}"; do
  case "$name" in
    promo) # 61.5 s: the original 41 s promo at 1.5x the pace (see PACE in video/index.html)
      mp4="$OUT/ciphey-tui-promo.mp4"
      render "$HERE/video" "$mp4" 22
      still "$HERE/video" "$TMPV/promo.mp4"
      # multi-layer decoding scene; wider crop because one caption is 1660 px wide
      gif "$TMPV/promo.mp4" 7.0 13.8 10 "$OUT/preview.gif" 1760:880:80:140 880
      poster "$mp4" 18.5 "$OUT/poster.jpg"
      stills "$mp4" 18.5 26.5 39.0 59.0 "$OUT/stills.jpg" ;;
    fast)
      mp4="$OUT/fast.mp4"
      render "$HERE/clips/fast" "$mp4" 20
      still "$HERE/clips/fast" "$TMPV/fast.mp4"
      gif "$TMPV/fast.mp4" 2.6 13.4 10 "$OUT/fast.gif"       # timed run + Rust vs Python bars
      poster "$mp4" 6.6 "$OUT/fast-poster.jpg"
      stills "$mp4" 1.2 6.6 9.8 15.5 "$OUT/fast-stills.jpg" ;;
    lemmeknow)
      mp4="$OUT/lemmeknow.mp4"
      render "$HERE/clips/lemmeknow" "$mp4" 20
      still "$HERE/clips/lemmeknow" "$TMPV/lemmeknow.mp4"
      gif "$TMPV/lemmeknow.mp4" 2.0 15.6 10 "$OUT/lemmeknow.gif"  # all three identifications
      poster "$mp4" 5.2 "$OUT/lemmeknow-poster.jpg"
      stills "$mp4" 5.2 13.6 17.4 20.4 "$OUT/lemmeknow-stills.jpg" ;;
    crib)
      mp4="$OUT/crib.mp4"
      render "$HERE/clips/crib" "$mp4" 20
      still "$HERE/clips/crib" "$TMPV/crib.mp4"
      gif "$TMPV/crib.mp4" 2.0 8.6 10 "$OUT/crib.gif"
      poster "$mp4" 9.5 "$OUT/crib-poster.jpg"
      stills "$mp4" 1.0 6.2 9.5 13.0 "$OUT/crib-stills.jpg" ;;
  esac
  ffprobe -v error -show_entries format=duration,size:stream=codec_name,width,height,r_frame_rate -of compact "$mp4"
done
ls -l "$OUT"
