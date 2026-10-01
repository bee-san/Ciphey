# Ciphey TUI promo video

A 41-second promo of the Ciphey terminal UI, built with [HyperFrames](https://hyperframes.heygen.com/). Every terminal frame replays a real `ciphey` session recorded in tmux; none of the terminal text was typed into the video by hand.

- `out/ciphey-tui-promo.mp4`: 1920×1080, H.264 (High, yuv420p), 30 fps, 41 s, 7.5 MB
- `out/preview.gif`, `out/poster.jpg`, `out/stills.jpg`: previews for the GitHub issue

## How it is made

1. `capture/capture.py` runs `target/release/ciphey` with a throw-away `$HOME` in an 88×20 tmux pane, types the keystrokes listed in `capture/demos.json`, waits for ciphey's real prompts, and saves a `tmux capture-pane -e` snapshot (colours included) after every step into `capture/out/`. It exits with an error if ciphey panics.
2. `capture/ansi_to_json.mjs` parses the snapshots into a cell grid and records the step at which each cell first appeared, writing `video/captures.js`.
3. `video/index.html` is the HyperFrames composition. One paused GSAP timeline reveals those cells at their recorded step (keystrokes one at a time, output line by line) and adds the title card, captions, highlight boxes and end card.
4. `hyperframes render` seeks the timeline frame by frame in headless Chrome and encodes with FFmpeg. Re-rendering on the same machine produced a byte-identical MP4.

| Demo | Input | What ciphey prints |
| --- | --- | --- |
| Multi-layer decoding | `base64(base64(base64(base64(text))))` | `Ciphey peels back every layer of encoding`, path `Base64 → Base64 → Base64 → Base64` |
| Knows what it found | hex | `flag{ciphey_did_the_hard_part}`, identified by LemmeKnow as a "Capture The Flag (CTF) Flag" |
| First-run setup | the base32 string from `images/first_run.tape` | the setup wizard (GirlyPop theme), then `Wow! That was a cool configuration!` |

The first two demos start with `capture/config-capptucin.toml`, which is the config the wizard writes when you pick Capptucin. The first-run demo starts without a config so the wizard appears.

## Regenerate

Requirements: Rust, tmux (tested with 3.6a), Python 3, Node.js 22 or newer, and `ffmpeg`/`ffprobe` on `PATH`.

```bash
media/tui-video/build.sh                 # build ciphey, re-record, check, render, previews
media/tui-video/build.sh --skip-capture  # reuse capture/out/
```

Step by step, from the repository root:

```bash
cargo build --release
python3 media/tui-video/capture/capture.py      # writes capture/out/
node media/tui-video/capture/ansi_to_json.mjs   # writes video/captures.js
cd media/tui-video/video
npx --yes hyperframes@0.8.103 preview           # live preview in the browser
npx --yes hyperframes@0.8.103 check
npx --yes hyperframes@0.8.103 render --crf 20 --output ../out/ciphey-tui-promo.mp4
```

To change the story, edit `SCENES` in `video/index.html` (timings, captions, highlights) or the steps in `capture/demos.json`.

## Pinned versions

- HyperFrames CLI 0.8.103, using the Chrome build it pins (`npx hyperframes browser ensure`); GSAP 3.14.2 from jsDelivr
- Fonts in `video/assets/fonts`: JetBrains Mono 2.304, Inter 4.1, and a subset of Noto Color Emoji 2.051 containing only the emoji ciphey prints. All are SIL OFL 1.1; the licence files are next to the fonts.
- Rendered with FFmpeg 8.1.3; any recent FFmpeg should work.

Many other inputs, including the strings in the README demos, currently crash ciphey in `src/decoders/vigenere_decoder.rs` (#908, fix proposed in #911), so the demos use inputs that avoid it.
