# Ciphey README videos

The videos in Ciphey's README, built with [HyperFrames](https://hyperframes.heygen.com/). Every terminal frame replays a real `ciphey` session recorded in tmux. No terminal text was typed into a video by hand, and the timings come from real runs.

| File | Length | What it shows |
| --- | --- | --- |
| `out/ciphey-tui-promo.mp4` | 61.5 s | The TUI tour from #919 at 1.5× the original pace: multi-layer decoding, LemmeKnow identifying a CTF flag, the first-run setup |
| `out/fast.mp4` | 16 s | `time ciphey -d -t …` on ROT13 → hex → Base64, then the measured comparison with Python Ciphey |
| `out/lemmeknow.mp4` | 21 s | Base64 and hex that decode to a password in a `mount` command, a TOTP secret and an IPv4 address, each named by LemmeKnow |
| `out/crib.mp4` | 14.5 s | `-r 'picoCTF\{'` pulling a picoCTF flag out of Base64 |

All are 1920×1080 H.264 (High, yuv420p), 30 fps, between 2.8 and 7.3 MB. Each has a looping GIF preview (`preview.gif` for the promo, `<name>.gif` for the others), a poster frame (`poster.jpg` / `<name>-poster.jpg`) and a 2×2 contact sheet (`stills.jpg` / `<name>-stills.jpg`).

## How it's made

1. `capture/capture.py` runs `target/release/ciphey` with a throw-away `$HOME` in an 88×20 tmux pane, types the keystrokes listed in `capture/demos.json`, waits for ciphey's real prompts and saves a `tmux capture-pane -e` snapshot (colours included) after every step into `capture/out/`. `ciphey` on that pane's `PATH` is the real binary behind `timeout --foreground 60`, so no run can outlive the capture. The script exits with an error if ciphey panics.
2. `capture/ansi_to_json.mjs` parses the snapshots into a cell grid, records the snapshot in which each cell first appeared and writes `video/captures.js`.
3. The compositions replay those cells on a paused GSAP timeline: keystrokes one at a time, output line by line. They add the title cards, captions, highlight boxes and end cards.
   - `video/index.html` is the promo. Its scenes are still authored on the original 41 s clock; `PACE = 1.5` stretches every start time and duration (holds, typing, captions and transitions) when it is added to the timeline.
   - `clips/fast`, `clips/lemmeknow` and `clips/crib` are one HyperFrames project per clip (HyperFrames wants one root composition per project). They share `clips/shared/clip-engine.js` (the same replay code, made reusable) and `clips/shared/clip.css`. `clips/sync.sh` copies those, the fonts, `captures.js` and `bench.js` into each project; the copies are gitignored.
4. `hyperframes render` seeks each timeline frame by frame in headless Chrome and encodes with FFmpeg.
5. The GIFs come from a second render with `--variables '{"bgDrift":false}'`, which freezes the faint background ciphertext. Drifting rows change every pixel of the frame and make the GIFs about 4× larger. The GIFs are cropped to the terminal and captions and scaled to half size, so terminal text stays readable.

The Fast clip takes its numbers from the recordings: the `real` time is parsed out of the captured `time` output and the comparison bars read `bench/results.json` (via `video/bench.js`).

| Demo (`capture/demos.json`) | Input | What ciphey prints |
| --- | --- | --- |
| `layers` | `base64(base64(base64(base64(text))))` | `Ciphey peels back every layer of encoding`, path `Base64 → Base64 → Base64 → Base64` |
| `identify` | hex | `flag{ciphey_did_the_hard_part}`, a "Capture The Flag (CTF) Flag" |
| `firstrun` | the base32 string from `images/first_run.tape` | the setup wizard (GirlyPop theme), then `Wow! That was a cool configuration!` |
| `fast` | `base64(hex(rot13("Ciphey is very fast")))`, run as `time ciphey -d -t …` | the plaintext, path `Base64 → Hexadecimal → caesar`, `real 0m0.156s` |
| `lk_mount` | `base64("mount -o username=bee,password=hunter2")` | "Mount Command With Clear Credentials" |
| `lk_totp` | `base64("otpauth://totp/bee?secret=JBSWY3DPEHPK3PXP&digits=6")` | "Time-Based One-Time Password (TOTP) URI" (`JBSWY3DPEHPK3PXP` is the usual example secret, not a real one) |
| `lk_ip` | `hex("192.168.0.1")` | "Internet Protocol (IP) Address Version 4" |
| `crib` | `base64("picoCTF{b4s3_64_1s_fun}")`, run with `-r 'picoCTF\{'` | "Regex matched: picoCTF\{", then the flag |

Every demo except `firstrun` starts with `capture/config-capptucin.toml`, the config the wizard writes when you pick Capptucin. `firstrun` starts without a config so the wizard appears. The recordings in `capture/out/` were made from `master` at 42fbebcc (v0.12.1 plus fixes).

## Speed numbers

`bench/bench_compare.py` times Ciphey against Python Ciphey 5.14.0 (`pip install ciphey==5.14.0`) on the same inputs and writes `bench/results.json`.

- Ciphey runs with `-d` and a fresh `$HOME` per run, so its result cache can never answer.
- Python Ciphey runs with `-g`.
- Every run of either is wrapped in `timeout 60`, and every answer is compared with the known plaintext.

The committed results are the wall-clock median of 10 runs per input (Python: 3) on a shared 16-CPU Linux machine (load average 13–28 during the run):

| Input | Ciphey | Python Ciphey 5.14.0 |
| --- | --- | --- |
| Base64 | 0.08 s | 0.75 s |
| Hex → Base64 | 0.12 s | 0.88 s |
| ROT13 → Hex → Base64 (the Fast clip) | 0.15 s | no answer within 60 s |
| URL → Base64 → Hex | 0.21 s | 1.15 s |
| Base64 ×4 | 0.52 s | 0.87 s |
| Hex → Base32 → Base64 → Hex | 0.82 s | 0.80 s, wrong answer |
| ROT13 → Hex → Base64 → Base32 | 1.65 s | no answer within 60 s |

```bash
python3 -m venv /tmp/pyciphey && /tmp/pyciphey/bin/pip install ciphey==5.14.0
cargo build --release
python3 media/tui-video/bench/bench_compare.py      # or: build.sh --bench
```

## Regenerate

Requirements: Rust, tmux (tested with 3.6a), Python 3, Node.js 22 or newer, and `ffmpeg`/`ffprobe` on `PATH`.

```bash
media/tui-video/build.sh                      # build ciphey, re-record, check, render all four, previews
media/tui-video/build.sh --skip-capture       # reuse capture/out/
media/tui-video/build.sh --skip-capture fast  # just one video (promo, fast, lemmeknow or crib)
```

Step by step, from the repository root:

```bash
cargo build --release
python3 media/tui-video/capture/capture.py         # writes capture/out/
node media/tui-video/capture/ansi_to_json.mjs      # writes video/captures.js
python3 media/tui-video/bench/bench_compare.py --js-only   # writes video/bench.js from results.json
media/tui-video/clips/sync.sh
cd media/tui-video/video                          # or clips/fast, clips/lemmeknow, clips/crib
npx --yes hyperframes@0.8.103 preview             # live preview in the browser
npx --yes hyperframes@0.8.103 check
npx --yes hyperframes@0.8.103 render --crf 22 --output ../out/ciphey-tui-promo.mp4
```

To change a story, edit `SCENES` in `video/index.html` or the `scenes` passed to `CipheyClip.run` in a clip's `index.html` (timings, captions, highlights), or the steps in `capture/demos.json`.

`hyperframes check` passes for all four projects with 0 errors. The remaining lint warnings suggest splitting scenes into sub-compositions, and the info notes are text briefly hidden behind the cursor or a highlight box.

## Pinned versions

- HyperFrames CLI 0.8.103, using the Chrome build it pins (`npx hyperframes browser ensure`); GSAP 3.14.2 from jsDelivr
- Fonts in `video/assets/fonts`: JetBrains Mono 2.304, Inter 4.1, and a subset of Noto Color Emoji 2.051 containing only the emoji ciphey prints. All are SIL OFL 1.1; the licence files are next to the fonts.
- Rendered with FFmpeg 8.1.3; any recent FFmpeg should work.
- `--top-results` is not used in any video: with more than 10 candidates it waits on a y/N prompt before the search is stopped (see the README PR).
