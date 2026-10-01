# ciphey-mcp video

A 29.5 s video of `ciphey-mcp`, the MCP server from [#1034](https://github.com/bee-san/Ciphey/pull/1034), built with [HyperFrames](https://hyperframes.heygen.com/). It shows the install command and client config, then an AI assistant (Kiro CLI) that is asked to decode a CTF string, calls ciphey's `decode` tool and answers with the flag.

| File | What it is |
| --- | --- |
| `out/ciphey-mcp.mp4` | 1920×1080 H.264 (High, yuv420p), 30 fps, 29.5 s, 5.1 MB |
| `out/ciphey-mcp.gif` | the chat scene (13.3 s), 960×540, 10 fps, for the README |
| `out/ciphey-mcp-poster.jpg` | poster frame: the tool result, with the plaintext and the decoder path highlighted |
| `out/ciphey-mcp-stills.jpg` | 2×2 contact sheet: setup, tool result, reply, end card |

## What's real

No chat text, tool call or result is typed into the composition. `capture/to_session_js.py` writes `video/session.js` from the recordings in `capture/out/`, and `video/index.html` takes the session from there. Only the captions, titles and end card are written by hand.

- The prompt, the `tools/call` arguments, the result and "Completed in 0.115s" come from a real Kiro CLI 2.21.3 session, recorded by `capture/kiro_session.sh`: `kiro-cli chat --no-interactive` with an agent whose only tools are ciphey-mcp's, behind a shim that copies every JSON-RPC line between Kiro and ciphey-mcp into `capture/out/kiro/`.
- The assistant's reply is Kiro's answer from that session (`capture/out/kiro/stdout.ansi`), word for word. Inline code is where Kiro printed it as code.
- `capture/mcp_session.py` speaks raw JSON-RPC to the same binary (`initialize` → `tools/list` → `tools/call decode` → `tools/call list_decoders`) and fails unless the plaintext comes back. `to_session_js.py` fails unless Kiro's result is identical to this one. "lists all 24" on the end card is the length of its `list_decoders` result.
- The install command and the `mcpServers` entry are read out of the README's MCP section.

Kiro CLI ran in a terminal; the video draws the same conversation as a generic chat window. It is paced for reading rather than real time: the spinner turns for 1.6 s, and the label next to it shows how long the call really took (Kiro CLI printed "Completed in 0.115s").

The input is `base64(hex(rot13("flag{ciphey_speaks_mcp}")))` (`capture/demo.json`). ciphey-mcp returns that plaintext with the path Base64 → Hexadecimal → caesar (key 13), accepted by the LemmeKnow checker. The recordings were made from `feat/mcp-server` at 1a09b8ce (ciphey 0.12.1).

## Regenerate

Requirements: Rust, Python 3, Node.js 22 or newer and `ffmpeg`/`ffprobe` on `PATH`; `kiro-cli`, logged in, for `--kiro`.

```bash
media/mcp-video/build.sh                 # build ciphey-mcp, re-record the scripted session, check, render, previews
media/mcp-video/build.sh --skip-capture  # reuse capture/out/
media/mcp-video/build.sh --kiro          # also re-record the Kiro session (its reply will be worded differently)
```

Step by step, from the repository root:

```bash
cargo build --release --features mcp --bin ciphey-mcp
python3 media/mcp-video/capture/mcp_session.py --bin target/release/ciphey-mcp
media/mcp-video/capture/kiro_session.sh target/release/ciphey-mcp   # optional, needs kiro-cli
python3 media/mcp-video/capture/to_session_js.py                     # writes video/session.js
cd media/mcp-video/video
npx --yes hyperframes@0.8.103 check
npx --yes hyperframes@0.8.103 render --crf 20 --output ../out/ciphey-mcp.mp4
```

The composition is a paused GSAP timeline that HyperFrames seeks frame by frame in headless Chrome before encoding with FFmpeg. The GIF comes from a second render with `--variables '{"bgDrift":false}'`, which freezes the faint background ciphertext: drifting rows change every pixel of every frame and make the GIF several times larger. The fonts (Inter and JetBrains Mono, both under the OFL) are in `video/assets/fonts/`. `build.sh` turns HyperFrames' anonymous telemetry off (`HYPERFRAMES_NO_TELEMETRY=1`).
