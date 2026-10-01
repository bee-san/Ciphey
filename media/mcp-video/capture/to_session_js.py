#!/usr/bin/env python3
"""Turn the recordings in capture/out/ into video/session.js for the composition.

Everything the video shows about the session comes from here, so no chat text, tool call
or result is typed into index.html by hand:

- the prompt (out/kiro/meta.json) and the assistant's reply (out/kiro/stdout.ansi, Kiro
  CLI's own output; inline code is its green 38;5;10 colour)
- the tool list, the tools/call arguments and the result, verbatim from the JSON-RPC
  lines Kiro CLI and ciphey-mcp exchanged (out/kiro/*.jsonl)
- the install command, the Kiro command and the mcpServers entry, from the README's
  "MCP server" section

It also checks that the Kiro session's result matches the scripted session
(out/jsonrpc-session.jsonl) and capture/demo.json.
"""
import json
import re
import sys
from pathlib import Path

from layers import build_layers

HERE = Path(__file__).resolve().parent
OUT = HERE / "out"
ROOT = HERE.parent.parent.parent
ANSI = re.compile(r"\x1b\[([0-9;]*)m")


def fail(message: str) -> None:
    sys.exit("to_session_js: " + message)


def jsonl(path: Path) -> list:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def request(messages: list, method: str, tool: str = None) -> dict:
    """The first request for `method` (and, for tools/call, for `tool`)."""
    for msg in messages:
        if msg.get("method") == method and "id" in msg and (tool is None or msg["params"]["name"] == tool):
            return msg
    fail(f"no {method} {tool or ''} request recorded")


def response(messages: list, req: dict) -> dict:
    """The result of the request `req`."""
    for msg in messages:
        if msg.get("id") == req["id"] and "result" in msg:
            return msg["result"]
    fail(f"no result for {req['method']} (id {req['id']})")


def styled_segments(line: str) -> list:
    """Split one line of Kiro CLI output into [kind, text] runs; green text is inline code."""
    segments, kind, pos = [], "text", 0
    for match in ANSI.finditer(line):
        if match.start() > pos:
            segments.append([kind, line[pos:match.start()]])
        codes = match.group(1)
        kind = "code" if codes == "38;5;10" else "marker" if codes == "38;5;141" else "text"
        pos = match.end()
    if pos < len(line):
        segments.append([kind, line[pos:]])
    merged = []
    for seg_kind, text in segments:
        if merged and merged[-1][0] == seg_kind:
            merged[-1][1] += text
        else:
            merged.append([seg_kind, text])
    return merged


def parse_kiro_stdout(text: str) -> tuple:
    lines = text.splitlines()
    plain = [ANSI.sub("", line) for line in lines]
    completed = next((m.group(1) for line in plain if (m := re.search(r"Completed in ([0-9.]+s)", line))), None)
    start = next((i for i, line in enumerate(plain) if line.startswith("> ")), None)
    if completed is None or start is None:
        fail("could not find the tool run and the reply in out/kiro/stdout.ansi")
    paragraphs, current = [], []
    for line in lines[start:]:
        segments = [seg for seg in styled_segments(line) if seg[1]]
        if segments and segments[0][0] == "marker":  # Kiro's "> " reply marker
            segments = segments[1:]
        if not "".join(text for _, text in segments).strip():
            if current:
                paragraphs.append(current)
                current = []
            continue
        if current:
            current.append(["text", " "])
        current.extend(segments)
    if current:
        paragraphs.append(current)
    return completed, paragraphs


def readme_blocks() -> dict:
    """The fenced code blocks of the README's MCP section, keyed by the heading above them."""
    blocks, heading, fence, in_section = {}, None, None, False
    for line in (ROOT / "README.md").read_text(encoding="utf-8").splitlines():
        if fence is not None:
            if line.startswith("```"):
                blocks.setdefault(heading, []).append("\n".join(fence))
                fence = None
            else:
                fence.append(line)
        elif line.startswith("```"):
            fence = []
        elif line.startswith("# "):
            in_section = line.startswith("# MCP server")
            heading = "MCP server" if in_section else None
        elif line.startswith("#") and in_section:
            heading = line.lstrip("# ").strip()
    blocks.pop(None, None)
    return blocks


def main() -> None:
    demo = json.loads((HERE / "demo.json").read_text())
    layers = build_layers(demo["plaintext"], demo["encode"])
    ciphertext = layers[-1]
    meta = json.loads((OUT / "kiro" / "meta.json").read_text())
    sent = jsonl(OUT / "kiro" / "client-to-server.jsonl")
    received = jsonl(OUT / "kiro" / "server-to-client.jsonl")
    scripted = [json.loads(entry["raw"]) for entry in jsonl(OUT / "jsonrpc-session.jsonl")]

    init = response(received, request(sent, "initialize"))
    tools = [tool["name"] for tool in response(received, request(sent, "tools/list"))["tools"]]
    call = request(sent, "tools/call", "decode")
    result = response(received, call)
    structured = result["structuredContent"]
    if result.get("isError"):
        fail("the recorded decode call failed")

    scripted_result = response(scripted, request(scripted, "tools/call", "decode"))["structuredContent"]
    decoder_count = len(response(scripted, request(scripted, "tools/call", "list_decoders"))["structuredContent"]["decoders"])
    if structured != scripted_result:
        fail("the Kiro session's result differs from the scripted session's")
    if structured.get("plaintext") != demo["plaintext"] or len(structured["path"]) != len(demo["encode"]):
        fail("the recorded result does not match capture/demo.json")
    if not meta["prompt"].endswith(ciphertext) or call["params"]["arguments"].get("text") != ciphertext:
        fail("the recorded prompt or tool call does not carry the demo ciphertext")

    completed, reply = parse_kiro_stdout((OUT / "kiro" / "stdout.ansi").read_text(encoding="utf-8"))
    if not any(kind == "code" and demo["plaintext"] in text for para in reply for kind, text in para):
        fail("the reply does not quote the plaintext")

    blocks = readme_blocks()
    install = blocks["MCP server"][0].splitlines()[0]
    kiro_add = blocks["Kiro"][0].strip()
    config = blocks["Other clients"][0]
    if not install.startswith("cargo install") or not kiro_add.startswith("kiro-cli mcp add"):
        fail("README's MCP section no longer has the expected install commands")

    session = {
        "client": meta["client"],
        "recorded": meta["recorded"],
        "server": init["serverInfo"],
        "protocolVersion": init["protocolVersion"],
        "tools": tools,
        "question": meta["prompt"][: -len(ciphertext)].rstrip(),
        "ciphertext": ciphertext,
        "toolName": call["params"]["name"],
        "arguments": call["params"]["arguments"],
        "result": structured,
        "completedIn": completed,
        "reply": reply,
        "layers": layers[::-1],  # ciphertext first, as ciphey peels them
        "decoderCount": decoder_count,
        "install": install,
        "kiroAdd": kiro_add,
        "config": config,
    }
    target = HERE.parent / "video" / "session.js"
    target.write_text(
        "// Generated by ../capture/to_session_js.py from the recordings in ../capture/out/. Do not edit.\n"
        "window.CIPHEY_MCP_SESSION = " + json.dumps(session, indent=2, ensure_ascii=False) + ";\n",
        encoding="utf-8")
    print("wrote", target)


if __name__ == "__main__":
    main()
