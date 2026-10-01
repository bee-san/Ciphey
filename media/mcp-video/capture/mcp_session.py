#!/usr/bin/env python3
"""Record a real MCP session with ciphey-mcp over stdio, with no SDK in between.

Sends initialize -> notifications/initialized -> tools/list -> tools/call decode ->
tools/call list_decoders, and writes every JSON-RPC line exactly as it went over the pipe
(direction, seconds since start, raw line) to capture/out/jsonrpc-session.jsonl.

The decode input is built from capture/demo.json (plaintext + encoding layers), and the run
fails unless ciphey-mcp hands that plaintext back.

Usage: python3 media/mcp-video/capture/mcp_session.py --bin target/release/ciphey-mcp
"""
import argparse
import json
import queue
import subprocess
import sys
import threading
import time
from pathlib import Path

from layers import build_ciphertext

HERE = Path(__file__).resolve().parent
TIMEOUT = 40  # seconds to wait for any one response (decode itself is capped at 30 s)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bin", required=True, help="path to the ciphey-mcp binary")
    parser.add_argument("--out", default=str(HERE / "out" / "jsonrpc-session.jsonl"))
    args = parser.parse_args()

    demo = json.loads((HERE / "demo.json").read_text())
    ciphertext = build_ciphertext(demo["plaintext"], demo["encode"])

    proc = subprocess.Popen([args.bin], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, encoding="utf-8", bufsize=1)
    lines: "queue.Queue[str | None]" = queue.Queue()

    def pump() -> None:
        for line in proc.stdout:
            lines.put(line)
        lines.put(None)

    threading.Thread(target=pump, daemon=True).start()
    log = []
    t0 = time.monotonic()

    def send(msg: dict) -> None:
        raw = json.dumps(msg, ensure_ascii=False)
        proc.stdin.write(raw + "\n")
        proc.stdin.flush()
        log.append({"t": round(time.monotonic() - t0, 3), "dir": "client->server", "raw": raw})

    def recv(expect_id: int) -> dict:
        while True:
            line = lines.get(timeout=TIMEOUT)
            if line is None:
                raise SystemExit("ciphey-mcp closed stdout; stderr:\n" + proc.stderr.read())
            raw = line.rstrip("\n")
            log.append({"t": round(time.monotonic() - t0, 3), "dir": "server->client", "raw": raw})
            msg = json.loads(raw)
            if msg.get("id") == expect_id:
                return msg

    send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-11-25", "capabilities": {},
        "clientInfo": {"name": "ciphey-mcp-video-recorder", "version": "1.0.0"}}})
    init = recv(1)["result"]
    send({"jsonrpc": "2.0", "method": "notifications/initialized"})
    send({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    tools = [tool["name"] for tool in recv(2)["result"]["tools"]]
    send({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
          "params": {"name": "decode", "arguments": {"text": ciphertext}}})
    decode = recv(3)["result"]
    send({"jsonrpc": "2.0", "id": 4, "method": "tools/call",
          "params": {"name": "list_decoders", "arguments": {}}})
    decoders = recv(4)["result"]["structuredContent"]["decoders"]
    proc.stdin.close()
    proc.wait(timeout=TIMEOUT)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("".join(json.dumps(entry, ensure_ascii=False) + "\n" for entry in log))

    result = decode.get("structuredContent") or {}
    print(f"server {init['serverInfo']['name']} {init['serverInfo']['version']}, "
          f"protocol {init['protocolVersion']}, tools {tools}, {len(decoders)} decoders")
    print("decode:", json.dumps(result, ensure_ascii=False))
    if decode.get("isError") or result.get("status") != "decoded" or result.get("plaintext") != demo["plaintext"]:
        print("error: ciphey-mcp did not return the expected plaintext", file=sys.stderr)
        return 1
    print("wrote", out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
