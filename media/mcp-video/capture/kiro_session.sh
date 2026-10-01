#!/usr/bin/env bash
# Record a real AI-assistant session that uses ciphey-mcp: Kiro CLI, non-interactive, with an
# agent whose only tools are the ciphey MCP server's. A small shim between Kiro and
# ciphey-mcp copies every JSON-RPC line both ways, so the video can show the exact tool call
# and result. Writes capture/out/kiro/{stdout.ansi,client-to-server.jsonl,
# server-to-client.jsonl,meta.json}.
#
# Needs kiro-cli, logged in. The reply is written by a language model, so a new recording
# will word it differently; build.sh only re-records it with --kiro.
#
# Usage: media/mcp-video/capture/kiro_session.sh /abs/path/to/ciphey-mcp
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
OUT="$HERE/out/kiro"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

mkdir -p "$OUT" "$WORK/.kiro/agents"
rm -f "$OUT"/client-to-server.jsonl "$OUT"/server-to-client.jsonl

cat > "$WORK/ciphey-mcp" <<EOF
#!/usr/bin/env bash
tee -a "$OUT/client-to-server.jsonl" | "$BIN" "\$@" | tee -a "$OUT/server-to-client.jsonl"
EOF
chmod +x "$WORK/ciphey-mcp"

cat > "$WORK/.kiro/agents/ciphey-demo.json" <<EOF
{
  "name": "ciphey-demo",
  "description": "Demo agent whose only tools come from the ciphey MCP server",
  "tools": ["@ciphey"],
  "allowedTools": ["@ciphey"],
  "mcpServers": { "ciphey": { "command": "$WORK/ciphey-mcp", "args": [] } }
}
EOF

PROMPT="$(cd "$HERE" && python3 -c '
import json
from layers import build_ciphertext
demo = json.load(open("demo.json"))
print(demo["prompt"].replace("{ciphertext}", build_ciphertext(demo["plaintext"], demo["encode"])))
')"

(cd "$WORK" && timeout 300 kiro-cli chat --no-interactive --agent ciphey-demo "$PROMPT") \
  > "$OUT/stdout.ansi" 2> "$WORK/stderr.log" || { cat "$WORK/stderr.log" >&2; exit 1; }

python3 - "$OUT/meta.json" "$PROMPT" "$(kiro-cli --version)" <<'EOF'
import json, sys, datetime
path, prompt, version = sys.argv[1:4]
json.dump({"client": version, "recorded": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
           "prompt": prompt}, open(path, "w"), indent=2, ensure_ascii=False)
open(path, "a").write("\n")
EOF
echo "recorded the Kiro CLI session in $OUT"
