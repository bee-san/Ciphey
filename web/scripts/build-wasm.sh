#!/usr/bin/env bash
# Builds the site's three WebAssembly modules into web/src/wasm/<tool>/, where the pages'
# workers import them:
#   decode    Ciphey's browser API, the ciphey-wasm crate (../wasm), built by wasm/build.sh
#   identify  pyWhat's `wasm` feature      } web/engine: cargo build, wasm-bindgen --target web,
#   language  gibberish-or-not's `wasm`    }             then wasm-opt -Oz
# and writes the three libraries' versions, which the footer shows, to src/wasm/versions.json.
#
# Needs the wasm32-unknown-unknown target, wasm-bindgen-cli 0.2.130 (every crate pins
# wasm-bindgen = "=0.2.130"), binaryen's wasm-opt, python3 and node on the PATH.
#   CARGO_TARGET_DIR  where cargo builds (default: the repository's target/)
#   CIPHEY_WASM_PKG   a directory with a ciphey-wasm package wasm/build.sh already made, to
#                     use instead of building one
#   MAX_WASM_BYTES, MAX_WASM_GZIP_BYTES  passed to wasm/build.sh (its size budget)
set -euo pipefail
cd "$(dirname "$0")/.."
web=$PWD
repo=$(cd .. && pwd)
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-$repo/target}
out=$web/src/wasm

for tool in cargo wasm-bindgen wasm-opt python3 node; do
  command -v "$tool" >/dev/null || { echo "build-wasm.sh: $tool is not on the PATH" >&2; exit 1; }
done
bindgen=$(wasm-bindgen --version | awk '{print $2}')
[ "$bindgen" = 0.2.130 ] || { echo "build-wasm.sh: wasm-bindgen $bindgen, need 0.2.130 (the crates pin it)" >&2; exit 1; }

# The modules embed source paths in their panic messages: write them relative to the cargo
# home and the repository, so a build is the same, byte for byte, on any machine
cargo_home=${CARGO_HOME:-$HOME/.cargo}
export RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=$cargo_home=/cargo --remap-path-prefix=$repo=/ciphey"

size() { printf '%-9s %9d bytes, gzip -9: %d\n' "$1" "$(stat -c %s "$2")" "$(gzip -9 -c "$2" | wc -c)"; }

mkdir -p "$out"
rm -rf "$out/decode" "$out/identify" "$out/language"

echo "== decode: Ciphey (ciphey-wasm)"
if [ -n "${CIPHEY_WASM_PKG:-}" ]; then
  mkdir -p "$out/decode"
  cp "$CIPHEY_WASM_PKG"/ciphey_wasm.js "$CIPHEY_WASM_PKG"/ciphey_wasm.d.ts "$CIPHEY_WASM_PKG"/ciphey_wasm_bg.wasm "$out/decode/"
else
  "$repo/wasm/build.sh" "$out/decode"
fi
size decode "$out/decode/ciphey_wasm_bg.wasm"

echo "== identify (pyWhat) and language (gibberish-or-not)"
cargo build --manifest-path engine/Cargo.toml --locked --release --target wasm32-unknown-unknown \
  -p ciphey-web-identify -p ciphey-web-language
for tool in identify language; do
  dir=$out/$tool
  wasm-bindgen --target web --out-dir "$dir" --out-name "$tool" \
    "$CARGO_TARGET_DIR/wasm32-unknown-unknown/release/ciphey_web_$tool.wasm"
  # wasm-opt reads the WebAssembly features the module uses from its target_features section
  wasm-opt -Oz --strip-debug --strip-producers "$dir/${tool}_bg.wasm" -o "$dir/${tool}_bg.wasm"
  size "$tool" "$dir/${tool}_bg.wasm"
done

# The versions: Ciphey's from its manifest, the other two from web/engine's lock file
ciphey=$(cargo metadata --manifest-path "$repo/Cargo.toml" --format-version 1 --no-deps \
  | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>console.log(JSON.parse(s).packages.find(p=>p.name==="ciphey").version))')
python3 - "$web/engine/Cargo.lock" "$ciphey" > "$out/versions.json" <<'PY'
import json, sys, tomllib
lock = tomllib.load(open(sys.argv[1], "rb"))
version = {p["name"]: p["version"] for p in lock["package"]}
print(json.dumps({"ciphey": sys.argv[2], "pywhat": version["pywhat"], "gibberish": version["gibberish-or-not"]}))
PY
echo "versions: $(cat "$out/versions.json")"
