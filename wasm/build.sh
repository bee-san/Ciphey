#!/usr/bin/env bash
# wasm/build.sh [out dir]: builds Ciphey's JavaScript package for the web (docs/wasm.md).
#
#   1. cargo build -p ciphey-wasm --target wasm32-unknown-unknown --profile wasm
#   2. wasm-bindgen --target web: ciphey_wasm.js, ciphey_wasm.d.ts, ciphey_wasm_bg.wasm
#   3. wasm-opt -Oz on ciphey_wasm_bg.wasm, unless SKIP_WASM_OPT=1
#   4. prints the module's size, raw and gzipped, and fails if it is over a budget:
#      MAX_WASM_BYTES and MAX_WASM_GZIP_BYTES (bytes; unset means no limit)
#
# Needs the wasm32-unknown-unknown target, wasm-bindgen-cli 0.2.130 (the version
# wasm/Cargo.toml pins) and binaryen's wasm-opt on PATH, and python3 for the sizes.
# The out dir defaults to wasm/pkg.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
# Relative to where it is run from, before the cd below
out=$(realpath -m "${1:-$root/wasm/pkg}")
target_dir=${CARGO_TARGET_DIR:-$root/target}

cd "$root"
cargo build -p ciphey-wasm --target wasm32-unknown-unknown --profile wasm
want=$(sed -n 's/^wasm-bindgen = "=\(.*\)"$/\1/p' wasm/Cargo.toml)
have=$(wasm-bindgen --version | awk '{print $2}')
if [ "$want" != "$have" ]; then
  echo "build.sh: wasm-bindgen $have is installed, but wasm/Cargo.toml pins $want" >&2
  exit 1
fi
mkdir -p "$out"
wasm-bindgen --target web --out-dir "$out" \
  "$target_dir/wasm32-unknown-unknown/wasm/ciphey_wasm.wasm"
module=$out/ciphey_wasm_bg.wasm
if [ "${SKIP_WASM_OPT:-0}" != 1 ]; then
  wasm-opt -Oz --strip-debug --strip-producers "$module" -o "$module.opt"
  mv "$module.opt" "$module"
fi

python3 - "$module" "${MAX_WASM_BYTES:-}" "${MAX_WASM_GZIP_BYTES:-}" <<'PY'
import gzip, sys
path, max_raw, max_gzip = sys.argv[1], sys.argv[2], sys.argv[3]
data = open(path, "rb").read()
raw, gz = len(data), len(gzip.compress(data, 9))
print(f"{path}: {raw:,} bytes, {gz:,} gzipped (gzip -9)")
over = []
if max_raw and raw > int(max_raw):
    over.append(f"{raw:,} bytes is over the budget of {int(max_raw):,}")
if max_gzip and gz > int(max_gzip):
    over.append(f"{gz:,} gzipped bytes is over the budget of {int(max_gzip):,}")
for line in over:
    print(f"build.sh: {line}", file=sys.stderr)
sys.exit(1 if over else 0)
PY
