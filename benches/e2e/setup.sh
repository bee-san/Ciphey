#!/usr/bin/env bash
# Installs what the end-to-end benchmark compares Ciphey with, and what corpus.py needs, into
# TOOLS (default: .tools/ at the repository root, which .gitignore leaves out; the runner wants
# CyberChef inside the repository). Every version is pinned: the Python ones here, npm's in
# benches/data/e2e/cyberchef-lock.json. docs/benchmark-e2e.md says why.
#
#   benches/e2e/setup.sh [all|ciphey-0.12.0|python-ciphey|node|gen]
#
#   $TOOLS/ciphey-0.12.0/bin/ciphey   ciphey 0.12.0 from crates.io (the last release)
#   $TOOLS/pyciphey/bin/python        Python Ciphey 5.14.0 from PyPI, on Python 3.9 (uv)
#   $TOOLS/node/                      npm cyberchef 11.5.0 (Magic) and jsfuck 0.4.0
#   $TOOLS/gen/bin/python             the PyPI encoders corpus.py uses, on Python 3.12 (uv)
#
# Needs cargo, uv (or $UV) and node/npm 24+ on PATH. The Python pins are kept in this script,
# and npm's lock in benches/data/e2e/cyberchef-lock.json (the exact 389 packages the baseline
# ran with), rather than in requirements.txt/package.json/package-lock.json files, so that
# GitHub's dependency graph doesn't report Python Ciphey's and CyberChef's old dependencies
# as Ciphey's.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
TOOLS=${TOOLS:-$ROOT/.tools}
UV=${UV:-uv}
what=${1:-all}
mkdir -p "$TOOLS"

if [[ $what == all || $what == ciphey-0.12.0 ]]; then
  # --locked: the Cargo.lock published with 0.12.0. The build dir is removed afterwards.
  cargo install ciphey --version 0.12.0 --locked --root "$TOOLS/ciphey-0.12.0" --target-dir "$TOOLS/ciphey-0.12.0-build"
  rm -rf "$TOOLS/ciphey-0.12.0-build"
fi

if [[ $what == all || $what == python-ciphey ]]; then
  # cipheycore 0.3.2 has wheels up to CPython 3.9. These are the versions uv resolved on
  # 2026-11-04 for ciphey==5.14.0.
  "$UV" python install 3.9
  "$UV" venv -p 3.9 "$TOOLS/pyciphey"
  pins=(
    ciphey==5.14.0 appdirs==1.4.4
    astroid==2.15.8  # codespell:ignore (a package name)
    base58==2.1.1 base91==1.0.1 cipheycore==0.3.2 cipheydists==0.3.35 click==7.1.2 colorama==0.4.6
    commonmark==0.9.2 dill==0.4.1 flake8==3.9.2 isort==5.13.2 langdetect==1.0.9 lazy-object-proxy==1.12.0
    loguru==0.5.3 mccabe==0.6.1 mock==4.0.3 name-that-hash==1.10.0 platformdirs==4.4.0 pybase62==0.4.3
    pycodestyle==2.7.0 pyflakes==2.3.1 pygments==2.21.0 pylint==2.17.7 pywhat==1.1.0 pyyaml==5.4.1
    rich==10.16.2 six==1.17.0 tomli==2.5.0 tomlkit==0.15.2 typing-extensions==4.16.0 wrapt==1.17.3
  )
  "$UV" pip install -p "$TOOLS/pyciphey/bin/python" "${pins[@]}"
fi

if [[ $what == all || $what == node ]]; then
  # npm ci installs exactly the lock. --ignore-scripts: cyberchef's postinstall runs grunt,
  # which isn't installed for users of the package; the one step the Node API needs (adding
  # .mjs to crypto-api's imports) is run by hand below. terser is a devDependency that the
  # Node API imports anyway.
  mkdir -p "$TOOLS/node"
  cat > "$TOOLS/node/package.json" <<'EOF'
{"name": "ciphey-e2e-tools", "private": true,
 "dependencies": {"cyberchef": "11.5.0", "jsfuck": "0.4.0", "terser": "5.51.2"}}
EOF
  cp "$ROOT/benches/data/e2e/cyberchef-lock.json" "$TOOLS/node/package-lock.json"
  (cd "$TOOLS/node" && npm ci --no-audit --no-fund --ignore-scripts &&
    node --no-warnings node_modules/cyberchef/src/core/config/scripts/fixCryptoApiImports.mjs)
fi

if [[ $what == all || $what == gen ]]; then
  "$UV" venv -p 3.12 "$TOOLS/gen"
  "$UV" pip install -p "$TOOLS/gen/bin/python" base45==0.4.4 base58==2.1.1 base65536==0.1.1 base91==1.0.1 \
    base92==2.0.0 cipheydists==0.3.35 future==1.0.0 lz4==4.4.5 lzstring==1.0.4 pybase62==1.0.0 \
    pycipher==0.5.2 six==1.17.0 zstandard==0.25.0
fi
echo "tools in $TOOLS"
