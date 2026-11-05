#!/usr/bin/env bash
# BRANCH ONLY (ciphey-web): removed before this branch lands, once Ciphey depends on
# gibberish-or-not 6 and pywhat 6 and builds for WebAssembly as it is.
#
# Until then Ciphey's WebAssembly build needs two temporary patches, which this script applies
# to the checkout it runs in (Cargo.toml and Cargo.lock are changed, never committed). It is
# ciphey-wasm's make-wasm-proof.sh (Ciphey PR #1136's evidence), with CARGO_HOME defaulting to
# ~/.cargo so it runs on GitHub's runners:
#   * gibberish-or-not 5.0.7 pulls in candle, tokenizers/onig (C) and reqwest/openssl for a
#     BERT model that `is_gibberish` never loads: the copy here has no model (is_gibberish and
#     is_password are unchanged);
#   * lemmeknow 0.8.0's wasm32 `Identifier::identify` passes a slice to `Regex::is_match` and
#     doesn't compile: the copy here has the native `&str` API.
set -euo pipefail
cd "$(dirname "$0")/../.."
REG=$(ls -d "${CARGO_HOME:-$HOME/.cargo}"/registry/src/index.crates.io-*/ 2>/dev/null | head -1 || true)
if [ -z "$REG" ] || [ ! -d "$REG/gibberish-or-not-5.0.7" ] || [ ! -d "$REG/lemmeknow-0.8.0" ]; then
  cargo fetch >/dev/null
  REG=$(ls -d "${CARGO_HOME:-$HOME/.cargo}"/registry/src/index.crates.io-*/ | head -1)
fi
P=.scratch/proof
rm -rf "$P"
mkdir -p "$P"

cp -r "$REG/gibberish-or-not-5.0.7" "$P/gibberish-or-not"
G=$P/gibberish-or-not
rm -rf "$G/.cargo" "$G/src/bin" "$G/benches" "$G/src/model.rs" "$G/src/cli.rs" "$G/Cargo.lock" "$G/Cargo.toml.orig"
python3 - "$G" <<'PY'
import re, sys
g = sys.argv[1]
lib = open(f"{g}/src/lib.rs").read()
lib = lib.replace("#[doc(hidden)]\nmod cli;\n", "").replace("mod model;\n", "")
lib = re.sub(r"// Core library exports\npub use model::\{[^}]*\};\n", "", lib)
lib = re.sub(r"// CLI utilities[^\n]*\n#\[doc\(hidden\)\]\npub use cli::download_with_progress_bar;\n", "", lib)
lib = lib.replace(""".map(|p| model::Model::exists(p))
            .unwrap_or(false)""", """.map(|_| false)
            .unwrap_or(false)""")
lib = re.sub(r"        // Try enhanced detection if available\n        if let Some\(path\) = &self.model_path \{.*?\n        \}\n\n", "", lib, flags=re.S)
assert "model::" not in lib and "cli::" not in lib, "model/cli references left"
open(f"{g}/src/lib.rs", "w").write(lib)
toml = open(f"{g}/Cargo.toml").read()
for dep in ("candle-core", "candle-nn", "candle-transformers", "chrono", "clap", "dirs", "env_logger",
            "reqwest", "safetensors", "tokenizers", "criterion"):
    toml = re.sub(r"\n\[(dev-)?dependencies\.%s\]\n(?:[^\[\n][^\n]*\n)*" % re.escape(dep), "\n", toml)
toml = re.sub(r"\n\[\[(bin|bench)\]\]\n(?:[^\[\n][^\n]*\n)*", "\n", toml)
open(f"{g}/Cargo.toml", "w").write(toml + "\n[workspace]\n")
PY

cp -r "$REG/lemmeknow-0.8.0" "$P/lemmeknow"
L=$P/lemmeknow
rm -f "$L/Cargo.lock" "$L/Cargo.toml.orig"
python3 - "$L" <<'PY'
import sys
l = sys.argv[1]
for path, ty in (("src/identifier/mod.rs", "&str"), ("src/identifier/bytes.rs", "&[u8]")):
    p = f"{l}/{path}"
    s = open(p).read()
    start = s.index('// Identifier implementation for wasm\n#[cfg(target_arch = "wasm32")]\nimpl Identifier {')
    end = s.index("\n}\n", start) + 3
    new = f'''// Identifier implementation for wasm (ciphey-wasm proof: 0.8.0's passes a slice to is_match)
#[cfg(target_arch = "wasm32")]
impl Identifier {{
    pub fn identify(&self, text: {ty}) -> Vec<Match> {{
        let regexes = if self.boundaryless {{ &BOUNDARYLESS_REGEX }} else {{ &REGEX }};
        DATA.iter()
            .enumerate()
            .filter_map(|(i, e)| {{
                if is_valid_filter(self, e) && regexes[i].is_match(text) {{
                    Some(Match::new(text.to_owned(), e.clone()))
                }} else {{
                    None
                }}
            }})
            .collect::<Vec<Match>>()
    }}

    pub fn first_match(&self, text: {ty}) -> Option<Match> {{
        let regexes = if self.boundaryless {{ &BOUNDARYLESS_REGEX }} else {{ &REGEX }};
        for (i, x) in DATA.iter().enumerate().filter(|(_, x)| is_valid_filter(self, x)) {{
            if regexes[i].is_match(text) {{
                return Some(Match::new(text.to_owned(), x.clone()));
            }}
        }}
        None
    }}
}}
'''
    open(p, "w").write(s[:start] + new + s[end:])
t = open(f"{l}/Cargo.toml").read()
open(f"{l}/Cargo.toml", "w").write(t + "\n[workspace]\n")
PY

if ! grep -q 'ciphey-wasm proof' Cargo.toml; then
  cat >> Cargo.toml <<'TOML'

# TEMPORARY ciphey-wasm proof (web/scripts/branch-only-wasm-proof.sh): never on master
[patch.crates-io]
gibberish-or-not = { path = ".scratch/proof/gibberish-or-not" }
lemmeknow = { path = ".scratch/proof/lemmeknow" }
TOML
fi
echo "wasm proof patches in place: $P"
