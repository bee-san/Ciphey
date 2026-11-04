#!/usr/bin/env python3
"""Makes the Decode page's examples without Ciphey, from Python's standard library, and checks
them against web/src/decode/examples.ts:

    python3 web/scripts/make-examples.py          # prints them; exit 1 if examples.ts differs
"""
import base64
import codecs
import json
import pathlib
import re
import sys

MORSE = {
    "A": ".-", "B": "-...", "C": "-.-.", "D": "-..", "E": ".", "F": "..-.", "G": "--.", "H": "....",
    "I": "..", "J": ".---", "K": "-.-", "L": ".-..", "M": "--", "N": "-.", "O": "---", "P": ".--.",
    "Q": "--.-", "R": ".-.", "S": "...", "T": "-", "U": "..-", "V": "...-", "W": ".--", "X": "-..-",
    "Y": "-.--", "Z": "--..",
}


def b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def morse(text: str) -> str:
    return " / ".join(" ".join(MORSE[c] for c in word) for word in text.upper().split())


def vigenere(text: str, key: str) -> str:
    out, i = [], 0
    for c in text:
        if c.isascii() and c.isalpha():
            base = ord("A") if c.isupper() else ord("a")
            shift = ord(key[i % len(key)].upper()) - ord("A")
            out.append(chr((ord(c) - base + shift) % 26 + base))
            i += 1
        else:
            out.append(c)
    return "".join(out)


VIGENERE = ("Ciphey works out the key of a Vigenere cipher by itself, so all you need is the ciphertext"
            " and a little patience while it tries the likely key lengths")
FLAG = "flag{c1ph3y_runs_1n_y0ur_br0ws3r}"
FRENCH = "Le petit chat dort sur le canapé pendant que la pluie tombe doucement"

EXAMPLES = {
    "base64x3": b64(b64(b64("Ciphey peels back every layer of encoding"))),
    "rot13-base64": b64(codecs.encode("Peel the layers one at a time", "rot13")),
    "morse": morse("Ciphey decodes Morse code as well"),
    "vigenere": vigenere(VIGENERE, "BROWSER"),
    "ctf-flag": b64(FLAG.encode().hex()),
    "french": b64(FRENCH),
}

if __name__ == "__main__":
    source = (pathlib.Path(__file__).parent.parent / "src/decode/examples.ts").read_text()
    found = dict(re.findall(r'id: "([^"]+)",\s*label: "[^"]*",\s*input:\s*"([^"]*)"', source))
    bad = [k for k, v in EXAMPLES.items() if found.get(k) != v]
    print(json.dumps(EXAMPLES, indent=2, ensure_ascii=False))
    if bad:
        print("examples.ts differs for:", ", ".join(bad), file=sys.stderr)
        sys.exit(1)
    print("examples.ts matches", file=sys.stderr)
