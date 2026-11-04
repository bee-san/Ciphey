"""`corpus.py --verify`: decode every case of the corpus again with a second implementation.

For each layer this knows a CyberChef recipe (CyberChef's own decoders, through cyberchef.py)
or a decoder from PyPI or the standard library. A case is checked when every layer has one:
CyberChef recipes are joined into one recipe; otherwise the layers are undone in Python. The
result must match the case's expected answer under its match rule. Cases with a layer that
has no second implementation are listed as unchecked (their encoders are tested by
corpus.py's selftest() known answers instead).
"""

import binascii
import email.header
import lzma
import unicodedata

from run import normalize


def cc(op, *args):
    return [{"op": op, "args": list(args)}]


B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
CC_STEPS = {
    "base64": cc("From Base64", "A-Za-z0-9+/=", True, False),
    "base64_url": cc("From Base64", "A-Za-z0-9-_", True, False),
    "base64_itoa64": cc("From Base64", "./0-9A-Za-z=", True, False),
    "base32": cc("From Base32", "A-Z2-7=", True),
    "base32hex": cc("From Base32", "0-9A-V=", True),
    "base32_crockford": cc("From Base32", "0-9A-HJKMNP-TV-Z=", True),
    "zbase32": cc("From Base32", "ybndrfg8ejkmcpqxot1uwisza345h769=", True),
    "hex": cc("From Hex", "Auto"),
    "hex_spaced": cc("From Hex", "Auto"),
    "base36": cc("From Base", 36) + cc("To Base", 16) + cc("From Hex", "Auto"),
    "bigint": cc("To Base", 16) + cc("From Hex", "Auto"),
    "base58_bitcoin": cc("From Base58", B58, True),
    "base58_ripple": cc("From Base58", "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz", True),
    "base58_flickr": cc("From Base58", "123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ", True),
    "base62": cc("From Base62", "0-9A-Za-z"),
    "base85": cc("From Base85", "0-9A-Za-z!#$%&()*+\\-;<=>?@^_`{|}~", True),
    "ascii85": cc("From Base85", "!-u", True),
    "ascii85_adobe": cc("From Base85", "!-u", True),
    "z85": cc("From Base85", "0-9a-zA-Z.\\-:+=^!/*?&<>()[]{}@%$#", True),
    "base92": cc("From Base92"),
    "binary": cc("From Binary", "Space", 8),
    "decimal": cc("From Decimal", "Space", False),
    "octal": cc("From Octal", "Space"),
    "url": cc("URL Decode"),
    "url_all": cc("URL Decode"),
    "html_dec": cc("From HTML Entity"),
    "html_hex": cc("From HTML Entity"),
    "unicode_escape": cc("Unescape Unicode Characters", "\\u"),
    "backslash_octal": cc("Unescape string"),
    "backslash_hex": cc("Unescape string"),
    "quoted_printable": cc("From Quoted Printable"),
    "punycode": cc("From Punycode", True),
    "utf16le": cc("Decode text", "UTF-16LE (1200)"),
    "hexdump_xxd": cc("From Hexdump"),
    "hexdump_c": cc("From Hexdump"),
    "morse": cc("From Morse Code", "Space", "Forward slash"),
    "morse_lines": cc("From Morse Code", "Space", "Line feed"),
    "braille": cc("From Braille"),
    "a1z26_spaces": cc("A1Z26 Cipher Decode", "Space"),
    "bacon26": cc("Bacon Cipher Decode", "Complete", "A/B", False),
    "bacon24": cc("Bacon Cipher Decode", "Standard (I=J and U=V)", "A/B", False),
    "citrix_ctx1": cc("Citrix CTX1 Decode"),
    "jwt": cc("JWT Decode"),
    "gzip": cc("Gunzip"),
    "zlib": cc("Zlib Inflate", 0, 0, "Adaptive", False, False),
    "deflate": cc("Raw Inflate", 0, 0, "Adaptive", False, False),
    "bzip2": cc("Bzip2 Decompress", False),
    "rot13": cc("ROT13", True, True, False, 13),
    "rot47": cc("ROT47", 47),
    "atbash": cc("Atbash Cipher"),
    "reverse": cc("Reverse", "Character"),
    "affine_5_8": cc("Affine Cipher Decode", 5, 8),
    "affine_7_3": cc("Affine Cipher Decode", 7, 3),
    "affine_11_20": cc("Affine Cipher Decode", 11, 20),
    "base45": cc("From Base45", "0-9A-Z $%*+\\-./:"),
    "bech32": cc("From Bech32", "Auto-detect", "Raw"),
    "modhex": cc("From Modhex", "Auto"),
    "utf7": cc("Decode text", "UTF-7 (65000)"),
    "ebcdic": cc("Decode text", "IBM EBCDIC US-Canada (37)"),
    "rot8000": cc("ROT8000"),
    "rotl3": cc("Rotate right", 3, False),
    "bitnot": cc("NOT"),
    "lzstring": cc("LZString Decompress", "Base64"),
    "md5": None, "sha1": None, "sha256": None, "ntlm": None,  # checked by hashing the answer
}
for k in (3, 7, 19, 23):
    CC_STEPS[f"caesar{k}"] = cc("ROT13", True, True, False, 26 - k)
for key in ("KEY", "LEMON", "CIPHER", "PASSWORD"):
    CC_STEPS[f"vigenere_{key.lower()}"] = cc("Vigenère Decode", key)
for rails in (2, 3, 5, 7):
    CC_STEPS[f"railfence{rails}"] = cc("Rail Fence Cipher Decode", rails, 0)
for k in (0x2A, 0x5C, 0x13):
    CC_STEPS[f"xor_{k:02x}"] = cc("XOR", {"option": "Hex", "string": f"{k:02x}"}, "Standard", False)
for key in ("KEY", "ICE", "s3cr3t"):
    CC_STEPS[f"xorkey_{key.lower()}"] = cc("XOR", {"option": "UTF8", "string": key}, "Standard", False)
for i, alphabet in enumerate(("QWERTYUIOPASDFGHJKLZXCVBNM", "ZEBRASCDFGHIJKLMNOPQTUVWXY", "MKXHAZRQDVPNOUCSYGLWEJBFTI")):
    plain = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    CC_STEPS[f"substitution{i + 1}"] = cc("Substitute", alphabet + alphabet.lower(), plain + plain.lower(), False)


def bf_run(prog, limit=10_000_000):
    """A small Brainfuck interpreter (8-bit cells), for checking the generated programs."""
    jump, stack = {}, []
    for i, c in enumerate(prog):
        if c == "[":
            stack.append(i)
        elif c == "]":
            j = stack.pop()
            jump[i], jump[j] = j, i
    cells, ptr, pc, out, steps = [0] * 30000, 0, 0, bytearray(), 0
    while pc < len(prog) and steps < limit:
        c = prog[pc]
        if c == ">":
            ptr += 1
        elif c == "<":
            ptr -= 1
        elif c == "+":
            cells[ptr] = (cells[ptr] + 1) % 256
        elif c == "-":
            cells[ptr] = (cells[ptr] - 1) % 256
        elif c == ".":
            out.append(cells[ptr])
        elif c == "[" and cells[ptr] == 0:
            pc = jump[pc]
        elif c == "]" and cells[ptr] != 0:
            pc = jump[pc]
        pc += 1
        steps += 1
    return bytes(out)


def py_steps():
    """Python decoders (bytes -> bytes) from PyPI and the standard library."""
    import base65536
    import base91
    import lz4.frame
    import pycipher
    import zstandard

    from corpus import OOK, PIKALANG

    def pairs_to_bf(text, table):
        inverse = {v: k for k, v in table.items()}
        words = text.split(" ")
        return "".join(inverse[" ".join(words[i : i + 2])] for i in range(0, len(words), 2))

    blub = {k: v.replace("Ook", "Blub") for k, v in OOK.items()}

    def t(fn):  # text -> text
        return lambda b: fn(b.decode("utf-8")).encode("utf-8")

    return {
        "base65536": t(lambda s: base65536.decode(s).decode("utf-8")),
        "base91": t(lambda s: base91.decode(s).decode("utf-8")),
        "uuencode": lambda b: b"".join(binascii.a2b_uu(line) for line in b.split(b"\n")[1:-2]),
        "mime_b": t(lambda s: "".join(p.decode(c or "ascii") if isinstance(p, bytes) else p for p, c in email.header.decode_header(s))),
        "mime_q": t(lambda s: "".join(p.decode(c or "ascii") if isinstance(p, bytes) else p for p, c in email.header.decode_header(s))),
        "unicode_plus": t(lambda s: "".join(chr(int(x[2:], 16)) for x in s.split(" "))),
        "utf16be_bom": lambda b: b.decode("utf-16").encode("utf-8"),
        "xz": lzma.decompress,
        "zstd": lambda b: zstandard.ZstdDecompressor().decompress(b),
        "lz4": lz4.frame.decompress,
        "bigint_named": lambda b: (lambda n: n.to_bytes((n.bit_length() + 7) // 8, "big"))(int(b.decode().split("= ")[1])),
        "brainfuck": lambda b: bf_run(b.decode()),
        "ook": lambda b: bf_run(pairs_to_bf(b.decode(), OOK)),
        "blub": lambda b: bf_run(pairs_to_bf(b.decode(), blub)),
        "pikalang": lambda b: bf_run("".join({v: k for k, v in PIKALANG.items()}[w] for w in b.decode().split(" "))),
        "zalgo": t(lambda s: "".join(c for c in s if unicodedata.category(c) != "Mn")),
        "fancy_bold": t(lambda s: unicodedata.normalize("NFKC", s)),
        "fullwidth": t(lambda s: unicodedata.normalize("NFKC", s)),
        "reverse_words": t(lambda s: " ".join(w[::-1] for w in s.split(" "))),
        "beaufort_fort": t(lambda s: pycipher.Beaufort("FORT").decipher(s)),
        "beaufort_secret": t(lambda s: pycipher.Beaufort("SECRET").decipher(s)),
        "beaufort_bravo": t(lambda s: pycipher.Beaufort("BRAVO").decipher(s)),
        "autokey_queen": t(lambda s: pycipher.Autokey("QUEEN").decipher(s)),
        "autokey_kilt": t(lambda s: pycipher.Autokey("KILT").decipher(s)),
        "porta": t(lambda s: pycipher.Porta("FORTIFICATION").decipher(s)),
        "columnar": t(lambda s: pycipher.ColTrans("GERMAN").decipher(s)),
        "double_transposition": t(lambda s: pycipher.ColTrans("GERMAN").decipher(pycipher.ColTrans("CIPHER").decipher(s))),
        "fractionated_morse": t(lambda s: pycipher.FracMorse("ROUNDTABLECFGHIJKMPQSVWXYZ").decipher(s)),
    }


def pycipher_square_steps():
    import pycipher

    from corpus import keyword_square

    return {
        "playfair_playfair": lambda s: pycipher.Playfair(key=keyword_square("PLAYFAIR EXAMPLE")).decipher(s),
        "playfair_monarchy": lambda s: pycipher.Playfair(key=keyword_square("MONARCHY")).decipher(s),
        "playfair_keyword": lambda s: pycipher.Playfair(key=keyword_square("KEYWORD")).decipher(s),
        "bifid": lambda s: pycipher.Bifid(key=keyword_square("BGWKZ QPNDS"), period=5).decipher(s),
        "adfgx": lambda s: pycipher.ADFGX(key=keyword_square("BTALPDHOZKQFVSNGICUXMREWY"), keyword="CARGO").decipher(s),
        "adfgvx": lambda s: pycipher.ADFGVX(key=keyword_square("PH0QG64MEA1YL2NOFDXKR3CVS5ZW7BJ9UTI8", 36), keyword="GERMAN").decipher(s),
    }


# pycipher's ciphers keep letters only, so their checks compare letters
LETTERS_ONLY = {"beaufort_fort", "beaufort_secret", "beaufort_bravo", "autokey_queen", "autokey_kilt", "porta", "columnar",
                "double_transposition", "fractionated_morse", "bifid", "adfgx", "adfgvx", "playfair_playfair",
                "playfair_monarchy", "playfair_keyword"}


def aa_inner(program):
    """The part of an AAEncode program that evaluates to the encoded text instead of running it."""
    head, sep, rest = program.rpartition("(ﾟДﾟ) ['_'] ( (ﾟДﾟ) ['_'] (")
    assert sep and rest.endswith(" ('_');"), "not aaencode's layout"
    return head + "( (ﾟДﾟ) ['_'] (" + rest[: -len(" ('_');")] + ";"


def verify(cases, chef):
    import json
    import os

    with open(os.path.join(chef.root, "node_modules", "cyberchef", "src", "core", "config", "OperationConfig.json"), encoding="utf-8") as fh:
        op_config = json.load(fh)
    py = py_steps()
    py["jsfuck"] = lambda b: chef.request({"op": "eval", "code": b.decode()})["output"].encode()
    py["aaencode"] = lambda b: chef.request({"op": "eval", "code": aa_inner(b.decode())})["output"].encode()
    for name, fn in pycipher_square_steps().items():
        py[name] = (lambda f: lambda b: f(b.decode()).encode())(fn)
    hashes = {"md5": cc("MD5"), "sha1": cc("SHA1", 80), "sha256": cc("SHA2", "256", 64, 160), "ntlm": cc("NT Hash")}

    def bake_bytes(data, steps):  # byte-exact: hex in, hex out (text outputs as UTF-8)
        tail = cc("Encode text", "UTF-8 (65001)") if op_config[steps[-1]["op"]]["outputType"] == "string" else []
        out = chef.bake(data.hex(), cc("From Hex", "Auto") + steps + tail + cc("To Hex", "None", 0))
        return bytes.fromhex(out)

    ok, bad, unchecked, by_method = 0, [], {}, {}
    for case in cases:
        if not case.layers or case.expected == "-":
            continue
        if case.category == "hash":
            got = chef.bake(case.expected, hashes[case.layers[0]])
            by_method["cyberchef (hash of the answer)"] = by_method.get("cyberchef (hash of the answer)", 0) + 1
            if got.lower() == case.input.lower():
                ok += 1
            else:
                bad.append((case.id, got, case.input))
            continue
        missing = [n for n in case.layers if not CC_STEPS.get(n) and n not in py]
        if missing:
            for n in missing:
                unchecked.setdefault(n, []).append(case.id)
            continue
        data = case.input.encode()
        pending, used = [], set()
        try:
            for n in reversed(case.layers):  # outermost first
                if CC_STEPS.get(n):
                    pending += CC_STEPS[n]
                    used.add("cyberchef")
                else:
                    if pending:
                        data, pending = bake_bytes(data, pending), []
                    data = py[n](data)
                    used.add("python")
            if pending:
                data = bake_bytes(data, pending)
        except Exception as e:  # a decoder that fails is a mismatch
            bad.append((case.id, f"error: {str(e).splitlines()[0][:100]}", case.expected))
            continue
        method = "+".join(sorted(used))
        by_method[method] = by_method.get(method, 0) + 1
        got = data.decode("utf-8", "replace")
        mode = "letters" if LETTERS_ONLY & set(case.layers) else case.match
        if normalize(got, mode) == normalize(case.expected, mode):
            ok += 1
        else:
            bad.append((case.id, got, case.expected))
    print(f"verified {ok} cases ({by_method}); {len(bad)} mismatches; layers without a second implementation: "
          + ", ".join(f"{n} ({len(v)})" for n, v in sorted(unchecked.items())))
    for cid, got, exp in bad:
        print(f"MISMATCH {cid}: got {got!r:.120} expected {exp!r:.120}")
    return 1 if bad else 0
