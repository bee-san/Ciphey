#!/usr/bin/env python3
"""Generate corpus v1 of Ciphey's end-to-end benchmark (benches/data/e2e/corpus-v1.tsv).

The corpus is frozen: it was generated once with SEED and committed, and this script must
reproduce it byte for byte (`--check`). Changing the cases means a new version
(corpus-v2.tsv) so that results stay comparable. See docs/benchmark-e2e.md.

Every ciphertext comes from an implementation that is independent of Ciphey's decoders:
Python's standard library, PyPI reference packages (pinned in setup.sh), CyberChef's
operations (through cyberchef.py) or a short encoder written here from the published
definition, cited next to it. `--verify` decodes every case again with a second, independent
implementation where one exists. Which cases CyberChef is comparable on comes from Magic's
own detection (cyberchef_tools), so generating needs the CyberChef install too.

    benches/e2e/setup.sh gen && benches/e2e/setup.sh node                     # into .tools/
    .tools/gen/bin/python benches/e2e/corpus.py --cyberchef .tools/node          # write
    .tools/gen/bin/python benches/e2e/corpus.py --cyberchef .tools/node --check  # compare
    .tools/gen/bin/python benches/e2e/corpus.py --cyberchef .tools/node --verify # decode again
"""

import argparse
import base64
import binascii
import bz2
import email.charset
import email.header
import gzip
import hashlib
import hmac
import json
import lzma
import math
import os
import quopri
import random
import re
import string
import sys
import urllib.parse
import warnings
import zlib

warnings.filterwarnings("ignore", category=SyntaxWarning)  # pycipher 0.5.2's regex strings

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
DATA = os.path.join(ROOT, "benches", "data", "e2e")
VERSION = 1
SEED = 20261104
OUT = os.path.join(DATA, f"corpus-v{VERSION}.tsv")

# Tools a case can be comparable on. Every case runs on Ciphey.
CIPHEY, PY, CC, CCI = "ciphey", "python-ciphey", "cyberchef", "cyberchef-intensive"

# ---------------------------------------------------------------------------------------
# Helpers


def u(data):
    """bytes -> str (UTF-8)."""
    return data.decode("utf-8")


def text(fn):
    """Lifts a str -> str encoder to the bytes -> bytes interface."""

    def wrapped(data, rng):
        return fn(u(data), rng).encode("utf-8")

    wrapped.__name__ = fn.__name__
    return wrapped


def to_radix(n, digits):
    if n == 0:
        return digits[0]
    out = []
    while n:
        n, r = divmod(n, len(digits))
        out.append(digits[r])
    return "".join(reversed(out))


def shift_letters(s, k):
    """Caesar shift by k, keeping case and everything that isn't an ASCII letter."""
    out = []
    for c in s:
        if "A" <= c <= "Z":
            out.append(chr((ord(c) - 65 + k) % 26 + 65))
        elif "a" <= c <= "z":
            out.append(chr((ord(c) - 97 + k) % 26 + 97))
        else:
            out.append(c)
    return "".join(out)


def map_letters(s, fn):
    """Applies fn(index of letter among the letters, value 0-25) -> 0-25 to every ASCII letter,
    keeping case and non-letters."""
    out, i = [], 0
    for c in s:
        if c.isascii() and c.isalpha():
            base = 65 if c.isupper() else 97
            out.append(chr(fn(i, ord(c) - base) % 26 + base))
            i += 1
        else:
            out.append(c)
    return "".join(out)


def letters_only(s):
    return "".join(c for c in s.upper() if "A" <= c <= "Z")


# ---------------------------------------------------------------------------------------
# Encoders: (data: bytes, rng) -> bytes. Text encoders work on the UTF-8 text.

# Base encodings (Python stdlib, RFC 4648)
def b64(data, rng):
    return base64.b64encode(data)


def b64url(data, rng):  # RFC 4648 §5 alphabet, padding dropped as in JWTs and URLs
    return base64.urlsafe_b64encode(data).rstrip(b"=")


B64_STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def b64_itoa64(data, rng):  # crypt(3)'s itoa64 alphabet, CyberChef's "itoa64" From Base64 preset
    alt = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    return base64.b64encode(data).translate(bytes.maketrans(B64_STD.encode(), alt.encode()))


def b32(data, rng):
    return base64.b32encode(data)


def b32hex(data, rng):  # RFC 4648 §7
    return base64.b32hexencode(data)


B32_STD = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


def b32_crockford(data, rng):  # https://www.crockford.com/base32.html, 5 bits at a time
    return base64.b32encode(data).rstrip(b"=").translate(bytes.maketrans(B32_STD, b"0123456789ABCDEFGHJKMNPQRSTVWXYZ"))


def zbase32(data, rng):  # https://philzimmermann.com/docs/human-oriented-base-32-encoding.txt
    return base64.b32encode(data).rstrip(b"=").translate(bytes.maketrans(B32_STD, b"ybndrfg8ejkmcpqxot1uwisza345h769"))


def b16_spaced(data, rng):
    return " ".join(f"{x:02X}" for x in data).encode()


def hexlower(data, rng):
    return data.hex().encode()


def base36(data, rng):  # int.from_bytes(text, "big") in radix 36, as PyPI base36.dumps
    return to_radix(int.from_bytes(data, "big"), "0123456789abcdefghijklmnopqrstuvwxyz").encode()


def bigint(data, rng):  # PyCryptodome bytes_to_long
    return str(int.from_bytes(data, "big")).encode()


def bigint_named(data, rng):  # as RSA challenges print it
    return f"m = {int.from_bytes(data, 'big')}".encode()


def b45(data, rng):  # RFC 9285, PyPI base45
    import base45

    return base45.b45encode(data)


def _b58(alphabet):
    def enc(data, rng):
        import base58

        return base58.b58encode(data, alphabet=alphabet)

    return enc


B58_BITCOIN = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
B58_RIPPLE = b"rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"
B58_FLICKR = b"123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ"
b58_bitcoin, b58_ripple, b58_flickr = _b58(B58_BITCOIN), _b58(B58_RIPPLE), _b58(B58_FLICKR)


def b58_monero(data, rng):
    # Monero's base58 (src/common/base58.cpp): 8-byte blocks, each written big-endian in a
    # fixed number of digits (11 for a full block), Bitcoin's alphabet.
    full_size = [0, 2, 3, 5, 6, 7, 9, 10, 11]
    out = []
    for i in range(0, len(data), 8):
        block = data[i : i + 8]
        n = int.from_bytes(block, "big")
        digits = []
        for _ in range(full_size[len(block)]):
            n, r = divmod(n, 58)
            digits.append(B58_BITCOIN[r : r + 1])
        out.append(b"".join(reversed(digits)))
    return b"".join(out)


def b62(data, rng):  # PyPI pybase62 encodebytes (what Python Ciphey decodes)
    import base62

    return base62.encodebytes(data).encode()


def b65536(data, rng):  # PyPI base65536 (qntm's encoding)
    import base65536

    return base65536.encode(data).encode()


def b85(data, rng):  # RFC 1924 alphabet, 4-byte groups (git, Python's b85encode)
    return base64.b85encode(data)


def a85(data, rng):
    return base64.a85encode(data)


def a85_adobe(data, rng):
    return base64.a85encode(data, adobe=True)


Z85_ALPHABET = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#"


def z85(data, rng):  # ZeroMQ RFC 32 (https://rfc.zeromq.org/spec/32/); length a multiple of 4
    assert len(data) % 4 == 0
    out = []
    for i in range(0, len(data), 4):
        n = int.from_bytes(data[i : i + 4], "big")
        chunk = []
        for _ in range(5):
            n, r = divmod(n, 85)
            chunk.append(Z85_ALPHABET[r : r + 1])
        out.append(b"".join(reversed(chunk)))
    return b"".join(out)


def b91(data, rng):  # PyPI base91 (basE91, Joachim Henke)
    import base91

    return base91.encode(data).encode()


def b92(data, rng):  # PyPI base92 (thenoviceoof's Base92)
    import base92

    out = base92.encode(data)
    return out.encode() if isinstance(out, str) else out


def b100(data, rng):  # AdamNiederer/base100: byte b is U+1F3F7 + b
    return "".join(chr(0x1F3F7 + x) for x in data).encode()


def uuencode(data, rng):  # binascii.b2a_uu, with the header and trailer of uuencode(1)
    lines = ["begin 644 message.txt"]
    for i in range(0, len(data), 45):
        lines.append(binascii.b2a_uu(data[i : i + 45], backtick=True).decode().rstrip("\n"))
    lines += ["`", "end"]
    return "\n".join(lines).encode()


XX_ALPHABET = "+-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def xxencode(data, rng):  # uuencode's layout with the xxencode alphabet (xxencode(1))
    lines = ["begin 644 message.txt"]
    for i in range(0, len(data), 45):
        chunk = data[i : i + 45]
        line = [XX_ALPHABET[len(chunk)]]
        padded = chunk + b"\0" * (-len(chunk) % 3)
        for j in range(0, len(padded), 3):
            n = int.from_bytes(padded[j : j + 3], "big")
            line += [XX_ALPHABET[(n >> s) & 63] for s in (18, 12, 6, 0)]
        lines.append("".join(line))
    lines += [XX_ALPHABET[0], "end"]
    return "\n".join(lines).encode()


BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _bech32_polymod(values):  # BIP-173 reference (sipa/bech32, MIT)
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if ((top >> i) & 1) else 0
    return chk


def _convertbits(data, frombits, tobits):
    acc = bits = 0
    out = []
    maxv = (1 << tobits) - 1
    for value in data:
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            out.append((acc >> bits) & maxv)
    if bits:
        out.append((acc << (tobits - bits)) & maxv)
    return out


def bech32(data, rng, hrp="msg"):
    values = _convertbits(data, 8, 5)
    expanded = [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]
    polymod = _bech32_polymod(expanded + values + [0] * 6) ^ 1
    checksum = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    return (hrp + "1" + "".join(BECH32_CHARSET[d] for d in values + checksum)).encode()


def modhex(data, rng):  # YubiKey modhex: hex digits 0-f written as cbdefghijklnrtuv
    return data.hex().translate(str.maketrans("0123456789abcdef", "cbdefghijklnrtuv")).encode()


def bubblebabble(data, rng):  # Antti Huima's Bubble Babble spec (OpenSSH's sshkey fingerprints)
    vowels, cons = "aeiouy", "bcdfghklmnprstvzx"
    out, seed = ["x"], 1
    rounds = len(data) // 2 + 1
    for i in range(rounds):
        if i + 1 < rounds or len(data) % 2:
            b1 = data[2 * i]
            out += [vowels[(((b1 >> 6) & 3) + seed) % 6], cons[(b1 >> 2) & 15], vowels[((b1 & 3) + seed // 6) % 6]]
            if i + 1 < rounds:
                b2 = data[2 * i + 1]
                out += [cons[(b2 >> 4) & 15], "-", cons[b2 & 15]]
                seed = (seed * 5 + b1 * 7 + b2) % 36
        else:
            out += [vowels[seed % 6], cons[16], vowels[seed // 6]]
    out.append("x")
    return "".join(out).encode()


def ternary(data, rng):  # each byte in base 3, space-separated (dCode "base-N" char codes)
    return " ".join(to_radix(x, "012") for x in data).encode()


def chucknorris(data, rng):  # 7-bit ASCII, runs written as "0 0..." (ones) / "00 0..." (zeros)
    bits = "".join(f"{x:07b}" for x in data)
    return " ".join(("0 " if m.group()[0] == "1" else "00 ") + "0" * len(m.group()) for m in re.finditer(r"0+|1+", bits)).encode()


def manchester(data, rng):  # IEEE 802.3 convention: 0 -> 01, 1 -> 10
    return "".join("10" if bit == "1" else "01" for bit in "".join(f"{x:08b}" for x in data)).encode()


def dna2bit(data, rng):  # A=00 C=01 G=10 T=11, four nucleotides per byte
    return "".join("ACGT"[(x >> s) & 3] for x in data for s in (6, 4, 2, 0)).encode()


# Numbers and text escapes
def binary(data, rng):
    return " ".join(f"{x:08b}" for x in data).encode()


def decimal(data, rng):
    return " ".join(str(x) for x in data).encode()


def octal(data, rng):
    return " ".join(f"{x:03o}" for x in data).encode()


@text
def url(s, rng):  # urllib.parse.quote, nothing kept safe
    return urllib.parse.quote(s, safe="")


def url_all(data, rng):  # every byte percent-encoded, as CTFs and CyberChef's "Encode all special chars" do
    return "".join(f"%{x:02X}" for x in data).encode()


@text
def html_dec(s, rng):
    return "".join(f"&#{ord(c)};" for c in s)


@text
def html_hex(s, rng):
    return "".join(f"&#x{ord(c):x};" for c in s)


@text
def uni_escape(s, rng):  # \uXXXX (JavaScript, JSON, Java)
    return "".join(f"\\u{ord(c):04x}" for c in s)


@text
def uni_plus(s, rng):  # U+XXXX, space-separated
    return " ".join(f"U+{ord(c):04X}" for c in s)


def bs_octal(data, rng):
    return "".join(f"\\{x:03o}" for x in data).encode()


def bs_hex(data, rng):
    return "".join(f"\\x{x:02x}" for x in data).encode()


def qp(data, rng):  # RFC 2045, Python's quopri
    return quopri.encodestring(data).rstrip(b"\n")


@text
def mime_b(s, rng):  # RFC 2047 B encoding, email.header
    return email.header.Header(s, "utf-8").encode()


@text
def mime_q(s, rng):  # RFC 2047 Q encoding, email.header
    cs = email.charset.Charset("utf-8")
    cs.header_encoding = email.charset.QP
    return email.header.Header(s, cs).encode()


@text
def punycode(s, rng):  # IDNA 2003 (Python's idna codec): xn-- labels
    return s.encode("idna").decode("ascii")


@text
def utf7(s, rng):
    return s.encode("utf-7").decode("ascii")


def utf16le(data, rng):
    return u(data).encode("utf-16-le")


def utf16be_bom(data, rng):  # big-endian with a byte order mark
    return b"\xfe\xff" + u(data).encode("utf-16-be")


def ebcdic(data, rng):  # IBM code page 037
    return u(data).encode("cp037")


def xxd(data, rng):  # the layout of `xxd`
    lines = []
    for off in range(0, len(data), 16):
        chunk = data[off : off + 16]
        groups = " ".join(chunk[i : i + 2].hex() for i in range(0, len(chunk), 2))
        ascii_ = "".join(chr(x) if 32 <= x < 127 else "." for x in chunk)
        lines.append(f"{off:08x}: {groups:<39}  {ascii_}")
    return "\n".join(lines).encode()


def hexdump_c(data, rng):  # the layout of `hexdump -C`
    lines = []
    for off in range(0, len(data), 16):
        chunk = [f"{x:02x}" for x in data[off : off + 16]]
        ascii_ = "".join(chr(x) if 32 <= x < 127 else "." for x in data[off : off + 16])
        lines.append(f"{off:08x}  {' '.join(chunk[:8]):<23}  {' '.join(chunk[8:]):<23}  |{ascii_}|")
    lines.append(f"{len(data):08x}")
    return "\n".join(lines).encode()


# Compression (the bytes then need a text layer: Base64 or hex)
def gz(data, rng):
    return gzip.compress(data, mtime=0)


def zl(data, rng):
    return zlib.compress(data, 9)


def deflate(data, rng):
    c = zlib.compressobj(9, zlib.DEFLATED, -15)
    return c.compress(data) + c.flush()


def bz(data, rng):
    return bz2.compress(data, 9)


def xz(data, rng):
    return lzma.compress(data, format=lzma.FORMAT_XZ)


def zstd(data, rng):  # PyPI zstandard
    import zstandard

    return zstandard.ZstdCompressor(level=3).compress(data)


def lz4frame(data, rng):  # PyPI lz4
    import lz4.frame

    return lz4.frame.compress(data)


@text
def lzstring_b64(s, rng):  # PyPI lzstring: LZString.compressToBase64
    import lzstring

    return lzstring.LZString().compressToBase64(s)


# Bytes ciphers
def xor1(key):
    def enc(data, rng):
        return bytes(x ^ key for x in data)

    enc.__name__ = f"xor1_{key:02x}"
    return enc


def xorkey(key):
    def enc(data, rng):
        return bytes(x ^ key[i % len(key)] for i, x in enumerate(data))

    enc.__name__ = "xorkey_" + key.decode()
    return enc


def rotl(n):
    def enc(data, rng):
        return bytes(((x << n) | (x >> (8 - n))) & 0xFF for x in data)

    return enc


def bitnot(data, rng):
    return bytes(x ^ 0xFF for x in data)


def ascii_shift(k, mod=256):
    def enc(data, rng):  # c = (p + k) mod m, written as Latin-1 text (CyberChef ADD)
        return "".join(chr((x + k) % mod) for x in data).encode("utf-8")

    return enc


# Symbol codes. Tables written out from their standards.
MORSE = {  # ITU-R M.1677-1
    "A": ".-", "B": "-...", "C": "-.-.", "D": "-..", "E": ".", "F": "..-.", "G": "--.", "H": "....",
    "I": "..", "J": ".---", "K": "-.-", "L": ".-..", "M": "--", "N": "-.", "O": "---", "P": ".--.",
    "Q": "--.-", "R": ".-.", "S": "...", "T": "-", "U": "..-", "V": "...-", "W": ".--", "X": "-..-",
    "Y": "-.--", "Z": "--..", "0": "-----", "1": ".----", "2": "..---", "3": "...--", "4": "....-",
    "5": ".....", "6": "-....", "7": "--...", "8": "---..", "9": "----.", ".": ".-.-.-", ",": "--..--",
    "?": "..--..", "'": ".----.", "!": "-.-.--", "/": "-..-.", "(": "-.--.", ")": "-.--.-", "&": ".-...",
    ":": "---...", ";": "-.-.-.", "=": "-...-", "+": ".-.-.", "-": "-....-", "_": "..--.-", '"': ".-..-.",
    "@": ".--.-.",
}


def _morse_words(s):
    return [[MORSE[c] for c in w] for w in s.upper().split()]


@text
def morse(s, rng):  # letters separated by spaces, words by " / "
    return " / ".join(" ".join(w) for w in _morse_words(s))


@text
def morse_lines(s, rng):  # CyberChef's To Morse Code default: words on separate lines
    return "\n".join(" ".join(w) for w in _morse_words(s))


@text
def morse_symbols(s, rng):  # Morse written with other symbols: _ for a dash
    return " / ".join(" ".join(m.replace("-", "_") for m in w) for w in _morse_words(s))


@text
def binary_xy(s, rng):  # binary written with two letters, X = 0 and Y = 1
    return " ".join(f"{x:08b}".replace("0", "X").replace("1", "Y") for x in s.encode())


BRAILLE = dict(zip(string.ascii_lowercase, "⠁⠃⠉⠙⠑⠋⠛⠓⠊⠚⠅⠇⠍⠝⠕⠏⠟⠗⠎⠞⠥⠧⠺⠭⠽⠵"))  # Unicode braille, grade 1


@text
def braille(s, rng):
    return "".join(BRAILLE.get(c, c) for c in s.lower())


@text
def a1z26(s, rng):  # dCode's style: letters joined by "-", words by spaces
    return " ".join("-".join(str(ord(c) - 96) for c in w if c.isalpha()) for w in s.lower().split())


@text
def bacon26(s, rng):  # Bacon's cipher with 26 distinct letters, A = AAAAA ... Z = BBAAB
    return " ".join(f"{ord(c) - 65:05b}".replace("0", "A").replace("1", "B") for c in letters_only(s))


POLYBIUS = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # 5x5, I and J share a cell


@text
def polybius(s, rng):
    return " ".join(f"{POLYBIUS.index(c) // 5 + 1}{POLYBIUS.index(c) % 5 + 1}" for c in letters_only(s).replace("J", "I"))


TAP = "ABCDEFGHIJLMNOPQRSTUVWXYZ"  # tap code square: no K, it is sent as C


def _tap_cells(s):
    return [divmod(TAP.index(c), 5) for c in letters_only(s).replace("K", "C")]


@text
def tap_dots(s, rng):  # each letter as two groups of taps
    return "  ".join("." * (r + 1) + " " + "." * (c + 1) for r, c in _tap_cells(s))


@text
def tap_digits(s, rng):
    return " ".join(f"{r + 1},{c + 1}" for r, c in _tap_cells(s))


KEYPAD = {"2": "ABC", "3": "DEF", "4": "GHI", "5": "JKL", "6": "MNO", "7": "PQRS", "8": "TUV", "9": "WXYZ"}  # ITU-T E.161
KEY_OF = {c: k for k, cs in KEYPAD.items() for c in cs}


@text
def t9(s, rng):
    return " ".join("".join(KEY_OF[c] for c in w if c in KEY_OF) for w in s.upper().split())


@text
def multitap(s, rng):  # presses separated by spaces, 0 for a space
    return " 0 ".join(" ".join(KEY_OF[c] * (KEYPAD[KEY_OF[c]].index(c) + 1) for c in w if c in KEY_OF) for w in s.upper().split())


DTMF_ROWS, DTMF_COLS = (697, 770, 852, 941), (1209, 1336, 1477, 1633)
DTMF_KEYS = ["123A", "456B", "789C", "*0#D"]


@text
def dtmf(s, rng):  # each key as its "low-high" frequency pair in Hz
    return " ".join(f"{DTMF_ROWS[r]}-{DTMF_COLS[row.index(c)]}" for c in s for r, row in enumerate(DTMF_KEYS) if c in row)


NATO = "Alfa Bravo Charlie Delta Echo Foxtrot Golf Hotel India Juliett Kilo Lima Mike November Oscar Papa Quebec Romeo Sierra Tango Uniform Victor Whiskey X-ray Yankee Zulu".split()


@text
def nato(s, rng):
    return " / ".join(" ".join(NATO[ord(c) - 65] for c in w if "A" <= c <= "Z") for w in s.upper().split())


def _galactic():
    import cipheydists  # LingoJam's Standard Galactic Alphabet, as Python Ciphey ships it

    return {v: k for k, v in cipheydists.get_translate("galactic").items()}


@text
def galactic(s, rng):
    table = _galactic()
    return "".join(table.get(c, c) for c in s.lower())


LEET = str.maketrans({"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7"})


@text
def leet(s, rng):
    return s.lower().translate(LEET)


@text
def fancy_bold(s, rng):  # Mathematical Bold (U+1D400 block)
    out = []
    for c in s:
        if "a" <= c <= "z":
            out.append(chr(0x1D41A + ord(c) - 97))
        elif "A" <= c <= "Z":
            out.append(chr(0x1D400 + ord(c) - 65))
        elif "0" <= c <= "9":
            out.append(chr(0x1D7CE + ord(c) - 48))
        else:
            out.append(c)
    return "".join(out)


@text
def fullwidth(s, rng):  # Halfwidth and Fullwidth Forms (U+FF01 to U+FF5E), U+3000 for a space
    return "".join("\u3000" if c == " " else chr(ord(c) + 0xFEE0) if "!" <= c <= "~" else c for c in s)


ZW0, ZW1, ZWSEP = "\u200b", "\u200c", "\u200d"


@text
def zw_binary(s, rng):  # zero-width space = 0, zero-width non-joiner = 1, after a cover word
    bits = "".join(f"{x:08b}" for x in s.encode())
    return "Nothing" + bits.replace("0", ZW0).replace("1", ZW1) + " to see here, move along."


@text
def zw_separated(s, rng):  # the same, with a zero-width joiner between the bytes
    hidden = ZWSEP.join(f"{x:08b}".replace("0", ZW0).replace("1", ZW1) for x in s.encode())
    return "Just an ordinary" + hidden + " sentence."


QWERTY = ["`1234567890-=", "qwertyuiop[]\\", "asdfghjkl;'", "zxcvbnm,./", '~!@#$%^&*()_+', "QWERTYUIOP{}|", 'ASDFGHJKL:"', "ZXCVBNM<>?"]
DVORAK = ["`1234567890[]", "',.pyfgcrl/=\\", "aoeuidhtns-", ";qjkxbmwvz", "~!@#$%^&*(){}", '"<>PYFGCRL?+|', "AOEUIDHTNS_", ":QJKXBMWVZ"]


@text
def qwerty_as_dvorak(s, rng):  # typed on QWERTY keys, read as Dvorak
    table = {q: d for qr, dr in zip(QWERTY, DVORAK) for q, d in zip(qr, dr)}
    return "".join(table.get(c, c) for c in s)


@text
def kbd_shift_right(s, rng):  # every key replaced by its right-hand neighbour on US QWERTY, wrapping
    table = {row[i]: row[(i + 1) % len(row)] for row in QWERTY for i in range(len(row))}
    return "".join(table.get(c, c) for c in s)


ACROSTIC_WORDS = {  # own word list for null-cipher cover texts
    "A": ["all", "after", "apples", "and"], "B": ["big", "brown", "bears"], "C": ["can", "carry", "cakes"],
    "D": ["dogs", "do", "dance"], "E": ["every", "evening", "eagerly"], "F": ["four", "friendly", "foxes"],
    "G": ["green", "gardens", "grow"], "H": ["happy", "horses", "hum"], "I": ["in", "ice", "igloos"],
    "J": ["jolly", "jugglers", "jump"], "K": ["kind", "kings", "knit"], "L": ["little", "lambs", "laugh"],
    "M": ["many", "mice", "march"], "N": ["nine", "nimble", "newts"], "O": ["old", "owls", "observe"],
    "P": ["purple", "parrots", "play"], "Q": ["quiet", "queens", "quilt"], "R": ["red", "rabbits", "run"],
    "S": ["seven", "silly", "sheep"], "T": ["ten", "tiny", "turtles"], "U": ["under", "umbrellas", "usually"],
    "V": ["very", "vain", "vultures"], "W": ["white", "wolves", "wander"], "X": ["xylophones"],
    "Y": ["yellow", "yaks", "yawn"], "Z": ["zany", "zebras", "zigzag"],
}


def null_acrostic(data, rng):  # the first letter of each word spells the message
    words = [rng.choice(ACROSTIC_WORDS[c]) for c in letters_only(u(data))]
    return (" ".join(words).capitalize() + ".").encode()


def pollux(data, rng):  # ACA Pollux: Morse, x between letters and xx between words, digits per class
    classes = {".": "147", "-": "258", "x": "3690"}
    morse_text = "xx".join("x".join(MORSE[c] for c in w) for w in u(data).upper().split())
    return "".join(rng.choice(classes[sym]) for sym in morse_text).encode()


@text
def yunying(s, rng):  # 01248 cipher: letter value as 8, 4, 2 and 1 summing to it, letters split by 0
    groups = []
    for c in letters_only(s):
        v, digits = ord(c) - 64, []
        for d in (8, 4, 2, 1):
            while v >= d:
                digits.append(str(d))
                v -= d
        groups.append("".join(digits))
    return "0".join(groups)


CODON = {  # one codon of the standard genetic code (NCBI table 1) per amino-acid letter
    "A": "GCT", "C": "TGT", "D": "GAT", "E": "GAA", "F": "TTT", "G": "GGT", "H": "CAT", "I": "ATT", "K": "AAA",
    "L": "CTG", "M": "ATG", "N": "AAT", "P": "CCA", "Q": "CAG", "R": "CGT", "S": "AGC", "T": "ACC", "V": "GTG",
    "W": "TGG", "Y": "TAC", " ": "TAA",
}


@text
def dna_codon(s, rng):
    return " ".join(CODON[c] for c in s.upper())


ITA2_LTRS = {  # ITA2 letters, value with bit 1 least significant ("543.21"): A = 00011
    "E": 1, "\n": 2, "A": 3, " ": 4, "S": 5, "I": 6, "U": 7, "\r": 8, "D": 9, "R": 10, "J": 11, "N": 12,
    "F": 13, "C": 14, "K": 15, "T": 16, "Z": 17, "L": 18, "W": 19, "H": 20, "Y": 21, "P": 22, "Q": 23,
    "O": 24, "B": 25, "G": 26, "M": 28, "X": 29, "V": 30,
}


@text
def baudot(s, rng):
    return " ".join(f"{ITA2_LTRS[c]:05b}" for c in s.upper())


CSV_VALUES = ["富强", "民主", "文明", "和谐", "自由", "平等", "公正", "法治", "爱国", "敬业", "诚信", "友善"]


def core_values(data, rng):
    # sym233/core-values-encoder: upper-case hex of the UTF-8 bytes in base 12; a hex digit
    # n >= 10 is written as 10, n - 10 or as 11, n - 6, picked at random.
    digits = []
    for c in data.hex().upper():
        n = int(c, 16)
        if n < 10:
            digits.append(n)
        elif rng.random() >= 0.5:
            digits += [10, n - 10]
        else:
            digits += [11, n - 6]
    return "".join(CSV_VALUES[d] for d in digits).encode()


# Esoteric languages
def bf_program(data):
    """A Brainfuck program that prints `data`: cell 0 holds the character, cell 1 counts loops."""
    out, cur = [], 0
    for x in data:
        d = x - cur
        sign = "+" if d > 0 else "-"
        if abs(d) > 12:
            q, r = divmod(abs(d), 10)
            out.append(">" + "+" * 10 + "[<" + sign * q + ">-]<" + sign * r)
        else:
            out.append(sign * abs(d))
        out.append(".")
        cur = x
    return "".join(out)


def brainfuck(data, rng):
    return bf_program(data).encode()


OOK = {">": "Ook. Ook?", "<": "Ook? Ook.", "+": "Ook. Ook.", "-": "Ook! Ook!", ".": "Ook! Ook.", ",": "Ook. Ook!", "[": "Ook! Ook?", "]": "Ook? Ook!"}
PIKALANG = {">": "pipi", "<": "pichu", "+": "pi", "-": "ka", ".": "pikachu", ",": "pikapi", "[": "pika", "]": "chu"}


def ook(data, rng):
    return " ".join(OOK[c] for c in bf_program(data)).encode()


def blub(data, rng):
    return " ".join(OOK[c].replace("Ook", "Blub") for c in bf_program(data)).encode()


def pikalang(data, rng):
    return " ".join(PIKALANG[c] for c in bf_program(data)).encode()


def whitespace_lang(data, rng):  # Whitespace: push each byte, print it as a character, end
    prog = []
    for x in data:
        prog.append("  " + " " + f"{x:b}".replace("0", " ").replace("1", "\t") + "\n")
        prog.append("\t\n  ")
    prog.append("\n\n\n")
    return "".join(prog).encode()


AA_DIGITS = [
    "(c^_^o)", "(ﾟΘﾟ)", "((o^_^o) - (ﾟΘﾟ))", "(o^_^o)", "(ﾟｰﾟ)", "((ﾟｰﾟ) + (ﾟΘﾟ))", "((o^_^o) +(o^_^o))",
    "((ﾟｰﾟ) + (o^_^o))", "((ﾟｰﾟ) + (ﾟｰﾟ))", "((ﾟｰﾟ) + (ﾟｰﾟ) + (ﾟΘﾟ))", "(ﾟДﾟ) .ﾟωﾟﾉ", "(ﾟДﾟ) .ﾟΘﾟﾉ",
    "(ﾟДﾟ) ['c']", "(ﾟДﾟ) .ﾟｰﾟﾉ", "(ﾟДﾟ) .ﾟДﾟﾉ", "(ﾟДﾟ) [ﾟΘﾟ]",
]
AA_HEAD = (
    "ﾟωﾟﾉ= /｀ｍ´）ﾉ ~┻━┻   //*´∇｀*/ ['_']; o=(ﾟｰﾟ)  =_=3; c=(ﾟΘﾟ) =(ﾟｰﾟ)-(ﾟｰﾟ); "
    "(ﾟДﾟ) =(ﾟΘﾟ)= (o^_^o)/ (o^_^o);"
    "(ﾟДﾟ)={ﾟΘﾟ: '_' ,ﾟωﾟﾉ : ((ﾟωﾟﾉ==3) +'_') [ﾟΘﾟ] "
    ",ﾟｰﾟﾉ :(ﾟωﾟﾉ+ '_')[o^_^o -(ﾟΘﾟ)] "
    ",ﾟДﾟﾉ:((ﾟｰﾟ==3) +'_')[ﾟｰﾟ] }; (ﾟДﾟ) [ﾟΘﾟ] =((ﾟωﾟﾉ==3) +'_') [c^_^o];"
    "(ﾟДﾟ) ['c'] = ((ﾟДﾟ)+'_') [ (ﾟｰﾟ)+(ﾟｰﾟ)-(ﾟΘﾟ) ];"
    "(ﾟДﾟ) ['o'] = ((ﾟДﾟ)+'_') [ﾟΘﾟ];"
    "(ﾟoﾟ)=(ﾟДﾟ) ['c']+(ﾟДﾟ) ['o']+(ﾟωﾟﾉ +'_')[ﾟΘﾟ]+ ((ﾟωﾟﾉ==3) +'_') [ﾟｰﾟ] + "
    "((ﾟДﾟ) +'_') [(ﾟｰﾟ)+(ﾟｰﾟ)]+ ((ﾟｰﾟ==3) +'_') [ﾟΘﾟ]+"
    "((ﾟｰﾟ==3) +'_') [(ﾟｰﾟ) - (ﾟΘﾟ)]+(ﾟДﾟ) ['c']+"
    "((ﾟДﾟ)+'_') [(ﾟｰﾟ)+(ﾟｰﾟ)]+ (ﾟДﾟ) ['o']+"
    "((ﾟｰﾟ==3) +'_') [ﾟΘﾟ];(ﾟДﾟ) ['_'] =(o^_^o) [ﾟoﾟ] [ﾟoﾟ];"
    "(ﾟεﾟ)=((ﾟｰﾟ==3) +'_') [ﾟΘﾟ]+ (ﾟДﾟ) .ﾟДﾟﾉ+"
    "((ﾟДﾟ)+'_') [(ﾟｰﾟ) + (ﾟｰﾟ)]+((ﾟｰﾟ==3) +'_') [o^_^o -ﾟΘﾟ]+"
    "((ﾟｰﾟ==3) +'_') [ﾟΘﾟ]+ (ﾟωﾟﾉ +'_') [ﾟΘﾟ]; "
    "(ﾟｰﾟ)+=(ﾟΘﾟ); (ﾟДﾟ)[ﾟεﾟ]='\\\\'; "
    "(ﾟДﾟ).ﾟΘﾟﾉ=(ﾟДﾟ+ ﾟｰﾟ)[o^_^o -(ﾟΘﾟ)];"
    "(oﾟｰﾟo)=(ﾟωﾟﾉ +'_')[c^_^o];"
    "(ﾟДﾟ) [ﾟoﾟ]='\\\"';"
    "(ﾟДﾟ) ['_'] ( (ﾟДﾟ) ['_'] (ﾟεﾟ+"
    "(ﾟДﾟ)[ﾟoﾟ]+ "
)


@text
def aaencode(s, rng):  # Yosuke Hasegawa's aaencode (utf-8.jp/public/aaencode.html), ported
    out = [AA_HEAD]
    for c in s:
        n = ord(c)
        t = "(ﾟДﾟ)[ﾟεﾟ]+"
        if n <= 127:
            t += "".join(AA_DIGITS[int(d)] + "+ " for d in f"{n:o}")
        else:
            t += "(oﾟｰﾟo)+ " + "".join(AA_DIGITS[int(d, 16)] + "+ " for d in f"{n:04x}"[-4:])
        out.append(t)
    out.append("(ﾟДﾟ)[ﾟoﾟ]) (ﾟΘﾟ)) ('_');")
    return "".join(out)


CHEF = None  # the CyberChef client (cyberchef.py), set by main()


@text
def jsfuck(s, rng):  # aemkei/jsfuck, the reference encoder (npm jsfuck), an expression that evaluates to s
    return CHEF.request({"op": "jsfuck", "input": s})["output"]


@text
def citrix_ctx1(s, rng):  # CyberChef's Citrix CTX1 Encode
    return CHEF.bake(s, [{"op": "Citrix CTX1 Encode", "args": []}])


@text
def rot8000(s, rng):  # CyberChef's ROT8000
    return CHEF.bake(s, [{"op": "ROT8000", "args": []}])


@text
def a1z26_cyberchef(s, rng):  # CyberChef's A1Z26 Cipher Encode, space-delimited
    return CHEF.bake(s, [{"op": "A1Z26 Cipher Encode", "args": ["Space"]}])


@text
def bacon24_cyberchef(s, rng):  # CyberChef's Bacon Cipher Encode, I=J and U=V, A/B
    return CHEF.bake(s, [{"op": "Bacon Cipher Encode", "args": ["Standard (I=J and U=V)", "A/B", False, False]}])


def jwt_hs256(data, rng):  # RFC 7519, HS256 with the key "secret"; the payload is the plaintext
    def enc(b):
        return base64.urlsafe_b64encode(b).rstrip(b"=")

    signing = enc(b'{"alg":"HS256","typ":"JWT"}') + b"." + enc(data)
    return signing + b"." + enc(hmac.new(b"secret", signing, hashlib.sha256).digest())


KENNY = "mpf"


@text
def kenny(s, rng):  # Kenny code: letter index in base 3 with m, p, f
    out = []
    for c in s:
        if c.isascii() and c.isalpha():
            i = ord(c.lower()) - 97
            code = KENNY[i // 9] + KENNY[i // 3 % 3] + KENNY[i % 3]
            out.append(code.capitalize() if c.isupper() else code)
        else:
            out.append(c)
    return "".join(out)


@text
def pig_latin(s, rng):
    out = []
    for w in s.lower().split():
        m = re.match(r"([^aeiou]*)(.*)", w)
        out.append(w + "way" if not m.group(1) else m.group(2) + m.group(1) + "ay")
    return " ".join(out)


@text
def reverse_words(s, rng):
    return " ".join(w[::-1] for w in s.split(" "))


UPSIDE = dict(zip("abcdefghijklmnopqrstuvwxyz.,'!?", "ɐqɔpǝɟƃɥᴉɾʞlɯuodbɹsʇnʌʍxʎz˙',¡¿"))


@text
def upside_down(s, rng):
    return "".join(UPSIDE.get(c, c) for c in reversed(s.lower()))


def zalgo(data, rng):  # 1 to 3 random combining marks (U+0300 to U+036F) after every letter
    out = []
    for c in u(data):
        out.append(c)
        if c.isalpha():
            out += [chr(rng.randrange(0x300, 0x370)) for _ in range(rng.randint(1, 3))]
    return "".join(out).encode()


RUNES = dict(zip("abcdefghijklmnoprstuwz", "ᚨᛒᚲᛞᛖᚠᚷᚺᛁᛃᚲᛚᛗᚾᛟᛈᚱᛊᛏᚢᚹᛉ"))  # Elder Futhark


@text
def runic(s, rng):
    return "".join(RUNES.get(c, c) for c in s.lower())


CISCO7 = "dsfd;kfoA,.iyewrkldJKDHSUBsgvca69834ncxv9873254k;fg87"


def cisco7(data, rng):  # Cisco IOS "password 7": XOR with a fixed key from a random offset
    seed = rng.randrange(16)
    return (f"{seed:02d}" + "".join(f"{x ^ ord(CISCO7[(seed + i) % len(CISCO7)]):02X}" for i, x in enumerate(data))).encode()


# Classical ciphers (case and non-letters kept unless the cipher has letters only)
def caesar(k):
    return text(lambda s, rng: shift_letters(s, k))


@text
def rot47(s, rng):
    return "".join(chr(33 + (ord(c) - 33 + 47) % 94) if 33 <= ord(c) <= 126 else c for c in s)


@text
def rot18(s, rng):
    return "".join(chr((ord(c) - 48 + 5) % 10 + 48) if "0" <= c <= "9" else c for c in shift_letters(s, 13))


@text
def atbash(s, rng):
    return map_letters(s, lambda i, v: 25 - v)


@text
def reverse(s, rng):
    return s[::-1]


def affine(a, b):
    return text(lambda s, rng: map_letters(s, lambda i, v: a * v + b))


def _key(key):
    return [ord(c) - 65 for c in key.upper()]


def vigenere(key):
    k = _key(key)
    return text(lambda s, rng: map_letters(s, lambda i, v: v + k[i % len(k)]))


def beaufort(key):  # the key letter minus the plaintext letter
    k = _key(key)
    return text(lambda s, rng: map_letters(s, lambda i, v: k[i % len(k)] - v))


def autokey(primer):  # Vigenère with the key stream primer + plaintext
    def enc(s, rng):
        stream = _key(primer) + [ord(c) - 65 for c in letters_only(s)]
        return map_letters(s, lambda i, v: v + stream[i])

    return text(enc)


@text
def trithemius(s, rng):  # progressive Caesar: the i-th letter shifted by i
    return map_letters(s, lambda i, v: v + i)


def substitution(alphabet):
    perm = [ord(c) - 65 for c in alphabet]
    return text(lambda s, rng: map_letters(s, lambda i, v: perm[v]))


def railfence(rails):
    def enc(s, rng):  # zigzag over every character, offset 0 (CyberChef's Rail Fence Cipher Encode)
        rows, r, d = [[] for _ in range(rails)], 0, 1
        for c in s:
            rows[r].append(c)
            if r == 0:
                d = 1
            elif r == rails - 1:
                d = -1
            r += d
        return "".join("".join(row) for row in rows)

    return text(enc)


def redefence(order):
    rails = len(order)

    def enc(s, rng):  # rail fence whose rails are read in the order of the key
        rows, r, d = [[] for _ in range(rails)], 0, 1
        for c in s:
            rows[r].append(c)
            if r == 0:
                d = 1
            elif r == rails - 1:
                d = -1
            r += d
        return "".join("".join(rows[i]) for i in order)

    return text(enc)


def route_columns(ncols):
    def enc(s, rng):  # written row by row in ncols columns, read down the columns (scytale)
        rows = [s[i : i + ncols] for i in range(0, len(s), ncols)]
        return "".join("".join(row[c] for row in rows if c < len(row)) for c in range(ncols))

    return text(enc)


def skip_cipher(k):
    def enc(s, rng):  # every k-th character, cyclically; gcd(k, len) = 1
        assert math.gcd(k, len(s)) == 1
        return "".join(s[(i * k) % len(s)] for i in range(len(s)))

    return text(enc)


def hill2(key=((3, 3), (2, 5))):
    def enc(s, rng):  # 2x2 Hill, C = K.P on column vectors (Wikipedia's example key)
        p = [ord(c) - 65 for c in letters_only(s)]
        assert len(p) % 2 == 0
        out = []
        for i in range(0, len(p), 2):
            x, y = p[i], p[i + 1]
            out += [(key[0][0] * x + key[0][1] * y) % 26, (key[1][0] * x + key[1][1] * y) % 26]
        return "".join(chr(v + 65) for v in out)

    return text(enc)


def keyword_square(keyword, size=25):
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ" if size == 25 else "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    seen = []
    for c in keyword.upper().replace("J", "I") if size == 25 else keyword.upper():
        if c in alphabet and c not in seen:
            seen.append(c)
    return "".join(seen + [c for c in alphabet if c not in seen])


def pycipher(name, *args, **kwargs):
    def enc(s, rng):  # PyPI pycipher, letters only
        import pycipher as pc

        return getattr(pc, name)(*args, **kwargs).encipher(s)

    enc.__name__ = "pycipher_" + name
    return text(enc)


def foursquare(key1, key2):
    plain = "ABCDEFGHIKLMNOPQRSTUVWXYZ"

    def enc(s, rng):  # Delastelle's four-square: plain squares top left and bottom right
        letters = letters_only(s).replace("J", "I")
        assert len(letters) % 2 == 0
        out = []
        for i in range(0, len(letters), 2):
            r1, c1 = divmod(plain.index(letters[i]), 5)
            r2, c2 = divmod(plain.index(letters[i + 1]), 5)
            out += [key1[r1 * 5 + c2], key2[r2 * 5 + c1]]
        return "".join(out)

    return text(enc)


def nihilist(square_key, key):
    def enc(s, rng):  # Polybius coordinates of plaintext + key letters, as numbers
        sq = keyword_square(square_key)
        coord = {c: (i // 5 + 1) * 10 + i % 5 + 1 for i, c in enumerate(sq)}
        kk = [coord[c] for c in key.upper().replace("J", "I")]
        letters = letters_only(s).replace("J", "I")
        return " ".join(str(coord[c] + kk[i % len(kk)]) for i, c in enumerate(letters))

    return text(enc)


def md4(data):
    """MD4 (RFC 1320), for NTLM test data: Python's hashlib has it only with OpenSSL's legacy
    provider. Checked against the RFC's test suite in selftest()."""
    def f(x, y, z):
        return (x & y) | (~x & z)

    def g(x, y, z):
        return (x & y) | (x & z) | (y & z)

    def h(x, y, z):
        return x ^ y ^ z

    def rotl32(v, n):
        v &= 0xFFFFFFFF
        return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF

    msg = data + b"\x80" + b"\0" * ((55 - len(data)) % 64) + (8 * len(data) % 2**64).to_bytes(8, "little")
    state = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]
    for off in range(0, len(msg), 64):
        x = [int.from_bytes(msg[off + 4 * i : off + 4 * i + 4], "little") for i in range(16)]
        a, b, c, d = state
        for i in range(16):  # round 1
            k, s = i, (3, 7, 11, 19)[i % 4]
            a, b, c, d = d, rotl32(a + f(b, c, d) + x[k], s), b, c
        for i in range(16):  # round 2
            k, s = (i % 4) * 4 + i // 4, (3, 5, 9, 13)[i % 4]
            a, b, c, d = d, rotl32(a + g(b, c, d) + x[k] + 0x5A827999, s), b, c
        for i in range(16):  # round 3
            k, s = (0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15)[i], (3, 9, 11, 15)[i % 4]
            a, b, c, d = d, rotl32(a + h(b, c, d) + x[k] + 0x6ED9EBA1, s), b, c
        state = [(v + w) & 0xFFFFFFFF for v, w in zip(state, (a, b, c, d))]
    return b"".join(v.to_bytes(4, "little") for v in state)


def hash_hex(name):
    def enc(data, rng):
        if name == "ntlm":  # MD4 of the UTF-16LE password
            return md4(u(data).encode("utf-16-le")).hex().encode()
        return hashlib.new(name, data, usedforsecurity=False).hexdigest().encode()

    enc.__name__ = "hash_" + name
    return enc


# ---------------------------------------------------------------------------------------
# Plaintexts


def load_plaintexts():
    pools = {}
    with open(os.path.join(DATA, "plaintexts.tsv"), encoding="utf-8") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            pool, pid, _source, value = line.split("\t")
            pools.setdefault(pool, []).append((pid, value))
    return pools


# ---------------------------------------------------------------------------------------
# What each tool can decode. A case is comparable on Python Ciphey 5.14.0 when it has a
# decoder or cracker for every layer (its registered modules, ciphey/basemods). It is
# comparable on CyberChef Magic when Magic would try the right operation at every layer: the
# layer's decoding operation (CC_OPS) is among the operations whose detection patterns match
# the text at that layer (Magic's own findMatchingInputOps, through the worker), and there are
# at most 3 layers (Magic's default depth runs recipes of at most 3 operations). In intensive
# mode a layer may instead be one Magic brute-forces (CC_BRUTE).


class Layer:
    def __init__(self, name, fn, tools=(), xfail="", match="exact"):
        self.name, self.fn, self.tools, self.xfail, self.match = name, fn, set(tools), xfail, match


L = {}


def layer(name, fn, tools=(), xfail="", match="exact"):
    L[name] = Layer(name, fn, tools, xfail, match)


P_ = PY
layer("base64", b64, (P_,))
layer("base64_url", b64url)
layer("base64_itoa64", b64_itoa64)
layer("base32", b32, (P_,))
layer("base32hex", b32hex)
layer("base32_crockford", b32_crockford)
layer("zbase32", zbase32)
layer("hex", hexlower, (P_,))
layer("hex_spaced", b16_spaced, (P_,))
layer("base36", base36)
layer("bigint", bigint)
layer("bigint_named", bigint_named)
layer("base58_bitcoin", b58_bitcoin, (P_,))
layer("base58_ripple", b58_ripple, (P_,))
layer("base58_flickr", b58_flickr)
layer("base58_monero", b58_monero)
layer("base62", b62, (P_,), xfail="#924")
layer("base65536", b65536)
layer("base85", b85, (P_,))
layer("ascii85", a85, (P_,))
layer("ascii85_adobe", a85_adobe)
layer("z85", z85)
layer("base91", b91, (P_,))
layer("base92", b92)
layer("base100", b100)
layer("uuencode", uuencode, (P_,))
layer("binary", binary, (P_,))
layer("decimal", decimal, (P_,))
layer("octal", octal, (P_,))
layer("url", url, (P_,))
layer("url_all", url_all, (P_,))
layer("html_dec", html_dec)
layer("html_hex", html_hex)
layer("unicode_escape", uni_escape)
layer("unicode_plus", uni_plus)
layer("backslash_octal", bs_octal)
layer("backslash_hex", bs_hex)
layer("quoted_printable", qp)
layer("mime_b", mime_b)
layer("mime_q", mime_q)
layer("punycode", punycode)
layer("utf16le", utf16le)
layer("utf16be_bom", utf16be_bom)
layer("hexdump_xxd", xxd)
layer("hexdump_c", hexdump_c)
layer("morse", morse, (P_,), match="fold")
layer("morse_lines", morse_lines, (P_,), match="fold")
layer("morse_symbols", morse_symbols, match="fold")
layer("binary_xy", binary_xy, (P_,))
layer("braille", braille, (P_,), match="fold")
layer("a1z26", a1z26, match="letters")
layer("a1z26_spaces", a1z26_cyberchef, match="letters")
layer("bacon26", bacon26, match="letters")
layer("bacon24", bacon24_cyberchef, match="letters")
layer("polybius", polybius, match="letters")
layer("tap_dots", tap_dots, match="letters")
layer("tap_digits", tap_digits, (P_,), match="letters")
layer("t9", t9, match="fold")
layer("multitap", multitap, (P_,), match="fold")
layer("dtmf", dtmf)
layer("nato", nato, match="letters")
layer("galactic", galactic, (P_,), match="fold")
layer("leetspeak", leet, (P_,), match="fold")
layer("fancy_bold", fancy_bold)
layer("fullwidth", fullwidth)
layer("zero_width", zw_binary)
layer("zero_width_sep", zw_separated)
layer("qwerty_dvorak", qwerty_as_dvorak)
layer("keyboard_shift", kbd_shift_right)
layer("null_acrostic", null_acrostic, match="letters")
layer("pollux", pollux, match="fold")
layer("yunying", yunying, match="letters")
layer("dna_codon", dna_codon, match="fold")
layer("baudot", baudot, (P_,), match="fold")
layer("core_values", core_values)
layer("brainfuck", brainfuck, (P_,))
layer("ook", ook)
layer("aaencode", aaencode)
layer("jsfuck", jsfuck)
layer("citrix_ctx1", citrix_ctx1)
layer("jwt", jwt_hs256, match="json")
layer("gzip", gz, (P_,))
layer("zlib", zl)
layer("deflate", deflate)
layer("bzip2", bz)
layer("xz", xz)
# Classical ciphers
for k in (3, 7, 13, 19, 23):
    layer(f"caesar{k}" if k != 13 else "rot13", caesar(k), (P_,))
layer("rot47", rot47, (P_,))
layer("rot18", rot18)
layer("atbash", atbash, (P_,))
layer("reverse", reverse, (P_,))
layer("affine_5_8", affine(5, 8), (P_,))
layer("affine_7_3", affine(7, 3), (P_,))
layer("affine_11_20", affine(11, 20), (P_,))
for key in ("KEY", "LEMON", "CIPHER", "PASSWORD"):
    layer(f"vigenere_{key.lower()}", vigenere(key), (P_,))
for key in ("FORT", "SECRET", "BRAVO"):
    layer(f"beaufort_{key.lower()}", beaufort(key))
for key in ("QUEEN", "KILT"):
    layer(f"autokey_{key.lower()}", autokey(key))
for rails in (2, 3, 5, 7):
    layer(f"railfence{rails}", railfence(rails))
for cols in (4, 6):
    layer(f"route{cols}", route_columns(cols))
for i, alphabet in enumerate(("QWERTYUIOPASDFGHJKLZXCVBNM", "ZEBRASCDFGHIJKLMNOPQTUVWXY", "MKXHAZRQDVPNOUCSYGLWEJBFTI")):
    layer(f"substitution{i + 1}", substitution(alphabet))
for kw in ("PLAYFAIR EXAMPLE", "MONARCHY", "KEYWORD"):
    layer("playfair_" + kw.split()[0].lower(), pycipher("Playfair", key=keyword_square(kw)), match="letters")
layer("hill2", hill2(), match="letters")
for k in (0x2A, 0x5C, 0x13):
    layer(f"xor_{k:02x}", xor1(k), (P_,))
for key in (b"KEY", b"ICE", b"s3cr3t"):
    layer("xorkey_" + key.decode().lower(), xorkey(key), (P_,))
layer("ascii_shift3", ascii_shift(3), (P_,))
layer("ascii_shift130", ascii_shift(130))  # Python Ciphey shifts within 0-127 only
# Not in Ciphey yet (expected failures until the issue's decoder lands)
layer("base45", b45, xfail="#923")
layer("bech32", bech32, xfail="#931")
layer("modhex", modhex, xfail="#932")
layer("xxencode", xxencode, xfail="#934")
layer("bubblebabble", bubblebabble, xfail="#936")
layer("utf7", utf7, xfail="#942")
layer("ebcdic", ebcdic, xfail="#944")
layer("cisco7", cisco7, xfail="#949")
layer("ternary", ternary, xfail="#953")
layer("chuck_norris", chucknorris, xfail="#954")
layer("manchester", manchester, xfail="#955")
layer("dna_2bit", dna2bit, xfail="#967")
layer("upside_down", upside_down, xfail="#970", match="fold")
layer("zalgo", zalgo, xfail="#972")
layer("runic", runic, xfail="#974", match="fold")
layer("kenny", kenny, xfail="#979")
layer("pig_latin", pig_latin, xfail="#980", match="fold")
layer("reverse_words", reverse_words, xfail="#983")
layer("pikalang", pikalang, xfail="#985")
layer("blub", blub, xfail="#985")
layer("whitespace_lang", whitespace_lang, xfail="#986")
layer("rot8000", rot8000, xfail="#993")
layer("trithemius", trithemius, xfail="#995")
layer("skip7", skip_cipher(7), xfail="#998")
layer("redefence", redefence((2, 0, 1)), xfail="#999")
layer("porta", pycipher("Porta", key="FORTIFICATION"), xfail="#1004", match="letters")
layer("foursquare", foursquare(keyword_square("EXAMPLE"), keyword_square("KEYWORD")), xfail="#1008", match="letters")
layer("bifid", pycipher("Bifid", key=keyword_square("BGWKZ QPNDS"), period=5), xfail="#1009", match="letters")
layer("nihilist", nihilist("ZEBRAS", "RUSSIAN"), xfail="#1012", match="letters")
layer("adfgx", pycipher("ADFGX", key=keyword_square("BTALPDHOZKQFVSNGICUXMREWY"), keyword="CARGO"), xfail="#1013", match="letters")
layer("adfgvx", pycipher("ADFGVX", key=keyword_square("PH0QG64MEA1YL2NOFDXKR3CVS5ZW7BJ9UTI8", 36), keyword="GERMAN"), xfail="#1013", match="letters")
layer("columnar", pycipher("ColTrans", "GERMAN"), xfail="#1014", match="letters")
layer("double_transposition", text(lambda s, rng: __import__("pycipher").ColTrans("CIPHER").encipher(__import__("pycipher").ColTrans("GERMAN").encipher(s))), xfail="#1015", match="letters")
layer("fractionated_morse", pycipher("FracMorse", key="ROUNDTABLECFGHIJKMPQSVWXYZ"), xfail="#1016", match="letters")
layer("rotl3", rotl(3), xfail="#1019")
layer("bitnot", bitnot)  # NOT is XOR with 0xFF: Ciphey's single-byte XOR cracker covers it
layer("zstd", zstd, xfail="#1025")
layer("lz4", lz4frame, xfail="#1026")
layer("lzstring", lzstring_b64, xfail="#1027")
for h in ("md5", "sha1", "sha256", "ntlm"):
    layer(h, hash_hex(h), xfail="#1029")

MATCH_ORDER = ["exact", "json", "fold", "letters"]

# The CyberChef operation that undoes each layer, among those Magic can detect
CC_OPS = {
    "base64": "From Base64", "base64_url": "From Base64", "base64_itoa64": "From Base64", "base32": "From Base32",
    "base32hex": "From Base32", "hex": "From Hex", "hex_spaced": "From Hex", "backslash_hex": "From Hex",
    "base58_bitcoin": "From Base58", "base58_ripple": "From Base58", "base85": "From Base85", "ascii85": "From Base85",
    "ascii85_adobe": "From Base85", "z85": "From Base85", "binary": "From Binary", "decimal": "From Decimal",
    "octal": "From Octal", "url": "URL Decode", "url_all": "URL Decode", "html_dec": "From HTML Entity",
    "html_hex": "From HTML Entity", "unicode_escape": "Unescape Unicode Characters",
    "unicode_plus": "Unescape Unicode Characters", "quoted_printable": "From Quoted Printable",
    "hexdump_xxd": "From Hexdump", "hexdump_c": "From Hexdump", "morse": "From Morse Code",
    "morse_lines": "From Morse Code", "a1z26_spaces": "A1Z26 Cipher Decode", "bacon26": "Bacon Cipher Decode",
    "bacon24": "Bacon Cipher Decode", "jwt": "JWT Decode", "gzip": "Gunzip", "zlib": "Zlib Inflate",
    "deflate": "Raw Inflate", "bzip2": "Bzip2 Decompress", "bech32": "From Bech32", "modhex": "From Modhex",
}
# Layers intensive mode brute-forces whether or not a pattern matches
CC_BRUTE = {"xor_2a", "xor_5c", "xor_13", "bitnot", "rotl3", "utf16le", "utf16be_bom", "ebcdic", "utf7"}
CC_DEPTH = 3


def is_ascii_printable(s):
    return all(32 <= ord(c) < 127 for c in s)


def no_letters(*bad):
    return lambda s: not any(c in s.upper() for c in bad)


def playfair_prep(s):
    """Wikipedia's Playfair preparation: letters only, J as I, an X after the first letter of a
    doubled pair, an X at the end of an odd text. The decryption gives this text back."""
    letters, out, i = letters_only(s).replace("J", "I"), [], 0
    while i < len(letters):
        a = letters[i]
        b = letters[i + 1] if i + 1 < len(letters) else None
        if b is None or a == b:
            out += [a, "X"]
            i += 1
        else:
            out += [a, b]
            i += 2
    return "".join(out)


def pad_even(s):
    letters = letters_only(s)
    return letters + "X" * (len(letters) % 2)


PREP = {"playfair_playfair": playfair_prep, "playfair_monarchy": playfair_prep, "playfair_keyword": playfair_prep,
        "foursquare": pad_even, "hill2": pad_even}


# The single-layer cases: (category, layers, pool, number of cases, plaintext filter)
SINGLE = [
    ("encoding", ["base64"], "sent", 2, None),
    ("encoding", ["base64_url"], "nonascii", 1, lambda s: b"/" in b64(s.encode(), None) or b"+" in b64(s.encode(), None)),
    ("encoding", ["base64_itoa64"], "sent", 1, None),
    ("encoding", ["base32"], "sent", 2, None),
    ("encoding", ["base32hex"], "sent", 1, None),
    ("encoding", ["base32_crockford"], "sent", 1, None),
    ("encoding", ["zbase32"], "sent", 1, None),
    ("encoding", ["hex"], "sent", 1, None),
    ("encoding", ["hex_spaced"], "sent", 1, None),
    ("encoding", ["base36"], "sent", 1, None),
    ("encoding", ["bigint"], "sent", 1, None),
    ("encoding", ["bigint_named"], "sent", 1, None),
    ("encoding", ["base58_bitcoin"], "sent", 1, None),
    ("encoding", ["base58_ripple"], "sent", 1, None),
    ("encoding", ["base58_flickr"], "sent", 1, None),
    ("encoding", ["base58_monero"], "sent", 1, None),
    ("encoding", ["base62"], "sent", 1, None),
    ("encoding", ["base65536"], "sent", 1, None),
    ("encoding", ["base85"], "sent", 1, None),
    ("encoding", ["ascii85"], "sent", 1, None),
    ("encoding", ["ascii85_adobe"], "sent", 1, None),
    ("encoding", ["z85"], "sent", 1, lambda s: len(s.encode()) % 4 == 0),
    ("encoding", ["base91"], "sent", 1, None),
    ("encoding", ["base92"], "sent", 1, None),
    ("encoding", ["base100"], "sent", 1, None),
    ("encoding", ["uuencode"], "sent", 1, None),
    ("encoding", ["binary"], "sent", 2, None),
    ("encoding", ["decimal"], "sent", 1, None),
    ("encoding", ["octal"], "sent", 1, None),
    ("encoding", ["url"], "sent", 1, None),
    ("encoding", ["url_all"], "sent", 1, None),
    ("encoding", ["html_dec"], "sent", 1, None),
    ("encoding", ["html_hex"], "sent", 1, None),
    ("encoding", ["unicode_escape"], "nonascii", 1, None),
    ("encoding", ["unicode_escape"], "sent", 1, None),
    ("encoding", ["unicode_plus"], "nonascii", 1, None),
    ("encoding", ["backslash_octal"], "sent", 1, None),
    ("encoding", ["backslash_hex"], "sent", 1, None),
    ("encoding", ["quoted_printable"], "nonascii", 1, None),
    ("encoding", ["mime_b"], "nonascii", 1, None),
    ("encoding", ["mime_q"], "nonascii", 1, None),
    ("encoding", ["punycode"], "domain", 2, None),
    ("encoding", ["utf16le", "base64"], "sent", 1, None),
    ("encoding", ["utf16be_bom", "hex"], "sent", 1, None),
    ("encoding", ["hexdump_xxd"], "sent", 1, None),
    ("encoding", ["hexdump_c"], "sent", 1, None),
    ("encoding", ["morse"], "letters", 1, None),
    ("encoding", ["morse_lines"], "letters", 1, None),
    ("encoding", ["morse_symbols"], "letters", 1, None),
    ("encoding", ["binary_xy"], "sent", 1, None),
    ("encoding", ["braille"], "letters", 1, None),
    ("encoding", ["a1z26"], "letters", 1, None),
    ("encoding", ["a1z26_spaces"], "letters", 1, None),
    ("encoding", ["bacon26"], "letters", 1, None),
    ("encoding", ["bacon24"], "letters", 1, no_letters("J", "U", "V")),
    ("encoding", ["polybius"], "letters", 1, no_letters("J")),
    ("encoding", ["tap_dots"], "letters", 1, no_letters("K")),
    ("encoding", ["tap_digits"], "letters", 1, no_letters("K")),
    ("encoding", ["t9"], "letters", 1, None),
    ("encoding", ["multitap"], "letters", 1, None),
    ("encoding", ["dtmf"], "digits", 1, None),
    ("encoding", ["nato"], "letters", 1, None),
    ("encoding", ["galactic"], "letters", 1, no_letters("X")),
    ("encoding", ["leetspeak"], "sent", 1, None),
    ("encoding", ["fancy_bold"], "sent", 1, None),
    ("encoding", ["fullwidth"], "sent", 1, None),
    ("encoding", ["zero_width"], "sent", 1, None),
    ("encoding", ["zero_width_sep"], "sent", 1, None),
    ("encoding", ["qwerty_dvorak"], "sent", 1, None),
    ("encoding", ["keyboard_shift"], "sent", 1, None),
    ("encoding", ["null_acrostic"], "letters", 1, None),
    ("encoding", ["pollux"], "letters", 1, None),
    ("encoding", ["yunying"], "letters", 1, None),
    ("encoding", ["dna_codon"], "dna", 1, None),
    ("encoding", ["baudot"], "letters", 1, None),
    ("encoding", ["core_values"], "sent", 1, None),
    ("encoding", ["brainfuck"], "sent", 1, None),
    ("encoding", ["ook"], "short", 1, None),
    ("encoding", ["aaencode"], "short", 1, None),
    ("encoding", ["jsfuck"], "short", 1, lambda s: len(s) <= 8),
    ("encoding", ["citrix_ctx1"], "password", 1, None),
    ("encoding", ["jwt"], "json", 1, None),
    ("encoding", ["gzip", "base64"], "sent", 1, None),
    ("encoding", ["gzip", "hex"], "sent", 1, None),
    ("encoding", ["zlib", "base64"], "sent", 1, None),
    ("encoding", ["deflate", "base64"], "sent", 1, None),
    ("encoding", ["bzip2", "base64"], "sent", 1, None),
    ("encoding", ["xz", "base64"], "sent", 1, None),
    # expected failures
    ("encoding", ["base45"], "sent", 1, None),
    ("encoding", ["bech32"], "letters", 1, lambda s: len(s) <= 40),
    ("encoding", ["modhex"], "sent", 1, None),
    ("encoding", ["xxencode"], "sent", 1, None),
    ("encoding", ["bubblebabble"], "sent", 1, None),
    ("encoding", ["utf7"], "nonascii", 1, None),
    ("encoding", ["ebcdic", "hex"], "sent", 1, None),
    ("encoding", ["cisco7"], "password", 1, None),
    ("encoding", ["ternary"], "sent", 1, None),
    ("encoding", ["chuck_norris"], "short", 1, None),
    ("encoding", ["manchester"], "short", 1, None),
    ("encoding", ["dna_2bit"], "sent", 1, None),
    ("encoding", ["upside_down"], "sent", 1, None),
    ("encoding", ["zalgo"], "sent", 1, None),
    ("encoding", ["runic"], "letters", 1, no_letters("Q", "V", "X", "Y", "K", "C", "J", "W")),
    ("encoding", ["kenny"], "sent", 1, None),
    ("encoding", ["pig_latin"], "letters", 1, None),
    ("encoding", ["reverse_words"], "sent", 1, None),
    ("encoding", ["pikalang"], "short", 1, None),
    ("encoding", ["blub"], "short", 1, None),
    ("encoding", ["whitespace_lang"], "short", 1, None),
    ("encoding", ["rot8000"], "sent", 1, None),
    ("encoding", ["rotl3", "hex"], "sent", 1, None),
    ("encoding", ["bitnot", "hex"], "sent", 1, None),
    ("encoding", ["zstd", "base64"], "sent", 1, None),
    ("encoding", ["lz4", "base64"], "sent", 1, None),
    ("encoding", ["lzstring"], "sent", 1, None),
    # classical ciphers
    ("classical", ["caesar3"], "sent", 1, None),
    ("classical", ["caesar7"], "sent", 1, None),
    ("classical", ["caesar19"], "para", 1, None),
    ("classical", ["caesar23"], "sent", 1, None),
    ("classical", ["rot13"], "sent", 2, None),
    ("classical", ["rot47"], "sent", 2, None),
    ("classical", ["rot18"], "digits_sent", 1, None),
    ("classical", ["atbash"], "sent", 2, None),
    ("classical", ["reverse"], "sent", 2, None),
    ("classical", ["affine_5_8"], "sent", 1, None),
    ("classical", ["affine_7_3"], "sent", 1, None),
    ("classical", ["affine_11_20"], "para", 1, None),
    ("classical", ["vigenere_key"], "para", 1, None),
    ("classical", ["vigenere_lemon"], "para", 1, None),
    ("classical", ["vigenere_cipher"], "para", 1, None),
    ("classical", ["vigenere_password"], "para", 1, None),
    ("classical", ["beaufort_fort"], "para", 1, None),
    ("classical", ["beaufort_secret"], "para", 1, None),
    ("classical", ["beaufort_bravo"], "para", 1, None),
    ("classical", ["autokey_queen"], "para", 1, None),
    ("classical", ["autokey_kilt"], "para", 1, None),
    ("classical", ["railfence2"], "sent", 1, None),
    ("classical", ["railfence3"], "sent", 1, None),
    ("classical", ["railfence5"], "sent", 1, None),
    ("classical", ["railfence7"], "para", 1, None),
    ("classical", ["route4"], "sent", 1, None),
    ("classical", ["route6"], "sent", 1, None),
    ("classical", ["substitution1"], "para", 1, None),
    ("classical", ["substitution2"], "long", 1, None),
    ("classical", ["substitution3"], "long", 1, None),
    ("classical", ["playfair_playfair"], "para", 1, None),
    ("classical", ["playfair_monarchy"], "para", 1, None),
    ("classical", ["playfair_keyword"], "long", 1, None),
    ("classical", ["hill2"], "letters", 1, None),
    ("classical", ["hill2"], "para", 1, None),
    ("classical", ["xor_2a", "hex"], "sent", 1, None),
    ("classical", ["xor_5c", "base64"], "sent", 1, None),
    ("classical", ["xor_13", "hex"], "sent", 1, None),
    ("classical", ["xorkey_key", "hex"], "para", 1, None),
    ("classical", ["xorkey_ice", "base64"], "para", 1, None),
    ("classical", ["xorkey_s3cr3t", "hex"], "para", 1, None),
    ("classical", ["ascii_shift3"], "sent", 1, None),
    ("classical", ["ascii_shift130"], "sent", 1, None),
    ("classical", ["trithemius"], "sent", 1, None),
    ("classical", ["skip7"], "sent", 1, lambda s: math.gcd(7, len(s)) == 1),
    ("classical", ["redefence"], "sent", 1, None),
    ("classical", ["porta"], "para", 1, None),
    ("classical", ["foursquare"], "para", 1, None),
    ("classical", ["bifid"], "para", 1, None),
    ("classical", ["nihilist"], "sent", 1, None),
    ("classical", ["adfgx"], "sent", 1, None),
    ("classical", ["adfgvx"], "sent", 1, None),
    ("classical", ["columnar"], "para", 1, None),
    ("classical", ["double_transposition"], "para", 1, None),
    ("classical", ["fractionated_morse"], "letters", 1, None),
]

for h in ("md5", "sha1", "sha256", "ntlm"):
    SINGLE.append(("hash", [h], "password", 4, None))

FLAG_PREFIXES = ["flag", "picoCTF", "HTB", "CTF", "DUCTF", "THM", "SEKAI", "ictf", "CSAW", "uiuctf", "FLAG", "corctf"]
FLAG_LAYERS = [
    ["base64"], ["hex"], ["rot13"], ["caesar7"], ["atbash"], ["base32"], ["url_all"], ["reverse"], ["binary"],
    ["base58_bitcoin"], ["railfence3"], ["xor_2a", "hex"], ["rot47"], ["base85"], ["decimal"], ["base64", "hex"],
    ["rot13", "base64"], ["reverse", "base64"], ["hex", "base32"], ["caesar19"], ["base64", "base64"],
    ["vigenere_key"], ["octal"], ["base32", "base64"], ["html_dec"], ["base91"], ["ascii85"], ["base64", "rot13"],
    ["atbash", "hex"], ["base62"],
]
SHORT_LAYERS = [["base64"], ["hex"], ["rot13"], ["caesar3"], ["binary"], ["base32"], ["reverse"], ["atbash"],
                ["url_all"], ["base58_bitcoin"], ["decimal"], ["rot47"], ["base85"], ["morse"], ["octal"]]
LONG_LAYERS = [["base64"], ["hex"], ["rot13"], ["caesar7"], ["vigenere_cipher"], ["railfence3"], ["atbash"], ["base32"],
               ["substitution1"], ["binary"], ["base64", "hex"], ["reverse"]]
CHAIN_OUTER = ["base64", "base32", "hex", "binary", "decimal", "octal", "base58_bitcoin", "base85", "url_all"]
CHAIN_INNER = ["rot13", "caesar7", "atbash", "reverse", "rot47"]
LANGS = ["de", "fr", "es", "it", "pt", "nl", "pl", "tr", "ru", "zh", "ja", "ko"]


# ---------------------------------------------------------------------------------------
# Building the cases


class Case:
    def __init__(self, cid, category, layers, plaintext, source, xfail="", expected=None, match=None, tools=None, ciphertext=None):
        self.id, self.category, self.layers, self.source = cid, category, layers, source
        self.plaintext = plaintext
        ls = [L[n] for n in layers]
        self.xfail = xfail or ",".join(sorted({x.xfail for x in ls if x.xfail}))
        if match is None:
            match = max((x.match for x in ls), key=MATCH_ORDER.index) if ls else "exact"
        self.match = match
        self.fixed_tools = tools is not None
        if tools is None:
            tools = {CIPHEY}
            if ls and all(PY in x.tools for x in ls):
                tools.add(PY)
        self.tools = tools
        self.expected = plaintext if expected is None else expected
        self.input = ciphertext
        self.subset = ""

    def encode(self, rng):
        data = self.plaintext.encode("utf-8")
        self.layer_data = []
        for name in self.layers:
            data = L[name].fn(data, rng)
            self.layer_data.append(data)
        self.input = data.decode("utf-8")
        if not self.fixed_tools or self.category == "language":
            self.tools |= cyberchef_tools(self.layers, self.layer_data)
        return self


def cyberchef_tools(layers, layer_data):
    """{CC, CCI}, {CCI} or set(): whether Magic would try the right operation at every layer."""
    if len(layers) > CC_DEPTH:
        return set()
    default = intensive = True
    for name, data in zip(layers, layer_data):
        detected = name in CC_OPS and CC_OPS[name] in CHEF.request({"op": "checks", "hex": data.hex()})["ops"]
        default = default and detected
        intensive = intensive and (detected or name in CC_BRUTE)
    return ({CC} if default else set()) | ({CCI} if intensive else set())


def pick(rng, pools, pool, n, filt=None):
    items = [(pid, t) for pid, t in pools[pool] if filt is None or filt(t)]
    if len(items) < n:
        raise SystemExit(f"pool {pool} has {len(items)} plaintexts for a filter that needs {n}")
    return rng.sample(items, n)


def rng_for(name):
    return random.Random(f"{SEED}:{name}")


def build_cases():
    pools = load_plaintexts()
    rng = rng_for("pools")
    pools["digits"] = [(f"R{i}", "".join(rng.choice(string.digits) for _ in range(10))) for i in range(3)]
    pools["digits_sent"] = [("S-digits1", "Meet me at 10:45 in room 237, not 19."), ("S-digits2", "The code is 4096 and the door is 12B.")]
    pools["json"] = [(pid, json.dumps({"msg": t, "admin": False}, separators=(",", ":"))) for pid, t in pools["sent"][:10]]
    cases = []
    seen_ids = set()

    def add(case):
        assert case.id not in seen_ids, case.id
        seen_ids.add(case.id)
        cases.append(case)

    counts = {}
    for category, layers, pool, n, filt in SINGLE:
        name = "+".join(layers)
        r = rng_for(f"{category}:{name}:{pool}")
        prefix = {"encoding": "enc", "classical": "cls", "hash": "hash"}[category]
        for pid, t in pick(r, pools, pool, n, filt):
            counts[name] = counts.get(name, 0) + 1
            if layers[0] in PREP:
                t = PREP[layers[0]](t)
            expected = letters_only(t) if category == "classical" and L[layers[0]].match == "letters" else t
            add(Case(f"{prefix}.{name}.{counts[name]}", category, layers, t, pid, expected=expected).encode(r))

    # CTF flags
    r = rng_for("flags")
    words = [t for _, t in pools["flagword"]]
    for k, layers in enumerate(FLAG_LAYERS, 1):
        prefix = FLAG_PREFIXES[(k - 1) % len(FLAG_PREFIXES)]
        body = words[(k - 1) % len(words)] if k % 4 else "".join(r.choice("0123456789abcdef") for _ in range(16))
        flag = f"{prefix}{{{body}}}"
        add(Case(f"flag.{k:02d}", "flag", layers, flag, "own" if k % 4 else "random").encode(r))

    # Short and long plaintexts
    r = rng_for("short")
    for k, ((pid, t), layers) in enumerate(zip(pick(r, pools, "short", len(SHORT_LAYERS)), SHORT_LAYERS), 1):
        if layers == ["morse"] and not all(c.upper() in MORSE or c == " " for c in t):
            raise SystemExit(f"short plaintext {t!r} can't be written in Morse")
        add(Case(f"short.{k:02d}", "short", layers, t, pid).encode(r))
    r = rng_for("long")
    longs = list(pools["long"])
    longs.append(("G01+G05", pools["long"][0][1] + " " + pools["long"][4][1]))
    for k, layers in enumerate(LONG_LAYERS, 1):
        pid, t = longs[(k - 1) % len(longs)]
        add(Case(f"long.{k:02d}", "long", layers, t, pid).encode(r))

    # Chains of 2 to 5 layers. Half use only base encodings that every tool has, half start
    # (innermost) with a classical cipher.
    r = rng_for("chains")
    sents = list(pools["sent"])
    k = 0
    for depth in (2, 3, 4, 5):
        for j in range(10):
            k += 1
            outer = [r.choice(CHAIN_OUTER) for _ in range(depth if j % 2 == 0 else depth - 1)]
            layers = outer if j % 2 == 0 else [r.choice(CHAIN_INNER)] + outer
            pid, t = r.choice(sents)
            add(Case(f"chain{depth}.{j + 1:02d}", "chain", layers, t, pid).encode(r))

    # Other languages: Base64, hex, and the plaintext itself
    r = rng_for("languages")
    lang = dict(pools["lang"])
    for code in LANGS:
        for layers, key in ((["base64"], "1"), (["hex"], "2"), ([], "1")):
            t = lang[code + key]
            tools = {CIPHEY} if layers else {CIPHEY, CC, CCI}  # Python Ciphey has only an English checker
            cid = f"lang.{code}.{'+'.join(layers) or 'plain'}"
            add(Case(cid, "language", layers, t, code + key, xfail="gibberish-or-not 6", tools=tools).encode(r))

    # Inputs that are already plaintext
    for pid, t in pools["plain"]:
        add(Case(f"plain.{pid}", "plaintext", [], t, pid, tools={CIPHEY, PY, CC, CCI}, ciphertext=t))

    # No answer: random, junk and near-English
    for c in no_answer_cases(pools):
        add(c)
    return cases


def markov_text(corpus, rng, order, length):
    """Character Markov chain text: looks like English, has almost no words."""
    model = {}
    for i in range(len(corpus) - order):
        model.setdefault(corpus[i : i + order], []).append(corpus[i + order])
    state = rng.choice([k for k in model if k[0] == " "])
    out = state
    while len(out) < length:
        nxt = model.get(state)
        if not nxt:
            state = rng.choice(list(model))
            continue
        out += rng.choice(nxt)
        state = out[-order:]
    return re.sub(r"\s+", " ", out).strip()


def no_answer_cases(pools):
    r = rng_for("no_answer")
    out = []

    def add(kind, value):
        n = sum(1 for c in out if c.layers == [] and c.id.startswith(f"none.{kind}.")) + 1
        out.append(Case(f"none.{kind}.{n}", "no_answer", [], "", "random", expected="-", match="none", tools={CIPHEY, PY, CC, CCI}, ciphertext=value))

    alnum = string.ascii_letters + string.digits
    for n in (12, 24, 40, 64):
        add("random_alnum", "".join(r.choice(alnum) for _ in range(n)))
    for n in (16, 32, 60):
        add("random_lower", "".join(r.choice(string.ascii_lowercase) for _ in range(n)))
    for n in (20, 48):
        add("random_upper", "".join(r.choice(string.ascii_uppercase) for _ in range(n)))
    for n in (20, 32, 40, 64):
        add("random_hex", "".join(r.choice("0123456789abcdef") for _ in range(n)))
    for n in (12, 24, 48, 96):
        add("random_base64", base64.b64encode(bytes(r.randrange(256) for _ in range(n))).decode())
    for n in (10, 20, 40):
        add("random_digits", "".join(r.choice(string.digits) for _ in range(n)))
    rows = ["qwertyuiop", "asdfghjkl", "zxcvbnm"]
    for n in (12, 20, 28, 36):
        add("keyboard_mash", "".join(r.choice(r.choice(rows)) for _ in range(n)))
    english = " ".join(t for _, t in pools["sent"] + pools["para"]).lower()
    english = re.sub(r"[^a-z ]", "", english)
    for n in (40, 60, 80, 100, 120, 160):  # letter bigrams of English: English-like, hardly any words
        add("bigram_english", markov_text(english, r, 1, n))
    for _, t in r.sample(pools["sent"], 3):
        words = []
        for w in t.lower().rstrip(".?!").split():
            letters = list(w)
            r.shuffle(letters)
            words.append("".join(letters))
        add("shuffled_words", " ".join(words))
    for n in (12, 30):
        add("random_cjk", "".join(chr(r.randrange(0x4E00, 0x9FA6)) for _ in range(n)))
    add("random_emoji", "".join(chr(r.randrange(0x1F600, 0x1F650)) for _ in range(16)))
    add("random_bits", "".join(r.choice("01") for _ in range(61)))
    add("random_morse", " ".join("".join(r.choice(".-") for _ in range(r.randint(1, 4))) for _ in range(24)))
    add("random_symbols", "".join(r.choice("!@#$%^&*()_+-=[]{};:,.<>?/|~") for _ in range(30)))
    return out


# ---------------------------------------------------------------------------------------
# Subsets. `quick` is the A/B check decoder PRs run against master (benches/README.md),
# `smoke` the ~10 cases CI runs. Chosen by id after the baseline runs (docs/benchmark-e2e.md).

QUICK = [
    # one layer: the common encodings and some of the newer decoders
    "enc.base64.1", "enc.base64_url.1", "enc.base32.1", "enc.hex.1", "enc.hex_spaced.1", "enc.base58_bitcoin.1",
    "enc.base85.1", "enc.ascii85.1", "enc.z85.1", "enc.base91.1", "enc.base65536.1", "enc.binary.1", "enc.decimal.1",
    "enc.octal.1", "enc.url_all.1", "enc.html_dec.1", "enc.unicode_escape.2", "enc.quoted_printable.1", "enc.morse.1",
    "enc.braille.1", "enc.a1z26_spaces.1", "enc.uuencode.1", "enc.gzip+base64.1", "enc.utf16le+base64.1",
    "enc.hexdump_xxd.1", "enc.punycode.2", "enc.leetspeak.1", "enc.nato.1", "enc.brainfuck.1", "enc.jwt.1",
    # classical ciphers
    "cls.caesar7.1", "cls.rot13.1", "cls.rot47.1", "cls.atbash.1", "cls.affine_5_8.1", "cls.vigenere_key.1",
    "cls.beaufort_fort.1", "cls.railfence3.1", "cls.substitution1.1", "cls.playfair_playfair.1", "cls.xor_2a+hex.1",
    "cls.xorkey_ice+base64.1", "cls.vigenere_lemon.1",
    # chains, flags, short and long text, other languages, plaintext input
    "chain2.01", "chain2.07", "chain3.01", "chain3.02", "chain3.08", "chain4.02", "chain4.04", "chain4.06", "chain4.07",
    "chain5.02", "chain5.10",
    "flag.01", "flag.03", "flag.11", "flag.16", "short.02", "short.03", "long.01", "long.05", "long.07", "long.09",
    "lang.fr.base64", "lang.de.hex", "plain.T01", "plain.T04", "plain.T06",
    # no plaintext: four that run to the timeout on master, three that end early
    "none.random_base64.1", "none.random_alnum.1", "none.random_cjk.1", "none.random_symbols.1",
    "none.bigram_english.1", "none.keyboard_mash.1", "none.random_hex.1",
]
# the CI smoke run: fast, and correct on master
SMOKE = ["enc.base64.1", "enc.hex.1", "enc.binary.1", "enc.base32.1", "enc.morse.1", "enc.url_all.1", "cls.rot13.1",
         "chain3.01", "flag.01", "plain.T01"]


# ---------------------------------------------------------------------------------------
# Output

COLUMNS = ["id", "category", "layers", "tools", "xfail", "match", "subset", "source", "input", "expected"]


def esc(s):
    for c in s:
        o = ord(c)
        if (o < 32 and c not in "\t\n\r") or o == 127:
            raise ValueError(f"control character {o:#x} in {s[:40]!r}")
    return s.replace("\\", "\\\\").replace("\t", "\\t").replace("\n", "\\n").replace("\r", "\\r")


def render(cases):
    ids = {c.id for c in cases}
    missing = [i for i in QUICK + SMOKE if i not in ids]
    assert not missing, f"subset ids that aren't cases: {missing}"
    lines = [
        f"# Ciphey end-to-end benchmark corpus v{VERSION}: {len(cases)} cases. Generated by benches/e2e/corpus.py",
        f"# (seed {SEED}); don't edit, see docs/benchmark-e2e.md. input and expected escape \\\\ \\t \\n \\r;",
        "# expected '-' means there is no plaintext. layers are innermost first.",
        "\t".join(COLUMNS),
    ]
    order = [CIPHEY, PY, CC, CCI]
    for c in cases:
        c.subset = ",".join(s for s, ids in (("quick", QUICK), ("smoke", SMOKE)) if c.id in ids)
        row = [c.id, c.category, ",".join(c.layers), ",".join(t for t in order if t in c.tools), c.xfail, c.match,
               c.subset, c.source, esc(c.input), esc(c.expected)]
        lines.append("\t".join(row))
    return "\n".join(lines) + "\n"


def selftest():
    """Known answers from the encodings' references."""
    assert base36("hello world".encode(), None) == b"fuvrsivvnfrbjwajo"  # Ciphey's doc, PyPI base36
    assert bigint("hello world".encode(), None) == b"126207244316550804821666916"
    assert z85(bytes.fromhex("864FD26FB559F75B"), None) == b"HelloWorld"  # ZeroMQ RFC 32
    assert bubblebabble(b"", None) == b"xexax" and bubblebabble(b"1234567890", None) == b"xesef-disof-gytuf-katof-movif-baxux"
    assert bubblebabble(b"Pineapple", None) == b"xigak-nyryk-humil-bosek-sonax"
    assert md4(b"").hex() == "31d6cfe0d16ae931b73c59d7e0c089c0" and md4(b"abc").hex() == "a448017aaf21d8525fc10ae87aa6729d"  # RFC 1320
    assert md4(b"12345678901234567890123456789012345678901234567890123456789012345678901234567890").hex() == "e33b4ddc9c38f2199c3e7b164fcc0536"
    assert hash_hex("ntlm")(b"password", None) == b"8846f7eaee8fb117ad06bdd830b7586c"
    assert cisco7_fixed(b"cisco", 2) == "02050D480809"
    assert qwerty_as_dvorak(b"hello world", None) == b"d.nnr ,rpne"
    assert kbd_shift_right(b"hello world", None) == b"jr;;p ept;f"
    assert hill2()(b"HELP", None) == b"HIAT"  # Wikipedia's example
    assert rot47(b"Hello", None) == b"w6==@"
    assert yunying(b"W", None) == b"88421"
    assert bech32(b"", None, hrp="a") == b"a12uel5l"  # BIP-173 test vector
    assert mime_b("café".encode(), None) == b"=?utf-8?b?Y2Fmw6k=?="
    # practicalcryptography.com's four-square example
    assert foursquare("ZGPTFOIHMUWDRCNYKEQAXVSBL", "MFNBDCRHSAXYOGVITUEWLQZKP")(b"attack at dawn", None) == b"TIYBFHTIZBSY"


def cisco7_fixed(data, seed):
    return f"{seed:02d}" + "".join(f"{x ^ ord(CISCO7[(seed + i) % len(CISCO7)]):02X}" for i, x in enumerate(data))


def main():
    global CHEF
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cyberchef", required=True, help="directory with node_modules/cyberchef and jsfuck (setup.sh)")
    ap.add_argument("--check", action="store_true", help="regenerate and compare with the committed corpus")
    ap.add_argument("--verify", action="store_true", help="decode every case again with independent decoders")
    args = ap.parse_args()
    sys.path.insert(0, HERE)
    from cyberchef import CyberChef

    CHEF = CyberChef(args.cyberchef)
    try:
        selftest()
        cases = build_cases()
        rendered = render(cases)
        if args.verify:
            from verify import verify

            sys.exit(verify(cases, CHEF))
        if args.check:
            with open(OUT, encoding="utf-8") as fh:
                old = fh.read()
            if old != rendered:
                print(f"{OUT} differs from what corpus.py generates", file=sys.stderr)
                sys.exit(1)
            print(f"{OUT}: {len(cases)} cases, identical")
            return
        with open(OUT, "w", encoding="utf-8") as fh:
            fh.write(rendered)
        by_cat = {}
        for c in cases:
            by_cat[c.category] = by_cat.get(c.category, 0) + 1
        print(f"wrote {OUT}: {len(cases)} cases {by_cat}")
    finally:
        CHEF.close()


if __name__ == "__main__":
    main()
