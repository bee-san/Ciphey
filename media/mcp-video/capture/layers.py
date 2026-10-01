"""Encoding layers used to build the demo ciphertext (capture/demo.json)."""
import base64
import codecs

ENCODERS = {
    "rot13": lambda text: codecs.encode(text, "rot13"),
    "hex": lambda text: text.encode("utf-8").hex(),
    "base64": lambda text: base64.b64encode(text.encode("utf-8")).decode("ascii"),
}


def build_layers(plaintext: str, encode: list) -> list:
    """Every intermediate string, from the plaintext to the final ciphertext."""
    layers = [plaintext]
    for name in encode:
        layers.append(ENCODERS[name](layers[-1]))
    return layers


def build_ciphertext(plaintext: str, encode: list) -> str:
    return build_layers(plaintext, encode)[-1]
