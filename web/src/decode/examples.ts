// The Decode page's examples. Each was made outside Ciphey (Python's base64, codecs and a
// few lines for Morse and Vigenère; see web/README.md), and the end-to-end test decodes each
// one and checks the plaintext.

export interface Example {
  id: string;
  label: string;
  input: string;
  /** What Ciphey should find. */
  plaintext: string;
  /** Only offered when Ciphey has a decoder of this name (for decoders still to land). */
  needs?: string;
}

export const EXAMPLES: readonly Example[] = [
  {
    id: "base64x3",
    label: "Base64 ×3",
    input: "VVRKc2QyRkhWalZKU0VKc1dsZDRla2xIU21oWk1uTm5XbGhhYkdOdWEyZGlSMFkxV2xoSloySXlXV2RhVnpWcVlqSlNjR0p0WXowPQ==",
    plaintext: "Ciphey peels back every layer of encoding",
  },
  {
    id: "rot13-base64",
    label: "ROT13 → Base64",
    input: "Q3JyeSBndXIgeW5scmVmIGJhciBuZyBuIGd2enI=",
    plaintext: "Peel the layers one at a time",
  },
  {
    id: "morse",
    label: "Morse code",
    input: "-.-. .. .--. .... . -.-- / -.. . -.-. --- -.. . ... / -- --- .-. ... . / -.-. --- -.. . / .- ... / .-- . .-.. .-..",
    plaintext: "CIPHEY DECODES MORSE CODE AS WELL",
  },
  {
    id: "vigenere",
    label: "Vigenère",
    input:
      "Dzddwc npiyo gyk uys gwc fg r Jeyiefis yatyfi pu axjfct, og ecm pcq five zg pzi tjgvajxvyk ojv e cjkhhw truzsjui nizza ax kszso llv mzyadc bfp zafkkij",
    plaintext:
      "Ciphey works out the key of a Vigenere cipher by itself, so all you need is the ciphertext and a little patience while it tries the likely key lengths",
  },
  {
    id: "ctf-flag",
    label: "CTF flag",
    input: "NjY2YzYxNjc3YjYzMzE3MDY4MzM3OTVmNzI3NTZlNzM1ZjMxNmU1Zjc5MzA3NTcyNWY2MjcyMzA3NzczMzM3Mjdk",
    plaintext: "flag{c1ph3y_runs_1n_y0ur_br0ws3r}",
  },
  {
    id: "french",
    label: "French text",
    input: "TGUgcGV0aXQgY2hhdCBkb3J0IHN1ciBsZSBjYW5hcMOpIHBlbmRhbnQgcXVlIGxhIHBsdWllIHRvbWJlIGRvdWNlbWVudA==",
    plaintext: "Le petit chat dort sur le canapé pendant que la pluie tombe doucement",
  },
];
