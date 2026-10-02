#!/usr/bin/env python3
"""Regenerates english_quadgrams.bin and english_short_words.txt.

    python3 src/storage/ngrams/generate.py [--cache DIR] [--heldout]

Both files are built from the public-domain books in BOOKS (Project Gutenberg plain
text). The script downloads each book once into the cache directory (default
target/gutenberg), cuts off Project Gutenberg's header and licence footer, and counts:

* english_quadgrams.bin: 26^4 bytes, one per letter quadgram AAAA..ZZZZ in that order
  (index = ((a*26 + b)*26 + c)*26 + d). Byte q stores log10 P(quadgram) = -q / 25,
  rounded, so the resolution is 0.04 and 255 means -10.2. Counts are over the letters
  of each book with everything else removed and case folded, so quadgrams run across
  word boundaries ("NTHE" from "in the"), which is what space-less text looks like.
  A quadgram that never occurs gets a count of 0.01.
* english_short_words.txt: common words of 1 to 3 characters (apostrophes allowed, e.g.
  "i'm"). gibberish-or-not's dictionary can't be asked about words this short, so the
  English checker uses this list for them. A word is kept if it
  - occurs at least SHORT_WORD_MIN_PER_MILLION times per million words,
  - in at least SHORT_WORD_MIN_BOOKS books (drops dialect and character names),
  - is written in lower case at least half the time when it isn't at the start of a
    sentence (drops names and abbreviations such as "Tom" and "Mr"; "i" is kept),
  - and is not a Roman numeral, a single letter other than "a" and "i", or one of the
    word fragments in NOT_WORDS.

The tables hold counts only, no text from the books. Jane Austen is left out on
purpose: examples/plaintext_eval.rs validates the thresholds on sentences from
Pride and Prejudice, which must not be in the training data. `--heldout` writes those
sentences to examples/data/heldout_pride_and_prejudice.txt instead.

Only the Python 3 standard library is needed.
"""

import argparse
import collections
import math
import os
import re
import sys
import urllib.request

# (Project Gutenberg ebook number, title). English originals only (no translations; checked
# against each file's header), public domain in the US. Mixed registers: novels, plays,
# poetry, essays, science, philosophy, economics and politics.
BOOKS = [
    (11, "Alice's Adventures in Wonderland"),
    (12, 'Through the Looking-Glass'),
    (16, 'Peter Pan'),
    (23, 'Narrative of the Life of Frederick Douglass'),
    (35, 'The Time Machine'),
    (36, 'The War of the Worlds'),
    (41, 'The Legend of Sleepy Hollow'),
    (43, 'The Strange Case of Dr. Jekyll and Mr. Hyde'),
    (45, 'Anne of Green Gables'),
    (46, 'A Christmas Carol'),
    (55, 'The Wonderful Wizard of Oz'),
    (74, 'The Adventures of Tom Sawyer'),
    (76, 'Adventures of Huckleberry Finn'),
    (84, 'Frankenstein'),
    (86, "A Connecticut Yankee in King Arthur's Court"),
    (108, 'The Return of Sherlock Holmes'),
    (113, 'The Secret Garden'),
    (120, 'Treasure Island'),
    (139, 'The Lost World'),
    (145, 'Middlemarch'),
    (147, 'Common Sense'),
    (159, 'The Island of Doctor Moreau'),
    (160, 'The Awakening, and Selected Short Stories'),
    (174, 'The Picture of Dorian Gray'),
    (205, 'Walden'),
    (209, 'The Turn of the Screw'),
    (215, 'The Call of the Wild'),
    (219, 'Heart of Darkness'),
    (236, 'The Jungle Book'),
    (244, 'A Study in Scarlet'),
    (245, 'Life on the Mississippi'),
    (289, 'The Wind in the Willows'),
    (345, 'Dracula'),
    (408, 'The Souls of Black Folk'),
    (432, 'The Ambassadors'),
    (514, 'Little Women'),
    (550, 'Silas Marner'),
    (580, 'The Pickwick Papers'),
    (730, 'Oliver Twist'),
    (766, 'David Copperfield'),
    (768, 'Wuthering Heights'),
    (829, "Gulliver's Travels"),
    (834, 'The Memoirs of Sherlock Holmes'),
    (844, 'The Importance of Being Earnest'),
    (863, 'The Mysterious Affair at Styles'),
    (885, 'An Ideal Husband'),
    (902, 'The Happy Prince, and Other Tales'),
    (910, 'White Fang'),
    (1023, 'Bleak House'),
    (1155, 'The Secret Adversary'),
    (1228, 'On the Origin of Species'),
    (1260, 'Jane Eyre'),
    (1322, 'Leaves of Grass'),
    (1400, 'Great Expectations'),
    (1404, 'The Federalist Papers'),
    (1661, 'The Adventures of Sherlock Holmes'),
    (1695, 'The Man Who Was Thursday'),
    (1837, 'The Prince and the Pauper'),
    (1952, 'The Yellow Wallpaper'),
    (2097, 'The Sign of the Four'),
    (2147, 'The Works of Edgar Allan Poe, Volume 1'),
    (2148, 'The Works of Edgar Allan Poe, Volume 2'),
    (2641, 'A Room with a View'),
    (2701, 'Moby Dick'),
    (2781, 'Just So Stories'),
    (2814, 'Dubliners'),
    (2833, 'The Portrait of a Lady, Volume 1'),
    (2852, 'The Hound of the Baskervilles'),
    (2891, 'Howards End'),
    (3176, 'The Innocents Abroad'),
    (3300, 'The Wealth of Nations'),
    (3825, 'Pygmalion'),
    (4217, 'A Portrait of the Artist as a Young Man'),
    (4276, 'North and South'),
    (4705, 'A Treatise of Human Nature'),
    (5230, 'The Invisible Man'),
    (5827, 'The Problems of Philosophy'),
    (6593, 'The History of Tom Jones, a Foundling'),
    (7370, 'Second Treatise of Government'),
    (8492, 'The King in Yellow'),
    (9662, 'An Enquiry Concerning Human Understanding'),
    (20203, 'Autobiography of Benjamin Franklin'),
    (25344, 'The Scarlet Letter'),
    (34901, 'On Liberty'),
    (37134, 'The Elements of Style'),
]

QUADGRAM_SCALE = 25.0  # byte = round(-log10(p) * QUADGRAM_SCALE)
UNSEEN_COUNT = 0.01
SHORT_WORD_MIN_PER_MILLION = 15.0
SHORT_WORD_MIN_BOOKS = 20
# Pieces of hyphenated words, abbreviations and French that pass the filters above
NOT_WORDS = {"co", "de", "em", "en", "la", "le", "non", "re", "th", "un"}

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
HELDOUT = os.path.join(ROOT, "examples", "data", "heldout_pride_and_prejudice.txt")
PRIDE_AND_PREJUDICE = 1342

ROMAN = re.compile(r"^(?=[ivxlcdm]+$)m{0,3}(cm|cd|d?c{0,3})(xc|xl|l?x{0,3})(ix|iv|v?i{0,3})$")
WORD = re.compile(r"[A-Za-z]+(?:'[A-Za-z]+)*")


def fetch(number, cache):
    path = os.path.join(cache, f"pg{number}.txt")
    if not os.path.exists(path):
        url = f"https://www.gutenberg.org/cache/epub/{number}/pg{number}.txt"
        print(f"downloading {url}", file=sys.stderr)
        request = urllib.request.Request(url, headers={"User-Agent": "ciphey ngram generator"})
        with urllib.request.urlopen(request, timeout=60) as response:
            data = response.read()
        with open(path, "wb") as f:
            f.write(data)
    with open(path, encoding="utf-8-sig", errors="replace") as f:
        return f.read()


def strip_gutenberg(text, number):
    """The book itself: everything between the START and END markers."""
    header = text[:5000]
    if not re.search(r"^Language: English\s*$", header, re.M) or re.search(r"^Translator", header, re.M | re.I):
        sys.exit(f"pg{number}.txt: not an English original")
    start = re.search(r"\*\*\* ?START OF (THE|THIS) PROJECT GUTENBERG EBOOK[^\n]*\n", text, re.I)
    end = re.search(r"\*\*\* ?END OF (THE|THIS) PROJECT GUTENBERG EBOOK", text, re.I)
    if not start or not end:
        sys.exit(f"pg{number}.txt: could not find the Project Gutenberg start/end markers")
    return text[start.end():end.start()]


def write_heldout(cache):
    """140 sentences and 60 short phrases from Pride and Prejudice, picked evenly."""
    body = strip_gutenberg(fetch(PRIDE_AND_PREJUDICE, cache), PRIDE_AND_PREJUDICE)
    for curly, straight in (("\u2018", "'"), ("\u2019", "'"), ("\u201c", '"'), ("\u201d", '"'), ("\u2014", " - "), ("_", "")):
        body = body.replace(curly, straight)
    body = re.sub(r"\s+", " ", body[body.index("It is a truth universally"):])
    # "Mr. Bennet" is not the end of a sentence
    body = re.sub(r"\b(Mr|Mrs|Dr|St)\.", r"\1", body)
    sentences = [s.strip(' "') for s in re.split(r'(?<=[.!?])\s+(?=["A-Z])', body)]
    usable = [
        s for s in sentences
        if s.isascii() and 5 <= len(s.split()) <= 14 and not re.search(r"[\[\]\d]|CHAPTER|Chapter", s)
    ]
    step = len(usable) // 140
    chosen = [usable[i * step] for i in range(140)]
    rest = [s for i, s in enumerate(usable) if i % step != 0]
    phrase_step = len(rest) // 60
    phrases = []
    for i in range(60):
        words = re.findall(r"[A-Za-z']+", rest[i * phrase_step])
        length = 1 + i % 4
        start = i % (len(words) - length + 1)
        phrases.append(" ".join(words[start : start + length]))
    os.makedirs(os.path.dirname(HELDOUT), exist_ok=True)
    with open(HELDOUT, "w", newline="\n") as f:
        f.write(
            "# Held-out text for examples/plaintext_eval.rs (PDETECT_HELDOUT=1): 140 sentences of 5 to 14\n"
            "# words and 60 phrases of 1 to 4 words from Jane Austen's Pride and Prejudice (1813, public\n"
            "# domain; Project Gutenberg ebook 1342). Nothing by Austen is in the books that\n"
            "# src/storage/ngrams/generate.py counts. Written by `generate.py --heldout`: every k-th\n"
            "# usable sentence, then 1, 2, 3 or 4 words (in turn) from inside every m-th other one.\n"
        )
        f.write("\n".join(chosen + phrases) + "\n")
    print(f"{len(usable)} usable sentences, wrote {HELDOUT}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--cache", default=os.path.join(ROOT, "target", "gutenberg"))
    parser.add_argument("--heldout", action="store_true", help="write the held-out file instead")
    args = parser.parse_args()
    os.makedirs(args.cache, exist_ok=True)
    if args.heldout:
        write_heldout(args.cache)
        return

    counts = [0] * (26 ** 4)
    total = 0
    words = collections.Counter()  # every word, lower-cased
    books = collections.Counter()  # short word -> number of books it is in
    lower = collections.Counter()  # short word -> times written in lower case
    capital = collections.Counter()  # short word -> times capitalised mid-sentence
    for number, title in BOOKS:
        body = strip_gutenberg(fetch(number, args.cache), number)
        letters = [ord(c) - 65 for c in body.upper() if "A" <= c <= "Z"]
        for i in range(len(letters) - 3):
            counts[((letters[i] * 26 + letters[i + 1]) * 26 + letters[i + 2]) * 26 + letters[i + 3]] += 1
        total += max(len(letters) - 3, 0)

        # Curly apostrophes count as apostrophes
        body = body.replace("\u2019", "'")
        in_book = set()
        for match in WORD.finditer(body):
            word = match.group(0)
            low = word.lower()
            words[low] += 1
            if len(low) > 3:
                continue
            in_book.add(low)
            if word == low:
                lower[low] += 1
            else:
                # Capitalised after a letter, comma or semicolon: not the start of a sentence
                i = match.start() - 1
                while i >= 0 and body[i] in " \t":
                    i -= 1
                if i >= 0 and (body[i].isalpha() or body[i] in ",;"):
                    capital[low] += 1
        books.update(in_book)
        print(f"{number:>6} {title}: {len(letters):,} letters", file=sys.stderr)

    table = bytearray(26 ** 4)
    for i, n in enumerate(counts):
        log_p = math.log10((n if n else UNSEEN_COUNT) / total)
        table[i] = min(255, round(-log_p * QUADGRAM_SCALE))
    with open(os.path.join(HERE, "english_quadgrams.bin"), "wb") as f:
        f.write(bytes(table))

    total_words = sum(words.values())
    short = sorted(
        w
        for w, n in words.items()
        if len(w) <= 3
        and n * 1e6 / total_words >= SHORT_WORD_MIN_PER_MILLION
        and books[w] >= SHORT_WORD_MIN_BOOKS
        and (w.startswith("i") and not w[1:2].isalpha() or lower[w] >= capital[w])
        and (len(w) > 1 or w in ("a", "i"))
        and (w == "i" or not ROMAN.match(w))
        and w not in NOT_WORDS
    )
    with open(os.path.join(HERE, "english_short_words.txt"), "w") as f:
        f.write("\n".join(short) + "\n")

    seen = sum(1 for n in counts if n)
    print(
        f"{len(BOOKS)} books, {total:,} quadgrams, {seen:,} of {26 ** 4:,} distinct quadgrams seen, "
        f"{total_words:,} words, {len(short)} short words",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
