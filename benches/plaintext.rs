//! Plaintext-detection benchmark: how well the checkers tell plaintext from the junk a
//! search produces, how long each check takes, and what that does to whole searches.
//!
//! ```text
//! cargo bench --bench plaintext                      # checkers and decoders, both splits
//! cargo bench --bench plaintext -- --split=heldout   # only the held-out half
//! cargo bench --bench plaintext -- --e2e             # also the end-to-end corpora (minutes)
//! cargo bench --bench plaintext -- --e2e-only
//! cargo bench --bench plaintext -- --examples        # list misclassified samples
//! cargo bench --bench plaintext -- --check < lines   # classify each line of stdin
//! cargo bench --bench plaintext -- --tsv=out.tsv     # also write the numbers as TSV
//! cargo bench --bench plaintext -- --dump=FILE       # every sample with every verdict
//! cargo bench --bench plaintext -- --vigenere-keys   # Vigenère key search by key length
//! cargo bench --bench plaintext -- --no-captured     # leave out the captured candidates
//! cargo bench --bench plaintext -- --capture=FILE    # re-capture search candidates
//! ```
//!
//! The data set is in `benches/data/plaintext/` (see docs/plaintext-detection.md):
//!
//! * `curated.tsv` and `gutenberg.tsv`: plaintext of many kinds, plus a few fixed negatives
//!   (hashes) and informational categories (other languages, formats Ciphey ignores on
//!   purpose) that are reported but left out of the totals. Formats that look like
//!   credentials are generated at start-up instead (`generated_formats`).
//! * Near misses derived from those here, the way decoders produce them: wrong Caesar,
//!   ROT47, Atbash, railfence and Vigenère keys, reversed text, one layer of encoding left,
//!   and random noise and mojibake. Each inherits its source's split.
//! * `captured.tsv`: texts the A* search really asked the checkers about on the end-to-end
//!   corpora (written by `--capture`), which are not the answer.
//! * `e2e.tsv` and `search.toml`: end-to-end inputs with their expected plaintext.
//!
//! Every sample is in the `train` or the `heldout` split. Thresholds are tuned on train
//! only; held-out is the check that they generalise.
//!
//! Deterministic: fixed data and an xorshift generator with a fixed seed. Timings are not:
//! they depend on the machine and its load.

mod common;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::Write as _;
use std::hint::black_box;
use std::io::Write as _;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use ciphey::checkers::{
    athena::Athena,
    checker_type::{Check, Checker},
    code_checker::CodeChecker,
    english::EnglishChecker,
    json_checker::JsonChecker,
    lemmeknow_checker::LemmeKnow,
    password::PasswordChecker,
    CheckerTypes,
};
use ciphey::config::Config;
use ciphey::decoders::{
    atbash_decoder::AtbashDecoder,
    caesar_decoder::CaesarDecoder,
    interface::{Crack, Decoder},
    railfence_decoder::RailfenceDecoder,
    rot47_decoder::ROT47Decoder,
    vigenere_decoder::VigenereDecoder,
};
use ciphey::{perform_cracking, CipheyError};
use data_encoding::{BASE32, HEXLOWER, HEXUPPER};
use gibberish_or_not::{is_gibberish, Sensitivity};

// ------------------------------------------------------------------ data set --

/// Train or held-out.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
enum Split {
    Train,
    Heldout,
}

impl Split {
    fn parse(s: &str) -> Split {
        match s {
            "train" => Split::Train,
            "heldout" => Split::Heldout,
            other => panic!("unknown split {other:?}"),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Split::Train => "train",
            Split::Heldout => "heldout",
        }
    }
}

/// What a checker should say about a sample.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Label {
    /// Plaintext: should be accepted.
    Pos,
    /// Not the plaintext: should be rejected.
    Neg,
    /// Reported, but not counted in any total: Ciphey doesn't claim to accept these
    /// (other languages, formats it ignores on purpose).
    Info,
}

/// One sample.
struct Sample {
    text: String,
    /// Category, e.g. `en_phrase` or `caesar_wrong`.
    cat: String,
    /// What the sample is a kind of, or derived from: `english`, `flag`, `json`, `code`,
    /// `net`, `lemmeknow`, `password`, `noise` or `search`.
    family: &'static str,
    label: Label,
    split: Split,
}

/// Label and family of a category in the TSV files.
fn tsv_category(cat: &str) -> (Label, &'static str) {
    match cat {
        "en_word" | "en_phrase" | "en_sentence" | "en_chat" | "en_technical" | "en_formal"
        | "en_ctf" | "en_paragraph" | "en_verse" | "en_literary" | "en_nospace" => {
            (Label::Pos, "english")
        }
        "ctf_flag" => (Label::Pos, "flag"),
        "json" => (Label::Pos, "json"),
        "code" => (Label::Pos, "code"),
        "url" | "email" | "ip" => (Label::Pos, "net"),
        "lemmeknow" => (Label::Pos, "lemmeknow"),
        "password" => (Label::Pos, "password"),
        "non_english" => (Label::Info, "non_english"),
        "lemmeknow_ignored" => (Label::Info, "lemmeknow_ignored"),
        "hash" => (Label::Neg, "noise"),
        "search_answer" => (Label::Pos, "search"),
        "search_hard" | "search_random" => (Label::Neg, "search"),
        other => panic!("unknown category {other:?} in benches/data/plaintext"),
    }
}

/// Path of a file in `benches/data/plaintext`.
fn data_file(name: &str) -> std::path::PathBuf {
    common::data_path("plaintext").join(name)
}

/// Undoes the TSV escapes `\t`, `\n`, `\r` and `\\`.
fn unescape(field: &str) -> String {
    let mut out = String::with_capacity(field.len());
    let mut chars = field.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('t') => out.push('\t'),
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('\\') => out.push('\\'),
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    out
}

/// Applies the TSV escapes.
fn escape(text: &str) -> String {
    text.replace('\\', "\\\\")
        .replace('\t', "\\t")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

/// The non-comment lines of a TSV file, split on tabs. A missing file is empty.
fn read_tsv(name: &str) -> Vec<Vec<String>> {
    let path = data_file(name);
    let Ok(text) = std::fs::read_to_string(&path) else {
        return Vec::new();
    };
    text.lines()
        // Git may check the files out with CRLF line ends on Windows
        .map(|line| line.strip_suffix('\r').unwrap_or(line))
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| line.split('\t').map(unescape).collect())
        .collect()
}

/// `category<TAB>split<TAB>text` files.
fn load_samples(name: &str) -> Vec<Sample> {
    read_tsv(name)
        .into_iter()
        .map(|fields| {
            let [cat, split, text] = <[String; 3]>::try_from(fields)
                .unwrap_or_else(|f| panic!("{name}: expected 3 fields, got {f:?}"));
            let (label, family) = tsv_category(&cat);
            Sample {
                text,
                cat,
                family,
                label,
                split: Split::parse(&split),
            }
        })
        .collect()
}

/// xorshift64* so the data set does not depend on the `rand` crate version.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// Inclusive range.
    fn range(&mut self, lo: usize, hi: usize) -> usize {
        lo + (self.next() % (hi - lo + 1) as u64) as usize
    }

    fn pick<T: Copy>(&mut self, items: &[T]) -> T {
        items[self.range(0, items.len() - 1)]
    }
}

/// A hash of `text` for choices that must not depend on the order samples are generated
/// in: FNV-1a, then MurmurHash3's finaliser, because FNV-1a's low bits are poorly mixed
/// (bit 0 is the parity of the number of odd bytes).
fn text_hash(text: &str) -> u64 {
    let mut h = text.bytes().fold(0xCBF2_9CE4_8422_2325u64, |h, b| {
        (h ^ u64::from(b)).wrapping_mul(0x100_0000_01B3)
    });
    h ^= h >> 33;
    h = h.wrapping_mul(0xFF51_AFD7_ED55_8CCD);
    h ^= h >> 33;
    h = h.wrapping_mul(0xC4CE_B9FE_1A85_EC53);
    h ^ (h >> 33)
}

// ------------------------------------------------- what decoders produce --

fn caesar(s: &str, k: u8) -> String {
    s.chars()
        .map(|c| match c {
            'a'..='z' => (((c as u8 - b'a' + k) % 26) + b'a') as char,
            'A'..='Z' => (((c as u8 - b'A' + k) % 26) + b'A') as char,
            _ => c,
        })
        .collect()
}

fn atbash(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'a'..='z' => (b'z' - (c as u8 - b'a')) as char,
            'A'..='Z' => (b'Z' - (c as u8 - b'A')) as char,
            _ => c,
        })
        .collect()
}

/// Rotates printable ASCII (`!` to `~`) by `shift`; ROT47 is 47.
fn rot47(s: &str, shift: u32) -> String {
    s.chars()
        .map(|c| {
            let b = c as u32;
            if (33..=126).contains(&b) {
                char::from_u32(((b - 33 + shift) % 94) + 33).unwrap()
            } else {
                c
            }
        })
        .collect()
}

fn reverse(s: &str) -> String {
    s.chars().rev().collect()
}

/// Letters only, in upper or lower case.
fn nospace(s: &str, upper: bool) -> String {
    s.chars()
        .filter(char::is_ascii_alphabetic)
        .map(|c| {
            if upper {
                c.to_ascii_uppercase()
            } else {
                c.to_ascii_lowercase()
            }
        })
        .collect()
}

fn vigenere(s: &str, key: &str, decrypt: bool) -> String {
    let k: Vec<u8> = key.bytes().map(|b| b - b'A').collect();
    let mut i = 0;
    s.chars()
        .map(|c| {
            if c.is_ascii_alphabetic() {
                let base = if c.is_ascii_uppercase() { b'A' } else { b'a' };
                let shift = if decrypt {
                    26 - k[i % k.len()]
                } else {
                    k[i % k.len()]
                };
                i += 1;
                (((c as u8 - base + shift) % 26) + base) as char
            } else {
                c
            }
        })
        .collect()
}

/// The railfence decoder's zigzag (src/decoders/railfence_decoder.rs).
fn zigzag(n: usize, offset: usize) -> impl Iterator<Item = usize> {
    (0..n - 1).chain((1..n).rev()).cycle().skip(offset)
}

fn rail_encrypt(text: &str, rails: usize) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut idx: Vec<(usize, usize)> = zigzag(rails, 0).zip(0..).take(chars.len()).collect();
    idx.sort();
    idx.iter().map(|&(_, p)| chars[p]).collect()
}

/// The railfence decoder's decryption, to make wrong keys' outputs.
fn rail_decrypt(text: &str, rails: usize, offset: usize) -> String {
    let n = text.chars().count();
    let mut indexes: Vec<_> = zigzag(rails, offset).zip(1..).take(n).collect();
    indexes.sort();
    let mut cwi: Vec<_> = text
        .chars()
        .zip(indexes)
        .map(|(c, (_, i))| (i, c))
        .collect();
    cwi.sort();
    cwi.iter().map(|(_, c)| c).collect()
}

const VIGENERE_KEYS: [&str; 6] = ["LEMON", "KEY", "CIPHEY", "SECRETKEY", "FLAG", "CRYPTO"];

const MORSE: [(char, &str); 36] = [
    ('A', ".-"),
    ('B', "-..."),
    ('C', "-.-."),
    ('D', "-.."),
    ('E', "."),
    ('F', "..-."),
    ('G', "--."),
    ('H', "...."),
    ('I', ".."),
    ('J', ".---"),
    ('K', "-.-"),
    ('L', ".-.."),
    ('M', "--"),
    ('N', "-."),
    ('O', "---"),
    ('P', ".--."),
    ('Q', "--.-"),
    ('R', ".-."),
    ('S', "..."),
    ('T', "-"),
    ('U', "..-"),
    ('V', "...-"),
    ('W', ".--"),
    ('X', "-..-"),
    ('Y', "-.--"),
    ('Z', "--.."),
    ('0', "-----"),
    ('1', ".----"),
    ('2', "..---"),
    ('3', "...--"),
    ('4', "....-"),
    ('5', "....."),
    ('6', "-...."),
    ('7', "--..."),
    ('8', "---.."),
    ('9', "----."),
];

/// One layer of encoding left on the plaintext: what the search sees one step before the
/// answer, or after a wrong step.
const ENCODINGS: [&str; 14] = [
    "base64",
    "base32",
    "hex",
    "hex_spaced",
    "binary",
    "decimal",
    "octal",
    "url",
    "morse",
    "a1z26",
    "html_entities",
    "unicode_escapes",
    "base58",
    "z85",
];

fn encode(text: &str, encoding: &str) -> String {
    let bytes = text.as_bytes();
    let join = |parts: Vec<String>, sep: &str| parts.join(sep);
    match encoding {
        "base64" => B64.encode(bytes),
        "base32" => BASE32.encode(bytes),
        "hex" => HEXLOWER.encode(bytes),
        "hex_spaced" => join(bytes.iter().map(|b| format!("{b:02X}")).collect(), " "),
        "binary" => join(bytes.iter().map(|b| format!("{b:08b}")).collect(), " "),
        "decimal" => join(bytes.iter().map(|b| b.to_string()).collect(), " "),
        "octal" => join(bytes.iter().map(|b| format!("{b:o}")).collect(), " "),
        "url" => urlencoding::encode(text).into_owned(),
        "morse" => join(
            text.split_whitespace()
                .map(|word| {
                    join(
                        word.chars()
                            .filter_map(|c| {
                                MORSE
                                    .iter()
                                    .find(|(l, _)| *l == c.to_ascii_uppercase())
                                    .map(|(_, m)| m.to_string())
                            })
                            .collect(),
                        " ",
                    )
                })
                .filter(|w| !w.is_empty())
                .collect(),
            " / ",
        ),
        "a1z26" => join(
            text.split_whitespace()
                .map(|word| {
                    join(
                        word.chars()
                            .filter(char::is_ascii_alphabetic)
                            .map(|c| (c.to_ascii_lowercase() as u8 - b'a' + 1).to_string())
                            .collect(),
                        "-",
                    )
                })
                .filter(|w| !w.is_empty())
                .collect(),
            " ",
        ),
        "html_entities" => text.chars().map(|c| format!("&#{};", c as u32)).collect(),
        "unicode_escapes" => text
            .chars()
            .map(|c| format!("\\u{:04X}", c as u32))
            .collect(),
        "base58" => bs58::encode(bytes).into_string(),
        "z85" => z85::encode(bytes),
        other => panic!("unknown encoding {other}"),
    }
}

/// UTF-8 bytes read as Latin-1, the usual mojibake.
fn latin1_misread(text: &str) -> String {
    text.bytes().map(char::from).collect()
}

/// UTF-16LE bytes read as Latin-1 (what Base64 of PowerShell's `-EncodedCommand` decodes
/// to before the UTF-16 decoder runs).
fn utf16_misread(text: &str) -> String {
    text.encode_utf16()
        .flat_map(u16::to_le_bytes)
        .map(char::from)
        .collect()
}

/// Adds `sample`'s near misses, the way decoders produce them, to `out`.
fn derive_near_misses(sample: &Sample, rng: &mut Rng, out: &mut Vec<Sample>) {
    let p = sample.text.as_str();
    let letters = p.chars().filter(char::is_ascii_alphabetic).count();
    let mut add = |cat: &str, text: String| {
        if text != p && !text.is_empty() {
            out.push(Sample {
                text,
                cat: cat.to_string(),
                family: sample.family,
                label: Label::Neg,
                split: sample.split,
            });
        }
    };
    match sample.family {
        "english" | "flag" => {
            let first = rng.range(1, 25) as u8;
            let mut second = rng.range(1, 24) as u8;
            if second >= first {
                second += 1;
            }
            let shifts: &[u8] = if letters >= 3 { &[first, second] } else { &[] };
            for &k in shifts {
                add("caesar_wrong", caesar(p, k));
            }
            add("rot47", rot47(p, 47));
            add("atbash", atbash(p));
            add("reversed", reverse(p));
            if p.chars().count() >= 10 {
                let ct = rail_encrypt(p, 3);
                let keys = [(2, 0), (2, 1), (3, 1), (4, 0), (4, 2), (5, 3)];
                for _ in 0..2 {
                    let (rails, offset) = rng.pick(&keys);
                    add("railfence_wrong", rail_decrypt(&ct, rails, offset));
                }
            }
            if sample.family == "english" && letters >= 10 {
                let key = rng.pick(&VIGENERE_KEYS);
                let ct = vigenere(p, key, false);
                let len = rng.range(3, 8);
                let wrong: String = (0..len)
                    .map(|_| (b'A' + rng.range(0, 25) as u8) as char)
                    .collect();
                if wrong != key {
                    add("vigenere_wrong", vigenere(&ct, &wrong, true));
                }
                if letters >= 20 {
                    // Partly decrypted: the last key letter is off by one
                    let mut partial: Vec<u8> = key.bytes().collect();
                    let last = partial.len() - 1;
                    partial[last] = b'A' + ((partial[last] - b'A' + 1) % 26);
                    add(
                        "vigenere_partial",
                        vigenere(&ct, std::str::from_utf8(&partial).unwrap(), true),
                    );
                }
            }
            add("encoded", encode(p, rng.pick(&ENCODINGS)));
        }
        "json" | "code" | "net" | "lemmeknow" | "password" => {
            if sample.family != "json" && letters >= 3 {
                add("caesar_wrong", caesar(p, rng.range(1, 25) as u8));
            }
            add("rot47", rot47(p, 47));
            add("reversed", reverse(p));
            add("encoded", encode(p, rng.pick(&ENCODINGS)));
        }
        _ => {}
    }
}

/// Upper case and space-less variants of half of the English sentences and phrases: the
/// shapes classical ciphers and Morse code leave plaintext in.
fn derive_variants(sample: &Sample, out: &mut Vec<Sample>) {
    let sentence_like = matches!(
        sample.cat.as_str(),
        "en_phrase"
            | "en_sentence"
            | "en_chat"
            | "en_technical"
            | "en_formal"
            | "en_ctf"
            | "en_literary"
            | "en_verse"
    );
    if !sentence_like {
        return;
    }
    let h = text_hash(&sample.text);
    let mut add = |cat: &str, text: String| {
        out.push(Sample {
            text,
            cat: cat.to_string(),
            family: "english",
            label: Label::Pos,
            split: sample.split,
        })
    };
    if h & 1 == 1 {
        add("en_caps", sample.text.to_uppercase());
    }
    let words = sample.text.split_whitespace().count();
    let letters = nospace(&sample.text, true);
    if h & 2 == 2 && words >= 2 && letters.len() >= 8 {
        add("en_nospace", nospace(&sample.text, h & 4 == 4));
    }
}

/// Random strings and mojibake: what wrong decoders make of anything.
fn noise(rng: &mut Rng, english: &[&Sample], foreign: &[&Sample], out: &mut Vec<Sample>) {
    let mut i = 0usize;
    let mut add = |cat: &str, text: String, out: &mut Vec<Sample>| {
        i += 1;
        out.push(Sample {
            text,
            cat: cat.to_string(),
            family: "noise",
            label: Label::Neg,
            split: if i.is_multiple_of(2) {
                Split::Train
            } else {
                Split::Heldout
            },
        });
    };
    let upper = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let lower = b"abcdefghijklmnopqrstuvwxyz";
    let alnum = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let ascii: Vec<u8> = (0x21u8..=0x7e).collect();
    let string = |rng: &mut Rng, alphabet: &[u8], lo: usize, hi: usize| -> String {
        let n = rng.range(lo, hi);
        (0..n).map(|_| rng.pick(alphabet) as char).collect()
    };
    for _ in 0..100 {
        let s = string(rng, upper, 4, 48);
        add("rand_upper", s, out);
        let s = string(rng, lower, 4, 48);
        add("rand_lower", s, out);
        let s = string(rng, alnum, 6, 64);
        add("rand_alnum", s, out);
        let s = string(rng, &ascii, 6, 64);
        add("rand_ascii", s, out);
        let s = string(rng, b"0123456789", 4, 24);
        add("digits", s, out);
        let n = rng.range(2, 40);
        let bytes: Vec<u8> = (0..n).map(|_| rng.next() as u8).collect();
        add("hex_random", HEXLOWER.encode(&bytes), out);
        add("base64_random", B64.encode(&bytes), out);
    }
    for _ in 0..60 {
        // Words of random letters
        let words = rng.range(2, 8);
        let s: Vec<String> = (0..words).map(|_| string(rng, lower, 1, 8)).collect();
        add("rand_words", s.join(" "), out);
        let n = rng.range(4, 32);
        let bytes: Vec<u8> = (0..n).map(|_| rng.next() as u8).collect();
        add("base32_random", BASE32.encode(&bytes), out);
        add("hex_upper_random", HEXUPPER.encode(&bytes), out);
        add(
            "binary_random",
            bytes
                .iter()
                .map(|b| format!("{b:08b}"))
                .collect::<Vec<_>>()
                .join(" "),
            out,
        );
        add("rand_bytes", latin1_misread_bytes(&bytes), out);
        add(
            "rand_bytes_lossy",
            String::from_utf8_lossy(&bytes).into_owned(),
            out,
        );
    }
    for sample in english.iter().step_by(12) {
        add("utf16_misread", utf16_misread(&sample.text), out);
    }
    for sample in foreign {
        if !sample.text.is_ascii() {
            add("latin1_misread", latin1_misread(&sample.text), out);
        }
    }
}

/// Bytes read as Latin-1.
fn latin1_misread_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|&b| char::from(b)).collect()
}

/// Samples of the LemmeKnow formats that look like credentials (API keys, tokens,
/// webhooks), made from random characters at start-up. Committed strings in these formats,
/// even pyWhat's published examples, are blocked by GitHub's secret scanning, so they
/// can't be in the data files. Shape-only patterns that Ciphey ignores on purpose (Twilio
/// SIDs, Bitly keys and other fixed-length hex) are `lemmeknow_ignored`.
fn generated_formats(rng: &mut Rng, out: &mut Vec<Sample>) {
    const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    const LOWER_ALNUM: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    const HEX: &[u8] = b"0123456789abcdef";
    const DIGITS: &[u8] = b"0123456789";
    const URL_SAFE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut s = |alphabet: &[u8], n: usize| -> String {
        (0..n).map(|_| rng.pick(alphabet) as char).collect()
    };
    let mut samples: Vec<(&str, String)> = Vec::new();
    for _ in 0..2 {
        samples.extend([
            (
                "lemmeknow",
                format!(
                    "xoxp-{}-{}-{}-{}",
                    s(DIGITS, 12),
                    s(DIGITS, 12),
                    s(DIGITS, 12),
                    s(LOWER_ALNUM, 32)
                ),
            ),
            (
                "lemmeknow",
                format!(
                    "https://hooks.slack.com/services/T{}/B{}/{}",
                    s(ALNUM, 9),
                    s(ALNUM, 9),
                    s(ALNUM, 24)
                ),
            ),
            ("lemmeknow", format!("sq0csp-{}", s(URL_SAFE, 43))),
            ("lemmeknow", format!("sk_live_{}", s(ALNUM, 24))),
            ("lemmeknow", format!("ghp_{}", s(ALNUM, 36))),
            ("lemmeknow", format!("gho_{}", s(ALNUM, 36))),
            ("lemmeknow", format!("npm_{}", s(ALNUM, 36))),
            (
                "lemmeknow",
                format!(
                    "{}-{}.apps.googleusercontent.com",
                    s(DIGITS, 12),
                    s(LOWER_ALNUM, 32)
                ),
            ),
            (
                "lemmeknow",
                format!("hawk.{}.{}", s(URL_SAFE, 20), s(URL_SAFE, 20)),
            ),
            ("lemmeknow", format!("NRAK-{}", s(LOWER_ALNUM, 27))),
            (
                "lemmeknow",
                format!(
                    "https://discord.com/api/webhooks/{}/{}",
                    s(DIGITS, 18),
                    s(URL_SAFE, 68)
                ),
            ),
            ("lemmeknow", format!("pypi-AgEIcHlwaS5vcmc{}", s(URL_SAFE, 50))),
            ("lemmeknow", format!("{}-us{}", s(HEX, 32), s(DIGITS, 1))),
            ("lemmeknow", format!("secret_{}", s(ALNUM, 43))),
            (
                "lemmeknow",
                format!("AIza{}", s(URL_SAFE, 35)),
            ),
            ("lemmeknow", format!("key-{}", s(ALNUM, 32))),
            ("lemmeknow", format!("pub{}", s(HEX, 32))),
            (
                "lemmeknow",
                format!("{}|{}", s(DIGITS, 16), s(ALNUM, 27)),
            ),
            ("lemmeknow_ignored", format!("AC{}", s(HEX, 32))),
            ("lemmeknow_ignored", s(HEX, 40)),
        ]);
    }
    for (i, (cat, text)) in samples.into_iter().enumerate() {
        let (label, family) = tsv_category(cat);
        out.push(Sample {
            text,
            cat: cat.to_string(),
            family,
            label,
            split: if i % 2 == 0 {
                Split::Train
            } else {
                Split::Heldout
            },
        });
    }
}

/// The whole data set: the TSV files plus everything derived from them, and the captured
/// search candidates unless `captured` is false.
fn build_dataset(captured: bool) -> Vec<Sample> {
    let mut base = load_samples("curated.tsv");
    base.extend(load_samples("gutenberg.tsv"));
    generated_formats(&mut Rng(0x0005_EC2E_7F02_2026), &mut base);
    let mut derived = Vec::new();
    let mut rng = Rng(0x00C1_FE7E_5EED_2026);
    for sample in &base {
        derive_variants(sample, &mut derived);
    }
    for sample in base.iter().filter(|s| s.label == Label::Pos) {
        derive_near_misses(sample, &mut rng, &mut derived);
    }
    // A wrong Caesar shift and a wrong railfence key of each space-less variant, the usual
    // classical-cipher junk
    let variants: Vec<(String, Split)> = derived
        .iter()
        .filter(|s| s.cat == "en_nospace")
        .map(|s| (s.text.clone(), s.split))
        .collect();
    for (text, split) in variants {
        let k = rng.range(1, 25) as u8;
        for (cat, wrong) in [
            ("caesar_wrong", caesar(&text, k)),
            (
                "railfence_wrong",
                rail_decrypt(&rail_encrypt(&text, 3), 2, 1),
            ),
        ] {
            derived.push(Sample {
                text: wrong,
                cat: cat.into(),
                family: "english",
                label: Label::Neg,
                split,
            });
        }
    }
    let english: Vec<&Sample> = base
        .iter()
        .filter(|s| s.family == "english" && s.label == Label::Pos)
        .collect();
    let foreign: Vec<&Sample> = base.iter().filter(|s| s.cat == "non_english").collect();
    noise(&mut rng, &english, &foreign, &mut derived);
    base.extend(derived);
    if captured {
        base.extend(load_samples("captured.tsv"));
    }

    // A derived negative that happens to be the same text as a positive (a wrong key that
    // decodes correctly, `level` reversed) is not a negative
    let positives: HashSet<String> = base
        .iter()
        .filter(|s| s.label != Label::Neg)
        .map(|s| s.text.clone())
        .collect();
    base.retain(|s| s.label != Label::Neg || !positives.contains(&s.text));
    base
}

// ------------------------------------------------------------------ checkers --

/// A checker under test.
struct Probe {
    name: String,
    /// Whether the checker accepts the text. This is what is timed.
    check: Box<dyn Fn(&str) -> bool>,
    /// Which checker accepted it and as what, for the false-positive breakdown.
    why: Box<dyn Fn(&str) -> String>,
}

const SENSITIVITIES: [(&str, Sensitivity); 3] = [
    ("Low", Sensitivity::Low),
    ("Medium", Sensitivity::Medium),
    ("High", Sensitivity::High),
];

fn probes() -> Vec<Probe> {
    let mut v = Vec::new();
    for (n, s) in SENSITIVITIES {
        let a = Checker::<Athena>::new().with_sensitivity(s);
        let b = Checker::<Athena>::new().with_sensitivity(s);
        v.push(Probe {
            name: format!("Athena@{n}"),
            check: Box::new(move |t| a.check(t).is_identified),
            why: Box::new(move |t| {
                let r = b.check(t);
                format!("{}: {}", r.checker_name, r.description)
            }),
        });
    }
    for (n, s) in SENSITIVITIES {
        let e = Checker::<EnglishChecker>::new().with_sensitivity(s);
        v.push(Probe {
            name: format!("English@{n}"),
            check: Box::new(move |t| e.check(t).is_identified),
            why: Box::new(|_| "English Checker: Words".into()),
        });
    }
    // What the English checker was before #1031, for comparison
    for (n, s) in [("Low", Sensitivity::Low), ("Medium", Sensitivity::Medium)] {
        v.push(Probe {
            name: format!("gibberish-or-not@{n}"),
            check: Box::new(move |t| !is_gibberish(t, s)),
            why: Box::new(|_| "gibberish-or-not".into()),
        });
    }
    let l = Checker::<LemmeKnow>::new();
    let l2 = Checker::<LemmeKnow>::new();
    v.push(Probe {
        name: "LemmeKnow".into(),
        check: Box::new(move |t| l.check(t).is_identified),
        why: Box::new(move |t| format!("LemmeKnow Checker: {}", l2.check(t).description)),
    });
    let j = Checker::<JsonChecker>::new();
    v.push(Probe {
        name: "JSON".into(),
        check: Box::new(move |t| j.check(t).is_identified),
        why: Box::new(|_| "JSON Checker".into()),
    });
    let p = Checker::<PasswordChecker>::new();
    v.push(Probe {
        name: "Password".into(),
        check: Box::new(move |t| p.check(t).is_identified),
        why: Box::new(|_| "Password Checker".into()),
    });
    let c = Checker::<CodeChecker>::new();
    v.push(Probe {
        name: "Code".into(),
        check: Box::new(move |t| c.check(t).is_identified),
        why: Box::new(|_| "Code Checker".into()),
    });
    v
}

/// One checker's answers on the data set, in sample order.
struct Run {
    name: String,
    hit: Vec<bool>,
    /// Nanoseconds per check, `None` when latency is not measured.
    ns: Option<Vec<f64>>,
}

/// Times one check. Checks under 2 µs are repeated so the timer's own cost doesn't count.
fn timed(check: &dyn Fn(&str) -> bool, text: &str) -> (bool, f64) {
    let t0 = Instant::now();
    let hit = check(black_box(text));
    let first = t0.elapsed();
    if first >= Duration::from_micros(2) {
        return (hit, first.as_nanos() as f64);
    }
    let reps = (2_000 / first.as_nanos().max(1)).clamp(2, 256) as u32;
    let t1 = Instant::now();
    for _ in 0..reps {
        black_box(check(black_box(text)));
    }
    (hit, t1.elapsed().as_nanos() as f64 / f64::from(reps))
}

fn run_probe(probe: &Probe, samples: &[Sample], latency: bool) -> Run {
    // Build the lazily compiled regexes and tables before timing anything
    for s in samples.iter().take(200) {
        black_box((probe.check)(&s.text));
    }
    let mut hit = Vec::with_capacity(samples.len());
    let mut ns = Vec::with_capacity(if latency { samples.len() } else { 0 });
    for s in samples {
        if latency {
            let (h, t) = timed(&probe.check, &s.text);
            hit.push(h);
            ns.push(t);
        } else {
            hit.push((probe.check)(&s.text));
        }
    }
    Run {
        name: probe.name.clone(),
        hit,
        ns: latency.then_some(ns),
    }
}

// ------------------------------------------------------------------- metrics --

#[derive(Default, Clone, Copy)]
struct Counts {
    tp: usize,
    fp: usize,
    tn: usize,
    fnn: usize,
}

impl Counts {
    fn add(&mut self, label: Label, hit: bool) {
        match (label, hit) {
            (Label::Pos, true) => self.tp += 1,
            (Label::Pos, false) => self.fnn += 1,
            (Label::Neg, true) => self.fp += 1,
            (Label::Neg, false) => self.tn += 1,
            (Label::Info, _) => {}
        }
    }

    fn precision(&self) -> Option<f64> {
        (self.tp + self.fp > 0).then(|| self.tp as f64 / (self.tp + self.fp) as f64)
    }

    fn recall(&self) -> Option<f64> {
        (self.tp + self.fnn > 0).then(|| self.tp as f64 / (self.tp + self.fnn) as f64)
    }

    fn f1(&self) -> Option<f64> {
        let (p, r) = (self.precision()?, self.recall()?);
        Some(if p + r > 0.0 {
            2.0 * p * r / (p + r)
        } else {
            0.0
        })
    }

    fn fpr(&self) -> Option<f64> {
        (self.fp + self.tn > 0).then(|| self.fp as f64 / (self.fp + self.tn) as f64)
    }
}

fn pct(v: Option<f64>) -> String {
    v.map_or("-".into(), |v| format!("{:.1}%", 100.0 * v))
}

/// Rates of false positives are small, so they get more digits.
fn pct_fine(v: Option<f64>) -> String {
    match v {
        None => "-".into(),
        Some(v) if v > 0.0 && v < 0.001 => format!("{:.3}%", 100.0 * v),
        Some(v) if v < 0.1 => format!("{:.2}%", 100.0 * v),
        Some(v) => format!("{:.1}%", 100.0 * v),
    }
}

fn f2(v: Option<f64>) -> String {
    v.map_or("-".into(), |v| format!("{v:.3}"))
}

fn fmt_ns(ns: f64) -> String {
    if ns < 1000.0 {
        format!("{ns:.0} ns")
    } else if ns < 1_000_000.0 {
        format!("{:.1} µs", ns / 1000.0)
    } else {
        format!("{:.1} ms", ns / 1_000_000.0)
    }
}

/// The `q` quantile (0 to 1) of sorted values.
fn quantile(sorted: &[f64], q: f64) -> f64 {
    if sorted.is_empty() {
        return f64::NAN;
    }
    sorted[((sorted.len() - 1) as f64 * q).round() as usize]
}

fn short(s: &str) -> String {
    let s = s
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('|', "\\|")
        .replace('`', "'");
    if s.chars().count() > 70 {
        format!("{}…", s.chars().take(70).collect::<String>())
    } else {
        s
    }
}

/// Machine-readable copies of the numbers (`--tsv=PATH`), for comparing two runs.
struct Tsv(Mutex<String>);

impl Tsv {
    fn put(&self, section: &str, split: &str, checker: &str, key: &str, value: impl ToString) {
        let mut s = self.0.lock().unwrap();
        let _ = writeln!(
            s,
            "{section}\t{split}\t{checker}\t{key}\t{}",
            value.to_string()
        );
    }
}

// ------------------------------------------------------------------- reports --

/// Which samples a report covers.
#[derive(Clone, Copy)]
enum Scope {
    All,
    Only(Split),
}

impl Scope {
    fn includes(self, split: Split) -> bool {
        match self {
            Scope::All => true,
            Scope::Only(s) => s == split,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Scope::All => "all",
            Scope::Only(s) => s.name(),
        }
    }
}

fn counts_where(
    samples: &[Sample],
    run: &Run,
    scope: Scope,
    keep: impl Fn(&Sample) -> bool,
) -> Counts {
    let mut c = Counts::default();
    for (s, &hit) in samples.iter().zip(&run.hit) {
        if scope.includes(s.split) && keep(s) {
            c.add(s.label, hit);
        }
    }
    c
}

fn report_overview(samples: &[Sample], tsv: &Tsv) {
    println!("## Data set\n");
    println!("| split | positives | negatives | informational (not counted) |");
    println!("|---|---:|---:|---:|");
    for split in [Split::Train, Split::Heldout] {
        let n = |label| {
            samples
                .iter()
                .filter(|s| s.split == split && s.label == label)
                .count()
        };
        println!(
            "| {} | {} | {} | {} |",
            split.name(),
            n(Label::Pos),
            n(Label::Neg),
            n(Label::Info)
        );
        tsv.put("dataset", split.name(), "-", "positives", n(Label::Pos));
        tsv.put("dataset", split.name(), "-", "negatives", n(Label::Neg));
    }
    println!();
}

fn report_overall(samples: &[Sample], runs: &[Run], scope: Scope, tsv: &Tsv) {
    println!(
        "## Overall ({} split{})\n",
        scope.name(),
        if matches!(scope, Scope::All) { "s" } else { "" }
    );
    println!("| checker | precision | recall | F1 | false positives | false-positive rate | missed positives |");
    println!("|---|---:|---:|---:|---:|---:|---:|");
    for run in runs {
        let c = counts_where(samples, run, scope, |_| true);
        println!(
            "| {} | {} | {} | {} | {} | {} | {} |",
            run.name,
            pct(c.precision()),
            pct(c.recall()),
            f2(c.f1()),
            c.fp,
            pct_fine(c.fpr()),
            c.fnn
        );
        for (k, v) in [
            ("precision", c.precision()),
            ("recall", c.recall()),
            ("f1", c.f1()),
            ("fpr", c.fpr()),
        ] {
            tsv.put("overall", scope.name(), &run.name, k, f2(v));
        }
        tsv.put("overall", scope.name(), &run.name, "fp", c.fp);
        tsv.put("overall", scope.name(), &run.name, "fn", c.fnn);
    }
    println!();
}

const FAMILIES: [&str; 7] = [
    "english",
    "flag",
    "json",
    "code",
    "net",
    "lemmeknow",
    "password",
];

fn report_families(samples: &[Sample], runs: &[Run], scope: Scope, tsv: &Tsv) {
    println!(
        "## Per family ({}): F1 (precision / recall)\n",
        scope.name()
    );
    println!("Precision counts the family's own near misses (wrong keys, reversed and encoded copies of its samples) as negatives. `noise` and `search` negatives come from no family; they count in the overall table.\n");
    print!("| family | positives | negatives |");
    for run in runs {
        print!(" {} |", run.name);
    }
    println!();
    print!("|---|---:|---:|");
    for _ in runs {
        print!("---|");
    }
    println!();
    for family in FAMILIES {
        let n = |label| {
            samples
                .iter()
                .filter(|s| scope.includes(s.split) && s.family == family && s.label == label)
                .count()
        };
        print!("| {family} | {} | {} |", n(Label::Pos), n(Label::Neg));
        for run in runs {
            let c = counts_where(samples, run, scope, |s| s.family == family);
            let p = c
                .precision()
                .map_or("-".into(), |p| format!("{:.0}", p * 100.0));
            let r = c
                .recall()
                .map_or("-".into(), |r| format!("{:.0}", r * 100.0));
            print!(" {} ({p} / {r}) |", f2(c.f1()));
            tsv.put(
                "family",
                scope.name(),
                &run.name,
                &format!("{family}.f1"),
                f2(c.f1()),
            );
            tsv.put(
                "family",
                scope.name(),
                &run.name,
                &format!("{family}.precision"),
                f2(c.precision()),
            );
            tsv.put(
                "family",
                scope.name(),
                &run.name,
                &format!("{family}.recall"),
                f2(c.recall()),
            );
        }
        println!();
    }
    println!();
}

/// Categories in the order they first appear, with their label.
fn categories(samples: &[Sample], scope: Scope) -> Vec<(String, &'static str, Label, usize)> {
    let mut v: Vec<(String, &'static str, Label, usize)> = Vec::new();
    for s in samples.iter().filter(|s| scope.includes(s.split)) {
        match v
            .iter_mut()
            .find(|c| c.0 == s.cat && c.1 == s.family && c.2 == s.label)
        {
            Some(c) => c.3 += 1,
            None => v.push((s.cat.clone(), s.family, s.label, 1)),
        }
    }
    v.sort_by(|a, b| {
        let rank = |l: Label| match l {
            Label::Pos => 0,
            Label::Info => 1,
            Label::Neg => 2,
        };
        (rank(a.2), a.1, &a.0).cmp(&(rank(b.2), b.1, &b.0))
    });
    v
}

fn report_categories(samples: &[Sample], runs: &[Run], scope: Scope, tsv: &Tsv) {
    let cats = categories(samples, scope);
    for (title, labels) in [
        ("Recall per positive category", &[Label::Pos][..]),
        (
            "Acceptance rate of informational categories (not counted)",
            &[Label::Info][..],
        ),
        (
            "False-positive rate per negative category",
            &[Label::Neg][..],
        ),
    ] {
        println!("## {title} ({})\n", scope.name());
        print!("| category | n |");
        for run in runs {
            print!(" {} |", run.name);
        }
        println!();
        print!("|---|---:|");
        for _ in runs {
            print!("---:|");
        }
        println!();
        for (cat, family, label, n) in cats.iter().filter(|c| labels.contains(&c.2)) {
            let shown = if *label == Label::Neg {
                format!("{family}/{cat}")
            } else {
                cat.clone()
            };
            print!("| {shown} | {n} |");
            for run in runs {
                let mut hits = 0;
                for (s, &hit) in samples.iter().zip(&run.hit) {
                    if scope.includes(s.split)
                        && &s.cat == cat
                        && s.family == *family
                        && s.label == *label
                        && hit
                    {
                        hits += 1;
                    }
                }
                let rate = hits as f64 / *n as f64;
                let cell = if *label == Label::Neg {
                    pct_fine(Some(rate))
                } else {
                    pct(Some(rate))
                };
                print!(" {cell} |");
                tsv.put("category", scope.name(), &run.name, &shown, f2(Some(rate)));
            }
            println!();
        }
        println!();
    }
}

fn report_latency(samples: &[Sample], runs: &[Run], scope: Scope, tsv: &Tsv) {
    println!("## Time per check ({})\n", scope.name());
    println!("Each sample is timed on its own (checks under 2 µs are repeated and averaged), then the quantiles are taken over samples. Almost everything a search checks is a negative, so the negative columns are the ones that add up.\n");
    println!("| checker | median | p99 | mean | median (negatives) | p99 (negatives) | median (positives) |");
    println!("|---|---:|---:|---:|---:|---:|---:|");
    for run in runs {
        let Some(ns) = &run.ns else { continue };
        let pick = |keep: &dyn Fn(&Sample) -> bool| {
            let mut v: Vec<f64> = samples
                .iter()
                .zip(ns)
                .filter(|(s, _)| scope.includes(s.split) && keep(s))
                .map(|(_, &t)| t)
                .collect();
            v.sort_by(f64::total_cmp);
            v
        };
        let all = pick(&|_| true);
        let neg = pick(&|s| s.label == Label::Neg);
        let pos = pick(&|s| s.label == Label::Pos);
        let mean = all.iter().sum::<f64>() / all.len().max(1) as f64;
        println!(
            "| {} | {} | {} | {} | {} | {} | {} |",
            run.name,
            fmt_ns(quantile(&all, 0.5)),
            fmt_ns(quantile(&all, 0.99)),
            fmt_ns(mean),
            fmt_ns(quantile(&neg, 0.5)),
            fmt_ns(quantile(&neg, 0.99)),
            fmt_ns(quantile(&pos, 0.5)),
        );
        tsv.put(
            "latency",
            scope.name(),
            &run.name,
            "p50",
            quantile(&all, 0.5).round(),
        );
        tsv.put(
            "latency",
            scope.name(),
            &run.name,
            "p99",
            quantile(&all, 0.99).round(),
        );
        tsv.put("latency", scope.name(), &run.name, "mean", mean.round());
        tsv.put(
            "latency",
            scope.name(),
            &run.name,
            "neg_p50",
            quantile(&neg, 0.5).round(),
        );
        tsv.put(
            "latency",
            scope.name(),
            &run.name,
            "neg_p99",
            quantile(&neg, 0.99).round(),
        );
    }
    println!();
}

fn report_false_positives(samples: &[Sample], runs: &[Run], probes: &[Probe], scope: Scope) {
    for (run, probe) in runs.iter().zip(probes) {
        if !run.name.starts_with("Athena") {
            continue;
        }
        let mut why: BTreeMap<String, (usize, BTreeMap<String, usize>, String)> = BTreeMap::new();
        for (s, &hit) in samples.iter().zip(&run.hit) {
            if hit && s.label == Label::Neg && scope.includes(s.split) {
                let e =
                    why.entry((probe.why)(&s.text))
                        .or_insert((0, BTreeMap::new(), s.text.clone()));
                e.0 += 1;
                *e.1.entry(format!("{}/{}", s.family, s.cat)).or_default() += 1;
            }
        }
        let total: usize = why.values().map(|v| v.0).sum();
        println!(
            "## What accepted negatives: {} ({total}, {})\n",
            run.name,
            scope.name()
        );
        println!("| accepted by | count | categories | example |\n|---|---:|---|---|");
        let mut v: Vec<_> = why.into_iter().collect();
        v.sort_by_key(|e| std::cmp::Reverse(e.1 .0));
        for (reason, (count, cats, example)) in v.iter().take(12) {
            let mut cats: Vec<_> = cats.iter().collect();
            cats.sort_by_key(|c| std::cmp::Reverse(*c.1));
            let cats: Vec<String> = cats
                .iter()
                .take(4)
                .map(|(c, n)| format!("{c} {n}"))
                .collect();
            println!(
                "| {reason} | {count} | {} | `{}` |",
                cats.join(", "),
                short(example)
            );
        }
        println!();
    }
}

fn report_examples(samples: &[Sample], runs: &[Run], scope: Scope, per_category: usize) {
    for run in runs.iter().filter(|r| r.name.starts_with("Athena")) {
        println!("## Misclassified: {} ({})\n", run.name, scope.name());
        let mut shown: HashMap<(String, &'static str), usize> = HashMap::new();
        for (s, &hit) in samples.iter().zip(&run.hit) {
            let wrong = match s.label {
                Label::Pos => !hit,
                Label::Neg => hit,
                Label::Info => false,
            };
            if !wrong || !scope.includes(s.split) {
                continue;
            }
            let n = shown.entry((s.cat.clone(), s.family)).or_default();
            *n += 1;
            if *n <= per_category {
                let kind = if s.label == Label::Pos {
                    "missed"
                } else {
                    "accepted"
                };
                println!(
                    "- {kind} {}/{} ({}): `{}`",
                    s.family,
                    s.cat,
                    s.split.name(),
                    short(&s.text)
                );
            }
        }
        println!();
    }
}

// ------------------------------------------------------------- decoder level --

#[derive(Default)]
struct DecoderCounts {
    n: usize,
    correct: usize,
    wrong: usize,
    none: usize,
    ns: u128,
    wrong_examples: Vec<String>,
}

/// What kind of plaintext a decoder case hides, for the decoder tables.
fn plaintext_kind(s: &Sample) -> Option<&'static str> {
    if s.label != Label::Pos {
        return None;
    }
    Some(match s.cat.as_str() {
        "en_sentence" | "en_chat" | "en_technical" | "en_formal" | "en_ctf" | "en_literary"
        | "en_verse" | "en_paragraph" => "prose",
        "en_word" | "en_phrase" => "short",
        "en_caps" => "caps",
        "en_nospace" => "nospace",
        "ctf_flag" => "flag",
        _ => return None,
    })
}

const KINDS: [&str; 5] = ["prose", "short", "caps", "nospace", "flag"];

fn crack_case<T>(
    decoder: &Decoder<T>,
    plaintext: &str,
    ciphertext: &str,
    checker: &CheckerTypes,
    counts: &mut DecoderCounts,
) where
    Decoder<T>: Crack,
{
    counts.n += 1;
    let t0 = Instant::now();
    let result = decoder.crack(ciphertext, checker);
    counts.ns += t0.elapsed().as_nanos();
    let found = result
        .unencrypted_text
        .as_ref()
        .and_then(|v| v.first())
        .filter(|_| result.success);
    match found {
        Some(text) if text == plaintext => counts.correct += 1,
        Some(text) => {
            counts.wrong += 1;
            if counts.wrong_examples.len() < 3 {
                counts.wrong_examples.push(format!(
                    "`{}` → `{}` instead of `{}`",
                    short(ciphertext),
                    short(text),
                    short(plaintext)
                ));
            }
        }
        None => counts.none += 1,
    }
}

fn report_decoders(samples: &[Sample], scope: Scope, tsv: &Tsv) {
    let checker = CheckerTypes::CheckAthena(Checker::<Athena>::new());
    // At most this many plaintexts of each kind, picked evenly, so the run stays short
    let per_kind = |limit: usize| -> Vec<(&'static str, &Sample)> {
        let mut v = Vec::new();
        for kind in KINDS {
            let all: Vec<&Sample> = samples
                .iter()
                .filter(|s| scope.includes(s.split) && plaintext_kind(s) == Some(kind))
                .collect();
            let step = all.len().div_ceil(limit).max(1);
            v.extend(all.into_iter().step_by(step).map(|s| (kind, s)));
        }
        v
    };
    let mut table: BTreeMap<(&str, &str), DecoderCounts> = BTreeMap::new();
    let caesar_dec = Decoder::<CaesarDecoder>::new();
    let rot47_dec = Decoder::<ROT47Decoder>::new();
    let rail_dec = Decoder::<RailfenceDecoder>::new();
    let vig_dec = Decoder::<VigenereDecoder>::new();
    let atbash_dec = Decoder::<AtbashDecoder>::new();
    for (kind, s) in per_kind(150) {
        let p = s.text.as_str();
        for k in [3u8, 13, 23] {
            let c = table.entry(("Caesar", kind)).or_default();
            crack_case(&caesar_dec, p, &caesar(p, k), &checker, c);
        }
        crack_case(
            &rot47_dec,
            p,
            &rot47(p, 47),
            &checker,
            table.entry(("ROT47", kind)).or_default(),
        );
        crack_case(
            &atbash_dec,
            p,
            &atbash(p),
            &checker,
            table.entry(("Atbash", kind)).or_default(),
        );
        if p.chars().count() >= 8 {
            for rails in [2usize, 3, 5] {
                let c = table.entry(("Railfence", kind)).or_default();
                crack_case(&rail_dec, p, &rail_encrypt(p, rails), &checker, c);
            }
        }
    }
    for (i, (kind, s)) in per_kind(60).into_iter().enumerate() {
        let p = s.text.as_str();
        if p.chars().filter(char::is_ascii_alphabetic).count() >= 25 {
            let key = VIGENERE_KEYS[i % VIGENERE_KEYS.len()];
            let c = table.entry(("Vigenère", kind)).or_default();
            crack_case(&vig_dec, p, &vigenere(p, key, false), &checker, c);
        }
    }

    println!("## Decoders ({})\n", scope.name());
    println!("`crack()` with the Athena checker, as the search calls it, on plaintexts of the data set encrypted with that cipher. Each cell is right / wrong plaintext accepted / nothing found.\n");
    print!("| decoder | all |");
    for kind in KINDS {
        print!(" {kind} |");
    }
    println!(" mean time |");
    print!("|---|---|");
    for _ in KINDS {
        print!("---|");
    }
    println!("---:|");
    for decoder in ["Caesar", "ROT47", "Atbash", "Railfence", "Vigenère"] {
        let mut total = DecoderCounts::default();
        let mut cells = Vec::new();
        for kind in KINDS {
            match table.get(&(decoder, kind)) {
                Some(c) => {
                    total.n += c.n;
                    total.correct += c.correct;
                    total.wrong += c.wrong;
                    total.none += c.none;
                    total.ns += c.ns;
                    cells.push(decoder_cell(c));
                }
                None => cells.push("-".into()),
            }
        }
        println!(
            "| {decoder} | {} | {} | {} |",
            decoder_cell(&total),
            cells.join(" | "),
            fmt_ns(total.ns as f64 / total.n.max(1) as f64)
        );
        let rate = |x: usize| f2(Some(x as f64 / total.n.max(1) as f64));
        tsv.put("decoder", scope.name(), decoder, "n", total.n);
        tsv.put(
            "decoder",
            scope.name(),
            decoder,
            "correct",
            rate(total.correct),
        );
        tsv.put("decoder", scope.name(), decoder, "wrong", rate(total.wrong));
        tsv.put("decoder", scope.name(), decoder, "none", rate(total.none));
    }
    println!();
    let examples: Vec<String> = table
        .iter()
        .flat_map(|((d, k), c)| {
            c.wrong_examples
                .iter()
                .map(move |e| format!("- {d}, {k}: {e}"))
        })
        .collect();
    if !examples.is_empty() {
        println!("Wrong plaintexts accepted:\n");
        for e in examples.iter().take(20) {
            println!("{e}");
        }
        println!();
    }
}

fn decoder_cell(c: &DecoderCounts) -> String {
    if c.n == 0 {
        return "-".into();
    }
    let p = |x: usize| format!("{:.0}%", 100.0 * x as f64 / c.n as f64);
    format!(
        "{} / {} / {} ({})",
        p(c.correct),
        p(c.wrong),
        p(c.none),
        c.n
    )
}

// ---------------------------------------------------------------- end to end --

/// What a search should return.
#[derive(Clone)]
enum Expected {
    Text(String),
    /// Nothing: the input has no plaintext to find.
    Nothing,
    /// The input itself, as already being plaintext.
    Input,
}

struct E2eCase {
    set: String,
    name: String,
    input: String,
    expected: Expected,
}

fn e2e_cases() -> Vec<E2eCase> {
    let mut cases = Vec::new();
    let fixtures: common::SearchFixtures = common::load("search.toml");
    for case in fixtures.case {
        cases.push(E2eCase {
            set: "search.toml".into(),
            expected: if case.kind == "no_solution" {
                Expected::Nothing
            } else {
                Expected::Text(case.expected)
            },
            name: case.name,
            input: case.input,
        });
    }
    for fields in read_tsv("e2e.tsv") {
        let [set, name, input, expected] = <[String; 4]>::try_from(fields)
            .unwrap_or_else(|f| panic!("e2e.tsv: expected 4 fields, got {f:?}"));
        let expected = match expected.as_str() {
            "-" => Expected::Nothing,
            "=" => Expected::Input,
            _ => Expected::Text(expected),
        };
        cases.push(E2eCase {
            set,
            name,
            input,
            expected,
        });
    }
    cases
}

/// How a search ended, compared with what it should have returned.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum Outcome {
    /// The expected plaintext (or nothing, when there is none).
    Correct,
    /// Some other plaintext: the search stopped on a false positive.
    Wrong,
    /// The input returned as plaintext when it wasn't.
    Unchanged,
    /// Nothing found although there was a plaintext.
    Missed,
}

fn grade(
    case: &E2eCase,
    result: &Result<Option<ciphey::DecoderResult>, CipheyError>,
) -> (Outcome, String) {
    match result {
        Ok(Some(found)) => {
            let text = found.text.first().cloned().unwrap_or_default();
            let path: Vec<&str> = found.path.iter().map(|p| p.decoder).collect();
            let returned_input = path == ["Default decoder"];
            let how = format!("`{}` ({})", short(&text), path.join(" → "));
            let outcome = match &case.expected {
                Expected::Text(t) if *t == text => Outcome::Correct,
                Expected::Input if returned_input => Outcome::Correct,
                _ if returned_input => Outcome::Unchanged,
                _ => Outcome::Wrong,
            };
            (outcome, how)
        }
        Ok(None) | Err(CipheyError::Timeout { .. }) => {
            let how = if matches!(result, Ok(None)) {
                "nothing (search exhausted)"
            } else {
                "nothing (timeout)"
            };
            let outcome = match case.expected {
                Expected::Nothing => Outcome::Correct,
                _ => Outcome::Missed,
            };
            (outcome, how.into())
        }
        Err(e) => (Outcome::Missed, format!("error: {e}")),
    }
}

fn run_e2e(timeout: u32, tsv: &Tsv) {
    let cases = e2e_cases();
    println!("## End to end\n");
    println!("`perform_cracking` on each input with a {timeout} s timeout, no cache and decoder statistics reset before each search (like a fresh `ciphey -d -c {timeout}` run). \"Wrong\" means the search stopped on a false positive; for inputs with no plaintext, any result is wrong.\n");
    let mut by_set: BTreeMap<String, Vec<(Outcome, f64, String, String)>> = BTreeMap::new();
    for case in &cases {
        common::fresh_search();
        let t0 = Instant::now();
        let result = perform_cracking(&case.input, common::bench_config());
        let secs = t0.elapsed().as_secs_f64();
        let (outcome, how) = grade(case, &result);
        tsv.put(
            "e2e",
            &case.set,
            &case.name,
            "outcome",
            format!("{outcome:?}"),
        );
        tsv.put("e2e", &case.set, &case.name, "secs", format!("{secs:.3}"));
        by_set
            .entry(case.set.clone())
            .or_default()
            .push((outcome, secs, case.name.clone(), how));
    }
    println!("| set | cases | correct | wrong (false positive) | input returned unchanged | missed | median time | mean time |");
    println!("|---|---:|---:|---:|---:|---:|---:|---:|");
    let all: Vec<(Outcome, f64, String, String)> = by_set.values().flatten().cloned().collect();
    let rows = by_set
        .iter()
        .map(|(set, results)| (set.as_str(), results))
        .chain(std::iter::once(("**all**", &all)));
    for (set, results) in rows {
        let n = |o| results.iter().filter(|r| r.0 == o).count();
        let mut times: Vec<f64> = results.iter().map(|r| r.1).collect();
        times.sort_by(f64::total_cmp);
        println!(
            "| {set} | {} | {} | {} | {} | {} | {:.2} s | {:.2} s |",
            results.len(),
            n(Outcome::Correct),
            n(Outcome::Wrong),
            n(Outcome::Unchanged),
            n(Outcome::Missed),
            quantile(&times, 0.5),
            times.iter().sum::<f64>() / times.len().max(1) as f64
        );
        tsv.put("e2e_summary", set, "-", "correct", n(Outcome::Correct));
        tsv.put("e2e_summary", set, "-", "wrong", n(Outcome::Wrong));
        tsv.put("e2e_summary", set, "-", "unchanged", n(Outcome::Unchanged));
        tsv.put("e2e_summary", set, "-", "missed", n(Outcome::Missed));
    }
    println!("\nNot correct:\n");
    for (set, results) in &by_set {
        for (outcome, secs, name, how) in results.iter().filter(|r| r.0 != Outcome::Correct) {
            println!("- {set}/{name}: {outcome:?} after {secs:.2} s: {how}");
        }
    }
    println!();
}

// ------------------------------------------------------------------- capture --

/// Records every text Athena is asked about, from its trace line.
struct CaptureLogger {
    texts: Mutex<Vec<String>>,
}

impl log::Log for CaptureLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.target() == "ciphey::checkers::athena"
    }

    fn log(&self, record: &log::Record) {
        if record.target() != "ciphey::checkers::athena" {
            return;
        }
        let message = record.args().to_string();
        if let Some(text) = message.strip_prefix("Athena checker running on text: ") {
            self.texts.lock().unwrap().push(text.to_string());
        }
    }

    fn flush(&self) {}
}

static CAPTURE: CaptureLogger = CaptureLogger {
    texts: Mutex::new(Vec::new()),
};

/// Whether `candidate` is the answer, up to case, spacing and punctuation.
fn same_letters(candidate: &str, expected: &str) -> bool {
    let key = |s: &str| -> String {
        s.chars()
            .filter(|c| c.is_alphanumeric())
            .flat_map(char::to_lowercase)
            .collect()
    };
    let (c, e) = (key(candidate), key(expected));
    !e.is_empty() && (c == e || c.contains(&e))
}

/// Runs every end-to-end search with a 1 s timeout and writes the texts the checkers were
/// asked about that are not the answer: all of those Athena@High accepted (`search_hard`)
/// and an even sample of the rest (`search_random`).
fn capture(path: &str) {
    log::set_logger(&CAPTURE).expect("a logger was already installed");
    log::set_max_level(log::LevelFilter::Trace);
    let lenient = Checker::<Athena>::new().with_sensitivity(Sensitivity::High);
    let mut rng = Rng(0x1031_CA97_04E5);
    let mut seen: HashSet<String> = HashSet::new();
    let mut rows: Vec<(String, String)> = Vec::new();
    let cases = e2e_cases();
    for (i, case) in cases.iter().enumerate() {
        CAPTURE.texts.lock().unwrap().clear();
        common::fresh_search();
        let _ = perform_cracking(&case.input, common::bench_config());
        // A search can still be checking on other threads for a moment after it returns
        std::thread::sleep(Duration::from_millis(50));
        let texts = std::mem::take(&mut *CAPTURE.texts.lock().unwrap());
        let expected = match &case.expected {
            Expected::Text(t) => Some(t.as_str()),
            Expected::Input => Some(case.input.as_str()),
            Expected::Nothing => None,
        };
        let mut unique: Vec<String> = texts
            .into_iter()
            .filter(|t| !t.trim().is_empty())
            .filter(|t| expected.is_none_or(|e| !same_letters(t, e)))
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        unique.sort();
        let total = unique.len();
        let (hard, easy): (Vec<String>, Vec<String>) = unique
            .into_iter()
            .partition(|t| lenient.check(t).is_identified);
        let mut kept = 0;
        for t in hard.into_iter().take(200) {
            if seen.insert(t.clone()) {
                rows.push(("search_hard".into(), t));
                kept += 1;
            }
        }
        // An even sample of the rest, 40 per search
        let step = easy.len().div_ceil(40).max(1);
        let offset = rng.range(0, step - 1);
        for t in easy.into_iter().skip(offset).step_by(step) {
            if seen.insert(t.clone()) {
                rows.push(("search_random".into(), t));
                kept += 1;
            }
        }
        eprintln!(
            "[{}/{}] {}/{}: {total} distinct texts checked, kept {kept}",
            i + 1,
            cases.len(),
            case.set,
            case.name
        );
    }
    rows.sort();
    let mut out = String::new();
    out.push_str(
        "# Texts the A* search asked the checkers about while searching the end-to-end corpora\n",
    );
    out.push_str("# (search.toml and e2e.tsv, 1 s timeout each) that are not the answer. search_hard: all that\n");
    out.push_str("# Athena@High accepted when they were captured (up to 200 per search); search_random: an\n");
    out.push_str(
        "# even sample of the rest (40 per search). Written by `cargo bench --bench plaintext --\n",
    );
    out.push_str("# --capture=FILE`; split by a hash of the text. category<TAB>split<TAB>text\n");
    for (cat, text) in rows {
        let split = if text_hash(&text) % 2 == 1 {
            "heldout"
        } else {
            "train"
        };
        let _ = writeln!(out, "{cat}\t{split}\t{}", escape(&text));
    }
    std::fs::write(path, out).expect("could not write the capture file");
    log::set_max_level(log::LevelFilter::Off);
    eprintln!("wrote {path}");
}

/// Writes every sample with the verdicts of Athena and the English checker at each
/// sensitivity and of the format checkers, for tuning thresholds outside this program.
fn dump(samples: &[Sample], path: &str) {
    let probes: Vec<Probe> = probes()
        .into_iter()
        .filter(|p| !p.name.starts_with("gibberish"))
        .collect();
    let mut out = String::from("split\tlabel\tfamily\tcategory");
    for p in &probes {
        let _ = write!(out, "\t{}", p.name);
    }
    out.push_str("\ttext\n");
    for s in samples {
        let _ = write!(
            out,
            "{}\t{:?}\t{}\t{}",
            s.split.name(),
            s.label,
            s.family,
            s.cat
        );
        for p in &probes {
            let _ = write!(out, "\t{}", u8::from((p.check)(&s.text)));
        }
        let _ = writeln!(out, "\t{}", escape(&s.text));
    }
    std::fs::write(path, out).expect("could not write the dump");
}

/// How often the Vigenère decoder finds the key, by key length and by letters per key
/// letter, on the data set's English encrypted with keys of 3 to 12 letters. This is
/// where `MIN_LETTERS_PER_KEY_LETTER` in src/decoders/vigenere_decoder.rs comes from.
fn vigenere_keys(samples: &[Sample]) {
    let checker = CheckerTypes::CheckAthena(Checker::<Athena>::new());
    let decoder = Decoder::<VigenereDecoder>::new();
    let keys = [
        "KEY",
        "FLAG",
        "LEMON",
        "CIPHEY",
        "CRYPTOS",
        "SECRETKY",
        "SECRETKEY",
        "VIGENERES",
        "PASSWORDKEY",
        "ABCDEFGHIJKL",
    ];
    // (letters per key letter, at most 20) -> (cases, right, wrong)
    let mut by_ratio: BTreeMap<usize, (usize, usize, usize)> = BTreeMap::new();
    let mut by_length: BTreeMap<usize, (usize, usize, usize)> = BTreeMap::new();
    for s in samples
        .iter()
        .filter(|s| s.label == Label::Pos && s.family == "english")
        .step_by(3)
    {
        let letters = s.text.chars().filter(char::is_ascii_alphabetic).count();
        if letters < 8 {
            continue;
        }
        for key in keys {
            let result = decoder.crack(&vigenere(&s.text, key, false), &checker);
            let found = result
                .unencrypted_text
                .as_ref()
                .and_then(|v| v.first())
                .filter(|_| result.success);
            for (map, bucket) in [
                (&mut by_ratio, (letters / key.len()).min(20)),
                (&mut by_length, key.len()),
            ] {
                let e = map.entry(bucket).or_default();
                e.0 += 1;
                match found {
                    Some(t) if *t == s.text => e.1 += 1,
                    Some(_) => e.2 += 1,
                    None => {}
                }
            }
        }
    }
    for (title, map) in [
        ("letters per key letter", &by_ratio),
        ("key length", &by_length),
    ] {
        println!("| {title} | cases | right key | wrong plaintext |\n|---:|---:|---:|---:|");
        for (bucket, (n, right, wrong)) in map {
            println!("| {bucket} | {n} | {right} | {wrong} |");
        }
        println!();
    }
}

// --------------------------------------------------------------------- main --

/// Command line, after `cargo bench --bench plaintext --`.
struct Args {
    /// Quick smoke run: `cargo bench -- --test`, or `cargo test --benches` (no `--bench`).
    test: bool,
    scope: Scope,
    examples: Option<usize>,
    latency: bool,
    decoders: bool,
    checkers: bool,
    e2e: Option<u32>,
    capture: Option<String>,
    check: bool,
    tsv: Option<String>,
    dump: Option<String>,
    vigenere_keys: bool,
    no_captured: bool,
    /// A criterion-style filter given to every bench binary that doesn't select this one.
    filtered_out: bool,
}

fn parse_args() -> Args {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    let mut args = Args {
        test: !raw.iter().any(|a| a == "--bench"),
        scope: Scope::All,
        examples: None,
        latency: true,
        decoders: true,
        checkers: true,
        e2e: None,
        capture: None,
        check: false,
        tsv: None,
        dump: None,
        vigenere_keys: false,
        no_captured: false,
        filtered_out: false,
    };
    // Criterion options that take a value, which must not be read as a filter
    const WITH_VALUE: [&str; 12] = [
        "--save-baseline",
        "--baseline",
        "--baseline-lenient",
        "--load-baseline",
        "--sample-size",
        "--warm-up-time",
        "--measurement-time",
        "--nresamples",
        "--noise-threshold",
        "--profile-time",
        "--output-format",
        "--color",
    ];
    let mut filters = Vec::new();
    let mut iter = raw.iter();
    while let Some(arg) = iter.next() {
        let (key, value) = arg.split_once('=').unwrap_or((arg.as_str(), ""));
        match key {
            "--bench" => {}
            "--test" => args.test = true,
            "--split" => {
                args.scope = match value {
                    "all" | "" => Scope::All,
                    split => Scope::Only(Split::parse(split)),
                }
            }
            "--examples" => args.examples = Some(value.parse().unwrap_or(5)),
            "--no-latency" => args.latency = false,
            "--no-decoders" => args.decoders = false,
            "--e2e" => args.e2e = Some(value.parse().unwrap_or(3)),
            "--e2e-only" => {
                args.e2e = Some(value.parse().unwrap_or(3));
                args.checkers = false;
                args.decoders = false;
            }
            "--capture" => args.capture = Some(value.to_string()),
            "--check" => args.check = true,
            "--tsv" => args.tsv = Some(value.to_string()),
            "--dump" => args.dump = Some(value.to_string()),
            "--vigenere-keys" => args.vigenere_keys = true,
            "--no-captured" => args.no_captured = true,
            k if WITH_VALUE.contains(&k) => {
                if value.is_empty() {
                    iter.next();
                }
            }
            k if k.starts_with('-') => {}
            _ => filters.push(arg.clone()),
        }
    }
    args.filtered_out = !filters.is_empty()
        && !filters.iter().any(|f| {
            regex::Regex::new(f).map_or(f.contains("plaintext"), |r| r.is_match("plaintext"))
        });
    args
}

fn main() {
    let args = parse_args();
    if args.filtered_out {
        return;
    }
    // Timeout for the searches: 1 s while capturing, as in the search benches
    let timeout = if args.capture.is_some() {
        1
    } else {
        args.e2e.unwrap_or(1)
    };
    common::init(Config {
        timeout,
        ..common::bench_config()
    });

    if let Some(path) = &args.capture {
        capture(path);
        return;
    }

    if args.check {
        let probes = probes();
        for line in std::io::stdin().lines().map_while(Result::ok) {
            let text = unescape(&line);
            if text.is_empty() {
                continue;
            }
            println!("`{}`", short(&text));
            for probe in &probes {
                let hit = (probe.check)(&text);
                let why = if hit && probe.name.starts_with("Athena") {
                    format!(" ({})", (probe.why)(&text))
                } else {
                    String::new()
                };
                println!("  {}: {hit}{why}", probe.name);
            }
            if let Some(q) = ciphey::storage::ngrams::quadgram_score(&text) {
                println!("  quadgram score: {q:.3}");
            }
        }
        return;
    }

    let tsv = Tsv(Mutex::new(String::new()));
    let mut samples = build_dataset(!args.no_captured);
    if let Some(path) = &args.dump {
        dump(&samples, path);
        return;
    }
    if args.vigenere_keys {
        vigenere_keys(&samples);
        return;
    }
    if args.test {
        // Smoke run: every 40th sample, no timing, no decoders
        samples = samples.into_iter().step_by(40).collect();
        let probes = probes();
        for probe in &probes {
            let run = run_probe(probe, &samples, false);
            assert_eq!(run.hit.len(), samples.len());
        }
        println!(
            "plaintext: {} samples checked by {} checkers",
            samples.len(),
            probes.len()
        );
        return;
    }

    println!("# Plaintext-detection benchmark\n");
    report_overview(&samples, &tsv);
    if args.checkers {
        let probes = probes();
        let runs: Vec<Run> = probes
            .iter()
            .map(|p| run_probe(p, &samples, args.latency))
            .collect();
        let scopes: Vec<Scope> = match args.scope {
            Scope::All => vec![
                Scope::Only(Split::Train),
                Scope::Only(Split::Heldout),
                Scope::All,
            ],
            only => vec![only],
        };
        for &scope in &scopes {
            report_overall(&samples, &runs, scope, &tsv);
        }
        let detail = args.scope;
        report_families(&samples, &runs, detail, &tsv);
        report_categories(&samples, &runs, detail, &tsv);
        if args.latency {
            report_latency(&samples, &runs, detail, &tsv);
        }
        report_false_positives(&samples, &runs, &probes, detail);
        if let Some(n) = args.examples {
            report_examples(&samples, &runs, detail, n);
        }
    }
    if args.decoders {
        for scope in [Scope::Only(Split::Train), Scope::Only(Split::Heldout)] {
            if args.scope.includes(match scope {
                Scope::Only(s) => s,
                Scope::All => Split::Train,
            }) {
                report_decoders(&samples, scope, &tsv);
            }
        }
    }
    if let Some(secs) = args.e2e {
        run_e2e(secs, &tsv);
    }
    std::io::stdout().flush().ok();
    if let Some(path) = &args.tsv {
        std::fs::write(path, tsv.0.into_inner().unwrap()).expect("could not write the TSV file");
    }
}
