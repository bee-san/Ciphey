//! Crack the ASCII shift cipher without knowing the key.
//!
//! Every byte of the plaintext is shifted by the same key k: `c = (p + k) mod 256`, which is
//! CyberChef's `ADD` with a one-byte key and what most CTF write-ups call an ASCII shift, or
//! `c = (p + k) mod 128`, dCode's definition ("the ASCII table is 128 characters") and the one
//! Python Ciphey cracked. Decryption is `p = (c - k) mod m`. Unlike Caesar it moves spaces,
//! digits and punctuation too, and unlike ROT47 it moves spaces and can leave the printable
//! range, so a ciphertext can hold control characters and bytes 0x80 and above.
//!
//! Ciphey passes text between decoders as `String`s, so those bytes arrive as the characters
//! U+0000 to U+00FF: typed in as Latin-1 text, or made by the Hexadecimal and Binary decoders
//! from bytes that aren't UTF-8. The Base64 decoder drops bytes that aren't UTF-8, so, like the
//! single-byte XOR cracker, this cracker also reads Base64 itself when its bytes aren't UTF-8.
//!
//! There are 255 keys mod 256, and 127 more mod 128 when every byte is below 0x80. They are
//! ranked without decrypting anything: a key's score is the English log-likelihood of the bytes
//! it would produce, computed from the ciphertext's byte histogram. Only the best 3 are
//! decrypted, and a decryption is only checked, with Low sensitivity for gibberish detection,
//! if it looks like text: mostly letters, digits and spaces, with English letter pairs and few
//! case changes, or shaped like a CTF flag. At most 3 decryptions are checked.
//!
//! Ciphey runs every decoder on every text the search expands, and most of those are
//! English-like candidates with spaces in them. An ASCII shift ciphertext has a space only
//! where the plaintext had the byte `32 - k`, so for spaces to make up 5% of it that byte has to
//! be a common one. When a text is at least 5% spaces only the keys that turn a space back into
//! one of `etaoinshr` are scored, 9 per modulus instead of up to 382. English and its Caesar,
//! ROT47 or Vigenère shifts aren't ASCII shifts, and those keys turn them into control
//! characters, high bytes and punctuation that don't look like text. Hex, decimal, binary and
//! Morse code are never cracked: no key turns text into them.
//! Reference: <https://www.dcode.fr/ascii-shift-cipher>

use crate::checkers::checker_result::CheckResult;
use crate::checkers::CheckerTypes;
use crate::decoders::affine_decoder::BIGRAM_LOG_PROBS;
use crate::decoders::xor_single_byte_decoder::decode_base64;
use gibberish_or_not::Sensitivity;
use once_cell::sync::Lazy;

use super::crack_results::CrackResult;
use super::interface::Crack;
use super::interface::Decoder;

use log::{debug, trace};

/// The shortest byte string worth cracking: shorter texts are too short to rank keys on.
const MIN_BYTES: usize = 6;

/// The moduli the cracker tries, in the order their keys are ranked on a tie: CyberChef's ADD
/// first, then dCode's 7-bit shift.
const MODULI: [u16; 2] = [256, 128];

/// How many of the best-ranked keys of each byte view are decrypted.
const KEYS_DECRYPTED: usize = 3;

/// How many decryptions are checked at most, the best of all byte views. When none of them is
/// identified, these are what the search gets.
const MAX_CHECKED: usize = 3;

/// A text with at least one space in this many bytes (5%) is only scored on the keys that turn
/// a space into one of [`SPACE_SOURCES`].
const SPACE_RULE_ONE_IN: usize = 20;

/// The plaintext bytes a space may stand for in a text that is at least 5% spaces: the nine
/// most common letters in English.
const SPACE_SOURCES: &[u8; 9] = b"etaoinshr";

/// [`looks_like_text`]: the lowest share, in percent, of a decryption that has to be ASCII
/// letters, digits, spaces, `_`, `{` or `}`. Digits, `_` and braces count because CTF flags are
/// the main use case: with letters and spaces alone `CTF{this_is_my_flag_2024}` is only 60%.
const MIN_TEXTLIKE_PERCENT: usize = 70;

/// [`looks_like_text`]: the fewest pairs of adjacent ASCII letters a decryption needs.
const MIN_LETTER_PAIRS: usize = 3;

/// [`looks_like_text`]: the lowest mean `ln P` of those letter pairs, from
/// `src/storage/ngrams/english_bigrams.txt` (case-folded).
const MIN_MEAN_BIGRAM_LOG_PROB: f32 = -6.3;

/// [`looks_like_text`]: at most one letter pair in this many (20%) may change case, `aB` or
/// `Ab`. This turns away hex-derived junk like `CsEDEDFCA?EsED` and keeps
/// `picoCTF{b4s3_64_1s_fun}` (one pair in six).
const MAX_CASE_FLIPS_ONE_IN: usize = 5;

/// English letter frequencies in percent, `a` to `z`.
const LETTER_PERCENT: [f32; 26] = [
    8.2, 1.5, 2.8, 4.3, 12.7, 2.2, 2.0, 6.1, 7.0, 0.15, 0.8, 4.0, 2.4, 6.7, 7.5, 1.9, 0.1, 6.0,
    6.3, 9.1, 2.8, 1.0, 2.4, 0.15, 2.0, 0.07,
];

/// The punctuation that is common in English and in CTF flags.
const COMMON_PUNCTUATION: &[u8; 12] = b".,'\"-!?:;()_";

/// `ln` of a weight for each byte, how likely it is in English text or a CTF flag:
/// * a lowercase letter: its frequency in [`LETTER_PERCENT`] × 0.42,
/// * an uppercase letter: its frequency × 0.30. That is high enough for all-caps plaintext such
///   as dCode's `ASCII_CODE` to outrank its lowercase twin (the key 32 lower), whose spaces and
///   underscores are `@` and DEL, and low enough for lowercase plaintext to outrank its
///   uppercase twin (the key 32 higher), whose spaces are NUL,
/// * a space: 0.17,
/// * each of [`COMMON_PUNCTUATION`]: 0.004,
/// * each digit, tab, LF and CR: 0.002,
/// * any other printable ASCII character: 0.0005,
/// * anything else (control characters, DEL, bytes 0x80 and above): 1e-6.
static UNIGRAM_LOG_PROBS: Lazy<[f32; 256]> = Lazy::new(|| {
    let mut weights = [1e-6_f32; 256];
    weights[0x21..=0x7e].fill(0.0005);
    for (offset, percent) in LETTER_PERCENT.iter().enumerate() {
        let frequency = percent / 100.0;
        weights[usize::from(b'a') + offset] = frequency * 0.42;
        weights[usize::from(b'A') + offset] = frequency * 0.30;
    }
    weights[usize::from(b' ')] = 0.17;
    for &symbol in COMMON_PUNCTUATION {
        weights[usize::from(symbol)] = 0.004;
    }
    for byte in (b'0'..=b'9').chain(*b"\t\n\r") {
        weights[usize::from(byte)] = 0.002;
    }
    weights.map(f32::ln)
});

/// [`UNIGRAM_LOG_PROBS`] by negated index, twice over: entry `j` is the weight of the byte
/// `-j mod 256`, for `j` in `0..512`. Under the key `k` the byte `b` decrypts to `b - k`, whose
/// weight is entry `k - b + 256`, so the weights of one byte under every key are 256
/// consecutive entries (see [`scores_of_every_key`]).
static NEGATED_LOG_PROBS_256: Lazy<Vec<f32>> = Lazy::new(|| negated_log_probs(256));

/// [`NEGATED_LOG_PROBS_256`] for keys mod 128: entry `j` is the weight of `-j mod 128`, for `j`
/// in `0..256`.
static NEGATED_LOG_PROBS_128: Lazy<Vec<f32>> = Lazy::new(|| negated_log_probs(128));

/// The weight of the byte `-j mod modulus` for every `j` in `0..2 * modulus`.
fn negated_log_probs(modulus: usize) -> Vec<f32> {
    (0..2 * modulus)
        .map(|j| UNIGRAM_LOG_PROBS[(modulus - j % modulus) % modulus])
        .collect()
}

/// The ASCII shift cracker, call:
/// `let ascii_shift_decoder = Decoder::<AsciiShiftDecoder>::new()` to create a new instance
/// And then call:
/// `result = ascii_shift_decoder.crack(input, &checker)` to crack an ASCII shift
/// The struct generated by new() comes from interface.rs
/// ```
/// use ciphey::decoders::ascii_shift_decoder::AsciiShiftDecoder;
/// use ciphey::decoders::interface::{Crack, Decoder};
/// use ciphey::checkers::{athena::Athena, CheckerTypes, checker_type::{Check, Checker}};
///
/// let decoder = Decoder::<AsciiShiftDecoder>::new();
/// let athena_checker = Checker::<Athena>::new();
/// let checker = CheckerTypes::CheckAthena(athena_checker);
///
/// // "hello world" with 7 added to every byte (CyberChef's ADD with the key 07)
/// let result = decoder.crack("olssv'~vysk", &checker);
/// assert!(result.success);
/// assert_eq!(result.unencrypted_text.unwrap()[0], "hello world");
/// assert_eq!(result.key.as_deref(), Some("7 (mod 256)"));
/// ```
pub struct AsciiShiftDecoder;

impl Crack for Decoder<AsciiShiftDecoder> {
    fn new() -> Decoder<AsciiShiftDecoder> {
        Decoder {
            name: "ASCII shift",
            description: "ASCII shift cipher: every byte is shifted by the same key, modulo 256 (CyberChef ADD) or modulo 128 (dCode). Unlike Caesar it shifts spaces, digits and punctuation; unlike ROT47 it can leave the printable range. The bytes are read as Latin-1 text, or as Base64 when that isn't UTF-8. The key is recovered from byte frequencies and the top 3 candidates are checked at Low sensitivity.",
            link: "https://www.dcode.fr/ascii-shift-cipher",
            tags: vec!["ascii_shift", "shift", "substitution", "classic", "decryption"],
            popularity: 0.4,
            phantom: std::marker::PhantomData,
        }
    }

    /// Checks the best decryptions that look like text, at most 3, and returns the first one
    /// the checker identifies, with its key as `7 (mod 256)`. If it identifies none, returns
    /// them all, unidentified, or no text at all if there were none.
    fn crack(&self, text: &str, checker: &CheckerTypes) -> CrackResult {
        trace!("Trying ASCII shift with text {:?}", text);
        let candidates = best_candidates(text);
        if candidates.is_empty() {
            debug!("ASCII shift found no decryption worth checking");
            return CrackResult::new(self, text.to_string());
        }
        // Use the checker with Low sensitivity, like the Caesar and ROT47 crackers
        let checker_with_sensitivity = checker.with_sensitivity(Sensitivity::Low);
        check_candidates(self, text, &candidates, |candidate| {
            checker_with_sensitivity.check(candidate)
        })
    }

    /// Gets all tags for this decoder
    fn get_tags(&self) -> &Vec<&str> {
        &self.tags
    }
    /// Gets the name for the current decoder
    fn get_name(&self) -> &str {
        self.name
    }
    /// Gets the popularity for the current decoder
    fn get_popularity(&self) -> f32 {
        self.popularity
    }
    /// Gets the description for the current decoder
    fn get_description(&self) -> &str {
        self.description
    }
    /// Gets the link for the current decoder
    fn get_link(&self) -> &str {
        self.link
    }
}

/// A key, and how well its decryption of a byte string reads as English.
#[derive(Debug, Clone, Copy, PartialEq)]
struct RankedKey {
    /// What was added to every byte to encrypt
    key: u8,
    /// 256 or 128
    modulus: u16,
    /// [`UNIGRAM_LOG_PROBS`] summed over the bytes of the decryption
    score: f32,
}

/// A decryption worth checking.
#[derive(Debug, Clone, PartialEq)]
struct Candidate {
    /// What was added to every byte to encrypt
    key: u8,
    /// 256 or 128
    modulus: u16,
    /// [`UNIGRAM_LOG_PROBS`] averaged over the bytes of the decryption, so decryptions of byte
    /// views of different lengths compare
    score: f32,
    /// The decryption, a character per byte (Latin-1)
    text: String,
}

impl Candidate {
    /// The key as the cracker reports it, e.g. `7 (mod 256)`.
    fn key_name(&self) -> String {
        format!("{} (mod {})", self.key, self.modulus)
    }
}

/// Runs `check` on each candidate in order and returns the first one it identifies. If it
/// identifies none, returns all of them, unidentified, with their keys separated by `, `.
fn check_candidates(
    decoder: &Decoder<AsciiShiftDecoder>,
    text: &str,
    candidates: &[Candidate],
    mut check: impl FnMut(&str) -> CheckResult,
) -> CrackResult {
    let mut results = CrackResult::new(decoder, text.to_string());
    for candidate in candidates {
        let checker_result = check(&candidate.text);
        if checker_result.is_identified {
            trace!(
                "Found a match with ASCII shift key {}",
                candidate.key_name()
            );
            results.unencrypted_text = Some(vec![candidate.text.clone()]);
            results.update_checker(&checker_result);
            results.key = Some(candidate.key_name());
            return results;
        }
    }
    if !candidates.is_empty() {
        // One key per text, in the same order
        let keys: Vec<String> = candidates.iter().map(Candidate::key_name).collect();
        results.key = Some(keys.join(", "));
        results.unencrypted_text = Some(candidates.iter().map(|c| c.text.clone()).collect());
    }
    results
}

/// The decryptions to check, best first: from each byte view of `text` (see [`byte_views`]),
/// the decryptions with its [`KEYS_DECRYPTED`] best-ranked keys that pass [`looks_like_text`],
/// at most [`MAX_CHECKED`] in all. Text that is [`numeric_text`] has none.
fn best_candidates(text: &str) -> Vec<Candidate> {
    if text.len() < MIN_BYTES || numeric_text(text) {
        return Vec::new();
    }
    let mut candidates: Vec<Candidate> = byte_views(text)
        .iter()
        .flat_map(|bytes| view_candidates(bytes))
        .collect();
    // A stable sort: on a tie the Latin-1 view's decryption, then the better-ranked key, wins
    candidates.sort_by(|a, b| b.score.total_cmp(&a.score));
    candidates.truncate(MAX_CHECKED);
    candidates
}

/// The decryptions of `bytes` with its [`KEYS_DECRYPTED`] best-ranked keys that pass
/// [`looks_like_text`], best first. All of a text's decryptions are different: two keys of
/// the same modulus shift every byte to different bytes, and [`rank_keys`] leaves out the mod
/// 128 keys that give a mod 256 decryption.
fn view_candidates(bytes: &[u8]) -> Vec<Candidate> {
    rank_keys(bytes, KEYS_DECRYPTED)
        .into_iter()
        .filter_map(|ranked| {
            let decrypted = shift(bytes, ranked.key, ranked.modulus);
            looks_like_text(&decrypted).then(|| Candidate {
                key: ranked.key,
                modulus: ranked.modulus,
                score: ranked.score / bytes.len() as f32,
                text: decrypted.into_iter().map(char::from).collect(),
            })
        })
        .collect()
}

/// The byte strings `text` might stand for, each at least [`MIN_BYTES`] long:
/// * its characters as bytes, if they are all U+00FF or below (Latin-1). This is how the
///   Hexadecimal and Binary decoders hand on bytes that aren't UTF-8. A wider character ends
///   the scan, so CJK text and emoji cost nothing;
/// * its Base64 decoding, if that isn't UTF-8. The Base64 decoder drops such bytes, and hands
///   on the ones that are UTF-8 itself, so this cracker gets those from it.
fn byte_views(text: &str) -> Vec<Vec<u8>> {
    let mut views = Vec::with_capacity(2);
    if let Some(latin1) = text
        .chars()
        .map(|c| u8::try_from(c).ok())
        .collect::<Option<Vec<u8>>>()
    {
        views.push(latin1);
    }
    if let Some(decoded) =
        decode_base64(text.trim()).filter(|decoded| std::str::from_utf8(decoded).is_err())
    {
        views.push(decoded);
    }
    views.retain(|view| view.len() >= MIN_BYTES);
    views
}

/// Whether `text` is nothing but hex digits (which include the decimal ones), whitespace and
/// the separators `,;:.-`: hex, decimal, octal or binary codes, Morse code, an IP address.
/// These are another decoder's input, and no key turns English or a CTF flag into such text:
/// it has 32 different characters, in short runs (the longest, `0` to `;`, is 12 long), and a
/// shift moves all of a text's bytes the same distance. Shifted, though, they make letter soup
/// that can pass [`looks_like_text`]: `192.168.0.1` becomes `dleadikacad`.
fn numeric_text(text: &str) -> bool {
    text.chars()
        .all(|c| c.is_ascii_hexdigit() || c.is_ascii_whitespace() || ",;:.-".contains(c))
}

/// The `limit` best keys for `bytes`, best first, with their scores: [`UNIGRAM_LOG_PROBS`]
/// summed over the bytes of the decryption. The scores come from the byte histogram, so ranking
/// costs `keys × distinct bytes` additions whatever the length, and decrypts nothing.
///
/// The keys are 1 to 255 mod 256, then, if every byte is below 0x80, the keys 1 to 127 mod 128
/// that wrap some bytes past 0 but not all of them: a mod 128 key that wraps no byte gives the
/// decryption of the same key mod 256, and one that wraps every byte that of the key + 128 mod
/// 256, and those are reported mod 256. When at least 5% of the bytes are spaces only the keys
/// that turn a space into one of [`SPACE_SOURCES`] are scored. On a tie mod 256 comes first,
/// then the lower key.
fn rank_keys(bytes: &[u8], limit: usize) -> Vec<RankedKey> {
    let mut counts = [0u32; 256];
    for &byte in bytes {
        counts[usize::from(byte)] += 1;
    }
    let histogram: Vec<(u8, f32)> = (0..=u8::MAX)
        .filter(|&byte| counts[usize::from(byte)] > 0)
        .map(|byte| (byte, counts[usize::from(byte)] as f32))
        .collect();
    let (Some(&(lowest, _)), Some(&(highest, _))) = (histogram.first(), histogram.last()) else {
        return Vec::new();
    };
    let spaced = counts[usize::from(b' ')] as usize * SPACE_RULE_ONE_IN >= bytes.len();
    let log_probs = &*UNIGRAM_LOG_PROBS;

    let mut ranked = Vec::new();
    for modulus in MODULI {
        if modulus == 128 && highest >= 0x80 {
            continue;
        }
        // A mod 128 key that wraps no byte, or every byte, gives a mod 256 decryption
        let tried = |key: u8| key != 0 && (modulus == 256 || (lowest < key && key <= highest));
        if spaced {
            // The keys that turn a space back into one of SPACE_SOURCES, scored one by one
            for key in SPACE_SOURCES
                .iter()
                .map(|&source| shift_byte(b' ', source, modulus))
                .filter(|&key| tried(key))
            {
                let score = histogram
                    .iter()
                    .map(|&(byte, count)| {
                        count * log_probs[usize::from(shift_byte(byte, key, modulus))]
                    })
                    .sum();
                ranked.push(RankedKey {
                    key,
                    modulus,
                    score,
                });
            }
        } else {
            let scores = scores_of_every_key(&histogram, modulus);
            for (key, &score) in (0..=u8::MAX).zip(scores.iter()) {
                if tried(key) {
                    ranked.push(RankedKey {
                        key,
                        modulus,
                        score,
                    });
                }
            }
        }
    }
    // Best first; on a tie mod 256 before mod 128, then the lower key
    if ranked.len() > limit {
        ranked.select_nth_unstable_by(limit, better);
        ranked.truncate(limit);
    }
    ranked.sort_by(better);
    ranked
}

/// Orders ranked keys best first: higher score, then mod 256 before mod 128, then the lower
/// key.
fn better(a: &RankedKey, b: &RankedKey) -> std::cmp::Ordering {
    b.score
        .total_cmp(&a.score)
        .then(b.modulus.cmp(&a.modulus))
        .then(a.key.cmp(&b.key))
}

/// The score of every key 0 to `modulus - 1` at once, from the histogram of the ciphertext.
/// Under the key `k` the byte `b` decrypts to `(b - k) mod modulus`, so the weights of one
/// byte under keys `0, 1, 2, ...` are consecutive entries of [`NEGATED_LOG_PROBS_256`] (or
/// `_128`), starting at `modulus - b mod modulus`. Each byte value adds one such run, scaled
/// by its count, to all the scores: a loop the compiler vectorises.
fn scores_of_every_key(histogram: &[(u8, f32)], modulus: u16) -> Vec<f32> {
    let modulus = usize::from(modulus);
    let negated = if modulus == 256 {
        &*NEGATED_LOG_PROBS_256
    } else {
        &*NEGATED_LOG_PROBS_128
    };
    let mut scores = vec![0.0f32; modulus];
    for &(byte, count) in histogram {
        let start = modulus - usize::from(byte) % modulus;
        let weights = &negated[start..start + modulus];
        for (score, &weight) in scores.iter_mut().zip(weights) {
            *score += count * weight;
        }
    }
    scores
}

/// Decrypts `bytes` with `key` mod `modulus` (256 or 128): `(byte - key) mod modulus`.
fn shift(bytes: &[u8], key: u8, modulus: u16) -> Vec<u8> {
    bytes
        .iter()
        .map(|&byte| shift_byte(byte, key, modulus))
        .collect()
}

/// `(byte - key) mod modulus`, for a modulus of 256 or 128. Both divide 256, so this is the
/// wrapping difference reduced mod `modulus`.
fn shift_byte(byte: u8, key: u8, modulus: u16) -> u8 {
    let mask = (modulus - 1) as u8;
    byte.wrapping_sub(key) & mask
}

/// Whether a decryption is worth checking: it is [`is_flag_shaped`], or
/// * at least [`MIN_TEXTLIKE_PERCENT`]% of it is ASCII letters, digits, spaces, `_`, `{` and
///   `}`,
/// * it has at least [`MIN_LETTER_PAIRS`] pairs of adjacent ASCII letters,
/// * whose mean English bigram `ln P` is at least [`MIN_MEAN_BIGRAM_LOG_PROB`], and
/// * at most one in [`MAX_CASE_FLIPS_ONE_IN`] of which changes case.
fn looks_like_text(bytes: &[u8]) -> bool {
    if is_flag_shaped(bytes) {
        return true;
    }
    let textlike = bytes
        .iter()
        .filter(|&&byte| byte.is_ascii_alphanumeric() || matches!(byte, b' ' | b'_' | b'{' | b'}'))
        .count();
    if textlike * 100 < bytes.len() * MIN_TEXTLIKE_PERCENT {
        return false;
    }

    let bigram_log_probs = &*BIGRAM_LOG_PROBS;
    let mut pairs = 0usize;
    let mut case_flips = 0usize;
    let mut log_prob = 0.0f32;
    for pair in bytes.windows(2) {
        let (first, second) = (pair[0], pair[1]);
        if first.is_ascii_alphabetic() && second.is_ascii_alphabetic() {
            pairs += 1;
            if first.is_ascii_uppercase() != second.is_ascii_uppercase() {
                case_flips += 1;
            }
            log_prob += bigram_log_probs[letter_index(first)][letter_index(second)];
        }
    }
    pairs >= MIN_LETTER_PAIRS
        && log_prob >= MIN_MEAN_BIGRAM_LOG_PROB * pairs as f32
        && case_flips * MAX_CASE_FLIPS_ONE_IN <= pairs
}

/// The position in the alphabet (0..26) of an ASCII letter, in either case.
fn letter_index(letter: u8) -> usize {
    usize::from(letter.to_ascii_lowercase() - b'a')
}

/// Whether `bytes` is shaped like a CTF flag, `prefix{...}`: an ASCII letter and 1 to 19 more
/// letters, digits or `_`, then `{`, 1 to 200 printable ASCII characters other than braces,
/// and `}` at the end. Such a decryption is always checked, as the checker knows flags:
/// leetspeak flags like `encryptCTF{3T_7U_BRU73?!}` read too little like English for the
/// bigram test of [`looks_like_text`].
fn is_flag_shaped(bytes: &[u8]) -> bool {
    let Some(open) = bytes.iter().position(|&byte| byte == b'{') else {
        return false;
    };
    let (prefix, rest) = bytes.split_at(open);
    let Some(inside) = rest[1..].strip_suffix(b"}") else {
        return false;
    };
    (2..=20).contains(&prefix.len())
        && prefix[0].is_ascii_alphabetic()
        && prefix
            .iter()
            .all(|&byte| byte.is_ascii_alphanumeric() || byte == b'_')
        && (1..=200).contains(&inside.len())
        && inside
            .iter()
            .all(|&byte| matches!(byte, b' '..=b'~') && byte != b'{' && byte != b'}')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkers::{
        athena::Athena,
        checker_type::{Check, Checker},
        CheckerTypes,
    };
    use crate::decoders::interface::{Crack, Decoder};
    use base64::{engine::general_purpose, Engine as _};

    /// The issue's example: "hello world" + 7 (mod 256)
    const ISSUE: &str = "olssv'~vysk";
    /// "hello world" + 129 (mod 256), CyberChef ADD 81: every byte is 0x80 or above
    const LATIN1: &str = "\u{e9}\u{e6}\u{ed}\u{ed}\u{f0}\u{a1}\u{f8}\u{f0}\u{f3}\u{ed}\u{e5}";
    /// "hello world" + 200 (mod 256), CyberChef ADD C8: wraps past 0xFF
    const WRAP: &str = "0-447\u{e8}?7:4,";
    /// "flag{ascii_shift_is_not_rot47}" + 13 (mod 256), CyberChef ADD 0D, with C1 controls
    const FLAG: &str =
        "synt\u{88}n\u{80}pvvl\u{80}uvs\u{81}lv\u{80}l{|\u{81}l\u{7f}|\u{81}AD\u{8a}";
    /// "CTF{this_is_my_flag_2024}" + 47 (mod 256), CyberChef ADD 2F
    const CTF: &str = "r\u{83}u\u{aa}\u{a3}\u{97}\u{98}\u{a2}\u{8e}\u{98}\u{a2}\u{8e}\u{9c}\u{a8}\u{8e}\u{95}\u{9b}\u{90}\u{96}\u{8e}a_ac\u{ac}";
    /// Python Ciphey's test vector: + 90 (mod 128)
    const LEGACY: &str = "\"?FFIzGSzH;G?zCMz<??z;H>z#zFCE?z>IAz;H>z;JJF?z;H>zNL??";
    /// The plaintext of [`LEGACY`]
    const LEGACY_PLAINTEXT: &str = "Hello my name is bee and I like dog and apple and tree";
    /// dCode's example: "ASCII_CODE" + 18, the same mod 128 and mod 256
    const DCODE: &str = "SeU[[qUaVW";
    /// encryptCTF 2019 "Julius": Base64 of "encryptCTF{3T_7U_BRU73?!}" + 24 (mod 256), as the
    /// challenge gave it (unpadded). The bytes aren't UTF-8, so the Base64 decoder drops them.
    /// <https://raw.githubusercontent.com/zst-ctf/encryptctf-2019-writeups/master/Solved/Julius/README.md>
    const JULIUS: &str = "fYZ7ipGIjFtsXpNLbHdPbXdaam1PS1c5lQ";
    /// The plaintext of [`JULIUS`]
    const JULIUS_FLAG: &str = "encryptCTF{3T_7U_BRU73?!}";
    /// The decoder benchmarks' miss input (benches/data/decoders.toml)
    const MISS: &str =
        "T00 l3= ox+#G WKyV pajU6j qxH@ %B4+a 5Pn^ 7p_v1q 9sLvu *+36i R5rL&3 mVJZI iO0 Ut8_m COTV";

    /// (ciphertext, plaintext, key, modulus) the Athena checker identifies. The mod 256
    /// vectors were made with CyberChef 10.24's ADD (key as hex) and decrypt back with its SUB;
    /// the mod 128 one with Python 3.9, `chr((ord(c) + 90) % 128)`. All are from #994.
    const IDENTIFIED: [(&str, &str, u8, u16); 6] = [
        (ISSUE, "hello world", 7, 256),
        (LATIN1, "hello world", 129, 256),
        (WRAP, "hello world", 200, 256),
        (FLAG, "flag{ascii_shift_is_not_rot47}", 13, 256),
        (CTF, "CTF{this_is_my_flag_2024}", 47, 256),
        (LEGACY, LEGACY_PLAINTEXT, 90, 128),
    ];

    /// The checker the search uses
    fn get_athena_checker() -> CheckerTypes {
        CheckerTypes::CheckAthena(Checker::<Athena>::new())
    }

    /// Runs the cracker on `text` with the Athena checker
    fn crack(text: &str) -> CrackResult {
        Decoder::<AsciiShiftDecoder>::new().crack(text, &get_athena_checker())
    }

    /// `text` as Latin-1 bytes
    fn latin1(text: &str) -> Vec<u8> {
        text.chars().map(|c| u8::try_from(c).unwrap()).collect()
    }

    /// Encrypts `plaintext` with `key` mod `modulus`: `(byte + key) mod modulus`
    fn encrypt(plaintext: &[u8], key: u8, modulus: u16) -> Vec<u8> {
        plaintext
            .iter()
            .map(|&byte| ((u16::from(byte) + u16::from(key)) % modulus) as u8)
            .collect()
    }

    /// Bytes as the Latin-1 text the Hexadecimal decoder makes of them
    fn as_latin1_text(bytes: &[u8]) -> String {
        bytes.iter().map(|&byte| char::from(byte)).collect()
    }

    /// Every key `rank_keys` tries on `bytes`, best first
    fn all_keys(bytes: &[u8]) -> Vec<RankedKey> {
        rank_keys(bytes, usize::MAX)
    }

    /// The `(key, modulus)` pairs `rank_keys` returns, in order
    fn ranked_keys(bytes: &[u8]) -> Vec<(u8, u16)> {
        all_keys(bytes)
            .iter()
            .map(|ranked| (ranked.key, ranked.modulus))
            .collect()
    }

    #[test]
    fn vectors_round_trip() {
        for (ciphertext, plaintext, key, modulus) in IDENTIFIED {
            let ciphertext = latin1(ciphertext);
            assert_eq!(shift(&ciphertext, key, modulus), plaintext.as_bytes());
            assert_eq!(encrypt(plaintext.as_bytes(), key, modulus), ciphertext);
        }
        assert_eq!(shift(DCODE.as_bytes(), 18, 256), b"ASCII_CODE");
        assert_eq!(shift(DCODE.as_bytes(), 18, 128), b"ASCII_CODE");
        // The issue's example is "ADD 07" in CyberChef: 0x68 + 7 = 0x6f
        assert_eq!(hex(ISSUE.as_bytes()), "6f6c737376277e7679736b");
        assert_eq!(
            hex(&latin1(CTF)),
            "728375aaa39798a28e98a28e9ca88e959b90968e615f6163ac"
        );
    }

    /// Lowercase hex of `bytes`, as CyberChef's To Hex writes it without a delimiter
    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn shift_undoes_encryption_for_every_key() {
        let plaintext = b"The Quick Brown Fox, 42 jumps over THE lazy dog!\n";
        for modulus in MODULI {
            for key in (1..=u8::MAX).take_while(|&key| u16::from(key) < modulus) {
                let ciphertext = encrypt(plaintext, key, modulus);
                assert_eq!(shift(&ciphertext, key, modulus), plaintext);
            }
        }
        // Wrapping past 0xff and 0x7f
        assert_eq!(shift(&[0x30], 200, 256), [0x68]);
        assert_eq!(shift(&[0x05], 10, 128), [0x7b]);
        assert_eq!(shift(&[0x05], 10, 256), [0xfb]);
    }

    #[test]
    fn unigram_weights_follow_the_plan() {
        let close = |a: f32, b: f32| (a - b).abs() < 1e-4;
        let log_probs = &*UNIGRAM_LOG_PROBS;
        assert!(close(log_probs[usize::from(b'e')], (0.127_f32 * 0.42).ln()));
        assert!(close(log_probs[usize::from(b'E')], (0.127_f32 * 0.30).ln()));
        assert!(close(
            log_probs[usize::from(b'z')],
            (0.0007_f32 * 0.42).ln()
        ));
        assert!(close(log_probs[usize::from(b' ')], 0.17_f32.ln()));
        for symbol in *b".,'\"-!?:;()_" {
            assert!(close(log_probs[usize::from(symbol)], 0.004_f32.ln()));
        }
        for byte in *b"07\n\r\t" {
            assert!(close(log_probs[usize::from(byte)], 0.002_f32.ln()));
        }
        for byte in *b"{}~@#" {
            assert!(close(log_probs[usize::from(byte)], 0.0005_f32.ln()));
        }
        for byte in [0x00, 0x1f, 0x7f, 0x80, 0xe9, 0xff] {
            assert!(close(log_probs[byte], 1e-6_f32.ln()));
        }
    }

    #[test]
    fn identified_vectors_report_their_keys() {
        for (ciphertext, plaintext, key, modulus) in IDENTIFIED {
            let result = crack(ciphertext);
            assert!(result.success, "{plaintext:?} was not cracked: {result:?}");
            assert_eq!(result.unencrypted_text.unwrap(), vec![plaintext]);
            assert_eq!(result.key, Some(format!("{key} (mod {modulus})")));
            assert_eq!(result.decoder, "ASCII shift");
        }
    }

    #[test]
    fn flags_are_identified_by_lemmeknow() {
        for ciphertext in [FLAG, CTF] {
            let result = crack(ciphertext);
            assert!(result.success, "{result:?}");
            assert_eq!(result.checker_name, "LemmeKnow Checker", "{result:?}");
        }
    }

    #[test]
    fn issue_example_is_mod_256_key_7() {
        let result = crack(ISSUE);
        assert!(result.success);
        assert_eq!(result.unencrypted_text.unwrap()[0], "hello world");
        assert_eq!(result.key.as_deref(), Some("7 (mod 256)"));
    }

    #[test]
    fn true_key_ranks_first() {
        // The issue, Latin-1, wrap and legacy vectors, and the two flags
        for (ciphertext, _, key, modulus) in IDENTIFIED {
            let ranked = ranked_keys(&latin1(ciphertext));
            assert_eq!(ranked[0], (key, modulus), "{ciphertext:?}");
        }
    }

    #[test]
    fn true_key_ranks_first_for_every_test_key() {
        // The keys of the plan's prototype run: mod 256 keys that leave every byte in ASCII,
        // move it to high bytes or wrap, including 187, 172 and 191, which turn e, t and a
        // into spaces; and mod 128 keys, including 59, 44 and 63, which do the same mod 128.
        let keys_256 = [1, 7, 13, 47, 64, 100, 127, 128, 172, 187, 191, 200, 255];
        let keys_128 = [7, 30, 44, 59, 90, 100];
        for plaintext in [
            "hello world",
            "THE BRITISH ARE COMING",
            "ASCII_CODE",
            LEGACY_PLAINTEXT,
            "flag{ascii_shift_is_not_rot47}",
            "CTF{this_is_my_flag_2024}",
            "picoCTF{b4s3_64_1s_fun}",
            "The quick brown fox jumps over the lazy dog",
            "Meet me at the old lighthouse after midnight and bring the map, the key and a torch.",
            JULIUS_FLAG,
        ] {
            let tests = keys_256
                .iter()
                .map(|&key| (key, 256))
                .chain(keys_128.iter().map(|&key| (key, 128)));
            for (key, modulus) in tests {
                let ciphertext = encrypt(plaintext.as_bytes(), key, modulus);
                let best = all_keys(&ciphertext)[0];
                assert_eq!(
                    shift(&ciphertext, best.key, best.modulus),
                    plaintext.as_bytes(),
                    "{plaintext:?} + {key} (mod {modulus}) ranked {} (mod {}) first",
                    best.key,
                    best.modulus
                );
            }
        }
    }

    #[test]
    fn dcode_example_is_the_first_candidate() {
        // Athena doesn't take ASCII_CODE for plaintext, but its key ranks first and it is the
        // only decryption that looks like text. Both moduli give it; mod 256 is reported.
        assert_eq!(ranked_keys(DCODE.as_bytes())[0], (18, 256));
        let result = crack(DCODE);
        assert_eq!(result.unencrypted_text.unwrap()[0], "ASCII_CODE");
        assert_eq!(result.key.as_deref(), Some("18 (mod 256)"));
    }

    #[test]
    fn julius_is_read_from_base64() {
        // The challenge's string is Base64 of bytes that aren't UTF-8. The flag doesn't read
        // like English, but it is shaped like a flag, so it is checked. LemmeKnow only knows
        // flag{}, ctf{} and ctfa{} flags, so Athena may not identify it; it comes first anyway.
        let raw = decode_base64(JULIUS).unwrap();
        assert!(std::str::from_utf8(&raw).is_err());
        assert_eq!(ranked_keys(&raw)[0], (24, 256));
        assert!(is_flag_shaped(JULIUS_FLAG.as_bytes()));
        assert!(!looks_like_text_without_flag_shape(JULIUS_FLAG.as_bytes()));

        let result = crack(JULIUS);
        assert_eq!(result.unencrypted_text.unwrap()[0], JULIUS_FLAG);
        assert!(result.key.unwrap().starts_with("24 (mod 256)"));
    }

    /// [`looks_like_text`] without the exception for flags
    fn looks_like_text_without_flag_shape(bytes: &[u8]) -> bool {
        let mut unshaped = bytes.to_vec();
        // Braces are textlike, so swapping them for `_` keeps the share of text
        for byte in &mut unshaped {
            if matches!(*byte, b'{' | b'}') {
                *byte = b'_';
            }
        }
        assert!(!is_flag_shaped(&unshaped));
        looks_like_text(&unshaped)
    }

    #[test]
    fn base64_of_shifted_bytes_is_cracked() {
        // The Latin-1 vector's bytes as Base64: not UTF-8, so only this cracker reads them
        let base64 = general_purpose::STANDARD.encode(latin1(LATIN1));
        let result = crack(&base64);
        assert!(result.success, "{result:?}");
        assert_eq!(result.unencrypted_text.unwrap()[0], "hello world");
        assert_eq!(result.key.as_deref(), Some("129 (mod 256)"));
    }

    #[test]
    fn base64_of_utf8_is_left_to_the_base64_decoder() {
        // The issue's example is ASCII, so the Base64 decoder hands it on and this cracker
        // gets it from there
        let base64 = general_purpose::STANDARD.encode(ISSUE);
        assert_eq!(byte_views(&base64), vec![base64.as_bytes().to_vec()]);
        assert!(crack(&base64).unencrypted_text.is_none());
    }

    #[test]
    fn misses() {
        for text in [
            "",
            "😀",
            "日本語テキスト",
            "hello",
            "hello world",
            "The quick brown fox jumps over the lazy dog",
            // ROT13 and ROT47 of the fox
            "Gur dhvpx oebja sbk whzcf bire gur ynml qbt",
            "%96 BF:4< 3C@H? 7@I ;F>AD @G6C E96 =2KJ 5@8",
            "aGVsbG8gd29ybGQ=",
            "SGVsbG8gV29ybGQhIEhvdyBhcmUgeW91Pw==",
            MISS,
            // Search inputs: accented letters, and hex
            "éèêëàâäôöûüçéèêëàâäôöûüçéèêëàâäôöûüçéèêëàâäôöûüç",
            "6f6c737376277e7679736b",
        ] {
            assert!(
                best_candidates(text).is_empty(),
                "{text:?}: {:?}",
                best_candidates(text)
            );
            let result = crack(text);
            assert!(!result.success, "{text:?}");
            assert!(result.unencrypted_text.is_none(), "{text:?}");
            assert!(result.key.is_none(), "{text:?}");
        }
    }

    #[test]
    fn short_and_wide_text_has_no_byte_view() {
        for text in [
            "",
            "hello",
            "olssv",
            "😀😀😀😀😀😀",
            "日本語テキスト",
            "ab\u{100}cdefgh",
        ] {
            assert!(byte_views(text).is_empty(), "{text:?}");
        }
        // Six characters are enough, whatever their UTF-8 length
        assert_eq!(byte_views("olssv'"), vec![b"olssv'".to_vec()]);
        assert_eq!(byte_views(LATIN1), vec![latin1(LATIN1)]);
    }

    #[test]
    fn spaced_text_is_scored_on_eighteen_keys_at_most() {
        for text in [
            "hello world",
            "The quick brown fox jumps over the lazy dog",
            MISS,
        ] {
            let ranked = all_keys(text.as_bytes());
            assert!(!ranked.is_empty() && ranked.len() <= 18, "{text:?}");
            for key in ranked {
                let source = shift_byte(b' ', key.key, key.modulus);
                assert!(SPACE_SOURCES.contains(&source), "{text:?}: {key:?}");
            }
        }
        // The keys that turn e, t and a into spaces
        let spaced = encrypt(b"meet me at the tea tent", 187, 256);
        assert!(ranked_keys(&spaced).contains(&(187, 256)));
        assert_eq!(ranked_keys(&spaced)[0], (187, 256));
    }

    #[test]
    fn unspaced_text_is_scored_on_every_key() {
        // Bytes 0x80 and above: mod 256 only
        assert_eq!(all_keys(&latin1(LATIN1)).len(), 255);
        // ASCII: the mod 128 keys that wrap some bytes but not all, here 0x2c < k <= 0x7e
        let bytes = b"0-447-?7:4,~";
        let ranked = all_keys(bytes);
        assert_eq!(ranked.len(), 255 + (0x7e - 0x2c));
        assert!(ranked
            .iter()
            .filter(|key| key.modulus == 128)
            .all(|key| (0x2d..=0x7e).contains(&key.key)));
    }

    #[test]
    fn decryptions_are_all_different() {
        for text in [DCODE, ISSUE, "SGVsbG8gV29ybGQhIEhvdyBhcmUgeW91Pw=="] {
            let bytes = text.as_bytes();
            let decryptions: std::collections::HashSet<Vec<u8>> = all_keys(bytes)
                .iter()
                .map(|key| shift(bytes, key.key, key.modulus))
                .collect();
            assert_eq!(decryptions.len(), all_keys(bytes).len(), "{text:?}");
        }
    }

    #[test]
    fn mod_128_keys_that_match_a_mod_256_key_are_left_out() {
        // Every byte of dCode's example is at least 18, so 18 mod 128 wraps nothing
        let ranked = ranked_keys(DCODE.as_bytes());
        assert!(ranked.contains(&(18, 256)));
        assert!(!ranked.contains(&(18, 128)));
        // 0x7b mod 128 wraps every byte, like 0xfb mod 256
        assert!(!ranked.contains(&(0x7b, 128)));
        assert_eq!(
            shift(DCODE.as_bytes(), 0x7b, 128),
            shift(DCODE.as_bytes(), 0xfb, 256)
        );
    }

    #[test]
    fn scores_of_every_key_are_the_sums_of_the_weights() {
        // Spaceless texts are scored for every key at once; the result has to be the sum of
        // the weights of the decrypted bytes, key by key
        for text in [
            JULIUS,
            LATIN1,
            WRAP,
            "SGVsbG8gV29ybGQhIEhvdyBhcmUgeW91Pw==",
            "\u{1}\u{7f}\u{0}",
        ] {
            let bytes = latin1(text);
            let ranked = all_keys(&bytes);
            assert!(!ranked.is_empty(), "{text:?}");
            for key in ranked {
                let direct: f32 = shift(&bytes, key.key, key.modulus)
                    .iter()
                    .map(|&byte| UNIGRAM_LOG_PROBS[usize::from(byte)])
                    .sum();
                assert!(
                    (direct - key.score).abs() <= 1e-3 * direct.abs().max(1.0),
                    "{text:?} {key:?}: {direct}"
                );
            }
        }
    }

    #[test]
    fn the_best_keys_are_the_start_of_the_full_ranking() {
        for text in [
            ISSUE,
            LATIN1,
            WRAP,
            LEGACY,
            DCODE,
            JULIUS,
            MISS,
            "hello world",
        ] {
            let bytes = latin1(text);
            let all = all_keys(&bytes);
            for limit in [0, 1, 3, 10] {
                let best = rank_keys(&bytes, limit);
                assert_eq!(best.len(), limit.min(all.len()), "{text:?}");
                assert_eq!(best, all[..best.len()], "{text:?}");
            }
        }
    }

    #[test]
    fn ties_go_to_mod_256_then_the_lower_key() {
        // Two control characters: most keys turn them into bytes with the same weight, so
        // many keys of both moduli tie
        let ranked = all_keys(b"\x01\x7f\x01\x7f\x01\x7f");
        assert!(ranked.iter().any(|key| key.modulus == 128));
        let mut ties = 0;
        for pair in ranked.windows(2) {
            assert!(pair[0].score >= pair[1].score);
            if pair[0].score == pair[1].score {
                ties += 1;
                assert!(
                    pair[0].modulus > pair[1].modulus
                        || (pair[0].modulus == pair[1].modulus && pair[0].key < pair[1].key),
                    "{pair:?}"
                );
            }
        }
        assert!(ties > 0);
    }

    #[test]
    fn numeric_text_is_not_cracked() {
        for text in [
            "192.168.0.1",
            "68656c6c6f20776f726c64",
            "01101000 01100101 01101100",
            "104 101 108 108 111",
            ".... . .-.. .-.. ---",
            "de:ad:be:ef:ca:fe",
        ] {
            assert!(numeric_text(text), "{text:?}");
            assert!(best_candidates(text).is_empty(), "{text:?}");
        }
        assert!(!numeric_text("hello world"));
        assert!(!numeric_text(ISSUE));
    }

    #[test]
    fn no_key_turns_text_into_numeric_text() {
        // The numeric pre-check never hides a real ASCII shift
        for plaintext in [
            "hello world",
            "attack at dawn",
            "flag{ascii_shift_is_not_rot47}",
            "CTF{this_is_my_flag_2024}",
            "ASCII_CODE",
            LEGACY_PLAINTEXT,
            JULIUS_FLAG,
        ] {
            for modulus in MODULI {
                for key in (1..=u8::MAX).take_while(|&key| u16::from(key) < modulus) {
                    let ciphertext = as_latin1_text(&encrypt(plaintext.as_bytes(), key, modulus));
                    assert!(
                        !numeric_text(&ciphertext),
                        "{plaintext:?} + {key} (mod {modulus})"
                    );
                }
            }
        }
    }

    #[test]
    fn text_gates() {
        for text in [
            "hello world",
            "ASCII_CODE",
            LEGACY_PLAINTEXT,
            "THE BRITISH ARE COMING",
        ] {
            assert!(looks_like_text(text.as_bytes()), "{text:?}");
        }
        for text in [
            // Hex-derived junk: too many case changes
            "CsEDEDFCA?EsED",
            // Too little text
            "ebiil\u{1d}tl\u{1}\u{2}\u{3}a",
            "-*114e<47 1)",
            // Fewer than three letter pairs
            "ab 12 cd 34",
            // Letter pairs that English doesn't have
            "qzxj vqkz jxqz",
        ] {
            assert!(!looks_like_text(&latin1(text)), "{text:?}");
        }
    }

    #[test]
    fn flag_shape() {
        for flag in [
            "flag{ascii_shift_is_not_rot47}",
            "CTF{this_is_my_flag_2024}",
            "picoCTF{b4s3_64_1s_fun}",
            JULIUS_FLAG,
            "DUCTF{a b}",
            "ab{c}",
        ] {
            assert!(is_flag_shaped(flag.as_bytes()), "{flag:?}");
        }
        for text in [
            "flag{}",
            "{flag}",
            "f{x}",
            "1ag{x}",
            "flag{x}y",
            "flag{x{y}",
            "fl-ag{x}",
            "abcdefghijklmnopqrstu{x}",
            "flag{\u{80}}",
            "flag{\n}",
            "hello world",
        ] {
            assert!(!is_flag_shaped(&latin1(text)), "{text:?}");
        }
        let long_flag = format!("flag{{{}}}", "a".repeat(200));
        assert!(is_flag_shaped(long_flag.as_bytes()));
        let too_long = format!("flag{{{}}}", "a".repeat(201));
        assert!(!is_flag_shaped(too_long.as_bytes()));
    }

    #[test]
    fn at_most_three_candidates_are_checked() {
        // Every key on a few plaintexts, plus Base64, whose bytes can be a second byte view
        let decoder = Decoder::<AsciiShiftDecoder>::new();
        let rejecting = Checker::<Athena>::new();
        let mut texts = vec![JULIUS.to_string(), DCODE.to_string(), MISS.to_string()];
        for plaintext in [
            "hello world",
            "ASCII_CODE",
            "flag{ascii_shift_is_not_rot47}",
        ] {
            for key in 1..=u8::MAX {
                let ciphertext = encrypt(plaintext.as_bytes(), key, 256);
                texts.push(general_purpose::STANDARD.encode(&ciphertext));
                texts.push(as_latin1_text(&ciphertext));
            }
        }
        let mut checked_any = false;
        for text in texts {
            let candidates = best_candidates(&text);
            assert!(candidates.len() <= MAX_CHECKED, "{text:?}: {candidates:?}");
            let mut checked = Vec::new();
            let result = check_candidates(&decoder, &text, &candidates, |candidate| {
                checked.push(candidate.to_string());
                CheckResult::new(&rejecting)
            });
            checked_any |= !checked.is_empty();
            assert!(!result.success);
            // Every candidate is checked once, in order, and handed on with its key
            let texts = result.unencrypted_text.unwrap_or_default();
            assert_eq!(texts, checked);
            let keys = result.key.unwrap_or_default();
            assert_eq!(
                keys.split(", ").filter(|key| !key.is_empty()).count(),
                texts.len()
            );
        }
        assert!(checked_any);
    }

    #[test]
    fn checking_stops_at_the_first_identified_candidate() {
        let decoder = Decoder::<AsciiShiftDecoder>::new();
        let accepting = Checker::<Athena>::new();
        let candidates = vec![
            Candidate {
                key: 1,
                modulus: 256,
                score: -3.0,
                text: "first".to_string(),
            },
            Candidate {
                key: 2,
                modulus: 128,
                score: -4.0,
                text: "second".to_string(),
            },
            Candidate {
                key: 3,
                modulus: 256,
                score: -5.0,
                text: "third".to_string(),
            },
        ];
        let mut calls = 0;
        let result = check_candidates(&decoder, "input", &candidates, |candidate| {
            calls += 1;
            let mut check_result = CheckResult::new(&accepting);
            check_result.is_identified = candidate == "second";
            check_result
        });
        assert_eq!(calls, 2);
        assert!(result.success);
        assert_eq!(result.unencrypted_text, Some(vec!["second".to_string()]));
        assert_eq!(result.key.as_deref(), Some("2 (mod 128)"));

        // None identified: all of them, with their keys
        let result = check_candidates(&decoder, "input", &candidates, |_| {
            CheckResult::new(&accepting)
        });
        assert!(!result.success);
        assert_eq!(
            result.key.as_deref(),
            Some("1 (mod 256), 2 (mod 128), 3 (mod 256)")
        );
        assert_eq!(result.unencrypted_text.unwrap().len(), 3);
    }

    #[test]
    fn decoder_metadata() {
        let decoder = Decoder::<AsciiShiftDecoder>::new();
        assert_eq!(decoder.get_name(), "ASCII shift");
        assert_eq!(
            decoder.get_link(),
            "https://www.dcode.fr/ascii-shift-cipher"
        );
        assert!((decoder.get_popularity() - 0.4).abs() < f32::EPSILON);
        // A cracker, not a decoder, and not reciprocal: two shifts compose into one
        let tags = decoder.get_tags();
        assert!(!tags.contains(&"decoder"));
        assert!(!tags.contains(&"reciprocal"));
        assert!(tags.contains(&"ascii_shift"));
    }

    #[test]
    fn registered_once() {
        let decoders = crate::filtration_system::get_decoder_by_name("ASCII shift");
        assert_eq!(decoders.components.len(), 1);
        assert_eq!(decoders.components[0].get_name(), "ASCII shift");
        // Cached results name their decoders, so the map key must be the name
        let decoder = crate::decoders::DECODER_MAP
            .get("ASCII shift")
            .expect("ASCII shift is in DECODER_MAP")
            .get::<()>();
        assert_eq!(decoder.get_name(), "ASCII shift");
    }
}
