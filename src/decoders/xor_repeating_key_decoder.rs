//! Crack repeating-key XOR: every plaintext byte `i` is XORed with `key[i mod L]` for a key
//! of 2 to 40 bytes ("Vigenère over bytes", Cryptopals set 1 challenges 5 and 6).
//!
//! Ciphey passes text between decoders, and the Hexadecimal and Base64 decoders only pass on
//! text, so the ciphertext bytes are read here: from hex, from Base64, or from text that
//! carries raw bytes (control or Latin-1 characters). For each of those byte views it
//!
//! 1. tries a crib for CTF flags (`flag{`, `picoCTF{`, ...), which recovers keys up to the
//!    prefix length even when the flag is too short or symbol-heavy for frequency analysis,
//! 2. ranks key lengths 2..=40 by the index of coincidence of the byte columns,
//! 3. solves every column as single-byte XOR with an English byte-frequency table and keeps
//!    the key length with the best score minus `L·ln 256`, so short texts don't overfit,
//! 4. shrinks the key to its shortest period, leaving 1-byte keys to single-byte XOR,
//! 5. refines the key with English letter bigrams, which fixes short texts where a column
//!    solved on its own picks the wrong byte (`kee` instead of `key`).
//!
//! Candidates are confirmed with the checker at Low sensitivity.

use crate::checkers::CheckerTypes;
use crate::decoders::interface::check_string_success;
use base64::{engine::general_purpose, Engine as _};
use gibberish_or_not::Sensitivity;
use once_cell::sync::Lazy;
use std::fmt::Write as _;

use super::crack_results::CrackResult;
use super::interface::Crack;
use super::interface::Decoder;

use log::{debug, trace};

/// Views shorter than this are too short to find a key length in.
const MIN_VIEW_BYTES: usize = 16;

/// Key lengths are ranked and solved on at most this many bytes of a view.
const SAMPLE_BYTES: usize = 512;

/// Longest key tried.
const MAX_KEY_LEN: usize = 40;

/// Each key byte needs at least this many ciphertext bytes to be solved.
const MIN_COLUMN_BYTES: usize = 6;

/// Number of key lengths (ranked by index of coincidence) that are solved.
const TOP_KEY_LENGTHS: usize = 8;

/// Key bytes per column the joint refinement chooses from. The plan's 5 missed the right
/// byte at rank 6 to 8 on some texts with 6 bytes per key byte; 8 costs next to nothing.
const REFINE_CHOICES: usize = 8;

/// Rounds of joint refinement.
const REFINE_ROUNDS: usize = 3;

/// A key length is only solved if at most one byte in this many disagrees with its column
/// about the high bit. ASCII plaintext gives every byte of a column the high bit of its key
/// byte, so this rejects random bytes before any scoring.
const HIGH_BIT_TOLERANCE: usize = 6;

/// Binary written as `0`s and `1`s is valid hex and Base64 too, and its views have at most
/// 8 distinct byte values, which XOR "improves" into letter soup. Real ciphertexts of 16 or
/// more bytes of text have more.
const MIN_DISTINCT_BYTES: usize = 9;

/// Lowest mean byte score a decryption needs before it is shown to the checker.
/// English scores −2.8 to −3.5, random bytes never above −6.3.
const MIN_SCORE: f64 = -4.5;

/// Lowest mean byte score of a decryption the checker rejected that is still passed on to
/// the search (reversed English, say).
const MIN_UNCONFIRMED_SCORE: f64 = -4.0;

/// A decryption the checker rejected is only passed on if its key was solved from at least
/// this many bytes per key byte. Shorter texts overfit into letter soup.
const MIN_UNCONFIRMED_COLUMN_BYTES: usize = 16;

/// ... and if each key byte's column has at least this many different byte values on
/// average. Text XORed with a key has 10 or more at 16 bytes per column; Base64-looking
/// text that decodes to a few repeating bytes (Caesar shifts of Base64, say) has 1 to 3,
/// which XOR turns into common letters.
const MIN_UNCONFIRMED_COLUMN_DISTINCT: usize = 8;

/// Flag formats for the crib.
const FLAG_PREFIXES: [&[u8]; 8] = [
    b"flag{",
    b"FLAG{",
    b"CTF{",
    b"ctf{",
    b"picoCTF{",
    b"HTB{",
    b"THM{",
    b"DUCTF{",
];

/// English letter frequencies of `a` to `z`, in percent.
const LETTER_FREQUENCIES: [f64; 26] = [
    8.17, 1.49, 2.78, 4.25, 12.70, 2.23, 2.02, 6.09, 6.97, 0.15, 0.77, 4.03, 2.41, 6.75, 7.51,
    1.93, 0.10, 5.99, 6.33, 9.06, 2.76, 0.98, 2.36, 0.15, 1.97, 0.07,
];

/// Punctuation, digits and whitespace common in English text.
const COMMON_SYMBOLS: &[u8; 24] = b".,'\"!?;:-()0123456789\n\t\r";

/// Printable symbols that are rare in prose but turn up in flags and code.
const RARE_SYMBOLS: &[u8; 21] = b"_{}@#$%&*+=/<>[]\\|~^`";

/// English letter bigram counts, one `XY count` pair per line.
const ENGLISH_BIGRAMS: &str = include_str!("../storage/ngrams/english_bigrams.txt");

/// Log-likelihood of each byte value in English text.
static BYTE_SCORES: Lazy<[f64; 256]> = Lazy::new(|| {
    let mut scores = [1e-6_f64.ln(); 256];
    for (offset, percent) in (0u8..).zip(LETTER_FREQUENCIES) {
        let lowercase = 0.82 * percent / 100.0;
        scores[usize::from(b'a' + offset)] = lowercase.ln();
        scores[usize::from(b'A' + offset)] = (lowercase * 0.15).ln();
    }
    scores[usize::from(b' ')] = 0.15_f64.ln();
    for &symbol in COMMON_SYMBOLS {
        scores[usize::from(symbol)] = (0.03_f64 / 24.0).ln();
    }
    for &symbol in RARE_SYMBOLS {
        scores[usize::from(symbol)] = (0.002_f64 / 21.0).ln();
    }
    scores
});

/// Pointwise mutual information `ln(P(ab) / (P(a·)·P(·b)))` of each pair of letters, from
/// [`ENGLISH_BIGRAMS`] with a count floor of 0.5. Unlike `ln P(ab)` it doesn't reward
/// turning letters into spaces.
static LETTER_PMI: Lazy<[[f64; 26]; 26]> = Lazy::new(|| {
    let mut counts = [[0.5_f64; 26]; 26];
    for line in ENGLISH_BIGRAMS.lines() {
        let mut fields = line.split_ascii_whitespace();
        let (Some(pair), Some(count)) = (fields.next(), fields.next()) else {
            continue;
        };
        let (Ok(count), [first, second]) = (count.parse::<f64>(), pair.as_bytes()) else {
            continue;
        };
        if let (Some(first), Some(second)) = (letter_index(*first), letter_index(*second)) {
            counts[first][second] = count.max(0.5);
        }
    }
    let total: f64 = counts.iter().flatten().sum();
    let mut firsts = [0.0_f64; 26];
    let mut seconds = [0.0_f64; 26];
    for (first, row) in counts.iter().enumerate() {
        for (second, count) in row.iter().enumerate() {
            firsts[first] += count;
            seconds[second] += count;
        }
    }
    let mut pmi = [[0.0_f64; 26]; 26];
    for (first, row) in pmi.iter_mut().enumerate() {
        for (second, value) in row.iter_mut().enumerate() {
            *value = (counts[first][second] * total / (firsts[first] * seconds[second])).ln();
        }
    }
    pmi
});

/// The repeating-key XOR cracker, call:
/// `let xor_decoder = Decoder::<XorRepeatingKeyDecoder>::new()` to create a new instance
/// And then call:
/// `result = xor_decoder.crack(input, &checker)` to crack hex, Base64 or raw ciphertext
/// The struct generated by new() comes from interface.rs
/// ```
/// use ciphey::decoders::xor_repeating_key_decoder::XorRepeatingKeyDecoder;
/// use ciphey::decoders::interface::{Crack, Decoder};
/// use ciphey::checkers::{athena::Athena, CheckerTypes, checker_type::{Check, Checker}};
///
/// let xor_decoder = Decoder::<XorRepeatingKeyDecoder>::new();
/// let athena_checker = Checker::<Athena>::new();
/// let checker = CheckerTypes::CheckAthena(athena_checker);
///
/// // Cryptopals set 1 challenge 5: key "ICE", shown as hex
/// let result = xor_decoder.crack(
///     "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f",
///     &checker,
/// );
/// assert_eq!(
///     result.unencrypted_text.unwrap()[0],
///     "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
/// );
/// assert_eq!(result.key.unwrap(), "ICE");
/// ```
pub struct XorRepeatingKeyDecoder;

impl Crack for Decoder<XorRepeatingKeyDecoder> {
    fn new() -> Decoder<XorRepeatingKeyDecoder> {
        Decoder {
            name: "Repeating-key XOR",
            description: "XOR with a repeating key of 2 to 40 bytes (Vigenère over bytes), read from hex, Base64 or raw bytes. Finds the key length from the index of coincidence, solves each key byte with English letter frequencies and refines the key with letter bigrams. A crib recovers keys of CTF flags such as flag{...}. Uses Low sensitivity for gibberish detection.",
            link: "https://en.wikipedia.org/wiki/XOR_cipher",
            tags: vec!["xor", "xor_repeating_key", "bitwise", "crypto"],
            popularity: 0.4,
            phantom: std::marker::PhantomData,
        }
    }

    /// Cracks every byte view of `text` and stops at the first decryption the checker
    /// accepts. If none is accepted, returns the best decryption that still scores like
    /// English (only for views that aren't text themselves), or nothing.
    fn crack(&self, text: &str, checker: &CheckerTypes) -> CrackResult {
        trace!("Trying repeating-key XOR with text {:?}", text);
        let mut results = CrackResult::new(self, text.to_string());

        let views = byte_views(text);
        if views.is_empty() {
            trace!("No hex, Base64 or raw bytes view for repeating-key XOR");
            return results;
        }

        let checker_with_sensitivity = checker.with_sensitivity(Sensitivity::Low);
        let mut unconfirmed: Option<Candidate> = None;

        for view in &views {
            // A view that is itself printable text only gets checker-confirmed results:
            // the encodings it could be (URL, Base85, ...) "improve" into letter soup.
            let may_pass_on = clean_text(view).is_none();
            let sample_len = view.len().min(SAMPLE_BYTES);

            for candidate in view_candidates(view) {
                if !check_string_success(&candidate.plaintext, text) {
                    continue;
                }
                let checker_result = checker_with_sensitivity.check(&candidate.plaintext);
                if checker_result.is_identified {
                    debug!(
                        "Repeating-key XOR key {} gives {:?}",
                        format_key(&candidate.key),
                        candidate.plaintext
                    );
                    results.key = Some(format_key(&candidate.key));
                    results.unencrypted_text = Some(vec![candidate.plaintext]);
                    results.update_checker(&checker_result);
                    return results;
                }

                if may_pass_on
                    && is_trustworthy_unconfirmed(&view[..sample_len], &candidate)
                    && unconfirmed
                        .as_ref()
                        .is_none_or(|u| candidate.score > u.score)
                {
                    unconfirmed = Some(candidate);
                }
            }
        }

        if let Some(candidate) = unconfirmed {
            trace!(
                "Repeating-key XOR key {} gives unconfirmed {:?}",
                format_key(&candidate.key),
                candidate.plaintext
            );
            results.key = Some(format_key(&candidate.key));
            results.unencrypted_text = Some(vec![candidate.plaintext]);
        }
        results
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

/// Recovers the key of repeating-key XOR ciphertext `bytes` and decrypts it, without a
/// checker. Returns the key at its shortest period and the plaintext, or `None` when the
/// bytes don't look like text XORed with a key of 2 to 40 bytes: fewer than 16 bytes,
/// random bytes, text that is already plain or encoded, or text XORed with a single byte
/// (that is the single-byte XOR cracker's job).
///
/// ```
/// use ciphey::decoders::xor_repeating_key_decoder::crack_bytes;
///
/// let plaintext = b"Meet me at the old oak tree after the rain stops.";
/// let ciphertext: Vec<u8> = plaintext
///     .iter()
///     .zip(b"key".iter().cycle())
///     .map(|(byte, key)| byte ^ key)
///     .collect();
/// let (key, text) = crack_bytes(&ciphertext).unwrap();
/// assert_eq!(key, b"key");
/// assert_eq!(text, "Meet me at the old oak tree after the rain stops.");
/// ```
pub fn crack_bytes(bytes: &[u8]) -> Option<(Vec<u8>, String)> {
    view_candidates(bytes)
        .into_iter()
        .next()
        .map(|candidate| (candidate.key, candidate.plaintext))
}

/// A decryption of one byte view.
struct Candidate {
    /// The key, at its shortest period.
    key: Vec<u8>,
    /// The decrypted view.
    plaintext: String,
    /// Mean byte score of the plaintext, see [`BYTE_SCORES`].
    score: f64,
}

/// The decryptions of `view` worth showing a checker, best first: keys from the flag crib,
/// shortest first, then the key found by frequency analysis.
fn view_candidates(view: &[u8]) -> Vec<Candidate> {
    if view.len() < MIN_VIEW_BYTES || is_plain_or_encoded_text(view) || is_single_byte_flag(view) {
        return Vec::new();
    }

    let mut candidates: Vec<Candidate> = crib_keys(view)
        .into_iter()
        .filter_map(|key| {
            // The crib only keeps keys that give printable ASCII, so this can't fail
            let plaintext = String::from_utf8(xor_with_key(view, &key)).ok()?;
            let score = mean_score(plaintext.as_bytes());
            Some(Candidate {
                key,
                plaintext,
                score,
            })
        })
        .collect();

    let sample = &view[..view.len().min(SAMPLE_BYTES)];
    if let Some(key) = frequency_key(sample) {
        if candidates.iter().all(|candidate| candidate.key != key) {
            let plaintext = xor_with_key(view, &key);
            let score = mean_score(&plaintext);
            if score >= MIN_SCORE {
                if let Some(plaintext) = clean_text(&plaintext) {
                    candidates.push(Candidate {
                        key,
                        plaintext: plaintext.to_string(),
                        score,
                    });
                }
            }
        }
    }
    candidates
}

/// The byte strings `text` could be carrying: hex digits, Base64, or the text itself when
/// it holds raw bytes. Plain text has none of them, and finding that out takes one scan.
///
/// Hex digits are in the Base64 alphabet too, but Base64 of a ciphertext only uses hex
/// digits by chance (about (22/64)^22 for 16 bytes), so hex isn't also read as Base64.
fn byte_views(text: &str) -> Vec<Vec<u8>> {
    let mut views: Vec<Vec<u8>> = Vec::new();
    match hex_view(text) {
        Some(view) => views.push(view),
        None => views.extend(base64_view(text)),
    }
    views.extend(raw_views(text));
    views.retain(|view| view.len() >= MIN_VIEW_BYTES);
    views
}

/// Hex digits, ignoring whitespace, `:` and `0x` prefixes, as bytes. Every group of digits
/// between separators must be whole bytes (an even number of digits): space-separated
/// decimal or octal codes such as `115 145 145` are made of hex digits too, but they're
/// another decoder's layer, not hex.
fn hex_view(text: &str) -> Option<Vec<u8>> {
    let text = text.as_bytes();
    let mut digits = Vec::with_capacity(text.len());
    let mut group_start = 0;
    let mut index = 0;
    while index < text.len() {
        let byte = text[index];
        if byte == b'0' && matches!(text.get(index + 1), Some(b'x' | b'X')) {
            index += 2;
            continue;
        }
        if byte.is_ascii_hexdigit() {
            digits.push(byte);
        } else if byte.is_ascii_whitespace() || byte == b':' {
            if !(digits.len() - group_start).is_multiple_of(2) {
                return None;
            }
            group_start = digits.len();
        } else {
            return None;
        }
        index += 1;
    }
    if !digits.len().is_multiple_of(2) || digits.len() < 2 * MIN_VIEW_BYTES {
        return None;
    }
    Some(hex_digits_to_bytes(&digits))
}

/// Pairs of ASCII hex digits as bytes. A trailing odd digit is ignored.
fn hex_digits_to_bytes(digits: &[u8]) -> Vec<u8> {
    digits
        .as_chunks::<2>()
        .0
        .iter()
        .map(|&[high, low]| (hex_value(high) << 4) | hex_value(low))
        .collect()
}

/// The value of an ASCII hex digit.
fn hex_value(digit: u8) -> u8 {
    match digit {
        b'0'..=b'9' => digit - b'0',
        b'a'..=b'f' => digit - b'a' + 10,
        b'A'..=b'F' => digit - b'A' + 10,
        _ => 0,
    }
}

/// Standard or URL-safe Base64 (`[A-Za-z0-9+/_-]+={0,2}`, possibly split into lines),
/// decoded with the engines the Base64 decoder uses. The text must have both uppercase and
/// lowercase letters: Base64 of 16 or more random-looking bytes practically always does,
/// while single-case text that fits the alphabet (Base32, a1z26 or Citrix output, words
/// run together) is something else.
fn base64_view(text: &str) -> Option<Vec<u8>> {
    let is_base64 =
        |byte: u8| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'-' | b'_');
    let trimmed = text.trim();
    let body = trimmed.trim_end_matches('=');
    if trimmed.len() - body.len() > 2
        || body.len() < (MIN_VIEW_BYTES * 4).div_ceil(3)
        || !body
            .bytes()
            .all(|byte| is_base64(byte) || matches!(byte, b'\r' | b'\n'))
        || !body.bytes().any(|byte| byte.is_ascii_uppercase())
        || !body.bytes().any(|byte| byte.is_ascii_lowercase())
    {
        return None;
    }
    // Base64 is often wrapped at 64 or 76 characters
    let body: Vec<u8> = body.bytes().filter(|&byte| is_base64(byte)).collect();
    general_purpose::STANDARD_NO_PAD
        .decode(&body)
        .or_else(|_| general_purpose::URL_SAFE_NO_PAD.decode(&body))
        .ok()
}

/// The bytes of text that carries raw bytes, recognised by a control character other than
/// tab and newlines, or a Latin-1 symbol (U+00A0 to U+00BF, `×`, `÷`). That is what the
/// Hexadecimal decoder outputs for binary data: UTF-8 when the bytes happen to be valid
/// UTF-8, Latin-1 otherwise. Text with only Latin-1 characters could be either, so both are
/// tried. Accented letters alone are taken for natural text: bytes of 0x80 and up from a
/// ciphertext also give C1 controls and symbols.
fn raw_views(text: &str) -> Vec<Vec<u8>> {
    let carries_bytes = text.chars().any(|c| {
        is_control_char(c) || ('\u{a0}'..='\u{bf}').contains(&c) || matches!(c, '×' | '÷')
    });
    if !carries_bytes {
        return Vec::new();
    }
    let latin1: Option<Vec<u8>> = text.chars().map(|c| u8::try_from(c).ok()).collect();
    match latin1 {
        Some(latin1) if latin1.is_ascii() => vec![latin1],
        Some(latin1) => vec![latin1, text.as_bytes().to_vec()],
        None => vec![text.as_bytes().to_vec()],
    }
}

/// Whether `c` is a control character other than tab, line feed and carriage return.
fn is_control_char(c: char) -> bool {
    c.is_control() && !matches!(c, '\t' | '\n' | '\r')
}

/// Whether `byte` is an ASCII control character other than tab, line feed and carriage
/// return. No key byte may decrypt its column to one of these.
fn is_control_byte(byte: u8) -> bool {
    (byte < 0x20 && !matches!(byte, b'\t' | b'\n' | b'\r')) || byte == 0x7f
}

/// `bytes` as text, if they are UTF-8 without control characters other than tab, line feed
/// and carriage return.
fn clean_text(bytes: &[u8]) -> Option<&str> {
    let text = std::str::from_utf8(bytes).ok()?;
    (!text.chars().any(is_control_char)).then_some(text)
}

/// Whether `view` is printable text that no key is needed for: text in the alphabet of
/// hex, Base64 or Base32 (an encoding of something else), text that already scores like
/// English, or UTF-8 with non-ASCII characters (accents, other scripts, emoji). XOR
/// "improves" the first two into letter soup, and ciphertext is practically never valid
/// UTF-8 with multi-byte characters.
fn is_plain_or_encoded_text(view: &[u8]) -> bool {
    clean_text(view).is_some_and(|text| {
        !text.is_ascii()
            || mean_score(view) >= MIN_SCORE
            || view.iter().all(|&byte| {
                byte.is_ascii_alphanumeric()
                    || byte.is_ascii_whitespace()
                    || matches!(byte, b'+' | b'/' | b'=' | b'_' | b'-')
            })
    })
}

/// Mean of [`BYTE_SCORES`] over `bytes`.
fn mean_score(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return f64::NEG_INFINITY;
    }
    let scores = &*BYTE_SCORES;
    bytes
        .iter()
        .map(|&byte| scores[usize::from(byte)])
        .sum::<f64>()
        / bytes.len() as f64
}

/// The letter's position in the alphabet, for ASCII letters of either case.
fn letter_index(byte: u8) -> Option<usize> {
    match byte {
        b'a'..=b'z' => Some(usize::from(byte - b'a')),
        b'A'..=b'Z' => Some(usize::from(byte - b'A')),
        _ => None,
    }
}

/// `bytes` XORed with `key` repeated.
pub(crate) fn xor_with_key(bytes: &[u8], key: &[u8]) -> Vec<u8> {
    bytes
        .iter()
        .zip(key.iter().cycle())
        .map(|(byte, key_byte)| byte ^ key_byte)
        .collect()
}

/// The shortest prefix of `key` that repeats to give `key` (`ICEICE` → `ICE`).
fn shortest_period(key: &[u8]) -> &[u8] {
    let len = key.len();
    (1..len)
        .find(|&period| {
            len.is_multiple_of(period)
                && key
                    .iter()
                    .enumerate()
                    .all(|(index, &byte)| byte == key[index % period])
        })
        .map_or(key, |period| &key[..period])
}

/// The key as text if every byte is printable ASCII (`ICE`), else as hex (`0x1337beef`).
pub(crate) fn format_key(key: &[u8]) -> String {
    if key.iter().all(|byte| (0x20..=0x7e).contains(byte)) {
        return key.iter().map(|&byte| char::from(byte)).collect();
    }
    let mut hex = String::from("0x");
    for byte in key {
        // Writing to a String can't fail
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// Whether `view` XORed with `key` starts with `prefix` and is printable ASCII ending in
/// `}` (before any trailing whitespace).
fn decrypts_to_flag(view: &[u8], key: &[u8], prefix: &[u8]) -> bool {
    if view.len() < prefix.len() {
        return false;
    }
    let mut last_visible = 0;
    for (index, (byte, key_byte)) in view.iter().zip(key.iter().cycle()).enumerate() {
        let plain = byte ^ key_byte;
        if prefix.get(index).is_some_and(|&expected| plain != expected)
            || !((0x20..=0x7e).contains(&plain) || matches!(plain, b'\t' | b'\n' | b'\r'))
        {
            return false;
        }
        if !plain.is_ascii_whitespace() {
            last_visible = plain;
        }
    }
    last_visible == b'}'
}

/// Whether `view` is a CTF flag XORed with a single byte (or with none). The single-byte
/// XOR cracker reports those; frequency analysis here would make letter soup of them.
fn is_single_byte_flag(view: &[u8]) -> bool {
    FLAG_PREFIXES.iter().any(|prefix| {
        view.first()
            .is_some_and(|&first| decrypts_to_flag(view, &[first ^ prefix[0]], prefix))
    })
}

/// Keys of 2 or more bytes that decrypt `view` to a CTF flag, shortest first. Each key is
/// the start of the view XORed with the start of a flag prefix, so keys up to the prefix
/// length are found exactly. Longer keys are not guessed: a printable but wrong flag would
/// still match LemmeKnow's flag pattern.
fn crib_keys(view: &[u8]) -> Vec<Vec<u8>> {
    let mut keys: Vec<Vec<u8>> = Vec::new();
    for prefix in FLAG_PREFIXES {
        if view.len() < prefix.len() {
            continue;
        }
        for len in 2..=prefix.len() {
            let key: Vec<u8> = view
                .iter()
                .zip(prefix)
                .take(len)
                .map(|(byte, plain)| byte ^ plain)
                .collect();
            let key = shortest_period(&key);
            if key.len() >= 2
                && !keys.iter().any(|k| k == key)
                && decrypts_to_flag(view, key, prefix)
            {
                keys.push(key.to_vec());
            }
        }
    }
    keys.sort_by_key(Vec::len);
    keys
}

/// Finds the key of `sample` by frequency analysis. Returns `None` for bytes with too few
/// distinct values, and when the key comes out as one byte or mostly one byte, which is
/// what plain text and single-byte XOR give.
fn frequency_key(sample: &[u8]) -> Option<Vec<u8>> {
    if distinct_bytes(sample.iter().copied()) < MIN_DISTINCT_BYTES {
        return None;
    }

    let max_len = MAX_KEY_LEN.min(sample.len() / MIN_COLUMN_BYTES);
    let mut counts = [0u32; 256];
    let mut by_coincidence: Vec<(f64, usize)> = (2..=max_len)
        .filter(|&len| high_bits_agree(sample, len))
        .map(|len| (mean_index_of_coincidence(sample, len, &mut counts), len))
        .collect();
    by_coincidence.sort_by(|a, b| b.0.total_cmp(&a.0).then(a.1.cmp(&b.1)));

    let mut lengths = Vec::with_capacity(TOP_KEY_LENGTHS + 1);
    if high_bits_agree(sample, 1) {
        lengths.push(1);
    }
    lengths.extend(
        by_coincidence
            .iter()
            .take(TOP_KEY_LENGTHS)
            .map(|&(_, len)| len),
    );

    // Minimum description length: every key byte costs ln 256
    let mut best: Option<(f64, Vec<u8>)> = None;
    for len in lengths {
        let mut total = -(len as f64) * 256_f64.ln();
        let mut key = Vec::with_capacity(len);
        for index in 0..len {
            let Some((score, byte)) = best_column_key(sample, len, index) else {
                break;
            };
            total += score;
            key.push(byte);
        }
        if key.len() == len
            && best
                .as_ref()
                .is_none_or(|(best_total, _)| total > *best_total)
        {
            best = Some((total, key));
        }
    }

    let (_, key) = best?;
    let key = shortest_period(&key);
    if key.len() < 2 {
        return None;
    }
    let key = refine_key(sample, key.to_vec());
    let key = shortest_period(&key);
    if key.len() < 2 || is_mostly_single_byte_key(sample, key) {
        return None;
    }
    Some(key.to_vec())
}

/// Whether more than half of `key` is the best single-byte key of `sample`. Text XORed with
/// one byte sometimes gets a longer key that "improves" a few of its bytes instead (an
/// email address XORed with 0x5a came out as `aghtlddinw@plcaowar.hrg`, which LemmeKnow
/// accepts). That is single-byte XOR, and its cracker's job.
fn is_mostly_single_byte_key(sample: &[u8], key: &[u8]) -> bool {
    best_column_key(sample, 1, 0).is_some_and(|(_, single)| {
        key.iter().filter(|&&byte| byte == single).count() * 2 > key.len()
    })
}

/// Number of different byte values in `bytes`.
fn distinct_bytes(bytes: impl IntoIterator<Item = u8>) -> usize {
    let mut seen = [false; 256];
    for byte in bytes {
        seen[usize::from(byte)] = true;
    }
    seen.iter().filter(|&&seen| seen).count()
}

/// Whether a decryption of `sample` the checker rejected is still likely to be right, and
/// so worth passing on to the search: it scores like English, and its key was solved from
/// enough, and varied enough, bytes per key byte.
fn is_trustworthy_unconfirmed(sample: &[u8], candidate: &Candidate) -> bool {
    let len = candidate.key.len();
    candidate.score >= MIN_UNCONFIRMED_SCORE
        && sample.len() >= MIN_UNCONFIRMED_COLUMN_BYTES * len
        && (0..len)
            .map(|index| distinct_bytes(column(sample, len, index)))
            .sum::<usize>()
            >= MIN_UNCONFIRMED_COLUMN_DISTINCT * len
}

/// Column `index` of `sample` split into `len` columns: the bytes `index`, `index + len`,
/// `index + 2·len`, ...
fn column(sample: &[u8], len: usize, index: usize) -> impl Iterator<Item = u8> + '_ {
    sample.iter().skip(index).step_by(len).copied()
}

/// Whether, splitting `sample` into `len` columns, few bytes have a different high bit from
/// most of their column. See [`HIGH_BIT_TOLERANCE`].
fn high_bits_agree(sample: &[u8], len: usize) -> bool {
    let disagreeing: usize = (0..len)
        .map(|index| {
            let (high, total) = column(sample, len, index).fold((0, 0), |(high, total), byte| {
                (high + usize::from(byte >> 7), total + 1)
            });
            high.min(total - high)
        })
        .sum();
    disagreeing * HIGH_BIT_TOLERANCE <= sample.len()
}

/// Mean index of coincidence of the `len` columns of `sample`. `counts` is scratch space
/// and must be all zeros; it is left that way.
fn mean_index_of_coincidence(sample: &[u8], len: usize, counts: &mut [u32; 256]) -> f64 {
    let mut total = 0.0;
    for index in 0..len {
        let mut pairs = 0u64;
        let mut size = 0u64;
        for byte in column(sample, len, index) {
            pairs += u64::from(counts[usize::from(byte)]);
            counts[usize::from(byte)] += 1;
            size += 1;
        }
        for byte in column(sample, len, index) {
            counts[usize::from(byte)] = 0;
        }
        if size >= 2 {
            total += 2.0 * pairs as f64 / (size * (size - 1)) as f64;
        }
    }
    total / len as f64
}

/// Summed byte score of every key byte that decrypts the column without control
/// characters, in key byte order.
fn column_key_scores(sample: &[u8], len: usize, index: usize) -> Vec<(f64, u8)> {
    let mut counts = [0u32; 256];
    for byte in column(sample, len, index) {
        counts[usize::from(byte)] += 1;
    }
    let present: Vec<(u8, f64)> = (0..=255u8)
        .zip(counts)
        .filter(|&(_, count)| count > 0)
        .map(|(byte, count)| (byte, f64::from(count)))
        .collect();
    let scores = &*BYTE_SCORES;
    (0..=255u8)
        .filter_map(|key_byte| {
            let mut score = 0.0;
            for &(byte, count) in &present {
                let plain = byte ^ key_byte;
                if is_control_byte(plain) {
                    return None;
                }
                score += count * scores[usize::from(plain)];
            }
            Some((score, key_byte))
        })
        .collect()
}

/// The best key byte for one column and its score. Ties go to the lower byte.
fn best_column_key(sample: &[u8], len: usize, index: usize) -> Option<(f64, u8)> {
    column_key_scores(sample, len, index)
        .into_iter()
        .fold(None, |best, candidate| match best {
            Some((score, _)) if candidate.0 <= score => best,
            _ => Some(candidate),
        })
}

/// Improves `key` by coordinate ascent: up to [`REFINE_ROUNDS`] times, tries each column's
/// [`REFINE_CHOICES`] best key bytes and keeps any that raise the byte scores plus the
/// letter bigram scores of the whole sample. Columns solved on their own ignore their
/// neighbours, which on short text picks e.g. `kee` instead of `key`.
fn refine_key(sample: &[u8], mut key: Vec<u8>) -> Vec<u8> {
    let len = key.len();
    let choices: Vec<Vec<u8>> = (0..len)
        .map(|index| {
            let mut scores = column_key_scores(sample, len, index);
            scores.sort_by(|a, b| b.0.total_cmp(&a.0).then(a.1.cmp(&b.1)));
            scores
                .into_iter()
                .take(REFINE_CHOICES)
                .map(|(_, byte)| byte)
                .collect()
        })
        .collect();

    for _ in 0..REFINE_ROUNDS {
        let mut improved = false;
        for (index, column_choices) in choices.iter().enumerate() {
            let mut current = column_contribution(sample, &key, index, key[index]);
            for &choice in column_choices {
                if choice == key[index] {
                    continue;
                }
                let score = column_contribution(sample, &key, index, choice);
                if score > current + 1e-9 {
                    key[index] = choice;
                    current = score;
                    improved = true;
                }
            }
        }
        if !improved {
            break;
        }
    }
    key
}

/// The part of the refinement objective that depends on key byte `index` when it is
/// `key_byte`: the byte scores of its column plus the bigram scores of letter pairs that
/// include a byte of the column. Keys are at least 2 bytes, so a byte's neighbours are in
/// other columns and decrypt with `key` as it is.
fn column_contribution(sample: &[u8], key: &[u8], index: usize, key_byte: u8) -> f64 {
    let scores = &*BYTE_SCORES;
    let pmi = &*LETTER_PMI;
    let letter_at = |position: usize| letter_index(sample[position] ^ key[position % key.len()]);

    let mut total = 0.0;
    for position in (index..sample.len()).step_by(key.len()) {
        let plain = sample[position] ^ key_byte;
        total += scores[usize::from(plain)];
        let Some(letter) = letter_index(plain) else {
            continue;
        };
        if let Some(before) = position.checked_sub(1).and_then(letter_at) {
            total += pmi[before][letter];
        }
        if let Some(after) = Some(position + 1)
            .filter(|&next| next < sample.len())
            .and_then(letter_at)
        {
            total += pmi[letter][after];
        }
    }
    total
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

    // helper for tests
    fn get_athena_checker() -> CheckerTypes {
        let athena_checker = Checker::<Athena>::new();
        CheckerTypes::CheckAthena(athena_checker)
    }

    fn crack(text: &str) -> CrackResult {
        Decoder::<XorRepeatingKeyDecoder>::new().crack(text, &get_athena_checker())
    }

    fn hex_bytes(hex: &str) -> Vec<u8> {
        hex_view(hex).expect("valid hex")
    }

    fn base64_bytes(base64: &str) -> Vec<u8> {
        base64_view(base64).expect("valid Base64")
    }

    /// Cryptopals set 1 challenge 5, from the issue. CyberChef `XOR` with the UTF8 key
    /// `ICE` then `To Hex` gives the same.
    const ICE_HEX: &str = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
    const ICE_PLAINTEXT: &str =
        "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";

    /// The Dickens vectors from the issue plan: CyberChef `XOR` (UTF8 key) then
    /// `To Base64`.
    const DICKENS: &str = "It was the best of times, it was the worst of times, it was the age of wisdom, it was the age of foolishness, it was the epoch of belief.";
    const CIPHEY_BASE64: &str = "Ch1QHwQKYx0YDUUbJhoESAofYx0ZBQAKb0kZHEUOIhpQHA0cYx4fGhYNYwYWSBEQLgwDREUQN0kHCRZZNwEVSAQeJkkfDkUOKhoUBwhVYwAESBIYMEkEAABZIg4VSAofYw8fBwkQMAEeDRYKb0kZHEUOIhpQHA0cYwwABwYRYwYWSAccLwAVDks=";
    const SIXTEEN_BYTE_KEY_BASE64: &str = "eUUSRFVGFkNQXEEABhcRRl9XEkddWFNEFBkIFkMTBBUQRVpWFEJZRUtNQQ0FRBEPXVRBHxRcQhdPWBJCFwwARlFWVxNbUxZAUUoFDQ5IRQ9EEUVSRxVCX10ZAAUGRAoAEFddXFhcRV9WXBIRT0QMEhBGU0AUQV5SGFwRDQAMRQlWEVBWWFxTURY=";

    const OAK_HEX: &str = "26001c1f45140e45181f450d03005904091d4b0a1800450d19001c4b041f1f000b4b11110e450b0a0c174b160d04150a45";
    const OAK_PLAINTEXT: &str = "Meet me at the old oak tree after the rain stops.";

    const HELLO_BASE64: &str = "ECo+BwpVeBg9GQkdeW8GAwwKeCYhSwRZKyoxGQANeCI3GBYYPypyDQoLeDY9Hks=";
    const HELLO_PLAINTEXT: &str = "Hello, World! This is a secret message for you.";

    const FOX_HEX: &str =
        "3f0d1c4b140c0206124b070b0412174b03161345131e08091845161d000b4b11110e45150a1f004b01160c";
    const FOX_PLAINTEXT: &str = "The quick brown fox jumps over the lazy dog";

    const FLAG_HEX: &str = "755bdf886845db9f7656ca867d50e184764ee1977c45e1866068d49a6043e1997a50db817645dbb07c59e18d6a43db9c6e";
    const FLAG_PLAINTEXT: &str = "flag{repeating_key_xor_is_just_vigenere_on_bytes}";

    /// Cryptopals set 1 challenge 6, <https://cryptopals.com/static/challenge-data/6.txt>
    const CRYPTOPALS_6: &str =
        include_str!("../../tests/test_fixtures/cryptopals_set1_challenge6.txt");

    /// The single-byte XOR vectors of #1017. They belong to the single-byte cracker.
    const SINGLE_BYTE_VECTORS: [&str; 8] = [
        "795a424344520a454c0a48464b49410a5b5f4b585e50060a405f4e4d4f0a47530a5c455d04",
        "eVpCQ0RSCkVMCkhGS0lBCltfS1heUAYKQF9OTU8KR1MKXEVdBA==",
        "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736",
        "l6um47K2qqCo46GxrLSt46Wsu+Optq6zsOOstaax47erpuOvorm646espA==",
        "97aba6e3b2b6aaa0a8e3a1b1acb4ade3a5acbbe3a9b6aeb3b0e3acb5a6b1e3b7aba6e3afa2b9bae3a7aca4",
        "3c363b3d21226a28056b2905346a2e0569343928232a2e6b6a3427",
        "FAUqLgsKBHMjFQwwCwUIOyBxJjcLBRg0JwEAMyYVczUhOwA0Ji8UOwsKEC0YEQAxGxoydwsFEDQYNX9/",
        "yZBCDR\nEL\nHFKIA\n[_KX^P\u{6}\n@_NMO\nGS\n\\E]\u{4}",
    ];

    fn assert_cracks(input: &str, key: &str, plaintext: &str) {
        let result = crack(input);
        assert!(result.success, "{input}: not identified, got {result:?}");
        assert_eq!(
            result.unencrypted_text.unwrap(),
            vec![plaintext.to_string()]
        );
        assert_eq!(result.key.as_deref(), Some(key));
        assert_eq!(result.decoder, "Repeating-key XOR");
    }

    fn assert_no_candidates(input: &str) {
        let result = crack(input);
        assert!(
            result.unencrypted_text.is_none(),
            "{input:?} should give no candidates, got {result:?}"
        );
        assert!(!result.success);
    }

    /// Deterministic pseudo-random bytes (xorshift64*).
    fn pseudo_random_bytes(seed: u64, len: usize) -> Vec<u8> {
        let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
        (0..len)
            .map(|_| {
                state ^= state >> 12;
                state ^= state << 25;
                state ^= state >> 27;
                (state.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 56) as u8
            })
            .collect()
    }

    #[test]
    fn cracks_cryptopals_1_5_ice() {
        assert_cracks(ICE_HEX, "ICE", ICE_PLAINTEXT);
        assert_eq!(
            crack_bytes(&hex_bytes(ICE_HEX)),
            Some((b"ICE".to_vec(), ICE_PLAINTEXT.to_string()))
        );
    }

    #[test]
    fn cracks_base64_key_ciphey() {
        assert_cracks(CIPHEY_BASE64, "Ciphey", DICKENS);
        assert_eq!(
            crack_bytes(&base64_bytes(CIPHEY_BASE64)),
            Some((b"Ciphey".to_vec(), DICKENS.to_string()))
        );
    }

    #[test]
    fn cracks_sixteen_byte_key() {
        assert_cracks(SIXTEEN_BYTE_KEY_BASE64, "0123456789abcdef", DICKENS);
        assert_eq!(
            crack_bytes(&base64_bytes(SIXTEEN_BYTE_KEY_BASE64)),
            Some((b"0123456789abcdef".to_vec(), DICKENS.to_string()))
        );
    }

    #[test]
    fn cracks_hex_key_key() {
        assert_cracks(OAK_HEX, "key", OAK_PLAINTEXT);
        assert_eq!(
            crack_bytes(&hex_bytes(OAK_HEX)),
            Some((b"key".to_vec(), OAK_PLAINTEXT.to_string()))
        );
    }

    #[test]
    fn cracks_base64_key_xorkey() {
        assert_cracks(HELLO_BASE64, "XORkey", HELLO_PLAINTEXT);
        assert_eq!(
            crack_bytes(&base64_bytes(HELLO_BASE64)),
            Some((b"XORkey".to_vec(), HELLO_PLAINTEXT.to_string()))
        );
    }

    #[test]
    fn cracks_pangram_thanks_to_refinement() {
        assert_cracks(FOX_HEX, "key", FOX_PLAINTEXT);
        assert_eq!(
            crack_bytes(&hex_bytes(FOX_HEX)),
            Some((b"key".to_vec(), FOX_PLAINTEXT.to_string()))
        );
    }

    #[test]
    fn refinement_turns_kee_into_key() {
        // Each column solved on its own gives "kee" for the pangram
        let sample = hex_bytes(FOX_HEX);
        let columns: Vec<u8> = (0..3)
            .map(|index| best_column_key(&sample, 3, index).unwrap().1)
            .collect();
        assert_eq!(columns, b"kee");
        assert_eq!(refine_key(&sample, columns), b"key");
    }

    #[test]
    fn cracks_flag_with_high_byte_key_by_crib() {
        assert_cracks(FLAG_HEX, "0x1337beef", FLAG_PLAINTEXT);
        let view = hex_bytes(FLAG_HEX);
        assert_eq!(crib_keys(&view), vec![vec![0x13, 0x37, 0xbe, 0xef]]);
        assert_eq!(
            crack_bytes(&view),
            Some((vec![0x13, 0x37, 0xbe, 0xef], FLAG_PLAINTEXT.to_string()))
        );
    }

    #[test]
    fn cracks_high_byte_key_by_frequency() {
        // The Dickens text XORed with 0xdeadbeef, as Base64
        let input = "l9memL/enpu2yJ6Nu97Kz7HLnpu3wNuc8o3Xm/7a35z+2daK/trRna3ZnoC4jcqGs8jNw/7Eys+pzM3PqsXbz7/K28+xy56Yt97agLOBnoaqjcmOrY3Kh7uN34i7jdGJ/svRgLLEzYewyM2c8o3Xm/7a35z+2daK/sjOgL3FnoC4jdyKssTbifA=";
        assert!(crib_keys(&base64_bytes(input)).is_empty());
        assert_cracks(input, "0xdeadbeef", DICKENS);
    }

    #[test]
    fn cracks_cryptopals_1_6() {
        // The canonical repeating-key XOR challenge: 2876 bytes, key of 29 bytes. The key
        // fixes the plaintext; the search itself can't return it, as results over about
        // 1000 characters fail its quality check.
        let ciphertext = base64_view(CRYPTOPALS_6).unwrap();
        assert_eq!(ciphertext.len(), 2876);
        let (key, plaintext) = crack_bytes(&ciphertext).expect("Cryptopals 1-6 should crack");
        assert_eq!(key, b"Terminator X: Bring the noise");
        assert_eq!(plaintext.len(), 2876);
        assert!(plaintext.starts_with(
            "I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \n"
        ));
        assert!(plaintext.ends_with("Come on, Come on, Come on \nPlay that funky music \n"));
    }

    #[test]
    fn cracks_raw_bytes_from_the_hexadecimal_decoder() {
        // What the Hexadecimal decoder outputs for the ICE ciphertext: ASCII with control
        // characters
        let raw = String::from_utf8(hex_bytes(ICE_HEX)).unwrap();
        assert_cracks(&raw, "ICE", ICE_PLAINTEXT);

        // ... and for the flag ciphertext, which isn't UTF-8: one Latin-1 char per byte
        let latin1: String = hex_bytes(FLAG_HEX).into_iter().map(char::from).collect();
        assert_cracks(&latin1, "0x1337beef", FLAG_PLAINTEXT);
    }

    #[test]
    fn hex_with_separators_and_prefixes() {
        let bytes = hex_bytes(OAK_HEX);
        let spaced: Vec<String> = bytes.iter().map(|byte| format!("{byte:02X}")).collect();
        assert_cracks(&spaced.join(" "), "key", OAK_PLAINTEXT);
        assert_cracks(&spaced.join(":"), "key", OAK_PLAINTEXT);
        assert_cracks(&format!("0x{OAK_HEX}"), "key", OAK_PLAINTEXT);
        let prefixed: Vec<String> = bytes.iter().map(|byte| format!("0x{byte:02x}")).collect();
        assert_cracks(&prefixed.join(" "), "key", OAK_PLAINTEXT);
    }

    #[test]
    fn decimal_and_octal_codes_are_not_hex() {
        // Space-separated codes are hex digits too, but groups of 3 digits aren't bytes.
        // These are what the Octal and Decimal decoders take off; reading them as hex
        // made every such node pay for a full analysis.
        for codes in [
            // Octal of "Meet me at the old lighthouse"
            "115 145 145 164 40 155 145 40 141 164 40 164 150 145 40 157 154 144 40 154 151 147 150 164 150 157 165 163 145",
            // Decimal of the same
            "77 101 101 116 32 109 101 32 97 116 32 116 104 101 32 111 108 100 32 108 105 103 104 116 104 111 117 115 101",
        ] {
            assert_eq!(hex_view(codes), None, "{codes:?}");
            assert!(byte_views(codes).is_empty(), "{codes:?}");
        }
        // Whole bytes per group are still hex
        assert_eq!(
            hex_view("4d 65 65 74 20 6d 65 20 61 74 20 74 68 65 20 6f"),
            Some(b"Meet me at the o".to_vec())
        );
        assert_eq!(
            hex_view("4d65 6574 206d 6520 6174 2074 6865 206f"),
            Some(b"Meet me at the o".to_vec())
        );
    }

    #[test]
    fn single_case_text_is_not_base64() {
        for text in [
            // Base32 of "The quick brown fox jumps over the lazy dog"
            "KRUGKIDROVUWG2ZAMJZG653OEBTG66BANJ2W24DTEBXXMZLSEB2GQZJANRQXU6JAMRXWO===",
            // Upper-case letters only, like Citrix CTX1 or a1z26 output
            "CCHIMAJKEGBMHACKFHANKBPLOGLMOELOPCKIPAKKLGOMFAAKEGBMEEBONDIJIFNPDDGJDB",
            "itwasthebestoftimesitwastheworstoftimes",
        ] {
            assert_eq!(base64_view(text), None, "{text:?}");
            assert!(byte_views(text).is_empty(), "{text:?}");
        }
        assert!(base64_view(HELLO_BASE64).is_some());
    }

    #[test]
    fn url_safe_base64() {
        let url_safe = HELLO_BASE64.replace('+', "-").replace('/', "_");
        assert_cracks(url_safe.trim_end_matches('='), "XORkey", HELLO_PLAINTEXT);
    }

    #[test]
    fn line_wrapped_base64() {
        // The Cryptopals 6.txt file as it is, 60 characters per line
        assert!(CRYPTOPALS_6.trim().contains('\n'));
        let view = base64_view(CRYPTOPALS_6).expect("wrapped Base64 should be read");
        assert_eq!(view.len(), 2876);
        let wrapped = format!("{}\r\n{}", &CIPHEY_BASE64[..76], &CIPHEY_BASE64[76..]);
        assert_cracks(&wrapped, "Ciphey", DICKENS);
        // Spaces are not line breaks: "hello world ..." is not Base64
        assert_eq!(base64_view("hello world this is plain text"), None);
    }

    #[test]
    fn passes_on_a_decryption_the_checker_rejects() {
        // Reversed English XORed with "ICE": the checker rejects the reversed text, but it
        // scores like English, so the search gets it and can apply Reverse next
        let reversed: String = format!("{ICE_PLAINTEXT} {DICKENS}").chars().rev().collect();
        let ciphertext = xor_with_key(reversed.as_bytes(), b"ICE");
        let hex: String = ciphertext
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let result = crack(&hex);
        assert!(!result.success);
        assert_eq!(result.unencrypted_text, Some(vec![reversed]));
        assert_eq!(result.key.as_deref(), Some("ICE"));
    }

    #[test]
    fn does_not_pass_on_unconfirmed_decryptions_of_text() {
        // The same reversed text in lowercase, XORed with "KEY", is printable: as text it
        // could be URL encoding or Base85, which XOR "improves" into letter soup, so only
        // a checker-confirmed decryption is returned
        let reversed: String = DICKENS.to_lowercase().chars().rev().collect();
        let ciphertext = xor_with_key(reversed.as_bytes(), b"KEY");
        assert!(clean_text(&ciphertext).is_some());
        assert_eq!(crack_bytes(&ciphertext), Some((b"KEY".to_vec(), reversed)));
        let hex: String = ciphertext
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_no_candidates(&hex);
    }

    #[test]
    fn does_not_pass_on_letter_soup_from_repetitive_bytes() {
        // A node from the binary_base64 search benchmark: the binary digits of a sentence,
        // Base64 encoded, then Caesar shifted. It is still valid Base64, of 288 bytes that
        // take only a few values per column, and a 6-byte key turns those into " e e a e".
        let node = "MMDDEEwxMMDDEExwMMDDEAggMMDDEExxMMDTAAxxMMDDEAggMMDDEAxxMMDDAAxwMMDDEAggMMDDEExxMMTDAAxwMMDDAEggMMDDAExxMMDDAEwxMMDTAAggMMDDEExxMMDDEAxxMMDDEAggMMDDEAxxMMDDAAxwMMDDEAggMMDDAExxMMDDAAwwMMDTAAggMMDDEExxMMDTAAwwMMDTEAggMMDDEExxMMTDAExwMMDDAEggMMDDAExxMMDDAEwxMMDTAAggMMDDEExxMMTDAAxxMMDTAEggMMDDEAxxMMDDEAwwMMDDAAggMMDDEExxMMDTAAxxMMDDEAggMMDDAExxMMDDAEwwMMDDAAggMMDDEExxMMDDEAxxMMTDEEgg";
        assert_no_candidates(node);
    }

    #[test]
    fn fails_on_random_bytes() {
        let random = "3ca33472d7fbe17a0129389332e605fba06bcb80b2b6c027ae2d9593ea489e0cbcbaecd82eccff3bd9fbcb84d7f50c72";
        assert_no_candidates(random);
        assert_eq!(crack_bytes(&hex_bytes(random)), None);

        for seed in 0..300 {
            let len = 16 + (seed as usize * 37) % 497;
            let bytes = pseudo_random_bytes(seed, len);
            assert_eq!(crack_bytes(&bytes), None, "seed {seed}, {len} bytes");
        }
    }

    #[test]
    fn leaves_single_byte_xor_to_the_single_byte_cracker() {
        for input in SINGLE_BYTE_VECTORS {
            assert_no_candidates(input);
            for view in byte_views(input) {
                assert_eq!(crack_bytes(&view), None, "{input:?}");
            }
        }
        // Plain and single-byte XORed English always comes out with a 1-byte key
        for text in [
            DICKENS,
            OAK_PLAINTEXT,
            FOX_PLAINTEXT,
            HELLO_PLAINTEXT,
            ICE_PLAINTEXT,
        ] {
            for key in [0u8, 0x01, 0x20, 0x2a, 0x5a, 0x80, 0xc3, 0xff] {
                let bytes: Vec<u8> = text.bytes().map(|byte| byte ^ key).collect();
                assert_eq!(crack_bytes(&bytes), None, "{text:?} XOR {key:#04x}");
            }
        }
    }

    #[test]
    fn does_not_improve_single_byte_xor_with_a_longer_key() {
        // An email address XORed with single bytes. Frequency analysis picks the 3-byte
        // key 0x5a5a5d for the first, which gives "aghtlddinw@plcaowar.hrg", and LemmeKnow
        // accepts that as an email address.
        let email = b"agotlcdiiw@wlcfowfr.org";
        for single in [0x5a, 0x13, 0xc3] {
            let bytes: Vec<u8> = email.iter().map(|byte| byte ^ single).collect();
            assert!(is_mostly_single_byte_key(
                &bytes,
                &[single, single, single ^ 7]
            ));
            assert_eq!(crack_bytes(&bytes), None, "XOR {single:#04x}");
            let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
            assert_no_candidates(&hex);
        }
        // Real keys share at most a byte or so with the single-byte key
        let ciphertext = hex_bytes(ICE_HEX);
        assert!(!is_mostly_single_byte_key(&ciphertext, b"ICE"));
    }

    #[test]
    fn defers_single_byte_xored_flags() {
        // flag{x0r_1s_n0t_3ncrypt10n} XOR 0x5a, from #1017. Frequency analysis would make
        // letter soup of it with a 4-byte key.
        let view = hex_bytes(SINGLE_BYTE_VECTORS[5]);
        assert!(is_single_byte_flag(&view));
        assert!(crib_keys(&view).is_empty());
        // A plain flag is a flag XORed with 0
        assert!(is_single_byte_flag(FLAG_PLAINTEXT.as_bytes()));
        assert!(!is_single_byte_flag(&hex_bytes(FLAG_HEX)));
    }

    #[test]
    fn fails_without_panicking_on_bad_input() {
        for input in [
            "",
            "😀",
            "😀😀😀😀😀😀😀😀😀😀😀😀😀😀😀😀",
            "hello world",
            "The quick brown fox jumps over the lazy dog",
            "0x",
            "=",
            "==",
            "\u{0}",
            "ÿ",
            "\u{1}\u{2}\u{3}",
        ] {
            assert_no_candidates(input);
        }
        for bytes in [&b""[..], b"a", b"\x00", b"\xff\xfe"] {
            assert_eq!(crack_bytes(bytes), None);
        }
    }

    #[test]
    fn fails_on_views_shorter_than_16_bytes() {
        // "Attack at dawn!" XOR "ICE" is 15 bytes
        let short = "08373128202e6922316927243e2d64";
        assert!(byte_views(short).is_empty());
        assert_no_candidates(short);
        assert_eq!(crack_bytes(&hex_digits_to_bytes(short.as_bytes())), None);
    }

    #[test]
    fn plain_and_encoded_text_gets_no_candidates() {
        for input in [
            // Hex, Base64 and Base32 of English
            "4d656574206d6520617420746865206f6c64206c69676874686f757365",
            "TWVldCBtZSBhdCB0aGUgb2xkIGxpZ2h0aG91c2UgYWZ0ZXIgbWlkbmlnaHQ=",
            "JVSWK5BANVSSAYLUEB2GQZJAN5WGIIDMNFTWQ5DIN52XGZJAMFTHIZLSEBWWSZDONFTWQ5BAMFXGIIDCOJUW4ZZAORUGKIDNMFYCYIDUNBSSA23FPEQGC3TEEBQSA5DPOJRWQLQ=",
            // Hex of Base64, and of URL encoding
            "564768684948463161574e7249474a796233647549475a7665434271645731776379427664585679494852686253427359587035494752765a773d3d",
            "4d6565742532306d652532306174253230746865253230",
            // Binary, which is valid hex too
            "01001101 01100101 01100101 01110100 00100000 01101101 01100101 00100000 01100001 01110100 00100000 01110100 01101000 01100101",
            "0100110101100101011001010111010000100000011011010110010100100000011000010111010000100000011101000110100001100101",
            // An MD5 digest
            "5d41402abc4b2a76b9719d911017c592",
            // Text in other languages, and the search benchmark's unicode case
            "éèêëàâäôöûüçéèêëàâäôöûüçéèêëàâäôöûüçéèêëàâäôöûüç",
            "Où est la bibliothèque ? Le café est très près de la gare, à côté du théâtre.",
            "¿Dónde está la biblioteca? El niño comió una piña en el café de la esquina.",
            "Съешь же ещё этих мягких французских булок, да выпей чаю",
            "我能吞下玻璃而不伤身体。我能吞下玻璃而不伤身体。",
        ] {
            assert_no_candidates(input);
        }
    }

    #[test]
    fn byte_views_of_text() {
        assert!(byte_views("hello world, this is plain text.").is_empty());
        // Hex digits are in the Base64 alphabet too, but hex isn't also read as Base64
        assert_eq!(byte_views(OAK_HEX), vec![hex_bytes(OAK_HEX)]);
        assert_eq!(byte_views(ICE_HEX), vec![hex_bytes(ICE_HEX)]);
        assert_eq!(byte_views(HELLO_BASE64), vec![base64_bytes(HELLO_BASE64)]);
        // Text with Latin-1 symbols is tried as Latin-1 and as UTF-8
        let latin1 = "±".repeat(16);
        assert_eq!(
            byte_views(&latin1),
            vec![vec![0xb1; 16], latin1.as_bytes().to_vec()]
        );
        // Accented letters alone are natural text
        assert!(byte_views(&"é".repeat(16)).is_empty());
        assert!(byte_views("Über den Wolken muss die Freiheit wohl grenzenlos sein").is_empty());
        // Text with other characters only as UTF-8
        let mixed = "\u{1}😀😀😀😀";
        assert_eq!(byte_views(mixed), vec![mixed.as_bytes().to_vec()]);
    }

    #[test]
    fn shortest_period_of_keys() {
        assert_eq!(shortest_period(b"ICEICE"), b"ICE");
        assert_eq!(shortest_period(b"ICE"), b"ICE");
        assert_eq!(shortest_period(b"aaaa"), b"a");
        assert_eq!(shortest_period(b"abab"), b"ab");
        assert_eq!(shortest_period(b"abaab"), b"abaab");
        assert_eq!(shortest_period(b""), b"");
    }

    #[test]
    fn formats_keys() {
        assert_eq!(format_key(b"ICE"), "ICE");
        assert_eq!(
            format_key(b"Terminator X: Bring the noise"),
            "Terminator X: Bring the noise"
        );
        assert_eq!(format_key(&[0x13, 0x37, 0xbe, 0xef]), "0x1337beef");
        assert_eq!(format_key(b"a\nb"), "0x610a62");
    }

    #[test]
    fn byte_scores_match_the_plan() {
        let scores = &*BYTE_SCORES;
        assert!((scores[usize::from(b'e')] - (0.82_f64 * 0.127).ln()).abs() < 1e-12);
        assert!((scores[usize::from(b'E')] - (0.82_f64 * 0.127 * 0.15).ln()).abs() < 1e-12);
        assert!((scores[usize::from(b' ')] - 0.15_f64.ln()).abs() < 1e-12);
        assert!((scores[usize::from(b'7')] - (0.03_f64 / 24.0).ln()).abs() < 1e-12);
        assert!((scores[usize::from(b'{')] - (0.002_f64 / 21.0).ln()).abs() < 1e-12);
        assert!((scores[0] - 1e-6_f64.ln()).abs() < 1e-12);
        assert!((scores[0xbe] - 1e-6_f64.ln()).abs() < 1e-12);
    }

    #[test]
    fn letter_pmi_matches_the_prototype() {
        // Values from the Python prototype of the issue plan
        let pmi = &*LETTER_PMI;
        let pair = |a: u8, b: u8| pmi[letter_index(a).unwrap()][letter_index(b).unwrap()];
        for (a, b, expected) in [
            (b'q', b'u', 3.527503),
            (b't', b'h', 1.819409),
            (b't', b'q', -0.917279),
            (b'k', b'e', 0.928013),
            (b'k', b'y', -0.074368),
            (b'q', b'z', -2.916221),
        ] {
            assert!(
                (pair(a, b) - expected).abs() < 1e-5,
                "{}{}",
                a as char,
                b as char
            );
        }
        // Case doesn't matter
        assert_eq!(letter_index(b'T'), letter_index(b't'));
    }

    #[test]
    fn registered_once_under_its_name() {
        let decoders = crate::filtration_system::get_decoder_by_name("Repeating-key XOR");
        assert_eq!(decoders.components.len(), 1);
        assert!((decoders.components[0].get_popularity() - 0.4).abs() < 1e-6);
        assert!(!decoders.components[0].get_tags().contains(&"decoder"));
        assert!(crate::decoders::DECODER_MAP.contains_key("Repeating-key XOR"));
    }

    #[test]
    fn cached_results_deserialise() {
        // The cache stores the path as JSON and looks decoders up by name
        let result = crack(ICE_HEX);
        let json = result.get_json().unwrap();
        let cached: CrackResult = serde_json::from_str(&json).unwrap();
        assert_eq!(cached.decoder, "Repeating-key XOR");
        assert_eq!(cached.key.as_deref(), Some("ICE"));
    }
}
