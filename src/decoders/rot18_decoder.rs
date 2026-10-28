//! Crack ROT5 and ROT18: the digits rotated by 5, and the letters by a Caesar shift.
//!
//! ROT5 rotates every ASCII digit by 5 (`0` ↔ `5`, `1` ↔ `6`, …, `4` ↔ `9`) and leaves
//! everything else alone. ROT18 is ROT13 on the ASCII letters plus ROT5 on the digits. Both
//! undo themselves. This cracker covers the general form, "digits +5, letters +k" for any
//! Caesar shift k: k = 0 is ROT5 and k = 13 is ROT18. Letters keep their case; whitespace,
//! punctuation and non-ASCII characters (`é`, `攻`, Arabic-Indic digits) are left as they
//! are. The key it reports is the shifts the text was encrypted with, `letters 13, digits 5`
//! for ROT18 and `letters 0, digits 5` for ROT5. References:
//! <https://en.wikipedia.org/wiki/ROT13#Variants>, <https://www.dcode.fr/rot18-cipher>,
//! <https://www.dcode.fr/rot5-cipher>, and CyberChef's `ROT13` with "Rotate numbers".
//!
//! # What it tries
//!
//! Text without an ASCII digit is turned away after one pass over its bytes: rotating its
//! letters is a Caesar shift, which the Caesar cracker tries. Otherwise the cracker tries at
//! most three letter shifts, each once, in this order: the one under which the letters best
//! fit English, then 0 (ROT5) and 13 (ROT18). The best fit is the shift with the lowest
//! unigram chi-squared against [`ENGLISH_FREQS`], computed from the letter counts the same
//! pass makes, without decrypting anything; with fewer than 12 letters it is too unreliable
//! to try. Without letters every shift gives the same text, which is tried once.
//!
//! # When it reports plaintext
//!
//! The digits decide. The English checker can't tell `1230` from `6785`, so Caesar and
//! Vigenère read ROT18 text as English with its digits still rotated (`Gur zrrgvat vf ng
//! 6785` is `The meeting is at 6785` to them), and this cracker would read ROT13 text, which
//! is much more common, with digits that were never rotated (`Ebgngr zr 13 cynprf!` would
//! be `Rotate me 68 places!`). When two decoders find plaintext in the same search step,
//! the one listed first in the filtration system wins, so a cracker listed before Caesar and
//! Vigenère that reported every reading the checker accepts would break ROT13 text with
//! numbers in it.
//!
//! Numbers in text mostly start with a small digit. By Benford's law
//! (<https://en.wikipedia.org/wiki/Benford%27s_law>) a number starts with a 1 4.5 times as
//! often as with a 6, and with a 4 twice as often as with a 9, and ROT5 swaps exactly those
//! pairs: 1 and 6, 2 and 7, 3 and 8, 4 and 9 (and 0 and 5, which count the same here). So
//! the same pass adds up, over the text's runs of digits, the log of how much more likely the
//! rotated first digit is than the text's own. Only if the rotated digits come out at least
//! e times as likely (a total of 1 or more: one number starting with 6 or 7, or two starting
//! with 8 or 9, more than the other way round) does the cracker decrypt the text and run the
//! checker: `6785` → `1230`, `647.613` → `192.168`, the leetspeak `r5t63` → `r0t18`.
//! Otherwise it turns the text away, as it does text without digits, and the Caesar reading
//! of the letters wins. ROT13 text with ordinary numbers in it (`13`, `2016`, the leetspeak
//! `Nap0leon_vs_Ca3s4r`) so goes to Caesar as before. Digits in long tokens that mix letters
//! and digits (16 characters or more: hashes, keys, passwords, Base64) and in hex (8 or more
//! characters whose letters lie within 6 consecutive letters, like the 8 hex digits at the
//! end of a picoCTF flag) are random and don't count either way, so most encoded text is
//! turned away after the one pass too.
//!
//! The checker runs with Low sensitivity for gibberish detection, as Caesar's does, at most
//! three times per text. Decodings it doesn't identify aren't handed on to the search: the
//! search would expand them, and their Caesar shifts, as well as the plain Caesar
//! readings, for little gain (it cost up to 19% more work in the `search` benchmarks, mostly
//! on Base64 and hex nodes), so ROT18 is only found as the last decoding step.
//!
//! # Known limits
//!
//! * Text whose own numbers mostly start with 5 to 9 is turned away: ROT18 of `Call me on
//!   555 0199 before 9 tonight` gives no decodings, and the search returns the Caesar
//!   reading, `Call me on 000 5644 before 4 tonight`.
//! * ROT13 or Caesar text whose own numbers mostly start with 6 to 9 is taken for ROT18:
//!   `We have 654 apples and 751 oranges` comes back as `109 apples and 206 oranges`.
//! * ROT18 has to be the last decoding step: Base64 of ROT18 text is found (Base64, then
//!   rot18), ROT18 of Base64 isn't, since the decodings aren't handed on (and the digits
//!   of Base64 don't count, so it is turned away anyway).
//! * ROT5 alone, with the letters untouched, can't be found by the search when the letters
//!   are English: such text is taken for plaintext before any decoder runs, and the English
//!   checker can't tell `1234` from `6789`.
//! * Plain English with digits in it is "cracked" into English with other digits when those
//!   look like ordinary numbers; the cracker can't know. In the search this doesn't happen,
//!   because such text is identified before any decoder runs on it.

use crate::checkers::CheckerTypes;
use crate::decoders::interface::check_string_success;
use crate::storage::ENGLISH_FREQS;
use gibberish_or_not::Sensitivity;

use super::crack_results::CrackResult;
use super::interface::Crack;
use super::interface::Decoder;

use log::trace;

/// How far ROT5 rotates a digit, to encrypt and to decrypt alike: 5 is half of 10.
const DIGIT_SHIFT: u8 = 5;

/// ROT18's letter shift: it is ROT13 on the letters.
const ROT13_SHIFT: u8 = 13;

/// The fewest ASCII letters for which the best-fitting letter shift is tried as well as ROT5
/// and ROT18. A chi-squared fit on fewer letters is too often wrong: a prototype ranked the
/// true shift 3rd for `Elm 1234` and 5th for `pin 4821`.
const MIN_LETTERS_TO_RANK: u32 = 12;

/// `ln(P(first digit is rot5(d)) / P(first digit is d))` for each digit d, by Benford's law,
/// `P(d) = log10(1 + 1/d)`. A leading 0 isn't covered by Benford's law; it is given the
/// probability of a leading 5, so 0 and 5 count for nothing either way. Positive for 6 to 9,
/// whose rotations 1 to 4 lead numbers more often. `leading_digit_evidence_is_benford` in the
/// tests checks the values.
const LEADING_DIGIT_EVIDENCE: [f64; 10] = [
    0.0, -1.503_312, -1.110_698, -0.893_012, -0.750_427, // 0-4
    0.0, 1.503_312, 1.110_698, 0.893_012, 0.750_427, // 5-9
];

/// The least digit evidence, in nats, for which the text is decrypted and its decodings
/// checked: by Benford's law the rotated digits must be at least e (about 2.7) times as
/// likely as the text's own. ROT13 and Caesar, which leave the digits alone, are much more
/// common than ROT18, so a positive total alone isn't enough. A number starting with 6 or 7
/// is (it rotates to 1 or 2), one starting with 8 or 9 isn't (3 or 4), two of those are.
const MIN_DIGIT_EVIDENCE: f64 = 1.0;

/// Tokens (runs of ASCII letters and digits) at least this long that mix letters and digits
/// don't count towards the digit evidence: they are hashes, keys, passwords or Base64,
/// whose digits are random and so say nothing about a rotation.
const MIN_RANDOM_TOKEN_LEN: usize = 16;

/// Nor do tokens at least this long that mix letters and digits, if all their letters lie
/// within [`HEX_LETTER_SPAN`] consecutive letters of the alphabet (wrapping from `z` to `a`):
/// that is hex under any letter shift.
const MIN_HEX_TOKEN_LEN: usize = 8;

/// How many consecutive letters hex uses: `a` to `f`.
const HEX_LETTER_SPAN: u32 = 6;

/// The ROT5 / ROT18 cracker, call:
/// `let rot18_decoder = Decoder::<Rot18Decoder>::new()` to create a new instance
/// And then call:
/// `result = rot18_decoder.crack(input, &checker)` to crack ROT18, ROT5 or ROT5 with another
/// letter shift
/// The struct generated by new() comes from interface.rs
/// ```
/// use ciphey::decoders::rot18_decoder::Rot18Decoder;
/// use ciphey::decoders::interface::{Crack, Decoder};
/// use ciphey::checkers::{athena::Athena, CheckerTypes, checker_type::{Check, Checker}};
///
/// let decode_rot18 = Decoder::<Rot18Decoder>::new();
/// let athena_checker = Checker::<Athena>::new();
/// let checker = CheckerTypes::CheckAthena(athena_checker);
///
/// let result = decode_rot18.crack("Gur zrrgvat vf ng 6785 va ebbz 959 ba gur frpbaq sybbe", &checker);
/// assert!(result.success);
/// // If it succeeds, the 0th element is the plaintext, else there are no decodings
/// assert_eq!(
///     result.unencrypted_text.unwrap()[0],
///     "The meeting is at 1230 in room 404 on the second floor"
/// );
/// assert_eq!(result.key.unwrap(), "letters 13, digits 5");
/// ```
pub struct Rot18Decoder;

impl Crack for Decoder<Rot18Decoder> {
    fn new() -> Decoder<Rot18Decoder> {
        Decoder {
            name: "rot18",
            description: "ROT5 rotates digits by 5, ROT18 is ROT13 on letters plus ROT5 on digits; also tries ROT5 with the best-fitting Caesar shift. Uses Low sensitivity for gibberish detection.",
            link: "https://en.wikipedia.org/wiki/ROT13#Variants",
            tags: vec!["rot18", "rot5", "decryption", "classic", "reciprocal"],
            popularity: 0.5,
            phantom: std::marker::PhantomData,
        }
    }

    /// Decrypts with the letter shifts of [`shifts_to_try`] in turn and stops at the first
    /// decoding the checker identifies, reporting its key as `letters <k>, digits 5`. Text
    /// whose digits don't look rotated (see the module docs) isn't decrypted at all, and
    /// decodings the checker doesn't identify aren't handed on.
    fn crack(&self, text: &str, checker: &CheckerTypes) -> CrackResult {
        trace!("Trying ROT5 / ROT18 with text {:?}", text);
        let mut results = CrackResult::new(self, text.to_string());

        let Some(scan) = scan(text) else {
            trace!("Failed to crack ROT18: the text has no ASCII digit");
            return results;
        };
        if scan.digit_evidence < MIN_DIGIT_EVIDENCE {
            trace!(
                "Failed to crack ROT18: the digits look unrotated (evidence {:.2})",
                scan.digit_evidence
            );
            return results;
        }

        // Use the checker with Low sensitivity, like the Caesar cracker
        let checker_with_sensitivity = checker.with_sensitivity(Sensitivity::Low);

        for shift in shifts_to_try(&scan) {
            // Undo the letter shift; +5 on the digits undoes itself
            let decoded_text = rot(text, (26 - shift) % 26, DIGIT_SHIFT);
            // A digit always changes, so this only guards against surprises
            if !check_string_success(&decoded_text, text) {
                continue;
            }
            let checker_result = checker_with_sensitivity.check(&decoded_text);
            if checker_result.is_identified {
                trace!("Found a match with ROT18 letter shift {}", shift);
                results.unencrypted_text = Some(vec![decoded_text]);
                results.update_checker(&checker_result);
                results.key = Some(format!("letters {shift}, digits {DIGIT_SHIFT}"));
                return results;
            }
        }

        trace!("Failed to crack ROT18: the checker identified none of the decodings");
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

/// What one pass over a text's bytes found.
struct Scan {
    /// How many times each ASCII letter occurs, case-folded, `a` first.
    letter_counts: [u32; 26],
    /// How many ASCII letters there are.
    letters: u32,
    /// The sum of [`LEADING_DIGIT_EVIDENCE`] over the first digits of the text's runs of
    /// ASCII digits, apart from those in tokens whose digits look random (see
    /// [`Token::digit_evidence`]): positive if the rotated digits look more like ordinary
    /// numbers.
    digit_evidence: f64,
}

/// Counts the letters and weighs the digits of `text` in one pass over its bytes, or `None`
/// if it has no ASCII digit. Bytes of multi-byte UTF-8 characters are never ASCII, so they
/// count as neither, and they end a token like any other character that isn't an ASCII
/// letter or digit.
fn scan(text: &str) -> Option<Scan> {
    let mut letter_counts = [0u32; 26];
    let mut letters = 0;
    let mut has_digit = false;
    let mut digit_evidence = 0.0;
    let mut token = Token::default();
    for byte in text.bytes() {
        if byte.is_ascii_digit() {
            has_digit = true;
            if !token.ends_in_digit {
                token.evidence += LEADING_DIGIT_EVIDENCE[usize::from(byte - b'0')];
            }
            token.ends_in_digit = true;
            token.len += 1;
        } else if byte.is_ascii_alphabetic() {
            let letter = byte.to_ascii_lowercase() - b'a';
            letter_counts[usize::from(letter)] += 1;
            letters += 1;
            token.letters |= 1 << letter;
            token.ends_in_digit = false;
            token.len += 1;
        } else {
            digit_evidence += token.digit_evidence();
            token = Token::default();
        }
    }
    digit_evidence += token.digit_evidence();
    has_digit.then_some(Scan {
        letter_counts,
        letters,
        digit_evidence,
    })
}

/// A run of ASCII letters and digits, as [`scan`] reads it.
#[derive(Default)]
struct Token {
    /// How many bytes it has.
    len: usize,
    /// The letters in it, case-folded, a bit each: `a` is bit 0.
    letters: u32,
    /// Whether its last byte so far is a digit, so the next digit isn't a first digit.
    ends_in_digit: bool,
    /// The sum of [`LEADING_DIGIT_EVIDENCE`] over the first digits of its runs of digits.
    evidence: f64,
}

impl Token {
    /// What the token's digits say about the rotation: nothing if they look random, that
    /// is if it mixes letters and digits and is at least [`MIN_RANDOM_TOKEN_LEN`] long
    /// (a hash, key, password or Base64), or at least [`MIN_HEX_TOKEN_LEN`] long with
    /// letters that fit in [`HEX_LETTER_SPAN`] consecutive letters (hex, `a` to `f`, under
    /// any letter shift, such as the 8 hex digits at the end of a picoCTF flag).
    fn digit_evidence(&self) -> f64 {
        let random = self.letters != 0
            && (self.len >= MIN_RANDOM_TOKEN_LEN
                || (self.len >= MIN_HEX_TOKEN_LEN && fits_hex_span(self.letters)));
        if random {
            0.0
        } else {
            self.evidence
        }
    }
}

/// Whether all of `letters` (a bit per letter, `a` = bit 0) lie within
/// [`HEX_LETTER_SPAN`] consecutive letters of the alphabet, wrapping from `z` to `a`.
fn fits_hex_span(letters: u32) -> bool {
    /// A bit for each of the 26 letters
    const ALPHABET: u32 = (1 << 26) - 1;
    /// The first `HEX_LETTER_SPAN` letters
    const SPAN: u32 = (1 << HEX_LETTER_SPAN) - 1;
    (0..26).any(|start| {
        let window = ((SPAN << start) | (SPAN >> (26 - start))) & ALPHABET;
        letters & !window == 0
    })
}

/// The letter shifts to decrypt with, in order and each once: the best-fitting one if there
/// are at least [`MIN_LETTERS_TO_RANK`] letters, then 0 (ROT5) and 13 (ROT18). Without
/// letters only 0, since every shift gives the same text.
fn shifts_to_try(scan: &Scan) -> Vec<u8> {
    if scan.letters == 0 {
        return vec![0];
    }
    let mut shifts = Vec::with_capacity(3);
    if scan.letters >= MIN_LETTERS_TO_RANK {
        shifts.extend(rank_shifts(&scan.letter_counts).first());
    }
    for shift in [0, ROT13_SHIFT] {
        if !shifts.contains(&shift) {
            shifts.push(shift);
        }
    }
    shifts
}

/// The 26 letter shifts k a text with these letter counts may have been encrypted with,
/// best fit first. Under shift k ciphertext letter i was plaintext letter (i - k) mod 26,
/// so English would give it about `n · ENGLISH_FREQS[(i - k) mod 26]` of its n letters;
/// the shifts are sorted by the chi-squared distance of the counts from that, and ties keep
/// the smaller shift first. Without letters every shift fits as well, so they come in order.
fn rank_shifts(counts: &[u32; 26]) -> Vec<u8> {
    let letters: f64 = counts.iter().map(|&count| f64::from(count)).sum();
    if letters == 0.0 {
        return (0..26).collect();
    }
    let mut scored: Vec<(f64, u8)> = (0..26u8)
        .map(|shift| {
            let chi_squared = counts
                .iter()
                .enumerate()
                .map(|(letter, &count)| {
                    let expected = letters * ENGLISH_FREQS[(letter + 26 - usize::from(shift)) % 26];
                    let difference = f64::from(count) - expected;
                    difference * difference / expected
                })
                .sum();
            (chi_squared, shift)
        })
        .collect();
    // A stable sort, so equal fits keep the smaller shift first
    scored.sort_by(|a, b| a.0.total_cmp(&b.0));
    scored.into_iter().map(|(_, shift)| shift).collect()
}

/// Moves every ASCII letter `letter_shift` places forward in the alphabet and every ASCII
/// digit `digit_shift` places forward among the digits, both wrapping around, and keeps
/// everything else. Encrypting with letter shift k is `rot(text, k, 5)`, and
/// `rot(text, 26 - k, 5)` decrypts it.
fn rot(text: &str, letter_shift: u8, digit_shift: u8) -> String {
    /// `c` moved `shift` places forward in the range of `size` characters from `first`.
    fn rotate(c: char, first: u8, size: u8, shift: u8) -> char {
        char::from(first + (c as u8 - first + shift % size) % size)
    }
    text.chars()
        .map(|c| match c {
            'a'..='z' => rotate(c, b'a', 26, letter_shift),
            'A'..='Z' => rotate(c, b'A', 26, letter_shift),
            '0'..='9' => rotate(c, b'0', 10, digit_shift),
            _ => c,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkers::{
        athena::Athena,
        checker_type::{Check, Checker},
        CheckerTypes,
    };
    use crate::decoders::DECODER_MAP;
    use crate::filtration_system::get_decoder_by_name;

    // The vectors below were made with CyberChef 10.24 (`ROT13` on the letters with amount k,
    // then `ROT13` with "Rotate numbers" only, amount 5) and independently with a Python 3
    // `rot()`, and decrypted back to the plaintext. The verdicts are Athena's at Low, as
    // `crack` runs it.

    /// The bench `miss` input, which every decoder must reject
    const MISS: &str =
        "T00 l3= ox+#G WKyV pajU6j qxH@ %B4+a 5Pn^ 7p_v1q 9sLvu *+36i R5rL&3 mVJZI iO0 Ut8_m COTV";

    // helper for tests
    fn get_athena_checker() -> CheckerTypes {
        let athena_checker = Checker::<Athena>::new();
        CheckerTypes::CheckAthena(athena_checker)
    }

    /// What the cracker makes of `text`
    fn crack(text: &str) -> CrackResult {
        Decoder::<Rot18Decoder>::new().crack(text, &get_athena_checker())
    }

    /// The best-fitting letter shift for `text`
    fn best_shift(text: &str) -> u8 {
        let scan = scan(text).expect("the text has a digit");
        rank_shifts(&scan.letter_counts)[0]
    }

    /// Asserts that the cracker identifies `plaintext` in `text` with key `key`
    #[track_caller]
    fn assert_cracked(text: &str, plaintext: &str, key: &str) {
        let result = crack(text);
        assert!(result.success, "{result:?}");
        assert_eq!(
            result.unencrypted_text.as_deref(),
            Some(&[plaintext.to_string()][..])
        );
        assert_eq!(result.key.as_deref(), Some(key));
    }

    #[test]
    fn rot_of_empty_text_is_empty() {
        assert_eq!(rot("", 13, 5), "");
    }

    #[test]
    fn rot_rotates_letters_and_digits_and_keeps_case() {
        assert_eq!(rot("Hello World 2024", 13, 5), "Uryyb Jbeyq 7579");
        assert_eq!(rot("xyz XYZ 789", 3, 5), "abc ABC 234");
        // ROT5 alone leaves the letters
        assert_eq!(rot("Room 101", 0, 5), "Room 656");
    }

    #[test]
    fn rot_leaves_everything_else() {
        assert_eq!(rot("attack at 0600 攻", 5, 5), "fyyfhp fy 5155 攻");
        // Non-ASCII letters and digits (Arabic-Indic three, Devanagari five), punctuation
        // and whitespace are copied
        assert_eq!(rot("é Ö ٣ ५ ½ ,.;!\t\n", 13, 5), "é Ö ٣ ५ ½ ,.;!\t\n");
    }

    #[test]
    fn rot_round_trips_for_every_shift() {
        let text = "The quick brown fox jumps over the lazy dog: 0123456789, THE QUICK BROWN FOX!";
        for shift in 0..26 {
            assert_eq!(
                rot(&rot(text, shift, 5), (26 - shift) % 26, 5),
                text,
                "{shift}"
            );
        }
        // ROT18 and ROT5 undo themselves
        assert_eq!(rot(&rot(text, 13, 5), 13, 5), text);
        assert_eq!(rot(&rot(text, 0, 5), 0, 5), text);
    }

    #[test]
    fn leading_digit_evidence_is_benford() {
        let benford =
            |digit: u8| (1.0 + 1.0 / f64::from(if digit == 0 { 5 } else { digit })).log10();
        for digit in 0..10u8 {
            let rotated = (digit + 5) % 10;
            let expected = (benford(rotated) / benford(digit)).ln();
            let actual = LEADING_DIGIT_EVIDENCE[usize::from(digit)];
            assert!(
                (actual - expected).abs() < 1e-6,
                "{digit}: {actual} vs {expected}"
            );
        }
    }

    #[test]
    fn digit_evidence_counts_the_first_digit_of_each_number() {
        let evidence = |text| scan(text).unwrap().digit_evidence;
        // 6785 and 959 rotate to 1230 and 404
        assert!((evidence("6785 959") - (1.503_312 + 0.750_427)).abs() < 1e-9);
        // 13 rotates to 68, and the leetspeak digits 0, 3 and 4 to 5, 8 and 9
        assert!(evidence("ebg_13_vfag_frpher") < 0.0);
        assert!(evidence("Gti0exhg_ol_Vt3l4k") < 0.0);
        // Only 0 and 5, or a 1 and a 6: nothing either way
        assert_eq!(evidence("0 5 50 05"), 0.0);
        assert_eq!(evidence("1 6"), 0.0);
    }

    #[test]
    fn random_looking_digits_do_not_count() {
        let evidence = |text| scan(text).unwrap().digit_evidence;
        for text in [
            // An MD5 in a flag, and its ROT13
            "flag{6f980c0101c8aa361977cac06508a3de}",
            "synt{6s980p0101p8nn361977pnp06508n3qr}",
            // The hex at the end of a picoCTF flag, and its Caesar shift by 8
            "picoCTF{25d7c61b}",
            "xqkwKBN{25l7k61j}",
            // A password, Base64
            "The password is 5Te8Y4drgCRfCx8ugdwuEX8KFC6k2EUu",
            "R3VyIHpycmd2YXQgdmYgbmcgNjc4NSB2YSBlYmJ6IDk1OSBiYSBndXIgZnJwYmFxIHN5YmJl",
        ] {
            assert_eq!(evidence(text), 0.0, "{text:?}");
        }
        // Leetspeak counts, and so does a long number
        assert!(evidence("r5t63") > 0.0);
        assert!(evidence("Gti0exhg_ol_Vt3l4k") < 0.0);
        assert!(evidence("12345678901234567890") < 0.0);
    }

    #[test]
    fn hex_letters_fit_six_consecutive_letters() {
        let letters = |text: &str| {
            text.bytes()
                .fold(0u32, |set, byte| set | 1 << (byte - b'a'))
        };
        for hex in ["abcdef", "dcb", "opq", "za", "uvwxyz", "yzabcd"] {
            assert!(fits_hex_span(letters(hex)), "{hex}");
        }
        for not_hex in ["abcdefg", "ag", "rotation", "xyzabcd"] {
            assert!(!fits_hex_span(letters(not_hex)), "{not_hex}");
        }
    }

    #[test]
    fn text_without_digits_is_not_scanned() {
        for text in ["", "😀", "hello world", "#", "٣٤٥"] {
            assert!(scan(text).is_none(), "{text:?}");
        }
    }

    #[test]
    fn rank_shifts_is_every_shift_once() {
        let scan = scan("Gur zrrgvat vf ng 6785 va ebbz 959 ba gur frpbaq sybbe").unwrap();
        let mut ranked = rank_shifts(&scan.letter_counts);
        ranked.sort_unstable();
        assert_eq!(ranked, (0..26).collect::<Vec<u8>>());
        // Without letters every shift fits as well
        assert_eq!(rank_shifts(&[0; 26]), (0..26).collect::<Vec<u8>>());
    }

    #[test]
    fn rank_shifts_finds_the_encryption_shift() {
        // The issue's ROT18 and ROT5 examples
        assert_eq!(best_shift("Zrrg zr ng 6789 Ryz Fgerrg ng 5490"), 13);
        assert_eq!(best_shift("Meet me at 6789 Elm Street at 5490"), 0);
        assert_eq!(
            best_shift("Aol tllapun pz ha 6785 pu yvvt 959 vu aol zljvuk msvvy"),
            7
        );
        assert_eq!(best_shift("Xvgg hz ji 000 5644 wzajmz 4 ojidbco"), 21);
    }

    #[test]
    fn shifts_to_try_puts_the_best_fit_first() {
        let shifts = |text| shifts_to_try(&scan(text).unwrap());
        assert_eq!(
            shifts("Aol tllapun pz ha 6785 pu yvvt 959 vu aol zljvuk msvvy"),
            [7, 0, 13]
        );
        assert_eq!(
            shifts("Gur zrrgvat vf ng 6785 va ebbz 959 ba gur frpbaq sybbe"),
            [13, 0]
        );
        assert_eq!(shifts("Meet me at 6789 Elm Street at 5490"), [0, 13]);
        // Fewer than 12 letters: only ROT5 and ROT18
        assert_eq!(shifts("synt{e5g63_6f_a5g_e5g68}"), [0, 13]);
        // No letters: one text
        assert_eq!(shifts("647.613.5.6"), [0]);
    }

    #[test]
    fn cracks_rot18() {
        assert_cracked(
            "Gur zrrgvat vf ng 6785 va ebbz 959 ba gur frpbaq sybbe",
            "The meeting is at 1230 in room 404 on the second floor",
            "letters 13, digits 5",
        );
        assert_cracked(
            "V jnf obea va 6430 naq zbirq gb Ybaqba va 7552",
            "I was born in 1985 and moved to London in 2007",
            "letters 13, digits 5",
        );
        // The bench `medium` text with ` Room 101.` appended, which Athena identifies
        assert_cracked(
            "Zrrg zr ng gur byq yvtugubhfr nsgre zvqavtug naq oevat gur znc, gur xrl naq n gbepu. Ebbz 656.",
            "Meet me at the old lighthouse after midnight and bring the map, the key and a torch. Room 101.",
            "letters 13, digits 5",
        );
    }

    #[test]
    fn cracks_rot5_with_another_letter_shift() {
        assert_cracked(
            "Aol tllapun pz ha 6785 pu yvvt 959 vu aol zljvuk msvvy",
            "The meeting is at 1230 in room 404 on the second floor",
            "letters 7, digits 5",
        );
    }

    #[test]
    fn cracks_a_rot18_flag() {
        // LemmeKnow takes it for a CTF flag
        assert_cracked(
            "synt{e5g63_6f_a5g_e5g68}",
            "flag{r0t18_1s_n0t_r0t13}",
            "letters 13, digits 5",
        );
    }

    #[test]
    fn cracks_rot5_digits() {
        // LemmeKnow takes it for an IPv4 address. No letters, so there is one decoding.
        assert_cracked("647.613.5.6", "192.168.0.1", "letters 0, digits 5");
    }

    #[test]
    fn decodes_the_issue_examples() {
        // Athena doesn't identify the issue's plaintext at Low (Medium does), so the search
        // doesn't get it, but it is the first decoding tried: ROT18, then ROT5 only
        for (text, shift) in [
            ("Zrrg zr ng 6789 Ryz Fgerrg ng 5490", 13),
            ("Meet me at 6789 Elm Street at 5490", 0),
        ] {
            assert_eq!(shifts_to_try(&scan(text).unwrap())[0], shift, "{text:?}");
            assert_eq!(
                rot(text, (26 - shift) % 26, 5),
                "Meet me at 1234 Elm Street at 0945"
            );
            let result = crack(text);
            assert!(!result.success, "{text:?}: {result:?}");
            assert!(result.unencrypted_text.is_none(), "{text:?}: {result:?}");
        }
    }

    #[test]
    fn leaves_rot13_with_ordinary_numbers_to_caesar() {
        // 13 would rotate to 68: the text's own digits look more like a number, so the text
        // is turned away, and the Caesar cracker's ROT13 reading is the answer
        for text in ["Ebgngr zr 13 cynprf!", "Gur synt vf: ebg_13_vfag_frpher"] {
            let result = crack(text);
            assert!(!result.success, "{text:?}");
            assert!(result.unencrypted_text.is_none(), "{text:?}: {result:?}");
        }
    }

    #[test]
    fn digits_that_look_unrotated_are_turned_away() {
        // ROT18 of "Call me on 555 0199 before 9 tonight" (letter shift 21). Its numbers
        // start with 5, 0 and 9, the rotations of the ciphertext's 0, 5 and 4, so the
        // cracker can't tell it from ROT13 or Caesar with ordinary numbers
        let result = crack("Xvgg hz ji 000 5644 wzajmz 4 ojidbco");
        assert!(!result.success, "{result:?}");
        assert!(result.unencrypted_text.is_none(), "{result:?}");
    }

    #[test]
    fn one_number_starting_with_8_or_9_is_not_enough() {
        // ROT18 of "The meeting is in room 404 on the second floor": 404 is 959, which
        // rotates back to a number only about twice as likely
        let result = crack("Gur zrrgvat vf va ebbz 959 ba gur frpbaq sybbe");
        assert!(result.unencrypted_text.is_none(), "{result:?}");
        // Two are
        assert_cracked(
            "Gur zrrgvat vf va ebbz 959 ba gur 9gu sybbe",
            "The meeting is in room 404 on the 4th floor",
            "letters 13, digits 5",
        );
    }

    #[test]
    fn unidentified_decodings_are_not_handed_on() {
        // Gibberish whose digits look rotated: decrypted with three shifts, none identified
        let text = "Qwv 6 zxkp 7 hbtr 6 mfdy";
        assert_eq!(shifts_to_try(&scan(text).unwrap()), [21, 0, 13]);
        let result = crack(text);
        assert!(!result.success, "{result:?}");
        assert!(result.unencrypted_text.is_none(), "{result:?}");
        assert!(result.key.is_none(), "{result:?}");
    }

    #[test]
    fn rot47_text_is_not_identified() {
        // ROT47 of "Hello, World!": too few letters to rank, so ROT5 and ROT18, neither
        // identified ("w1==@[ (@C=0P" and "j1==@[ (@P=0C"); rot47 cracks it
        let text = "w6==@[ (@C=5P";
        assert_eq!(shifts_to_try(&scan(text).unwrap()), [0, 13]);
        let result = crack(text);
        assert!(!result.success, "{result:?}");
        assert!(result.unencrypted_text.is_none(), "{result:?}");
    }

    #[test]
    fn the_bench_miss_input_is_turned_away() {
        // Its digits look unrotated (evidence -0.68), so nothing is decrypted or checked
        let result = crack(MISS);
        assert!(!result.success, "{result:?}");
        assert!(result.unencrypted_text.is_none(), "{result:?}");
    }

    #[test]
    fn fails_without_digits() {
        // Including ROT13 and Atbash without digits, which are Caesar's and Atbash's
        for text in [
            "",
            "😀",
            "hello world",
            "#",
            "Zrrg zr ng gur byq yvtugubhfr",
            "svool dliow",
        ] {
            let result = crack(text);
            assert!(!result.success, "{text:?}");
            assert!(result.unencrypted_text.is_none(), "{text:?}");
        }
    }

    #[test]
    fn is_registered() {
        let decoders = get_decoder_by_name("rot18");
        assert_eq!(decoders.components.len(), 1);
        assert_eq!(decoders.components[0].get_name(), "rot18");
        assert!(DECODER_MAP.contains_key("rot18"));
    }
}
