//! Decode leetspeak ("1337"), where letters are written as look-alike digits and symbols
//! inside otherwise ordinary words: `l337 5p34k 15 3l173` is `leet speak is elite`.
//!
//! There is no single leet alphabet. This decoder reads the common symbols of Wikipedia's
//! table (<https://en.wikipedia.org/wiki/Leet#Orthography>):
//!
//! * one character: `0` o, `3` e, `4` a, `5` s, `6` g, `7` t, `8` b, `9` g, `@` a, `$` s,
//!   `+` t, `#` h, and inside a word `(` c and `!` i,
//! * one character for either of two letters: `1` i or l, `|` l or i, `2` z or r,
//! * several characters, read before any single one and longest first: `|\/|` and `/\/\` m,
//!   `\/\/` w, `|-|` h, `|\|` and `/\/` n, `|<` k, `|)` d, `|>` p, `|=` f, `|3` b, `|2` r,
//!   `\/` v, `/\` a, `><` x.
//!
//! Everything else (letters, `_`, braces, punctuation) is copied, so `flag{h3ll0_w0rld}`
//! is `flag{hello_world}`. Punctuation around a word (`h3ll0!`, `(0d3`) is kept as it is.
//!
//! A word with `1`, `|` or `2` in it is read every way (up to 16 ways, see `readings`)
//! and the first reading in an English word list wins: `1337` is `leet` and `3l173` is
//! `elite`. Otherwise `1` reads as `i` (CyberChef's choice), `|` as `l` and `2` as `z`.
//! The word list is `src/storage/ngrams/english_words.txt` with some leet and computing
//! words it lacks (`LEET_WORDS`), and a few suffixes are stripped (`TESTING` is a word
//! because `TEST` is). The substituted letters are upper case when the word's own letters
//! are (`H3LL0` is `HELLO`, `7H3` is `THE`) and lower case otherwise (`M337` is `Meet`).
//!
//! The checks run cheapest first, so most text costs one pass over its bytes:
//! 1. The text is ASCII, has a digit or one of `@ $ | + # < > \ /`, no token (a run of
//!    characters between whitespace, `_`, `{` and `}`) longer than 24 characters (Base64,
//!    hex and the other encodings are one long token), and a letter, unless it is a
//!    single short token such as `1337`.
//! 2. At least half of the words with a leet symbol in them are dictionary words, and one
//!    of those has at least 3 letters. This rejects English that merely contains numbers
//!    (`I have 2 cats`), version numbers, e-mail addresses and the like.
//!
//! Only then is the decoded text given to the checker.
//!
//! References: <https://en.wikipedia.org/wiki/Leet>, CyberChef's "Convert Leet Speak"
//! (<https://github.com/gchq/CyberChef/blob/master/src/core/operations/ConvertLeetSpeak.mjs>)
//! and Python Ciphey's table
//! (<https://github.com/Ciphey/CipheyDists/blob/master/cipheydists/translate/leet.json>).

use crate::checkers::CheckerTypes;
use crate::decoders::interface::check_string_success;
use once_cell::sync::Lazy;

use super::crack_results::CrackResult;
use super::interface::Crack;
use super::interface::Decoder;

use log::{debug, trace};

/// The longest token, a run of characters between whitespace, `_`, `{` and `}`, that leet
/// text may have. Base64, Base32, Base58, hex, URL encoding and JWTs are a single long
/// token; leet words and the parts of a CTF flag are much shorter.
const MAX_TOKEN_LEN: usize = 24;

/// Text with no letter at all is only read if it is a single token of at most this many
/// characters, such as `1337` or `|-|3||0`. Decimal, binary and A1Z26 have several tokens.
const MAX_LETTERLESS_LEN: usize = 8;

/// A word with at most this many symbols that stand for two letters is read every way,
/// 2⁴ = 16 at most. With more, only the readings where they all take their usual letter,
/// or all take the other one, are tried.
const MAX_EXHAUSTIVE_AMBIGUOUS: usize = 4;

/// At least one of the words that decoded to a dictionary word must be this long: `a` and
/// `i` (`4`, `1`) are words, but they're also what a stray number decodes to.
const MIN_WORD_LEN: usize = 3;

/// Dictionary words that stripping one of these suffixes turns into a word are words too,
/// if they have at least [`MIN_INFLECTED_LEN`] letters and the stem at least
/// [`MIN_STEM_LEN`]. The word list has `TEST` and `JUMP` but not `TESTING` and `JUMPS`.
const SUFFIXES: [&str; 6] = ["S", "ES", "ED", "ING", "LY", "ER"];

/// Suffixes that replaced a final `E` of the stem: `HAVING` is `HAVE` + `ING`.
const SUFFIXES_AFTER_E: [&str; 2] = ["ING", "ED"];

/// See [`SUFFIXES`].
const MIN_INFLECTED_LEN: usize = 5;

/// See [`SUFFIXES`].
const MIN_STEM_LEN: usize = 3;

/// Leet, CTF and computing words that the Project Gutenberg word list doesn't have, in
/// alphabetical order for binary search.
const LEET_WORDS: &[&str] = &[
    "ACCESS",
    "ADMIN",
    "AWESOME",
    "CIPHER",
    "CODE",
    "CODING",
    "CONGRATS",
    "CRACKER",
    "CTF",
    "DUDE",
    "ELEET",
    "ELITE",
    "EPIC",
    "EXPLOIT",
    "GAMER",
    "GAMERS",
    "GEEK",
    "HACK",
    "HACKED",
    "HACKER",
    "HACKERS",
    "HAX", // codespell:ignore
    "HAXOR",
    "INTERNET",
    "LAMER",
    "LEET",
    "LINUX",
    "LOGIN",
    "NERD",
    "NEWB",
    "NOOB",
    "ONLINE",
    "OWNED",
    "PASSWORD",
    "PASSWORDS",
    "PHREAK",
    "PWN",
    "PWNED",
    "ROX",
    "RULEZ",
    "SERVER",
    "SKILLZ",
    "SUX",
    "USER",
    "WAREZ",
];

/// Leet symbols of more than one character and the letter each stands for, longest first:
/// at each position the first that matches is read.
const MULTI_SYMBOLS: [(&[u8], u8); 15] = [
    (br"|\/|", b'm'),
    (br"/\/\", b'm'),
    (br"\/\/", b'w'),
    (b"|-|", b'h'),
    (br"|\|", b'n'),
    (br"/\/", b'n'),
    (b"|<", b'k'),
    (b"|)", b'd'),
    (b"|>", b'p'),
    (b"|=", b'f'),
    (b"|3", b'b'),
    (b"|2", b'r'),
    (br"\/", b'v'),
    (br"/\", b'a'),
    (b"><", b'x'),
];

/// The words of `english_words.txt` (upper case, from Project Gutenberg books, see
/// `gen_quadgrams.py`) in the file's alphabetical order, for binary search. A sorted list
/// costs a tenth of a hash set to build, and is only built once a text gets past the
/// first check.
static ENGLISH_WORDS: Lazy<Vec<&'static str>> = Lazy::new(|| {
    include_str!("../storage/ngrams/english_words.txt")
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect()
});

/// The Leetspeak decoder, call:
/// `let leetspeak_decoder = Decoder::<LeetspeakDecoder>::new()` to create a new instance
/// And then call:
/// `result = leetspeak_decoder.crack(input)` to decode leetspeak
/// The struct generated by new() comes from interface.rs
/// ```
/// use ciphey::decoders::leetspeak_decoder::LeetspeakDecoder;
/// use ciphey::decoders::interface::{Crack, Decoder};
/// use ciphey::checkers::{athena::Athena, CheckerTypes, checker_type::{Check, Checker}};
///
/// let decode_leetspeak = Decoder::<LeetspeakDecoder>::new();
/// let athena_checker = Checker::<Athena>::new();
/// let checker = CheckerTypes::CheckAthena(athena_checker);
///
/// let result = decode_leetspeak.crack("l337 5p34k 15 3l173", &checker);
/// assert!(result.success);
/// assert_eq!(result.unencrypted_text.unwrap()[0], "leet speak is elite");
///
/// // Text that is English already isn't leet, even with a number in it
/// let result = decode_leetspeak.crack("I have 2 cats and 3 dogs", &checker);
/// assert!(result.unencrypted_text.is_none());
/// ```
pub struct LeetspeakDecoder;

impl Crack for Decoder<LeetspeakDecoder> {
    fn new() -> Decoder<LeetspeakDecoder> {
        Decoder {
            name: "Leetspeak",
            description: "Leetspeak (1337) replaces letters with look-alike digits and symbols; the decoder picks i/l (and z/r) per word with an English word list",
            link: "https://en.wikipedia.org/wiki/Leet",
            tags: vec!["leetspeak", "leet", "substitution", "decoder"],
            popularity: 0.4,
            phantom: std::marker::PhantomData,
        }
    }

    /// Decodes `text` if it reads as leetspeak (see the module documentation) and asks the
    /// checker about the result. Text that doesn't read as leetspeak gets no
    /// `unencrypted_text`.
    fn crack(&self, text: &str, checker: &CheckerTypes) -> CrackResult {
        trace!("Trying leetspeak with text {:?}", text);
        let decoded_text = decode_leetspeak(text);

        trace!("Decoded text for leetspeak: {:?}", decoded_text);
        let mut results = CrackResult::new(self, text.to_string());

        let Some(decoded_text) = decoded_text else {
            debug!("Failed to decode leetspeak because decode_leetspeak returned None");
            return results;
        };

        if !check_string_success(&decoded_text, text) {
            debug!(
                "Failed to decode leetspeak because check_string_success returned false on string {}",
                decoded_text
            );
            return results;
        }

        let checker_result = checker.check(&decoded_text);
        results.unencrypted_text = Some(vec![decoded_text]);

        results.update_checker(&checker_result);

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

/// What a character, or a run of characters forming one symbol, of a word reads as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Unit {
    /// A character that isn't a leet symbol, such as a letter, copied as it is.
    Copied(u8),
    /// A leet symbol for this lower-case letter.
    Letter(u8),
    /// A leet symbol for either of these lower-case letters, the usual one first.
    Either(u8, u8),
}

/// What happened to one word of the text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Word {
    /// It has no leet symbol, and was copied.
    Plain,
    /// It has a leet symbol, but no reading of it is a dictionary word.
    Unresolved,
    /// It reads as a dictionary word of this many letters.
    Resolved(usize),
}

/// Decodes `text` if it reads as leetspeak, or returns `None` if it doesn't. See the
/// module documentation for the checks.
fn decode_leetspeak(text: &str) -> Option<String> {
    let mut remaining = count_tokens(text)?;

    let mut decoded = String::with_capacity(text.len());
    // Words with a leet symbol, and those that read as dictionary words
    let mut leet_words = 0;
    let mut resolved = 0;
    let mut longest_resolved = 0;

    let mut rest = text;
    while !rest.is_empty() {
        let separators = rest.bytes().take_while(|&b| is_separator(b)).count();
        decoded.push_str(&rest[..separators]);
        rest = &rest[separators..];

        let token_len = rest.bytes().take_while(|&b| !is_separator(b)).count();
        if token_len == 0 {
            break;
        }
        let (token, after) = rest.split_at(token_len);
        rest = after;
        remaining -= 1;

        match decode_token(token, &mut decoded) {
            Word::Plain => {}
            Word::Unresolved => leet_words += 1,
            Word::Resolved(len) => {
                leet_words += 1;
                resolved += 1;
                longest_resolved = longest_resolved.max(len);
            }
        }
        // Even if every remaining token read as a word, fewer than half would
        if 2 * resolved + remaining < leet_words {
            return None;
        }
    }

    (leet_words > 0 && 2 * resolved >= leet_words && longest_resolved >= MIN_WORD_LEN)
        .then_some(decoded)
}

/// The first check, one pass over the bytes: the number of tokens of `text` if it could be
/// leet, or `None` if it can't (see the module documentation).
fn count_tokens(text: &str) -> Option<usize> {
    let mut has_letter = false;
    let mut has_symbol = false;
    let mut tokens = 0;
    let mut token_len = 0;
    let mut longest = 0;
    for &byte in text.as_bytes() {
        if !byte.is_ascii() {
            return None;
        }
        if is_separator(byte) {
            token_len = 0;
            continue;
        }
        if token_len == 0 {
            tokens += 1;
        }
        token_len += 1;
        if token_len > MAX_TOKEN_LEN {
            return None;
        }
        longest = longest.max(token_len);
        has_letter |= byte.is_ascii_alphabetic();
        has_symbol |= byte.is_ascii_digit()
            || matches!(
                byte,
                b'@' | b'$' | b'|' | b'+' | b'#' | b'<' | b'>' | b'\\' | b'/'
            );
    }
    let short_letterless = tokens == 1 && longest <= MAX_LETTERLESS_LEN;
    (has_symbol && (has_letter || short_letterless)).then_some(tokens)
}

/// Whether `byte` separates tokens: ASCII whitespace, `_`, `{` or `}`.
fn is_separator(byte: u8) -> bool {
    byte.is_ascii_whitespace() || matches!(byte, b'_' | b'{' | b'}')
}

/// Whether `byte` is punctuation that can surround a word: it is copied, not read.
fn is_punctuation(byte: u8) -> bool {
    matches!(
        byte,
        b'.' | b','
            | b';'
            | b':'
            | b'!'
            | b'?'
            | b'"'
            | b'\''
            | b'('
            | b')'
            | b'['
            | b']'
            | b'-'
            | b'*'
    )
}

/// Decodes one token (at most [`MAX_TOKEN_LEN`] ASCII characters) onto the end of `out`.
/// The punctuation around the word in it is copied as it is.
fn decode_token(token: &str, out: &mut String) -> Word {
    let bytes = token.as_bytes();
    let start = bytes
        .iter()
        .position(|&b| !is_punctuation(b))
        .unwrap_or(bytes.len());
    let mut end = bytes.len();
    // A final `)` belongs to the word when it ends `|)`, the symbol for d
    while end > start && is_punctuation(bytes[end - 1]) {
        if bytes[end - 1] == b')' && end - 1 > start && bytes[end - 2] == b'|' {
            break;
        }
        end -= 1;
    }

    out.push_str(&token[..start]);
    let word = decode_word(&bytes[start..end], out);
    out.push_str(&token[end..]);
    word
}

/// Decodes the word `core` onto the end of `out`, picking the reading that is a
/// dictionary word if there is one.
fn decode_word(core: &[u8], out: &mut String) -> Word {
    let mut units = [Unit::Copied(0); MAX_TOKEN_LEN];
    let len = read_units(core, &mut units);
    let units = &units[..len];

    if units.iter().all(|unit| matches!(unit, Unit::Copied(_))) {
        // No leet symbol: copy it. `core` is ASCII, as the whole text is.
        out.extend(core.iter().map(|&b| char::from(b)));
        return Word::Plain;
    }

    let ambiguous = units
        .iter()
        .filter(|unit| matches!(unit, Unit::Either(..)))
        .count();
    // Only words of letters can be in the dictionary
    let alphabetic = units.iter().all(|unit| match unit {
        Unit::Copied(byte) => byte.is_ascii_alphabetic(),
        Unit::Letter(_) | Unit::Either(..) => true,
    });
    let word_reading = if alphabetic {
        readings(ambiguous).find(|&reading| is_word(&spell(units, reading)[..len]))
    } else {
        None
    };

    let upper = substitutes_are_upper_case(core);
    let reading = word_reading.unwrap_or(0);
    let mut ambiguous_seen = 0;
    for unit in units {
        let letter = match *unit {
            Unit::Copied(byte) => {
                out.push(char::from(byte));
                continue;
            }
            Unit::Letter(letter) => letter,
            Unit::Either(usual, other) => {
                let letter = pick(usual, other, reading, ambiguous_seen);
                ambiguous_seen += 1;
                letter
            }
        };
        out.push(char::from(if upper {
            letter.to_ascii_uppercase()
        } else {
            letter
        }));
    }

    match word_reading {
        Some(_) => Word::Resolved(len),
        None => Word::Unresolved,
    }
}

/// Splits `core` into [`Unit`]s, reading symbols of several characters first, longest
/// first. Returns how many units it wrote to `units`.
fn read_units(core: &[u8], units: &mut [Unit; MAX_TOKEN_LEN]) -> usize {
    let mut len = 0;
    let mut i = 0;
    while i < core.len() && len < MAX_TOKEN_LEN {
        let rest = &core[i..];
        let multi = if matches!(rest[0], b'|' | b'\\' | b'/' | b'>') {
            MULTI_SYMBOLS
                .iter()
                .find(|(symbol, _)| rest.starts_with(symbol))
        } else {
            None
        };
        units[len] = match multi {
            Some(&(symbol, letter)) => {
                i += symbol.len();
                Unit::Letter(letter)
            }
            None => {
                i += 1;
                single_symbol(rest[0])
            }
        };
        len += 1;
    }
    len
}

/// What a single character reads as.
fn single_symbol(byte: u8) -> Unit {
    let letter = match byte {
        b'0' => b'o',
        b'3' => b'e',
        b'4' | b'@' => b'a',
        b'5' | b'$' => b's',
        b'6' | b'9' => b'g',
        b'7' | b'+' => b't',
        b'8' => b'b',
        b'#' => b'h',
        // Only inside a word: around one they are punctuation (see `decode_token`)
        b'(' => b'c',
        b'!' => b'i',
        b'1' => return Unit::Either(b'i', b'l'),
        b'|' => return Unit::Either(b'l', b'i'),
        b'2' => return Unit::Either(b'z', b'r'),
        _ => return Unit::Copied(byte),
    };
    Unit::Letter(letter)
}

/// The readings of a word with `ambiguous` symbols that stand for two letters, in the
/// order they are tried. Bit `n` of a reading is set if the `n`th such symbol takes its
/// other letter, so reading 0, where they all take the usual one, comes first.
fn readings(ambiguous: usize) -> impl Iterator<Item = u32> {
    let (count, last) = if ambiguous <= MAX_EXHAUSTIVE_AMBIGUOUS {
        (1u32 << ambiguous, None)
    } else {
        // All usual, then all other
        (1, Some((1u32 << ambiguous.min(MAX_TOKEN_LEN)) - 1))
    };
    (0..count).chain(last)
}

/// One reading of `units`, upper-cased, padded with zeros after the last unit.
fn spell(units: &[Unit], reading: u32) -> [u8; MAX_TOKEN_LEN] {
    let mut word = [0; MAX_TOKEN_LEN];
    let mut ambiguous_seen = 0;
    for (letter, unit) in word.iter_mut().zip(units) {
        *letter = match *unit {
            Unit::Copied(byte) => byte,
            Unit::Letter(letter) => letter,
            Unit::Either(usual, other) => {
                let letter = pick(usual, other, reading, ambiguous_seen);
                ambiguous_seen += 1;
                letter
            }
        }
        .to_ascii_uppercase();
    }
    word
}

/// The letter the `index`th symbol that stands for two letters takes in `reading` (see
/// [`readings`]).
fn pick(usual: u8, other: u8, reading: u32, index: u32) -> u8 {
    if (reading >> index) & 1 == 0 {
        usual
    } else {
        other
    }
}

/// Whether the letters leet symbols stand for are written in upper case in this word:
/// when its own letters are, and there are at least two of them (`H3LL0`, `W0RLD`), or
/// the only one isn't the first character (`7H3`). `M337` is `Meet`, and a word without
/// letters (`1337`) is lower case.
fn substitutes_are_upper_case(core: &[u8]) -> bool {
    let letters = core.iter().filter(|b| b.is_ascii_alphabetic()).count();
    let upper = core.iter().filter(|b| b.is_ascii_uppercase()).count();
    match letters {
        0 => false,
        // The only letter, so it is the first character if that is a letter
        1 => upper == 1 && !core[0].is_ascii_alphabetic(),
        _ => upper == letters,
    }
}

/// Whether the upper-case ASCII letters `word` are a word: in [`ENGLISH_WORDS`] or
/// [`LEET_WORDS`], or one of their words with a suffix from [`SUFFIXES`] or
/// [`SUFFIXES_AFTER_E`].
fn is_word(word: &[u8]) -> bool {
    let Ok(word) = std::str::from_utf8(word) else {
        return false;
    };
    let english_words = &*ENGLISH_WORDS;
    let listed = |word: &str| {
        english_words.binary_search(&word).is_ok() || LEET_WORDS.binary_search(&word).is_ok()
    };
    if listed(word) {
        return true;
    }
    if word.len() < MIN_INFLECTED_LEN {
        return false;
    }
    let is_stem = |stem: &str| stem.len() >= MIN_STEM_LEN && listed(stem);
    if SUFFIXES
        .iter()
        .filter_map(|suffix| word.strip_suffix(suffix))
        .any(is_stem)
    {
        return true;
    }
    SUFFIXES_AFTER_E
        .iter()
        .filter_map(|suffix| word.strip_suffix(suffix))
        .any(|stem| {
            // The stem with its E back
            let mut with_e = [0; MAX_TOKEN_LEN + 1];
            let len = stem.len();
            if len >= with_e.len() {
                return false;
            }
            with_e[..len].copy_from_slice(stem.as_bytes());
            with_e[len] = b'E';
            std::str::from_utf8(&with_e[..=len]).is_ok_and(is_stem)
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkers::{
        athena::Athena,
        checker_type::{Check, Checker},
    };

    // helper for tests
    fn get_athena_checker() -> CheckerTypes {
        let athena_checker = Checker::<Athena>::new();
        CheckerTypes::CheckAthena(athena_checker)
    }

    fn crack(text: &str) -> CrackResult {
        Decoder::<LeetspeakDecoder>::new().crack(text, &get_athena_checker())
    }

    /// The bench `medium` plaintext, through CyberChef 10.24's "To Leet Speak"
    const MEDIUM: &str =
        "M337 m3 47 7h3 0ld l1gh7h0u53 4f73r m1dn1gh7 4nd br1ng 7h3 m4p, 7h3 k3y 4nd 4 70rch.";

    /// The bench `long` plaintext, through CyberChef 10.24's "To Leet Speak"
    const LONG: &str = "C1ph3y 15 4n 4u70m473d d3c0d1ng 700l. Y0u g1v3 17 3ncryp73d 0r 3nc0d3d 73x7 4nd 17 7r135 70 w0rk 0u7 wh47 w45 d0n3 70 17, w17h0u7 y0u h4v1ng 70 kn0w 7h3 k3y 0r 3v3n 7h3 c1ph3r. 17 534rch35 7hr0ugh m4ny p0551bl3 d3c0d1ng5, ch3ck5 34ch c4nd1d473 70 533 wh37h3r 17 l00k5 l1k3 3ngl15h 0r m47ch35 4 kn0wn p4773rn 5uch 45 4n 3m41l 4ddr355, 4nd 570p5 wh3n 17 f1nd5 50m37h1ng 7h47 r34d5 l1k3 pl41n73x7. M057 0f 7h3 71m3 7h15 74k35 l355 7h4n 4 53c0nd, wh1ch m4k35 17 h4ndy f0r c4p7ur3 7h3 fl4g ch4ll3ng35, puzzl3 hun75 4nd f0r 4ny0n3 wh0 57umbl35 4cr055 4 57r4ng3 57r1ng 1n 4 l0g f1l3.";

    /// The bench `miss` string, gibberish every decoder rejects
    const MISS: &str =
        "T00 l3= ox+#G WKyV pajU6j qxH@ %B4+a 5Pn^ 7p_v1q 9sLvu *+36i R5rL&3 mVJZI iO0 Ut8_m COTV";

    #[test]
    fn leetspeak_decodes_issue_example() {
        let result = crack("l337 5p34k 15 3l173");
        assert!(result.success, "{result:?}");
        assert_eq!(result.unencrypted_text.unwrap()[0], "leet speak is elite");
    }

    #[test]
    fn leetspeak_decodes_vectors_the_checker_identifies() {
        // CC: CyberChef 10.24 "Convert Leet Speak" (From Leet Speak) gives the same.
        // proto: the Python prototype of this algorithm in the issue's plan, where
        // CyberChef differs (it only maps 4 3 1 0 5 7, and 1 always to i).
        for (leet, plain) in [
            ("h3ll0 w0rld", "hello world"), // CC
            (
                MEDIUM,
                "Meet me at the old lighthouse after midnight and bring the map, the key and a torch.",
            ), // CC
            (
                "7h3 qu1ck br0wn f0x jump5 0v3r 7h3 l4zy d0g",
                "the quick brown fox jumps over the lazy dog",
            ), // CC
            ("4ll y0ur b453 4r3 b3l0ng 70 u5", "all your base are belong to us"), // CC
            ("Th15 15 4 735t", "This is a test"), // CC
            // TESTING is a word because TEST is
            ("T3st1ng 1s fun", "Testing is fun"), // CC
            // LemmeKnow identifies it as a CTF flag
            ("flag{h3ll0_w0rld}", "flag{hello_world}"), // CC
            ("Y0u h4v3 b33n pwn3d", "You have been pwned"), // CC
            // CyberChef gives "ieet haxor"
            ("1337 h4x0r", "leet haxor"), // proto
            ("1337", "leet"),             // proto
            // CyberChef leaves |-| and |<
            ("7|-|3 |<3y 15 |-|3r3", "the key is here"), // proto
        ] {
            let result = crack(leet);
            assert!(result.success, "{leet:?} wasn't identified: {result:?}");
            assert_eq!(result.unencrypted_text.unwrap()[0], plain, "{leet:?}");
        }
    }

    #[test]
    fn leetspeak_decodes_vectors() {
        for (leet, plain) in [
            // CyberChef gives HeLLo WoRLD: it always maps to lower case
            ("H3LL0 W0RLD", "HELLO WORLD"), // proto
            // CyberChef gives "ieet"
            ("w1ll k1ll 1337 l1f3", "will kill leet life"), // proto
            ("7357", "test"),                               // CC
            ("|-|3ll0 \\/\\/0rld", "hello world"),          // proto
            // CyberChef leaves the !
            ("7h!5 15 17", "this is it"), // proto
            ("h3ll0!", "hello!"),         // CC
            (
                "C1ph3y 15 4n 4u70m473d d3c0d1ng 700l.",
                "Ciphey is an automated decoding tool.",
            ), // CC
            // ELEET only via LEET_WORDS
            ("31337", "eleet"),
            // Letterless single token, with lone | as l
            ("|-|3||0", "hello"),
            // `|)` at the end of a word is d, not punctuation
            ("600|) |\\/|0rn1n6", "good morning"),
            ("/\\/\\4p 0f 7|-|3 /\\/0r7|-|", "map of the north"),
            ("h4><0r", "haxor"),
        ] {
            assert_eq!(
                decode_leetspeak(leet).as_deref(),
                Some(plain),
                "{leet:?} decoded wrongly"
            );
            let result = crack(leet);
            assert_eq!(result.unencrypted_text.unwrap()[0], plain, "{leet:?}");
        }
    }

    #[test]
    fn leetspeak_decodes_long_text() {
        // The capitals of "It" and "English" were written as 1 and 3, so they are lost
        let result = crack(LONG);
        assert!(result.success, "{result:?}");
        assert_eq!(
            result.unencrypted_text.unwrap()[0],
            "Ciphey is an automated decoding tool. You give it encrypted or encoded text and it tries to work out what was done to it, without you having to know the key or even the cipher. it searches through many possible decodings, checks each candidate to see whether it looks like english or matches a known pattern such as an email address, and stops when it finds something that reads like plaintext. Most of the time this takes less than a second, which makes it handy for capture the flag challenges, puzzle hunts and for anyone who stumbles across a strange string in a log file."
        );
    }

    #[test]
    fn two_reads_as_r_when_that_makes_a_word() {
        // TryHackMe c4ptur3-th3-fl4g, "Translation & Shifting 1": `2` is r in c4p7u23 and
        // 1 is l in f149
        assert_eq!(
            decode_leetspeak("c4n y0u c4p7u23 7h3 f149?").as_deref(),
            Some("can you capture the flag?")
        );
        // ...and z otherwise
        assert_eq!(
            decode_leetspeak("hunter2 15 h3r3").as_deref(),
            Some("hunterz is here")
        );
    }

    #[test]
    fn punctuation_around_words_is_kept() {
        // A leading ( is punctuation, not c. ODE isn't a word, but the other two are.
        assert_eq!(
            decode_leetspeak("(0d3 15 h3r3").as_deref(),
            Some("(ode is here")
        );
        assert_eq!(
            decode_leetspeak("\"h3ll0\", [w0rld]!").as_deref(),
            Some("\"hello\", [world]!")
        );
        // Inside a word ( is c and ! is i
        assert_eq!(
            decode_leetspeak("7h!5 r0(k5").as_deref(),
            Some("this rocks")
        );
    }

    #[test]
    fn substituted_letters_follow_the_case_of_the_word() {
        assert_eq!(decode_leetspeak("7H3 K3Y").as_deref(), Some("THE KEY"));
        // One capital, first: the word was capitalised, not written in capitals
        assert_eq!(decode_leetspeak("M337 M3").as_deref(), Some("Meet Me"));
        assert_eq!(
            decode_leetspeak("C1ph3y 15 h3r3").as_deref(),
            Some("Ciphey is here")
        );
        assert!(!substitutes_are_upper_case(b"1337"));
        assert!(!substitutes_are_upper_case(b"M337"));
        assert!(substitutes_are_upper_case(b"7H3"));
        assert!(substitutes_are_upper_case(b"H3LL0"));
        assert!(!substitutes_are_upper_case(b"H3ll0"));
        assert!(!substitutes_are_upper_case(b"h3LL0"));
    }

    #[test]
    fn short_words_alone_are_not_leet() {
        // Each reads as a word of one letter, or not as a word
        for text in [
            "(0d3",
            "hunter2",
            "C1ph3y",
            "my_var_1 = 42",
            "x = 3 + 4 * 2",
        ] {
            assert_eq!(decode_leetspeak(text), None, "{text:?}");
        }
    }

    #[test]
    fn leetspeak_rejects_text_that_isnt_leet() {
        for text in [
            "",
            "   ",
            "😀",
            "⠓⠑⠇⠇⠕",
            "日本語",
            "h3ll0 wörld",
            "hello world",
            "Hello, World!",
            "I have 2 cats and 3 dogs",
            "Windows 10 is great",
            "Room 101 is on floor 3",
            "The 3rd of May 2024",
            "$100 and 50% off",
            "2024",
            "101",
            "404",
            "68656c6c6f20776f726c64",
            "68 65 6c 6c 6f 20 77 6f 72 6c 64",
            "aGVsbG8gd29ybGQ=",
            "TWVldCBtZSBhdCB0aGUgb2xkIGxpZ2h0aG91c2U=",
            "104 101 108 108 111 32 119 111 114 108 100",
            "01101000 01101001",
            "8-5-12-12-15 23-15-18-12-4",
            ".... . .-.. .-.. --- / .-- --- .-. .-.. -..",
            "user@example.com",
            "192.168.0.1",
            "v1.2.3",
            "a1b2c3d4e5f6",
            // rot47 of the bench medium plaintext: 3 of its 17 words read as words
            "|66E >6 2E E96 @=5 =:89E9@FD6 27E6C >:5?:89E 2?5 3C:?8 E96 >2A[ E96 <6J 2?5 2 E@C49]",
            MISS,
        ] {
            let result = crack(text);
            assert!(!result.success, "{text:?}: {result:?}");
            assert!(result.unencrypted_text.is_none(), "{text:?}: {result:?}");
        }
    }

    #[test]
    fn first_check_rejects_encodings() {
        // One token longer than MAX_TOKEN_LEN
        assert_eq!(
            count_tokens("TWVldCBtZSBhdCB0aGUgb2xkIGxpZ2h0aG91c2U="),
            None
        );
        // No letter and more than one token
        assert_eq!(count_tokens("104 101 108"), None);
        // No digit or symbol
        assert_eq!(count_tokens("hello world"), None);
        assert_eq!(count_tokens("h3ll0 w0rld"), Some(2));
        assert_eq!(count_tokens("flag{h3ll0_w0rld}"), Some(3));
        assert_eq!(count_tokens(" 1337 "), Some(1));
    }

    #[test]
    fn readings_try_every_combination_of_a_few_ambiguous_symbols() {
        assert_eq!(readings(0).collect::<Vec<_>>(), [0]);
        assert_eq!(readings(2).collect::<Vec<_>>(), [0, 1, 2, 3]);
        assert_eq!(readings(4).count(), 16);
        // More: all usual letters, or all others
        assert_eq!(readings(5).collect::<Vec<_>>(), [0, 0b11111]);
        assert_eq!(readings(24).collect::<Vec<_>>(), [0, (1 << 24) - 1]);
    }

    #[test]
    fn multi_character_symbols_are_longest_first() {
        for pair in MULTI_SYMBOLS.windows(2) {
            assert!(pair[0].0.len() >= pair[1].0.len(), "{pair:?}");
        }
        let mut units = [Unit::Copied(0); MAX_TOKEN_LEN];
        let len = read_units(b"|\\/|0|<", &mut units);
        assert_eq!(
            units[..len],
            [Unit::Letter(b'm'), Unit::Letter(b'o'), Unit::Letter(b'k')]
        );
    }

    #[test]
    fn dictionary_parses() {
        assert!(ENGLISH_WORDS.len() > 11_000);
        // Binary search needs both lists in order
        assert!(ENGLISH_WORDS.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(LEET_WORDS.windows(2).all(|pair| pair[0] < pair[1]));
        for word in ENGLISH_WORDS.iter().chain(LEET_WORDS) {
            assert!(word.bytes().all(|b| b.is_ascii_uppercase()), "{word:?}");
            assert!(is_word(word.as_bytes()), "{word:?}");
        }
        assert!(is_word(b"LIGHTHOUSE"));
        assert!(is_word(b"HELLO"));
        // Inflections of dictionary words
        assert!(is_word(b"TESTING"));
        assert!(is_word(b"JUMPS"));
        assert!(is_word(b"HAVING"));
        // LEET_WORDS
        assert!(is_word(b"LEET"));
        assert!(is_word(b"HAXOR"));
        assert!(!is_word(b"ZOZA"));
        assert!(!is_word(b"IEET"));
        assert!(!is_word(b"leet"));
    }

    #[test]
    fn leetspeak_handles_panic_if_empty_string() {
        let result = crack("");
        assert!(result.unencrypted_text.is_none());
    }

    #[test]
    fn leetspeak_handles_panic_if_emoji() {
        let result = crack("😂");
        assert!(result.unencrypted_text.is_none());
    }

    #[test]
    fn leetspeak_is_registered() {
        let decoders = crate::filtration_system::get_decoder_by_name("Leetspeak");
        assert_eq!(decoders.components.len(), 1);
        assert!(crate::decoders::DECODER_MAP.contains_key("Leetspeak"));
        let decoder = Decoder::<LeetspeakDecoder>::new();
        assert!(decoder.get_tags().contains(&"decoder"));
    }
}
