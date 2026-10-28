//! Find a message hidden in a null cipher (concealment cipher), such as an acrostic.
//!
//! A null cipher hides a message in an innocent-looking cover text: the reader keeps the
//! letters at agreed positions and ignores the rest, the "nulls". This decoder tries the
//! usual rules:
//!
//! * the first or last letter of each word (an acrostic),
//! * the first or last letter of each line, for texts of three or more lines,
//! * letter 2, 3, 4 or 5 of each word, skipping shorter words,
//! * every 2nd, 3rd, 4th or 5th letter of the text, from each possible first letter,
//! * the capital letters, unless the text is mostly capitals,
//! * letter 1, 2 or 3 after each punctuation mark (`, . ; : ! ?`), as in the Trevanion
//!   letter.
//!
//! The hidden message is returned as upper-case letters without spaces (`HELLOWORLD`), with
//! the rule that found it as the key. See <https://en.wikipedia.org/wiki/Null_cipher> and
//! <https://www.dcode.fr/acrostic-extraction>.
//!
//! The checker accepts `HELLO WORLD` but not `HELLOWORLD`, so each candidate is first split
//! into dictionary words, and the checker is shown the spaced form. Only candidates whose
//! words cover at least 90% of their letters, in pieces that are mostly longer than two
//! letters, get that far: ordinary English yields candidates such as `SET IT R T IT EST
//! HOLE`, which the checker would accept. With a crib (`--regex`) the crib decides instead,
//! so every candidate is checked as it is and spaced.
//!
//! Ciphey runs every decoder on every text the search expands, so text that can't be a
//! cover text (fewer than six words, or less than 70% letters, like Base64 and hex) is
//! turned away after one pass over at most its first 4,000 characters.
//!
//! An English cover text is itself accepted as plaintext before the search starts, so in
//! practice the full search only reaches this decoder with a crib, which turns the other
//! checkers off.

use super::crack_results::CrackResult;
use super::interface::{Crack, Decoder};
use crate::checkers::checker_result::CheckResult;
use crate::checkers::CheckerTypes;
use crate::config::get_config;
use crate::decoders::affine_decoder::BIGRAM_LOG_PROBS;
use log::trace;
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::hash::{BuildHasherDefault, Hasher};
use std::ops::Range;

/// Pre-check: the fewest whitespace-separated words (with at least one ASCII letter) that
/// a cover text needs. Encodings like Base64, hex and binary have one or two.
const MIN_WORDS: usize = 6;

/// Pre-check: ASCII letters must make up at least this many tenths of the characters that
/// aren't whitespace.
const MIN_LETTER_TENTHS: usize = 7;

/// Only the first this many characters are read. Hidden messages are short, and longer
/// texts are only ever the input itself.
const MAX_CHARS: usize = 4_000;

/// Candidates with fewer letters than this are dropped: short letter runs read as words
/// by chance.
const MIN_MESSAGE_LETTERS: usize = 8;

/// The line rules need at least this many lines that contain a letter.
const MIN_LINES: usize = 3;

/// The capital-letter rule needs at least this many capitals.
const MIN_CAPITALS: usize = 4;

/// The punctuation rules need at least this many punctuation marks.
const MIN_MARKS: usize = 4;

/// The punctuation marks that the punctuation rules count from.
const PUNCTUATION: &[u8] = b",.;:!?";

/// The longest dictionary word the segmentation looks for.
const MAX_WORD_LEN: usize = 12;

// A word of MAX_WORD_LEN letters, five bits each, has to fit in a lexicon key
const _: () = assert!(MAX_WORD_LEN * 5 <= u64::BITS as usize);

/// Segmentation score of a letter that isn't part of a dictionary word. A word of `n`
/// letters scores `n²`.
const UNCOVERED_PENALTY: i64 = 4;

/// A candidate is shown to the checker only if dictionary words cover at least this share
/// of its letters...
const MIN_COVERAGE: f32 = 0.9;

/// ...and at most this share of its pieces are one or two letters long.
const MAX_SHORT_SHARE: f32 = 0.5;

/// How many candidates, best first, are shown to the checker, and returned when none is
/// identified.
const MAX_CHECKED: usize = 3;

/// Rule: the first letter of each word.
const FIRST_OF_WORD: &str = "first letter of each word";
/// Rule: the last letter of each word.
const LAST_OF_WORD: &str = "last letter of each word";
/// Rule: the first letter of each line.
const FIRST_OF_LINE: &str = "first letter of each line";
/// Rule: the last letter of each line.
const LAST_OF_LINE: &str = "last letter of each line";
/// Rule: the capital letters.
const CAPITALS: &str = "capital letters";

/// Rules: letter `n` of each word with at least `n` letters, as `(n, rule)`.
const LETTER_OF_WORD_RULES: [(usize, &str); 4] = [
    (2, "letter 2 of each word"),
    (3, "letter 3 of each word"),
    (4, "letter 4 of each word"),
    (5, "letter 5 of each word"),
];

/// Rules: every `step`-th letter of the text, starting with letter `first` (1-based), as
/// `(step, first, rule)`.
const EVERY_NTH_RULES: [(usize, usize, &str); 14] = [
    (2, 1, "every 2nd letter from 1"),
    (2, 2, "every 2nd letter from 2"),
    (3, 1, "every 3rd letter from 1"),
    (3, 2, "every 3rd letter from 2"),
    (3, 3, "every 3rd letter from 3"),
    (4, 1, "every 4th letter from 1"),
    (4, 2, "every 4th letter from 2"),
    (4, 3, "every 4th letter from 3"),
    (4, 4, "every 4th letter from 4"),
    (5, 1, "every 5th letter from 1"),
    (5, 2, "every 5th letter from 2"),
    (5, 3, "every 5th letter from 3"),
    (5, 4, "every 5th letter from 4"),
    (5, 5, "every 5th letter from 5"),
];

/// Rules: the `n`-th letter after each punctuation mark, as `(n, rule)`.
const AFTER_PUNCTUATION_RULES: [(usize, &str); 3] = [
    (1, "letter 1 after each punctuation mark"),
    (2, "letter 2 after each punctuation mark"),
    (3, "letter 3 after each punctuation mark"),
];

/// Every upper-case word of up to [`MAX_WORD_LEN`] letters, and every beginning of one,
/// by [`key`], mapped to whether it is a whole word. The beginnings let the segmentation
/// stop extending a piece as soon as no word starts that way.
type Lexicon = HashMap<u64, bool, BuildHasherDefault<KeyHasher>>;

/// The [`Lexicon`] of `src/storage/ngrams/english_words.txt`, which is embedded in the
/// binary.
static LEXICON: Lazy<Lexicon> =
    Lazy::new(|| parse_lexicon(include_str!("../storage/ngrams/english_words.txt")));

/// The Null cipher decoder, call:
/// `let null_cipher_decoder = Decoder::<NullCipherDecoder>::new()` to create a new instance
/// And then call:
/// `result = null_cipher_decoder.crack(input, &checker)` to find a hidden message
/// The struct generated by new() comes from interface.rs
/// ```
/// use ciphey::decoders::null_cipher_decoder::NullCipherDecoder;
/// use ciphey::decoders::interface::{Crack, Decoder};
/// use ciphey::checkers::{athena::Athena, CheckerTypes, checker_type::{Check, Checker}};
///
/// let null_cipher_decoder = Decoder::<NullCipherDecoder>::new();
/// let athena_checker = Checker::<Athena>::new();
/// let checker = CheckerTypes::CheckAthena(athena_checker);
///
/// // An acrostic: the first letter of each word
/// let result = null_cipher_decoder.crack(
///     "Help Everyone Love Lots Of Wildlife: Observe Raptors, Lizards, Deer.",
///     &checker,
/// );
/// assert!(result.success);
/// assert_eq!(result.unencrypted_text.unwrap()[0], "HELLOWORLD");
/// assert_eq!(result.key.unwrap(), "first letter of each word");
/// ```
pub struct NullCipherDecoder;

impl Crack for Decoder<NullCipherDecoder> {
    fn new() -> Decoder<NullCipherDecoder> {
        Decoder {
            name: "Null cipher",
            description: "Null cipher / acrostic: a message hidden in the first or last letters of the words or lines of an innocent text, in every n-th letter, in the capital letters, or in the letters after punctuation. Only works end to end with a crib (-r), because an English cover text is accepted as plaintext before the search starts.",
            link: "https://en.wikipedia.org/wiki/Null_cipher",
            tags: vec!["null", "acrostic", "steganography", "classic"],
            // Rare outside puzzles, and without a crib the search seldom reaches it
            popularity: 0.3,
            phantom: std::marker::PhantomData,
        }
    }

    /// Extracts a candidate message with every rule and checks them. On success the
    /// message is the only element of `unencrypted_text`, upper-case letters without
    /// spaces, and `key` names the rule. Otherwise up to [`MAX_CHECKED`] candidates that
    /// read as dictionary words are returned unidentified, so the search can keep
    /// decoding them, or nothing if there are none.
    fn crack(&self, text: &str, checker: &CheckerTypes) -> CrackResult {
        trace!("Trying null cipher with text {:?}", text);
        crack_cover(self, text, checker, get_config().regex.is_some())
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

/// A candidate message and how well it splits into dictionary words.
struct Reading {
    /// The rule that extracted it.
    rule: &'static str,
    /// The extracted letters, upper case, without spaces.
    message: String,
    /// The letters split into dictionary words (and leftover letters) with spaces.
    spaced: String,
    /// Share of the letters inside dictionary words.
    coverage: f32,
    /// Share of the pieces that are one or two letters long.
    short: f32,
}

impl Reading {
    /// Whether the checker gets to see this candidate outside crib mode.
    fn reads_as_words(&self) -> bool {
        self.coverage >= MIN_COVERAGE && self.short <= MAX_SHORT_SHARE
    }
}

/// `crack` with the mode passed in. With `crib_mode` (a regex is set, so the checker only
/// runs the crib), every candidate is checked, as it is and then spaced. Otherwise only
/// the best [`MAX_CHECKED`] candidates that read as words are, spaced.
fn crack_cover(
    decoder: &Decoder<NullCipherDecoder>,
    text: &str,
    checker: &CheckerTypes,
    crib_mode: bool,
) -> CrackResult {
    let mut results = CrackResult::new(decoder, text.to_string());
    let Some(cover) = cover_text(text) else {
        trace!("Null cipher: not a cover text");
        return results;
    };

    let mut readings = Vec::new();
    for (rule, message) in candidates(cover) {
        if crib_mode {
            let check = checker.check(&message);
            if check.is_identified {
                return found(results, rule, message, &check);
            }
        }
        let (spaced, coverage, short) = segment(&message);
        if crib_mode && spaced != message {
            let check = checker.check(&spaced);
            if check.is_identified {
                return found(results, rule, message, &check);
            }
        }
        readings.push(Reading {
            rule,
            message,
            spaced,
            coverage,
            short,
        });
    }

    let best = rank(readings);
    if !crib_mode {
        for reading in &best {
            let check = checker.check(&reading.spaced);
            if check.is_identified {
                return found(results, reading.rule, reading.message.clone(), &check);
            }
        }
    }
    if best.is_empty() {
        trace!("Null cipher: no candidate reads as words");
        return results;
    }
    results.unencrypted_text = Some(best.into_iter().map(|reading| reading.message).collect());
    results
}

/// Records `message`, found with `rule` and identified by `check`, in `results`.
fn found(
    mut results: CrackResult,
    rule: &'static str,
    message: String,
    check: &CheckResult,
) -> CrackResult {
    trace!("Null cipher: found {} with the {}", message, rule);
    results.unencrypted_text = Some(vec![message]);
    results.update_checker(check);
    results.key = Some(rule.to_string());
    results
}

/// The first [`MAX_CHARS`] characters of `text`, if they look like a cover text: at least
/// [`MIN_WORDS`] whitespace-separated words with an ASCII letter in them, and ASCII
/// letters making up at least [`MIN_LETTER_TENTHS`] tenths of the characters that aren't
/// whitespace.
fn cover_text(text: &str) -> Option<&str> {
    let text = match text.char_indices().nth(MAX_CHARS) {
        Some((end, _)) => &text[..end],
        None => text,
    };
    let mut words = 0usize;
    let mut word_has_letter = false;
    let mut letters = 0usize;
    let mut non_whitespace = 0usize;
    for c in text.chars() {
        if c.is_whitespace() {
            words += usize::from(word_has_letter);
            word_has_letter = false;
        } else {
            non_whitespace += 1;
            if c.is_ascii_alphabetic() {
                letters += 1;
                word_has_letter = true;
            }
        }
    }
    words += usize::from(word_has_letter);
    if words < MIN_WORDS || letters * 10 < non_whitespace * MIN_LETTER_TENTHS {
        return None;
    }
    Some(text)
}

/// Every candidate message in `text`, as `(rule, letters)`: the [`extractions`] with at
/// least [`MIN_MESSAGE_LETTERS`] letters but no more than half of the text's (rounded
/// up), in the order of the rules, and a message that an earlier rule already found kept
/// under the earlier rule's name only.
///
/// A message hides among the letters around it, so a rule that keeps most of them finds
/// the text, not a message. Without this, letters spaced out like `M e e t   m e` would
/// be read as an acrostic of one-letter words: Repeating-key XOR turns UTF-16 text into
/// that.
fn candidates(text: &str) -> Vec<(&'static str, String)> {
    let max_letters = text
        .bytes()
        .filter(u8::is_ascii_alphabetic)
        .count()
        .div_ceil(2);
    let mut out: Vec<(&'static str, String)> = Vec::new();
    for (rule, message) in extractions(text) {
        if (MIN_MESSAGE_LETTERS..=max_letters).contains(&message.len())
            && out.iter().all(|(_, other)| *other != message)
        {
            out.push((rule, message));
        }
    }
    out
}

/// What each rule that applies to `text` extracts from it, as `(rule, letters)`, in the
/// order of the rules above. Letters are ASCII and upper-cased; anything else, non-ASCII
/// letters included, is skipped. The line rules need [`MIN_LINES`] lines with a letter,
/// the capital-letter rule [`MIN_CAPITALS`] capitals that are less than half of the
/// letters, and the punctuation rules [`MIN_MARKS`] punctuation marks.
fn extractions(text: &str) -> Vec<(&'static str, String)> {
    // The ASCII letters of the text, upper-cased, the range of them in each word, and
    // the capitals among them
    let mut letters: Vec<u8> = Vec::with_capacity(text.len());
    let mut words: Vec<Range<usize>> = Vec::new();
    let mut capitals: Vec<u8> = Vec::new();
    for word in text.split_whitespace() {
        let start = letters.len();
        for byte in word.bytes() {
            if byte.is_ascii_uppercase() {
                letters.push(byte);
                capitals.push(byte);
            } else if byte.is_ascii_lowercase() {
                letters.push(byte.to_ascii_uppercase());
            }
        }
        if letters.len() > start {
            words.push(start..letters.len());
        }
    }

    let mut out = Vec::with_capacity(26);
    out.push((
        FIRST_OF_WORD,
        text_of(words.iter().map(|word| letters[word.start])),
    ));
    out.push((
        LAST_OF_WORD,
        text_of(words.iter().map(|word| letters[word.end - 1])),
    ));

    // The first and last letter of each line that has a letter
    let lines: Vec<(u8, u8)> = text
        .lines()
        .filter_map(|line| {
            let mut line_letters = line.bytes().filter(u8::is_ascii_alphabetic);
            let first = line_letters.next()?;
            let last = line_letters.next_back().unwrap_or(first);
            Some((first.to_ascii_uppercase(), last.to_ascii_uppercase()))
        })
        .collect();
    if lines.len() >= MIN_LINES {
        out.push((
            FIRST_OF_LINE,
            text_of(lines.iter().map(|&(first, _)| first)),
        ));
        out.push((LAST_OF_LINE, text_of(lines.iter().map(|&(_, last)| last))));
    }

    for (n, rule) in LETTER_OF_WORD_RULES {
        out.push((
            rule,
            text_of(
                words
                    .iter()
                    .filter(|word| word.len() >= n)
                    .map(|word| letters[word.start + n - 1]),
            ),
        ));
    }

    for (step, first, rule) in EVERY_NTH_RULES {
        out.push((
            rule,
            text_of(letters.iter().copied().skip(first - 1).step_by(step)),
        ));
    }

    // All-caps text, like a telegram, has no message in its capitals
    if capitals.len() >= MIN_CAPITALS && capitals.len() * 2 < letters.len() {
        out.push((CAPITALS, text_of(capitals.iter().copied())));
    }

    // How many letters come before each punctuation mark. Marks with no letter between
    // them, like `...` or `?!`, count once.
    let mut marks: Vec<usize> = Vec::new();
    let mut letters_so_far = 0usize;
    for byte in text.bytes() {
        if byte.is_ascii_alphabetic() {
            letters_so_far += 1;
        } else if PUNCTUATION.contains(&byte) && marks.last() != Some(&letters_so_far) {
            marks.push(letters_so_far);
        }
    }
    if marks.len() >= MIN_MARKS {
        for (n, rule) in AFTER_PUNCTUATION_RULES {
            out.push((
                rule,
                text_of(
                    marks
                        .iter()
                        .filter_map(|&before| letters.get(before + n - 1).copied()),
                ),
            ));
        }
    }

    out
}

/// The ASCII letters `letters` as a string.
fn text_of(letters: impl Iterator<Item = u8>) -> String {
    letters.map(char::from).collect()
}

/// Splits `letters` (upper-case ASCII) into dictionary words, as `(spaced, coverage,
/// short)`: the pieces joined with spaces, the share of the letters inside dictionary
/// words, and the share of the pieces that are one or two letters long.
///
/// The split maximises the sum of the squared lengths of its words, minus
/// [`UNCOVERED_PENALTY`] for each letter left out of every word, so it prefers a few long
/// words to many short ones. Words are at most [`MAX_WORD_LEN`] letters. Text that isn't
/// ASCII has no dictionary words.
fn segment(letters: &str) -> (String, f32, f32) {
    if letters.is_empty() || !letters.is_ascii() {
        return (letters.to_string(), 0.0, 1.0);
    }
    let lexicon = &*LEXICON;
    let bytes = letters.as_bytes();
    let len = bytes.len();
    // best[end]: the best score of a split of letters[..end], whose last piece starts
    // at back[end].0 and is a dictionary word if back[end].1
    let mut best = vec![i64::MIN; len + 1];
    let mut back = vec![(0usize, false); len + 1];
    best[0] = 0;
    for start in 0..len {
        // Every position can be reached, one leftover letter at a time
        let base = best[start];
        let mut letter_is_word = false;
        // The key of letters[start..end], one letter longer each time
        let mut piece_key = 0;
        for end in start + 1..=len.min(start + MAX_WORD_LEN) {
            let Some(next_key) = append_letter(piece_key, bytes[end - 1]) else {
                break;
            };
            piece_key = next_key;
            // No word starts this way: longer pieces from `start` aren't words either
            let Some(&is_word) = lexicon.get(&piece_key) else {
                break;
            };
            if is_word {
                letter_is_word |= end == start + 1;
                let piece = (end - start) as i64;
                let score = base + piece * piece;
                if score > best[end] {
                    best[end] = score;
                    back[end] = (start, true);
                }
            }
        }
        if !letter_is_word {
            let score = base - UNCOVERED_PENALTY;
            if score > best[start + 1] {
                best[start + 1] = score;
                back[start + 1] = (start, false);
            }
        }
    }

    let mut pieces = Vec::new();
    let mut end = len;
    while end > 0 {
        let (start, is_word) = back[end];
        pieces.push((start..end, is_word));
        end = start;
    }
    pieces.reverse();

    let covered: usize = pieces
        .iter()
        .filter(|(_, is_word)| *is_word)
        .map(|(piece, _)| piece.len())
        .sum();
    let short = pieces.iter().filter(|(piece, _)| piece.len() <= 2).count();
    let mut spaced = String::with_capacity(len + pieces.len());
    for (i, (piece, _)) in pieces.iter().enumerate() {
        if i > 0 {
            spaced.push(' ');
        }
        spaced.push_str(&letters[piece.clone()]);
    }
    (
        spaced,
        covered as f32 / len as f32,
        short as f32 / pieces.len() as f32,
    )
}

/// The best [`MAX_CHECKED`] readings that read as words (see [`Reading::reads_as_words`]):
/// highest coverage first, then fewest short pieces, then the most English-looking letter
/// pairs. Ties keep the order of the rules.
fn rank(readings: Vec<Reading>) -> Vec<Reading> {
    let mut ranked: Vec<(f32, Reading)> = readings
        .into_iter()
        .filter(Reading::reads_as_words)
        .map(|reading| (mean_bigram_log_prob(&reading.message), reading))
        .collect();
    // A stable sort, so the ranking is deterministic
    ranked.sort_by(|(left_pairs, left), (right_pairs, right)| {
        right
            .coverage
            .total_cmp(&left.coverage)
            .then(left.short.total_cmp(&right.short))
            .then(right_pairs.total_cmp(left_pairs))
    });
    ranked.truncate(MAX_CHECKED);
    ranked.into_iter().map(|(_, reading)| reading).collect()
}

/// The mean English `ln P` of the pairs of adjacent letters in `message`, from the table
/// the Affine decoder uses. Higher is more English-looking.
fn mean_bigram_log_prob(message: &str) -> f32 {
    let log_probs = &*BIGRAM_LOG_PROBS;
    let (total, pairs) = message
        .as_bytes()
        .windows(2)
        .filter_map(|pair| Some((letter_index(pair[0])?, letter_index(pair[1])?)))
        .fold((0.0f32, 0usize), |(total, pairs), (first, second)| {
            (total + log_probs[first][second], pairs + 1)
        });
    if pairs == 0 {
        return f32::NEG_INFINITY;
    }
    total / pairs as f32
}

/// The position in the alphabet (0..26) of an ASCII letter, in either case.
fn letter_index(byte: u8) -> Option<usize> {
    byte.is_ascii_alphabetic()
        .then(|| usize::from(byte.to_ascii_uppercase() - b'A'))
}

/// Reads one upper-case word per line into a [`Lexicon`], skipping `#` comments, blank
/// lines, and words longer than [`MAX_WORD_LEN`] or with anything but the letters A to Z.
fn parse_lexicon(source: &str) -> Lexicon {
    let mut lexicon = Lexicon::default();
    for word in source.lines().map(str::trim) {
        if word.is_empty() || key(word).is_none() {
            continue;
        }
        // Only A to Z, so every byte is a character boundary
        for end in 1..=word.len() {
            if let Some(beginning) = key(&word[..end]) {
                *lexicon.entry(beginning).or_insert(false) |= end == word.len();
            }
        }
    }
    lexicon
}

/// The [`Lexicon`] key of `word`: its letters A to Z as 1 to 26, five bits each, the
/// first letter highest, so every word of up to [`MAX_WORD_LEN`] letters has its own
/// key. `None` if `word` has anything but the letters A to Z, or too many of them.
fn key(word: &str) -> Option<u64> {
    if word.len() > MAX_WORD_LEN {
        return None;
    }
    word.bytes().try_fold(0, append_letter)
}

/// The key of a word with `letter` appended, given the key of the word (0 for no
/// letters), or `None` if `letter` isn't one of A to Z.
fn append_letter(key: u64, letter: u8) -> Option<u64> {
    letter
        .is_ascii_uppercase()
        .then(|| key << 5 | u64::from(letter - b'A' + 1))
}

/// Hashes [`Lexicon`] keys with the splitmix64 finaliser: much faster than the default
/// SipHash, which matters as the segmentation looks up every piece it tries. The keys
/// come from a fixed word list, so there's no flooding to defend against.
#[derive(Default)]
struct KeyHasher(u64);

impl Hasher for KeyHasher {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.write_u64(self.0 ^ u64::from(byte));
        }
    }

    fn write_u64(&mut self, value: u64) {
        let mut mixed = value.wrapping_add(0x9e37_79b9_7f4a_7c15);
        mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        self.0 = mixed ^ (mixed >> 31);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkers::{
        athena::Athena,
        checker_type::{Check, Checker},
        lemmeknow_checker::LemmeKnow,
        CheckerTypes,
    };
    use crate::decoders::interface::{Crack, Decoder};

    // helper for tests
    fn get_athena_checker() -> CheckerTypes {
        let athena_checker = Checker::<Athena>::new();
        CheckerTypes::CheckAthena(athena_checker)
    }

    /// The example from #982, an acrostic written by hand.
    const ISSUE_EXAMPLE: &str =
        "Help Everyone Love Lots Of Wildlife: Observe Raptors, Lizards, Deer.";

    /// The German WWI telegram from <https://en.wikipedia.org/wiki/Null_cipher>: the first
    /// letters of its words spell "Pershing sails from NY June 1" (`PERSHINGSAILSFROMNYJUNEI`).
    const WWI_TELEGRAM: &str = "PRESIDENT'S EMBARGO RULING SHOULD HAVE IMMEDIATE NOTICE. \
        GRAVE SITUATION AFFECTING INTERNATIONAL LAW. STATEMENT FORESHADOWS RUIN OF MANY \
        NEUTRALS. YELLOW JOURNALS UNIFYING NATIONAL EXCITEMENT IMMENSELY.";

    /// Sir John Trevanion's letter from <https://en.wikipedia.org/wiki/Null_cipher>: the
    /// third letter after each punctuation mark spells "Panel at east end of chapel
    /// slides".
    const TREVANION_LETTER: &str = "WORTHIE SIR JOHN, HOPE, THAT IS YE BESTE COMFORT OF \
        YE AFFLICTED, CANNOT MUCH, I FEAR ME, HELP YOU NOW. THAT I WOULD SAY TO YOU, IS \
        THIS ONLY: IF EVER I MAY BE ABLE TO REQUITE THAT I DO OWE YOU, STAND NOT UPON \
        ASKING ME. TIS NOT MUCH THAT I CAN DO; BUT WHAT I CAN DO, BEE YE VERY SURE I WILL. \
        I KNOW THAT, IF DETHE COMES, IF ORDINARY MEN FEAR IT, IT FRIGHTS NOT YOU, \
        ACCOUNTING IT FOR A HIGH HONOUR, TO HAVE SUCH A REWARDE OF YOUR LOYALTY. PRAY YET \
        YOU MAY BE SPARED THIS SOE BITTER, CUP. I FEAR NOT THAT YOU WILL GRUDGE ANY \
        SUFFERINGS; ONLY IF BIE SUBMISSIONS YOU CAN TURN THEM AWAY, TIS THE PART OF A WISE \
        MAN. TELL ME, AN IF YOU CAN, TO DO FOR YOU ANYTHINGE THAT YOU WOLDE HAVE DONE. THE \
        GENERAL GOES BACK ON WEDNESDAY. RESTINGE YOUR SERVANT TO COMMAND.";

    /// The gibberish string that every decoder's bench must reject
    /// (`miss` in `benches/data/decoders.toml`).
    const BENCH_MISS: &str =
        "T00 l3= ox+#G WKyV pajU6j qxH@ %B4+a 5Pn^ 7p_v1q 9sLvu *+36i R5rL&3 mVJZI iO0 Ut8_m COTV";

    /// Asserts that `crack` finds `message` in `cover` with `rule`.
    fn assert_found(cover: &str, message: &str, rule: &str) {
        let decoder = Decoder::<NullCipherDecoder>::new();
        let result = decoder.crack(cover, &get_athena_checker());
        assert!(result.success, "not identified: {result:?}");
        assert_eq!(result.unencrypted_text.unwrap(), vec![message.to_string()]);
        assert_eq!(result.key.as_deref(), Some(rule));
    }

    /// Asserts that `crack` returns nothing for `text`.
    fn assert_nothing(text: &str) {
        let decoder = Decoder::<NullCipherDecoder>::new();
        let result = decoder.crack(text, &get_athena_checker());
        assert!(!result.success, "{text:?}: {result:?}");
        assert!(
            result.unencrypted_text.is_none(),
            "{text:?}: {:?}",
            result.unencrypted_text
        );
    }

    /// What `extractions` finds in `text`, by rule.
    fn extractions_by_rule(text: &str) -> HashMap<&'static str, String> {
        extractions(text).into_iter().collect()
    }

    // The covers below are the test vectors of the plan on #982: each extraction was
    // checked with a Python 3.9 script, and the two Wikipedia examples have their
    // published plaintext.

    #[test]
    fn first_letter_of_each_word() {
        assert_found(ISSUE_EXAMPLE, "HELLOWORLD", "first letter of each word");
    }

    #[test]
    fn letter_3_after_each_punctuation_mark() {
        // The checker sees PANEL ATE AS TEND OF CHAPEL SLIDE S
        assert_found(
            TREVANION_LETTER,
            "PANELATEASTENDOFCHAPELSLIDES",
            "letter 3 after each punctuation mark",
        );
    }

    #[test]
    fn last_letter_of_each_word() {
        assert_found(
            "Calm, free bee cat: data art, good idea, how sudden.",
            "MEETATDAWN",
            "last letter of each word",
        );
    }

    #[test]
    fn first_letter_of_each_line() {
        assert_found(
            "Morning light is on the hill,\nEvery path is quiet still,\n\
             Each small bird begins to sing,\nTime moves slow in early spring.\n\
             All the fields are wet with dew,\nTrees stand dark against the blue,\n\
             Down the lane a cart goes by,\nAnd the smoke drifts to the sky.\n\
             We will wait until the sun\nNames the day and night is done.",
            "MEETATDAWN",
            "first letter of each line",
        );
    }

    #[test]
    fn capital_letters() {
        // The first letters give THIELATLATOWORLDF, which doesn't read as words
        assert_found(
            "the Hill is Everywhere, Look at the Lake and the Ocean; We Only Run Late, \
             Dear friend",
            "HELLOWORLD",
            "capital letters",
        );
    }

    #[test]
    fn letter_2_of_each_word() {
        // Every 3rd letter from 2 gives the same letters; the earlier rule keeps them
        assert_found(
            "aHb cEd eLf gLh iOj kWl mOn oRp qLr sDt",
            "HELLOWORLD",
            "letter 2 of each word",
        );
    }

    #[test]
    fn every_3rd_letter() {
        // The first letters give HEIPWRTD
        assert_found(
            "Hat ebbl idla powl waro rero tlot dog",
            "HELLOWORLD",
            "every 3rd letter from 1",
        );
    }

    #[test]
    fn wwi_telegram_needs_a_crib() {
        // PERSHING and N Y aren't dictionary words, so outside crib mode the checker
        // doesn't see it. tests/null_cipher_crib.rs finds it with a crib.
        let cover = cover_text(WWI_TELEGRAM).expect("the telegram is a cover text");
        assert!(candidates(cover).contains(&(
            "first letter of each word",
            "PERSHINGSAILSFROMNYJUNEI".to_string()
        )));
        let (spaced, coverage, short) = segment("PERSHINGSAILSFROMNYJUNEI");
        assert_eq!(spaced, "PER S H IN G SAILS FROM N Y JUNE I");
        assert!(coverage < MIN_COVERAGE, "coverage {coverage}");
        assert!(short > MAX_SHORT_SHARE, "short {short}");
        assert_nothing(WWI_TELEGRAM);
    }

    #[test]
    fn segments_hello_world() {
        assert_eq!(segment("HELLOWORLD"), ("HELLO WORLD".to_string(), 1.0, 0.0));
    }

    #[test]
    fn segments_with_leftover_letters() {
        // No dictionary word starts with QX or XM, so Q and X are left over
        let (spaced, coverage, short) = segment("QXMEETATDAWN");
        assert_eq!(spaced, "Q X MEET AT DAWN");
        assert_eq!(coverage, 10.0 / 12.0);
        assert_eq!(short, 3.0 / 5.0);
    }

    #[test]
    fn segments_nothing_without_ascii_letters() {
        assert_eq!(segment(""), (String::new(), 0.0, 1.0));
        assert_eq!(segment("É"), ("É".to_string(), 0.0, 1.0));
    }

    #[test]
    fn every_rule_extracts_its_letters() {
        let found = extractions_by_rule("Ab, cd. Ef; gh: ij! kl? mn\nop qr\nst uv\nwx yz");
        assert_eq!(found["first letter of each word"], "ACEGIKMOQSUWY");
        assert_eq!(found["last letter of each word"], "BDFHJLNPRTVXZ");
        assert_eq!(found["first letter of each line"], "AOSW");
        assert_eq!(found["last letter of each line"], "NRVZ");
        assert_eq!(found["letter 2 of each word"], "BDFHJLNPRTVXZ");
        // No word has 3 letters
        assert_eq!(found["letter 3 of each word"], "");
        assert_eq!(found["every 2nd letter from 1"], "ACEGIKMOQSUWY");
        assert_eq!(found["every 2nd letter from 2"], "BDFHJLNPRTVXZ");
        assert_eq!(found["every 3rd letter from 3"], "CFILORUX");
        assert_eq!(found["every 5th letter from 3"], "CHMRW");
        assert_eq!(found["letter 1 after each punctuation mark"], "CEGIKM");
        assert_eq!(found["letter 2 after each punctuation mark"], "DFHJLN");
        assert_eq!(found["letter 3 after each punctuation mark"], "EGIKMO");
        // Two capitals are too few
        assert!(!found.contains_key("capital letters"));
        assert_eq!(found.len(), 25);
    }

    #[test]
    fn rules_that_dont_apply_are_skipped() {
        // One line, no punctuation, all capitals
        let found = extractions_by_rule("ONE TWO THREE FOUR FIVE SIX SEVEN EIGHT");
        assert_eq!(found.len(), 2 + 4 + 14);
        for rule in [FIRST_OF_LINE, LAST_OF_LINE, CAPITALS] {
            assert!(!found.contains_key(rule), "{rule}");
        }
        assert!(!found.keys().any(|rule| rule.contains("punctuation")));
        // Three lines, four capitals that are under half of the letters, and four marks
        let found = extractions_by_rule("The Cat, sat.\nOn the mat;\nWith a hat!");
        assert_eq!(found[FIRST_OF_LINE], "TOW");
        assert_eq!(found[LAST_OF_LINE], "TTT");
        assert_eq!(found[CAPITALS], "TCOW");
        assert_eq!(found["letter 1 after each punctuation mark"], "SOW");
    }

    #[test]
    fn runs_of_punctuation_count_once() {
        let found = extractions_by_rule("one... two?! three; four: five");
        assert_eq!(found["letter 1 after each punctuation mark"], "TTFF");
    }

    #[test]
    fn spaced_out_letters_are_not_an_acrostic() {
        // What Repeating-key XOR makes of UTF-16LE text in the utf16le_base64 search
        // bench: every character followed by a space. Each "word" is one letter, so the
        // first letters are the whole text, which reads as words.
        let spaced_out: String = "Meet me at the old lighthouse after midnight and bring \
             the map, the key and a torch."
            .chars()
            .flat_map(|c| [c, ' '])
            .collect();
        assert!(extractions(&spaced_out).contains(&(
            FIRST_OF_WORD,
            "MEETMEATTHEOLDLIGHTHOUSEAFTERMIDNIGHTANDBRINGTHEMAPTHEKEYANDATORCH".to_string()
        )));
        assert!(candidates(&spaced_out)
            .iter()
            .all(|(rule, _)| *rule != FIRST_OF_WORD && *rule != LAST_OF_WORD));
        assert_nothing(&spaced_out);
        // Half of the letters, rounded up, is still allowed: every 2nd letter of 55
        let found = candidates("abcdefghi jklmnopqr stuvwxyza bcdefghij klmnopqrs tuvwxyzabc");
        assert!(found.contains(&(
            "every 2nd letter from 1",
            "ACEGIKMOQSUWYACEGIKMOQSUWYAC".to_string()
        )));
    }

    #[test]
    fn short_and_repeated_candidates_are_dropped() {
        // Title Case: the capitals are the first letters, which keep the earlier name
        let found = candidates("Help Everyone Love Lots Of Wildlife Or Run Late Daily");
        assert_eq!(found[0], (FIRST_OF_WORD, "HELLOWORLD".to_string()));
        assert!(found.iter().all(|(rule, _)| *rule != CAPITALS));
        // 7 words give 7 first letters, one too few
        let found = candidates("one two three four five six seven");
        assert!(found.iter().all(|(rule, _)| *rule != FIRST_OF_WORD));
        assert!(found
            .iter()
            .all(|(_, message)| message.len() >= MIN_MESSAGE_LETTERS));
        // Every candidate is listed once
        for (i, (_, message)) in found.iter().enumerate() {
            assert!(found[..i].iter().all(|(_, other)| other != message));
        }
    }

    #[test]
    fn all_caps_text_has_no_capital_letters_rule() {
        let cover = cover_text(WWI_TELEGRAM).unwrap();
        assert!(!extractions_by_rule(cover).contains_key(CAPITALS));
    }

    #[test]
    fn non_ascii_letters_are_skipped() {
        let found =
            candidates("éclair Help Everyone Love Lots Of Wildlife Observe Raptors Lizards Deer");
        // The ASCII letters of "éclair" are CLAIR
        assert_eq!(found[0], (FIRST_OF_WORD, "CHELLOWORLD".to_string()));
    }

    #[test]
    fn pre_checks() {
        assert_eq!(cover_text(ISSUE_EXAMPLE), Some(ISSUE_EXAMPLE));
        // Five words
        assert_eq!(cover_text("Help Everyone Love Lots Of"), None);
        // Words without letters don't count
        assert_eq!(cover_text("Help Everyone Love Lots Of 12 34 56"), None);
        // The bench's miss string has 16 words, but only 63% letters
        assert_eq!(cover_text(BENCH_MISS), None);
        // Long text is cut to its first MAX_CHARS characters...
        let long = "Help Everyone Love Lots Of Wildlife ".repeat(200);
        assert_eq!(cover_text(&long).unwrap().chars().count(), MAX_CHARS);
        // ...and only they are checked
        let long = "é ".repeat(MAX_CHARS) + ISSUE_EXAMPLE;
        assert_eq!(cover_text(&long), None);
    }

    #[test]
    fn returns_nothing_for_other_input() {
        for text in [
            "",
            "😀",
            "hello world",
            "12345 67890",
            "aGVsbG8gd29ybGQ=",
            "48656c6c6f20576f726c64",
            "01001000 01100101 01101100 01101100 01101111 00100000 01010111",
            BENCH_MISS,
        ] {
            assert_nothing(text);
        }
    }

    #[test]
    fn returns_nothing_for_english_without_a_message() {
        for text in [
            "The quick brown fox jumps over the lazy dog while the cat sleeps on the warm \
             windowsill.",
            // ROT13 of it
            "Gur dhvpx oebja sbk whzcf bire gur ynml qbt juvyr gur png fyrrcf ba gur jnez \
             jvaqbjfvyy.",
            "It was the best of times, it was the worst of times, it was the age of wisdom, \
             it was the age of foolishness.",
        ] {
            assert_nothing(text);
        }
    }

    #[test]
    fn unidentified_candidates_are_returned_for_the_search() {
        // LemmeKnow doesn't identify HELLO WORLD, so the candidate that reads as words is
        // returned unidentified, for the search to keep decoding
        let decoder = Decoder::<NullCipherDecoder>::new();
        let lemmeknow = CheckerTypes::CheckLemmeKnow(Checker::<LemmeKnow>::new());
        let result = decoder.crack(ISSUE_EXAMPLE, &lemmeknow);
        assert!(!result.success);
        assert_eq!(
            result.unencrypted_text,
            Some(vec!["HELLOWORLD".to_string()])
        );
        assert_eq!(result.key, None);
    }

    #[test]
    fn crib_mode_checks_every_candidate_spaced() {
        // In crib mode the checker runs only the crib, so the thresholds don't apply. The
        // global config of the unit tests has no crib, so Athena, which accepts the
        // telegram's spaced message, stands in for one here.
        let decoder = Decoder::<NullCipherDecoder>::new();
        let checker = get_athena_checker();
        assert!(!crack_cover(&decoder, WWI_TELEGRAM, &checker, false).success);
        let result = crack_cover(&decoder, WWI_TELEGRAM, &checker, true);
        assert!(result.success);
        assert_eq!(
            result.unencrypted_text,
            Some(vec!["PERSHINGSAILSFROMNYJUNEI".to_string()])
        );
        assert_eq!(result.key.as_deref(), Some("first letter of each word"));
    }

    #[test]
    fn messages_of_short_words_dont_reach_the_checker() {
        // By design: two of the three pieces are short, which ordinary English produces
        // by chance too
        let (spaced, coverage, short) = segment("DOITATONE");
        assert_eq!(spaced, "DO IT ATONE");
        assert_eq!(coverage, 1.0);
        assert!(short > MAX_SHORT_SHARE, "short {short}");
    }

    #[test]
    fn ranking_drops_readings_that_dont_read_as_words() {
        let reading = |rule, message: &str, coverage, short| Reading {
            rule,
            message: message.to_string(),
            spaced: message.to_string(),
            coverage,
            short,
        };
        let ranked = rank(vec![
            reading("too few words", "PERSHINGSAILS", 0.89, 0.0),
            reading("too many short pieces", "ATONEDOIT", 1.0, 0.51),
            reading("reads as words", "HELLOWORLD", 0.9, 0.5),
        ]);
        let rules: Vec<&str> = ranked.iter().map(|reading| reading.rule).collect();
        assert_eq!(rules, ["reads as words"]);
    }

    #[test]
    fn ranking_prefers_coverage_then_fewer_short_pieces_then_english_pairs() {
        let reading = |rule, message: &str, coverage, short| Reading {
            rule,
            message: message.to_string(),
            spaced: message.to_string(),
            coverage,
            short,
        };
        let ranked = rank(vec![
            reading("a", "QZQZQZQZ", 0.95, 0.1),
            reading("b", "THETHETHE", 0.95, 0.1),
            reading("c", "HELLOWORLD", 0.95, 0.2),
            reading("d", "MEETATDAWN", 1.0, 0.3),
            reading("e", "ATTACKATDAWN", 0.92, 0.0),
        ]);
        let rules: Vec<&str> = ranked.iter().map(|reading| reading.rule).collect();
        assert_eq!(rules, ["d", "b", "a"]);
    }

    #[test]
    fn mean_bigram_log_prob_ranks_english_higher() {
        assert!(mean_bigram_log_prob("THETHE") > mean_bigram_log_prob("QZQZQZ"));
        assert_eq!(mean_bigram_log_prob("A"), f32::NEG_INFINITY);
    }

    #[test]
    fn decoder_metadata() {
        let decoder = Decoder::<NullCipherDecoder>::new();
        assert_eq!(decoder.get_name(), "Null cipher");
        assert_eq!(decoder.get_popularity(), 0.3);
        assert_eq!(
            decoder.get_link(),
            "https://en.wikipedia.org/wiki/Null_cipher"
        );
        // Several rules, ranked: not a one-to-one decoder, and not reciprocal
        let tags = decoder.get_tags();
        assert!(!tags.contains(&"decoder"));
        assert!(!tags.contains(&"reciprocal"));
        assert!(tags.contains(&"acrostic"));
    }

    #[test]
    fn registered_once() {
        let decoders = crate::filtration_system::get_decoder_by_name("Null cipher");
        assert_eq!(decoders.components.len(), 1);
        assert_eq!(decoders.components[0].get_name(), "Null cipher");
        let decoder = crate::decoders::DECODER_MAP
            .get("Null cipher")
            .expect("Null cipher is in DECODER_MAP")
            .get::<()>();
        assert_eq!(decoder.get_name(), "Null cipher");
    }

    /// Looks `word` up in [`LEXICON`].
    fn lookup(word: &str) -> Option<bool> {
        LEXICON.get(&key(word).unwrap()).copied()
    }

    #[test]
    fn lexicon_has_words_and_their_beginnings() {
        assert_eq!(lookup("HELLO"), Some(true));
        assert_eq!(lookup("HELL"), Some(true));
        assert_eq!(lookup("MIDNIG"), Some(false));
        assert_eq!(lookup("A"), Some(true));
        assert_eq!(lookup("I"), Some(true));
        assert_eq!(lookup("QX"), None);
        // 12 letters is the longest
        assert_eq!(lookup("CIRCUMSTANCE"), Some(true));
        assert_eq!(key("CIRCUMSTANCES"), None);
        // 11,619 words of up to 12 letters, and 30,455 words and beginnings of words
        assert_eq!(LEXICON.values().filter(|&&is_word| is_word).count(), 11_619);
        assert_eq!(LEXICON.len(), 30_455);
    }

    #[test]
    fn keys_tell_words_apart() {
        assert_eq!(key(""), Some(0));
        assert_eq!(key("A"), Some(1));
        assert_eq!(key("AA"), Some(33));
        assert_eq!(key("Z"), Some(26));
        assert_eq!(key("ZZZZZZZZZZZZ"), Some((1 << 60) / 31 * 26));
        assert_eq!(key("a"), None);
        assert_eq!(key("É"), None);
        assert_eq!(append_letter(key("HELL").unwrap(), b'O'), key("HELLO"));
    }

    #[test]
    fn parse_lexicon_skips_comments_and_long_words() {
        let lexicon = parse_lexicon("# A comment\nAT\n\nATE\nSESQUIPEDALIAN\nlower\nA-Z\n");
        let mut entries: Vec<(u64, bool)> = lexicon.into_iter().collect();
        entries.sort_unstable();
        let expected = [("A", false), ("AT", true), ("ATE", true)]
            .map(|(word, is_word)| (key(word).unwrap(), is_word));
        assert_eq!(entries, expected);
    }
}
