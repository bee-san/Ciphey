//! Decode T9 predictive text, where every letter is written as the phone keypad key it is
//! on, pressed once: `43556 96753` is `hello world`.
//!
//! The keys are those of ITU-T E.161: `2` is ABC, `3` DEF, `4` GHI, `5` JKL, `6` MNO,
//! `7` PQRS, `8` TUV and `9` WXYZ. See <https://en.wikipedia.org/wiki/T9_(predictive_text)>
//! and <https://www.dcode.fr/t9-cipher>. Words are separated by whitespace or punctuation,
//! or by `0` and `1`, which dCode's encoder writes for a space and for punctuation.
//!
//! Words can share keys (`2665` is BOOK, COOL and COOK), so every word is looked up in an
//! English dictionary: `src/storage/ngrams/english_words.txt`, plus `EXTRA_WORDS`, modern
//! words that the 19th-century novels it was counted from don't have. The words of a key are
//! ranked by how often their quadgrams occur in English (`english_quadgrams.txt`), and the
//! 5 most likely sentences are shown to the checker in turn. A word that isn't in the
//! dictionary keeps its digits (`we are the 242674667`).
//!
//! Each word is ranked on its own, so the most likely sentence isn't always the right one:
//! `6338 63 28 3296` reads as `meet of at dawn` first, because OF is more common than ME.
//! That is a sentence of real words too, and the checker accepts it.
//!
//! Cheap checks reject other text first, in this order, before the dictionary is loaded:
//! 1. The text starts with a digit and has nothing but digits, whitespace and `-,;:./|*#`.
//! 2. It has at least 3 digits from 2 to 9, the digits that are letters.
//! 3. Not every word is one digit repeated, like Multi-tap's `44 33 555`.
//! 4. At most one word in four may be missing from the dictionary. Words of 1 or 2 digits
//!    are checked first, against a table built at compile time, so Decimal, Octal and A1Z26
//!    text (`77 101 101 116` splits into `77 6`) fails without loading anything. Then every
//!    word is checked against the dictionary's key strings, which are much cheaper to load
//!    than the scored dictionary, so big integers and other long runs of digits fail there.

use super::crack_results::CrackResult;
use super::interface::{Crack, Decoder};
use crate::checkers::CheckerTypes;
use gibberish_or_not::Sensitivity;
use log::{debug, trace};
use once_cell::sync::Lazy;
use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap, HashSet};

/// The letters on keys 2 to 9, from ITU-T E.161.
const KEYPAD: [&str; 8] = ["ABC", "DEF", "GHI", "JKL", "MNO", "PQRS", "TUV", "WXYZ"];

/// The key of each letter A to Z, as its digit minus 2.
const LETTER_KEYS: [u8; 26] = {
    let mut keys = [0; 26];
    let mut key = 0;
    while key < KEYPAD.len() {
        let letters = KEYPAD[key].as_bytes();
        let mut i = 0;
        while i < letters.len() {
            keys[(letters[i] - b'A') as usize] = key as u8;
            i += 1;
        }
        key += 1;
    }
    keys
};

/// Length of the longest dictionary word, MISUNDERSTANDINGS. Longer runs of digits aren't
/// words. A key string of this many digits, 3 bits each after a leading 1, fits a `u64`.
const MAX_WORD_LEN: usize = 17;

/// Text with fewer digits from 2 to 9 than this is at most two letters long.
const MIN_DIGITS: usize = 3;

/// The most sentences shown to the checker, most likely first.
const MAX_SENTENCES: usize = 5;

/// The most sentences returned when the checker accepts none of them.
const MAX_RETURNED: usize = 3;

/// Word scores are log10 probabilities in millionths, so that sentences made of the same
/// words in different places add up to exactly the same score.
const SCORE_SCALE: f64 = 1_000_000.0;

/// Modern words that `english_words.txt` doesn't have, and that T9 messages and CTF
/// challenges use. Words that are also in the file are only added once.
const EXTRA_WORDS: &str = "\
    ABORT ADMIN AIRPORT ANDROID APP APPS AUDIO AWESOME BINARY BLUETOOTH BOSS BROWSER BUFFER \
    BUS CAMERA CHALLENGE CHALLENGES CIPHER CIPHERS CODE CODED CODES COMPUTER COMPUTERS \
    COOKIE COOKIES CRYPTO CRYPTOGRAPHY CTF DATABASE DEADLINE DECODE DECODED DECODER DECODING \
    DECRYPT DECRYPTED DECRYPTION DIGITAL DOWNLOAD DRONE ELECTRONIC EMAIL EMAILS ENCODE \
    ENCODED ENCODING ENCRYPT ENCRYPTED ENCRYPTION EXAM EXPLOIT FLASHLIGHT HACK HACKED HACKER \
    HACKERS HACKING HARDWARE HEX HEXADECIMAL HI HOMEWORK INSTALL INTERNET KERNEL KEYBOARD \
    KIDS LAPTOP LASER LEVELS LINUX LOGIN LOGOUT LOL MALWARE MOBILE MOM MOVIE MOVIES NETWORK \
    NETWORKS NINJA OK OKAY OMG ONLINE OVERFLOW PASSWORD PASSWORDS PAYLOAD PHONE PHONES PHOTO \
    PHOTOS PIXEL PIZZA PLAYER PROGRAM PROGRAMMER PROGRAMS PUZZLES PYTHON RADAR ROBOT ROBOTS \
    SATELLITE SCRIPT SERVER SERVERS SESSION SMS SOFTWARE SOLVER SPIES STACK TARGET TEAM TEAMS \
    TELEPHONE TESTS TEXTING TEXTS TORCH UNICORN UNLOCK UPDATE UPLOAD USER USERNAME USERS \
    VIDEO VIDEOS VIRUS WEB WEBSITE WEEKEND WIFI WIZARD YEAH ZOMBIE";

/// The dictionary words of every key string (see [`word_key`]), most likely first. Built on
/// first use, which only happens once some text has passed the cheap checks.
static WORDS: Lazy<HashMap<u64, Vec<Word>>> = Lazy::new(|| {
    build_dictionary(
        listed_words(),
        include_str!("../storage/ngrams/english_quadgrams.txt"),
    )
});

/// Every key string that has a dictionary word, sorted. Much cheaper to build than
/// [`WORDS`], which also parses and scores the quadgrams, so text that is mostly not words,
/// like a big integer, is rejected with it first.
static KEYS: Lazy<Box<[u64]>> = Lazy::new(|| {
    let mut keys: Vec<u64> = listed_words()
        .filter_map(|word| word_key(word.as_bytes()))
        .collect();
    keys.sort_unstable();
    keys.dedup();
    keys.into_boxed_slice()
});

/// The words of `english_words.txt` and [`EXTRA_WORDS`].
fn listed_words() -> impl Iterator<Item = &'static str> {
    include_str!("../storage/ngrams/english_words.txt")
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .chain(EXTRA_WORDS.split_ascii_whitespace())
}

/// Whether each key string of 1 or 2 digits (8 to 15 and 64 to 127, see [`word_key`]) has a
/// dictionary word, read from the same word lists at compile time. Decimal, Octal and A1Z26
/// text splits into numbers like these at its `0`s and `1`s, so it can be rejected without
/// building [`KEYS`] or [`WORDS`].
static SHORT_WORDS: [bool; 128] = mark_short_words(
    mark_short_words(
        [false; 128],
        include_bytes!("../storage/ngrams/english_words.txt"),
    ),
    EXTRA_WORDS.as_bytes(),
);

/// Marks the key strings of the words of 1 or 2 letters in `words` in `table`. Words are
/// runs of upper-case letters, and lines that start with `#` are skipped.
const fn mark_short_words(mut table: [bool; 128], words: &[u8]) -> [bool; 128] {
    let mut i = 0;
    while i < words.len() {
        if words[i] == b'#' && (i == 0 || words[i - 1] == b'\n') {
            while i < words.len() && words[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        let start = i;
        let mut key = 1;
        while i < words.len() && words[i].is_ascii_uppercase() {
            if i - start < 2 {
                key = (key << 3) | LETTER_KEYS[(words[i] - b'A') as usize] as usize;
            }
            i += 1;
        }
        match i - start {
            0 => i += 1,
            1 | 2 => table[key] = true,
            _ => {}
        }
    }
    table
}

/// The T9 decoder, call:
/// `let t9_decoder = Decoder::<T9Decoder>::new()` to create a new instance
/// And then call:
/// `result = t9_decoder.crack(input, &checker)` to decode a T9 string
/// The struct generated by new() comes from interface.rs
/// ```
/// use ciphey::decoders::t9_decoder::T9Decoder;
/// use ciphey::decoders::interface::{Crack, Decoder};
/// use ciphey::checkers::{athena::Athena, CheckerTypes, checker_type::{Check, Checker}};
///
/// let decode_t9 = Decoder::<T9Decoder>::new();
/// let athena_checker = Checker::<Athena>::new();
/// let checker = CheckerTypes::CheckAthena(athena_checker);
///
/// let result = decode_t9.crack("43556 96753", &checker);
/// assert!(result.success);
/// assert_eq!(result.unencrypted_text.unwrap()[0], "hello world");
/// ```
pub struct T9Decoder;

impl Crack for Decoder<T9Decoder> {
    fn new() -> Decoder<T9Decoder> {
        Decoder {
            name: "T9",
            description: "T9 predictive text: each letter is its phone keypad key pressed once (2=ABC … 9=WXYZ), so 43556 is hello. Words are looked up in an English dictionary and the most likely reading is returned; 0 and 1 separate words.",
            link: "https://en.wikipedia.org/wiki/T9_(predictive_text)",
            tags: vec!["t9", "sms", "phone", "keypad", "predictive", "substitution"],
            popularity: 0.3,
            phantom: std::marker::PhantomData,
        }
    }

    /// Reads `text` as T9 and checks the most likely sentences, best first, with Low
    /// sensitivity. The first one the checker accepts is returned on its own. If it accepts
    /// none, the 3 most likely are returned. `unencrypted_text` is `None` when `text` isn't
    /// T9.
    fn crack(&self, text: &str, checker: &CheckerTypes) -> CrackResult {
        trace!("Trying T9 with text {:?}", text);
        let mut results = CrackResult::new(self, text.to_string());

        let Some(sentences) = candidates(text) else {
            debug!("Failed to decode T9 because the text isn't keypad digits of English words");
            return results;
        };

        let checker = checker.with_sensitivity(Sensitivity::Low);
        for sentence in &sentences {
            let checker_result = checker.check(sentence);
            if checker_result.is_identified {
                trace!("T9 found plaintext {:?}", sentence);
                results.unencrypted_text = Some(vec![sentence.clone()]);
                results.update_checker(&checker_result);
                return results;
            }
        }

        results.unencrypted_text = Some(sentences.into_iter().take(MAX_RETURNED).collect());
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

/// The most likely readings of `text` as T9, best first: at most 5 sentences of lower-case
/// words joined by single spaces. `None` if `text` isn't T9.
pub(crate) fn candidates(text: &str) -> Option<Vec<String>> {
    let text = text.trim();
    let tokens = tokenize(text.as_bytes())?;
    // Words of 1 or 2 digits are checked against a table built at compile time, then every
    // word against the key strings, before the scored dictionary is built
    if too_many_unknown(&tokens, |key| key >= 128 || SHORT_WORDS[key as usize])
        || too_many_unknown(&tokens, |key| KEYS.binary_search(&key).is_ok())
    {
        return None;
    }
    let words = look_up(&tokens)?;

    // Only the tokens with more than one word make a choice
    let (choice_tokens, choices): (Vec<usize>, Vec<&[Word]>) = words
        .iter()
        .enumerate()
        .filter_map(|(token, words)| words.filter(|words| words.len() > 1).map(|w| (token, w)))
        .unzip();

    let sentences = best_sentences(&choices, MAX_SENTENCES)
        .iter()
        .map(|picks| {
            let mut alternative = vec![0; tokens.len()];
            for pick in picks {
                alternative[choice_tokens[pick.choice]] = pick.alternative;
            }
            write_sentence(text, &tokens, &words, &alternative)
        })
        .collect();
    Some(sentences)
}

/// A run of the digits 2 to 9, which is one word.
struct Token {
    /// Where its first digit is in the text.
    start: usize,
    /// Where it ends in the text.
    end: usize,
    /// Its key string, as [`word_key`] builds it, or `None` if it's longer than every word.
    key: Option<u64>,
}

/// Splits `text` into words, or returns `None` if it fails one of the cheap checks.
fn tokenize(text: &[u8]) -> Option<Vec<Token>> {
    // Almost every input fails here, on its first byte
    if !text.first().is_some_and(u8::is_ascii_digit) {
        return None;
    }

    let mut tokens = Vec::new();
    let mut current: Option<Token> = None;
    let mut digits = 0;
    // Whether some word has two different digits
    let mut mixed = false;
    for (i, &byte) in text.iter().enumerate() {
        match byte {
            b'2'..=b'9' => {
                let token = current.get_or_insert(Token {
                    start: i,
                    end: i,
                    key: Some(1),
                });
                mixed |= byte != text[token.start];
                token.end = i + 1;
                token.key = token
                    .key
                    .filter(|_| token.end - token.start <= MAX_WORD_LEN)
                    .map(|key| (key << 3) | u64::from(byte - b'2'));
                digits += 1;
            }
            // `0` and `1` are a space and punctuation
            b'0' | b'1' => tokens.extend(current.take()),
            _ if is_separator(byte) => tokens.extend(current.take()),
            _ => return None,
        }
    }
    tokens.extend(current);

    // Text where every word is one repeated digit (`44 33 555`, `2 4 2 4`) is Multi-tap
    // or A1Z26, and as T9 reads as words like `hi`, `a` and `i`
    if digits < MIN_DIGITS || !mixed {
        return None;
    }
    Some(tokens)
}

/// Whether `byte` can separate two words.
fn is_separator(byte: u8) -> bool {
    byte.is_ascii_whitespace()
        || matches!(
            byte,
            b'-' | b',' | b';' | b':' | b'.' | b'/' | b'|' | b'*' | b'#'
        )
}

/// Whether more than one token in four is longer than every word or has a key string that
/// `might_be_a_word` rules out, so that [`look_up`] would fail too.
fn too_many_unknown(tokens: &[Token], might_be_a_word: impl Fn(u64) -> bool) -> bool {
    let unknown = tokens
        .iter()
        .filter(|token| !token.key.is_some_and(&might_be_a_word))
        .count();
    unknown * 4 > tokens.len()
}

/// The dictionary words of each token, `None` for tokens that aren't a word. Returns `None`
/// if more than one token in four isn't a word: random digits rarely get that far.
fn look_up(tokens: &[Token]) -> Option<Vec<Option<&'static [Word]>>> {
    let dictionary: &'static HashMap<u64, Vec<Word>> = &WORDS;
    let mut unknown = 0;
    let mut words = Vec::with_capacity(tokens.len());
    for token in tokens {
        let found = token.key.and_then(|key| dictionary.get(&key));
        if found.is_none() {
            unknown += 1;
            if unknown * 4 > tokens.len() {
                return None;
            }
        }
        words.push(found.map(Vec::as_slice));
    }
    Some(words)
}

/// Writes out a sentence: the `alternative[i]`-th word of every token `i` in lower case, or
/// the token's digits if it isn't a word.
fn write_sentence(
    text: &str,
    tokens: &[Token],
    words: &[Option<&[Word]>],
    alternative: &[usize],
) -> String {
    let mut sentence = String::with_capacity(text.len());
    for (i, (token, words)) in tokens.iter().zip(words).enumerate() {
        if i > 0 {
            sentence.push(' ');
        }
        match words {
            Some(words) => sentence.push_str(words[alternative[i]].text),
            None => sentence.push_str(&text[token.start..token.end]),
        }
    }
    sentence.make_ascii_lowercase();
    sentence
}

/// A sentence other than the most likely one picks the `alternative`-th most likely word
/// (counting from 0) for some of the tokens that have more than one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct Pick {
    /// Which of those tokens, as an index into the `choices` of [`best_sentences`].
    choice: usize,
    /// Which of its words, never 0.
    alternative: usize,
}

/// A sentence waiting in [`best_sentences`]'s queue.
#[derive(PartialEq, Eq)]
struct Pending {
    /// Its score, less the score of the most likely sentence. Never positive.
    score: i64,
    /// Its picks, in order of `choice`.
    picks: Vec<Pick>,
}

impl Ord for Pending {
    /// The queue pops the greatest first: the highest score and, of equal scores, the one
    /// whose list of word indices is lexicographically smallest.
    fn cmp(&self, other: &Self) -> Ordering {
        self.score
            .cmp(&other.score)
            .then_with(|| compare_picks(&other.picks, &self.picks))
    }
}

impl PartialOrd for Pending {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Compares two sentences by their lists of word indices, one per choice, lexicographically.
fn compare_picks(a: &[Pick], b: &[Pick]) -> Ordering {
    for (x, y) in a.iter().zip(b) {
        if x.choice != y.choice {
            // The sentence that leaves its best word first has the larger index there
            return y.choice.cmp(&x.choice);
        }
        if x.alternative != y.alternative {
            return x.alternative.cmp(&y.alternative);
        }
    }
    a.len().cmp(&b.len())
}

/// The `count` highest-scoring sentences, best first, as their picks. `choices` holds the
/// words of each token that has more than one, most likely first; a sentence's score is the
/// sum of its words' scores.
///
/// Best-first enumeration: the most likely sentence picks every token's first word, and
/// each sentence taken from the queue adds those that pick the next word for one token.
/// Words are sorted by score, so no sentence scores higher than the one it was made from.
fn best_sentences(choices: &[&[Word]], count: usize) -> Vec<Vec<Pick>> {
    let mut best = Vec::with_capacity(count);
    let mut queue = BinaryHeap::from([Pending {
        score: 0,
        picks: Vec::new(),
    }]);
    let mut seen: HashSet<Vec<Pick>> = HashSet::new();

    while best.len() < count {
        let Some(sentence) = queue.pop() else {
            break;
        };
        // The last sentence needs no successors
        if best.len() + 1 < count {
            for next in successors(&sentence, choices) {
                if seen.insert(next.picks.clone()) {
                    queue.push(next);
                }
            }
        }
        best.push(sentence.picks);
    }
    best
}

/// The sentences that differ from `sentence` by picking the next word for one token.
fn successors<'a>(
    sentence: &'a Pending,
    choices: &'a [&[Word]],
) -> impl Iterator<Item = Pending> + 'a {
    choices
        .iter()
        .enumerate()
        .filter_map(move |(choice, words)| {
            let at = sentence.picks.partition_point(|pick| pick.choice < choice);
            let current = match sentence.picks.get(at) {
                Some(pick) if pick.choice == choice => pick.alternative,
                _ => 0,
            };
            let next = current + 1;
            if next == words.len() {
                return None;
            }
            let mut picks = sentence.picks.clone();
            if current == 0 {
                picks.insert(
                    at,
                    Pick {
                        choice,
                        alternative: next,
                    },
                );
            } else {
                picks[at].alternative = next;
            }
            let score =
                sentence.score + i64::from(words[next].score) - i64::from(words[current].score);
            Some(Pending { score, picks })
        })
}

/// A dictionary word and how likely it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Word {
    /// The word, in upper case.
    text: &'static str,
    /// Its score from [`QuadgramCounts::score`].
    score: i32,
}

/// Groups `words` (upper case; others are skipped) by key string, scored with the
/// quadgram counts in `quadgrams`, each group sorted by score and then alphabetically.
fn build_dictionary(
    words: impl Iterator<Item = &'static str>,
    quadgrams: &str,
) -> HashMap<u64, Vec<Word>> {
    let counts = QuadgramCounts::parse(quadgrams);
    let mut dictionary: HashMap<u64, Vec<Word>> = HashMap::new();
    for text in words {
        let word = text.as_bytes();
        if let (Some(key), Some(score)) = (word_key(word), counts.score(word)) {
            dictionary
                .entry(key)
                .or_default()
                .push(Word { text, score });
        }
    }
    for words in dictionary.values_mut() {
        words.sort_unstable_by(|a, b| b.score.cmp(&a.score).then_with(|| a.text.cmp(b.text)));
        // A word listed twice is scored the same both times, so the copies are adjacent
        words.dedup();
    }
    dictionary
}

/// The key string of an upper-case word: a 1 followed by 3 bits per letter, its key's digit
/// minus 2. `None` if the word has other characters or is longer than [`MAX_WORD_LEN`].
fn word_key(word: &[u8]) -> Option<u64> {
    if word.is_empty() || word.len() > MAX_WORD_LEN {
        return None;
    }
    word.iter().try_fold(1, |key, &letter| {
        letter
            .is_ascii_uppercase()
            .then(|| (key << 3) | u64::from(LETTER_KEYS[usize::from(letter - b'A')]))
    })
}

/// Quadgram counts for scoring words. They are only kept while the dictionary is built.
struct QuadgramCounts {
    /// The count of every quadgram, by [`ngram_index`].
    quadgrams: Vec<u32>,
    /// The summed count of the quadgrams that start with each trigram...
    trigrams: Vec<u64>,
    /// ...and with each bigram.
    bigrams: Vec<u64>,
    /// The count of all quadgrams.
    total: u64,
}

impl QuadgramCounts {
    /// Reads `ABCD count` lines, skipping `#` comments and malformed lines.
    fn parse(data: &str) -> QuadgramCounts {
        let mut counts = QuadgramCounts {
            quadgrams: vec![0; 26 * 26 * 26 * 26],
            trigrams: vec![0; 26 * 26 * 26],
            bigrams: vec![0; 26 * 26],
            total: 0,
        };
        for line in data.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut fields = line.split_ascii_whitespace();
            let (Some(quadgram), Some(count)) = (fields.next(), fields.next()) else {
                continue;
            };
            let index = Some(quadgram.as_bytes())
                .filter(|quadgram| quadgram.len() == 4)
                .and_then(ngram_index);
            let (Some(index), Ok(count)) = (index, count.parse::<u32>()) else {
                continue;
            };
            counts.quadgrams[index] = counts.quadgrams[index].saturating_add(count);
            counts.trigrams[index / 26] += u64::from(count);
            counts.bigrams[index / (26 * 26)] += u64::from(count);
            counts.total += u64::from(count);
        }
        counts
    }

    /// The score of an upper-case word, in millionths of a log10 probability:
    /// * 4 or more letters: the sum of its quadgrams' log10(count / total), with
    ///   log10(0.5 / total) for quadgrams that aren't listed, as if seen half a time.
    /// * 3 letters: log10((T + 0.5) / total), where T is the summed count of the quadgrams
    ///   that start with the word.
    /// * 2 letters: the same with the quadgrams that start with its 2 letters.
    /// * 1 letter: 0.
    ///
    /// `None` if the word has characters other than A to Z.
    fn score(&self, word: &[u8]) -> Option<i32> {
        if !word.iter().all(u8::is_ascii_uppercase) {
            return None;
        }
        let total = self.total.max(1) as f64;
        let log10_probability = |count: f64| (count / total).log10();
        let score = match word.len() {
            0 | 1 => 0.0,
            2 => log10_probability(self.bigrams[ngram_index(word)?] as f64 + 0.5),
            3 => log10_probability(self.trigrams[ngram_index(word)?] as f64 + 0.5),
            _ => {
                let mut sum = 0.0;
                for quadgram in word.windows(4) {
                    let count = self.quadgrams[ngram_index(quadgram)?];
                    sum += log10_probability(if count == 0 { 0.5 } else { f64::from(count) });
                }
                sum
            }
        };
        Some((score * SCORE_SCALE).round() as i32)
    }
}

/// The index of up to 4 upper-case letters, read as a number in base 26. `None` for other
/// characters.
fn ngram_index(letters: &[u8]) -> Option<usize> {
    letters.iter().try_fold(0, |index, &letter| {
        letter
            .is_ascii_uppercase()
            .then(|| index * 26 + usize::from(letter - b'A'))
    })
}

#[cfg(test)]
mod tests {
    use super::{
        best_sentences, build_dictionary, candidates, mark_short_words, tokenize, too_many_unknown,
        word_key, Pick, QuadgramCounts, T9Decoder, Word, EXTRA_WORDS, KEYPAD, KEYS, MAX_WORD_LEN,
        SCORE_SCALE, SHORT_WORDS, WORDS,
    };
    use crate::checkers::athena::Athena;
    use crate::checkers::checker_type::{Check, Checker};
    use crate::checkers::CheckerTypes;
    use crate::decoders::a1z26_decoder::A1Z26Decoder;
    use crate::decoders::decimal_decoder::DecimalDecoder;
    use crate::decoders::interface::{Crack, Decoder};
    use crate::decoders::multi_tap_decoder::MultiTapDecoder;
    use crate::decoders::{DecoderType, DECODER_MAP};
    use crate::filtration_system::get_decoder_by_name;
    use std::collections::HashSet;

    // helper for tests
    fn get_athena_checker() -> CheckerTypes {
        let athena_checker = Checker::<Athena>::new();
        CheckerTypes::CheckAthena(athena_checker)
    }

    // Asserts the decoder finds `expected` and the Athena checker accepts it
    fn assert_cracks(text: &str, expected: &str) {
        let result = Decoder::<T9Decoder>::new().crack(text, &get_athena_checker());
        assert!(result.success, "{text:?} wasn't identified: {result:?}");
        assert_eq!(result.unencrypted_text.unwrap(), [expected], "for {text:?}");
    }

    // Asserts the decoder rejects `text`, without panicking
    fn assert_fails(text: &str) {
        let result = Decoder::<T9Decoder>::new().crack(text, &get_athena_checker());
        assert_eq!(result.unencrypted_text, None, "for {text:?}");
        assert!(!result.success, "{text:?} failed but was marked successful");
        assert_eq!(candidates(text), None, "for {text:?}");
    }

    // The keypad digits of a word, from the ITU-T E.161 table
    fn digits_of(word: &str) -> String {
        word.bytes()
            .map(|letter| {
                let key = KEYPAD
                    .iter()
                    .position(|letters| letters.as_bytes().contains(&letter))
                    .expect("an upper-case letter");
                char::from(b'2' + key as u8)
            })
            .collect()
    }

    // The test vectors are from the implementation plan in
    // https://github.com/bee-san/Ciphey/issues/961, computed there with a Python prototype of
    // this ranking over english_words.txt + EXTRA_WORDS and english_quadgrams.txt, and
    // recomputed with a separate Python implementation for this PR. The digits come from the
    // ITU-T E.161 keypad (`digits_of` here), as on https://www.dcode.fr/t9-cipher.

    #[test]
    fn decodes_the_issue_example() {
        // https://github.com/bee-san/Ciphey/issues/961
        assert_cracks("43556 96753", "hello world");
    }

    #[test]
    fn decodes_other_word_separators() {
        assert_cracks("43556-96753", "hello world");
        assert_cracks("43556,96753", "hello world");
        assert_cracks("  43556\n96753\r\n", "hello world");
        assert_cracks("43556 / 96753 #", "hello world");
    }

    #[test]
    fn decodes_zero_as_a_space() {
        // dCode's encoder writes 0 for a space. End to end the search never gets here: the
        // LemmeKnow checker takes 10 to 13 digits for a phone number first.
        assert_cracks("43556096753", "hello world");
        assert_eq!(candidates("43556096753").unwrap(), ["hello world"]);
        assert_eq!(candidates("4355619675310").unwrap(), ["hello world"]);
    }

    #[test]
    fn decodes_a_single_word() {
        assert_cracks("43556", "hello");
    }

    #[test]
    fn decodes_dcode_example() {
        // https://www.dcode.fr/t9-cipher: TELEPHONE. It's one of EXTRA_WORDS.
        assert_eq!(digits_of("TELEPHONE"), "835374663");
        assert_eq!(candidates("835374663").unwrap(), ["telephone"]);
    }

    #[test]
    fn ranks_textonyms() {
        // dCode's example of words sharing keys
        assert_eq!(candidates("2665").unwrap(), ["book", "cool", "cook"]);
        assert_eq!(
            candidates("4663 6676464").unwrap(),
            [
                "good morning",
                "gone morning",
                "home morning",
                "hood morning"
            ]
        );
    }

    #[test]
    fn decodes_sentences() {
        assert_cracks(
            "843 3524 47 443336 46 843 427336",
            "the flag is hidden in the garden",
        );
        assert_cracks("8447 47 2 732738 6377243", "this is a secret message");
        assert_cracks("843 32453 427 526333", "the eagle has landed");
        assert_cracks("288225 28 3296", "attack at dawn");
        assert_cracks("4 5683 968 76 6824", "i love you so much");
    }

    #[test]
    fn ranks_sentences() {
        assert_eq!(
            candidates("843 3524 47 443336 46 843 427336").unwrap(),
            [
                "the flag is hidden in the garden",
                "the flag is hidden go the garden",
                // THE and TIE score the same in either place: the one that changes the
                // later word comes first
                "the flag is hidden in tie garden",
                "tie flag is hidden in the garden",
                "the flag is hidden go tie garden",
            ]
        );
        assert_eq!(
            candidates("4 5683 968 76 6824").unwrap(),
            [
                "i love you so much",
                "i loud you so much",
                "i jove you so much",
                "i love wot so much",
                "i loud wot so much",
            ]
        );
    }

    #[test]
    fn known_wrong_first_reading() {
        // OF is more common than ME, so the right reading is second. Both are real words
        // and the checker accepts the first.
        assert_eq!(
            candidates("6338 63 28 3296").unwrap(),
            ["meet of at dawn", "meet me at dawn"]
        );
        assert_cracks("6338 63 28 3296", "meet of at dawn");
    }

    #[test]
    fn keeps_unknown_words_as_digits() {
        // CHAMPIONS and SWORDFISH aren't in the dictionary; PASSWORD is one of EXTRA_WORDS.
        // One word in four may be unknown.
        assert_cracks("93 273 843 242674667", "we are the 242674667");
        assert_eq!(
            candidates("843 72779673 47 796733474").unwrap(),
            ["the password is 796733474", "tie password is 796733474"]
        );
    }

    #[test]
    fn decodes_the_longest_word() {
        assert_eq!(MAX_WORD_LEN, "MISUNDERSTANDINGS".len());
        let digits = digits_of("MISUNDERSTANDINGS");
        assert_eq!(
            candidates(&format!("843 {digits}")).unwrap(),
            ["the misunderstandings", "tie misunderstandings"]
        );
        // One more digit is longer than every word
        assert_eq!(candidates(&format!("843 {digits}7")), None);
        assert_eq!(
            candidates(&format!("843 2 4 {digits}7")).unwrap()[0],
            format!("the a i {digits}7")
        );
    }

    #[test]
    fn returns_three_candidates_when_none_is_identified() {
        // RING and SING in 2 places make 4 sentences, and Athena accepts none of them
        let text = "7464 7464";
        assert_eq!(
            candidates(text).unwrap(),
            ["ring ring", "ring sing", "sing ring", "sing sing"]
        );
        let result = Decoder::<T9Decoder>::new().crack(text, &get_athena_checker());
        assert!(!result.success);
        assert_eq!(
            result.unencrypted_text.unwrap(),
            ["ring ring", "ring sing", "sing ring"]
        );

        // Fewer if there are fewer
        let result = Decoder::<T9Decoder>::new().crack("47 48 843", &get_athena_checker());
        assert!(!result.success);
        assert_eq!(result.unencrypted_text.unwrap(), ["is it the", "is it tie"]);
    }

    #[test]
    fn checks_at_most_five_sentences() {
        // THE and TIE in 3 places make 8 sentences
        assert_eq!(
            candidates("843 843 843").unwrap(),
            [
                "the the the",
                "the the tie",
                "the tie the",
                "tie the the",
                "the tie tie"
            ]
        );
    }

    #[test]
    fn fails_on_non_t9_text() {
        for text in [
            "",
            "   ",
            "😀",
            "hello world",
            "４３５５６",
            "43556 96753 😀",
            "43556 96753x",
            // The decoders bench's `miss` input, rejected on its first byte
            "T00 l3= ox+#G WKyV pajU6j qxH@ %B4+a 5Pn^ 7p_v1q 9sLvu *+36i R5rL&3 mVJZI iO0 Ut8_m COTV",
            // No letters
            "0 0 0",
            "1 1 1",
            "- - -",
            // Fewer than 3 letters
            "4 2",
            "40 2",
            // Every word is one repeated digit
            "2 3 4",
            "2 4 2 4",
            "22 33 44",
            // More than one word in four isn't a word
            "12 34 56",
            "23 45 67",
            "99999999999999999999 843",
        ] {
            assert_fails(text);
        }
    }

    #[test]
    fn fails_on_neighbouring_encodings() {
        for text in [
            // Multi-tap
            "44 33 555 555 666 0 9 666 777 555 3",
            "7777 666 7777",
            "3222666333",
            // Decimal and A1Z26 `hello`
            "104 101 108 108 111",
            "8-5-12-12-15",
            // DTMF frequency pairs
            "852-1336 770-1477 852-1209",
            // Phone numbers
            "5551234567",
            "8675309",
            "555-123-4567",
            "+1 555 123 4567",
            // Times, IP addresses, hexadecimal
            "12:30:45",
            "192.168.0.1",
            "4d656574",
        ] {
            assert_fails(text);
        }
    }

    #[test]
    fn leaves_multi_tap_to_multi_tap() {
        let multi_tap = Decoder::<MultiTapDecoder>::new();
        // Multi-tap presses a key once per letter position, so every word is one repeated
        // digit, which T9 skips
        for (text, plaintext) in [
            ("44 33 555 555 666 0 9 666 777 555 3", "HELLO WORLD"),
            ("6-33-33-8 6-33 2-8 3-2-9-66", "MEET ME AT DAWN"),
        ] {
            assert_fails(text);
            let result = multi_tap.crack(text, &get_athena_checker());
            assert_eq!(result.unencrypted_text.unwrap()[0], plaintext);
        }
        // And Multi-tap reads nothing in T9 text
        for text in ["43556 96753", "843 3524 47 443336 46 843 427336"] {
            let result = multi_tap.crack(text, &get_athena_checker());
            assert_eq!(result.unencrypted_text, None, "for {text:?}");
        }
    }

    #[test]
    fn leaves_a1z26_to_a1z26() {
        // A1Z26 reads `2 4 2 4` as BDBD; as T9 it would be `a i a i`
        let text = "2 4 2 4";
        assert_fails(text);
        let a1z26 = Decoder::<A1Z26Decoder>::new();
        let result = a1z26.crack(text, &get_athena_checker());
        assert_eq!(result.unencrypted_text.unwrap()[0], "BDBD");
    }

    #[test]
    fn decimal_reads_little_t9() {
        let decimal = Decoder::<DecimalDecoder>::new();
        // Two numbers are too few for Decimal; above 255 the codes aren't printable ASCII
        for text in [
            "43556 96753",
            "843 3524 47 443336 46 843 427336",
            "8447 47 2 732738 6377243",
        ] {
            let result = decimal.crack(text, &get_athena_checker());
            assert_eq!(result.unencrypted_text, None, "for {text:?}");
        }
        // Short words can be both, and read differently
        let text = "47 48 843";
        assert_eq!(candidates(text).unwrap(), ["is it the", "is it tie"]);
        let result = decimal.crack(text, &get_athena_checker());
        assert_ne!(result.unencrypted_text.unwrap()[0], "is it the");
    }

    #[test]
    fn tokenizes() {
        let text = "843 72-0-1 4355609675310 2";
        let tokens = tokenize(text.as_bytes()).unwrap();
        let words: Vec<&str> = tokens.iter().map(|t| &text[t.start..t.end]).collect();
        assert_eq!(words, ["843", "72", "43556", "96753", "2"]);
        for (token, word) in tokens.iter().zip(["THE", "PA", "HELLO", "WORLD", "A"]) {
            assert_eq!(token.key, word_key(word.as_bytes()), "for {word}");
        }
        // A word longer than every dictionary word has no key
        let text = b"222222222222222222 43";
        assert_eq!(tokenize(text).unwrap()[0].key, None);
        let text = b"22222222222222222 43";
        assert!(tokenize(text).unwrap()[0].key.is_some());
    }

    #[test]
    fn word_keys() {
        assert_eq!(word_key(b"HELLO"), word_key(b"GEKKO"));
        assert_ne!(word_key(b"HELLO"), word_key(b"HELL"));
        // Keys of different lengths never collide: the leading 1 marks the length
        assert_ne!(word_key(b"A"), word_key(b"AA"));
        assert_eq!(word_key(b"A"), Some(0b1_000));
        assert_eq!(word_key(b"Z"), Some(0b1_111));
        assert_eq!(word_key(b"AZ"), Some(0b1_000_111));
        assert_eq!(word_key(b""), None);
        assert_eq!(word_key(b"hello"), None);
        assert_eq!(word_key(b"DON'T"), None);
        assert_eq!(
            word_key(b"MISUNDERSTANDINGS"),
            Some(word_key_of_digits("64786337782634647"))
        );
        assert_eq!(word_key(b"MISUNDERSTANDINGSS"), None);
        for (key, letters) in KEYPAD.iter().enumerate() {
            for letter in letters.bytes() {
                assert_eq!(word_key(&[letter]), Some(8 | key as u64));
            }
        }
    }

    // The key string tokenize builds for a run of digits 2 to 9
    fn word_key_of_digits(digits: &str) -> u64 {
        let text = format!("{digits} 23");
        tokenize(text.as_bytes()).unwrap()[0].key.unwrap()
    }

    #[test]
    fn scores_words() {
        let counts = QuadgramCounts::parse(
            "# comment\n\nABCD 3\nBCDE 1\nBCDE 2\nAB 5\nABCDE 5\nabcd 5\nABCD x\nABCD\nXYZW 4\n",
        );
        // ABCD 3, BCDE 1 + 2 and XYZW 4 are counted; the other lines are malformed
        let total: f64 = 10.0;
        assert_eq!(counts.total, 10);
        let score = |log10: f64| Some((log10 * SCORE_SCALE).round() as i32);
        assert_eq!(counts.score(b"A"), Some(0));
        assert_eq!(counts.score(b"AB"), score(((3.0 + 0.5) / total).log10()));
        assert_eq!(counts.score(b"BC"), score(((3.0 + 0.5) / total).log10()));
        assert_eq!(counts.score(b"QQ"), score((0.5 / total).log10()));
        assert_eq!(counts.score(b"XYZ"), score(((4.0 + 0.5) / total).log10()));
        assert_eq!(counts.score(b"ABCD"), score((3.0 / total).log10()));
        assert_eq!(
            counts.score(b"ABCDE"),
            score((3.0 / total).log10() + (3.0 / total).log10())
        );
        // Quadgrams that aren't listed count as half a quadgram
        assert_eq!(
            counts.score(b"ABCDZ"),
            score((3.0 / total).log10() + (0.5 / total).log10())
        );
        assert_eq!(counts.score(b"ABcD"), None);
        assert_eq!(counts.score(b"a"), None);
        assert_eq!(counts.score(b"A-"), None);
    }

    #[test]
    fn builds_the_dictionary() {
        let quadgrams = "GOOD 9\nOODS 1\nHOME 4\nGONE 4\nHOOD 1\n";
        let words = [
            "HOOD", "GOOD", "GONE", "HOME", "GOOD", "GOODS", "good", "A", "I",
        ];
        let dictionary = build_dictionary(words.into_iter(), quadgrams);
        let texts = |word: &str| -> Vec<&str> {
            dictionary[&word_key(word.as_bytes()).unwrap()]
                .iter()
                .map(|word| word.text)
                .collect()
        };
        // By score, then alphabetically; GOOD is only listed once
        assert_eq!(texts("GOOD"), ["GOOD", "GONE", "HOME", "HOOD"]);
        assert_eq!(texts("GOODS"), ["GOODS"]);
        assert_eq!(texts("A"), ["A"]);
        assert_eq!(dictionary.len(), 4);
    }

    #[test]
    fn short_word_table_matches_the_dictionary() {
        for key in 0..128u64 {
            assert_eq!(
                SHORT_WORDS[key as usize],
                WORDS.contains_key(&key),
                "key string {key:#b}"
            );
        }
        // A, I; AM, AN, ...; HI and OK are among EXTRA_WORDS
        assert_eq!(SHORT_WORDS.iter().filter(|&&word| word).count(), 23);
        assert!(SHORT_WORDS[word_key(b"HI").unwrap() as usize]);
        assert!(!SHORT_WORDS[word_key(b"D").unwrap() as usize]);
        // Comment lines and words of 3 or more letters don't count
        let table = mark_short_words([false; 128], b"# AB CD\nTHE\nOK\n\nX Y-Z#B");
        let marked: Vec<u64> = (0..128).filter(|&key| table[key as usize]).collect();
        let mut expected: Vec<u64> = ["OK", "X", "Y", "Z", "B"]
            .iter()
            .map(|word| word_key(word.as_bytes()).unwrap())
            .collect();
        expected.sort_unstable();
        // X, Y and Z are all on key 9, B on key 2
        expected.dedup();
        assert_eq!(marked, expected);
    }

    // The pre-check against the compile-time table of 1 and 2 letter words
    fn short_words_rule_out(text: &str) -> bool {
        let tokens = tokenize(text.as_bytes()).expect(text);
        too_many_unknown(&tokens, |key| key >= 128 || SHORT_WORDS[key as usize])
    }

    // The pre-check against every key string
    fn keys_rule_out(text: &str) -> bool {
        let tokens = tokenize(text.as_bytes()).expect(text);
        too_many_unknown(&tokens, |key| KEYS.binary_search(&key).is_ok())
    }

    #[test]
    fn rejects_short_numbers_without_the_dictionary() {
        // Decimal, Octal and A1Z26 `Meet me at...`, split at their 0s and 1s
        for text in [
            "77 101 101 116 32 109 101 32 97 116 32 116 104 101",
            "115 145 145 164 40 155 145 40 141 164 40 164 150 145",
            "13-5-5-20 13-5 1-20 20-8-5 15-12-4 12-9-7-8-20-8-15-21-19-5 11-5-25",
            "8675309",
            "192.168.0.1",
            // A token longer than every word
            "99999999999999999999 843",
        ] {
            assert!(short_words_rule_out(text), "for {text:?}");
        }
        // T9 text passes, even when most of its words are short
        for text in [
            "43556 96753",
            "4 5683 968 76 6824",
            "47 48 843",
            "2 247439 2 2",
        ] {
            assert!(!short_words_rule_out(text), "for {text:?}");
            assert!(!keys_rule_out(text), "for {text:?}");
        }
    }

    #[test]
    fn rejects_long_numbers_without_the_scored_dictionary() {
        // The big integer of `Meet me at the old lighthouse...` (the search bench's
        // big_integer case) splits into 35 words at its 0s and 1s. Only 5 are short
        // non-words, so it passes the first check, but 27 have no dictionary word.
        let big_integer = "5924286894360222175456110753752027428824911406952436191673549997864792617447030598048630620176057525265340209895115724741248167312932204479423391834119139432169971560672548040885900086328";
        assert!(!short_words_rule_out(big_integer));
        assert!(keys_rule_out(big_integer));
        assert_fails(big_integer);
        // A phone number with its area code
        assert!(keys_rule_out("2025550143"));
    }

    #[test]
    fn key_set_matches_the_dictionary() {
        let mut keys: Vec<u64> = WORDS.keys().copied().collect();
        keys.sort_unstable();
        assert_eq!(&KEYS[..], &keys[..]);
        assert_eq!(KEYS.len(), 11_102);
    }

    #[test]
    fn the_dictionary_is_sorted_and_has_every_extra_word() {
        let mut extra = HashSet::new();
        for word in EXTRA_WORDS.split_ascii_whitespace() {
            assert!(extra.insert(word), "{word} is listed twice");
            let key = word_key(word.as_bytes()).expect("upper case A to Z");
            assert!(
                WORDS[&key].iter().any(|w| w.text == word),
                "{word} isn't in the dictionary"
            );
        }
        for words in WORDS.values() {
            for pair in words.windows(2) {
                assert!(
                    (pair[0].score, pair[1].text) > (pair[1].score, pair[0].text),
                    "{:?} should come after {:?}",
                    pair[0],
                    pair[1]
                );
            }
        }
    }

    // Two equally likely words for each of `n` tokens, and one less likely
    fn ties(n: usize) -> Vec<&'static [Word]> {
        const TIED: &[Word] = &[
            Word {
                text: "X",
                score: 0,
            },
            Word {
                text: "Y",
                score: -10,
            },
            Word {
                text: "Z",
                score: -10,
            },
        ];
        vec![TIED; n]
    }

    fn pick(choice: usize, alternative: usize) -> Pick {
        Pick {
            choice,
            alternative,
        }
    }

    #[test]
    fn enumerates_sentences_best_first() {
        let sentences = best_sentences(&ties(2), 9);
        let expected: [&[Pick]; 9] = [
            &[],
            // Score -10: the smallest index tuples first, (0, 1), (0, 2), (1, 0), (2, 0)
            &[pick(1, 1)],
            &[pick(1, 2)],
            &[pick(0, 1)],
            &[pick(0, 2)],
            // Score -20
            &[pick(0, 1), pick(1, 1)],
            &[pick(0, 1), pick(1, 2)],
            &[pick(0, 2), pick(1, 1)],
            &[pick(0, 2), pick(1, 2)],
        ];
        assert_eq!(sentences, expected);
        // Fewer if asked for fewer, or if there aren't that many
        assert_eq!(best_sentences(&ties(2), 3), expected[..3]);
        assert_eq!(best_sentences(&ties(2), 20), expected);
        assert_eq!(best_sentences(&ties(1), 5).len(), 3);
        assert_eq!(best_sentences(&[], 5), [Vec::<Pick>::new()]);
        assert!(best_sentences(&ties(2), 0).is_empty());
    }

    #[test]
    fn enumerates_long_texts_quickly() {
        // 5 sentences of 10,000 ambiguous words
        let sentences = best_sentences(&ties(10_000), 5);
        assert_eq!(
            sentences,
            [
                vec![],
                vec![pick(9_999, 1)],
                vec![pick(9_999, 2)],
                vec![pick(9_998, 1)],
                vec![pick(9_998, 2)],
            ]
        );
    }

    #[test]
    fn is_registered() {
        // Exactly one decoder by that name runs in the search
        let decoders = get_decoder_by_name("T9");
        assert_eq!(decoders.components.len(), 1);
        assert_eq!(decoders.components[0].get_name(), "T9");
        // Cached results name the decoder; reading them back looks it up here
        let decoder = DECODER_MAP
            .get("T9")
            .expect("T9 should be in DECODER_MAP")
            .get::<DecoderType>();
        assert_eq!(decoder.get_name(), "T9");
    }

    #[test]
    fn metadata() {
        let decoder = Decoder::<T9Decoder>::new();
        assert_eq!(decoder.get_popularity(), 0.3);
        assert_eq!(
            decoder.get_tags(),
            &["t9", "sms", "phone", "keypad", "predictive", "substitution"]
        );
        // It returns ranked guesses, like the crackers, not one decoding
        assert!(!decoder.get_tags().contains(&"decoder"));
        assert_eq!(
            decoder.get_link(),
            "https://en.wikipedia.org/wiki/T9_(predictive_text)"
        );
    }
}
