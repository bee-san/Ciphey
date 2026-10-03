//! Cracks the Beaufort cipher, finding the key length and the key itself.
//!
//! Beaufort is the reciprocal variant of Vigenère: with key letter K, the letter P is
//! encrypted as C = K − P (mod 26) and decrypted the same way, P = K − C, so encrypting
//! twice with the same key gives the text back. Only ASCII letters change, and they keep
//! their case. Digits, whitespace, punctuation and non-ASCII characters are copied and
//! don't use up a key letter, as in the Vigenère decoder.
//!
//! Since K − C = (25 − C) − (25 − K), a Beaufort ciphertext is a Vigenère ciphertext of
//! the same plaintext once both the text and the key go through Atbash. So the key search
//! is the Vigenère decoder's, run on the Atbash of the letters, and the key it finds is
//! turned back with Atbash. "Variant Beaufort" (P = C + K) is Vigenère with a negated key,
//! which the Vigenère decoder already cracks, so it isn't handled here.
//!
//! The search, after cheap checks that turn most text away in microseconds (see
//! `passes_gates`: too few letters, other symbols or changes of case inside words, an
//! index of coincidence or letter frequencies like English's, or a Caesar, Atbash or
//! Affine key that reads it as English):
//! 1. rank the key lengths from 2 to 20 letters (and at most a sixth of the text) by
//!    the index of coincidence of their columns, and keep the best six. From 100 letters
//!    on, text whose columns at the best length read as Caesar shifts of English rather
//!    than reflected ones is Vigenère, and is left to the Vigenère decoder,
//! 2. find a key of each length with the Vigenère key search on the Atbash of the letters,
//! 3. score each decryption by how often its quadgrams (runs of four letters) occur in
//!    English, less a penalty for long keys, and refine the best three keys a letter at
//!    a time,
//! 4. show the best three distinct keys of two or more letters to the checker. A key of
//!    one letter is Atbash (Z) or an Affine key with a = 25, which those decoders crack.
//!
//! On 810 test texts (9 English paragraphs, prefixes of 30 to 200 letters, 10 keys of 2
//! to 15 letters) it finds 98% of the keys with 15 or more letters of text per key letter,
//! 89% with 10 to 14 and 59% with 6 to 9. The quadgram counts are in
//! `src/storage/ngrams/english_quadgrams.txt`, and the table is the Vigenère autokey
//! cracker's: almost every text that gets as far as the key search here is scored there
//! too, so it is only built once.
//!
//! References: <https://en.wikipedia.org/wiki/Beaufort_cipher>,
//! <https://www.dcode.fr/beaufort-cipher>,
//! <http://practicalcryptography.com/ciphers/classical-era/beaufort/>

use super::affine_decoder::BIGRAM_LOG_PROBS;
use super::crack_results::CrackResult;
use super::interface::{Crack, Decoder};
use super::vigenere_autokey_decoder::QUADGRAMS;
use super::vigenere_decoder::{break_vigenere_letters, cipher_letters};
use crate::checkers::CheckerTypes;
use crate::storage::ENGLISH_FREQS;
use gibberish_or_not::Sensitivity;
use log::{debug, trace};

/// Gate 1: the fewest ASCII letters worth searching.
const MIN_LETTERS: usize = 20;

/// Gate 2: there must be at least this many ASCII letters for each character that is
/// neither an ASCII letter nor ASCII whitespace (digits, punctuation, non-ASCII
/// characters), so at most 7.7% of the rest. English and its Beaufort ciphertexts have
/// 2 to 3%, Base64, Base32 and Base58 10 to 18% and the decoder benchmarks' `miss` string
/// 37%.
const LETTERS_PER_OTHER: usize = 12;

/// Gate 3 applies once the text has this many pairs of adjacent ASCII letters. Fewer
/// give a noisy share: one "McDonald" in 20 letters is already one pair in seven.
const MIN_PAIRS_FOR_CASE_GATE: usize = 20;

/// Gate 3: at most one pair of adjacent letters in this many may be a lower-case letter
/// followed by an upper-case one (`aB`). Beaufort keeps each letter's case, and English
/// almost never changes case inside a word: the Affine decoder measured at most one pair
/// in 11 in 4,480 windows of Project Gutenberg books and Ciphey's docs. Base64 does it
/// about one pair in four, and Base64 of text that is mostly digits and spaces, such as
/// binary or Baudot, has almost no digits of its own to fail gate 2 with.
const LOWER_UPPER_PAIRS_ONE_IN: usize = 8;

/// Gate 4 applies from this many letters on. Shorter English varies too much: prefixes of
/// 30 to 60 letters have an index of coincidence as low as 0.049.
const IOC_GATE_LETTERS: usize = 100;

/// Gate 4: the highest index of coincidence. English of 100 letters or more has 0.063 to
/// 0.066 (and so do its Caesar, Atbash and Affine encryptions), Beaufort ciphertexts of it
/// with keys of two or more letters at most 0.057.
const MAX_IOC: f64 = 0.060;

/// Gate 5: the highest mean natural log of the English frequency of each letter. Below 100
/// letters gate 4 lets English through, and transpositions of it (reversed text, rail
/// fence) keep its letters. On windows of 20 to 200 letters of 17 English paragraphs, 90%
/// score above −3.13 (and every window of 100 or more letters above −3.15); their
/// Beaufort ciphertexts never scored above −3.20.
const MAX_ENGLISH_LETTER_LOG_PROB: f64 = -3.15;

/// Gate 6: the highest mean `ln P` per pair of consecutive letters (across word breaks)
/// that the best Caesar, Atbash or Affine key may give, below 40 pairs. With that key the
/// text reads as English letter pairs, and the decoder of that key is cheaper. On windows
/// of 17 English paragraphs: the best key for their affine encryptions scored at least
/// −6.81 (20 to 39 letters, 90% above −5.84), the best key for their Beaufort ciphertexts
/// at most −5.49 (90% below −6.27).
const MAX_AFFINE_PAIR_LOG_PROB_SHORT: f32 = -6.0;

/// Gate 6, from 40 pairs on. The best key for affine encryptions scored at least −6.40
/// (40 to 59 letters), −6.01 (60 to 99) and −5.78 (100 to 200), for Beaufort ciphertexts
/// at most −6.13, −6.68 and −6.93.
const MAX_AFFINE_PAIR_LOG_PROB: f32 = -6.3;

/// Gate 6 only scores this many letters: more don't tell the keys apart any better, and
/// scoring 312 keys on every distinct letter pair of a long text takes a few hundred
/// microseconds.
const AFFINE_GATE_MAX_LETTERS: usize = 150;

/// Gate 7 applies from this many letters on: below it a column is too short to tell a
/// Caesar shift of English from a reflected one.
const VIGENERE_GATE_LETTERS: usize = 100;

/// Gate 7: a text is left to the Vigenère decoder if, at the best-ranked key length, its
/// columns fit English better as Caesar shifts than as reflected (Beaufort) shifts by more
/// than this many nats per letter, divided by the square root of the number of letters
/// (see [`reflection_preference`]). On windows of 100 to 576 letters of 17 English
/// paragraphs this rejected none of 1,080 Beaufort ciphertexts, and 51% of their Vigenère
/// ciphertexts of 100 to 149 letters, 77% of 150 to 199, 97% of 200 to 299 and all longer
/// ones.
const VIGENERE_PREFERENCE_SCALE: f64 = 1.1;

/// The shortest key searched. A key of one letter is Atbash or Affine.
const MIN_KEY_LENGTH: usize = 2;

/// The longest key searched.
const MAX_KEY_LENGTH: usize = 20;

/// Keys may be at most a sixth as long as the text, so every key letter decrypts at least
/// six letters. With fewer the key search rarely finds the right key, but it can fit a
/// key to almost any short text: with a cap of a quarter, 2 to 12% of strings of 20 to 40
/// random letters without spaces got a key whose decryption the checker accepted.
const MIN_LETTERS_PER_KEY_LETTER: usize = 6;

/// How many key lengths are searched: the ones whose columns have the highest average
/// index of coincidence. Searching all of them finds hardly any more keys (3 more of the
/// 810 test texts) and takes twice as long.
const KEY_LENGTHS_SEARCHED: usize = 6;

/// How many of the best-scoring keys are refined. Refining is most of the cost of a search
/// that finds nothing, as on short Vigenère and Vigenère autokey ciphertexts, which pass
/// the gates. Refining five keys instead found 4 more of the 810 test keys (578) and took
/// 1.7 times as long on such text.
const KEYS_REFINED: usize = 3;

/// The most rounds of refinement. Each round tries every letter at every key position,
/// and stops early once a round changes nothing. Four rounds find 23 more keys than two
/// in the 810 test texts, most of them with 6 to 14 letters per key letter; more rounds
/// find no more.
const REFINE_ROUNDS: usize = 4;

/// The most decryptions shown to the checker.
const MAX_CHECKED: usize = 3;

/// The lowest score a decryption shown to the checker may have. Correct decryptions score
/// −4.1 to −4.3 on average (−4.9 at worst on 20 to 60 letters), and the best key for
/// random letters below −5.2 from 84 letters on.
const MIN_CHECKED_SCORE: f32 = -5.0;

/// The lowest score at which the best decryption is returned for the search to keep
/// decoding when the checker accepts none.
const MIN_UNCONFIRMED_SCORE: f32 = -4.6;

/// Number of quadgrams that start with the same letter, 26³.
const QUADGRAMS_PER_LETTER: usize = 26 * 26 * 26;

/// The Beaufort cracker. Call:
/// `let decoder = Decoder::<BeaufortDecoder>::new()` to create one,
/// and `decoder.crack(text, &checker)` to crack `text`.
/// ```
/// use ciphey::decoders::beaufort_decoder::BeaufortDecoder;
/// use ciphey::decoders::interface::{Crack, Decoder};
/// use ciphey::checkers::{athena::Athena, CheckerTypes, checker_type::{Check, Checker}};
///
/// let decoder = Decoder::<BeaufortDecoder>::new();
/// let checker = CheckerTypes::CheckAthena(Checker::<Athena>::new());
///
/// // Encrypted with the key LEMON
/// let result = decoder.crack(
///     "Zaiv bh et vgh qbl cdyfvgxkuk nglix bdbzghel mbk knebh sxi cnw, lfk dhg mbk l lyxle.",
///     &checker,
/// );
/// assert!(result.success);
/// assert_eq!(
///     result.unencrypted_text.unwrap()[0],
///     "Meet me at the old lighthouse after midnight and bring the map, the key and a torch."
/// );
/// assert_eq!(result.key.unwrap(), "LEMON");
/// ```
pub struct BeaufortDecoder;

impl Crack for Decoder<BeaufortDecoder> {
    fn new() -> Decoder<BeaufortDecoder> {
        Decoder {
            name: "Beaufort",
            description: "Beaufort cipher, the reciprocal Vigenère variant P = K − C. Finds the key length and key automatically. Uses Low sensitivity for gibberish detection on spaced text, Medium on unspaced text.",
            link: "https://en.wikipedia.org/wiki/Beaufort_cipher",
            tags: vec!["beaufort", "vigenere", "substitution", "classical", "reciprocal"],
            popularity: 0.4,
            phantom: std::marker::PhantomData,
        }
    }

    /// Searches for the key. On success the plaintext is the only element of
    /// `unencrypted_text` and `key` holds the key in capitals. When the checker accepts
    /// none of the decryptions but the best one still reads like English, that one is
    /// returned unconfirmed, with its key, so the search can keep decoding it.
    ///
    /// Decryptions of text with whitespace are checked with Low sensitivity, like the
    /// other classical ciphers, and of text without it with Medium: Low rarely accepts
    /// English without spaces.
    fn crack(&self, text: &str, checker: &CheckerTypes) -> CrackResult {
        trace!("Trying Beaufort with text {:?}", text);
        let mut results = CrackResult::new(self, text.to_string());
        let keys = rank_keys(text);
        if keys.is_empty() {
            trace!("Beaufort found no key worth checking");
            return results;
        }
        let sensitivity = if text.bytes().any(|byte| byte.is_ascii_whitespace()) {
            Sensitivity::Low
        } else {
            Sensitivity::Medium
        };
        let checker = checker.with_sensitivity(sensitivity);
        let mut confirm = |plaintext: &str| {
            let check = checker.check(plaintext);
            check.is_identified.then_some(check)
        };

        match solve(text, keys, &mut confirm) {
            Outcome::Confirmed {
                plaintext,
                key,
                check,
            } => {
                debug!("Beaufort found key {key}");
                results.unencrypted_text = Some(vec![plaintext]);
                results.update_checker(&check);
                results.key = Some(key);
            }
            Outcome::Unconfirmed { plaintext, key } => {
                debug!("Beaufort best guess, key {key}: {plaintext}");
                results.unencrypted_text = Some(vec![plaintext]);
                results.key = Some(key);
            }
            Outcome::Failed => trace!("Beaufort found no key"),
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

/// What [`solve`] found. `T` is what the checker returns.
enum Outcome<T> {
    /// The checker accepted this decryption.
    Confirmed {
        /// The decryption of the whole text.
        plaintext: String,
        /// Its key, in capitals.
        key: String,
        /// What the checker said.
        check: T,
    },
    /// The checker accepted nothing, but this decryption reads like English.
    Unconfirmed {
        /// The decryption of the whole text.
        plaintext: String,
        /// Its key, in capitals.
        key: String,
    },
    /// Nothing worth returning.
    Failed,
}

/// Cracks `text` with `keys`, what [`rank_keys`] found for it: shows the decryptions,
/// best first, to `confirm` until it returns `Some`, so `confirm` runs at most
/// [`MAX_CHECKED`] times.
fn solve<T>(
    text: &str,
    keys: Vec<(f32, String)>,
    confirm: &mut dyn FnMut(&str) -> Option<T>,
) -> Outcome<T> {
    for (score, key) in &keys {
        let plaintext = decrypt(text, key);
        if let Some(check) = confirm(&plaintext) {
            trace!("Beaufort key {key} (score {score:.3}) confirmed");
            return Outcome::Confirmed {
                plaintext,
                key: key.clone(),
                check,
            };
        }
    }
    match keys.into_iter().next() {
        Some((score, key)) if score >= MIN_UNCONFIRMED_SCORE => Outcome::Unconfirmed {
            plaintext: decrypt(text, &key),
            key,
        },
        _ => Outcome::Failed,
    }
}

/// The keys worth showing the checker for `text`, in capitals, best first, with their
/// scores: at most [`MAX_CHECKED`] different keys of two letters or more, scoring at
/// least [`MIN_CHECKED_SCORE`]. Empty if `text` fails [`passes_gates`].
///
/// A key's score is the mean log10 probability of the quadgrams of its decryption, less
/// `key length / number of quadgrams`: a long key can be fitted to a short text, so it
/// has to read better than a short one to beat it.
fn rank_keys(text: &str) -> Vec<(f32, String)> {
    if !passes_gates(text) {
        return Vec::new();
    }
    search_keys(text)
}

/// [`rank_keys`] without the gates. `text` has at least [`MIN_LETTERS`] ASCII letters.
fn search_keys(text: &str) -> Vec<(f32, String)> {
    let letters = cipher_letters(text);
    let lengths = likely_key_lengths(&letters);
    if let Some(&best) = lengths.first() {
        if looks_like_vigenere(&letters, best) {
            trace!("Beaufort: the columns at key length {best} read as Vigenère");
            return Vec::new();
        }
    }
    let atbash: Vec<usize> = letters.iter().map(|&letter| 25 - letter).collect();
    let scorer = Scorer::new(letters.iter().map(|&letter| letter as u8).collect());

    let mut keys: Vec<(f32, Vec<u8>)> = lengths
        .into_iter()
        .filter_map(|length| {
            let key = from_vigenere_key(&break_vigenere_letters(&atbash, length))?;
            Some((scorer.score(&key), key))
        })
        .collect();
    sort_best_first(&mut keys);
    keys.truncate(KEYS_REFINED);

    let mut refined: Vec<(f32, Vec<u8>)> = Vec::with_capacity(keys.len());
    for (_, mut key) in keys {
        scorer.refine(&mut key);
        // LEMONLEMON decrypts the same as LEMON, and a key of one letter is Atbash or
        // Affine, which their own decoders crack
        let key = primitive_period(&key);
        if key.len() < MIN_KEY_LENGTH || refined.iter().any(|(_, seen)| seen == key) {
            continue;
        }
        refined.push((scorer.score(key), key.to_vec()));
    }
    sort_best_first(&mut refined);
    trace!(
        "Beaufort keys: {:?}",
        refined
            .iter()
            .map(|(score, key)| (*score, key_string(key)))
            .collect::<Vec<_>>()
    );
    refined
        .into_iter()
        .filter(|(score, _)| *score >= MIN_CHECKED_SCORE)
        .take(MAX_CHECKED)
        .map(|(score, key)| (score, key_string(&key)))
        .collect()
}

/// The cheap checks, in one pass over the text: at least [`MIN_LETTERS`] ASCII letters,
/// at most one other character (not whitespace) per [`LETTERS_PER_OTHER`] letters, few
/// changes from lower to upper case between adjacent letters (see
/// [`LOWER_UPPER_PAIRS_ONE_IN`]), and from [`IOC_GATE_LETTERS`] letters on an index of
/// coincidence of at most [`MAX_IOC`], below English's. Shorter texts must not have
/// English letter frequencies already ([`MAX_ENGLISH_LETTER_LOG_PROB`]), and no Caesar,
/// Atbash or Affine key may turn them into English letter pairs (see
/// [`reads_as_affine_english`]).
fn passes_gates(text: &str) -> bool {
    let mut counts = [0u32; 26];
    let mut letters = 0usize;
    let mut other = 0usize;
    // Adjacent pairs of ASCII letters, and those that are lower case then upper case
    let mut pairs = 0usize;
    let mut lower_upper_pairs = 0usize;
    let mut previous_letter: Option<u8> = None;
    for byte in text.bytes() {
        if byte.is_ascii_alphabetic() {
            counts[usize::from(byte.to_ascii_uppercase() - b'A')] += 1;
            letters += 1;
            if let Some(previous) = previous_letter {
                pairs += 1;
                if previous.is_ascii_lowercase() && byte.is_ascii_uppercase() {
                    lower_upper_pairs += 1;
                }
            }
            previous_letter = Some(byte);
        } else {
            previous_letter = None;
            if !byte.is_ascii_whitespace() && !is_utf8_continuation(byte) {
                // Counts every character that isn't an ASCII letter or whitespace once
                other += 1;
            }
        }
    }
    if letters < MIN_LETTERS || other * LETTERS_PER_OTHER > letters {
        return false;
    }
    if pairs >= MIN_PAIRS_FOR_CASE_GATE && lower_upper_pairs * LOWER_UPPER_PAIRS_ONE_IN > pairs {
        return false;
    }
    if letters >= IOC_GATE_LETTERS && index_of_coincidence(&counts, letters) > MAX_IOC {
        return false;
    }
    english_letter_log_prob(&counts, letters) <= MAX_ENGLISH_LETTER_LOG_PROB
        && !reads_as_affine_english(text)
}

/// The mean natural log of the English frequency of each of the `total` letters counted
/// in `counts`.
fn english_letter_log_prob(counts: &[u32; 26], total: usize) -> f64 {
    let sum: f64 = counts
        .iter()
        .zip(ENGLISH_FREQS)
        .map(|(&count, frequency)| f64::from(count) * frequency.ln())
        .sum();
    sum / total.max(1) as f64
}

/// Whether the identity, a Caesar shift, Atbash or another Affine key turns the pairs of
/// consecutive ASCII letters of `text` (across word breaks, the first
/// [`AFFINE_GATE_MAX_LETTERS`] letters) into pairs that are as likely in English as
/// [`MAX_AFFINE_PAIR_LOG_PROB`] says, scored with the Affine decoder's letter-pair table.
/// Such text is plain English or one of those ciphers, which their own decoders crack, and
/// not worth a Beaufort key search. Stops at the first key that does, so English and its
/// Caesar shifts take a few microseconds and Beaufort ciphertexts, which try all 312 keys,
/// a few dozen.
fn reads_as_affine_english(text: &str) -> bool {
    let mut pair_counts = [[0u16; 26]; 26];
    let mut previous: Option<usize> = None;
    let mut total = 0usize;
    let letters = text
        .bytes()
        .filter(u8::is_ascii_alphabetic)
        .take(AFFINE_GATE_MAX_LETTERS);
    for byte in letters {
        let letter = usize::from(byte.to_ascii_uppercase() - b'A');
        if let Some(first) = previous {
            pair_counts[first][letter] = pair_counts[first][letter].saturating_add(1);
            total += 1;
        }
        previous = Some(letter);
    }
    let pairs: Vec<(usize, usize, f32)> = pair_counts
        .iter()
        .enumerate()
        .flat_map(|(first, row)| {
            row.iter()
                .enumerate()
                .filter(|(_, &count)| count > 0)
                .map(move |(second, &count)| (first, second, f32::from(count)))
        })
        .collect();
    let limit = if total < 40 {
        MAX_AFFINE_PAIR_LOG_PROB_SHORT
    } else {
        MAX_AFFINE_PAIR_LOG_PROB
    } * total as f32;
    let log_probs = &*BIGRAM_LOG_PROBS;
    // The identity and Caesar shifts first, then Atbash and its shifts: the likeliest
    AFFINE_MULTIPLIERS.iter().any(|&a| {
        (0..26).any(|b| {
            let table: [usize; 26] = std::array::from_fn(|c| (a * c + b) % 26);
            let score: f32 = pairs
                .iter()
                .map(|&(first, second, count)| count * log_probs[table[first]][table[second]])
                .sum();
            score >= limit
        })
    })
}

/// The multipliers of the Affine keys p = a·c + b, the identity's first and Atbash's next.
const AFFINE_MULTIPLIERS: [usize; 12] = [1, 25, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23];

/// Whether `byte` continues a multi-byte UTF-8 character.
fn is_utf8_continuation(byte: u8) -> bool {
    byte & 0xC0 == 0x80
}

/// Index of coincidence: the chance that two letters picked at random are the same.
fn index_of_coincidence(counts: &[u32; 26], total: usize) -> f64 {
    if total < 2 {
        return 0.0;
    }
    let pairs: u64 = counts
        .iter()
        .map(|&n| u64::from(n) * u64::from(n.saturating_sub(1)))
        .sum();
    pairs as f64 / (total as f64 * (total - 1) as f64)
}

/// The [`KEY_LENGTHS_SEARCHED`] key lengths, from [`MIN_KEY_LENGTH`] to [`MAX_KEY_LENGTH`]
/// and at most a [`MIN_LETTERS_PER_KEY_LETTER`]th of the text, whose columns (the letters
/// that one key letter decrypts) have the highest average index of coincidence. A column
/// of the right length is a Caesar shift of English, with English's index of
/// coincidence; a wrong one mixes several shifts and has a lower one. Shorter lengths
/// come first on ties.
fn likely_key_lengths(letters: &[usize]) -> Vec<usize> {
    let longest = MAX_KEY_LENGTH.min(letters.len() / MIN_LETTERS_PER_KEY_LETTER);
    let mut lengths: Vec<(f64, usize)> = (MIN_KEY_LENGTH..=longest)
        .map(|length| (mean_column_coincidence(letters, length), length))
        .collect();
    // A stable sort, so ties keep the shorter length first
    lengths.sort_by(|a, b| b.0.total_cmp(&a.0));
    lengths
        .into_iter()
        .take(KEY_LENGTHS_SEARCHED)
        .map(|(_, length)| length)
        .collect()
}

/// The average index of coincidence of the `length` columns of `letters`.
fn mean_column_coincidence(letters: &[usize], length: usize) -> f64 {
    let total: f64 = (0..length)
        .map(|column| {
            let mut counts = [0u32; 26];
            let mut size = 0;
            for &letter in letters[column..].iter().step_by(length) {
                counts[letter] += 1;
                size += 1;
            }
            index_of_coincidence(&counts, size)
        })
        .sum();
    total / length as f64
}

/// Gate 7: whether, from [`VIGENERE_GATE_LETTERS`] letters on, the columns of `letters`
/// for a key of `length` letters fit English letter frequencies so much better as Caesar
/// shifts (Vigenère) than as reflected shifts (Beaufort) that the text is a Vigenère
/// ciphertext, which the Vigenère decoder cracks. See [`VIGENERE_PREFERENCE_SCALE`].
fn looks_like_vigenere(letters: &[usize], length: usize) -> bool {
    letters.len() >= VIGENERE_GATE_LETTERS
        && reflection_preference(letters, length)
            < -VIGENERE_PREFERENCE_SCALE / (letters.len() as f64).sqrt()
}

/// How much better, in nats per letter, the columns of `letters` for a key of `length`
/// letters fit English letter frequencies as reflected shifts, `k − c` (Beaufort), than
/// as Caesar shifts, `c − k` (Vigenère), each with its best key letter. Positive for
/// Beaufort ciphertexts, negative for Vigenère ones, near 0 for random letters.
fn reflection_preference(letters: &[usize], length: usize) -> f64 {
    let log_freqs = ENGLISH_FREQS.map(f64::ln);
    let mut total = 0.0;
    for column in 0..length {
        let mut counts = [0u32; 26];
        for &letter in letters[column..].iter().step_by(length) {
            counts[letter] += 1;
        }
        let mut best_reflected = f64::NEG_INFINITY;
        let mut best_shifted = f64::NEG_INFINITY;
        for key in 0..26 {
            let mut reflected = 0.0;
            let mut shifted = 0.0;
            for (cipher, &count) in counts.iter().enumerate() {
                let count = f64::from(count);
                reflected += count * log_freqs[(key + 26 - cipher) % 26];
                shifted += count * log_freqs[(cipher + 26 - key) % 26];
            }
            best_reflected = best_reflected.max(reflected);
            best_shifted = best_shifted.max(shifted);
        }
        total += best_reflected - best_shifted;
    }
    total / letters.len().max(1) as f64
}

/// The Beaufort key, as 0 to 25, for a key the Vigenère key search found on the Atbash
/// of the text. `None` if a key position has no letter (the search leaves a space when a
/// column has no letter pairs to score).
fn from_vigenere_key(vigenere_key: &str) -> Option<Vec<u8>> {
    vigenere_key
        .bytes()
        .map(|byte| byte.is_ascii_uppercase().then(|| 25 - (byte - b'A')))
        .collect()
}

/// The shortest key that repeats to `key`: `LEMON` for `LEMONLEMON`. Both decrypt every
/// text the same way.
fn primitive_period(key: &[u8]) -> &[u8] {
    (1..key.len())
        .filter(|&period| key.len().is_multiple_of(period))
        .find(|&period| {
            key.iter()
                .zip(key.iter().cycle().skip(period))
                .all(|(a, b)| a == b)
        })
        .map_or(key, |period| &key[..period])
}

/// `key`, as 0 to 25, in capitals.
fn key_string(key: &[u8]) -> String {
    key.iter()
        .map(|&letter| char::from(b'A' + letter))
        .collect()
}

/// Sorts `(score, key)` pairs best first, keeping the order of ties.
fn sort_best_first(keys: &mut [(f32, Vec<u8>)]) {
    keys.sort_by(|a, b| b.0.total_cmp(&a.0));
}

/// Beaufort with key letter `key` on `letter`, both 0 to 25. It encrypts and decrypts.
fn beaufort(key: u8, letter: u8) -> u8 {
    (key + 26 - letter) % 26
}

/// Decrypts (or encrypts: Beaufort is its own inverse) `text` with `key`. ASCII letters
/// are decrypted with the key's letters in turn and keep their case; everything else is
/// copied and uses up no key letter. Letters of the key may be in either case and
/// anything else in it is ignored; a key without letters leaves the text as it is.
pub(crate) fn decrypt(text: &str, key: &str) -> String {
    let shifts: Vec<u8> = key
        .bytes()
        .filter(u8::is_ascii_alphabetic)
        .map(|byte| byte.to_ascii_uppercase() - b'A')
        .collect();
    if shifts.is_empty() {
        return text.to_string();
    }
    let mut next = 0;
    text.chars()
        .map(|c| {
            if !c.is_ascii_alphabetic() {
                return c;
            }
            let base = if c.is_ascii_uppercase() { b'A' } else { b'a' };
            let shift = shifts[next % shifts.len()];
            next += 1;
            char::from(base + beaufort(shift, c as u8 - base))
        })
        .collect()
}

/// Scores Beaufort keys for one ciphertext by the English quadgrams of their decryptions.
struct Scorer {
    /// The ciphertext's ASCII letters as 0 to 25. At least [`MIN_LETTERS`] of them.
    cipher: Vec<u8>,
    /// log10 probability of every quadgram, see `QUADGRAMS`.
    table: &'static [f32],
}

impl Scorer {
    /// A scorer for the letters `cipher`, at least four of them.
    fn new(cipher: Vec<u8>) -> Scorer {
        Scorer {
            cipher,
            table: &QUADGRAMS,
        }
    }

    /// The number of quadgrams in the text.
    fn quadgrams(&self) -> usize {
        self.cipher.len() - 3
    }

    /// The letters decrypted with `key`.
    fn decrypt(&self, key: &[u8]) -> Vec<u8> {
        self.cipher
            .iter()
            .zip(key.iter().cycle())
            .map(|(&letter, &key)| beaufort(key, letter))
            .collect()
    }

    /// The key's score: the mean log10 probability of the quadgrams of its decryption,
    /// less the key length per quadgram.
    fn score(&self, key: &[u8]) -> f32 {
        let quadgrams = self.quadgrams() as f64;
        ((self.total(&self.decrypt(key)) - key.len() as f64) / quadgrams) as f32
    }

    /// The sum of the log10 probabilities of every quadgram of `plain`.
    fn total(&self, plain: &[u8]) -> f64 {
        let mut index = 0;
        let mut sum = 0.0;
        for (i, &letter) in plain.iter().enumerate() {
            index = index % QUADGRAMS_PER_LETTER * 26 + usize::from(letter);
            if i >= 3 {
                sum += f64::from(self.table[index]);
            }
        }
        sum
    }

    /// Improves `key` a letter at a time: for each position, the letter whose decryption
    /// has the best quadgram score, for up to [`REFINE_ROUNDS`] rounds over the key or
    /// until a round changes nothing. The Vigenère key search picks each letter from the
    /// pairs of letters next to it, which on short texts gets a few of them wrong;
    /// quadgrams of the whole text tell them apart.
    fn refine(&self, key: &mut [u8]) {
        let length = key.len();
        let mut plain = self.decrypt(key);
        for _ in 0..REFINE_ROUNDS {
            let mut changed = false;
            for (position, key_letter) in key.iter_mut().enumerate() {
                let current = *key_letter;
                let mut best = (self.around(&plain, position, length), current);
                for letter in (0..26).filter(|&letter| letter != current) {
                    self.set_column(&mut plain, position, length, letter);
                    let score = self.around(&plain, position, length);
                    if score > best.0 {
                        best = (score, letter);
                    }
                }
                self.set_column(&mut plain, position, length, best.1);
                if best.1 != current {
                    *key_letter = best.1;
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
    }

    /// Decrypts the letters at key position `position` of a key of `length` letters in
    /// `plain` with the key letter `key`.
    fn set_column(&self, plain: &mut [u8], position: usize, length: usize, key: u8) {
        let column = plain[position..].iter_mut().step_by(length);
        for (plain, &letter) in column.zip(self.cipher[position..].iter().step_by(length)) {
            *plain = beaufort(key, letter);
        }
    }

    /// The sum of the log10 probabilities of the quadgrams of `plain` that contain a letter
    /// at key position `position` of a key of `length` letters: the ones that change when
    /// that key letter does. With a key of fewer than four letters that is all of them.
    fn around(&self, plain: &[u8], position: usize, length: usize) -> f64 {
        if length < 4 {
            return self.total(plain);
        }
        let last = plain.len() - 4;
        let mut sum = 0.0;
        // The quadgram starting at `start` has the letter at `start + offset`
        for offset in 0..4 {
            let mut start = (position + length - offset) % length;
            while start <= last {
                let quadgram = &plain[start..start + 4];
                let index = quadgram
                    .iter()
                    .fold(0, |index, &letter| index * 26 + usize::from(letter));
                sum += f64::from(self.table[index]);
                start += length;
            }
        }
        sum
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkers::{
        athena::Athena,
        checker_result::CheckResult,
        checker_type::{Check, Checker},
    };

    // Test vectors from the implementation plan in
    // https://github.com/bee-san/Ciphey/issues/1002. The ciphertexts were made with a
    // case-preserving Beaufort and match, on their letters, pycipher 0.5.2
    // `Beaufort(key).encipher` (round-tripped with `Beaufort.decipher`) and secretpy 0.12
    // `Beaufort().encrypt`; `vectors_match_their_keys` re-encrypts them.

    /// The decoder benchmarks' medium plaintext.
    const LIGHTHOUSE: &str =
        "Meet me at the old lighthouse after midnight and bring the map, the key and a torch.";
    /// [`LIGHTHOUSE`] with the key LEMON.
    const LEMON_CIPHERTEXT: &str =
        "Zaiv bh et vgh qbl cdyfvgxkuk nglix bdbzghel mbk knebh sxi cnw, lfk dhg mbk l lyxle.";

    /// No punctuation, key SECRET.
    const SECRET_PLAINTEXT: &str =
        "Defend the east wall of the castle at dawn and hold it until the relief column arrives";
    /// [`SECRET_PLAINTEXT`] with the key SECRET.
    const SECRET_CIPHERTEXT: &str =
        "Paxnrq zxy nebz icgt fn lvn ctalrn ea pege egp xogb lz kpywi zxy aaikax pqiysp rnckjyz"; // codespell:ignore pege

    /// Key CASTLE.
    const CASTLE_PLAINTEXT: &str = "Defend the east wall of the castle at dawn and hold it until the relief column arrives, then fall back to the keep.";
    /// [`CASTLE_PLAINTEXT`] with the key CASTLE.
    const CASTLE_CIPHERTEXT: &str = "Zwnpyb jto plmj esia qx hlp jekhhp ll zawg lrz teii wj gfadt jto chtuwn rxtiof tunufob, sxyn ntat baqj sq jto jhan.";

    /// The 174-letter Dickens text the monoalphabetic substitution tests use.
    const DICKENS: &str = "It was the best of times, it was the worst of times, it was the age of wisdom, it was the age of foolishness, it was the epoch of belief, it was the epoch of incredulity, it was the season of Light, it was the season of Darkness";
    /// [`DICKENS`] with the key CIPHEY.
    const CIPHEY_CIPHERTEXT: &str = "Up thm fve odmf od wzsuk, aw leg jbl lqhkp bc lqqex, zl ccq waa ywe bc iqkfbv, wf gix oxu ccl tz touezmrpexp, wf gix oxu ytbfx kx hlwwux, aw leg jbl dpkab bc wlarleknupr, zl ccq waa gyixtr kx Xhbxf, up thm fve xdegov bc Bylycdmg";

    /// [`DICKENS`] without spaces or punctuation, in capitals.
    const DICKENS_UNSPACED: &str = "ITWASTHEBESTOFTIMESITWASTHEWORSTOFTIMESITWASTHEAGEOFWISDOMITWASTHEAGEOFFOOLISHNESSITWASTHEEPOCHOFBELIEFITWASTHEEPOCHOFINCREDULITYITWASTHESEASONOFLIGHTITWASTHESEASONOFDARKNESS";
    /// [`DICKENS_UNSPACED`] with the key CIPHEY.
    const CIPHEY_UNSPACED: &str = "UPTHMFVEODMFODWZSUKAWLEGJBLLQHKPBCLQQEXZLCCQWAAYWEBCIQKFBVWFGIXOXUCCLTZTOUEZMRPEXPWFGIXOXUYTBFXKXHLWWUXAWLEGJBLDPKABBCWLARLEKNUPRZLCCQWAAGYIXTRKXXHBXFUPTHMFVEXDEGOVBCBYLYCDMG";

    /// The decoder benchmarks' long plaintext.
    const LONG_PLAINTEXT: &str = "Ciphey is an automated decoding tool. You give it encrypted or encoded text and it tries to work out what was done to it, without you having to know the key or even the cipher. It searches through many possible decodings, checks each candidate to see whether it looks like English or matches a known pattern such as an email address, and stops when it finds something that reads like plaintext. Most of the time this takes less than a second, which makes it handy for capture the flag challenges, puzzle hunts and for anyone who stumbles across a strange string in a log file.";
    /// [`LONG_PLAINTEXT`] with the key FORTIFICATION.
    const FORTIFICATION_CIPHERTEXT: &str = "Dgcmeh ak ag iuurcraec fyyffgaz vdfx. Hui ulnk fm kerrhtjwq ux jsmdqec pyda ibk xv ycabq jm xuxd ruy xbfp gab faab vd lp, jajtfov pru ktnxvw hf ybzj vkp ybk oj pnka mhn raqbyj. Lp wjfxpmen pvjfoig toev trqkssxk kbmdqasck, ymemdn krrb dipxlfoub vd beb mvwabkw xv gfuvq rsje Kazdjbb rr qaaghjn o hgujv naapkws wxrb fq cn pwofu ooqrbqk, agf wurzz xbbv uh oabkn wdhembunn phnm xntfn xuqp tdnxbyplm. Woia uj uyk ylwb pvsb podbw gpqn pvag i wjdaeq, myaat hiejn gy misfe vfr mnqvxce mby viii lyogiescyi, eopouk kzvmq cnq daw fbtfvb mvm bpubednb idroib i wuooene nplsgc ga f ddn dxxy.";

    /// The issue's example, from pycipher 0.5.2 `Beaufort('FORTIFICATION')`: 28 letters
    /// for a 13-letter key, too few to find it.
    const ISSUE_CIPHERTEXT: &str = "CKMPVCPVWPIWUJOGIUAPVWRIWUUK";
    /// The plaintext of [`ISSUE_CIPHERTEXT`].
    const ISSUE_PLAINTEXT: &str = "DEFENDTHEEASTWALLOFTHECASTLE";

    /// The atbash decoder benchmarks' medium input: Beaufort with the key Z.
    const ATBASH_CIPHERTEXT: &str =
        "Nvvg nv zg gsv low ortsgslfhv zugvi nrwmrtsg zmw yirmt gsv nzk, gsv pvb zmw z glixs.";
    /// Beaufort with the key D, which is Affine with a = 25, b = 3.
    const KEY_D_CIPHERTEXT: &str =
        "Rzzk rz dk kwz psa svxwkwpjlz dykzm rvaqvxwk dqa cmvqx kwz rdo, kwz tzf dqa d kpmbw.";

    /// The Vigenère decoder benchmarks' inputs (keys KEY and LEMON).
    const VIGENERE_MEDIUM: &str =
        "Wicd qc kx rri mvh jskfdlmewc kjrov kshlskfd eln fpsre dlc wen, dlc uiw krb k xmbgf.";
    /// See [`VIGENERE_MEDIUM`].
    const VIGENERE_LONG: &str = "Nmbvrj me oa lyfczlxqr qpgarvyk fcbw. Cai ttzq wg proflaxqr bc izqboip hrix mbq tx ffvpw fc jzvw che atog hee rbyi fc ve, auhuzyf mbf lmjvyk fc xysi hup oqm bc ihsa elq qvalqf. Ve wqoenlqg gsvaits qmbl asegvmpq rrnspwarw, ovrnoe snnl ooaompogp xa grp atsgsid wg wsayf wmws Rykxwfs sd anegtsf l ozcjy tmhgpvz ghnl mg ny iyovw eprepwe, oao wfccd atsa tx rwaow eczpxtwar xtog cimrf wmws cweubgpbf. Abdx at gsi fwzp xtwf eewsf wieg gsez o fpgabq, hluqu xewsf tx toaoc rce nebhhci fvr qpmu psexzrykqg, cfdlzr syzhf lrp tbc ezmbyi ivb dxgaowie opcseg n dxdoari ehetrs wa l pau stpq.";

    /// The decoder benchmarks' `miss` input.
    const MISS: &str =
        "T00 l3= ox+#G WKyV pajU6j qxH@ %B4+a 5Pn^ 7p_v1q 9sLvu *+36i R5rL&3 mVJZI iO0 Ut8_m COTV";

    /// The Autokey test vector of https://github.com/bee-san/Ciphey/issues/1003.
    const AUTOKEY: &str =
        "Wicf qi tf xhx hsh ztjsbnvnzs uxxew fmuzqjub guw belox buk fht, fht dlc krb a grrvv.";

    /// The search benchmarks' Base64 input.
    const BASE64: &str = "TWVldCBtZSBhdCB0aGUgb2xkIGxpZ2h0aG91c2UgYWZ0ZXIgbWlkbmlnaHQgYW5kIGJyaW5nIHRoZSBtYXAsIHRoZSBrZXkgYW5kIGEgdG9yY2gu";

    /// Base64 of Baudot code (tests/baudot_decoder.rs): 87 letters and one `=`, so only
    /// its changes of case give it away. The checker accepted a decryption of it once.
    const BASE64_OF_DIGITS: &str =
        "MTAxMDAgMDAwMDEgMTAwMTAgMTAwMTAgMTEwMDAgMDAxMDAgMTAwMTEgMTEwMDAgMDEwMTAgMTAwMTAgMDEwMDE=";

    /// Every vector the cracker solves: (ciphertext, key, plaintext).
    const SOLVED: [(&str, &str, &str); 6] = [
        (LEMON_CIPHERTEXT, "LEMON", LIGHTHOUSE),
        (SECRET_CIPHERTEXT, "SECRET", SECRET_PLAINTEXT),
        (CASTLE_CIPHERTEXT, "CASTLE", CASTLE_PLAINTEXT),
        (CIPHEY_CIPHERTEXT, "CIPHEY", DICKENS),
        (CIPHEY_UNSPACED, "CIPHEY", DICKENS_UNSPACED),
        (FORTIFICATION_CIPHERTEXT, "FORTIFICATION", LONG_PLAINTEXT),
    ];

    fn athena() -> CheckerTypes {
        CheckerTypes::CheckAthena(Checker::<Athena>::new())
    }

    /// Runs `crack` with the Athena checker.
    fn crack(text: &str) -> CrackResult {
        Decoder::<BeaufortDecoder>::new().crack(text, &athena())
    }

    /// `x` with every ASCII letter Caesar-shifted by `shift`.
    fn caesar(text: &str, shift: u8) -> String {
        text.chars()
            .map(|c| match c {
                'a'..='z' => char::from(b'a' + (c as u8 - b'a' + shift) % 26),
                'A'..='Z' => char::from(b'A' + (c as u8 - b'A' + shift) % 26),
                other => other,
            })
            .collect()
    }

    #[test]
    fn vectors_match_their_keys() {
        for (ciphertext, key, plaintext) in SOLVED {
            assert_eq!(decrypt(ciphertext, key), plaintext, "{key}");
            // Beaufort is its own inverse
            assert_eq!(decrypt(plaintext, key), ciphertext, "{key}");
        }
        assert_eq!(decrypt(ISSUE_CIPHERTEXT, "FORTIFICATION"), ISSUE_PLAINTEXT);
        assert_eq!(decrypt(ATBASH_CIPHERTEXT, "Z"), LIGHTHOUSE);
        assert_eq!(decrypt(KEY_D_CIPHERTEXT, "D"), LIGHTHOUSE);
    }

    #[test]
    fn cracks_every_vector() {
        for (ciphertext, key, plaintext) in SOLVED {
            let result = crack(ciphertext);
            assert!(result.success, "{key}: {:?}", result.unencrypted_text);
            assert_eq!(
                result.unencrypted_text,
                Some(vec![plaintext.to_string()]),
                "{key}"
            );
            assert_eq!(result.key.as_deref(), Some(key));
            assert_eq!(result.decoder, "Beaufort");
        }
    }

    #[test]
    fn finds_every_key_first() {
        for (ciphertext, key, _) in SOLVED {
            let keys = rank_keys(ciphertext);
            assert_eq!(
                keys.first().map(|(_, found)| found.as_str()),
                Some(key),
                "{keys:?}"
            );
        }
    }

    #[test]
    fn unspaced_text_is_checked_with_medium_sensitivity() {
        // Athena at Low doesn't accept the unspaced plaintext, at Medium it does
        let low = athena().with_sensitivity(Sensitivity::Low);
        let medium = athena().with_sensitivity(Sensitivity::Medium);
        assert!(!low.check(DICKENS_UNSPACED).is_identified);
        assert!(medium.check(DICKENS_UNSPACED).is_identified);
        assert!(crack(CIPHEY_UNSPACED).success);
    }

    #[test]
    fn issue_example_decrypts_with_its_key_but_is_too_short_to_crack() {
        assert_eq!(decrypt(ISSUE_CIPHERTEXT, "FORTIFICATION"), ISSUE_PLAINTEXT);
        assert_eq!(decrypt(ISSUE_PLAINTEXT, "fortification"), ISSUE_CIPHERTEXT);
        let result = crack(ISSUE_CIPHERTEXT);
        assert!(!result.success, "{:?}", result.unencrypted_text);
    }

    #[test]
    fn fails_without_panicking() {
        let rot13 = caesar(LIGHTHOUSE, 13);
        for text in [
            "",
            "😀",
            "hello world",
            "12345!@#$%",
            MISS,
            LIGHTHOUSE,
            &rot13,
            VIGENERE_MEDIUM,
            VIGENERE_LONG,
            ATBASH_CIPHERTEXT,
            KEY_D_CIPHERTEXT,
            AUTOKEY,
            BASE64,
            BASE64_OF_DIGITS,
        ] {
            let result = crack(text);
            assert!(!result.success, "{text:?}");
            assert_eq!(result.unencrypted_text, None, "{text:?}");
            assert_eq!(result.key, None, "{text:?}");
        }
    }

    #[test]
    fn rejects_other_formats_at_the_gates() {
        let hex = "4d656574206d6520617420746865206f6c64206c69676874686f757365";
        for text in [
            "",
            "😀",
            "hello world",
            "12345!@#$%",
            MISS,
            BASE64,
            BASE64_OF_DIGITS,
            hex,
        ] {
            assert!(!passes_gates(text), "{text:?}");
        }
        // English of 100 letters or more has too high an index of coincidence, and so do
        // its Caesar, Atbash and Affine encryptions
        assert!(!passes_gates(DICKENS));
        assert!(!passes_gates(&caesar(DICKENS, 3)));
        assert!(!passes_gates(LONG_PLAINTEXT));
        // Shorter English has English letter frequencies, and so do its transpositions
        let reversed: String = LIGHTHOUSE.chars().rev().collect();
        for text in [LIGHTHOUSE, &reversed, DICKENS_UNSPACED] {
            let (counts, letters) = letter_counts(text);
            assert!(english_letter_log_prob(&counts, letters) > MAX_ENGLISH_LETTER_LOG_PROB);
            assert!(!passes_gates(text), "{text:?}");
        }
        // Every vector passes them
        for (ciphertext, key, _) in SOLVED {
            assert!(passes_gates(ciphertext), "{key}");
        }
    }

    #[test]
    fn leaves_caesar_atbash_and_affine_to_their_decoders() {
        // Shorter than 100 letters, so their index of coincidence doesn't give them away,
        // but a Caesar, Atbash or Affine key turns them into English letter pairs
        let rot13 = caesar(LIGHTHOUSE, 13);
        for text in [rot13.as_str(), ATBASH_CIPHERTEXT, KEY_D_CIPHERTEXT] {
            let (counts, letters) = letter_counts(text);
            assert!(letters < IOC_GATE_LETTERS);
            assert!(english_letter_log_prob(&counts, letters) <= MAX_ENGLISH_LETTER_LOG_PROB);
            assert!(reads_as_affine_english(text), "{text:?}");
            assert!(!passes_gates(text), "{text:?}");
        }
        // No such key reads a Beaufort ciphertext as English
        for (ciphertext, key, _) in SOLVED {
            assert!(!reads_as_affine_english(ciphertext), "{key}");
        }
        // Should one get through anyway, the key search finds Z and D, keys of one
        // letter, and drops them
        for text in [ATBASH_CIPHERTEXT, KEY_D_CIPHERTEXT] {
            assert!(search_keys(text).is_empty(), "{:?}", search_keys(text));
        }
    }

    #[test]
    fn leaves_long_vigenere_to_the_vigenere_decoder() {
        // The Vigenère benchmarks' long input passes the gates, but its columns read as
        // Caesar shifts of English, not as reflected ones
        assert!(passes_gates(VIGENERE_LONG));
        let letters = cipher_letters(VIGENERE_LONG);
        let length = likely_key_lengths(&letters)[0];
        assert!(reflection_preference(&letters, length) < -0.1);
        assert!(looks_like_vigenere(&letters, length));
        assert!(search_keys(VIGENERE_LONG).is_empty());
        // Every Beaufort vector of 100 letters or more leans the other way
        for (ciphertext, key, _) in SOLVED {
            let letters = cipher_letters(ciphertext);
            if letters.len() < VIGENERE_GATE_LETTERS {
                continue;
            }
            let length = likely_key_lengths(&letters)[0];
            assert!(reflection_preference(&letters, length) > 0.0, "{key}");
            assert!(!looks_like_vigenere(&letters, length), "{key}");
        }
        // Too short to tell
        let letters = cipher_letters(VIGENERE_MEDIUM);
        assert!(!looks_like_vigenere(&letters, 3));
    }

    /// The letter counts and the number of ASCII letters of `text`.
    fn letter_counts(text: &str) -> ([u32; 26], usize) {
        let mut counts = [0u32; 26];
        let letters = cipher_letters(text);
        for &letter in &letters {
            counts[letter] += 1;
        }
        (counts, letters.len())
    }

    #[test]
    fn gates_count_characters_not_bytes() {
        // 20 letters and one other character are allowed (12 letters per other), however
        // many bytes it takes: 'é' is two, '€' three and '😀' four
        for other in ['!', 'é', '€', '😀'] {
            let text = format!("abcdefghij{other}klmnopqrst");
            assert!(passes_gates(&text), "{text:?}");
            // ...but not two of them, until there are 24 letters
            let text = format!("abcdefghij{other}klmnopqrst{other}");
            assert!(!passes_gates(&text), "{text:?}");
            let text = format!("abcdefghij{other}klmnopqrstuvwx{other}");
            assert!(passes_gates(&text), "{text:?}");
        }
        // Whitespace doesn't count
        assert!(passes_gates("abcde fghij\tklmno\npqrst \r\n"));
        assert!(!passes_gates("abcdefghijklmnopqrs"));
        assert_eq!(index_of_coincidence(&[0; 26], 0), 0.0);
    }

    #[test]
    fn rejects_changes_of_case_inside_words() {
        // Base64 changes from lower to upper case about one letter pair in four
        assert!(!passes_gates(BASE64_OF_DIGITS));
        let letters_only: String = BASE64_OF_DIGITS.replace('=', "");
        assert!(!passes_gates(&letters_only));
        // English names and acronyms are fine, and so is text in capitals or without
        // spaces
        assert!(passes_gates(LEMON_CIPHERTEXT));
        assert!(passes_gates(&LEMON_CIPHERTEXT.replace("Zaiv", "ZaIv")));
        assert!(passes_gates(CIPHEY_UNSPACED));
        assert!(passes_gates(&CIPHEY_UNSPACED.to_ascii_lowercase()));
        // Too few pairs to tell: 20 letters are 19 pairs
        assert!(passes_gates("aBcDeFgHiJkLmNoPqRsT"));
        assert!(!passes_gates("aBcDeFgHiJkLmNoPqRsTu"));
    }

    #[test]
    fn checks_at_most_three_decryptions() {
        // Even when the checker accepts nothing, it is asked at most MAX_CHECKED times
        let texts = [
            LEMON_CIPHERTEXT,
            SECRET_CIPHERTEXT,
            CIPHEY_UNSPACED,
            FORTIFICATION_CIPHERTEXT,
            LIGHTHOUSE,
            VIGENERE_LONG,
            AUTOKEY,
            ISSUE_CIPHERTEXT,
        ];
        for text in texts {
            let mut calls = 0;
            let outcome = solve(text, rank_keys(text), &mut |_| -> Option<()> {
                calls += 1;
                None
            });
            assert!(calls <= MAX_CHECKED, "{calls} calls for {text:?}");
            assert!(rank_keys(text).len() <= MAX_CHECKED, "{text:?}");
            assert!(!matches!(outcome, Outcome::Confirmed { .. }));
        }
    }

    #[test]
    fn stops_at_the_first_accepted_decryption() {
        let mut calls = 0;
        let keys = rank_keys(LEMON_CIPHERTEXT);
        let outcome = solve(LEMON_CIPHERTEXT, keys, &mut |plaintext| {
            calls += 1;
            (plaintext == LIGHTHOUSE).then_some(())
        });
        assert_eq!(calls, 1);
        assert!(matches!(
            outcome,
            Outcome::Confirmed { ref key, .. } if key == "LEMON"
        ));
    }

    #[test]
    fn returns_the_best_decryption_unconfirmed() {
        // When the checker accepts nothing, the best decryption is returned if it reads
        // like English, so the search can decode it further
        let keys = rank_keys(FORTIFICATION_CIPHERTEXT);
        let outcome = solve(FORTIFICATION_CIPHERTEXT, keys, &mut |_| -> Option<
            CheckResult,
        > { None });
        match outcome {
            Outcome::Unconfirmed { plaintext, key } => {
                assert_eq!(plaintext, LONG_PLAINTEXT);
                assert_eq!(key, "FORTIFICATION");
            }
            _ => panic!("expected an unconfirmed decryption"),
        }
    }

    #[test]
    fn keeps_case_and_non_letters() {
        // Non-ASCII letters are copied and don't use up a key letter. Checked with the
        // case-preserving Beaufort the vectors were checked with.
        let plaintext = "Café, Öl and 42 émigrés: done!";
        let ciphertext = decrypt(plaintext, "KEY");
        assert_eq!(ciphertext, "Ieté, Öz elh 42 ésqenég: hqlg!");
        assert_eq!(decrypt(&ciphertext, "key"), plaintext);
        assert_eq!(decrypt("", "KEY"), "");
        assert_eq!(decrypt("Text", ""), "Text");
        assert_eq!(decrypt("Text", "12"), "Text");
    }

    #[test]
    fn cracks_text_with_non_ascii_letters() {
        let plaintext = LIGHTHOUSE.replace("old", "öld café");
        let result = crack(&decrypt(&plaintext, "LEMON"));
        assert!(result.success);
        assert_eq!(result.unencrypted_text, Some(vec![plaintext]));
        assert_eq!(result.key.as_deref(), Some("LEMON"));
    }

    #[test]
    fn hex_decoded_latin1_does_not_panic() {
        // What the hexadecimal decoder can hand on: Latin-1 characters from bytes that
        // aren't UTF-8 (https://github.com/bee-san/ciphey/issues/908). Rejected at the
        // gates on their own, and skipped by the key search among enough letters.
        let latin1 = "'V&ÖWæõVg\u{96}f";
        assert!(!crack(latin1).success);
        let text = format!("{LEMON_CIPHERTEXT} ÖVæ\u{96}f");
        assert!(passes_gates(&text));
        let keys = rank_keys(&text);
        assert_eq!(keys.first().map(|(_, key)| key.as_str()), Some("LEMON"));
    }

    #[test]
    fn primitive_period_of_keys() {
        assert_eq!(primitive_period(b"LEMONLEMON"), b"LEMON");
        assert_eq!(primitive_period(b"ZZ"), b"Z");
        assert_eq!(primitive_period(b"ABAB"), b"AB");
        assert_eq!(primitive_period(b"ABABA"), b"ABABA");
        assert_eq!(primitive_period(b"ABCABD"), b"ABCABD");
        assert_eq!(primitive_period(b"Q"), b"Q");
        assert_eq!(primitive_period(b""), b"");
    }

    #[test]
    fn vigenere_keys_turn_into_beaufort_keys() {
        // Atbash of each letter, and nothing for a key position without a letter
        assert_eq!(from_vigenere_key("AZ"), Some(vec![25, 0]));
        assert_eq!(from_vigenere_key("A Z"), None);
        let atbash: Vec<usize> = cipher_letters(LEMON_CIPHERTEXT)
            .into_iter()
            .map(|letter| 25 - letter)
            .collect();
        let key = from_vigenere_key(&break_vigenere_letters(&atbash, 5)).unwrap();
        // The Vigenère key search gets one letter wrong on 66 letters...
        assert_ne!(key_string(&key), "LEMON");
        // ...which refining fixes
        let scorer = Scorer::new(
            cipher_letters(LEMON_CIPHERTEXT)
                .iter()
                .map(|&l| l as u8)
                .collect(),
        );
        let mut refined = key;
        scorer.refine(&mut refined);
        assert_eq!(key_string(&refined), "LEMON");
    }

    #[test]
    fn refining_scores_only_the_quadgrams_that_change() {
        // `around` must agree with re-scoring the whole text
        let scorer = Scorer::new(
            cipher_letters(CASTLE_CIPHERTEXT)
                .iter()
                .map(|&l| l as u8)
                .collect(),
        );
        for length in [2, 3, 4, 5, 6, 9, 13] {
            let key: Vec<u8> = (0..length as u8).map(|i| (i * 7 + 3) % 26).collect();
            for position in 0..length {
                let mut plain = scorer.decrypt(&key);
                let before_total = scorer.total(&plain);
                let before = scorer.around(&plain, position, length);
                scorer.set_column(&mut plain, position, length, (key[position] + 11) % 26);
                let delta_total = scorer.total(&plain) - before_total;
                let delta = scorer.around(&plain, position, length) - before;
                assert!(
                    (delta_total - delta).abs() < 1e-6,
                    "length {length}, position {position}: {delta_total} vs {delta}"
                );
            }
        }
    }

    #[test]
    fn likely_key_lengths_rank_the_true_length_first() {
        let letters = cipher_letters(FORTIFICATION_CIPHERTEXT);
        let lengths = likely_key_lengths(&letters);
        assert_eq!(lengths.len(), KEY_LENGTHS_SEARCHED);
        assert_eq!(lengths[0], 13, "{lengths:?}");
        // At most a sixth of the text
        let letters = cipher_letters("abcdefghijklmnopqrstuvwxyz");
        assert_eq!(likely_key_lengths(&letters), [2, 3, 4]);
        // No key lengths at all for fewer than 12 letters
        assert!(likely_key_lengths(&cipher_letters("abcdefghijk")).is_empty());
    }

    #[test]
    fn is_registered_once() {
        let decoders = crate::filtration_system::get_decoder_by_name("Beaufort");
        assert_eq!(decoders.components.len(), 1);
        let decoder = &decoders.components[0];
        assert_eq!(decoder.get_name(), "Beaufort");
        assert_eq!(
            decoder.get_tags(),
            &vec![
                "beaufort",
                "vigenere",
                "substitution",
                "classical",
                "reciprocal"
            ]
        );
        assert!(!decoder.get_tags().contains(&"decoder"));
        assert_eq!(decoder.get_popularity(), 0.4);
        assert_eq!(
            decoder.get_link(),
            "https://en.wikipedia.org/wiki/Beaufort_cipher"
        );
        assert!(crate::decoders::DECODER_MAP.contains_key("Beaufort"));
    }

    #[test]
    fn comes_before_vigenere_in_the_search() {
        // When both find plaintext in the same step, the search keeps this order
        let decoders = crate::filtration_system::get_all_decoders();
        let names: Vec<&str> = decoders
            .components
            .iter()
            .map(|decoder| decoder.get_name())
            .collect();
        let beaufort = names.iter().position(|&name| name == "Beaufort");
        let vigenere = names.iter().position(|&name| name == "Vigenere");
        assert!(beaufort.is_some() && beaufort < vigenere, "{names:?}");
    }
}
