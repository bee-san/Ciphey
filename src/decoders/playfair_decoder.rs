//! Cracks the Playfair cipher, which encrypts pairs of letters with a 5×5 key square of
//! the 25 letters A to Z without J (J is written as I).
//!
//! The plaintext is reduced to its letters, upper case with J as I, and split into
//! pairs. An X goes between the two letters of a pair that would be the same (a Z if
//! they are Xs), and pads a final single letter. Each pair is then replaced using the
//! square: two letters in one row by the letters to their right, two letters in one
//! column by the letters below them, and otherwise by the other two corners of their
//! rectangle, each letter taking the column of the other. Decryption goes left and up
//! instead. See <https://en.wikipedia.org/wiki/Playfair_cipher>.
//!
//! Shifting the rows or the columns of a square round doesn't change what it does, so 25
//! squares decrypt the same way and there are 25!/25 ≈ 6·10²³ keys to search. The square
//! is found with simulated annealing over swaps of two letters (and now and then of two
//! rows or columns, or flips of the square), scoring each decryption by how often its
//! quadgrams (runs of four letters) occur in English, following
//! <http://practicalcryptography.com/cryptanalysis/stochastic-searching/cryptanalysis-playfair/>.
//! The quadgram counts and the dictionary are in `src/storage/ngrams/`.
//!
//! The search takes up to a second and a half and needs about 200 letters, so cheap checks
//! run first and reject, in microseconds, text that can't be Playfair ciphertext that
//! long:
//! 1. 200 to 2,000 characters, an even number of letters, at least 90% of the characters
//!    that aren't whitespace letters, and no J.
//! 2. No pair of identical letters: the encryption never makes one.
//! 3. Letter frequencies that aren't English's, as they are in plain English and in
//!    transpositions of it (reversed text, rail fence).
//! 4. An index of coincidence below English's. Playfair's is lower, while Caesar, Atbash
//!    and other substitutions keep English's.
//!
//! The plaintext comes back as the cipher leaves it: upper case, without spaces, and with
//! the X fillers, such as `HIDETHEGOLDINTHETREXESTUMP`.

use super::crack_results::CrackResult;
use super::interface::{Crack, Decoder};
use crate::checkers::checker_result::CheckResult;
use crate::checkers::CheckerTypes;
use crate::config::get_config;
use crate::storage::ENGLISH_FREQS;
use gibberish_or_not::Sensitivity;
use log::{debug, trace};
use once_cell::sync::Lazy;
use std::collections::HashSet;
use std::time::{Duration, Instant};

/// Fewer letters than this and the search rarely finds the square: a wrong square can
/// score as well as the right one, and one run of the annealing finds it in only about a
/// fifth of 200-letter texts.
const MIN_LETTERS: usize = 200;

/// Longer texts are left alone. A Playfair message is rarely this long, and the checks
/// before the search then take longer than they should for text that isn't Playfair.
const MAX_CHARS: usize = 2_000;

/// Letter J. The square has no J: it is written as I.
const J: u8 = 9;

/// Minimum [`chi_squared`] of the letter frequencies against English's. In the
/// measurements of the implementation plan (#1006), Playfair ciphertext had 1.9 or more
/// (5th percentile), and English and transpositions of it 0.41 or less (95th percentile)
/// from 80 letters up.
const MIN_CHI_SQUARED: f64 = 1.0;

/// Maximum index of coincidence. Playfair ciphertext has 0.050 (median) and 0.060 or less
/// (95th percentile); English, and Caesar, Atbash and other substitutions of it, 0.064 to
/// 0.066 (median).
const MAX_IOC: f64 = 0.065;

/// The annealing only decrypts and scores this many letters: longer texts don't need
/// more to find the square, and every evaluation decrypts all of them.
const SEARCH_LETTERS: usize = 400;

/// The starting temperature of the annealing, in log10 probability. It falls linearly
/// to 0 over a run. Of 5, 7.5, 10, 12, 15, 20 and 30, 10 found the square most often, or
/// within the noise of the best, at 200, 250, 300 and 400 letters: in 46% of the runs at
/// 300 letters, against 32% for 20.
const START_TEMPERATURE: f64 = 10.0;

/// Fitness, the average log10 probability of a decryption's quadgrams, at or above which
/// the square counts as found. In 4,560 annealing runs on 192 paragraphs of two Project
/// Gutenberg books, the runs that found the square scored -4.0 to -4.7, and all but two of
/// the others below -5.0.
const SOLVED_FITNESS: f64 = -4.8;

/// Squares one letter swap from a solution whose fitness is within this of it are
/// compared on dictionary words too (see [`prefer_words`]). The wrong squares the
/// annealing ended on scored 0.007 to 0.04 better than the right ones.
const NEAR_FITNESS: f64 = 0.05;

/// A decryption is only shown to the checker if dictionary words can cover this share of
/// its letters, as they are or with every X removed (the fillers break up words). The
/// checker reads unspaced text as one long word, and is only asked at High sensitivity.
const MIN_COVERAGE: f64 = 0.9;

/// The longest word looked for in the dictionary when measuring coverage. Longer words
/// are rare, and each extra length is another lookup at every letter.
const MAX_WORD: usize = 20;

/// log10 probability of every quadgram, indexed by [`quadgram_index`].
static QUADGRAMS: Lazy<Box<[f32]>> =
    Lazy::new(|| parse_quadgrams(include_str!("../storage/ngrams/english_quadgrams.txt")));

/// Upper-case English words.
static DICTIONARY: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    include_str!("../storage/ngrams/english_words.txt")
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect()
});

/// The Playfair cracker. Call:
/// `let decoder = Decoder::<PlayfairDecoder>::new()` to create one,
/// and `decoder.crack(text, &checker)` to crack `text`.
/// ```
/// use ciphey::decoders::playfair_decoder::PlayfairDecoder;
/// use ciphey::decoders::interface::{Crack, Decoder};
/// use ciphey::checkers::{athena::Athena, CheckerTypes, checker_type::{Check, Checker}};
///
/// let decoder = Decoder::<PlayfairDecoder>::new();
/// let checker = CheckerTypes::CheckAthena(Checker::<Athena>::new());
///
/// // 300 letters of Treasure Island, encrypted with the square of the keyword TREASURE
/// let result = decoder.crack(
///     "RGROSKIQDSTFCYCAMRIREAYRTSRETOROCPFTCEQKQEOXOPCQSRLRRPCPRGAEOPLEATRGCIKRHERPUARDIS\
///      XRMRMXAEHOSKGVYDFISTINLFRASICQIZIQXRKDPBRGROEDAWQCYDHORPUAIRORVEHOTRRPEGTSRHKSDICP\
///      HKQBFGQLGKHIRSPBRGCIDYRSHOINSGAYBTTFHOHUMENRGEKBESRWDBSGSTTATSPBRGSCNEOTETREASOGMH\
///      FHXEPCBSPNRGSISCRTINFGCAEHFTRSEVRGACXENERGCIDYRSHOEKOT",
///     &checker,
/// );
/// assert!(result.success);
/// // The fillers stay: "sudden" is SUDXDEN, "just" is IUST
/// assert!(result.unencrypted_text.unwrap()[0].starts_with("THENALLOFASUDXDENTHEREWASATREMENDOUSEXPLOSION"));
/// assert_eq!(result.key.unwrap(), "TREASUBCDFGHIKLMNOPQVWXYZ");
/// ```
pub struct PlayfairDecoder;

impl Crack for Decoder<PlayfairDecoder> {
    fn new() -> Decoder<PlayfairDecoder> {
        Decoder {
            name: "Playfair",
            description: "Playfair cipher: pairs of letters are substituted with a 5x5 key square (I and J share a cell). Recovers the square by simulated annealing scored with English quadgrams; needs about 200 letters of ciphertext and up to a second of CPU.",
            link: "https://en.wikipedia.org/wiki/Playfair_cipher",
            tags: vec!["playfair", "digraph", "substitution", "classic", "cipher"],
            popularity: 0.3,
            phantom: std::marker::PhantomData,
        }
    }

    /// Searches for the key square. On success the plaintext is the only element of
    /// `unencrypted_text`, upper case and with the X fillers, and `key` is the square, row
    /// by row (`PLAYFIREXMBCDGHKNOQSTUVWZ` for the keyword PLAYFAIR EXAMPLE). When the
    /// checker doesn't accept the decryption but it reads like English, it is returned
    /// unconfirmed, so the search can keep decoding it.
    fn crack(&self, text: &str, checker: &CheckerTypes) -> CrackResult {
        trace!("Trying Playfair with text {:?}", text);
        let mut results = CrackResult::new(self, text.to_string());
        let crib = get_config().regex.is_some();
        let mut confirm = |plaintext: &str| check(checker, plaintext);

        match crack_text(
            text,
            &Budget::DEFAULT,
            crib,
            &mut Stats::default(),
            &mut confirm,
        ) {
            Outcome::Confirmed {
                plaintext,
                key,
                check,
            } => {
                debug!("Playfair found square {key}");
                results.unencrypted_text = Some(vec![plaintext]);
                results.update_checker(&check);
                results.key = Some(key);
            }
            Outcome::Unconfirmed { plaintext, key } => {
                debug!("Playfair best guess, square {key}: {plaintext}");
                results.unencrypted_text = Some(vec![plaintext]);
                results.key = Some(key);
            }
            Outcome::Failed(reason) => {
                trace!("Playfair gave up: {reason:?}");
            }
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

/// Asks `checker` whether `plaintext`, a decryption, is plaintext. It has no word breaks,
/// so this is at High sensitivity, and only once dictionary words cover most of it.
fn check(checker: &CheckerTypes, plaintext: &str) -> Option<CheckResult> {
    let result = checker.with_sensitivity(Sensitivity::High).check(plaintext);
    result.is_identified.then_some(result)
}

/// What [`crack_text`] found. `T` is what the checker returns.
enum Outcome<T> {
    /// The checker accepted this decryption.
    Confirmed {
        /// The decryption, upper case with the fillers.
        plaintext: String,
        /// The key square, row by row.
        key: String,
        /// What the checker said.
        check: T,
    },
    /// The square decrypts to something that reads like English, but the checker didn't
    /// accept it.
    Unconfirmed {
        /// The decryption, upper case with the fillers.
        plaintext: String,
        /// The key square, row by row.
        key: String,
    },
    /// Nothing that reads like English.
    Failed(Reason),
}

/// Leaves out what the checker said, which needn't be `Debug`.
impl<T> std::fmt::Debug for Outcome<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Outcome::Confirmed { plaintext, key, .. } => f
                .debug_struct("Confirmed")
                .field("plaintext", plaintext)
                .field("key", key)
                .finish_non_exhaustive(),
            Outcome::Unconfirmed { plaintext, key } => f
                .debug_struct("Unconfirmed")
                .field("plaintext", plaintext)
                .field("key", key)
                .finish(),
            Outcome::Failed(reason) => f.debug_tuple("Failed").field(reason).finish(),
        }
    }
}

/// Why [`crack_text`] failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reason {
    /// Fewer than [`MIN_LETTERS`] letters.
    TooShort,
    /// More than [`MAX_CHARS`] characters.
    TooLong,
    /// An odd number of letters: Playfair ciphertext is pairs of letters.
    OddLength,
    /// Less than 90% of the characters that aren't whitespace are letters.
    NotLetters,
    /// A J, which the square doesn't have.
    HasJ,
    /// A pair of identical letters, which the encryption never makes.
    DoubledPair,
    /// The letters have English frequencies, so they weren't substituted.
    EnglishFrequencies,
    /// The index of coincidence is English's, as in a Caesar or other substitution.
    Coincidence,
    /// The search found no square that decrypts to English.
    NotFound,
}

/// Counters, so the tests can see how much work was done.
#[derive(Debug, Default)]
struct Stats {
    /// Annealing runs started.
    runs: u32,
    /// Squares scored.
    evaluations: u64,
    /// Decryptions shown to the checker.
    checked: u32,
}

/// How much searching [`solve`] may do.
#[derive(Debug, Clone, Copy)]
struct Budget {
    /// Most annealing runs. The search stops at the first that finds the square.
    runs: u32,
    /// Temperature steps per run.
    steps: u32,
    /// Squares scored at each temperature.
    evaluations_per_step: u32,
    /// Once this much time has passed, the run going on stops and no other starts. The
    /// first run always finishes. The search thread can't stop a decoder, and a search
    /// that times out waits for the decoders it is running, so this keeps a timeout
    /// from being stretched by much.
    time_limit: Option<Duration>,
}

impl Budget {
    /// What `crack` uses: up to five runs of 200,000 evaluations each, about a quarter
    /// of a second each on 300 letters, and no run after one and a half seconds (the
    /// first always finishes). One run finds the square of about a fifth of 200-letter
    /// texts and half of 300-letter ones, and the runs are independent.
    const DEFAULT: Budget = Budget {
        runs: 5,
        steps: 100,
        evaluations_per_step: 2_000,
        time_limit: Some(Duration::from_millis(1_500)),
    };
}

/// Cracks `text`. A decryption that reads like English is passed to `confirm` if
/// dictionary words cover most of it, or straight away if a regex crib is set (`crib`),
/// as the crib is all the checker looks at then.
fn crack_text<T>(
    text: &str,
    budget: &Budget,
    crib: bool,
    stats: &mut Stats,
    confirm: &mut dyn FnMut(&str) -> Option<T>,
) -> Outcome<T> {
    let letters = match parse(text) {
        Ok(letters) => letters,
        Err(reason) => return Outcome::Failed(reason),
    };
    let Some((square, fitness)) = solve(&letters, budget, stats) else {
        return Outcome::Failed(Reason::NotFound);
    };
    let square = canonical(&square);
    let key = square_string(&square);
    trace!("Playfair square {key} has fitness {fitness:.3}");
    finish(decipher(&letters, &square), key, crib, stats, confirm)
}

/// The outcome for `plaintext`, the decryption with the square `key`: it is shown to
/// `confirm` if dictionary words cover most of it or a crib is set.
fn finish<T>(
    plaintext: String,
    key: String,
    crib: bool,
    stats: &mut Stats,
    confirm: &mut dyn FnMut(&str) -> Option<T>,
) -> Outcome<T> {
    if crib || reads_as_words(&plaintext) {
        stats.checked += 1;
        if let Some(check) = confirm(&plaintext) {
            return Outcome::Confirmed {
                plaintext,
                key,
                check,
            };
        }
    }
    Outcome::Unconfirmed { plaintext, key }
}

/// Runs the checks that don't need the quadgrams on `text` and returns its letters, as 0
/// to 25.
fn parse(text: &str) -> Result<Vec<u8>, Reason> {
    // Bytes first: a character is at least one byte and at most four
    if text.len() < MIN_LETTERS {
        return Err(Reason::TooShort);
    }
    if text.len() > 4 * MAX_CHARS {
        return Err(Reason::TooLong);
    }
    let mut letters = Vec::with_capacity(text.len().min(MAX_CHARS));
    let mut chars = 0;
    let mut others = 0;
    for c in text.chars() {
        chars += 1;
        if chars > MAX_CHARS {
            return Err(Reason::TooLong);
        }
        if c.is_ascii_alphabetic() {
            let letter = c.to_ascii_uppercase() as u8 - b'A';
            if letter == J {
                return Err(Reason::HasJ);
            }
            letters.push(letter);
        } else if !c.is_whitespace() {
            others += 1;
        }
    }
    let count = letters.len();
    if count < MIN_LETTERS {
        return Err(Reason::TooShort);
    }
    if !count.is_multiple_of(2) {
        return Err(Reason::OddLength);
    }
    if count * 10 < (count + others) * 9 {
        return Err(Reason::NotLetters);
    }
    let (pairs, _) = letters.as_chunks::<2>();
    if pairs.iter().any(|[first, second]| first == second) {
        return Err(Reason::DoubledPair);
    }

    let mut counts = [0usize; 26];
    for &letter in &letters {
        counts[usize::from(letter)] += 1;
    }
    if chi_squared(&counts, count) < MIN_CHI_SQUARED {
        return Err(Reason::EnglishFrequencies);
    }
    if index_of_coincidence(&counts, count) > MAX_IOC {
        return Err(Reason::Coincidence);
    }
    Ok(letters)
}

/// The χ² statistic of the letter `counts` against English letter frequencies, divided by
/// the number of letters, `total`.
fn chi_squared(counts: &[usize; 26], total: usize) -> f64 {
    counts
        .iter()
        .zip(ENGLISH_FREQS)
        .map(|(&count, expected)| {
            let observed = count as f64 / total as f64;
            (observed - expected).powi(2) / expected
        })
        .sum()
}

/// Index of coincidence: the chance that two letters picked at random are the same.
fn index_of_coincidence(counts: &[usize; 26], total: usize) -> f64 {
    let pairs: usize = counts.iter().map(|&n| n * n.saturating_sub(1)).sum();
    pairs as f64 / (total * (total - 1)) as f64
}

/// Whether dictionary words cover at least [`MIN_COVERAGE`] of `plaintext` (see
/// [`reading_coverage`]).
fn reads_as_words(plaintext: &str) -> bool {
    reading_coverage(plaintext) >= MIN_COVERAGE
}

/// The share of `plaintext`, upper-case letters, that dictionary words cover, as it is or
/// with its Xs removed, whichever is more: the fillers break up words.
fn reading_coverage(plaintext: &str) -> f64 {
    let without_x: Vec<u8> = plaintext.bytes().filter(|&b| b != b'X').collect();
    word_coverage(plaintext.as_bytes()).max(word_coverage(&without_x))
}

/// The share of `letters`, upper-case ASCII letters, that dictionary words can cover,
/// with the words placed so that they cover as many as possible.
fn word_coverage(letters: &[u8]) -> f64 {
    if letters.is_empty() {
        return 0.0;
    }
    let dictionary = &*DICTIONARY;
    // covered[i]: the most letters of letters[..i] that words can cover
    let mut covered = vec![0usize; letters.len() + 1];
    for start in 0..letters.len() {
        covered[start + 1] = covered[start + 1].max(covered[start]);
        let longest = MAX_WORD.min(letters.len() - start);
        for len in 1..=longest {
            let end = start + len;
            let is_word = std::str::from_utf8(&letters[start..end])
                .is_ok_and(|word| dictionary.contains(word));
            if is_word {
                covered[end] = covered[end].max(covered[start] + len);
            }
        }
    }
    covered[letters.len()] as f64 / letters.len() as f64
}

/// A key square: the letter in each of its 25 cells, row by row, as 0 to 25. It never has
/// a J.
pub(crate) type Square = [u8; 25];

/// The 25 letters in alphabetical order: the square of an empty keyword.
const ALPHABET: Square = {
    let mut square = [0; 25];
    let mut i = 0;
    while i < 25 {
        square[i] = if i < J as usize { i as u8 } else { i as u8 + 1 };
        i += 1;
    }
    square
};

/// The cells the letters in cells `a` and `b` turn into, `[a * 25 + b]`, when each letter
/// of a row or column pair moves `shift` cells round its row or column: 1 encrypts, 4
/// (one back) decrypts. The cells don't depend on which letters are where.
const fn cell_pairs(shift: usize) -> [[u8; 2]; 625] {
    let mut table = [[0; 2]; 625];
    let mut a = 0;
    while a < 25 {
        let mut b = 0;
        while b < 25 {
            let (row_a, col_a, row_b, col_b) = (a / 5, a % 5, b / 5, b % 5);
            let pair = if row_a == row_b {
                [
                    row_a * 5 + (col_a + shift) % 5,
                    row_b * 5 + (col_b + shift) % 5,
                ]
            } else if col_a == col_b {
                [
                    (row_a + shift) % 5 * 5 + col_a,
                    (row_b + shift) % 5 * 5 + col_b,
                ]
            } else {
                [row_a * 5 + col_b, row_b * 5 + col_a]
            };
            table[a * 25 + b] = [pair[0] as u8, pair[1] as u8];
            b += 1;
        }
        a += 1;
    }
    table
}

/// [`cell_pairs`] for decryption.
static DECRYPT_CELLS: [[u8; 2]; 625] = cell_pairs(4);

/// The cell of each letter of `square`. J's entry is 0 and never used.
fn positions(square: &Square) -> [u8; 26] {
    let mut positions = [0; 26];
    let mut cell = 0;
    while cell < 25 {
        positions[usize::from(square[cell])] = cell as u8;
        cell += 1;
    }
    positions
}

/// Decrypts or encrypts `letters`, an even number of them as 0 to 25 without J, with
/// `square`, using `cells` from [`cell_pairs`], into `out`.
fn crypt(letters: &[u8], square: &Square, cells: &[[u8; 2]; 625], out: &mut [u8]) {
    let positions = positions(square);
    let mut i = 0;
    while i + 1 < letters.len() {
        let a = usize::from(positions[usize::from(letters[i])]);
        let b = usize::from(positions[usize::from(letters[i + 1])]);
        let pair = cells[a * 25 + b];
        out[i] = square[usize::from(pair[0])];
        out[i + 1] = square[usize::from(pair[1])];
        i += 2;
    }
}

/// Decrypts `letters`, an even number of them as 0 to 25 without J, with `square`, into
/// upper-case text.
fn decipher(letters: &[u8], square: &Square) -> String {
    let mut plain = vec![0; letters.len()];
    crypt(letters, square, &DECRYPT_CELLS, &mut plain);
    plain
        .iter()
        .map(|&letter| char::from(b'A' + letter))
        .collect()
}

/// Decrypts the letters of `text` with `square`: upper or lower case, with J read as I.
/// Everything else is dropped. `None` if `text` has no letters, or an odd number of them.
pub(crate) fn decipher_text(text: &str, square: &Square) -> Option<String> {
    let letters: Vec<u8> = text
        .bytes()
        .filter(u8::is_ascii_alphabetic)
        .map(|b| match b.to_ascii_uppercase() - b'A' {
            J => J - 1,
            letter => letter,
        })
        .collect();
    (!letters.is_empty() && letters.len().is_multiple_of(2)).then(|| decipher(&letters, square))
}

/// The square made from `keyword`: its letters, each once and with J as I, then the rest
/// of the alphabet in order. The 25 letters of a square are their own keyword. Whitespace
/// is ignored. `None` if `keyword` has no letters, or anything but ASCII letters and
/// whitespace.
pub(crate) fn square_from_keyword(keyword: &str) -> Option<Square> {
    let mut letters = Vec::with_capacity(25);
    for c in keyword.chars().filter(|c| !c.is_whitespace()) {
        if !c.is_ascii_alphabetic() {
            return None;
        }
        let letter = match c.to_ascii_uppercase() as u8 - b'A' {
            J => J - 1,
            letter => letter,
        };
        if !letters.contains(&letter) {
            letters.push(letter);
        }
    }
    if letters.is_empty() {
        return None;
    }
    for letter in ALPHABET {
        if !letters.contains(&letter) {
            letters.push(letter);
        }
    }
    letters.try_into().ok()
}

/// `square` as 25 upper-case letters, row by row.
pub(crate) fn square_string(square: &Square) -> String {
    square
        .iter()
        .map(|&letter| char::from(b'A' + letter))
        .collect()
}

/// `square` with its rows shifted up by `rows` and its columns left by `columns`. All 25
/// such shifts encrypt and decrypt the same way.
fn shifted(square: &Square, rows: usize, columns: usize) -> Square {
    std::array::from_fn(|cell| {
        let (row, column) = (cell / 5, cell % 5);
        square[(row + rows) % 5 * 5 + (column + columns) % 5]
    })
}

/// The one of the 25 squares equivalent to `square` that ends in the longest run of
/// letters in alphabetical order, the first of them in alphabetical order on a tie. A
/// square made from a keyword ends with the rest of the alphabet in order, so this is
/// usually the square the keyword made: `PLAYFIREXMBCDGHKNOQSTUVWZ`, not
/// `GHDCBKNOQSTUVWZPLAYFIREXM`.
fn canonical(square: &Square) -> Square {
    let ordered_tail = |square: &Square| {
        1 + square
            .windows(2)
            .rev()
            .take_while(|pair| pair[0] < pair[1])
            .count()
    };
    let mut best = *square;
    for rows in 0..5 {
        for columns in 0..5 {
            let candidate = shifted(square, rows, columns);
            let (tail, best_tail) = (ordered_tail(&candidate), ordered_tail(&best));
            if tail > best_tail || (tail == best_tail && candidate < best) {
                best = candidate;
            }
        }
    }
    best
}

/// Scores squares on a run of cipher letters by the quadgrams of their decryption.
struct Scorer<'a> {
    /// The quadgram table.
    table: &'a [f32],
    /// The cipher letters, as 0 to 25: an even number of them, at least four.
    letters: &'a [u8],
}

impl<'a> Scorer<'a> {
    /// A scorer for `letters`, an even number of at least four letters, at most
    /// [`SEARCH_LETTERS`].
    fn new(letters: &'a [u8]) -> Scorer<'a> {
        Scorer {
            table: &QUADGRAMS,
            letters,
        }
    }

    /// Number of quadgrams.
    fn window_count(&self) -> usize {
        self.letters.len() - 3
    }

    /// Total log10 probability of the quadgrams of the text decrypted with `square`.
    fn score(&self, square: &Square) -> f32 {
        let letters = self.letters;
        let mut plain = [0u8; SEARCH_LETTERS];
        crypt(letters, square, &DECRYPT_CELLS, &mut plain);

        let table = self.table;
        let mut index = usize::from(plain[0]) * 17_576
            + usize::from(plain[1]) * 676
            + usize::from(plain[2]) * 26
            + usize::from(plain[3]);
        let mut score = table[index];
        // Plain loops and index arithmetic rather than iterators and `%`: this is the inner
        // loop of the search, and the tests run it unoptimised
        let mut i = 4;
        while i < letters.len() {
            // Drop the quadgram's first letter and add the next one
            index = (index - usize::from(plain[i - 4]) * 17_576) * 26 + usize::from(plain[i]);
            score += table[index];
            i += 1;
        }
        score
    }
}

/// Searches for the square that decrypts `letters` (the ciphertext's letters as 0 to 25,
/// an even number of them, at least four) to English. Returns it with the fitness of the
/// decryption, the average log10 probability of its quadgrams, once a run finds one with
/// [`SOLVED_FITNESS`] or better. The runs are seeded from the letters, so a text is always
/// cracked the same way, as long as the time limit doesn't cut the search short.
fn solve(letters: &[u8], budget: &Budget, stats: &mut Stats) -> Option<(Square, f64)> {
    let started = Instant::now();
    let scorer = Scorer::new(&letters[..letters.len().min(SEARCH_LETTERS)]);
    let mut hash = Fnv::new();
    for &letter in letters {
        hash.write(u32::from(letter));
    }
    let seed = hash.finish();

    for run in 0..budget.runs {
        let deadline = match budget.time_limit {
            Some(limit) if run > 0 => Some(started + limit),
            _ => None,
        };
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            debug!("Playfair stopped after {run} runs: out of time");
            break;
        }
        stats.runs += 1;
        let mut rng = Rng::new(seed.wrapping_add(u64::from(run)));
        let Some((square, score)) = anneal(&scorer, budget, deadline, &mut rng, stats) else {
            debug!("Playfair stopped in run {run}: out of time");
            break;
        };
        let (square, score) = polish(&scorer, square, score, stats);
        let fitness = f64::from(score) / scorer.window_count() as f64;
        trace!("Playfair annealing run {run}: fitness {fitness:.3}");
        if fitness >= SOLVED_FITNESS {
            let square = prefer_words(letters, &scorer, square, score, stats);
            let fitness = f64::from(scorer.score(&square)) / scorer.window_count() as f64;
            return Some((square, fitness));
        }
    }
    None
}

/// Of `square`, whose score is `score`, and the squares one swap of two letters away that
/// score within [`NEAR_FITNESS`] of it, the one whose decryption of `letters` dictionary
/// words cover most (see [`reading_coverage`]).
///
/// Quadgrams can't always tell the right square from one with two letters swapped that
/// change only a few pairs, X and Y say: about 2% of the annealing runs that found a
/// square ended one swap from the right one, which scored a little worse. Words can tell
/// them apart.
fn prefer_words(
    letters: &[u8],
    scorer: &Scorer,
    square: Square,
    score: f32,
    stats: &mut Stats,
) -> Square {
    let near = (NEAR_FITNESS * scorer.window_count() as f64) as f32;
    let mut best = (reading_coverage(&decipher(letters, &square)), square);
    for a in 0..25 {
        for b in a + 1..25 {
            let mut candidate = square;
            candidate.swap(a, b);
            if scorer.score(&candidate) < score - near {
                continue;
            }
            let coverage = reading_coverage(&decipher(letters, &candidate));
            if coverage > best.0 {
                best = (coverage, candidate);
            }
        }
    }
    stats.evaluations += 300;
    best.1
}

/// The orders of five rows (or columns) that start with the first: the other orders only
/// shift these round, which changes nothing.
static ORDERS: Lazy<Vec<[usize; 5]>> = Lazy::new(|| {
    let mut orders = Vec::with_capacity(24);
    for code in 0..5usize.pow(4) {
        let order: [usize; 5] = std::array::from_fn(|i| {
            if i == 0 {
                0
            } else {
                code / 5usize.pow(i as u32 - 1) % 5
            }
        });
        if (0..5).all(|line| order.contains(&line)) {
            orders.push(order);
        }
    }
    orders
});

/// Hill climbs from `square`, whose score is `score`, until nothing improves it: tries
/// every order of its rows, every order of its columns and every swap of two letters.
///
/// Annealing runs often end on the right rows in the wrong order, or the right columns:
/// two of them cycled round, which no single swap of two rows or columns improves.
fn polish(scorer: &Scorer, mut square: Square, mut score: f32, stats: &mut Stats) -> (Square, f32) {
    /// Least gain that counts as an improvement, above the rounding of the scores.
    const GAIN: f32 = 1e-3;
    // Bounded in case rounding makes two squares look like improvements of each other
    for _ in 0..20 {
        let start = score;
        for order in ORDERS.iter() {
            for by_rows in [true, false] {
                let candidate: Square = std::array::from_fn(|cell| {
                    let (row, column) = (cell / 5, cell % 5);
                    if by_rows {
                        square[order[row] * 5 + column]
                    } else {
                        square[row * 5 + order[column]]
                    }
                });
                let candidate_score = scorer.score(&candidate);
                if candidate_score > score + GAIN {
                    square = candidate;
                    score = candidate_score;
                }
            }
        }
        for a in 0..25 {
            for b in a + 1..25 {
                let mut candidate = square;
                candidate.swap(a, b);
                let candidate_score = scorer.score(&candidate);
                if candidate_score > score + GAIN {
                    square = candidate;
                    score = candidate_score;
                }
            }
        }
        stats.evaluations += 2 * ORDERS.len() as u64 + 300;
        if score <= start + GAIN {
            break;
        }
    }
    (square, score)
}

/// One simulated annealing run from a random square. A mutation (see [`mutate`]) is kept
/// if it improves the score, and with probability e^(Δ/T) if it doesn't, with the
/// temperature T falling linearly from [`START_TEMPERATURE`] towards 0 over the run.
/// Returns the best square seen and its score, or `None` if `deadline` passed first.
fn anneal(
    scorer: &Scorer,
    budget: &Budget,
    deadline: Option<Instant>,
    rng: &mut Rng,
    stats: &mut Stats,
) -> Option<(Square, f32)> {
    let mut square = ALPHABET;
    for i in (1..25).rev() {
        square.swap(i, rng.below(i + 1));
    }
    let mut score = scorer.score(&square);
    let mut best = (square, score);

    for step in 0..budget.steps {
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return None;
        }
        let t = START_TEMPERATURE * f64::from(budget.steps - step) / f64::from(budget.steps);
        for _ in 0..budget.evaluations_per_step {
            let mut candidate = square;
            mutate(&mut candidate, rng);
            let candidate_score = scorer.score(&candidate);
            let delta = f64::from(candidate_score - score);
            if delta >= 0.0 || rng.unit() < (delta / t).exp() {
                square = candidate;
                score = candidate_score;
                if score > best.1 {
                    best = (square, score);
                }
            }
        }
        stats.evaluations += u64::from(budget.evaluations_per_step);
    }
    Some(best)
}

/// Changes `square` at random: nine times in ten it swaps two letters, and otherwise it
/// swaps two rows or two columns, flips it top to bottom or left to right, or turns it
/// round. The big changes get the search out of squares that are right but for a
/// reflection.
fn mutate(square: &mut Square, rng: &mut Rng) {
    /// Two different numbers below 5.
    fn two_lines(rng: &mut Rng) -> (usize, usize) {
        let a = rng.below(5);
        let b = rng.below(4);
        (a, if b >= a { b + 1 } else { b })
    }
    match rng.below(50) {
        0 => {
            let (a, b) = two_lines(rng);
            for column in 0..5 {
                square.swap(a * 5 + column, b * 5 + column);
            }
        }
        1 => {
            let (a, b) = two_lines(rng);
            for row in 0..5 {
                square.swap(row * 5 + a, row * 5 + b);
            }
        }
        2 => square.reverse(),
        3 => {
            for row in 0..2 {
                for column in 0..5 {
                    square.swap(row * 5 + column, (4 - row) * 5 + column);
                }
            }
        }
        4 => {
            for row in square.as_chunks_mut::<5>().0 {
                row.reverse();
            }
        }
        _ => {
            let a = rng.below(25);
            let b = rng.below(24);
            square.swap(a, if b >= a { b + 1 } else { b });
        }
    }
}

/// Index of a quadgram of upper-case letters in [`QUADGRAMS`].
fn quadgram_index(quadgram: &str) -> Option<usize> {
    let bytes = quadgram.as_bytes();
    if bytes.len() != 4 {
        return None;
    }
    bytes.iter().try_fold(0, |index, &b| {
        b.is_ascii_uppercase()
            .then(|| index * 26 + usize::from(b - b'A'))
    })
}

/// Turns `ABCD count` lines (and `#` comments) into log10 probabilities. Quadgrams that
/// aren't listed get log10(0.5 / total), as if they had been seen half a time.
fn parse_quadgrams(data: &str) -> Box<[f32]> {
    let mut counts = vec![0u64; 26 * 26 * 26 * 26];
    let mut total = 0u64;
    for line in data.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split_ascii_whitespace();
        let parsed = fields
            .next()
            .and_then(quadgram_index)
            .zip(fields.next().and_then(|count| count.parse::<u64>().ok()));
        if let Some((index, count)) = parsed {
            counts[index] += count;
            total += count;
        }
    }
    let total = total.max(1) as f64;
    let floor = (0.5 / total).log10() as f32;
    counts
        .into_iter()
        .map(|count| {
            if count == 0 {
                floor
            } else {
                (count as f64 / total).log10() as f32
            }
        })
        .collect()
}

/// xorshift64*, seeded from the letters so a text is always cracked the same way.
struct Rng(u64);

impl Rng {
    /// A generator seeded with `seed`.
    fn new(seed: u64) -> Rng {
        // splitmix64 spreads the seed's bits; xorshift needs a non-zero state
        let mut z = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        Rng((z ^ (z >> 31)) | 1)
    }

    /// The next 64 random bits.
    fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// A number in `0..n`.
    fn below(&mut self, n: usize) -> usize {
        (((self.next_u64() >> 32) * n as u64) >> 32) as usize
    }

    /// A number in `[0, 1)`.
    fn unit(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }
}

/// 64-bit FNV-1a. Unlike `DefaultHasher` it hashes the same in every Rust version, so a
/// text is always cracked the same way.
struct Fnv(u64);

impl Fnv {
    /// An empty hash.
    fn new() -> Fnv {
        Fnv(0xCBF2_9CE4_8422_2325)
    }

    /// Adds `value` to the hash.
    fn write(&mut self, value: u32) {
        for byte in value.to_le_bytes() {
            self.0 ^= u64::from(byte);
            self.0 = self.0.wrapping_mul(0x0100_0000_01B3);
        }
    }

    /// The hash.
    fn finish(&self) -> u64 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkers::{
        athena::Athena,
        checker_type::{Check, Checker},
    };

    // Test vectors from the implementation plan in
    // https://github.com/bee-san/Ciphey/issues/1006, and one more from the same book. The
    // ciphertexts were made with pycipher 0.5.2 `Playfair(square).encipher` from the
    // prepared plaintexts (pycipher doesn't add the fillers itself) and decrypted back with
    // its `decipher`; `vectors_match_their_squares` re-encrypts them here.

    /// Wikipedia's example and the issue's: "Hide the gold in the tree stump", keyword
    /// PLAYFAIR EXAMPLE.
    const ISSUE_CIPHERTEXT: &str = "BMODZBXDNABEKUDMUIXMMOUVIF";
    /// Its prepared plaintext.
    const ISSUE_PLAINTEXT: &str = "HIDETHEGOLDINTHETREXESTUMP";
    /// The square of PLAYFAIR EXAMPLE.
    const ISSUE_SQUARE: &str = "PLAYFIREXMBCDGHKNOQSTUVWZ";

    /// 300 letters of Treasure Island (Project Gutenberg #120, chapter 2), keyword
    /// TREASURE.
    const TREASURE_CIPHERTEXT: &str = "RGROSKIQDSTFCYCAMRIREAYRTSRETOROCPFTCEQKQEOXOPCQSRLRRPCPRGAEOPLEATRGCIKRHERPUARDISXRMRMXAEHOSKGVYDFISTINLFRASICQIZIQXRKDPBRGROEDAWQCYDHORPUAIRORVEHOTRRPEGTSRHKSDICPHKQBFGQLGKHIRSPBRGCIDYRSHOINSGAYBTTFHOHUMENRGEKBESRWDBSGSTTATSPBRGSCNEOTETREASOGMHFHXEPCBSPNRGSISCRTINFGCAEHFTRSEVRGACXENERGCIDYRSHOEKOT";
    /// Its prepared plaintext: fillers in SUDXDEN and FOLXLOWED, "just" as IUST.
    const TREASURE_PLAINTEXT: &str = "THENALLOFASUDXDENTHEREWASATREMENDOUSEXPLOSIONOFOATHSANDOTHERNOISESTHECHAIRANDTABLEWENTOVERINALUMPACLASHOFSTEELFOLXLOWEDANDTHENACRYOFPAINANDTHENEXTINSTANTISAWBLACKDOGINFULLFLIGHTANDTHECAPTAINHOTLYPURSUINGBOTHWITHDRAWNCUTLASSESANDTHEFORMERSTREAMINGBLOXODFROMTHELEFTSHOULDERIUSTATXTHEDOXORTHECAPTAINAIME";
    /// The source of [`TREASURE_PLAINTEXT`]: its first 300 prepared letters.
    const TREASURE_SOURCE: &str = "Then all of a sudden there was a tremendous explosion of oaths and other noises--the chair and table went over in a lump, a clash of steel followed, and then a cry of pain, and the next instant I saw Black Dog in full flight, and the captain hotly pursuing, both with drawn cutlasses, and the former streaming blood from the left shoulder. Just at the door the captain aimed at the fugitive";
    /// The square of TREASURE.
    const TREASURE_SQUARE: &str = "TREASUBCDFGHIKLMNOPQVWXYZ";

    /// The 576-character plaintext of the decoder benchmarks, 470 letters once prepared,
    /// keyword LIGHTHOUSE.
    const LIGHTHOUSE_CIPHERTEXT: &str = "NUQGFHGUUROSLAROHAPGFSBUCGPILABOVESILWUHHAWNQZRGSFAMUQBUFSKGSYAKPCGLAZHUAGUVAMBAAIYIKAZUDPUMAHULIZGLLEAIVEEIOZUWHLABMUZIEFFAVEQAYORIEFNUQGAQGLEAKZFIAELTMASILQURXQUEUGMOSFUFSBUWSDFIUFDAAOFIKUPCGCKAAHUESYUYEFLTAQGLOBABOGTCSYUQHIGULEMNKAFIAEKRMUIWRSGZHAMPESFIOEUROQUTTOPGKPAEEOPCAGSMUXEFWUHKUWPDEUQOLTUWHLTEAZAOPDIGFAMGUTRISYLRUELAKHEFLGQOLTGUAKFAOGAEAGTERUEABUPCYIUNLQKRAEGLTEPCHQAMKURGANAHEFBHSTFIOTHOPIAENSVYVTFECWGAURFKAMURVEQUYIUEIAVMHOEOKNUEEOAGZKPIAEAZUWHGRUOBHDGISY";
    /// Its prepared plaintext, ending in a padding X.
    const LIGHTHOUSE_PLAINTEXT: &str = "CIPHEYISANAUTOMATEDXDECODINGTOOLYOUGIVEITENCRYPTEDORENCODEDTEXTANDITTRIESTOWORKOUTWHATWASDONETOITWITHOUTYOUHAVINGTOKNOWTHEKEYOREVENTHECIPHERITSEARCHESTHROUGHMANYPOSSIBLEDECODINGSCHECKSEACHCANDIDATETOSEXEWHETHERITLOOKSLIKEXENGLISHORMATCHESAKNOWNPATXTERNSUCHASANEMAILADXDRESSANDSTOPSWHENITFINDSSOMETHINGTHATREADSLIKEPLAINTEXTMOSTOFTHETIMETHISTAKESLESSTHANASECONDWHICHMAKESITHANDYFORCAPTURETHEFLAGCHALLENGESPUZXZLEHUNTSANDFORANYONEWHOSTUMBLESACROSSASTRANGESTRINGINALOGFILEX";
    /// The source of [`LIGHTHOUSE_PLAINTEXT`] (`benches/data/decoders.toml`).
    const LIGHTHOUSE_SOURCE: &str = "Ciphey is an automated decoding tool. You give it encrypted or encoded text and it tries to work out what was done to it, without you having to know the key or even the cipher. It searches through many possible decodings, checks each candidate to see whether it looks like English or matches a known pattern such as an email address, and stops when it finds something that reads like plaintext. Most of the time this takes less than a second, which makes it handy for capture the flag challenges, puzzle hunts and for anyone who stumbles across a strange string in a log file.";
    /// The square of LIGHTHOUSE.
    const LIGHTHOUSE_SQUARE: &str = "LIGHTOUSEABCDFKMNPQRVWXYZ";

    /// 300 letters of Treasure Island (chapter 15), keyword TAMPERING, made the same way.
    /// The square with X and Y swapped scores better on quadgrams than the right one, and
    /// the annealing runs end on it.
    const TAMPERING_CIPHERTEXT: &str = "ZPAMPMGNAVPORDQLOCIQOQGBTBKBNGOWZKAMIULEPCMANRPBMIALBTDTQVOVDPARDPFKTMICQDDTFMGNIEOUDAPOADPCNGMITDAUHDTOORGBDQGCTUEGLEPCTPTBMKTDMVPCMAKPAIOPPMGFWATZTBADOCDPHOQAAZDPRCTMQYULBTFATMIFPXKMTIQDOGVTTBKBIPRMLITZRWABGMILASCRDWGNLPQWWOLPROVRKPBTDQBTMIFDPOAMIULEDQGLQATPTADSOWKMLHMETMIFPODAPOUQPCNGDBGBPCTBTKQO";
    /// Its prepared plaintext.
    const TAMPERING_PLAINTEXT: &str = "YETAMANITWASICOULDNOLONGERBEINDOUBTABOUTTHATIBEGANTORECALXLWHATIHADHEARDOFCANXNIBALSIWASWITHINANACEOFCALLINGFORHELPBUTTHEMEREFACTXTHATHEWASAMANHOWEVERWILDHADSOMEWHATREASXSUREDMEANDMYFEAROFSILVERBEGANTOREVIVEINPROPORTIONISTOXODSTILLTHEREFOREANDCASTABOUTFORSOMEMETHODOFESCAPEANDASIWASSOTHINKINGTHERECOL";
    /// The source of [`TAMPERING_PLAINTEXT`]: its first 300 prepared letters.
    const TAMPERING_SOURCE: &str = "Yet a man it was, I could no longer be in doubt about that. I began to recall what I had heard of cannibals. I was within an ace of calling for help. But the mere fact that he was a man, however wild, had somewhat reassured me, and my fear of Silver began to revive in proportion. I stood still, therefore, and cast about for some method of escape; and as I was so thinking, the recollection";
    /// The square of TAMPERING.
    const TAMPERING_SQUARE: &str = "TAMPERINGBCDFHKLOQSUVWXYZ";

    /// The `miss` input of `benches/data/decoders.toml`, gibberish no decoder accepts.
    const MISS: &str =
        "T00 l3= ox+#G WKyV pajU6j qxH@ %B4+a 5Pn^ 7p_v1q 9sLvu *+36i R5rL&3 mVJZI iO0 Ut8_m COTV";

    /// `text` reduced to its letters, upper case with J as I, in pairs: an X between two
    /// identical letters of a pair (a Z between two Xs), and an X (or Z) after a final
    /// single letter. What Playfair encrypts.
    fn prepare(text: &str) -> String {
        let letters: Vec<u8> = text
            .bytes()
            .filter(u8::is_ascii_alphabetic)
            .map(|b| match b.to_ascii_uppercase() {
                b'J' => b'I',
                b => b,
            })
            .collect();
        let filler = |letter: u8| if letter == b'X' { b'Z' } else { b'X' };
        let mut prepared = Vec::with_capacity(letters.len() * 2);
        let mut i = 0;
        while i < letters.len() {
            let first = letters[i];
            match letters.get(i + 1) {
                Some(&second) if second != first => {
                    prepared.extend([first, second]);
                    i += 2;
                }
                _ => {
                    prepared.extend([first, filler(first)]);
                    i += 1;
                }
            }
        }
        String::from_utf8(prepared).unwrap()
    }

    /// The square written as 25 letters.
    fn square(letters: &str) -> Square {
        let square: Vec<u8> = letters.bytes().map(|b| b - b'A').collect();
        square.try_into().unwrap()
    }

    /// The letters of `text` as 0 to 25.
    fn letters(text: &str) -> Vec<u8> {
        text.bytes().map(|b| b - b'A').collect()
    }

    /// Encrypts `prepared`, a prepared plaintext, with `square`.
    fn encipher(prepared: &str, square: &Square) -> String {
        let letters = letters(prepared);
        let mut cipher = vec![0; letters.len()];
        crypt(&letters, square, &cell_pairs(1), &mut cipher);
        cipher
            .iter()
            .map(|&letter| char::from(b'A' + letter))
            .collect()
    }

    /// Atbash: A and Z swapped, B and Y, and so on.
    fn atbash(text: &str) -> String {
        text.bytes()
            .map(|b| char::from(b'Z' - (b - b'A')))
            .collect()
    }

    /// The Athena checker, as the search uses it.
    fn athena() -> CheckerTypes {
        CheckerTypes::CheckAthena(Checker::<Athena>::new())
    }

    /// Cracks `text` with the Athena checker and no time limit, so the result doesn't
    /// depend on how busy the machine is.
    fn crack_fresh(text: &str) -> (Outcome<CheckResult>, Stats) {
        let checker = athena();
        let budget = Budget {
            time_limit: None,
            ..Budget::DEFAULT
        };
        let mut stats = Stats::default();
        let outcome = crack_text(text, &budget, false, &mut stats, &mut |plaintext| {
            check(&checker, plaintext)
        });
        (outcome, stats)
    }

    /// Asserts that `text` fails with `reason` before the search starts.
    #[track_caller]
    fn assert_rejected(text: &str, reason: Reason) {
        assert_eq!(parse(text).err(), Some(reason), "{text:?}");
        let (outcome, stats) = crack_fresh(text);
        assert!(
            matches!(outcome, Outcome::Failed(r) if r == reason),
            "{text:?}: {outcome:?}"
        );
        assert_eq!(stats.runs, 0, "{text:?} was searched");
        assert_eq!(stats.evaluations, 0, "{text:?} was searched");
        assert_eq!(stats.checked, 0, "{text:?} was shown to the checker");
    }

    #[test]
    fn vectors_match_their_squares() {
        assert_eq!(prepare("Hide the gold in the tree stump"), ISSUE_PLAINTEXT);
        assert_eq!(&prepare(TREASURE_SOURCE)[..300], TREASURE_PLAINTEXT);
        assert_eq!(&prepare(TAMPERING_SOURCE)[..300], TAMPERING_PLAINTEXT);
        assert_eq!(prepare(LIGHTHOUSE_SOURCE), LIGHTHOUSE_PLAINTEXT);
        for (ciphertext, plaintext, key) in [
            (ISSUE_CIPHERTEXT, ISSUE_PLAINTEXT, ISSUE_SQUARE),
            (TREASURE_CIPHERTEXT, TREASURE_PLAINTEXT, TREASURE_SQUARE),
            (TAMPERING_CIPHERTEXT, TAMPERING_PLAINTEXT, TAMPERING_SQUARE),
            (
                LIGHTHOUSE_CIPHERTEXT,
                LIGHTHOUSE_PLAINTEXT,
                LIGHTHOUSE_SQUARE,
            ),
        ] {
            assert_eq!(encipher(plaintext, &square(key)), ciphertext);
            assert_eq!(decipher(&letters(ciphertext), &square(key)), plaintext);
        }
    }

    #[test]
    fn prepare_adds_fillers() {
        assert_eq!(prepare("balloon"), "BALXLOON");
        assert_eq!(prepare("XX"), "XZXZ");
        assert_eq!(prepare("Jam!"), "IAMX");
        assert_eq!(prepare(""), "");
    }

    #[test]
    fn squares_come_from_keywords() {
        let keyword = |keyword: &str| square_from_keyword(keyword).map(|s| square_string(&s));
        assert_eq!(keyword("PLAYFAIR EXAMPLE").as_deref(), Some(ISSUE_SQUARE));
        assert_eq!(keyword("playfair example").as_deref(), Some(ISSUE_SQUARE));
        assert_eq!(keyword("Treasure").as_deref(), Some(TREASURE_SQUARE));
        assert_eq!(keyword("LIGHTHOUSE").as_deref(), Some(LIGHTHOUSE_SQUARE));
        // A square is its own keyword
        assert_eq!(keyword(TREASURE_SQUARE).as_deref(), Some(TREASURE_SQUARE));
        // J is I
        assert_eq!(keyword("JAM").as_deref(), Some("IAMBCDEFGHKLNOPQRSTUVWXYZ"));
        assert_eq!(keyword(""), None);
        assert_eq!(keyword("   "), None);
        assert_eq!(keyword("KEY1"), None);
        assert_eq!(square_string(&ALPHABET), "ABCDEFGHIKLMNOPQRSTUVWXYZ");
    }

    #[test]
    fn every_shift_of_a_square_decrypts_the_same() {
        for key in [ISSUE_SQUARE, TREASURE_SQUARE, LIGHTHOUSE_SQUARE] {
            let original = square(key);
            for rows in 0..5 {
                for columns in 0..5 {
                    let shifted = shifted(&original, rows, columns);
                    assert_eq!(
                        decipher(&letters(ISSUE_CIPHERTEXT), &shifted),
                        decipher(&letters(ISSUE_CIPHERTEXT), &original)
                    );
                    // ... and the keyword's square is the one reported
                    assert_eq!(canonical(&shifted), original, "{key} {rows} {columns}");
                }
            }
        }
        assert_eq!(canonical(&ALPHABET), ALPHABET);
    }

    #[test]
    fn cracks_treasure_island() {
        let decoder = Decoder::<PlayfairDecoder>::new();
        let result = decoder.crack(TREASURE_CIPHERTEXT, &athena());
        assert!(result.success, "{result:?}");
        assert_eq!(result.decoder, "Playfair");
        assert_eq!(
            result.unencrypted_text,
            Some(vec![TREASURE_PLAINTEXT.to_string()])
        );
        let key = result.key.unwrap();
        assert_eq!(key, TREASURE_SQUARE);
        assert_eq!(
            decipher_text(TREASURE_CIPHERTEXT, &square(&key)).as_deref(),
            Some(TREASURE_PLAINTEXT)
        );
    }

    #[test]
    fn cracks_the_long_benchmark_text() {
        let (outcome, stats) = crack_fresh(LIGHTHOUSE_CIPHERTEXT);
        match outcome {
            Outcome::Confirmed { plaintext, key, .. } => {
                assert_eq!(plaintext, LIGHTHOUSE_PLAINTEXT);
                assert_eq!(key, LIGHTHOUSE_SQUARE);
                assert_eq!(
                    decipher(&letters(LIGHTHOUSE_CIPHERTEXT), &square(&key)),
                    plaintext
                );
            }
            other => panic!("not cracked: {other:?}"),
        }
        assert!(stats.runs >= 1);
        assert_eq!(stats.checked, 1);
    }

    #[test]
    fn lower_case_ciphertext_in_groups_cracks_the_same_way() {
        let groups: Vec<String> = TREASURE_CIPHERTEXT
            .to_ascii_lowercase()
            .as_bytes()
            .chunks(5)
            .map(|group| String::from_utf8_lossy(group).into_owned())
            .collect();
        let grouped = groups.join(" ");
        assert_eq!(parse(&grouped), parse(TREASURE_CIPHERTEXT));
        match crack_fresh(&grouped).0 {
            Outcome::Confirmed { plaintext, key, .. } => {
                assert_eq!(plaintext, TREASURE_PLAINTEXT);
                assert_eq!(key, TREASURE_SQUARE);
            }
            other => panic!("not cracked: {other:?}"),
        }
    }

    #[test]
    fn crack_fails_without_panicking() {
        let decoder = Decoder::<PlayfairDecoder>::new();
        for text in ["", "😀", "ab", "hello world", ISSUE_CIPHERTEXT, MISS] {
            let result = decoder.crack(text, &athena());
            assert!(!result.success, "{text:?}");
            assert_eq!(result.unencrypted_text, None, "{text:?}");
            assert_eq!(result.key, None, "{text:?}");
            assert_rejected(text, Reason::TooShort);
        }
    }

    #[test]
    fn rejects_text_that_is_not_playfair_before_searching() {
        let dropped = &TREASURE_CIPHERTEXT[1..];
        assert_rejected(dropped, Reason::OddLength);
        let with_j = format!(
            "{}J{}",
            &TREASURE_CIPHERTEXT[..2],
            &TREASURE_CIPHERTEXT[2..]
        );
        assert_rejected(&with_j, Reason::HasJ);
        assert_rejected(&with_j.to_ascii_lowercase(), Reason::HasJ);
        let doubled = format!("AA{}", &TREASURE_CIPHERTEXT[2..]);
        assert_rejected(&doubled, Reason::DoubledPair);
        // A digit after every five letters: 83% letters
        let numbered: String = TREASURE_CIPHERTEXT
            .as_bytes()
            .chunks(5)
            .map(|group| format!("{}1", String::from_utf8_lossy(group)))
            .collect();
        assert_rejected(&numbered, Reason::NotLetters);
        assert_rejected(&"AB".repeat(1_001), Reason::TooLong);
        assert_rejected(&"AB ".repeat(3_000), Reason::TooLong);

        // English and transpositions of it: the plaintexts, and one backwards
        let reversed: String = TREASURE_PLAINTEXT.chars().rev().collect();
        for english in [TREASURE_PLAINTEXT, LIGHTHOUSE_PLAINTEXT, &reversed] {
            assert_rejected(english, Reason::EnglishFrequencies);
        }

        // A substitution keeps English's index of coincidence: Atbash of a prepared
        // paragraph of Treasure Island with no Q, so no J, and no doubled pairs
        let atbash = atbash(&prepare(
            "I slipped the bolt at once, and we stood and panted for a moment in the dark, \
             alone in the house with the dead captain's body. Then my mother got a candle in \
             the bar, and holding each other's hands, we advanced into the parlour. He lay \
             as we had left him, on his back, with his eyes open and one arm stretched out.",
        ));
        assert_eq!(atbash.len(), 242);
        assert_rejected(&atbash, Reason::Coincidence);
    }

    #[test]
    fn benchmark_inputs_never_reach_the_search() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("benches/data");
        let mut checked = 0;
        for file in ["decoders.toml", "search.toml"] {
            let text = std::fs::read_to_string(dir.join(file)).unwrap();
            let fixtures: toml::Value = toml::from_str(&text).unwrap();
            if let Some(miss) = fixtures.get("miss").and_then(toml::Value::as_str) {
                assert!(parse(miss).is_err());
                checked += 1;
            }
            for case in fixtures["case"].as_array().unwrap() {
                let input = case["input"].as_str().unwrap();
                let playfair =
                    case.get("decoder").and_then(toml::Value::as_str) == Some("Playfair");
                assert_eq!(parse(input).is_ok(), playfair, "{file}: {case}");
                checked += 1;
            }
        }
        assert!(checked > 150, "{checked}");
    }

    #[test]
    fn rejecting_the_miss_input_takes_microseconds() {
        let decoder = Decoder::<PlayfairDecoder>::new();
        let checker = athena();
        // The fastest of five batches, so a busy machine doesn't fail the test
        let fastest = (0..5)
            .map(|_| {
                let start = Instant::now();
                for _ in 0..1_000 {
                    assert!(!decoder.crack(std::hint::black_box(MISS), &checker).success);
                }
                start.elapsed() / 1_000
            })
            .min()
            .unwrap();
        assert!(fastest < Duration::from_micros(5), "{fastest:?} per call");
    }

    #[test]
    fn statistics_of_the_vectors() {
        for (ciphertext, ioc_range) in [
            (TREASURE_CIPHERTEXT, 0.056..0.058),
            (LIGHTHOUSE_CIPHERTEXT, 0.054..0.056),
        ] {
            let letters = parse(ciphertext).unwrap();
            let mut counts = [0; 26];
            for &letter in &letters {
                counts[usize::from(letter)] += 1;
            }
            let ioc = index_of_coincidence(&counts, letters.len());
            assert!(ioc_range.contains(&ioc), "{ioc}");
            let chi = chi_squared(&counts, letters.len());
            assert!(chi > 1.5, "{chi}");

            let scorer = Scorer::new(&letters[..letters.len().min(SEARCH_LETTERS)]);
            let wrong = f64::from(scorer.score(&ALPHABET)) / scorer.window_count() as f64;
            assert!(wrong < -5.5, "{wrong}");
        }
        let letters = letters(TREASURE_CIPHERTEXT);
        let scorer = Scorer::new(&letters);
        let right = scorer.score(&square(TREASURE_SQUARE));
        let fitness = f64::from(right) / scorer.window_count() as f64;
        assert!(fitness > SOLVED_FITNESS + 0.3, "{fitness}");
        // The score is the quadgrams of the decryption
        let plain = TREASURE_PLAINTEXT.as_bytes();
        let by_hand: f32 = plain
            .windows(4)
            .map(|quadgram| {
                QUADGRAMS[quadgram_index(std::str::from_utf8(quadgram).unwrap()).unwrap()]
            })
            .sum();
        assert!((by_hand - right).abs() < 1e-2, "{by_hand} {right}");
    }

    #[test]
    fn coverage_allows_for_the_fillers() {
        // HIDE THE GOLD IN THE TREE STUMP: the filler in TREXES costs 19% of the letters
        let as_is = word_coverage(ISSUE_PLAINTEXT.as_bytes());
        assert!((0.75..MIN_COVERAGE).contains(&as_is), "{as_is}");
        assert!(reads_as_words(ISSUE_PLAINTEXT));
        assert!(reads_as_words(TREASURE_PLAINTEXT));
        assert!(reads_as_words(LIGHTHOUSE_PLAINTEXT));
        assert!(!reads_as_words(TREASURE_CIPHERTEXT));
        assert!(!reads_as_words(&atbash(TREASURE_PLAINTEXT)));
        assert_eq!(word_coverage(b""), 0.0);
    }

    #[test]
    fn polish_puts_rows_and_columns_in_order() {
        let letters = letters(TREASURE_CIPHERTEXT);
        let scorer = Scorer::new(&letters);
        let right = square(TREASURE_SQUARE);
        // Rows 1, 2 and 3 cycled, columns 0, 2 and 4 cycled, and two letters swapped: no
        // single swap of two letters, rows or columns gets back to the right square
        let mut wrong: Square = std::array::from_fn(|cell| {
            let (row, column) = (cell / 5, cell % 5);
            let row = [0, 2, 3, 1, 4][row];
            let column = [2, 1, 4, 3, 0][column];
            right[row * 5 + column]
        });
        wrong.swap(0, 24);
        let score = scorer.score(&wrong);
        let (polished, polished_score) = polish(&scorer, wrong, score, &mut Stats::default());
        assert_eq!(decipher(&letters, &polished), TREASURE_PLAINTEXT);
        assert_eq!(canonical(&polished), right);
        assert!(polished_score > score);
    }

    #[test]
    fn words_settle_swaps_the_quadgrams_cannot() {
        let letters = letters(TAMPERING_CIPHERTEXT);
        let scorer = Scorer::new(&letters);
        let right = square(TAMPERING_SQUARE);
        let mut wrong = right;
        // X and Y
        wrong.swap(22, 23);
        let (right_score, wrong_score) = (scorer.score(&right), scorer.score(&wrong));
        // The quadgrams prefer the wrong square, by less than NEAR_FITNESS
        assert!(wrong_score > right_score, "{wrong_score} {right_score}");
        let near = (NEAR_FITNESS * scorer.window_count() as f64) as f32;
        assert!(right_score >= wrong_score - near);
        assert_ne!(decipher(&letters, &wrong), TAMPERING_PLAINTEXT);

        let prefer = |letters: &[u8], square: Square| {
            let scorer = Scorer::new(letters);
            prefer_words(
                letters,
                &scorer,
                square,
                scorer.score(&square),
                &mut Stats::default(),
            )
        };
        assert_eq!(prefer(&letters, wrong), right);
        // A right square stays
        assert_eq!(prefer(&letters, right), right);
        let treasure = square(TREASURE_SQUARE);
        assert_eq!(
            prefer(&self::letters(TREASURE_CIPHERTEXT), treasure),
            treasure
        );
    }

    #[test]
    fn cracks_a_text_the_quadgrams_alone_get_wrong() {
        match crack_fresh(TAMPERING_CIPHERTEXT).0 {
            Outcome::Confirmed { plaintext, key, .. } => {
                assert_eq!(plaintext, TAMPERING_PLAINTEXT);
                assert_eq!(key, TAMPERING_SQUARE);
            }
            other => panic!("not cracked: {other:?}"),
        }
    }

    #[test]
    fn annealing_is_deterministic() {
        let letters = letters(TREASURE_CIPHERTEXT);
        let scorer = Scorer::new(&letters);
        let budget = Budget {
            runs: 1,
            steps: 10,
            evaluations_per_step: 200,
            time_limit: None,
        };
        let run = |seed| {
            let mut stats = Stats::default();
            let found = anneal(&scorer, &budget, None, &mut Rng::new(seed), &mut stats);
            assert_eq!(stats.evaluations, 2_000);
            found.unwrap()
        };
        assert_eq!(run(1), run(1));
        assert_ne!(run(1).0, run(2).0);
        // A deadline that has passed stops the run
        let past = Instant::now();
        assert_eq!(
            anneal(
                &scorer,
                &budget,
                Some(past),
                &mut Rng::new(1),
                &mut Stats::default()
            ),
            None
        );
    }

    #[test]
    fn the_first_run_always_finishes() {
        let letters = letters(TREASURE_CIPHERTEXT);
        let budget = Budget {
            runs: 3,
            steps: 2,
            evaluations_per_step: 10,
            time_limit: Some(Duration::ZERO),
        };
        let mut stats = Stats::default();
        assert_eq!(solve(&letters, &budget, &mut stats), None);
        assert_eq!(stats.runs, 1);
        assert!(stats.evaluations >= 20);
    }

    #[test]
    fn mutations_keep_every_letter() {
        let mut rng = Rng::new(7);
        let mut square = ALPHABET;
        for _ in 0..10_000 {
            mutate(&mut square, &mut rng);
            let mut sorted = square;
            sorted.sort_unstable();
            assert_eq!(sorted, ALPHABET);
        }
        assert_ne!(square, ALPHABET);
        assert_eq!(ORDERS.len(), 24);
    }

    #[test]
    fn a_crib_skips_the_dictionary() {
        // The checker gets to see a decryption that isn't words only when a crib is set,
        // as it then only looks for the crib
        let (plaintext, key) = ("QZQZ".to_string(), "K".to_string());
        assert!(!reads_as_words(&plaintext));
        let shown = |crib| {
            let mut asked = false;
            let outcome = finish(
                plaintext.clone(),
                key.clone(),
                crib,
                &mut Stats::default(),
                &mut |_: &str| {
                    asked = true;
                    None::<()>
                },
            );
            assert!(matches!(outcome, Outcome::Unconfirmed { .. }));
            asked
        };
        assert!(shown(true));
        assert!(!shown(false));
    }

    #[test]
    fn is_registered_once() {
        let name = "Playfair";
        let decoders = crate::filtration_system::get_decoder_by_name(name);
        assert_eq!(decoders.components.len(), 1);
        let decoder = &decoders.components[0];
        assert_eq!(decoder.get_name(), name);
        assert_eq!(
            decoder.get_tags(),
            &vec!["playfair", "digraph", "substitution", "classic", "cipher"]
        );
        assert!(!decoder.get_tags().contains(&"decoder"));
        assert_eq!(decoder.get_popularity(), 0.3);
        assert_eq!(
            decoder.get_link(),
            "https://en.wikipedia.org/wiki/Playfair_cipher"
        );
        assert!(crate::decoders::DECODER_MAP.contains_key(name));
    }

    #[test]
    fn listed_before_vigenere() {
        let decoders = crate::filtration_system::get_all_decoders();
        let position = |wanted: &str| {
            decoders
                .components
                .iter()
                .position(|decoder| decoder.get_name() == wanted)
                .unwrap()
        };
        assert!(position("Playfair") < position("Vigenere"));
    }

    #[test]
    fn quadgram_table() {
        assert_eq!(QUADGRAMS.len(), 26 * 26 * 26 * 26);
        let that = QUADGRAMS[quadgram_index("THAT").unwrap()];
        let unseen = QUADGRAMS[quadgram_index("QXZJ").unwrap()];
        assert!(that > -2.6, "{that}");
        assert!(unseen < -6.9, "{unseen}");
        assert!(QUADGRAMS.iter().all(|&p| p >= unseen && p < 0.0));
        assert_eq!(quadgram_index("abcd"), None);
        assert_eq!(quadgram_index("ABC"), None);
    }

    #[test]
    fn decipher_text_reads_any_case_and_j_as_i() {
        let issue = square(ISSUE_SQUARE);
        assert_eq!(
            decipher_text("bmodz bxdna bekud muixm mouvi f", &issue).as_deref(),
            Some(ISSUE_PLAINTEXT)
        );
        assert_eq!(decipher_text("BMODZ", &issue), None);
        assert_eq!(decipher_text("", &issue), None);
        assert_eq!(decipher_text("JB", &issue), decipher_text("IB", &issue));
    }

    #[test]
    fn rng_is_deterministic_and_in_range() {
        let mut a = Rng::new(42);
        let mut b = Rng::new(42);
        for _ in 0..1000 {
            assert_eq!(a.next_u64(), b.next_u64());
            assert!(a.below(7) < 7);
            b.below(7);
            let unit = a.unit();
            b.unit();
            assert!((0.0..1.0).contains(&unit));
        }
        assert_ne!(Rng::new(1).next_u64(), Rng::new(2).next_u64());
    }
}
