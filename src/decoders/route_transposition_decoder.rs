//! Cracks route transpositions: the scytale, the Caesar box and the route ciphers.
//!
//! The sender writes the text row by row into a grid of N columns, R = ⌈L/N⌉ rows for a
//! text of L characters, and reads it off along a fixed route. In a ragged grid the last
//! row is short, so the first L mod N columns have R cells and the others R − 1, as in
//! the columnar transposition. The routes are:
//!
//! * `columns`: down each column, left to right. This is the scytale, the Caesar box (a
//!   square grid) and Python Ciphey's route decoder. Writing the text down the columns
//!   and reading the rows gives the same permutation.
//! * `rows`: the inverse of `columns`. The sender wrote the text down N ragged columns and
//!   read the rows. It differs from `columns` only when N doesn't divide L.
//! * `snake`: down the first column, up the second, down the third and so on.
//! * `spiral`: inwards from a corner, clockwise or counter-clockwise, on full grids only.
//!   An outward spiral is a reversed inward one, which the search finds as Reverse and
//!   then this decoder.
//!
//! Every character moves, spaces and punctuation included, unless the text is letters in
//! groups (`SXAAU YPOCR DVHFK`) or in one block: then its whitespace is dropped first.
//! See <https://en.wikipedia.org/wiki/Transposition_cipher#Route_cipher> and
//! <https://www.dcode.fr/route-cipher>.
//!
//! There is no key to search: 2 to 20 columns and every route give at most about 150
//! readings. They are ranked by how often their quadgrams (runs of four letters) occur in
//! English, from the table in `src/storage/ngrams/`, and only the best three can reach
//! the checker. Cheap checks run first and reject text that can't be a transposition of
//! English before any reading is made:
//! 1. At most 5,000 characters, at least 10 ASCII letters, and letters make up at least
//!    80% of the characters that aren't whitespace. This rules out hexadecimal, binary,
//!    Morse code and most gibberish in one pass over the text.
//! 2. English letter frequencies. A transposition moves the letters but doesn't change
//!    them, so Base64, Caesar, Vigenère and other substitutions of English, whose letters
//!    are not English's, can't be one.
//! 3. The text doesn't read as English already (by its quadgram score): then there is
//!    nothing to undo.

use super::crack_results::CrackResult;
use super::interface::{check_string_success, Crack, Decoder};
use crate::checkers::CheckerTypes;
use crate::storage::ENGLISH_FREQS;
use gibberish_or_not::Sensitivity;
use log::{debug, trace};
use once_cell::sync::Lazy;
use std::collections::HashSet;
use std::fmt;

/// Number of possible quadgrams, 26⁴.
const QUADGRAM_COUNT: usize = 26 * 26 * 26 * 26;

/// Longer texts are left alone: the search only hands on texts of up to 820 characters
/// after the first step, and every reading moves every character.
const MAX_CHARS: usize = 5_000;

/// Fewer ASCII letters than this and a wrong reading scores as well as the right one.
const MIN_LETTERS: usize = 10;

/// The mean log10 English frequency of the letters of English text, from
/// [`ENGLISH_FREQS`]: Σ p·log10 p is -1.257, and windows of 10 to 400 letters of Ciphey's
/// docs have a median of -1.26 at every length.
const ENGLISH_LETTER_FIT: f64 = -1.26;

/// How far below [`ENGLISH_LETTER_FIT`], times the square root of the number of letters,
/// a transposition of English may score. No window of 10 to 400 letters of Ciphey's docs
/// (594 paragraphs, 88,000 letters) is more than 1.63 below. Base64 of English is always
/// further from 66 letters on, and ROT13 of English 94% of the time; Atbash, other shifts,
/// Vigenère and random letters are in between. Pangrams that use each letter once are just
/// outside, the issue's `SPHINXOFBLACKQUARTZJUDGEMYVOW` among them.
const LETTER_FIT_SPREAD: f64 = 2.0;

/// Texts with more letters than this are held to the bound for this many: their letter
/// frequencies vary with the subject more than by chance.
const LETTER_FIT_LETTERS: usize = 200;

/// Most columns tried. Puzzles rarely use more, and every extra width adds readings that
/// can outscore the right one by chance.
const MAX_COLUMNS: usize = 20;

/// Only this many letters at the start of a reading are scored. That is enough to rank
/// the readings, and keeps the cost of a long text down.
const SCORED_LETTERS: usize = 200;

/// Fitness, the average log10 probability of a text's quadgrams, at or above which it
/// reads as English. Correct readings of English paragraphs score -3.8 to -4.7; the best
/// wrong reading of a text that isn't a route cipher scored -5.06 for plain English,
/// -5.5 for a rail fence of English, -6.5 for ROT13 and -6.7 for Base64.
const ENGLISH_FITNESS: f64 = -4.8;

/// The best reading is shown to the checker if it scores at least this...
const BEST_CHECK_FITNESS: f64 = -5.5;

/// ...and the second and third best if they score at least this.
const NEXT_CHECK_FITNESS: f64 = -5.0;

/// Most readings shown to the checker, best first.
const MAX_CHECKED: usize = 3;

/// A reading without whitespace is only shown to the checker, at High sensitivity, if
/// dictionary words can cover this share of its letters: High accepts most strings of
/// English letters. Correct readings of English paragraphs cover at least 0.92, wrong
/// readings that score well 0.6 to 0.88.
const MIN_COVERAGE: f64 = 0.9;

/// The word coverage of a reading looks at this many letters at most.
const COVERAGE_LETTERS: usize = 1_000;

/// Marks a character that isn't an ASCII letter.
const NOT_A_LETTER: u8 = u8::MAX;

/// log10 probability of every quadgram, indexed by [`quadgram_index`]. The same table
/// the Monoalphabetic Substitution cracker reads.
static QUADGRAMS: Lazy<Box<[f32]>> =
    Lazy::new(|| parse_quadgrams(include_str!("../storage/ngrams/english_quadgrams.txt")));

/// Upper-case English words.
static DICTIONARY: Lazy<Dictionary> =
    Lazy::new(|| Dictionary::parse(include_str!("../storage/ngrams/english_words.txt")));

/// log10 of the English frequency of each letter A to Z.
static LETTER_LOG10: Lazy<[f64; 26]> = Lazy::new(|| ENGLISH_FREQS.map(f64::log10));

/// The route transposition cracker. Call:
/// `let decoder = Decoder::<RouteTranspositionDecoder>::new()` to create one,
/// and `decoder.crack(text, &checker)` to crack `text`.
/// ```
/// use ciphey::checkers::{athena::Athena, checker_type::{Check, Checker}, CheckerTypes};
/// use ciphey::decoders::interface::{Crack, Decoder};
/// use ciphey::decoders::route_transposition_decoder::RouteTranspositionDecoder;
///
/// let decoder = Decoder::<RouteTranspositionDecoder>::new();
/// let checker = CheckerTypes::CheckAthena(Checker::<Athena>::new());
///
/// // Written in rows of 7 characters, spaces included, and read off column by column
/// let result = decoder.crack(
///     "M  ge hbh y eaoh mtret tetltai i haot dhfdanmenr t otnnga dcmhlueid pk heeisrg t,ea.",
///     &checker,
/// );
/// assert!(result.success);
/// assert_eq!(
///     result.unencrypted_text.unwrap()[0],
///     "Meet me at the old lighthouse after midnight and bring the map, the key and a torch."
/// );
/// assert_eq!(result.key.unwrap(), "7 columns");
/// ```
pub struct RouteTranspositionDecoder;

impl Crack for Decoder<RouteTranspositionDecoder> {
    fn new() -> Decoder<RouteTranspositionDecoder> {
        Decoder {
            name: "Route Transposition",
            description: "Scytale, Caesar box and route transposition: the text is written into a grid of N columns and read off by columns, by columns alternating up and down, by rows, or in a spiral. Tries 2–20 columns and every route, ranks the results by English quadgram statistics and checks the best few.",
            link: "https://en.wikipedia.org/wiki/Transposition_cipher#Route_cipher",
            tags: vec!["route", "scytale", "transposition", "classic", "cipher"],
            popularity: 0.4,
            phantom: std::marker::PhantomData,
        }
    }

    /// Tries every route. On success the plaintext is the only element of
    /// `unencrypted_text`, and `key` says how it was read off the grid: `7 columns`,
    /// `6 columns, snake`, `5 columns, written by columns` or `3 columns, spiral
    /// counter-clockwise from bottom-left`. When the checker accepts nothing but the best
    /// reading still reads like English, that reading is returned unconfirmed, so the
    /// search can keep decoding it.
    fn crack(&self, text: &str, checker: &CheckerTypes) -> CrackResult {
        trace!("Trying route transposition with text {:?}", text);
        let mut results = CrackResult::new(self, text.to_string());
        let mut confirm = |candidate: &str, sensitivity: Sensitivity| {
            let result = checker.with_sensitivity(sensitivity).check(candidate);
            result.is_identified.then_some(result)
        };

        match crack_text(text, &mut Stats::default(), &mut confirm) {
            Outcome::Confirmed {
                plaintext,
                key,
                check,
            } => {
                debug!("Route transposition found {key}: {plaintext}");
                results.unencrypted_text = Some(vec![plaintext]);
                results.update_checker(&check);
                results.key = Some(key);
            }
            Outcome::Unconfirmed { plaintext, key } => {
                debug!("Route transposition best guess, {key}: {plaintext}");
                results.unencrypted_text = Some(vec![plaintext]);
                results.key = Some(key);
            }
            Outcome::Failed(reason) => {
                trace!("Route transposition gave up: {reason:?}");
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

/// What [`crack_text`] found. `T` is what the checker returns.
enum Outcome<T> {
    /// The checker accepted this reading.
    Confirmed {
        /// The plaintext.
        plaintext: String,
        /// How it was read off the grid, see [`Key`].
        key: String,
        /// What the checker said.
        check: T,
    },
    /// The checker accepted nothing, but this reading reads like English.
    Unconfirmed {
        /// The best reading.
        plaintext: String,
        /// How it was read off the grid, see [`Key`].
        key: String,
    },
    /// Nothing that reads like English.
    Failed(Reason),
}

/// Why [`crack_text`] failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reason {
    /// More than [`MAX_CHARS`] characters.
    TooLong,
    /// Fewer than [`MIN_LETTERS`] ASCII letters.
    TooFewLetters,
    /// Under 80% of the characters that aren't whitespace are ASCII letters.
    NotLetters,
    /// The letters aren't English letters in another order, see [`fits_english_letters`].
    LetterFrequencies,
    /// It reads as English already.
    AlreadyEnglish,
    /// No reading reads like English, or the checker rejected the ones that do.
    NotFound,
}

/// Counters, so the tests can see how much work was done.
#[derive(Debug, Default)]
struct Stats {
    /// Readings made and scored.
    built: usize,
    /// Readings shown to the checker.
    checked: usize,
}

/// Cracks `text`. The best readings are passed to `confirm` with the sensitivity to
/// check them at, until it returns `Some`.
fn crack_text<T>(
    text: &str,
    stats: &mut Stats,
    confirm: &mut dyn FnMut(&str, Sensitivity) -> Option<T>,
) -> Outcome<T> {
    let counts = match check_letters(text) {
        Ok(counts) => counts,
        Err(reason) => return Outcome::Failed(reason),
    };
    if !fits_english_letters(&counts) {
        return Outcome::Failed(Reason::LetterFrequencies);
    }
    let ciphertext = Ciphertext::new(text);
    if ciphertext.fitness(0..ciphertext.chars.len()) >= ENGLISH_FITNESS {
        return Outcome::Failed(Reason::AlreadyEnglish);
    }

    let transposed: String = ciphertext.chars.iter().collect();
    // The distinct readings looked at so far, best first, with their key and fitness
    let mut considered: Vec<(String, Key, f64)> = Vec::with_capacity(MAX_CHECKED);
    for (key, fitness) in ciphertext.ranked_keys(stats) {
        let bar = if considered.is_empty() {
            BEST_CHECK_FITNESS
        } else {
            NEXT_CHECK_FITNESS
        };
        if considered.len() == MAX_CHECKED || fitness < bar {
            // The rest score lower
            break;
        }
        let candidate = ciphertext.decrypt(key);
        // Equal texts score the same, so a repeat comes right after the first one, but
        // compare with all of them: different routes can give the same text
        if candidate == transposed
            || !check_string_success(&candidate, text)
            || considered.iter().any(|(seen, _, _)| *seen == candidate)
        {
            continue;
        }
        let check = if ciphertext.spaced {
            stats.checked += 1;
            confirm(&candidate, Sensitivity::Low)
        } else if word_coverage(&candidate) >= MIN_COVERAGE {
            // The checker reads unspaced text as one word, and High accepts most of
            // them, so it only sees readings that dictionary words mostly cover
            stats.checked += 1;
            confirm(&candidate, Sensitivity::High)
        } else {
            None
        };
        if let Some(check) = check {
            return Outcome::Confirmed {
                plaintext: candidate,
                key: key.to_string(),
                check,
            };
        }
        considered.push((candidate, key, fitness));
    }

    match considered.into_iter().next() {
        Some((plaintext, key, fitness)) if fitness >= ENGLISH_FITNESS => Outcome::Unconfirmed {
            plaintext,
            key: key.to_string(),
        },
        _ => Outcome::Failed(Reason::NotFound),
    }
}

/// The first cheap check, in one pass over `text` and without allocating: at most
/// [`MAX_CHARS`] characters, at least [`MIN_LETTERS`] ASCII letters, and letters make up at
/// least 80% of the characters that aren't whitespace. Hexadecimal (11% letters), binary,
/// Morse code and the benchmark's gibberish (63%) fail; Base64 (86 to 88%) passes and is
/// left to [`fits_english_letters`]. Returns how often each letter occurs.
fn check_letters(text: &str) -> Result<[usize; 26], Reason> {
    // A character takes at most four bytes
    if text.len() > 4 * MAX_CHARS {
        return Err(Reason::TooLong);
    }
    let mut counts = [0; 26];
    let mut chars = 0;
    let mut letters = 0;
    let mut visible = 0;
    for c in text.chars() {
        chars += 1;
        if c.is_ascii_alphabetic() {
            counts[usize::from(c.to_ascii_uppercase() as u8 - b'A')] += 1;
            letters += 1;
            visible += 1;
        } else if !c.is_whitespace() {
            visible += 1;
        }
    }
    if chars > MAX_CHARS {
        Err(Reason::TooLong)
    } else if letters < MIN_LETTERS {
        Err(Reason::TooFewLetters)
    } else if letters * 5 < visible * 4 {
        Err(Reason::NotLetters)
    } else {
        Ok(counts)
    }
}

/// Whether letters occurring `counts` times could be English letters in another order:
/// their mean log10 English frequency is at most [`LETTER_FIT_SPREAD`] / √letters below
/// [`ENGLISH_LETTER_FIT`]. A transposition doesn't change the letters, so this rejects
/// the Base64, Caesar and Vigenère texts a search mostly sees without making a reading.
fn fits_english_letters(counts: &[usize; 26]) -> bool {
    let letters: usize = counts.iter().sum();
    if letters == 0 {
        return false;
    }
    let total: f64 = counts
        .iter()
        .zip(LETTER_LOG10.iter())
        .map(|(&count, log_freq)| count as f64 * log_freq)
        .sum();
    let bound = LETTER_FIT_SPREAD / (letters.min(LETTER_FIT_LETTERS) as f64).sqrt();
    total / letters as f64 >= ENGLISH_LETTER_FIT - bound
}

/// The characters that are transposed.
struct Ciphertext {
    /// The characters, in ciphertext order.
    chars: Vec<char>,
    /// The letter of each character, upper-cased, as 0 to 25, or [`NOT_A_LETTER`].
    letters: Vec<u8>,
    /// Whether the characters include whitespace. Readings are checked at Low
    /// sensitivity if so, and need dictionary words to cover them if not.
    spaced: bool,
}

impl Ciphertext {
    /// The characters of `text` to transpose: all of them, or the non-whitespace ones if
    /// [`drops_whitespace`] says so.
    fn new(text: &str) -> Ciphertext {
        if drops_whitespace(text) {
            Ciphertext::from_chars(text.chars().filter(|c| !c.is_whitespace()).collect())
        } else {
            Ciphertext::from_chars(text.chars().collect())
        }
    }

    /// `chars`, transposed as they are.
    fn from_chars(chars: Vec<char>) -> Ciphertext {
        let letters = chars
            .iter()
            .map(|&c| {
                if c.is_ascii_alphabetic() {
                    c.to_ascii_uppercase() as u8 - b'A'
                } else {
                    NOT_A_LETTER
                }
            })
            .collect();
        let spaced = chars.iter().any(|c| c.is_whitespace());
        Ciphertext {
            chars,
            letters,
            spaced,
        }
    }

    /// Average log10 probability of the quadgrams of the first [`SCORED_LETTERS`]
    /// letters of the text that `order` reads: its `i`-th character is the `order[i]`-th
    /// character of the ciphertext. Characters that aren't letters are skipped.
    fn fitness(&self, order: impl IntoIterator<Item = usize>) -> f64 {
        let table = &*QUADGRAMS;
        let mut index = 0;
        let mut seen = 0;
        let mut total = 0.0;
        for position in order {
            let letter = self.letters[position];
            if letter == NOT_A_LETTER {
                continue;
            }
            index = (index * 26 + usize::from(letter)) % QUADGRAM_COUNT;
            seen += 1;
            if seen >= 4 {
                total += f64::from(table[index]);
            }
            if seen == SCORED_LETTERS {
                break;
            }
        }
        if seen < 4 {
            return f64::NEG_INFINITY;
        }
        total / (seen - 3) as f64
    }

    /// Every key with the fitness of its reading, best first. Keys that score the same
    /// keep the order of [`keys`].
    fn ranked_keys(&self, stats: &mut Stats) -> Vec<(Key, f64)> {
        let len = self.chars.len();
        let mut order = Vec::with_capacity(len);
        let mut ranked: Vec<(Key, f64)> = keys(len)
            .map(|key| {
                key.order(len, &mut order);
                stats.built += 1;
                (key, self.fitness(order.iter().copied()))
            })
            .collect();
        // A stable sort
        ranked.sort_by(|a, b| b.1.total_cmp(&a.1));
        ranked
    }

    /// The text read off the grid with `key`.
    fn decrypt(&self, key: Key) -> String {
        let mut order = Vec::with_capacity(self.chars.len());
        key.order(self.chars.len(), &mut order);
        order
            .into_iter()
            .map(|position| self.chars[position])
            .collect()
    }
}

/// Whether to drop the whitespace of `text` before transposing it: when it has no
/// whitespace between its characters (a trailing newline, say), and when it is ASCII
/// letters in three or more groups that are all the same length apart from a shorter
/// last one, as ciphertexts are often written (`SXAAU YPOCR DVHFK TGOIB`). Otherwise the
/// whitespace was transposed with the rest of the text, as a rail fence transposes it.
fn drops_whitespace(text: &str) -> bool {
    let groups: Vec<&str> = text.split_whitespace().collect();
    let Some((last, rest)) = groups.split_last() else {
        return true;
    };
    if rest.is_empty() {
        return true;
    }
    let size = groups[0].len();
    groups.len() >= 3
        && rest.iter().all(|group| group.len() == size)
        && last.len() <= size
        && groups
            .iter()
            .all(|group| group.bytes().all(|b| b.is_ascii_alphabetic()))
}

/// One way of reading a text off a grid. The plaintext is written row by row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Route {
    /// Down each column, left to right: the scytale.
    Columns,
    /// Along each row, top to bottom, with the plaintext written down the columns: the
    /// inverse of [`Route::Columns`].
    Rows,
    /// Down the first column, up the second, and so on.
    Snake,
    /// Inwards from `corner`, which only full grids have.
    Spiral {
        /// Where the route starts.
        corner: Corner,
        /// Whether it turns clockwise.
        clockwise: bool,
    },
}

/// A corner of the grid, where a spiral starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Corner {
    /// The first cell of the first row.
    TopLeft,
    /// The last cell of the first row.
    TopRight,
    /// The first cell of the last row.
    BottomLeft,
    /// The last cell of the last row.
    BottomRight,
}

/// Every spiral route, in the order they are tried.
const SPIRALS: [Route; 8] = [
    Route::Spiral {
        corner: Corner::TopLeft,
        clockwise: true,
    },
    Route::Spiral {
        corner: Corner::TopLeft,
        clockwise: false,
    },
    Route::Spiral {
        corner: Corner::TopRight,
        clockwise: true,
    },
    Route::Spiral {
        corner: Corner::TopRight,
        clockwise: false,
    },
    Route::Spiral {
        corner: Corner::BottomLeft,
        clockwise: true,
    },
    Route::Spiral {
        corner: Corner::BottomLeft,
        clockwise: false,
    },
    Route::Spiral {
        corner: Corner::BottomRight,
        clockwise: true,
    },
    Route::Spiral {
        corner: Corner::BottomRight,
        clockwise: false,
    },
];

/// Row and column steps of the four directions, in clockwise order: right, down, left,
/// up. Turning clockwise is the next one, counter-clockwise the one before.
const STEPS: [(isize, isize); 4] = [(0, 1), (1, 0), (0, -1), (-1, 0)];

/// A route and a grid width.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Key {
    /// How the text was read off the grid.
    route: Route,
    /// Number of columns.
    columns: usize,
}

/// Every key for a text of `len` characters: [`Route::Columns`], [`Route::Rows`] and
/// [`Route::Snake`] for 2 to [`MAX_COLUMNS`] columns (but at least two rows), then the
/// spirals for the widths that fill the grid. Of two keys that give the same text, the
/// search reports the one listed first, so the scytale comes first.
fn keys(len: usize) -> impl Iterator<Item = Key> {
    let widest = MAX_COLUMNS.min(len / 2);
    let plain = [Route::Columns, Route::Rows, Route::Snake]
        .into_iter()
        .flat_map(move |route| (2..=widest).map(move |columns| Key { route, columns }));
    let spirals = (2..=widest)
        .filter(move |&columns| len.is_multiple_of(columns))
        .flat_map(|columns| SPIRALS.into_iter().map(move |route| Key { route, columns }));
    plain.chain(spirals)
}

impl Key {
    /// Fills `order` with the ciphertext position of each character of the plaintext of
    /// a text of `len` characters: plaintext character `i` is ciphertext character
    /// `order[i]`.
    fn order(self, len: usize, order: &mut Vec<usize>) {
        order.clear();
        let columns = self.columns;
        let rows = len.div_ceil(columns);
        // Columns that have a cell in the last row
        let full = match len % columns {
            0 => columns,
            short => short,
        };
        // Where each column starts in a text read off column by column, and where the
        // last one ends: the first `full` columns are `rows` long, the others one less
        let mut starts = [0; MAX_COLUMNS + 1];
        for column in 0..columns {
            let height = if column < full { rows } else { rows - 1 };
            starts[column + 1] = starts[column] + height;
        }
        let width = |row: usize| if row + 1 == rows { full } else { columns };

        match self.route {
            Route::Columns => {
                for row in 0..rows {
                    order.extend((0..width(row)).map(|column| starts[column] + row));
                }
            }
            Route::Snake => {
                for row in 0..rows {
                    order.extend((0..width(row)).map(|column| {
                        if column % 2 == 0 {
                            starts[column] + row
                        } else {
                            starts[column + 1] - 1 - row
                        }
                    }));
                }
            }
            Route::Rows => {
                for column in 0..columns {
                    let height = starts[column + 1] - starts[column];
                    order.extend((0..height).map(|row| row * columns + column));
                }
            }
            Route::Spiral { corner, clockwise } => {
                spiral(rows, columns, corner, clockwise, order);
            }
        }
        debug_assert_eq!(order.len(), len);
    }
}

/// Fills `order` as [`Key::order`] does for a spiral over a full grid of `rows` by
/// `columns` cells: the route starts at `corner`, runs along the edge and turns at each
/// corner, then does the same on the grid inside. Each run but the first two is one cell
/// shorter than the run two before it: a route that starts along a row runs `columns`,
/// `rows - 1`, `columns - 1`, `rows - 2`, ... cells, until a run would be empty.
fn spiral(rows: usize, columns: usize, corner: Corner, clockwise: bool, order: &mut Vec<usize>) {
    let len = rows * columns;
    order.resize(len, 0);
    // The start, and the first direction as an index into STEPS. Clockwise from the top
    // left goes right, counter-clockwise goes down, and so on.
    let (start_row, start_column, mut direction) = match (corner, clockwise) {
        (Corner::TopLeft, true) => (0, 0, 0),
        (Corner::TopLeft, false) => (0, 0, 1),
        (Corner::TopRight, true) => (0, columns - 1, 1),
        (Corner::TopRight, false) => (0, columns - 1, 2),
        (Corner::BottomRight, true) => (rows - 1, columns - 1, 2),
        (Corner::BottomRight, false) => (rows - 1, columns - 1, 3),
        (Corner::BottomLeft, true) => (rows - 1, 0, 3),
        (Corner::BottomLeft, false) => (rows - 1, 0, 0),
    };
    let turn = if clockwise { 1 } else { 3 };
    // Cells in this run, and in the run before it
    let (mut run, mut previous) = if STEPS[direction].0 == 0 {
        (columns, rows)
    } else {
        (rows, columns)
    };
    // One step before the start, so that every run steps onto its first cell
    let (row_step, column_step) = STEPS[direction];
    let mut row = start_row as isize - row_step;
    let mut column = start_column as isize - column_step;
    let mut step = 0;
    while run > 0 {
        let (row_step, column_step) = STEPS[direction];
        for _ in 0..run {
            row += row_step;
            column += column_step;
            order[row as usize * columns + column as usize] = step;
            step += 1;
        }
        direction = (direction + turn) % 4;
        // `previous` is at least 1: the grid's other side, or the run before this one
        (run, previous) = (previous - 1, run);
    }
    debug_assert_eq!(step, len);
}

impl Corner {
    /// The corner's name in a key.
    fn name(self) -> &'static str {
        match self {
            Corner::TopLeft => "top-left",
            Corner::TopRight => "top-right",
            Corner::BottomLeft => "bottom-left",
            Corner::BottomRight => "bottom-right",
        }
    }
}

impl fmt::Display for Key {
    /// `5 columns`, `6 columns, snake`, `5 columns, written by columns` or
    /// `3 columns, spiral counter-clockwise from bottom-left`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} columns", self.columns)?;
        match self.route {
            Route::Columns => Ok(()),
            Route::Rows => write!(f, ", written by columns"),
            Route::Snake => write!(f, ", snake"),
            Route::Spiral { corner, clockwise } => write!(
                f,
                ", spiral {} from {}",
                if clockwise {
                    "clockwise"
                } else {
                    "counter-clockwise"
                },
                corner.name()
            ),
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
    let mut counts = vec![0u64; QUADGRAM_COUNT];
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

/// Upper-case English words, for telling which readings without spaces read as English.
struct Dictionary {
    /// The words.
    words: HashSet<&'static str>,
    /// Length of the longest word.
    longest: usize,
}

impl Dictionary {
    /// Reads one word per line, skipping `#` comments.
    fn parse(data: &'static str) -> Dictionary {
        let words: HashSet<&str> = data
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .collect();
        let longest = words.iter().map(|word| word.len()).max().unwrap_or(0);
        Dictionary { words, longest }
    }

    /// Whether the upper-case ASCII letters `word` are a word.
    fn contains(&self, word: &[u8]) -> bool {
        word.len() <= self.longest
            && std::str::from_utf8(word).is_ok_and(|word| self.words.contains(word))
    }
}

/// The share of the letters of `plaintext` that dictionary words can cover, with the
/// words placed so that they cover as many as possible. Only the first
/// [`COVERAGE_LETTERS`] letters are looked at.
fn word_coverage(plaintext: &str) -> f64 {
    let letters: Vec<u8> = plaintext
        .bytes()
        .filter(u8::is_ascii_alphabetic)
        .take(COVERAGE_LETTERS)
        .map(|b| b.to_ascii_uppercase())
        .collect();
    if letters.is_empty() {
        return 0.0;
    }
    let dictionary = &*DICTIONARY;
    // covered[i]: the most letters of letters[..i] that words can cover
    let mut covered = vec![0usize; letters.len() + 1];
    for start in 0..letters.len() {
        covered[start + 1] = covered[start + 1].max(covered[start]);
        let longest = dictionary.longest.min(letters.len() - start);
        for len in 1..=longest {
            let end = start + len;
            if dictionary.contains(&letters[start..end]) {
                covered[end] = covered[end].max(covered[start] + len);
            }
        }
    }
    covered[letters.len()] as f64 / letters.len() as f64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkers::{
        athena::Athena,
        checker_result::CheckResult,
        checker_type::{Check, Checker},
    };

    /// The bench `medium` plaintext.
    const LIGHTHOUSE: &str =
        "Meet me at the old lighthouse after midnight and bring the map, the key and a torch.";

    /// [`LIGHTHOUSE`] in rows of 7 characters, spaces and punctuation included, read off
    /// by columns. Made by the issue's Python prototype and decoded back by Python
    /// Ciphey's `route.py` (`decode_with(7)`, git `dbd5aa95`).
    const LIGHTHOUSE_7_COLUMNS: &str =
        "M  ge hbh y eaoh mtret tetltai i haot dhfdanmenr t otnnga dcmhlueid pk heeisrg t,ea.";

    /// The letters of [`LIGHTHOUSE`], upper case.
    const LIGHTHOUSE_LETTERS: &str =
        "MEETMEATTHEOLDLIGHTHOUSEAFTERMIDNIGHTANDBRINGTHEMAPTHEKEYANDATORCH";

    /// The pangram of the issue.
    const SPHINX: &str = "SPHINXOFBLACKQUARTZJUDGEMYVOW";

    /// [`SPHINX`] in 5 columns, the issue's example. pycipher's `ColTrans("ABCDE")` gives
    /// the same.
    const SPHINX_5_COLUMNS: &str = "SXAAUYPOCRDVHFKTGOIBQZEWNLUJM";

    /// The lighthouse letters in 7 columns, a ragged grid (66 = 9 · 7 + 3).
    const LETTERS_7_COLUMNS: &str =
        "MTLURHIAYRETISMTNPACEHGEIAGTNHTEHADNTHDMOTFNDHEAELHTIBEKTADOEGRMEO";

    /// The bench `miss` input, which every decoder rejects.
    const MISS: &str =
        "T00 l3= ox+#G WKyV pajU6j qxH@ %B4+a 5Pn^ 7p_v1q 9sLvu *+36i R5rL&3 mVJZI iO0 Ut8_m COTV";

    /// [`LIGHTHOUSE`] in hexadecimal, the bench `medium` input of that decoder.
    const HEX: &str = "4d656574206d6520617420746865206f6c64206c69676874686f757365206166746572206d69646e6967687420616e64206272696e6720746865206d61702c20746865206b657920616e64206120746f7263682e";

    /// [`LIGHTHOUSE`] in Base64, the bench `medium` input of that decoder.
    const BASE64: &str = "TWVldCBtZSBhdCB0aGUgb2xkIGxpZ2h0aG91c2UgYWZ0ZXIgbWlkbmlnaHQgYW5kIGJyaW5nIHRoZSBtYXAsIHRoZSBrZXkgYW5kIGEgdG9yY2gu";

    /// [`LIGHTHOUSE`] in ROT13, Atbash and Vigenère (key KEY), the bench `medium` inputs
    /// of those decoders.
    const SUBSTITUTIONS: [&str; 3] = [
        "Zrrg zr ng gur byq yvtugubhfr nsgre zvqavtug naq oevat gur znc, gur xrl naq n gbepu.",
        "Nvvg nv zg gsv low ortsgslfhv zugvi nrwmrtsg zmw yirmt gsv nzk, gsv pvb zmw z glixs.",
        "Wicd qc kx rri mvh jskfdlmewc kjrov kshlskfd eln fpsre dlc wen, dlc uiw krb k xmbgf.",
    ];

    /// The bench `long` plaintext.
    const CIPHEY: &str = "Ciphey is an automated decoding tool. You give it encrypted or encoded text and it tries to work out what was done to it, without you having to know the key or even the cipher. It searches through many possible decodings, checks each candidate to see whether it looks like English or matches a known pattern such as an email address, and stops when it finds something that reads like plaintext. Most of the time this takes less than a second, which makes it handy for capture the flag challenges, puzzle hunts and for anyone who stumbles across a strange string in a log file.";

    /// A reading of a text, as [`rank_candidates`] lists them.
    #[derive(Debug)]
    struct Ranked {
        /// How the text was read off the grid.
        key: Key,
        /// The reading.
        text: String,
        /// Its quadgram fitness.
        fitness: f64,
    }

    /// Every distinct reading of `text` other than `text` itself, best first, with no
    /// checks. Shows how texts the checker can't confirm are ranked.
    fn rank_candidates(text: &str) -> Vec<Ranked> {
        let ciphertext = Ciphertext::new(text);
        let transposed: String = ciphertext.chars.iter().collect();
        let mut seen = HashSet::new();
        ciphertext
            .ranked_keys(&mut Stats::default())
            .into_iter()
            .map(|(key, fitness)| Ranked {
                key,
                text: ciphertext.decrypt(key),
                fitness,
            })
            .filter(|ranked| ranked.text != transposed && seen.insert(ranked.text.clone()))
            .collect()
    }

    /// The Athena checker, as the search uses it.
    fn athena() -> CheckerTypes {
        CheckerTypes::CheckAthena(Checker::<Athena>::new())
    }

    /// `crack` with the Athena checker.
    fn crack(text: &str) -> CrackResult {
        Decoder::<RouteTranspositionDecoder>::new().crack(text, &athena())
    }

    /// [`crack_text`] with the Athena checker, and the sensitivity of every check.
    fn crack_counted(text: &str) -> (Outcome<CheckResult>, Stats, Vec<Sensitivity>) {
        let checker = athena();
        let mut stats = Stats::default();
        let mut asked = Vec::new();
        let mut confirm = |candidate: &str, sensitivity: Sensitivity| {
            asked.push(sensitivity);
            let result = checker.with_sensitivity(sensitivity).check(candidate);
            result.is_identified.then_some(result)
        };
        let outcome = crack_text(text, &mut stats, &mut confirm);
        (outcome, stats, asked)
    }

    /// Asserts that `crack` finds `plaintext` with `key`, after at most three checks.
    #[track_caller]
    fn assert_cracks(ciphertext: &str, plaintext: &str, key: &str) {
        let result = crack(ciphertext);
        assert!(result.success, "{ciphertext:?} wasn't cracked: {result:?}");
        assert_eq!(
            result.unencrypted_text.as_deref(),
            Some(&[plaintext.to_string()][..])
        );
        assert_eq!(result.key.as_deref(), Some(key));
        assert!(check_string_success(plaintext, ciphertext));

        let (outcome, stats, asked) = crack_counted(ciphertext);
        assert!(matches!(outcome, Outcome::Confirmed { .. }));
        assert!(stats.checked <= MAX_CHECKED, "{stats:?}");
        assert_eq!(stats.checked, asked.len());
    }

    /// Asserts that `crack` returns nothing for `text`.
    #[track_caller]
    fn assert_fails(text: &str) {
        let result = crack(text);
        assert!(!result.success, "{text:?}: {result:?}");
        assert!(result.unencrypted_text.is_none(), "{text:?}: {result:?}");
        assert!(result.key.is_none(), "{text:?}: {result:?}");
    }

    /// Asserts that the cheap checks reject `text` for `reason` before any reading is
    /// made or checked.
    #[track_caller]
    fn assert_rejected_early(text: &str, reason: Reason) {
        let (outcome, stats, asked) = crack_counted(text);
        assert!(
            matches!(outcome, Outcome::Failed(found) if found == reason),
            "{text:?} should fail with {reason:?}"
        );
        assert_eq!(stats.built, 0, "{text:?}");
        assert!(asked.is_empty(), "{text:?}");
    }

    /// Writes `plaintext` into the grid of `key` and reads it off: the inverse of
    /// [`Ciphertext::decrypt`].
    fn encrypt(plaintext: &str, key: Key) -> String {
        let chars: Vec<char> = plaintext.chars().collect();
        let mut order = Vec::new();
        key.order(chars.len(), &mut order);
        let mut ciphertext = vec!['\0'; chars.len()];
        for (&position, &c) in order.iter().zip(&chars) {
            ciphertext[position] = c;
        }
        ciphertext.into_iter().collect()
    }

    /// The columnar transposition with the key in alphabetical order (pycipher's
    /// `ColTrans("ABCDE"[:columns]).encipher`, but keeping every character): write the
    /// text in rows of `columns` characters, then read each column top to bottom.
    fn scytale_reference(plaintext: &str, columns: usize) -> String {
        let chars: Vec<char> = plaintext.chars().collect();
        (0..columns)
            .flat_map(|column| chars.iter().skip(column).step_by(columns))
            .collect()
    }

    /// A key, for short tests.
    fn key(route: Route, columns: usize) -> Key {
        Key { route, columns }
    }

    /// `text` in groups of five characters, as ciphertexts are often written.
    fn in_groups_of_five(text: &str) -> String {
        let chars: Vec<char> = text.chars().collect();
        chars
            .chunks(5)
            .map(|group| group.iter().collect::<String>())
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// The spiral starting at `corner`.
    fn spiral_from(corner: Corner, clockwise: bool) -> Route {
        Route::Spiral { corner, clockwise }
    }

    #[test]
    fn every_order_is_a_permutation() {
        for len in 4..=120 {
            for key in keys(len) {
                let mut order = Vec::new();
                key.order(len, &mut order);
                let mut sorted = order.clone();
                sorted.sort_unstable();
                assert!(
                    sorted.iter().copied().eq(0..len),
                    "{key:?} on {len} characters: {order:?}"
                );
            }
        }
    }

    #[test]
    fn columns_match_the_columnar_transposition() {
        let text: String = CIPHEY.chars().take(97).collect();
        for len in [10, 29, 64, 66, 84, 97] {
            let plaintext: String = text.chars().take(len).collect();
            for columns in 2..=MAX_COLUMNS.min(len / 2) {
                let ciphertext = scytale_reference(&plaintext, columns);
                let ciphertext = Ciphertext::from_chars(ciphertext.chars().collect());
                assert_eq!(
                    ciphertext.decrypt(key(Route::Columns, columns)),
                    plaintext,
                    "{columns} columns, {len} characters"
                );
            }
        }
    }

    #[test]
    fn rows_are_the_inverse_of_columns() {
        for len in 10..=60 {
            let plaintext: String = CIPHEY.chars().take(len).collect();
            for columns in 2..=MAX_COLUMNS.min(len / 2) {
                // Reading the rows undoes reading the columns...
                let by_columns = encrypt(&plaintext, key(Route::Columns, columns));
                assert_eq!(
                    encrypt(&by_columns, key(Route::Rows, columns)),
                    plaintext,
                    "{columns} columns, {len} characters"
                );
                // ...and on a full grid it is reading the columns of the other width
                if len.is_multiple_of(columns) && len / columns <= MAX_COLUMNS {
                    assert_eq!(
                        encrypt(&plaintext, key(Route::Rows, columns)),
                        encrypt(&plaintext, key(Route::Columns, len / columns))
                    );
                }
            }
        }
    }

    #[test]
    fn decrypt_undoes_encrypt() {
        for len in [10, 12, 29, 36, 64, 66, 84, 100] {
            let plaintext: String = CIPHEY.chars().take(len).collect();
            for key in keys(len) {
                let ciphertext = encrypt(&plaintext, key);
                assert_eq!(
                    Ciphertext::from_chars(ciphertext.chars().collect()).decrypt(key),
                    plaintext,
                    "{key}"
                );
            }
        }
    }

    #[test]
    fn spirals_walk_the_edge_inwards() {
        // 3 rows of 4 letters:
        //   A B C D
        //   E F G H
        //   I J K L
        let grid = "ABCDEFGHIJKL";
        let read = |corner, clockwise| encrypt(grid, key(spiral_from(corner, clockwise), 4));
        assert_eq!(read(Corner::TopLeft, true), "ABCDHLKJIEFG");
        assert_eq!(read(Corner::TopLeft, false), "AEIJKLHDCBFG");
        assert_eq!(read(Corner::TopRight, true), "DHLKJIEABCGF");
        assert_eq!(read(Corner::TopRight, false), "DCBAEIJKLHGF");
        assert_eq!(read(Corner::BottomLeft, true), "IEABCDHLKJFG");
        assert_eq!(read(Corner::BottomLeft, false), "IJKLHDCBAEFG");
        assert_eq!(read(Corner::BottomRight, true), "LKJIEABCDHGF");
        assert_eq!(read(Corner::BottomRight, false), "LHDCBAEIJKGF");
    }

    #[test]
    fn keys_are_counted_as_in_the_issue() {
        // 3 routes for 2 to 14 columns
        assert_eq!(keys(29).count(), 39);
        // ...for 2 to 20 columns, and 8 spirals for each of 2, 3, 4, 6, 7, 12 and 14
        assert_eq!(keys(84).count(), 19 * 3 + 7 * 8);
        // Distinct readings: the issue counts 35, 106 and 128
        assert_eq!(rank_candidates(SPHINX_5_COLUMNS).len(), 35);
        assert_eq!(rank_candidates(LIGHTHOUSE_7_COLUMNS).len(), 106);
        let long = encrypt(CIPHEY, key(Route::Columns, 9));
        assert_eq!(rank_candidates(&long).len(), 128);
    }

    #[test]
    fn keys_are_named() {
        assert_eq!(key(Route::Columns, 5).to_string(), "5 columns");
        assert_eq!(key(Route::Snake, 6).to_string(), "6 columns, snake");
        assert_eq!(
            key(Route::Rows, 5).to_string(),
            "5 columns, written by columns"
        );
        assert_eq!(
            key(spiral_from(Corner::BottomLeft, false), 3).to_string(),
            "3 columns, spiral counter-clockwise from bottom-left"
        );
        assert_eq!(
            key(spiral_from(Corner::TopRight, true), 11).to_string(),
            "11 columns, spiral clockwise from top-right"
        );
    }

    // The vectors of the issue: made by its Python prototype; the `columns` ones decode
    // back with Python Ciphey's `route.py` (`decode_with(cols)`, git `dbd5aa95`), and the
    // letters-only ones also match pycipher 0.5.2 `ColTrans("ABCDE…"[:N]).encipher`.

    #[test]
    fn issue_pangram_is_ranked_first_but_not_confirmed() {
        // 5 columns. Athena rejects this pangram at every sensitivity, and dictionary
        // words cover only 76% of it, so it would never be checked. Its letters, one of
        // each, are too far from English frequencies for crack to rank it at all.
        let ranked = rank_candidates(SPHINX_5_COLUMNS);
        assert_eq!(ranked[0].key, key(Route::Columns, 5));
        assert_eq!(ranked[0].text, SPHINX);
        assert!((ranked[0].fitness + 5.72).abs() < 0.01, "{ranked:?}");
        assert!(word_coverage(SPHINX) < MIN_COVERAGE);

        assert_rejected_early(SPHINX_5_COLUMNS, Reason::LetterFrequencies);
        assert_fails(SPHINX_5_COLUMNS);
    }

    #[test]
    fn pangram_with_common_letters_is_cracked() {
        // Unlike the issue's pangram, this one repeats THE and passes the letter check
        let plaintext = "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG";
        assert_cracks(
            &encrypt(plaintext, key(Route::Columns, 5)),
            plaintext,
            "5 columns",
        );
    }

    #[test]
    fn issue_pangram_in_groups_of_five_is_ranked_first() {
        let grouped = in_groups_of_five(SPHINX_5_COLUMNS);
        assert_eq!(grouped, "SXAAU YPOCR DVHFK TGOIB QZEWN LUJM");
        let ranked = rank_candidates(&grouped);
        assert_eq!(ranked[0].key, key(Route::Columns, 5));
        assert_eq!(ranked[0].text, SPHINX);
        assert_fails(&grouped);
    }

    #[test]
    fn cracks_hello_world() {
        // Python Ciphey's tests/test_rail_route.py; 4 columns
        assert_cracks("HOLEWDLOLR", "HELLOWORLD", "4 columns");
    }

    #[test]
    fn cracks_two_columns() {
        // Also a rail fence with 2 rails
        assert_cracks(
            "MEMATELLGTOSATRINGTNBIGHMPHKYNAOCETETHODIHHUEFEMDIHADRNTEATEEADTRH",
            LIGHTHOUSE_LETTERS,
            "2 columns",
        );
    }

    #[test]
    fn cracks_a_ragged_grid() {
        // 66 = 9 · 7 + 3
        assert_cracks(LETTERS_7_COLUMNS, LIGHTHOUSE_LETTERS, "7 columns");
    }

    #[test]
    fn cracks_a_snake() {
        assert_cracks(
            "MALTAITIMKATEANADFHDTEETLOTNNGPYORATTDIEUIHTMEGSRGBHHNCHDEERHMEHOE",
            LIGHTHOUSE_LETTERS,
            "6 columns, snake",
        );
    }

    #[test]
    fn cracks_text_written_by_columns() {
        assert_cracks(
            "MLEBEEIRRKEGMIETHINYMTDGAEHNTNAOIHDTUGEATSHMTHETAOEAAPROFNTCLTDHHD",
            LIGHTHOUSE_LETTERS,
            "5 columns, written by columns",
        );
    }

    #[test]
    fn cracks_a_spiral() {
        // 6 rows of 11
        assert_cracks(
            "EUNNKHCROTADNAYEGISOMEETMEATTHODIEHTPAMEHTGELDLIGHTHIRBDNATHAFTERM",
            LIGHTHOUSE_LETTERS,
            "11 columns, spiral clockwise from top-right",
        );
    }

    #[test]
    fn cracks_a_caesar_box() {
        // 8 × 8 = 64 letters
        assert_cracks(
            "MTGANBMYEHHFIRAAEETTGIPNTOHEHNTDMLORTGHAEDUMATETALSINHKOTIEDDEER",
            "MEETMEATTHEOLDLIGHTHOUSEAFTERMIDNIGHTANDBRINGTHEMAPTHEKEYANDATOR",
            "8 columns",
        );
    }

    #[test]
    fn cracks_the_wikipedia_route_cipher() {
        // https://en.wikipedia.org/wiki/Transposition_cipher#Route_cipher writes the
        // plaintext down the columns of 3 rows and reads clockwise from the top right:
        // on the grid written in rows that is counter-clockwise from the bottom left.
        assert_cracks(
            "EJXCTEDECDAEWRIORFEONALEVSE",
            "WEAREDISCOVEREDFLEEATONCEJX",
            "3 columns, spiral counter-clockwise from bottom-left",
        );
    }

    #[test]
    fn cracks_spaced_text_at_low_sensitivity() {
        assert_cracks(LIGHTHOUSE_7_COLUMNS, LIGHTHOUSE, "7 columns");
        let (_, _, asked) = crack_counted(LIGHTHOUSE_7_COLUMNS);
        assert_eq!(asked, [Sensitivity::Low]);
    }

    #[test]
    fn checks_unspaced_text_at_high_sensitivity() {
        let (_, _, asked) = crack_counted("HOLEWDLOLR");
        assert_eq!(asked, [Sensitivity::High]);
    }

    #[test]
    fn cracks_letters_in_groups_of_five() {
        let grouped = in_groups_of_five(LETTERS_7_COLUMNS);
        assert!(grouped.starts_with("MTLUR HIAYR ETISM"));
        assert_cracks(&grouped, LIGHTHOUSE_LETTERS, "7 columns");
    }

    #[test]
    fn cracks_a_trailing_newline() {
        assert_cracks("HOLEWDLOLR\n", "HELLOWORLD", "4 columns");
    }

    #[test]
    fn keeps_case_and_punctuation() {
        let plaintext = "Attack at Dawn! The Enemy is weak, so bring the Map.";
        let ciphertext = encrypt(plaintext, key(Route::Snake, 5));
        assert_cracks(&ciphertext, plaintext, "5 columns, snake");
    }

    #[test]
    fn non_ascii_characters_move_with_the_text() {
        let plaintext =
            "Meet me at the café after midnight and bring the map, the key and a torch.";
        let ciphertext = encrypt(plaintext, key(Route::Columns, 6));
        assert_cracks(&ciphertext, plaintext, "6 columns");
    }

    #[test]
    fn long_text_is_ranked_and_cracked() {
        // The bench `long` input: 576 characters in 9 columns
        let ciphertext = encrypt(CIPHEY, key(Route::Columns, 9));
        assert!(ciphertext
            .starts_with("C ad.eyeetots oakkepstabicc h khhwn   s mh ioeil ,aachh,h nurriliati"));
        let ranked = rank_candidates(&ciphertext);
        assert_eq!(ranked[0].key, key(Route::Columns, 9));
        assert!(ranked[1].fitness < BEST_CHECK_FITNESS, "{:?}", ranked[1]);
        assert_cracks(&ciphertext, CIPHEY, "9 columns");
    }

    #[test]
    fn hackvent_scytale_is_ranked_first() {
        // Hackvent 2014, "Day 03: Candle 1"
        // (https://raw.githubusercontent.com/shiltemann/CTF-writeups-public/master/Hackvent_2014/dec03.md).
        // Half of the plaintext is Base32, so it scores too low to be checked.
        let ranked = rank_candidates(
            "WAIYTELZEREMSOK3TEBZWETUE2EB2HIRMRYGBUGKSRASIIXGQ5HYSESYWCZDYCACBS43JIOHNRAA3DAURDES2DGO",
        );
        assert_eq!(ranked[0].key, key(Route::Columns, 9));
        assert_eq!(
            ranked[0].text,
            "WEWISHYOUAMERRYCHRISTMASANDYOURSECRETKEYISBASE32GIYSA2LTEBXW43DZEBUGC3DGEB2GQZJAORZHK5DI"
        );
    }

    #[test]
    fn cheap_checks_reject_before_any_reading() {
        assert_rejected_early("", Reason::TooFewLetters);
        assert_rejected_early("😀", Reason::TooFewLetters);
        assert_rejected_early("ab", Reason::TooFewLetters);
        // The issue's hex has only 4 letters (a to f); the bench's has 11% letters
        assert_rejected_early(
            "4d656574206d6520617420746865206f6c64",
            Reason::TooFewLetters,
        );
        assert_rejected_early(HEX, Reason::NotLetters);
        assert_rejected_early(MISS, Reason::NotLetters);
        assert_rejected_early(BASE64, Reason::LetterFrequencies);
        assert_rejected_early("hello world", Reason::AlreadyEnglish);
        assert_rejected_early(LIGHTHOUSE, Reason::AlreadyEnglish);
        assert_rejected_early(LIGHTHOUSE_LETTERS, Reason::AlreadyEnglish);
        assert_rejected_early(&"a".repeat(MAX_CHARS + 1), Reason::TooLong);
        assert_rejected_early(&"😀".repeat(MAX_CHARS + 1), Reason::TooLong);
    }

    #[test]
    fn fails_without_panicking() {
        for text in [
            "",
            "😀",
            "ab",
            "hello world",
            LIGHTHOUSE,
            "4d656574206d6520617420746865206f6c64",
            "aGVsbG8gdGhlcmUgZ2VuZXJhbA==",
            MISS,
            // The bench rail fence input: its best reading scores -5.53
            "M ahlihetmi  nhatkaaretm tteodlgtos fe ingtadbigtemp h e n  oc.ee   huardhnr  ,eydth",
            "!!!!!!!!!!abcdefghij",
            "aaaaaaaaaaaaaaaaaaaaaaaaa",
            "😀😀😀😀😀😀😀😀 abcdefghijklmnopqrstuvwxyz",
        ] {
            assert_fails(text);
        }
    }

    #[test]
    fn letters_of_other_ciphers_are_rejected_before_any_reading() {
        // Base64, ROT13, Atbash and Vigenère of the lighthouse sentence: the letters of a
        // transposition of English are English letters, and these aren't
        assert_rejected_early(BASE64, Reason::LetterFrequencies);
        for text in SUBSTITUTIONS {
            assert_rejected_early(text, Reason::LetterFrequencies);
        }
        // Base64 of a short text can get through, and is ranked out without a check
        let short = "dGhlIGtleSBpcyBoZXJl";
        assert!(fits_english_letters(&check_letters(short).unwrap()));
        let (outcome, stats, asked) = crack_counted(short);
        assert!(matches!(outcome, Outcome::Failed(Reason::NotFound)));
        assert!(stats.built > 0);
        assert!(asked.is_empty());
    }

    #[test]
    fn english_letters_fit() {
        let fits = |text: &str| fits_english_letters(&check_letters(text).unwrap());
        for text in [
            LIGHTHOUSE,
            LIGHTHOUSE_LETTERS,
            LIGHTHOUSE_7_COLUMNS,
            "HOLEWDLOLR",
            "EJXCTEDECDAEWRIORFEONALEVSE",
            CIPHEY,
        ] {
            assert!(fits(text), "{text:?}");
        }
        assert!(!fits(BASE64));
        assert!(!fits("XYZZYQUUXJAZZ"));
    }

    #[test]
    fn ciphertext_of_other_ciphers_is_not_checked() {
        // Substitutions keep the letters in place, so no reading puts them back in an
        // English order. With their spaces, and without them.
        for text in SUBSTITUTIONS {
            let unspaced: String = text.chars().filter(char::is_ascii_alphabetic).collect();
            for text in [text, unspaced.as_str()] {
                let (outcome, stats, asked) = crack_counted(text);
                assert!(matches!(outcome, Outcome::Failed(_)), "{text:?}");
                assert!(asked.is_empty(), "{text:?} was checked ({stats:?})");
            }
        }
    }

    #[test]
    fn checks_at_most_three_readings() {
        // A checker that accepts nothing sees the best reading and at most two more
        for text in [
            LIGHTHOUSE_7_COLUMNS,
            "HOLEWDLOLR",
            "MLEBEEIRRKEGMIETHINYMTDGAEHNTNAOIHDTUGEATSHMTHETAOEAAPROFNTCLTDHHD",
            "EUNNKHCROTADNAYEGISOMEETMEATTHODIEHTPAMEHTGELDLIGHTHIRBDNATHAFTERM",
            "EJXCTEDECDAEWRIORFEONALEVSE",
        ] {
            let mut calls = 0;
            let mut reject = |_: &str, _: Sensitivity| -> Option<()> {
                calls += 1;
                None
            };
            let mut stats = Stats::default();
            let outcome = crack_text(text, &mut stats, &mut reject);
            assert!(
                (1..=MAX_CHECKED).contains(&calls),
                "{text:?}: {calls} checks"
            );
            assert_eq!(stats.checked, calls);
            // The best reading reads like English, so it is handed on unconfirmed
            assert!(
                matches!(outcome, Outcome::Unconfirmed { .. }),
                "{text:?} should give an unconfirmed reading"
            );
        }
    }

    #[test]
    fn unconfirmed_reading_is_returned_without_success() {
        let mut reject = |_: &str, _: Sensitivity| -> Option<()> { None };
        let outcome = crack_text(LIGHTHOUSE_7_COLUMNS, &mut Stats::default(), &mut reject);
        match outcome {
            Outcome::Unconfirmed { plaintext, key } => {
                assert_eq!(plaintext, LIGHTHOUSE);
                assert_eq!(key, "7 columns");
            }
            _ => panic!("expected an unconfirmed reading"),
        }
    }

    #[test]
    fn readings_equal_to_the_input_are_skipped() {
        // Every reading of one repeated letter is the input itself
        let (outcome, stats, asked) = crack_counted("EEEEEEEEEEEEEEEEEEEE");
        assert!(matches!(outcome, Outcome::Failed(Reason::NotFound)));
        assert!(stats.built > 0);
        assert!(asked.is_empty());
        assert!(rank_candidates("EEEEEEEEEEEEEEEEEEEE").is_empty());
    }

    #[test]
    fn whitespace_is_dropped_only_between_groups_of_letters() {
        assert!(drops_whitespace("SXAAU YPOCR DVHFK TGOIB QZEWN LUJM"));
        assert!(drops_whitespace("HOLEWDLOLR"));
        assert!(drops_whitespace("  HOLEWDLOLR\n"));
        assert!(drops_whitespace(""));
        // Two groups, groups of different lengths, or something besides letters
        assert!(!drops_whitespace("SXAAU YPOCR"));
        assert!(!drops_whitespace("SXAAU YPOCR DVHF TGOIB"));
        assert!(!drops_whitespace("SXAAU YPOCR DVHFK TGOIB QZEWN LUJMEE"));
        assert!(!drops_whitespace("SXAA, YPOC. DVHF"));
        assert!(!drops_whitespace(LIGHTHOUSE_7_COLUMNS));
    }

    #[test]
    fn fitness_matches_the_issue() {
        let fitness = |text: &str| {
            let ciphertext = Ciphertext::new(text);
            ciphertext.fitness(0..ciphertext.chars.len())
        };
        // Correct readings score -3.8 to -4.7, so these read as English...
        assert!(fitness(LIGHTHOUSE) >= ENGLISH_FITNESS);
        assert!(fitness(LIGHTHOUSE_LETTERS) >= ENGLISH_FITNESS);
        assert!(fitness("HELLOWORLD") >= ENGLISH_FITNESS);
        // ...and their transpositions don't
        assert!(fitness(LIGHTHOUSE_7_COLUMNS) < ENGLISH_FITNESS);
        // Unseen quadgrams count as half a sighting: log10(0.5 / 5,557,930)
        assert!((fitness("QXZJQXZJ") + 7.046).abs() < 0.001);
        // Too few letters to score
        assert_eq!(fitness("ABC"), f64::NEG_INFINITY);
    }

    #[test]
    fn coverage_tells_words_from_near_misses() {
        assert_eq!(word_coverage("HELLOWORLD"), 1.0);
        assert!(word_coverage(LIGHTHOUSE_LETTERS) >= MIN_COVERAGE);
        assert!(word_coverage("WEAREDISCOVEREDFLEEATONCEJX") >= MIN_COVERAGE);
        assert!(word_coverage("QXZJVKWQXZJVKW") < 0.5);
        assert_eq!(word_coverage("1234"), 0.0);
    }

    #[test]
    fn decoder_is_registered() {
        let decoders = crate::filtration_system::get_decoder_by_name("Route Transposition");
        assert_eq!(decoders.components.len(), 1);
        let decoder = &decoders.components[0];
        assert_eq!(decoder.get_popularity(), 0.4);
        assert!(!decoder.get_tags().contains(&"decoder"));
        assert!(!decoder.get_tags().contains(&"reciprocal"));
        assert!(crate::decoders::DECODER_MAP.contains_key("Route Transposition"));
    }

    #[test]
    fn comes_before_vigenere_in_the_search() {
        // Results found in one step that tie on checker class and cost keep this order,
        // and Vigenère turns unspaced transpositions into English-looking junk
        let names: Vec<String> = crate::filtration_system::get_all_decoders()
            .components
            .iter()
            .map(|decoder| decoder.get_name().to_string())
            .collect();
        let position = |name: &str| names.iter().position(|found| found == name).unwrap();
        assert!(position("Route Transposition") < position("Vigenere"));
    }
}
