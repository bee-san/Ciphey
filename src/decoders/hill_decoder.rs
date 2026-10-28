//! Hill cipher cracker.
//!
//! The Hill cipher (Lester Hill, 1929) writes the letters A to Z as 0 to 25, cuts the text
//! into blocks of n letters and encrypts each block P, as a column vector, as C = K·P
//! (mod 26). The key K is an n×n matrix whose determinant is coprime with 26, so it has an
//! inverse mod 26 and the ciphertext decrypts as P = K⁻¹·C. The plaintext is padded to a
//! whole number of blocks (with X on Wikipedia, random letters on dCode), so the ciphertext
//! is letters only and its length is a multiple of n. This is the convention of
//! [Wikipedia](https://en.wikipedia.org/wiki/Hill_cipher) and
//! [dCode](https://www.dcode.fr/hill-cipher). Scripts that multiply a row vector by the key
//! (P·K) use the transposed key: this cracker breaks those too, and reports the transpose
//! of their key.
//!
//! This cracker breaks 2×2 and 3×3 keys. There are 157,248 invertible 2×2 matrices and
//! about 1.6·10¹² 3×3 ones, but row i of the decryption matrix D = K⁻¹ decides plaintext
//! letters i, i + n, i + 2n, … on its own, so D can be recovered row by row (Bauer and
//! Millward, "Cracking Matrix Encryption Row by Row", Cryptologia 31(1), 2007):
//! 1. Every one of the 26ⁿ rows is scored by the English letter frequencies of the letters
//!    it decrypts, and the best few are kept ([`SEARCH_2X2`], [`SEARCH_3X3`]).
//! 2. Every matrix made of n kept rows that is invertible mod 26 is scored by the English
//!    letter pairs of its decryption, and the best of those by quadgram fitness.
//! 3. Up to three that read like English go to the checker.
//!
//! Ciphey runs every decoder on every text the search expands, so cheap checks first turn
//! away text that can't be the Hill ciphertext of English (see [`ciphertext_letters`]):
//! too few letters, too many other characters (Base64, hex), a letter count that isn't a
//! multiple of 2 or 3, English's letter frequencies (English, rearranged or substituted),
//! letter pairs that an Affine key (Caesar and Atbash included) makes English, or text
//! that reads as English already. Most of them cost one pass over the bytes, without
//! allocating.

use super::affine_decoder::{inverse_mod_26, BIGRAM_LOG_PROBS};
use super::crack_results::CrackResult;
use super::interface::{Crack, Decoder};
use super::monoalphabetic_substitution_decoder::QUADGRAMS;
use crate::checkers::CheckerTypes;
use crate::storage::ENGLISH_FREQS;
use gibberish_or_not::Sensitivity;
use log::{debug, trace};
use once_cell::sync::Lazy;
use std::fmt;

/// Fewest ASCII letters worth cracking. Shorter texts have too few blocks for the letter
/// statistics to pick out the rows of the key.
const MIN_LETTERS: usize = 20;

/// Fewest ASCII letters for which 3×3 keys are tried. With fewer, the letter statistics
/// of a row rarely single it out.
const MIN_LETTERS_3X3: usize = 60;

/// At most one character in this many ASCII letters may be something other than an ASCII
/// letter or whitespace. Hill ciphertext is letters, perhaps in groups. Base64, hex and
/// Base32 have many more digits and symbols, and the bench `miss` string has 27 for 46
/// letters.
const OTHER_ONE_IN: usize = 12;

/// The index of coincidence is only checked from this many letters: shorter Hill
/// ciphertexts can have one as high as English's (up to 0.084 at 20 to 40 letters).
const IOC_MIN_LETTERS: usize = 100;

/// Highest index of coincidence of a Hill ciphertext of at least [`IOC_MIN_LETTERS`]
/// letters. In 200 random 2×2 encryptions of English at each length, the highest was
/// 0.0592 at 100 letters, 0.0583 at 150 and 0.0526 from 200 letters; 3×3 at most 0.0520.
/// English has a median of 0.068 and was never below 0.053 at 100 letters or 0.063 at 200.
/// A key that is a permutation matrix times a number keeps the IoC of English, but such a
/// key only rearranges an Affine encryption within each block.
const MAX_IOC: f64 = 0.062;

/// The letter frequencies are only checked from this many letters (see
/// [`MAX_LETTER_SCORE`]): in shorter texts they vary too much.
const LETTER_SCORE_MIN_LETTERS: usize = 60;

/// Highest mean [`LETTER_SCORES`] (100 · log10 of the English frequency of each letter) of a
/// Hill ciphertext of at least [`LETTER_SCORE_MIN_LETTERS`] letters. A Hill key spreads the
/// letters out, while English and every rearrangement of it (Reverse, rail fence) keep
/// English's letter frequencies. On 1,000 windows per length of two books outside the
/// quadgram corpus (Project Gutenberg 98 and 2600), random 2×2 Hill encryptions scored at
/// most -137.1 (at 80 letters) and 3×3 ones -145.8, while English scored above this in
/// 98.7% of windows of 60 letters and 99.7% of 100.
const MAX_LETTER_SCORE: i32 = -133;

/// Affine keys are only tried on texts of at least this many letters (see
/// [`AFFINE_PAIR_SCORE`]): on shorter ones Hill ciphertexts can score like English.
const AFFINE_MIN_LETTERS: usize = 40;

/// Lowest mean [`PAIR_SCORES`] (100 · ln P) per pair of consecutive letters that an Affine
/// key (Caesar shifts and Atbash included) must give a text, from [`AFFINE_MIN_LETTERS`]
/// letters on, for it to be left to the Caesar, Atbash and Affine decoders as an Affine
/// encryption of English. On the same windows, Affine encryptions of English scored at
/// least this under their own key in 94.5% of windows of 40 letters, 97.7% of 60 and 99.4%
/// of 100, while 2×2 and 3×3 Hill encryptions never scored above -612 under any key.
const AFFINE_PAIR_SCORE: i32 = -580;

/// Quadgram fitness (the mean log10 probability of a text's quadgrams) at or above which a
/// text reads as English. Input that does is not decrypted, and a decryption that doesn't
/// is not shown to the checker. English scores about -4.0 to -4.5 and correct decryptions
/// -3.7 to -4.9, while ROT13, Atbash, Vigenère and Hill ciphertexts score -5.5 to -6.3.
/// The best decryption of Vigenère, Beaufort, Autokey, ROT13, Atbash and random letters
/// scored at most -5.17 from 30 letters on, so on text that isn't a Hill ciphertext the
/// checker is normally not called at all.
const ENGLISH_FITNESS: f32 = -5.0;

/// When the checker accepts none of the decryptions, the best one is still handed on to
/// the search, unconfirmed, if its fitness is at least this. Short and unspaced plaintexts
/// such as the 20 letters `SHORTMESSAGEFORHILLX` are often not accepted by the checker.
const UNCONFIRMED_FITNESS: f32 = -4.6;

/// Most decryptions shown to the checker, best first.
const MAX_CHECKED: usize = 3;

/// Decryptions, and the input, are scored on the first this many letters. A multiple of 2
/// and of 3, so it is whole blocks of either size.
const SCORE_LETTERS: usize = 300;

/// How many matrices of each size are scored by quadgrams: the ones whose decryptions have
/// the most English letter pairs. See [`rank_matrices`].
const QUADGRAM_SCORED: usize = 32;

/// Matrices are shortlisted by the letter pairs of the decryption of the first this many
/// letters, a multiple of 2 and of 3.
const PAIR_LETTERS: usize = 120;

/// How the key search runs for one key size.
struct Search {
    /// The number of rows and columns of the key, 2 or 3.
    size: usize,
    /// Rows are ranked on the first this many blocks.
    rank_blocks: usize,
    /// How many of the 26ⁿ rows are kept, and so how many matrices are tried: this to the
    /// power n.
    top_rows: usize,
}

/// The search for 2×2 keys: the best 26 of the 676 rows, ranked on up to 200 letters, so
/// 26² = 676 matrices. Of 40 random 2×2 encryptions of English at each length, it found
/// the key of 30 at 20 letters, 36 at 24, 39 at 30 and 40 from 60 letters.
const SEARCH_2X2: Search = Search {
    size: 2,
    rank_blocks: 100,
    top_rows: 26,
};

/// The search for 3×3 keys: the best 16 of the 17,576 rows, ranked on up to 150 letters,
/// so 16³ = 4,096 matrices. Of 40 random 3×3 encryptions of English at each length, it
/// found the key of 23 at 60 letters, 35 at 90, 38 at 120 and 40 from 150. Ranking the
/// rows on 300 letters found no more.
const SEARCH_3X3: Search = Search {
    size: 3,
    rank_blocks: 50,
    top_rows: 16,
};

/// `round(100 · log10 p)` for the English frequency p of each letter: what a decrypted
/// letter adds to the score of a row. From -90 for E to -313 for Z, so the scores of
/// [`SEARCH_2X2`]'s 100 blocks still fit in an `i16`.
static LETTER_SCORES: Lazy<[i16; 26]> =
    Lazy::new(|| ENGLISH_FREQS.map(|frequency| (100.0 * frequency.log10()).round() as i16));

/// `ROW_SCORES[c][t][k]` is the score of the letter `(t + k·c) mod 26` in [`LETTER_SCORES`]:
/// for a block whose last letter is `c`, the score of the row with last entry `k` whose
/// other entries give `t`. One slice scores all 26 last entries, so ranking the rows is a
/// run of additions of 32 `i16`s (the last 6 are 0), which compile to a few vector
/// instructions.
static ROW_SCORES: Lazy<Box<[[[i16; 32]; 26]]>> = Lazy::new(|| {
    let scores = &*LETTER_SCORES;
    let mut table = vec![[[0i16; 32]; 26]; 26];
    for (c, by_partial) in table.iter_mut().enumerate() {
        for (t, row) in by_partial.iter_mut().enumerate() {
            for (k, score) in row.iter_mut().take(26).enumerate() {
                *score = scores[(t + k * c) % 26];
            }
        }
    }
    table.into_boxed_slice()
});

/// The Hill cipher cracker. Call:
/// `let decoder = Decoder::<HillDecoder>::new()` to create one,
/// and `decoder.crack(text, &checker)` to crack `text`.
/// ```
/// use ciphey::decoders::hill_decoder::HillDecoder;
/// use ciphey::decoders::interface::{Crack, Decoder};
/// use ciphey::checkers::{athena::Athena, CheckerTypes, checker_type::{Check, Checker}};
///
/// let decoder = Decoder::<HillDecoder>::new();
/// let checker = CheckerTypes::CheckAthena(Checker::<Athena>::new());
///
/// // Encrypted with Wikipedia's 2×2 key [[3, 3], [2, 5]]
/// let result = decoder.crack(
///     "WSRZWSFRAVCAQLFKNVAVYYOEPZRGJQHFLONVFMWPCJLDXDHIKYYVHIQOUWWPFRPJBN",
///     &checker,
/// );
/// assert!(result.success);
/// assert_eq!(
///     result.unencrypted_text.unwrap()[0],
///     "MEETMEATTHEOLDLIGHTHOUSEAFTERMIDNIGHTANDBRINGTHEMAPTHEKEYANDATORCH"
/// );
/// // The encryption key K, rows in order
/// assert_eq!(result.key.unwrap(), "[[3,3],[2,5]]");
/// ```
pub struct HillDecoder;

impl Crack for Decoder<HillDecoder> {
    fn new() -> Decoder<HillDecoder> {
        Decoder {
            name: "Hill",
            description: "Hill cipher: blocks of 2 or 3 letters multiplied by an invertible key matrix mod 26. Recovers the matrix row by row with letter-frequency statistics and ranks the combinations by quadgram fitness. Uses Low sensitivity for gibberish detection on spaced text, Medium on unspaced text.",
            link: "https://en.wikipedia.org/wiki/Hill_cipher",
            tags: vec!["hill", "matrix", "substitution", "classical"],
            popularity: 0.3,
            phantom: std::marker::PhantomData,
        }
    }

    /// Searches for the key. On success the plaintext is the only element of
    /// `unencrypted_text` and `key` is the encryption matrix K, rows in order, as
    /// `[[3,3],[2,5]]`. When the checker accepts none of the decryptions but the best one
    /// still reads like English (see [`UNCONFIRMED_FITNESS`]), that one is returned
    /// unconfirmed, with its key, so the search can keep decoding it.
    ///
    /// The plaintext keeps the case of each letter and every other character of `text`.
    fn crack(&self, text: &str, checker: &CheckerTypes) -> CrackResult {
        trace!("Trying Hill cipher with text {:?}", text);
        let mut results = CrackResult::new(self, text.to_string());

        let Some(ciphertext) = ciphertext_letters(text) else {
            return results;
        };
        let ranked = rank(&ciphertext);
        let Some(best) = ranked.first() else {
            trace!("Hill: no key decrypts the text to English");
            return results;
        };

        // The checker reads unspaced text as one word: only Medium identifies it
        let sensitivity = if text.trim().bytes().any(|byte| byte.is_ascii_whitespace()) {
            Sensitivity::Low
        } else {
            Sensitivity::Medium
        };
        let checker_with_sensitivity = checker.with_sensitivity(sensitivity);

        let mut best_plaintext = None;
        for candidate in &ranked {
            let plaintext = candidate.plaintext(text, &ciphertext.letters);
            let check = checker_with_sensitivity.check(&plaintext);
            if check.is_identified {
                debug!("Hill found key {}", candidate.key());
                results.unencrypted_text = Some(vec![plaintext]);
                results.update_checker(&check);
                results.key = Some(candidate.key());
                return results;
            }
            best_plaintext.get_or_insert(plaintext);
        }

        if best.fitness >= UNCONFIRMED_FITNESS {
            debug!(
                "Hill best guess, key {} (fitness {:.2})",
                best.key(),
                best.fitness
            );
            results.unencrypted_text = best_plaintext.map(|plaintext| vec![plaintext]);
            results.key = Some(best.key());
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

/// A square matrix over the integers mod 26: a Hill key or its inverse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Matrix {
    /// The number of rows and columns, 2 or 3.
    size: usize,
    /// The entries, 0 to 25, row by row. Only the first `size` rows and columns are used;
    /// the rest are 0.
    rows: [[u8; 3]; 3],
}

impl Matrix {
    /// The matrix with these rows, entries taken mod 26, if it is 2×2 or 3×3.
    fn from_rows<R: AsRef<[u32]>>(rows: &[R]) -> Option<Matrix> {
        let size = rows.len();
        if !(2..=3).contains(&size) || rows.iter().any(|row| row.as_ref().len() != size) {
            return None;
        }
        let mut matrix = Matrix {
            size,
            rows: [[0; 3]; 3],
        };
        for (to, from) in matrix.rows.iter_mut().zip(rows) {
            for (entry, &value) in to.iter_mut().zip(from.as_ref()) {
                *entry = (value % 26) as u8;
            }
        }
        Some(matrix)
    }

    /// The entry in row `row` and column `column`, as an `i32` for arithmetic.
    fn at(&self, row: usize, column: usize) -> i32 {
        i32::from(self.rows[row][column])
    }

    /// The determinant mod 26.
    fn determinant(&self) -> u8 {
        let m = |row, column| self.at(row, column);
        let determinant = if self.size == 2 {
            m(0, 0) * m(1, 1) - m(0, 1) * m(1, 0)
        } else {
            (0..3)
                .map(|column| m(0, column) * self.cofactor(0, column))
                .sum()
        };
        determinant.rem_euclid(26) as u8
    }

    /// The cofactor of the entry in row `row` and column `column` of a 3×3 matrix, its sign
    /// included: the cyclic order of the other rows and columns gives the sign.
    fn cofactor(&self, row: usize, column: usize) -> i32 {
        let (r1, r2) = ((row + 1) % 3, (row + 2) % 3);
        let (c1, c2) = ((column + 1) % 3, (column + 2) % 3);
        self.at(r1, c1) * self.at(r2, c2) - self.at(r1, c2) * self.at(r2, c1)
    }

    /// Whether the matrix is invertible mod 26: its determinant is odd and not 13.
    #[cfg(test)]
    fn is_invertible(&self) -> bool {
        is_unit(i32::from(self.determinant()))
    }

    /// The inverse mod 26, the adjugate times the inverse of the determinant, if the
    /// matrix is invertible.
    fn inverse(&self) -> Option<Matrix> {
        let determinant_inverse = i32::from(inverse_mod_26(self.determinant())?);
        let mut inverse = Matrix {
            size: self.size,
            rows: [[0; 3]; 3],
        };
        for row in 0..self.size {
            for column in 0..self.size {
                // The adjugate is the transpose of the matrix of cofactors
                let adjugate = if self.size == 2 {
                    let sign = if row == column { 1 } else { -1 };
                    sign * self.at(1 - column, 1 - row)
                } else {
                    self.cofactor(column, row)
                };
                inverse.rows[row][column] = (adjugate * determinant_inverse).rem_euclid(26) as u8;
            }
        }
        Some(inverse)
    }

    /// The matrix applied to each block of `letters` (0 to 25) as a column vector, mod 26.
    /// `letters` must be whole blocks.
    fn apply(&self, letters: &[u8]) -> Vec<u8> {
        let mut result = Vec::with_capacity(letters.len());
        for block in letters.chunks_exact(self.size) {
            for row in &self.rows[..self.size] {
                let sum: u32 = row
                    .iter()
                    .zip(block)
                    .map(|(&entry, &letter)| u32::from(entry) * u32::from(letter))
                    .sum();
                result.push((sum % 26) as u8);
            }
        }
        result
    }
}

impl fmt::Display for Matrix {
    /// Writes the matrix as rows of entries in brackets, without spaces: `[[3,3],[2,5]]`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[")?;
        for (index, row) in self.rows[..self.size].iter().enumerate() {
            if index > 0 {
                write!(f, ",")?;
            }
            write!(f, "[")?;
            for (column, entry) in row[..self.size].iter().enumerate() {
                if column > 0 {
                    write!(f, ",")?;
                }
                write!(f, "{entry}")?;
            }
            write!(f, "]")?;
        }
        write!(f, "]")
    }
}

/// The ASCII letters of a text that passed the pre-checks, and the key sizes to try.
#[derive(Debug)]
struct Ciphertext {
    /// The ASCII letters of the text as 0 to 25, in order.
    letters: Vec<u8>,
    /// Whether to try 2×2 keys.
    try_2x2: bool,
    /// Whether to try 3×3 keys.
    try_3x3: bool,
}

/// The ASCII letters of `text`, if it could be the Hill ciphertext of English. The first
/// checks run on the counts of one pass over the bytes:
/// 1. At least [`MIN_LETTERS`] ASCII letters.
/// 2. At most one character that isn't an ASCII letter or whitespace (non-ASCII included)
///    per [`OTHER_ONE_IN`] letters.
/// 3. The number of letters is a multiple of 2, or of 3 and at least [`MIN_LETTERS_3X3`],
///    since the plaintext was padded to whole blocks.
/// 4. With at least [`IOC_MIN_LETTERS`] letters, an index of coincidence of at most
///    [`MAX_IOC`]: English, and any Caesar, Atbash, Affine or other substitution of it,
///    has more repeated letters.
/// 5. With at least [`LETTER_SCORE_MIN_LETTERS`] letters, letter frequencies unlike
///    English's (see [`MAX_LETTER_SCORE`]), as in English rearranged by Reverse or rail
///    fence.
///
/// Then, on the letters:
/// 6. With at least [`AFFINE_MIN_LETTERS`] letters, no Affine key, Caesar and Atbash
///    included, decrypts them to English letter pairs (see [`AFFINE_PAIR_SCORE`]).
/// 7. They don't read as English already (see [`ENGLISH_FITNESS`]).
fn ciphertext_letters(text: &str) -> Option<Ciphertext> {
    let mut counts = [0u32; 26];
    let mut letters = 0usize;
    let mut other = 0usize;
    for &byte in text.as_bytes() {
        match byte {
            b'A'..=b'Z' => {
                counts[usize::from(byte - b'A')] += 1;
                letters += 1;
            }
            b'a'..=b'z' => {
                counts[usize::from(byte - b'a')] += 1;
                letters += 1;
            }
            byte if byte.is_ascii_whitespace() => {}
            // Count characters, not bytes: skip UTF-8 continuation bytes
            byte if byte & 0xC0 == 0x80 => {}
            _ => other += 1,
        }
    }

    if letters < MIN_LETTERS || other * OTHER_ONE_IN > letters {
        return None;
    }
    let try_2x2 = letters.is_multiple_of(2);
    let try_3x3 = letters.is_multiple_of(3) && letters >= MIN_LETTERS_3X3;
    if !try_2x2 && !try_3x3 {
        return None;
    }
    if letters >= IOC_MIN_LETTERS {
        let repeats: u64 = counts
            .iter()
            .map(|&count| u64::from(count) * u64::from(count.saturating_sub(1)))
            .sum();
        let ioc = repeats as f64 / (letters as f64 * (letters - 1) as f64);
        if ioc > MAX_IOC {
            trace!("Hill: index of coincidence {ioc:.4} is English's");
            return None;
        }
    }
    if letters >= LETTER_SCORE_MIN_LETTERS {
        let total: i64 = counts
            .iter()
            .zip(LETTER_SCORES.iter())
            .map(|(&count, &score)| i64::from(count) * i64::from(score))
            .sum();
        if total > i64::from(MAX_LETTER_SCORE) * letters as i64 {
            trace!("Hill: the letters have English's frequencies");
            return None;
        }
    }

    let letters = letters_of(text);
    let scored = &letters[..letters.len().min(SCORE_LETTERS)];
    if letters.len() >= AFFINE_MIN_LETTERS && affine_reads_as_english(scored, &counts) {
        trace!("Hill: an Affine key decrypts the text");
        return None;
    }
    let fitness = fitness(scored);
    if fitness >= ENGLISH_FITNESS {
        trace!("Hill: the text reads as English already (fitness {fitness:.2})");
        return None;
    }
    Some(Ciphertext {
        letters,
        try_2x2,
        try_3x3,
    })
}

/// How many of the 312 Affine keys, the best by the letter frequencies they give, are
/// scored by letter pairs in [`affine_reads_as_english`]. On 2,000 Affine encryptions of
/// English per length (40, 60 and 80 letters), the best 4 found a key that reads as
/// English as often as trying all 312 did.
const AFFINE_KEYS_TRIED: usize = 8;

/// The 312 Affine decryption tables `p = a(c - b) mod 26`, Caesar shifts (`a = 1`, the
/// identity first) and Atbash included.
static AFFINE_KEYS: Lazy<Vec<[u8; 26]>> = Lazy::new(|| {
    [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]
        .into_iter()
        .flat_map(|a: usize| {
            (0..26).map(move |b| {
                let mut key = [0u8; 26];
                for (c, plain) in key.iter_mut().enumerate() {
                    *plain = (a * (c + 26 - b) % 26) as u8;
                }
                key
            })
        })
        .collect()
});

/// Whether some Affine key, the identity, a Caesar shift or Atbash included, turns the
/// pairs of consecutive `letters` (at least 2) into English ones: a mean [`PAIR_SCORES`]
/// of at least [`AFFINE_PAIR_SCORE`]. Only the [`AFFINE_KEYS_TRIED`] keys whose
/// decryptions have the most English letter frequencies, by `counts` (how often each
/// letter occurs in the text), are tried.
fn affine_reads_as_english(letters: &[u8], counts: &[u32; 26]) -> bool {
    let letter_scores = &*LETTER_SCORES;
    let mut best = Best::new(AFFINE_KEYS_TRIED);
    for (index, key) in AFFINE_KEYS.iter().enumerate() {
        let score: i64 = counts
            .iter()
            .zip(key)
            .map(|(&count, &plain)| i64::from(count) * i64::from(letter_scores[usize::from(plain)]))
            .sum();
        best.offer(score, index);
    }
    let needed = AFFINE_PAIR_SCORE * (letters.len() as i32 - 1);
    let pair_scores = &**PAIR_SCORES;
    best.items.iter().any(|&(_, index)| {
        let key = &AFFINE_KEYS[index];
        let score: i32 = letters
            .windows(2)
            .map(|pair| {
                pair_scores[pair_index(key[usize::from(pair[0])], key[usize::from(pair[1])])]
            })
            .sum();
        score >= needed
    })
}

/// The mean log10 probability of the quadgrams of `letters` (0 to 25) in English, from
/// [`QUADGRAMS`]. `letters` must have at least 4 letters.
fn fitness(letters: &[u8]) -> f32 {
    let table = &*QUADGRAMS;
    let mut index = 0usize;
    let mut total = 0.0f32;
    for (position, &letter) in letters.iter().enumerate() {
        index = (index % (26 * 26 * 26)) * 26 + usize::from(letter);
        if position >= 3 {
            total += table[index];
        }
    }
    total / letters.len().saturating_sub(3).max(1) as f32
}

/// A decryption matrix and how English its decryption reads.
#[derive(Clone, Copy, Debug)]
struct Ranked {
    /// The [`fitness`] of the decryption of the first [`SCORE_LETTERS`] letters.
    fitness: f32,
    /// The decryption matrix D = K⁻¹.
    decryption: Matrix,
}

impl Ranked {
    /// The key as the cracker reports it: the encryption matrix K = D⁻¹.
    fn key(&self) -> String {
        // D is invertible, or it wouldn't have been ranked
        self.decryption
            .inverse()
            .map_or_else(String::new, |key| key.to_string())
    }

    /// `text`, whose ASCII letters are `letters`, decrypted with D.
    fn plaintext(&self, text: &str, letters: &[u8]) -> String {
        with_letters(text, &self.decryption.apply(letters))
    }
}

/// The decryption matrices worth checking for `ciphertext`, best first: at most
/// [`MAX_CHECKED`], each with a fitness of at least [`ENGLISH_FITNESS`].
fn rank(ciphertext: &Ciphertext) -> Vec<Ranked> {
    let mut ranked = Vec::new();
    if ciphertext.try_2x2 {
        rank_matrices(&ciphertext.letters, &SEARCH_2X2, &mut ranked);
    }
    if ciphertext.try_3x3 {
        rank_matrices(&ciphertext.letters, &SEARCH_3X3, &mut ranked);
    }
    // A stable sort, so ties keep their order and the ranking is deterministic
    ranked.sort_by(|left, right| right.fitness.total_cmp(&left.fitness));
    ranked.retain(|candidate| candidate.fitness >= ENGLISH_FITNESS);
    ranked.truncate(MAX_CHECKED);
    ranked
}

/// Adds to `ranked` the decryption matrices of `search.size` that are worth a quadgram
/// score, with the fitness of their decryption of the first [`SCORE_LETTERS`] letters.
///
/// The candidates are every matrix made of `search.size` of the best rows of
/// [`best_rows`], in any order, that is invertible mod 26 and not diagonal. A diagonal key
/// multiplies the letters at each place in a block by a number: an Affine cipher per place,
/// not a Hill cipher (and with one number for every place, the Affine decoder's). Each
/// candidate is first
/// scored by the English letter pairs of its decryption of the first [`PAIR_LETTERS`]
/// letters, which costs a few additions from sums worked out once for every two rows, and
/// only the best [`QUADGRAM_SCORED`] are scored by quadgrams. On English from two books
/// outside the quadgram corpus, encrypted with random keys (100 texts per length for 2×2,
/// 60 for 3×3), this ranked the right key first as often as scoring every matrix by
/// quadgrams did, at every length from 20 letters (2×2) and 60 (3×3) to 300.
///
/// It is normal for no candidate to be left: on a Caesar or Affine encryption the best
/// rows have one entry that isn't 0, and only make singular or diagonal matrices.
fn rank_matrices(letters: &[u8], search: &Search, ranked: &mut Vec<Ranked>) {
    let size = search.size;
    let rows = best_rows(letters, search);
    let scored = &letters[..letters.len().min(SCORE_LETTERS)];
    // decrypted[r][b]: the letter row r gives in block b, wherever it is placed in D
    let decrypted: Vec<Vec<u8>> = rows
        .iter()
        .map(|row| row_letters(&row[..size], scored))
        .collect();

    // Letter pairs are scored on the first PAIR_LETTERS letters. A matrix with the same
    // row twice is singular, so pairs of a row with itself are never needed.
    let blocks = PAIR_LETTERS.min(scored.len()) / size;
    let count = rows.len();

    // The matrices with the most English letter pairs. On equal scores the first offered
    // is kept, so the result only depends on the scores.
    let mut shortlist = Best::new(QUADGRAM_SCORED);
    let entries: Vec<[i32; 3]> = rows.iter().map(|row| row.map(i32::from)).collect();
    if size == 2 {
        for (i, a) in entries.iter().enumerate() {
            for (j, b) in entries.iter().enumerate() {
                let determinant = (a[0] * b[1] - a[1] * b[0]).rem_euclid(26);
                let diagonal = a[1] == 0 && b[0] == 0;
                if i != j && is_unit(determinant) && !diagonal {
                    let (first, second) = (&decrypted[i], &decrypted[j]);
                    let score =
                        pairs_within(first, second, blocks) + pairs_across(second, first, blocks);
                    shortlist.offer(score, [i, j, 0]);
                }
            }
        }
    } else {
        // within[i][j]: row i then row j inside a block; across[i][j]: row i at the end of
        // a block, then row j at the start of the next
        let mut within = vec![0i32; count * count];
        let mut across = vec![0i32; count * count];
        for i in 0..count {
            for j in (0..count).filter(|&j| j != i) {
                within[i * count + j] = pairs_within(&decrypted[i], &decrypted[j], blocks);
                across[i * count + j] = pairs_across(&decrypted[i], &decrypted[j], blocks);
            }
        }
        for (i, a) in entries.iter().enumerate() {
            for (j, b) in entries.iter().enumerate() {
                if i == j {
                    continue;
                }
                let upper_diagonal = a[1] == 0 && a[2] == 0 && b[0] == 0 && b[2] == 0;
                for (k, c) in entries.iter().enumerate() {
                    if k == i || k == j {
                        continue;
                    }
                    // The score is three lookups, cheaper than the determinant, and most
                    // matrices don't score well enough to be kept: an item that isn't wanted
                    // wouldn't be kept whatever its determinant, so this skips no matrix
                    // that would have been
                    let score =
                        within[i * count + j] + within[j * count + k] + across[k * count + i];
                    if !shortlist.wants(score) {
                        continue;
                    }
                    // Expanded along the first row
                    let determinant = (a[0] * (b[1] * c[2] - b[2] * c[1])
                        + a[1] * (b[2] * c[0] - b[0] * c[2])
                        + a[2] * (b[0] * c[1] - b[1] * c[0]))
                        .rem_euclid(26);
                    let diagonal = upper_diagonal && c[0] == 0 && c[1] == 0;
                    if is_unit(determinant) && !diagonal {
                        shortlist.offer(score, [i, j, k]);
                    }
                }
            }
        }
    }

    let mut plaintext = vec![0u8; scored.len()];
    for &(_, chosen) in &shortlist.items {
        let mut decryption = Matrix {
            size,
            rows: [[0; 3]; 3],
        };
        for (place, &row) in chosen[..size].iter().enumerate() {
            decryption.rows[place] = rows[row];
            for (block, &letter) in decrypted[row].iter().enumerate() {
                plaintext[block * size + place] = letter;
            }
        }
        ranked.push(Ranked {
            fitness: fitness(&plaintext),
            decryption,
        });
    }
}

/// Whether `determinant`, 0 to 25, is coprime with 26, so a matrix with it is invertible.
fn is_unit(determinant: i32) -> bool {
    determinant % 2 == 1 && determinant != 13
}

/// The score of every letter pair, `round(100 · ln P)` of the Affine decoder's
/// [`BIGRAM_LOG_PROBS`] (from `english_bigrams.txt`): whole numbers, so that adding them up
/// is fast and the shortlist of [`rank_matrices`] has no rounding. Pair `a`, `b` is at
/// [`pair_index`]`(a, b)`; the table has room for any two values below 32, so looking a pair
/// up needs no bounds check.
static PAIR_SCORES: Lazy<Box<[i32; 1024]>> = Lazy::new(|| {
    let mut table = Box::new([0i32; 1024]);
    for (first, row) in (0u8..).zip(BIGRAM_LOG_PROBS.iter()) {
        for (second, &log_probability) in (0u8..).zip(row) {
            table[pair_index(first, second)] = (100.0 * log_probability).round() as i32;
        }
    }
    table
});

/// Where the pair of letters `first`, `second` (0 to 25) is in [`PAIR_SCORES`].
fn pair_index(first: u8, second: u8) -> usize {
    (usize::from(first & 31) << 5) | usize::from(second & 31)
}

/// The score of the letter pairs `first[b]`, `second[b]` for each of the first `blocks`
/// blocks: two rows' letters, the second right after the first in each block.
fn pairs_within(first: &[u8], second: &[u8], blocks: usize) -> i32 {
    let table = &**PAIR_SCORES;
    first[..blocks]
        .iter()
        .zip(&second[..blocks])
        .map(|(&a, &b)| table[pair_index(a, b)])
        .sum()
}

/// The score of the letter pairs `first[b]`, `second[b + 1]` for each of the first `blocks`
/// blocks: two rows' letters, the first at the end of a block and the second at the start
/// of the next.
fn pairs_across(first: &[u8], second: &[u8], blocks: usize) -> i32 {
    let table = &**PAIR_SCORES;
    first[..blocks.saturating_sub(1)]
        .iter()
        .zip(&second[1..blocks])
        .map(|(&a, &b)| table[pair_index(a, b)])
        .sum()
}

/// The `keep` best-scoring items offered so far, best first. On equal scores the item
/// offered first comes first.
struct Best<S, T> {
    /// How many items to keep.
    keep: usize,
    /// The kept items with their scores, best first.
    items: Vec<(S, T)>,
}

impl<S: PartialOrd + Copy, T> Best<S, T> {
    /// Keeps the best `keep` items.
    fn new(keep: usize) -> Self {
        Best {
            keep,
            items: Vec::with_capacity(keep + 1),
        }
    }

    /// Whether an item scoring `score` would be kept.
    fn wants(&self, score: S) -> bool {
        self.items.len() < self.keep || self.items.last().is_some_and(|&(worst, _)| score > worst)
    }

    /// Keeps `item` if it is one of the best so far.
    fn offer(&mut self, score: S, item: T) {
        if !self.wants(score) {
            return;
        }
        let position = self.items.partition_point(|&(kept, _)| kept >= score);
        self.items.insert(position, (score, item));
        self.items.truncate(self.keep);
    }
}

/// The letter that a row of a decryption matrix, `row`, gives for each block of
/// `letters`: their dot product mod 26. `letters` must be whole blocks of `row.len()`.
fn row_letters(row: &[u8], letters: &[u8]) -> Vec<u8> {
    letters
        .chunks_exact(row.len())
        .map(|block| {
            let sum: u32 = row
                .iter()
                .zip(block)
                .map(|(&entry, &letter)| u32::from(entry) * u32::from(letter))
                .sum();
            (sum % 26) as u8
        })
        .collect()
}

/// The `search.top_rows` rows (entries 0 to 25, the first `search.size` used) of a
/// decryption matrix whose letters look most English by their single-letter frequencies,
/// best first. A row is scored on the letter it decrypts at its place in each of the first
/// `search.rank_blocks` blocks of `letters`, by [`LETTER_SCORES`].
///
/// Rows that can't be part of an invertible matrix are left out: those whose entries are
/// all even (the determinant would be even), and those whose entries are all 0 or 13
/// (it would be a multiple of 13). These rows decrypt every block to one of a few letters,
/// so they would otherwise rank first.
fn best_rows(letters: &[u8], search: &Search) -> Vec<[u8; 3]> {
    let size = search.size;
    let table = &*ROW_SCORES;
    let blocks: Vec<&[u8]> = letters
        .chunks_exact(size)
        .take(search.rank_blocks)
        .collect();
    let firsts: Vec<u8> = blocks.iter().map(|block| block[0]).collect();
    let seconds: Vec<u8> = blocks.iter().map(|block| block[1]).collect();
    let lasts: Vec<usize> = blocks
        .iter()
        .map(|block| usize::from(block[size - 1]))
        .collect();

    let mut best = Best::new(search.top_rows);
    // partials[i]: what the entries of the row before its last give for block i, mod 26
    let mut partials = vec![0u8; blocks.len()];
    for first in 0..26u8 {
        for (partial, &letter) in partials.iter_mut().zip(&firsts) {
            *partial = ((u32::from(first) * u32::from(letter)) % 26) as u8;
        }
        // For 3×3 rows, the second entry too: adding 1 to it adds the block's second
        // letter to the partial
        for second in 0..if size == 2 { 1 } else { 26u8 } {
            if second > 0 {
                for (partial, &letter) in partials.iter_mut().zip(&seconds) {
                    // Both are below 26, so the sum is below 52: if it is 26 or more,
                    // `sum - 26` doesn't wrap and is the smaller of the two
                    let sum = *partial + letter;
                    *partial = sum.min(sum.wrapping_sub(26));
                }
            }
            let mut totals = [0i16; 32];
            for (&partial, &last) in partials.iter().zip(&lasts) {
                let scores = &table[last][usize::from(partial)];
                for (total, &score) in totals.iter_mut().zip(scores) {
                    *total = total.saturating_add(score);
                }
            }
            let best_total = totals[..26].iter().copied().max().unwrap_or(i16::MIN);
            if !best.wants(best_total) {
                continue;
            }
            for (last, &score) in (0..26u8).zip(&totals) {
                if !best.wants(score) {
                    continue;
                }
                let row = if size == 2 {
                    [first, last, 0]
                } else {
                    [first, second, last]
                };
                let entries = &row[..size];
                let all_even = entries.iter().all(|&entry| entry % 2 == 0);
                let all_thirteens = entries.iter().all(|&entry| entry % 13 == 0);
                if !all_even && !all_thirteens {
                    best.offer(score, row);
                }
            }
        }
    }
    best.items.into_iter().map(|(_, row)| row).collect()
}

/// `text` with its ASCII letters replaced, in order, by `letters` (0 to 25), each in the
/// case of the letter it replaces. Everything else is copied.
fn with_letters(text: &str, letters: &[u8]) -> String {
    let mut letters = letters.iter();
    text.chars()
        .map(|c| {
            if !c.is_ascii_alphabetic() {
                return c;
            }
            let base = if c.is_ascii_uppercase() { b'A' } else { b'a' };
            letters
                .next()
                .map_or(c, |&letter| char::from(base + letter))
        })
        .collect()
}

/// The ASCII letters of `text` as 0 to 25. Only ASCII letters: the bytes of multi-byte
/// characters (`é`, or Latin-1 that the hex decoder made) are never ASCII, so filtering
/// bytes is the same as filtering characters, and nothing indexes past the alphabet.
fn letters_of(text: &str) -> Vec<u8> {
    text.bytes()
        .filter(u8::is_ascii_alphabetic)
        .map(|byte| byte.to_ascii_uppercase() - b'A')
        .collect()
}

/// Why [`decrypt`] can't decrypt a text with a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyError {
    /// The key isn't a 2×2 or 3×3 matrix.
    Size,
    /// The key isn't invertible mod 26: its determinant mod 26, given here, is even or 13.
    Singular(u8),
    /// The text's ASCII letters, this many, don't make whole blocks of the key's size.
    Length(usize),
}

/// Decrypts `text` with the Hill key `key`: the encryption matrix K, 2×2 or 3×3, rows in
/// order, entries taken mod 26, as the cracker reports it. Each block of ASCII letters is
/// multiplied by K⁻¹; letters keep their case and everything else is copied.
///
/// # Errors
///
/// A [`KeyError`] if the key isn't a 2×2 or 3×3 matrix, isn't invertible mod 26, or the
/// text's ASCII letters don't make whole blocks.
pub(crate) fn decrypt<R: AsRef<[u32]>>(text: &str, key: &[R]) -> Result<String, KeyError> {
    let key = Matrix::from_rows(key).ok_or(KeyError::Size)?;
    let decryption = key.inverse().ok_or(KeyError::Singular(key.determinant()))?;
    let letters = letters_of(text);
    if !letters.len().is_multiple_of(decryption.size) {
        return Err(KeyError::Length(letters.len()));
    }
    Ok(with_letters(text, &decryption.apply(&letters)))
}

/// `key` written as the cracker reports keys, entries mod 26: `[[3,3],[2,5]]`. `None` if
/// it isn't a 2×2 or 3×3 matrix.
pub(crate) fn format_key<R: AsRef<[u32]>>(key: &[R]) -> Option<String> {
    Matrix::from_rows(key).map(|key| key.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkers::{
        athena::Athena,
        checker_type::{Check, Checker},
        CheckerTypes,
    };

    /// Wikipedia's 2×2 example key, which also encrypts the issue's example.
    const KEY_3_3_2_5: [[u32; 2]; 2] = [[3, 3], [2, 5]];

    /// Wikipedia's 3×3 example key, GYBNQKURP.
    const KEY_GYBNQKURP: [[u32; 3]; 3] = [[6, 24, 1], [13, 16, 10], [20, 17, 15]];

    /// A 3×3 key for the Dickens and bench `long` vectors.
    const KEY_2_4_5: [[u32; 3]; 3] = [[2, 4, 5], [9, 2, 1], [3, 17, 7]];

    /// The letters of the bench `medium` plaintext, 66 of them.
    const LIGHTHOUSE: &str = "MEETMEATTHEOLDLIGHTHOUSEAFTERMIDNIGHTANDBRINGTHEMAPTHEKEYANDATORCH";

    /// The bench `medium` plaintext as written, with spaces and punctuation.
    const LIGHTHOUSE_SPACED: &str =
        "Meet me at the old lighthouse after midnight and bring the map, the key and a torch.";

    /// The opening of A Tale of Two Cities, 174 letters.
    const DICKENS: &str = "ITWASTHEBESTOFTIMESITWASTHEWORSTOFTIMESITWASTHEAGEOFWISDOMITWASTHEAGEOF\
        FOOLISHNESSITWASTHEEPOCHOFBELIEFITWASTHEEPOCHOFINCREDULITYITWASTHESEASONOFLIGHTITWAST\
        HESEASONOFDARKNESS";

    /// The letters of the bench `long` plaintext, 463 of them, padded with XX to 465.
    const LONG_PADDED: &str = "CIPHEYISANAUTOMATEDDECODINGTOOLYOUGIVEITENCRYPTEDORENCODEDTEXT\
        ANDITTRIESTOWORKOUTWHATWASDONETOITWITHOUTYOUHAVINGTOKNOWTHEKEYOREVENTHECIPHERITSEARCH\
        ESTHROUGHMANYPOSSIBLEDECODINGSCHECKSEACHCANDIDATETOSEEWHETHERITLOOKSLIKEENGLISHORMAT\
        CHESAKNOWNPATTERNSUCHASANEMAILADDRESSANDSTOPSWHENITFINDSSOMETHINGTHATREADSLIKEPLAINT\
        EXTMOSTOFTHETIMETHISTAKESLESSTHANASECONDWHICHMAKESITHANDYFORCAPTURETHEFLAGCHALLENGES\
        PUZZLEHUNTSANDFORANYONEWHOSTUMBLESACROSSASTRANGESTRINGINALOGFILEXX";

    /// The bench `long` vector: [`LONG_PADDED`] encrypted with [`KEY_2_4_5`].
    const LONG_CIPHERTEXT: &str = "HXNURXKESWHXYDPSQNMLKXXFUABIFDGFTASKUXFPKIKYVWVGRUCSMNIGRYRW\
        SLCABQRSFSUKWNHQOLVDVUEDWHPOAVHOGZFZPZXOHJWZRQMXJKECCXMALZJWQICHBNIEHHGVEWYAXKFGIAOSZ\
        IETNJWHSVRDLRXWAJSYAOJKGLNCKTKRHAKXEEQSMAWPDABQXUMYKRUSUOIFIHWFGISLFRHXYSOMQPODJZEOP\
        XNAKXIQUKLPIRIEFSUPIFJNUKUYHJJBFBJUKXLXTPREGWSHOIFXWWDWIMDZSYOCLYPSOFEYYFPDWCYSOWBYH\
        NONXQOYKPWSIHWARRPDUBXVIYQWGJVJZBYIOOWVHXZAQHFDWOCQCKODUCRYVMIBHHVUWPDUFFSIOMRWUZQKO\
        CEBSOKREDMKGZZLYVSETKXZWRBEFVWPNOJKUIQYRZWYYCXISDNPJCUABQULEDBTUUHBS";

    /// The bench `miss` input, which every decoder rejects.
    const MISS: &str =
        "T00 l3= ox+#G WKyV pajU6j qxH@ %B4+a 5Pn^ 7p_v1q 9sLvu *+36i R5rL&3 mVJZI iO0 Ut8_m COTV";

    fn checker() -> CheckerTypes {
        CheckerTypes::CheckAthena(Checker::<Athena>::new())
    }

    fn crack(text: &str) -> CrackResult {
        Decoder::<HillDecoder>::new().crack(text, &checker())
    }

    /// Encrypts `text` with the key `key`, the way [`decrypt`] undoes it.
    fn encrypt<R: AsRef<[u32]>>(text: &str, key: &[R]) -> String {
        let key = Matrix::from_rows(key).expect("a 2×2 or 3×3 key");
        assert!(key.is_invertible(), "{key} isn't a key");
        with_letters(text, &key.apply(&letters_of(text)))
    }

    /// Asserts that `crack` identifies `ciphertext` as `plaintext` with `key`.
    #[track_caller]
    fn assert_cracks(ciphertext: &str, plaintext: &str, key: &str) {
        let result = crack(ciphertext);
        assert!(result.success, "not identified: {result:?}");
        assert_eq!(result.unencrypted_text, Some(vec![plaintext.to_string()]));
        assert_eq!(result.key.as_deref(), Some(key));
        assert_eq!(result.decoder, "Hill");
    }

    /// Asserts that `crack` hands nothing on for `text`.
    #[track_caller]
    fn assert_fails(text: &str) {
        let result = crack(text);
        assert!(!result.success, "{text:?}: {result:?}");
        assert_eq!(result.unencrypted_text, None, "{text:?}");
        assert_eq!(result.key, None, "{text:?}");
    }

    // The vectors were made with a separate Python implementation of the column-vector
    // convention, which reproduces Wikipedia's HELP -> HIAT, ACT -> POH and CAT -> FIN
    // and dCode's DCODEZ -> MDLNFN, and cross-checked with PyPI hillcipher 0.0.4's
    // `encrypt` given the transposed key. The tests below re-encrypt each one.

    #[test]
    fn reference_vectors_encrypt() {
        // Wikipedia, https://en.wikipedia.org/wiki/Hill_cipher
        assert_eq!(encrypt("HELP", &KEY_3_3_2_5), "HIAT");
        assert_eq!(encrypt("ACT", &KEY_GYBNQKURP), "POH");
        assert_eq!(encrypt("CAT", &KEY_GYBNQKURP), "FIN");
        // dCode, https://www.dcode.fr/hill-cipher
        assert_eq!(encrypt("DCODEZ", &[[2, 3], [5, 7]]), "MDLNFN");
    }

    #[test]
    fn reference_vectors_decrypt() {
        assert_eq!(decrypt("HIAT", &KEY_3_3_2_5), Ok("HELP".to_string()));
        assert_eq!(decrypt("POH", &KEY_GYBNQKURP), Ok("ACT".to_string()));
        assert_eq!(decrypt("FIN", &KEY_GYBNQKURP), Ok("CAT".to_string()));
        assert_eq!(
            decrypt("MDLNFN", &[[2, 3], [5, 7]]),
            Ok("DCODEZ".to_string())
        );
        // Entries are taken mod 26
        assert_eq!(decrypt("HIAT", &[[29, 3], [2, 31]]), Ok("HELP".to_string()));
    }

    #[test]
    fn inverses_match_the_references() {
        // dCode's inverse of [[2,3],[5,7]]
        let key = Matrix::from_rows(&[[2, 3], [5, 7]]).unwrap();
        assert_eq!(key.inverse().unwrap().to_string(), "[[19,3],[5,24]]");
        // Wikipedia's inverse of GYBNQKURP
        let key = Matrix::from_rows(&KEY_GYBNQKURP).unwrap();
        assert_eq!(key.determinant(), 25);
        assert_eq!(
            key.inverse().unwrap().to_string(),
            "[[8,5,10],[21,8,21],[21,12,8]]"
        );
        // Wikipedia's 2×2 key has determinant 9 and inverse [[15,17],[20,9]]
        let key = Matrix::from_rows(&KEY_3_3_2_5).unwrap();
        assert_eq!(key.determinant(), 9);
        assert_eq!(key.inverse().unwrap().to_string(), "[[15,17],[20,9]]");
    }

    #[test]
    fn inverse_is_an_inverse_for_every_2x2_key_and_many_3x3_keys() {
        let identity_2x2 = Matrix::from_rows(&[[1, 0], [0, 1]]).unwrap();
        let mut invertible = 0;
        for entries in 0..26u32.pow(4) {
            let rows = [
                [entries / 17_576, entries / 676 % 26],
                [entries / 26 % 26, entries % 26],
            ];
            let key = Matrix::from_rows(&rows).unwrap();
            let Some(inverse) = key.inverse() else {
                assert!(!key.is_invertible(), "{key}");
                continue;
            };
            assert!(key.is_invertible(), "{key}");
            invertible += 1;
            assert_eq!(multiply(&key, &inverse), identity_2x2, "{key}");
            assert_eq!(multiply(&inverse, &key), identity_2x2, "{key}");
        }
        // The number of invertible 2×2 matrices mod 26
        assert_eq!(invertible, 157_248);

        let identity_3x3 = Matrix::from_rows(&[[1, 0, 0], [0, 1, 0], [0, 0, 1]]).unwrap();
        let mut seed = 0x2545_F491_4F6C_DD1Du64;
        let mut tried = 0;
        while tried < 2_000 {
            let mut rows = [[0u32; 3]; 3];
            for entry in rows.iter_mut().flatten() {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                *entry = (seed % 26) as u32;
            }
            let key = Matrix::from_rows(&rows).unwrap();
            if let Some(inverse) = key.inverse() {
                tried += 1;
                assert_eq!(multiply(&key, &inverse), identity_3x3, "{key}");
                assert_eq!(multiply(&inverse, &key), identity_3x3, "{key}");
            }
        }
    }

    /// The product of two matrices of the same size, mod 26.
    fn multiply(left: &Matrix, right: &Matrix) -> Matrix {
        let size = left.size;
        let mut product = Matrix {
            size,
            rows: [[0; 3]; 3],
        };
        for row in 0..size {
            for column in 0..size {
                let sum: i32 = (0..size)
                    .map(|k| left.at(row, k) * right.at(k, column))
                    .sum();
                product.rows[row][column] = (sum % 26) as u8;
            }
        }
        product
    }

    #[test]
    fn singular_keys_and_wrong_sizes_dont_decrypt() {
        // Determinant 2·3 - 4·1 = 2
        assert_eq!(
            decrypt("HIAT", &[[2, 4], [1, 3]]),
            Err(KeyError::Singular(2))
        );
        // Determinant 13
        assert_eq!(
            decrypt("HIAT", &[[13, 0], [0, 1]]),
            Err(KeyError::Singular(13))
        );
        assert_eq!(
            decrypt("HIAT", &[[0, 0], [0, 0]]),
            Err(KeyError::Singular(0))
        );
        // 5 letters aren't whole blocks of 2, or of 3
        assert_eq!(decrypt("HIATX", &KEY_3_3_2_5), Err(KeyError::Length(5)));
        assert_eq!(decrypt("HIAT", &KEY_GYBNQKURP), Err(KeyError::Length(4)));
        assert_eq!(decrypt("HIAT", &[[1u32]]), Err(KeyError::Size));
        assert_eq!(
            decrypt(
                "HIAT",
                &[[1, 0, 0, 0], [0, 1, 0, 0], [0, 0, 1, 0], [0, 0, 0, 1]]
            ),
            Err(KeyError::Size)
        );
        assert_eq!(decrypt("HIAT", &[vec![3, 3], vec![2]]), Err(KeyError::Size));
    }

    #[test]
    fn every_vector_round_trips() {
        let vectors: [(&str, &[[u32; 2]], &str); 4] = [
            ("XTPJPUOUCKEGFCURFTYH", &KEY_3_3_2_5, "SHORTMESSAGEFORHILLX"),
            (
                "WSRZWSFRAVCAQLFKNVAVYYOEPZRGJQHFLONVFMWPCJLDXDHIKYYVHIQOUWWPFRPJBN",
                &KEY_3_3_2_5,
                LIGHTHOUSE,
            ),
            (
                "VLFTLWVGACOCLZKHLVVMPBKIIZJRWFPZGXANTUCLBXVTJSYNVGAPEXUSPNCLOMNNNCARIS",
                &[[5, 8], [17, 3]],
                "DEFENDTHEEASTWALLOFTHECASTLEATDAWNANDHOLDITUNTILTHERELIEFCOLUMNARRIVES",
            ),
            (
                "GBIOMFFXRFMFMZNJIMCGVDOWFCMKEFMFMZNJIMCGVDOWFCSMUUMZUSOXQWGBIOMFFXWQAGRYGKDLUZ\
                 TPEYGBIOMFFXINOEHPLWCLQAPTVDOWFCYORNADMZKLCVQHWHGBQYVDOWFCGISMYWVHNOGOVYGBIOMFF\
                 XWEOWYDMZHJHRTPEY",
                &[[11, 8], [3, 7]],
                DICKENS,
            ),
        ];
        for (ciphertext, key, plaintext) in vectors {
            assert_eq!(encrypt(plaintext, key), ciphertext);
            assert_eq!(decrypt(ciphertext, key), Ok(plaintext.to_string()));
        }
        let vectors: [(&str, &[[u32; 3]], &str); 3] = [
            (
                "QAEQLUHAKWJCTPURKDKFHKQMJKGCCDDWQRKDXNDHRUCIDAJNJUXAJNYSEDEGCCNBLL",
                &KEY_GYBNQKURP,
                LIGHTHOUSE,
            ),
            (
                "UCHLDXJUSTNJNZAGWWHPLEIKIHWDJHAGHWNEAEWUCHLDXETLUYCITDOAVVNTEIKIHWSQAVLGJJTTLP\
                 CNZHPLEIKIHWICBYUPIZIWPPHCYEIKIHWICBYUPDWIOELLAKEEVUCHLDXQLHUCIUKXQXYFJKUCHLDXQ\
                 LHUCIUKXWZOJEAOMC",
                &KEY_2_4_5,
                DICKENS,
            ),
            (LONG_CIPHERTEXT, &KEY_2_4_5, LONG_PADDED),
        ];
        for (ciphertext, key, plaintext) in vectors {
            assert_eq!(encrypt(plaintext, key), ciphertext);
            assert_eq!(decrypt(ciphertext, key), Ok(plaintext.to_string()));
        }
    }

    #[test]
    fn issue_example_is_ranked_first_but_not_identified() {
        // The issue's example. 20 unspaced letters are too few for the checker at Medium,
        // but the decryption reads like English, so it is handed on with its key.
        let ciphertext = "XTPJPUOUCKEGFCURFTYH";
        let ranked = rank(&ciphertext_letters(ciphertext).unwrap());
        let inverse = Matrix::from_rows(&KEY_3_3_2_5).unwrap().inverse().unwrap();
        assert_eq!(ranked[0].decryption, inverse);
        assert_eq!(ranked[0].key(), "[[3,3],[2,5]]");
        assert!(ranked[0].fitness >= UNCONFIRMED_FITNESS, "{ranked:?}");

        let result = crack(ciphertext);
        assert!(!result.success, "{result:?}");
        assert_eq!(
            result.unencrypted_text,
            Some(vec!["SHORTMESSAGEFORHILLX".to_string()])
        );
        assert_eq!(result.key.as_deref(), Some("[[3,3],[2,5]]"));
    }

    #[test]
    fn issue_example_in_lowercase_groups_keeps_case_and_spacing() {
        // The spaces are block groups, not word breaks, so the checker doesn't accept it
        let result = crack("xtpj puou ckeg fcur ftyh");
        assert!(!result.success, "{result:?}");
        assert_eq!(
            result.unencrypted_text,
            Some(vec!["shor tmes sage forh illx".to_string()])
        );
        assert_eq!(result.key.as_deref(), Some("[[3,3],[2,5]]"));
    }

    #[test]
    fn lighthouse_2x2() {
        // 66 letters, so 3×3 keys are tried too; the 2×2 key scores far better
        assert_cracks(
            "WSRZWSFRAVCAQLFKNVAVYYOEPZRGJQHFLONVFMWPCJLDXDHIKYYVHIQOUWWPFRPJBN",
            LIGHTHOUSE,
            "[[3,3],[2,5]]",
        );
    }

    #[test]
    fn lighthouse_3x3() {
        assert_cracks(
            "QAEQLUHAKWJCTPURKDKFHKQMJKGCCDDWQRKDXNDHRUCIDAJNJUXAJNYSEDEGCCNBLL",
            LIGHTHOUSE,
            "[[6,24,1],[13,16,10],[20,17,15]]",
        );
    }

    #[test]
    fn castle_2x2() {
        assert_cracks(
            "VLFTLWVGACOCLZKHLVVMPBKIIZJRWFPZGXANTUCLBXVTJSYNVGAPEXUSPNCLOMNNNCARIS",
            "DEFENDTHEEASTWALLOFTHECASTLEATDAWNANDHOLDITUNTILTHERELIEFCOLUMNARRIVES",
            "[[5,8],[17,3]]",
        );
    }

    #[test]
    fn dickens_3x3() {
        assert_cracks(
            "UCHLDXJUSTNJNZAGWWHPLEIKIHWDJHAGHWNEAEWUCHLDXETLUYCITDOAVVNTEIKIHWSQAVLGJJTTLPCNZ\
             HPLEIKIHWICBYUPIZIWPPHCYEIKIHWICBYUPDWIOELLAKEEVUCHLDXQLHUCIUKXQXYFJKUCHLDXQLHUCI\
             UKXWZOJEAOMC",
            DICKENS,
            "[[2,4,5],[9,2,1],[3,17,7]]",
        );
    }

    #[test]
    fn dickens_2x2() {
        assert_cracks(
            "GBIOMFFXRFMFMZNJIMCGVDOWFCMKEFMFMZNJIMCGVDOWFCSMUUMZUSOXQWGBIOMFFXWQAGRYGKDLUZTPE\
             YGBIOMFFXINOEHPLWCLQAPTVDOWFCYORNADMZKLCVQHWHGBQYVDOWFCGISMYWVHNOGOVYGBIOMFFXWEOW\
             YDMZHJHRTPEY",
            DICKENS,
            "[[11,8],[3,7]]",
        );
    }

    #[test]
    fn ctf_flag_with_mixed_case() {
        // JerseyCTF III "jack-and-jill" (https://ctftime.org/writeup/36829): 30 letters,
        // key [[3,9],[4,7]], and each letter keeps its case
        assert_cracks(
            "pgQVJFCohpccuyBSbwxcxpVZCAATRT",
            "hiTHEREwelcomeTOlinearALGEBRAZ",
            "[[3,9],[4,7]]",
        );
        assert_eq!(
            decrypt("pgQVJFCohpccuyBSbwxcxpVZCAATRT", &[[3, 9], [4, 7]]),
            Ok("hiTHEREwelcomeTOlinearALGEBRAZ".to_string())
        );
    }

    #[test]
    fn long_3x3_is_found_but_not_identified() {
        // The checker doesn't accept 465 letters of unspaced English at Medium, so the
        // decryption comes back unconfirmed, with its key
        let result = crack(LONG_CIPHERTEXT);
        assert!(!result.success, "{result:?}");
        assert_eq!(result.unencrypted_text, Some(vec![LONG_PADDED.to_string()]));
        assert_eq!(result.key.as_deref(), Some("[[2,4,5],[9,2,1],[3,17,7]]"));
    }

    #[test]
    fn transposed_key_is_found_and_reported_transposed() {
        // Scripts that multiply row vectors (P·K) encrypt with the transpose of the
        // column-vector key
        let ciphertext = encrypt(LIGHTHOUSE, &[[3, 2], [3, 5]]);
        assert_cracks(&ciphertext, LIGHTHOUSE, "[[3,2],[3,5]]");
    }

    #[test]
    fn spaced_mixed_case_text_keeps_its_layout() {
        // Hill encryption of the spaced bench plaintext, keeping its case, spaces and
        // punctuation: the checker sees word breaks, at Low sensitivity
        let ciphertext = encrypt(LIGHTHOUSE_SPACED, &KEY_3_3_2_5);
        assert_eq!(
            ciphertext,
            "Wsrz ws fr avc aql fknvavyyoe pzrgj qhflonvf mwp cjldx dhi kyy, vhi qou wwp f rpjbn."
        );
        assert_cracks(&ciphertext, LIGHTHOUSE_SPACED, "[[3,3],[2,5]]");
    }

    #[test]
    fn non_ascii_letters_pass_through() {
        // Non-ASCII letters aren't part of the alphabet: they are copied and use up no
        // place in a block
        let ciphertext = "WSRZWSFRAVCAQLFKNVAVYYOEPZRGJQHFLONVFMWPCJLDXDHIKYYVHIQOUWWPFRPJBN";
        let with_accent = format!("{}é{}", &ciphertext[..30], &ciphertext[30..]);
        let result = crack(&with_accent);
        let expected = format!("{}é{}", &LIGHTHOUSE[..30], &LIGHTHOUSE[30..]);
        assert_eq!(result.unencrypted_text, Some(vec![expected.clone()]));
        assert_eq!(result.key.as_deref(), Some("[[3,3],[2,5]]"));
        assert_eq!(decrypt(&with_accent, &KEY_3_3_2_5), Ok(expected));
    }

    #[test]
    fn at_most_three_decryptions_are_checked() {
        let texts = [
            "XTPJPUOUCKEGFCURFTYH",
            "WSRZWSFRAVCAQLFKNVAVYYOEPZRGJQHFLONVFMWPCJLDXDHIKYYVHIQOUWWPFRPJBN",
            "QAEQLUHAKWJCTPURKDKFHKQMJKGCCDDWQRKDXNDHRUCIDAJNJUXAJNYSEDEGCCNBLL",
            LONG_CIPHERTEXT,
            // Letters only, length a multiple of 6: both key sizes are tried
            "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZ",
        ];
        for text in texts {
            if let Some(ciphertext) = ciphertext_letters(text) {
                let ranked = rank(&ciphertext);
                assert!(ranked.len() <= MAX_CHECKED, "{text}: {ranked:?}");
                assert!(
                    ranked.iter().all(|r| r.fitness >= ENGLISH_FITNESS),
                    "{text}: {ranked:?}"
                );
                assert!(
                    ranked.windows(2).all(|w| w[0].fitness >= w[1].fitness),
                    "{text}: {ranked:?}"
                );
            }
        }
    }

    #[test]
    fn short_or_unpadded_text_is_rejected_by_the_pre_checks() {
        // Wikipedia's examples are too short to crack without the key
        for text in ["HIAT", "POH", "IHHWVC SWFRCP"] {
            assert!(ciphertext_letters(text).is_none(), "{text}");
        }
        // 35 letters: not a whole number of blocks of 2, and too few for 3×3
        assert!(ciphertext_letters("THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG").is_none());
        // 21 letters are 7 blocks of 3, but 3×3 keys need 60
        assert!(ciphertext_letters("XTPJPUOUCKEGFCURFTYHX").is_none());
        // 63 letters: odd, so only 3×3 keys are tried
        let odd = &LIGHTHOUSE[..63];
        let ciphertext = encrypt(odd, &KEY_GYBNQKURP);
        let letters = ciphertext_letters(&ciphertext).unwrap();
        assert!(!letters.try_2x2 && letters.try_3x3);
    }

    #[test]
    fn index_of_coincidence_check() {
        // 465 letters of Hill ciphertext pass; the same letters as English don't
        assert!(ciphertext_letters(LONG_CIPHERTEXT).is_some());
        assert!(ciphertext_letters(LONG_PADDED).is_none());
        // Below IOC_MIN_LETTERS letters the IoC isn't checked
        let letters = ciphertext_letters(&encrypt(LIGHTHOUSE, &KEY_3_3_2_5)).unwrap();
        assert!(letters.try_2x2 && letters.try_3x3);
    }

    #[test]
    fn pre_checks_turn_away_rearranged_and_substituted_english() {
        use crate::decoders::{affine_decoder, caesar_decoder, railfence_decoder};
        // English rearranged keeps English's letter frequencies
        let reversed: String = LIGHTHOUSE.chars().rev().collect();
        let rail_fence = railfence_decoder::railfence_decoder(LIGHTHOUSE, 3, 0);
        // Caesar, Atbash and Affine keys turn the letter pairs back into English ones
        let caesar = caesar_decoder::caesar(LIGHTHOUSE, 3);
        let atbash = affine_decoder::decrypt(LIGHTHOUSE, 25, 25);
        let affine = affine_decoder::decrypt(LIGHTHOUSE, 7, 3);
        for text in [&reversed, &rail_fence, &caesar, &atbash, &affine] {
            assert!(ciphertext_letters(text).is_none(), "{text}");
        }
        // Shorter than the checks need: left to the key search, which finds nothing
        let short_caesar = caesar_decoder::caesar(&LIGHTHOUSE[..38], 3);
        assert!(ciphertext_letters(&short_caesar).is_some());
        assert!(rank(&ciphertext_letters(&short_caesar).unwrap()).is_empty());
    }

    #[test]
    fn every_hill_vector_passes_the_pre_checks() {
        for text in [
            "XTPJPUOUCKEGFCURFTYH",
            "pgQVJFCohpccuyBSbwxcxpVZCAATRT",
            "WSRZWSFRAVCAQLFKNVAVYYOEPZRGJQHFLONVFMWPCJLDXDHIKYYVHIQOUWWPFRPJBN",
            "QAEQLUHAKWJCTPURKDKFHKQMJKGCCDDWQRKDXNDHRUCIDAJNJUXAJNYSEDEGCCNBLL",
            "VLFTLWVGACOCLZKHLVVMPBKIIZJRWFPZGXANTUCLBXVTJSYNVGAPEXUSPNCLOMNNNCARIS",
            LONG_CIPHERTEXT,
            &encrypt(DICKENS, &KEY_2_4_5),
            &encrypt(DICKENS, &[[11, 8], [3, 7]]),
            &encrypt(LIGHTHOUSE_SPACED, &KEY_3_3_2_5),
        ] {
            assert!(ciphertext_letters(text).is_some(), "{text}");
        }
    }

    #[test]
    fn inputs_that_arent_hill_ciphertext_fail() {
        let inputs = [
            "",
            "😀",
            "hello world",
            "12345!@#$%",
            MISS,
            // 35 letters
            "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG",
            // English, unspaced and spaced: it reads as English already
            LIGHTHOUSE,
            LIGHTHOUSE_SPACED,
            // ROT13 and Atbash of it: no key reads as English
            "Zrrg zr ng gur byq yvtugubhfr nsgre zvqavtug naq oevat gur znc, gur xrl naq n gbepu.",
            "Nvvg nv zg gsv low ortsgslfhv zugvi nrwmrtsg zmw yirmt gsv nzk, gsv pvb zmw z glixs.",
            // The bench's Vigenère input
            "Wicd qc kx rri mvh jskfdlmewc kjrov kshlskfd eln fpsre dlc wen, dlc uiw krb k xmbgf.",
            // Affine, a=5 b=8 and a=7 b=3
            "Yt uek tpo nokt ax tyiok, yt uek tpo uabkt ax tyiok",
            "Usl nfdpz eyrbg wrm ofvcj rqly usl ktix arh bsdkl usl ptu jkllcj.",
            // Beaufort
            "Zaiv bh et vgh qbl cdyfvgxkuk nglix bdbzghel mbk knebh sxi cnw, lfk dhg mbk l lyxle.",
            // The bench's Base64 input
            "TWVldCBtZSBhdCB0aGUgb2xkIGxpZ2h0aG91c2UgYWZ0ZXIgbWlkbmlnaHQgYW5kIGJyaW5nIHRoZSBtYXAsIHRoZSBrZXkgYW5kIGEgdG9yY2gu",
            // Hexadecimal and Latin-1 the hex decoder makes
            "4d656574206d6520617420746865206f6c64206c69676874686f757365",
            "'V&ÖWæõVg\u{96}f",
            // Every letter once, three times: no key reads as English
            "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ];
        for text in inputs {
            assert_fails(text);
        }
    }

    #[test]
    fn other_classical_ciphers_get_nothing() {
        // Ciphertexts of the crackers listed after Hill in the search (the Playfair,
        // Vigenère Autokey and Route Transposition decoders' test and bench vectors):
        // Hill hands nothing on, so it can't beat them when both run in one step
        let texts = [
            "BMODZBXDNABEKUDMUIXMMOUVIF",
            "RGROSKIQDSTFCYCAMRIREAYRTSRETOROCPFTCEQKQEOXOPCQSRLRRPCPRGAEOPLEATRGCIKRHERPUARDIS\
             XRMRMXAEHOSKGVYDFISTINLFRASICQIZIQXRKDPBRGROEDAWQCYDHORPUAIRORVEHOTRRPEGTSRHKSDICP\
             HKQBFGQLGKHIRSPBRGCIDYRSHOINSGAYBTTFHOHUMENRGEKBESRWDBSGSTTATSPBRGSCNEOTETREASOGMH\
             FHXEPCBSPNRGSISCRTINFGCAEHFTRSEVRGACXENERGCIDYRSHOEKOT",
            "NUQGFHGUUROSLAROHAPGFSBUCGPILABOVESILWUHHAWNQZRGSFAMUQBUFSKGSYAKPCGLAZHUAGUVAMBAAI\
             YIKAZUDPUMAHULIZGLLEAIVEEIOZUWHLABMUZIEFFAVEQAYORIEFNUQGAQGLEAKZFIAELTMASILQURXQUE\
             UGMOSFUFSBUWSDFIUFDAAOF",
            "Wicf qi tf xhx hsh ztjsbnvnzs uxxew fmuzqjub guw belox buk fht, fht dlc krb a grrvv.",
            "M  ge hbh y eaoh mtret tetltai i haot dhfdanmenr t otnnga dcmhlueid pk heeisrg t,ea.",
        ];
        for text in texts {
            assert_fails(text);
            if let Some(ciphertext) = ciphertext_letters(text) {
                assert!(rank(&ciphertext).is_empty(), "{text}");
            }
        }
    }

    #[test]
    fn affine_keeps_its_ciphertexts() {
        // Multiplying by a number is a diagonal key, which Hill leaves to Affine
        let ciphertext = encrypt(LIGHTHOUSE, &[[5, 0], [0, 5]]);
        assert_fails(&ciphertext);
        let ciphertext = encrypt(&LIGHTHOUSE[..60], &[[7, 0, 0], [0, 7, 0], [0, 0, 7]]);
        assert_fails(&ciphertext);
    }

    #[test]
    fn rows_that_cant_be_in_a_key_are_left_out() {
        let letters = letters_of(LONG_CIPHERTEXT);
        for size in [2, 3] {
            let search = Search {
                size,
                rank_blocks: 100,
                top_rows: 50,
            };
            let rows = best_rows(&letters, &search);
            assert_eq!(rows.len(), 50);
            for row in &rows {
                let entries = &row[..size];
                assert!(!entries.iter().all(|&e| e % 2 == 0), "{row:?}");
                assert!(!entries.iter().all(|&e| e % 13 == 0), "{row:?}");
            }
        }
    }

    #[test]
    fn rows_of_the_key_rank_among_the_best() {
        let letters = letters_of(LONG_CIPHERTEXT);
        let decryption = Matrix::from_rows(&KEY_2_4_5).unwrap().inverse().unwrap();
        let best = best_rows(&letters, &SEARCH_3X3);
        assert_eq!(best.len(), SEARCH_3X3.top_rows);
        for row in &decryption.rows {
            assert!(best.contains(row), "{row:?} not in {best:?}");
        }
    }

    #[test]
    fn best_keeps_the_first_of_equal_scores() {
        let mut best = Best::new(2);
        for (score, item) in [(1, 'a'), (3, 'b'), (2, 'c'), (3, 'd'), (2, 'e')] {
            best.offer(score, item);
        }
        assert_eq!(best.items, [(3, 'b'), (3, 'd')]);
        assert!(!best.wants(3));
        assert!(best.wants(4));
    }

    #[test]
    fn fitness_tells_english_from_ciphertext() {
        let english = fitness(&letters_of(LIGHTHOUSE));
        let ciphertext = fitness(&letters_of(
            "WSRZWSFRAVCAQLFKNVAVYYOEPZRGJQHFLONVFMWPCJLDXDHIKYYVHIQOUWWPFRPJBN",
        ));
        assert!(english > ENGLISH_FITNESS, "{english}");
        assert!(ciphertext < ENGLISH_FITNESS, "{ciphertext}");
    }

    #[test]
    fn decoder_metadata() {
        let decoder = Decoder::<HillDecoder>::new();
        assert_eq!(decoder.get_name(), "Hill");
        assert_eq!(
            decoder.get_link(),
            "https://en.wikipedia.org/wiki/Hill_cipher"
        );
        assert_eq!(
            decoder.get_tags(),
            &vec!["hill", "matrix", "substitution", "classical"]
        );
        assert!(!decoder.get_tags().contains(&"decoder"));
        assert!(!decoder.get_tags().contains(&"reciprocal"));
        assert!((decoder.get_popularity() - 0.3).abs() < f32::EPSILON);
    }

    #[test]
    fn registered_once() {
        let decoders = crate::filtration_system::get_decoder_by_name("Hill");
        assert_eq!(decoders.components.len(), 1);
        assert_eq!(decoders.components[0].get_name(), "Hill");
        assert!(crate::decoders::DECODER_MAP.contains_key("Hill"));
    }

    #[test]
    fn hill_runs_before_vigenere_in_the_search() {
        // A Hill plaintext and a Vigenère false positive found in the same step tie, and
        // the first in the list wins
        let decoders = crate::filtration_system::get_all_decoders();
        let names: Vec<&str> = decoders
            .components
            .iter()
            .map(|decoder| decoder.get_name())
            .collect();
        let position = |name| names.iter().position(|&n| n == name).unwrap();
        assert!(position("Hill") < position("Vigenere"), "{names:?}");
    }

    #[test]
    fn key_format() {
        let key = Matrix::from_rows(&KEY_GYBNQKURP).unwrap();
        assert_eq!(key.to_string(), "[[6,24,1],[13,16,10],[20,17,15]]");
        assert_eq!(
            format_key(&[[29u32, 3], [2, 5]]),
            Some("[[3,3],[2,5]]".to_string())
        );
        assert_eq!(format_key(&[[1u32]]), None);
    }
}
