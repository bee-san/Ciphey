//! Cracks the Vigenère autokey (autoclave) cipher. Its key stream is a short primer
//! followed by the plaintext itself: with letters as 0 to 25, `c[i] = p[i] + k[i]`
//! (mod 26), where `k[i]` is `primer[i]` for the first `L` letters and `p[i - L]` after
//! them. Only ASCII letters are enciphered and use up key letters. Case, digits, spaces,
//! punctuation and other characters are kept, so on the letters this is the cipher of
//! pycipher's `Autokey` and dCode's autoclave cipher, which drop everything else. See
//! <https://en.wikipedia.org/wiki/Autokey_cipher>.
//!
//! The key stream doesn't repeat, so the Vigenère cracker's statistics don't apply, but
//! each primer letter can be found on its own: the letters at positions `j`, `j + L`,
//! `j + 2L`, ... only depend on primer letter `j`. Decrypting them with primer letter A
//! gives a sequence `s`, and with primer letter `k` the plaintext is `s[t] - k` at even
//! `t` and `s[t] + k` at odd `t`. So for each primer length from 1 to 15 the cracker
//! 1. picks each primer letter by how English the letters of its class look (26 × L
//!    letter-frequency scores instead of 26^L keys),
//! 2. scores the whole decryption by how often its quadgrams (runs of four letters) occur
//!    in English, and
//! 3. for the 5 best primer lengths, sets each primer letter in turn to the letter that
//!    gives the best quadgram score, for up to two passes over the primer.
//!
//! The best few decryptions go to the checker. See
//! <http://practicalcryptography.com/cryptanalysis/stochastic-searching/cryptanalysis-autokey-cipher/>.
//! The quadgram counts are in `src/storage/ngrams/english_quadgrams.txt`.
//!
//! The search takes a fraction of a millisecond for a sentence and a few for a page, so
//! text that isn't mostly letters is rejected first, in one pass and without allocating:
//! it needs at least 20 ASCII letters, 8 of them different, at most one other character
//! that isn't a word separator (whitespace, or `_` as in CTF flags) per 12 letters (a
//! digit, punctuation, a non-ASCII character...), and few changes from lower to upper
//! case inside words. This rules out Base64, hexadecimal and the other encodings.

use super::crack_results::CrackResult;
use super::interface::{Crack, Decoder};
use crate::checkers::CheckerTypes;
use crate::storage::ENGLISH_FREQS;
use gibberish_or_not::Sensitivity;
use log::{debug, trace};
use once_cell::sync::Lazy;

/// Fewer ASCII letters than this and the text isn't searched: there is too little of it
/// to tell the primer apart from the plaintext.
const MIN_LETTERS: usize = 20;

/// The fewest different letters worth searching. Autokey ciphertexts of 20 or more
/// letters of English used at least 8 (with 5,000 random primers of 1 to 15 letters for
/// each length from 20 to 200 letters), 13 from 40 letters on. A run of one letter, as the
/// hexadecimal decoder makes of `ffff...`, decrypts to periodic text such as
/// `foraroforaro...` that the checker can take for English, and the Baconian and DNA
/// alphabets have 2 and 4 letters.
const MIN_DISTINCT_LETTERS: u32 = 8;

/// The text is only searched if it has at most one character that is neither an ASCII
/// letter nor a word separator (whitespace or `_`) per this many letters. English
/// sentences have 2 to 3% of them, Base64, Base32 and Base58 10 to 18%.
const LETTERS_PER_OTHER: usize = 12;

/// The case check below only applies to texts with at least this many pairs of adjacent
/// letters: fewer give a noisy share.
const MIN_PAIRS_FOR_CASE_GATE: usize = 20;

/// At most one pair of adjacent letters in this many may be a lower-case letter followed
/// by an upper-case one (`aB`). The cipher keeps each letter's case, and English almost
/// never changes case inside a word (at most one pair in 11, as the Affine decoder
/// measured), while Base64 does it about one pair in four. Base64 of text that is mostly
/// digits and spaces, such as binary or Baudot, has almost no digits of its own for the
/// check above to catch.
const LOWER_UPPER_PAIRS_ONE_IN: usize = 8;

/// The longest primer tried.
const MAX_PRIMER: usize = 15;

/// Primers are at most a quarter as long as the text's letters. With fewer than about 6
/// letters per primer letter the cracker can't tell the right primer from a wrong one.
const LETTERS_PER_PRIMER_LETTER: usize = 4;

/// Only the first this many letters are searched; the decryption shown to the checker is
/// the whole text. That is over 30 letters per primer letter, which is plenty, and keeps
/// the search of a long text as fast as that of a page.
const SEARCH_LETTERS: usize = 500;

/// This many primer lengths, the best before refining, are refined.
const REFINED_LENGTHS: usize = 5;

/// The most passes over the primer when refining it. A pass that changes nothing ends
/// the refining early.
const REFINE_ROUNDS: usize = 2;

/// The most decryptions shown to the checker, best first.
const MAX_CHECKED: usize = 3;

/// The [`fitness`] at or above which a decryption is shown to the checker. Correct
/// decryptions of English score -4.05 to -4.4. Plain English, Caesar, Vigenère and
/// Beaufort ciphertexts and random letters almost never have a decryption this good.
const CHECK_FITNESS: f32 = -5.0;

/// What each primer letter costs in a decryption's [`fitness`], in log10 probability: a
/// longer primer fits a text more freely. With a cost of 1, the checker accepted a
/// decryption of 88 of 15,400 texts of 20 to 150 letters that weren't autokey ciphertexts
/// (English, Caesar, Atbash, Vigenère, random letters, with and without spaces), and a
/// decryption with a wrong primer, nearly always of the right length, for 247 of 4,400
/// autokey ciphertexts. With 2 it accepted 3 (unspaced, of 20 and 40 letters) and 150,
/// and found 5 fewer primers (2,661).
const PRIMER_LETTER_COST: f32 = 2.0;

/// If the checker accepts none of the decryptions, the best one is still handed on to
/// the search, as a text to decode further, if its [`fitness`] is at least this.
const UNCONFIRMED_FITNESS: f32 = -4.6;

/// Number of possible quadgrams, 26⁴.
const QUADGRAM_COUNT: usize = 26 * 26 * 26 * 26;

/// log10 probability of every quadgram, indexed by [`quadgram_at`]. Built on first use.
static QUADGRAMS: Lazy<Box<[f32]>> =
    Lazy::new(|| parse_quadgrams(include_str!("../storage/ngrams/english_quadgrams.txt")));

/// `CLASS_SCORES[parity][s][k]`: log10 of the English frequency of the letter that a
/// letter `s` of a class decrypted with primer letter A becomes with primer letter `k`,
/// `s - k` at even places (`parity` 0) of the class and `s + k` at odd places (1). One
/// row adds a letter's score for all 26 primer letters at once.
static CLASS_SCORES: Lazy<[[[f32; 26]; 26]; 2]> = Lazy::new(|| {
    let unigrams = ENGLISH_FREQS.map(|freq| freq.log10() as f32);
    let mut table = [[[0.0; 26]; 26]; 2];
    for s in 0..26 {
        for k in 0..26 {
            table[0][s][k] = unigrams[(s + 26 - k) % 26];
            table[1][s][k] = unigrams[(s + k) % 26];
        }
    }
    table
});

/// The Vigenère autokey cracker. Call
/// `let decoder = Decoder::<VigenereAutokeyDecoder>::new()` to create one, and
/// `decoder.crack(text, &checker)` to crack `text`.
/// ```
/// use ciphey::decoders::vigenere_autokey_decoder::VigenereAutokeyDecoder;
/// use ciphey::decoders::interface::{Crack, Decoder};
/// use ciphey::checkers::{athena::Athena, CheckerTypes, checker_type::{Check, Checker}};
///
/// let decoder = Decoder::<VigenereAutokeyDecoder>::new();
/// let checker = CheckerTypes::CheckAthena(Checker::<Athena>::new());
///
/// // Primer KEY: the plaintext is enciphered with K, E, Y and then with its own letters
/// let result = decoder.crack(
///     "Wicf qi tf xhx hsh ztjsbnvnzs uxxew fmuzqjub guw belox buk fht, fht dlc krb a grrvv.",
///     &checker,
/// );
/// assert!(result.success);
/// assert_eq!(
///     result.unencrypted_text.unwrap()[0],
///     "Meet me at the old lighthouse after midnight and bring the map, the key and a torch."
/// );
/// assert_eq!(result.key.unwrap(), "KEY");
/// ```
pub struct VigenereAutokeyDecoder;

impl Crack for Decoder<VigenereAutokeyDecoder> {
    fn new() -> Decoder<VigenereAutokeyDecoder> {
        Decoder {
            name: "Vigenere Autokey",
            description: "Autokey (autoclave) Vigenère cipher: a short primer followed by the plaintext as the key stream. Recovers the primer by solving each residue class independently and refining with quadgram statistics. Uses Low sensitivity for gibberish detection on spaced text, Medium on unspaced text.",
            link: "https://en.wikipedia.org/wiki/Autokey_cipher",
            tags: vec!["autokey", "vigenere", "substitution", "classical"],
            popularity: 0.3,
            phantom: std::marker::PhantomData,
        }
    }

    /// Searches for the primer. On success the plaintext is the only element of
    /// `unencrypted_text` and `key` is the primer, in upper case. When the checker
    /// accepts none of the decryptions but the best one still reads like English, that
    /// one is returned unconfirmed, so the search can keep decoding it.
    fn crack(&self, text: &str, checker: &CheckerTypes) -> CrackResult {
        trace!("Trying Vigenère autokey with text {:?}", text);
        let mut results = CrackResult::new(self, text.to_string());

        let census = Census::of(text);
        if !census.worth_searching() {
            trace!("Vigenère autokey skipped the text: {census:?}");
            return results;
        }

        let candidates = rank_letters(&search_letters(text));
        let Some(best) = candidates.first() else {
            trace!("Vigenère autokey found no primer that gives English");
            return results;
        };

        // Without word breaks the English checker reads the text as one long word, and
        // only accepts English at Medium sensitivity
        let sensitivity = if census.whitespace > 0 {
            Sensitivity::Low
        } else {
            Sensitivity::Medium
        };
        let checker = checker.with_sensitivity(sensitivity);
        for candidate in &candidates {
            let primer = primer_string(&candidate.primer);
            let plaintext = decrypt(text, &primer);
            let check = checker.check(&plaintext);
            if check.is_identified {
                debug!(
                    "Vigenère autokey found primer {primer} (fitness {:.3})",
                    candidate.fitness
                );
                results.unencrypted_text = Some(vec![plaintext]);
                results.update_checker(&check);
                results.key = Some(primer);
                return results;
            }
        }

        if best.fitness >= UNCONFIRMED_FITNESS {
            let primer = primer_string(&best.primer);
            debug!(
                "Vigenère autokey best guess, primer {primer} (fitness {:.3})",
                best.fitness
            );
            results.unencrypted_text = Some(vec![decrypt(text, &primer)]);
            results.key = Some(primer);
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

/// How many characters of each kind a text has, for the checks before the search.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Census {
    /// ASCII letters.
    letters: usize,
    /// ASCII whitespace.
    whitespace: usize,
    /// Underscores, which separate the words of CTF flags like `flag{like_this}`.
    underscores: usize,
    /// Every other character, including non-ASCII letters.
    other: usize,
    /// Pairs of adjacent ASCII letters.
    pairs: usize,
    /// Pairs of adjacent ASCII letters that are a lower-case letter followed by an
    /// upper-case one (`aB`).
    lower_upper_pairs: usize,
    /// Bit `i` is set if the text has letter `i` (A is 0), in either case.
    seen: u32,
}

impl Census {
    /// Counts the characters of `text`.
    fn of(text: &str) -> Census {
        let mut census = Census::default();
        // Whether the character before was a lower-case letter, if it was a letter
        let mut previous_lowercase: Option<bool> = None;
        for c in text.chars() {
            if c.is_ascii_alphabetic() {
                census.letters += 1;
                census.seen |= 1 << (c.to_ascii_uppercase() as u8 - b'A');
                if let Some(previous_lowercase) = previous_lowercase {
                    census.pairs += 1;
                    if previous_lowercase && c.is_ascii_uppercase() {
                        census.lower_upper_pairs += 1;
                    }
                }
                previous_lowercase = Some(c.is_ascii_lowercase());
                continue;
            }
            previous_lowercase = None;
            if c.is_ascii_whitespace() {
                census.whitespace += 1;
            } else if c == '_' {
                census.underscores += 1;
            } else {
                census.other += 1;
            }
        }
        census
    }

    /// Whether the text could be English enciphered with an autokey: enough letters, and
    /// enough different ones, few characters that are neither letters nor word
    /// separators, and few changes from lower to upper case inside words.
    fn worth_searching(&self) -> bool {
        self.letters >= MIN_LETTERS
            && self.seen.count_ones() >= MIN_DISTINCT_LETTERS
            && self.other * LETTERS_PER_OTHER <= self.letters
            && (self.pairs < MIN_PAIRS_FOR_CASE_GATE
                || self.lower_upper_pairs * LOWER_UPPER_PAIRS_ONE_IN <= self.pairs)
    }
}

/// A primer the search found.
#[derive(Debug, Clone)]
struct Candidate {
    /// The [`fitness`] of the decryption.
    fitness: f32,
    /// The primer, as letters 0 to 25.
    primer: Vec<u8>,
    /// The decryption of the searched letters, as letters 0 to 25.
    plain: Vec<u8>,
}

/// The first [`SEARCH_LETTERS`] ASCII letters of `text`, as 0 to 25. Bytes of multi-byte
/// characters are never ASCII, so filtering bytes is the same as filtering characters,
/// and Latin-1 letters such as `Ö` can't index out of range.
fn search_letters(text: &str) -> Vec<u8> {
    text.bytes()
        .filter(u8::is_ascii_alphabetic)
        .take(SEARCH_LETTERS)
        .map(|byte| byte.to_ascii_uppercase() - b'A')
        .collect()
}

/// The best primers for `letters`, best first: at most [`MAX_CHECKED`] of them, each with
/// a [`fitness`] of at least [`CHECK_FITNESS`], and no two with the same decryption.
fn rank_letters(letters: &[u8]) -> Vec<Candidate> {
    let n = letters.len();
    let longest = MAX_PRIMER.min(n / LETTERS_PER_PRIMER_LETTER);
    if longest == 0 {
        return Vec::new();
    }
    let quadgrams: &[f32] = &QUADGRAMS;

    // One primer per length, each letter solved on its own class
    let mut plain = vec![0; n];
    let mut lengths: Vec<(f32, Vec<u8>)> = (1..=longest)
        .map(|length| {
            let primer = solve_classes(letters, length);
            decrypt_letters(letters, &primer, &mut plain);
            let score = fitness(total_score(&plain, quadgrams), length, n);
            (score, primer)
        })
        .collect();
    // A stable sort, so of two lengths that score the same the shorter comes first
    lengths.sort_by(|a, b| b.0.total_cmp(&a.0));
    lengths.truncate(REFINED_LENGTHS);

    let mut candidates: Vec<Candidate> = lengths
        .into_iter()
        .map(|(_, mut primer)| {
            let mut plain = vec![0; n];
            decrypt_letters(letters, &primer, &mut plain);
            let total = refine(&mut primer, &mut plain, quadgrams);
            Candidate {
                fitness: fitness(total, primer.len(), n),
                primer,
                plain,
            }
        })
        .collect();
    candidates.sort_by(|a, b| b.fitness.total_cmp(&a.fitness));

    let mut kept: Vec<Candidate> = Vec::with_capacity(MAX_CHECKED);
    for candidate in candidates {
        if candidate.fitness < CHECK_FITNESS || kept.len() == MAX_CHECKED {
            break;
        }
        if kept.iter().all(|other| other.plain != candidate.plain) {
            kept.push(candidate);
        }
    }
    kept
}

/// The primer of `length` letters whose letters each make their own class of `letters`
/// look most like English, by letter frequencies. Class `j` is the letters at positions
/// `j`, `j + length`, `j + 2·length`, ..., and only depends on primer letter `j`.
fn solve_classes(letters: &[u8], length: usize) -> Vec<u8> {
    let table = &*CLASS_SCORES;
    (0..length)
        .map(|j| {
            // scores[k]: how English class j looks with primer letter k
            let mut scores = [0f32; 26];
            // The class decrypted with primer letter A: each plaintext letter is the
            // ciphertext letter minus the plaintext letter before it in the class
            let mut previous = 0;
            for (t, &letter) in letters[j..].iter().step_by(length).enumerate() {
                previous = (letter + 26 - previous) % 26;
                let row = &table[t % 2][usize::from(previous)];
                for (score, &add) in scores.iter_mut().zip(row) {
                    *score += add;
                }
            }
            // The first best letter
            let mut best = 0;
            for (k, &score) in scores.iter().enumerate() {
                if score > scores[best] {
                    best = k;
                }
            }
            best as u8
        })
        .collect()
}

/// Decrypts `letters` (0 to 25) with `primer` (0 to 25, not empty) into `plain`, which is
/// as long as `letters`.
fn decrypt_letters(letters: &[u8], primer: &[u8], plain: &mut [u8]) {
    for i in 0..letters.len() {
        let key = if i < primer.len() {
            primer[i]
        } else {
            plain[i - primer.len()]
        };
        plain[i] = (letters[i] + 26 - key) % 26;
    }
}

/// Sets each letter of `primer` in turn to the letter that gives the best quadgram score,
/// for up to [`REFINE_ROUNDS`] passes over the primer, and returns the total quadgram
/// score of the final decryption. `plain` is the decryption with `primer` before and
/// after.
///
/// Changing primer letter `j` only changes the letters of class `j`, so only the
/// quadgrams with one of those letters in them are scored again.
fn refine(primer: &mut [u8], plain: &mut [u8], quadgrams: &[f32]) -> f32 {
    let n = plain.len();
    let length = primer.len();
    let mut overlapping = (length < 4).then(|| Overlapping::new(plain, length));

    for _ in 0..REFINE_ROUNDS {
        let mut changed = false;
        for (j, primer_letter) in primer.iter_mut().enumerate() {
            // scores[d]: the score of the quadgrams that change, with primer letter j
            // raised by d
            let scores = match overlapping.as_mut() {
                Some(overlapping) => overlapping.shift_scores(plain, j, quadgrams),
                None => shift_scores(plain, j, length, quadgrams),
            };
            // The first best, so the letter only changes for a better score
            let mut best = 0;
            for (delta, &score) in scores.iter().enumerate() {
                if score > scores[best] {
                    best = delta;
                }
            }
            if best != 0 {
                let delta = best as u8;
                for (t, i) in (j..n).step_by(length).enumerate() {
                    plain[i] = shifted(plain[i], t, delta);
                }
                if let Some(overlapping) = overlapping.as_mut() {
                    overlapping.trial.copy_from_slice(plain);
                }
                *primer_letter = (*primer_letter + delta) % 26;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    total_score(plain, quadgrams)
}

/// What the plaintext letter at place `t` of its class becomes when the class's primer
/// letter is raised by `delta`: `delta` less at even places, `delta` more at odd places.
fn shifted(letter: u8, t: usize, delta: u8) -> u8 {
    if t.is_multiple_of(2) {
        (letter + 26 - delta) % 26
    } else {
        (letter + delta) % 26
    }
}

/// [`refine`]'s scores for a primer of 4 or more letters, whose classes have letters at
/// least 4 apart: each quadgram has at most one letter of class `j`. For each of them,
/// the quadgram's index without that letter is worked out once, and the 26 letters it
/// can become are added in.
fn shift_scores(plain: &[u8], j: usize, length: usize, quadgrams: &[f32]) -> [f32; 26] {
    /// What a letter at each place of a quadgram counts for in its index.
    const PLACE: [usize; 4] = [26 * 26 * 26, 26 * 26, 26, 1];
    let n = plain.len();
    let mut scores = [0f32; 26];
    for (t, i) in (j..n).step_by(length).enumerate() {
        let letter = plain[i];
        for start in i.saturating_sub(3)..=i.min(n - 4) {
            let place = PLACE[i - start];
            let others = quadgram_at(&plain[start..start + 4]) - usize::from(letter) * place;
            for (delta, score) in (0..26).zip(scores.iter_mut()) {
                *score += quadgrams[others + usize::from(shifted(letter, t, delta)) * place];
            }
        }
    }
    scores
}

/// [`refine`]'s scores for a primer of 1 to 3 letters, whose classes can have several
/// letters in one quadgram: each change is decrypted into a copy of the plaintext, and
/// the quadgrams with a letter of the class in them scored on it.
struct Overlapping {
    /// The primer's length.
    length: usize,
    /// The plaintext, with the letters of one class changed while scoring it.
    trial: Vec<u8>,
    /// The start of each quadgram with a letter of the class in it, each once.
    windows: Vec<usize>,
}

impl Overlapping {
    /// Scratch space for refining the decryption `plain` with a primer of `length`.
    fn new(plain: &[u8], length: usize) -> Overlapping {
        Overlapping {
            length,
            trial: plain.to_vec(),
            windows: Vec::with_capacity(plain.len()),
        }
    }

    /// See [`refine`]. `self.trial` equals `plain` before and after.
    fn shift_scores(&mut self, plain: &[u8], j: usize, quadgrams: &[f32]) -> [f32; 26] {
        let n = plain.len();
        self.windows.clear();
        for i in (j..n).step_by(self.length) {
            let first = i.saturating_sub(3);
            let first = self
                .windows
                .last()
                .map_or(first, |&last| first.max(last + 1));
            self.windows.extend(first..=i.min(n - 4));
        }
        let mut scores = [0f32; 26];
        for (delta, score) in (0..26).zip(scores.iter_mut()) {
            for (t, i) in (j..n).step_by(self.length).enumerate() {
                self.trial[i] = shifted(plain[i], t, delta);
            }
            *score = self
                .windows
                .iter()
                .map(|&start| quadgrams[quadgram_at(&self.trial[start..start + 4])])
                .sum();
        }
        for i in (j..n).step_by(self.length) {
            self.trial[i] = plain[i];
        }
        scores
    }
}

/// Mean log10 probability of the quadgrams of a decryption of `n` letters with a primer
/// of `length` letters, whose quadgram scores add up to `total`, less
/// [`PRIMER_LETTER_COST`] per primer letter.
fn fitness(total: f32, length: usize, n: usize) -> f32 {
    (total - PRIMER_LETTER_COST * length as f32) / (n - 3) as f32
}

/// The sum of the log10 probabilities of the quadgrams of `plain`.
fn total_score(plain: &[u8], quadgrams: &[f32]) -> f32 {
    plain
        .windows(4)
        .map(|quadgram| quadgrams[quadgram_at(quadgram)])
        .sum()
}

/// Index in [`QUADGRAMS`] of the first four letters (0 to 25) of `letters`.
fn quadgram_at(letters: &[u8]) -> usize {
    letters[..4]
        .iter()
        .fold(0, |index, &letter| index * 26 + usize::from(letter))
}

/// Index in [`QUADGRAMS`] of a quadgram of upper-case letters.
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
/// aren't listed get log10(0.5 / total), as if they had been seen half a time. The same
/// as the Monoalphabetic Substitution cracker's table.
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

/// `primer` (letters 0 to 25) as upper-case letters.
fn primer_string(primer: &[u8]) -> String {
    primer
        .iter()
        .map(|&letter| char::from(b'A' + letter))
        .collect()
}

/// Decrypts `text` with the autokey primer `primer`, ASCII letters in either case. The
/// first letters of `text` are decrypted with the primer's letters and the rest with the
/// plaintext's own letters, from the first on. Letters keep their case, and anything
/// that isn't an ASCII letter is copied and uses up no key letter. Anything in `primer`
/// that isn't an ASCII letter is ignored; with no letters at all, `text` comes back as it
/// is.
pub(crate) fn decrypt(text: &str, primer: &str) -> String {
    let primer: Vec<u8> = primer
        .bytes()
        .filter(u8::is_ascii_alphabetic)
        .map(|byte| byte.to_ascii_uppercase() - b'A')
        .collect();
    if primer.is_empty() {
        return text.to_string();
    }
    let mut plain: Vec<u8> = Vec::with_capacity(text.len());
    let mut result = String::with_capacity(text.len());
    for c in text.chars() {
        if !c.is_ascii_alphabetic() {
            result.push(c);
            continue;
        }
        let i = plain.len();
        let key = if i < primer.len() {
            primer[i]
        } else {
            plain[i - primer.len()]
        };
        let base = if c.is_ascii_uppercase() { b'A' } else { b'a' };
        let letter = (c as u8 - base + 26 - key) % 26;
        plain.push(letter);
        result.push(char::from(base + letter));
    }
    result
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

    /// The plaintext of the KEY and QUEENLY vectors, and of the bench's medium inputs.
    const LIGHTHOUSE: &str =
        "Meet me at the old lighthouse after midnight and bring the map, the key and a torch.";

    /// The plaintext of the FORTIFICATION vector, and of the bench's long inputs.
    const CIPHEY: &str = "Ciphey is an automated decoding tool. You give it encrypted or \
        encoded text and it tries to work out what was done to it, without you having to \
        know the key or even the cipher. It searches through many possible decodings, \
        checks each candidate to see whether it looks like English or matches a known \
        pattern such as an email address, and stops when it finds something that reads \
        like plaintext. Most of the time this takes less than a second, which makes it \
        handy for capture the flag challenges, puzzle hunts and for anyone who stumbles \
        across a strange string in a log file.";

    /// The unspaced Dickens passage of the issue's longer example.
    const DICKENS_UNSPACED: &str = "ITWASTHEBESTOFTIMESITWASTHEWORSTOFTIMESITWASTHEAGEOFWISDOMITWASTHEAGEOFFOOLISHNESSITWASTHEEPOCHOFBELIEFITWASTHEEPOCHOFINCREDULITYITWASTHESEASONOFLIGHTITWASTHESEASONOFDARKNESS";

    /// Ciphertext, primer and plaintext of every vector the cracker must solve.
    ///
    /// The ciphertexts were made with a case-preserving autokey that copies everything
    /// but letters, and their letters checked against pycipher 0.5.2
    /// (`Autokey(primer).encipher`, round-tripped with `Autokey(primer).decipher`).
    const VECTORS: &[(&str, &str, &str)] = &[
        (
            "Wicf qi tf xhx hsh ztjsbnvnzs uxxew fmuzqjub guw belox buk fht, fht dlc krb a grrvv.",
            "KEY",
            LIGHTHOUSE,
        ),
        (
            "Cyix zp yf xlx apd ebnlhsrfak hyasl emdsbkyf iqq jxpgg gkf dic, zal oqy pgk e dspcu.",
            "QUEENLY",
            LIGHTHOUSE,
        ),
        (
            "Vihvrw wlj invm depl gy php noxmsi ct vthr agg hkyd vw bbelt mbr kmwblj tswcqs cfcchrs",
            "SECRET",
            "Defend the east wall of the castle at dawn and hold it until the relief column arrives",
        ),
        (
            "Kiqpbg xmi rdla aeld hb tsp qflapg al wlan tqd dblq la iywqe nux zpepiw gztyrp \
             ocluiej, kpzr xtsp ofcv ep tjo dsxw.",
            "HELLO",
            "Defend the east wall of the castle at dawn and hold it until the relief column \
             arrives, then fall back to the keep.",
        ),
        (
            "Kb lhw rpx xekm vj umexg, nm emw lpx sojla sb hzexg, nm emw lpx wgw hm aiyhcr, eb \
             odg fpx wgw hm joupwxmbsda, aa jek lpx apgvo sj qsnpsk, jx hiw ypx apgvo sj \
             xbeysicykkc, ln hil rpx oeslvr gj Lauuh, ne egz mpx oeslvr gj Dsfxbjvs",
            "CIPHEY",
            "It was the best of times, it was the worst of times, it was the age of wisdom, it \
             was the age of foolishness, it was the epoch of belief, it was the epoch of \
             incredulity, it was the season of Light, it was the season of Darkness",
        ),
        (
            // The issue's longer example: no word breaks, so only Medium sensitivity
            // accepts the plaintext
            "KBLHWRPXXEKMVJUMEXGNMEMWLPXSOJLASBHZEXGNMEMWLPXWGWHMAIYHCREBODGFPXWGWHMJOUPWXMBSDAAAJEKLPXAPGVOSJQSNPSKJXHIWYPXAPGVOSJXBEYSICYKKCLNHILRPXOESLVRGJLAUUHNEEGZMPXOESLVRGJDSFXBJVS",
            "CIPHEY",
            DICKENS_UNSPACED,
        ),
        (
            concat!(
                "Hwgamd qu ag iigqupaib lwcbdcgu fohp. Bry iwym vz xbqcwdnkl jv mggbfvb ixbw ",
                "oeh vv humhl xl poen wnm npel poo rfxs nh ea, wbphgxh lsn vioevz ac egmk noe ", // codespell:ignore noe
                "fml uk sfrb pal gstfsi. Mo wrtygjmh aliwnyl mrpf tglzzpfk kqcbbxbyk, kipgnw ",
                "gofp pgffphcdw xo ulg wuhbkek mm zgsoo smdl Ieoetgv yj xidglry l sfvke ",
                "bamvlvf sepv wf pn xfezy sxfyeks, nrp sbzpv zyif at slfwg hgilxuqgl budl jsmhl ",
                "sqxk isabexeal. Xwcx dq tpr mmjx fval hfdlw emew moif t soggyh, ozbjh zaciu wg ",
                "kwula mar mehbnye gkc kzri cwtfcignix, aufbse sfrgy efs znq lrfiax ohb ",
                "vyidbycg ngnvgk t mfslrye ukfafg ag r lbm jaev.",
            ),
            "FORTIFICATION",
            CIPHEY,
        ),
    ];

    /// The bench's `miss` input, which every decoder must reject.
    const BENCH_MISS: &str =
        "T00 l3= ox+#G WKyV pajU6j qxH@ %B4+a 5Pn^ 7p_v1q 9sLvu *+36i R5rL&3 mVJZI iO0 Ut8_m COTV";

    fn athena() -> CheckerTypes {
        CheckerTypes::CheckAthena(Checker::<Athena>::new())
    }

    fn crack(text: &str) -> CrackResult {
        Decoder::<VigenereAutokeyDecoder>::new().crack(text, &athena())
    }

    /// Enciphers `text` with the autokey primer `primer`, keeping case and everything that
    /// isn't an ASCII letter: the inverse of [`decrypt`].
    fn encrypt(text: &str, primer: &str) -> String {
        let key: Vec<u8> = primer
            .bytes()
            .map(|b| b.to_ascii_uppercase() - b'A')
            .collect();
        let plain: Vec<u8> = search_letters_all(text);
        let mut i = 0;
        text.chars()
            .map(|c| {
                if !c.is_ascii_alphabetic() {
                    return c;
                }
                let k = if i < key.len() {
                    key[i]
                } else {
                    plain[i - key.len()]
                };
                i += 1;
                let base = if c.is_ascii_uppercase() { b'A' } else { b'a' };
                char::from(base + (c as u8 - base + k) % 26)
            })
            .collect()
    }

    /// Every ASCII letter of `text` as 0 to 25.
    fn search_letters_all(text: &str) -> Vec<u8> {
        text.bytes()
            .filter(u8::is_ascii_alphabetic)
            .map(|byte| byte.to_ascii_uppercase() - b'A')
            .collect()
    }

    /// The primers the search ranks for `text`, with their fitness, best first.
    fn rank_primers(text: &str) -> Vec<(f32, String)> {
        rank_letters(&search_letters(text))
            .into_iter()
            .map(|candidate| (candidate.fitness, primer_string(&candidate.primer)))
            .collect()
    }

    #[test]
    fn vectors_round_trip() {
        for &(ciphertext, primer, plaintext) in VECTORS {
            assert_eq!(decrypt(ciphertext, primer), plaintext, "{primer}");
            assert_eq!(encrypt(plaintext, primer), ciphertext, "{primer}");
        }
    }

    #[test]
    fn wikipedia_example_decrypts_with_its_primer() {
        // Wikipedia's example, also pycipher's Autokey("QUEENLY")
        assert_eq!(decrypt("QNXEPVYTWTWP", "QUEENLY"), "ATTACKATDAWN");
        assert_eq!(decrypt("qnxepvytwtwp", "queenly"), "attackatdawn");
        assert_eq!(encrypt("ATTACKATDAWN", "QUEENLY"), "QNXEPVYTWTWP");
    }

    #[test]
    fn wikipedia_example_is_too_short_to_crack() {
        // 12 letters, under 2 per primer letter: no statistic can find QUEENLY, and Athena
        // doesn't take ATTACKATDAWN for plaintext anyway
        assert!(crack("QNXEPVYTWTWP").unencrypted_text.is_none());
    }

    #[test]
    fn vectors_are_cracked() {
        for &(ciphertext, primer, plaintext) in VECTORS {
            let result = crack(ciphertext);
            assert!(result.success, "{primer}: {result:?}");
            assert_eq!(result.key.as_deref(), Some(primer));
            assert_eq!(
                result.unencrypted_text.as_deref(),
                Some(&[plaintext.to_string()][..]),
                "{primer}"
            );
        }
    }

    #[test]
    fn right_primer_ranks_first() {
        for &(ciphertext, primer, _) in VECTORS {
            let ranked = rank_primers(ciphertext);
            assert!(ranked.len() <= MAX_CHECKED, "{primer}: {ranked:?}");
            assert_eq!(
                ranked.first().map(|(_, found)| found.as_str()),
                Some(primer),
                "{ranked:?}"
            );
            assert!(ranked.iter().all(|&(fitness, _)| fitness >= CHECK_FITNESS));
        }
    }

    #[test]
    fn unspaced_text_is_checked_at_medium_sensitivity() {
        // The issue's longer example has no word breaks
        let ciphertext = VECTORS[5].0;
        assert!(!ciphertext.contains(' '));
        let result = crack(ciphertext);
        assert!(result.success);
        assert_eq!(result.unencrypted_text.unwrap()[0], DICKENS_UNSPACED);
    }

    #[test]
    fn text_that_is_not_autokey_is_rejected() {
        let inputs = [
            "",
            "😀",
            "hello world",
            "12345!@#$%",
            BENCH_MISS,
            // Plain English and its ROT13
            LIGHTHOUSE,
            "Zrrg zr ng gur byq yvtugubhfr nsgre zvqavtug naq oevat gur znc, gur xrl naq n gbepu.",
            CIPHEY,
            // The bench's Vigenère inputs, keys KEY and LEMON
            "Wicd qc kx rri mvh jskfdlmewc kjrov kshlskfd eln fpsre dlc wen, dlc uiw krb k xmbgf.",
            "Nmbvrj me oa lyfczlxqr qpgarvyk fcbw. Cai ttzq wg proflaxqr bc izqboip hrix mbq tx \
             ffvpw fc jzvw che atog hee rbyi fc ve, auhuzyf mbf lmjvyk fc xysi hup oqm bc ihsa \
             elq qvalqf. Ve wqoenlqg gsvaits qmbl asegvmpq rrnspwarw, ovrnoe snnl ooaompogp xa \
             grp atsgsid wg wsayf wmws Rykxwfs sd anegtsf l ozcjy tmhgpvz ghnl mg ny iyovw \
             eprepwe, oao wfccd atsa tx rwaow eczpxtwar xtog cimrf wmws cweubgpbf. Abdx at gsi \
             fwzp xtwf eewsf wieg gsez o fpgabq, hluqu xewsf tx toaoc rce nebhhci fvr qpmu \
             psexzrykqg, cfdlzr syzhf lrp tbc ezmbyi ivb dxgaowie opcseg n dxdoari ehetrs wa l \
             pau stpq.",
            // The bench's Atbash input
            "Nvvg nv zg gsv low ortsgslfhv zugvi nrwmrtsg zmw yirmt gsv nzk, gsv pvb zmw z glixs.",
            // Beaufort, key KEY
            "Zaiv bh et vgh qbl cdyfvgxkuk nglix bdbzghel mbk knebh sxi cnw, lfk dhg mbk l lyxle.",
            // The bench's Base64 input
            "TWVldCBtZSBhdCB0aGUgb2xkIGxpZ2h0aG91c2UgYWZ0ZXIgbWlkbmlnaHQgYW5kIGJyaW5nIHRoZSBtYXAsIHRoZSBrZXkgYW5kIGEgdG9yY2gu",
            // Random letters
            "qwhxv rtkpl zmnbd fgjsa yceou iwqzx lpkrt vbnmd hgfsj aeyuo",
        ];
        for input in inputs {
            let result = crack(input);
            assert!(!result.success, "{input:?}: {result:?}");
            assert!(result.unencrypted_text.is_none(), "{input:?}: {result:?}");
            assert!(rank_primers(input).is_empty(), "{input:?}");
        }
    }

    #[test]
    fn repeated_letter_is_rejected() {
        // What the hexadecimal decoder makes of rot47 of a CTF challenge's `--_--___...`
        // (encryptctf 2019, "Hard Looks"). With primer ARO it decrypts to periodic text,
        // which the checker took for English at Medium sensitivity.
        let text = "f".repeat(120);
        assert_eq!(&decrypt(&text, "ARO")[..12], "foraroforaro");
        assert!(crack(&text).unencrypted_text.is_none());
    }

    #[test]
    fn checks_before_the_search() {
        // Enough letters, and few characters that aren't letters or whitespace
        assert!(Census::of(LIGHTHOUSE).worth_searching());
        assert!(Census::of(VECTORS[5].0).worth_searching());
        // 19 letters
        assert!(!Census::of("abcdefghij klmnopqrs").worth_searching());
        assert!(Census::of("abcdefghij klmnopqrst").worth_searching());
        // 24 letters and 2 others pass, 3 others don't
        assert!(Census::of("abcdefghijkl, mnopqrstuvwx.").worth_searching());
        assert!(!Census::of("abcdefghijkl, mnopqrstuvwx.!").worth_searching());
        // The bench miss input: 46 letters and 25 others
        let miss = Census::of(BENCH_MISS);
        assert_eq!(
            (
                miss.letters,
                miss.whitespace,
                miss.underscores,
                miss.other,
                miss.pairs,
                miss.lower_upper_pairs
            ),
            (46, 15, 2, 25, 23, 7)
        );
        assert!(!miss.worth_searching());
        // Non-ASCII letters count as other characters
        assert_eq!(Census::of("éÖa ").other, 2);
        // Underscores separate words, like spaces
        assert!(Census::of("abcdefghijkl_mnopqrstuvwx_yz").worth_searching());
        // Base64 of binary digits has no other characters, but changes case inside
        // words: 29 of its 119 letter pairs are lower then upper case
        let base64 =
            "MDEwMDExMDEgMDExMDAxMDEgMDExMDAxMDEgMDExMTAxMDAgMDAxMDAwMDAgMDExMDExMDEgMDExMDAx\
                      MDEgMDAxMDAwMDAgMDExMDAwMDEgMDExMTAxMDAg";
        let census = Census::of(base64);
        assert_eq!((census.other, census.lower_upper_pairs), (0, 29));
        assert!(!census.worth_searching());
        // A few in English are fine
        assert!(
            Census::of("McDonald sold an iPhone to MacGregor for his eBay shop").worth_searching()
        );
        // A run of one letter, which decrypts to periodic text such as `foraroforaro`, and
        // the two letters of Bacon's cipher have too few different letters
        assert!(!Census::of(&"f".repeat(120)).worth_searching());
        assert!(!Census::of(&"AABBA BABAA ".repeat(10)).worth_searching());
        assert_eq!(Census::of("abcdefgh abcdefgh abcd").seen.count_ones(), 8);
        assert!(Census::of("abcdefgh abcdefgh abcd").worth_searching());
        assert!(!Census::of("abcdefga abcdefga abcd").worth_searching());
    }

    #[test]
    fn non_ascii_letters_are_kept_and_use_no_key_letter() {
        let plaintext = "Meet me at the old lighthouse café after midnight and bring the map, \
            the key and a torch.";
        let ciphertext = encrypt(plaintext, "KEY");
        assert!(ciphertext.contains("é "));
        assert_eq!(decrypt(&ciphertext, "KEY"), plaintext);
        // Without the é the other letters decrypt the same
        assert_eq!(
            decrypt(&ciphertext.replace('é', ""), "KEY"),
            plaintext.replace('é', "")
        );
        // Other non-ASCII letters are copied too
        assert_eq!(
            decrypt(&encrypt("Ödön Öz, über", "KEY"), "KEY"),
            "Ödön Öz, über"
        );
        let result = crack(&ciphertext);
        assert!(result.success, "{result:?}");
        assert_eq!(result.unencrypted_text.unwrap()[0], plaintext);
        assert_eq!(result.key.as_deref(), Some("KEY"));
    }

    #[test]
    fn hex_decoded_latin1_input_does_not_panic() {
        // What the hexadecimal decoder makes of `275626d657e6f556679666`, see #908
        let result = crack("'V&ÖWæõVg\u{96}f");
        assert!(result.unencrypted_text.is_none());
        // Letters VWVGF, which pycipher's Autokey("KEY") deciphers to LSXVN
        assert_eq!(decrypt("'V&ÖWæõVg\u{96}f", "KEY"), "'L&ÖSæõXv\u{96}n");
    }

    #[test]
    fn case_and_punctuation_are_kept() {
        assert_eq!(
            decrypt("Rijvs, Uyvjn!", "key"),
            decrypt("Rijvs, Uyvjn!", "KEY")
        );
        let text = "Hello, World! 123";
        // pycipher's Autokey("B") enciphers HELLOWORLD to ILPWZKKFCO
        assert_eq!(encrypt(text, "B"), "Ilpwz, Kkfco! 123");
        assert_eq!(decrypt("Ilpwz, Kkfco! 123", "B"), text);
    }

    #[test]
    fn primer_without_letters_leaves_the_text_alone() {
        assert_eq!(decrypt("Hello", ""), "Hello");
        assert_eq!(decrypt("Hello", "123"), "Hello");
    }

    #[test]
    fn one_letter_primer_is_searched() {
        let plaintext = "There is nothing like dancing after all, and the rain continued \
            the whole evening without intermission";
        let ciphertext = encrypt(plaintext, "Q");
        let result = crack(&ciphertext);
        assert!(result.success, "{result:?}");
        assert_eq!(result.key.as_deref(), Some("Q"));
        assert_eq!(result.unencrypted_text.unwrap()[0], plaintext);
    }

    #[test]
    fn long_text_is_searched_on_its_first_letters() {
        // Far more letters than SEARCH_LETTERS: the primer is found on the first ones and
        // the whole text decrypted
        let plaintext = [CIPHEY; 4].join(" ");
        let ciphertext = encrypt(&plaintext, "LANTERN");
        assert!(search_letters_all(&ciphertext).len() > 3 * SEARCH_LETTERS);
        let result = crack(&ciphertext);
        assert!(result.success, "{result:?}");
        assert_eq!(result.key.as_deref(), Some("LANTERN"));
        assert_eq!(result.unencrypted_text.unwrap()[0], plaintext);
    }

    #[test]
    fn best_guess_is_returned_when_the_checker_accepts_nothing() {
        // LemmeKnow alone doesn't take English for plaintext, so the best decryption comes
        // back unconfirmed, for the search to decode further
        let checker = CheckerTypes::CheckLemmeKnow(Checker::<LemmeKnow>::new());
        let result = Decoder::<VigenereAutokeyDecoder>::new().crack(VECTORS[0].0, &checker);
        assert!(!result.success);
        assert_eq!(result.unencrypted_text, Some(vec![LIGHTHOUSE.to_string()]));
        assert_eq!(result.key.as_deref(), Some("KEY"));
    }

    #[test]
    fn refining_matches_scoring_the_whole_text() {
        // The windows `refine` rescores give the same totals as scoring everything again,
        // for primers short enough that the windows of one class overlap
        let quadgrams: &[f32] = &QUADGRAMS;
        let letters = search_letters(VECTORS[4].0);
        for length in 1..=8 {
            let mut primer = solve_classes(&letters, length);
            let mut plain = vec![0; letters.len()];
            decrypt_letters(&letters, &primer, &mut plain);
            let before = total_score(&plain, quadgrams);
            let after = refine(&mut primer, &mut plain, quadgrams);
            let mut expected = vec![0; letters.len()];
            decrypt_letters(&letters, &primer, &mut expected);
            assert_eq!(plain, expected, "length {length}");
            assert_eq!(after, total_score(&expected, quadgrams), "length {length}");
            // Only better scores change a letter (up to rounding in the sums)
            assert!(after >= before - 1e-3, "length {length}");
        }
    }

    #[test]
    fn refining_scores_match_scoring_every_change() {
        // For every primer length and letter, the scores `refine` picks from rank the 26
        // letters as decrypting with each of them and scoring the whole text does
        let quadgrams: &[f32] = &QUADGRAMS;
        let letters = search_letters(VECTORS[3].0);
        let n = letters.len();
        for length in 1..=MAX_PRIMER {
            let primer = solve_classes(&letters, length);
            let mut plain = vec![0; n];
            decrypt_letters(&letters, &primer, &mut plain);
            let mut overlapping = Overlapping::new(&plain, length);
            for j in 0..length {
                let scores = if length < 4 {
                    overlapping.shift_scores(&plain, j, quadgrams)
                } else {
                    shift_scores(&plain, j, length, quadgrams)
                };
                assert_eq!(overlapping.trial, plain);
                for delta in 0..26u8 {
                    let mut changed = primer.clone();
                    changed[j] = (changed[j] + delta) % 26;
                    let mut expected = vec![0; n];
                    decrypt_letters(&letters, &changed, &mut expected);
                    // The scores leave out the quadgrams that don't change, the same for
                    // every letter
                    let difference =
                        total_score(&expected, quadgrams) - total_score(&plain, quadgrams);
                    let got = scores[usize::from(delta)] - scores[0];
                    assert!(
                        (got - difference).abs() < 1e-2,
                        "length {length}, letter {j}, delta {delta}: {got} vs {difference}"
                    );
                }
            }
        }
    }

    #[test]
    fn class_solve_matches_scoring_each_letter() {
        // The table-driven class solve picks the letter that scoring each class's
        // decryptions letter by letter does
        let unigrams = ENGLISH_FREQS.map(|freq| freq.log10() as f32);
        for &(ciphertext, _, _) in VECTORS {
            let letters = search_letters(ciphertext);
            for length in 1..=MAX_PRIMER.min(letters.len() / 4) {
                let expected: Vec<u8> = (0..length)
                    .map(|j| {
                        let mut class = Vec::new();
                        let mut previous = 0;
                        for &letter in letters[j..].iter().step_by(length) {
                            previous = (letter + 26 - previous) % 26;
                            class.push(previous);
                        }
                        let score = |k: u8| -> f32 {
                            class
                                .iter()
                                .enumerate()
                                .map(|(t, &s)| unigrams[usize::from(shifted(s, t, k))])
                                .sum()
                        };
                        (0..26).fold(0, |best, k| if score(k) > score(best) { k } else { best })
                    })
                    .collect();
                assert_eq!(solve_classes(&letters, length), expected, "length {length}");
            }
        }
    }

    #[test]
    fn class_solve_finds_a_long_texts_primer() {
        // With about 35 letters per primer letter the letter frequencies alone find it
        let letters = search_letters(VECTORS[6].0);
        assert_eq!(primer_string(&solve_classes(&letters, 13)), "FORTIFICATION");
    }

    #[test]
    fn quadgram_table_is_log_probabilities() {
        let table: &[f32] = &QUADGRAMS;
        assert_eq!(table.len(), QUADGRAM_COUNT);
        let the = table[quadgram_index("THAT").unwrap()];
        let rare = table[quadgram_index("QXZJ").unwrap()];
        assert!(the > -3.0 && the < -2.0, "{the}");
        assert!(rare < -6.0, "{rare}");
        assert_eq!(quadgram_index("ABC"), None);
        assert_eq!(quadgram_index("abcd"), None);
        assert_eq!(quadgram_at(&[25, 25, 25, 25]), QUADGRAM_COUNT - 1);
    }

    #[test]
    fn ctf_flag_primer_is_found() {
        // UTCTF 2025 "Autokey Cipher": underscores separate the words, and with the
        // braces there are 2 other characters for 50 letters
        let ciphertext = "lpqwma{rws_ywpqaauad_rrqfcfkq_wuey_ifwo_xlkvxawjh_pkbgrzf}";
        assert!(Census::of(ciphertext).worth_searching());
        let ranked = rank_primers(ciphertext);
        assert_eq!(ranked[0].1, "RWLLMUVP", "{ranked:?}");
        assert_eq!(
            decrypt(ciphertext, "RWLLMUVP"),
            "utflag{why_frequency_analysis_when_know_beginning_letters}"
        );
    }

    #[test]
    fn decoder_describes_itself() {
        let decoder = Decoder::<VigenereAutokeyDecoder>::new();
        assert_eq!(decoder.get_name(), "Vigenere Autokey");
        assert_eq!(decoder.get_popularity(), 0.3);
        assert!(!decoder.get_tags().contains(&"decoder"));
        assert!(!decoder.get_tags().contains(&"reciprocal"));
        assert_eq!(
            decoder.get_link(),
            "https://en.wikipedia.org/wiki/Autokey_cipher"
        );
    }

    #[test]
    fn decoder_is_registered_under_its_own_name() {
        use crate::filtration_system::get_decoder_by_name;
        // The names share a prefix, and each finds exactly its own decoder
        for name in ["Vigenere Autokey", "Vigenere"] {
            let found = get_decoder_by_name(name);
            assert_eq!(found.components.len(), 1, "{name}");
            assert_eq!(found.components[0].get_name(), name);
        }
        assert!(crate::decoders::DECODER_MAP.contains_key("Vigenere Autokey"));
    }
}
