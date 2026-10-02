//! Cracks monoalphabetic substitution ciphers: every letter is replaced by another,
//! using any permutation of the alphabet as the key. Aristocrats keep the word breaks
//! and punctuation, Patristocrats drop them (or write the letters in groups of five).
//! Caesar, Atbash and Affine are special cases, which their own decoders crack faster.
//!
//! There are 26! ≈ 4·10²⁶ keys, too many to try, so the key is found with simulated
//! annealing over swaps of two key letters, scoring each decryption by how often its
//! quadgrams (runs of four letters) occur in English. See
//! <http://practicalcryptography.com/cryptanalysis/stochastic-searching/cryptanalysis-simple-substitution-cipher/>.
//! Quadgram statistics can't tell rare letters apart in a short text, so for an
//! Aristocrat the key is then adjusted to turn more of its words into dictionary words.
//! The quadgram counts and the dictionary are in `src/storage/ngrams/`, built by
//! `gen_quadgrams.py` there from public-domain Project Gutenberg books.
//!
//! The search takes milliseconds, so cheap checks run first and reject, in microseconds,
//! text that can't be a substitution of English:
//! 1. At least 60 ASCII letters, and nothing but letters, whitespace and common
//!    punctuation. This rules out Base64, hexadecimal and the other encodings.
//! 2. An index of coincidence like English's. A substitution doesn't change it, while
//!    Vigenère and random letters have a much lower one.
//! 3. Letter frequencies that aren't English's already, as they are in plain English
//!    and in transpositions of it (reversed text, rail fence).
//! 4. The text doesn't read as English already (by its quadgram score), and no Caesar,
//!    Atbash or Affine key decrypts it: those decoders are cheaper.
//!
//! Every substitution of one plaintext has the same letter pattern, so results are cached
//! by pattern. The 25 Caesar shifts of a ciphertext, which the A* search tries next,
//! don't each start a new search.

use super::crack_results::CrackResult;
use super::interface::{Crack, Decoder};
use crate::checkers::checker_result::CheckResult;
use crate::checkers::CheckerTypes;
use crate::storage::ENGLISH_FREQS;
use gibberish_or_not::Sensitivity;
use log::{debug, trace};
use once_cell::sync::Lazy;
use std::collections::{HashMap, HashSet};
use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

/// Number of possible quadgrams, 26⁴.
const QUADGRAM_COUNT: usize = 26 * 26 * 26 * 26;

/// Fewer letters than this and a wrong key can score better than the right one.
const MIN_LETTERS: usize = 60;

/// Minimum index of coincidence. A substitution doesn't change it. English has about
/// 0.066, but short texts vary: 1.5% of 60 to 79 letter paragraphs of English novels are
/// below 0.050 (and 10.6% below 0.055). Vigenère averages 0.044 and random letters 0.038.
const MIN_IOC: f64 = 0.050;

/// The lowest mean `ln P` per pair of consecutive letters that the best Caesar, Atbash or
/// Affine key may give, from the letter-pair table the Affine decoder uses, before a text
/// is left to those decoders without loading the quadgram table. Caesar, Atbash and Affine
/// encryptions of 3,585 windows of 60 to 250 letters from Project Gutenberg books and
/// Ciphey's docs scored -5.50 (median) under their own key; random substitutions of the same
/// windows never scored above -5.77 under any of the 312 keys. Texts in between go on to
/// the quadgram check, which decides as before.
const AFFINE_PAIR_LOG_PROB: f32 = -5.6;

/// Minimum [`frequency_gap`]. Below it the letters already have English frequencies.
/// Plain English paragraphs of 60 or more letters stay under 0.15 (99% under 0.11), and
/// substitutions of them start at 0.13 (99% above 0.2).
const MIN_FREQUENCY_GAP: f64 = 0.1;

/// Fitness, the average log10 probability of a text's quadgrams, at or above which it
/// reads as English. Correct decryptions of paragraphs from English novels score -3.8
/// to -4.7, Vigenère -5.6 and random letters -6.0.
const ENGLISH_FITNESS: f64 = -4.8;

/// Fitness at or above which a decryption is shown to the checker. If the first two
/// annealing runs don't reach it, the rest don't either.
const CHECK_FITNESS: f64 = -4.7;

/// The checks for text that reads as English as it is or after a Caesar, Atbash or
/// Affine key score this many quadgrams of a key first...
const PREFIX_QUADGRAMS: usize = 48;

/// ...and skip the rest of the text for keys that average below this on them. Correct
/// decryptions of 2,500 paragraphs of English novels averaged at least -4.87 on their
/// first 48 quadgrams, and each of 77,625 wrong Affine keys averaged below -5.4.
const PREFIX_FITNESS: f64 = -5.5;

/// If the first annealing run can't reach this fitness the text isn't a substitution of
/// English, and the other runs won't do better.
const GIVE_UP_FITNESS: f64 = -5.0;

/// Most annealing runs. One run finds the key about 75% of the time for 120 or more
/// letters, and less often for fewer. The runs stop early once the best key so far has
/// been found twice.
const RUNS: usize = 8;

/// Most decryptions shown to the checker, best first.
const MAX_CHECKED: usize = 3;

/// Swaps tried per annealing run.
const SWAPS_PER_RUN: u32 = 30_000;

/// Starting temperature of each run, in log10 probability, for a text of
/// [`REFERENCE_QUADGRAMS`] quadgrams. It is scaled with the length of the text, since a
/// swap changes the score of a longer text by more, and falls linearly to 0.
const START_TEMPERATURE: f64 = 10.0;

/// See [`START_TEMPERATURE`].
const REFERENCE_QUADGRAMS: f64 = 171.0;

/// The annealing only scores this many letters: longer texts don't need more to find the
/// key, and every swap re-scores the quadgrams with either letter in them.
const SEARCH_LETTERS: usize = 250;

/// The key is then polished on up to this many letters, which places the letters that
/// only occur later in a long text.
const POLISH_LETTERS: usize = 4_000;

/// Weight of a letter in a dictionary word, against log10 quadgram probabilities, when
/// polishing the key of an Aristocrat.
const WORD_WEIGHT: f64 = 1.0;

/// A decryption without word breaks is only shown to the checker if dictionary words
/// can cover this share of its letters. The checker can't judge it otherwise: it reads
/// the whole text as one word.
const MIN_COVERAGE_WITHOUT_BREAKS: f64 = 0.9;

/// A decryption with word breaks is only shown to the checker if this share of the
/// letters of its words are in dictionary words. Paragraphs of English novels have at
/// least 0.38 (median 0.92), the modern test texts 0.64. The checker accepted two short
/// decryptions of Vigenère ciphertexts, with 0.10 and 0.22.
const MIN_COVERAGE_WITH_BREAKS: f64 = 0.3;

/// The cache is cleared when it grows past this many patterns.
const CACHE_LIMIT: usize = 1024;

/// How long a thread waits for another thread searching the same pattern before giving up.
const CACHE_WAIT: Duration = Duration::from_secs(10);

/// Marks a letter that doesn't occur in a key or label table.
const NONE: u8 = u8::MAX;

/// log10 probability of every quadgram, indexed by [`quadgram_index`].
static QUADGRAMS: Lazy<Box<[f32]>> =
    Lazy::new(|| parse_quadgrams(include_str!("../storage/ngrams/english_quadgrams.txt")));

/// Upper-case English words.
static DICTIONARY: Lazy<Dictionary> =
    Lazy::new(|| Dictionary::parse(include_str!("../storage/ngrams/english_words.txt")));

/// Search results of every thread, by letter pattern.
static CACHE: Lazy<SearchCache> = Lazy::new(SearchCache::new);

/// The monoalphabetic substitution cracker. Call:
/// `let decoder = Decoder::<MonoalphabeticSubstitutionDecoder>::new()` to create one,
/// and `decoder.crack(text, &checker)` to crack `text`.
/// ```
/// use ciphey::decoders::monoalphabetic_substitution_decoder::MonoalphabeticSubstitutionDecoder;
/// use ciphey::decoders::interface::{Crack, Decoder};
/// use ciphey::checkers::{athena::Athena, CheckerTypes, checker_type::{Check, Checker}};
///
/// let decoder = Decoder::<MonoalphabeticSubstitutionDecoder>::new();
/// let checker = CheckerTypes::CheckAthena(Checker::<Athena>::new());
///
/// // Key PHQGIUMEAYLNOFDXJKRCVSTZWB: plaintext A is written P, B is written H, ...
/// let result = decoder.crack(
///     "Qaxeiw ar pf pvcdopcaq giqkwxcadf cddn. Wdv masi ac ifqkwxcig cizc pfg ac ckair cd \
///      tdkl dvc tepc tpr gdfi cd ac, ceif redtr wdv cei xnpafcizc. Ac lfdtr opfw ifqdgafmr \
///      pfg qnprraqpn qaxeikr, pfg ac liixr nipkfafm fit dfir.",
///     &checker,
/// );
/// assert!(result.success);
/// assert_eq!(
///     result.unencrypted_text.unwrap()[0],
///     "Ciphey is an automatic decryption tool. You give it encrypted text and it tries to \
///      work out what was done to it, then shows you the plaintext. It knows many encodings \
///      and classical ciphers, and it keeps learning new ones."
/// );
/// // The cipher letter of each plaintext letter, `?` for letters the plaintext doesn't have
/// assert_eq!(result.key.unwrap(), "P?QGI?MEA?LNOFDX?KRCVSTZW?");
/// ```
pub struct MonoalphabeticSubstitutionDecoder;

impl Crack for Decoder<MonoalphabeticSubstitutionDecoder> {
    fn new() -> Decoder<MonoalphabeticSubstitutionDecoder> {
        Decoder {
            name: "Monoalphabetic Substitution",
            description: "A simple substitution cipher replaces every letter with another letter, using any permutation of the alphabet as the key, as in cryptograms, keyword ciphers, Aristocrats and Patristocrats. Ciphey finds the key with simulated annealing scored by English quadgram frequencies. Uses Low sensitivity for gibberish detection when the text has word breaks, once 30% of its letters are in dictionary words. Without word breaks, the decryption is split into dictionary words and only checked, at High sensitivity, if they cover 90% of it.",
            link: "https://en.wikipedia.org/wiki/Substitution_cipher",
            tags: vec!["substitution", "monoalphabetic", "classic", "cryptogram"],
            popularity: 0.4,
            phantom: std::marker::PhantomData,
        }
    }

    /// Searches for the key. On success the plaintext is the only element of
    /// `unencrypted_text`, and `key` holds the cipher letter of each plaintext letter A
    /// to Z, with `?` for letters the plaintext doesn't have. When the checker doesn't
    /// accept anything but the best decryption still reads like English, that decryption
    /// is returned unconfirmed, so the search can keep decoding it.
    ///
    /// The plaintext keeps the case, punctuation and other characters of `text`, except
    /// that text without word breaks loses its whitespace, such as the spaces between
    /// groups of five letters.
    fn crack(&self, text: &str, checker: &CheckerTypes) -> CrackResult {
        trace!("Trying monoalphabetic substitution with text {:?}", text);
        let mut results = CrackResult::new(self, text.to_string());
        let mut confirm = |candidate: &str, layout: Layout| check(checker, candidate, layout);

        match crack_text(text, Some(&CACHE), &mut Stats::default(), &mut confirm) {
            Outcome::Confirmed {
                plaintext,
                key,
                check,
            } => {
                debug!("Monoalphabetic substitution found key {key}");
                results.unencrypted_text = Some(vec![plaintext]);
                results.update_checker(&check);
                results.key = Some(key);
            }
            Outcome::Unconfirmed { plaintext, key } => {
                debug!("Monoalphabetic substitution best guess, key {key}: {plaintext}");
                results.unencrypted_text = Some(vec![plaintext]);
                results.key = Some(key);
            }
            Outcome::Failed(reason) => {
                trace!("Monoalphabetic substitution gave up: {reason:?}");
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

/// Asks `checker` whether `candidate`, a decryption laid out as `layout`, is plaintext.
fn check(checker: &CheckerTypes, candidate: &str, layout: Layout) -> Option<CheckResult> {
    let sensitivity = match layout {
        Layout::Words => Sensitivity::Low,
        // Only asked once dictionary words cover most of the text
        Layout::Unspaced => Sensitivity::High,
    };
    let result = checker.with_sensitivity(sensitivity).check(candidate);
    result.is_identified.then_some(result)
}

/// What [`crack_text`] found. `T` is what the checker returns.
enum Outcome<T> {
    /// The checker accepted this decryption.
    Confirmed {
        /// The decryption, laid out as [`Ciphertext::decrypt`] describes.
        plaintext: String,
        /// The cipher letter of each plaintext letter A to Z, `?` for missing ones.
        key: String,
        /// What the checker said.
        check: T,
    },
    /// The checker didn't accept anything, but this decryption reads like English.
    Unconfirmed {
        /// The decryption, laid out as [`Ciphertext::decrypt`] describes.
        plaintext: String,
        /// The cipher letter of each plaintext letter A to Z, `?` for missing ones.
        key: String,
    },
    /// Nothing that reads like English.
    Failed(Reason),
}

/// Why [`crack_text`] failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reason {
    /// A character no cryptogram has: a digit, `+`, `/`, `=`, an emoji...
    Alphabet,
    /// Fewer than [`MIN_LETTERS`] letters.
    TooShort,
    /// The index of coincidence is too low for a substitution of English.
    Coincidence,
    /// The letters already have English frequencies, so they weren't substituted.
    EnglishFrequencies,
    /// It reads as English already.
    AlreadyEnglish,
    /// A Caesar, Atbash or Affine key decrypts it, and those decoders are cheaper.
    Affine,
    /// An earlier search of the same letter pattern found nothing the checker accepted,
    /// or another thread is still searching it.
    Cached,
    /// The search found nothing that reads like English.
    NotFound,
    /// Fewer different letters than English uses (see [`min_distinct_letters`]).
    FewDistinctLetters,
}

/// How a decryption is checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Layout {
    /// Words are separated by spaces, as in an Aristocrat. Checked at Low sensitivity,
    /// like the other classical ciphers, once enough of the words are dictionary words.
    Words,
    /// No word breaks: a Patristocrat, maybe in groups of five letters. The whitespace is
    /// removed, and the checker only sees decryptions that dictionary words mostly
    /// cover, at High sensitivity.
    Unspaced,
}

/// Counters, so the tests can see how much work was done.
#[derive(Debug, Default)]
struct Stats {
    /// Whole-text quadgram scores, by the checks before the search.
    scored: u64,
    /// Key swaps scored by the annealing and polishing.
    swaps: u64,
    /// Decryptions shown to the checker.
    checked: u64,
    /// The cache answered, or another thread was still searching the same pattern.
    cache_hit: bool,
}

/// Cracks `text`. Each decryption that scores well enough is passed to `confirm`, until
/// it returns `Some`. `cache` is `None` in tests that need a fresh search.
fn crack_text<T>(
    text: &str,
    cache: Option<&SearchCache>,
    stats: &mut Stats,
    confirm: &mut dyn FnMut(&str, Layout) -> Option<T>,
) -> Outcome<T> {
    let ciphertext = match Ciphertext::parse(text) {
        Ok(ciphertext) => ciphertext,
        Err(reason) => return Outcome::Failed(reason),
    };

    let searching = match cache.map(|cache| cache.lookup(ciphertext.pattern)) {
        None => None,
        Some(Lookup::Miss(searching)) => Some(searching),
        Some(Lookup::Hit(cached)) => {
            stats.cache_hit = true;
            return from_cache(text, &ciphertext, cached, cache, stats, confirm);
        }
        Some(Lookup::Busy) => {
            stats.cache_hit = true;
            return Outcome::Failed(Reason::Cached);
        }
    };

    match search(text, &ciphertext, stats, confirm) {
        Ok(Found {
            key,
            check: Some(check),
        }) => {
            if let Some(searching) = searching {
                searching.finish(Cached::Solved(ciphertext.labels_to_plain(&key)));
            }
            Outcome::Confirmed {
                plaintext: ciphertext.decrypt(text, &key),
                key: key_string(&key, &ciphertext.present),
                check,
            }
        }
        Ok(Found { key, check: None }) => {
            // Returned once, as a candidate for the A* search to decode further. Other
            // substitutions of it would only return the same plaintext again.
            if let Some(searching) = searching {
                searching.finish(Cached::Unsolved);
            }
            Outcome::Unconfirmed {
                plaintext: ciphertext.decrypt(text, &key),
                key: key_string(&key, &ciphertext.present),
            }
        }
        Err(reason) => {
            // The quadgram checks in `search` reject plain English but not its
            // substitutions, though both have the same pattern, so only a search that
            // ran is worth caching.
            if let (Reason::NotFound, Some(searching)) = (reason, searching) {
                searching.finish(Cached::Unsolved);
            }
            Outcome::Failed(reason)
        }
    }
}

/// [`crack_text`] for a pattern that was searched before.
fn from_cache<T>(
    text: &str,
    ciphertext: &Ciphertext,
    cached: Cached,
    cache: Option<&SearchCache>,
    stats: &mut Stats,
    confirm: &mut dyn FnMut(&str, Layout) -> Option<T>,
) -> Outcome<T> {
    let Cached::Solved(plain_of_label) = cached else {
        return Outcome::Failed(Reason::Cached);
    };
    let Some(key) = ciphertext.key_from_labels(&plain_of_label) else {
        // Only a hash collision gets here
        return Outcome::Failed(Reason::Cached);
    };
    if is_affine(&key, &ciphertext.present) {
        // Plain English, or a Caesar, Atbash or Affine ciphertext
        return Outcome::Failed(Reason::Affine);
    }
    let plaintext = ciphertext.decrypt(text, &key);
    stats.checked += 1;
    match confirm(&plaintext, ciphertext.layout) {
        Some(check) => Outcome::Confirmed {
            key: key_string(&key, &ciphertext.present),
            plaintext,
            check,
        },
        None => {
            // The checker said yes before, so a human must have said no since. Don't
            // ask them again.
            if let Some(cache) = cache {
                cache.store(ciphertext.pattern, Cached::Unsolved);
            }
            Outcome::Failed(Reason::Cached)
        }
    }
}

/// The best key [`search`] found.
struct Found<T> {
    /// Plaintext letter of each cipher letter.
    key: [u8; 26],
    /// What the checker said, if it accepted the decryption.
    check: Option<T>,
}

/// Runs the quadgram checks and then the annealing runs on a text that passed the
/// checks in [`Ciphertext::parse`].
fn search<T>(
    text: &str,
    ciphertext: &Ciphertext,
    stats: &mut Stats,
    confirm: &mut dyn FnMut(&str, Layout) -> Option<T>,
) -> Result<Found<T>, Reason> {
    let letters = &ciphertext.letters;
    if let Some(reason) = affine_by_letter_pairs(&letters[..letters.len().min(SEARCH_LETTERS)]) {
        return Err(reason);
    }
    let scorer = Scorer::new(&letters[..letters.len().min(SEARCH_LETTERS)]);

    stats.scored += 1;
    if scorer.reads_as_english(&IDENTITY) {
        return Err(Reason::AlreadyEnglish);
    }
    for key in affine_keys().skip(1) {
        stats.scored += 1;
        if scorer.reads_as_english(&key) {
            return Err(Reason::Affine);
        }
    }

    // Long texts: the keys found on the first SEARCH_LETTERS letters are polished on more
    // of the text, which places the letters that only occur later.
    let whole_text = (letters.len() > SEARCH_LETTERS)
        .then(|| Scorer::new(&letters[..letters.len().min(POLISH_LETTERS)]));
    let whole_text = whole_text.as_ref().unwrap_or(&scorer);
    let words = (ciphertext.layout == Layout::Words).then(|| Words::new(text));
    // What the polishing maximises, so the candidates are compared on it
    let rank = |key: &[u8; 26]| {
        let word_letters = words
            .as_ref()
            .map_or(0, |words| words.dictionary_letters(key));
        whole_text.score(key) + WORD_WEIGHT * word_letters as f64
    };

    let start = frequency_key(scorer.letters);
    let temperature = start_temperature(scorer.window_count());
    let mut rng = Rng::new(ciphertext.pattern);
    let mut candidates: Vec<Candidate> = Vec::new();
    let mut best_rejected: Option<([u8; 26], f64)> = None;

    for run in 0..RUNS {
        let key = anneal(&scorer, start, temperature, &mut rng, stats);
        let key = polish(&scorer, key, stats);
        let fitness = scorer.fitness(&key);
        trace!("Annealing run {run}: fitness {fitness:.3}");
        if run == 0 && fitness < GIVE_UP_FITNESS {
            return Err(Reason::NotFound);
        }
        let key = if letters.len() > SEARCH_LETTERS {
            polish(whole_text, key, stats)
        } else {
            key
        };
        if fitness < CHECK_FITNESS {
            if best_rejected.is_none_or(|(_, best)| fitness > best) {
                best_rejected = Some((key, fitness));
            }
            if run == 1 && candidates.is_empty() {
                break;
            }
            continue;
        }

        let key = match &words {
            Some(words) => polish_words(whole_text, words, key, stats),
            None => key,
        };
        let used = used_part(&key, &ciphertext.present);
        match candidates
            .iter_mut()
            .find(|candidate| candidate.used == used)
        {
            Some(candidate) => candidate.found += 1,
            None => candidates.push(Candidate {
                key,
                used,
                rank: rank(&key),
                found: 1,
            }),
        }
        candidates.sort_by(|a, b| b.rank.total_cmp(&a.rank));
        // A wrong key can read well enough for the checker, so stop once the best key
        // has been found twice rather than at the first one
        if candidates[0].found >= 2 {
            break;
        }
    }

    for candidate in candidates.iter().take(MAX_CHECKED) {
        let plaintext = ciphertext.decrypt(text, &candidate.key);
        let reads_as_words = match &words {
            Some(words) => words.coverage(&candidate.key) >= MIN_COVERAGE_WITH_BREAKS,
            None => word_coverage(&plaintext) >= MIN_COVERAGE_WITHOUT_BREAKS,
        };
        if !reads_as_words {
            continue;
        }
        stats.checked += 1;
        if let Some(check) = confirm(&plaintext, ciphertext.layout) {
            return Ok(Found {
                key: candidate.key,
                check: Some(check),
            });
        }
    }

    match (candidates.first(), best_rejected) {
        (Some(candidate), _) => Ok(Found {
            key: candidate.key,
            check: None,
        }),
        (None, Some((key, fitness))) if fitness >= ENGLISH_FITNESS => {
            Ok(Found { key, check: None })
        }
        _ => Err(Reason::NotFound),
    }
}

/// A key that scored well enough to show the checker.
struct Candidate {
    /// Plaintext letter of each cipher letter.
    key: [u8; 26],
    /// `key` without the letters that don't occur.
    used: [u8; 26],
    /// Quadgram score plus [`WORD_WEIGHT`] for each letter in a dictionary word.
    rank: f64,
    /// Number of annealing runs that ended on this key.
    found: u32,
}

/// The input, reduced to what the search needs.
struct Ciphertext {
    /// The ASCII letters, upper-cased, as 0 to 25.
    letters: Vec<u8>,
    /// Which letters occur.
    present: [bool; 26],
    /// Number of each letter in order of first appearance, or [`NONE`].
    labels: [u8; 26],
    /// Hash of the text with each letter replaced by its label. It is the same for every
    /// substitution of one plaintext.
    pattern: u64,
    /// How decryptions are checked.
    layout: Layout,
}

impl Ciphertext {
    /// Runs the checks that don't need the quadgrams on `text` and splits out its letters.
    fn parse(text: &str) -> Result<Ciphertext, Reason> {
        if text.len() < MIN_LETTERS {
            return Err(Reason::TooShort);
        }
        let mut letters = Vec::with_capacity(text.len());
        let mut labels = [NONE; 26];
        let mut distinct = 0;
        let mut pattern = Fnv::new();
        for c in text.chars() {
            if c.is_ascii_alphabetic() {
                let letter = c.to_ascii_uppercase() as u8 - b'A';
                let label = &mut labels[usize::from(letter)];
                if *label == NONE {
                    *label = distinct;
                    distinct += 1;
                }
                letters.push(letter);
                pattern.write(u32::from(*label));
            } else if is_cryptogram_symbol(c) {
                // Above every label, so a letter and a symbol never hash the same
                pattern.write(0x100 + u32::from(c));
            } else {
                return Err(Reason::Alphabet);
            }
        }
        if letters.len() < MIN_LETTERS {
            return Err(Reason::TooShort);
        }
        if usize::from(distinct) < min_distinct_letters(letters.len()) {
            return Err(Reason::FewDistinctLetters);
        }

        let mut counts = [0usize; 26];
        for &letter in &letters {
            counts[usize::from(letter)] += 1;
        }
        if index_of_coincidence(&counts, letters.len()) < MIN_IOC {
            return Err(Reason::Coincidence);
        }
        if frequency_gap(&counts, letters.len()) < MIN_FREQUENCY_GAP {
            return Err(Reason::EnglishFrequencies);
        }

        Ok(Ciphertext {
            present: counts.map(|count| count > 0),
            letters,
            labels,
            pattern: pattern.finish(),
            layout: Layout::of(text),
        })
    }

    /// Decrypts `text`, this ciphertext, with `key`. Case and everything that isn't an
    /// ASCII letter are kept, except that text without word breaks loses its whitespace.
    fn decrypt(&self, text: &str, key: &[u8; 26]) -> String {
        let plaintext = decrypt(text, key);
        match self.layout {
            Layout::Words => plaintext,
            Layout::Unspaced => plaintext.split_whitespace().collect(),
        }
    }

    /// The plaintext letter of each label under `key`, for the cache.
    fn labels_to_plain(&self, key: &[u8; 26]) -> [u8; 26] {
        let mut plain_of_label = [NONE; 26];
        for (letter, &label) in self.labels.iter().enumerate() {
            if label != NONE {
                plain_of_label[usize::from(label)] = key[letter];
            }
        }
        plain_of_label
    }

    /// The key that decrypts this text to the plaintext a cache entry was made from,
    /// with [`NONE`] for letters that don't occur. `None` if the entry doesn't fit,
    /// which only a hash collision can cause.
    fn key_from_labels(&self, plain_of_label: &[u8; 26]) -> Option<[u8; 26]> {
        let mut key = [NONE; 26];
        let mut used = [false; 26];
        for (letter, &label) in self.labels.iter().enumerate() {
            if label == NONE {
                continue;
            }
            let plain = plain_of_label[usize::from(label)];
            if plain >= 26 || std::mem::replace(&mut used[usize::from(plain)], true) {
                return None;
            }
            key[letter] = plain;
        }
        Some(key)
    }
}

impl Layout {
    /// Whether `text` has word breaks. Text with no whitespace has none, and neither does
    /// text in three or more groups of letters that are all the same length, apart from
    /// a shorter last one.
    fn of(text: &str) -> Layout {
        let groups: Vec<&str> = text.split_whitespace().collect();
        let Some((last, rest)) = groups.split_last() else {
            return Layout::Unspaced;
        };
        let size = groups[0].len();
        let grouped = groups.len() >= 3
            && rest.iter().all(|group| group.len() == size)
            && last.len() <= size
            && groups
                .iter()
                .all(|group| group.bytes().all(|b| b.is_ascii_alphabetic()));
        if groups.len() == 1 || grouped {
            Layout::Unspaced
        } else {
            Layout::Words
        }
    }
}

/// Characters a cryptogram can have besides ASCII letters. Non-ASCII letters are kept
/// as they are. Digits and `+ / =` are left out: almost every Base64, hexadecimal or
/// numeric encoding has one.
fn is_cryptogram_symbol(c: char) -> bool {
    c.is_whitespace()
        || matches!(
            c,
            '.' | ','
                | ';'
                | ':'
                | '!'
                | '?'
                | '\''
                | '"'
                | '-'
                | '('
                | ')'
                | '‘'
                | '’'
                | '“'
                | '”'
                | '–'
                | '—'
                | '…'
        )
        || (!c.is_ascii() && c.is_alphabetic())
}

/// Index of coincidence: the chance that two letters picked at random are the same.
fn index_of_coincidence(counts: &[usize; 26], total: usize) -> f64 {
    let pairs: usize = counts.iter().map(|&n| n * n.saturating_sub(1)).sum();
    pairs as f64 / (total * (total - 1)) as f64
}

/// How much better English letter frequencies fit the text after relabelling its letters
/// in frequency order than as they are, in log10 likelihood per letter. Substituted text
/// gains a lot. English, or any rearrangement of English, gains next to nothing.
fn frequency_gap(counts: &[usize; 26], total: usize) -> f64 {
    let log_freqs = ENGLISH_FREQS.map(f64::log10);
    let as_is: f64 = counts
        .iter()
        .zip(log_freqs)
        .map(|(&n, log_freq)| n as f64 * log_freq)
        .sum();

    let mut sorted_counts = *counts;
    sorted_counts.sort_unstable_by(|a, b| b.cmp(a));
    let mut sorted_log_freqs = log_freqs;
    sorted_log_freqs.sort_unstable_by(|a, b| b.total_cmp(a));
    let relabelled: f64 = sorted_counts
        .iter()
        .zip(sorted_log_freqs)
        .map(|(&n, log_freq)| n as f64 * log_freq)
        .sum();

    (relabelled - as_is) / total as f64
}

/// The key that maps the most frequent cipher letter to E, the next to T and so on.
fn frequency_key(letters: &[u8]) -> [u8; 26] {
    let mut counts = [0usize; 26];
    for &letter in letters {
        counts[usize::from(letter)] += 1;
    }
    let mut cipher_order: Vec<u8> = (0..26).collect();
    cipher_order.sort_by_key(|&c| std::cmp::Reverse(counts[usize::from(c)]));
    let mut english_order: Vec<u8> = (0..26).collect();
    english_order
        .sort_by(|&a, &b| ENGLISH_FREQS[usize::from(b)].total_cmp(&ENGLISH_FREQS[usize::from(a)]));

    let mut key = [0; 26];
    for (cipher, plain) in cipher_order.into_iter().zip(english_order) {
        key[usize::from(cipher)] = plain;
    }
    key
}

/// The key that leaves every letter alone.
const IDENTITY: [u8; 26] = {
    let mut key = [0; 26];
    let mut i = 0;
    while i < 26 {
        key[i] = i as u8;
        i += 1;
    }
    key
};

/// The 312 Affine decryption keys `p = a(c - b) mod 26`, the identity first. They
/// include every Caesar shift (`a = 1`) and Atbash (`a = 25, b = 25`).
fn affine_keys() -> impl Iterator<Item = [u8; 26]> {
    const MULTIPLIERS: [usize; 12] = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25];
    MULTIPLIERS.into_iter().flat_map(|a| {
        (0..26).map(move |b| {
            let mut key = [0; 26];
            for (c, plain) in key.iter_mut().enumerate() {
                *plain = (a * (c + 26 - b) % 26) as u8;
            }
            key
        })
    })
}

/// The fewest different letters a substitution of English with `letters` letters has.
/// A key maps distinct letters to distinct letters, and in more than 13,000 windows of
/// Project Gutenberg books and Ciphey's docs, English never used fewer than 10 different
/// letters in 60, 15 in 150 or 17 in 300. Text with fewer is in a smaller alphabet, such as
/// Baconian (2 letters) or Citrix CTX1 (16), and an annealing run on it is wasted.
fn min_distinct_letters(letters: usize) -> usize {
    match letters {
        300.. => 17,
        150.. => 14,
        _ => 9,
    }
}

/// [`Reason::Affine`] (or [`Reason::AlreadyEnglish`] for the identity) if a Caesar, Atbash or
/// Affine key turns the pairs of consecutive `letters` into English ones, scored with the
/// Affine decoder's letter-pair table (see [`AFFINE_PAIR_LOG_PROB`]). This catches most of
/// what the quadgram check in [`search`] would, without parsing the 60,000-line quadgram
/// table, which is most of the time a fresh process spends on a ROT13 input.
fn affine_by_letter_pairs(letters: &[u8]) -> Option<Reason> {
    let mut counts = [[0u32; 26]; 26];
    for pair in letters.windows(2) {
        counts[usize::from(pair[0])][usize::from(pair[1])] += 1;
    }
    let pairs: Vec<(usize, usize, f32)> = counts
        .iter()
        .enumerate()
        .flat_map(|(first, row)| {
            row.iter()
                .enumerate()
                .filter(|(_, &count)| count > 0)
                .map(move |(second, &count)| (first, second, count as f32))
        })
        .collect();
    let total = letters.len().saturating_sub(1).max(1) as f32;
    let log_probs = &*crate::decoders::affine_decoder::BIGRAM_LOG_PROBS;
    affine_keys().enumerate().find_map(|(index, key)| {
        let score: f32 = pairs
            .iter()
            .map(|&(first, second, count)| {
                count * log_probs[usize::from(key[first])][usize::from(key[second])]
            })
            .sum();
        (score / total >= AFFINE_PAIR_LOG_PROB).then_some(if index == 0 {
            Reason::AlreadyEnglish
        } else {
            Reason::Affine
        })
    })
}

/// Whether some Affine key decrypts every letter that occurs the way `key` does.
fn is_affine(key: &[u8; 26], present: &[bool; 26]) -> bool {
    affine_keys().any(|affine| (0..26).all(|c| !present[c] || affine[c] == key[c]))
}

/// The part of `key` that changes the decryption: letters that don't occur map to [`NONE`].
fn used_part(key: &[u8; 26], present: &[bool; 26]) -> [u8; 26] {
    let mut used = *key;
    for (plain, &present) in used.iter_mut().zip(present) {
        if !present {
            *plain = NONE;
        }
    }
    used
}

/// Decrypts `text` with `key`, keeping case and everything that isn't an ASCII letter.
/// Every letter of `text` has a plaintext letter in `key`.
fn decrypt(text: &str, key: &[u8; 26]) -> String {
    text.chars()
        .map(|c| {
            if c.is_ascii_uppercase() {
                char::from(b'A' + key[usize::from(c as u8 - b'A')])
            } else if c.is_ascii_lowercase() {
                char::from(b'a' + key[usize::from(c as u8 - b'a')])
            } else {
                c
            }
        })
        .collect()
}

/// The cipher letter of each plaintext letter A to Z under `key`, `?` for the plaintext
/// letters that no letter in the text decrypts to.
fn key_string(key: &[u8; 26], present: &[bool; 26]) -> String {
    let mut cipher_of_plain = ['?'; 26];
    for (cipher, (&plain, &present)) in key.iter().zip(present).enumerate() {
        if present {
            cipher_of_plain[usize::from(plain)] = char::from(b'A' + cipher as u8);
        }
    }
    cipher_of_plain.iter().collect()
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

/// Upper-case English words, for telling which decryptions read as English.
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
/// [`POLISH_LETTERS`] letters are looked at.
fn word_coverage(plaintext: &str) -> f64 {
    let letters: Vec<u8> = plaintext
        .bytes()
        .filter(u8::is_ascii_alphabetic)
        .take(POLISH_LETTERS)
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

/// The words of an Aristocrat, for scoring keys by how many of their letters decrypt to
/// dictionary words.
struct Words {
    /// The cipher letters of each word, as 0 to 25.
    words: Vec<Vec<u8>>,
    /// The words that contain each letter, each listed once.
    of_letter: [Vec<u32>; 26],
}

impl Words {
    /// The words of `text`, up to [`POLISH_LETTERS`] letters of them. Words with a
    /// non-ASCII letter are left out: no dictionary word matches them, and splitting
    /// "résumé" into "R" and "SUM" would score "SUM" instead.
    fn new(text: &str) -> Words {
        let mut letters = 0;
        let words: Vec<Vec<u8>> = text
            .split(|c: char| !c.is_alphabetic())
            .filter(|word| !word.is_empty() && word.bytes().all(|b| b.is_ascii_alphabetic()))
            .take_while(|word| {
                letters += word.len();
                letters <= POLISH_LETTERS
            })
            .map(|word| {
                word.bytes()
                    .map(|b| b.to_ascii_uppercase() - b'A')
                    .collect()
            })
            .collect();
        let mut of_letter: [Vec<u32>; 26] = Default::default();
        for (w, word) in words.iter().enumerate() {
            for (i, &c) in word.iter().enumerate() {
                if !word[..i].contains(&c) {
                    of_letter[usize::from(c)].push(w as u32);
                }
            }
        }
        Words { words, of_letter }
    }

    /// Number of letters of word `w` that are in the dictionary under `key`: its length
    /// or 0.
    fn score(&self, w: usize, key: &[u8; 26]) -> usize {
        let word = &self.words[w];
        let mut plain = [0u8; 32];
        if word.len() > plain.len() {
            return 0;
        }
        for (p, &c) in plain.iter_mut().zip(word) {
            *p = b'A' + key[usize::from(c)];
        }
        if DICTIONARY.contains(&plain[..word.len()]) {
            word.len()
        } else {
            0
        }
    }

    /// Number of letters in words that are in the dictionary under `key`.
    fn dictionary_letters(&self, key: &[u8; 26]) -> usize {
        (0..self.words.len()).map(|w| self.score(w, key)).sum()
    }

    /// The share of the letters that are in dictionary words under `key`.
    fn coverage(&self, key: &[u8; 26]) -> f64 {
        let letters: usize = self.words.iter().map(Vec::len).sum();
        self.dictionary_letters(key) as f64 / letters.max(1) as f64
    }
}

/// Hill climbs from `key` on the quadgram score plus [`WORD_WEIGHT`] for every letter in
/// a dictionary word. The quadgrams find most of the key, but in a short text they can't
/// tell rare letters apart, and the dictionary can: "JUMP" is a word and "FUMP" isn't.
fn polish_words(scorer: &Scorer, words: &Words, key: [u8; 26], stats: &mut Stats) -> [u8; 26] {
    let mut state = KeyState::new(scorer, key);
    let mut word_scores: Vec<usize> = (0..words.words.len())
        .map(|w| words.score(w, &key))
        .collect();
    // seen[w] == round: word w was already re-scored for this swap
    let mut seen = vec![0u32; words.words.len()];
    let mut round = 0;
    let mut changed: Vec<(u32, usize)> = Vec::new();
    for _ in 0..20 {
        let mut improved = false;
        for x in 0..26 {
            for y in x + 1..26 {
                if !scorer.has(x) && !scorer.has(y) {
                    continue;
                }
                let quadgram_delta = state.swap_delta(x, y);
                stats.swaps += 1;
                let mut swapped = state.key;
                swapped.swap(usize::from(x), usize::from(y));
                round += 1;
                changed.clear();
                let mut word_delta = 0.0;
                for &w in words.of_letter[usize::from(x)]
                    .iter()
                    .chain(&words.of_letter[usize::from(y)])
                {
                    if std::mem::replace(&mut seen[w as usize], round) == round {
                        continue;
                    }
                    let score = words.score(w as usize, &swapped);
                    if score != word_scores[w as usize] {
                        word_delta += score as f64 - word_scores[w as usize] as f64;
                        changed.push((w, score));
                    }
                }
                if quadgram_delta + WORD_WEIGHT * word_delta > 1e-3 {
                    state.accept(x, y, quadgram_delta);
                    for &(w, score) in &changed {
                        word_scores[w as usize] = score;
                    }
                    improved = true;
                }
            }
        }
        if !improved {
            break;
        }
    }
    state.key
}

/// Scores keys on a run of cipher letters. Window `w` is the quadgram
/// `letters[w..w + 4]`.
struct Scorer<'a> {
    /// The quadgram table.
    table: &'a [f32],
    /// The cipher letters, as 0 to 25. At least four.
    letters: &'a [u8],
    /// The windows that contain each letter, each listed once:
    /// `windows[starts[c]..starts[c + 1]]` for letter `c`.
    windows: Vec<u32>,
    /// See `windows`.
    starts: [usize; 27],
}

impl<'a> Scorer<'a> {
    /// A scorer for `letters`, which has at least four letters.
    fn new(letters: &'a [u8]) -> Scorer<'a> {
        // Each distinct letter of each window
        let distinct = |quadgram: &'a [u8]| {
            quadgram
                .iter()
                .enumerate()
                .filter(|&(i, c)| !quadgram[..i].contains(c))
                .map(|(_, &c)| usize::from(c))
        };
        let mut starts = [0; 27];
        for quadgram in letters.windows(4) {
            for c in distinct(quadgram) {
                starts[c + 1] += 1;
            }
        }
        for c in 0..26 {
            starts[c + 1] += starts[c];
        }
        let mut next = starts;
        let mut windows = vec![0; starts[26]];
        for (w, quadgram) in letters.windows(4).enumerate() {
            for c in distinct(quadgram) {
                windows[next[c]] = w as u32;
                next[c] += 1;
            }
        }
        Scorer {
            table: &QUADGRAMS,
            letters,
            windows,
            starts,
        }
    }

    /// Number of quadgrams.
    fn window_count(&self) -> usize {
        self.letters.len() - 3
    }

    /// The windows that contain `letter`.
    fn windows_of(&self, letter: u8) -> &[u32] {
        let c = usize::from(letter);
        &self.windows[self.starts[c]..self.starts[c + 1]]
    }

    /// Whether `letter` occurs.
    fn has(&self, letter: u8) -> bool {
        let c = usize::from(letter);
        self.starts[c] != self.starts[c + 1]
    }

    /// log10 probability of window `w` decrypted with `key`.
    fn window_score(&self, key: &[u8; 26], w: usize) -> f32 {
        let q = &self.letters[w..w + 4];
        let index = usize::from(key[usize::from(q[0])]) * 17_576
            + usize::from(key[usize::from(q[1])]) * 676
            + usize::from(key[usize::from(q[2])]) * 26
            + usize::from(key[usize::from(q[3])]);
        self.table[index]
    }

    /// Average log10 probability per quadgram of the text decrypted with `key`.
    fn fitness(&self, key: &[u8; 26]) -> f64 {
        self.score(key) / self.window_count() as f64
    }

    /// Total log10 probability of the quadgrams of the text decrypted with `key`.
    fn score(&self, key: &[u8; 26]) -> f64 {
        let mut score = 0.0;
        for w in 0..self.window_count() {
            score += f64::from(self.window_score(key, w));
        }
        score
    }

    /// Whether the text decrypted with `key` has an English [`Scorer::fitness`]. Most
    /// keys are ruled out on the first [`PREFIX_QUADGRAMS`] quadgrams.
    fn reads_as_english(&self, key: &[u8; 26]) -> bool {
        let prefix = self.window_count().min(PREFIX_QUADGRAMS);
        let mut score = 0.0;
        for w in 0..prefix {
            score += f64::from(self.window_score(key, w));
        }
        if score < PREFIX_FITNESS * prefix as f64 {
            return false;
        }
        for w in prefix..self.window_count() {
            score += f64::from(self.window_score(key, w));
        }
        score >= ENGLISH_FITNESS * self.window_count() as f64
    }
}

/// The starting temperature for a text of `window_count` quadgrams.
fn start_temperature(window_count: usize) -> f64 {
    START_TEMPERATURE * window_count as f64 / REFERENCE_QUADGRAMS
}

/// A key and the score of every window under it, so that a swap only re-scores the
/// windows that contain one of the two letters.
struct KeyState<'s, 'a> {
    /// What the key is scored on.
    scorer: &'s Scorer<'a>,
    /// Plaintext letter of each cipher letter.
    key: [u8; 26],
    /// Score of each window under `key`.
    window_scores: Vec<f32>,
    /// Sum of `window_scores`.
    score: f64,
    /// The windows the last [`KeyState::swap_delta`] re-scored, with their new scores.
    pending: Vec<(u32, f32)>,
}

impl<'s, 'a> KeyState<'s, 'a> {
    /// Scores `key` on `scorer`.
    fn new(scorer: &'s Scorer<'a>, key: [u8; 26]) -> KeyState<'s, 'a> {
        let window_scores: Vec<f32> = (0..scorer.window_count())
            .map(|w| scorer.window_score(&key, w))
            .collect();
        KeyState {
            scorer,
            key,
            score: window_scores.iter().map(|&s| f64::from(s)).sum(),
            window_scores,
            pending: Vec::new(),
        }
    }

    /// How much the score would change if cipher letters `x` and `y` swapped plaintext
    /// letters. [`KeyState::accept`] makes the swap.
    fn swap_delta(&mut self, x: u8, y: u8) -> f64 {
        let scorer = self.scorer;
        let mut key = self.key;
        key.swap(usize::from(x), usize::from(y));
        self.pending.clear();
        let mut delta = 0.0f32;
        for &w in scorer.windows_of(x) {
            let w = w as usize;
            let score = scorer.window_score(&key, w);
            delta += score - self.window_scores[w];
            self.pending.push((w as u32, score));
        }
        for &w in scorer.windows_of(y) {
            let w = w as usize;
            // Windows with both letters were re-scored above
            let q = &scorer.letters[w..w + 4];
            if q[0] == x || q[1] == x || q[2] == x || q[3] == x {
                continue;
            }
            let score = scorer.window_score(&key, w);
            delta += score - self.window_scores[w];
            self.pending.push((w as u32, score));
        }
        f64::from(delta)
    }

    /// Makes the swap the last [`KeyState::swap_delta`] scored.
    fn accept(&mut self, x: u8, y: u8, delta: f64) {
        self.key.swap(usize::from(x), usize::from(y));
        for &(w, score) in &self.pending {
            self.window_scores[w as usize] = score;
        }
        self.score += delta;
    }
}

/// One simulated annealing run from `start`: random swaps, always kept if they improve
/// the score and kept with probability e^(Δ/T) if they don't, with the temperature T
/// falling linearly from `temperature` to 0. Returns the best key seen.
fn anneal(
    scorer: &Scorer,
    start: [u8; 26],
    temperature: f64,
    rng: &mut Rng,
    stats: &mut Stats,
) -> [u8; 26] {
    // Swapping two letters that don't occur changes nothing, so x always occurs
    let present: Vec<u8> = (0..26).filter(|&c| scorer.has(c)).collect();
    let mut state = KeyState::new(scorer, start);
    let mut best = (state.score, state.key);
    for i in 0..SWAPS_PER_RUN {
        let t = temperature * f64::from(SWAPS_PER_RUN - i) / f64::from(SWAPS_PER_RUN);
        let x = present[rng.below(present.len())];
        let mut y = rng.below(25) as u8;
        if y >= x {
            y += 1;
        }
        let delta = state.swap_delta(x, y);
        if delta >= 0.0 || rng.unit() < (delta / t).exp() {
            state.accept(x, y, delta);
            if state.score > best.0 {
                best = (state.score, state.key);
            }
        }
    }
    stats.swaps += u64::from(SWAPS_PER_RUN);
    best.1
}

/// Hill climbs from `key`: makes every swap that improves the score until none does.
fn polish(scorer: &Scorer, key: [u8; 26], stats: &mut Stats) -> [u8; 26] {
    let mut state = KeyState::new(scorer, key);
    // Bounded in case rounding makes two swaps look like improvements of each other
    for _ in 0..100 {
        let mut improved = false;
        for x in 0..26 {
            for y in x + 1..26 {
                if !scorer.has(x) && !scorer.has(y) {
                    continue;
                }
                let delta = state.swap_delta(x, y);
                stats.swaps += 1;
                if delta > 1e-3 {
                    state.accept(x, y, delta);
                    improved = true;
                }
            }
        }
        if !improved {
            break;
        }
    }
    state.key
}

/// xorshift64*, seeded from the letter pattern so a text is always cracked the same way.
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

/// What an earlier search found for a letter pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cached {
    /// The checker accepted the decryption. Entry `i` is the plaintext letter of the
    /// pattern's `i`th distinct letter.
    Solved([u8; 26]),
    /// Nothing the checker accepted.
    Unsolved,
}

/// Search results by pattern hash, shared by every thread.
struct SearchCache {
    /// `None` while a thread is searching the pattern.
    entries: Mutex<HashMap<u64, Option<Cached>>>,
    /// Notified when a search finishes.
    finished: Condvar,
}

/// The answer to [`SearchCache::lookup`].
enum Lookup<'c> {
    /// An earlier search found this.
    Hit(Cached),
    /// No result yet. The caller searches, and publishes what it finds through this.
    Miss(Searching<'c>),
    /// Another thread has been searching the pattern for too long.
    Busy,
}

/// Marks a pattern as being searched until it is finished or dropped.
struct Searching<'c> {
    /// The cache to publish to.
    cache: &'c SearchCache,
    /// The pattern being searched.
    pattern: u64,
}

impl SearchCache {
    /// An empty cache.
    fn new() -> SearchCache {
        SearchCache {
            entries: Mutex::new(HashMap::new()),
            finished: Condvar::new(),
        }
    }

    /// Locks the entries. Every update leaves them consistent, so a lock poisoned by a
    /// panic elsewhere is fine to use.
    fn entries(&self) -> MutexGuard<'_, HashMap<u64, Option<Cached>>> {
        self.entries.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The result for `pattern`. If another thread is searching it, waits for that
    /// search instead of repeating it.
    fn lookup(&self, pattern: u64) -> Lookup<'_> {
        let (mut entries, wait) = self
            .finished
            .wait_timeout_while(self.entries(), CACHE_WAIT, |entries| {
                matches!(entries.get(&pattern), Some(None))
            })
            .unwrap_or_else(PoisonError::into_inner);
        match entries.get(&pattern) {
            Some(Some(cached)) => Lookup::Hit(*cached),
            Some(None) if wait.timed_out() => Lookup::Busy,
            _ => {
                entries.insert(pattern, None);
                Lookup::Miss(Searching {
                    cache: self,
                    pattern,
                })
            }
        }
    }

    /// Records the result for `pattern`.
    fn store(&self, pattern: u64, cached: Cached) {
        let mut entries = self.entries();
        if entries.len() >= CACHE_LIMIT {
            // Keep the markers of searches still running
            entries.retain(|_, cached| cached.is_none());
        }
        entries.insert(pattern, Some(cached));
        drop(entries);
        self.finished.notify_all();
    }
}

impl Searching<'_> {
    /// Publishes the search's result.
    fn finish(self, cached: Cached) {
        self.cache.store(self.pattern, cached);
        // The entry isn't a marker any more, so dropping `self` leaves it alone
    }
}

impl Drop for Searching<'_> {
    /// Removes the marker if the search ended without a result to cache, so the next
    /// lookup searches again.
    fn drop(&mut self) {
        let mut entries = self.cache.entries();
        if matches!(entries.get(&self.pattern), Some(None)) {
            entries.remove(&self.pattern);
        }
        drop(entries);
        self.cache.finished.notify_all();
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
    // https://github.com/bee-san/Ciphey/issues/1005. The ciphertexts were made with
    // CyberChef 11.5 `Substitute` (plaintext alphabet -> key), and the first matches
    // pycipher 0.5.2 `SimpleSubstitution`; `vectors_match_their_keys` re-encrypts them.

    /// The issue's example, an Aristocrat with key QWERTYUIOPASDFGHJKLZXCVBNM.
    const DICKENS_CIPHERTEXT: &str = "OZ VQL ZIT WTLZ GY ZODTL, OZ VQL ZIT VGKLZ GY ZODTL, OZ VQL ZIT QUT GY VOLRGD, OZ VQL ZIT QUT GY YGGSOLIFTLL, OZ VQL ZIT THGEI GY WTSOTY, OZ VQL ZIT THGEI GY OFEKTRXSOZN, OZ VQL ZIT LTQLGF GY SOUIZ, OZ VQL ZIT LTQLGF GY RQKAFTLL";
    /// Its plaintext.
    const DICKENS: &str = "IT WAS THE BEST OF TIMES, IT WAS THE WORST OF TIMES, IT WAS THE AGE OF WISDOM, IT WAS THE AGE OF FOOLISHNESS, IT WAS THE EPOCH OF BELIEF, IT WAS THE EPOCH OF INCREDULITY, IT WAS THE SEASON OF LIGHT, IT WAS THE SEASON OF DARKNESS";
    /// The key of [`DICKENS_CIPHERTEXT`].
    const QWERTY: &str = "QWERTYUIOPASDFGHJKLZXCVBNM";

    /// The same as a Patristocrat: no spaces or punctuation.
    const DICKENS_PATRISTOCRAT: &str = "OZVQLZITWTLZGYZODTLOZVQLZITVGKLZGYZODTLOZVQLZITQUTGYVOLRGDOZVQLZITQUTGYYGGSOLIFTLLOZVQLZITTHGEIGYWTSOTYOZVQLZITTHGEIGYOFEKTRXSOZNOZVQLZITLTQLGFGYSOUIZOZVQLZITLTQLGFGYRQKAFTLL";
    /// The plaintext the issue gives for the example.
    const DICKENS_UNSPACED: &str = "ITWASTHEBESTOFTIMESITWASTHEWORSTOFTIMESITWASTHEAGEOFWISDOMITWASTHEAGEOFFOOLISHNESSITWASTHEEPOCHOFBELIEFITWASTHEEPOCHOFINCREDULITYITWASTHESEASONOFLIGHTITWASTHESEASONOFDARKNESS";

    /// Mixed case and a full stop, keyword key ZEBRAS.
    const ZEBRAS_CIPHERTEXT: &str = "Fq vzp qda eapq ls qfjap, fq vzp qda vlopq ls qfjap, fq vzp qda zca ls vfprlj, fq vzp qda zca ls sllifpdkapp, fq vzp qda amlbd ls eaifas, fq vzp qda amlbd ls fkboartifqx, fq vzp qda pazplk ls ifcdq, fq vzp qda pazplk ls rzohkapp.";
    /// Its plaintext.
    const ZEBRAS_PLAINTEXT: &str = "It was the best of times, it was the worst of times, it was the age of wisdom, it was the age of foolishness, it was the epoch of belief, it was the epoch of incredulity, it was the season of light, it was the season of darkness.";
    /// The key of [`ZEBRAS_CIPHERTEXT`].
    const ZEBRAS: &str = "ZEBRASCDFGHIJKLMNOPQTUVWXY";

    /// Modern text, with a word ("Ciphey") no dictionary has.
    const CIPHEY_CIPHERTEXT: &str = "Qaxeiw ar pf pvcdopcaq giqkwxcadf cddn. Wdv masi ac ifqkwxcig cizc pfg ac ckair cd tdkl dvc tepc tpr gdfi cd ac, ceif redtr wdv cei xnpafcizc. Ac lfdtr opfw ifqdgafmr pfg qnprraqpn qaxeikr, pfg ac liixr nipkfafm fit dfir.";
    /// Its plaintext.
    const CIPHEY_PLAINTEXT: &str = "Ciphey is an automatic decryption tool. You give it encrypted text and it tries to work out what was done to it, then shows you the plaintext. It knows many encodings and classical ciphers, and it keeps learning new ones.";
    /// The key of [`CIPHEY_CIPHERTEXT`].
    const PHQG: &str = "PHQGIUMEAYLNOFDXJKRCVSTZWB";

    /// Encrypts the ASCII letters of `plaintext`: plaintext letter A becomes `key[0]`,
    /// B becomes `key[1]` and so on, keeping case.
    fn encrypt(plaintext: &str, key: &str) -> String {
        let key = key.as_bytes();
        plaintext
            .chars()
            .map(|c| {
                if c.is_ascii_uppercase() {
                    char::from(key[usize::from(c as u8 - b'A')])
                } else if c.is_ascii_lowercase() {
                    char::from(key[usize::from(c as u8 - b'a')].to_ascii_lowercase())
                } else {
                    c
                }
            })
            .collect()
    }

    /// `key` with `?` for the letters `plaintext` doesn't have: what `crack` can recover.
    fn recoverable_key(key: &str, plaintext: &str) -> String {
        let upper = plaintext.to_ascii_uppercase();
        key.chars()
            .zip('A'..='Z')
            .map(|(cipher, plain)| if upper.contains(plain) { cipher } else { '?' })
            .collect()
    }

    /// Rotates the ASCII letters of `text` by `shift`.
    fn caesar(text: &str, shift: u8) -> String {
        let key: String = (0..26)
            .map(|i| char::from(b'A' + (i + shift) % 26))
            .collect();
        encrypt(text, &key)
    }

    fn athena() -> CheckerTypes {
        CheckerTypes::CheckAthena(Checker::<Athena>::new())
    }

    /// Cracks `text` with the Athena checker and no cache, as `crack` would.
    fn crack_fresh(text: &str) -> (Outcome<CheckResult>, Stats) {
        let checker = athena();
        let mut stats = Stats::default();
        let outcome = crack_text(text, None, &mut stats, &mut |candidate, layout| {
            check(&checker, candidate, layout)
        });
        (outcome, stats)
    }

    /// The plaintext and key the checker confirmed for `text`, if any.
    fn solve(text: &str) -> Option<(String, String)> {
        match crack_fresh(text).0 {
            Outcome::Confirmed { plaintext, key, .. } => Some((plaintext, key)),
            _ => None,
        }
    }

    /// Asserts that `text` fails with `reason` without annealing, and returns the stats.
    fn assert_fails_fast(text: &str, reason: Reason) -> Stats {
        let (outcome, stats) = crack_fresh(text);
        match outcome {
            Outcome::Failed(r) => assert_eq!(r, reason, "{text:?}"),
            _ => panic!("expected {reason:?} for {text:?}"),
        }
        assert_eq!(stats.swaps, 0, "{text:?} was searched");
        assert_eq!(stats.checked, 0, "{text:?} was shown to the checker");
        stats
    }

    #[test]
    fn vectors_match_their_keys() {
        assert_eq!(encrypt(DICKENS, QWERTY), DICKENS_CIPHERTEXT);
        assert_eq!(encrypt(DICKENS_UNSPACED, QWERTY), DICKENS_PATRISTOCRAT);
        assert_eq!(encrypt(ZEBRAS_PLAINTEXT, ZEBRAS), ZEBRAS_CIPHERTEXT);
        assert_eq!(encrypt(CIPHEY_PLAINTEXT, PHQG), CIPHEY_CIPHERTEXT);
    }

    #[test]
    fn cracks_the_issue_example() {
        let (plaintext, key) = solve(DICKENS_CIPHERTEXT).expect("not cracked");
        assert_eq!(plaintext, DICKENS);
        assert_eq!(key, recoverable_key(QWERTY, DICKENS));
        assert_eq!(key, "QWERTYUIO?ASDFGH?KLZX?V?N?");
    }

    #[test]
    fn cracks_a_patristocrat() {
        let (plaintext, key) = solve(DICKENS_PATRISTOCRAT).expect("not cracked");
        assert_eq!(plaintext, DICKENS_UNSPACED);
        assert_eq!(key, recoverable_key(QWERTY, DICKENS));
    }

    #[test]
    fn cracks_a_patristocrat_in_groups_of_five() {
        let groups: Vec<String> = DICKENS_PATRISTOCRAT
            .as_bytes()
            .chunks(5)
            .map(|group| String::from_utf8_lossy(group).into_owned())
            .collect();
        let (plaintext, key) = solve(&groups.join(" ")).expect("not cracked");
        // The groups aren't words, so they are joined up
        assert_eq!(plaintext, DICKENS_UNSPACED);
        assert_eq!(key, recoverable_key(QWERTY, DICKENS));
    }

    #[test]
    fn cracks_mixed_case_keeping_case_and_punctuation() {
        let (plaintext, key) = solve(ZEBRAS_CIPHERTEXT).expect("not cracked");
        assert_eq!(plaintext, ZEBRAS_PLAINTEXT);
        assert_eq!(key, recoverable_key(ZEBRAS, ZEBRAS_PLAINTEXT));
    }

    #[test]
    fn cracks_modern_text() {
        let (plaintext, key) = solve(CIPHEY_CIPHERTEXT).expect("not cracked");
        assert_eq!(plaintext, CIPHEY_PLAINTEXT);
        assert_eq!(key, recoverable_key(PHQG, CIPHEY_PLAINTEXT));
        assert_eq!(key, "P?QGI?MEA?LNOFDX?KRCVSTZW?");
    }

    #[test]
    fn non_ascii_letters_pass_through() {
        let plaintext = CIPHEY_PLAINTEXT.replace("tool.", "tool, résumé in hand.");
        let (cracked, _) = solve(&encrypt(&plaintext, PHQG)).expect("not cracked");
        assert_eq!(cracked, plaintext);
    }

    #[test]
    fn crack_reports_success_and_key() {
        let decoder = Decoder::<MonoalphabeticSubstitutionDecoder>::new();
        let result = decoder.crack(ZEBRAS_CIPHERTEXT, &athena());
        assert!(result.success);
        assert_eq!(result.decoder, "Monoalphabetic Substitution");
        assert_eq!(
            result.unencrypted_text,
            Some(vec![ZEBRAS_PLAINTEXT.to_string()])
        );
        assert_eq!(
            result.key.unwrap(),
            recoverable_key(ZEBRAS, ZEBRAS_PLAINTEXT)
        );
    }

    #[test]
    fn crack_fails_without_panicking() {
        let decoder = Decoder::<MonoalphabeticSubstitutionDecoder>::new();
        let rot13 = caesar(DICKENS, 13);
        for text in [
            "",
            "😀",
            "Hello, World!",
            DICKENS,
            &rot13,
            "aGVsbG8gdGhlcmUgZ2VuZXJhbA==",
        ] {
            let result = decoder.crack(text, &athena());
            assert!(!result.success, "{text:?}");
            assert_eq!(result.unencrypted_text, None, "{text:?}");
            assert_eq!(result.key, None, "{text:?}");
        }
    }

    #[test]
    fn rejects_short_text_without_searching() {
        for text in ["", "😀", "Hello, World!", &DICKENS_CIPHERTEXT[..80]] {
            let stats = assert_fails_fast(text, Reason::TooShort);
            assert_eq!(stats.scored, 0);
        }
    }

    #[test]
    fn rejects_other_alphabets_without_searching() {
        let with_digit = DICKENS_CIPHERTEXT.replace("OZ VQL", "OZ 2 VQL");
        let with_emoji = format!("{DICKENS_CIPHERTEXT} 😀");
        let base64 = "SXQgd2FzIHRoZSBiZXN0IG9mIHRpbWVzLCBpdCB3YXMgdGhlIHdvcnN0IG9mIHRpbWVzLCBpdCB3YXMgdGhlIGFnZSBvZiB3aXNkb20=";
        let hex = "4974207761732074686520626573742074696d65732c206974207761732074686520776f7273742074696d6573";
        for text in [&with_digit, &with_emoji, base64, hex] {
            let stats = assert_fails_fast(text, Reason::Alphabet);
            assert_eq!(stats.scored, 0);
        }
    }

    #[test]
    fn rejects_polyalphabetic_and_random_text_without_searching() {
        // Vigenère, key CRYPTII, from the Vigenère decoder's tests
        let vigenere = "Err xgbmncgvxvkg zq toqlger xg bpgzp puqtkkw ih ilcgr, axizp kfghcoj fzhxzdckgdg, ivf jmaom xtfzaxua, yzrw kmagrpra apqngcz bpgp ndlamuj qikwvi dcbhzqgj, cmaqjkk ltnzwrcyhmqkkkw, pgl lkjnatg kqxlxmqdg jixeta efketzidcc ih i gqllv vpqnu.";
        let random =
            "QWHDKZMVBXPLRUGTCJYOEFANSIWQKZXMJVBDYHGLUTPRCOEFSNAIZKQXWJVMBYDHLGUTRPOCFENSAIQZWKX";
        for text in [vigenere, random] {
            let stats = assert_fails_fast(text, Reason::Coincidence);
            assert_eq!(stats.scored, 0);
        }
    }

    #[test]
    fn rejects_english_and_its_transpositions_without_searching() {
        let reversed: String = DICKENS.chars().rev().collect();
        // Two-rail rail fence: every other character, then the rest
        let rail_fence: String = DICKENS
            .chars()
            .step_by(2)
            .chain(DICKENS.chars().skip(1).step_by(2))
            .collect();
        for text in [
            DICKENS,
            DICKENS_UNSPACED,
            CIPHEY_PLAINTEXT,
            &reversed,
            &rail_fence,
        ] {
            let stats = assert_fails_fast(text, Reason::EnglishFrequencies);
            assert_eq!(stats.scored, 0);
        }
    }

    #[test]
    fn leaves_caesar_atbash_and_affine_to_their_decoders() {
        let atbash: String = "ZYXWVUTSRQPONMLKJIHGFEDCBA".to_string();
        // Affine a = 5, b = 8: plaintext letter p becomes 5p + 8
        let affine: String = (0..26u8)
            .map(|p| char::from(b'A' + (5 * p + 8) % 26))
            .collect();
        for text in [
            caesar(DICKENS, 13),
            caesar(DICKENS_UNSPACED, 3),
            encrypt(ZEBRAS_PLAINTEXT, &atbash),
            encrypt(CIPHEY_PLAINTEXT, &affine),
        ] {
            let stats = assert_fails_fast(&text, Reason::Affine);
            assert!(stats.scored <= 312);
        }
    }

    #[test]
    fn letter_pairs_leave_most_affine_texts_without_quadgrams() {
        // The cheap letter-pair check catches these before any quadgram is scored
        for text in [caesar(DICKENS, 13), caesar(DICKENS_UNSPACED, 3)] {
            let letters = Ciphertext::parse(&text).unwrap().letters;
            assert_eq!(affine_by_letter_pairs(&letters), Some(Reason::Affine));
            let stats = assert_fails_fast(&text, Reason::Affine);
            assert_eq!(stats.scored, 0, "{text:?}");
        }
        // ... and lets every genuine substitution through to the search
        for text in [
            DICKENS_CIPHERTEXT,
            DICKENS_PATRISTOCRAT,
            ZEBRAS_CIPHERTEXT,
            CIPHEY_CIPHERTEXT,
        ] {
            let letters = Ciphertext::parse(text).unwrap().letters;
            assert_eq!(affine_by_letter_pairs(&letters), None, "{text:?}");
        }
    }

    #[test]
    fn rejects_small_alphabets_without_searching() {
        // The Baconian input of benches/data/search.toml: two letters
        let baconian = "ABABBAABAAAABAABAABA ABABBAABAA AAAAABAABA BAABAAABBBAABAA ABBABABABAAAABB ABABAABAAAAABBAAABBBBAABAAABBBABBABBAABBBAAABAABAA AAAAAAABABBAABAAABAABAAAA ABABBABAAAAAABBABBAAABAAAAABBAAABBBBAABA AAAAAABBAAAAABB AAAABBAAAAABAAAABBAAAABBA BAABAAABBBAABAA ABABBAAAAAABBBA BAABAAABBBAABAA ABAABAABAABABBA AAAAAABBAAAAABB AAAAA BAABAABBABBAAAAAAABAAABBB";
        // Its Citrix CTX1 input: 336 letters from A to P
        let citrix = "OIENINCIOIENJMDJLMBJNBHELEBBJEDBPFFAIBCEKBAENFHALNBINIHNPIFNJHDCPLFOJPDKLPBKNDHGLKBPNNHILFBAMBGEKJAMMGGDLDBGMAGFKFAAIFCAOEEBICCHPGFDJDDGOBEEMBGEKMAJMFGAKBAEMPGKKGADMBGEKJAMNNHIPNFIJMDJPCFHJGDDLGBDNEHBKGADMPGKKBAEMGGDOGEDJCDHPKFPJPDKLPBKNCHHLDBGMDGGOPEKMPGKLLBONDHGLGBDJGDDPNFIJIDNOBEEMBGEKAAFMOGLKKAPIKCPOLEOMLGOLPBKNAHFKCAHMBGEKJAMIHCC";
        for text in [baconian, citrix] {
            let stats = assert_fails_fast(text, Reason::FewDistinctLetters);
            assert_eq!(stats.scored, 0);
        }
        // English has more: the test texts from 60 letters up
        for text in [
            &DICKENS_CIPHERTEXT[..80],
            DICKENS_CIPHERTEXT,
            ZEBRAS_CIPHERTEXT,
            CIPHEY_CIPHERTEXT,
        ] {
            let ciphertext = Ciphertext::parse(text);
            assert!(
                !matches!(ciphertext, Err(Reason::FewDistinctLetters)),
                "{text:?}"
            );
        }
        assert_eq!(min_distinct_letters(60), 9);
        assert_eq!(min_distinct_letters(150), 14);
        assert_eq!(min_distinct_letters(336), 17);
    }

    #[test]
    fn short_patristocrat_does_not_panic() {
        // 82 letters: below about 80 a wrong key can outscore the right one, so this is
        // best effort only
        let (outcome, _) = crack_fresh(&DICKENS_PATRISTOCRAT[..82]);
        if let Outcome::Confirmed { plaintext, .. } | Outcome::Unconfirmed { plaintext, .. } =
            outcome
        {
            assert_eq!(plaintext.len(), 82);
        }
    }

    #[test]
    fn same_text_cracks_the_same_way() {
        let first = crack_fresh(CIPHEY_CIPHERTEXT);
        let second = crack_fresh(CIPHEY_CIPHERTEXT);
        assert_eq!(first.1.swaps, second.1.swaps);
        assert!(matches!(
            (first.0, second.0),
            (Outcome::Confirmed { key: a, .. }, Outcome::Confirmed { key: b, .. }) if a == b
        ));
    }

    /// Cracks `text` through `cache` with the Athena checker.
    fn crack_cached(text: &str, cache: &SearchCache) -> (Outcome<CheckResult>, Stats) {
        let checker = athena();
        let mut stats = Stats::default();
        let outcome = crack_text(text, Some(cache), &mut stats, &mut |candidate, layout| {
            check(&checker, candidate, layout)
        });
        (outcome, stats)
    }

    #[test]
    fn substitutions_of_a_solved_text_hit_the_cache() {
        let cache = SearchCache::new();
        let (first, stats) = crack_cached(DICKENS_CIPHERTEXT, &cache);
        assert!(matches!(first, Outcome::Confirmed { .. }));
        assert!(!stats.cache_hit);
        assert!(stats.swaps > 0);

        // A Caesar shift of the ciphertext is another substitution of the same plaintext
        let shifted = caesar(DICKENS_CIPHERTEXT, 5);
        let shifted_key = caesar(QWERTY, 5);
        let (second, stats) = crack_cached(&shifted, &cache);
        assert!(stats.cache_hit);
        assert_eq!(stats.swaps, 0);
        match second {
            Outcome::Confirmed { plaintext, key, .. } => {
                assert_eq!(plaintext, DICKENS);
                assert_eq!(key, recoverable_key(&shifted_key, DICKENS));
            }
            _ => panic!("cache hit not confirmed"),
        }

        // So are the plaintext and its Caesar shifts, but those are left to Caesar.
        // (The plaintext itself doesn't get as far as the cache.)
        let (third, stats) = crack_cached(&caesar(DICKENS, 7), &cache);
        assert!(matches!(third, Outcome::Failed(Reason::Affine)));
        assert!(stats.cache_hit);
        assert_eq!(stats.swaps, 0);
    }

    #[test]
    fn unconfirmed_results_are_only_returned_once() {
        let cache = SearchCache::new();
        let mut stats = Stats::default();
        let mut reject = |_: &str, _: Layout| -> Option<()> { None };
        let first = crack_text(CIPHEY_CIPHERTEXT, Some(&cache), &mut stats, &mut reject);
        match first {
            Outcome::Unconfirmed { plaintext, .. } => assert_eq!(plaintext, CIPHEY_PLAINTEXT),
            _ => panic!("expected an unconfirmed result"),
        }
        assert!(stats.checked > 0);

        let mut stats = Stats::default();
        let second = crack_text(
            &caesar(CIPHEY_CIPHERTEXT, 1),
            Some(&cache),
            &mut stats,
            &mut reject,
        );
        assert!(matches!(second, Outcome::Failed(Reason::Cached)));
        assert!(stats.cache_hit);
        assert_eq!(stats.swaps, 0);
    }

    #[test]
    fn concurrent_searches_of_one_pattern_search_once() {
        let cache = SearchCache::new();
        let results: Vec<(Outcome<CheckResult>, Stats)> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..4)
                .map(|shift| {
                    let cache = &cache;
                    scope.spawn(move || crack_cached(&caesar(ZEBRAS_CIPHERTEXT, shift), cache))
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        let searches = results.iter().filter(|(_, stats)| stats.swaps > 0).count();
        assert_eq!(searches, 1);
        for (outcome, _) in &results {
            match outcome {
                Outcome::Confirmed { plaintext, .. } => assert_eq!(plaintext, ZEBRAS_PLAINTEXT),
                _ => panic!("not confirmed"),
            }
        }
    }

    #[test]
    fn cache_marker_is_removed_when_a_search_has_nothing_to_store() {
        let cache = SearchCache::new();
        let Lookup::Miss(searching) = cache.lookup(1) else {
            panic!("empty cache hit");
        };
        drop(searching);
        assert!(matches!(cache.lookup(1), Lookup::Miss(_)));
    }

    #[test]
    fn cache_is_cleared_when_full() {
        let cache = SearchCache::new();
        for pattern in 0..CACHE_LIMIT as u64 {
            cache.store(pattern, Cached::Unsolved);
        }
        assert!(matches!(cache.lookup(0), Lookup::Hit(Cached::Unsolved)));
        cache.store(u64::MAX, Cached::Unsolved);
        assert!(matches!(cache.lookup(1), Lookup::Miss(_)));
        assert!(matches!(
            cache.lookup(u64::MAX),
            Lookup::Hit(Cached::Unsolved)
        ));
    }

    #[test]
    fn pattern_is_the_same_for_every_substitution() {
        let pattern = |text: &str| Ciphertext::parse(text).unwrap().pattern;
        let plain = pattern(&encrypt(DICKENS, QWERTY));
        assert_eq!(pattern(&caesar(DICKENS_CIPHERTEXT, 9)), plain);
        assert_eq!(pattern(&encrypt(DICKENS, ZEBRAS)), plain);
        assert_eq!(
            pattern(&encrypt(&DICKENS.to_ascii_lowercase(), PHQG)),
            plain
        );
        assert_ne!(pattern(&encrypt(&DICKENS.replace(',', ";"), QWERTY)), plain);
        assert_ne!(pattern(DICKENS_PATRISTOCRAT), plain);
    }

    #[test]
    fn layout_detects_word_breaks() {
        assert_eq!(Layout::of(DICKENS_CIPHERTEXT), Layout::Words);
        assert_eq!(Layout::of(DICKENS_PATRISTOCRAT), Layout::Unspaced);
        assert_eq!(Layout::of("OZVQL ZITWT LZGYZ ODTLO ZV"), Layout::Unspaced);
        assert_eq!(Layout::of("OZVQLZ ITWTLZ GYZODT"), Layout::Unspaced);
        assert_eq!(Layout::of("OZVQL ZITWT"), Layout::Words);
        assert_eq!(Layout::of("OZVQL, ZITWT LZGYZ"), Layout::Words);
        assert_eq!(Layout::of("OZV QLZIT WTLZG"), Layout::Words);
    }

    #[test]
    fn statistics_of_the_vectors() {
        let ciphertext = Ciphertext::parse(DICKENS_CIPHERTEXT).unwrap();
        let mut counts = [0; 26];
        for &letter in &ciphertext.letters {
            counts[usize::from(letter)] += 1;
        }
        let ioc = index_of_coincidence(&counts, ciphertext.letters.len());
        assert!((ioc - 0.0797).abs() < 0.0001, "{ioc}");
        assert!(frequency_gap(&counts, ciphertext.letters.len()) > 0.5);

        let scorer = Scorer::new(&ciphertext.letters);
        assert!(scorer.fitness(&IDENTITY) < -5.5);
        assert!(!scorer.reads_as_english(&IDENTITY));
        let mut key = [0; 26];
        for (plain, cipher) in QWERTY.bytes().enumerate() {
            key[usize::from(cipher - b'A')] = plain as u8;
        }
        let fitness = scorer.fitness(&key);
        assert!(fitness > CHECK_FITNESS, "{fitness}");
        assert!(scorer.reads_as_english(&key));
        assert!((scorer.score(&key) / scorer.window_count() as f64 - fitness).abs() < 1e-9);
    }

    #[test]
    fn affine_keys_are_distinct_permutations() {
        let keys: Vec<[u8; 26]> = affine_keys().collect();
        assert_eq!(keys.len(), 312);
        assert_eq!(keys[0], IDENTITY);
        let distinct: HashSet<[u8; 26]> = keys.iter().copied().collect();
        assert_eq!(distinct.len(), 312);
        for key in &keys {
            let mut sorted = *key;
            sorted.sort_unstable();
            assert_eq!(sorted, IDENTITY);
        }
        let atbash: [u8; 26] = std::array::from_fn(|c| 25 - c as u8);
        assert!(keys.contains(&atbash));
        let present = [true; 26];
        assert!(is_affine(&atbash, &present));
        let mut swapped = IDENTITY;
        swapped.swap(0, 1);
        assert!(!is_affine(&swapped, &present));
        // Only the letters that occur count
        let mut present = [true; 26];
        present[0] = false;
        present[1] = false;
        assert!(is_affine(&swapped, &present));
    }

    #[test]
    fn key_string_marks_missing_letters() {
        let mut key = IDENTITY;
        key.swap(0, 25);
        let mut present = [false; 26];
        present[0] = true; // cipher A decrypts to Z
        present[1] = true; // cipher B decrypts to B
        assert_eq!(key_string(&key, &present), "?B???????????????????????A");
    }

    #[test]
    fn decrypt_keeps_case_and_symbols() {
        let mut key = IDENTITY;
        key.swap(0, 1);
        assert_eq!(decrypt("Ab, ba! é 😀", &key), "Ba, ab! é 😀");
    }

    #[test]
    fn quadgram_table() {
        let table = parse_quadgrams("# comment\nABCD 3\nTHAT 1\nbad line\nTOOLONG 9\n\n");
        let floor = (0.5f64 / 4.0).log10() as f32;
        assert_eq!(table.len(), QUADGRAM_COUNT);
        assert_eq!(
            table[quadgram_index("ABCD").unwrap()],
            (0.75f64).log10() as f32
        );
        assert_eq!(
            table[quadgram_index("THAT").unwrap()],
            (0.25f64).log10() as f32
        );
        assert_eq!(table[quadgram_index("QQQQ").unwrap()], floor);
        assert_eq!(quadgram_index("abcd"), None);

        let that = QUADGRAMS[quadgram_index("THAT").unwrap()];
        let unseen = QUADGRAMS[quadgram_index("QXZJ").unwrap()];
        assert!(that > -2.6, "{that}");
        assert!(unseen < -6.9, "{unseen}");
        assert!(QUADGRAMS.iter().all(|&p| p >= unseen && p < 0.0));
    }

    #[test]
    fn dictionary_covers_english() {
        for word in [
            "IT",
            "WAS",
            "THE",
            "BEST",
            "OF",
            "TIMES",
            "INCREDULITY",
            "DARKNESS",
        ] {
            assert!(DICTIONARY.contains(word.as_bytes()), "{word}");
        }
        // Ten 19th-century novels don't have every word: "FOOLISHNESS" and "EPOCH" are
        // missing. What matters is that most of a text is covered and gibberish isn't.
        assert!(!DICTIONARY.contains(b"EPOCH"));
        assert!(!DICTIONARY.contains(b"XQZ"));
        assert!(!DICTIONARY.contains(b"the"));
        let coverage = word_coverage(DICKENS_UNSPACED);
        assert!(coverage > MIN_COVERAGE_WITHOUT_BREAKS, "{coverage}");
        assert_eq!(word_coverage("ITWASTHEBESTOFTIMES"), 1.0);
        assert!(word_coverage("XQZJXQZJXQZJXQZJ") < 0.2);
        assert_eq!(word_coverage(""), 0.0);
    }

    #[test]
    fn is_registered_once() {
        let name = "Monoalphabetic Substitution";
        let decoders = crate::filtration_system::get_decoder_by_name(name);
        assert_eq!(decoders.components.len(), 1);
        let decoder = &decoders.components[0];
        assert_eq!(decoder.get_name(), name);
        assert_eq!(
            decoder.get_tags(),
            &vec!["substitution", "monoalphabetic", "classic", "cryptogram"]
        );
        assert!(!decoder.get_tags().contains(&"decoder"));
        assert_eq!(decoder.get_popularity(), 0.4);
        assert_eq!(
            decoder.get_link(),
            "https://en.wikipedia.org/wiki/Substitution_cipher"
        );
        assert!(crate::decoders::DECODER_MAP.contains_key(name));
    }

    #[test]
    fn words_coverage() {
        let words = Words::new(DICKENS);
        assert_eq!(words.words.len(), 48);
        // "FOOLISHNESS" and "EPOCH" (twice) aren't in the word list
        assert_eq!(words.dictionary_letters(&IDENTITY), 174 - 11 - 2 * 5);
        let coverage = words.coverage(&IDENTITY);
        assert!((coverage - 153.0 / 174.0).abs() < 1e-12, "{coverage}");
        // Decrypted with a wrong key, almost nothing is a word
        let mut wrong = IDENTITY;
        wrong.swap(4, 19); // E <-> T
        wrong.swap(0, 14); // A <-> O
        assert!(words.coverage(&wrong) < MIN_COVERAGE_WITH_BREAKS);
        // Words with non-ASCII letters are left out
        assert_eq!(Words::new("café au lait").words.len(), 2);
        assert_eq!(Words::new("").coverage(&IDENTITY), 0.0);
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
