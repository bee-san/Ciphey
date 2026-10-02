//! English letter statistics used to score candidate plaintexts.
//!
//! * [`quadgram_score`]: how English a run of letters is, from the log probabilities of
//!   its letter quadgrams. It needs no spaces, so it is what the English checker uses for
//!   space-less candidates such as `THEQUICKBROWNFOX`, the usual output of classical
//!   ciphers.
//! * [`bigram_fitness`]: the same idea with letter bigrams. Caesar, railfence and ROT47
//!   use it to rank their candidates, so they only ask the checker about the best one.
//! * [`is_short_word`]: common English words of one to three characters. gibberish-or-not's
//!   dictionary can't be asked about words this short.
//!
//! [`quadgram_score`]: crate::storage::ngrams::quadgram_score
//! [`bigram_fitness`]: crate::storage::ngrams::bigram_fitness
//! [`is_short_word`]: crate::storage::ngrams::is_short_word
//!
//! `english_quadgrams.bin` and `english_short_words.txt` are generated from public-domain
//! books by `generate.py` in this directory; see that script for the method and the book
//! list. `english_bigrams.txt` is the bigram table the Vigenère decoder already used.

use once_cell::sync::Lazy;

/// Number of letter quadgrams, `AAAA` to `ZZZZ`.
const QUADGRAMS: usize = 26 * 26 * 26 * 26;

/// One byte per quadgram: `log10 P(quadgram) = -byte / QUADGRAM_SCALE`.
static QUADGRAM_TABLE: &[u8; QUADGRAMS] = include_bytes!("english_quadgrams.bin");

/// See `QUADGRAM_SCALE` in `generate.py`.
const QUADGRAM_SCALE: f64 = 25.0;

/// Common words of one to three characters, one per line, sorted.
static SHORT_WORDS: &str = include_str!("english_short_words.txt");

/// The words in [`SHORT_WORDS`].
static SHORT_WORD_LIST: Lazy<Vec<&'static str>> = Lazy::new(|| SHORT_WORDS.lines().collect());

/// Short words of modern English that the 19th-century books the list is built from
/// hardly use.
const MODERN_SHORT_WORDS: [&str; 10] = [
    "app", "hey", "hi", "id", "lol", "ok", "pc", "tv", "web", "wow",
];

/// `english_bigrams.txt` as log10 probabilities, indexed `[first][second]`.
static BIGRAMS: Lazy<[[f64; 26]; 26]> = Lazy::new(|| {
    let mut counts = [[0.0f64; 26]; 26];
    let mut total = 0.0;
    for line in include_str!("english_bigrams.txt").lines() {
        let mut fields = line.split_ascii_whitespace();
        let (Some(pair), Some(count)) = (fields.next(), fields.next()) else {
            continue;
        };
        let (Some(count), [a, b]) = (count.parse::<f64>().ok(), pair.as_bytes()) else {
            continue;
        };
        if a.is_ascii_alphabetic() && b.is_ascii_alphabetic() {
            counts[letter_index(*a)][letter_index(*b)] = count;
            total += count;
        }
    }
    let mut log_probabilities = [[0.0; 26]; 26];
    for (row, counts) in log_probabilities.iter_mut().zip(counts) {
        for (log_p, count) in row.iter_mut().zip(counts) {
            // Unseen pairs count as one occurrence
            *log_p = (count.max(1.0) / total).log10();
        }
    }
    log_probabilities
});

/// 0 for `a`/`A` to 25 for `z`/`Z`. Only call it on ASCII letters.
fn letter_index(letter: u8) -> usize {
    (letter.to_ascii_uppercase() - b'A') as usize
}

/// The mean log10 probability of the letter quadgrams in `text`, or `None` if it has
/// fewer than 4 ASCII letters.
///
/// Letters are case-folded and everything else is skipped, so `"Hello, World"` scores
/// the same as `"HELLOWORLD"`. English text scores about -4 to -5, random letters about
/// -7 and below.
///
/// ```
/// use ciphey::storage::ngrams::quadgram_score;
///
/// let english = quadgram_score("THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG").unwrap();
/// let shifted = quadgram_score("WKHTXLFNEURZQIRAMXPSVRYHUWKHODCBGRJ").unwrap();
/// assert!(english > shifted + 1.0);
/// assert_eq!(quadgram_score("abc"), None);
/// ```
pub fn quadgram_score(text: &str) -> Option<f64> {
    let (mut window, mut letters, mut sum) = (0usize, 0usize, 0u32);
    for letter in text.bytes().filter(u8::is_ascii_alphabetic) {
        window = (window * 26 + letter_index(letter)) % QUADGRAMS;
        letters += 1;
        if letters >= 4 {
            sum += u32::from(QUADGRAM_TABLE[window]);
        }
    }
    (letters >= 4).then(|| -f64::from(sum) / QUADGRAM_SCALE / (letters - 3) as f64)
}

/// The mean log10 probability of the letter bigrams in `text`, or `None` if it has
/// fewer than 2 ASCII letters. Letters are case-folded and everything else is skipped.
///
/// Used to rank the candidates of a cipher: the shift or key whose output scores
/// highest is the one most likely to be English.
pub fn bigram_fitness(text: &str) -> Option<f64> {
    let table: &[[f64; 26]; 26] = &BIGRAMS;
    let (mut previous, mut pairs, mut sum): (Option<usize>, usize, f64) = (None, 0, 0.0);
    for letter in text.bytes().filter(u8::is_ascii_alphabetic) {
        let index = letter_index(letter);
        if let Some(previous) = previous {
            sum += table[previous][index];
            pairs += 1;
        }
        previous = Some(index);
    }
    (pairs > 0).then(|| sum / pairs as f64)
}

/// Whether `word`, in lower case, is a common English word of one to three characters,
/// such as `a`, `is`, `me` or `i'm`.
pub fn is_short_word(word: &str) -> bool {
    SHORT_WORD_LIST.binary_search(&word).is_ok() || MODERN_SHORT_WORDS.contains(&word)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quadgram_table_has_one_entry_per_quadgram() {
        assert_eq!(QUADGRAM_TABLE.len(), 26usize.pow(4));
        let index = |q: &str| q.bytes().fold(0, |i, b| i * 26 + letter_index(b));
        let log_p = |q: &str| -f64::from(QUADGRAM_TABLE[index(q)]) / QUADGRAM_SCALE;
        // The most common quadgrams are around 0.5%
        assert!(log_p("TION") > -3.0, "{}", log_p("TION"));
        assert!(log_p("THAT") > -3.0, "{}", log_p("THAT"));
        // Unseen ones get the floor
        assert!(log_p("QXZJ") < -8.0, "{}", log_p("QXZJ"));
    }

    #[test]
    fn quadgram_score_separates_english_from_wrong_shifts() {
        let english = quadgram_score("WEAREDISCOVEREDFLEEATONCE").unwrap();
        let railfence = quadgram_score("WECRLTEERDSOEEFEAOCAIVDEN").unwrap();
        assert!(english > -5.0, "{english}");
        assert!(railfence < english - 1.0, "{railfence} vs {english}");
    }

    #[test]
    fn quadgram_score_ignores_case_and_non_letters() {
        assert_eq!(
            quadgram_score("Hello, World!"),
            quadgram_score("HELLOWORLD")
        );
        assert_eq!(quadgram_score("a1b2c"), None);
    }

    #[test]
    fn bigram_fitness_prefers_english() {
        let english = bigram_fitness("attack at dawn").unwrap();
        let shifted = bigram_fitness("dwwdfn dw gdzq").unwrap();
        assert!(english > shifted);
        assert_eq!(bigram_fitness("a"), None);
    }

    #[test]
    fn short_words() {
        for word in [
            "a", "i", "is", "me", "to", "at", "an", "no", "the", "i'm", "hi", "ok",
        ] {
            assert!(is_short_word(word), "{word}");
        }
        for word in ["xq", "zzz", "iii", "mr", "Is"] {
            assert!(!is_short_word(word), "{word}");
        }
    }

    #[test]
    fn short_word_list_is_sorted_lower_case_and_short() {
        let words: Vec<&str> = SHORT_WORDS.lines().collect();
        assert!(words.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(words
            .iter()
            .all(|w| (1..=3).contains(&w.len()) && *w == w.to_lowercase()));
    }
}
