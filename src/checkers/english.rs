use crate::checkers::checker_result::CheckResult;
use crate::storage::ngrams::{is_short_word, quadgram_score, quadgram_score_and_letters};
use gibberish_or_not::{is_gibberish, Sensitivity};
use lemmeknow::Identifier;

use crate::checkers::checker_type::{Check, Checker};

/// Checks English plaintext.
///
/// The candidate is normalised first (see `normalise_string`), rejected if it looks like
/// decoder output (`looks_like_decoder_output`: words cased like `hHeREoUtHo`, mostly
/// symbols such as `!%TOO(NO`, unbalanced brackets), and then classified by shape. The
/// full list of rules and thresholds, and the benchmark they were tuned with, are in
/// `docs/plaintext-detection.md`.
///
/// 1. **Space-less letters** (no whitespace, at least `SPACELESS_MIN_LETTERS` (8) letters,
///    at least 90% letters), the usual output of Caesar, railfence and other classical
///    ciphers: the mean [quadgram score](crate::storage::ngrams::quadgram_score) must
///    reach the sensitivity's threshold, or the text must be one dictionary word. Up to
///    12 letters it must also split into known words (`HELLOWORLD`, not the railfence
///    shuffle `HWORLDELLO`), unless its quadgram score is very high: a long single word
///    like `experience` can't be looked up, since the dictionary only answers for 4 to
///    9 letters.
/// 2. **Mostly known words**: two or more words, at least one of three or more letters, of
///    which more than 80% are English words, counting the common one to three letter
///    words gibberish-or-not's dictionary lacks (`a`, `is`, `me` ...) and leaving numbers
///    out. So `call me` and `meet me at noon` pass, but not decoder output like `I A`.
///    Without whitespace the words must be separated by writing's punctuation.
/// 3. **Other text without whitespace** (digits or symbols mixed in, like
///    `ThI2THAtThE2THe0`), **one or two words**: only a single dictionary word passes, of
///    five or more letters at Low. gibberish-or-not's letter-pair scores accept too much
///    of this decoder junk.
/// 4. **Everything else**: rejected if its letters' quadgram score is below
///    `quadgram_veto`, far from any natural language (wrong Caesar shifts such as
///    `Max mkxtlnkx bl unkbxw ngwxk`), if no word is English, or if fewer than
///    `min_known_ratio` of the words are and it isn't in another language (reversed text,
///    wrong railfence keys, partly decrypted Vigenère); otherwise gibberish-or-not's
///    `is_gibberish` at the checker's sensitivity decides.
pub struct EnglishChecker;

/// Space-less text needs at least this many letters for its quadgram score to mean
/// anything. Shorter words are looked up in the dictionary instead.
const SPACELESS_MIN_LETTERS: usize = 8;

/// Space-less text up to this many letters must split into known words: a few quadgrams
/// can't tell English from a shuffle of it, like railfence's wrong keys.
const SPLIT_MAX_LETTERS: usize = 12;

/// ...unless it has at least [`SPLIT_EXEMPT_MIN_LETTERS`] letters and its quadgram score is
/// at least this. Most real words of 10 to 12 letters that can't be split score above it,
/// and the shuffles in the #1031 corpora below.
const SPLIT_EXEMPT_SCORE: f64 = -4.4;

/// Words up to 9 letters are in the dictionary, so only longer ones may need the exemption.
const SPLIT_EXEMPT_MIN_LETTERS: usize = 10;

/// A space-less candidate from a cipher whose key search games letter statistics (see
/// [`has_mostly_words`]) needs at least this share of its letters inside known words.
/// Real space-less sentences in the #1031 corpora are covered 94% of the time at this
/// level, Vigenère's wrong keys in the search 4%.
const SPACELESS_MIN_WORD_COVERAGE: f64 = 0.85;

/// Text with at least [`QUADGRAM_VETO_MIN_LETTERS`] letters that scores below this is not
/// English, whatever gibberish-or-not says. English, even ALL CAPS, names and code,
/// scores above -5.3 in the #1031 corpora, and French, German and Spanish above -6.5.
/// Reversed English and wrong Caesar shifts mostly score below. High, the most lenient
/// sensitivity, only vetoes text further away.
fn quadgram_veto(sensitivity: Sensitivity) -> f64 {
    match sensitivity {
        Sensitivity::Low | Sensitivity::Medium => -6.5,
        Sensitivity::High => -7.5,
    }
}

/// Fewer letters give too few quadgrams for the veto to be reliable.
const QUADGRAM_VETO_MIN_LETTERS: usize = 12;

/// The minimum mean quadgram score for space-less text at each sensitivity (Low is the
/// strictest). Chosen with the #1031 harness so that the issue's corpus
/// has no more false positives than before, and checked on held-out text.
fn quadgram_threshold(sensitivity: Sensitivity) -> f64 {
    match sensitivity {
        Sensitivity::Low => -5.1,
        Sensitivity::Medium => -5.3,
        Sensitivity::High => -5.6,
    }
}

/// given an input, check every item in the array and return true if any of them match
impl Check for Checker<EnglishChecker> {
    fn new() -> Self {
        Checker {
            name: "English Checker",
            description: "Uses gibberish detection to check if text is meaningful English",
            link: "https://crates.io/crates/gibberish-or-not",
            tags: vec!["english", "nlp"],
            expected_runtime: 0.01,
            popularity: 1.0,
            lemmeknow_config: Identifier::default(),
            sensitivity: Sensitivity::Medium, // Default to Medium sensitivity
            _phantom: std::marker::PhantomData,
        }
    }

    fn check(&self, text: &str) -> CheckResult {
        CheckResult {
            is_identified: is_english(text, self.sensitivity),
            // The text as given, not the normalised copy: this is what the human checker
            // asks about and what top results lists.
            text: text.to_string(),
            checker_name: self.name,
            checker_description: self.description,
            description: "Words".to_string(),
            link: self.link,
        }
    }

    fn with_sensitivity(mut self, sensitivity: Sensitivity) -> Self {
        self.sensitivity = sensitivity;
        self
    }

    fn get_sensitivity(&self) -> Sensitivity {
        self.sensitivity
    }
}

/// Whether `text` reads as English at `sensitivity`. See [`EnglishChecker`].
pub(crate) fn is_english(text: &str, sensitivity: Sensitivity) -> bool {
    let normalised = normalise_string(text);
    if normalised.is_empty() {
        return false;
    }
    let trimmed = text.trim();
    if looks_like_decoder_output(trimmed) {
        return false;
    }
    let spaceless = !trimmed.contains(char::is_whitespace);

    if spaceless && is_mostly_letters(trimmed) {
        if is_single_word(&normalised, sensitivity) {
            return true;
        }
        let Some(score) = quadgram_score(trimmed) else {
            return false;
        };
        if score < quadgram_threshold(sensitivity) {
            return false;
        }
        let letters: String = trimmed
            .chars()
            .filter(char::is_ascii_alphabetic)
            .map(|c| c.to_ascii_lowercase())
            .collect();
        return letters.len() > SPLIT_MAX_LETTERS
            || (letters.len() >= SPLIT_EXEMPT_MIN_LETTERS && score >= SPLIT_EXEMPT_SCORE)
            || splits_into_words(&letters);
    }

    let words: Vec<&str> = normalised.split(' ').collect();
    // Numbers are neither English nor not: `number 1 1 number 2 0 operation` is three
    // English words
    let alpha_words: Vec<&str> = words
        .iter()
        .copied()
        .filter(|word| word.chars().any(char::is_alphabetic))
        .collect();
    // Without spaces, words must be separated the way writing separates them
    // (`Hello,world!How`), and numbers count against them: `9=inn@on` and
    // `SO[\OTSTONTNOTTR` are junk
    let candidates: &[&str] = if spaceless { &words } else { &alpha_words };
    // Cheapest first: a quadgram score far from any language rejects text with spaces
    // before its words are looked up
    if !spaceless {
        let (score, letters) = quadgram_score_and_letters(trimmed);
        if letters >= QUADGRAM_VETO_MIN_LETTERS
            && score.is_some_and(|score| score < quadgram_veto(sensitivity))
        {
            return false;
        }
    }
    let known = known_words(candidates, min_known_ratio(sensitivity));
    if candidates.len() >= 2
        && known == Known::Mostly
        && (!spaceless || is_separated_like_writing(trimmed))
        && candidates.iter().any(|word| word.chars().count() >= 3)
    {
        return true;
    }
    if spaceless {
        return words.len() == 1 && is_single_word(words[0], sensitivity);
    }
    // Two words that aren't both words, like `terces pot` (reversed) or `peg knioge` (a
    // wrong railfence key)
    if alpha_words.len() <= 2 {
        return alpha_words.len() == 1 && is_single_word(alpha_words[0], sensitivity);
    }
    if known == Known::None || (known == Known::Few && !is_other_language(&alpha_words)) {
        return false;
    }
    !is_gibberish(&normalised, sensitivity)
}

/// Text with spaces needs at least this share of English words (one to three letter words
/// included), unless it is in another language (see [`is_other_language`]). In the
/// benchmark's English (benches/plaintext.rs) under 1% of sentences fall below half, and
/// almost all reversed text, wrong railfence keys and partly decrypted Vigenère do.
fn min_known_ratio(sensitivity: Sensitivity) -> f64 {
    match sensitivity {
        Sensitivity::Low | Sensitivity::Medium => 0.5,
        Sensitivity::High => 0.35,
    }
}

/// Whether `word` (lower case) is a common short word of French, German, Spanish,
/// Italian, Portuguese or Dutch that is not an English word. Ciphey doesn't claim to
/// recognise these languages, but gibberish-or-not accepts some of their sentences, and
/// two of these words keep text out of [`min_known_ratio`].
fn is_other_language_word(word: &str) -> bool {
    matches!(
        word,
        "aux"
            | "avec"
            | "ce"
            | "ces"
            | "cette"
            | "dans"
            | "des"
            | "du"
            | "est"
            | "il"
            | "je"
            | "la"
            | "le"
            | "les"
            | "mais"
            | "ne"
            | "nous"
            | "pas"
            | "pour"
            | "que"
            | "qui"
            | "sur"
            | "une"
            | "vous"
            | "das"
            | "dem"
            | "der"
            | "dich"
            | "ein"
            | "eine"
            | "für"
            | "ich"
            | "ist"
            | "mit"
            | "nicht"
            | "sehr"
            | "sie"
            | "uns"
            | "und"
            | "wir"
            | "zu"
            | "con"
            | "del"
            | "el"
            | "está"
            | "las"
            | "los"
            | "muy"
            | "por"
            | "una"
            | "di"
            | "che"
            | "non"
            | "per"
            | "sono"
            | "não"
            | "com"
            | "para"
            | "um"
            | "uma"
            | "een"
            | "het"
            | "niet"
            | "van"
    )
}

/// Whether at least two different words of `words` (lower case) are other languages'
/// words: see [`is_other_language_word`].
fn is_other_language(words: &[&str]) -> bool {
    let mut found: Option<&str> = None;
    for word in words {
        if is_other_language_word(word) {
            match found {
                Some(first) if first != *word => return true,
                _ => found = Some(word),
            }
        }
    }
    false
}

/// Whether `text` has the case, symbols or brackets of decoder output rather than of
/// writing:
///
/// * **case**: Caesar, Vigenère, Atbash and the like only change letters, so on mixed-case
///   input (Base64, random characters) they give words like `hHeREoUtHo`, `baLL` or
///   `NoNeININ` (see [`has_word_case`]). Rejected when more than a third of the words, or
///   any of three words or fewer, are cased like that.
/// * **symbols**: more than a third of the characters (spaces aside) are symbols and one of
///   them is in [`DECODER_SYMBOLS`], like `!%TOO(NO` or `%{DINe}.`. Code has symbols too,
///   but fewer: `x = [i * i for i in range(5)]` is a fifth.
/// * **brackets**: square or curly brackets that don't balance. Writing closes them; junk
///   such as `[bede 'cab'  'ea` doesn't.
///
/// One pass over the text: almost every text a search checks is rejected, and rejecting
/// it early is what keeps checking fast.
fn looks_like_decoder_output(text: &str) -> bool {
    let (mut words, mut odd_case) = (0usize, 0usize);
    let (mut chars, mut symbols, mut decoder_symbol) = (0usize, 0usize, false);
    let (mut square, mut curly) = (0i32, 0i32);
    let mut token_start: Option<usize> = None;
    let bytes = text.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if b.is_ascii_alphabetic() {
            token_start.get_or_insert(i);
        } else if let Some(start) = token_start.take() {
            words += 1;
            odd_case += usize::from(!has_word_case(&bytes[start..i]));
        }
        if b.is_ascii_whitespace() {
            continue;
        }
        // Count characters, not bytes: only the first byte of a UTF-8 sequence
        if b & 0xC0 != 0x80 {
            chars += 1;
        }
        if b.is_ascii_punctuation() {
            symbols += 1;
            decoder_symbol |= DECODER_SYMBOLS.as_bytes().contains(&b);
        } else if b >= 0x80 && b & 0xC0 != 0x80 {
            // A non-ASCII character that isn't a letter (`©`, `«`) counts as a symbol
            let c = text[i..].chars().next().unwrap_or_default();
            symbols += usize::from(!c.is_alphanumeric());
        }
        match b {
            b'[' => square += 1,
            b']' => square -= 1,
            b'{' => curly += 1,
            b'}' => curly -= 1,
            _ => {}
        }
    }
    if let Some(start) = token_start {
        words += 1;
        odd_case += usize::from(!has_word_case(&bytes[start..]));
    }
    (odd_case > 0 && (odd_case * 3 > words || words <= 3))
        || (decoder_symbol && symbols * 3 > chars)
        || square != 0
        || curly != 0
}

/// Whether a run of ASCII letters is cased the way written words are: all lower case, all
/// upper case, capitalised, or capitalised words run together (`GitHub`, `iPhone`,
/// `McDonald`, `URLs`).
fn has_word_case(token: &[u8]) -> bool {
    let upper = token.iter().filter(|c| c.is_ascii_uppercase()).count();
    if token.len() < 2 || upper == 0 || upper == token.len() {
        return true;
    }
    // An acronym's plural
    if token.ends_with(b"s") && upper == token.len() - 1 {
        return true;
    }
    // Otherwise every capital starts a lower case run: `GitHub`, not `HuB` or `aLL`
    token
        .iter()
        .zip(token.iter().skip(1).map(Some).chain(std::iter::once(None)))
        .all(|(c, next)| !c.is_ascii_uppercase() || next.is_some_and(u8::is_ascii_lowercase))
}

/// Punctuation that separates words in writing.
const WRITING_PUNCTUATION: &str = ".,!?;:'\"-()";

/// Whether every character of `text` that isn't a letter or digit is
/// [`WRITING_PUNCTUATION`].
fn is_separated_like_writing(text: &str) -> bool {
    text.chars()
        .all(|c| c.is_alphanumeric() || WRITING_PUNCTUATION.contains(c))
}

/// Symbols that decoders put in their output but writing hardly uses. `#`, `$`, `@`, `&`,
/// `/` and `_` are left out: `#42`, `$5`, `@name`, `and/or`, `snake_case`.
const DECODER_SYMBOLS: &str = "\\^[]{}|~=<>%*+`";

/// Whether `word` (lower case) is plaintext on its own: a dictionary word, of at least
/// [`LOW_MIN_WORD_LETTERS`] letters at Low sensitivity.
///
/// Low is what Caesar, ROT47, railfence and Vigenère check with. One in 150 strings of four
/// letters is in the dictionary, and those ciphers ask about the most English-looking of
/// their keys, so wrong keys find four-letter words often: `SHAG`, `MEAN`, `scut` and `AdEn`
/// ended searches of inputs with no plaintext. One in 2,000 strings of five letters is a
/// word.
fn is_single_word(word: &str, sensitivity: Sensitivity) -> bool {
    (sensitivity != Sensitivity::Low || word.chars().count() >= LOW_MIN_WORD_LETTERS)
        && is_dictionary_word(word)
}

/// See [`is_single_word`].
const LOW_MIN_WORD_LETTERS: usize = 5;

/// At least [`SPACELESS_MIN_LETTERS`] ASCII letters, and at least 90% of the characters.
fn is_mostly_letters(text: &str) -> bool {
    let (letters, chars) = text.chars().fold((0, 0), |(letters, chars), c| {
        (letters + usize::from(c.is_ascii_alphabetic()), chars + 1)
    });
    letters >= SPACELESS_MIN_LETTERS && letters * 10 >= chars * 9
}

/// Whether at least `min_ratio` of the words in `text` are English words, counting the
/// common one to three letter words. Text without whitespace that is mostly letters must
/// instead have at least [`SPACELESS_MIN_WORD_COVERAGE`] of its letters inside known
/// words; other text without whitespace (flags, URLs ...) passes.
///
/// For decoders whose key search maximises the very letter statistics the English checker
/// scores, like Vigenère: their wrong keys give text such as
/// `She sehls sea ohells xy the saa shora` or `theththttrictirm` that passes those checks,
/// but most of its "words" aren't words.
pub(crate) fn has_mostly_words(text: &str, min_ratio: f64) -> bool {
    let trimmed = text.trim();
    if !trimmed.contains(char::is_whitespace) {
        // The English checker rejects these anyway, and splitting long text into words
        // costs a dictionary lookup per letter and word length
        if !is_mostly_letters(trimmed)
            || quadgram_score(trimmed)
                .is_none_or(|score| score < quadgram_threshold(Sensitivity::High))
        {
            return true;
        }
        let letters: String = trimmed
            .chars()
            .filter(char::is_ascii_alphabetic)
            .map(|c| c.to_ascii_lowercase())
            .collect();
        return word_coverage(&letters) >= SPACELESS_MIN_WORD_COVERAGE;
    }
    let normalised = normalise_string(text);
    let words: Vec<&str> = normalised.split(' ').collect();
    let known = words.iter().filter(|word| is_known_word(word)).count();
    known as f64 >= min_ratio * words.len() as f64
}

/// The largest share of `letters` (lower case ASCII letters) that a split into English
/// words and leftover letters can put inside words: 1.0 for `meetmeatnoon`.
fn word_coverage(letters: &str) -> f64 {
    if letters.is_empty() {
        return 0.0;
    }
    // uncovered[i]: fewest letters of letters[..i] left outside words
    let mut uncovered = vec![usize::MAX; letters.len() + 1];
    uncovered[0] = 0;
    for start in 0..letters.len() {
        let here = uncovered[start];
        if here == usize::MAX {
            continue;
        }
        uncovered[start + 1] = uncovered[start + 1].min(here + 1);
        for end in start + 1..=(start + 9).min(letters.len()) {
            if uncovered[end] > here && is_known_word(&letters[start..end]) {
                uncovered[end] = here;
            }
        }
    }
    1.0 - uncovered[letters.len()] as f64 / letters.len() as f64
}

/// Whether `letters` (lower case ASCII letters) is a run of English words, such as
/// `meetmeatnoon`.
fn splits_into_words(letters: &str) -> bool {
    // reachable[i]: letters[..i] splits into words
    let mut reachable = vec![false; letters.len() + 1];
    reachable[0] = true;
    for start in 0..letters.len() {
        if !reachable[start] {
            continue;
        }
        // The dictionary only answers for words of up to 9 letters
        for end in start + 1..=(start + 9).min(letters.len()) {
            if !reachable[end] && is_known_word(&letters[start..end]) {
                reachable[end] = true;
            }
        }
    }
    reachable[letters.len()]
}

/// How many of a text's words are English words, as far as [`known_words`] needs to know.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Known {
    /// More than 80%
    Mostly,
    /// At least the floor, but not more than 80%
    Enough,
    /// Some, but fewer than the floor
    Few,
    /// None at all
    None,
}

/// How many of `words` (lower case) are English words: more than 80%, at least `floor`
/// (a share), fewer, or none. Stops looking words up as soon as the answer is clear:
/// every lookup is a dictionary search, and long texts have many words.
fn known_words(words: &[&str], floor: f64) -> Known {
    let n = words.len();
    let need = (floor * n as f64).ceil() as usize;
    let (mut known, mut unknown) = (0usize, 0usize);
    for (i, word) in words.iter().enumerate() {
        if is_known_word(word) {
            known += 1;
        } else {
            unknown += 1;
        }
        // known > 80% of words <=> unknown < 20% of words
        if unknown * 5 >= n {
            let left = n - i - 1;
            if known >= need.max(1) {
                return Known::Enough;
            }
            // Without a known word yet, keep looking: none at all is a stronger answer
            if known > 0 && known + left < need {
                return Known::Few;
            }
        }
    }
    match (known, unknown) {
        (0, _) => Known::None,
        (_, unknown) if unknown * 5 < n => Known::Mostly,
        (known, _) if known >= need => Known::Enough,
        _ => Known::Few,
    }
}

/// Whether `word` (lower case, letters and apostrophes) is an English word.
pub(crate) fn is_known_word(word: &str) -> bool {
    if !word.chars().all(|c| c.is_alphabetic() || c == '\'') {
        return false;
    }
    match word.chars().count() {
        0 => false,
        1..=3 => is_short_word(word),
        4..=9 => is_dictionary_word(word),
        // Too long to look up on its own (see `is_dictionary_word`): a word if it splits
        // into words (`understanding`, `throughout`) or its quadgrams are very English
        // (`congratulations`). Wrong keys make long strings of English letters
        // (`otstontnottr`, `hegifidded`) that a looser score let through.
        _ => quadgram_score(word).is_some_and(|score| {
            (score >= LONG_WORD_MIN_SCORE && has_varied_letters(word))
                || (score >= LONG_WORD_SPLIT_MIN_SCORE
                    && word.bytes().all(|b| b.is_ascii_lowercase())
                    && splits_into_words(word))
        }),
    }
}

/// Words of 10 or more letters that don't split into words must score at least this. Of
/// the long words in the benchmark's plaintext 93% split or reach it (`photography`
/// doesn't), of those in its near misses 6%.
const LONG_WORD_MIN_SCORE: f64 = -4.6;

/// Whether a word has as many different letters as words of its length do: at least 45%
/// up to 16 letters. Wrong keys on digit strings use a handful of letters
/// (`otstontnottr`); `mississippi` is a rare word that doesn't pass.
fn has_varied_letters(word: &str) -> bool {
    let letters = word.chars().count();
    if letters > 16 {
        return true;
    }
    let mut seen = [false; 128];
    let mut distinct = 0usize;
    for b in word.bytes().filter(u8::is_ascii) {
        if !seen[usize::from(b)] {
            seen[usize::from(b)] = true;
            distinct += 1;
        }
    }
    distinct * 20 >= letters * 9
}

/// Long words scoring below this aren't split into words at all: splitting costs a
/// dictionary lookup per letter and word length, and nothing that low is English.
const LONG_WORD_SPLIT_MIN_SCORE: f64 = -5.6;

/// Whether `word` (lower case) is in gibberish-or-not's dictionary.
///
/// gibberish-or-not only looks a text up in its dictionary when it is 4 to 9 bytes long:
/// it rejects anything shorter outright and scores anything longer.
fn is_dictionary_word(word: &str) -> bool {
    (4..10).contains(&word.len()) && !is_gibberish(word, Sensitivity::Medium)
}

/// Strings look funny, they might have commas, be uppercase etc
/// This normalises the string so English checker can work on it
/// In particular it:
/// * lowercases the string,
/// * turns punctuation into spaces, so `Hello,world!How` is three words and not
///   `helloworldhow`, except for apostrophes inside a word (`don't`, `o'clock`), which
///   the dictionary spells with them,
/// * and collapses runs of whitespace into one space, trimming both ends.
fn normalise_string(input: &str) -> String {
    let chars: Vec<char> = input.chars().collect();
    let mut normalised = String::with_capacity(input.len());
    for (i, &c) in chars.iter().enumerate() {
        let in_word_apostrophe = c == '\''
            && i > 0
            && chars[i - 1].is_alphabetic()
            && chars.get(i + 1).is_some_and(|next| next.is_alphabetic());
        let c = if (c.is_ascii_punctuation() && !in_word_apostrophe) || c.is_whitespace() {
            ' '
        } else {
            c.to_ascii_lowercase()
        };
        // No leading space and no runs of spaces
        if c != ' ' || (!normalised.is_empty() && !normalised.ends_with(' ')) {
            normalised.push(c);
        }
    }
    if normalised.ends_with(' ') {
        normalised.pop();
    }
    normalised
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkers::{
        checker_type::{Check, Checker},
        english::EnglishChecker,
    };
    // Import Sensitivity directly
    use gibberish_or_not::Sensitivity;

    fn english(text: &str, sensitivity: Sensitivity) -> bool {
        Checker::<EnglishChecker>::new()
            .with_sensitivity(sensitivity)
            .check(text)
            .is_identified
    }

    #[test]
    fn test_check_basic() {
        let checker = Checker::<EnglishChecker>::new();
        assert!(checker.check("preinterview").is_identified);
    }

    #[test]
    fn test_check_basic2() {
        let checker = Checker::<EnglishChecker>::new();
        assert!(checker.check("exuberant").is_identified);
    }

    #[test]
    fn test_check_multiple_words() {
        let checker = Checker::<EnglishChecker>::new();
        assert!(
            checker
                .check("this is a valid english sentence")
                .is_identified
        );
    }

    #[test]
    fn test_check_non_dictionary_word() {
        let checker = Checker::<EnglishChecker>::new();
        assert!(
            !checker
                .check("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaBabyShark")
                .is_identified
        );
    }

    #[test]
    fn test_check_multiple_words2() {
        let checker = Checker::<EnglishChecker>::new();
        assert!(checker.check("preinterview hello dog").is_identified);
    }
    #[test]
    fn test_check_normalise_string_works_with_lowercasing() {
        let x = normalise_string("Hello Dear");
        assert_eq!(x, "hello dear")
    }
    #[test]
    fn test_check_normalise_string_works_with_puncuation() {
        let x = normalise_string("Hello, Dear");
        assert_eq!(x, "hello dear")
    }
    #[test]
    fn test_check_normalise_string_works_with_messy_puncuation() {
        // Punctuation separates words instead of being deleted
        let x = normalise_string(".He/ll?O, Dea!r");
        assert_eq!(x, "he ll o dea r")
    }

    #[test]
    fn normalise_string_keeps_apostrophes_inside_words() {
        assert_eq!(normalise_string("Don't stop!"), "don't stop");
        assert_eq!(
            normalise_string("Rock'n'roll isn't dead"),
            "rock'n'roll isn't dead"
        );
        assert_eq!(
            normalise_string("Item #42: 'fragile' - handle"),
            "item 42 fragile handle"
        );
        assert_eq!(
            normalise_string("Hello,world!How are\tyou?"),
            "hello world how are you"
        );
        assert_eq!(normalise_string("  ?!  "), "");
    }

    #[test]
    fn test_checker_works_with_puncuation_and_lowercase() {
        // Punctuation separates words (it used to be deleted, which made
        // `Prei?nterview He!llo` read as `preinterview hello`)
        let checker = Checker::<EnglishChecker>::new();
        assert!(checker.check("Preinterview? Hello, Dog!").is_identified);
    }

    #[test]
    fn test_check_result_has_the_original_text() {
        // The text is normalised for detection only. Returning the normalised copy made the
        // human checker ask about "hello world" when the candidate was "Hello, World!".
        let checker = Checker::<EnglishChecker>::new();
        let result = checker.check("Hello, World!");
        assert!(result.is_identified);
        assert_eq!(result.text, "Hello, World!");
    }

    #[test]
    fn test_check_fail_single_puncuation_char() {
        let checker = Checker::<EnglishChecker>::new();
        assert!(!checker.check("#").is_identified);
        assert!(!checker.check("").is_identified);
    }

    #[test]
    fn short_phrases_with_one_and_two_letter_words() {
        // gibberish-or-not's dictionary has no words shorter than three letters, and
        // text under 10 characters had to be a single dictionary word
        for phrase in [
            "call me",
            "hi there",
            "is it in the box",
            "meet me at noon",
            "I'm here",
        ] {
            assert!(english(phrase, Sensitivity::Low), "{phrase}");
        }
        // One word must still be a real word of four or more letters, and a few one and
        // two letter words aren't enough
        for not_english in [
            "yes",
            "an",
            "xq zv",
            "BYFFIQILFX",
            "I A",
            "a i a i",
            "is it",
        ] {
            assert!(!english(not_english, Sensitivity::Medium), "{not_english}");
        }
    }

    #[test]
    fn punctuation_separates_words() {
        assert!(english("Wait... what?!", Sensitivity::Low));
        assert!(english("Hello,world!How are you?", Sensitivity::Low));
        assert!(english("Don't stop believing!", Sensitivity::Low));
    }

    #[test]
    fn spaceless_text_uses_quadgrams() {
        for text in [
            "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG",
            "WEAREDISCOVEREDFLEEATONCE",
            "HELLOWORLD",
            "attackatdawn",
        ] {
            assert!(english(text, Sensitivity::Low), "{text}");
        }
        for junk in [
            "WKHTXLFNEURZQIRAMXPSVRYHUWKHODCBGRJ", // Caesar +3
            "WECRLTEERDSOEEFEAOCAIVDEN",           // railfence, 3 rails
            "BYFFIQILFX",                          // a wrong Caesar shift of HELLOWORLD
            "TISUYYOQVTHERBMEITHAATNMONOERETOHTH",
            // Wrong railfence keys: English letters and quadgrams, but no words
            "HWORLDELLO",
            "KATWANTATCAD",
            "MORGINGOOND",
        ] {
            assert!(!english(junk, Sensitivity::Medium), "{junk}");
        }
    }

    #[test]
    fn short_spaceless_text_must_split_into_words() {
        assert!(splits_into_words("meetmeatnoon"));
        assert!(splits_into_words("goodmorning"));
        assert!(!splits_into_words("katwantatcad"));
        // A long word the dictionary can't be asked about passes on its quadgram score
        assert!(english("EXPERIENCE", Sensitivity::Low));
        assert!(english("MEETMEATNOON", Sensitivity::Low));
        // Below 10 letters words are in the dictionary, so a high score isn't enough
        assert!(!english("THRETHAN", Sensitivity::Low));
    }

    #[test]
    fn spaceless_decoder_junk_with_digits_is_not_english() {
        // Vigenere and Reverse outputs on base64 input that used to be accepted
        for junk in [
            "ThI2THAtThE2THe0",
            "==FRiERthI2N",
            "nthaNANHfilES020ERUErI0ntt1=hHHe",
            "ToEterNth2EtkoLhALNhE2NheHIoNAE1NGDttHriNHmeSR==",
            "==EatIThiThowXmEwfINoNos",
        ] {
            assert!(!english(junk, Sensitivity::Medium), "{junk}");
        }
        // A single word with punctuation is still a word
        assert!(english("Hello!", Sensitivity::Low));
    }

    #[test]
    fn spaced_text_far_from_english_is_not_english() {
        // Accepted by gibberish-or-not at Medium; a wrong Caesar shift and a Reverse ->
        // Caesar output from the #1031 end-to-end cases
        for junk in [
            "Max mkxtlnkx bl unkbxw ngwxk max hew htd mkxx gxtk max kboxk",
            "gjebrd him yd ufoit him rcho xetw lto fop xhv ufwnw gfbrwe tb etxttetw faT",
            // No English word in it at all
            "Boa rsnerW f  gahfnmemuftirenon h",
        ] {
            assert!(!english(junk, Sensitivity::Medium), "{junk}");
        }
        // Other languages are not English either, but are far enough from junk to pass
        // where gibberish-or-not accepts them
        assert!(english(
            "Je ne sais pas ce que tu veux dire",
            Sensitivity::Medium
        ));
    }

    #[test]
    fn has_mostly_words_counts_known_words() {
        // Wrong-key Vigenère outputs from the #1031 harness
        assert!(!has_mostly_words(
            "She sehls sea ohells xy the saa shora every oummer iorninc",
            0.7
        ));
        assert!(!has_mostly_words(
            "Attask the nerth gaje at damn and held the rridge kntil neon",
            0.7
        ));
        assert!(has_mostly_words(
            "She sells sea shells by the sea shore every summer morning",
            0.7
        ));
        // 11 of 15 words: a near miss from the search
        assert!(!has_mostly_words(
            "1HE TREASURE IS BURIED UNDER THE OLD OAK TREE NEAR THE RIVER [W MPG [OZEQF",
            0.75
        ));
        // Without spaces, the share of letters inside words counts
        assert!(has_mostly_words("THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG", 0.7));
        assert!(!has_mostly_words("theththttrictirm", 0.7));
        assert!(!has_mostly_words("QTHEDTHINTHEHYTHRYATATHV", 0.7));
        assert!(
            has_mostly_words("picoCTF{b4s3_64_1s_fun}", 0.7),
            "not mostly letters"
        );
        assert!((word_coverage("meetmeatnoon") - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_default_sensitivity_is_medium() {
        let checker = Checker::<EnglishChecker>::new();
        assert!(matches!(checker.get_sensitivity(), Sensitivity::Medium));
    }

    #[test]
    fn test_with_sensitivity_changes_sensitivity() {
        let checker = Checker::<EnglishChecker>::new().with_sensitivity(Sensitivity::Low);
        assert!(matches!(checker.get_sensitivity(), Sensitivity::Low));

        let checker = Checker::<EnglishChecker>::new().with_sensitivity(Sensitivity::High);
        assert!(matches!(checker.get_sensitivity(), Sensitivity::High));
    }

    #[test]
    fn test_sensitivity_affects_gibberish_detection() {
        // A Vigenère decryption with one key letter wrong: about half of its words are
        // words. High, the most lenient sensitivity, still takes it.
        let text = "let me jnow whdn you gdt home";
        assert!(!english(text, Sensitivity::Low));
        assert!(!english(text, Sensitivity::Medium));
        assert!(english(text, Sensitivity::High));
        // Junk with one English word in it is rejected at every sensitivity
        let junk = "Rcl maocr otmwi lit dnoen oehc 13 iron seah.";
        for sensitivity in [Sensitivity::Low, Sensitivity::Medium, Sensitivity::High] {
            assert!(!english(junk, sensitivity), "{sensitivity:?}");
        }
    }

    #[test]
    fn decoder_case_is_not_english() {
        // Caesar, Vigenère and the like keep the case of mixed-case input
        for junk in [
            "hHeREoUtHo",
            "baLL^^",
            "NoNeININ",
            "EnDTHEMEtALtInv",
            "doRa-(mE",
            "uoY era",
        ] {
            assert!(!english(junk, Sensitivity::Medium), "{junk}");
        }
        for text in [
            "GitHub is down again",
            "my iPhone died",
            "McDonald's is open late",
            "Use HTTPS URLs for the API",
            "TheQuickBrownFox",
        ] {
            assert!(english(text, Sensitivity::Medium), "{text}");
        }
    }

    #[test]
    fn symbol_junk_is_not_english() {
        for junk in [
            "!%TOO(NO",
            "%{DINe}.",
            "9=inn@on",
            "SO[\\OTSTONTNOTTR",
            "[bede 'cab'  'ea",
        ] {
            assert!(!english(junk, Sensitivity::Medium), "{junk}");
        }
        for text in [
            "The cost is $5.99 - a bargain!",
            "Item #42: 'fragile' - handle with care.",
            "Hello,world!How are you?",
            "meet at 221 Baker Street at 7",
        ] {
            assert!(english(text, Sensitivity::Medium), "{text}");
        }
    }

    #[test]
    fn most_words_must_be_words() {
        // Reversed text, wrong railfence keys and partly decrypted Vigenère
        for junk in [
            "terces pot",
            "peg knioge",
            ".gnidoced peek ,resolc gnitteg era uoY",
            "where zre you? ve're wahting ottside",
            "so otstontnottr",
            "_hegifidded  if ",
        ] {
            assert!(!english(junk, Sensitivity::Medium), "{junk}");
        }
        for text in [
            "Sherlock Holmes",
            "hello world",
            "Congratulations on the new job!!",
            "understanding cryptography takes time",
        ] {
            assert!(english(text, Sensitivity::Medium), "{text}");
        }
    }

    #[test]
    fn single_words_need_five_letters_at_low() {
        // Low is what Caesar, ROT47, railfence and Vigenère check with
        assert!(!english("SHAG", Sensitivity::Low));
        assert!(english("SHAG", Sensitivity::Medium));
        assert!(english("attack", Sensitivity::Low));
        assert!(english("Hello!", Sensitivity::Low));
    }

    #[test]
    fn quadgram_thresholds_get_more_lenient_from_low_to_high() {
        assert!(quadgram_threshold(Sensitivity::Low) > quadgram_threshold(Sensitivity::Medium));
        assert!(quadgram_threshold(Sensitivity::Medium) > quadgram_threshold(Sensitivity::High));
    }
}
