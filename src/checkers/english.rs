use crate::checkers::checker_result::CheckResult;
use crate::storage::ngrams::{is_short_word, quadgram_score};
use gibberish_or_not::{is_gibberish, Sensitivity};
use lemmeknow::Identifier;

use crate::checkers::checker_type::{Check, Checker};

/// Checks English plaintext.
///
/// The candidate is normalised first (see `normalise_string`) and then classified by
/// shape:
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
///    words gibberish-or-not's dictionary lacks (`a`, `is`, `me` ...). This is
///    gibberish-or-not's own "almost every word is English" rule with those words added,
///    so `call me` and `meet me at noon` pass, but not decoder output like `I A`.
/// 3. **Other text without whitespace** (digits or symbols mixed in, like
///    `ThI2THAtThE2THe0`): only a single dictionary word passes. gibberish-or-not's
///    letter-pair scores accept too much of this decoder junk.
/// 4. **Everything else**: gibberish-or-not's `is_gibberish` at the checker's sensitivity,
///    unless the letters' quadgram score is below `quadgram_veto`, far from any natural
///    language (wrong Caesar shifts such as `Max mkxtlnkx bl unkbxw ngwxk`, reversed text),
///    or three or more words contain not a single English word.
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
/// strictest). Chosen with `examples/plaintext_eval.rs` so that the issue #1031 corpus
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
fn is_english(text: &str, sensitivity: Sensitivity) -> bool {
    let normalised = normalise_string(text);
    if normalised.is_empty() {
        return false;
    }
    let trimmed = text.trim();
    let spaceless = !trimmed.contains(char::is_whitespace);

    if spaceless && is_mostly_letters(trimmed) {
        if is_dictionary_word(&normalised) {
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
    if words.len() >= 2
        && words.iter().any(|word| word.chars().count() >= 3)
        && mostly_known_words(&words)
    {
        return true;
    }
    if spaceless {
        return words.len() == 1 && is_dictionary_word(words[0]);
    }
    if words.len() >= 3 && !words.iter().any(|word| is_known_word(word)) {
        return false;
    }
    if trimmed.bytes().filter(u8::is_ascii_alphabetic).count() >= QUADGRAM_VETO_MIN_LETTERS
        && quadgram_score(trimmed).is_some_and(|score| score < quadgram_veto(sensitivity))
    {
        return false;
    }
    !is_gibberish(&normalised, sensitivity)
}

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

/// Whether more than 80% of `words` (lower case) are English words.
fn mostly_known_words(words: &[&str]) -> bool {
    // known > 80% of words <=> unknown < 20% of words
    let mut unknown = 0;
    for word in words {
        if !is_known_word(word) {
            unknown += 1;
            if unknown * 5 >= words.len() {
                return false;
            }
        }
    }
    true
}

/// Whether `word` (lower case, letters and apostrophes) is an English word.
fn is_known_word(word: &str) -> bool {
    if !word.chars().all(|c| c.is_alphabetic() || c == '\'') {
        return false;
    }
    match word.chars().count() {
        0 => false,
        1..=3 => is_short_word(word),
        4..=9 => is_dictionary_word(word),
        // Too long to look up on its own (see `is_dictionary_word`), but long words
        // carry enough quadgrams to tell
        _ => {
            quadgram_score(word).is_some_and(|score| score >= quadgram_threshold(Sensitivity::Low))
        }
    }
}

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
        let checker = Checker::<EnglishChecker>::new();
        assert!(checker.check("Prei?nterview He!llo Dog?").is_identified);
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
        // Wrong-key Vigenère outputs from examples/plaintext_eval.rs
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
        // This text has one English word "iron" but is otherwise gibberish
        let text = "Rcl maocr otmwi lit dnoen oehc 13 iron seah.";

        // With Low sensitivity, it should be classified as gibberish
        let low_checker = Checker::<EnglishChecker>::new().with_sensitivity(Sensitivity::Low);
        assert!(!low_checker.check(text).is_identified);

        // With High sensitivity, it should be classified as English
        let high_checker = Checker::<EnglishChecker>::new().with_sensitivity(Sensitivity::High);
        assert!(high_checker.check(text).is_identified);
    }

    #[test]
    fn quadgram_thresholds_get_more_lenient_from_low_to_high() {
        assert!(quadgram_threshold(Sensitivity::Low) > quadgram_threshold(Sensitivity::Medium));
        assert!(quadgram_threshold(Sensitivity::Medium) > quadgram_threshold(Sensitivity::High));
    }
}
