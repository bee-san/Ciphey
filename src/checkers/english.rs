use crate::checkers::checker_result::CheckResult;
use gibberish_or_not::{is_gibberish, Sensitivity};
use lemmeknow::Identifier;

use crate::checkers::checker_type::{Check, Checker};
use crate::config::get_config;

/// Checks English plaintext.
pub struct EnglishChecker;

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
            enhanced_detector: None,
            sensitivity: Sensitivity::Medium, // Default to Medium sensitivity
            _phantom: std::marker::PhantomData,
        }
    }

    fn check(&self, text: &str) -> CheckResult {
        // Normalize before checking
        let normalised = normalise_string(text);

        // Get config to check if enhanced detection is enabled
        let config = get_config();
        let is_enhanced = config.enhanced_detection;

        let mut result = CheckResult {
            // Use a more sensitive setting if enhanced detection is enabled
            is_identified: if is_enhanced {
                // When enhanced detection is enabled, use a more sensitive setting
                // This is a simple approximation since we don't have the actual BERT model
                !is_gibberish(&normalised, Sensitivity::High)
            } else {
                !is_gibberish(&normalised, self.sensitivity)
            },
            // The text as given, not the normalised copy: this is what the human checker
            // asks about and what top results lists.
            text: text.to_string(),
            checker_name: self.name,
            checker_description: self.description,
            description: "Words".to_string(),
            link: self.link,
        };

        // Handle edge case of very short strings after normalization
        if normalised.len() < 2 {
            // Reduced from 3 since normalization may remove punctuation
            result.is_identified = false;
        }

        result
    }

    fn with_sensitivity(mut self, sensitivity: Sensitivity) -> Self {
        self.sensitivity = sensitivity;
        self
    }

    fn get_sensitivity(&self) -> Sensitivity {
        self.sensitivity
    }
}

/// Strings look funny, they might have commas, be uppercase etc
/// This normalises the string so English checker can work on it
/// In particular it:
/// Removes punctuation from the string
/// Lowercases the string
fn normalise_string(input: &str) -> String {
    // The replace function supports patterns https://doc.rust-lang.org/std/str/pattern/trait.Pattern.html#impl-Pattern%3C%27a%3E-3
    // TODO add more punctuation
    input
        .to_ascii_lowercase()
        .chars()
        .filter(|x| !x.is_ascii_punctuation())
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::checkers::english::normalise_string;
    use crate::checkers::{
        checker_type::{Check, Checker},
        english::EnglishChecker,
    };
    // Import Sensitivity directly
    use gibberish_or_not::Sensitivity;

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
        let x = normalise_string(".He/ll?O, Dea!r");
        assert_eq!(x, "hello dear")
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
}
