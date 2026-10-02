use crate::checkers::checker_result::CheckResult;
use crate::checkers::checker_type::{Check, Checker};
use crate::config::get_config;
use gibberish_or_not::Sensitivity;
use lemmeknow::Identifier;
use log::trace;
#[cfg(test)]
use std::collections::HashSet;

/// WordlistChecker checks if the input text exactly matches any word in a user-provided wordlist
pub struct WordlistChecker;

impl Check for Checker<WordlistChecker> {
    fn new() -> Self {
        Checker {
            name: "Wordlist Checker",
            description:
                "Checks if the input text exactly matches any word in a user-provided wordlist",
            link: "",
            tags: vec!["wordlist", "exact-match"],
            expected_runtime: 0.01,
            popularity: 1.0,
            lemmeknow_config: Identifier::default(),
            sensitivity: Sensitivity::Medium, // Dummy value - not used by this checker
            _phantom: std::marker::PhantomData,
        }
    }

    fn check(&self, text: &str) -> CheckResult {
        let config = get_config();

        // Only run this checker if a wordlist is provided
        if let Some(wordlist) = &config.wordlist {
            trace!("Running wordlist checker with {} entries", wordlist.len());

            // Perform exact matching against the wordlist
            let is_match = wordlist.contains(text);

            if is_match {
                trace!("Found exact match in wordlist for: {}", text);
                let mut result = CheckResult::new(self);
                result.is_identified = true;
                result.text = text.to_string();
                result.description =
                    "text which matches an entry in the provided wordlist".to_string();
                return result;
            }

            trace!("No match found in wordlist for: {}", text);
        } else {
            trace!("Wordlist checker skipped - no wordlist provided");
        }

        // No match found or no wordlist provided
        CheckResult::new(self)
    }

    fn with_sensitivity(mut self, sensitivity: Sensitivity) -> Self {
        // Wordlist checker doesn't use sensitivity, but we need to implement this method
        // to satisfy the Check trait. The sensitivity value is stored but not used.
        self.sensitivity = sensitivity;
        self
    }

    fn get_sensitivity(&self) -> Sensitivity {
        // Return the stored sensitivity value, though it's not used for checking
        self.sensitivity
    }
}

// Extension methods for testing
#[cfg(test)]
impl Checker<WordlistChecker> {
    /// Check with a directly provided wordlist (for testing)
    fn check_with_wordlist(&self, text: &str, wordlist: &HashSet<String>) -> CheckResult {
        trace!("Running wordlist checker with {} entries", wordlist.len());

        // Perform exact matching against the wordlist
        let is_match = wordlist.contains(text);

        if is_match {
            trace!("Found exact match in wordlist for: {}", text);
            let mut result = CheckResult::new(self);
            result.is_identified = true;
            result.text = text.to_string();
            result.description = "Text matches an entry in the provided wordlist".to_string();
            return result;
        }

        trace!("No match found in wordlist for: {}", text);

        // No match found
        CheckResult::new(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_wordlist_match() {
        // Create a test wordlist
        let mut wordlist = HashSet::new();
        wordlist.insert("password123".to_string());
        wordlist.insert("hello".to_string());
        wordlist.insert("test".to_string());

        // Create checker and test
        let checker = Checker::<WordlistChecker>::new();

        // Print debug info to help diagnose the issue
        println!("Testing with wordlist containing: password123, hello, test");

        // Should match
        let result = checker.check_with_wordlist("hello", &wordlist);
        println!("Result for 'hello': is_identified={}", result.is_identified);
        assert!(result.is_identified);

        // Should not match
        let result = checker.check_with_wordlist("goodbye", &wordlist);
        println!(
            "Result for 'goodbye': is_identified={}",
            result.is_identified
        );
        assert!(!result.is_identified);
    }

    #[test]
    fn test_no_wordlist() {
        // Create an empty wordlist
        let wordlist = HashSet::new();

        // Create checker and test
        let checker = Checker::<WordlistChecker>::new();

        // Print debug info
        println!("Testing with empty wordlist");

        // Should not match anything when no wordlist is provided
        let result = checker.check_with_wordlist("hello", &wordlist);
        println!(
            "Result for 'hello' with empty wordlist: is_identified={}",
            result.is_identified
        );
        assert!(!result.is_identified);
    }
}
