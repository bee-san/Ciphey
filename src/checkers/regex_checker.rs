use gibberish_or_not::Sensitivity;
use lemmeknow::Identifier;

use super::checker_type::{Check, Checker};
use crate::{checkers::checker_result::CheckResult, config::get_config};
use log::trace;
use regex::Regex;
use std::sync::OnceLock;

/// The crib from the config and its compiled form.
static COMPILED_REGEX: OnceLock<(String, Regex)> = OnceLock::new();

/// The Regex Checker checks if the text matches a known Regex pattern.
/// This is the struct for it.
pub struct RegexChecker;

impl Check for Checker<RegexChecker> {
    fn new() -> Self {
        Checker {
            name: "Regex Checker",
            description: "Uses Regex to check for regex matches, useful for finding cribs.",
            link: "https://github.com/rust-lang/regex",
            tags: vec!["crib", "regex"],
            expected_runtime: 0.01,
            popularity: 1.0,
            lemmeknow_config: Identifier::default(),
            sensitivity: Sensitivity::Medium, // Default to Medium sensitivity
            enhanced_detector: None,
            _phantom: std::marker::PhantomData,
        }
    }

    fn check(&self, text: &str) -> CheckResult {
        trace!("Checking {} with regex", text);
        let config = get_config();
        let pattern = config.regex.as_deref().unwrap();
        // The config can't change once it is set, so the pattern is compiled once. If it
        // ever differs from the cached one, compile it fresh like before.
        let cached =
            COMPILED_REGEX.get_or_init(|| (pattern.to_string(), Regex::new(pattern).unwrap()));
        let uncached;
        let re = if cached.0 == pattern {
            &cached.1
        } else {
            uncached = Regex::new(pattern).unwrap();
            &uncached
        };

        let regex_check_result = re.is_match(text);
        let mut plaintext_found = false;
        let printed_name = format!("Regex matched: {re}");
        if regex_check_result {
            plaintext_found = true;
        }

        CheckResult {
            is_identified: plaintext_found,
            text: text.to_string(),
            checker_name: self.name,
            checker_description: self.description,
            description: printed_name,
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
