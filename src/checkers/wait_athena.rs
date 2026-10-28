/// WaitAthena checker is a variant of Athena that collects all plaintexts found during the search.
/// While Athena exits immediately when a plaintext is found, WaitAthena continues checking and
/// stores all plaintexts it finds until the timer expires.
/// Unlike Athena, WaitAthena does not use the human checker and automatically accepts all potential plaintexts.
use crate::{checkers::checker_result::CheckResult, config::get_config};
use gibberish_or_not::Sensitivity;
use lemmeknow::Identifier;
use log::trace;

use crate::storage::wait_athena_storage;

use super::{
    checker_type::{Check, Checker},
    identify_plaintext,
    regex_checker::RegexChecker,
    wordlist::WordlistChecker,
};

/// WaitAthena checker runs all other checkers and stores results for later display
/// This is identical to Athena but instead of returning immediately, it stores results
/// and continues checking until the timer expires
pub struct WaitAthena;

impl Check for Checker<WaitAthena> {
    fn new() -> Self {
        Checker {
            name: "WaitAthena Checker",
            description: "Runs all available checkers and stores results until timer expires",
            link: "",
            tags: vec!["wait_athena", "all"],
            expected_runtime: 1.0,
            popularity: 1.0,
            lemmeknow_config: Identifier::default(),
            sensitivity: Sensitivity::Medium, // Default to Medium sensitivity
            _phantom: std::marker::PhantomData,
        }
    }

    fn check(&self, text: &str) -> CheckResult {
        let config = get_config();

        // If regex is specified, only run the regex checker
        // operates exactly the same as athena
        if config.regex.is_some() {
            trace!("running regex");
            let regex_checker = Checker::<RegexChecker>::new().with_sensitivity(self.sensitivity);
            let regex_result = regex_checker.check(text);
            if regex_result.is_identified {
                let mut check_res = CheckResult::new(&regex_checker);
                check_res.is_identified = true; // No human checker involvement
                check_res.text = regex_result.text;
                check_res.description = regex_result.description;

                // Store the result instead of returning immediately
                wait_athena_storage::add_plaintext_result(
                    check_res.text.clone(),
                    check_res.description.clone(),
                    regex_checker.name.to_string(),
                    "RegexChecker".to_string(),
                );

                // Continue checking by returning the result
                return check_res;
            }
        } else {
            // Run wordlist checker first if a wordlist is provided
            if config.wordlist.is_some() {
                trace!("running wordlist checker");
                let wordlist_checker =
                    Checker::<WordlistChecker>::new().with_sensitivity(self.sensitivity);
                let wordlist_result = wordlist_checker.check(text);
                if wordlist_result.is_identified {
                    let mut check_res = CheckResult::new(&wordlist_checker);
                    check_res.is_identified = true; // No human checker involvement
                    check_res.text = wordlist_result.text;
                    check_res.description = wordlist_result.description;

                    // Store the result instead of returning immediately
                    wait_athena_storage::add_plaintext_result(
                        check_res.text.clone(),
                        check_res.description.clone(),
                        wordlist_checker.name.to_string(),
                        "WordlistChecker".to_string(),
                    );

                    // Continue checking by returning the result
                    return check_res;
                }
            }

            if let Some(found) = identify_plaintext(text, self.sensitivity) {
                let kind = found.kind;
                let check_res = found.into_result(text); // No human checker involvement

                // Store the result instead of returning immediately
                wait_athena_storage::add_plaintext_result(
                    check_res.text.clone(),
                    check_res.description.clone(),
                    check_res.checker_name.to_string(),
                    kind.to_string(),
                );

                // Continue checking by returning the result
                return check_res;
            }
        }

        CheckResult::new(self)
    }

    fn with_sensitivity(mut self, sensitivity: Sensitivity) -> Self {
        self.sensitivity = sensitivity;
        self
    }

    fn get_sensitivity(&self) -> Sensitivity {
        self.sensitivity
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gibberish_or_not::Sensitivity;

    #[test]
    fn test_check_english_sentence() {
        let checker = Checker::<WaitAthena>::new();
        assert!(checker.check("test valid english sentence").is_identified);
    }

    #[test]
    fn test_check_dictionary_word() {
        let checker = Checker::<WaitAthena>::new();
        assert!(checker.check("exuberant").is_identified);
    }

    #[test]
    fn test_check_json_and_ctf_flags() {
        let checker = Checker::<WaitAthena>::new();
        let json = checker.check("[{\"id\": 1, \"title\": \"hello world\"}]");
        assert!(json.is_identified);
        assert_eq!(json.checker_name, "JSON Checker");
        assert!(checker.check("DUCTF{d0wn_und3r}").is_identified);
    }

    #[test]
    fn test_default_sensitivity_is_medium() {
        let checker = Checker::<WaitAthena>::new();
        assert!(matches!(checker.get_sensitivity(), Sensitivity::Medium));
    }

    #[test]
    fn test_with_sensitivity_changes_sensitivity() {
        let checker = Checker::<WaitAthena>::new().with_sensitivity(Sensitivity::Low);
        assert!(matches!(checker.get_sensitivity(), Sensitivity::Low));

        let checker = Checker::<WaitAthena>::new().with_sensitivity(Sensitivity::High);
        assert!(matches!(checker.get_sensitivity(), Sensitivity::High));
    }
}
