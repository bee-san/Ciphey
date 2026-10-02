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
    english::EnglishChecker,
    json_checker::JsonChecker,
    lemmeknow_checker::LemmeKnow,
    password::PasswordChecker,
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

            // In Ciphey if the user uses the regex checker all the other checkers turn off
            // This is because they are looking for one specific bit of information so will not want the other checkers
            let lemmeknow = Checker::<LemmeKnow>::new().with_sensitivity(self.sensitivity);
            let lemmeknow_result = lemmeknow.check(text);
            if lemmeknow_result.is_identified {
                let mut check_res = CheckResult::new(&lemmeknow);
                check_res.is_identified = true; // No human checker involvement
                check_res.text = lemmeknow_result.text;
                check_res.description = lemmeknow_result.description;

                // Store the result instead of returning immediately
                wait_athena_storage::add_plaintext_result(
                    check_res.text.clone(),
                    check_res.description.clone(),
                    lemmeknow.name.to_string(),
                    "LemmeKnow".to_string(),
                );

                // Continue checking by returning the result
                return check_res;
            }

            let json = Checker::<JsonChecker>::new().with_sensitivity(self.sensitivity);
            let json_result = json.check(text);
            if json_result.is_identified {
                let mut check_res = CheckResult::new(&json);
                check_res.is_identified = true; // No human checker involvement
                check_res.text = json_result.text;
                check_res.description = json_result.description;

                // Store the result instead of returning immediately
                wait_athena_storage::add_plaintext_result(
                    check_res.text.clone(),
                    check_res.description.clone(),
                    json.name.to_string(),
                    "JsonChecker".to_string(),
                );

                // Continue checking by returning the result
                return check_res;
            }

            let password = Checker::<PasswordChecker>::new().with_sensitivity(self.sensitivity);
            let password_result = password.check(text);
            if password_result.is_identified {
                let mut check_res = CheckResult::new(&password);
                check_res.is_identified = true; // No human checker involvement
                check_res.text = password_result.text;
                check_res.description = password_result.description;

                // Store the result instead of returning immediately
                wait_athena_storage::add_plaintext_result(
                    check_res.text.clone(),
                    check_res.description.clone(),
                    password.name.to_string(),
                    "PasswordChecker".to_string(),
                );

                // Continue checking by returning the result
                return check_res;
            }

            let english = Checker::<EnglishChecker>::new().with_sensitivity(self.sensitivity);
            let english_result = english.check(text);
            if english_result.is_identified {
                let mut check_res = CheckResult::new(&english);
                check_res.is_identified = true; // No human checker involvement
                check_res.text = english_result.text;
                check_res.description = english_result.description;

                // Store the result instead of returning immediately
                wait_athena_storage::add_plaintext_result(
                    check_res.text.clone(),
                    check_res.description.clone(),
                    english.name.to_string(),
                    "EnglishChecker".to_string(),
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
