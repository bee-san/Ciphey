/// Athena checker runs all other checkers and returns immediately when a plaintext is found.
/// This is the standard checker that exits early when a plaintext is found.
/// For a version that continues checking and collects all plaintexts, see WaitAthena.
use crate::{checkers::checker_result::CheckResult, config::get_config};
use gibberish_or_not::Sensitivity;
use lemmeknow::Identifier;
use log::trace;

use super::{
    checker_type::{Check, Checker},
    english::EnglishChecker,
    human_checker,
    json_checker::JsonChecker,
    lemmeknow_checker::LemmeKnow,
    password::PasswordChecker,
    regex_checker::RegexChecker,
    wordlist::WordlistChecker,
};

/// Athena checker runs all other checkers
pub struct Athena;

impl Check for Checker<Athena> {
    fn new() -> Self {
        Checker {
            // TODO: Update fields with proper values
            name: "Athena Checker",
            description: "Runs all available checkers",
            link: "",
            tags: vec!["athena", "all"],
            expected_runtime: 0.01,
            popularity: 1.0,
            lemmeknow_config: Identifier::default(),
            sensitivity: Sensitivity::Medium, // Default to Medium sensitivity
            _phantom: std::marker::PhantomData,
        }
    }

    /// Runs the checkers in order and stops at the first that identifies `text`:
    ///
    /// * with a `--regex` crib, only the regex checker,
    /// * otherwise the wordlist (if there is one), LemmeKnow (known formats and CTF
    ///   flags), JSON, the common-password list and finally the English checker.
    ///
    /// The human checker then has the last word on that candidate.
    fn check(&self, text: &str) -> CheckResult {
        trace!("Athena checker running on text: {}", text);
        let config = get_config();

        // In Ciphey if the user uses the regex checker all the other checkers turn off
        // This is because they are looking for one specific bit of information so will not want the other checkers
        if config.regex.is_some() {
            trace!("running regex");
            let regex_checker = Checker::<RegexChecker>::new().with_sensitivity(self.sensitivity);
            let regex_result = regex_checker.check(text);
            if regex_result.is_identified {
                return confirm(&regex_checker, regex_result);
            }
            return CheckResult::new(self);
        }

        // Run wordlist checker first if a wordlist is provided
        if config.wordlist.is_some() {
            trace!("running wordlist checker");
            let wordlist_checker =
                Checker::<WordlistChecker>::new().with_sensitivity(self.sensitivity);
            let wordlist_result = wordlist_checker.check(text);
            if wordlist_result.is_identified {
                return confirm(&wordlist_checker, wordlist_result);
            }
        }

        // TODO: wrap all checkers in oncecell so we only create them once!
        let lemmeknow = Checker::<LemmeKnow>::new().with_sensitivity(self.sensitivity);
        let lemmeknow_result = lemmeknow.check(text);
        if lemmeknow_result.is_identified {
            return confirm(&lemmeknow, lemmeknow_result);
        }

        let json = Checker::<JsonChecker>::new().with_sensitivity(self.sensitivity);
        let json_result = json.check(text);
        if json_result.is_identified {
            return confirm(&json, json_result);
        }

        let password = Checker::<PasswordChecker>::new().with_sensitivity(self.sensitivity);
        let password_result = password.check(text);
        if password_result.is_identified {
            return confirm(&password, password_result);
        }

        let english = Checker::<EnglishChecker>::new().with_sensitivity(self.sensitivity);
        let english_result = english.check(text);
        if english_result.is_identified {
            return confirm(&english, english_result);
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

/// Asks the human checker about `found`, which `checker` identified, and returns the
/// answer as that checker's result.
fn confirm<Type>(checker: &Checker<Type>, found: CheckResult) -> CheckResult {
    let human_result = human_checker::human_checker(&found);
    trace!(
        "Human checker called from {} with result: {}",
        checker.name,
        human_result
    );
    let mut check_res = CheckResult::new(checker);
    check_res.is_identified = human_result;
    check_res.text = found.text;
    check_res.description = found.description;
    check_res
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identify(text: &str) -> CheckResult {
        Checker::<Athena>::new().check(text)
    }

    #[test]
    fn flags_json_and_short_phrases_are_found() {
        // All missed before https://github.com/bee-san/Ciphey/issues/1031
        let flag = identify("picoCTF{b4s3_64_1s_fun}");
        assert!(flag.is_identified);
        assert_eq!(flag.checker_name, "LemmeKnow Checker");

        let json = identify("{\"key\": \"value\"}");
        assert!(json.is_identified);
        assert_eq!(json.checker_name, "JSON Checker");

        let phrase = identify("call me");
        assert!(phrase.is_identified);
        assert_eq!(phrase.checker_name, "English Checker");
    }

    #[test]
    fn charset_only_lemmeknow_matches_are_not_plaintext() {
        for junk in [
            "736563726574",
            "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8",
            "BYFFIQILFX",
        ] {
            assert!(!identify(junk).is_identified, "{junk}");
        }
    }
}
