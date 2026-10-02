/// Athena checker runs all other checkers and returns immediately when a plaintext is found.
/// This is the standard checker that exits early when a plaintext is found.
/// For a version that continues checking and collects all plaintexts, see WaitAthena.
use crate::{checkers::checker_result::CheckResult, cli_pretty_printing, config::get_config};
use gibberish_or_not::Sensitivity;
use lemmeknow::Identifier;
use log::trace;

use super::{
    checker_type::{Check, Checker},
    english::EnglishChecker,
    human_checker,
    lemmeknow_checker::LemmeKnow,
    password::PasswordChecker,
    regex_checker::RegexChecker,
    wordlist::WordlistChecker,
};

/// Athena checker runs all other checkers
pub struct Athena;

/// A text one of Athena's checkers identified, before the human has been asked about it.
pub(crate) struct Hit {
    /// What the checker that identified the text returned. The human is asked about this.
    found: CheckResult,
    /// Athena's answer if the human agrees, named after that checker.
    answer: CheckResult,
}

impl Hit {
    /// `found` came from `checker`.
    fn new<Type>(checker: &Checker<Type>, found: CheckResult) -> Self {
        Hit {
            found,
            answer: CheckResult::new(checker),
        }
    }
}

impl Checker<Athena> {
    /// Runs Athena's checkers on `text` in turn and returns what the first one that
    /// identifies it found, without asking the human. [`Check::check`] is `find` followed
    /// by [`Checker::confirm`].
    ///
    /// This has no side effects, so it can run on many candidates at once (see
    /// [`crate::checkers::CheckerTypes::first_identified`]).
    pub(crate) fn find(&self, text: &str) -> Option<Hit> {
        let config = get_config();

        // If regex is specified, only run the regex checker
        if config.regex.is_some() {
            trace!("running regex");
            let regex_checker = Checker::<RegexChecker>::new().with_sensitivity(self.sensitivity);
            let regex_result = regex_checker.check(text);
            return regex_result
                .is_identified
                .then(|| Hit::new(&regex_checker, regex_result));
        }

        // Run wordlist checker first if a wordlist is provided
        if config.wordlist.is_some() {
            trace!("running wordlist checker");
            let wordlist_checker =
                Checker::<WordlistChecker>::new().with_sensitivity(self.sensitivity);
            let wordlist_result = wordlist_checker.check(text);
            if wordlist_result.is_identified {
                return Some(Hit::new(&wordlist_checker, wordlist_result));
            }
        }

        // In Ciphey if the user uses the regex checker all the other checkers turn off
        // This is because they are looking for one specific bit of information so will not want the other checkers
        // TODO: wrap all checkers in oncecell so we only create them once!
        let lemmeknow = Checker::<LemmeKnow>::new().with_sensitivity(self.sensitivity);
        let lemmeknow_result = lemmeknow.check(text);
        if lemmeknow_result.is_identified {
            return Some(Hit::new(&lemmeknow, lemmeknow_result));
        }

        let password = Checker::<PasswordChecker>::new().with_sensitivity(self.sensitivity);
        let password_result = password.check(text);
        if password_result.is_identified {
            return Some(Hit::new(&password, password_result));
        }

        let english = Checker::<EnglishChecker>::new().with_sensitivity(self.sensitivity);
        let english_result = english.check(text);
        if english_result.is_identified {
            return Some(Hit::new(&english, english_result));
        }

        None
    }

    /// Asks the human checker about `hit` and returns Athena's answer: identified if
    /// the human agrees (or isn't being asked), named after the checker that found it.
    pub(crate) fn confirm(&self, hit: Hit) -> CheckResult {
        let human_result = human_checker::human_checker(&hit.found);
        trace!(
            "Human checker called from {} with result: {}",
            hit.answer.checker_name,
            human_result
        );
        let mut check_res = hit.answer;
        check_res.is_identified = human_result;
        check_res.text = hit.found.text;
        check_res.description = hit.found.description;
        cli_pretty_printing::success(&format!(
            "DEBUG: Athena {} - human_result: {}, check_res.is_identified: {}",
            check_res.checker_name, human_result, check_res.is_identified
        ));
        check_res
    }
}

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
            enhanced_detector: None,
            _phantom: std::marker::PhantomData,
        }
    }

    fn check(&self, text: &str) -> CheckResult {
        trace!("Athena checker running on text: {}", text);
        match self.find(text) {
            Some(hit) => self.confirm(hit),
            None => CheckResult::new(self),
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
