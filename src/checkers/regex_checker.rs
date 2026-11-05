use gibberish_or_not::Sensitivity;
use lemmeknow::Identifier;

use super::checker_type::{Check, Checker};
use crate::{checkers::checker_result::CheckResult, config::get_config};
use log::trace;
use regex::Regex;
use std::cell::RefCell;
use std::sync::OnceLock;

/// The crib from the config and its compiled form.
static COMPILED_REGEX: OnceLock<(String, Regex)> = OnceLock::new();

thread_local! {
    /// The last crib this thread compiled that isn't [`COMPILED_REGEX`]'s. Searches with
    /// their own options (`ciphey::search`) can each have a crib; each thread compiles a
    /// new one once, and only keeps the last.
    static THREAD_REGEX: RefCell<Option<(String, Regex)>> = const { RefCell::new(None) };
}

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
            _phantom: std::marker::PhantomData,
        }
    }

    fn check(&self, text: &str) -> CheckResult {
        trace!("Checking {} with regex", text);
        let config = get_config();
        // Athena only calls this with a crib in the config. Natively, a search with other
        // options on another thread can swap the config in between (see `ciphey::search`):
        // then nothing matches.
        let Some(pattern) = config.regex.as_deref() else {
            return CheckResult::new(self);
        };
        // The global config can't change once it is set, so its pattern is compiled once.
        // `perform_cracking` and `Search::new` reject a pattern that doesn't compile.
        let cached =
            COMPILED_REGEX.get_or_init(|| (pattern.to_string(), Regex::new(pattern).unwrap()));
        if cached.0 == pattern {
            return self.check_regex(&cached.1, text);
        }
        // A search's own crib
        THREAD_REGEX.with(|slot| {
            let mut slot = slot.borrow_mut();
            if slot.as_ref().is_none_or(|(cached, _)| cached != pattern) {
                let Ok(re) = Regex::new(pattern) else {
                    return CheckResult::new(self);
                };
                *slot = Some((pattern.to_string(), re));
            }
            let (_, re) = slot.as_ref().expect("just set");
            self.check_regex(re, text)
        })
    }

    fn with_sensitivity(mut self, sensitivity: Sensitivity) -> Self {
        self.sensitivity = sensitivity;
        self
    }

    fn get_sensitivity(&self) -> Sensitivity {
        self.sensitivity
    }
}

impl Checker<RegexChecker> {
    /// Checks whether `re` matches `text`. [`Check::check`] does this with the crib from
    /// the config; [`crate::detection`] passes its own.
    pub(crate) fn check_regex(&self, re: &Regex, text: &str) -> CheckResult {
        CheckResult {
            is_identified: re.is_match(text),
            text: text.to_string(),
            checker_name: self.name,
            checker_description: self.description,
            description: format!("Regex matched: {re}"),
            link: self.link,
        }
    }
}
