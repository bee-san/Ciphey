/// Athena checker runs all other checkers and returns immediately when a plaintext is found.
/// This is the standard checker that exits early when a plaintext is found.
/// For a version that continues checking and collects all plaintexts, see WaitAthena.
use crate::{
    checkers::checker_result::CheckResult,
    cli_pretty_printing,
    config::{get_config, is_global_config_set},
};
use dashmap::DashSet;
use gibberish_or_not::Sensitivity;
use lemmeknow::Identifier;
use log::trace;
use once_cell::sync::Lazy;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicUsize, Ordering};

use super::{
    checker_type::{Check, Checker},
    english::EnglishChecker,
    human_checker,
    lemmeknow_checker::LemmeKnow,
    password::PasswordChecker,
    regex_checker::RegexChecker,
    wordlist::WordlistChecker,
};

/// Texts every checker rejected, as [`rejection_key`]s.
///
/// A search meets the same candidate many times: Vigenere's key lengths often decrypt
/// to the same text, and different decoder paths reach the same strings (Caesar after
/// Atbash and Atbash after Caesar give the same 25 texts). Without a human answer,
/// whether Athena rejects a text depends only on the text, the sensitivity and the
/// config, and the config can't change once it is set, so a text rejected once is
/// rejected again. Only rejections made with the config set are kept.
static REJECTED: Lazy<Rejections> = Lazy::new(|| Rejections::new(REJECTED_LIMIT));

/// [`REJECTED`] is emptied when it grows past this many entries (a few MB).
const REJECTED_LIMIT: usize = 200_000;

/// A set of [`rejection_key`]s that empties itself when it grows past `limit`.
struct Rejections {
    /// The keys.
    keys: DashSet<u128>,
    /// Roughly how many keys `keys` holds: inserts since it was last emptied.
    count: AtomicUsize,
    /// Size at which `keys` is emptied.
    limit: usize,
}

impl Rejections {
    /// An empty set.
    fn new(limit: usize) -> Self {
        Rejections {
            keys: DashSet::new(),
            count: AtomicUsize::new(0),
            limit,
        }
    }

    /// Whether `key` was inserted since the set was last emptied.
    fn contains(&self, key: u128) -> bool {
        self.keys.contains(&key)
    }

    /// Adds `key`, first emptying the set if it is full.
    fn insert(&self, key: u128) {
        if self.count.fetch_add(1, Ordering::Relaxed) >= self.limit {
            self.clear();
        }
        self.keys.insert(key);
    }

    /// Empties the set.
    fn clear(&self) {
        self.keys.clear();
        self.count.store(0, Ordering::Relaxed);
    }
}

/// 128-bit hash of `text` checked at `sensitivity`: two 64-bit SipHashes of the input
/// with different prefixes, so that unrelated texts never share a key in practice.
fn rejection_key(text: &str, sensitivity: Sensitivity) -> u128 {
    let sensitivity = match sensitivity {
        Sensitivity::Low => 0u8,
        Sensitivity::Medium => 1,
        Sensitivity::High => 2,
    };
    let half = |prefix: u8| {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        (prefix, sensitivity, text).hash(&mut hasher);
        hasher.finish()
    };
    (u128::from(half(0)) << 64) | u128::from(half(1))
}

/// Forgets every rejection, so the next search starts the way it would in a fresh
/// process. Called at the start of each search.
pub(crate) fn forget_rejections() {
    REJECTED.clear();
}

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
    /// Its only side effect is remembering rejections, so it can run on many candidates at once (see
    /// [`crate::checkers::CheckerTypes::first_identified`]).
    pub(crate) fn find(&self, text: &str) -> Option<Hit> {
        // Asked before `get_config`: if the config is set now, `get_config` returns it
        // and it can't change during this check.
        let rejection = is_global_config_set().then(|| rejection_key(text, self.sensitivity));
        if let Some(key) = rejection {
            if REJECTED.contains(key) {
                trace!("Athena already rejected this text");
                return None;
            }
        }
        let hit = self.find_uncached(text);
        // Every checker said no, without asking the human.
        if let (None, Some(key)) = (&hit, rejection) {
            REJECTED.insert(key);
        }
        hit
    }

    /// [`Checker::find`] without the [`REJECTED`] cache.
    fn find_uncached(&self, text: &str) -> Option<Hit> {
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

        // Not called `password`: CodeQL takes anything named like that for a secret and
        // flags every log line its result reaches. This is the common-password list.
        let common_pw = Checker::<PasswordChecker>::new().with_sensitivity(self.sensitivity);
        let common_pw_result = common_pw.check(text);
        if common_pw_result.is_identified {
            return Some(Hit::new(&common_pw, common_pw_result));
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{set_global_config, Config};

    #[test]
    fn rejection_keys_differ_by_text_and_sensitivity() {
        let key = rejection_key("some text", Sensitivity::Medium);
        assert_eq!(key, rejection_key("some text", Sensitivity::Medium));
        assert_ne!(key, rejection_key("some text", Sensitivity::Low));
        assert_ne!(key, rejection_key("some text", Sensitivity::High));
        assert_ne!(key, rejection_key("some texu", Sensitivity::Medium));
        assert_ne!(key, rejection_key("", Sensitivity::Medium));
    }

    #[test]
    fn rejections_empty_themselves_when_full() {
        let rejections = Rejections::new(2);
        rejections.insert(1);
        rejections.insert(2);
        assert!(rejections.contains(1) && rejections.contains(2));
        // The third insert empties the set first
        rejections.insert(3);
        assert!(!rejections.contains(1) && !rejections.contains(2));
        assert!(rejections.contains(3));
        rejections.clear();
        assert!(!rejections.contains(3));
    }

    #[test]
    fn checking_again_gives_the_same_answer_at_each_sensitivity() {
        // Rejections are only remembered once the config is set
        set_global_config(Config::default());
        // Gibberish at Low sensitivity, English at High (see the English checker's tests)
        let text = "Rcl maocr otmwi lit dnoen oehc 13 iron seah.";
        let low = Checker::<Athena>::new().with_sensitivity(Sensitivity::Low);
        let high = Checker::<Athena>::new().with_sensitivity(Sensitivity::High);
        for _ in 0..2 {
            assert!(!low.check(text).is_identified);
            // A rejection at Low sensitivity says nothing about High
            assert!(high.check(text).is_identified);
        }
        let english = Checker::<Athena>::new();
        for _ in 0..2 {
            assert!(english.check("hello there general kenobi").is_identified);
            assert!(!english.check("vjkrerkdnxhrfjekfdjexk").is_identified);
        }
    }
}
