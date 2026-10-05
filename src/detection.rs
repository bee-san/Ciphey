//! Plaintext detection: is a text plaintext, and what is it?
//!
//! Ciphey's search stops at the first decoding that passes its plaintext checks.
//! [`detect_plaintext`](crate::detection::detect_plaintext) runs those checks on any text and says which checker accepted it,
//! what it took the text for and, if the checker has a measure of it, how sure it is:
//!
//! ```
//! use ciphey::detection::{detect_plaintext, CheckerKind, DetectOptions};
//!
//! let options = DetectOptions::default();
//!
//! let found = detect_plaintext("192.168.0.1", &options).unwrap();
//! assert_eq!(found.checker, CheckerKind::LemmeKnow);
//! assert_eq!(found.description, "Internet Protocol (IP) Address Version 4");
//! assert_eq!(found.confidence, Some(0.7));
//!
//! let found = detect_plaintext("hello there general", &options).unwrap();
//! assert_eq!(found.checker, CheckerKind::English);
//! assert_eq!(found.description, "Words");
//!
//! // LemmeKnow knows the flag{...} format
//! let found = detect_plaintext("flag{b4s3_64_1s_fun}", &options).unwrap();
//! assert_eq!(found.description, "Capture The Flag (CTF) Flag");
//!
//! // Base64 of "hello there" isn't plaintext yet
//! assert!(detect_plaintext("aGVsbG8gdGhlcmU=", &options).is_none());
//! ```
//!
//! The checkers run in a fixed order, and the first one that accepts the text answers:
//!
//! 1. [`CheckerKind::Regex`](crate::detection::CheckerKind::Regex): a crib, text matching a regular expression;
//! 2. [`CheckerKind::Wordlist`](crate::detection::CheckerKind::Wordlist): exact matches from a wordlist;
//! 3. [`CheckerKind::LemmeKnow`](crate::detection::CheckerKind::LemmeKnow): over a hundred formats, from IP addresses to API keys;
//! 4. [`CheckerKind::Password`](crate::detection::CheckerKind::Password): a list of common passwords;
//! 5. [`CheckerKind::English`](crate::detection::CheckerKind::English): English text.
//!
//! Plaintext detection isn't perfect: short phrases, other languages, JSON and most flag
//! formats other than `flag{...}` are often missed, and a crib or a wordlist helps a lot.
//! [#1031](https://github.com/bee-san/Ciphey/issues/1031) tracks the improvements.
//!
//! [`DetectOptions`](crate::detection::DetectOptions) chooses which of them run and how lenient the English checker is.
//! The defaults run LemmeKnow, the password list and English at [`Sensitivity::Medium`](crate::detection::Sensitivity::Medium),
//! which is what Athena, the checker the search uses, does with the default
//! [`Config`](crate::config::Config). These are Athena's checkers, unchanged. Unlike
//! Athena, `detect_plaintext` never asks the human checker, and it takes its crib and
//! wordlist from the options, not from the process-wide config.

use std::collections::HashSet;
use std::fmt;
use std::str::FromStr;
use std::sync::Arc;

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::checkers::checker_result::CheckResult;
use crate::checkers::checker_type::{Check, Checker};
use crate::checkers::english::EnglishChecker;
use crate::checkers::lemmeknow_checker::LemmeKnow;
use crate::checkers::password::PasswordChecker;
use crate::checkers::regex_checker::RegexChecker;
use crate::checkers::wordlist::WordlistChecker;
use crate::config::get_config;
use crate::decoders::jwt_decoder::{jwt_structure_checker, structure_result};
use crate::CipheyError;

/// One of Ciphey's plaintext checkers.
///
/// It converts to and from the name Ciphey reports (`English Checker`, as in
/// `CrackResult::checker_name`) and a short id (`english`, used in JSON). Ciphey may
/// gain checkers, so match on it with a wildcard arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum CheckerKind {
    /// Text that a regular expression matches, a crib: [`DetectOptions::regex`], or
    /// `Config::regex` (`ciphey --regex`) in a search. With a crib the other checkers are
    /// off, as you are looking for one thing.
    #[serde(rename = "regex")]
    Regex,
    /// Text that is exactly one entry of a wordlist: [`DetectOptions::wordlist`], or
    /// `Config::wordlist` (`ciphey --wordlist`) in a search.
    #[serde(rename = "wordlist")]
    Wordlist,
    /// [LemmeKnow](https://github.com/swanandx/lemmeknow), the Rust port of pyWhat: over
    /// a hundred formats, such as IP and email addresses, URLs, API keys and crypto
    /// wallet addresses. The whole text has to be the match.
    #[serde(rename = "lemmeknow")]
    LemmeKnow,
    /// Text that is exactly one of the common passwords gibberish-or-not knows.
    #[serde(rename = "password")]
    Password,
    /// English, judged by gibberish-or-not's dictionary and n-gram checks. The only
    /// checker [`Sensitivity`] changes.
    #[serde(rename = "english")]
    English,
    /// Only in decoder results: a well-formed JSON Web Token, which the JWT decoder
    /// accepts on its structure when no other checker identifies the payload.
    /// [`detect_plaintext`] never reports it.
    #[serde(rename = "jwt_structure")]
    JwtStructure,
}

impl CheckerKind {
    /// Every checker: those [`detect_plaintext`] runs, in its order, then
    /// [`CheckerKind::JwtStructure`].
    pub const ALL: &'static [CheckerKind] = &[
        CheckerKind::Regex,
        CheckerKind::Wordlist,
        CheckerKind::LemmeKnow,
        CheckerKind::Password,
        CheckerKind::English,
        CheckerKind::JwtStructure,
    ];

    /// The checker's name as Ciphey reports it, e.g. `English Checker`.
    pub fn name(self) -> &'static str {
        self.name_and_description().0
    }

    /// What the checker does, in a sentence.
    pub fn description(self) -> &'static str {
        self.name_and_description().1
    }

    /// The short id used in JSON, e.g. `english`. [`str::parse`] accepts it, as well as
    /// the [`name`](CheckerKind::name).
    pub fn id(self) -> &'static str {
        match self {
            CheckerKind::Regex => "regex",
            CheckerKind::Wordlist => "wordlist",
            CheckerKind::LemmeKnow => "lemmeknow",
            CheckerKind::Password => "password",
            CheckerKind::English => "english",
            CheckerKind::JwtStructure => "jwt_structure",
        }
    }

    /// The name and description of the checker, taken from the checker itself.
    fn name_and_description(self) -> (&'static str, &'static str) {
        /// The name and description of `checker`
        fn of<Type>(checker: &Checker<Type>) -> (&'static str, &'static str) {
            (checker.name, checker.description)
        }
        match self {
            CheckerKind::Regex => of(&Checker::<RegexChecker>::new()),
            CheckerKind::Wordlist => of(&Checker::<WordlistChecker>::new()),
            CheckerKind::LemmeKnow => of(&Checker::<LemmeKnow>::new()),
            CheckerKind::Password => of(&Checker::<PasswordChecker>::new()),
            CheckerKind::English => of(&Checker::<EnglishChecker>::new()),
            CheckerKind::JwtStructure => of(&jwt_structure_checker()),
        }
    }

    /// The checker Ciphey reports as `name`, e.g. in `CrackResult::checker_name`.
    pub(crate) fn from_name(name: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|kind| kind.name() == name)
    }
}

impl fmt::Display for CheckerKind {
    /// Writes the checker's [`name`](CheckerKind::name).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl FromStr for CheckerKind {
    type Err = CipheyError;

    /// Parses a checker's [`id`](CheckerKind::id) or [`name`](CheckerKind::name), in any
    /// case: `english`, `English Checker`.
    fn from_str(name: &str) -> Result<Self, Self::Err> {
        let wanted = name.trim();
        Self::ALL
            .iter()
            .copied()
            .find(|kind| {
                kind.id().eq_ignore_ascii_case(wanted) || kind.name().eq_ignore_ascii_case(wanted)
            })
            .ok_or_else(|| CipheyError::UnknownChecker {
                name: name.to_string(),
            })
    }
}

/// How readily the English checker takes text for English. The other checkers ignore it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Sensitivity {
    /// The strictest: it lets the least gibberish through and misses the most English.
    /// Most of Ciphey's crackers use it, as they try many keys and a wrong one can look
    /// like English.
    Low,
    /// The default, used by Athena and most decoders.
    #[default]
    Medium,
    /// The most lenient: it accepts English with typos, names or other noise in it, and
    /// more gibberish.
    High,
}

impl From<Sensitivity> for gibberish_or_not::Sensitivity {
    fn from(sensitivity: Sensitivity) -> Self {
        match sensitivity {
            Sensitivity::Low => gibberish_or_not::Sensitivity::Low,
            Sensitivity::Medium => gibberish_or_not::Sensitivity::Medium,
            Sensitivity::High => gibberish_or_not::Sensitivity::High,
        }
    }
}

impl From<gibberish_or_not::Sensitivity> for Sensitivity {
    fn from(sensitivity: gibberish_or_not::Sensitivity) -> Self {
        match sensitivity {
            gibberish_or_not::Sensitivity::Low => Sensitivity::Low,
            gibberish_or_not::Sensitivity::Medium => Sensitivity::Medium,
            gibberish_or_not::Sensitivity::High => Sensitivity::High,
        }
    }
}

/// What a checker found. [`detect_plaintext`] returns it, and decoder results carry it
/// on candidates Ciphey's checks accepted.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[non_exhaustive]
pub struct Detection {
    /// The checker that accepted the text.
    pub checker: CheckerKind,
    /// What the checker took the text for: `Words` (English), the name of the format
    /// LemmeKnow matched (`Internet Protocol (IP) Address Version 4`), `Common Password`,
    /// `Regex matched: <pattern>`, `JSON Web Token`, ...
    pub description: String,
    /// How sure the checker is, from 0 to 1, if it has a measure of it. Only LemmeKnow
    /// does: this is the pyWhat rarity of the format it matched, 1 for formats that
    /// little else matches (an AWS S3 URL), less for broader ones (0.7 for an IP address
    /// or a URL, 0.5 for an email address). Ciphey ignores matches below 0.1. The other
    /// checkers answer yes or no and leave this `None`.
    pub confidence: Option<f32>,
}

impl Detection {
    /// A detection by `checker`, which took `text` for `description`.
    fn new(checker: CheckerKind, description: String, text: &str) -> Self {
        let confidence = match checker {
            CheckerKind::LemmeKnow => lemmeknow_rarity(text, &description),
            _ => None,
        };
        Detection {
            checker,
            description,
            confidence,
        }
    }
}

/// Which checkers [`detect_plaintext`] runs, and how.
///
/// The default runs [`CheckerKind::LemmeKnow`], [`CheckerKind::Password`] and
/// [`CheckerKind::English`] at [`Sensitivity::Medium`], as Athena does with the default
/// config. Whatever you choose, the checkers run in the order of [`CheckerKind::ALL`].
///
/// ```
/// use ciphey::detection::{detect_plaintext, CheckerKind, DetectOptions, Sensitivity};
///
/// // English only, at the strictest setting
/// let options = DetectOptions::new()
///     .checkers([CheckerKind::English])
///     .sensitivity(Sensitivity::Low);
/// assert!(detect_plaintext("192.168.0.1", &options).is_none());
/// assert!(detect_plaintext("hello there general", &options).is_some());
///
/// // A crib, like `ciphey --regex`: only text it matches counts
/// let crib = DetectOptions::new().regex(r"^flag\{.*\}$")?;
/// let found = detect_plaintext("flag{b4s3_64_1s_fun}", &crib).unwrap();
/// assert_eq!(found.checker, CheckerKind::Regex);
/// assert!(detect_plaintext("hello there general", &crib).is_none());
///
/// // A wordlist is checked before the others
/// let words = ["hunter2".to_string()].into_iter().collect();
/// let options = DetectOptions::new().wordlist(words);
/// let found = detect_plaintext("hunter2", &options).unwrap();
/// assert_eq!(found.checker, CheckerKind::Wordlist);
/// # Ok::<(), ciphey::CipheyError>(())
/// ```
#[derive(Clone)]
pub struct DetectOptions {
    /// The checkers chosen to run. They run in the order of [`CheckerKind::ALL`].
    checkers: Vec<CheckerKind>,
    /// How lenient the English checker is.
    sensitivity: Sensitivity,
    /// The crib [`CheckerKind::Regex`] uses.
    regex: Option<Regex>,
    /// The words [`CheckerKind::Wordlist`] uses, shared so the options clone cheaply.
    wordlist: Option<Arc<HashSet<String>>>,
}

impl Default for DetectOptions {
    fn default() -> Self {
        DetectOptions {
            checkers: vec![
                CheckerKind::LemmeKnow,
                CheckerKind::Password,
                CheckerKind::English,
            ],
            sensitivity: Sensitivity::Medium,
            regex: None,
            wordlist: None,
        }
    }
}

impl fmt::Debug for DetectOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DetectOptions")
            .field("checkers", &self.checkers)
            .field("sensitivity", &self.sensitivity)
            .field("regex", &self.regex.as_ref().map(Regex::as_str))
            .field(
                "wordlist_entries",
                &self.wordlist.as_ref().map(|words| words.len()),
            )
            .finish()
    }
}

impl DetectOptions {
    /// The default options, see [`DetectOptions`].
    pub fn new() -> Self {
        Self::default()
    }

    /// How lenient the English checker is. The default is [`Sensitivity::Medium`].
    pub fn sensitivity(mut self, sensitivity: Sensitivity) -> Self {
        self.sensitivity = sensitivity;
        self
    }

    /// Runs these checkers instead of the ones chosen so far. They still run in the order
    /// of [`CheckerKind::ALL`]. [`CheckerKind::Regex`] needs a pattern from
    /// [`DetectOptions::regex`] and [`CheckerKind::Wordlist`] a
    /// [`wordlist`](DetectOptions::wordlist), otherwise they don't run.
    /// [`CheckerKind::JwtStructure`] never does.
    pub fn checkers(mut self, checkers: impl IntoIterator<Item = CheckerKind>) -> Self {
        self.checkers = checkers.into_iter().collect();
        self
    }

    /// Accepts only text that `pattern` matches, like `ciphey --regex`: the other checkers
    /// are turned off, as you are looking for one thing. Turn them back on with
    /// [`DetectOptions::checkers`] if you want them too. The pattern can match anywhere in
    /// the text; anchor it with `^` and `$` to match the whole text.
    ///
    /// # Errors
    ///
    /// [`CipheyError::InvalidRegex`] if `pattern` isn't a valid regular expression.
    pub fn regex(mut self, pattern: &str) -> Result<Self, CipheyError> {
        self.regex = Some(Regex::new(pattern).map_err(CipheyError::InvalidRegex)?);
        self.checkers = vec![CheckerKind::Regex];
        Ok(self)
    }

    /// Also accepts text that is exactly one of `words`, checked before LemmeKnow, the
    /// passwords and English, like `ciphey --wordlist`. [`load_wordlist`] reads one from a
    /// file.
    ///
    /// [`load_wordlist`]: crate::config::load_wordlist
    pub fn wordlist(mut self, words: HashSet<String>) -> Self {
        self.wordlist = Some(Arc::new(words));
        if !self.checkers.contains(&CheckerKind::Wordlist) {
            self.checkers.push(CheckerKind::Wordlist);
        }
        self
    }

    /// The checkers [`detect_plaintext`] will run, in order: the chosen ones that can run.
    pub fn enabled_checkers(&self) -> impl Iterator<Item = CheckerKind> + '_ {
        CheckerKind::ALL.iter().copied().filter(|kind| {
            self.checkers.contains(kind)
                && match kind {
                    CheckerKind::Regex => self.regex.is_some(),
                    CheckerKind::Wordlist => self.wordlist.is_some(),
                    CheckerKind::JwtStructure => false,
                    _ => true,
                }
        })
    }
}

/// Runs the plaintext checkers `options` chooses on `text` and returns what the first
/// one to accept it found, or `None` if none does.
///
/// See the [module docs](self) for the order. The checkers are Athena's, with the same
/// settings, so with the default options this accepts exactly what the search accepts
/// with the default config. One setting comes from the process-wide config: if
/// `Config::enhanced_detection` is on, the English checker uses
/// [`Sensitivity::High`] whatever you choose, as it does in the search. The human checker
/// is never asked.
///
/// ```
/// use ciphey::detection::{detect_plaintext, CheckerKind, DetectOptions};
///
/// let found = detect_plaintext("123456", &DetectOptions::default()).unwrap();
/// assert_eq!(found.checker, CheckerKind::Password);
/// assert_eq!(found.description, "Common Password");
/// assert_eq!(found.confidence, None);
/// ```
pub fn detect_plaintext(text: &str, options: &DetectOptions) -> Option<Detection> {
    let sensitivity = gibberish_or_not::Sensitivity::from(options.sensitivity);
    options.enabled_checkers().find_map(|kind| {
        let result = match kind {
            CheckerKind::Regex => Checker::<RegexChecker>::new()
                .with_sensitivity(sensitivity)
                .check_regex(options.regex.as_ref()?, text),
            CheckerKind::Wordlist => Checker::<WordlistChecker>::new()
                .with_sensitivity(sensitivity)
                .check_with_wordlist(text, options.wordlist.as_ref()?),
            CheckerKind::LemmeKnow => Checker::<LemmeKnow>::new()
                .with_sensitivity(sensitivity)
                .check(text),
            CheckerKind::Password => Checker::<PasswordChecker>::new()
                .with_sensitivity(sensitivity)
                .check(text),
            CheckerKind::English => Checker::<EnglishChecker>::new()
                .with_sensitivity(sensitivity)
                .check(text),
            CheckerKind::JwtStructure => return None,
        };
        result
            .is_identified
            .then(|| Detection::new(kind, result.description, text))
    })
}

/// The default [`DetectOptions`], for [`is_plaintext`].
static DEFAULT_OPTIONS: Lazy<DetectOptions> = Lazy::new(DetectOptions::default);

/// Whether Ciphey's plaintext checks accept `text`, with the default options: what
/// [`detect_plaintext`] says with [`DetectOptions::default`].
///
/// ```
/// assert!(ciphey::is_plaintext("hello there general"));
/// assert!(!ciphey::is_plaintext("aGVsbG8gdGhlcmUgZ2VuZXJhbA=="));
/// ```
pub fn is_plaintext(text: &str) -> bool {
    detect_plaintext(text, &DEFAULT_OPTIONS).is_some()
}

/// The [`Detection`] for what Athena, or one of its checkers, said about `text`, if it
/// identified it.
pub(crate) fn from_check_result(result: CheckResult, text: &str) -> Option<Detection> {
    if !result.is_identified {
        return None;
    }
    let Some(checker) = CheckerKind::from_name(result.checker_name) else {
        // Nothing from the result is logged: it can be a password the checker matched
        log::warn!("A checker without a CheckerKind accepted a text");
        return None;
    };
    Some(Detection::new(checker, result.description, text))
}

/// The [`Detection`] for `text`, which a decoder's checker accepted and reported as
/// `checker_name` and `checker_description` in its `CrackResult`.
///
/// A `CrackResult` doesn't keep what the checker took the text for, so the same checker
/// runs again to find out. Some decoders accept a text for a value inside it (Zlib, and
/// JWT with a crib), which the checker doesn't find in the whole text: those get the
/// checker's own description.
pub(crate) fn for_accepted_decoding(
    checker_name: &str,
    checker_description: &str,
    text: &str,
) -> Option<Detection> {
    let Some(checker) = CheckerKind::from_name(checker_name) else {
        log::warn!("A checker without a CheckerKind accepted a decoding");
        return None;
    };
    let again = match checker {
        // The search only uses the regex checker when the config has a crib
        CheckerKind::Regex => get_config()
            .regex
            .is_some()
            .then(|| Checker::<RegexChecker>::new().check(text)),
        CheckerKind::Wordlist => Some(Checker::<WordlistChecker>::new().check(text)),
        CheckerKind::LemmeKnow => Some(Checker::<LemmeKnow>::new().check(text)),
        CheckerKind::Password => Some(Checker::<PasswordChecker>::new().check(text)),
        CheckerKind::English => Some(Checker::<EnglishChecker>::new().check(text)),
        CheckerKind::JwtStructure => Some(structure_result(text)),
    };
    Some(match again {
        Some(result) if !result.description.is_empty() => {
            Detection::new(checker, result.description, text)
        }
        _ => Detection {
            checker,
            description: checker_description.to_string(),
            confidence: None,
        },
    })
}

/// The pyWhat rarity of the format called `name` that LemmeKnow finds in `text`.
fn lemmeknow_rarity(text: &str, name: &str) -> Option<f32> {
    Checker::<LemmeKnow>::new()
        .lemmeknow_config
        .identify(text)
        .into_iter()
        .find(|found| found.data.name == name)
        .map(|found| found.data.rarity)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkers::athena::Athena;
    use crate::checkers::human_checker::without_prompts;
    use crate::checkers::CHECKER_MAP;

    /// Hits and misses for every checker, including texts the sensitivities disagree on.
    const CORPUS: &[&str] = &[
        "",
        "#",
        "a",
        "hello",
        "exuberant",
        "preinterview",
        "hello there general",
        "Hello, World!",
        "This is a perfectly normal English sentence about cats.",
        "Rcl maocr otmwi lit dnoen oehc 13 iron seah.",
        "Max mkxtlnkx bl unkbxw ngwxk",
        "yob llud a kcaJ",
        "vjkrerkdnxhrfjekfdjexk",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaBabyShark",
        "192.168.0.1",
        "https://github.com/bee-san/Ciphey",
        "someone@example.com",
        "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
        "123456",
        "password",
        "qwerty",
        "hunter2",
        "aGVsbG8gdGhlcmUgZ2VuZXJhbA==",
        "68656c6c6f20776f726c64",
        "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8",
        "736563726574",
        "BYFFIQILFX",
        "picoCTF{b4s3_64_1s_fun}",
        "{\"key\": \"value\"}",
        "Ceci n'est pas une pipe",
        "日本語のテキスト",
        "Tqxxa ftue ue mz qjmybxq fqjf tffbe://saasxq.oay !",
        "mount -o username=bee,password=hunter2 //server/share /mnt",
    ];

    /// The sensitivities, strictest first
    const SENSITIVITIES: [Sensitivity; 3] =
        [Sensitivity::Low, Sensitivity::Medium, Sensitivity::High];

    #[test]
    fn default_options_agree_with_athena() {
        for sensitivity in SENSITIVITIES {
            let athena = Checker::<Athena>::new().with_sensitivity(sensitivity.into());
            let options = DetectOptions::new().sensitivity(sensitivity);
            for &text in CORPUS {
                let expected = without_prompts(|| athena.check(text));
                let found = detect_plaintext(text, &options);
                assert_eq!(
                    found.is_some(),
                    expected.is_identified,
                    "{text:?} at {sensitivity:?}: {found:?}"
                );
                if let Some(found) = found {
                    assert_eq!(found.checker.name(), expected.checker_name, "{text:?}");
                    assert_eq!(found.description, expected.description, "{text:?}");
                }
            }
        }
    }

    #[test]
    fn checkers_identify_what_they_know() {
        let options = DetectOptions::default();

        let ip = detect_plaintext("192.168.0.1", &options).unwrap();
        assert_eq!(ip.checker, CheckerKind::LemmeKnow);
        assert_eq!(ip.description, "Internet Protocol (IP) Address Version 4");
        assert_eq!(ip.confidence, Some(0.7));

        let email = detect_plaintext("someone@example.com", &options).unwrap();
        assert_eq!(email.checker, CheckerKind::LemmeKnow);
        assert_eq!(email.confidence, Some(0.5));

        let password = detect_plaintext("123456", &options).unwrap();
        assert_eq!(password.checker, CheckerKind::Password);
        assert_eq!(password.description, "Common Password");
        assert_eq!(password.confidence, None);

        let english = detect_plaintext("hello there general", &options).unwrap();
        assert_eq!(english.checker, CheckerKind::English);
        assert_eq!(english.description, "Words");
        assert_eq!(english.confidence, None);

        for junk in [
            "",
            "#",
            "vjkrerkdnxhrfjekfdjexk",
            "aGVsbG8gdGhlcmUgZ2VuZXJhbA==",
        ] {
            assert_eq!(detect_plaintext(junk, &options), None, "{junk:?}");
            assert!(!is_plaintext(junk), "{junk:?}");
        }
        assert!(is_plaintext("hello there general"));
    }

    #[test]
    fn sensitivity_changes_only_the_english_checker() {
        // One English word in gibberish: only High takes it for English
        let text = "Rcl maocr otmwi lit dnoen oehc 13 iron seah.";
        let at =
            |sensitivity| detect_plaintext(text, &DetectOptions::new().sensitivity(sensitivity));
        assert_eq!(at(Sensitivity::Low), None);
        assert_eq!(at(Sensitivity::High).unwrap().checker, CheckerKind::English);

        for sensitivity in SENSITIVITIES {
            let options = DetectOptions::new().sensitivity(sensitivity);
            let ip = detect_plaintext("192.168.0.1", &options).unwrap();
            assert_eq!(ip.checker, CheckerKind::LemmeKnow);
        }
    }

    #[test]
    fn checkers_can_be_chosen() {
        let english_only = DetectOptions::new().checkers([CheckerKind::English]);
        assert_eq!(
            english_only.enabled_checkers().collect::<Vec<_>>(),
            [CheckerKind::English]
        );
        assert_eq!(detect_plaintext("192.168.0.1", &english_only), None);
        assert_eq!(detect_plaintext("123456", &english_only), None);
        assert!(detect_plaintext("hello there general", &english_only).is_some());

        let nothing = DetectOptions::new().checkers([]);
        assert_eq!(detect_plaintext("hello there general", &nothing), None);

        // The order is fixed whatever order they're given in
        let reversed = DetectOptions::new().checkers([
            CheckerKind::English,
            CheckerKind::Password,
            CheckerKind::LemmeKnow,
        ]);
        assert_eq!(
            reversed.enabled_checkers().collect::<Vec<_>>(),
            [
                CheckerKind::LemmeKnow,
                CheckerKind::Password,
                CheckerKind::English
            ]
        );

        // Regex and Wordlist only run with a pattern and a wordlist, JwtStructure never
        let unusable = DetectOptions::new().checkers(CheckerKind::ALL.iter().copied());
        assert_eq!(
            unusable.enabled_checkers().collect::<Vec<_>>(),
            [
                CheckerKind::LemmeKnow,
                CheckerKind::Password,
                CheckerKind::English
            ]
        );
    }

    #[test]
    fn a_crib_turns_the_other_checkers_off() {
        let crib = DetectOptions::new().regex(r"flag\{").unwrap();
        assert_eq!(
            crib.enabled_checkers().collect::<Vec<_>>(),
            [CheckerKind::Regex]
        );

        let found = detect_plaintext("the flag{is here}", &crib).unwrap();
        assert_eq!(found.checker, CheckerKind::Regex);
        assert_eq!(found.description, r"Regex matched: flag\{");
        assert_eq!(detect_plaintext("hello there general", &crib), None);

        // Asked for, the others run after the crib
        let both = crib.checkers([CheckerKind::Regex, CheckerKind::English]);
        assert_eq!(
            detect_plaintext("hello there general", &both)
                .unwrap()
                .checker,
            CheckerKind::English
        );
        assert_eq!(
            detect_plaintext("flag{x}", &both).unwrap().checker,
            CheckerKind::Regex
        );

        assert!(matches!(
            DetectOptions::new().regex("(unclosed"),
            Err(CipheyError::InvalidRegex(_))
        ));
    }

    #[test]
    fn a_wordlist_is_checked_first() {
        let words: HashSet<String> = ["hello there general", "zxqv"]
            .into_iter()
            .map(String::from)
            .collect();
        let options = DetectOptions::new().wordlist(words);
        assert_eq!(
            options.enabled_checkers().collect::<Vec<_>>(),
            [
                CheckerKind::Wordlist,
                CheckerKind::LemmeKnow,
                CheckerKind::Password,
                CheckerKind::English
            ]
        );

        let found = detect_plaintext("hello there general", &options).unwrap();
        assert_eq!(found.checker, CheckerKind::Wordlist);
        assert_eq!(
            found.description,
            "text which matches an entry in the provided wordlist"
        );
        assert_eq!(
            detect_plaintext("zxqv", &options).unwrap().checker,
            CheckerKind::Wordlist
        );
        // Exact matches only
        assert_eq!(detect_plaintext("zxqv ", &options), None);
        // The other checkers still run
        assert_eq!(
            detect_plaintext("192.168.0.1", &options).unwrap().checker,
            CheckerKind::LemmeKnow
        );
        let debug = format!("{options:?}");
        assert!(debug.contains("wordlist_entries: Some(2)"), "{debug}");
    }

    #[test]
    fn every_checker_that_can_accept_text_has_a_kind() {
        // Athena and WaitAthena report the checker that accepted the text, and the
        // template checker is a template
        let aggregates = ["Athena Checker", "WaitAthena Checker", "Template checker"];
        for &name in CHECKER_MAP.keys() {
            if aggregates.contains(&name) {
                continue;
            }
            let kind = CheckerKind::from_name(name)
                .unwrap_or_else(|| panic!("add a CheckerKind for the {name:?} checker"));
            assert_eq!(kind.name(), name);
        }
        for kind in CheckerKind::ALL {
            assert!(CHECKER_MAP.contains_key(kind.name()), "{kind:?}");
            assert!(!kind.description().is_empty(), "{kind:?}");
        }
    }

    #[test]
    fn checker_kinds_parse_and_serialize() {
        for &kind in CheckerKind::ALL {
            assert_eq!(kind.id().parse::<CheckerKind>().unwrap(), kind);
            assert_eq!(kind.name().parse::<CheckerKind>().unwrap(), kind);
            assert_eq!(kind.to_string(), kind.name());
            let json = serde_json::to_string(&kind).unwrap();
            assert_eq!(json, format!("\"{}\"", kind.id()));
            assert_eq!(serde_json::from_str::<CheckerKind>(&json).unwrap(), kind);
        }
        assert_eq!(
            " ENGLISH ".parse::<CheckerKind>().unwrap(),
            CheckerKind::English
        );
        assert!(matches!(
            "gibberish".parse::<CheckerKind>(),
            Err(CipheyError::UnknownChecker { name }) if name == "gibberish"
        ));

        assert_eq!(serde_json::to_string(&Sensitivity::Low).unwrap(), "\"low\"");
        assert_eq!(
            serde_json::from_str::<Sensitivity>("\"high\"").unwrap(),
            Sensitivity::High
        );
        for sensitivity in SENSITIVITIES {
            let theirs = gibberish_or_not::Sensitivity::from(sensitivity);
            assert_eq!(Sensitivity::from(theirs), sensitivity);
        }

        let found = detect_plaintext("192.168.0.1", &DetectOptions::default()).unwrap();
        assert_eq!(
            serde_json::to_value(&found).unwrap(),
            serde_json::json!({
                "checker": "lemmeknow",
                "description": "Internet Protocol (IP) Address Version 4",
                "confidence": 0.7_f32,
            })
        );
    }

    #[test]
    fn accepted_decodings_are_described_like_detections() {
        let lemmeknow = Checker::<LemmeKnow>::new();
        let found =
            for_accepted_decoding(lemmeknow.name, lemmeknow.description, "192.168.0.1").unwrap();
        assert_eq!(
            found,
            detect_plaintext("192.168.0.1", &DetectOptions::default()).unwrap()
        );

        // Accepted for a value inside the text: the checker's own description
        let inside = for_accepted_decoding(
            lemmeknow.name,
            lemmeknow.description,
            r#"{"url": "https://example.com"}"#,
        )
        .unwrap();
        assert_eq!(inside.checker, CheckerKind::LemmeKnow);
        assert_eq!(inside.description, lemmeknow.description);
        assert_eq!(inside.confidence, None);

        let jwt = for_accepted_decoding("JWT Structure", "", r#"{"sub":"1"}"#).unwrap();
        assert_eq!(jwt.checker, CheckerKind::JwtStructure);
        assert_eq!(jwt.description, "JSON Web Token");

        assert_eq!(for_accepted_decoding("No Such Checker", "", "text"), None);
    }
}
