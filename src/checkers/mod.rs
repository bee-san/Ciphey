use self::{
    athena::Athena,
    checker_result::CheckResult,
    checker_type::{Check, CheckInfo, Checker},
    code_checker::CodeChecker,
    english::EnglishChecker,
    json_checker::JsonChecker,
    lemmeknow_checker::LemmeKnow,
    password::PasswordChecker,
    regex_checker::RegexChecker,
    wait_athena::WaitAthena,
    wordlist::WordlistChecker,
};

use gibberish_or_not::Sensitivity;
use once_cell::sync::Lazy;
use rayon::prelude::*;
use std::collections::HashMap;

/// The default checker we use which simply calls all other checkers in order.
pub mod athena;
/// The checkerResult struct is used to store the results of a checker.
pub mod checker_result;
/// This is the base checker that all other checkers inherit from.
pub mod checker_type;
/// The Code Checker checks if the text is source code or a shell command
pub mod code_checker;
/// The default checker we use which simply calls all other checkers in order.
pub mod default_checker;
/// The English Checker is a checker that checks if the input is English
pub mod english;
/// The Human Checker asks humans if the expected plaintext is real plaintext
pub mod human_checker;
/// The JSON Checker checks if the text is a JSON object or array
pub mod json_checker;
/// The LemmeKnow Checker checks if the text matches a known Regex pattern.
pub mod lemmeknow_checker;
/// The Password checker checks if the text matches a known common password
pub mod password;
/// The Regex checker checks to see if the intended text matches the plaintext
pub mod regex_checker;
/// The WaitAthena Checker is a variant of Athena that collects all plaintexts found during the search
pub mod wait_athena;
/// The Wordlist checker checks if the text exactly matches any word in a user-provided wordlist
pub mod wordlist;

/// What one of the plaintext checkers identified a text as.
pub(crate) struct Identification {
    /// Name of the checker that identified the text, as in [`CheckResult::checker_name`]
    pub(crate) checker_name: &'static str,
    /// Its description
    pub(crate) checker_description: &'static str,
    /// Its link
    pub(crate) link: &'static str,
    /// What the text is, like "Words" or "Email Address"
    pub(crate) description: String,
    /// The tag WaitAthena stores with the result, like "EnglishChecker"
    pub(crate) kind: &'static str,
}

impl Identification {
    /// `checker` identified the text as `description`.
    fn by<T>(checker: &Checker<T>, kind: &'static str, description: String) -> Self {
        Identification {
            checker_name: checker.name,
            checker_description: checker.description,
            link: checker.link,
            description,
            kind,
        }
    }

    /// The identification as an identified [`CheckResult`] for `text`.
    pub(crate) fn into_result(self, text: &str) -> CheckResult {
        CheckResult {
            is_identified: true,
            text: text.to_string(),
            description: self.description,
            checker_name: self.checker_name,
            checker_description: self.checker_description,
            link: self.link,
        }
    }
}

/// The checkers [`identify_plaintext`] runs, built once: building one allocates, and
/// Athena runs on every candidate of every decoder.
static LEMMEKNOW_CHECKER: Lazy<Checker<LemmeKnow>> = Lazy::new(Checker::<LemmeKnow>::new);
/// See [`LEMMEKNOW_CHECKER`].
static JSON_CHECKER: Lazy<Checker<JsonChecker>> = Lazy::new(Checker::<JsonChecker>::new);
/// See [`LEMMEKNOW_CHECKER`].
static PASSWORD_CHECKER: Lazy<Checker<PasswordChecker>> =
    Lazy::new(Checker::<PasswordChecker>::new);
/// See [`LEMMEKNOW_CHECKER`].
static ENGLISH_CHECKER: Lazy<Checker<EnglishChecker>> = Lazy::new(Checker::<EnglishChecker>::new);
/// See [`LEMMEKNOW_CHECKER`].
static CODE_CHECKER: Lazy<Checker<CodeChecker>> = Lazy::new(Checker::<CodeChecker>::new);

/// Runs the plaintext checkers of Athena and WaitAthena (after the wordlist) in order and
/// returns the first identification: LemmeKnow (known formats and CTF flags), JSON, the
/// common-password list, English at `sensitivity`, and code. The order is cheapest and
/// most specific first; English goes before code so that text that reads as English is
/// reported as words.
///
/// Nothing is allocated unless a checker identifies the text: almost every text a search
/// checks is rejected.
pub(crate) fn identify_plaintext(text: &str, sensitivity: Sensitivity) -> Option<Identification> {
    let lemmeknow = &*LEMMEKNOW_CHECKER;
    if let Some(description) = lemmeknow_checker::identify(&lemmeknow.lemmeknow_config, text) {
        return Some(Identification::by(lemmeknow, "LemmeKnow", description));
    }
    if let Some(description) = json_checker::identify(text) {
        return Some(Identification::by(
            &*JSON_CHECKER,
            "JsonChecker",
            description,
        ));
    }
    if password::is_common_password(text) {
        return Some(Identification::by(
            &*PASSWORD_CHECKER,
            "PasswordChecker",
            "Common Password".to_string(),
        ));
    }
    if english::is_english(text, sensitivity) {
        return Some(Identification::by(
            &*ENGLISH_CHECKER,
            "EnglishChecker",
            "Words".to_string(),
        ));
    }
    if let Some(description) = code_checker::identify(text) {
        return Some(Identification::by(
            &*CODE_CHECKER,
            "CodeChecker",
            description,
        ));
    }
    None
}
/// [`CheckerTypes::first_identified`] checks candidates in parallel when they add up to
/// at least this many bytes. Below that the checks are cheap (an 84 character text's 93
/// ROT47 candidates are 8 KB), and a decoder's loop isn't what a search step waits for.
const PARALLEL_CHECK_MIN_BYTES: usize = 16 * 1024;

/// CheckerTypes is a wrapper enum for Checker
pub enum CheckerTypes {
    /// Wrapper for LemmeKnow Checker
    CheckLemmeKnow(Checker<LemmeKnow>),
    /// Wrapper for English Checker
    CheckEnglish(Checker<EnglishChecker>),
    /// Wrapper for Athena Checker
    CheckAthena(Checker<Athena>),
    /// Wrapper for WaitAthena Checker
    CheckWaitAthena(Checker<WaitAthena>),
    /// Wrapper for Regex
    CheckRegex(Checker<RegexChecker>),
    /// Wrapper for Password Checker
    CheckPassword(Checker<PasswordChecker>),
    /// Wrapper for Wordlist Checker
    CheckWordlist(Checker<WordlistChecker>),
    /// Wrapper for JSON Checker
    CheckJson(Checker<JsonChecker>),
    /// Wrapper for Code Checker
    CheckCode(Checker<CodeChecker>),
}

impl CheckerTypes {
    /// The index of the first of `texts` this checker identifies, and the result, exactly
    /// as checking them one at a time and stopping at the first hit would give.
    ///
    /// Brute-force decoders (Caesar, ROT47, railfence) produce 25 to 93 candidates. A
    /// search step runs every decoder at once, but checking one decoder's candidates
    /// one after another made the step take as long as that loop, which on long text is
    /// the slowest part of the step. When the candidates add up to at least
    /// [`PARALLEL_CHECK_MIN_BYTES`], Athena's automatic checkers, which have no side
    /// effects, run on them in parallel, looking for the first one they identify in order;
    /// rayon stops starting new candidates once one is found. The human checker is then
    /// asked about it, as the loop asked, and if the human says no the search goes on
    /// after it. Smaller candidate lists, and other checkers, are checked one at a time.
    pub(crate) fn first_identified(&self, texts: &[String]) -> Option<(usize, CheckResult)> {
        let total_bytes: usize = texts.iter().map(String::len).sum();
        match self {
            CheckerTypes::CheckAthena(athena) if total_bytes >= PARALLEL_CHECK_MIN_BYTES => {
                let mut start = 0;
                while start < texts.len() {
                    let (i, hit) = texts[start..]
                        .par_iter()
                        .enumerate()
                        .find_map_first(|(i, text)| athena.find(text).map(|hit| (i, hit)))?;
                    let result = athena.confirm(hit);
                    if result.is_identified {
                        return Some((start + i, result));
                    }
                    start += i + 1;
                }
                None
            }
            _ => texts.iter().enumerate().find_map(|(i, text)| {
                let result = self.check(text);
                result.is_identified.then_some((i, result))
            }),
        }
    }

    /// This functions calls appropriate check function of Checker
    pub fn check(&self, text: &str) -> CheckResult {
        match self {
            CheckerTypes::CheckLemmeKnow(lemmeknow_checker) => lemmeknow_checker.check(text),
            CheckerTypes::CheckEnglish(english_checker) => english_checker.check(text),
            CheckerTypes::CheckAthena(athena_checker) => athena_checker.check(text),
            CheckerTypes::CheckWaitAthena(wait_athena_checker) => wait_athena_checker.check(text),
            CheckerTypes::CheckRegex(regex_checker) => regex_checker.check(text),
            CheckerTypes::CheckPassword(password_checker) => password_checker.check(text),
            CheckerTypes::CheckWordlist(wordlist_checker) => wordlist_checker.check(text),
            CheckerTypes::CheckJson(json_checker) => json_checker.check(text),
            CheckerTypes::CheckCode(code_checker) => code_checker.check(text),
        }
    }

    /// Sets the sensitivity level for gibberish detection
    pub fn with_sensitivity(&self, sensitivity: Sensitivity) -> Self {
        match self {
            CheckerTypes::CheckLemmeKnow(_checker) => {
                let mut new_checker = Checker::<LemmeKnow>::new();
                new_checker.sensitivity = sensitivity;
                CheckerTypes::CheckLemmeKnow(new_checker)
            }
            CheckerTypes::CheckEnglish(_checker) => {
                let mut new_checker = Checker::<EnglishChecker>::new();
                new_checker.sensitivity = sensitivity;
                CheckerTypes::CheckEnglish(new_checker)
            }
            CheckerTypes::CheckAthena(_checker) => {
                let mut new_checker = Checker::<Athena>::new();
                new_checker.sensitivity = sensitivity;
                CheckerTypes::CheckAthena(new_checker)
            }
            CheckerTypes::CheckWaitAthena(_checker) => {
                let mut new_checker = Checker::<WaitAthena>::new();
                new_checker.sensitivity = sensitivity;
                CheckerTypes::CheckWaitAthena(new_checker)
            }
            CheckerTypes::CheckRegex(_checker) => {
                let mut new_checker = Checker::<RegexChecker>::new();
                new_checker.sensitivity = sensitivity;
                CheckerTypes::CheckRegex(new_checker)
            }
            CheckerTypes::CheckPassword(_checker) => {
                let mut new_checker = Checker::<PasswordChecker>::new();
                new_checker.sensitivity = sensitivity;
                CheckerTypes::CheckPassword(new_checker)
            }
            CheckerTypes::CheckWordlist(_checker) => {
                let mut new_checker = Checker::<WordlistChecker>::new();
                new_checker.sensitivity = sensitivity;
                CheckerTypes::CheckWordlist(new_checker)
            }
            CheckerTypes::CheckJson(_checker) => {
                let mut new_checker = Checker::<JsonChecker>::new();
                new_checker.sensitivity = sensitivity;
                CheckerTypes::CheckJson(new_checker)
            }
            CheckerTypes::CheckCode(_checker) => {
                let mut new_checker = Checker::<CodeChecker>::new();
                new_checker.sensitivity = sensitivity;
                CheckerTypes::CheckCode(new_checker)
            }
        }
    }

    /// Gets the current sensitivity level
    pub fn get_sensitivity(&self) -> Sensitivity {
        match self {
            CheckerTypes::CheckLemmeKnow(checker) => checker.get_sensitivity(),
            CheckerTypes::CheckEnglish(checker) => checker.get_sensitivity(),
            CheckerTypes::CheckAthena(checker) => checker.get_sensitivity(),
            CheckerTypes::CheckWaitAthena(checker) => checker.get_sensitivity(),
            CheckerTypes::CheckRegex(checker) => checker.get_sensitivity(),
            CheckerTypes::CheckPassword(checker) => checker.get_sensitivity(),
            CheckerTypes::CheckWordlist(checker) => checker.get_sensitivity(),
            CheckerTypes::CheckJson(checker) => checker.get_sensitivity(),
            CheckerTypes::CheckCode(checker) => checker.get_sensitivity(),
        }
    }
}

/// Wrapper struct to hold Checkers for CHECKER_MAP
pub struct CheckerBox {
    /// Wrapper box to hold Checkers for CHECKER_MAP
    value: Box<dyn CheckInfo + Sync + Send>,
}

impl CheckerBox {
    /// Constructor for CheckerBox. Takes in a Checker and stores it as the
    /// internal value
    fn new<T: 'static + CheckInfo + Sync + Send>(value: T) -> Self {
        Self {
            value: Box::new(value),
        }
    }

    /// Getter method for CheckerBox to return the internal Box
    pub fn get<T: 'static>(&self) -> &(dyn CheckInfo + Sync + Send) {
        self.value.as_ref()
    }
}

/// Global hashmap for translating strings to Checkers
pub static CHECKER_MAP: Lazy<HashMap<&str, CheckerBox>> = Lazy::new(|| {
    HashMap::from([
        ("Athena Checker", CheckerBox::new(Checker::<Athena>::new())),
        (
            "Code Checker",
            CheckerBox::new(Checker::<CodeChecker>::new()),
        ),
        (
            "English Checker",
            CheckerBox::new(Checker::<EnglishChecker>::new()),
        ),
        (
            "Template checker",
            CheckerBox::new(Checker::<default_checker::DefaultChecker>::new()),
        ),
        (
            "JSON Checker",
            CheckerBox::new(Checker::<JsonChecker>::new()),
        ),
        (
            "LemmeKnow Checker",
            CheckerBox::new(Checker::<LemmeKnow>::new()),
        ),
        (
            "Password Checker",
            CheckerBox::new(Checker::<PasswordChecker>::new()),
        ),
        (
            "Regex Checker",
            CheckerBox::new(Checker::<RegexChecker>::new()),
        ),
        (
            "WaitAthena Checker",
            CheckerBox::new(Checker::<WaitAthena>::new()),
        ),
        (
            "Wordlist Checker",
            CheckerBox::new(Checker::<WordlistChecker>::new()),
        ),
        // Names JWTs accepted on their structure, see the JWT decoder
        (
            "JWT Structure",
            CheckerBox::new(crate::decoders::jwt_decoder::jwt_structure_checker()),
        ),
    ])
});

// test
#[cfg(test)]
mod tests {
    use crate::checkers::{
        athena::Athena,
        checker_type::{Check, Checker},
        lemmeknow_checker::LemmeKnow,
        CheckerTypes, PARALLEL_CHECK_MIN_BYTES,
    };

    #[test]
    fn test_check_ip_address() {
        let athena = CheckerTypes::CheckAthena(Checker::<Athena>::new());
        assert!(athena.check("test valid english sentence").is_identified);
    }

    #[test]
    fn first_identified_returns_the_first_hit_in_order() {
        let short: Vec<String> = [
            "vjkrerkdnxhrfjekfdjexk",
            "qwfpgjluyarstdhneiozxcvbkm",
            "hello there general kenobi",
            "https://google.com",
        ]
        .iter()
        .map(|text| text.to_string())
        .collect();
        // Long enough to be checked in parallel: gibberish stays gibberish and the
        // English sentence stays English when repeated.
        let gibberish = "vjkrerkdnxhrfjekfdjexk qwfpgjluyarstdhneiozxcvbkm ".repeat(100);
        let english = "hello there general kenobi, how are you today? ".repeat(100);
        let long = vec![gibberish.clone(), gibberish.clone(), english, gibberish];
        assert!(long.iter().map(String::len).sum::<usize>() >= PARALLEL_CHECK_MIN_BYTES);

        let athena = CheckerTypes::CheckAthena(Checker::<Athena>::new());
        for texts in [&short, &long] {
            let (index, result) = athena.first_identified(texts).expect("a hit");
            assert_eq!(index, 2);
            assert!(result.is_identified);
            assert_eq!(result.text, texts[2]);
            assert_eq!(result.checker_name, "English Checker");
            // The same as checking one at a time
            let one_by_one = texts
                .iter()
                .position(|text| athena.check(text).is_identified);
            assert_eq!(one_by_one, Some(index));
            assert!(athena.first_identified(&texts[..2]).is_none());
        }
        assert!(athena.first_identified(&[]).is_none());

        // Other checkers check one at a time
        let lemmeknow = CheckerTypes::CheckLemmeKnow(Checker::<LemmeKnow>::new());
        let (index, result) = lemmeknow.first_identified(&short).expect("a hit");
        assert_eq!(index, 3);
        assert_eq!(result.checker_name, "LemmeKnow Checker");
    }

    #[test]
    fn test_check_goes_to_dictionary() {
        let athena = CheckerTypes::CheckAthena(Checker::<Athena>::new());
        assert!(athena.check("exuberant").is_identified);
    }
}
