//! The `detect_plaintext` tool: runs ciphey's plaintext checks on a text, with
//! [`ciphey::detect_plaintext`], and says which checker accepted it and what it took it for.

use ciphey::detection::{CheckerKind, DetectOptions, Detection, Sensitivity};
use rmcp::schemars;
use serde::{Deserialize, Serialize};

use crate::server::{check_length, check_regex, MAX_INPUT_CHARS, MAX_REGEX_CHARS};

/// Arguments of the `detect_plaintext` tool.
#[derive(Debug, Default, Deserialize, schemars::JsonSchema)]
pub struct DetectParams {
    /// The text to check (at most 65536 characters). It is checked as it is: nothing is
    /// decoded first.
    #[schemars(length(min = 1, max = MAX_INPUT_CHARS))]
    pub text: String,
    /// The checkers to run, by default all three. `lemmeknow` recognises over 100 formats
    /// (IP and email addresses, URLs, API keys and tokens, crypto wallets, credit card
    /// numbers, CTF flags, ...), `password` matches common passwords and `english` accepts
    /// English text. They run in that order, and the first to accept the text answers.
    pub checkers: Option<Vec<CheckerChoice>>,
    /// How readily the English checker takes text for English: `low` is the strictest,
    /// `medium` the default, and `high` the most lenient (it accepts English with typos,
    /// names or other noise in it, and more gibberish). The other checkers ignore it.
    pub sensitivity: Option<SensitivityChoice>,
    /// A regex or crib, such as `^flag\{` (at most 1000 characters). On its own it is the
    /// only check, as in `decode`: text it matches is plaintext. Pass `checkers` as well to
    /// run them after it.
    #[schemars(length(max = MAX_REGEX_CHARS))]
    pub regex: Option<String>,
}

/// A checker `detect_plaintext` can be asked to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[schemars(inline)]
pub enum CheckerChoice {
    // The variants have no doc comments on purpose: with them, schemars describes the enum
    // with `oneOf`, which some MCP clients don't understand, instead of a plain `enum`.
    Lemmeknow,
    Password,
    English,
}

impl From<CheckerChoice> for CheckerKind {
    fn from(choice: CheckerChoice) -> Self {
        match choice {
            CheckerChoice::Lemmeknow => CheckerKind::LemmeKnow,
            CheckerChoice::Password => CheckerKind::Password,
            CheckerChoice::English => CheckerKind::English,
        }
    }
}

/// How lenient the English checker is, see [`DetectParams::sensitivity`].
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
#[schemars(inline)]
pub enum SensitivityChoice {
    // No doc comments, as for `CheckerChoice`.
    Low,
    #[default]
    Medium,
    High,
}

impl From<SensitivityChoice> for Sensitivity {
    fn from(choice: SensitivityChoice) -> Self {
        match choice {
            SensitivityChoice::Low => Sensitivity::Low,
            SensitivityChoice::Medium => Sensitivity::Medium,
            SensitivityChoice::High => Sensitivity::High,
        }
    }
}

impl DetectParams {
    /// Checks the input limits and fills in defaults. An `Err` tells the caller what to fix.
    pub fn into_request(self) -> Result<DetectRequest, String> {
        if self.text.is_empty() {
            return Err("`text` is empty: pass the text to check".to_string());
        }
        check_length("text", &self.text, MAX_INPUT_CHARS)?;
        let request = DetectRequest {
            text: self.text,
            checkers: self.checkers,
            sensitivity: self.sensitivity.unwrap_or_default(),
            regex: check_regex(self.regex)?,
        };
        if request.options()?.enabled_checkers().next().is_none() {
            return Err(
                "there are no checkers to run: list at least one of `lemmeknow`, \
                 `password` and `english` in `checkers`, or pass a `regex`"
                    .to_string(),
            );
        }
        Ok(request)
    }
}

/// A validated `detect_plaintext` call, sent from the server to a worker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectRequest {
    /// The text to check.
    pub text: String,
    /// The checkers to run, or `None` for the default ones (or only the crib, if there is
    /// one).
    pub checkers: Option<Vec<CheckerChoice>>,
    /// How lenient the English checker is.
    pub sensitivity: SensitivityChoice,
    /// A crib, checked before the other checkers.
    pub regex: Option<String>,
}

impl DetectRequest {
    /// The library's options for this request.
    pub fn options(&self) -> Result<DetectOptions, String> {
        let mut options = DetectOptions::new().sensitivity(self.sensitivity.into());
        if let Some(pattern) = &self.regex {
            // Turns the other checkers off, as `ciphey --regex` does.
            options = options
                .regex(pattern)
                .map_err(|error| format!("`regex` is not a valid regular expression: {error}"))?;
        }
        if let Some(checkers) = &self.checkers {
            let crib = self.regex.as_ref().map(|_| CheckerKind::Regex);
            options = options.checkers(crib.into_iter().chain(checkers.iter().map(|&c| c.into())));
        }
        Ok(options)
    }
}

/// Runs the checks `request` asks for. Called in a worker.
pub fn run(request: &DetectRequest) -> Result<DetectOutput, String> {
    let options = request.options()?;
    let detection = ciphey::detect_plaintext(&request.text, &options);
    Ok(DetectOutput {
        is_plaintext: detection.is_some(),
        detection: detection.as_ref().map(DetectionOutput::from),
        checkers: options
            .enabled_checkers()
            .map(|kind| kind.id().to_string())
            .collect(),
    })
}

/// Result of the `detect_plaintext` tool.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DetectOutput {
    /// Whether one of the checkers accepted the text as plaintext.
    pub is_plaintext: bool,
    /// What the checker that accepted the text found. Null if none accepted it.
    pub detection: Option<DetectionOutput>,
    /// The checkers that ran, in order, such as `["lemmeknow", "password", "english"]`.
    pub checkers: Vec<String>,
}

/// What one of ciphey's plaintext checkers found.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DetectionOutput {
    /// The checker that accepted the text: `regex` (the crib), `lemmeknow`, `password`,
    /// `english`, or `jwt_structure` (a well-formed JSON Web Token, only in `decode_with`
    /// results of the JWT decoder).
    pub checker: String,
    /// What the checker took the text for: `Words` for English, the name of the format
    /// LemmeKnow matched, such as `Internet Protocol (IP) Address Version 4`,
    /// `Common Password`, or `Regex matched: <pattern>`.
    pub description: String,
    /// How sure the checker is, from 0 to 1, if it has a measure of it. Only LemmeKnow does:
    /// the rarity of the format it matched, 1 for formats little else matches (an AWS S3
    /// URL), less for broad ones (0.7 for an IP address or a URL, 0.5 for an email address).
    /// Null for the other checkers, which answer yes or no.
    pub confidence: Option<f64>,
}

impl From<&Detection> for DetectionOutput {
    fn from(detection: &Detection) -> Self {
        Self {
            checker: detection.checker.id().to_string(),
            description: detection.description.clone(),
            confidence: detection.confidence.map(tidy_confidence),
        }
    }
}

/// `confidence` as the `f64` with the same shortest decimal form, so that 0.7 is sent as
/// 0.7 and not as 0.699999988079071.
fn tidy_confidence(confidence: f32) -> f64 {
    confidence
        .to_string()
        .parse()
        .unwrap_or_else(|_| f64::from(confidence))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(text: &str) -> DetectParams {
        DetectParams {
            text: text.to_string(),
            ..DetectParams::default()
        }
    }

    fn detect(params: DetectParams) -> DetectOutput {
        run(&params.into_request().unwrap()).unwrap()
    }

    #[test]
    fn into_request_applies_defaults() {
        assert_eq!(
            params("192.168.0.1").into_request().unwrap(),
            DetectRequest {
                text: "192.168.0.1".to_string(),
                checkers: None,
                sensitivity: SensitivityChoice::Medium,
                regex: None,
            }
        );
    }

    #[test]
    fn into_request_checks_the_limits() {
        let error = params("").into_request().unwrap_err();
        assert!(error.contains("`text` is empty"), "{error}");

        assert!(params(&"é".repeat(MAX_INPUT_CHARS)).into_request().is_ok());
        let error = params(&"é".repeat(MAX_INPUT_CHARS + 1))
            .into_request()
            .unwrap_err();
        assert!(error.contains("the limit is 65536"), "{error}");

        let error = DetectParams {
            regex: Some("(unclosed".to_string()),
            ..params("hi")
        }
        .into_request()
        .unwrap_err();
        assert!(error.contains("not a valid regular expression"), "{error}");

        let error = DetectParams {
            regex: Some("a".repeat(MAX_REGEX_CHARS + 1)),
            ..params("hi")
        }
        .into_request()
        .unwrap_err();
        assert!(error.contains("the limit is 1000"), "{error}");
    }

    #[test]
    fn into_request_needs_a_checker_to_run() {
        let error = DetectParams {
            checkers: Some(Vec::new()),
            ..params("hello there general")
        }
        .into_request()
        .unwrap_err();
        assert!(error.contains("no checkers to run"), "{error}");

        // A crib on its own is enough, and "" means no crib, as clients send it for an
        // argument they don't use.
        let crib_only = DetectParams {
            checkers: Some(Vec::new()),
            regex: Some("hello".to_string()),
            ..params("hello there general")
        };
        assert!(crib_only.into_request().is_ok());
        let empty_crib = DetectParams {
            checkers: Some(Vec::new()),
            regex: Some(String::new()),
            ..params("hello there general")
        };
        assert!(empty_crib.into_request().is_err());
    }

    #[test]
    fn reports_the_checker_description_and_confidence() {
        let ip = detect(params("192.168.0.1"));
        assert!(ip.is_plaintext);
        assert_eq!(
            ip.detection,
            Some(DetectionOutput {
                checker: "lemmeknow".to_string(),
                description: "Internet Protocol (IP) Address Version 4".to_string(),
                confidence: Some(0.7),
            })
        );
        assert_eq!(ip.checkers, ["lemmeknow", "password", "english"]);

        let english = detect(params("hello there general")).detection.unwrap();
        assert_eq!(english.checker, "english");
        assert_eq!(english.description, "Words");
        assert_eq!(english.confidence, None);

        let password = detect(params("123456")).detection.unwrap();
        assert_eq!(password.checker, "password");

        let base64 = detect(params("aGVsbG8gdGhlcmUgZ2VuZXJhbA=="));
        assert!(!base64.is_plaintext);
        assert_eq!(base64.detection, None);
    }

    #[test]
    fn runs_only_the_chosen_checkers() {
        let english_only = DetectParams {
            checkers: Some(vec![CheckerChoice::English]),
            ..params("192.168.0.1")
        };
        let output = detect(english_only);
        assert!(!output.is_plaintext);
        assert_eq!(output.checkers, ["english"]);

        // They run in the library's order, whatever order they're given in.
        let reversed = DetectParams {
            checkers: Some(vec![CheckerChoice::English, CheckerChoice::Lemmeknow]),
            ..params("192.168.0.1")
        };
        let output = detect(reversed);
        assert_eq!(output.checkers, ["lemmeknow", "english"]);
        assert_eq!(output.detection.unwrap().checker, "lemmeknow");
    }

    #[test]
    fn a_crib_is_the_only_check_unless_checkers_are_chosen() {
        let crib = DetectParams {
            regex: Some(r"^flag\{".to_string()),
            ..params("hello there general")
        };
        let output = detect(crib);
        assert!(!output.is_plaintext);
        assert_eq!(output.checkers, ["regex"]);

        let found = detect(DetectParams {
            regex: Some(r"^flag\{".to_string()),
            ..params("flag{b4s3_64_1s_fun}")
        })
        .detection
        .unwrap();
        assert_eq!(found.checker, "regex");
        assert_eq!(found.description, r"Regex matched: ^flag\{");

        let crib_then_english = DetectParams {
            regex: Some(r"^flag\{".to_string()),
            checkers: Some(vec![CheckerChoice::English]),
            ..params("hello there general")
        };
        let output = detect(crib_then_english);
        assert_eq!(output.checkers, ["regex", "english"]);
        assert_eq!(output.detection.unwrap().checker, "english");
    }

    #[test]
    fn sensitivity_changes_the_english_checker() {
        // One English word in gibberish: only `high` takes it for English.
        let text = "Rcl maocr otmwi lit dnoen oehc 13 iron seah.";
        let at = |sensitivity| {
            detect(DetectParams {
                sensitivity: Some(sensitivity),
                ..params(text)
            })
            .is_plaintext
        };
        assert!(!at(SensitivityChoice::Low));
        assert!(at(SensitivityChoice::High));
    }

    #[test]
    fn confidences_keep_their_decimal_form() {
        assert_eq!(tidy_confidence(0.7), 0.7);
        assert_eq!(tidy_confidence(0.5), 0.5);
        assert_eq!(tidy_confidence(1.0), 1.0);
    }
}
