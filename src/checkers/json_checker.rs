use crate::checkers::checker_result::CheckResult;
use gibberish_or_not::Sensitivity;
use lemmeknow::Identifier;
use serde_json::Value;

use crate::checkers::checker_type::{Check, Checker};

/// Checks if the text is a JSON object or array, such as `{"key": "value"}`.
///
/// Scalars are rejected: `1`, `"x"` and `true` are valid JSON too, but saying so tells
/// nobody anything. Empty objects and arrays are rejected for the same reason.
pub struct JsonChecker;

impl Check for Checker<JsonChecker> {
    fn new() -> Self {
        Checker {
            name: "JSON Checker",
            description: "Checks if the text is a JSON object or array",
            link: "https://www.json.org/",
            tags: vec!["json", "structured"],
            expected_runtime: 0.01,
            popularity: 1.0,
            lemmeknow_config: Identifier::default(),
            sensitivity: Sensitivity::Medium,
            _phantom: std::marker::PhantomData,
        }
    }

    fn check(&self, text: &str) -> CheckResult {
        let mut result = CheckResult::new(self);
        result.text = text.to_string();
        if let Some(description) = identify(text) {
            result.is_identified = true;
            result.description = description;
        }
        result
    }

    fn with_sensitivity(mut self, sensitivity: Sensitivity) -> Self {
        self.sensitivity = sensitivity;
        self
    }

    fn get_sensitivity(&self) -> Sensitivity {
        self.sensitivity
    }
}

/// What the JSON checker identifies `text` as, if anything.
pub(crate) fn identify(text: &str) -> Option<String> {
    is_json_object_or_array(text).then(|| "JavaScript Object Notation (JSON)".to_string())
}

/// Whether `text` is a non-empty JSON object or array.
///
/// Caesar, Atbash and Vigenère keep this true (they only change letters), so they don't
/// ask the checkers about their candidates when their input is JSON: every candidate would
/// pass as JSON.
pub(crate) fn is_json_object_or_array(text: &str) -> bool {
    let trimmed = text.trim();
    // Skips the parser for almost every candidate
    let bracketed = matches!(
        (trimmed.as_bytes().first(), trimmed.as_bytes().last()),
        (Some(b'{'), Some(b'}')) | (Some(b'['), Some(b']'))
    );
    if !bracketed {
        return false;
    }
    match serde_json::from_str::<Value>(trimmed) {
        Ok(Value::Object(object)) => !object.is_empty(),
        Ok(Value::Array(array)) => !array.is_empty(),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn is_json(text: &str) -> bool {
        Checker::<JsonChecker>::new().check(text).is_identified
    }

    #[test]
    fn objects_and_arrays_are_json() {
        for json in [
            "{\"key\": \"value\"}",
            "{\"user\":\"admin\",\"pass\":\"hunter2\"}",
            "[1, 2, 3, 4]",
            "[{\"id\": 1, \"title\": \"hello world\"}]",
            "{\"error\": null, \"ok\": true}\n",
        ] {
            assert!(is_json(json), "{json}");
        }
    }

    #[test]
    fn scalars_empty_containers_and_invalid_json_are_not() {
        for text in [
            "1",
            "\"x\"",
            "true",
            "null",
            "{}",
            "[]",
            "{key: value}",
            "[1, 2",
            "{\"a\": 1}}",
            "hello",
        ] {
            assert!(!is_json(text), "{text}");
        }
    }

    #[test]
    fn the_result_keeps_the_text() {
        let result = Checker::<JsonChecker>::new().check("[1, 2]");
        assert_eq!(result.text, "[1, 2]");
        assert_eq!(result.description, "JavaScript Object Notation (JSON)");
    }
}
