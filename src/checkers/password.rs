use crate::checkers::checker_result::CheckResult;
use gibberish_or_not::{is_password, Sensitivity};
use lemmeknow::Identifier;

use crate::checkers::checker_type::{Check, Checker};

/// Checks if the input matches a known common password.
///
/// Only passwords of at least [`MIN_PASSWORD_CHARS`] characters, three of them different,
/// count: the list has a thousand four-letter entries and hundreds of digit strings and
/// repeated letters (`1130`, `geil`, `tttttttt`), and wrong decoder keys produce such strings
/// all the time. Digit strings need [`MIN_DIGIT_PASSWORD_CHARS`].
pub struct PasswordChecker;

/// The fewest characters a common password must have to count as plaintext.
const MIN_PASSWORD_CHARS: usize = 5;

/// The fewest characters a common password made of digits only must have (`123456`).
const MIN_DIGIT_PASSWORD_CHARS: usize = 6;

/// The longest entry on gibberish-or-not's common-password list. Longer text skips the
/// lookup, which hashes the whole text.
const MAX_PASSWORD_CHARS: usize = 23;

/// Whether `text` is a common password that counts as plaintext: see [`PasswordChecker`].
pub(crate) fn is_common_password(text: &str) -> bool {
    text.len() <= MAX_PASSWORD_CHARS && could_be_a_password(text) && is_password(text)
}

/// Whether `text` is long and varied enough for a password-list match to mean anything:
/// see [`PasswordChecker`].
fn could_be_a_password(text: &str) -> bool {
    let mut distinct = [0u8; 3];
    let (mut chars, mut kinds, mut digits) = (0usize, 0usize, true);
    for b in text.bytes() {
        chars += 1;
        digits &= b.is_ascii_digit();
        if kinds < 3 && !distinct[..kinds].contains(&b) {
            distinct[kinds] = b;
            kinds += 1;
        }
    }
    kinds >= 3
        && chars
            >= if digits {
                MIN_DIGIT_PASSWORD_CHARS
            } else {
                MIN_PASSWORD_CHARS
            }
}

/// Implementation of the Check trait for PasswordChecker
impl Check for Checker<PasswordChecker> {
    fn new() -> Self {
        Checker {
            name: "Password Checker",
            description: "Checks if the input exactly matches a known common password",
            link: "https://crates.io/crates/gibberish-or-not",
            tags: vec!["password", "security"],
            expected_runtime: 0.01,
            popularity: 1.0,
            lemmeknow_config: Identifier::default(),
            sensitivity: Sensitivity::Medium,
            _phantom: std::marker::PhantomData,
        }
    }

    fn check(&self, text: &str) -> CheckResult {
        CheckResult {
            is_identified: is_common_password(text),
            text: text.to_string(),
            checker_name: self.name,
            checker_description: self.description,
            description: "Common Password".to_string(),
            link: self.link,
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
    use gibberish_or_not::Sensitivity;

    #[test]
    fn test_check_common_password() {
        let checker = Checker::<PasswordChecker>::new();
        assert!(checker.check("123456").is_identified);
    }

    #[test]
    fn test_check_not_password() {
        let checker = Checker::<PasswordChecker>::new();
        assert!(!checker.check("not-a-common-password").is_identified);
    }

    #[test]
    fn test_check_case_sensitive() {
        let checker = Checker::<PasswordChecker>::new();
        // Test exact matching with different cases
        let original = checker.check("password").is_identified;
        let uppercase = checker.check("PASSWORD").is_identified;
        assert!(original != uppercase, "Case sensitivity test failed");
    }

    #[test]
    fn short_and_repetitive_passwords_are_not_plaintext() {
        // All on the common-password list, and all found by wrong keys in searches of
        // inputs with no plaintext (benches/data/plaintext/e2e.tsv)
        let checker = Checker::<PasswordChecker>::new();
        for junk in ["1130", "geil", "tttttttt", "111111", "2424"] {
            assert!(!checker.check(junk).is_identified, "{junk}");
        }
        for password in ["123456", "abc123", "dragon", "trustno1", "letmein"] {
            assert!(checker.check(password).is_identified, "{password}");
        }
    }

    #[test]
    fn test_default_sensitivity_is_medium() {
        let checker = Checker::<PasswordChecker>::new();
        assert!(matches!(checker.get_sensitivity(), Sensitivity::Medium));
    }

    #[test]
    fn test_with_sensitivity_changes_sensitivity() {
        let checker = Checker::<PasswordChecker>::new().with_sensitivity(Sensitivity::Low);
        assert!(matches!(checker.get_sensitivity(), Sensitivity::Low));

        let checker = Checker::<PasswordChecker>::new().with_sensitivity(Sensitivity::High);
        assert!(matches!(checker.get_sensitivity(), Sensitivity::High));
    }
}
