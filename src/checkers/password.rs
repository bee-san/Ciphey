use crate::checkers::checker_result::CheckResult;
use gibberish_or_not::{is_password, Sensitivity};
use lemmeknow::Identifier;

use crate::checkers::checker_type::{Check, Checker};

/// Checks if the input matches a known common password.
pub struct PasswordChecker;

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
            is_identified: is_password(text),
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
