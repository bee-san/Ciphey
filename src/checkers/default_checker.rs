use gibberish_or_not::Sensitivity;
use lemmeknow::Identifier;

use super::{
    checker_result::CheckResult,
    checker_type::{Check, Checker},
};

/// The default checker is used to check if the text is plaintext
/// Based on what the ciphey team has found to be the best checker.
pub struct DefaultChecker;

impl Check for Checker<DefaultChecker> {
    fn new() -> Self {
        Checker {
            name: "Template checker",
            description: "This is a default template checker. If you're seeing this, it's an error. Please contact us on Discord http://discord.skerritt.blog",
            link: "http://discord.skerritt.blog",
            tags: vec![],
            expected_runtime: 0.0,
            popularity: 0.0,
            lemmeknow_config: Identifier::default(),
            sensitivity: Sensitivity::Medium, // Default to Medium sensitivity
            _phantom: std::marker::PhantomData,
        }
    }

    fn check(&self, _text: &str) -> CheckResult {
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

#[cfg(test)]
mod tests {
    use crate::checkers::{
        checker_result::CheckResult,
        checker_type::{Check, Checker},
        default_checker::DefaultChecker,
    };

    #[test]
    fn default_checker_works() {
        let checker = Checker::<DefaultChecker>::new();
        let checker_result = CheckResult::new(&checker);
        assert!(!checker_result.is_identified);
    }
}
