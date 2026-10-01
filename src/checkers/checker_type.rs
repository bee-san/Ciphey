/// Checker_type is a type used to define checkers
/// This means that we can standardise the way we check for plaintext
use crate::checkers::checker_result::CheckResult;
use gibberish_or_not::Sensitivity;
use lemmeknow::Identifier;

/// Every checker is of type CheckerType
/// This will let us pick & choose which checkers to use
/// at runtime.
pub struct Checker<Type> {
    /// The name of the checker
    pub name: &'static str,
    /// The description of the checker
    /// you can take the first line from Wikipedia
    /// Sometimes our checkers do not exist on Wikipedia so we write our own.
    pub description: &'static str,
    /// The link to the checker's website
    /// Wikipedia link, articles, github etc
    pub link: &'static str,
    /// The tags of the checker
    pub tags: Vec<&'static str>,
    /// The expected runtime of the checker
    /// We get this by bench marking the code
    pub expected_runtime: f32,
    /// The popularity of the checker
    pub popularity: f32,
    /// lemmeknow config object
    pub lemmeknow_config: Identifier,
    /// The sensitivity level for gibberish detection
    /// This is only used by checkers that implement the SensitivityAware trait
    pub sensitivity: Sensitivity,
    /// Enhanced gibberish detector using BERT model
    /// This is only used when enhanced detection is enabled
    pub enhanced_detector: Option<()>, // Changed from GibberishDetector to () since we don't have the actual type
    /// <https://doc.rust-lang.org/std/marker/struct.PhantomData.html>
    /// Let's us save memory by telling the compiler that our type
    /// acts like a type `T` even though it doesn't.
    /// Stops the compiler complaining, else we'd need to implement
    /// some magic to make it work.
    pub _phantom: std::marker::PhantomData<Type>,
}

/// Helper trait for returning info from a Checker
pub trait CheckInfo {
    /// Returns the checker name
    fn get_name(&self) -> &str;
    /// Returns the checker description
    fn get_description(&self) -> &str;
}

impl<Type> CheckInfo for Checker<Type> {
    /// Returns the checker name
    fn get_name(&self) -> &str {
        self.name
    }
    /// Returns the checker description
    fn get_description(&self) -> &str {
        self.description
    }
}

/// Every checker must implement this trait
/// Which checks the given text to see if its plaintext
/// and returns CheckResult, which is our results object.
pub trait Check {
    /// Returns a new struct of type CheckerType
    fn new() -> Self
    where
        Self: Sized;
    /// Checks the given text to see if its plaintext
    fn check(&self, text: &str) -> CheckResult;
    /// Sets the sensitivity level for gibberish detection
    fn with_sensitivity(self, sensitivity: Sensitivity) -> Self
    where
        Self: Sized;
    /// Gets the current sensitivity level
    fn get_sensitivity(&self) -> Sensitivity;
}

/// Optional trait for checkers that use sensitivity for gibberish detection
/// Not all checkers need to implement this trait
/// This is a future improvement - not currently used
pub trait SensitivityAware {
    /// Sets the sensitivity level for gibberish detection
    fn with_sensitivity(self, sensitivity: Sensitivity) -> Self
    where
        Self: Sized;
    /// Gets the current sensitivity level
    fn get_sensitivity(&self) -> Sensitivity;
}
