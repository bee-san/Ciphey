/// import general checker
use crate::checkers::{
    checker_type::{Check, Checker},
    default_checker::DefaultChecker,
};
use std::collections::HashSet;

/// Library input is the default API input
/// The CLI turns its arguments into a LibraryInput struct
#[allow(dead_code)]
pub struct LibraryInput<Type> {
    /// The input to be decoded.
    /// Given to us by the user.
    pub encoded_text: String,
    /// A level of verbosity to determine.
    /// How much we print in logs.
    pub verbose: i32,
    /// The checker to use
    pub checker: Checker<Type>,
    /// Pre-loaded wordlist (allows library users to provide wordlist directly)
    pub wordlist: Option<HashSet<String>>,
}

impl Default for LibraryInput<DefaultChecker> {
    fn default() -> Self {
        LibraryInput {
            encoded_text: String::new(),
            // this will be of type Checker<DefaultChecker>
            verbose: 0,
            checker: Checker::new(),
            wordlist: None,
        }
    }
}

impl<Type> LibraryInput<Type> {
    /// Set a pre-loaded wordlist
    ///
    /// This method is part of the public API for library users who want to provide
    /// a pre-loaded wordlist directly. While it may not be used internally yet,
    /// it's maintained for API compatibility and future use cases.
    #[allow(dead_code)]
    pub fn with_wordlist(mut self, wordlist: HashSet<String>) -> Self {
        self.wordlist = Some(wordlist);
        self
    }
}
