//! Reverses the input string
//! Performs error handling and returns a string
//! Call reverse_decoder.crack to use. It returns option<String> and check with
//! `result.is_some()` to see if it returned okay.

use crate::checkers::CheckerTypes;

use super::crack_results::CrackResult;
use super::interface::Crack;
use super::interface::Decoder;

use log::trace;
/// The Reverse decoder is a decoder that reverses the input string.
/// ```rust
/// use ciphey::decoders::reverse_decoder::ReverseDecoder;
/// use ciphey::decoders::interface::{Crack, Decoder};
/// use ciphey::config::{set_global_config, Config};
/// use ciphey::checkers::{athena::Athena, CheckerTypes, checker_type::{Check, Checker}};
///
/// let reversedecoder = Decoder::<ReverseDecoder>::new();
/// let athena_checker = Checker::<Athena>::new();
/// let checker = CheckerTypes::CheckAthena(athena_checker);
///
/// let result = reversedecoder.crack("stac", &checker).unencrypted_text;
/// assert!(result.is_some());
/// assert_eq!(result.unwrap()[0], "cats");
/// ```
pub struct ReverseDecoder;

impl Crack for Decoder<ReverseDecoder> {
    fn new() -> Decoder<ReverseDecoder> {
        Decoder {
            name: "Reverse",
            description: "Reverses a string. stac -> cats",
            link: "http://string-functions.com/reverse.aspx",
            tags: vec!["reverse", "decoder", "reciprocal"],
            // I have never seen a reversed string in a CTF
            // or otherwise
            popularity: 0.7,
            phantom: std::marker::PhantomData,
        }
    }

    /// This function does the actual decoding
    /// It returns an Option<string> if it was successful
    /// Else the Option returns nothing and the error is logged in Trace
    fn crack(&self, text: &str, checker: &CheckerTypes) -> CrackResult {
        trace!("Running reverse string");
        let mut result = CrackResult::new(self, text.to_string());
        if text.is_empty() {
            return result;
        }
        let rev_str: String = text.chars().rev().collect();
        let checker_res = checker.check(&rev_str);

        result.unencrypted_text = Some(vec![rev_str]);
        result.update_checker(&checker_res);
        result
    }
    /// Gets all tags for this decoder
    fn get_tags(&self) -> &Vec<&str> {
        &self.tags
    }
    /// Gets the name for the current decoder
    fn get_name(&self) -> &str {
        self.name
    }
    /// Gets the popularity for the current decoder
    fn get_popularity(&self) -> f32 {
        self.popularity
    }
    /// Gets the description for the current decoder
    fn get_description(&self) -> &str {
        self.description
    }
    /// Gets the link for the current decoder
    fn get_link(&self) -> &str {
        self.link
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        checkers::{
            athena::Athena,
            checker_type::{Check, Checker},
        },
        decoders::interface::Crack,
    };

    // helper for tests
    fn get_athena_checker() -> CheckerTypes {
        let athena_checker = Checker::<Athena>::new();
        CheckerTypes::CheckAthena(athena_checker)
    }

    #[test]
    fn returns_success() {
        let reverse_decoder = Decoder::<ReverseDecoder>::new();
        let result = reverse_decoder
            .crack("stac", &get_athena_checker())
            .unencrypted_text
            .expect("No unencrypted string for reverse decoder");
        assert_eq!(result[0], "cats");
    }

    #[test]
    fn returns_nothing() {
        let reverse_decoder = Decoder::<ReverseDecoder>::new();
        let result = reverse_decoder
            .crack("", &get_athena_checker())
            .unencrypted_text;
        assert!(result.is_none());
    }
}
