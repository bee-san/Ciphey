use crate::checkers::CheckerTypes;
use crate::decoders::interface::check_string_success;

use super::crack_results::CrackResult;
use super::interface::Crack;
use super::interface::Decoder;

use log::{info, trace};

/// Atbash Decoder
pub struct AtbashDecoder;

impl Crack for Decoder<AtbashDecoder> {
    fn new() -> Decoder<AtbashDecoder> {
        Decoder {
            name: "atbash",
            description: "Atbash is a monoalphabetic substitution cipher originally used to encrypt the Hebrew alphabet. It can be modified for use with any known writing system with a standard collating order.",
            link: "https://en.wikipedia.org/wiki/Atbash",
            tags: vec!["atbash", "substitution", "decoder", "reciprocal"],
            popularity: 0.6,
            phantom: std::marker::PhantomData,
        }
    }

    /// This function does the actual decoding
    /// It returns an Option<string> if it was successful
    /// Else the Option returns nothing and the error is logged in Trace
    fn crack(&self, text: &str, checker: &CheckerTypes) -> CrackResult {
        trace!("Trying atbash with text {:?}", text);
        let decoded_text = atbash_to_alphabet(text);

        trace!("Decoded text for atbash: {:?}", decoded_text);
        let mut results = CrackResult::new(self, text.to_string());

        if !check_string_success(&decoded_text, text) {
            info!(
                "Failed to decode atbash because check_string_success returned false on string {}",
                decoded_text
            );
            return results;
        }

        let checker_result = checker.check(&decoded_text);
        results.unencrypted_text = Some(vec![decoded_text]);

        results.update_checker(&checker_result);

        results
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

/// Maps atbash to the alphabet
fn atbash_to_alphabet(text: &str) -> String {
    text.chars()
        .map(|char| match char {
            letter @ 'a'..='z' => (b'a' + b'z' - letter as u8) as char,
            letter @ 'A'..='Z' => (b'A' + b'Z' - letter as u8) as char,
            other => other,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::AtbashDecoder;
    use crate::{
        checkers::{
            athena::Athena,
            checker_type::{Check, Checker},
            CheckerTypes,
        },
        decoders::interface::{Crack, Decoder},
    };

    // helper for tests
    fn get_athena_checker() -> CheckerTypes {
        let athena_checker = Checker::<Athena>::new();
        CheckerTypes::CheckAthena(athena_checker)
    }

    #[test]
    fn test_atbash() {
        let decoder = Decoder::<AtbashDecoder>::new();
        let result = decoder.crack("svool dliow", &get_athena_checker());
        assert_eq!(result.unencrypted_text.unwrap()[0], "hello world");
    }

    #[test]
    fn test_atbash_capitalization() {
        let decoder = Decoder::<AtbashDecoder>::new();
        let result = decoder.crack(
            "Zgyzhs Hslfow Pvvk Xzkrgzorazgrlm orpv GSRH",
            &get_athena_checker(),
        );
        assert_eq!(
            result.unencrypted_text.unwrap()[0],
            "Atbash Should Keep Capitalization like THIS"
        );
    }

    #[test]
    fn test_atbash_non_alphabetic_characters() {
        let decoder = Decoder::<AtbashDecoder>::new();
        let result = decoder.crack(
            "Zgyzhs hslfow ovzev xszizxgvih orpv gsvhv: ',.39=_#%^ rmgzxg zugvi wvxlwrmt!",
            &get_athena_checker(),
        );
        assert_eq!(
            result.unencrypted_text.unwrap()[0],
            "Atbash should leave characters like these: ',.39=_#%^ intact after decoding!"
        );
    }

    #[test]
    fn atbash_decode_empty_string() {
        // Atbash returns an empty string, this is a valid atbash string
        // but returns False on check_string_success
        let atbash_decoder = Decoder::<AtbashDecoder>::new();
        let result = atbash_decoder
            .crack("", &get_athena_checker())
            .unencrypted_text;
        assert!(result.is_none());
    }

    #[test]
    fn atbash_decode_handles_panics() {
        let atbash_decoder = Decoder::<AtbashDecoder>::new();
        let result = atbash_decoder
            .crack("583920482058430191", &get_athena_checker())
            .unencrypted_text;
        assert!(result.is_none());
    }

    #[test]
    fn atbash_handle_panic_if_empty_string() {
        let atbash_decoder = Decoder::<AtbashDecoder>::new();
        let result = atbash_decoder
            .crack("", &get_athena_checker())
            .unencrypted_text;
        assert!(result.is_none());
    }

    #[test]
    fn atbash_work_if_string_not_atbash() {
        let atbash_decoder = Decoder::<AtbashDecoder>::new();
        let result = atbash_decoder
            .crack("hello good day!", &get_athena_checker())
            .unencrypted_text;
        assert!(result.is_some());
    }

    #[test]
    fn atbash_handle_panic_if_emoji() {
        let atbash_decoder = Decoder::<AtbashDecoder>::new();
        let result = atbash_decoder
            .crack("😂", &get_athena_checker())
            .unencrypted_text;
        assert!(result.is_none());
    }
}
