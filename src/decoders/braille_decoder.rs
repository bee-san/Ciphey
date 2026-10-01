use super::crack_results::CrackResult;
use super::interface::Crack;
use super::interface::Decoder;
use crate::checkers::CheckerTypes;

use log::trace;
use std::collections::HashMap;

/// Braille Decoder
pub struct BrailleDecoder;

impl Crack for Decoder<BrailleDecoder> {
    fn new() -> Decoder<BrailleDecoder> {
        Decoder {
            name: "Braille",
            description: "Braille is a tactile writing system used by people who are visually impaired. It consists of raised dots arranged in cells of up to six dots in a 3×2 pattern.",
            link: "https://en.wikipedia.org/wiki/Braille",
            tags: vec!["braille", "substitution", "decoder"],
            popularity: 0.4,
            phantom: std::marker::PhantomData,
        }
    }

    fn crack(&self, text: &str, checker: &CheckerTypes) -> CrackResult {
        trace!("Trying braille with text {:?}", text);
        let mut results = CrackResult::new(self, text.to_string());

        if text.is_empty() {
            return results;
        }

        let decoded_text = braille_to_text(text);

        // check if the decoder transformed the input
        if decoded_text == text {
            return results; // unencrypted text is already None by default
        }

        let checker_result = checker.check(&decoded_text);
        if checker_result.is_identified {
            trace!("Found a match with braille");
            results.unencrypted_text = Some(vec![decoded_text]);
            results.update_checker(&checker_result);
            return results;
        }

        results.unencrypted_text = Some(vec![decoded_text]);
        results
    }

    fn get_tags(&self) -> &Vec<&str> {
        &self.tags
    }

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

/// Converts Braille Unicode characters to their corresponding Latin alphabet characters
///
/// This function maps each Braille character to its corresponding Latin letter
/// and returns the decoded text as a String.
fn braille_to_text(text: &str) -> String {
    let mut mapping = HashMap::new();
    mapping.insert('⠁', 'a');
    mapping.insert('⠃', 'b');
    mapping.insert('⠉', 'c');
    mapping.insert('⠙', 'd');
    mapping.insert('⠑', 'e');
    mapping.insert('⠋', 'f');
    mapping.insert('⠛', 'g');
    mapping.insert('⠓', 'h');
    mapping.insert('⠊', 'i');
    mapping.insert('⠚', 'j');
    mapping.insert('⠅', 'k');
    mapping.insert('⠇', 'l');
    mapping.insert('⠍', 'm');
    mapping.insert('⠝', 'n');
    mapping.insert('⠕', 'o');
    mapping.insert('⠏', 'p');
    mapping.insert('⠟', 'q');
    mapping.insert('⠗', 'r');
    mapping.insert('⠎', 's');
    mapping.insert('⠞', 't');
    mapping.insert('⠥', 'u');
    mapping.insert('⠧', 'v');
    mapping.insert('⠺', 'w');
    mapping.insert('⠭', 'x');
    mapping.insert('⠽', 'y');
    mapping.insert('⠵', 'z');
    mapping.insert('⠀', ' ');

    text.chars()
        .map(|c| *mapping.get(&c).unwrap_or(&c))
        .collect::<String>()
}

#[cfg(test)]
mod tests {
    use super::BrailleDecoder;
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
    fn braille_decodes_successfully() {
        let braille_decoder = Decoder::<BrailleDecoder>::new();
        let result = braille_decoder.crack("⠓⠑⠇⠇⠕⠀⠺⠕⠗⠇⠙", &get_athena_checker());
        assert_eq!(result.unencrypted_text.unwrap()[0], "hello world");
    }

    #[test]
    fn braille_handles_panic_if_empty_string() {
        let braille_decoder = Decoder::<BrailleDecoder>::new();
        let result = braille_decoder
            .crack("", &get_athena_checker())
            .unencrypted_text;
        assert!(result.is_none());
    }

    #[test]
    fn test_braille_long_sentence() {
        let braille_decoder = Decoder::<BrailleDecoder>::new();
        let test_string = "⠓⠑⠇⠇⠕⠀⠍⠽⠀⠝⠁⠍⠑⠀⠊⠎⠀⠃⠑⠑⠀⠁⠝⠙⠀⠊⠀⠇⠊⠅⠑⠀⠙⠕⠛⠀⠁⠝⠙⠀⠁⠏⠏⠇⠑⠀⠁⠝⠙⠀⠞⠗⠑⠑";
        let expected = "hello my name is bee and i like dog and apple and tree";

        let result = braille_decoder.crack(test_string, &get_athena_checker());

        assert!(result.unencrypted_text.is_some());
        assert_eq!(result.unencrypted_text.unwrap()[0].to_lowercase(), expected);
    }

    #[test]
    fn test_braille_handles_invalid_chars() {
        let braille_decoder = Decoder::<BrailleDecoder>::new();
        let result = braille_decoder
            .crack("123ABC", &get_athena_checker())
            .unencrypted_text;
        assert!(result.is_none());
    }

    #[test]
    fn test_braille_handles_mixed_content() {
        let braille_decoder = Decoder::<BrailleDecoder>::new();
        let result = braille_decoder
            .crack("⠓⠑⠇⠇⠕123", &get_athena_checker())
            .unencrypted_text;
        assert!(result.is_some());
        assert_eq!(result.unwrap()[0], "hello123");
    }
}
