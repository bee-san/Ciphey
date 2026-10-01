use crate::checkers::CheckerTypes;
use crate::decoders::interface::check_string_success;

use super::crack_results::CrackResult;
use super::interface::Crack;
use super::interface::Decoder;

use log::{debug, info, trace};
use regex::Regex;

/// A1Z26 Decoder
pub struct A1Z26Decoder;

impl Crack for Decoder<A1Z26Decoder> {
    fn new() -> Self {
        Decoder {
            name: "a1z26",
            description: "A1Z26 is an encoding that maps each letter to its numeric position in the alphabet. This encoding cannot represent spaces or punctuation.",
            link: "https://dadstuffsite.com/a1z26-cipher-what-it-is-and-how-to-teach-your-kids/",
            tags: vec!["A1Z26", "substitution", "decoder"],
            popularity: 0.6,
            phantom: std::marker::PhantomData,
        }
    }

    /// Decode using the A1Z26 encoding
    /// It returns an `Option<String>` if it was successful
    /// Else the Option returns nothing and the error is logged in Trace
    ///
    /// A1Z26 is an encoding that maps each letter to its numeric position in the alphabet. This
    /// encoding cannot represent spaces or punctuation. The output of a successful decoding will
    /// be a string of capital letters with no spaces or punctuation.
    ///
    /// This implementation accepts a list of decimal numbers separated by any combination of
    /// delimiters including `,` `;` `:` '-' and whitespace. For successful decoding, the input
    /// must contain at least one numeric digit, and every number must be in the range 1 to 26. The
    /// input is allowed to start and end with delimiters.
    ///
    /// If the input includes any characters other than numeric digits and recognized delimiters,
    /// then decoding will fail.
    ///
    /// Note that the string `-1` decodes to `A` because the `-` is interpreted as a delimiter, not a negative sign.
    fn crack(&self, text: &str, checker: &CheckerTypes) -> CrackResult {
        trace!("Trying A1Z26 with text {:?}", text);

        let decoded_text = decode_a1z26(text);
        trace!("Decoded text for A1Z26: {:?}", decoded_text);

        let mut results = CrackResult::new(self, text.to_string());

        if decoded_text.is_none() {
            debug!("Failed to decode A1Z26");
            return results;
        }

        let decoded_text = decoded_text.unwrap();
        if !check_string_success(&decoded_text, text) {
            info!(
                "Failed to decode A1Z26 because check_string_success returned false on string {}",
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

/// This function does the actual decoding
/// It returns an `Option<String>` if it was successful
/// Else the Option returns nothing and the error is logged in Trace
fn decode_a1z26(ctext: &str) -> Option<String> {
    let re_has_a_digit = Regex::new(r"[0-9]").expect("Regex should be valid");
    if !re_has_a_digit.is_match(ctext) {
        return None;
    }

    let re_all_valid_chars = Regex::new(r"\A([0-9,;:\-\s])*\z").expect("Regex should be valid");
    if !re_all_valid_chars.is_match(ctext) {
        return None;
    }

    let re_delimiters = Regex::new(r"[,;:\-\s]+").expect("Regex should be valid");
    let letters: Option<Vec<char>> = re_delimiters
        .split(ctext)
        .filter(|x| !x.is_empty())
        .map(decode_one_char_a1z26)
        .collect();
    let decoded_text: Option<String> = letters.map(|x| x.into_iter().collect());

    decoded_text
}

/// Decode a single numeric string (decimal digits only) to a single character
fn decode_one_char_a1z26(num_text: &str) -> Option<char> {
    let num: u8 = num_text.parse().ok()?;
    if (1..=26).contains(&num) {
        let letter = (b'A' + num - 1) as char;
        Some(letter)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkers::athena::Athena;
    use crate::checkers::checker_type::{Check, Checker};
    use crate::checkers::CheckerTypes;
    use crate::decoders::interface::Crack;

    // helper for tests
    fn get_athena_checker() -> CheckerTypes {
        let athena_checker = Checker::<Athena>::new();
        CheckerTypes::CheckAthena(athena_checker)
    }

    #[test]
    fn test_a1z26_crack() {
        let decoder = Decoder::<A1Z26Decoder>::new();
        let result = decoder.crack("8 5 12 12 15", &get_athena_checker());
        assert_eq!(result.unencrypted_text.unwrap()[0], "HELLO");
    }

    #[test]
    fn test_a1z26_crack_empty_ctext() {
        let decoder = Decoder::<A1Z26Decoder>::new();
        let result = decoder.crack("", &get_athena_checker());
        assert_eq!(result.unencrypted_text, None);
    }

    #[test]
    fn test_pangram() {
        let decoder = Decoder::<A1Z26Decoder>::new();
        let result = decoder.crack("20 8 5 17 21 9 3 11 2 18 15 23 14 6 15 24 10 21 13 16 5 4 15 22 5 18 20 8 5 12 1 26 25 4 15 7", &get_athena_checker());
        assert_eq!(
            result.unencrypted_text.unwrap()[0],
            "THEQUICKBROWNFOXJUMPEDOVERTHELAZYDOG"
        );
    }

    #[test]
    fn test_empty_ctext() {
        let decoder = Decoder::<A1Z26Decoder>::new();
        let result = decoder.crack("", &get_athena_checker());
        assert_eq!(result.unencrypted_text, None);
    }

    #[test]
    fn test_whitespace_1() {
        let decoder = Decoder::<A1Z26Decoder>::new();
        let result = decoder.crack(" ", &get_athena_checker());
        assert_eq!(result.unencrypted_text, None);
    }

    #[test]
    fn test_whitespace_2() {
        let decoder = Decoder::<A1Z26Decoder>::new();
        let result = decoder.crack("  ", &get_athena_checker());
        assert_eq!(result.unencrypted_text, None);
    }

    #[test]
    fn test_delimiters_only() {
        let decoder = Decoder::<A1Z26Decoder>::new();
        let result = decoder.crack(" \t-:,;\n \r\n \n\r \r ", &get_athena_checker());
        assert_eq!(result.unencrypted_text, None);
    }

    #[test]
    fn test_invalid_chars() {
        let decoder = Decoder::<A1Z26Decoder>::new();
        let result = decoder.crack("1 2 3 x 4 5 6", &get_athena_checker());
        assert_eq!(result.unencrypted_text, None);
    }

    #[test]
    fn test_zero() {
        let decoder = Decoder::<A1Z26Decoder>::new();
        let result = decoder.crack("0", &get_athena_checker());
        assert_eq!(result.unencrypted_text, None);
    }

    #[test]
    fn test_large_number() {
        let decoder = Decoder::<A1Z26Decoder>::new();
        let result = decoder.crack("27", &get_athena_checker());
        assert_eq!(result.unencrypted_text, None);
    }

    #[test]
    fn test_excessive_number() {
        let decoder = Decoder::<A1Z26Decoder>::new();
        let result = decoder.crack(
            "1234567890123456789012345678901234567890",
            &get_athena_checker(),
        );
        assert_eq!(result.unencrypted_text, None);
    }

    #[test]
    fn test_fractional_number() {
        let decoder = Decoder::<A1Z26Decoder>::new();
        let result = decoder.crack("3.5", &get_athena_checker());
        assert_eq!(result.unencrypted_text, None);
    }

    #[test]
    fn test_short_ctext() {
        let decoder = Decoder::<A1Z26Decoder>::new();
        let result = decoder.crack("9", &get_athena_checker());
        assert_eq!(result.unencrypted_text.unwrap()[0], "I");
    }

    #[test]
    fn test_short_ctext_extra_delimiters_1() {
        let decoder = Decoder::<A1Z26Decoder>::new();
        let result = decoder.crack(" 9 ", &get_athena_checker());
        assert_eq!(result.unencrypted_text.unwrap()[0], "I");
    }

    #[test]
    fn test_short_ctext_extra_delimiters_2() {
        let decoder = Decoder::<A1Z26Decoder>::new();
        let result = decoder.crack("-9", &get_athena_checker());
        assert_eq!(result.unencrypted_text.unwrap()[0], "I");
    }

    #[test]
    fn test_short_ctext_extra_delimiters_3() {
        let decoder = Decoder::<A1Z26Decoder>::new();
        let result = decoder.crack("9\n", &get_athena_checker());
        assert_eq!(result.unencrypted_text.unwrap()[0], "I");
    }

    #[test]
    fn test_short_ctext_extra_delimiters_4() {
        let decoder = Decoder::<A1Z26Decoder>::new();
        let result = decoder.crack(":\n-\t,9;\r,", &get_athena_checker());
        assert_eq!(result.unencrypted_text.unwrap()[0], "I");
    }

    #[test]
    fn test_delimited_ctext() {
        let decoder = Decoder::<A1Z26Decoder>::new();
        let result = decoder.crack(",8-5:12,12;15\t23\r15\n18:,12-;4-", &get_athena_checker());
        assert_eq!(result.unencrypted_text.unwrap()[0], "HELLOWORLD");
    }
}
