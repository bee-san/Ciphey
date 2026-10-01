use crate::checkers::CheckerTypes;
use crate::decoders::interface::check_string_success;

use super::crack_results::CrackResult;
use super::interface::Crack;
use super::interface::Decoder;

use log::{debug, info, trace};
use once_cell::sync::Lazy;
use regex::Regex;

/// Runs of whitespace, collapsed to one space in the decoded text.
static RE_WHITESPACE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\s+").unwrap());

/// Morse Code Decoder
/// Does not support decoding of morse code with / instead of a space
/// or new lines for new words.
pub struct MorseCodeDecoder;

impl Crack for Decoder<MorseCodeDecoder> {
    fn new() -> Decoder<MorseCodeDecoder> {
        Decoder {
            name: "Morse Code",
            description: "Morse code is a method used in telecommunication to encode text characters as standardized sequences of two different signal durations, called dots and dashes, or dits and dahs.",
            link: "https://en.wikipedia.org/wiki/Morse_code",
            tags: vec!["morseCode", "decoder", "signals"],
            popularity: 0.7,
            phantom: std::marker::PhantomData,
        }
    }

    /// This function does the actual decoding
    /// It returns an `Option<String>` if it was successful
    /// Else the Option returns nothing and the error is logged in Trace
    fn crack(&self, text: &str, checker: &CheckerTypes) -> CrackResult {
        trace!("Trying Morse Code with text {:?}", text);
        // TODO support new line and slash morse code
        let text = normalise_morse_string(text);
        let decoded_text: Option<String> = text.split(' ').map(morse_to_alphanumeric).collect();

        // remove leading and trailing spaces, and collapse repeated spaces into a single space
        let decoded_text =
            decoded_text.map(|s| RE_WHITESPACE.replace_all(s.trim(), " ").into_owned());

        trace!("Decoded text for morse code: {:?}", decoded_text);
        let mut results = CrackResult::new(self, text.to_string());

        if decoded_text.is_none() {
            debug!("Failed to decode Morse Code because a character was not in the dictionary");
            return results;
        }

        let decoded_text = decoded_text.unwrap();
        if !check_string_success(&decoded_text, &text) {
            info!(
                "Failed to decode morse code because check_string_success returned false on string {}",
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

/// Replace new lines, line breaks, and other delimiters with the standard delimiter '/'
fn normalise_morse_string(text: &str) -> String {
    // The replace function supports patterns https://doc.rust-lang.org/std/str/pattern/trait.Pattern.html#impl-Pattern%3C%27a%3E-3
    // Spaces are included before and after so that '/' gets split into a separate token
    text.to_lowercase()
        .replace(['/', '\\', ':', ',', '\n', '\r'], " / ")
}

/// Maps morse code to its alphanumeric character, returns None for invalid morse-code
fn morse_to_alphanumeric(text: &str) -> Option<&str> {
    let result = match text {
        ".-" => "A",
        "-..." => "B",
        "-.-." => "C",
        "-.." => "D",
        "." => "E",
        "..-." => "F",
        "--." => "G",
        "...." => "H",
        ".." => "I",
        ".---" => "J",
        "-.-" => "K",
        ".-.." => "L",
        "--" => "M",
        "-." => "N",
        "---" => "O",
        ".--." => "P",
        "--.-" => "Q",
        ".-." => "R",
        "..." => "S",
        "-" => "T",
        "..-" => "U",
        "...-" => "V",
        ".--" => "W",
        "-..-" => "X",
        "-.--" => "Y",
        "--.." => "Z",

        ".----" => "1",
        "..---" => "2",
        "...--" => "3",
        "....-" => "4",
        "....." => "5",
        "-...." => "6",
        "--..." => "7",
        "---.." => "8",
        "----." => "9",
        "-----" => "0",

        ".-..." => "&",
        ".--.-." => "@",
        "---..." => ":",
        "--..--" => ",",
        ".-.-.-" => ".",
        ".----." => "'",
        ".-..-." => "\"",
        "..--.." => "?",
        "-..-." => "/",
        "-...-" => "=",
        ".-.-." => "+",
        "-....-" => "-",
        "-.--." => "(",
        "-.--.-" => ")",
        "/" => " ",
        "-.-.--" => "!",
        " " => " ",
        "" => "",
        // Turns line breaks and new lines into space. This may break what the plaintext is supposed to be
        // But enables us to support them
        "\n" => " ",
        "\r" => " ",
        _ => return None,
    };

    Some(result)
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
    fn test_morse_code() {
        let decoder = Decoder::<MorseCodeDecoder>::new();
        let result = decoder.crack(
            ".---- ----. ..--- .-.-.- .---- -.... ---.. .-.-.- ----- .-.-.- .----",
            &get_athena_checker(),
        );
        assert_eq!(result.unencrypted_text.unwrap()[0], "192.168.0.1");
    }
    #[test]
    fn test_morse_code_new_line() {
        let decoder = Decoder::<MorseCodeDecoder>::new();
        let result = decoder.crack(
            ".---- ----. ..--- .-.-.- .---- -.... ---.. .-.-.- ----- .-.-.- .----\n",
            &get_athena_checker(),
        );
        assert_eq!(result.unencrypted_text.unwrap()[0], "192.168.0.1");
    }
    #[test]
    fn test_morse_code_new_line_with_space() {
        let decoder = Decoder::<MorseCodeDecoder>::new();
        let result = decoder.crack(
            ".---- ----. ..--- .-.-.- .---- -.... ---.. .-.-.- ----- .-.-.- .---- \n",
            &get_athena_checker(),
        );
        assert_eq!(result.unencrypted_text.unwrap()[0], "192.168.0.1");
    }
    #[test]
    fn test_morse_code_carriage_return_with_space() {
        let decoder = Decoder::<MorseCodeDecoder>::new();
        let result = decoder.crack(
            ".---- ----. ..--- .-.-.- .---- -.... ---.. .-.-.- ----- .-.-.- .---- \r",
            &get_athena_checker(),
        );
        assert_eq!(result.unencrypted_text.unwrap()[0], "192.168.0.1");
    }

    #[test]
    fn test_morse_code_both_new_line_and_carriage_return() {
        let decoder = Decoder::<MorseCodeDecoder>::new();
        let result = decoder.crack(
            ".... . .-.. .-.. --- \n.-- --- .-. .-.. -.. -.-.-- \r.---- ..--- ...-- \r",
            &get_athena_checker(),
        );
        assert_eq!(result.unencrypted_text.unwrap()[0], "HELLO WORLD! 123");
    }

    #[test]
    fn test_morse_code_slash() {
        let decoder = Decoder::<MorseCodeDecoder>::new();
        let result = decoder.crack(
            r".... . .-.. .-.. --- / .-- --- .-. .-.. -.. -.-.--",
            &get_athena_checker(),
        );
        assert_eq!(result.unencrypted_text.unwrap()[0], "HELLO WORLD!");
    }

    #[test]
    fn test_morse_code_slash_tight() {
        let decoder = Decoder::<MorseCodeDecoder>::new();
        let result = decoder.crack(
            r".... . .-.. .-.. ---/.-- --- .-. .-.. -.. -.-.--",
            &get_athena_checker(),
        );
        assert_eq!(result.unencrypted_text.unwrap()[0], "HELLO WORLD!");
    }

    #[test]
    fn test_morse_code_backslash() {
        let decoder = Decoder::<MorseCodeDecoder>::new();
        let result = decoder.crack(
            r".... . .-.. .-.. --- \ .-- --- .-. .-.. -.. -.-.--",
            &get_athena_checker(),
        );
        assert_eq!(result.unencrypted_text.unwrap()[0], "HELLO WORLD!");
    }

    #[test]
    fn test_morse_code_backslash_tight() {
        let decoder = Decoder::<MorseCodeDecoder>::new();
        let result = decoder.crack(
            r".... . .-.. .-.. ---\.-- --- .-. .-.. -.. -.-.--",
            &get_athena_checker(),
        );
        assert_eq!(result.unencrypted_text.unwrap()[0], "HELLO WORLD!");
    }

    #[test]
    fn test_morse_code_line_feed() {
        let decoder = Decoder::<MorseCodeDecoder>::new();
        let result = decoder.crack(
            r".... . .-.. .-.. ---
            .-- --- .-. .-.. -.. -.-.--",
            &get_athena_checker(),
        );
        assert_eq!(result.unencrypted_text.unwrap()[0], "HELLO WORLD!");
    }

    #[test]
    fn test_morse_code_comma() {
        let decoder = Decoder::<MorseCodeDecoder>::new();
        let result = decoder.crack(
            r".... . .-.. .-.. --- , .-- --- .-. .-.. -.. -.-.--",
            &get_athena_checker(),
        );
        assert_eq!(result.unencrypted_text.unwrap()[0], "HELLO WORLD!");
    }

    #[test]
    fn test_morse_code_comma_tight() {
        let decoder = Decoder::<MorseCodeDecoder>::new();
        let result = decoder.crack(
            r".... . .-.. .-.. ---,.-- --- .-. .-.. -.. -.-.--",
            &get_athena_checker(),
        );
        assert_eq!(result.unencrypted_text.unwrap()[0], "HELLO WORLD!");
    }

    #[test]
    fn test_morse_code_colon() {
        let decoder = Decoder::<MorseCodeDecoder>::new();
        let result = decoder.crack(
            r".... . .-.. .-.. --- : .-- --- .-. .-.. -.. -.-.--",
            &get_athena_checker(),
        );
        assert_eq!(result.unencrypted_text.unwrap()[0], "HELLO WORLD!");
    }

    #[test]
    fn test_morse_code_colon_tight() {
        let decoder = Decoder::<MorseCodeDecoder>::new();
        let result = decoder.crack(
            r".... . .-.. .-.. ---:.-- --- .-. .-.. -.. -.-.--",
            &get_athena_checker(),
        );
        assert_eq!(result.unencrypted_text.unwrap()[0], "HELLO WORLD!");
    }
}
