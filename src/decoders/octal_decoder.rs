//! Decode octal byte values, such as `150 145 154 154 157` for `hello`.
//!
//! Every byte of the text is written as its base-8 value, and the values are separated by
//! whitespace, `,`, `;`, `:` or `\`, so the C and Python escape form `\150\145\154` decodes
//! too. Multi-byte UTF-8 characters take several values (`é` is `303 251`). A single run of
//! 3-digit groups with no separators (`150145154`) is accepted as well.
//!
//! References: [Wikipedia: Octal](https://en.wikipedia.org/wiki/Octal),
//! [CyberChef From Octal](https://gchq.github.io/CyberChef/#recipe=From_Octal('Space')) and
//! [Python `\ooo` escapes](https://docs.python.org/3/reference/lexical_analysis.html#escape-sequences).
//!
//! ```
//! use ciphey::checkers::{
//!     athena::Athena,
//!     checker_type::{Check, Checker},
//!     CheckerTypes,
//! };
//! use ciphey::decoders::interface::{Crack, Decoder};
//! use ciphey::decoders::octal_decoder::OctalDecoder;
//!
//! let decoder = Decoder::<OctalDecoder>::new();
//! let checker = CheckerTypes::CheckAthena(Checker::<Athena>::new());
//!
//! let result = decoder.crack("150 145 154 154 157 40 167 157 162 154 144", &checker);
//! assert!(result.success);
//! assert_eq!(result.unencrypted_text.unwrap()[0], "hello world");
//!
//! // `8` is not an octal digit, so decimal character codes are rejected straight away
//! let result = decoder.crack("104 101 108 108 111", &checker);
//! assert!(result.unencrypted_text.is_none());
//! ```

use crate::checkers::CheckerTypes;
use crate::decoders::interface::{bytes_to_string, check_string_success};

use super::crack_results::CrackResult;
use super::interface::Crack;
use super::interface::Decoder;

use log::{debug, info, trace};

/// The fewest bytes worth decoding. The search throws away anything shorter
/// (`check_if_string_cant_be_decoded`), so there is no point producing it.
const MIN_BYTES: usize = 3;

/// The shortest run of digits accepted without separators: three 3-digit groups.
const MIN_UNSEPARATED_DIGITS: usize = MIN_BYTES * 3;

/// Octal Decoder
pub struct OctalDecoder;

impl Crack for Decoder<OctalDecoder> {
    fn new() -> Decoder<OctalDecoder> {
        Decoder {
            name: "Octal",
            description: "Octal is the base-8 numeral system, using the digits 0 to 7. Octal-encoded text writes each byte as its base-8 value, from 0 to 377 (h is 150), with the values separated by spaces, commas, new lines or backslashes as in C and Python escapes.",
            link: "https://en.wikipedia.org/wiki/Octal",
            tags: vec!["octal", "base", "decoder"],
            popularity: 0.6,
            phantom: std::marker::PhantomData,
        }
    }

    /// Decodes octal byte values into text.
    ///
    /// The input may only contain the digits `0` to `7` and the separators (ASCII
    /// whitespace, `,`, `;`, `:` and `\`). Anything else, including `8`, `9`, letters and
    /// non-ASCII text, fails on a single pass over the input, which keeps this decoder cheap
    /// for the search. Each value is 1 to 3 digits, or 4 digits with a leading `0`, and at
    /// most `377`. Input without any separators is read as 3-digit groups.
    ///
    /// The bytes are read as UTF-8, falling back to Latin-1. A result containing control
    /// characters other than tabs and line breaks fails, as text doesn't contain them.
    fn crack(&self, text: &str, checker: &CheckerTypes) -> CrackResult {
        trace!("Trying octal with text {:?}", text);
        let mut results = CrackResult::new(self, text.to_string());

        let Some(decoded_text) = octal_to_string(text) else {
            debug!("Failed to decode octal");
            return results;
        };
        trace!("Decoded text for octal: {:?}", decoded_text);

        if !check_string_success(&decoded_text, text) {
            info!(
                "Failed to decode octal because check_string_success returned false on string {}",
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

/// Decodes octal to a string.
///
/// Returns `None` if `text` isn't octal, or if the result is only whitespace or contains
/// control characters other than tabs and line breaks. Small numbers such as A1Z26's
/// `1 2 3` are valid octal, but they decode to `\x01\x02\x03`, which isn't text.
fn octal_to_string(text: &str) -> Option<String> {
    let decoded = bytes_to_string(octal_to_bytes(text)?);
    if decoded.trim().is_empty()
        || decoded
            .chars()
            .any(|c| c.is_control() && !matches!(c, '\t' | '\n' | '\r'))
    {
        return None;
    }
    Some(decoded)
}

/// Turns octal values into the bytes they stand for, or `None` if `text` isn't octal.
fn octal_to_bytes(text: &str) -> Option<Vec<u8>> {
    // One pass that stops at the first byte that is neither an octal digit nor a separator.
    // Nearly every input the search tries, including decimal character codes, fails here.
    if !text
        .bytes()
        .all(|byte| matches!(byte, b'0'..=b'7') || is_separator(byte))
    {
        return None;
    }

    // Runs of separators count as one, and leading or trailing separators are ignored
    let mut values = text
        .as_bytes()
        .split(|&byte| is_separator(byte))
        .filter(|value| !value.is_empty());
    // `None` for empty input, or input made of separators only
    let first = values.next()?;

    let bytes: Vec<u8> = match values.next() {
        // No separators: `150145154` is a run of 3-digit groups
        None => {
            if first.len() < MIN_UNSEPARATED_DIGITS || !first.len().is_multiple_of(3) {
                return None;
            }
            first
                .chunks(3)
                .map(octal_digits_to_byte)
                .collect::<Option<_>>()?
        }
        Some(second) => [first, second]
            .into_iter()
            .chain(values)
            .map(parse_value)
            .collect::<Option<_>>()?,
    };

    if bytes.len() < MIN_BYTES {
        return None;
    }
    Some(bytes)
}

/// Whether `byte` separates two octal values: ASCII whitespace, `,`, `;`, `:`, or `\` for
/// the C and Python escape form `\150\145\154`.
fn is_separator(byte: u8) -> bool {
    byte.is_ascii_whitespace() || matches!(byte, b',' | b';' | b':' | b'\\')
}

/// Parses one separated value: 1 to 3 octal digits, or 4 digits with a leading `0`
/// (`0150`). Longer values fail.
fn parse_value(value: &[u8]) -> Option<u8> {
    let digits = match value {
        [b'0', rest @ ..] if rest.len() == 3 => rest,
        _ if value.len() <= 3 => value,
        _ => return None,
    };
    octal_digits_to_byte(digits)
}

/// The byte that up to 3 octal digits stand for, or `None` above `377` (255).
/// The digits must already be known to be `0` to `7`.
fn octal_digits_to_byte(digits: &[u8]) -> Option<u8> {
    let value = digits
        .iter()
        .fold(0u16, |value, digit| value * 8 + u16::from(digit - b'0'));
    u8::try_from(value).ok()
}

#[cfg(test)]
mod tests {
    use super::{octal_to_bytes, octal_to_string, OctalDecoder};
    use crate::{
        checkers::{
            athena::Athena,
            checker_type::{Check, Checker},
            CheckerTypes,
        },
        decoders::interface::{Crack, Decoder},
    };

    // Unless noted otherwise the test vectors were made with Python 3,
    // `sep.join(f'{b:o}' for b in text.encode())`, and decode back with CyberChef's
    // From Octal: https://gchq.github.io/CyberChef/#recipe=From_Octal('Space')

    // helper for tests
    fn get_athena_checker() -> CheckerTypes {
        let athena_checker = Checker::<Athena>::new();
        CheckerTypes::CheckAthena(athena_checker)
    }

    // Cracks `ciphertext` and asserts the checker accepted `plaintext`
    fn assert_cracks_to(ciphertext: &str, plaintext: &str) {
        let decoder = Decoder::<OctalDecoder>::new();
        let result = decoder.crack(ciphertext, &get_athena_checker());
        assert_eq!(result.unencrypted_text.unwrap()[0], plaintext);
        assert!(result.success, "the checker should accept {plaintext:?}");
    }

    // Cracks `ciphertext` and asserts the decoder rejected it
    fn assert_fails(ciphertext: &str) {
        let decoder = Decoder::<OctalDecoder>::new();
        let result = decoder.crack(ciphertext, &get_athena_checker());
        assert!(!result.success, "{ciphertext:?} should fail");
        assert_eq!(result.unencrypted_text, None, "{ciphertext:?} should fail");
    }

    #[test]
    fn octal_decodes_issue_example() {
        // https://github.com/bee-san/Ciphey/issues/950
        assert_cracks_to("150 145 154 154 157 40 167 157 162 154 144", "hello world");
    }

    #[test]
    fn octal_decodes_pangram() {
        // CyberChef To Octal (Space delimiter)
        assert_cracks_to(
            "124 150 145 40 161 165 151 143 153 40 142 162 157 167 156 40 146 157 170 40 152 165 155 160 163 40 157 166 145 162 40 164 150 145 40 154 141 172 171 40 144 157 147",
            "The quick brown fox jumps over the lazy dog",
        );
    }

    #[test]
    fn octal_decodes_python_ciphey_test_vector() {
        // test_octal in Python Ciphey 5.14.0's tests/test_main.py (tag 5.14.0 of this repo)
        assert_cracks_to(
            "110 145 154 154 157 40 155 171 40 156 141 155 145 40 151 163 40 142 145 145 40 141 156 144 40 111 40 154 151 153 145 40 144 157 147 40 141 156 144 40 141 160 160 154 145 40 141 156 144 40 164 162 145 145",
            "Hello my name is bee and I like dog and apple and tree",
        );
    }

    #[test]
    fn octal_with_comma_separators_decodes() {
        assert_cracks_to(
            "110,145,154,154,157,54,40,127,157,162,154,144,41",
            "Hello, World!",
        );
    }

    #[test]
    fn octal_with_backslash_escapes_decodes() {
        // Python: codecs.decode(text, 'unicode_escape') == 'hello world'
        assert_cracks_to(
            r"\150\145\154\154\157\40\167\157\162\154\144",
            "hello world",
        );
    }

    #[test]
    fn octal_without_separators_decodes_3_digit_groups() {
        // Python: ''.join(f'{b:03o}' for b in b'hello world')
        assert_cracks_to("150145154154157040167157162154144", "hello world");
    }

    #[test]
    fn octal_with_line_breaks_decodes() {
        assert_eq!(
            octal_to_string("150\n145\n154\n154\n157").as_deref(),
            Some("hello")
        );
        assert_eq!(
            octal_to_string("150\r\n145\r\n154\r\n154\r\n157\r\n").as_deref(),
            Some("hello")
        );
    }

    #[test]
    fn octal_with_mixed_and_surrounding_separators_decodes() {
        assert_eq!(
            octal_to_string(" \t,150; 145:154\t154\\157,\n").as_deref(),
            Some("hello")
        );
    }

    #[test]
    fn octal_with_4_digit_values_decodes() {
        // A leading zero is allowed: CyberChef's From Octal parses 0150 as 150
        assert_eq!(
            octal_to_string("0150 0145 0154 0154 0157").as_deref(),
            Some("hello")
        );
    }

    #[test]
    fn octal_decodes_utf8_across_values() {
        assert_eq!(
            octal_to_string("103 141 146 303 251 40 141 165 40 154 141 151 164").as_deref(),
            Some("Café au lait")
        );
        assert_eq!(octal_to_string("360 237 230 200").as_deref(), Some("😀"));
    }

    #[test]
    fn octal_falls_back_to_latin1_when_not_utf8() {
        // "café" encoded as Latin-1: é is 351 (0xE9), which is not valid UTF-8 on its own
        assert_eq!(octal_to_string("143 141 146 351").as_deref(), Some("café"));
    }

    #[test]
    fn octal_value_above_377_fails() {
        // 400 is 256, which is not a byte. CyberChef fails with "not a valid byteArray".
        assert_eq!(octal_to_bytes("150 400 154"), None);
        assert_eq!(octal_to_bytes("150 777 154"), None);
        assert_eq!(octal_to_bytes("150 0400 154"), None);
        // Unseparated, the second group is 400
        assert_eq!(octal_to_bytes("150400154"), None);
        assert_fails("150 400 154");
    }

    #[test]
    fn octal_value_with_too_many_digits_fails() {
        assert_eq!(octal_to_bytes("150 01450 154"), None);
        assert_eq!(octal_to_bytes("150 1450 154"), None);
        assert_eq!(octal_to_bytes("150 00000150 154"), None);
    }

    #[test]
    fn octal_that_decodes_to_control_characters_fails() {
        // A1Z26 "1 2 3" is valid octal for \x01\x02\x03
        assert_fails("1 2 3");
        assert_eq!(octal_to_string("0 0 0"), None);
        // DEL, and C1 control characters from the Latin-1 fallback
        assert_eq!(octal_to_string("177 177 177"), None);
        assert_eq!(octal_to_string("200 201 202"), None);
        // Tabs and line breaks are allowed
        assert_eq!(
            octal_to_string("150 11 151 12 15").as_deref(),
            Some("h\ti\n\r")
        );
    }

    #[test]
    fn octal_that_decodes_to_whitespace_only_fails() {
        // Spaces, and the A1Z26 text "11 12 15" read as a tab and line breaks
        assert_eq!(octal_to_string("40 40 40"), None);
        assert_fails("11 12 15");
    }

    #[test]
    fn non_octal_digits_fail() {
        // Decimal character codes for "hello" contain an 8
        assert_fails("104 101 108 108 111");
        assert_fails("150 145 159");
    }

    #[test]
    fn unseparated_digits_need_complete_3_digit_groups() {
        assert_fails("1234567");
        // 10 digits
        assert_eq!(octal_to_bytes("1501451541"), None);
        // Only two groups
        assert_eq!(octal_to_bytes("150145"), None);
        assert_eq!(octal_to_bytes("150"), None);
    }

    #[test]
    fn octal_with_fewer_than_3_values_fails() {
        assert_eq!(octal_to_bytes("150 151"), None);
        assert_eq!(octal_to_bytes("150"), None);
        assert_eq!(octal_to_bytes("7"), None);
    }

    #[test]
    fn octal_with_other_separators_fails() {
        assert_fails("150-145-154-154-157");
        assert_fails("150.145.154.154.157");
        assert_fails("0o150 0o145 0o154");
    }

    #[test]
    fn octal_handles_panic_if_empty_string() {
        assert_fails("");
    }

    #[test]
    fn octal_handles_separators_only() {
        assert_fails(" ");
        assert_fails(" \t\r\n,;:\\ ");
    }

    #[test]
    fn octal_handles_panic_if_emoji() {
        assert_fails("😀");
        assert_fails("150 145 154 😀");
    }

    #[test]
    fn octal_handles_english_text() {
        assert_fails("hello world");
        assert_fails("hello my name is panicky mc panic face!");
    }

    #[test]
    fn octal_decoder_is_registered() {
        let decoders = crate::filtration_system::get_decoder_by_name("Octal");
        assert_eq!(decoders.components.len(), 1);
        assert_eq!(decoders.components[0].get_name(), "Octal");

        // Cached results find their decoder by name
        let decoder = crate::decoders::DECODER_MAP
            .get("Octal")
            .expect("Octal should be in DECODER_MAP")
            .get::<crate::decoders::DecoderType>();
        assert_eq!(decoder.get_name(), "Octal");
    }
}
