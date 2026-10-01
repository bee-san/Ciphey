use crate::checkers::CheckerTypes;
use crate::decoders::interface::check_string_success;

use super::crack_results::CrackResult;
use super::interface::Crack;
use super::interface::Decoder;

use log::{debug, info, trace};

/// Citrix CTX1 Decoder
pub struct CitrixCTX1Decoder;

/// Error enum
#[derive(Debug)]
enum Error {
    /// Error when the input is not divisible by 4
    InvalidLength,
    /// Error with left-hand side subtraction
    LhsOverflow,
    /// Error with right-hand side subtraction
    RhsOverflow,
    /// Error if the result isn't UTF-8
    InvalidUtf8,
}

impl Crack for Decoder<CitrixCTX1Decoder> {
    fn new() -> Decoder<CitrixCTX1Decoder> {
        Decoder {
            name: "Citrix Ctx1",
            description: "Citrix CTX1 is a very old encoding that was used for encoding Citrix passwords.",
            link: "https://www.remkoweijnen.nl/blog/2012/05/13/encoding-and-decoding-citrix-passwords/",
            tags: vec!["citrix_ctx1", "citrix", "passwords", "decoder"],
            popularity: 0.1,
            phantom: std::marker::PhantomData,
        }
    }

    /// This function does the actual decoding
    /// It returns an `Option<String>` if it was successful
    /// Else the Option returns nothing and the error is logged in Trace
    fn crack(&self, text: &str, checker: &CheckerTypes) -> CrackResult {
        trace!("Trying citrix_ctx1 with text {:?}", text);
        let decoded_text: Result<String, Error> = decode_citrix_ctx1(text);

        let mut results = CrackResult::new(self, text.to_string());

        if decoded_text.is_err() {
            debug!("Failed to decode citrix_ctx1: {:?}", decoded_text);
            return results;
        }

        trace!("Decoded text for citrix_ctx1: {:?}", decoded_text);

        let decoded_text = decoded_text.unwrap();
        if !check_string_success(&decoded_text, text) {
            info!(
                "Failed to decode citrix_ctx1 because check_string_success returned false on string {}",
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

/// Decodes Citrix CTX1
fn decode_citrix_ctx1(text: &str) -> Result<String, Error> {
    if !text.len().is_multiple_of(4) {
        return Err(Error::InvalidLength);
    }

    let mut rev = text.as_bytes().to_vec();
    rev.reverse();
    let mut result = Vec::new();
    let mut temp;

    for i in (0..rev.len()).step_by(2) {
        if i + 2 >= rev.len() {
            temp = 0;
        } else {
            temp = ((rev[i + 2].checked_sub(0x41)).ok_or(Error::LhsOverflow)? & 0xF)
                ^ (((rev[i + 3].checked_sub(0x41)).ok_or(Error::RhsOverflow)? << 4) & 0xF0);
        }
        temp ^= (((rev[i].checked_sub(0x41)).ok_or(Error::LhsOverflow)? & 0xF)
            ^ (((rev[i + 1].checked_sub(0x41)).ok_or(Error::RhsOverflow)? << 4) & 0xF0))
            ^ 0xA5;
        result.push(temp);
    }

    result.retain(|&x| x != 0);
    result.reverse();

    String::from_utf8(result).map_err(|_| Error::InvalidUtf8)
}

#[cfg(test)]
mod tests {
    use super::CitrixCTX1Decoder;
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
    fn citrix_ctx1_decodes_successfully() {
        // This tests if Citrix CTX1 can decode Citrix CTX1 successfully
        let decoder = Decoder::<CitrixCTX1Decoder>::new();
        let result = decoder.crack(
            "MNGIKIANMEGBKIANMHGCOHECJADFPPFKINCIOBEEIFCA",
            &get_athena_checker(),
        );
        assert_eq!(result.unencrypted_text.unwrap()[0], "hello world");
    }

    #[test]
    fn citrix_ctx1_decodes_lowercase_successfully() {
        // This tests if Citrix CTX1 can decode lowercase strings
        let decoder = Decoder::<CitrixCTX1Decoder>::new();
        let result = decoder.crack(
            "pbfejjdmpaffidcgkdagmkgpljbmjjdmpffajkdponeiiicnpkfpjjdmpifnilcoooelmoglincioeebjadfocehilcopdfgndhgjadfmegbjmdjknai",
            &get_athena_checker(),
        );
        assert_eq!(
            result.unencrypted_text.unwrap()[0],
            "This is lowercase Citrix CTX1"
        );
    }

    #[test]
    fn citrix_ctx1_handles_substraction_overflow() {
        // This tests if Citrix CTX1 can handle subtraction overflows
        // It should return None and not panic
        let citrix_ctx1_decoder = Decoder::<CitrixCTX1Decoder>::new();
        let result = citrix_ctx1_decoder
            .crack("NUWEN43XR44TLAYHSU4DVI2ISF======", &get_athena_checker())
            .unencrypted_text;
        assert!(result.is_none());
    }

    #[test]
    fn citrix_ctx1_handles_length_not_divisible_by_4() {
        // This tests if Citrix CTX1 can handle strings with length that are not divisible by 4
        // It should return None
        let citrix_ctx1_decoder = Decoder::<CitrixCTX1Decoder>::new();
        let result = citrix_ctx1_decoder
            .crack("AAA", &get_athena_checker())
            .unencrypted_text;
        assert!(result.is_none());
    }

    #[test]
    fn citrix_ctx1_decode_handles_panics() {
        // This tests if Citrix CTX1 can handle panics
        // It should return None
        let citrix_ctx1_decoder = Decoder::<CitrixCTX1Decoder>::new();
        let result = citrix_ctx1_decoder
            .crack(
                "hello my name is panicky mc panic face!",
                &get_athena_checker(),
            )
            .unencrypted_text;
        assert!(result.is_none());
    }

    #[test]
    fn citrix_ctx1_handle_panic_if_empty_string() {
        // This tests if Citrix CTX1 can handle an empty string
        // It should return None
        let citrix_ctx1_decoder = Decoder::<CitrixCTX1Decoder>::new();
        let result = citrix_ctx1_decoder
            .crack("", &get_athena_checker())
            .unencrypted_text;
        assert!(result.is_none());
    }

    #[test]
    fn citrix_ctx1_decodes_emoji_successfully() {
        // This tests if Citrix CTX1 can decode an emoji
        let citrix_ctx1_decoder = Decoder::<CitrixCTX1Decoder>::new();
        let result = citrix_ctx1_decoder.crack("😂", &get_athena_checker());
        assert_eq!(result.unencrypted_text.unwrap()[0], "[*");
    }
}
