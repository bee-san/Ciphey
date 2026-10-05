use crate::checkers::CheckerTypes;
use crate::decoders::interface::{bytes_to_string, check_string_success};

use super::crack_results::CrackResult;
use super::interface::Crack;
use super::interface::Decoder;

use log::{debug, info, trace};

/// Hexadecimal Decoder
pub struct HexadecimalDecoder;

/// Error enum
#[derive(Debug)]
enum Error {
    /// Error when the input is not divisible by 2
    InvalidLength,
}

impl Crack for Decoder<HexadecimalDecoder> {
    fn new() -> Decoder<HexadecimalDecoder> {
        Decoder {
            name: "Hexadecimal",
            description: "Data is broken into 4-bit sequences, and each value (between 0 and 15 inclusively) is encoded using one of 16 symbols from the ASCII character set. Although any 16 symbols from the ASCII character set can be used, in practice the ASCII digits '0'–'9' and the letters 'A'–'F' (or the lowercase 'a'–'f') are always chosen in order to align with standard written notation for hexadecimal numbers.",
            link: "https://en.wikipedia.org/wiki/Hexadecimal#Base16_(transfer_encoding)",
            tags: vec!["hexadecimal", "hex", "base", "decoder"],
            popularity: 0.9,
            phantom: std::marker::PhantomData,
        }
    }

    /// This function does the actual decoding
    /// It returns an `Option<String>` if it was successful
    /// Else the Option returns nothing and the error is logged in Trace
    fn crack(&self, text: &str, checker: &CheckerTypes) -> CrackResult {
        trace!("Trying hexadecimal with text {:?}", text);
        let decoded_text: Result<String, Error> = hexadecimal_to_string(text);
        let mut results = CrackResult::new(self, text.to_string());

        if decoded_text.is_err() {
            debug!("Failed to decode hexadecimal: {:?}", decoded_text);
            return results;
        }

        trace!("Decoded text for hexadecimal: {:?}", decoded_text);

        let decoded_text = decoded_text.unwrap();

        if !check_string_success(&decoded_text, text) {
            info!(
                "Failed to decode hexadecimal because check_string_success returned false on string {}",
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

/// Decodes hexadecimal to string
fn hexadecimal_to_string(hex: &str) -> Result<String, Error> {
    // Remove "0x" delimiters
    let hex = hex.replace("0x", "");
    // Remove all non-hexadecimal characters from the string
    let hex = hex.replace(|c: char| !c.is_ascii_hexdigit(), "");

    // Convert the hexadecimal string to a vector of bytes
    let bytes = hex.as_bytes();

    // Ensure that the vector of bytes has an even length, so it can be processed in pairs
    if bytes.len() % 2 == 1 {
        return Err(Error::InvalidLength);
    }

    // Iterate over the vector of bytes in pairs
    let decoded: Vec<u8> = bytes
        .chunks(2)
        // Each pair is two ASCII hexadecimal digits, so this can't fail
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect();

    // Pushing each byte as a char treated the bytes as Latin-1, turning UTF-8 text
    // like "café" into "cafÃ©"
    Ok(bytes_to_string(decoded))
}

#[cfg(test)]
mod tests {
    use super::{hexadecimal_to_string, HexadecimalDecoder};
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
    fn hexadecimal_with_no_spaces_decodes_successfully() {
        // This tests if Hexadecimal can decode Hexadecimal with no spaces successfully
        let decoder = Decoder::<HexadecimalDecoder>::new();
        let result = decoder.crack(
            "537068696e78206f6620626c61636b2071756172747a2c206a75646765206d7920766f772e",
            &get_athena_checker(),
        );
        assert_eq!(
            result.unencrypted_text.unwrap()[0],
            "Sphinx of black quartz, judge my vow."
        );
    }

    #[test]
    fn hexadecimal_with_spaces_decodes_successfully() {
        // This tests if Hexadecimal can decode Hexadecimal with spaces successfully
        // We use the hex string from the "c4ptur3-th3-fl4g" THM room
        let decoder = Decoder::<HexadecimalDecoder>::new();
        let result = decoder.crack(
            "68 65 78 61 64 65 63 69 6d 61 6c 20 6f 72 20 62 61 73 65 31 36 3f",
            &get_athena_checker(),
        );
        assert_eq!(
            result.unencrypted_text.unwrap()[0],
            "hexadecimal or base16?"
        );
    }

    #[test]
    fn hexadecimal_with_delimiters_decodes_successfully() {
        // This tests if Hexadecimal can decode Hexadecimal with delimiters successfully
        let decoder = Decoder::<HexadecimalDecoder>::new();
        let result = decoder.crack(
            "68;74;74;70;73;3a;2f;2f;77;77;77;2e;67;6f;6f;67;6c;65;2e;63;6f;6d",
            &get_athena_checker(),
        );
        assert_eq!(
            result.unencrypted_text.unwrap()[0],
            "https://www.google.com"
        );
    }

    #[test]
    fn uppercase_hexadecimal_decodes_successfully() {
        // This tests if Hexadecimal can decode uppercase Hexadecimal successfully
        let decoder = Decoder::<HexadecimalDecoder>::new();
        let result = decoder.crack(
            "5570706572636173652068657861646563696D616C",
            &get_athena_checker(),
        );
        assert_eq!(result.unencrypted_text.unwrap()[0], "Uppercase hexadecimal");
    }

    #[test]
    fn hexadecimal_with_0x_delimiters_decodes_successfully() {
        // This tests if Hexadecimal can decode Hexadecimal with 0x delimiters successfully
        let decoder = Decoder::<HexadecimalDecoder>::new();
        let result = decoder.crack(
            "0x540x680x690x730x200x750x730x650x730x200x300x780x200x610x730x200x740x680x650x200x700x720x650x660x690x780x200x620x650x740x770x650x650x6e0x200x650x760x650x720x790x200x630x680x750x6e0x6b",
            &get_athena_checker(),
        );
        assert_eq!(
            result.unencrypted_text.unwrap()[0],
            "This uses 0x as the prefix between every chunk"
        );
    }

    #[test]
    fn hexadecimal_with_0x_and_comma_delimiters_decodes_successfully() {
        // This tests if Hexadecimal can decode Hexadecimal with 0x and comma delimiters successfully
        let decoder = Decoder::<HexadecimalDecoder>::new();
        let result = decoder.crack(
            "0x48,0x65,0x78,0x61,0x64,0x65,0x63,0x69,0x6d,0x61,0x6c,0x20,0x77,0x69,0x74,0x68,0x20,0x30,0x78,0x20,0x2b,0x20,0x63,0x6f,0x6d,0x6d,0x61,0x73",
            &get_athena_checker(),
        );
        assert_eq!(
            result.unencrypted_text.unwrap()[0],
            "Hexadecimal with 0x + commas"
        );
    }

    #[test]
    fn hexadecimal_decodes_utf8_text() {
        // Every byte used to become its own Latin-1 character: "café" came out as "cafÃ©"
        assert_eq!(hexadecimal_to_string("636166c3a9").unwrap(), "café");
        assert_eq!(
            hexadecimal_to_string("e697a5e69cace8aa9e").unwrap(),
            "日本語"
        );
        assert_eq!(hexadecimal_to_string("f09f9882").unwrap(), "😂");
    }

    #[test]
    fn hexadecimal_falls_back_to_latin1_when_not_utf8() {
        // "café" encoded as Latin-1
        assert_eq!(hexadecimal_to_string("636166e9").unwrap(), "café");
    }

    #[test]
    fn hexadecimal_handles_panics() {
        // This tests if Hexadecimal can handle panics
        // It should return Some
        // This is because Hexadecimal can technically decode it, but it will be gibberish
        let hexadecimal_decoder = Decoder::<HexadecimalDecoder>::new();
        let result = hexadecimal_decoder
            .crack(
                "hello my name is panicky mc panic face!",
                &get_athena_checker(),
            )
            .unencrypted_text;
        assert!(result.is_some());
    }

    #[test]
    fn hexadecimal_handles_panic_if_empty_string() {
        // This tests if Hexadecimal can handle an empty string
        // It should return None
        let citrix_ctx1_decoder = Decoder::<HexadecimalDecoder>::new();
        let result = citrix_ctx1_decoder
            .crack("", &get_athena_checker())
            .unencrypted_text;
        assert!(result.is_none());
    }

    #[test]
    fn hexadecimal_handles_panic_if_emoji() {
        // This tests if Hexadecimal can handle an emoji
        // It should return None
        let base64_url_decoder = Decoder::<HexadecimalDecoder>::new();
        let result = base64_url_decoder
            .crack("😂", &get_athena_checker())
            .unencrypted_text;
        assert!(result.is_none());
    }
}
