use crate::checkers::CheckerTypes;

use super::crack_results::CrackResult;

/// The Interface defines what the struct for each decoder looks like
//TODO: rename this file
pub struct Decoder<Type> {
    /// The English name of the decoder.
    pub name: &'static str,
    /// A description, you can take the first line from Wikipedia
    /// Sometimes our decoders do not exist on Wikipedia so we write our own.
    pub description: &'static str,
    /// Wikipedia Link
    pub link: &'static str,
    /// The tags it has. See other decoders. Think of it as a "category"
    /// This is used to filter decoders.
    /// For example, if you want to filter decoders that are "base64"
    /// you would use the tag "base64" or "base".
    /// You can also add tags like "online" to filter decoders that are online.
    pub tags: Vec<&'static str>,
    /// We get popularity by eye-balling it or using the API's data
    pub popularity: f32,
    /// we don't use the Type, so we use PhantomData to mark it!
    pub phantom: std::marker::PhantomData<Type>,
}

/// The default implementation for a decoder
pub struct DefaultDecoder;
impl Default for Decoder<DefaultDecoder> {
    fn default() -> Decoder<DefaultDecoder> {
        Decoder {
            name: "Default decoder",
            description: "N/A",
            link: "N/A",
            tags: vec!["N/A"],
            popularity: 0.0,
            phantom: std::marker::PhantomData,
        }
    }
}

impl Crack for Decoder<DefaultDecoder> {
    fn new() -> Decoder<DefaultDecoder> {
        Decoder::default()
    }
    /// Returns a dummy CrackResult
    fn crack(&self, text: &str, _checker: &CheckerTypes) -> CrackResult {
        CrackResult::new(self, text.to_string())
    }
    /// Gets all tags for this decoder
    fn get_tags(&self) -> &Vec<&str> {
        &self.tags
    }
    /// Gets the name for the current decoder
    fn get_name(&self) -> &str {
        self.name
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

/// All decoders will share the same Crack trait
/// Which let's us put them into a vector and iterate over them,
/// Running `.crack()` on each of them.
/// Relevant docs: <https://docs.rs/crack/0.3.0/crack/trait.Crack.html>
pub trait Crack {
    /// This function generates a new crack trait
    fn new() -> Self
    where
        Self: Sized;
    /// Crack is the function that actually does the decoding
    fn crack(&self, text: &str, checker: &CheckerTypes) -> CrackResult;
    /// Get all tags for the current decoder
    fn get_tags(&self) -> &Vec<&str>;
    /// Get the name of the current decoder
    fn get_name(&self) -> &str;
    /// Gets the description of the current decoder
    fn get_description(&self) -> &str;
    /// Gets the link for the current decoder
    fn get_link(&self) -> &str;
    /// Get the popularity of the decoder (a value between 0.0 and 1.0)
    /// Default implementation returns the decoder's popularity field
    fn get_popularity(&self) -> f32 {
        // This is a default implementation that will be used if the decoder
        // doesn't override this method. In a real implementation, each decoder
        // would override this to return its actual popularity value.
        0.5
    }
}

/// Returns a boolean of True if the string is successfully changed
/// So empty strings fail, but non-empty strings succeed
/// and only if the string is different from the original text.
pub fn check_string_success(decoded_text: &str, original_text: &str) -> bool {
    if decoded_text.is_empty() {
        return false;
    } else if decoded_text != original_text {
        return true;
    }
    false
}

/// Turns decoded bytes into text.
///
/// The bytes are read as UTF-8 when they are valid UTF-8, as encoded text almost always
/// is. Otherwise each byte becomes the Latin-1 character with that value, so every byte
/// still maps to a character.
pub(crate) fn bytes_to_string(bytes: Vec<u8>) -> String {
    String::from_utf8(bytes)
        .unwrap_or_else(|error| error.into_bytes().into_iter().map(char::from).collect())
}
