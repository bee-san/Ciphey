//! The library API for running one decoder, re-exported from [`crate::decoders`]: a
//! function per decoder ([`functions`]), decryption with a known key ([`keys`]),
//! [`decode_with`] and [`list_decoders`].

mod functions;
mod keys;
#[cfg(test)]
mod tests;

pub use functions::*;
pub use keys::*;

use std::collections::HashSet;

use once_cell::sync::Lazy;
use serde::Serialize;

use super::crack_results::CrackResult;
use super::interface::{Crack, Decoder};
use crate::checkers::athena::Athena;
use crate::checkers::checker_type::{Check, Checker};
use crate::checkers::human_checker::without_prompts;
use crate::checkers::CheckerTypes;
use crate::detection::{self, Detection};
use crate::CipheyError;

/// What one decoder made of a text.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[non_exhaustive]
pub struct Decoded {
    /// The decoder's name, as in [`DecoderInfo::name`] and `CrackResult::decoder`.
    pub decoder: &'static str,
    /// The decodings, the one Ciphey's checks accepted first. See the
    /// [module docs](crate::decoders#what-comes-back) for which decodings these are.
    pub candidates: Vec<Candidate>,
}

impl Decoded {
    /// The candidate Ciphey's plaintext checks accepted, if any.
    pub fn plaintext(&self) -> Option<&Candidate> {
        self.candidates
            .iter()
            .find(|candidate| candidate.is_plaintext())
    }

    /// Whether the decoder produced nothing, usually because the text isn't in its format.
    pub fn is_empty(&self) -> bool {
        self.candidates.is_empty()
    }

    /// Turns what a decoder's `crack` returned into candidates, dropping empty and repeated
    /// decodings.
    fn from_crack_result(result: CrackResult) -> Self {
        let texts = result.unencrypted_text.unwrap_or_default();
        let keys = candidate_keys(result.key.as_deref(), texts.len());
        let mut seen = HashSet::new();
        let mut candidates: Vec<Candidate> = texts
            .into_iter()
            .zip(keys)
            .filter(|(text, _)| !text.is_empty() && seen.insert(text.clone()))
            .map(|(text, key)| Candidate {
                text,
                key,
                detection: None,
            })
            .collect();
        if result.success {
            // A decoder whose checker accepts a decoding returns only that one
            if let Some(plaintext) = candidates.first_mut() {
                plaintext.detection = detection::for_accepted_decoding(
                    result.checker_name,
                    result.checker_description,
                    &plaintext.text,
                );
            }
        }
        Decoded {
            decoder: result.decoder,
            candidates,
        }
    }
}

/// One decoding of a text.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[non_exhaustive]
pub struct Candidate {
    /// The decoded text.
    pub text: String,
    /// The key that gave this text, in the decoder's format (see
    /// [`DecoderInfo::key_format`]), if the decoder reported one. A few decoders report
    /// other details here instead: the JWT header, the gzip file name, the git object
    /// type of a zlib stream, the UTF-16 byte order, the Baconian alphabet.
    pub key: Option<String>,
    /// What Ciphey's plaintext checks found, if they accepted this text.
    pub detection: Option<Detection>,
}

impl Candidate {
    /// Whether Ciphey's plaintext checks accepted this text.
    pub fn is_plaintext(&self) -> bool {
        self.detection.is_some()
    }
}

/// A decoder, as [`list_decoders`] lists it.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[non_exhaustive]
pub struct DecoderInfo {
    /// The decoder's name, as in `CrackResult::decoder`, e.g. `Base64` or `caesar`.
    pub name: &'static str,
    /// The function in [`crate::decoders`] that runs it, e.g. `base64`.
    pub function: &'static str,
    /// Other names [`decode_with`] knows it by, e.g. `b64`. It also takes the
    /// [`name`](DecoderInfo::name) and the [`function`](DecoderInfo::function).
    pub aliases: &'static [&'static str],
    /// The decoder's tags, which group decoders, e.g. `base`, `classic`, `decoder`.
    pub tags: Vec<&'static str>,
    /// What the decoder decodes, in a sentence or two.
    pub description: &'static str,
    /// Where to read more about it.
    pub link: &'static str,
    /// The key [`decode_with`] can decrypt with, and how to write it. `None` if the
    /// decoder takes no key.
    pub key_format: Option<&'static str>,
}

impl DecoderInfo {
    /// Whether the decoder can decrypt with a key, see [`DecoderInfo::key_format`].
    pub fn accepts_key(&self) -> bool {
        self.key_format.is_some()
    }

    /// Every name [`decode_with`] knows the decoder by.
    fn names(&self) -> impl Iterator<Item = &'static str> {
        [self.name, self.function]
            .into_iter()
            .chain(self.aliases.iter().copied())
    }
}

/// Options for [`decode_with`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct DecodeOptions {
    /// Decrypt with this key instead of cracking, in the format of
    /// [`DecoderInfo::key_format`]. `None`, the default, cracks.
    pub key: Option<String>,
}

impl DecodeOptions {
    /// Options that decrypt with `key`.
    pub fn with_key(key: impl Into<String>) -> Self {
        DecodeOptions {
            key: Some(key.into()),
        }
    }
}

/// Lists every decoder [`decode_with`] and the functions in [`crate::decoders`] can run,
/// sorted by function name.
///
/// ```
/// let caesar = ciphey::list_decoders()
///     .iter()
///     .find(|decoder| decoder.function == "caesar")
///     .unwrap();
/// assert_eq!(caesar.name, "caesar");
/// assert!(caesar.aliases.contains(&"rot13"));
/// assert!(caesar.tags.contains(&"classic"));
/// assert!(caesar.accepts_key());
///
/// let base64 = ciphey::decoder_info("b64").unwrap();
/// assert_eq!(base64.name, "Base64");
/// assert!(!base64.accepts_key());
/// ```
pub fn list_decoders() -> &'static [DecoderInfo] {
    &INFOS
}

/// The decoder [`decode_with`] would run for `name`, if there is one. See [`decode_with`]
/// for the names it knows.
pub fn decoder_info(name: &str) -> Option<&'static DecoderInfo> {
    find(name).map(|(_, info)| info)
}

/// Runs the decoder called `name` on `text`, as its function in [`crate::decoders`] does.
///
/// `name` is the decoder's [name](DecoderInfo::name), [function](DecoderInfo::function)
/// or one of its [aliases](DecoderInfo::aliases), ignoring case, spaces, hyphens and
/// underscores: `Base64`, `base64` and `b64`, or `Single-byte XOR` and `xor_single_byte`.
///
/// Without a key it decodes, or cracks, `text`. With [`DecodeOptions::with_key`] it
/// decrypts with that key, written as the decoder's [`DecoderInfo::key_format`] says.
/// See the [module docs](crate::decoders#what-comes-back) for what comes back.
///
/// ```
/// use ciphey::{decode_with, DecodeOptions};
///
/// let cracked = decode_with("rot13", "Uryyb jbeyq", &DecodeOptions::default())?;
/// assert_eq!(cracked.plaintext().unwrap().text, "Hello world");
///
/// let decrypted = decode_with("Vigenère", "Rijvs uyvjn", &DecodeOptions::with_key("key"))?;
/// assert_eq!(decrypted.candidates[0].text, "Hello world");
/// assert_eq!(decrypted.candidates[0].key.as_deref(), Some("KEY"));
///
/// let decrypted = decode_with("affine", "IHHWVC SWFRCP", &DecodeOptions::with_key("a=5, b=8"))?;
/// assert_eq!(decrypted.candidates[0].text, "AFFINE CIPHER");
/// # Ok::<(), ciphey::CipheyError>(())
/// ```
///
/// # Errors
///
/// * [`CipheyError::UnknownDecoder`] if no decoder has the name `name`.
/// * [`CipheyError::KeyNotSupported`] if there is a key and the decoder takes none.
/// * [`CipheyError::InvalidKey`] if the decoder can't use the key.
pub fn decode_with(
    name: &str,
    text: &str,
    options: &DecodeOptions,
) -> Result<Decoded, CipheyError> {
    let (entry, info) = find(name).ok_or_else(|| CipheyError::UnknownDecoder {
        name: name.to_string(),
    })?;
    match (&options.key, &entry.key) {
        (None, _) => Ok((entry.crack)(text)),
        (Some(key), Some(support)) => (support.decrypt)(text, key),
        (Some(_), None) => Err(CipheyError::KeyNotSupported { decoder: info.name }),
    }
}

/// How the library API runs one decoder.
struct Entry {
    /// The decoder's function in [`crate::decoders`].
    function: &'static str,
    /// Other names [`decode_with`] knows the decoder by.
    aliases: &'static [&'static str],
    /// What the decoder says about itself.
    about: fn() -> About,
    /// Decodes or cracks a text.
    crack: fn(&str) -> Decoded,
    /// How to decrypt with a key, for decoders that can.
    key: Option<KeySupport>,
}

impl Entry {
    /// The decoder as [`list_decoders`] lists it.
    fn info(&self) -> DecoderInfo {
        let about = (self.about)();
        DecoderInfo {
            name: about.name,
            function: self.function,
            aliases: self.aliases,
            tags: about.tags,
            description: about.description,
            link: about.link,
            key_format: self.key.as_ref().map(|key| key.format),
        }
    }
}

/// How [`decode_with`] decrypts with a key.
struct KeySupport {
    /// How to write the key, for [`DecoderInfo::key_format`].
    format: &'static str,
    /// Decrypts a text with a key written that way.
    decrypt: fn(&str, &str) -> Result<Decoded, CipheyError>,
}

/// The fields a decoder describes itself with.
struct About {
    /// The decoder's name
    name: &'static str,
    /// The decoder's description
    description: &'static str,
    /// The decoder's link
    link: &'static str,
    /// The decoder's tags
    tags: Vec<&'static str>,
}

/// What `Decoder<T>` says about itself.
fn about<T>() -> About
where
    Decoder<T>: Crack,
{
    let decoder = Decoder::<T>::new();
    About {
        name: decoder.name,
        description: decoder.description,
        link: decoder.link,
        tags: decoder.tags,
    }
}

/// The name of `Decoder<T>`.
fn name_of<T>() -> &'static str
where
    Decoder<T>: Crack,
{
    Decoder::<T>::new().name
}

/// Every decoder as [`list_decoders`] lists it, in the order of [`functions::ENTRIES`].
static INFOS: Lazy<Vec<DecoderInfo>> =
    Lazy::new(|| functions::ENTRIES.iter().map(Entry::info).collect());

/// The decoder [`decode_with`] runs for `name`.
fn find(name: &str) -> Option<(&'static Entry, &'static DecoderInfo)> {
    let wanted = normalise(name);
    functions::ENTRIES
        .iter()
        .zip(INFOS.iter())
        .find(|(_, info)| info.names().any(|known| normalise(known) == wanted))
}

/// `name` in lower case without spaces, hyphens and underscores, so `Single-byte XOR`
/// and `single_byte_xor` are the same name.
fn normalise(name: &str) -> String {
    name.chars()
        .filter(|c| !matches!(c, ' ' | '-' | '_'))
        .flat_map(char::to_lowercase)
        .collect()
}

/// Decodes or cracks `text` with `Decoder<T>`, checking its decodings with Athena as the
/// search does. The human checker is never asked.
fn crack<T>(text: &str) -> Decoded
where
    Decoder<T>: Crack,
{
    let decoder = Decoder::<T>::new();
    let checker = CheckerTypes::CheckAthena(Checker::<Athena>::new());
    let result = without_prompts(|| decoder.crack(text, &checker));
    Decoded::from_crack_result(result)
}

/// What decrypting with a key gave: a candidate for each `(text, key)` in `decryptions`,
/// checked with Athena at its default sensitivity, the accepted ones first. Empty and
/// repeated texts are dropped.
fn decrypted<T>(decryptions: Vec<(String, String)>) -> Decoded
where
    Decoder<T>: Crack,
{
    let mut seen = HashSet::new();
    let mut candidates: Vec<Candidate> = decryptions
        .into_iter()
        .filter(|(text, _)| !text.is_empty() && seen.insert(text.clone()))
        .map(|(text, key)| {
            let result = without_prompts(|| Checker::<Athena>::new().check(&text));
            Candidate {
                detection: detection::from_check_result(result, &text),
                text,
                key: Some(key),
            }
        })
        .collect();
    // A stable sort, so the rest keep their order
    candidates.sort_by_key(|candidate| !candidate.is_plaintext());
    Decoded {
        decoder: name_of::<T>(),
        candidates,
    }
}

/// The key of each of `count` candidates: the decoder's key if it made one candidate, one
/// key each if it listed `count` keys separated by `, ` (as the single-byte XOR cracker
/// does), otherwise none.
fn candidate_keys(key: Option<&str>, count: usize) -> Vec<Option<String>> {
    match key {
        Some(key) if count == 1 => vec![Some(key.to_string())],
        Some(key) if count > 1 => {
            let keys: Vec<&str> = key.split(", ").collect();
            if keys.len() == count {
                keys.into_iter().map(|key| Some(key.to_string())).collect()
            } else {
                vec![None; count]
            }
        }
        _ => vec![None; count],
    }
}
