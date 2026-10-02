//! Decrypting with a known key: the `*_with_key` functions, and the keys
//! [`decode_with`](super::decode_with) parses for them.

use super::{decrypted, name_of, Decoded, KeySupport};
use crate::decoders::affine_decoder::{self, AffineDecoder};
use crate::decoders::caesar_decoder::{self, CaesarDecoder};
use crate::decoders::interface::{bytes_to_string, Crack, Decoder};
use crate::decoders::monoalphabetic_substitution_decoder::{
    self, MonoalphabeticSubstitutionDecoder,
};
use crate::decoders::railfence_decoder::{self, RailfenceDecoder};
use crate::decoders::rot47_decoder::{self, ROT47Decoder};
use crate::decoders::vigenere_decoder::{self, VigenereDecoder};
use crate::decoders::xor_repeating_key_decoder::{self, XorRepeatingKeyDecoder};
use crate::decoders::xor_single_byte_decoder::{self, XorSingleByteDecoder};
use crate::CipheyError;

/// Decrypts the Caesar cipher with a known shift.
///
/// `shift` is how far each letter moves forward to decode, the key
/// [`caesar`](super::caesar) reports, taken mod 26: 13 decodes ROT13, and text encrypted
/// with the classic shift of 3 decodes with 23, or -3. Only ASCII letters change.
///
/// ```
/// use ciphey::decoders::caesar_with_key;
///
/// assert_eq!(caesar_with_key("Uryyb jbeyq", 13).candidates[0].text, "Hello world");
///
/// let decoded = caesar_with_key("Khoor zruog", -3);
/// assert_eq!(decoded.candidates[0].text, "Hello world");
/// assert_eq!(decoded.candidates[0].key.as_deref(), Some("23"));
/// ```
pub fn caesar_with_key(text: &str, shift: i64) -> Decoded {
    let shift = shift.rem_euclid(26) as u8;
    decrypted::<CaesarDecoder>(vec![(
        caesar_decoder::caesar(text, shift),
        shift.to_string(),
    )])
}

/// Decrypts ROT47, or another rotation of the 94 printable ASCII characters `!` to `~`.
///
/// `shift` is how far each of them moves forward to decode, taken mod 94. ROT47 is 47,
/// which undoes itself.
///
/// ```
/// let decoded = ciphey::decoders::rot47_with_key("96==@ H@C=5", 47);
/// assert_eq!(decoded.candidates[0].text, "hello world");
/// ```
pub fn rot47_with_key(text: &str, shift: i64) -> Decoded {
    let shift = shift.rem_euclid(94) as u8;
    decrypted::<ROT47Decoder>(vec![(
        rot47_decoder::rot47_to_alphabet(text, shift),
        shift.to_string(),
    )])
}

/// Decrypts the Vigenère cipher with a known key.
///
/// The key is ASCII letters in either case, such as `LEMON`. The text's letters are
/// decrypted with the key's letters in turn; anything else is copied and uses up no key
/// letter.
///
/// ```
/// let decoded = ciphey::decoders::vigenere_with_key("Rijvs uyvjn", "key")?;
/// assert_eq!(decoded.candidates[0].text, "Hello world");
/// assert_eq!(decoded.candidates[0].key.as_deref(), Some("KEY"));
/// # Ok::<(), ciphey::CipheyError>(())
/// ```
///
/// # Errors
///
/// [`CipheyError::InvalidKey`] if the key is empty or has anything but ASCII letters.
pub fn vigenere_with_key(text: &str, key: &str) -> Result<Decoded, CipheyError> {
    if key.is_empty() || !key.bytes().all(|byte| byte.is_ascii_alphabetic()) {
        return Err(invalid_key::<VigenereDecoder>(format!(
            "{key:?} isn't a key: it must be one or more letters, such as LEMON"
        )));
    }
    let key = key.to_ascii_uppercase();
    Ok(decrypted::<VigenereDecoder>(vec![(
        vigenere_decoder::decrypt(text, &key),
        key,
    )]))
}

/// Decrypts the Affine cipher with a known key: text encrypted as E(x) = (a·x + b) mod 26
/// is decrypted as D(y) = a⁻¹·(y − b) mod 26.
///
/// Both numbers are taken mod 26, and `a` must be coprime with 26: 1, 3, 5, 7, 9, 11, 15,
/// 17, 19, 21, 23 or 25. Letters keep their case and anything else is copied.
///
/// ```
/// let decoded = ciphey::decoders::affine_with_key("IHHWVC SWFRCP", 5, 8)?;
/// assert_eq!(decoded.candidates[0].text, "AFFINE CIPHER");
/// assert_eq!(decoded.candidates[0].key.as_deref(), Some("a=5, b=8"));
/// # Ok::<(), ciphey::CipheyError>(())
/// ```
///
/// # Errors
///
/// [`CipheyError::InvalidKey`] if `a` isn't coprime with 26.
pub fn affine_with_key(text: &str, a: u32, b: u32) -> Result<Decoded, CipheyError> {
    let (reduced_a, reduced_b) = ((a % 26) as u8, (b % 26) as u8);
    if affine_decoder::inverse_mod_26(reduced_a).is_none() {
        return Err(invalid_key::<AffineDecoder>(format!(
            "a = {a} isn't coprime with 26: it must be 1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23 or 25 (mod 26)"
        )));
    }
    Ok(decrypted::<AffineDecoder>(vec![(
        affine_decoder::decrypt(text, reduced_a, reduced_b),
        format!("a={reduced_a}, b={reduced_b}"),
    )]))
}

/// Decrypts the rail fence cipher with a known number of rails and offset.
///
/// The plaintext was written in a zigzag over `rails` rails, starting `offset` steps into
/// the zigzag, and read off one rail after another. There must be at least 2 rails, and
/// no more than the text is long. The offset is taken mod the zigzag's length,
/// 2·(rails − 1).
///
/// ```
/// let decoded = ciphey::decoders::railfence_with_key("Hoo!el,Wrdl l", 3, 0)?;
/// assert_eq!(decoded.candidates[0].text, "Hello, World!");
/// assert_eq!(decoded.candidates[0].key.as_deref(), Some("rails=3, offset=0"));
/// # Ok::<(), ciphey::CipheyError>(())
/// ```
///
/// # Errors
///
/// [`CipheyError::InvalidKey`] if there are fewer than 2 rails, or more rails than the
/// text has bytes.
pub fn railfence_with_key(text: &str, rails: usize, offset: usize) -> Result<Decoded, CipheyError> {
    if rails < 2 {
        return Err(invalid_key::<RailfenceDecoder>(
            "there must be at least 2 rails",
        ));
    }
    if rails > text.len().max(2) {
        return Err(invalid_key::<RailfenceDecoder>(format!(
            "{rails} rails is more than the text is long"
        )));
    }
    let offset = offset % (2 * (rails - 1));
    Ok(decrypted::<RailfenceDecoder>(vec![(
        railfence_decoder::railfence_decoder(text, rails, offset),
        format!("rails={rails}, offset={offset}"),
    )]))
}

/// Decrypts single-byte XOR with a known key byte.
///
/// The ciphertext bytes are read from `text` the way the cracker reads them, whatever
/// their length: the bytes it spells in hex, if it is hex; otherwise its Base64 decoding,
/// if it is Base64, and its own bytes. Each reading gives a candidate. Bytes that aren't
/// UTF-8 come back one character per byte (Latin-1).
///
/// ```
/// let decoded = ciphey::decoders::xor_single_byte_with_key(
///     "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736",
///     0x58,
/// );
/// assert_eq!(decoded.candidates[0].text, "Cooking MC's like a pound of bacon");
/// assert!(decoded.candidates[0].is_plaintext());
/// ```
pub fn xor_single_byte_with_key(text: &str, key: u8) -> Decoded {
    decrypted::<XorSingleByteDecoder>(xor_decryptions(
        text,
        &[key],
        &xor_single_byte_decoder::format_key(key),
    ))
}

/// Decrypts XOR with a known key, repeated over the text.
///
/// The ciphertext is read from `text` as [`xor_single_byte_with_key`] reads it.
///
/// ```
/// // Cryptopals set 1 challenge 5
/// let decoded = ciphey::decoders::xor_repeating_key_with_key(
///     "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f",
///     b"ICE",
/// )?;
/// assert_eq!(
///     decoded.candidates[0].text,
///     "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal",
/// );
/// # Ok::<(), ciphey::CipheyError>(())
/// ```
///
/// # Errors
///
/// [`CipheyError::InvalidKey`] if the key is empty.
pub fn xor_repeating_key_with_key(text: &str, key: &[u8]) -> Result<Decoded, CipheyError> {
    if key.is_empty() {
        return Err(invalid_key::<XorRepeatingKeyDecoder>(
            "the key must be at least one byte",
        ));
    }
    Ok(decrypted::<XorRepeatingKeyDecoder>(xor_decryptions(
        text,
        key,
        &xor_repeating_key_decoder::format_key(key),
    )))
}

/// Decrypts monoalphabetic substitution with a known key.
///
/// The key is 26 letters, the cipher letter of each plaintext letter A to Z:
/// `QWERTYUIOPASDFGHJKLZXCVBNM` says A was written as Q, B as W and so on. That is how
/// [`monoalphabetic_substitution`](super::monoalphabetic_substitution) reports the keys it
/// finds, with `?` for plaintext letters that don't occur. Letters keep their case and
/// anything else is copied.
///
/// ```
/// let decoded = ciphey::decoders::monoalphabetic_substitution_with_key(
///     "Itssg vgksr",
///     "QWERTYUIOPASDFGHJKLZXCVBNM",
/// )?;
/// assert_eq!(decoded.candidates[0].text, "Hello world");
/// # Ok::<(), ciphey::CipheyError>(())
/// ```
///
/// # Errors
///
/// [`CipheyError::InvalidKey`] if the key isn't 26 letters or `?`s, has a letter twice,
/// or doesn't say which letter one of the text's letters stands for.
pub fn monoalphabetic_substitution_with_key(text: &str, key: &str) -> Result<Decoded, CipheyError> {
    let letters: Vec<char> = key.chars().collect();
    if letters.len() != 26 || !letters.iter().all(|&c| c == '?' || c.is_ascii_alphabetic()) {
        return Err(invalid_key::<MonoalphabeticSubstitutionDecoder>(format!(
            "{key:?} isn't a key: it must be 26 letters, the cipher letter of each plaintext \
             letter A to Z, with ? for letters that aren't used"
        )));
    }
    // The plaintext letter of each cipher letter
    let mut plain_of = [None; 26];
    for (plain, cipher) in (0u8..).zip(letters.iter().map(char::to_ascii_uppercase)) {
        if cipher == '?' {
            continue;
        }
        let slot = &mut plain_of[letter_index(cipher)];
        if slot.is_some() {
            return Err(invalid_key::<MonoalphabeticSubstitutionDecoder>(format!(
                "{cipher} is in the key twice"
            )));
        }
        *slot = Some(plain);
    }
    let missing = text
        .chars()
        .filter(char::is_ascii_alphabetic)
        .map(|c| c.to_ascii_uppercase())
        .find(|&c| plain_of[letter_index(c)].is_none());
    if let Some(missing) = missing {
        return Err(invalid_key::<MonoalphabeticSubstitutionDecoder>(format!(
            "the key doesn't say which letter {missing} stands for"
        )));
    }
    let table = plain_of.map(Option::unwrap_or_default);
    Ok(decrypted::<MonoalphabeticSubstitutionDecoder>(vec![(
        monoalphabetic_substitution_decoder::decrypt(text, &table),
        letters.iter().map(char::to_ascii_uppercase).collect(),
    )]))
}

/// Caesar's key for [`decode_with`](super::decode_with).
pub(super) const CAESAR: KeySupport = KeySupport {
    format: "A whole number, the shift that decodes the text (taken mod 26), as the cracker \
             reports it: 13 for ROT13, 23 or -3 to undo the classic shift of 3.",
    decrypt: caesar_key,
};

/// ROT47's key for [`decode_with`](super::decode_with).
pub(super) const ROT47: KeySupport = KeySupport {
    format: "A whole number, the rotation of the printable ASCII characters that decodes \
             the text (taken mod 94): 47 for ROT47.",
    decrypt: rot47_key,
};

/// Vigenère's key for [`decode_with`](super::decode_with).
pub(super) const VIGENERE: KeySupport = KeySupport {
    format: "The keyword, in letters: LEMON.",
    decrypt: vigenere_key,
};

/// Affine's key for [`decode_with`](super::decode_with).
pub(super) const AFFINE: KeySupport = KeySupport {
    format: "a and b of E(x) = (a*x + b) mod 26, as the cracker reports them: a=5, b=8 \
             (or 5, 8). a must be coprime with 26.",
    decrypt: affine_key,
};

/// The rail fence's key for [`decode_with`](super::decode_with).
pub(super) const RAILFENCE: KeySupport = KeySupport {
    format: "The number of rails, and the offset into the zigzag if it isn't 0: 3, \
             rails=3, offset=1 (or 3, 1).",
    decrypt: railfence_key,
};

/// Single-byte XOR's key for [`decode_with`](super::decode_with).
pub(super) const XOR_SINGLE_BYTE: KeySupport = KeySupport {
    format: "The key byte, as a number (88), in hex (0x58, as the cracker reports it) or \
             as one character (X).",
    decrypt: xor_single_byte_key,
};

/// Repeating-key XOR's key for [`decode_with`](super::decode_with).
pub(super) const XOR_REPEATING_KEY: KeySupport = KeySupport {
    format: "The key as text (ICE), or as bytes in hex after 0x (0x494345).",
    decrypt: xor_repeating_key_key,
};

/// Monoalphabetic substitution's key for [`decode_with`](super::decode_with).
pub(super) const MONOALPHABETIC_SUBSTITUTION: KeySupport = KeySupport {
    format: "26 letters, the cipher letter of each plaintext letter A to Z, with ? for \
             letters the text doesn't use, as the cracker reports it: \
             QWERTYUIOPASDFGHJKLZXCVBNM.",
    decrypt: monoalphabetic_substitution_key,
};

/// [`caesar_with_key`] with the key written as [`CAESAR`] says.
fn caesar_key(text: &str, key: &str) -> Result<Decoded, CipheyError> {
    Ok(caesar_with_key(text, parse_integer::<CaesarDecoder>(key)?))
}

/// [`rot47_with_key`] with the key written as [`ROT47`] says.
fn rot47_key(text: &str, key: &str) -> Result<Decoded, CipheyError> {
    Ok(rot47_with_key(text, parse_integer::<ROT47Decoder>(key)?))
}

/// [`vigenere_with_key`] with the key written as [`VIGENERE`] says.
fn vigenere_key(text: &str, key: &str) -> Result<Decoded, CipheyError> {
    vigenere_with_key(text, key.trim())
}

/// [`affine_with_key`] with the key written as [`AFFINE`] says.
fn affine_key(text: &str, key: &str) -> Result<Decoded, CipheyError> {
    match parse_numbers::<AffineDecoder, 2>(key, ["a", "b"], "a=5, b=8")? {
        [Some(a), Some(b)] => affine_with_key(text, a, b),
        _ => Err(invalid_key::<AffineDecoder>(format!(
            "{key:?} needs both a and b, as in a=5, b=8"
        ))),
    }
}

/// [`railfence_with_key`] with the key written as [`RAILFENCE`] says.
fn railfence_key(text: &str, key: &str) -> Result<Decoded, CipheyError> {
    match parse_numbers::<RailfenceDecoder, 2>(key, ["rails", "offset"], "rails=3, offset=1")? {
        [Some(rails), offset] => {
            railfence_with_key(text, rails as usize, offset.unwrap_or(0) as usize)
        }
        [None, _] => Err(invalid_key::<RailfenceDecoder>(format!(
            "{key:?} doesn't say how many rails there are, as in rails=3, offset=1"
        ))),
    }
}

/// [`xor_single_byte_with_key`] with the key written as [`XOR_SINGLE_BYTE`] says.
fn xor_single_byte_key(text: &str, key: &str) -> Result<Decoded, CipheyError> {
    let trimmed = key.trim();
    let byte = if !trimmed.is_empty() && trimmed.bytes().all(|byte| byte.is_ascii_digit()) {
        trimmed.parse().ok()
    } else if let Some(hex) = hex_digits(trimmed) {
        u8::from_str_radix(hex, 16).ok()
    } else {
        let mut chars = key.chars();
        match (chars.next(), chars.next()) {
            (Some(c), None) => u8::try_from(c).ok(),
            _ => None,
        }
    };
    let byte = byte.ok_or_else(|| {
        invalid_key::<XorSingleByteDecoder>(format!(
            "{key:?} isn't a byte: write it as 88, 0x58 or X"
        ))
    })?;
    Ok(xor_single_byte_with_key(text, byte))
}

/// [`xor_repeating_key_with_key`] with the key written as [`XOR_REPEATING_KEY`] says.
fn xor_repeating_key_key(text: &str, key: &str) -> Result<Decoded, CipheyError> {
    let Some(hex) = hex_digits(key.trim()) else {
        return xor_repeating_key_with_key(text, key.as_bytes());
    };
    if hex.is_empty() || hex.len() % 2 != 0 {
        return Err(invalid_key::<XorRepeatingKeyDecoder>(format!(
            "{key:?} isn't whole bytes: write two hex digits per byte after 0x, as in 0x494345"
        )));
    }
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        // Two ASCII hex digits, so neither the slice nor the parse can fail
        .filter_map(|start| u8::from_str_radix(&hex[start..start + 2], 16).ok())
        .collect();
    xor_repeating_key_with_key(text, &bytes)
}

/// [`monoalphabetic_substitution_with_key`] with the key written as
/// [`MONOALPHABETIC_SUBSTITUTION`] says.
fn monoalphabetic_substitution_key(text: &str, key: &str) -> Result<Decoded, CipheyError> {
    monoalphabetic_substitution_with_key(text, key.trim())
}

/// The digits of `0x...` or `0X...`, if `key` is hex digits after one of those.
fn hex_digits(key: &str) -> Option<&str> {
    key.strip_prefix("0x")
        .or_else(|| key.strip_prefix("0X"))
        .filter(|digits| digits.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

/// `key` as a whole number.
fn parse_integer<T>(key: &str) -> Result<i64, CipheyError>
where
    Decoder<T>: Crack,
{
    key.trim()
        .parse()
        .map_err(|_| invalid_key::<T>(format!("{key:?} isn't a whole number")))
}

/// The numbers in `key` for each of `names`, given in order (`5, 8`) or by name
/// (`a=5, b=8`, in any order and case), separated by commas, semicolons or spaces. The
/// ones not given are `None`. `example` shows the right way in the error.
fn parse_numbers<T, const N: usize>(
    key: &str,
    names: [&str; N],
    example: &str,
) -> Result<[Option<u32>; N], CipheyError>
where
    Decoder<T>: Crack,
{
    let invalid = || invalid_key::<T>(format!("{key:?} isn't a key like {example}"));
    // "a = 5" is "a=5"
    let tight = key.split('=').map(str::trim).collect::<Vec<_>>().join("=");
    let mut values = [None; N];
    let parts = tight
        .split(|c: char| matches!(c, ',' | ';') || c.is_whitespace())
        .map(|part| part.trim_matches(|c| matches!(c, '(' | ')')))
        .filter(|part| !part.is_empty());
    for part in parts {
        let (slot, value) = match part.split_once('=') {
            Some((name, value)) => (
                names
                    .iter()
                    .position(|known| known.eq_ignore_ascii_case(name)),
                value,
            ),
            None => (values.iter().position(Option::is_none), part),
        };
        let slot = slot
            .filter(|&slot| values[slot].is_none())
            .ok_or_else(invalid)?;
        values[slot] = Some(value.parse().map_err(|_| invalid())?);
    }
    Ok(values)
}

/// The decryption of each reading of `text`'s bytes (see [`xor_views`]) with `key`,
/// repeated, each with `formatted_key` as its key.
fn xor_decryptions(text: &str, key: &[u8], formatted_key: &str) -> Vec<(String, String)> {
    xor_views(text)
        .iter()
        .map(|view| {
            let plaintext = xor_repeating_key_decoder::xor_with_key(view, key);
            (bytes_to_string(plaintext), formatted_key.to_string())
        })
        .collect()
}

/// The ciphertext bytes `text` can stand for, as the XOR crackers read them but whatever
/// their length: what it spells in hex, if it is hex; otherwise what it spells in Base64,
/// if it is Base64, and its own bytes.
fn xor_views(text: &str) -> Vec<Vec<u8>> {
    let trimmed = text.trim();
    if let Some(bytes) = xor_single_byte_decoder::hex_view(trimmed) {
        return vec![bytes];
    }
    let mut views: Vec<Vec<u8>> = xor_single_byte_decoder::decode_base64(trimmed)
        .into_iter()
        .collect();
    views.push(own_bytes(text));
    views
}

/// The bytes of `text`: one per character if all of them are below U+0100, as in text an
/// earlier decoder made from bytes, otherwise its UTF-8.
fn own_bytes(text: &str) -> Vec<u8> {
    text.chars()
        .map(|c| u8::try_from(c).ok())
        .collect::<Option<Vec<u8>>>()
        .unwrap_or_else(|| text.as_bytes().to_vec())
}

/// The position of an upper-case ASCII letter in the alphabet, 0 to 25.
fn letter_index(letter: char) -> usize {
    usize::from(letter as u8 - b'A')
}

/// A [`CipheyError::InvalidKey`] for `Decoder<T>`.
fn invalid_key<T>(reason: impl Into<String>) -> CipheyError
where
    Decoder<T>: Crack,
{
    CipheyError::InvalidKey {
        decoder: name_of::<T>(),
        reason: reason.into(),
    }
}
