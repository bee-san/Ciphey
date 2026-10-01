//! This module contains all the code for decoders
//! Think of a decoder as a decryption method that doesn't require a key
//! The `interface.rs` defines what each decoder looks like.
//! Once you have made a decoder you need to add it to the filtration system's
//! mod.rs file
//! you will also need to make it a public module in this file.

/// The a1z26_decoder module decodes A1Z26
pub mod a1z26_decoder;
/// The ascii85_decoder module decodes Ascii85 (Adobe / btoa Base85)
pub mod ascii85_decoder;
/// The atbash_decoder module decodes atbash
pub mod atbash_decoder;
/// The baconian_decoder module decodes Bacon's cipher
pub mod baconian_decoder;
/// The base32_decoder module decodes base32
pub mod base32_decoder;
/// The base58_bitcoin_decoder module decodes base58 bitcoin
pub mod base58_bitcoin_decoder;
/// The base58_monero_decoder module decodes base58 monero
pub mod base58_monero_decoder;
/// The binary_decoder module decodes binary
pub mod binary_decoder;
/// The decimal_decoder module decodes decimal character codes
pub mod decimal_decoder;
/// The hexadecimal_decoder module decodes hexadecimal
pub mod hexadecimal_decoder;
/// The html_entity_decoder module decodes HTML entities
pub mod html_entity_decoder;
/// The octal_decoder module decodes octal
pub mod octal_decoder;

/// The base58_ripple_decoder module decodes base58 ripple
pub mod base58_ripple_decoder;

/// The base58_flickr decoder module decodes base58 flickr
pub mod base58_flickr_decoder;

/// The base64_decoder module decodes base64
/// It is public as we use it in some tests.
pub mod base64_decoder;
/// The base65536 module decodes base65536
pub mod base65536_decoder;
/// The base85_decoder module decodes Base85 with the RFC 1924 alphabet
pub mod base85_decoder;
/// The base91_decoder module decodes base91
pub mod base91_decoder;
/// The citrix_ctx1_decoder module decodes citrix ctx1
pub mod citrix_ctx1_decoder;
/// The crack_results module defines the CrackResult
/// Each and every decoder return same CrackResult
pub mod crack_results;
/// The jwt_decoder module decodes JSON Web Tokens (JWT)
pub mod jwt_decoder;
/// The quoted_printable_decoder module decodes Quoted-Printable (RFC 2045)
pub mod quoted_printable_decoder;
/// The unicode_escape_decoder module decodes Unicode escapes like `\u00e9`, `%u00E9` and `U+00E9`
pub mod unicode_escape_decoder;
/// The url_decoder module decodes url
pub mod url_decoder;
/// The utf16_decoder module decodes UTF-16 (LE/BE) text
pub mod utf16_decoder;

/// The interface module defines the interface for decoders
/// Each and every decoder has the same struct & traits
pub mod interface;

/// The reverse_decoder module decodes reverse text
/// Stac -> Cats
/// It is public as we use it in some tests.
pub mod reverse_decoder;

/// The morse_code module decodes morse code
/// It is public as we use it in some tests.
pub mod morse_code;

/// For the caesar cipher decoder
pub mod caesar_decoder;

/// For the railfence cipher decoder
pub mod railfence_decoder;
/// For the rot47 decoder
pub mod rot47_decoder;

/// For the z85 cipher decoder
pub mod z85_decoder;

/// For the braille decoder
pub mod braille_decoder;

/// The substitution_generic_decoder module handles generic substitution ciphers
pub mod substitution_generic_decoder;

/// A brainfuck interpreter
pub mod brainfuck_interpreter;

/// The vigenere_decoder module decodes Vigenère cipher text
pub mod vigenere_decoder;

use ascii85_decoder::Ascii85Decoder;
/// The zlib_decoder module inflates zlib (RFC 1950) streams
pub mod zlib_decoder;

use atbash_decoder::AtbashDecoder;
use baconian_decoder::BaconianDecoder;
use base32_decoder::Base32Decoder;
use base58_bitcoin_decoder::Base58BitcoinDecoder;
use base58_flickr_decoder::Base58FlickrDecoder;
use base58_monero_decoder::Base58MoneroDecoder;
use base58_ripple_decoder::Base58RippleDecoder;
use binary_decoder::BinaryDecoder;
use decimal_decoder::DecimalDecoder;
use hexadecimal_decoder::HexadecimalDecoder;
use html_entity_decoder::HtmlEntityDecoder;
use interface::{Crack, Decoder};

use a1z26_decoder::A1Z26Decoder;
use base64_decoder::Base64Decoder;
use base65536_decoder::Base65536Decoder;
use base85_decoder::Base85Decoder;
use base91_decoder::Base91Decoder;
use braille_decoder::BrailleDecoder;
use caesar_decoder::CaesarDecoder;
use citrix_ctx1_decoder::CitrixCTX1Decoder;
use jwt_decoder::JwtDecoder;
use morse_code::MorseCodeDecoder;
use octal_decoder::OctalDecoder;
use quoted_printable_decoder::QuotedPrintableDecoder;
use railfence_decoder::RailfenceDecoder;
use reverse_decoder::ReverseDecoder;
use rot47_decoder::ROT47Decoder;
use substitution_generic_decoder::SubstitutionGenericDecoder;
use unicode_escape_decoder::UnicodeEscapeDecoder;
use url_decoder::URLDecoder;
use utf16_decoder::Utf16Decoder;
use vigenere_decoder::VigenereDecoder;
use z85_decoder::Z85Decoder;
use zlib_decoder::ZlibDecoder;

use brainfuck_interpreter::BrainfuckInterpreter;

use once_cell::sync::Lazy;
use std::collections::HashMap;

/// Enum for annotating Decoder types, specifically for retrieving decoders from
/// DECODER_MAP
pub enum DecoderType {
    /// default decoder
    DefaultDecoder(interface::DefaultDecoder),
    /// a1z26 decoder
    A1z26Decoder(a1z26_decoder::A1Z26Decoder),
    /// ascii85 decoder
    Ascii85Decoder(ascii85_decoder::Ascii85Decoder),
    /// atbash decoder
    AtbashDecoder(atbash_decoder::AtbashDecoder),
    /// baconian decoder
    BaconianDecoder(baconian_decoder::BaconianDecoder),
    /// base32 decoder
    Base32Decoder(base32_decoder::Base32Decoder),
    /// base58 bitcoin decoder
    Base58BitcoinDecoder(base58_bitcoin_decoder::Base58BitcoinDecoder),
    /// base58 monero decoder
    Base58MoneroDecoder(base58_monero_decoder::Base58MoneroDecoder),
    /// binary decoder
    BinaryDecoder(binary_decoder::BinaryDecoder),
    /// decimal decoder
    DecimalDecoder(decimal_decoder::DecimalDecoder),
    /// hexadecimal decoder
    HexadecimalDecoder(hexadecimal_decoder::HexadecimalDecoder),
    /// octal decoder
    OctalDecoder(octal_decoder::OctalDecoder),
    /// HTML entity decoder
    HtmlEntityDecoder(html_entity_decoder::HtmlEntityDecoder),
    /// base58 ripple decoder
    Base58RippleDecoder(base58_ripple_decoder::Base58RippleDecoder),
    /// base58 flickr decoder
    Base58FlickrDecoder(base58_flickr_decoder::Base58FlickrDecoder),
    /// base64 decoder
    Base64Decoder(base64_decoder::Base64Decoder),
    /// base65536 decoder
    Base65536Decoder(base65536_decoder::Base65536Decoder),
    /// base85 (RFC 1924) decoder
    Base85Decoder(base85_decoder::Base85Decoder),
    /// base91 decoder
    Base91Decoder(base91_decoder::Base91Decoder),
    /// citrix ctx1 decoder
    CitrixCtx1Decoder(citrix_ctx1_decoder::CitrixCTX1Decoder),
    /// jwt decoder
    JwtDecoder(jwt_decoder::JwtDecoder),
    /// url decoder
    UrlDecoder(url_decoder::URLDecoder),
    /// unicode escape decoder
    UnicodeEscapeDecoder(unicode_escape_decoder::UnicodeEscapeDecoder),
    /// quoted-printable decoder
    QuotedPrintableDecoder(quoted_printable_decoder::QuotedPrintableDecoder),
    /// UTF-16 decoder
    Utf16Decoder(utf16_decoder::Utf16Decoder),
    /// reverse decoder
    ReverseDecoder(reverse_decoder::ReverseDecoder),
    /// morse decoder
    MorseCode(morse_code::MorseCodeDecoder),
    /// caesar decoder
    CaesarDecoder(caesar_decoder::CaesarDecoder),
    /// railfence decoder
    RailfenceDecoder(railfence_decoder::RailfenceDecoder),
    /// rot47 decoder
    Rot47Decoder(rot47_decoder::ROT47Decoder),
    /// z85 decoder
    Z85Decoder(z85_decoder::Z85Decoder),
    /// braille decoder
    BrailleDecoder(braille_decoder::BrailleDecoder),
    /// substitution decoder
    SubstitutionGenericDecoder(substitution_generic_decoder::SubstitutionGenericDecoder),
    /// brainfuck interpreter
    BrainfuckInterpreter(brainfuck_interpreter::BrainfuckInterpreter),
    /// vigenere decoder
    VigenereDecoder(vigenere_decoder::VigenereDecoder),
    /// zlib decoder
    ZlibDecoder(zlib_decoder::ZlibDecoder),
}

/// Wrapper struct to hold Decoders for DECODER_MAP
pub struct DecoderBox {
    /// Wrapper box to hold Decoders for DECODER_MAP
    value: Box<dyn Crack + Sync + Send>,
}

impl DecoderBox {
    /// Constructor for DecoderBox. Takes in a Decoder and stores it as the
    /// internal value
    fn new<T: 'static + Crack + Sync + Send>(value: T) -> Self {
        Self {
            value: Box::new(value),
        }
    }

    /// Getter method for DecoderBox to return the internal Box
    pub fn get<T: 'static>(&self) -> &(dyn Crack + Sync + Send) {
        self.value.as_ref()
    }
}

/// Global hashmap for translating strings to Decoders
pub static DECODER_MAP: Lazy<HashMap<&str, DecoderBox>> = Lazy::new(|| {
    HashMap::from([
        (
            "Default decoder",
            DecoderBox::new(Decoder::<interface::DefaultDecoder>::new()),
        ),
        (
            "Vigenere",
            DecoderBox::new(Decoder::<VigenereDecoder>::new()),
        ),
        ("Binary", DecoderBox::new(Decoder::<BinaryDecoder>::new())),
        ("Decimal", DecoderBox::new(Decoder::<DecimalDecoder>::new())),
        (
            "Hexadecimal",
            DecoderBox::new(Decoder::<HexadecimalDecoder>::new()),
        ),
        ("Octal", DecoderBox::new(Decoder::<OctalDecoder>::new())),
        (
            "HTML Entities",
            DecoderBox::new(Decoder::<HtmlEntityDecoder>::new()),
        ),
        (
            "Base58 Bitcoin",
            DecoderBox::new(Decoder::<Base58BitcoinDecoder>::new()),
        ),
        (
            "Base58 Monero",
            DecoderBox::new(Decoder::<Base58MoneroDecoder>::new()),
        ),
        (
            "Base58 Ripple",
            DecoderBox::new(Decoder::<Base58RippleDecoder>::new()),
        ),
        (
            "Base58 Flickr",
            DecoderBox::new(Decoder::<Base58FlickrDecoder>::new()),
        ),
        ("Base64", DecoderBox::new(Decoder::<Base64Decoder>::new())),
        ("Base85", DecoderBox::new(Decoder::<Base85Decoder>::new())),
        ("Base91", DecoderBox::new(Decoder::<Base91Decoder>::new())),
        (
            "Base65536",
            DecoderBox::new(Decoder::<Base65536Decoder>::new()),
        ),
        (
            "Citrix Ctx1",
            DecoderBox::new(Decoder::<CitrixCTX1Decoder>::new()),
        ),
        ("JWT", DecoderBox::new(Decoder::<JwtDecoder>::new())),
        ("URL", DecoderBox::new(Decoder::<URLDecoder>::new())),
        (
            "Unicode Escapes",
            DecoderBox::new(Decoder::<UnicodeEscapeDecoder>::new()),
        ),
        (
            "Quoted-Printable",
            DecoderBox::new(Decoder::<QuotedPrintableDecoder>::new()),
        ),
        ("UTF-16", DecoderBox::new(Decoder::<Utf16Decoder>::new())),
        ("Base32", DecoderBox::new(Decoder::<Base32Decoder>::new())),
        ("Reverse", DecoderBox::new(Decoder::<ReverseDecoder>::new())),
        (
            "Morse Code",
            DecoderBox::new(Decoder::<MorseCodeDecoder>::new()),
        ),
        ("atbash", DecoderBox::new(Decoder::<AtbashDecoder>::new())),
        (
            "Baconian",
            DecoderBox::new(Decoder::<BaconianDecoder>::new()),
        ),
        ("caesar", DecoderBox::new(Decoder::<CaesarDecoder>::new())),
        (
            "railfence",
            DecoderBox::new(Decoder::<RailfenceDecoder>::new()),
        ),
        ("rot47", DecoderBox::new(Decoder::<ROT47Decoder>::new())),
        ("Z85", DecoderBox::new(Decoder::<Z85Decoder>::new())),
        ("Ascii85", DecoderBox::new(Decoder::<Ascii85Decoder>::new())),
        ("a1z26", DecoderBox::new(Decoder::<A1Z26Decoder>::new())),
        ("Braille", DecoderBox::new(Decoder::<BrailleDecoder>::new())),
        (
            "simplesubstitution",
            DecoderBox::new(Decoder::<SubstitutionGenericDecoder>::new()),
        ),
        (
            "Brainfuck",
            DecoderBox::new(Decoder::<BrainfuckInterpreter>::new()),
        ),
        ("Zlib", DecoderBox::new(Decoder::<ZlibDecoder>::new())),
    ])
});
