//! The decoders, and functions to run one of them on a text.
//!
//! # Running one decoder
//!
//! Every decoder has a function here named after it: [`base64`](crate::decoders::base64),
//! [`hexadecimal`](crate::decoders::hexadecimal), [`caesar`](crate::decoders::caesar),
//! [`vigenere`](crate::decoders::vigenere), [`xor_single_byte`](crate::decoders::xor_single_byte) and so on. Encodings are decoded, and
//! ciphers are cracked; the ones that take a key can also decrypt with a key you know,
//! with `*_with_key` functions such as [`caesar_with_key`](crate::decoders::caesar_with_key) and
//! [`vigenere_with_key`](crate::decoders::vigenere_with_key).
//! [`decode_with`](crate::decoders::decode_with) runs a decoder chosen by name at run time, and [`list_decoders`](crate::decoders::list_decoders) lists
//! them all with their aliases, tags and key formats.
//!
//! ```
//! use ciphey::decoders::{self, DecodeOptions};
//!
//! // An encoding comes back decoded
//! let decoded = decoders::base64("aGVsbG8gd29ybGQ=");
//! assert_eq!(decoded.candidates[0].text, "hello world");
//!
//! // A cipher without its key is cracked
//! let cracked = decoders::caesar("Uryyb jbeyq");
//! let plaintext = cracked.plaintext().unwrap();
//! assert_eq!(plaintext.text, "Hello world");
//! assert_eq!(plaintext.key.as_deref(), Some("13"));
//!
//! // With the key it is decrypted
//! let decrypted = decoders::vigenere_with_key("Rijvs uyvjn", "KEY")?;
//! assert_eq!(decrypted.candidates[0].text, "Hello world");
//!
//! // The same, by name
//! let decrypted = decoders::decode_with("vigenere", "Rijvs uyvjn", &DecodeOptions::with_key("KEY"))?;
//! assert!(decrypted.candidates[0].is_plaintext());
//! # Ok::<(), ciphey::CipheyError>(())
//! ```
//!
//! # What comes back
//!
//! A [`Decoded`](crate::decoders::Decoded): the decoder's [`Candidate`](crate::decoders::Candidate)s. Each has the decoded text, the key that
//! gave it if the decoder reports one, and a
//! [`Detection`](crate::detection::Detection) if Ciphey's plaintext checks accepted it.
//!
//! Without a key the decoder runs as it does in a search, and nothing is filtered out
//! of what it returns: it checks its decodings and stops at the first one the checks
//! accept, which comes back alone and marked as plaintext
//! ([`Decoded::plaintext`](crate::decoders::Decoded::plaintext)). If they accept none,
//! you get, unmarked, the decodings it would hand on to the search for you to judge: all
//! 25 Caesar shifts, say, or a Base64 decoding that isn't English. Crackers with many keys
//! hand on only their best few, or none. Only empty and repeated decodings are dropped.
//! Text that isn't in the decoder's format gives no candidates.
//!
//! With a key there is nothing to crack: the text is decrypted with it, and the result is
//! checked and marked if the checks accept it.
//!
//! The checks are Athena's, the checker the search uses: at the sensitivity each cracker
//! picks when cracking, and at Athena's default with a key. Like the search, they follow
//! the process-wide [`Config`](crate::config::Config): with `Config::regex` set only text
//! that the crib matches counts, and `Config::wordlist` adds the wordlist. The default
//! config needs no setting up. The human checker is never asked, so these functions
//! never read from stdin. To check a text yourself, with your own choice of checkers,
//! use [`detect_plaintext`](crate::detection::detect_plaintext).
//!
//! # Adding a decoder
//!
//! Think of a decoder as a decryption method that doesn't require a key.
//! The `interface.rs` defines what each decoder looks like.
//! Once you have made a decoder you need to add it to the filtration system's
//! mod.rs file and give it a function in `api/functions.rs`;
//! you will also need to make it a public module in this file.

mod api;
pub use api::*;

/// The a1z26_decoder module decodes A1Z26
pub mod a1z26_decoder;
/// The aaencode_decoder module decodes AAEncode (JavaScript written as Japanese emoticons)
pub mod aaencode_decoder;
/// The affine_decoder module cracks the affine cipher
pub mod affine_decoder;
/// The ascii85_decoder module decodes Ascii85 (Adobe / btoa Base85)
pub mod ascii85_decoder;
/// The ascii_shift_decoder module cracks the ASCII shift cipher (every byte shifted by one key)
pub mod ascii_shift_decoder;
/// The atbash_decoder module decodes atbash
pub mod atbash_decoder;
/// The backslash_escape_decoder module decodes C, Python and JavaScript string escapes like `\x41` and `\101`
pub mod backslash_escape_decoder;
/// The baconian_decoder module decodes Bacon's cipher
pub mod baconian_decoder;
/// The base32_decoder module decodes base32
pub mod base32_decoder;
/// The base36_decoder module decodes Base36 (bytes as one big-endian radix-36 integer)
pub mod base36_decoder;
/// The base58_bitcoin_decoder module decodes base58 bitcoin
pub mod base58_bitcoin_decoder;
/// The base58_monero_decoder module decodes base58 monero
pub mod base58_monero_decoder;
/// The baudot_decoder module decodes Baudot code (ITA2 and US-TTY, 5-bit teleprinter code)
pub mod baudot_decoder;
/// The beaufort_decoder module cracks the Beaufort cipher, the reciprocal Vigenère variant
pub mod beaufort_decoder;
/// The big_integer_decoder module decodes a big decimal integer to its bytes (long_to_bytes)
pub mod big_integer_decoder;
/// The binary_decoder module decodes binary
pub mod binary_decoder;
/// The bzip2_decoder module decompresses bzip2 given as Base64, hex or raw bytes
pub mod bzip2_decoder;
/// The decimal_decoder module decodes decimal character codes
pub mod decimal_decoder;
/// The dna_codon_decoder module decodes DNA/RNA codons to one-letter amino-acid codes
pub mod dna_codon_decoder;
/// The dtmf_decoder module decodes DTMF (touch-tone) frequency pairs
pub mod dtmf_decoder;
/// The hexadecimal_decoder module decodes hexadecimal
pub mod hexadecimal_decoder;
/// The hexdump_decoder module decodes the output of xxd, hexdump and od
pub mod hexdump_decoder;
/// The html_entity_decoder module decodes HTML entities
pub mod html_entity_decoder;
/// The jsfuck_decoder module evaluates JSFuck, JavaScript written with only `[]()!+`
pub mod jsfuck_decoder;
/// The keyboard_layout_decoder module decodes text typed on one keyboard layout and read as another
pub mod keyboard_layout_decoder;
/// The octal_decoder module decodes octal
pub mod octal_decoder;
/// The ook_decoder module runs Ook! programs (Brainfuck written as `Ook.` `Ook?` `Ook!`)
pub mod ook_decoder;
/// The playfair_decoder module cracks the Playfair cipher
pub mod playfair_decoder;
/// The polybius_decoder module decodes the Polybius square cipher
pub mod polybius_decoder;

/// The base58_ripple_decoder module decodes base58 ripple
pub mod base58_ripple_decoder;

/// The base58_flickr decoder module decodes base58 flickr
pub mod base58_flickr_decoder;

/// The base100_decoder module decodes Base100 (emoji)
pub mod base100_decoder;
/// The base64_alt_decoder module decodes Base64 written with a non-standard alphabet
pub mod base64_alt_decoder;
/// The base64_decoder module decodes base64
/// It is public as we use it in some tests.
pub mod base64_decoder;
/// The base65536 module decodes base65536
pub mod base65536_decoder;
/// The base85_decoder module decodes Base85 with the RFC 1924 alphabet
pub mod base85_decoder;
/// The base91_decoder module decodes base91
pub mod base91_decoder;
/// The base92_decoder module decodes Base92 (thenoviceoof)
pub mod base92_decoder;
/// The citrix_ctx1_decoder module decodes citrix ctx1
pub mod citrix_ctx1_decoder;
/// The core_socialist_values_decoder module decodes the Core Socialist Values encoding (社会主义核心价值观)
pub mod core_socialist_values_decoder;
/// The crack_results module defines the CrackResult
/// Each and every decoder return same CrackResult
pub mod crack_results;
/// The gzip_decoder module decompresses gzip given as Base64 or hex
pub mod gzip_decoder;
/// The hill_decoder module cracks the Hill cipher (2×2 and 3×3 key matrices)
pub mod hill_decoder;
/// The jwt_decoder module decodes JSON Web Tokens (JWT)
pub mod jwt_decoder;
/// The keyboard_shift_decoder module cracks the keyboard shift cipher (`jr;;p` for `hello`)
pub mod keyboard_shift_decoder;
/// The leetspeak_decoder module decodes leetspeak (1337)
pub mod leetspeak_decoder;
/// The mime_encoded_word_decoder module decodes MIME encoded-words (RFC 2047)
pub mod mime_encoded_word_decoder;
/// The multi_tap_decoder module decodes Multi-tap phone keypad text like `44 33 555`
pub mod multi_tap_decoder;
/// The punycode_decoder module decodes Punycode and IDNA `xn--` labels
pub mod punycode_decoder;
/// The quoted_printable_decoder module decodes Quoted-Printable (RFC 2045)
pub mod quoted_printable_decoder;
/// The tap_code_decoder module decodes tap code (knock code)
pub mod tap_code_decoder;
/// The unicode_escape_decoder module decodes Unicode escapes like `\u00e9`, `%u00E9` and `U+00E9`
pub mod unicode_escape_decoder;
/// The unicode_fancy_text_decoder module decodes Unicode look-alike "fonts" like `𝐡𝐞𝐥𝐥𝐨` and `ｈｅｌｌｏ`
pub mod unicode_fancy_text_decoder;
/// The url_decoder module decodes url
pub mod url_decoder;
/// The utf16_decoder module decodes UTF-16 (LE/BE) text
pub mod utf16_decoder;
/// The uuencode_decoder module decodes Uuencode (Unix-to-Unix encoding)
pub mod uuencode_decoder;
/// The xz_decoder module decompresses XZ and legacy LZMA (`.lzma`) files
pub mod xz_decoder;

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

/// The nato_phonetic_decoder module decodes text spelled with the NATO phonetic alphabet
pub mod nato_phonetic_decoder;

/// For the caesar cipher decoder
pub mod caesar_decoder;

/// For the railfence cipher decoder
pub mod railfence_decoder;
/// For the ROT5 / ROT18 decoder (digits rotated by 5, letters by a Caesar shift)
pub mod rot18_decoder;
/// For the rot47 decoder
pub mod rot47_decoder;
/// The route_transposition_decoder module cracks the scytale, the Caesar box and route ciphers
pub mod route_transposition_decoder;

/// For the z85 cipher decoder
pub mod z85_decoder;

/// For the braille decoder
pub mod braille_decoder;

/// The standard_galactic_alphabet_decoder module decodes the Standard Galactic Alphabet
/// (Minecraft's enchanting table)
pub mod standard_galactic_alphabet_decoder;

/// The substitution_generic_decoder module handles generic substitution ciphers
pub mod substitution_generic_decoder;

/// A brainfuck interpreter
pub mod brainfuck_interpreter;

/// The vigenere_decoder module decodes Vigenère cipher text
pub mod vigenere_decoder;

/// The vigenere_autokey_decoder module cracks the Vigenère autokey (autoclave) cipher
pub mod vigenere_autokey_decoder;

use ascii85_decoder::Ascii85Decoder;
/// The zlib_decoder module inflates zlib (RFC 1950) streams
pub mod zlib_decoder;

/// The raw_deflate_decoder module inflates raw DEFLATE (RFC 1951) streams
pub mod raw_deflate_decoder;

/// The xor_single_byte_decoder module cracks single-byte XOR
pub mod xor_single_byte_decoder;

/// The xor_repeating_key_decoder module cracks XOR with a repeating multi-byte key
pub mod xor_repeating_key_decoder;

/// The zero_width_decoder module reads messages hidden as zero-width Unicode characters
pub mod zero_width_decoder;

/// The monoalphabetic_substitution_decoder module cracks simple substitution ciphers
pub mod monoalphabetic_substitution_decoder;

/// The t9_decoder module decodes T9 predictive text (phone keypad digits)
pub mod t9_decoder;
/// The yunying_decoder module decodes the 01248 (Yunying) cipher, letters as sums of 1, 2, 4 and 8
pub mod yunying_decoder;

/// The null_cipher_decoder module finds messages hidden in null ciphers such as acrostics
pub mod null_cipher_decoder;

use atbash_decoder::AtbashDecoder;
use backslash_escape_decoder::BackslashEscapeDecoder;
use baconian_decoder::BaconianDecoder;
use base32_decoder::Base32Decoder;
use base36_decoder::Base36Decoder;
use base58_bitcoin_decoder::Base58BitcoinDecoder;
use base58_flickr_decoder::Base58FlickrDecoder;
use base58_monero_decoder::Base58MoneroDecoder;
use base58_ripple_decoder::Base58RippleDecoder;
use baudot_decoder::BaudotDecoder;
use beaufort_decoder::BeaufortDecoder;
use big_integer_decoder::BigIntegerDecoder;
use binary_decoder::BinaryDecoder;
use bzip2_decoder::Bzip2Decoder;
use decimal_decoder::DecimalDecoder;
use dna_codon_decoder::DnaCodonDecoder;
use dtmf_decoder::DtmfDecoder;
use hexadecimal_decoder::HexadecimalDecoder;
use hexdump_decoder::HexdumpDecoder;
use html_entity_decoder::HtmlEntityDecoder;
use interface::{Crack, Decoder};

use a1z26_decoder::A1Z26Decoder;
use aaencode_decoder::AAEncodeDecoder;
use affine_decoder::AffineDecoder;
use ascii_shift_decoder::AsciiShiftDecoder;
use base100_decoder::Base100Decoder;
use base64_alt_decoder::Base64AltDecoder;
use base64_decoder::Base64Decoder;
use base65536_decoder::Base65536Decoder;
use base85_decoder::Base85Decoder;
use base91_decoder::Base91Decoder;
use base92_decoder::Base92Decoder;
use braille_decoder::BrailleDecoder;
use caesar_decoder::CaesarDecoder;
use citrix_ctx1_decoder::CitrixCTX1Decoder;
use core_socialist_values_decoder::CoreSocialistValuesDecoder;
use gzip_decoder::GzipDecoder;
use hill_decoder::HillDecoder;
use jsfuck_decoder::JsFuckDecoder;
use jwt_decoder::JwtDecoder;
use keyboard_layout_decoder::KeyboardLayoutDecoder;
use keyboard_shift_decoder::KeyboardShiftDecoder;
use leetspeak_decoder::LeetspeakDecoder;
use mime_encoded_word_decoder::MimeEncodedWordDecoder;
use monoalphabetic_substitution_decoder::MonoalphabeticSubstitutionDecoder;
use morse_code::MorseCodeDecoder;
use multi_tap_decoder::MultiTapDecoder;
use nato_phonetic_decoder::NatoPhoneticDecoder;
use null_cipher_decoder::NullCipherDecoder;
use octal_decoder::OctalDecoder;
use ook_decoder::OokDecoder;
use playfair_decoder::PlayfairDecoder;
use polybius_decoder::PolybiusDecoder;
use punycode_decoder::PunycodeDecoder;
use quoted_printable_decoder::QuotedPrintableDecoder;
use railfence_decoder::RailfenceDecoder;
use raw_deflate_decoder::RawDeflateDecoder;
use reverse_decoder::ReverseDecoder;
use rot18_decoder::Rot18Decoder;
use rot47_decoder::ROT47Decoder;
use route_transposition_decoder::RouteTranspositionDecoder;
use standard_galactic_alphabet_decoder::StandardGalacticAlphabetDecoder;
use substitution_generic_decoder::SubstitutionGenericDecoder;
use t9_decoder::T9Decoder;
use tap_code_decoder::TapCodeDecoder;
use unicode_escape_decoder::UnicodeEscapeDecoder;
use unicode_fancy_text_decoder::UnicodeFancyTextDecoder;
use url_decoder::URLDecoder;
use utf16_decoder::Utf16Decoder;
use uuencode_decoder::UuencodeDecoder;
use vigenere_autokey_decoder::VigenereAutokeyDecoder;
use vigenere_decoder::VigenereDecoder;
use xor_repeating_key_decoder::XorRepeatingKeyDecoder;
use xor_single_byte_decoder::XorSingleByteDecoder;
use xz_decoder::XzDecoder;
use yunying_decoder::YunyingDecoder;
use z85_decoder::Z85Decoder;
use zero_width_decoder::ZeroWidthDecoder;
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
    /// 01248 (Yunying) decoder
    YunyingDecoder(yunying_decoder::YunyingDecoder),
    /// AAEncode decoder
    AAEncodeDecoder(aaencode_decoder::AAEncodeDecoder),
    /// ascii85 decoder
    Ascii85Decoder(ascii85_decoder::Ascii85Decoder),
    /// affine decoder
    AffineDecoder(affine_decoder::AffineDecoder),
    /// atbash decoder
    AtbashDecoder(atbash_decoder::AtbashDecoder),
    /// baconian decoder
    BaconianDecoder(baconian_decoder::BaconianDecoder),
    /// baudot (ITA2) decoder
    BaudotDecoder(baudot_decoder::BaudotDecoder),
    /// Beaufort cracker
    BeaufortDecoder(beaufort_decoder::BeaufortDecoder),
    /// Polybius square decoder
    PolybiusDecoder(polybius_decoder::PolybiusDecoder),
    /// Playfair cracker
    PlayfairDecoder(playfair_decoder::PlayfairDecoder),
    /// base32 decoder
    Base32Decoder(base32_decoder::Base32Decoder),
    /// base36 decoder
    Base36Decoder(base36_decoder::Base36Decoder),
    /// base58 bitcoin decoder
    Base58BitcoinDecoder(base58_bitcoin_decoder::Base58BitcoinDecoder),
    /// base58 monero decoder
    Base58MoneroDecoder(base58_monero_decoder::Base58MoneroDecoder),
    /// big integer to bytes decoder
    BigIntegerDecoder(big_integer_decoder::BigIntegerDecoder),
    /// binary decoder
    BinaryDecoder(binary_decoder::BinaryDecoder),
    /// decimal decoder
    DecimalDecoder(decimal_decoder::DecimalDecoder),
    /// DNA codon decoder
    DnaCodonDecoder(dna_codon_decoder::DnaCodonDecoder),
    /// DTMF decoder
    DtmfDecoder(dtmf_decoder::DtmfDecoder),
    /// hexadecimal decoder
    HexadecimalDecoder(hexadecimal_decoder::HexadecimalDecoder),
    /// hexdump decoder
    HexdumpDecoder(hexdump_decoder::HexdumpDecoder),
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
    /// base64 decoder for non-standard alphabets
    Base64AltDecoder(base64_alt_decoder::Base64AltDecoder),
    /// base100 (emoji) decoder
    Base100Decoder(base100_decoder::Base100Decoder),
    /// base65536 decoder
    Base65536Decoder(base65536_decoder::Base65536Decoder),
    /// base85 (RFC 1924) decoder
    Base85Decoder(base85_decoder::Base85Decoder),
    /// base91 decoder
    Base91Decoder(base91_decoder::Base91Decoder),
    /// base92 decoder
    Base92Decoder(base92_decoder::Base92Decoder),
    /// citrix ctx1 decoder
    CitrixCtx1Decoder(citrix_ctx1_decoder::CitrixCTX1Decoder),
    /// core socialist values decoder
    CoreSocialistValuesDecoder(core_socialist_values_decoder::CoreSocialistValuesDecoder),
    /// jwt decoder
    JwtDecoder(jwt_decoder::JwtDecoder),
    /// keyboard layout decoder
    KeyboardLayoutDecoder(keyboard_layout_decoder::KeyboardLayoutDecoder),
    /// keyboard shift cracker
    KeyboardShiftDecoder(keyboard_shift_decoder::KeyboardShiftDecoder),
    /// leetspeak decoder
    LeetspeakDecoder(leetspeak_decoder::LeetspeakDecoder),
    /// gzip decoder
    GzipDecoder(gzip_decoder::GzipDecoder),
    /// bzip2 decoder
    Bzip2Decoder(bzip2_decoder::Bzip2Decoder),
    /// xz and lzma-alone decoder
    XzDecoder(xz_decoder::XzDecoder),
    /// Hill cipher cracker
    HillDecoder(hill_decoder::HillDecoder),
    /// url decoder
    UrlDecoder(url_decoder::URLDecoder),
    /// punycode decoder
    PunycodeDecoder(punycode_decoder::PunycodeDecoder),
    /// unicode escape decoder
    UnicodeEscapeDecoder(unicode_escape_decoder::UnicodeEscapeDecoder),
    /// unicode fancy text decoder
    UnicodeFancyTextDecoder(unicode_fancy_text_decoder::UnicodeFancyTextDecoder),
    /// backslash escape decoder
    BackslashEscapeDecoder(backslash_escape_decoder::BackslashEscapeDecoder),
    /// quoted-printable decoder
    QuotedPrintableDecoder(quoted_printable_decoder::QuotedPrintableDecoder),
    /// MIME encoded-word decoder
    MimeEncodedWordDecoder(mime_encoded_word_decoder::MimeEncodedWordDecoder),
    /// UTF-16 decoder
    Utf16Decoder(utf16_decoder::Utf16Decoder),
    /// uuencode decoder
    UuencodeDecoder(uuencode_decoder::UuencodeDecoder),
    /// reverse decoder
    ReverseDecoder(reverse_decoder::ReverseDecoder),
    /// morse decoder
    MorseCode(morse_code::MorseCodeDecoder),
    /// multi-tap decoder
    MultiTapDecoder(multi_tap_decoder::MultiTapDecoder),
    /// tap code decoder
    TapCodeDecoder(tap_code_decoder::TapCodeDecoder),
    /// NATO phonetic alphabet decoder
    NatoPhoneticDecoder(nato_phonetic_decoder::NatoPhoneticDecoder),
    /// caesar decoder
    CaesarDecoder(caesar_decoder::CaesarDecoder),
    /// railfence decoder
    RailfenceDecoder(railfence_decoder::RailfenceDecoder),
    /// ROT5 / ROT18 decoder
    Rot18Decoder(rot18_decoder::Rot18Decoder),
    /// rot47 decoder
    Rot47Decoder(rot47_decoder::ROT47Decoder),
    /// route transposition cracker
    RouteTranspositionDecoder(route_transposition_decoder::RouteTranspositionDecoder),
    /// ASCII shift cracker
    AsciiShiftDecoder(ascii_shift_decoder::AsciiShiftDecoder),
    /// z85 decoder
    Z85Decoder(z85_decoder::Z85Decoder),
    /// zero-width steganography decoder
    ZeroWidthDecoder(zero_width_decoder::ZeroWidthDecoder),
    /// braille decoder
    BrailleDecoder(braille_decoder::BrailleDecoder),
    /// standard galactic alphabet decoder
    StandardGalacticAlphabetDecoder(
        standard_galactic_alphabet_decoder::StandardGalacticAlphabetDecoder,
    ),
    /// substitution decoder
    SubstitutionGenericDecoder(substitution_generic_decoder::SubstitutionGenericDecoder),
    /// brainfuck interpreter
    BrainfuckInterpreter(brainfuck_interpreter::BrainfuckInterpreter),
    /// Ook! interpreter
    OokDecoder(ook_decoder::OokDecoder),
    /// JSFuck decoder
    JsFuckDecoder(jsfuck_decoder::JsFuckDecoder),
    /// vigenere decoder
    VigenereDecoder(vigenere_decoder::VigenereDecoder),
    /// vigenere autokey cracker
    VigenereAutokeyDecoder(vigenere_autokey_decoder::VigenereAutokeyDecoder),
    /// zlib decoder
    ZlibDecoder(zlib_decoder::ZlibDecoder),
    /// raw DEFLATE decoder
    RawDeflateDecoder(raw_deflate_decoder::RawDeflateDecoder),
    /// single-byte xor cracker
    XorSingleByteDecoder(xor_single_byte_decoder::XorSingleByteDecoder),
    /// repeating-key XOR cracker
    XorRepeatingKeyDecoder(xor_repeating_key_decoder::XorRepeatingKeyDecoder),
    /// monoalphabetic substitution cracker
    MonoalphabeticSubstitutionDecoder(
        monoalphabetic_substitution_decoder::MonoalphabeticSubstitutionDecoder,
    ),
    /// T9 predictive text decoder
    T9Decoder(t9_decoder::T9Decoder),
    /// null cipher (acrostic) decoder
    NullCipherDecoder(null_cipher_decoder::NullCipherDecoder),
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
        (
            "Vigenere Autokey",
            DecoderBox::new(Decoder::<VigenereAutokeyDecoder>::new()),
        ),
        (
            "Beaufort",
            DecoderBox::new(Decoder::<BeaufortDecoder>::new()),
        ),
        (
            "Repeating-key XOR",
            DecoderBox::new(Decoder::<XorRepeatingKeyDecoder>::new()),
        ),
        ("Binary", DecoderBox::new(Decoder::<BinaryDecoder>::new())),
        ("Decimal", DecoderBox::new(Decoder::<DecimalDecoder>::new())),
        ("DTMF", DecoderBox::new(Decoder::<DtmfDecoder>::new())),
        (
            "Big integer to bytes",
            DecoderBox::new(Decoder::<BigIntegerDecoder>::new()),
        ),
        (
            "DNA Codon",
            DecoderBox::new(Decoder::<DnaCodonDecoder>::new()),
        ),
        (
            "Hexadecimal",
            DecoderBox::new(Decoder::<HexadecimalDecoder>::new()),
        ),
        ("Hexdump", DecoderBox::new(Decoder::<HexdumpDecoder>::new())),
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
        (
            "Base64 Alt",
            DecoderBox::new(Decoder::<Base64AltDecoder>::new()),
        ),
        ("Base85", DecoderBox::new(Decoder::<Base85Decoder>::new())),
        ("Base91", DecoderBox::new(Decoder::<Base91Decoder>::new())),
        ("Base92", DecoderBox::new(Decoder::<Base92Decoder>::new())),
        ("Base100", DecoderBox::new(Decoder::<Base100Decoder>::new())),
        (
            "Base65536",
            DecoderBox::new(Decoder::<Base65536Decoder>::new()),
        ),
        (
            "Citrix Ctx1",
            DecoderBox::new(Decoder::<CitrixCTX1Decoder>::new()),
        ),
        (
            "Core Socialist Values",
            DecoderBox::new(Decoder::<CoreSocialistValuesDecoder>::new()),
        ),
        ("JWT", DecoderBox::new(Decoder::<JwtDecoder>::new())),
        (
            "Leetspeak",
            DecoderBox::new(Decoder::<LeetspeakDecoder>::new()),
        ),
        ("Gzip", DecoderBox::new(Decoder::<GzipDecoder>::new())),
        ("Bzip2", DecoderBox::new(Decoder::<Bzip2Decoder>::new())),
        ("XZ", DecoderBox::new(Decoder::<XzDecoder>::new())),
        ("URL", DecoderBox::new(Decoder::<URLDecoder>::new())),
        (
            "Punycode",
            DecoderBox::new(Decoder::<PunycodeDecoder>::new()),
        ),
        (
            "Unicode Escapes",
            DecoderBox::new(Decoder::<UnicodeEscapeDecoder>::new()),
        ),
        (
            "Unicode Fancy Text",
            DecoderBox::new(Decoder::<UnicodeFancyTextDecoder>::new()),
        ),
        (
            "Backslash Escapes",
            DecoderBox::new(Decoder::<BackslashEscapeDecoder>::new()),
        ),
        (
            "Quoted-Printable",
            DecoderBox::new(Decoder::<QuotedPrintableDecoder>::new()),
        ),
        (
            "MIME Encoded-Word",
            DecoderBox::new(Decoder::<MimeEncodedWordDecoder>::new()),
        ),
        ("UTF-16", DecoderBox::new(Decoder::<Utf16Decoder>::new())),
        ("Base32", DecoderBox::new(Decoder::<Base32Decoder>::new())),
        ("Base36", DecoderBox::new(Decoder::<Base36Decoder>::new())),
        (
            "Uuencode",
            DecoderBox::new(Decoder::<UuencodeDecoder>::new()),
        ),
        ("Reverse", DecoderBox::new(Decoder::<ReverseDecoder>::new())),
        (
            "Morse Code",
            DecoderBox::new(Decoder::<MorseCodeDecoder>::new()),
        ),
        (
            "Multi-tap",
            DecoderBox::new(Decoder::<MultiTapDecoder>::new()),
        ),
        (
            "Tap Code",
            DecoderBox::new(Decoder::<TapCodeDecoder>::new()),
        ),
        (
            "NATO Phonetic Alphabet",
            DecoderBox::new(Decoder::<NatoPhoneticDecoder>::new()),
        ),
        ("atbash", DecoderBox::new(Decoder::<AtbashDecoder>::new())),
        (
            "Baconian",
            DecoderBox::new(Decoder::<BaconianDecoder>::new()),
        ),
        ("Baudot", DecoderBox::new(Decoder::<BaudotDecoder>::new())),
        (
            "Polybius Square",
            DecoderBox::new(Decoder::<PolybiusDecoder>::new()),
        ),
        (
            "Playfair",
            DecoderBox::new(Decoder::<PlayfairDecoder>::new()),
        ),
        ("caesar", DecoderBox::new(Decoder::<CaesarDecoder>::new())),
        ("Affine", DecoderBox::new(Decoder::<AffineDecoder>::new())),
        ("Hill", DecoderBox::new(Decoder::<HillDecoder>::new())),
        (
            "railfence",
            DecoderBox::new(Decoder::<RailfenceDecoder>::new()),
        ),
        ("rot18", DecoderBox::new(Decoder::<Rot18Decoder>::new())),
        ("rot47", DecoderBox::new(Decoder::<ROT47Decoder>::new())),
        (
            "Route Transposition",
            DecoderBox::new(Decoder::<RouteTranspositionDecoder>::new()),
        ),
        (
            "ASCII shift",
            DecoderBox::new(Decoder::<AsciiShiftDecoder>::new()),
        ),
        ("Z85", DecoderBox::new(Decoder::<Z85Decoder>::new())),
        (
            "Zero-width",
            DecoderBox::new(Decoder::<ZeroWidthDecoder>::new()),
        ),
        ("Ascii85", DecoderBox::new(Decoder::<Ascii85Decoder>::new())),
        ("a1z26", DecoderBox::new(Decoder::<A1Z26Decoder>::new())),
        (
            "01248 (Yunying)",
            DecoderBox::new(Decoder::<YunyingDecoder>::new()),
        ),
        ("Braille", DecoderBox::new(Decoder::<BrailleDecoder>::new())),
        (
            "Standard Galactic Alphabet",
            DecoderBox::new(Decoder::<StandardGalacticAlphabetDecoder>::new()),
        ),
        (
            "simplesubstitution",
            DecoderBox::new(Decoder::<SubstitutionGenericDecoder>::new()),
        ),
        (
            "Brainfuck",
            DecoderBox::new(Decoder::<BrainfuckInterpreter>::new()),
        ),
        ("Ook!", DecoderBox::new(Decoder::<OokDecoder>::new())),
        (
            "AAEncode",
            DecoderBox::new(Decoder::<AAEncodeDecoder>::new()),
        ),
        ("JSFuck", DecoderBox::new(Decoder::<JsFuckDecoder>::new())),
        ("Zlib", DecoderBox::new(Decoder::<ZlibDecoder>::new())),
        (
            "Raw DEFLATE",
            DecoderBox::new(Decoder::<RawDeflateDecoder>::new()),
        ),
        (
            "Single-byte XOR",
            DecoderBox::new(Decoder::<XorSingleByteDecoder>::new()),
        ),
        (
            "Monoalphabetic Substitution",
            DecoderBox::new(Decoder::<MonoalphabeticSubstitutionDecoder>::new()),
        ),
        ("T9", DecoderBox::new(Decoder::<T9Decoder>::new())),
        (
            "Keyboard shift",
            DecoderBox::new(Decoder::<KeyboardShiftDecoder>::new()),
        ),
        (
            "Keyboard layout",
            DecoderBox::new(Decoder::<KeyboardLayoutDecoder>::new()),
        ),
        (
            "Null cipher",
            DecoderBox::new(Decoder::<NullCipherDecoder>::new()),
        ),
    ])
});
