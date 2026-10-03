//! Proposal: <https://broadleaf-angora-7db.notion.site/Filtration-System-7143b36a42f1466faea3077bfc7e859e>
//! Given a filter object, return an array of decoders/crackers which have been filtered

use std::sync::mpsc::channel;

use crate::checkers::CheckerTypes;
use crate::cli_pretty_printing;
use crate::decoders::ascii85_decoder::Ascii85Decoder;
use crate::decoders::ascii_shift_decoder::AsciiShiftDecoder;
use crate::decoders::atbash_decoder::AtbashDecoder;
use crate::decoders::backslash_escape_decoder::BackslashEscapeDecoder;
use crate::decoders::baconian_decoder::BaconianDecoder;
use crate::decoders::base32_decoder::Base32Decoder;
use crate::decoders::base36_decoder::Base36Decoder;
use crate::decoders::base58_bitcoin_decoder::Base58BitcoinDecoder;
use crate::decoders::base58_monero_decoder::Base58MoneroDecoder;
use crate::decoders::baudot_decoder::BaudotDecoder;
use crate::decoders::beaufort_decoder::BeaufortDecoder;
use crate::decoders::big_integer_decoder::BigIntegerDecoder;
use crate::decoders::binary_decoder::BinaryDecoder;
use crate::decoders::bzip2_decoder::Bzip2Decoder;
use crate::decoders::decimal_decoder::DecimalDecoder;
use crate::decoders::dna_codon_decoder::DnaCodonDecoder;
use crate::decoders::dtmf_decoder::DtmfDecoder;
use crate::decoders::hexadecimal_decoder::HexadecimalDecoder;
use crate::decoders::hexdump_decoder::HexdumpDecoder;
use crate::decoders::html_entity_decoder::HtmlEntityDecoder;
use crate::decoders::octal_decoder::OctalDecoder;
use crate::decoders::ook_decoder::OokDecoder;
use crate::decoders::playfair_decoder::PlayfairDecoder;
use crate::decoders::polybius_decoder::PolybiusDecoder;
use crate::DecoderResult;

use crate::decoders::base58_flickr_decoder::Base58FlickrDecoder;
use crate::decoders::base58_ripple_decoder::Base58RippleDecoder;

use crate::decoders::a1z26_decoder::A1Z26Decoder;
use crate::decoders::aaencode_decoder::AAEncodeDecoder;
use crate::decoders::affine_decoder::AffineDecoder;
use crate::decoders::base100_decoder::Base100Decoder;
use crate::decoders::base64_alt_decoder::Base64AltDecoder;
use crate::decoders::base64_decoder::Base64Decoder;
use crate::decoders::base65536_decoder::Base65536Decoder;
use crate::decoders::base85_decoder::Base85Decoder;
use crate::decoders::base91_decoder::Base91Decoder;
use crate::decoders::base92_decoder::Base92Decoder;
use crate::decoders::braille_decoder::BrailleDecoder;
use crate::decoders::caesar_decoder::CaesarDecoder;
use crate::decoders::citrix_ctx1_decoder::CitrixCTX1Decoder;
use crate::decoders::core_socialist_values_decoder::CoreSocialistValuesDecoder;
use crate::decoders::crack_results::CrackResult;
use crate::decoders::gzip_decoder::GzipDecoder;
use crate::decoders::hill_decoder::HillDecoder;
use crate::decoders::interface::{Crack, Decoder};
use crate::decoders::jsfuck_decoder::JsFuckDecoder;
use crate::decoders::jwt_decoder::JwtDecoder;
use crate::decoders::keyboard_layout_decoder::KeyboardLayoutDecoder;
use crate::decoders::keyboard_shift_decoder::KeyboardShiftDecoder;
use crate::decoders::leetspeak_decoder::LeetspeakDecoder;
use crate::decoders::mime_encoded_word_decoder::MimeEncodedWordDecoder;
use crate::decoders::monoalphabetic_substitution_decoder::MonoalphabeticSubstitutionDecoder;
use crate::decoders::morse_code::MorseCodeDecoder;
use crate::decoders::multi_tap_decoder::MultiTapDecoder;
use crate::decoders::nato_phonetic_decoder::NatoPhoneticDecoder;
use crate::decoders::null_cipher_decoder::NullCipherDecoder;
use crate::decoders::punycode_decoder::PunycodeDecoder;
use crate::decoders::quoted_printable_decoder::QuotedPrintableDecoder;
use crate::decoders::railfence_decoder::RailfenceDecoder;
use crate::decoders::raw_deflate_decoder::RawDeflateDecoder;
use crate::decoders::reverse_decoder::ReverseDecoder;
use crate::decoders::rot47_decoder::ROT47Decoder;
use crate::decoders::route_transposition_decoder::RouteTranspositionDecoder;
use crate::decoders::standard_galactic_alphabet_decoder::StandardGalacticAlphabetDecoder;
use crate::decoders::substitution_generic_decoder::SubstitutionGenericDecoder;
use crate::decoders::t9_decoder::T9Decoder;
use crate::decoders::tap_code_decoder::TapCodeDecoder;
use crate::decoders::unicode_escape_decoder::UnicodeEscapeDecoder;
use crate::decoders::unicode_fancy_text_decoder::UnicodeFancyTextDecoder;
use crate::decoders::url_decoder::URLDecoder;
use crate::decoders::utf16_decoder::Utf16Decoder;
use crate::decoders::uuencode_decoder::UuencodeDecoder;
use crate::decoders::vigenere_autokey_decoder::VigenereAutokeyDecoder;
use crate::decoders::vigenere_decoder::VigenereDecoder;
use crate::decoders::xor_repeating_key_decoder::XorRepeatingKeyDecoder;
use crate::decoders::xor_single_byte_decoder::XorSingleByteDecoder;
use crate::decoders::xz_decoder::XzDecoder;
use crate::decoders::yunying_decoder::YunyingDecoder;
use crate::decoders::z85_decoder::Z85Decoder;
use crate::decoders::zero_width_decoder::ZeroWidthDecoder;
use crate::decoders::zlib_decoder::ZlibDecoder;

use crate::decoders::brainfuck_interpreter::BrainfuckInterpreter;

use log::trace;
use rayon::prelude::*;

/// The struct which contains all of the decoders
/// Where decoders is crackers, decryptors, etc.
/// This contains a public attribute Components
/// Which contains all of them. See `pub fn run` which is impl'd on
/// the Decoders for the Crack trait in action.
/// Relevant docs: https://doc.rust-lang.org/book/ch17-02-trait-objects.html
pub struct Decoders {
    /// Components is a vector of decoders.
    pub components: Vec<Box<dyn Crack + Sync>>,
}

impl Decoders {
    /// Iterate over all of the decoders and run .crack(text) on them
    /// Then if the checker succeed, we short-circuit the iterator
    /// and stop all processing as soon as possible.
    /// We are using Trait Objects
    /// https://doc.rust-lang.org/book/ch17-02-trait-objects.html
    /// Which allows us to have multiple different structs in the same vector
    /// But each struct shciphey the same `.crack()` method, so it's fine.
    pub fn run(&self, text: &str, checker: CheckerTypes) -> MyResults {
        trace!("Running .crack() on all decoders");
        let (sender, receiver) = channel();
        self.components
            .into_par_iter()
            .try_for_each_with(sender, |s, i| {
                let results = i.crack(text, &checker);
                if results.success {
                    cli_pretty_printing::success(&format!(
                        "DEBUG: filtration_system - Decoder {} succeeded, short-circuiting",
                        results.decoder
                    ));
                    s.send(results.clone()).expect("expected no send error!");
                    // returning None short-circuits the iterator
                    // we don't process any further as we got success
                    return None;
                }
                cli_pretty_printing::success(&format!(
                    "DEBUG: filtration_system - Decoder {} failed, continuing",
                    results.decoder
                ));
                s.send(results.clone()).expect("expected no send error!");
                // return Some(()) to indicate that continue processing
                Some(())
            });

        let mut all_results: Vec<CrackResult> = Vec::new();

        while let Ok(result) = receiver.recv() {
            // if we recv success, break.
            if result.success {
                cli_pretty_printing::success(&format!("DEBUG: filtration_system - Received successful result from {}, returning Break", result.decoder));
                return MyResults::Break(result);
            }
            all_results.push(result)
        }

        cli_pretty_printing::success(&format!(
            "DEBUG: filtration_system - No successful results, returning Continue with {} results",
            all_results.len()
        ));
        MyResults::Continue(all_results)
    }
}

/// [`Enum`] for our custom results.
/// if our checker succeed, we return `Break` variant containing [`CrackResult`]
/// else we return `Continue` with the decoded results.
pub enum MyResults {
    /// Variant containing successful [`CrackResult`]
    Break(CrackResult),
    /// Contains [`Vec`] of [`CrackResult`] for further processing
    Continue(Vec<CrackResult>),
}

impl MyResults {
    /// named with _ to pass dead_code warning
    /// as we aren't using it, it's just used in tests
    pub fn _break_value(self) -> Option<CrackResult> {
        match self {
            MyResults::Break(val) => Some(val),
            MyResults::Continue(_) => None,
        }
    }
}

/// Filter struct for decoder filtering
pub struct DecoderFilter {
    /// Tags to include in the filter - decoders must have at least one of these tags
    include_tags: Vec<String>,
    /// Tags to exclude from the filter - decoders must not have any of these tags
    exclude_tags: Vec<String>,
}

impl DecoderFilter {
    /// Create a new empty filter
    pub fn new() -> Self {
        DecoderFilter {
            include_tags: Vec::new(),
            exclude_tags: Vec::new(),
        }
    }

    /// Add a tag to include
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn include_tag(mut self, tag: &str) -> Self {
        self.include_tags.push(tag.to_string());
        self
    }

    /// Add a tag to exclude
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn exclude_tag(mut self, tag: &str) -> Self {
        self.exclude_tags.push(tag.to_string());
        self
    }

    /// Check if a decoder matches the filter
    #[allow(clippy::borrowed_box)]
    pub fn matches(&self, decoder: &Box<dyn Crack + Sync>) -> bool {
        let tags = decoder.get_tags();

        // If include_tags is not empty, at least one tag must match
        if !self.include_tags.is_empty() {
            let has_included_tag = self
                .include_tags
                .iter()
                .any(|include_tag| tags.iter().any(|tag| *tag == include_tag));

            if !has_included_tag {
                return false;
            }
        }

        // If exclude_tags is not empty, no tag must match
        if !self.exclude_tags.is_empty() {
            let has_excluded_tag = self
                .exclude_tags
                .iter()
                .any(|exclude_tag| tags.iter().any(|tag| *tag == exclude_tag));

            if has_excluded_tag {
                return false;
            }
        }

        true
    }
}

/// Get decoders with the "decoder" tag
#[cfg_attr(not(test), allow(dead_code))]
pub fn get_decoder_tagged_decoders(text_struct: &DecoderResult) -> Decoders {
    trace!("Getting decoder-tagged decoders");
    let filter = DecoderFilter::new().include_tag("decoder");
    filter_decoders_by_tags(text_struct, &filter)
}

/// Get decoders without the "decoder" tag
#[cfg_attr(not(test), allow(dead_code))]
pub fn get_non_decoder_tagged_decoders(text_struct: &DecoderResult) -> Decoders {
    trace!("Getting non-decoder-tagged decoders");
    let filter = DecoderFilter::new().exclude_tag("decoder");
    filter_decoders_by_tags(text_struct, &filter)
}

/// Filter decoders based on custom tags
pub fn filter_decoders_by_tags(_text_struct: &DecoderResult, filter: &DecoderFilter) -> Decoders {
    trace!("Filtering decoders by tags");

    // Get all decoders
    let all_decoders = get_all_decoders();

    // Filter decoders based on tags
    let filtered_components = all_decoders
        .components
        .into_iter()
        .filter(|decoder| filter.matches(decoder))
        .collect();

    Decoders {
        components: filtered_components,
    }
}

/// Get all available decoders
pub fn get_all_decoders() -> Decoders {
    trace!("Getting all decoders");
    filter_and_get_decoders(&DecoderResult::default())
}

/// Currently takes no args as this is just a spike to get all the basic functionality working
pub fn filter_and_get_decoders(_text_struct: &DecoderResult) -> Decoders {
    trace!("Filtering and getting all decoders");
    let jwt = Decoder::<JwtDecoder>::new();
    let zero_width = Decoder::<ZeroWidthDecoder>::new();
    let leetspeak = Decoder::<LeetspeakDecoder>::new();
    let ook = Decoder::<OokDecoder>::new();
    let jsfuck = Decoder::<JsFuckDecoder>::new();
    let hill = Decoder::<HillDecoder>::new();
    let route_transposition = Decoder::<RouteTranspositionDecoder>::new();
    let playfair = Decoder::<PlayfairDecoder>::new();
    let vigenere_autokey = Decoder::<VigenereAutokeyDecoder>::new();
    let beaufort = Decoder::<BeaufortDecoder>::new();
    let vigenere = Decoder::<VigenereDecoder>::new();
    let xor_repeating_key = Decoder::<XorRepeatingKeyDecoder>::new();
    let binary = Decoder::<BinaryDecoder>::new();
    let decimal = Decoder::<DecimalDecoder>::new();
    let multi_tap = Decoder::<MultiTapDecoder>::new();
    let big_integer = Decoder::<BigIntegerDecoder>::new();
    let dtmf = Decoder::<DtmfDecoder>::new();
    let dna_codon = Decoder::<DnaCodonDecoder>::new();
    let t9 = Decoder::<T9Decoder>::new();
    let hexadecimal = Decoder::<HexadecimalDecoder>::new();
    let hexdump = Decoder::<HexdumpDecoder>::new();
    let octal = Decoder::<OctalDecoder>::new();
    let html_entity = Decoder::<HtmlEntityDecoder>::new();
    let base58_bitcoin = Decoder::<Base58BitcoinDecoder>::new();
    let base58_monero = Decoder::<Base58MoneroDecoder>::new();
    let base58_ripple = Decoder::<Base58RippleDecoder>::new();
    let base58_flickr = Decoder::<Base58FlickrDecoder>::new();
    let base64 = Decoder::<Base64Decoder>::new();
    let base64_alt = Decoder::<Base64AltDecoder>::new();
    let base85 = Decoder::<Base85Decoder>::new();
    let base91 = Decoder::<Base91Decoder>::new();
    let base92 = Decoder::<Base92Decoder>::new();
    let core_socialist_values = Decoder::<CoreSocialistValuesDecoder>::new();
    let base65536 = Decoder::<Base65536Decoder>::new();
    let base100 = Decoder::<Base100Decoder>::new();
    let citrix_ctx1 = Decoder::<CitrixCTX1Decoder>::new();
    let url = Decoder::<URLDecoder>::new();
    let punycode = Decoder::<PunycodeDecoder>::new();
    let unicode_escape = Decoder::<UnicodeEscapeDecoder>::new();
    let unicode_fancy_text = Decoder::<UnicodeFancyTextDecoder>::new();
    let backslash_escape = Decoder::<BackslashEscapeDecoder>::new();
    let quoted_printable = Decoder::<QuotedPrintableDecoder>::new();
    let mime_encoded_word = Decoder::<MimeEncodedWordDecoder>::new();
    let utf16 = Decoder::<Utf16Decoder>::new();
    let base32 = Decoder::<Base32Decoder>::new();
    let base36 = Decoder::<Base36Decoder>::new();
    let uuencode = Decoder::<UuencodeDecoder>::new();
    let reversedecoder = Decoder::<ReverseDecoder>::new();
    let morsecodedecoder = Decoder::<MorseCodeDecoder>::new();
    let tap_code = Decoder::<TapCodeDecoder>::new();
    let nato_phonetic = Decoder::<NatoPhoneticDecoder>::new();
    let atbashdecoder = Decoder::<AtbashDecoder>::new();
    let baconian = Decoder::<BaconianDecoder>::new();
    let baudot = Decoder::<BaudotDecoder>::new();
    let polybius = Decoder::<PolybiusDecoder>::new();
    let caesardecoder = Decoder::<CaesarDecoder>::new();
    let affine = Decoder::<AffineDecoder>::new();
    let railfencedecoder = Decoder::<RailfenceDecoder>::new();
    let rot47decoder = Decoder::<ROT47Decoder>::new();
    let ascii_shift = Decoder::<AsciiShiftDecoder>::new();
    let z85 = Decoder::<Z85Decoder>::new();
    let ascii85 = Decoder::<Ascii85Decoder>::new();
    let a1z26decoder = Decoder::<A1Z26Decoder>::new();
    let yunying = Decoder::<YunyingDecoder>::new();
    let brailledecoder = Decoder::<BrailleDecoder>::new();
    let standard_galactic_alphabet = Decoder::<StandardGalacticAlphabetDecoder>::new();
    let substitution_generic = Decoder::<SubstitutionGenericDecoder>::new();
    let zlib = Decoder::<ZlibDecoder>::new();
    let raw_deflate = Decoder::<RawDeflateDecoder>::new();
    let gzip = Decoder::<GzipDecoder>::new();
    let bzip2 = Decoder::<Bzip2Decoder>::new();
    let xz = Decoder::<XzDecoder>::new();

    let brainfuck = Decoder::<BrainfuckInterpreter>::new();
    let aaencode = Decoder::<AAEncodeDecoder>::new();
    let xor_single_byte = Decoder::<XorSingleByteDecoder>::new();
    let monoalphabetic_substitution = Decoder::<MonoalphabeticSubstitutionDecoder>::new();
    let keyboard_layout = Decoder::<KeyboardLayoutDecoder>::new();
    let keyboard_shift = Decoder::<KeyboardShiftDecoder>::new();
    let null_cipher = Decoder::<NullCipherDecoder>::new();

    Decoders {
        components: vec![
            // First: the search ranks results found in the same step by checker class and
            // path cost, then keeps this order. Railfence rearranges a JWT into strings the
            // LemmeKnow checker takes for URLs, which must not beat the decoded JWT.
            Box::new(jwt),
            // Before every decoder that reads the cover text around a hidden message
            // (Vigenere, Reverse, the classical ciphers, simplesubstitution): when two find
            // plaintext in the same step, the search reports the one listed first.
            Box::new(zero_width),
            // Before Vigenere, which turns codon inputs into English-looking junk (`AOT HBR
            // JKR ...`). The search ranks the codon plaintext first anyway, since it passes
            // the strict English check and the junk doesn't; this order only settles a tie.
            Box::new(dna_codon),
            // Before Vigenere: results found in the same step tie on checker class and
            // cost and keep this order, and Vigenere keys can turn the letters of leet
            // text into something the English checker accepts. Leetspeak only answers when
            // most of its words are dictionary words.
            Box::new(leetspeak),
            // Before Vigenere and simplesubstitution, which can turn an Ook! program into
            // text the English checker accepts, in the same step as this runs it: on a tie
            // the first in this list is reported.
            Box::new(ook),
            // Before the classical ciphers: when two decoders find plaintext in the same
            // step, the search reports the one listed first. Its first check rejects text
            // that isn't JSFuck at the first byte, so running early costs nothing.
            Box::new(jsfuck),
            // Before Vigenere: a Hill plaintext and a Vigenère false positive found in the
            // same step tie on checker class and cost, and the first in this list wins.
            // Vigenère keys turn Hill ciphertexts into English-looking junk
            // (`XTPJPUOUCKEGFCURFTYH` into `STNINTETNFEEEATHEETH`), while Hill hands the
            // checker nothing on Vigenère ciphertexts. Before Route Transposition, Playfair
            // and Vigenère Autokey for the same reason: Hill turns away their ciphertexts
            // before its key search, or finds no key that reads as English.
            Box::new(hill),
            // Before Vigenere: results found in the same step tie on checker class and
            // cost and keep this order, and Vigenere keys turn an unspaced transposition
            // into English-looking junk that the English checker accepts. Route
            // Transposition only shows the checker readings that score as English.
            Box::new(route_transposition),
            // Before Vigenere, which turns Playfair ciphertext into English-looking junk
            // (`ALEETHLVMZRFEARETHNNGUINHE` for the Wikipedia example) that the English
            // checker accepts. An unspaced Playfair plaintext and the junk tie on checker
            // class and cost when both are found in the same step, and the first in this
            // list is reported.
            Box::new(playfair),
            // Before Vigenere: on unspaced text both can return an English hit at Medium
            // sensitivity from the same step, which ties on checker class and cost and
            // keeps this order, and Vigenere keys can turn an autokey ciphertext into text
            // the English checker accepts.
            Box::new(vigenere_autokey),
            // Before Vigenere: on text without spaces both can find plaintext the Medium
            // English check accepts in the same step, where they tie on checker class and
            // cost and keep this order. Vigenere turns a Beaufort ciphertext into junk that
            // check can accept; Beaufort only answers with a key whose decryption reads as
            // English quadgrams.
            Box::new(beaufort),
            Box::new(vigenere),
            Box::new(xor_repeating_key),
            Box::new(reversedecoder),
            // Before Base64, and so before railfence and rot47 too: results found in the
            // same step tie on checker class and cost and keep this order. The y64 reading
            // of `aGVsbG8gd29ybGQ-` (`hello world`) has to beat Base64's `hello world>`.
            Box::new(base64_alt),
            Box::new(base64),
            Box::new(base58_bitcoin),
            Box::new(base58_monero),
            Box::new(base58_ripple),
            Box::new(base58_flickr),
            Box::new(base91),
            Box::new(base92),
            Box::new(base85),
            // Before Base65536, whose alphabet has some of the same Han characters and which
            // decodes this encoding to junk: when two decoders find plaintext in the same
            // step, the search reports the one listed first.
            Box::new(core_socialist_values),
            Box::new(base65536),
            // Before rot47, which reads each emoji as its low byte and so turns Base100 of
            // printable ASCII back into the ASCII with a shift of 9
            Box::new(base100),
            Box::new(binary),
            // Before Hexadecimal, which skips the `=` in `=48=65` and decodes it too: when
            // two decoders find the same plaintext the search reports the first one.
            Box::new(quoted_printable),
            Box::new(mime_encoded_word),
            // Before Hexadecimal, which reads a dump's offsets and ASCII column as hex too
            Box::new(hexdump),
            Box::new(hexadecimal),
            Box::new(octal),
            Box::new(html_entity),
            Box::new(base32),
            Box::new(base36),
            Box::new(uuencode),
            // Before rot47: when two decoders find plaintext in the same step the search
            // reports the one listed first, and LemmeKnow takes rot47 of `104,101,108,...`
            // for a Bitcoin Cash address.
            Box::new(decimal),
            // Before rot47 for the same reason: rot47 turns `222-666-3-33` (CODE) into
            // `555099906066`, which LemmeKnow takes for a phone number.
            Box::new(multi_tap),
            // Before rot47 too, which turns digits into `_`, `` ` `` and `a`-`h`. Decimal also
            // reads a run of digits, but where one of the two finds text the other almost
            // never does.
            Box::new(big_integer),
            // With the other number decoders and before the classical ciphers, for the
            // same reason: when several decoders find plaintext in one search batch, the
            // first in this list wins a tie.
            Box::new(dtmf),
            // Before railfence: results found in the same step tie and keep this order, and
            // railfence turns T9's `43556 96753` into `4936575563 `, which LemmeKnow takes
            // for a phone number.
            Box::new(t9),
            // Before the classical ciphers: when several decoders find plaintext in one
            // search batch, the first in this list wins a tie, and rot47 turns Base64
            // into strings LemmeKnow takes for URLs.
            Box::new(xor_single_byte),
            // Before Morse Code, which also reads knocks written with dots (`.. ...` is IS),
            // and rot47, which turns `5,2 1,1 4,4` into words like `XOU TOT WOW`: when both
            // find plaintext in the same step, the first in this list is reported.
            Box::new(tap_code),
            Box::new(morsecodedecoder),
            // Before the classical ciphers too: railfence rearranges `Hotel/Echo/Lima/...`
            // into text the English checker accepts, in the same step as this finds it.
            Box::new(nato_phonetic),
            Box::new(atbashdecoder),
            Box::new(baconian),
            // After Baconian: both read groups of five 0s and 1s, and when two decoders
            // find plaintext in the same step the search reports the one listed first.
            Box::new(baudot),
            // Before rot47, which shifts digits to other digits that LemmeKnow can take for
            // a number it knows, and so can win a tie in the same search step
            Box::new(polybius),
            Box::new(caesardecoder),
            Box::new(affine),
            Box::new(railfencedecoder),
            Box::new(citrix_ctx1),
            Box::new(url),
            Box::new(punycode),
            Box::new(unicode_escape),
            Box::new(backslash_escape),
            Box::new(utf16),
            // Before rot47: when two decoders find plaintext in the same step the search
            // reports the one listed first, and rot47 can shift 01248 digits into strings
            // LemmeKnow takes for Litecoin addresses (the issue example `88421…` becomes
            // `LLHFE…`).
            Box::new(yunying),
            // Before rot47, which reads each character as its low byte and so turns
            // fullwidth, squared and negative circled letters into ASCII too: when two
            // decoders find plaintext in the same step the search reports the one listed
            // first, and rot47 reads `🄷🄴🄻🄻🄾, 🅆🄾🅁🄻🄳!` as `HELLO= WORLD2`.
            Box::new(unicode_fancy_text),
            Box::new(rot47decoder),
            // After rot47 and Caesar: when no byte leaves `!` to `~` and there are no
            // spaces, ASCII shift and rot47 give the same text, and on letters alone it can
            // match a Caesar shift. When two decoders find plaintext in the same step the
            // search reports the one listed first.
            Box::new(ascii_shift),
            Box::new(z85),
            Box::new(ascii85),
            Box::new(a1z26decoder),
            Box::new(brailledecoder),
            Box::new(standard_galactic_alphabet),
            Box::new(substitution_generic),
            Box::new(gzip),
            Box::new(bzip2),
            Box::new(brainfuck),
            Box::new(aaencode),
            Box::new(zlib),
            Box::new(raw_deflate),
            Box::new(xz),
            Box::new(monoalphabetic_substitution),
            Box::new(keyboard_shift),
            Box::new(keyboard_layout),
            // Last: a hidden message is a rarer answer than any other decoder's, so the
            // others win ties within a search batch.
            Box::new(null_cipher),
        ],
    }
}

/// Get a specific decoder by name
#[cfg_attr(not(test), allow(dead_code))]
pub fn get_decoder_by_name(decoder_name: &str) -> Decoders {
    trace!("Getting decoder by name: {}", decoder_name);
    let all_decoders = get_all_decoders();

    let filtered_components = all_decoders
        .components
        .into_iter()
        .filter(|d| d.get_name() == decoder_name)
        .collect();

    Decoders {
        components: filtered_components,
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        checkers::{
            athena::Athena,
            checker_type::{Check, Checker},
            CheckerTypes,
        },
        DecoderResult,
    };

    use super::{
        filter_and_get_decoders, filter_decoders_by_tags, get_decoder_by_name,
        get_decoder_tagged_decoders, get_non_decoder_tagged_decoders, DecoderFilter,
    };

    #[test]
    fn it_works() {
        let _decoders = filter_and_get_decoders(&DecoderResult::default());
        assert_eq!(2 + 2, 4);
    }

    #[test]
    fn decoders_can_call_dot_run() {
        let decoders = filter_and_get_decoders(&DecoderResult::default());
        let athena_checker = Checker::<Athena>::new();
        let checker = CheckerTypes::CheckAthena(athena_checker);
        decoders.run("TXIgUm9ib3QgaXMgZ3JlYXQ=", checker);
        assert_eq!(true, true);
    }

    #[test]
    fn test_decoder_filter_include_tag() {
        let filter = DecoderFilter::new().include_tag("base");
        let decoders = filter_decoders_by_tags(&DecoderResult::default(), &filter);

        // Verify all returned decoders have the "base" tag or a tag starting with "base"
        for decoder in decoders.components.iter() {
            let tags = decoder.get_tags();
            let has_base_tag = tags
                .iter()
                .any(|tag| *tag == "base" || tag.starts_with("base"));
            assert!(
                has_base_tag,
                "Decoder {} should have 'base' tag or tag starting with 'base', but has tags: {:?}",
                decoder.get_name(),
                tags
            );
        }

        // Ensure we have at least one decoder with the "base" tag
        assert!(
            !decoders.components.is_empty(),
            "Should have at least one decoder with 'base' tag"
        );
    }

    #[test]
    fn test_decoder_filter_exclude_tag() {
        let filter = DecoderFilter::new().exclude_tag("base64");
        let decoders = filter_decoders_by_tags(&DecoderResult::default(), &filter);

        // Verify none of the returned decoders have the "base64" tag
        for decoder in decoders.components.iter() {
            let tags = decoder.get_tags();
            assert!(
                !tags.contains(&"base64"),
                "Decoder {} should not have 'base64' tag, but has tags: {:?}",
                decoder.get_name(),
                tags
            );
        }

        // Ensure we have some decoders without the "base64" tag
        assert!(
            !decoders.components.is_empty(),
            "Should have some decoders without 'base64' tag"
        );
    }

    #[test]
    fn test_decoder_filter_combined() {
        let filter = DecoderFilter::new()
            .include_tag("base")
            .exclude_tag("base64");

        let decoders = filter_decoders_by_tags(&DecoderResult::default(), &filter);

        // Verify all returned decoders have the "base" tag but not the "base64" tag
        for decoder in decoders.components.iter() {
            let tags = decoder.get_tags();
            let has_base_tag = tags
                .iter()
                .any(|tag| *tag == "base" || tag.starts_with("base"));
            assert!(
                has_base_tag,
                "Decoder {} should have 'base' tag or tag starting with 'base', but has tags: {:?}",
                decoder.get_name(),
                tags
            );
            assert!(
                !tags.contains(&"base64"),
                "Decoder {} should not have 'base64' tag, but has tags: {:?}",
                decoder.get_name(),
                tags
            );
        }
    }

    #[test]
    fn test_get_decoder_tagged_decoders() {
        let decoders = get_decoder_tagged_decoders(&DecoderResult::default());

        // Check if we have any decoders with the "decoder" tag
        let has_decoder_tag = decoders
            .components
            .iter()
            .any(|decoder| decoder.get_tags().contains(&"decoder"));

        // This test might pass or fail depending on whether any decoders have the "decoder" tag
        // If none have it, we should at least get an empty list
        if !has_decoder_tag {
            assert!(
                decoders.components.is_empty(),
                "If no decoders have the 'decoder' tag, the result should be empty"
            );
        }
    }

    #[test]
    fn test_get_non_decoder_tagged_decoders() {
        let decoders = get_non_decoder_tagged_decoders(&DecoderResult::default());

        // Verify none of the returned decoders have the "decoder" tag
        for decoder in decoders.components.iter() {
            assert!(
                !decoder.get_tags().contains(&"decoder"),
                "Decoder {} should not have 'decoder' tag, but has tags: {:?}",
                decoder.get_name(),
                decoder.get_tags()
            );
        }

        // We should have at least some decoders without the "decoder" tag
        assert!(
            !decoders.components.is_empty(),
            "Should have some decoders without 'decoder' tag"
        );
    }

    #[test]
    fn test_get_decoder_by_name() {
        let decoder_name = "Base64";
        let decoders = get_decoder_by_name(decoder_name);

        assert_eq!(
            decoders.components.len(),
            1,
            "Should return exactly one decoder"
        );
        assert_eq!(
            decoders.components[0].get_name(),
            decoder_name,
            "Should return the requested decoder"
        );
    }

    #[test]
    fn test_get_decoder_by_name_nonexistent() {
        let decoders = get_decoder_by_name("nonexistent_decoder");
        assert!(
            decoders.components.is_empty(),
            "Should return empty decoders for nonexistent name"
        );
    }
}
