//! One function per decoder, and the table [`decode_with`] and [`list_decoders`] read.
//!
//! To add a decoder, add an entry here. A test fails until every decoder in the search
//! has one.

use super::keys;
use super::{about, crack, Decoded, Entry};
use crate::decoders::a1z26_decoder::A1Z26Decoder;
use crate::decoders::aaencode_decoder::AAEncodeDecoder;
use crate::decoders::affine_decoder::AffineDecoder;
use crate::decoders::ascii85_decoder::Ascii85Decoder;
use crate::decoders::atbash_decoder::AtbashDecoder;
use crate::decoders::backslash_escape_decoder::BackslashEscapeDecoder;
use crate::decoders::baconian_decoder::BaconianDecoder;
use crate::decoders::base100_decoder::Base100Decoder;
use crate::decoders::base32_decoder::Base32Decoder;
use crate::decoders::base36_decoder::Base36Decoder;
use crate::decoders::base58_bitcoin_decoder::Base58BitcoinDecoder;
use crate::decoders::base58_flickr_decoder::Base58FlickrDecoder;
use crate::decoders::base58_monero_decoder::Base58MoneroDecoder;
use crate::decoders::base58_ripple_decoder::Base58RippleDecoder;
use crate::decoders::base64_alt_decoder::Base64AltDecoder;
use crate::decoders::base64_decoder::Base64Decoder;
use crate::decoders::base65536_decoder::Base65536Decoder;
use crate::decoders::base85_decoder::Base85Decoder;
use crate::decoders::base91_decoder::Base91Decoder;
use crate::decoders::base92_decoder::Base92Decoder;
use crate::decoders::baudot_decoder::BaudotDecoder;
use crate::decoders::big_integer_decoder::BigIntegerDecoder;
use crate::decoders::binary_decoder::BinaryDecoder;
use crate::decoders::braille_decoder::BrailleDecoder;
use crate::decoders::brainfuck_interpreter::BrainfuckInterpreter;
use crate::decoders::caesar_decoder::CaesarDecoder;
use crate::decoders::citrix_ctx1_decoder::CitrixCTX1Decoder;
use crate::decoders::core_socialist_values_decoder::CoreSocialistValuesDecoder;
use crate::decoders::decimal_decoder::DecimalDecoder;
use crate::decoders::dna_codon_decoder::DnaCodonDecoder;
use crate::decoders::dtmf_decoder::DtmfDecoder;
use crate::decoders::gzip_decoder::GzipDecoder;
use crate::decoders::hexadecimal_decoder::HexadecimalDecoder;
use crate::decoders::hexdump_decoder::HexdumpDecoder;
use crate::decoders::html_entity_decoder::HtmlEntityDecoder;
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
use crate::decoders::octal_decoder::OctalDecoder;
use crate::decoders::ook_decoder::OokDecoder;
use crate::decoders::playfair_decoder::PlayfairDecoder;
use crate::decoders::polybius_decoder::PolybiusDecoder;
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
use crate::decoders::vigenere_decoder::VigenereDecoder;
use crate::decoders::xor_repeating_key_decoder::XorRepeatingKeyDecoder;
use crate::decoders::xor_single_byte_decoder::XorSingleByteDecoder;
use crate::decoders::yunying_decoder::YunyingDecoder;
use crate::decoders::z85_decoder::Z85Decoder;
use crate::decoders::zero_width_decoder::ZeroWidthDecoder;
use crate::decoders::zlib_decoder::ZlibDecoder;

/// Defines `pub fn <function>(text: &str) -> Decoded` for each decoder, which decodes or
/// cracks `text` with it, and [`ENTRIES`], the table of all of them.
macro_rules! decoder_functions {
    ($(
        $(#[$attr:meta])*
        $function:ident: $decoder:ty, aliases [$($alias:literal),*], key $key:expr;
    )*) => {
        $(
            $(#[$attr])*
            pub fn $function(text: &str) -> Decoded {
                crack::<$decoder>(text)
            }
        )*

        /// Every decoder, in the order [`list_decoders`](super::list_decoders) lists them.
        pub(super) static ENTRIES: &[Entry] = &[$(
            Entry {
                function: stringify!($function),
                aliases: &[$($alias),*],
                about: about::<$decoder>,
                crack: $function,
                key: $key,
            },
        )*];
    };
}

decoder_functions! {
    /// Decodes A1Z26, letters written as their place in the alphabet.
    ///
    /// ```
    /// let decoded = ciphey::decoders::a1z26("8 5 12 12 15");
    /// assert_eq!(decoded.candidates[0].text, "HELLO");
    /// ```
    a1z26: A1Z26Decoder, aliases [], key None;

    /// Decodes AAEncode, JavaScript written as Japanese-style emoticons, back to its
    /// source. A program starts `ﾟωﾟﾉ= /｀ｍ´）ﾉ ~┻━┻` and ends `('_');`. Nothing is run:
    /// the escapes in the program are read straight back.
    ///
    /// ```
    /// // aaencode("hello world") from utf-8.jp's encoder, 1,405 characters
    /// let program = concat!(
    ///     r#"ﾟωﾟﾉ= /｀ｍ´）ﾉ ~┻━┻   //*´∇｀*/ ['_']; o=(ﾟｰﾟ)  =_=3; c=(ﾟΘﾟ) =(ﾟｰﾟ)-(ﾟｰﾟ); "#,
    ///     // ... the rest of the 1,405 characters ...
    /// #   r#"(ﾟДﾟ) =(ﾟΘﾟ)= (o^_^o)/ (o^_^o);(ﾟДﾟ)={ﾟΘﾟ: '_' ,ﾟωﾟﾉ : ((ﾟωﾟﾉ==3) +'_') [ﾟΘﾟ] ,ﾟｰﾟﾉ :(ﾟωﾟﾉ+ "#,
    /// #   r#"'_')[o^_^o -(ﾟΘﾟ)] ,ﾟДﾟﾉ:((ﾟｰﾟ==3) +'_')[ﾟｰﾟ] }; (ﾟДﾟ) [ﾟΘﾟ] =((ﾟωﾟﾉ==3) +'_') [c^_^o];"#,
    /// #   r#"(ﾟДﾟ) ['c'] = ((ﾟДﾟ)+'_') [ (ﾟｰﾟ)+(ﾟｰﾟ)-(ﾟΘﾟ) ];(ﾟДﾟ) ['o'] = ((ﾟДﾟ)+'_') [ﾟΘﾟ];"#,
    /// #   r#"(ﾟoﾟ)=(ﾟДﾟ) ['c']+(ﾟДﾟ) ['o']+(ﾟωﾟﾉ +'_')[ﾟΘﾟ]+ ((ﾟωﾟﾉ==3) +'_') [ﾟｰﾟ] + "#,
    /// #   r#"((ﾟДﾟ) +'_') [(ﾟｰﾟ)+(ﾟｰﾟ)]+ ((ﾟｰﾟ==3) +'_') [ﾟΘﾟ]+((ﾟｰﾟ==3) +'_') [(ﾟｰﾟ) - (ﾟΘﾟ)]+(ﾟДﾟ) ['c']+((ﾟДﾟ)+'_') [(ﾟｰﾟ)+(ﾟｰﾟ)]+ "#,
    /// #   r#"(ﾟДﾟ) ['o']+((ﾟｰﾟ==3) +'_') [ﾟΘﾟ];(ﾟДﾟ) ['_'] =(o^_^o) [ﾟoﾟ] [ﾟoﾟ];(ﾟεﾟ)=((ﾟｰﾟ==3) +'_') [ﾟΘﾟ]+ "#,
    /// #   r#"(ﾟДﾟ) .ﾟДﾟﾉ+((ﾟДﾟ)+'_') [(ﾟｰﾟ) + (ﾟｰﾟ)]+((ﾟｰﾟ==3) +'_') [o^_^o -ﾟΘﾟ]+((ﾟｰﾟ==3) +'_') [ﾟΘﾟ]+ "#,
    /// #   r#"(ﾟωﾟﾉ +'_') [ﾟΘﾟ]; (ﾟｰﾟ)+=(ﾟΘﾟ); (ﾟДﾟ)[ﾟεﾟ]='\\'; (ﾟДﾟ).ﾟΘﾟﾉ=(ﾟДﾟ+ ﾟｰﾟ)[o^_^o -(ﾟΘﾟ)];"#,
    /// #   r#"(oﾟｰﾟo)=(ﾟωﾟﾉ +'_')[c^_^o];(ﾟДﾟ) [ﾟoﾟ]='\"';(ﾟДﾟ) ['_'] ( (ﾟДﾟ) ['_'] (ﾟεﾟ+(ﾟДﾟ)[ﾟoﾟ]+ "#,
    /// #   r#"(ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((ﾟｰﾟ) + (ﾟΘﾟ))+ (c^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ (ﾟｰﾟ)+ ((ﾟｰﾟ) + "#,
    /// #   r#"(ﾟΘﾟ))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((ﾟｰﾟ) + (ﾟΘﾟ))+ (ﾟｰﾟ)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((ﾟｰﾟ) + "#,
    /// #   r#"(ﾟΘﾟ))+ (ﾟｰﾟ)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((ﾟｰﾟ) + (ﾟΘﾟ))+ ((ﾟｰﾟ) + (o^_^o))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟｰﾟ)+ "#,
    /// #   r#"(c^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((o^_^o) +(o^_^o))+ ((ﾟｰﾟ) + (o^_^o))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ "#,
    /// #   r#"((ﾟｰﾟ) + (ﾟΘﾟ))+ ((ﾟｰﾟ) + (o^_^o))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((o^_^o) +(o^_^o))+ "#,
    /// #   r#"((o^_^o) - (ﾟΘﾟ))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((ﾟｰﾟ) + (ﾟΘﾟ))+ (ﾟｰﾟ)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ "#,
    /// #   r#"(ﾟｰﾟ)+ (ﾟｰﾟ)+ "#,
    ///     r#"(ﾟДﾟ)[ﾟoﾟ]) (ﾟΘﾟ)) ('_');"#,
    /// );
    /// let decoded = ciphey::decoders::aaencode(program);
    /// assert_eq!(decoded.plaintext().unwrap().text, "hello world");
    /// ```
    aaencode: AAEncodeDecoder, aliases ["aadecode"], key None;

    /// Cracks the Affine cipher, E(x) = (a·x + b) mod 26. Ciphey ranks the keys by how
    /// English their letter pairs look and checks the best few. To decrypt with a known
    /// key, use [`affine_with_key`](super::affine_with_key).
    ///
    /// ```
    /// let decoded = ciphey::decoders::affine("IHHWVC SWFRCP");
    /// let plaintext = decoded.plaintext().unwrap();
    /// assert_eq!(plaintext.text, "AFFINE CIPHER");
    /// assert_eq!(plaintext.key.as_deref(), Some("a=5, b=8"));
    /// ```
    affine: AffineDecoder, aliases [], key Some(keys::AFFINE);

    /// Decodes Ascii85, the Base85 of Adobe and btoa, with or without its `<~ ~>`.
    ///
    /// ```
    /// let decoded = ciphey::decoders::ascii85("<~BOu!rD]j7BEbo7~>");
    /// assert_eq!(decoded.candidates[0].text, "hello world");
    /// ```
    ascii85: Ascii85Decoder, aliases ["btoa"], key None;

    /// Decodes Atbash, which swaps A and Z, B and Y, and so on.
    ///
    /// ```
    /// let decoded = ciphey::decoders::atbash("svool dliow");
    /// assert_eq!(decoded.plaintext().unwrap().text, "hello world");
    /// ```
    atbash: AtbashDecoder, aliases [], key None;

    /// Decodes backslash escapes as C, Python and JavaScript string literals write them:
    /// `\110`, `\x48`, `\n` and so on. Escapes stand for bytes, read as UTF-8.
    ///
    /// ```
    /// let decoded = ciphey::decoders::backslash_escapes(r"\x68\x65\x6c\x6c\x6f\x20\x77\x6f\x72\x6c\x64");
    /// assert_eq!(decoded.candidates[0].text, "hello world");
    /// ```
    backslash_escapes: BackslashEscapeDecoder, aliases ["backslash_escape", "string_escapes"], key None;

    /// Decodes Bacon's cipher: five A/B symbols per letter, which can be any two
    /// characters or hidden in the letter case of a cover text. The key says which
    /// alphabet and which symbols it took.
    ///
    /// ```
    /// let decoded = ciphey::decoders::baconian("AABBB AABAA ABABA ABABA ABBAB");
    /// let plaintext = decoded.plaintext().unwrap();
    /// assert_eq!(plaintext.text, "HELLO");
    /// assert_eq!(plaintext.key.as_deref(), Some("standard, A=A B=B"));
    /// ```
    baconian: BaconianDecoder, aliases ["bacon"], key None;

    /// Decodes Base100, which writes every byte as one emoji.
    ///
    /// ```
    /// let decoded = ciphey::decoders::base100("👟👜👣👣👦🐗👮👦👩👣👛");
    /// assert_eq!(decoded.candidates[0].text, "hello world");
    /// ```
    base100: Base100Decoder, aliases ["emoji"], key None;

    /// Decodes Base32.
    ///
    /// ```
    /// let decoded = ciphey::decoders::base32("NBSWY3DPEB3W64TMMQ======");
    /// assert_eq!(decoded.candidates[0].text, "hello world");
    /// ```
    base32: Base32Decoder, aliases ["b32"], key None;

    /// Decodes Base36, text written as one number in base 36 (digits `0` to `9`, then `a` to
    /// `z`, in either case).
    ///
    /// ```
    /// let decoded = ciphey::decoders::base36("fuvrsivvnfrbjwajo");
    /// assert_eq!(decoded.candidates[0].text, "hello world");
    /// ```
    base36: Base36Decoder, aliases [], key None;

    /// Decodes Base58 with the Bitcoin alphabet, the usual one.
    ///
    /// ```
    /// let decoded = ciphey::decoders::base58_bitcoin("StV1DL6CwTryKyV");
    /// assert_eq!(decoded.candidates[0].text, "hello world");
    /// ```
    base58_bitcoin: Base58BitcoinDecoder, aliases ["base58"], key None;

    /// Decodes Base58 with Flickr's alphabet.
    ///
    /// ```
    /// let decoded = ciphey::decoders::base58_flickr("rTu1dk6cWsRYjYu");
    /// assert_eq!(decoded.candidates[0].text, "hello world");
    /// ```
    base58_flickr: Base58FlickrDecoder, aliases [], key None;

    /// Decodes Base58 the way Monero writes it.
    ///
    /// ```
    /// let decoded = ciphey::decoders::base58_monero("StV1DL6CwTryKyV");
    /// assert_eq!(decoded.candidates[0].text, "hello world");
    /// ```
    base58_monero: Base58MoneroDecoder, aliases [], key None;

    /// Decodes Base58 with Ripple's alphabet.
    ///
    /// ```
    /// let decoded = ciphey::decoders::base58_ripple("StVrDLaUATiyKyV");
    /// assert_eq!(decoded.candidates[0].text, "hello world");
    /// ```
    base58_ripple: Base58RippleDecoder, aliases [], key None;

    /// Decodes Base64, standard or URL-safe.
    ///
    /// ```
    /// let decoded = ciphey::decoders::base64("aGVsbG8gd29ybGQ=");
    /// assert_eq!(decoded.candidates[0].text, "hello world");
    /// ```
    base64: Base64Decoder, aliases ["b64"], key None;

    /// Decodes Base64 written with a non-standard alphabet, such as crypt(3)'s itoa64,
    /// bcrypt's or CyberChef's Atom128, trying each one. The key names the alphabet.
    /// Standard and URL-safe Base64 are [`base64`](fn@base64).
    ///
    /// ```
    /// let decoded = ciphey::decoders::base64_alt(
    ///     "J4VZ653pOKBf647mPrRi64NjS0/eRKpkQm/jRaJm65FcNG/gMLdt64FjNk==",
    /// );
    /// let plaintext = decoded.plaintext().unwrap();
    /// assert_eq!(plaintext.text, "The quick brown fox jumps over the lazy dog");
    /// assert_eq!(plaintext.key.as_deref(), Some("itoa64 / crypt(3)"));
    /// ```
    base64_alt: Base64AltDecoder, aliases [], key None;

    /// Decodes Base65536, which writes two bytes as one Unicode character.
    ///
    /// ```
    /// let decoded = ciphey::decoders::base65536("𒅓鹨𖡮𒀠啦ꍢ顡啫𓍱𓁡𠁴唬𓍪鱤啥𖥭𔐠𔕯ᔮ");
    /// assert_eq!(decoded.candidates[0].text, "Sphinx of black quartz, judge my vow.");
    /// ```
    base65536: Base65536Decoder, aliases [], key None;

    /// Decodes Base85 with the RFC 1924 alphabet. Adobe's is [`ascii85`](fn@ascii85) and
    /// ZeroMQ's [`z85`](fn@z85).
    ///
    /// ```
    /// let decoded = ciphey::decoders::base85("Xk~0{Zy<MXa%^M");
    /// assert_eq!(decoded.candidates[0].text, "hello world");
    /// ```
    base85: Base85Decoder, aliases ["rfc1924"], key None;

    /// Decodes basE91.
    ///
    /// ```
    /// let decoded = ciphey::decoders::base91("TPwJh>Io2Tv!lE");
    /// assert_eq!(decoded.candidates[0].text, "hello world");
    /// ```
    base91: Base91Decoder, aliases [], key None;

    /// Decodes Base92.
    ///
    /// ```
    /// let decoded = ciphey::decoders::base92("Fc_$aOTdKnsM*k");
    /// assert_eq!(decoded.candidates[0].text, "hello world");
    /// ```
    base92: Base92Decoder, aliases [], key None;

    /// Decodes Baudot code (ITA2 and the US teletypewriter variant), five bits per
    /// character with letter and figure shifts. The key says how it read the bits.
    ///
    /// ```
    /// let decoded = ciphey::decoders::baudot(
    ///     "10100 00001 10010 10010 11000 00100 10011 11000 01010 10010 01001",
    /// );
    /// let plaintext = decoded.plaintext().unwrap();
    /// assert_eq!(plaintext.text, "HELLO WORLD");
    /// assert_eq!(plaintext.key.as_deref(), Some("MSB-first, US-TTY"));
    /// ```
    baudot: BaudotDecoder, aliases ["ita2", "murray"], key None;

    /// Decodes a big integer: the bytes of the text read as one big-endian number and
    /// written in decimal, as PyCryptodome's `long_to_bytes` decodes it. An optional
    /// `name =` prefix (`m = 4149…`) and Python 2's trailing `L` are accepted.
    ///
    /// ```
    /// let decoded = ciphey::decoders::big_integer("126207244316550804821666916");
    /// assert_eq!(decoded.candidates[0].text, "hello world");
    /// ```
    big_integer: BigIntegerDecoder, aliases ["long_to_bytes", "bigint"], key None;

    /// Decodes character codes written in binary, trying every code length from 1 to 24
    /// bits.
    ///
    /// ```
    /// let decoded = ciphey::decoders::binary(
    ///     "01101000 01100101 01101100 01101100 01101111 00100000 01110111 01101111 01110010 01101100 01100100",
    /// );
    /// assert_eq!(decoded.plaintext().unwrap().text, "hello world");
    /// ```
    binary: BinaryDecoder, aliases ["bin"], key None;

    /// Decodes Braille.
    ///
    /// ```
    /// let decoded = ciphey::decoders::braille("⠓⠑⠇⠇⠕⠀⠺⠕⠗⠇⠙");
    /// assert_eq!(decoded.candidates[0].text, "hello world");
    /// ```
    braille: BrailleDecoder, aliases [], key None;

    /// Runs a Brainfuck program and returns what it prints. Programs that run too long are
    /// stopped.
    ///
    /// ```
    /// let decoded = ciphey::decoders::brainfuck(
    ///     ">++++++++[<+++++++++>-]<.>++++[<+++++++>-]<+.+++++++..+++.>>++++++[<+++++++>-]<++.------------.>++++++[<+++++++++>-]<+.<.+++.------.--------.>>>++++[<++++++++>-]<+.",
    /// );
    /// assert_eq!(decoded.candidates[0].text, "Hello, World!");
    /// ```
    brainfuck: BrainfuckInterpreter, aliases ["bf"], key None;

    /// Cracks the Caesar cipher, ROT13 included: the shift that Ciphey's checks accept
    /// comes back as the plaintext, with the shift as its key. To decrypt with a known
    /// shift, use [`caesar_with_key`](super::caesar_with_key).
    ///
    /// ```
    /// let decoded = ciphey::decoders::caesar("uryyb guvf vf ybat grkg");
    /// let plaintext = decoded.plaintext().unwrap();
    /// assert_eq!(plaintext.text, "hello this is long text");
    /// assert_eq!(plaintext.key.as_deref(), Some("13"));
    /// ```
    caesar: CaesarDecoder, aliases ["rot13"], key Some(keys::CAESAR);

    /// Decodes Citrix CTX1, which Citrix uses to obfuscate stored passwords.
    ///
    /// ```
    /// let decoded = ciphey::decoders::citrix_ctx1("MNGIKIANMEGBKIANMHGCOHECJADFPPFKINCIOBEEIFCA");
    /// assert_eq!(decoded.candidates[0].text, "hello world");
    /// ```
    citrix_ctx1: CitrixCTX1Decoder, aliases ["ctx1"], key None;

    /// Decodes the Core Socialist Values encoding (社会主义核心价值观编码): the UTF-8
    /// bytes of the text as base-12 digits, each written as one of the twelve
    /// two-character values from 富强 (0) to 友善 (11).
    ///
    /// ```
    /// let decoded = ciphey::decoders::core_socialist_values(
    ///     "公正爱国公正平等公正友善公正公正友善公正公正诚信平等文明富强法治法治公正诚信平等法治文明公正诚信文明公正自由",
    /// );
    /// assert_eq!(decoded.candidates[0].text, "hello world");
    /// ```
    core_socialist_values: CoreSocialistValuesDecoder, aliases ["core_values", "社会主义核心价值观"], key None;

    /// Decodes character codes written in decimal, also as `String.fromCharCode(...)`.
    ///
    /// ```
    /// let decoded = ciphey::decoders::decimal("104 101 108 108 111 32 119 111 114 108 100");
    /// assert_eq!(decoded.candidates[0].text, "hello world");
    /// ```
    decimal: DecimalDecoder, aliases ["charcode"], key None;

    /// Decodes DNA or RNA codons, triplets of `ACGT` or `ACGU`, to one-letter amino-acid
    /// codes with the standard genetic code. Stop codons become spaces.
    ///
    /// ```
    /// let decoded = ciphey::decoders::dna_codon("ATG GAA GAA ACA TAA ATG GAA TAA GCA ACA TAA GAC GCA TGG AAC");
    /// assert_eq!(decoded.plaintext().unwrap().text, "MEET ME AT DAWN");
    /// ```
    dna_codon: DnaCodonDecoder, aliases ["dna", "codon", "codons"], key None;

    /// Decodes DTMF (touch-tone) frequency pairs, one low and one high frequency per
    /// telephone key in either order, so `852-1336` is `8`. The output is the keys 0 to 9,
    /// `*`, `#` and A to D.
    ///
    /// ```
    /// let decoded = ciphey::decoders::dtmf("852-1336 770-1477 852-1209 770-1336 697-1477 941-1336 852-1477");
    /// assert_eq!(decoded.candidates[0].text, "8675309");
    /// ```
    dtmf: DtmfDecoder, aliases ["touch_tone"], key None;

    /// Decompresses gzip written as Base64 or hex. The key is the file name stored in the
    /// archive, if it has one.
    ///
    /// ```
    /// let decoded = ciphey::decoders::gzip(
    ///     "H4sIAAAAAAAC/wvJSFUoLM1MzlZIKsovz1NIy69QyCrNLShWyC9LLVIoAUrnJFZVKqTkpwMAOaNPQSsAAAA=",
    /// );
    /// assert_eq!(decoded.candidates[0].text, "The quick brown fox jumps over the lazy dog");
    /// ```
    gzip: GzipDecoder, aliases [], key None;

    /// Decodes hexadecimal.
    ///
    /// ```
    /// let decoded = ciphey::decoders::hexadecimal("68656c6c6f20776f726c64");
    /// assert_eq!(decoded.candidates[0].text, "hello world");
    /// ```
    hexadecimal: HexadecimalDecoder, aliases ["hex", "base16"], key None;

    /// Decodes a hex dump back to the bytes that were dumped: the output of `xxd`,
    /// `hexdump -C`, `od` and similar. The offsets and the ASCII column are ignored.
    ///
    /// ```
    /// let decoded = ciphey::decoders::hexdump(
    ///     "00000000: 4865 6c6c 6f2c 2057 6f72 6c64 21         Hello, World!",
    /// );
    /// assert_eq!(decoded.candidates[0].text, "Hello, World!");
    /// ```
    hexdump: HexdumpDecoder, aliases ["xxd", "od"], key None;

    /// Decodes HTML entities such as `&lt;`, `&#233;` and `&#x2615;`.
    ///
    /// ```
    /// let decoded = ciphey::decoders::html_entities("&lt;b&gt;Tom &amp; Jerry&lt;/b&gt;");
    /// assert_eq!(decoded.candidates[0].text, "<b>Tom & Jerry</b>");
    /// ```
    html_entities: HtmlEntityDecoder, aliases ["html", "html_entity"], key None;

    /// Evaluates JSFuck, JavaScript written with only `[]()!+`, with a small built-in
    /// evaluator: no JavaScript is run. A program wrapped in `Function(...)()` comes back
    /// as its source.
    ///
    /// ```
    /// let decoded = ciphey::decoders::jsfuck("(![]+[])[+[]]+([][[]]+[])[+[]]+([][[]]+[])[+!+[]]");
    /// assert_eq!(decoded.candidates[0].text, "fun");
    /// ```
    jsfuck: JsFuckDecoder, aliases [], key None;

    /// Decodes the payload of a JSON Web Token. The signature isn't checked. The key is the
    /// decoded header.
    ///
    /// ```
    /// let decoded = ciphey::decoders::jwt(
    ///     "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    /// );
    /// let payload = decoded.plaintext().unwrap();
    /// assert_eq!(payload.text, r#"{"sub":"1234567890","name":"John Doe","iat":1516239022}"#);
    /// assert_eq!(payload.key.as_deref(), Some(r#"{"alg":"HS256","typ":"JWT"}"#));
    /// ```
    jwt: JwtDecoder, aliases ["json_web_token"], key None;

    /// Decodes text typed on one keyboard layout and read as another: QWERTY, Dvorak,
    /// Colemak and AZERTY, each way, and the keyboard cipher that writes the alphabet in
    /// QWERTY key order (A is Q, B is W, ...). The key names the layouts, as
    /// `typed→read`.
    ///
    /// ```
    /// // `hello world` typed on QWERTY keys and read as Dvorak
    /// let decoded = ciphey::decoders::keyboard_layout("d.nnr ,rpne");
    /// let plaintext = decoded.plaintext().unwrap();
    /// assert_eq!(plaintext.text, "hello world");
    /// assert_eq!(plaintext.key.as_deref(), Some("QWERTY→Dvorak"));
    /// ```
    keyboard_layout: KeyboardLayoutDecoder, aliases ["keyboard_change"], key None;

    /// Cracks the keyboard shift cipher, where every key was replaced by a neighbouring
    /// key: one or two to the right or left, or the key above or below, on US QWERTY, or
    /// one along the letter rows of AZERTY or QWERTZ. The key names the shift that
    /// encrypted the text.
    ///
    /// ```
    /// let decoded = ciphey::decoders::keyboard_shift("jr;;p ept;f");
    /// let plaintext = decoded.plaintext().unwrap();
    /// assert_eq!(plaintext.text, "hello world");
    /// assert_eq!(plaintext.key.as_deref(), Some("QWERTY right 1"));
    /// ```
    keyboard_shift: KeyboardShiftDecoder, aliases [], key None;

    /// Decodes leetspeak, letters written as look-alike digits and symbols (`3` for e,
    /// `|<` for k). `1`, `|` and `2` each stand for two letters, and Ciphey picks the one
    /// that makes an English word. Text where fewer than half of the words with a digit or
    /// symbol in them read as words returns no candidates.
    ///
    /// ```
    /// let decoded = ciphey::decoders::leetspeak("l337 5p34k 15 3l173");
    /// assert_eq!(decoded.plaintext().unwrap().text, "leet speak is elite");
    /// ```
    leetspeak: LeetspeakDecoder, aliases ["leet", "1337"], key None;

    /// Decodes MIME encoded-words (RFC 2047), the `=?charset?B?...?=` and
    /// `=?charset?Q?...?=` of email headers.
    ///
    /// ```
    /// let decoded = ciphey::decoders::mime_encoded_word("=?utf-8?b?Q2Fmw6kgb2zDqSDigJMgcsOpc3Vtw6k=?=");
    /// assert_eq!(decoded.candidates[0].text, "Café olé – résumé");
    /// ```
    mime_encoded_word: MimeEncodedWordDecoder, aliases ["rfc2047", "encoded_word"], key None;

    /// Cracks monoalphabetic substitution, where any permutation of the alphabet is the
    /// key (cryptograms, Aristocrats, Patristocrats). It needs at least 60 letters. The key
    /// gives the cipher letter of each plaintext letter A to Z. To decrypt with a known
    /// key, use [`monoalphabetic_substitution_with_key`](super::monoalphabetic_substitution_with_key).
    ///
    /// Ciphey remembers, for as long as the process runs, the letter patterns it couldn't
    /// solve, so asking again about the same text, or another substitution of it, returns
    /// no candidates.
    ///
    /// This is the cipher usually called simple substitution. Ciphey's decoder named
    /// `simplesubstitution` is another one, [`symbol_substitution`].
    ///
    /// ```
    /// let decoded = ciphey::decoders::monoalphabetic_substitution(
    ///     "Qaxeiw ar pf pvcdopcaq giqkwxcadf cddn. Wdv masi ac ifqkwxcig cizc pfg ac ckair cd \
    ///      tdkl dvc tepc tpr gdfi cd ac, ceif redtr wdv cei xnpafcizc. Ac lfdtr opfw ifqdgafmr \
    ///      pfg qnprraqpn qaxeikr, pfg ac liixr nipkfafm fit dfir.",
    /// );
    /// let plaintext = decoded.plaintext().unwrap();
    /// assert!(plaintext.text.starts_with("Ciphey is an automatic decryption tool."));
    /// assert_eq!(plaintext.key.as_deref(), Some("P?QGI?MEA?LNOFDX?KRCVSTZW?"));
    /// ```
    monoalphabetic_substitution: MonoalphabeticSubstitutionDecoder,
        aliases ["monoalphabetic", "cryptogram", "aristocrat", "patristocrat"],
        key Some(keys::MONOALPHABETIC_SUBSTITUTION);

    /// Decodes Morse code.
    ///
    /// ```
    /// let decoded = ciphey::decoders::morse(".---- ----. ..--- .-.-.- .---- -.... ---.. .-.-.- ----- .-.-.- .----");
    /// assert_eq!(decoded.plaintext().unwrap().text, "192.168.0.1");
    /// ```
    morse: MorseCodeDecoder, aliases [], key None;

    /// Decodes Multi-tap, the text entry of keypad phones: `44` is H, `555` is L, and `0`
    /// is a space.
    ///
    /// ```
    /// let decoded = ciphey::decoders::multi_tap("44 33 555 555 666 0 9 666 777 555 3");
    /// assert_eq!(decoded.candidates[0].text, "HELLO WORLD");
    /// ```
    multi_tap: MultiTapDecoder, aliases ["multitap", "phone_keypad"], key None;

    /// Decodes text spelled with the NATO phonetic alphabet, the first letter of each code
    /// word: `Hotel Echo Lima Lima Oscar` is `hello`. Words are two spaces apart, as
    /// CyberChef writes them, or their code words are joined with `-`, `/` or `|`.
    ///
    /// ```
    /// let decoded = ciphey::decoders::nato_phonetic("Hotel-Echo-Lima-Lima-Oscar Whiskey-Oscar-Romeo-Lima-Delta");
    /// assert_eq!(decoded.plaintext().unwrap().text, "hello world");
    /// ```
    nato_phonetic: NatoPhoneticDecoder, aliases ["nato", "phonetic_alphabet", "spelling_alphabet"], key None;

    /// Finds a message hidden in a null cipher: the first or last letters of the words or
    /// lines of a cover text (an acrostic), every n-th letter, the capital letters, or the
    /// letters after punctuation. The message comes back in capitals without spaces, and
    /// the key names the rule that found it. Ciphey's checks only see messages that split
    /// into dictionary words, unless `Config::regex` is set.
    ///
    /// ```
    /// let decoded = ciphey::decoders::null_cipher(
    ///     "Help Everyone Love Lots Of Wildlife: Observe Raptors, Lizards, Deer.",
    /// );
    /// let plaintext = decoded.plaintext().unwrap();
    /// assert_eq!(plaintext.text, "HELLOWORLD");
    /// assert_eq!(plaintext.key.as_deref(), Some("first letter of each word"));
    /// ```
    null_cipher: NullCipherDecoder, aliases ["acrostic", "concealment_cipher"], key None;

    /// Decodes character codes written in octal.
    ///
    /// ```
    /// let decoded = ciphey::decoders::octal("150 145 154 154 157 40 167 157 162 154 144");
    /// assert_eq!(decoded.candidates[0].text, "hello world");
    /// ```
    octal: OctalDecoder, aliases ["oct"], key None;

    /// Runs an Ook! program, Brainfuck written as pairs of `Ook.`, `Ook?` and `Ook!`, and
    /// returns what it prints. The short form, with only `.`, `?` and `!`, is read too.
    /// Programs that run too long are stopped.
    ///
    /// ```
    /// // `++++++++[>+++++++++++++<-]>.+.` in short Ook!
    /// let decoded = ciphey::decoders::ook(
    ///     ". . . . . . . . . . . . . . . . ! ? . ? . . . . . . . . . . . . . . . . . . . . . . . . . . ? . ! ! ? ! . ? ! . . . ! .",
    /// );
    /// assert_eq!(decoded.candidates[0].text, "hi");
    /// ```
    ook: OokDecoder, aliases ["short_ook"], key None;

    /// Cracks the Playfair cipher, which encrypts pairs of letters with a 5×5 key square.
    /// It needs at least 200 letters, and the search for the square can take a second or
    /// so. The plaintext comes back upper case and with the cipher's X fillers, and the key
    /// is the square, row by row. To decrypt with a known keyword or square, use
    /// [`playfair_with_key`](super::playfair_with_key).
    ///
    /// ```
    /// // 300 letters of Treasure Island, with the square of the keyword TREASURE
    /// let decoded = ciphey::decoders::playfair(
    ///     "RGROSKIQDSTFCYCAMRIREAYRTSRETOROCPFTCEQKQEOXOPCQSRLRRPCPRGAEOPLEATRGCIKRHERPUARDIS\
    ///      XRMRMXAEHOSKGVYDFISTINLFRASICQIZIQXRKDPBRGROEDAWQCYDHORPUAIRORVEHOTRRPEGTSRHKSDICP\
    ///      HKQBFGQLGKHIRSPBRGCIDYRSHOINSGAYBTTFHOHUMENRGEKBESRWDBSGSTTATSPBRGSCNEOTETREASOGMH\
    ///      FHXEPCBSPNRGSISCRTINFGCAEHFTRSEVRGACXENERGCIDYRSHOEKOT",
    /// );
    /// let plaintext = decoded.plaintext().unwrap();
    /// assert!(plaintext.text.starts_with("THENALLOFASUDXDENTHEREWASATREMENDOUSEXPLOSION"));
    /// assert_eq!(plaintext.key.as_deref(), Some("TREASUBCDFGHIKLMNOPQVWXYZ"));
    /// ```
    playfair: PlayfairDecoder, aliases [], key Some(keys::PLAYFAIR);

    /// Decodes the Polybius square cipher: each letter as its row and column in a 5×5
    /// square with I and J in one cell, written as digits (`23` is H) or as letters from
    /// `ABCDE` or `ADFGX`. Also the 6×6 square of A–Z and 0–9, column-row order and the
    /// tap code square. The key says which square and order it took.
    ///
    /// ```
    /// let decoded = ciphey::decoders::polybius("23 15 31 31 34  52 34 42 31 14");
    /// let plaintext = decoded.plaintext().unwrap();
    /// assert_eq!(plaintext.text, "HELLO WORLD");
    /// assert_eq!(plaintext.key.as_deref(), Some("5x5 I=J, row-column"));
    /// ```
    polybius: PolybiusDecoder, aliases ["polybius_square"], key None;

    /// Decodes Punycode (RFC 3492), and the `xn--` labels of internationalised domain names
    /// wherever they are in the text.
    ///
    /// ```
    /// let decoded = ciphey::decoders::punycode("https://xn--bcher-kva.example.com/");
    /// assert_eq!(decoded.candidates[0].text, "https://bücher.example.com/");
    /// ```
    punycode: PunycodeDecoder, aliases ["idna"], key None;

    /// Decodes Quoted-Printable (RFC 2045), the encoding of email bodies.
    ///
    /// ```
    /// let decoded = ciphey::decoders::quoted_printable("Cr=C3=A8me br=C3=BBl=C3=A9e =3D burnt cream");
    /// assert_eq!(decoded.candidates[0].text, "Crème brûlée = burnt cream");
    /// ```
    quoted_printable: QuotedPrintableDecoder, aliases ["qp"], key None;

    /// Cracks the rail fence (zigzag) cipher, trying 2 to 9 rails at every offset. If
    /// Ciphey's checks accept none of the 72 arrangements, all of them come back,
    /// unmarked. To decrypt with a known key, use
    /// [`railfence_with_key`](super::railfence_with_key).
    ///
    /// ```
    /// let decoded = ciphey::decoders::railfence("Hoo!el,Wrdl l");
    /// assert_eq!(decoded.plaintext().unwrap().text, "Hello, World!");
    /// ```
    railfence: RailfenceDecoder, aliases ["zigzag"], key Some(keys::RAILFENCE);

    /// Inflates raw DEFLATE (RFC 1951), the compressed data inside zlib and gzip without
    /// their header and checksum, written as Base64 or hex. PHP's `gzdeflate`, .NET's
    /// `DeflateStream` and CyberChef's Raw Deflate write it.
    ///
    /// ```
    /// let decoded = ciphey::decoders::raw_deflate(
    ///     "C8lIVSgszUzOVkgqyi/PU0jLr1DIKs0tKFbIL0stUigBSuckVlUqpOSnAwA=",
    /// );
    /// assert_eq!(decoded.candidates[0].text, "The quick brown fox jumps over the lazy dog");
    /// ```
    raw_deflate: RawDeflateDecoder, aliases ["raw_inflate", "deflate"], key None;

    /// Reverses the text.
    ///
    /// ```
    /// let decoded = ciphey::decoders::reverse("stac");
    /// assert_eq!(decoded.candidates[0].text, "cats");
    /// ```
    reverse: ReverseDecoder, aliases [], key None;

    /// Cracks ROT47 and the other rotations of the 94 printable ASCII characters. To
    /// decrypt with a known rotation, use [`rot47_with_key`](super::rot47_with_key).
    ///
    /// ```
    /// let decoded = ciphey::decoders::rot47("wt{{~ (~#{s");
    /// assert_eq!(decoded.plaintext().unwrap().text, "HELLO WORLD");
    /// ```
    rot47: ROT47Decoder, aliases [], key Some(keys::ROT47);

    /// Cracks route transpositions: the scytale, the Caesar box and the route ciphers,
    /// which write the text into a grid of columns and read it off by columns, by
    /// columns alternately down and up, by rows or in a spiral. Ciphey tries 2 to 20
    /// columns and every route, ranks the readings by English quadgram statistics and
    /// checks the best few. Text that no reading turns into English gives no candidates.
    ///
    /// ```
    /// // "HELLOWORLD" written in rows of 4 letters and read off column by column
    /// let decoded = ciphey::decoders::route_transposition("HOLEWDLOLR");
    /// let plaintext = decoded.plaintext().unwrap();
    /// assert_eq!(plaintext.text, "HELLOWORLD");
    /// assert_eq!(plaintext.key.as_deref(), Some("4 columns"));
    /// ```
    route_transposition: RouteTranspositionDecoder,
        aliases ["scytale", "caesar_box", "route_cipher"], key None;

    /// Decodes the Standard Galactic Alphabet (Commander Keen, Minecraft's enchanting
    /// table) written with look-alike Unicode symbols, as LingoJam's translator and
    /// Python Ciphey write it. Capitals, digits and punctuation are kept.
    ///
    /// ```
    /// let decoded = ciphey::decoders::standard_galactic_alphabet("⍑ᒷꖎꖎ𝙹 ∴𝙹∷ꖎ↸");
    /// assert_eq!(decoded.candidates[0].text, "hello world");
    /// ```
    standard_galactic_alphabet: StandardGalacticAlphabetDecoder,
        aliases ["galactic", "sga", "enchanting_table"], key None;

    /// Decodes Morse code or binary written with other symbols, trying every way of
    /// mapping up to four symbols onto them. Ciphey calls this decoder
    /// `simplesubstitution`; the simple substitution cipher of the textbooks, where each
    /// letter stands for another, is [`monoalphabetic_substitution`].
    ///
    /// ```
    /// // "hello" in binary, with A for 0 and B for 1
    /// let decoded = ciphey::decoders::symbol_substitution("ABBABAAAABBAABABABBABBAAABBABBAAABBABBBB");
    /// assert_eq!(decoded.plaintext().unwrap().text, "hello");
    /// ```
    symbol_substitution: SubstitutionGenericDecoder, aliases ["substitution_generic"], key None;

    /// Decodes T9 predictive text, where every letter is its phone keypad key pressed once
    /// (`2` for ABC … `9` for WXYZ). Each word is looked up in an English dictionary, so
    /// the most likely readings come back, best first. For keys pressed several times
    /// (`44 33 555`), use [`multi_tap`].
    ///
    /// ```
    /// let decoded = ciphey::decoders::t9("43556 96753");
    /// assert_eq!(decoded.plaintext().unwrap().text, "hello world");
    ///
    /// // Words that share keys come back best first: 4663 is GOOD, GONE, HOME and HOOD
    /// let decoded = ciphey::decoders::t9("4663 6676464");
    /// assert_eq!(decoded.candidates[0].text, "good morning");
    /// ```
    t9: T9Decoder, aliases ["predictive_text"], key None;

    /// Decodes tap code (knock code): each letter is its row and column in a 5×5 square with
    /// K sent as C, written as `row,col` pairs or as knocks such as `.. ...`.
    ///
    /// ```
    /// let decoded = ciphey::decoders::tap_code("2,3 1,5 3,1 3,1 3,4  5,2 3,4 4,2 3,1 1,4");
    /// assert_eq!(decoded.candidates[0].text, "HELLO WORLD");
    /// ```
    tap_code: TapCodeDecoder, aliases ["knock_code", "knock"], key None;

    /// Decodes Unicode escapes: `\u00e9`, `\u{1F600}`, `%u00E9`, `U+00E9` and similar.
    ///
    /// ```
    /// let decoded = ciphey::decoders::unicode_escapes(r"\u0043\u0061\u0066\u00E9\u0020\u2615");
    /// assert_eq!(decoded.candidates[0].text, "Café ☕");
    /// ```
    unicode_escapes: UnicodeEscapeDecoder, aliases ["unicode_escape"], key None;

    /// Decodes Unicode "fancy text", letters and digits written with look-alike Unicode
    /// characters: mathematical bold, italic, script, fraktur, double-struck and
    /// monospace, fullwidth, circled, squared, small capitals, superscripts and regional
    /// indicators. Other characters are kept.
    ///
    /// ```
    /// let decoded = ciphey::decoders::unicode_fancy_text("𝐡𝐞𝐥𝐥𝐨 𝐰𝐨𝐫𝐥𝐝");
    /// assert_eq!(decoded.candidates[0].text, "hello world");
    /// ```
    unicode_fancy_text: UnicodeFancyTextDecoder, aliases ["fancy_text", "fancy_font"], key None;

    /// Decodes URL (percent) encoding.
    ///
    /// ```
    /// let decoded = ciphey::decoders::url("hello%20world%21");
    /// assert_eq!(decoded.candidates[0].text, "hello world!");
    /// ```
    url: URLDecoder, aliases ["percent_encoding", "urlencode"], key None;

    /// Decodes UTF-16 text that an earlier step turned into one character per byte, such as
    /// the Base64 of a PowerShell `-EncodedCommand`. The key is the byte order, `LE` or
    /// `BE`.
    ///
    /// ```
    /// let decoded = ciphey::decoders::utf16(
    ///     "W\0r\0i\0t\0e\0-\0O\0u\0t\0p\0u\0t\0 \0'\0h\0e\0l\0l\0o\0 \0w\0o\0r\0l\0d\0'\0",
    /// );
    /// assert_eq!(decoded.candidates[0].text, "Write-Output 'hello world'");
    /// assert_eq!(decoded.candidates[0].key.as_deref(), Some("LE"));
    /// ```
    utf16: Utf16Decoder, aliases [], key None;

    /// Decodes Uuencode, with or without its `begin` and `end` lines.
    ///
    /// ```
    /// let decoded = ciphey::decoders::uuencode("begin 644 hello.txt\n+:&5L;&\\@=V]R;&0`\n`\nend\n");
    /// assert_eq!(decoded.candidates[0].text, "hello world");
    /// ```
    uuencode: UuencodeDecoder, aliases ["uu"], key None;

    /// Cracks the Vigenère cipher: Ciphey finds the key length and the key from the letter
    /// statistics. To decrypt with a known key, use
    /// [`vigenere_with_key`](super::vigenere_with_key).
    ///
    /// ```
    /// let decoded = ciphey::decoders::vigenere(
    ///     "Altd hlbe tg lrncmwxpo kpxs evl ztrsuicp qptspf. Ivplyprr th pw clhoic pozc",
    /// );
    /// let plaintext = decoded.plaintext().unwrap();
    /// assert_eq!(
    ///     plaintext.text,
    ///     "This text is encrypted with the vigenere cipher. Breaking it is rather easy",
    /// );
    /// assert_eq!(plaintext.key.as_deref(), Some("HELLO"));
    /// ```
    vigenere: VigenereDecoder, aliases ["vigenère"], key Some(keys::VIGENERE);

    /// Cracks XOR with a repeating key of 2 to 40 bytes, given as hex, Base64 or raw bytes.
    /// To decrypt with a known key, use
    /// [`xor_repeating_key_with_key`](super::xor_repeating_key_with_key).
    ///
    /// ```
    /// // Cryptopals set 1 challenge 5
    /// let decoded = ciphey::decoders::xor_repeating_key(
    ///     "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f",
    /// );
    /// let plaintext = decoded.plaintext().unwrap();
    /// assert_eq!(
    ///     plaintext.text,
    ///     "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal",
    /// );
    /// assert_eq!(plaintext.key.as_deref(), Some("ICE"));
    /// ```
    xor_repeating_key: XorRepeatingKeyDecoder, aliases [], key Some(keys::XOR_REPEATING_KEY);

    /// Cracks XOR with a single-byte key, given as hex, Base64 or raw bytes. To decrypt
    /// with a known key, use [`xor_single_byte_with_key`](super::xor_single_byte_with_key).
    ///
    /// ```
    /// // Cryptopals set 1 challenge 3
    /// let decoded = ciphey::decoders::xor_single_byte(
    ///     "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736",
    /// );
    /// let plaintext = decoded.plaintext().unwrap();
    /// assert_eq!(plaintext.text, "Cooking MC's like a pound of bacon");
    /// assert_eq!(plaintext.key.as_deref(), Some("0x58"));
    /// ```
    xor_single_byte: XorSingleByteDecoder, aliases [], key Some(keys::XOR_SINGLE_BYTE);

    /// Decodes the 01248 (Yunying, 云影) cipher: each letter is digits 1, 2, 4 and 8 that add
    /// up to its place in the alphabet, and `0` separates the letters. The output is
    /// unspaced upper case.
    ///
    /// ```
    /// // CTF Wiki's example: 88421 is 8+8+4+2+1 = 23, W
    /// let decoded = ciphey::decoders::yunying("8842101220480224404014224202480122");
    /// assert_eq!(decoded.candidates[0].text, "WELLDONE");
    /// ```
    yunying: YunyingDecoder, aliases ["01248"], key None;

    /// Decodes Z85, ZeroMQ's Base85.
    ///
    /// ```
    /// let decoded = ciphey::decoders::z85("nm=QNzY&b1A+]nf");
    /// assert_eq!(decoded.candidates[0].text, "Hello World!");
    /// ```
    z85: Z85Decoder, aliases [], key None;

    /// Reads a message hidden as zero-width Unicode characters in a cover text, or in a
    /// bare run of them: binary with or without a byte separator (as Steganographr
    /// writes it), 330k's Unicode steganography, zwsp-steg and zero-width-lib. Only the
    /// hidden message comes back, and the key names the scheme.
    ///
    /// ```
    /// // The bits of "hi", U+200B for 0 and U+200C for 1, with U+200D between the bytes
    /// let decoded = ciphey::decoders::zero_width(
    ///     "Nothing\u{200b}\u{200c}\u{200c}\u{200b}\u{200c}\u{200b}\u{200b}\u{200b}\u{200d}\
    ///      \u{200b}\u{200c}\u{200c}\u{200b}\u{200c}\u{200b}\u{200b}\u{200c} to see here",
    /// );
    /// assert_eq!(decoded.candidates[0].text, "hi");
    /// assert_eq!(decoded.candidates[0].key.as_deref(), Some("separator U+200D, U+200B=0"));
    /// ```
    zero_width: ZeroWidthDecoder, aliases ["zero_width_steganography", "zwsp"], key None;

    /// Inflates a zlib stream (RFC 1950) written as Base64 or hex, including git objects
    /// and Flask session cookies. For a git object the key is its type, such as
    /// `git blob`.
    ///
    /// ```
    /// let decoded = ciphey::decoders::zlib(
    ///     "eJwLyUhVKCzNTM5WSCrKL89TSMuvUMgqzS0oVsgvSy1SKAFK5yRWVSqk5KcDAFvcD9o=",
    /// );
    /// assert_eq!(decoded.candidates[0].text, "The quick brown fox jumps over the lazy dog");
    /// ```
    zlib: ZlibDecoder, aliases [], key None;
}
