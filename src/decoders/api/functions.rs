//! One function per decoder, and the table [`decode_with`] and [`list_decoders`] read.
//!
//! To add a decoder, add an entry here. A test fails until every decoder in the search
//! has one.

use super::keys;
use super::{about, crack, Decoded, Entry};
use crate::decoders::a1z26_decoder::A1Z26Decoder;
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
use crate::decoders::decimal_decoder::DecimalDecoder;
use crate::decoders::gzip_decoder::GzipDecoder;
use crate::decoders::hexadecimal_decoder::HexadecimalDecoder;
use crate::decoders::hexdump_decoder::HexdumpDecoder;
use crate::decoders::html_entity_decoder::HtmlEntityDecoder;
use crate::decoders::jwt_decoder::JwtDecoder;
use crate::decoders::mime_encoded_word_decoder::MimeEncodedWordDecoder;
use crate::decoders::monoalphabetic_substitution_decoder::MonoalphabeticSubstitutionDecoder;
use crate::decoders::morse_code::MorseCodeDecoder;
use crate::decoders::multi_tap_decoder::MultiTapDecoder;
use crate::decoders::octal_decoder::OctalDecoder;
use crate::decoders::punycode_decoder::PunycodeDecoder;
use crate::decoders::quoted_printable_decoder::QuotedPrintableDecoder;
use crate::decoders::railfence_decoder::RailfenceDecoder;
use crate::decoders::reverse_decoder::ReverseDecoder;
use crate::decoders::rot47_decoder::ROT47Decoder;
use crate::decoders::substitution_generic_decoder::SubstitutionGenericDecoder;
use crate::decoders::unicode_escape_decoder::UnicodeEscapeDecoder;
use crate::decoders::url_decoder::URLDecoder;
use crate::decoders::utf16_decoder::Utf16Decoder;
use crate::decoders::uuencode_decoder::UuencodeDecoder;
use crate::decoders::vigenere_decoder::VigenereDecoder;
use crate::decoders::xor_repeating_key_decoder::XorRepeatingKeyDecoder;
use crate::decoders::xor_single_byte_decoder::XorSingleByteDecoder;
use crate::decoders::z85_decoder::Z85Decoder;
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

    /// Decodes character codes written in decimal, also as `String.fromCharCode(...)`.
    ///
    /// ```
    /// let decoded = ciphey::decoders::decimal("104 101 108 108 111 32 119 111 114 108 100");
    /// assert_eq!(decoded.candidates[0].text, "hello world");
    /// ```
    decimal: DecimalDecoder, aliases ["charcode"], key None;

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

    /// Decodes character codes written in octal.
    ///
    /// ```
    /// let decoded = ciphey::decoders::octal("150 145 154 154 157 40 167 157 162 154 144");
    /// assert_eq!(decoded.candidates[0].text, "hello world");
    /// ```
    octal: OctalDecoder, aliases ["oct"], key None;

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

    /// Decodes Unicode escapes: `\u00e9`, `\u{1F600}`, `%u00E9`, `U+00E9` and similar.
    ///
    /// ```
    /// let decoded = ciphey::decoders::unicode_escapes(r"\u0043\u0061\u0066\u00E9\u0020\u2615");
    /// assert_eq!(decoded.candidates[0].text, "Café ☕");
    /// ```
    unicode_escapes: UnicodeEscapeDecoder, aliases ["unicode_escape"], key None;

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

    /// Decodes Z85, ZeroMQ's Base85.
    ///
    /// ```
    /// let decoded = ciphey::decoders::z85("nm=QNzY&b1A+]nf");
    /// assert_eq!(decoded.candidates[0].text, "Hello World!");
    /// ```
    z85: Z85Decoder, aliases [], key None;

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
