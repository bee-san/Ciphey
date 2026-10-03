//! Tests for the library API for running one decoder: one per decoder, then keys,
//! [`decode_with`] and the shape of the results.

use std::collections::HashSet;

use super::*;
use crate::checkers::checker_type::{Check, Checker};
use crate::checkers::english::EnglishChecker;
use crate::decoders::DECODER_MAP;
use crate::detection::CheckerKind;
use crate::filtration_system::get_all_decoders;

/// Asserts that Ciphey's checks accepted `expected` as the first candidate.
#[track_caller]
fn assert_plaintext(decoded: &Decoded, expected: &str) {
    let plaintext = decoded
        .plaintext()
        .unwrap_or_else(|| panic!("no plaintext in {decoded:#?}"));
    assert_eq!(plaintext.text, expected, "{decoded:#?}");
    assert!(
        std::ptr::eq(plaintext, &decoded.candidates[0]),
        "the plaintext isn't first: {decoded:#?}"
    );
}

/// Asserts that the first candidate is `expected`, whether or not the checks accepted it.
#[track_caller]
fn assert_first(decoded: &Decoded, expected: &str) {
    let first = decoded
        .candidates
        .first()
        .unwrap_or_else(|| panic!("no candidates in {decoded:#?}"));
    assert_eq!(first.text, expected, "{decoded:#?}");
}

/// The key of the accepted candidate.
#[track_caller]
fn plaintext_key(decoded: &Decoded) -> &str {
    decoded
        .plaintext()
        .and_then(|plaintext| plaintext.key.as_deref())
        .unwrap_or_else(|| panic!("no plaintext with a key in {decoded:#?}"))
}

/// `decode_with` with a key, unwrapped.
#[track_caller]
fn with_key(decoder: &str, text: &str, key: &str) -> Decoded {
    decode_with(decoder, text, &DecodeOptions::with_key(key))
        .unwrap_or_else(|error| panic!("{decoder} with key {key:?}: {error}"))
}

/// The reason `decode_with` gives for rejecting `key`.
#[track_caller]
fn key_error(decoder: &str, text: &str, key: &str) -> String {
    match decode_with(decoder, text, &DecodeOptions::with_key(key)) {
        Err(CipheyError::InvalidKey { reason, .. }) => reason,
        other => panic!("{decoder} with key {key:?} should be an invalid key: {other:?}"),
    }
}

/// English encrypted with the Vigenère key CRYPTII, long enough for the cracker
const VIGENERE_CRYPTII: &str = "Ck jdp tqiyr, p vib'u gsebta gonpgl bq tmkxz uqjr dy bpg \
    vvehamf jsgyikg fd xma mavq. Iam lqdchmqk err wta zckftk xwqi adewz xzqxhv ipu mceg byf \
    rnima qw adgm kgcjh, hxbkdgoxl nqi qtgaqvztxmg bq sjjx ivf pcaewekjf vkmmp; zrh tjqnzrn \
    mw lkjrxgockjf qxbegvl gxl ipu egxmv kj jxfqbgu.";

// Every decoder

#[test]
fn every_decoder_in_the_search_has_a_function() {
    let searched: HashSet<String> = get_all_decoders()
        .components
        .iter()
        .map(|decoder| decoder.get_name().to_string())
        .collect();
    let mapped: HashSet<String> = DECODER_MAP
        .keys()
        .filter(|&&name| name != "Default decoder")
        .map(|name| name.to_string())
        .collect();
    let listed: HashSet<String> = list_decoders()
        .iter()
        .map(|info| info.name.to_string())
        .collect();
    let mut missing: Vec<&String> = searched
        .union(&mapped)
        .filter(|n| !listed.contains(*n))
        .collect();
    missing.sort();
    assert!(
        missing.is_empty(),
        "give {missing:?} a function in src/decoders/api/functions.rs (decoder_functions!)"
    );
    assert_eq!(listed, searched, "list_decoders and the search differ");
    assert_eq!(listed, mapped, "list_decoders and DECODER_MAP differ");
    assert_eq!(
        list_decoders().len(),
        listed.len(),
        "a decoder is listed twice"
    );
}

#[test]
fn decoders_are_described_by_themselves_and_sorted() {
    let functions: Vec<&str> = list_decoders().iter().map(|info| info.function).collect();
    let mut sorted = functions.clone();
    sorted.sort_unstable();
    assert_eq!(functions, sorted);

    for info in list_decoders() {
        let decoder = DECODER_MAP[info.name].get::<()>();
        assert_eq!(info.description, decoder.get_description(), "{}", info.name);
        assert_eq!(info.link, decoder.get_link(), "{}", info.name);
        assert_eq!(&info.tags, decoder.get_tags(), "{}", info.name);
        assert!(!info.description.is_empty(), "{}", info.name);
    }
}

#[test]
fn names_and_aliases_are_unique() {
    let mut seen = HashSet::new();
    for info in list_decoders() {
        // The name and function may be the same name, but no two decoders may share one
        let own: HashSet<String> = info.names().map(normalise).collect();
        for name in own {
            assert!(seen.insert(name.clone()), "{name:?} names two decoders");
        }
        assert!(
            decoder_info(info.function).is_some_and(|found| found.name == info.name),
            "{}",
            info.function
        );
    }
}

#[test]
fn crackers_with_keys_take_keys() {
    let keyed: Vec<&str> = list_decoders()
        .iter()
        .filter(|info| info.accepts_key())
        .map(|info| info.function)
        .collect();
    assert_eq!(
        keyed,
        [
            "affine",
            "caesar",
            "monoalphabetic_substitution",
            "railfence",
            "rot47",
            "vigenere",
            "xor_repeating_key",
            "xor_single_byte",
        ]
    );
    for info in list_decoders() {
        assert_eq!(info.accepts_key(), info.key_format.is_some());
    }
}

// One test per decoder

#[test]
fn a1z26_decodes() {
    assert_first(&a1z26("1-20-20-1-3-11-1-20-4-1-23-14"), "ATTACKATDAWN");
    assert!(a1z26("1 2 3 x 4 5 6").is_empty());
}

#[test]
fn affine_cracks() {
    let decoded = affine("Jffg jf dmgfs gaf gxtd edsgp");
    assert_plaintext(&decoded, "Meet me after the toga party");
    assert_eq!(plaintext_key(&decoded), "a=7, b=3");
}

#[test]
fn ascii85_decodes() {
    assert_plaintext(&ascii85("<~BOu!rD]j7BEbo7~>"), "hello world");
    assert_plaintext(&ascii85("BOu!rD]j7BEbo7"), "hello world");
}

#[test]
fn atbash_decodes() {
    assert_plaintext(
        &atbash("Draziwh olev zgyzhs kfaaovh"),
        "Wizards love atbash puzzles",
    );
}

#[test]
fn backslash_escapes_decode() {
    assert_plaintext(
        &backslash_escapes(r"\124\150\145 \x71\x75\x69\x63\x6b brown fox"),
        "The quick brown fox",
    );
}

#[test]
fn baconian_decodes() {
    let decoded = baconian("10001 00100 00010 10000 00100 10010");
    assert_plaintext(&decoded, "SECRET");
    assert_eq!(plaintext_key(&decoded), "standard, 0=A 1=B");
}

#[test]
fn base100_decodes() {
    assert_plaintext(&base100("👟👜👣👣👦🐗👮👦👩👣👛"), "hello world");
}

#[test]
fn base32_decodes() {
    assert_plaintext(
        &base32("KRUGKIDROVUWG2ZAMJZG653OEBTG66BANJ2W24DTEBXXMZLSEB2GQZJANRQXU6JAMRXWO==="),
        "The quick brown fox jumps over the lazy dog",
    );
}

#[test]
fn base36_decodes() {
    assert_plaintext(&base36("fuvrsivvnfrbjwajo"), "hello world");
    assert_plaintext(&base36("FUVRSIVVNFRBJWAJO"), "hello world");
}

#[test]
fn base58_bitcoin_decodes() {
    assert_plaintext(&base58_bitcoin("StV1DL6CwTryKyV"), "hello world");
}

#[test]
fn base58_flickr_decodes() {
    assert_plaintext(&base58_flickr("rTu1dk6cWsRYjYu"), "hello world");
}

#[test]
fn base58_monero_decodes() {
    assert_plaintext(&base58_monero("StV1DL6CwTryKyV"), "hello world");
}

#[test]
fn base58_ripple_decodes() {
    assert_plaintext(&base58_ripple("StVrDLaUATiyKyV"), "hello world");
}

#[test]
fn base64_decodes() {
    assert_plaintext(&base64("aGVsbG8gd29ybGQ="), "hello world");
    // URL-safe Base64
    assert_first(
        &base64("SXMgdGhpcyBVUkwtc2FmZT8gWWVzOiB-fn4-Pj4"),
        "Is this URL-safe? Yes: ~~~>>>",
    );
}

#[test]
fn base64_alt_decodes() {
    let decoded = base64_alt("J4VZ653pOKBf647mPrRi64NjS0/eRKpkQm/jRaJm65FcNG/gMLdt64FjNk==");
    assert_plaintext(&decoded, "The quick brown fox jumps over the lazy dog");
    assert_eq!(plaintext_key(&decoded), "itoa64 / crypt(3)");
}

#[test]
fn base65536_decodes() {
    assert_first(
        &base65536("𒅓鹨𖡮𒀠啦ꍢ顡啫𓍱𓁡𠁴唬𓍪鱤啥𖥭𔐠𔕯ᔮ"),
        "Sphinx of black quartz, judge my vow.",
    );
}

#[test]
fn base85_decodes() {
    assert_first(
        &base85("Q*dZ$Zg?PXW*}m0VPk6`adlyGbb2fxYIS61Wgu;NAa-weE&"),
        "Sphinx of black quartz, judge my vow.",
    );
}

#[test]
fn base91_decodes() {
    assert_plaintext(&base91("TPwJh>Io2Tv!lE"), "hello world");
}

#[test]
fn base92_decodes() {
    assert_plaintext(&base92("Fc_$aOTdKnsM*k"), "hello world");
}

#[test]
fn baudot_decodes() {
    let decoded = baudot("10100 00001 10010 10010 11000 00100 10011 11000 01010 10010 01001");
    assert_plaintext(&decoded, "HELLO WORLD");
    assert_eq!(plaintext_key(&decoded), "MSB-first, US-TTY");
}

#[test]
fn big_integer_decodes() {
    assert_plaintext(
        &big_integer(
            "flag = 50937517511040843800057610630687734629648772740622533002167079526478786571835272839786109",
        ),
        "flag{long_to_bytes_is_not_encryption}",
    );
    assert_eq!(
        decoder_info("long_to_bytes").unwrap().name,
        "Big integer to bytes"
    );
}

#[test]
fn binary_decodes() {
    assert_plaintext(
        &binary("01010011011100000110100001101001011011100111100000100000011011110110011000100000011000100110110001100001011000110110101100100000011100010111010101100001011100100111010001111010"),
        "Sphinx of black quartz",
    );
}

#[test]
fn braille_decodes() {
    assert_plaintext(&braille("⠓⠑⠇⠇⠕⠀⠺⠕⠗⠇⠙"), "hello world");
}

#[test]
fn brainfuck_runs() {
    assert_first(
        &brainfuck("++++++++[>++++[>++>+++>+++>+<<<<-]>+>+>->>+[<]<-]>>.>---.+++++++..+++.>>.<-.<.+++.------.--------.>>+.>++."),
        "Hello World!\n",
    );
}

#[test]
fn caesar_cracks() {
    let decoded = caesar("Ijkjsi ymj jfxy bfqq tk ymj hfxyqj");
    assert_plaintext(&decoded, "Defend the east wall of the castle");
    // The shift that decodes it: 26 - 5
    assert_eq!(plaintext_key(&decoded), "21");
}

#[test]
fn citrix_ctx1_decodes() {
    assert_plaintext(
        &citrix_ctx1("MNGIKIANMEGBKIANMHGCOHECJADFPPFKINCIOBEEIFCA"),
        "hello world",
    );
}

#[test]
fn decimal_decodes() {
    assert_plaintext(
        &decimal("String.fromCharCode(102,108,97,103,123,100,101,99,105,109,97,108,125)"),
        "flag{decimal}",
    );
}

#[test]
fn dtmf_decodes() {
    // LemmeKnow takes the keys for a phone number
    assert_plaintext(
        &dtmf("697-1209 852-1336 941-1336 941-1336 770-1336 770-1336 770-1336 697-1209 697-1336 697-1477 770-1209"),
        "18005551234",
    );
    // dCode's example: the keys aren't identified, but they are still the first candidate
    assert_first(
        &dtmf("1633-941/1633-852/1336-941/1633-941/1477-697"),
        "DC0D3",
    );
}

#[test]
fn gzip_decompresses() {
    assert_plaintext(
        &gzip("1f8b08000000000002ff0bc94855484ecc4e55c82c564854c8c94cd551482a2d5128c900f2535293f35332f3d2417245a98939004bd5f6822c000000"),
        "The cake is a lie, but this decoding is real",
    );
}

#[test]
fn hexadecimal_decodes() {
    assert_plaintext(
        &hexadecimal("54686520717569636B2062726F776E20666F78206A756D7073206F76657220746865206C617A7920646F67"),
        "The quick brown fox jumps over the lazy dog",
    );
}

#[test]
fn hexdump_decodes() {
    assert_plaintext(
        &hexdump(
            "00000000  48 65 6c 6c 6f 2c 20 57  6f 72 6c 64 21           |Hello, World!|\n0000000d",
        ),
        "Hello, World!",
    );
}

#[test]
fn html_entities_decode() {
    assert_first(
        &html_entities("&#72;&#101;&#108;&#108;&#111;&#32;&#38;&#97;&#109;&#112;&#59;&#32;&#103;&#111;&#111;&#100;&#98;&#121;&#101;"),
        "Hello &amp; goodbye",
    );
}

#[test]
fn jwt_decodes() {
    let decoded =
        jwt("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWxpY2UiLCJhZG1pbiI6dHJ1ZX0.");
    assert_plaintext(&decoded, r#"{"user":"alice","admin":true}"#);
    assert_eq!(plaintext_key(&decoded), r#"{"alg":"none","typ":"JWT"}"#);
    let detection = decoded.candidates[0].detection.as_ref().unwrap();
    assert_eq!(detection.checker, CheckerKind::JwtStructure);
    assert_eq!(detection.description, "JSON Web Token");
}

#[test]
fn mime_encoded_word_decodes() {
    assert_first(
        &mime_encoded_word("=?utf-8?b?Q2Fmw6kgb2zDqSDigJMgcsOpc3Vtw6k=?="),
        "Café olé – résumé",
    );
    assert_first(
        &mime_encoded_word("=?ISO-8859-1?Q?Gr=FC=DFe_aus_K=F6ln?="),
        "Grüße aus Köln",
    );
}

#[test]
fn monoalphabetic_substitution_cracks() {
    // Not the text of the doc test: the cracker remembers the letter patterns it has seen
    let decoded = monoalphabetic_substitution(
        "Qda ifeozox bzk klv otk z pfkcia rablrao ex kzja, pl qllip qdzq zioazrx hklv vdzq \
         qdax zoa illhfkc zq kl ilkcao dzua ql pazobd slo fq. Haxp vloh qll, vdak xlt dzua \
         qdaj.",
    );
    assert_plaintext(
        &decoded,
        "The library can now run a single decoder by name, so tools that already know what \
         they are looking at no longer have to search for it. Keys work too, when you have \
         them.",
    );
    assert_eq!(plaintext_key(&decoded), "ZEBRASCDF?HIJKL??OPQTUV?X?");
}

#[test]
fn morse_decodes() {
    assert_plaintext(
        &morse(".---- ----. ..--- .-.-.- .---- -.... ---.. .-.-.- ----- .-.-.- .----"),
        "192.168.0.1",
    );
}

#[test]
fn multi_tap_decodes() {
    assert_plaintext(
        &multi_tap("44-33-555-555-666 9-666-777-555-3"),
        "HELLO WORLD",
    );
}

#[test]
fn nato_phonetic_decodes() {
    assert_plaintext(
        &nato_phonetic("Hotel Echo Lima Lima Oscar  Whiskey Oscar Romeo Lima Delta "),
        "hello world",
    );
    assert_first(&nato_phonetic("Delta-Hotel-Niner-Eight"), "dh98");
    assert!(nato_phonetic("hello world").is_empty());
}

#[test]
fn octal_decodes() {
    assert_plaintext(
        &octal("124 150 145 40 161 165 151 143 153 40 142 162 157 167 156 40 146 157 170 40 152 165 155 160 163 40 157 166 145 162 40 164 150 145 40 154 141 172 171 40 144 157 147"),
        "The quick brown fox jumps over the lazy dog",
    );
}

#[test]
fn polybius_decodes() {
    let decoded = polybius("DF AX FA FA FG  XD FG GD FA AG");
    assert_plaintext(&decoded, "HELLO WORLD");
    assert_eq!(
        plaintext_key(&decoded),
        "5x5 I=J, row-column, letters ADFGX"
    );
    // Unidentified: both row-column readings come back, without keys
    let decoded = polybius("25 45 32 35  34 51 15 42");
    assert!(decoded.plaintext().is_none(), "{decoded:#?}");
    let texts: Vec<&str> = decoded.candidates.iter().map(|c| c.text.as_str()).collect();
    assert_eq!(texts, ["KUMP OVER", "JUMP OVER"]);
}

#[test]
fn punycode_decodes() {
    assert_first(&punycode("xn--bcher-kva"), "bücher");
    assert_first(
        &punycode("Schne Gre aus Mnchen-iwb41ctei"),
        "Schöne Grüße aus München",
    );
}

#[test]
fn quoted_printable_decodes() {
    assert_first(
        &quoted_printable("Gr=C3=BC=C3=9Fe aus K=C3=B6ln, sch=C3=B6ne Gr=C3=BC=C3=9Fe"),
        "Grüße aus Köln, schöne Grüße",
    );
}

#[test]
fn railfence_cracks() {
    assert_plaintext(&railfence("Hoo!el,Wrdl l"), "Hello, World!");
}

#[test]
fn reverse_decodes() {
    assert_plaintext(&reverse("sdrawkcab si siht"), "this is backwards");
}

#[test]
fn rot47_cracks() {
    assert_plaintext(&rot47("wt{{~ (~#{s"), "HELLO WORLD");
}

#[test]
fn standard_galactic_alphabet_decodes() {
    assert_plaintext(&standard_galactic_alphabet("⍑ᒷꖎꖎ𝙹 ∴𝙹∷ꖎ↸"), "hello world");
    let decoded = decode_with(
        "galactic",
        "ℸ ̣ ⍑ᒷ ᑑ⚍╎ᓵꖌ ʖ∷𝙹∴リ ⎓𝙹 ̇/",
        &DecodeOptions::default(),
    )
    .expect("galactic is an alias");
    assert_plaintext(&decoded, "the quick brown fox");
}

#[test]
fn symbol_substitution_decodes() {
    // "hello" in binary, with A for 0 and B for 1
    assert_plaintext(
        &symbol_substitution("ABBABAAAABBAABABABBABBAAABBABBAAABBABBBB"),
        "hello",
    );
}

#[test]
fn tap_code_decodes() {
    assert_plaintext(
        &tap_code(".. ...  . .....  ... .  ... .  ... ...."),
        "HELLO",
    );
    assert_eq!(decoder_info("knock code").unwrap().name, "Tap Code");
}

#[test]
fn unicode_escapes_decode() {
    assert_first(
        &unicode_escapes(r"na\u00efve r\u{e9}sum\U000000E9 \U0001F600"),
        "naïve résumé 😀",
    );
}

#[test]
fn url_decodes() {
    assert_first(
        &url("https%3A%2F%2Fexample.com%2F%3Fq%3Dhello%20world%26x%3D1"),
        "https://example.com/?q=hello world&x=1",
    );
    assert_plaintext(&url("hello%20world%21"), "hello world!");
}

#[test]
fn utf16_decodes() {
    let decoded = utf16(
        "\0T\0h\0e\0 \0q\0u\0i\0c\0k\0 \0b\0r\0o\0w\0n\0 \0f\0o\0x\0 \0j\0u\0m\0p\0s\0 \0o\0v\0e\0r\0 \0t\0h\0e\0 \0l\0a\0z\0y\0 \0d\0o\0g",
    );
    assert_plaintext(&decoded, "The quick brown fox jumps over the lazy dog");
    assert_eq!(plaintext_key(&decoded), "BE");
}

#[test]
fn uuencode_decodes() {
    assert_plaintext(&uuencode("+:&5L;&\\@=V]R;&0"), "hello world");
}

#[test]
fn vigenere_cracks() {
    let decoded = vigenere(VIGENERE_CRYPTII);
    assert_plaintext(
        &decoded,
        "At low light, a cat's pupils expand to cover most of the exposed surface of its \
         eyes. The domestic cat has rather poor color vision and only two types of cone \
         cells, optimized for sensitivity to blue and yellowish green; its ability to \
         distinguish between red and green is limited.",
    );
    assert_eq!(plaintext_key(&decoded), "CRYPTII");
    // Short texts give the key search too little to go on
    assert!(vigenere("Lxfopv ef rnhr").plaintext().is_none());
}

#[test]
fn xor_repeating_key_cracks() {
    let decoded = xor_repeating_key(
        "32111713061f530417520115040b4f52041a174501000c1a1445171a00541e041301451b1545171a00541d0a11060d11010b430204070045141b111c531c0c074b",
    );
    assert_plaintext(
        &decoded,
        "Attack at dawn, and bring the maps of the northern pass with you.",
    );
    assert_eq!(plaintext_key(&decoded), "secret");
}

#[test]
fn xor_single_byte_cracks() {
    let decoded = xor_single_byte("Z09PXgpHTwpIUwpeQk8KRUZOCkVLQQpeWE9PCkteCkRFRUQ=");
    assert_plaintext(&decoded, "Meet me by the old oak tree at noon");
    assert_eq!(plaintext_key(&decoded), "0x2a");
}

#[test]
fn z85_decodes() {
    assert_plaintext(&z85("nm=QNzY&b1A+]nf"), "Hello World!");
}

#[test]
fn zero_width_decodes() {
    // The bits of each byte, U+200B for 0 and U+200C for 1, with U+200D between the
    // bytes, hidden in a cover text (https://github.com/bee-san/Ciphey/issues/973)
    let hidden = "hello world"
        .bytes()
        .map(|byte| {
            format!("{byte:08b}")
                .replace('0', "\u{200b}")
                .replace('1', "\u{200c}")
        })
        .collect::<Vec<_>>()
        .join("\u{200d}");
    let decoded = zero_width(&format!("Nothing{hidden} to see here"));
    assert_plaintext(&decoded, "hello world");
    assert_eq!(plaintext_key(&decoded), "separator U+200D, U+200B=0");
    assert_eq!(decoder_info("zwsp").unwrap().name, "Zero-width");
}

#[test]
fn zlib_inflates() {
    assert_plaintext(
        &zlib("eJxzzizISK1UyMxLy0ksSS1WqMrJTFIoLilKTcwtVkjLL1KozC8FAPwuDa0="),
        "Ciphey inflates zlib streams for you",
    );
}

// Keys

#[test]
fn caesar_decrypts_with_a_key() {
    let decoded = caesar_with_key("Ijkjsi ymj jfxy bfqq tk ymj hfxyqj", -5);
    assert_plaintext(&decoded, "Defend the east wall of the castle");
    assert_eq!(plaintext_key(&decoded), "21");
    // Shifts are taken mod 26
    assert_eq!(caesar_with_key("Uryyb", 13), caesar_with_key("Uryyb", 39));
    assert_first(&caesar_with_key("Uryyb", 0), "Uryyb");
}

#[test]
fn rot47_decrypts_with_a_key() {
    let decoded = rot47_with_key("%96 \"F:4< qC@H? u@I yF>AD ~G6C %96 {2KJ s@8]", 47);
    assert_plaintext(&decoded, "The Quick Brown Fox Jumps Over The Lazy Dog.");
    assert_eq!(rot47_with_key("abc", 47), rot47_with_key("abc", 47 + 94));
    assert_eq!(rot47_with_key("abc", -47), rot47_with_key("abc", 47));
}

#[test]
fn vigenere_decrypts_with_a_key() {
    let decoded = vigenere_with_key(
        "Lxfopv ef rnhr, fvr prqal hmxz apzqf fpi gg pzqubt",
        "lemon",
    )
    .unwrap();
    assert_plaintext(
        &decoded,
        "Attack at dawn, the enemy will never see us coming",
    );
    assert_eq!(plaintext_key(&decoded), "LEMON");
    for key in ["", "le mon", "l3mon", "lémon"] {
        assert!(
            matches!(
                vigenere_with_key("text", key),
                Err(CipheyError::InvalidKey {
                    decoder: "Vigenere",
                    ..
                })
            ),
            "{key:?}"
        );
    }
}

#[test]
fn affine_decrypts_with_a_key() {
    let decoded = affine_with_key("Jffg jf dmgfs gaf gxtd edsgp", 7, 3).unwrap();
    assert_plaintext(&decoded, "Meet me after the toga party");
    assert_eq!(plaintext_key(&decoded), "a=7, b=3");
    // Taken mod 26
    assert_eq!(
        affine_with_key("Jffg", 7 + 26, 3 + 52).unwrap().candidates[0]
            .key
            .as_deref(),
        Some("a=7, b=3")
    );
    for a in [0, 2, 13, 26, 28] {
        assert!(
            matches!(
                affine_with_key("text", a, 1),
                Err(CipheyError::InvalidKey {
                    decoder: "Affine",
                    ..
                })
            ),
            "a = {a}"
        );
    }
}

#[test]
fn railfence_decrypts_with_a_key() {
    let decoded = railfence_with_key("eo, cWr cvd eaneeadseefeto irl ", 4, 1).unwrap();
    assert_first(&decoded, "We are discovered, flee at once");
    assert_eq!(
        decoded.candidates[0].key.as_deref(),
        Some("rails=4, offset=1")
    );
    // Offsets are taken mod the zigzag's length
    assert_eq!(
        railfence_with_key("eo, cWr cvd eaneeadseefeto irl ", 4, 7).unwrap(),
        decoded
    );
    for rails in [0, 1, 32] {
        assert!(
            matches!(
                railfence_with_key("eo, cWr cvd eaneeadseefeto irl ", rails, 0),
                Err(CipheyError::InvalidKey {
                    decoder: "railfence",
                    ..
                })
            ),
            "{rails} rails"
        );
    }
}

#[test]
fn xor_single_byte_decrypts_with_a_key() {
    // Base64
    let decoded =
        xor_single_byte_with_key("Z09PXgpHTwpIUwpeQk8KRUZOCkVLQQpeWE9PCkteCkRFRUQ=", 0x2a);
    assert_plaintext(&decoded, "Meet me by the old oak tree at noon");
    assert_eq!(plaintext_key(&decoded), "0x2a");

    // Hex, however short
    assert_first(&xor_single_byte_with_key("4243", 0x20), "bc");

    // Valid Base64 and text: both readings come back, the plaintext first
    let decoded = xor_single_byte_with_key("test", 0x20);
    assert_eq!(decoded.candidates.len(), 2, "{decoded:#?}");
    assert_plaintext(&decoded, "TEST");

    // Bytes that aren't UTF-8 come back as Latin-1
    assert_first(&xor_single_byte_with_key("41", 0x80), "\u{c1}");
}

#[test]
fn xor_repeating_key_decrypts_with_a_key() {
    let decoded = xor_repeating_key_with_key(
        "32111713061f530417520115040b4f52041a174501000c1a1445171a00541e041301451b1545171a00541d0a11060d11010b430204070045141b111c531c0c074b",
        b"secret",
    )
    .unwrap();
    assert_plaintext(
        &decoded,
        "Attack at dawn, and bring the maps of the northern pass with you.",
    );
    assert_eq!(plaintext_key(&decoded), "secret");
    // Keys that aren't text are shown in hex
    assert_eq!(
        xor_repeating_key_with_key("0102", &[0, 0xff])
            .unwrap()
            .candidates[0]
            .key
            .as_deref(),
        Some("0x00ff")
    );
    assert!(matches!(
        xor_repeating_key_with_key("0102", &[]),
        Err(CipheyError::InvalidKey { .. })
    ));
}

#[test]
fn monoalphabetic_substitution_decrypts_with_a_key() {
    let decoded =
        monoalphabetic_substitution_with_key("Itssg vgksr", "qwertyuiopasdfghjklzxcvbnm").unwrap();
    assert_plaintext(&decoded, "Hello world");
    assert_eq!(plaintext_key(&decoded), "QWERTYUIOPASDFGHJKLZXCVBNM");

    // The key the cracker reports, with ? for letters that aren't used, works too
    let text = "Qda ifeozox bzk klv otk z pfkcia rablrao.";
    let decoded = monoalphabetic_substitution_with_key(text, "ZEBRASCDF?HIJKL??OPQTUV?X?").unwrap();
    assert_first(&decoded, "The library can now run a single decoder.");

    let invalid = |text, key| match monoalphabetic_substitution_with_key(text, key) {
        Err(CipheyError::InvalidKey { reason, .. }) => reason,
        other => panic!("{key:?}: {other:?}"),
    };
    assert!(invalid("Itssg", "QWERTY").contains("26 letters"));
    assert!(invalid("Itssg", "QWERTYUIOPASDFGHJKLZXCVBN1").contains("26 letters"));
    assert!(invalid("Itssg", "QWERTYUIOPASDFGHJKLZXCVBNQ").contains("Q is in the key twice"));
    // Nothing decrypts to Z, so M (a cipher letter missing from the key) can't be read
    assert!(monoalphabetic_substitution_with_key("Itssg", "QWERTYUIOPASDFGHJKLZXCVBN?").is_ok());
    assert!(invalid("Mtssg", "QWERTYUIOPASDFGHJKLZXCVBN?").contains("which letter M stands for"));
}

// decode_with

#[test]
fn decode_with_knows_names_functions_and_aliases() {
    for name in ["Base64", "base64", "b64", " B-6_4 ", "BASE64"] {
        let decoded = decode_with(name, "aGVsbG8gd29ybGQ=", &DecodeOptions::default()).unwrap();
        assert_eq!(decoded.decoder, "Base64", "{name:?}");
        assert_plaintext(&decoded, "hello world");
    }
    for name in ["Single-byte XOR", "single_byte_xor", "xor_single_byte"] {
        assert_eq!(
            decoder_info(name).unwrap().name,
            "Single-byte XOR",
            "{name:?}"
        );
    }
    assert_eq!(decoder_info("Vigenère").unwrap().name, "Vigenere");
    assert_eq!(decoder_info("rot13").unwrap().name, "caesar");
    assert_eq!(decoder_info("hex").unwrap().name, "Hexadecimal");
    assert_eq!(decoder_info("morse_code").unwrap().name, "Morse Code");
    // Ciphey's name for the symbol substitution decoder, not the monoalphabetic cracker
    assert_eq!(
        decoder_info("simple substitution").unwrap().function,
        "symbol_substitution"
    );

    // The same result as the decoder's function
    assert_eq!(
        decode_with("caesar", "Uryyb jbeyq", &DecodeOptions::default()).unwrap(),
        caesar("Uryyb jbeyq")
    );
}

#[test]
fn decode_with_reports_unknown_decoders_and_keys() {
    assert!(matches!(
        decode_with("base63", "text", &DecodeOptions::default()),
        Err(CipheyError::UnknownDecoder { name }) if name == "base63"
    ));
    assert!(decoder_info("").is_none());
    assert!(matches!(
        decode_with("base64", "text", &DecodeOptions::with_key("13")),
        Err(CipheyError::KeyNotSupported { decoder: "Base64" })
    ));
}

#[test]
fn decode_with_reads_every_key_format() {
    // Caesar and ROT47: whole numbers
    assert_plaintext(&with_key("caesar", "Uryyb jbeyq", "13"), "Hello world");
    assert_plaintext(&with_key("rot13", "Khoor zruog", " -3 "), "Hello world");
    assert!(key_error("caesar", "Uryyb", "thirteen").contains("isn't a whole number"));
    assert_plaintext(&with_key("rot47", "wt{{~ (~#{s", "47"), "HELLO WORLD");

    // Vigenère: letters
    let text = "Lxfopv ef rnhr, fvr prqal hmxz apzqf fpi gg pzqubt";
    assert_plaintext(
        &with_key("vigenere", text, " lemon "),
        "Attack at dawn, the enemy will never see us coming",
    );
    assert!(key_error("vigenere", text, "lemon2").contains("letters"));

    // Affine: a and b, in order or by name
    let text = "Jffg jf dmgfs gaf gxtd edsgp";
    for key in [
        "a=7, b=3",
        "7,3",
        "7 3",
        "b=3 a=7",
        "(7, 3)",
        "A = 7 ; B = 3",
        "b=3, 7",
    ] {
        assert_plaintext(
            &with_key("affine", text, key),
            "Meet me after the toga party",
        );
    }
    for key in [
        "7", "a=7", "a=7, c=3", "7, 3, 1", "a=7, a=3", "a=x, b=3", "",
    ] {
        assert!(!key_error("affine", text, key).is_empty(), "{key:?}");
    }
    assert!(key_error("affine", text, "a=2, b=3").contains("coprime"));

    // Rail fence: rails, and the offset if it isn't 0
    let text = "eo, cWr cvd eaneeadseefeto irl ";
    for key in ["rails=4, offset=1", "4,1", "4 1", "offset=1 rails=4"] {
        assert_first(
            &with_key("railfence", text, key),
            "We are discovered, flee at once",
        );
    }
    assert_plaintext(
        &with_key("rail_fence", "Hoo!el,Wrdl l", "3"),
        "Hello, World!",
    );
    assert!(key_error("railfence", text, "offset=1").contains("how many rails"));
    assert!(key_error("railfence", text, "1").contains("at least 2 rails"));

    // Single-byte XOR: a number, hex or a character
    let text = "Z09PXgpHTwpIUwpeQk8KRUZOCkVLQQpeWE9PCkteCkRFRUQ=";
    for key in ["0x2a", "0X2A", "42", "*"] {
        assert_plaintext(
            &with_key("xor_single_byte", text, key),
            "Meet me by the old oak tree at noon",
        );
    }
    for key in ["256", "0x100", "**", "0x", ""] {
        assert!(
            key_error("Single-byte XOR", text, key).contains("isn't a byte"),
            "{key:?}"
        );
    }

    // Repeating-key XOR: text, or hex after 0x
    let text = "32111713061f530417520115040b4f52041a174501000c1a1445171a00541e041301451b1545171a00541d0a11060d11010b430204070045141b111c531c0c074b";
    for key in ["secret", "0x736563726574"] {
        assert_plaintext(
            &with_key("xor_repeating_key", text, key),
            "Attack at dawn, and bring the maps of the northern pass with you.",
        );
    }
    for key in ["0x", "0x736"] {
        assert!(
            key_error("xor_repeating_key", text, key).contains("whole bytes"),
            "{key:?}"
        );
    }
    // Not hex after 0x: the key is that text
    assert_eq!(
        with_key("xor_repeating_key", "0102", "0xZZ").candidates[0]
            .key
            .as_deref(),
        Some("0xZZ")
    );

    // Monoalphabetic substitution: 26 letters
    assert_plaintext(
        &with_key("cryptogram", "Itssg vgksr", " QWERTYUIOPASDFGHJKLZXCVBNM "),
        "Hello world",
    );
}

#[test]
fn cracked_keys_decrypt_again() {
    // The key a cracker reports gives the same plaintext with decode_with
    let cases = [
        ("caesar", "Ijkjsi ymj jfxy bfqq tk ymj hfxyqj"),
        ("affine", "Jffg jf dmgfs gaf gxtd edsgp"),
        ("vigenere", VIGENERE_CRYPTII),
        ("xor_single_byte", "Z09PXgpHTwpIUwpeQk8KRUZOCkVLQQpeWE9PCkteCkRFRUQ="),
        (
            "xor_repeating_key",
            "32111713061f530417520115040b4f52041a174501000c1a1445171a00541e041301451b1545171a00541d0a11060d11010b430204070045141b111c531c0c074b",
        ),
    ];
    for (decoder, text) in cases {
        let cracked = decode_with(decoder, text, &DecodeOptions::default()).unwrap();
        let plaintext = cracked.plaintext().unwrap_or_else(|| panic!("{decoder}"));
        let decrypted = with_key(decoder, text, plaintext.key.as_deref().unwrap());
        assert_eq!(decrypted.candidates[0].text, plaintext.text, "{decoder}");
        assert_eq!(decrypted.candidates[0].key, plaintext.key, "{decoder}");
    }
}

// What comes back

#[test]
fn decodings_that_are_not_plaintext_come_back_unmarked() {
    let decoded = caesar("xkcd");
    assert_eq!(decoded.candidates.len(), 25, "{decoded:#?}");
    assert!(decoded.plaintext().is_none());
    assert!(decoded
        .candidates
        .iter()
        .all(|c| c.key.is_none() && !c.is_plaintext()));
    assert!(
        decoded.candidates.iter().any(|c| c.text == "kxpq"),
        "ROT13 is among them"
    );

    // A Base64 decoding that isn't English is still the decoding
    let decoded = base64("AAECAwQFBgc=");
    assert_first(&decoded, "\0\u{1}\u{2}\u{3}\u{4}\u{5}\u{6}\u{7}");
    assert!(decoded.plaintext().is_none());
}

#[test]
fn text_in_another_format_gives_nothing() {
    for decoded in [
        base64("!!!"),
        hexadecimal("xyz"),
        jwt("hello"),
        gzip("hello"),
        url(""),
    ] {
        assert!(decoded.is_empty(), "{decoded:#?}");
        assert!(decoded.plaintext().is_none());
    }
}

#[test]
fn empty_and_repeated_decodings_are_dropped() {
    let decoder = Decoder::<crate::decoders::caesar_decoder::CaesarDecoder>::new();
    let mut result = CrackResult::new(&decoder, "text".to_string());
    result.unencrypted_text = Some(vec![
        String::new(),
        "one".to_string(),
        "two".to_string(),
        "one".to_string(),
    ]);
    let decoded = Decoded::from_crack_result(result);
    let texts: Vec<&str> = decoded.candidates.iter().map(|c| c.text.as_str()).collect();
    assert_eq!(texts, ["one", "two"]);
    assert_eq!(decoded.decoder, "caesar");
}

#[test]
fn keys_are_shared_out_between_candidates() {
    assert_eq!(
        candidate_keys(Some("a=5, b=8"), 1),
        [Some("a=5, b=8".into())]
    );
    assert_eq!(
        candidate_keys(Some("0x01, 0x02"), 2),
        [Some("0x01".into()), Some("0x02".into())]
    );
    assert_eq!(candidate_keys(Some("0x01, 0x02"), 3), [None, None, None]);
    assert_eq!(candidate_keys(None, 2), [None, None]);
    assert!(candidate_keys(Some("key"), 0).is_empty());
}

#[test]
fn accepted_decodings_say_what_they_are() {
    let decoded = hexadecimal("3139322e3136382e302e31");
    let detection = decoded.plaintext().unwrap().detection.as_ref().unwrap();
    assert_eq!(detection.checker, CheckerKind::LemmeKnow);
    assert_eq!(
        detection.description,
        "Internet Protocol (IP) Address Version 4"
    );
    assert_eq!(detection.confidence, Some(0.7));

    let decoded = base64("aGVsbG8gdGhlcmUgZ2VuZXJhbA==");
    let detection = decoded.plaintext().unwrap().detection.as_ref().unwrap();
    assert_eq!(detection.checker, CheckerKind::English);
    assert_eq!(detection.description, "Words");

    // Ciphers check at their own sensitivity: Caesar's is the strictest
    let strict =
        Checker::<EnglishChecker>::new().with_sensitivity(gibberish_or_not::Sensitivity::Low);
    let plaintext = caesar("Uryyb jbeyq").plaintext().unwrap().text.clone();
    assert!(strict.check(&plaintext).is_identified);
}

#[test]
fn results_serialize_to_json() {
    let decoded = caesar_with_key("Uryyb jbeyq", 13);
    assert_eq!(
        serde_json::to_value(&decoded).unwrap(),
        serde_json::json!({
            "decoder": "caesar",
            "candidates": [{
                "text": "Hello world",
                "key": "13",
                "detection": {"checker": "english", "description": "Words", "confidence": null},
            }],
        })
    );
    let info = serde_json::to_value(decoder_info("caesar").unwrap()).unwrap();
    assert_eq!(info["name"], "caesar");
    assert_eq!(info["function"], "caesar");
    assert_eq!(info["aliases"], serde_json::json!(["rot13"]));
    assert!(info["key_format"].as_str().unwrap().contains("ROT13"));
}
