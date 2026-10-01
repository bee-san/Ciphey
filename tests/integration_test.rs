use ciphey::checkers::checker_result::CheckResult;
use ciphey::checkers::checker_type::{Check, Checker};
use ciphey::checkers::english::EnglishChecker;
use ciphey::config::Config;
use ciphey::decoders::base64_decoder::Base64Decoder;
use ciphey::decoders::crack_results::CrackResult;
use ciphey::decoders::interface::{Crack, Decoder};
use ciphey::perform_cracking;
use ciphey::storage::database;
use ciphey::{set_test_db_path, TestDatabase};
use serial_test::{parallel, serial};
use uuid::Uuid;

// TODO Below fails because Library API is broken.
// https://github.com/bee-san/ciphey/issues/48
#[test]
#[parallel]
fn test_it_works() {
    // It will panic if it doesn't work!
    // Plaintext is `Mutley, you snickering, floppy eared hound. When courage is needed, you’re never around. Those m...	`
    let config = Config::default();
    perform_cracking("TXV0bGV5LCB5b3Ugc25pY2tlcmluZywgZmxvcHB5IGVhcmVkIGhvdW5kLiBXaGVuIGNvdXJhZ2UgaXMgbmVlZGVkLCB5b3XigJlyZSBuZXZlciBhcm91bmQuIFRob3NlIG1lZGFscyB5b3Ugd2VhciBvbiB5b3VyIG1vdGgtZWF0ZW4gY2hlc3Qgc2hvdWxkIGJlIHRoZXJlIGZvciBidW5nbGluZyBhdCB3aGljaCB5b3UgYXJlIGJlc3QuIFNvLCBzdG9wIHRoYXQgcGlnZW9uLCBzdG9wIHRoYXQgcGlnZW9uLCBzdG9wIHRoYXQgcGlnZW9uLCBzdG9wIHRoYXQgcGlnZW9uLCBzdG9wIHRoYXQgcGlnZW9uLCBzdG9wIHRoYXQgcGlnZW9uLCBzdG9wIHRoYXQgcGlnZW9uLiBIb3d3d3chIE5hYiBoaW0sIGphYiBoaW0sIHRhYiBoaW0sIGdyYWIgaGltLCBzdG9wIHRoYXQgcGlnZW9uIG5vdy4g", config).unwrap();
    assert_eq!(true, true);
}

#[test]
#[parallel]
fn test_no_panic_if_empty_string() {
    // It will panic if it doesn't work!
    let config = Config::default();
    perform_cracking("", config).unwrap();
    assert_eq!(true, true);
}

#[test]
#[parallel]
fn test_no_panic_with_non_ascii_letters() {
    // Regression test for https://github.com/bee-san/ciphey/issues/902
    // Every decoder runs on the input, and the Vigenère decoder used to panic on
    // non-ASCII letters ('ż' became index 59 of a 26-entry table, 'ę' underflowed),
    // which crashed the whole search. Any result or a timeout is fine, a panic is not.
    for text in ["Może jutro", "Dziękuję, cześć"] {
        let _ = perform_cracking(text, Config::default());
    }
}

#[test]
#[serial]
fn test_quoted_printable_is_cracked() {
    // https://github.com/bee-san/ciphey/issues/937
    let _test_db = TestDatabase::default();
    set_test_db_path();

    let result = perform_cracking("=48=65=6C=6C=6F=20=57=6F=72=6C=64", Config::default())
        .unwrap()
        .expect("the search should crack Quoted-Printable");
    assert_eq!(result.text[0], "Hello World");
    let path: Vec<&str> = result.path.iter().map(|step| step.decoder).collect();
    assert!(path.contains(&"Quoted-Printable"), "path was {path:?}");
}

#[test]
#[serial]
fn test_quoted_printable_wrapped_base64_is_cracked() {
    // Python's `quopri.encodestring` of unpadded Base64 longer than 76 characters. Only the
    // soft line break shows it's Quoted-Printable, and Base64 can't decode it until the
    // break is removed.
    let _test_db = TestDatabase::default();
    set_test_db_path();

    let result = perform_cracking(
        "UXVvdGVkLVByaW50YWJsZSB3cmFwcyBsb25nIGxpbmVzIGF0IDc2IGNoYXJhY3RlcnMgd2l0aCB=\r\nzb2Z0IGxpbmUgYnJlYWtz",
        Config::default(),
    )
    .unwrap()
    .expect("the search should crack Base64 wrapped in Quoted-Printable");
    assert_eq!(
        result.text[0],
        "Quoted-Printable wraps long lines at 76 characters with soft line breaks"
    );
    let path: Vec<&str> = result.path.iter().map(|step| step.decoder).collect();
    assert_eq!(path, ["Quoted-Printable", "Base64"]);
}

/// Runs the whole search on `input` and returns the plaintext and the decoders used, in order.
fn crack(input: &str) -> (String, Vec<&'static str>) {
    let result = perform_cracking(input, Config::default())
        .unwrap()
        .expect("the search should find the plaintext");
    let path = result.path.iter().map(|step| step.decoder).collect();
    (result.text[0].clone(), path)
}

// The UTF-16 tests need a search two decoders deep to finish within the default 5 s timeout
// in a debug build. They're `serial` so they don't share the CPU with the parallel tests,
// some of which search until they time out.

#[test]
#[serial]
fn test_utf16le_powershell_encoded_command() {
    // PowerShell's -EncodedCommand is Base64 of UTF-16LE (issue #943):
    // base64.b64encode("Write-Output 'Hello, World!'".encode("utf-16-le"))
    assert_eq!(
        crack("VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAEgAZQBsAGwAbwAsACAAVwBvAHIAbABkACEAJwA="),
        (
            "Write-Output 'Hello, World!'".to_string(),
            vec!["Base64", "UTF-16"]
        )
    );
}

#[test]
#[serial]
#[ignore = "Vigenere accepts junk from this input at depth 1, before Base64 -> UTF-16 is tried (#1031)"]
fn test_utf16le_powershell_encoded_command_from_issue() {
    // The example from issue #943. The UTF-16 decoder decodes it (see its unit tests), and the
    // search finds it when Vigenere results are checked at Low sensitivity (#1031, fix 9).
    // base64.b64encode("Write-Output 'hello world'".encode("utf-16-le"))
    assert_eq!(
        crack("VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAGgAZQBsAGwAbwAgAHcAbwByAGwAZAAnAA=="),
        (
            "Write-Output 'hello world'".to_string(),
            vec!["Base64", "UTF-16"]
        )
    );
}

#[test]
#[serial]
fn test_utf16be_hex() {
    // "The quick brown fox jumps over the lazy dog".encode("utf-16-be").hex()
    assert_eq!(
        crack("00540068006500200071007500690063006b002000620072006f0077006e00200066006f00780020006a0075006d007000730020006f00760065007200200074006800650020006c0061007a007900200064006f0067"),
        (
            "The quick brown fox jumps over the lazy dog".to_string(),
            vec!["Hexadecimal", "UTF-16"]
        )
    );
}

#[test]
#[serial]
fn test_utf16le_with_bom_hex() {
    // "hello world".encode("utf-16").hex(), which starts with the byte order mark FF FE
    assert_eq!(
        crack("fffe680065006c006c006f00200077006f0072006c006400"),
        ("hello world".to_string(), vec!["Hexadecimal", "UTF-16"])
    );
}

/*
#[test]
fn test_program_parses_files_and_cracks() {
    // It should be able to open and crack this file
    let file_path = "tests/test_fixtures/base64_3_times_with_no_new_line";
    let config = Config::default();
    let to_crack = read_and_parse_file(file_path.to_string());
    let result = perform_cracking(&to_crack, config);
    assert_eq!(true, true);
    // The base64 string decodes to "VFoW2RHbHdiR1VndXMUdlbHBVV1RCSlIxWjFXVEk1YTJGWE5XNWpkejA5"
    let result = result.unwrap();
    assert!(
        !result.text.is_empty(),
        "Decoding should produce some result"
    );
}
*/
/*
#[test]
#[ignore]
fn test_program_parses_files_with_new_line_and_cracks() {
    // It should be able to open and crack this file
    let file_path = "tests/test_fixtures/rot13_base64_hex_with_newline";
    let config = Config::default();
    let to_crack = read_and_parse_file(file_path.to_string());
    let result = perform_cracking(&to_crack, config);
    assert_eq!(true, true);
    assert!(result.unwrap().text[0] == "This is a test!");
}
*/

#[test]
#[serial]
fn test_cache_miss_simple_base64() {
    let _test_db = TestDatabase::default();
    set_test_db_path();

    let encoded_text_1 = String::from("aGVsbG8gd29ybGQK");
    let decoded_text_1 = String::from("hello world\n");

    let config = Config::default();
    let result = perform_cracking(encoded_text_1.as_str(), config).unwrap();
    assert!(result.is_some());
    assert!(result.unwrap().path.last().unwrap().success);

    let row_result = database::read_cache(&encoded_text_1);
    assert!(row_result.is_ok());
    let row_result = row_result.unwrap();
    assert!(row_result.is_some());

    let row: database::CacheRow = row_result.unwrap();

    let base64_decoder = Decoder::<Base64Decoder>::new();
    let mut expected_crack_result: CrackResult =
        CrackResult::new(&base64_decoder, encoded_text_1.clone());
    expected_crack_result.unencrypted_text = Some(vec![decoded_text_1.clone()]);
    let expected_checker = Checker::<EnglishChecker>::new();
    let mut expected_check_result = CheckResult::new(&expected_checker);
    expected_check_result.is_identified = true;
    expected_crack_result.update_checker(&expected_check_result);
    let expected_path = vec![expected_crack_result.get_json().unwrap()];

    assert_eq!(row.encoded_text, encoded_text_1);
    assert_eq!(row.decoded_text, decoded_text_1);
    assert_eq!(row.path, expected_path);
    assert!(row.successful);
}

#[test]
#[serial]
fn test_cache_hit_simple_base64() {
    let _test_db = TestDatabase::default();
    set_test_db_path();

    let encoded_text_1 = String::from("aGVsbG8gd29ybGQK");
    let decoded_text_1 = String::from("hello world\n");

    let base64_decoder = Decoder::<Base64Decoder>::new();
    let mut expected_crack_result: CrackResult =
        CrackResult::new(&base64_decoder, encoded_text_1.clone());
    expected_crack_result.unencrypted_text = Some(vec![decoded_text_1.clone()]);
    let expected_checker = Checker::<EnglishChecker>::new();
    let mut expected_check_result = CheckResult::new(&expected_checker);
    expected_check_result.is_identified = true;
    expected_crack_result.update_checker(&expected_check_result);
    let expected_path = vec![expected_crack_result.get_json().unwrap()];

    let _result = database::insert_cache(&database::CacheEntry {
        uuid: Uuid::new_v4(),
        encoded_text: encoded_text_1.clone(),
        decoded_text: decoded_text_1.clone(),
        path: vec![expected_crack_result],
        execution_time_ms: 100,
    });

    let config = Config::default();
    let result = perform_cracking(encoded_text_1.as_str(), config).unwrap();
    assert!(result.is_some());
    assert!(result.unwrap().path.last().unwrap().success);

    let row_result = database::read_cache(&encoded_text_1);
    assert!(row_result.is_ok());
    let row_result = row_result.unwrap();
    assert!(row_result.is_some());

    let row: database::CacheRow = row_result.unwrap();
    assert_eq!(row.encoded_text, encoded_text_1);
    assert_eq!(row.decoded_text, decoded_text_1);
    assert_eq!(row.path, expected_path);
    assert!(row.successful);
}

#[test]
#[serial]
fn test_search_cracks_base85() {
    // RFC 1924 Base85, made with Python's `base64.b85encode`
    let _test_db = TestDatabase::default();
    set_test_db_path();

    let result = perform_cracking(
        "RA^-&adl~9Yan8BZ+C7WW^Z^PYISXJb0BYaWpW^NXk{R5VS0HWWN&8",
        Config::default(),
    )
    .unwrap()
    .expect("the search should crack Base85");
    assert_eq!(
        result.text[0],
        "The quick brown fox jumps over the lazy dog"
    );
    let path: Vec<&str> = result.path.iter().map(|step| step.decoder).collect();
    assert!(path.contains(&"Base85"), "path was {path:?}");
}

#[test]
#[serial]
fn test_search_cracks_base85_twice() {
    // Base85 is stackable, so the search may apply it twice in a row. Two layers take
    // 1-2 s in a debug build; the longer timeout is headroom for slow CI runners.
    let _test_db = TestDatabase::default();
    set_test_db_path();

    let config = Config {
        timeout: 20,
        ..Config::default()
    };
    let result = perform_cracking(
        "QbArVCShc3emPlTZa6|(D?>L|S6*6PP+3V+SW03rLRn!~a93VVSZjMyHC9tFNLN=*CO7",
        config,
    )
    .unwrap()
    .expect("the search should crack Base85 applied twice");
    assert_eq!(
        result.text[0],
        "The quick brown fox jumps over the lazy dog"
    );
    let path: Vec<&str> = result.path.iter().map(|step| step.decoder).collect();
    assert_eq!(path, ["Base85", "Base85"]);
}

/// The decoders on the path of a search result
fn decoder_path(result: &ciphey::DecoderResult) -> Vec<&str> {
    result.path.iter().map(|step| step.decoder).collect()
}

#[test]
#[serial]
fn test_ascii85_is_cracked() {
    // https://github.com/bee-san/Ciphey/issues/926
    // Python 3: base64.a85encode(b"The quick brown fox jumps over the lazy dog", adobe=True)
    let _test_db = TestDatabase::default();
    set_test_db_path();

    let result = perform_cracking(
        "<~<+ohcEHPu*CER),Dg-(AAoDo:C3=B4F!,CEATAo8BOr<&@=!2AA8c)~>",
        Config::default(),
    )
    .unwrap()
    .expect("the search should crack Ascii85");
    assert_eq!(
        result.text[0],
        "The quick brown fox jumps over the lazy dog"
    );
    assert!(
        decoder_path(&result).contains(&"Ascii85"),
        "{:?}",
        decoder_path(&result)
    );
}

#[test]
#[serial]
fn test_base64_of_ascii85_is_cracked() {
    // Base64 of the Ascii85 above, so the search has to chain two encodings
    let _test_db = TestDatabase::default();
    set_test_db_path();

    let result = perform_cracking(
        "PH48K29oY0VIUHUqQ0VSKSxEZy0oQUFvRG86QzM9QjRGISxDRUFUQW84Qk9yPCZAPSEyQUE4Yyl+Pg==",
        Config::default(),
    )
    .unwrap()
    .expect("the search should crack Base64 -> Ascii85");
    assert_eq!(
        result.text[0],
        "The quick brown fox jumps over the lazy dog"
    );
    assert_eq!(decoder_path(&result), ["Base64", "Ascii85"]);
}

/// The example token from jwt.io (HS256, secret `your-256-bit-secret`)
const JWT_IO_TOKEN: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
/// The payload of [`JWT_IO_TOKEN`]
const JWT_IO_PAYLOAD: &str = r#"{"sub":"1234567890","name":"John Doe","iat":1516239022}"#;

#[test]
#[serial]
fn test_jwt_is_decoded() {
    let _test_db = TestDatabase::default();
    set_test_db_path();

    let result = perform_cracking(JWT_IO_TOKEN, Config::default())
        .unwrap()
        .expect("the JWT should be decoded");
    assert_eq!(result.text[0], JWT_IO_PAYLOAD);
    let last = result.path.last().unwrap();
    assert_eq!(last.decoder, "JWT");
    assert!(last.success);
    assert_eq!(last.key.as_deref(), Some(r#"{"alg":"HS256","typ":"JWT"}"#));

    // The cached path names the "JWT Structure" checker, which has to be known to read
    // the cache back
    let row = database::read_cache(&JWT_IO_TOKEN.to_string())
        .unwrap()
        .expect("the result should be cached");
    let cached_last: CrackResult = serde_json::from_str(row.path.last().unwrap()).unwrap();
    assert_eq!(cached_last.decoder, "JWT");
    assert_eq!(cached_last.checker_name, "JWT Structure");
}

#[test]
#[serial]
fn test_jwt_with_flag_claim_is_decoded() {
    let _test_db = TestDatabase::default();
    set_test_db_path();

    // {"alg":"none","typ":"JWT"} . {"flag":"flag{jwt_is_not_encryption}"} . (no signature)
    let result = perform_cracking(
        "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJmbGFnIjoiZmxhZ3tqd3RfaXNfbm90X2VuY3J5cHRpb259In0.",
        Config::default(),
    )
    .unwrap()
    .expect("the JWT should be decoded");
    assert_eq!(result.text[0], r#"{"flag":"flag{jwt_is_not_encryption}"}"#);
    assert_eq!(result.path.last().unwrap().decoder, "JWT");
}

#[test]
#[serial]
fn test_jwt_inside_base64_is_decoded() {
    let _test_db = TestDatabase::default();
    set_test_db_path();

    // Base64 of JWT_IO_TOKEN
    let result = perform_cracking(
        "ZXlKaGJHY2lPaUpJVXpJMU5pSXNJblI1Y0NJNklrcFhWQ0o5LmV5SnpkV0lpT2lJeE1qTTBOVFkzT0Rrd0lpd2libUZ0WlNJNklrcHZhRzRnUkc5bElpd2lhV0YwSWpveE5URTJNak01TURJeWZRLlNmbEt4d1JKU01lS0tGMlFUNGZ3cE1lSmYzNlBPazZ5SlZfYWRRc3N3NWM=",
        Config::default(),
    )
    .unwrap()
    .expect("the JWT should be decoded");
    assert_eq!(result.text[0], JWT_IO_PAYLOAD);
    let decoders: Vec<&str> = result.path.iter().map(|step| step.decoder).collect();
    assert_eq!(decoders, ["Base64", "JWT"]);
}
