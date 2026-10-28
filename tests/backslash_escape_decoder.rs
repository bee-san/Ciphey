//! End-to-end tests for the Backslash Escapes decoder
//! (<https://github.com/bee-san/Ciphey/issues/941>): the whole search, as the CLI runs it,
//! has to find the plaintext.

use ciphey::config::Config;
use ciphey::perform_cracking;
use ciphey::storage::database::DB_PATH;
use ciphey::DecoderResult;
use serial_test::serial;

/// "Hello, World!" with octal and hex escapes. Octal rejects the `x` and Hexadecimal finds
/// an odd number of digits, so only Backslash Escapes decodes it.
const HELLO_WORLD_ESCAPED: &str = r"\110\145\154\154\157\054\040\x57\x6f\x72\x6c\x64\x21";

/// The default config with a longer timeout.
///
/// Ciphey's config is process-wide and only the first one set takes effect, so every test
/// here uses this one. The two-layer searches take a couple of seconds in an unoptimised
/// build on a busy machine, close to the default 5 second timeout. Every search returns as
/// soon as it finds the plaintext, so a passing test never waits for the timeout.
fn config() -> Config {
    Config {
        timeout: 30,
        ..Config::default()
    }
}

/// Runs the whole search on `text` and returns what it found.
fn crack(text: &str) -> DecoderResult {
    // With no database path every connection is a fresh in-memory database, so the search
    // doesn't read the cache in ~/.ciphey (an answer cached by another build would stand
    // in for the search under test) and doesn't write to it.
    let _ = DB_PATH.set(None);
    perform_cracking(text, config())
        .unwrap_or_else(|error| panic!("searching {text:?} failed: {error}"))
        .unwrap_or_else(|| panic!("the search found nothing for {text:?}"))
}

/// The names of the decoders the search used, in order.
fn path(result: &DecoderResult) -> Vec<&str> {
    result.path.iter().map(|step| step.decoder).collect()
}

#[test]
#[serial]
fn octal_and_hex_escapes_are_cracked() {
    let result = crack(HELLO_WORLD_ESCAPED);
    assert_eq!(result.text[0], "Hello, World!");
    assert_eq!(path(&result), ["Backslash Escapes"]);
}

#[test]
#[serial]
fn escaped_sentence_is_cracked() {
    // The `medium` input of benches/data/decoders.toml: letters as \xHH, the rest as \NNN.
    // Hexadecimal decodes the digits it finds in here to gibberish.
    let result = crack(
        r"\x4d\x65\x65\x74\040\x6d\x65\040\x61\x74\040\x74\x68\x65\040\x6f\x6c\x64\040\x6c\x69\x67\x68\x74\x68\x6f\x75\x73\x65\040\x61\x66\x74\x65\x72\040\x6d\x69\x64\x6e\x69\x67\x68\x74\040\x61\x6e\x64\040\x62\x72\x69\x6e\x67\040\x74\x68\x65\040\x6d\x61\x70\054\040\x74\x68\x65\040\x6b\x65\x79\040\x61\x6e\x64\040\x61\040\x74\x6f\x72\x63\x68\056",
    );
    assert_eq!(
        result.text[0],
        "Meet me at the old lighthouse after midnight and bring the map, the key and a torch."
    );
    assert_eq!(path(&result), ["Backslash Escapes"]);
}

#[test]
#[serial]
fn escapes_inside_base64_are_cracked() {
    // Python 3: base64.b64encode(HELLO_WORLD_ESCAPED.encode())
    let result = crack("XDExMFwxNDVcMTU0XDE1NFwxNTdcMDU0XDA0MFx4NTdceDZmXHg3Mlx4NmNceDY0XHgyMQ==");
    assert_eq!(result.text[0], "Hello, World!");
    assert_eq!(path(&result), ["Base64", "Backslash Escapes"]);
}

#[test]
#[serial]
fn double_escaped_string_is_cracked() {
    // HELLO_WORLD_ESCAPED with every backslash escaped again. Decoding it twice in a row
    // needs Backslash Escapes in the search's list of stackable decoders.
    let result = crack(r"\\110\\145\\154\\154\\157\\054\\040\\x57\\x6f\\x72\\x6c\\x64\\x21");
    assert_eq!(result.text[0], "Hello, World!");
    assert_eq!(path(&result), ["Backslash Escapes", "Backslash Escapes"]);
}

#[test]
#[serial]
fn pure_octal_escapes_are_cracked() {
    // The example in the issue. Octal decodes it to the same text, and whichever of the two
    // the search tries first wins, so the path isn't checked.
    let result = crack(r"\150\145\154\154\157\040\167\157\162\154\144");
    assert_eq!(result.text[0], "hello world");
}

#[test]
#[serial]
fn pure_hex_escapes_are_cracked() {
    // Hexadecimal decodes these too, so the path isn't checked
    let result = crack(
        r"\x54\x68\x65\x20\x71\x75\x69\x63\x6b\x20\x62\x72\x6f\x77\x6e\x20\x66\x6f\x78\x20\x6a\x75\x6d\x70\x73\x20\x6f\x76\x65\x72\x20\x74\x68\x65\x20\x6c\x61\x7a\x79\x20\x64\x6f\x67",
    );
    assert_eq!(
        result.text[0],
        "The quick brown fox jumps over the lazy dog"
    );
}
