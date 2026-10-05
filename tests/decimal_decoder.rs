//! End-to-end tests for the Decimal decoder (<https://github.com/bee-san/Ciphey/issues/951>):
//! the whole search, as the CLI runs it, has to find the plaintext through Decimal.

use ciphey::config::Config;
use ciphey::perform_cracking;
use ciphey::storage::database::DB_PATH;
use ciphey::DecoderResult;

/// Runs the whole search on `text` and returns what it found.
fn crack(text: &str) -> DecoderResult {
    // With no database path every connection is a fresh in-memory database, so the search
    // doesn't read the cache in ~/.ciphey (an answer cached by another build would stand
    // in for the search under test) and doesn't write to it.
    let _ = DB_PATH.set(None);
    perform_cracking(text, Config::default())
        .unwrap_or_else(|error| panic!("searching {text:?} failed: {error}"))
        .unwrap_or_else(|| panic!("the search found nothing for {text:?}"))
}

/// The names of the decoders the search used, in order.
fn path(result: &DecoderResult) -> Vec<&str> {
    result.path.iter().map(|step| step.decoder).collect()
}

#[test]
fn decimal_bytes_are_cracked() {
    // The example in the issue
    let result = crack("104 101 108 108 111 32 119 111 114 108 100");
    assert_eq!(result.text[0], "hello world");
    assert_eq!(path(&result), ["Decimal"]);
}

#[test]
fn string_from_char_code_is_cracked() {
    let result = crack("String.fromCharCode(104,101,108,108,111,32,119,111,114,108,100)");
    assert_eq!(result.text[0], "hello world");
    assert_eq!(path(&result), ["Decimal"]);
}

#[test]
fn pangram_is_cracked() {
    // CyberChef: To Decimal (Space) of "The quick brown fox jumps over the lazy dog"
    let result = crack("84 104 101 32 113 117 105 99 107 32 98 114 111 119 110 32 102 111 120 32 106 117 109 112 115 32 111 118 101 114 32 116 104 101 32 108 97 122 121 32 100 111 103");
    assert_eq!(
        result.text[0],
        "The quick brown fox jumps over the lazy dog"
    );
    assert_eq!(path(&result), ["Decimal"]);
}

#[test]
fn comma_separated_decimal_beats_rot47() {
    // ROT47 turns this into `POSKPOPKPOWK...`, which LemmeKnow takes for a Bitcoin Cash
    // address, in the same search step as Decimal finds the plaintext
    let result = crack("104,101,108,108,111,32,119,111,114,108,100");
    assert_eq!(result.text[0], "hello world");
    assert_eq!(path(&result), ["Decimal"]);
}

#[test]
fn decimal_inside_base64_is_cracked() {
    // Python 3: base64.b64encode(b"104 101 108 108 111 32 119 111 114 108 100")
    let result = crack("MTA0IDEwMSAxMDggMTA4IDExMSAzMiAxMTkgMTExIDExNCAxMDggMTAw");
    assert_eq!(result.text[0], "hello world");
    assert_eq!(path(&result), ["Base64", "Decimal"]);
}
