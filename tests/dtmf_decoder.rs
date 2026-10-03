//! End-to-end tests for the DTMF decoder (<https://github.com/bee-san/Ciphey/issues/959>):
//! the whole search, as the CLI runs it, has to find the keys through DTMF.

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
fn issue_example_is_cracked() {
    // Without the DTMF decoder the search settles on `rot47 → Vigenere` gibberish
    let result = crack("852-1336 770-1477 852-1209 770-1336 697-1477 941-1336 852-1477");
    assert_eq!(result.text[0], "8675309");
    assert_eq!(path(&result), ["DTMF"]);
}

#[test]
fn high_low_order_is_cracked() {
    // The high frequency first, as dCode writes it
    let result = crack("1336-852 1477-770 1209-852 1336-770 1477-697 1336-941 1477-852");
    assert_eq!(result.text[0], "8675309");
    assert_eq!(path(&result), ["DTMF"]);
}

#[test]
fn glued_frequencies_are_cracked() {
    // 7 digits per key, the form Python Ciphey decoded
    let result = crack("8521336770147785212097701336697147794113368521477");
    assert_eq!(result.text[0], "8675309");
    assert_eq!(path(&result), ["DTMF"]);
}

#[test]
fn phone_number_is_cracked() {
    // LemmeKnow identifies the keys as a phone number
    let result = crack("697-1209 852-1336 941-1336 941-1336 770-1336 770-1336 770-1336 697-1209 697-1336 697-1477 770-1209");
    assert_eq!(result.text[0], "18005551234");
    assert_eq!(path(&result), ["DTMF"]);
}

#[test]
fn dtmf_inside_base64_is_cracked() {
    // Python 3: base64.b64encode(b"852-1336 770-1477 852-1209 770-1336 697-1477 941-1336 852-1477")
    let result = crack(
        "ODUyLTEzMzYgNzcwLTE0NzcgODUyLTEyMDkgNzcwLTEzMzYgNjk3LTE0NzcgOTQxLTEzMzYgODUyLTE0Nzc=",
    );
    assert_eq!(result.text[0], "8675309");
    assert_eq!(path(&result), ["Base64", "DTMF"]);
}

#[test]
fn multi_tap_inside_dtmf_is_cracked() {
    // The Multi-tap key presses for MEET ME AT DAWN (`0` is a space), one letter per line,
    // as DTMF. The line breaks become the spaces between Multi-tap's letters.
    let result = crack("770-1477\n697-1477 697-1477\n697-1477 697-1477\n852-1336\n941-1336\n770-1477\n697-1477 697-1477\n941-1336\n697-1336\n852-1336\n941-1336\n697-1477\n697-1336\n852-1477\n770-1477 770-1477");
    assert_eq!(result.text[0], "MEET ME AT DAWN");
    assert_eq!(path(&result), ["DTMF", "Multi-tap"]);
}
