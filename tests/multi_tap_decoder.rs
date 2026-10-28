//! End-to-end tests for the Multi-tap decoder (<https://github.com/bee-san/Ciphey/issues/960>):
//! the whole search, as the CLI runs it, has to find the plaintext through Multi-tap.
//!
//! Without the Multi-tap decoder the search returns a wrong answer for each of these inputs
//! (gibberish via rot47 → Reverse, Hexadecimal → Affine → Vigenere or railfence → Vigenere,
//! rot47's `555099906066`), or none before the timeout.

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
    // The longer timeout is headroom for slow CI runners. The config is process-wide, so
    // every test uses the same one.
    let config = Config {
        timeout: 20,
        ..Config::default()
    };
    perform_cracking(text, config)
        .unwrap_or_else(|error| panic!("searching {text:?} failed: {error}"))
        .unwrap_or_else(|| panic!("the search found nothing for {text:?}"))
}

/// The names of the decoders the search used, in order.
fn path(result: &DecoderResult) -> Vec<&str> {
    result.path.iter().map(|step| step.decoder).collect()
}

#[test]
fn issue_example_is_cracked() {
    // The example in the issue: key presses separated by spaces, 0 for a space
    let result = crack("44 33 555 555 666 0 9 666 777 555 3");
    assert_eq!(result.text[0], "HELLO WORLD");
    assert_eq!(path(&result), ["Multi-tap"]);
}

#[test]
fn dcode_hyphenated_form_is_cracked() {
    // dCode joins the letters of a word with hyphens and separates words with spaces
    let result = crack("44-33-555-555-666 9-666-777-555-3");
    assert_eq!(result.text[0], "HELLO WORLD");
    assert_eq!(path(&result), ["Multi-tap"]);
}

#[test]
fn dcode_example_beats_rot47() {
    // dCode's example. In the same search step rot47 turns it into `555099906066`, which
    // LemmeKnow takes for a phone number; Multi-tap wins because it is listed first in
    // `filter_and_get_decoders`.
    let result = crack("222-666-3-33");
    assert_eq!(result.text[0], "CODE");
    assert_eq!(path(&result), ["Multi-tap"]);
}

#[test]
fn meet_me_at_dawn_is_cracked() {
    let result = crack("6 33 33 8 0 6 33 0 2 8 0 3 2 9 66");
    assert_eq!(result.text[0], "MEET ME AT DAWN");
    assert_eq!(path(&result), ["Multi-tap"]);
}

#[test]
fn multi_tap_inside_base64_is_cracked() {
    // printf '44 33 555 555 666 0 9 666 777 555 3' | base64 -w0
    let result = crack("NDQgMzMgNTU1IDU1NSA2NjYgMCA5IDY2NiA3NzcgNTU1IDM=");
    assert_eq!(result.text[0], "HELLO WORLD");
    assert_eq!(path(&result), ["Base64", "Multi-tap"]);
}
