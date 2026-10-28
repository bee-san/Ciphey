//! End-to-end tests for the Base36 decoder (<https://github.com/bee-san/Ciphey/issues/922>):
//! the whole search, as the CLI runs it, has to find the plaintext through Base36.
//!
//! The Base36 vectors were made with Python 3's `int.from_bytes(data, "big")` written in
//! radix 36 (`0-9a-z`) and decoded back with `int(text, 36).to_bytes(...)`.
//!
//! The tests run one at a time: every search uses all cores, and side by side on a slow
//! CI runner they would slow each other down.

use ciphey::config::Config;
use ciphey::perform_cracking;
use ciphey::storage::database::DB_PATH;
use ciphey::DecoderResult;
use serial_test::serial;

/// Runs the whole search on `text` and returns what it found.
fn crack(text: &str) -> DecoderResult {
    // With no database path every connection is a fresh in-memory database, so the search
    // doesn't read the cache in ~/.ciphey (an answer cached by another build would stand
    // in for the search under test) and doesn't write to it.
    let _ = DB_PATH.set(None);
    // The decoder statistics the search uses in its edge costs live as long as the
    // process. Clearing them makes every search explore like a fresh `ciphey` run, so
    // the result doesn't depend on which tests ran before.
    ciphey::reset_decoder_stats();
    // The default config apart from the timeout: `cargo test` builds without
    // optimisations, and CI runners have few cores. The config is global to the process,
    // so every test here gets the same one.
    let config = Config {
        timeout: 30,
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
#[serial]
fn issue_example_is_cracked() {
    // On master the search returned the false positive `assistdofheaeango`
    // (Reverse -> Vigenere) for this input
    let result = crack("fuvrsivvnfrbjwajo");
    assert_eq!(result.text[0], "hello world");
    assert_eq!(path(&result), ["Base36"]);
}

#[test]
#[serial]
fn upper_case_is_cracked() {
    let result = crack("FUVRSIVVNFRBJWAJO");
    assert_eq!(result.text[0], "hello world");
    assert_eq!(path(&result), ["Base36"]);
}

#[test]
#[serial]
fn pangram_is_cracked() {
    let result = crack("29t3ubyznhh32o9x3pzvljp1qa22wun2quo35naempn0gtx0lxiyrf3qwwi0lzu165j");
    assert_eq!(
        result.text[0],
        "The quick brown fox jumps over the lazy dog"
    );
    assert_eq!(path(&result), ["Base36"]);
}

#[test]
#[serial]
fn base36_inside_base64_is_cracked() {
    // Python 3: base64.b64encode() of the Base36 of the bench `medium` plaintext
    let result = crack("YTgyMnYxb3o4ZjFnNjIwMWMwN2U4eTk0cnVkNmhlMDI4OW80ZDBmeGkycHRoaHY2MG0yczluZm51NnF1bDJ6d3hwbjh3ZGd6ZmViYmI3cm1sNnRiMGhsMnplOGt5ZTVwMTM1NXZmejhuaDlvdG5ydmtxZG1rZWNkOHM2cmF0ZGc2bQ==");
    assert_eq!(
        result.text[0],
        "Meet me at the old lighthouse after midnight and bring the map, the key and a torch."
    );
    assert_eq!(path(&result), ["Base64", "Base36"]);
}
