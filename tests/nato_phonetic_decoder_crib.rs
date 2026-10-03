//! End-to-end tests for the NATO phonetic alphabet decoder
//! (<https://github.com/bee-san/Ciphey/issues/964>) with a crib, the way
//! `ciphey -r '^hello world$'` runs it.
//!
//! Code words separated by spaces, as CyberChef's `Convert to NATO alphabet` writes them,
//! are English words. Without a crib, the plaintext check at the start of the search
//! accepts the input itself (`Hotel Echo Lima Lima Oscar  Whiskey ...` is returned
//! unchanged), and a Base64 layer around it stops after Base64 for the same reason. A crib
//! turns the other checkers off, so the decoder has to find the text that matches.
//!
//! This is its own test binary because the config is global to the process: the first
//! `perform_cracking` call sets it for every later call. The tests run one at a time: every
//! search uses all cores, and side by side on a slow CI runner they would slow each other
//! down.

use ciphey::config::Config;
use ciphey::perform_cracking;
use ciphey::storage::database::DB_PATH;
use ciphey::DecoderResult;
use serial_test::serial;

/// Runs the whole search on `text` with the crib `^hello world$` and returns what it found.
fn crack(text: &str) -> DecoderResult {
    // With no database path every connection is a fresh in-memory database, so the search
    // doesn't read the cache in ~/.ciphey and doesn't write to it.
    let _ = DB_PATH.set(None);
    // Every search explores like a fresh `ciphey` run, whatever ran before
    ciphey::reset_decoder_stats();
    let config = Config {
        regex: Some("^hello world$".to_string()),
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
    // CyberChef's `Convert to NATO alphabet` of `hello world`. On master the search timed
    // out with this crib.
    let result = crack("Hotel Echo Lima Lima Oscar  Whiskey Oscar Romeo Lima Delta ");
    assert_eq!(result.text[0], "hello world");
    assert_eq!(path(&result), ["NATO Phonetic Alphabet"]);
}

#[test]
#[serial]
fn other_translators_word_gaps_are_cracked() {
    // https://www.omnicalculator.com/everyday-life/nato-phonetic-alphabet
    let result = crack("Hotel Echo Lima Lima Oscar (space) Whiskey Oscar Romeo Lima Delta");
    assert_eq!(result.text[0], "hello world");
    assert_eq!(path(&result), ["NATO Phonetic Alphabet"]);

    // https://www.wordcounttool.com/nato-phonetic-translator
    let result = crack("Hotel Echo Lima Lima Oscar / Whiskey Oscar Romeo Lima Delta");
    assert_eq!(result.text[0], "hello world");
    assert_eq!(path(&result), ["NATO Phonetic Alphabet"]);
}

#[test]
#[serial]
fn nato_inside_base64_is_cracked() {
    // Python 3: base64.b64encode(b"Hotel Echo Lima Lima Oscar  Whiskey Oscar Romeo Lima Delta")
    let result =
        crack("SG90ZWwgRWNobyBMaW1hIExpbWEgT3NjYXIgIFdoaXNrZXkgT3NjYXIgUm9tZW8gTGltYSBEZWx0YQ==");
    assert_eq!(result.text[0], "hello world");
    assert_eq!(path(&result), ["Base64", "NATO Phonetic Alphabet"]);
}
