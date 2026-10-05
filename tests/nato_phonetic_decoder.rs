//! End-to-end tests for the NATO phonetic alphabet decoder
//! (<https://github.com/bee-san/Ciphey/issues/964>): the whole search, as the CLI runs it,
//! has to find the plaintext through NATO Phonetic Alphabet.
//!
//! Code words separated by spaces, CyberChef's `Hotel Echo Lima Lima Oscar  Whiskey ...`,
//! are English words, so the plaintext check at the start of the search accepts the input
//! itself and no decoder runs. `tests/nato_phonetic_decoder_crib.rs` covers that layout
//! with a crib. These tests use the layouts that check doesn't accept: code words joined
//! with `-` or `/`.
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
fn hyphen_joined_code_words_are_cracked() {
    // On master the search returned `Affine -> railfence` gibberish for this input
    let result = crack("Hotel-Echo-Lima-Lima-Oscar Whiskey-Oscar-Romeo-Lima-Delta");
    assert_eq!(result.text[0], "hello world");
    assert_eq!(path(&result), ["NATO Phonetic Alphabet"]);
}

#[test]
#[serial]
fn slash_joined_code_words_beat_railfence() {
    // Railfence rearranges this into `e/re ailH/m/ y/LliR/...`, which the English checker
    // accepts, in the same search step. On master that was the answer.
    let result = crack("Hotel/Echo/Lima/Lima/Oscar  Whiskey/Oscar/Romeo/Lima/Delta");
    assert_eq!(result.text[0], "hello world");
    assert_eq!(path(&result), ["NATO Phonetic Alphabet"]);
}

#[test]
#[serial]
fn sentence_with_punctuation_is_cracked() {
    // The bench `medium` plaintext, each word's code words joined with `-`
    let result = crack("Mike-Echo-Echo-Tango Mike-Echo Alfa-Tango Tango-Hotel-Echo Oscar-Lima-Delta Lima-India-Golf-Hotel-Tango-Hotel-Oscar-Uniform-Sierra-Echo Alfa-Foxtrot-Tango-Echo-Romeo Mike-India-Delta-November-India-Golf-Hotel-Tango Alfa-November-Delta Bravo-Romeo-India-November-Golf Tango-Hotel-Echo Mike-Alfa-Papa-Comma Tango-Hotel-Echo Kilo-Echo-Yankee Alfa-November-Delta Alfa Tango-Oscar-Romeo-Charlie-Hotel-Stop");
    assert_eq!(
        result.text[0],
        "meet me at the old lighthouse after midnight and bring the map, the key and a torch."
    );
    assert_eq!(path(&result), ["NATO Phonetic Alphabet"]);
}

#[test]
#[serial]
fn nato_inside_base64_is_cracked() {
    // Python 3: base64.b64encode(b"Hotel-Echo-Lima-Lima-Oscar Whiskey-Oscar-Romeo-Lima-Delta").
    // On master the search returned `Base64 -> atbash -> Vigenere` gibberish.
    let result =
        crack("SG90ZWwtRWNoby1MaW1hLUxpbWEtT3NjYXIgV2hpc2tleS1Pc2Nhci1Sb21lby1MaW1hLURlbHRh");
    assert_eq!(result.text[0], "hello world");
    assert_eq!(path(&result), ["Base64", "NATO Phonetic Alphabet"]);
}
