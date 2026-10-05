//! End-to-end tests for the Route Transposition decoder
//! (<https://github.com/bee-san/Ciphey/issues/997>): the whole search, as the CLI runs it,
//! has to find the plaintext through Route Transposition.
//!
//! The ciphertexts were made by the issue's Python prototype, writing the plaintext in rows
//! of 7 characters and reading the columns, and decode back with Python Ciphey's
//! `route.py` (`decode_with(7)`, git `dbd5aa95`). The letters-only one also matches pycipher
//! 0.5.2's `ColTrans("ABCDEFG").encipher`.
//!
//! The tests run one at a time: every search uses all cores, and side by side on a slow
//! CI runner they would slow each other down.

use ciphey::config::Config;
use ciphey::perform_cracking;
use ciphey::storage::database::DB_PATH;
use ciphey::DecoderResult;
use serial_test::serial;

/// The plaintext of the spaced ciphertexts, the bench `medium` text.
const LIGHTHOUSE: &str =
    "Meet me at the old lighthouse after midnight and bring the map, the key and a torch.";

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
fn spaced_text_is_cracked() {
    // Every character moved, spaces and punctuation too: the bench `medium` input
    let result = crack(
        "M  ge hbh y eaoh mtret tetltai i haot dhfdanmenr t otnnga dcmhlueid pk heeisrg t,ea.",
    );
    assert_eq!(result.text[0], LIGHTHOUSE);
    assert_eq!(path(&result), ["Route Transposition"]);
    assert_eq!(result.path[0].key.as_deref(), Some("7 columns"));
}

#[test]
#[serial]
fn unspaced_text_is_cracked() {
    // A ragged grid, 66 = 9 · 7 + 3. On master (cc45d40a) the search settled on a
    // Vigenère false positive at the same depth: this only passes while Route
    // Transposition comes before Vigenere in the filtration system's list.
    let result = crack("MTLURHIAYRETISMTNPACEHGEIAGTNHTEHADNTHDMOTFNDHEAELHTIBEKTADOEGRMEO");
    assert_eq!(
        result.text[0],
        "MEETMEATTHEOLDLIGHTHOUSEAFTERMIDNIGHTANDBRINGTHEMAPTHEKEYANDATORCH"
    );
    assert_eq!(path(&result), ["Route Transposition"]);
}

#[test]
#[serial]
fn spaced_text_inside_base64_is_cracked() {
    // Python 3.9: base64.b64encode() of the spaced ciphertext above
    let result = crack("TSAgZ2UgaGJoIHkgZWFvaCBtdHJldCB0ZXRsdGFpIGkgaGFvdCBkaGZkYW5tZW5yIHQgb3RubmdhIGRjbWhsdWVpZCBwayBoZWVpc3JnIHQsZWEu");
    assert_eq!(result.text[0], LIGHTHOUSE);
    assert_eq!(path(&result), ["Base64", "Route Transposition"]);
}
