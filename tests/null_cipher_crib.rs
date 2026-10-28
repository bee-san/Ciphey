//! End-to-end tests for the Null cipher decoder (#982): the full A* search, through
//! `perform_cracking`, has to find the message hidden in a cover text.
//!
//! They run in crib mode (`--regex`). With the default checkers an English cover text is
//! accepted as plaintext before the search starts, so `perform_cracking` would return the
//! cover unchanged. A crib turns the other checkers off. The global config is set once
//! per process, so every test in this file uses the same crib.

use ciphey::config::Config;
use ciphey::storage::database::DB_PATH;
use ciphey::{perform_cracking, DecoderResult};

/// The crib for every test here.
const CRIB: &str = "HELLO|PERSHING";

/// Runs the whole search on `cover` with [`CRIB`] and returns what it found.
fn search(cover: &str) -> DecoderResult {
    // Keep the cache in memory, so nothing under ~/.ciphey is read or written.
    let _ = DB_PATH.set(None);
    let config = Config {
        regex: Some(CRIB.to_string()),
        ..Config::default()
    };
    perform_cracking(cover, config)
        .expect("the search finishes before the timeout")
        .expect("the search finds the hidden message")
}

/// Asserts that the search finds `message` in `cover` in one Null cipher step that
/// reports `rule`.
fn assert_found(cover: &str, message: &str, rule: &str) {
    let result = search(cover);
    let path: Vec<&str> = result.path.iter().map(|step| step.decoder).collect();
    assert_eq!(result.text[0], message, "path: {path:?}");
    assert_eq!(path, ["Null cipher"]);
    assert_eq!(result.path[0].key.as_deref(), Some(rule));
}

#[test]
fn crib_search_finds_the_issue_acrostic() {
    // The example from #982
    assert_found(
        "Help Everyone Love Lots Of Wildlife: Observe Raptors, Lizards, Deer.",
        "HELLOWORLD",
        "first letter of each word",
    );
}

#[test]
fn crib_search_finds_the_wwi_telegram() {
    // From https://en.wikipedia.org/wiki/Null_cipher: "Pershing sails from NY June 1".
    // Without a crib the decoder doesn't show it to the checker: PERSHING and NY aren't
    // dictionary words.
    assert_found(
        "PRESIDENT'S EMBARGO RULING SHOULD HAVE IMMEDIATE NOTICE. GRAVE SITUATION \
         AFFECTING INTERNATIONAL LAW. STATEMENT FORESHADOWS RUIN OF MANY NEUTRALS. YELLOW \
         JOURNALS UNIFYING NATIONAL EXCITEMENT IMMENSELY.",
        "PERSHINGSAILSFROMNYJUNEI",
        "first letter of each word",
    );
}
