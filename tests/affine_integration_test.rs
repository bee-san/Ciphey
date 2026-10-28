//! End-to-end tests for the Affine cracker (#991): the full A* search, through
//! `perform_cracking` with the default config, has to find the plaintext with
//! Affine in the path.

use ciphey::config::Config;
use ciphey::{perform_cracking, DecoderResult};

/// Runs the whole search on `ciphertext` and returns what it found.
fn search(ciphertext: &str) -> DecoderResult {
    // Keep the cache in memory, so every search is a cache miss and nothing under
    // ~/.ciphey is read or written.
    let _ = ciphey::storage::database::DB_PATH.set(None);
    perform_cracking(ciphertext, Config::default())
        .expect("the search finishes before the timeout")
        .expect("the search finds plaintext")
}

/// Asserts that the search turns `ciphertext` into `plaintext` with an Affine step
/// that reports `key`.
fn assert_cracked(ciphertext: &str, plaintext: &str, key: &str) {
    let result = search(ciphertext);
    let path: Vec<&str> = result.path.iter().map(|step| step.decoder).collect();
    assert_eq!(result.text[0], plaintext, "path: {path:?}");
    let affine = result
        .path
        .iter()
        .find(|step| step.decoder == "Affine")
        .unwrap_or_else(|| panic!("no Affine step in {path:?}"));
    assert_eq!(affine.key.as_deref(), Some(key));
}

#[test]
fn search_cracks_affine_hello_world() {
    // a = 7, b = 3, checked with CyberChef's Affine Cipher Decode
    assert_cracked("Afccx, Bxscy!", "Hello, World!", "a=7, b=3");
}

#[test]
fn search_cracks_affine_sentence() {
    // a = 11, b = 19, checked with CyberChef's Affine Cipher Decode
    assert_cracked(
        "Usl nfdpz eyrbg wrm ofvcj rqly usl ktix arh bsdkl usl ptu jkllcj.",
        "The quick brown fox jumps over the lazy dog while the cat sleeps.",
        "a=11, b=19",
    );
}
