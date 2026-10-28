//! End-to-end tests for the Punycode decoder (<https://github.com/bee-san/Ciphey/issues/938>):
//! the whole search, as the CLI runs it, has to find the plaintext through Punycode.
//!
//! Most Punycode never reaches the search. LemmeKnow takes bare `xn--` domains such as
//! `xn--mnchen-3ya.de` for URLs, and the English checker takes sentences with an `xn--`
//! label or raw Punycode in them (`The flag is caf-pnb`) for English, so Ciphey returns
//! them unchanged before trying any decoder. The inputs here are ones that aren't
//! plaintext as they are; the unit tests in `src/decoders/punycode_decoder.rs` cover the
//! rest.

use ciphey::config::Config;
use ciphey::perform_cracking;
use ciphey::storage::database::DB_PATH;
use ciphey::DecoderResult;

/// The config for every test here: the default one with a longer timeout.
///
/// Ciphey's config is process-wide and only the first one set takes effect, so the tests
/// in this file can't use different ones. The two-layer search in
/// `base64_of_a_domain_is_cracked` can come close to the default 5 second timeout in an
/// unoptimised build on a busy machine. Every search returns as soon as it finds the
/// plaintext, so a passing test never waits for the timeout.
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
fn subdomain_label_is_cracked() {
    // Python: "hello.müller.example.com".encode("idna"). Without the Punycode decoder the
    // search settles on an atbash → railfence false positive at depth 2.
    let result = crack("hello.xn--mller-kva.example.com");
    assert_eq!(result.text[0], "hello.müller.example.com");
    assert_eq!(path(&result), ["Punycode"]);
}

#[test]
fn another_subdomain_label_is_cracked() {
    // Python: "login.bücher.example.com".encode("idna")
    let result = crack("login.xn--bcher-kva.example.com");
    assert_eq!(result.text[0], "login.bücher.example.com");
    assert_eq!(path(&result), ["Punycode"]);
}

#[test]
fn base64_of_a_domain_is_cracked() {
    // Python: base64.b64encode(b"hello.xn--mller-kva.example.com")
    let result = crack("aGVsbG8ueG4tLW1sbGVyLWt2YS5leGFtcGxlLmNvbQ==");
    assert_eq!(result.text[0], "hello.müller.example.com");
    assert_eq!(path(&result), ["Base64", "Punycode"]);
}
