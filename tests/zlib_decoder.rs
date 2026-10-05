//! End-to-end tests for the Zlib decoder (<https://github.com/bee-san/Ciphey/issues/1021>):
//! the whole search, as the CLI runs it, has to find the plaintext through Zlib.

use ciphey::config::Config;
use ciphey::perform_cracking;
use ciphey::storage::database::DB_PATH;
use ciphey::DecoderResult;

const FOX: &str = "The quick brown fox jumps over the lazy dog";

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
fn zlib_in_base64_is_cracked() {
    // Python 3: base64.b64encode(zlib.compress(FOX))
    let result = crack("eJwLyUhVKCzNTM5WSCrKL89TSMuvUMgqzS0oVsgvSy1SKAFK5yRWVSqk5KcDAFvcD9o=");
    assert_eq!(result.text[0], FOX);
    assert_eq!(path(&result), ["Zlib"]);
}

#[test]
fn zlib_in_hex_is_cracked() {
    // Python 3: zlib.compress(FOX).hex()
    let result = crack("789c0bc94855282ccd4cce56482aca2fcf5348cbaf50c82acd2d2856c82f4b2d5228014ae72456552aa4e4a703005bdc0fda");
    assert_eq!(result.text[0], FOX);
    assert_eq!(path(&result), ["Zlib"]);
}

#[test]
fn git_loose_object_is_cracked() {
    // `git hash-object -w` of FOX + "\n" (object 84102df4576c91e5176899893215babee5ad1215)
    let result =
        crack("eAFLyslPUjAxYQjJSFUoLM1MzlZIKsovz1NIy69QyCrNLShWyC9LLVIoAUrnJFZVKqTkp3MBANaIEgs=");
    assert_eq!(result.text[0], format!("{FOX}\n"));
    assert_eq!(path(&result), ["Zlib"]);
    assert_eq!(result.path[0].key.as_deref(), Some("git blob"));
}

#[test]
fn flask_session_cookie_is_cracked() {
    // A real Flask session cookie (itsdangerous 2.2.0, salt "cookie-session", HMAC-SHA1)
    let result = crack(".eJxNikEOgDAIBP_CuS_wM6SxSBorGGgPpunfxZuX3dnMThhOBhvkclWBBKaNfrMpMxUM3roNSnC0zOG_mhF-opN7VXHMRuiVJf6iHUl2e-5OZcF6ATTKJYw.ar7Csw.9oMCUUZEyBpz7prlNVxFW_RVWso");
    assert_eq!(
        result.text[0],
        r#"{"user":"admin","role":"admin","logged_in":true,"flag":"flag{flask_sessions_are_signed_not_encrypted}"}"#
    );
    assert_eq!(path(&result), ["Zlib"]);
}

#[test]
fn zlib_inside_zlib_is_cracked() {
    // Python 3: base64.b64encode(zlib.compress(zlib.compress(FOX))). The first step hands
    // the inner stream on as Latin-1 text, which the second reads back as raw bytes.
    let result = crack(
        "eJwBMgDN/3icC8lIVSgszUzOVkgqyi/PU0jLr1DIKs0tKFbIL0stUigBSuckVlUqpOSnAwBb3A/aExYUhg==",
    );
    assert_eq!(result.text[0], FOX);
    assert_eq!(path(&result), ["Zlib", "Zlib"]);
}
