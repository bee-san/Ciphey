//! End-to-end tests for the Unicode escape decoder: the whole search, started through
//! `perform_cracking`, has to find the plaintext.

use ciphey::config::Config;
use ciphey::perform_cracking;
use ciphey::{set_test_db_path, TestDatabase};
use serial_test::serial;

/// The config for every test here: the default one with a longer timeout.
///
/// Ciphey's config is process-wide and only the first one set takes effect, so the tests
/// in this file can't use different ones. The two-layer search in
/// `test_cracks_base64_of_unicode_escapes` takes a couple of seconds in an unoptimised
/// build on a busy machine, close to the default 5 second timeout. Every search returns
/// as soon as it finds the plaintext, so a passing test never waits for the timeout.
fn config() -> Config {
    Config {
        timeout: 30,
        ..Config::default()
    }
}

/// Cracks `encoded` and returns the plaintext and the names of the decoders on the path
fn crack(encoded: &str) -> (String, Vec<&'static str>) {
    let _test_db = TestDatabase::default();
    set_test_db_path();

    let result = perform_cracking(encoded, config())
        .expect("the search should not time out")
        .expect("the search should find the plaintext");
    let path = result.path.iter().map(|step| step.decoder).collect();
    (result.text[0].clone(), path)
}

#[test]
#[serial]
fn test_cracks_backslash_u_escapes() {
    let (plaintext, path) =
        crack(r"\u0048\u0065\u006C\u006C\u006F\u002C\u0020\u0057\u006F\u0072\u006C\u0064\u0021");
    assert_eq!(plaintext, "Hello, World!");
    assert!(path.contains(&"Unicode Escapes"), "path: {path:?}");
}

#[test]
#[serial]
fn test_cracks_percent_u_escapes() {
    // JavaScript escape() style, made with CyberChef "Escape Unicode Characters" (prefix %u)
    let (plaintext, path) = crack(
        "%u0054%u0068%u0065%u0020%u0071%u0075%u0069%u0063%u006B%u0020%u0062%u0072%u006F%u0077%u006E%u0020%u0066%u006F%u0078%u0020%u006A%u0075%u006D%u0070%u0073%u0020%u006F%u0076%u0065%u0072%u0020%u0074%u0068%u0065%u0020%u006C%u0061%u007A%u0079%u0020%u0064%u006F%u0067",
    );
    assert_eq!(plaintext, "The quick brown fox jumps over the lazy dog");
    assert!(path.contains(&"Unicode Escapes"), "path: {path:?}");
}

#[test]
#[serial]
fn test_cracks_base64_of_unicode_escapes() {
    // Base64 of the \u escapes in test_cracks_backslash_u_escapes
    let (plaintext, path) = crack(
        "XHUwMDQ4XHUwMDY1XHUwMDZDXHUwMDZDXHUwMDZGXHUwMDJDXHUwMDIwXHUwMDU3XHUwMDZGXHUwMDcyXHUwMDZDXHUwMDY0XHUwMDIx",
    );
    assert_eq!(plaintext, "Hello, World!");
    assert_eq!(path, ["Base64", "Unicode Escapes"]);
}
