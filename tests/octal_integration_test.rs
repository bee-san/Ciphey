//! The whole search has to find the plaintext of octal input on its own,
//! with the Octal decoder in the path. <https://github.com/bee-san/Ciphey/issues/950>

use ciphey::config::Config;
use ciphey::perform_cracking;
use ciphey::{set_test_db_path, TestDatabase};
use serial_test::serial;

/// Runs `perform_cracking` with the default config and returns the plaintext and the
/// names of the decoders on the path to it.
fn crack(ciphertext: &str) -> (String, Vec<&'static str>) {
    let _test_db = TestDatabase::default();
    set_test_db_path();

    let result = perform_cracking(ciphertext, Config::default())
        .expect("the search should not fail")
        .expect("the search should find the plaintext");
    let path = result.path.iter().map(|step| step.decoder).collect();
    (result.text[0].clone(), path)
}

#[test]
#[serial]
fn perform_cracking_decodes_octal_issue_example() {
    let (plaintext, path) = crack("150 145 154 154 157 40 167 157 162 154 144");
    assert_eq!(plaintext, "hello world");
    assert!(path.contains(&"Octal"), "path was {path:?}");
}

#[test]
#[serial]
fn perform_cracking_decodes_octal_pangram() {
    let (plaintext, path) = crack("124 150 145 40 161 165 151 143 153 40 142 162 157 167 156 40 146 157 170 40 152 165 155 160 163 40 157 166 145 162 40 164 150 145 40 154 141 172 171 40 144 157 147");
    assert_eq!(plaintext, "The quick brown fox jumps over the lazy dog");
    assert!(path.contains(&"Octal"), "path was {path:?}");
}

#[test]
#[serial]
fn perform_cracking_decodes_base64_then_octal() {
    // Base64 of "150 145 154 154 157 40 167 157 162 154 144"
    let (plaintext, path) = crack("MTUwIDE0NSAxNTQgMTU0IDE1NyA0MCAxNjcgMTU3IDE2MiAxNTQgMTQ0");
    assert_eq!(plaintext, "hello world");
    assert_eq!(path, ["Base64", "Octal"]);
}
