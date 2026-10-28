//! End-to-end tests for the JSFuck decoder (<https://github.com/bee-san/Ciphey/issues/987>):
//! the whole search, as the CLI runs it, has to find the text a JSFuck expression gives.
//!
//! The inputs are vectors from `tests/test_fixtures/jsfuck.toml`, written by jsfuck.js and
//! checked with node (see the comments in the file).
//!
//! The tests run one at a time: every search uses all cores, and side by side on a slow
//! CI runner they would slow each other down.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ciphey::config::Config;
use ciphey::perform_cracking;
use ciphey::storage::database::DB_PATH;
use ciphey::DecoderResult;
use serde::Deserialize;
use serial_test::serial;

/// The vectors in `tests/test_fixtures/jsfuck.toml`
#[derive(Deserialize)]
struct Fixture {
    vector: Vec<Vector>,
}

/// `JSFuck.encode(plaintext, wrap)` from the jsfuck.js of `dialect`
#[derive(Deserialize)]
struct Vector {
    dialect: String,
    plaintext: String,
    wrap: bool,
    code: String,
}

/// The code of the vector for `plaintext` from `dialect`, without the eval wrapper
fn vector(dialect: &str, plaintext: &str) -> String {
    let fixture: Fixture = toml::from_str(include_str!("test_fixtures/jsfuck.toml"))
        .expect("tests/test_fixtures/jsfuck.toml parses");
    fixture
        .vector
        .into_iter()
        .find(|v| v.dialect == dialect && v.plaintext == plaintext && !v.wrap)
        .unwrap_or_else(|| panic!("no {dialect} vector for {plaintext:?}"))
        .code
}

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
fn jsfuck_0_4_0_is_cracked() {
    // npm jsfuck@0.4.0 writes `hello world` in 4,103 characters. The search only accepts
    // a result under 5% of the input because JSFuck is tagged `program`. On master it
    // timed out.
    let code = vector("0.4.0", "hello world");
    assert_eq!(code.len(), 4103);
    let result = crack(&code);
    assert_eq!(result.text[0], "hello world");
    assert_eq!(path(&result), ["JSFuck"]);
}

#[test]
#[serial]
fn jsfuck_0_5_0_is_cracked() {
    // What jsfuck.com writes today: [].at, String.name, at("-1"). On master the search
    // found nothing.
    let result = crack(&vector("0.5.0", "flag{jsfuck}"));
    assert_eq!(result.text[0], "flag{jsfuck}");
    assert_eq!(path(&result), ["JSFuck"]);
}

#[test]
#[serial]
fn jsfuck_inside_base64_is_cracked() {
    // GNU coreutils `base64 -w0` of the 653-character 0.4.0 program for `a nice day`. On
    // master the search answered `EAxzHxzFxHAHxzz...` (Base64 -> rot47 -> caesar -> rot47).
    let encoded = STANDARD.encode(vector("0.4.0", "a nice day"));
    assert_eq!(encoded.len(), 872);
    assert!(encoded.starts_with("KCFbXStbXSlbKyErW11dKygrWyFbXV0rW11bKCFb"));
    let result = crack(&encoded);
    assert_eq!(result.text[0], "a nice day");
    assert_eq!(path(&result), ["Base64", "JSFuck"]);
}
