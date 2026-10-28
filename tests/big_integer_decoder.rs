//! End-to-end tests for the Big integer to bytes decoder
//! (<https://github.com/bee-san/Ciphey/issues/952>): the whole search, as the CLI runs it,
//! has to find the plaintext through it.
//!
//! The integers were made with Python 3's `int.from_bytes(data, "big")` (PyCryptodome's
//! `bytes_to_long`) and decoded back with `n.to_bytes((n.bit_length() + 7) // 8, "big")`
//! (`long_to_bytes`).
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
fn pangram_is_cracked() {
    // On master the search returned rot47 -> Vigenere gibberish for this input
    let result = crack("11815744420664747200359014215611078249874077418792906203758916158211866334739307190174417697959789752167");
    assert_eq!(
        result.text[0],
        "The quick brown fox jumps over the lazy dog"
    );
    assert_eq!(path(&result), ["Big integer to bytes"]);
}

#[test]
#[serial]
fn rsa_style_flag_is_cracked() {
    // `print("flag =", bytes_to_long(flag))`, as RSA challenges print their message
    let result = crack(
        "flag = 50937517511040843800057610630687734629648772740622533002167079526478786571835272839786109",
    );
    assert_eq!(result.text[0], "flag{long_to_bytes_is_not_encryption}");
    assert_eq!(path(&result), ["Big integer to bytes"]);
}

#[test]
#[serial]
fn big_integer_inside_base64_is_cracked() {
    // GNU coreutils base64 of the big integer of the bench `medium` plaintext
    let result = crack("NTkyNDI4Njg5NDM2MDIyMjE3NTQ1NjExMDc1Mzc1MjAyNzQyODgyNDkxMTQwNjk1MjQzNjE5MTY3MzU0OTk5Nzg2NDc5MjYxNzQ0NzAzMDU5ODA0ODYzMDYyMDE3NjA1NzUyNTI2NTM0MDIwOTg5NTExNTcyNDc0MTI0ODE2NzMxMjkzMjIwNDQ3OTQyMzM5MTgzNDExOTEzOTQzMjE2OTk3MTU2MDY3MjU0ODA0MDg4NTkwMDA4NjMyODE1OTQxNDU3MjUwOTIzMA==");
    assert_eq!(
        result.text[0],
        "Meet me at the old lighthouse after midnight and bring the map, the key and a torch."
    );
    assert_eq!(path(&result), ["Base64", "Big integer to bytes"]);
}
