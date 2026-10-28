//! End-to-end tests for the MIME encoded-word decoder (<https://github.com/bee-san/Ciphey/issues/945>):
//! the whole search, as the CLI runs it, has to find the plaintext through MIME Encoded-Word.

use ciphey::config::Config;
use ciphey::perform_cracking;
use ciphey::storage::database::DB_PATH;
use ciphey::DecoderResult;

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
fn b_encoded_word_is_cracked() {
    // Python 3: email.header.Header("Hello, World!", "utf-8").encode()
    let result = crack("=?utf-8?B?SGVsbG8sIFdvcmxkIQ==?=");
    assert_eq!(result.text[0], "Hello, World!");
    assert_eq!(path(&result), ["MIME Encoded-Word"]);
}

#[test]
fn q_encoded_word_is_cracked() {
    let result = crack("=?utf-8?Q?The_quick_brown_fox_jumps_over_the_lazy_dog?=");
    assert_eq!(
        result.text[0],
        "The quick brown fox jumps over the lazy dog"
    );
    assert_eq!(path(&result), ["MIME Encoded-Word"]);
}

#[test]
fn words_in_two_charsets_are_cracked() {
    // RFC 2047 §8: an ISO-8859-1 word and an ISO-8859-2 word, joined
    let result = crack(
        "=?ISO-8859-1?B?SWYgeW91IGNhbiByZWFkIHRoaXMgeW8=?= =?ISO-8859-2?B?dSB1bmRlcnN0YW5kIHRoZSBleGFtcGxlLg==?=",
    );
    assert_eq!(
        result.text[0],
        "If you can read this you understand the example."
    );
    assert_eq!(path(&result), ["MIME Encoded-Word"]);
}

#[test]
fn encoded_word_inside_base64_is_cracked() {
    // Python 3: base64.b64encode(b"=?utf-8?Q?The_quick_brown_fox_jumps_over_the_lazy_dog?=")
    let result =
        crack("PT91dGYtOD9RP1RoZV9xdWlja19icm93bl9mb3hfanVtcHNfb3Zlcl90aGVfbGF6eV9kb2c/PQ==");
    assert_eq!(
        result.text[0],
        "The quick brown fox jumps over the lazy dog"
    );
    assert_eq!(path(&result), ["Base64", "MIME Encoded-Word"]);
}
