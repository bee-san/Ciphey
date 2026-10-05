//! End-to-end tests for the Polybius Square decoder
//! (<https://github.com/bee-san/Ciphey/issues/963>): the whole search, as the CLI runs it,
//! has to find the plaintext through Polybius Square.
//!
//! The ciphertexts were made with pycipher 0.5.2's `PolybiusSquare` and the standard
//! square `ABCDEFGHIKLMNOPQRSTUVWXYZ`, one word at a time, with two spaces between words.
//! Without word breaks the plaintext runs together (`HELLOWORLD`), which the English
//! checker doesn't accept, so every input here has them.

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
fn digit_pairs_are_cracked() {
    // The example in the issue, with a word break
    let result = crack("23 15 31 31 34  52 34 42 31 14");
    assert_eq!(result.text[0], "HELLO WORLD");
    assert_eq!(path(&result), ["Polybius Square"]);
}

#[test]
fn longer_message_is_cracked() {
    let result = crack("32 15 15 44  32 15  11 44  32 24 14 33 24 22 23 44");
    assert_eq!(result.text[0], "MEET ME AT MIDNIGHT");
    assert_eq!(path(&result), ["Polybius Square"]);
}

#[test]
fn adfgx_letter_pairs_are_cracked() {
    // pycipher: PolybiusSquare(..., 5, "ADFGX")
    let result = crack("DF AX FA FA FG  XD FG GD FA AG");
    assert_eq!(result.text[0], "HELLO WORLD");
    assert_eq!(path(&result), ["Polybius Square"]);
}

#[test]
fn polybius_inside_base64_is_cracked() {
    // Python 3: base64.b64encode(b"52 15  11 42 15  14 24 43 ...  34 33 13 15"). Base64 of
    // the shorter vectors above ends at depth 1 instead: Vigenere turns the Base64 text
    // itself into a false positive before the search gets to Polybius Square at depth 2.
    let result = crack("NTIgMTUgIDExIDQyIDE1ICAxNCAyNCA0MyAxMyAzNCA1MSAxNSA0MiAxNSAxNCAgMjEgMzEgMTUgMTUgIDExIDQ0ICAzNCAzMyAxMyAxNQ==");
    assert_eq!(result.text[0], "WE ARE DISCOVERED FLEE AT ONCE");
    assert_eq!(path(&result), ["Base64", "Polybius Square"]);
}
