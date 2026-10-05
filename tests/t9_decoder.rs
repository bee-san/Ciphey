//! End-to-end tests for the T9 decoder (<https://github.com/bee-san/Ciphey/issues/961>):
//! the whole search, as the CLI runs it, has to find the plaintext through T9.

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
fn issue_example_is_cracked() {
    // Railfence turns this into `4936575563 `, which LemmeKnow takes for a phone number, in
    // the same search step: T9 comes first in the decoder list
    let result = crack("43556 96753");
    assert_eq!(result.text[0], "hello world");
    assert_eq!(path(&result), ["T9"]);
}

#[test]
fn sentence_is_cracked() {
    let result = crack("843 3524 47 443336 46 843 427336");
    assert_eq!(result.text[0], "the flag is hidden in the garden");
    assert_eq!(path(&result), ["T9"]);
}

#[test]
fn sentence_with_a_one_letter_word_is_cracked() {
    let result = crack("8447 47 2 732738 6377243");
    assert_eq!(result.text[0], "this is a secret message");
    assert_eq!(path(&result), ["T9"]);
}

#[test]
fn t9_inside_dtmf_is_cracked() {
    // The DTMF tones of `43556 96753`, with a line break between the words, which DTMF
    // decodes to a space. Athena doesn't take the digits for plaintext, so the search goes
    // on to T9.
    let result = crack(
        "770-1209 697-1477 770-1336 770-1336 770-1477\n852-1477 770-1477 852-1209 770-1336 697-1477",
    );
    assert_eq!(result.text[0], "hello world");
    assert_eq!(path(&result), ["DTMF", "T9"]);
}
