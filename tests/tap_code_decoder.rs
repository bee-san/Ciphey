//! End-to-end tests for the Tap Code decoder (<https://github.com/bee-san/Ciphey/issues/962>):
//! the whole search, as the CLI runs it, has to find the plaintext through Tap Code.
//!
//! The vectors use the square in Python Ciphey's tap code table (cipheydists
//! `translate/tap_code.json`), which is Wikipedia's: <https://en.wikipedia.org/wiki/Tap_code>.
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
fn issue_example_is_cracked() {
    // On master the search returned `67597575789678867558` for this input
    let result = crack("2,3 1,5 3,1 3,1 3,4  5,2 3,4 4,2 3,1 1,4");
    assert_eq!(result.text[0], "HELLO WORLD");
    assert_eq!(path(&result), ["Tap Code"]);
}

#[test]
#[serial]
fn issue_knock_example_beats_morse_code() {
    // Morse Code reads the same dots as `ISE5SESESH`, which the English checker accepts
    // too; on master that was the answer
    let result = crack(".. ...  . .....  ... .  ... .  ... ....");
    assert_eq!(result.text[0], "HELLO");
    assert_eq!(path(&result), ["Tap Code"]);
}

#[test]
#[serial]
fn knocks_with_word_gaps_are_cracked() {
    // One space inside a letter, two between letters, three between words
    let result = crack(
        "... ..  . .....  . .....  .... ....   ... ..  . .....   . .  .... ....   ... ..  .. ....  . ....  ... ...  .. ....  .. ..  .. ...  .... ....",
    );
    assert_eq!(result.text[0], "MEET ME AT MIDNIGHT");
    assert_eq!(path(&result), ["Tap Code"]);
}

#[test]
#[serial]
fn wikipedia_bullets_are_cracked() {
    // Wikipedia's example: U+2022 bullets, one space inside a letter, three between letters
    let result = crack("•• •••   • •••••   ••• •   ••• •   ••• ••••");
    assert_eq!(result.text[0], "HELLO");
    assert_eq!(path(&result), ["Tap Code"]);
}

#[test]
#[serial]
fn digit_pairs_beat_rot47() {
    // rot47 turns the digits and commas into `XOU TOT WOW TOX WOU`, which the English
    // checker accepts in the same search step
    let result = crack("5,2 1,1 4,4 1,5 4,2");
    assert_eq!(result.text[0], "WATER");
    assert_eq!(path(&result), ["Tap Code"]);
}

#[test]
#[serial]
fn tap_code_inside_base64_is_cracked() {
    // Python 3: base64.b64encode(b"2,3 1,5 3,1 3,1 3,4  5,2 3,4 4,2 3,1 1,4")
    let result = crack("MiwzIDEsNSAzLDEgMywxIDMsNCAgNSwyIDMsNCA0LDIgMywxIDEsNA==");
    assert_eq!(result.text[0], "HELLO WORLD");
    assert_eq!(path(&result), ["Base64", "Tap Code"]);
}
