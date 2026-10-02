//! End-to-end tests for the Baudot decoder (<https://github.com/bee-san/Ciphey/issues/956>):
//! the whole search, as the CLI runs it, has to find the plaintext through Baudot.
//!
//! The vectors were made with an independent Python ITA2 encoder built from Wikipedia's
//! table (<https://en.wikipedia.org/wiki/Baudot_code#ITA_2_and_US-TTY>), most significant
//! bit first with the US-TTY figures, and decode back to the same text with the tables of
//! the PyPI package `baudot` 0.1.1.
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
    // On master (aa5ce486) the search settled on the false positive `THIREUSEARP`
    // (Baconian -> Vigenere) for this input
    let result = crack("10100 00001 10010 10010 11000 00100 10011 11000 01010 10010 01001");
    assert_eq!(result.text[0], "HELLO WORLD");
    assert_eq!(path(&result), ["Baudot"]);
}

#[test]
#[serial]
fn figures_are_cracked() {
    // FIGS before 10, LTRS before PM
    let result = crack("11100 00001 00001 10000 00100 11100 00001 00100 00011 10000 00100 11011 10111 10110 00100 11111 10110 11100");
    assert_eq!(result.text[0], "MEET ME AT 10 PM");
    assert_eq!(path(&result), ["Baudot"]);
}

#[test]
#[serial]
fn least_significant_bit_first_is_cracked() {
    // HELLO WORLD with each group written in transmission order
    let result = crack("00101 10000 01001 01001 00011 00100 11001 00011 01010 01001 10010");
    assert_eq!(result.text[0], "HELLO WORLD");
    assert_eq!(path(&result), ["Baudot"]);
}

#[test]
#[serial]
fn sentence_with_punctuation_is_cracked() {
    // The bench `medium` plaintext upper-cased; the comma and full stop are figures
    let result = crack("11100 00001 00001 10000 00100 11100 00001 00100 00011 10000 00100 10000 10100 00001 00100 11000 10010 01001 00100 10010 00110 11010 10100 10000 10100 11000 00111 00101 00001 00100 00011 01101 10000 00001 01010 00100 11100 00110 01001 01100 00110 11010 10100 10000 00100 00011 01100 01001 00100 11001 01010 00110 01100 11010 00100 10000 10100 00001 00100 11100 00011 10110 11011 01100 00100 11111 10000 10100 00001 00100 01111 00001 10101 00100 00011 01100 01001 00100 00011 00100 10000 11000 01010 01110 10100 11011 11100");
    assert_eq!(
        result.text[0],
        "MEET ME AT THE OLD LIGHTHOUSE AFTER MIDNIGHT AND BRING THE MAP, THE KEY AND A TORCH."
    );
    assert_eq!(path(&result), ["Baudot"]);
}

#[test]
#[serial]
fn baudot_inside_base64_is_cracked() {
    // Python 3: base64.b64encode() of the issue example. On master the search returned
    // a Reverse -> Vigenere false positive for it.
    let result = crack(
        "MTAxMDAgMDAwMDEgMTAwMTAgMTAwMTAgMTEwMDAgMDAxMDAgMTAwMTEgMTEwMDAgMDEwMTAgMTAwMTAgMDEwMDE=",
    );
    assert_eq!(result.text[0], "HELLO WORLD");
    assert_eq!(path(&result), ["Base64", "Baudot"]);
}

#[test]
#[serial]
fn sentence_inside_base64_is_cracked() {
    // Python 3: base64.b64encode() of the sentence above
    let result = crack("MTExMDAgMDAwMDEgMDAwMDEgMTAwMDAgMDAxMDAgMTExMDAgMDAwMDEgMDAxMDAgMDAwMTEgMTAwMDAgMDAxMDAgMTAwMDAgMTAxMDAgMDAwMDEgMDAxMDAgMTEwMDAgMTAwMTAgMDEwMDEgMDAxMDAgMTAwMTAgMDAxMTAgMTEwMTAgMTAxMDAgMTAwMDAgMTAxMDAgMTEwMDAgMDAxMTEgMDAxMDEgMDAwMDEgMDAxMDAgMDAwMTEgMDExMDEgMTAwMDAgMDAwMDEgMDEwMTAgMDAxMDAgMTExMDAgMDAxMTAgMDEwMDEgMDExMDAgMDAxMTAgMTEwMTAgMTAxMDAgMTAwMDAgMDAxMDAgMDAwMTEgMDExMDAgMDEwMDEgMDAxMDAgMTEwMDEgMDEwMTAgMDAxMTAgMDExMDAgMTEwMTAgMDAxMDAgMTAwMDAgMTAxMDAgMDAwMDEgMDAxMDAgMTExMDAgMDAwMTEgMTAxMTAgMTEwMTEgMDExMDAgMDAxMDAgMTExMTEgMTAwMDAgMTAxMDAgMDAwMDEgMDAxMDAgMDExMTEgMDAwMDEgMTAxMDEgMDAxMDAgMDAwMTEgMDExMDAgMDEwMDEgMDAxMDAgMDAwMTEgMDAxMDAgMTAwMDAgMTEwMDAgMDEwMTAgMDExMTAgMTAxMDAgMTEwMTEgMTExMDA=");
    assert_eq!(
        result.text[0],
        "MEET ME AT THE OLD LIGHTHOUSE AFTER MIDNIGHT AND BRING THE MAP, THE KEY AND A TORCH."
    );
    assert_eq!(path(&result), ["Base64", "Baudot"]);
}
