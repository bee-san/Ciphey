//! End-to-end tests for the Zero-width decoder
//! (<https://github.com/bee-san/Ciphey/issues/973>): the whole search, as the CLI runs it,
//! has to find a message hidden in zero-width characters.
//!
//! The inputs here are bare payloads, the zero-width characters without a cover text, as
//! they are when extracted from a file. With the default checkers a cover text such as
//! `Nothing to see here` is accepted as plaintext before any decoder runs, so a message
//! in a cover text is found with a crib (`tests/zero_width_crib.rs`).
//!
//! Every payload was made by the tool named with it and decoded back by the same tool
//! (see the unit tests in `src/decoders/zero_width_decoder.rs`).
//!
//! The tests run one at a time: every search uses all cores, and side by side on a slow
//! CI runner they would slow each other down.

use ciphey::config::Config;
use ciphey::perform_cracking;
use ciphey::storage::database::DB_PATH;
use ciphey::DecoderResult;
use serial_test::serial;

/// Copies `text`, writing each letter between `[` and `]` as its zero-width character:
/// `B` U+200B, `C` U+200C, `D` U+200D, `E` U+200E, `F` U+200F, `W` U+2060, `Z` U+FEFF.
fn zw(text: &str) -> String {
    let mut inside = false;
    text.chars()
        .filter_map(|c| match c {
            '[' => {
                inside = true;
                None
            }
            ']' => {
                inside = false;
                None
            }
            _ if !inside => Some(c),
            'B' => Some('\u{200B}'),
            'C' => Some('\u{200C}'),
            'D' => Some('\u{200D}'),
            'E' => Some('\u{200E}'),
            'F' => Some('\u{200F}'),
            'W' => Some('\u{2060}'),
            'Z' => Some('\u{FEFF}'),
            _ => panic!("{c:?} isn't a zero-width letter"),
        })
        .collect()
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
fn issue_scheme_is_cracked() {
    // U+200B for 0, U+200C for 1, U+200D between the bytes. On master the search
    // answered `EITIITES6IBSTE6ITIITIINEITEI` (Reverse -> simplesubstitution).
    let result = crack(&zw("[BCCBCBBBDBCCBBCBCDBCCBCCBBDBCCBCCBBDBCCBCCCCDBBCBBBBBDBCCCBCCCDBCCBCCCCDBCCCBBCBDBCCBCCBBDBCCBBCBB]"));
    assert_eq!(result.text[0], "hello world");
    assert_eq!(path(&result), ["Zero-width"]);
}

#[test]
#[serial]
fn steganographr_is_cracked() {
    // Bits without leading zeros, U+2060 between the bytes, U+FEFF around the message
    let result = crack(&zw("[ZCCBBBBCWCCCBCBBWCCCBCBBWCCBBBBCWCCBBBCCWCCBCBCCWCBBBBBWCCBBBBCWCCCBCBBWCBBBBBWCCBBCBBWCCBBBBCWCCCBCCCWCCBCCCBZ]"));
    assert_eq!(result.text[0], "attack at dawn");
    assert_eq!(path(&result), ["Zero-width"]);
}

#[test]
#[serial]
fn zwsp_steg_is_cracked() {
    // zwsp-steg 1.0.1's MODE_FULL: 7 base-5 digits per UTF-16 code unit. On master the
    // search found nothing.
    let result = crack(&zw("[BBBBFCFBBBBFBCBBBBFBCBBBBFECBBBBCCDBBBBFCFBBBBFBCBBBBCCDBBBBEFDBBBBFECBBBBCCDBBBBFCFBBBBFCBBBBBFBBBBBBFDBBBBBFCBBBBBFBEBBBBFBFBBBBFEC]"));
    assert_eq!(result.text[0], "meet me at midnight");
    assert_eq!(path(&result), ["Zero-width"]);
}

#[test]
#[serial]
fn zero_width_inside_base64_is_cracked() {
    // GNU coreutils `base64 -w0` of the UTF-8 bytes of the issue_scheme_is_cracked
    // payload. The message is 11 characters of 392, which the search only accepts
    // because Zero-width is tagged `program`. On master the search answered
    // `HETHEAHITHITH4ETRVI4RETHITHE` (Base64 -> simplesubstitution -> Vigenere).
    let result = crack("4oCL4oCM4oCM4oCL4oCM4oCL4oCL4oCL4oCN4oCL4oCM4oCM4oCL4oCL4oCM4oCL4oCM4oCN4oCL4oCM4oCM4oCL4oCM4oCM4oCL4oCL4oCN4oCL4oCM4oCM4oCL4oCM4oCM4oCL4oCL4oCN4oCL4oCM4oCM4oCL4oCM4oCM4oCM4oCM4oCN4oCL4oCL4oCM4oCL4oCL4oCL4oCL4oCL4oCN4oCL4oCM4oCM4oCM4oCL4oCM4oCM4oCM4oCN4oCL4oCM4oCM4oCL4oCM4oCM4oCM4oCM4oCN4oCL4oCM4oCM4oCM4oCL4oCL4oCM4oCL4oCN4oCL4oCM4oCM4oCL4oCM4oCM4oCL4oCL4oCN4oCL4oCM4oCM4oCL4oCL4oCM4oCL4oCL");
    assert_eq!(result.text[0], "hello world");
    assert_eq!(path(&result), ["Base64", "Zero-width"]);
}
