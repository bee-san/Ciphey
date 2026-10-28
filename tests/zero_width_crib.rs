//! End-to-end tests for the Zero-width decoder
//! (<https://github.com/bee-san/Ciphey/issues/973>) with a crib, as `ciphey -r 'flag\{'`
//! runs it.
//!
//! With the default checkers a cover text such as `Nothing to see here` is accepted as
//! plaintext before any decoder runs. With a crib only the regex checker runs, so the
//! cover isn't accepted and the search finds the message hidden in it. The config is
//! global to the process, so these tests are in their own file, apart from the
//! default-config ones in `tests/zero_width_decoder.rs`.
//!
//! The payload is the issue's scheme (U+200B for 0, U+200C for 1, U+200D between the
//! bytes), made with Python 3.9 and decoded back with it.
//!
//! The tests run one at a time: every search uses all cores, and side by side on a slow
//! CI runner they would slow each other down.

use ciphey::config::Config;
use ciphey::storage::database::DB_PATH;
use ciphey::{perform_cracking, CipheyError, DecoderResult};
use serial_test::serial;

/// `flag{zero_width_is_fun}` in the issue's scheme, in `zw` notation
const FLAG: &str = "[BCCBBCCBDBCCBCCBBDBCCBBBBCDBCCBBCCCDBCCCCBCCDBCCCCBCBDBCCBBCBCDBCCCBBCBDBCCBCCCCDBCBCCCCCDBCCCBCCCDBCCBCBBCDBCCBBCBBDBCCCBCBBDBCCBCBBBDBCBCCCCCDBCCBCBBCDBCCCBBCCDBCBCCCCCDBCCBBCCBDBCCCBCBCDBCCBCCCBDBCCCCCBC]";

/// Copies `text`, writing each letter between `[` and `]` as its zero-width character:
/// `B` U+200B, `C` U+200C, `D` U+200D.
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
            _ => panic!("{c:?} isn't a zero-width letter"),
        })
        .collect()
}

/// Runs the whole search on `text` with the crib `flag\{`.
fn search(text: &str) -> Result<Option<DecoderResult>, CipheyError> {
    // With no database path every connection is a fresh in-memory database, so nothing
    // in ~/.ciphey is read or written.
    let _ = DB_PATH.set(None);
    // Every search explores like a fresh `ciphey` run, whichever tests ran before
    ciphey::reset_decoder_stats();
    // The config is global to the process, so every test here gets the same one. The
    // flags are found in the first step; the timeout bounds the search that finds
    // nothing.
    let config = Config {
        timeout: 10,
        regex: Some(r"flag\{".to_string()),
        ..Config::default()
    };
    perform_cracking(text, config)
}

/// Runs the whole search on `text` with the crib and returns what it found.
fn crack(text: &str) -> DecoderResult {
    search(text)
        .unwrap_or_else(|error| panic!("searching {text:?} failed: {error}"))
        .unwrap_or_else(|| panic!("the search found nothing for {text:?}"))
}

/// The names of the decoders the search used, in order.
fn path(result: &DecoderResult) -> Vec<&str> {
    result.path.iter().map(|step| step.decoder).collect()
}

#[test]
#[serial]
fn flag_in_a_cover_text_is_cracked() {
    // On master the search timed out
    let result = crack(&zw(&format!("Nothing{FLAG} to see here")));
    assert_eq!(result.text[0], "flag{zero_width_is_fun}");
    assert_eq!(path(&result), ["Zero-width"]);
}

#[test]
#[serial]
fn flag_in_a_long_cover_text_is_cracked() {
    // The flag is 23 characters of 615. The search only accepts a result under 5% of
    // the input from a decoder tagged `program`, as Zero-width is.
    let text = zw(&format!(
        "The quick brown fox jumps over the lazy dog while the cat sleeps on the warm windowsill. Nothing about this paragraph is unusual and it reads like any other note you might find in a shared folder. It {FLAG}talks about the weather, which was mild for the time of year, and about dinner plans for the weekend. There is really nothing to see here, so move along and do not look too closely at the spaces between words."
    ));
    assert_eq!(text.chars().count(), 615);
    let result = crack(&text);
    assert_eq!(result.text[0], "flag{zero_width_is_fun}");
    assert_eq!(path(&result), ["Zero-width"]);
}

#[test]
#[serial]
fn cover_text_alone_is_not_reported() {
    // Without the hidden characters there is no flag to find
    let result = search("Nothing to see here");
    assert!(
        matches!(result, Ok(None) | Err(CipheyError::Timeout { .. })),
        "{result:?}"
    );
}
