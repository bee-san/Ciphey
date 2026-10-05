//! End-to-end tests for the 01248 (Yunying) decoder
//! (<https://github.com/bee-san/Ciphey/issues/965>): the whole search, as the CLI runs it,
//! has to find the plaintext through 01248.
//!
//! The vectors were made with an independent Python encoder (each letter's position
//! written greedily with 8, 4, 2 and 1, groups joined with 0) and decoded back with a
//! Python version of the decoder's rules. The issue's own example, CTF Wiki's
//! `8842101220480224404014224202480122` (`WELLDONE`), isn't here: Athena doesn't take
//! `WELLDONE` for plaintext, so the search goes on and settles on a rot47 false positive.
//! The unit tests check that it decodes.
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
fn congratulations_is_cracked() {
    // On master (a2eb7aa7) the search returned rot47-based junk for this input
    let result = crack("21084210842042108820108840884108401088408108421084208821");
    assert_eq!(result.text[0], "CONGRATULATIONS");
    assert_eq!(path(&result), ["01248 (Yunying)"]);
}

#[test]
#[serial]
fn hello_there_general_is_cracked() {
    let result = crack("804108408408421088408041088204104210410842041088201084");
    assert_eq!(result.text[0], "HELLOTHEREGENERAL");
    assert_eq!(path(&result), ["01248 (Yunying)"]);
}

#[test]
#[serial]
fn sentence_is_cracked() {
    // The bench `medium` plaintext without its spaces and punctuation, which 01248 can't
    // write
    let result = crack("84104104108840841041010884088408041084210840408408104210808840808421088410882104101042088404108820841081040842081042108088401084204020882081084204210884080410841010880884080410821041088810108420401088408421088202108");
    assert_eq!(
        result.text[0],
        "MEETMEATTHEOLDLIGHTHOUSEAFTERMIDNIGHTANDBRINGTHEMAPTHEKEYANDATORCH"
    );
    assert_eq!(path(&result), ["01248 (Yunying)"]);
}

#[test]
#[serial]
fn yunying_inside_base64_is_cracked() {
    // Python 3: base64.b64encode() of the CONGRATULATIONS encoding above
    let result =
        crack("MjEwODQyMTA4NDIwNDIxMDg4MjAxMDg4NDA4ODQxMDg0MDEwODg0MDgxMDg0MjEwODQyMDg4MjE=");
    assert_eq!(result.text[0], "CONGRATULATIONS");
    assert_eq!(path(&result), ["Base64", "01248 (Yunying)"]);
}
