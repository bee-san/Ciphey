//! End-to-end tests for the Leetspeak decoder (<https://github.com/bee-san/Ciphey/issues/969>):
//! the whole search, as the CLI runs it, has to find the plaintext through Leetspeak.
//!
//! The leet texts were made with CyberChef 10.24's "Convert Leet Speak" (To Leet Speak),
//! apart from the TryHackMe one, and decode back to the same text with its From Leet Speak
//! where that maps the same symbols.
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
    // On master (0d46a598) the search settled on a rot47 -> Vigenere false positive
    let result = crack("l337 5p34k 15 3l173");
    assert_eq!(result.text[0], "leet speak is elite");
    assert_eq!(path(&result), ["Leetspeak"]);
}

#[test]
#[serial]
fn hello_world_is_cracked() {
    let result = crack("h3ll0 w0rld");
    assert_eq!(result.text[0], "hello world");
    assert_eq!(path(&result), ["Leetspeak"]);
}

#[test]
#[serial]
fn pangram_is_cracked() {
    let result = crack("7h3 qu1ck br0wn f0x jump5 0v3r 7h3 l4zy d0g");
    assert_eq!(
        result.text[0],
        "the quick brown fox jumps over the lazy dog"
    );
    assert_eq!(path(&result), ["Leetspeak"]);
}

#[test]
#[serial]
fn sentence_with_punctuation_is_cracked() {
    // The bench `medium` plaintext
    let result = crack(
        "M337 m3 47 7h3 0ld l1gh7h0u53 4f73r m1dn1gh7 4nd br1ng 7h3 m4p, 7h3 k3y 4nd 4 70rch.",
    );
    assert_eq!(
        result.text[0],
        "Meet me at the old lighthouse after midnight and bring the map, the key and a torch."
    );
    assert_eq!(path(&result), ["Leetspeak"]);
}

#[test]
#[serial]
fn tryhackme_challenge_is_cracked() {
    // TryHackMe c4ptur3-th3-fl4g, "Translation & Shifting 1"
    // (https://raw.githubusercontent.com/AfvanMoopen/tryhackme-/master/c4ptur3-th3-fl4g/README.md).
    // 2 is r in c4p7u23, and 1 is l in f149.
    let result = crack("c4n y0u c4p7u23 7h3 f149?");
    assert_eq!(result.text[0], "can you capture the flag?");
    assert_eq!(path(&result), ["Leetspeak"]);
}

#[test]
#[serial]
fn sentence_inside_base64_is_cracked() {
    // Python 3: base64.b64encode() of the bench `medium` leet text above. (Base64 of the
    // shorter issue example isn't: the search accepts a Vigenere false positive of the
    // Base64 text itself first, a plaintext detection problem.)
    let result = crack("TTMzNyBtMyA0NyA3aDMgMGxkIGwxZ2g3aDB1NTMgNGY3M3IgbTFkbjFnaDcgNG5kIGJyMW5nIDdoMyBtNHAsIDdoMyBrM3kgNG5kIDQgNzByY2gu");
    assert_eq!(
        result.text[0],
        "Meet me at the old lighthouse after midnight and bring the map, the key and a torch."
    );
    assert_eq!(path(&result), ["Base64", "Leetspeak"]);
}
