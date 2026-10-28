//! End-to-end tests for the Beaufort cracker (<https://github.com/bee-san/Ciphey/issues/1002>):
//! the whole search, as the CLI runs it, has to find the plaintext through Beaufort.
//!
//! The ciphertexts keep the plaintext's case and non-letters, and their letters match
//! pycipher 0.5.2 `Beaufort(key).encipher`. On master before this decoder the search
//! answered both with a Vigenère false positive ("Kthc he ro inn ...").
//!
//! The tests run one at a time: every search uses all cores, and side by side on a slow
//! CI runner they would slow each other down.

use ciphey::config::Config;
use ciphey::perform_cracking;
use ciphey::storage::database::DB_PATH;
use ciphey::DecoderResult;
use serial_test::serial;

/// The decoder benchmarks' medium plaintext.
const LIGHTHOUSE: &str =
    "Meet me at the old lighthouse after midnight and bring the map, the key and a torch.";

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
fn beaufort_ciphertext_is_cracked() {
    // Key LEMON
    let result = crack(
        "Zaiv bh et vgh qbl cdyfvgxkuk nglix bdbzghel mbk knebh sxi cnw, lfk dhg mbk l lyxle.",
    );
    assert_eq!(result.text[0], LIGHTHOUSE, "path: {:?}", path(&result));
    assert_eq!(path(&result), ["Beaufort"]);
    assert_eq!(result.path[0].key.as_deref(), Some("LEMON"));
}

#[test]
#[serial]
fn beaufort_inside_base64_is_cracked() {
    // base64(beaufort(LIGHTHOUSE, LEMON)), from Python 3.9's base64.b64encode
    let result = crack(
        "WmFpdiBiaCBldCB2Z2ggcWJsIGNkeWZ2Z3hrdWsgbmdsaXggYmRiemdoZWwgbWJrIGtuZWJoIHN4aSBjbncsIGxmayBkaGcgbWJrIGwgbHl4bGUu",
    );
    assert_eq!(result.text[0], LIGHTHOUSE, "path: {:?}", path(&result));
    assert_eq!(path(&result), ["Base64", "Beaufort"]);
}

#[test]
#[serial]
fn unspaced_beaufort_ciphertext_is_cracked() {
    // Key CIPHEY, the Dickens text without spaces or punctuation. Checked with Medium
    // sensitivity, where Vigenère can also find something in the same step; Beaufort
    // comes first in the decoder list, so it wins the tie.
    let result = crack(
        "UPTHMFVEODMFODWZSUKAWLEGJBLLQHKPBCLQQEXZLCCQWAAYWEBCIQKFBVWFGIXOXUCCLTZTOUEZMRPEXPWFGIXOXUYTBFXKXHLWWUXAWLEGJBLDPKABBCWLARLEKNUPRZLCCQWAAGYIXTRKXXHBXFUPTHMFVEXDEGOVBCBYLYCDMG",
    );
    assert_eq!(
        result.text[0],
        "ITWASTHEBESTOFTIMESITWASTHEWORSTOFTIMESITWASTHEAGEOFWISDOMITWASTHEAGEOFFOOLISHNESSITWASTHEEPOCHOFBELIEFITWASTHEEPOCHOFINCREDULITYITWASTHESEASONOFLIGHTITWASTHESEASONOFDARKNESS",
        "path: {:?}",
        path(&result)
    );
    assert_eq!(path(&result), ["Beaufort"]);
    assert_eq!(result.path[0].key.as_deref(), Some("CIPHEY"));
}

#[test]
#[serial]
fn atbash_is_still_cracked_by_atbash() {
    // Beaufort with the one-letter key Z is Atbash, which Beaufort leaves to Atbash
    let result = crack(
        "Nvvg nv zg gsv low ortsgslfhv zugvi nrwmrtsg zmw yirmt gsv nzk, gsv pvb zmw z glixs.",
    );
    assert_eq!(result.text[0], LIGHTHOUSE);
    assert_eq!(path(&result), ["atbash"]);
}
