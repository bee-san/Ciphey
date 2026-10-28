//! End-to-end tests for the Core Socialist Values decoder
//! (<https://github.com/bee-san/Ciphey/issues/978>): the whole search, as the CLI runs it,
//! has to find the plaintext through Core Socialist Values.
//!
//! The encodings were made with `valuesEncode` from the reference implementation,
//! sym233/core-values-encoder@a419ea5 `src/index.js`
//! (<https://github.com/sym233/core-values-encoder>), and decoded back with its
//! `valuesDecode`.
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
    // On master the search returned `33333` (rot47 → Hexadecimal) for this input
    let result = crack("公正爱国公正平等公正友善公正公正友善公正公正诚信平等文明富强法治法治公正诚信平等法治文明公正诚信文明公正自由");
    assert_eq!(result.text[0], "hello world");
    assert_eq!(path(&result), ["Core Socialist Values"]);
}

#[test]
#[serial]
fn fox_pangram_is_cracked() {
    // The reference's random choice of escape, as it is. On master the search returned
    // Vigenère junk (rot47 → atbash → Hexadecimal → Vigenere).
    let result = crack("平等自由公正爱国公正平等文明富强法治民主法治平等公正敬业公正和谐公正诚信民主文明富强公正文明法治文明公正友善敬业法治法治公正诚信自由文明富强公正公正公正友善敬业法治爱国文明富强公正诚信富强法治平等公正友善法治法治富强法治和谐文明富强公正诚信平等法治公正公正平等法治文明文明富强法治自由公正爱国公正平等文明富强公正诚信文明公正民主法治诚信富强法治敬业文明富强公正自由公正诚信平等公正法治");
    assert_eq!(
        result.text[0],
        "The quick brown fox jumps over the lazy dog"
    );
    assert_eq!(path(&result), ["Core Socialist Values"]);
}

#[test]
#[serial]
fn core_socialist_values_inside_base64_is_cracked() {
    // Python 3: base64.b64encode() of the issue example's UTF-8. On master the search
    // returned Vigenère junk (caesar → Hexadecimal → Vigenere).
    let result = crack("5YWs5q2j54ix5Zu95YWs5q2j5bmz562J5YWs5q2j5Y+L5ZaE5YWs5q2j5YWs5q2j5Y+L5ZaE5YWs5q2j5YWs5q2j6K+a5L+h5bmz562J5paH5piO5a+M5by65rOV5rK75rOV5rK75YWs5q2j6K+a5L+h5bmz562J5rOV5rK75paH5piO5YWs5q2j6K+a5L+h5paH5piO5YWs5q2j6Ieq55Sx");
    assert_eq!(result.text[0], "hello world");
    assert_eq!(path(&result), ["Base64", "Core Socialist Values"]);
}
