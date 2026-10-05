//! End-to-end tests for the Keyboard shift decoder (<https://github.com/bee-san/Ciphey/issues/976>):
//! the whole search, as the CLI runs it, has to find the plaintext through Keyboard shift.
//!
//! Without the Keyboard shift decoder the search returns a wrong answer for these inputs:
//! `jr;;p ept;f` comes back as `QODSExO xIx` via railfence → rot47, and the others as
//! gibberish via Vigenère.

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
    // The longer timeout is headroom for slow CI runners. The config is process-wide, so
    // every test uses the same one.
    let config = Config {
        timeout: 20,
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
fn issue_example_is_cracked() {
    // The example in the issue: every key one to the right on US QWERTY
    let result = crack("jr;;p ept;f");
    assert_eq!(result.text[0], "hello world");
    assert_eq!(path(&result), ["Keyboard shift"]);
    assert_eq!(result.path[0].key.as_deref(), Some("QWERTY right 1"));
}

#[test]
fn flag_is_cracked() {
    // `_`, `{` and `}` are keys too: one to the right they are `+`, `}` and `|`
    let result = crack("g;sh}lrunpstf+djogy+od+rsdu|");
    assert_eq!(result.text[0], "flag{keyboard_shift_is_easy}");
    assert_eq!(path(&result), ["Keyboard shift"]);
}

#[test]
fn shift_up_is_cracked() {
    // Every key replaced by the key above it, so the digits take part
    let result = crack("y3oo9 294oe");
    assert_eq!(result.text[0], "hello world");
    assert_eq!(path(&result), ["Keyboard shift"]);
    assert_eq!(result.path[0].key.as_deref(), Some("QWERTY up"));
}

#[test]
fn keyboard_shift_inside_base64_is_cracked() {
    // Python 3: base64.b64encode(b"<rry ,r sy yjr p;f ;ohjyjpidr sgyrt ,ofmohjy smf ntomh yjr ,s[. yjr lru smf s yptvj/")
    let result = crack(
        "PHJyeSAsciBzeSB5anIgcDtmIDtvaGp5anBpZHIgc2d5cnQgLG9mbW9oankgc21mIG50b21oIHlqciAsc1suIHlqciBscnUgc21mIHMgeXB0dmov",
    );
    assert_eq!(
        result.text[0],
        "Meet me at the old lighthouse after midnight and bring the map, the key and a torch."
    );
    assert_eq!(path(&result), ["Base64", "Keyboard shift"]);
}
