//! End-to-end tests for the ASCII shift cracker (<https://github.com/bee-san/Ciphey/issues/994>):
//! the whole search, as the CLI runs it, has to find the plaintext through ASCII shift.
//!
//! The mod 256 ciphertexts were made with CyberChef 10.24's ADD (key as hex) and decrypt back
//! with its SUB; the mod 128 one is Python Ciphey's test vector, `chr((ord(c) + 90) % 128)`.
//!
//! The tests run one at a time: every search uses all cores, and side by side on a slow CI
//! runner they would slow each other down.

use ciphey::config::Config;
use ciphey::perform_cracking;
use ciphey::storage::database::DB_PATH;
use ciphey::DecoderResult;
use serial_test::serial;

/// Runs the whole search on `text` and returns what it found.
fn crack(text: &str) -> DecoderResult {
    // With no database path every connection is a fresh in-memory database, so the search
    // doesn't read the cache in ~/.ciphey (an answer cached by another build would stand in
    // for the search under test) and doesn't write to it.
    let _ = DB_PATH.set(None);
    // The decoder statistics the search uses in its edge costs live as long as the process.
    // Clearing them makes every search explore like a fresh `ciphey` run, so the result
    // doesn't depend on which tests ran before.
    ciphey::reset_decoder_stats();
    // The default config apart from the timeout: `cargo test` builds without optimisations,
    // and CI runners have few cores. The config is global to the process, so every test here
    // gets the same one.
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

/// The key the ASCII shift step reported.
fn key(result: &DecoderResult) -> Option<&str> {
    result
        .path
        .iter()
        .find(|step| step.decoder == "ASCII shift")?
        .key
        .as_deref()
}

#[test]
#[serial]
fn issue_example() {
    // "hello world" + 7: rot47 and Caesar both fail on it, and master answered with
    // `rot47 -> Vigenere` junk
    let result = crack("olssv'~vysk");
    assert_eq!(result.text[0], "hello world");
    assert_eq!(path(&result), ["ASCII shift"]);
    assert_eq!(key(&result), Some("7 (mod 256)"));
}

#[test]
#[serial]
fn every_byte_above_0x7f() {
    // "hello world" + 129: Latin-1 text that only this cracker reads
    let result = crack("\u{e9}\u{e6}\u{ed}\u{ed}\u{f0}\u{a1}\u{f8}\u{f0}\u{f3}\u{ed}\u{e5}");
    assert_eq!(result.text[0], "hello world");
    assert_eq!(path(&result), ["ASCII shift"]);
    assert_eq!(key(&result), Some("129 (mod 256)"));
}

#[test]
#[serial]
fn wrapping_past_0xff() {
    // "hello world" + 200: `h` (0x68) wraps to `0`
    let result = crack("0-447\u{e8}?7:4,");
    assert_eq!(result.text[0], "hello world");
    assert_eq!(path(&result), ["ASCII shift"]);
    assert_eq!(key(&result), Some("200 (mod 256)"));
}

#[test]
#[serial]
fn python_ciphey_mod_128_vector() {
    let result = crack("\"?FFIzGSzH;G?zCMz<??z;H>z#zFCE?z>IAz;H>z;JJF?z;H>zNL??");
    assert_eq!(
        result.text[0],
        "Hello my name is bee and I like dog and apple and tree"
    );
    assert_eq!(path(&result), ["ASCII shift"]);
    assert_eq!(key(&result), Some("90 (mod 128)"));
}

#[test]
#[serial]
fn hex_of_the_issue_example() {
    // CyberChef's To Hex of the issue's ciphertext: Hexadecimal hands the bytes on and
    // ASCII shift cracks them
    let result = crack("6f6c737376277e7679736b");
    assert_eq!(result.text[0], "hello world");
    assert_eq!(path(&result), ["Hexadecimal", "ASCII shift"]);
    assert_eq!(key(&result), Some("7 (mod 256)"));
}

#[test]
#[serial]
fn base64_of_bytes_that_are_not_utf8() {
    // Base64 of "hello world" + 129. The Base64 decoder drops bytes that aren't UTF-8, so
    // ASCII shift reads the Base64 itself, and the path is that one step.
    let result = crack("6ebt7fCh+PDz7eU=");
    assert_eq!(result.text[0], "hello world");
    assert_eq!(path(&result), ["ASCII shift"]);
    assert_eq!(key(&result), Some("129 (mod 256)"));
}

#[test]
#[serial]
fn ctf_flag_with_c1_controls() {
    // "flag{ascii_shift_is_not_rot47}" + 13: `{`, `_` and `}` become C1 control characters
    let result =
        crack("synt\u{88}n\u{80}pvvl\u{80}uvs\u{81}lv\u{80}l{|\u{81}l\u{7f}|\u{81}AD\u{8a}");
    assert_eq!(result.text[0], "flag{ascii_shift_is_not_rot47}");
    assert_eq!(path(&result), ["ASCII shift"]);
    assert_eq!(key(&result), Some("13 (mod 256)"));
}
