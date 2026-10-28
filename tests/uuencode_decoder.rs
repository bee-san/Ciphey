//! End-to-end tests for the Uuencode decoder (<https://github.com/bee-san/Ciphey/issues/958>):
//! the whole search, as the CLI runs it, has to find the plaintext through Uuencode.
//!
//! The vectors were made with Python 3.9's `uu.encode(..., backtick=True)` and
//! `binascii.b2a_uu`, and decoded back with `binascii.a2b_uu` and perl's `unpack("u", ...)`.
//! The issue's own example isn't here: the search takes its `begin`/`end` lines for English
//! and returns the input unchanged, before any decoder runs. The unit tests decode it.
//!
//! The tests run one at a time: every search uses all cores, and side by side on a slow
//! CI runner they would slow each other down.

use ciphey::config::Config;
use ciphey::perform_cracking;
use ciphey::storage::database::DB_PATH;
use ciphey::DecoderResult;
use serial_test::serial;

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
fn uuencoded_file_is_cracked() {
    // uu.encode(..., name="data.txt", mode=0o644, backtick=True). On master the search
    // returned rot47 -> Vigenere gibberish.
    let result = crack(
        r#"begin 644 data.txt
M365E="!M92!A="!T:&4@;VQD(&QI9VAT:&]U<V4@869T97(@;6ED;FEG:'0@
G86YD(&)R:6YG('1H92!M87`L('1H92!K97D@86YD(&$@=&]R8V@N
`
end
"#,
    );
    assert_eq!(result.text[0], LIGHTHOUSE);
    assert_eq!(path(&result), ["Uuencode"]);
}

#[test]
#[serial]
fn single_line_is_cracked() {
    // binascii.b2a_uu(b"Hello, World!", backtick=True), without the line break
    let result = crack(r"-2&5L;&\L(%=O<FQD(0``");
    assert_eq!(result.text[0], "Hello, World!");
    assert_eq!(path(&result), ["Uuencode"]);
}

#[test]
#[serial]
fn uuencode_inside_base64_is_cracked() {
    // base64.b64encode() of the two data lines above, each ending in a line break
    let result = crack("TTM2NUU9IiFNOTIhQT0iIVQ6JjRAO1ZRRCgmUUk5VkFUOiZdVTxWNEA4NjlUOTcoQDs2RUQ7RkVHOicwQApHODZZRCgmKVI6NllHKCcxSDkyIU04N2BMKCcxSDkyIUs5N0RAODZZRCgmJEA9Jl1SOFZATgo=");
    assert_eq!(result.text[0], LIGHTHOUSE);
    assert_eq!(path(&result), ["Base64", "Uuencode"]);
}
