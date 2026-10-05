//! End-to-end tests for the Unicode Fancy Text decoder
//! (<https://github.com/bee-san/Ciphey/issues/971>): the whole search, as the CLI runs it,
//! has to find the plaintext through Unicode Fancy Text.
//!
//! Without the decoder the search gives up on the circled and small capitals inputs, runs
//! out of time on the monospace one, and returns gibberish for the bold one (rot47 →
//! caesar → Single-byte XOR) and for its Base64 (railfence → rot47). rot47 reads every
//! character as its low byte, so it turns fullwidth text into ASCII by accident, and
//! squared text into `HELLO= WORLD2`.

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
fn mathematical_bold_is_cracked() {
    // The example in the issue
    let result = crack("𝐡𝐞𝐥𝐥𝐨 𝐰𝐨𝐫𝐥𝐝");
    assert_eq!(result.text[0], "hello world");
    assert_eq!(path(&result), ["Unicode Fancy Text"]);
}

#[test]
fn circled_letters_are_cracked() {
    // One of the issue's other forms
    let result = crack("ⓗⓔⓛⓛⓞ ⓦⓞⓡⓛⓓ");
    assert_eq!(result.text[0], "hello world");
    assert_eq!(path(&result), ["Unicode Fancy Text"]);
}

#[test]
fn small_capitals_are_cracked() {
    let result = crack("ʜᴇʟʟᴏ ᴡᴏʀʟᴅ");
    assert_eq!(result.text[0], "hello world");
    assert_eq!(path(&result), ["Unicode Fancy Text"]);
}

#[test]
fn monospace_pangram_is_cracked() {
    let result = crack("𝚃𝚑𝚎 𝚚𝚞𝚒𝚌𝚔 𝚋𝚛𝚘𝚠𝚗 𝚏𝚘𝚡 𝚓𝚞𝚖𝚙𝚜 𝚘𝚟𝚎𝚛 𝚝𝚑𝚎 𝚕𝚊𝚣𝚢 𝚍𝚘𝚐");
    assert_eq!(
        result.text[0],
        "The quick brown fox jumps over the lazy dog"
    );
    assert_eq!(path(&result), ["Unicode Fancy Text"]);
}

#[test]
fn fullwidth_is_cracked() {
    // The issue's last form. rot47 finds the same `hello world` in the same search step;
    // the search reports Unicode Fancy Text because it is listed first in
    // `filter_and_get_decoders`.
    let result = crack("ｈｅｌｌｏ ｗｏｒｌｄ");
    assert_eq!(result.text[0], "hello world");
    assert_eq!(path(&result), ["Unicode Fancy Text"]);
}

#[test]
fn squared_letters_beat_rot47() {
    // In the same search step rot47 turns this into `HELLO= WORLD2`, which the English
    // checker accepts too; Unicode Fancy Text wins because it is listed first.
    let result = crack("🄷🄴🄻🄻🄾, 🅆🄾🅁🄻🄳!");
    assert_eq!(result.text[0], "HELLO, WORLD!");
    assert_eq!(path(&result), ["Unicode Fancy Text"]);
}

#[test]
fn fancy_text_inside_base64_is_cracked() {
    // printf '𝐡𝐞𝐥𝐥𝐨 𝐰𝐨𝐫𝐥𝐝' | base64 -w0
    let result = crack("8J2QofCdkJ7wnZCl8J2QpfCdkKgg8J2QsPCdkKjwnZCr8J2QpfCdkJ0=");
    assert_eq!(result.text[0], "hello world");
    assert_eq!(path(&result), ["Base64", "Unicode Fancy Text"]);
}
