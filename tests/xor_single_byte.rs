//! Full searches that need the single-byte XOR cracker (#1017).

use ciphey::config::Config;
use ciphey::perform_cracking;
use ciphey::DecoderResult;

/// The fox pangram
const FOX: &str = "The quick brown fox jumps over the lazy dog";

/// Runs the full search on `input` with the default config. The cache is in memory, so
/// every search is a miss and nothing under `~/.ciphey` is read or written.
fn crack(input: &str) -> DecoderResult {
    let _ = ciphey::storage::database::DB_PATH.set(None);
    perform_cracking(input, Config::default())
        .unwrap_or_else(|e| panic!("search failed for {input:?}: {e}"))
        .unwrap_or_else(|| panic!("no plaintext found for {input:?}"))
}

/// The decoders on the path, in order
fn decoders(result: &DecoderResult) -> Vec<&'static str> {
    result.path.iter().map(|step| step.decoder).collect()
}

/// The key the XOR step reported
fn xor_key(result: &DecoderResult) -> Option<&str> {
    let step = result
        .path
        .iter()
        .find(|step| step.decoder == "Single-byte XOR")?;
    step.key.as_deref()
}

#[test]
fn cryptopals_hex() {
    // https://cryptopals.com/sets/1/challenges/3
    let result = crack("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
    assert_eq!(result.text[0], "Cooking MC's like a pound of bacon");
    assert!(
        decoders(&result).contains(&"Single-byte XOR"),
        "{:?}",
        decoders(&result)
    );
    assert_eq!(xor_key(&result), Some("0x58"));
}

#[test]
fn high_bit_key_in_base64() {
    // Every byte has its high bit set, so the Base64 decoder alone gets nowhere
    let result = crack("l6um47K2qqCo46GxrLSt46Wsu+Optq6zsOOstaax47erpuOvorm646espA==");
    assert_eq!(result.text[0], FOX);
    assert!(
        decoders(&result).contains(&"Single-byte XOR"),
        "{:?}",
        decoders(&result)
    );
    assert_eq!(xor_key(&result), Some("0xc3"));
}

#[test]
fn ctf_flag_in_hex() {
    let result = crack("3c363b3d21226a28056b2905346a2e0569343928232a2e6b6a3427");
    assert_eq!(result.text[0], "flag{x0r_1s_n0t_3ncrypt10n}");
    assert!(
        decoders(&result).contains(&"Single-byte XOR"),
        "{:?}",
        decoders(&result)
    );
    assert_eq!(xor_key(&result), Some("0x5a"));
}

#[test]
fn base64_xor_base64() {
    // #808: Base64 of the pangram, XORed with 0x42, then Base64 again
    let result =
        crack("FAUqLgsKBHMjFQwwCwUIOyBxJjcLBRg0JwEAMyYVczUhOwA0Ji8UOwsKEC0YEQAxGxoydwsFEDQYNX9/");
    assert_eq!(result.text[0], FOX);
    assert_eq!(decoders(&result), ["Single-byte XOR", "Base64"]);
    assert_eq!(xor_key(&result), Some("0x42"));
}
