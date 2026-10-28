//! End-to-end tests for the Bzip2 decoder (<https://github.com/bee-san/Ciphey/issues/1023>):
//! the whole search, as the CLI runs it, has to find the plaintext through Bzip2.
//!
//! The bzip2 data is Python 3.9's `bz2.compress(data)` (level 9), checked with
//! `bzip2 -dc` (bzip2 1.0.8).
//!
//! The tests run one at a time: every search uses all cores, and side by side on a slow
//! CI runner they would slow each other down.

use ciphey::config::Config;
use ciphey::perform_cracking;
use ciphey::storage::database::DB_PATH;
use ciphey::DecoderResult;
use serial_test::serial;

const FOX: &str = "The quick brown fox jumps over the lazy dog";

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
fn bzip2_as_base64_is_cracked() {
    let result = crack("QlpoOTFBWSZTWUWd7mEAAAQTgEAABAA////wIAAxRoaAAAAx6ammTIYRtG1HYmIISe16oVNlZbEl4+JgsfiYOd1MCW+c6F3JFOFCQRZ3uYQ=");
    assert_eq!(result.text[0], FOX);
    assert_eq!(path(&result), ["Bzip2"]);
}

#[test]
#[serial]
fn bzip2_as_hex_is_cracked() {
    let result = crack("425a6839314159265359459dee610000041380400004003ffffff0200031468680000031e9a9a64c8611b46d4762620849ed7aa1536565b125e3e260b1f89839dd4c096f9ce85dc914e142411677b984");
    assert_eq!(result.text[0], FOX);
    assert_eq!(path(&result), ["Bzip2"]);
}

#[test]
#[serial]
fn bzip2_flag_is_cracked() {
    // base64.b64encode(bz2.compress(b"flag{bzip2_block_sorting}"))
    let result = crack(
        "QlpoOTFBWSZTWWimefAAAAOLgBAAAAC5rdwaIAAxTJiZBkYUABso2o0tbq4WS6BPmU+BXUPi7kinChINFM8+AA==",
    );
    assert_eq!(result.text[0], "flag{bzip2_block_sorting}");
    assert_eq!(path(&result), ["Bzip2"]);
}

#[test]
#[serial]
fn bzip2_inside_bzip2_is_cracked() {
    // base64.b64encode(bz2.compress(bz2.compress(FOX)))
    let result = crack("QlpoOTFBWSZTWZmZ/HkAAA5//8RgLQBDACAg86QIMnJCgJBFAABGISAkIAAgAAI4Y0BAoABUYAAAAAAAABpkGAAAADQDQANAAACuUkQYQNG/UWJzzOR5EYNxKwIdr0CrHdhSiZrT548BablhwG4NFwK9Bc7d+iX83ADLoXgbwi+6I+/F3JFOFCQmZn8eQA==");
    assert_eq!(result.text[0], FOX);
    assert_eq!(path(&result), ["Bzip2", "Bzip2"]);
}

#[test]
#[serial]
fn bzip2_hex_inside_base64_is_cracked() {
    // base64.b64encode(bz2.compress(FOX).hex().encode())
    let result = crack("NDI1YTY4MzkzMTQxNTkyNjUzNTk0NTlkZWU2MTAwMDAwNDEzODA0MDAwMDQwMDNmZmZmZmYwMjAwMDMxNDY4NjgwMDAwMDMxZTlhOWE2NGM4NjExYjQ2ZDQ3NjI2MjA4NDllZDdhYTE1MzY1NjViMTI1ZTNlMjYwYjFmODk4MzlkZDRjMDk2ZjljZTg1ZGM5MTRlMTQyNDExNjc3Yjk4NA==");
    assert_eq!(result.text[0], FOX);
    assert_eq!(path(&result), ["Base64", "Bzip2"]);
}

#[test]
#[serial]
fn bzip2_as_binary_is_cracked() {
    // The bits of bz2.compress(FOX). The Binary decoder turns them into bytes, which are
    // not UTF-8, so it passes them on as Latin-1 text and Bzip2 reads them from that.
    let result = crack("01000010 01011010 01101000 00111001 00110001 01000001 01011001 00100110 01010011 01011001 01000101 10011101 11101110 01100001 00000000 00000000 00000100 00010011 10000000 01000000 00000000 00000100 00000000 00111111 11111111 11111111 11110000 00100000 00000000 00110001 01000110 10000110 10000000 00000000 00000000 00110001 11101001 10101001 10100110 01001100 10000110 00010001 10110100 01101101 01000111 01100010 01100010 00001000 01001001 11101101 01111010 10100001 01010011 01100101 01100101 10110001 00100101 11100011 11100010 01100000 10110001 11111000 10011000 00111001 11011101 01001100 00001001 01101111 10011100 11101000 01011101 11001001 00010100 11100001 01000010 01000001 00010110 01110111 10111001 10000100");
    assert_eq!(result.text[0], FOX);
    assert_eq!(path(&result), ["Binary", "Bzip2"]);
}

#[test]
#[serial]
fn gzip_inside_bzip2_is_cracked() {
    // base64.b64encode(bz2.compress(gzip.compress(FOX, mtime=0)))
    let result = crack("QlpoOTFBWSZTWbzcZ80AAAd+VfhIAACEXoAgIFzbAAAIDICAe4SAAACgAFRjRoNGEYjRoaNMTahU9RkHqAyAaNNMmjahwEDGQFSGcEgl8qDR2tnqzwrZ3B2LBfBMUjFqmvcRRJGzEUpqAA/F3JFOFCQvNxnzQA==");
    assert_eq!(result.text[0], FOX);
    assert_eq!(path(&result), ["Bzip2", "Gzip"]);
}

#[test]
#[serial]
#[cfg(unix)] // ciphey can't be given a temporary home directory on Windows
fn issue_example_is_cracked_with_a_crib() {
    // The default checkers don't take "Sphinx of black quartz, judge my vow." for English
    // (#1031), so without a crib the search goes on past it. The config is global to a
    // process, so this runs the ciphey binary to give the search a regex.
    let home = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("ciphey-bzip2-{}", std::process::id()));
    // An empty config file skips the first-run setup
    std::fs::create_dir_all(home.join(".ciphey")).unwrap();
    std::fs::write(home.join(".ciphey").join("config.toml"), "").unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_ciphey"))
        .args(["-d", "-r", "^Sphinx", "-t"])
        // The example in https://github.com/bee-san/Ciphey/issues/1023
        .arg("QlpoOTFBWSZTWX8PrZ8AAAQTgEAFCAA///fwIAAxQADQAAFGpiPQJkeoD9IZH/uFU+ROpY849TVELpy9lQD59QFyLuSKcKEg/h9bPg==")
        .env("HOME", &home)
        .stdin(std::process::Stdio::null())
        .output()
        .expect("could not run ciphey");
    let _ = std::fs::remove_dir_all(&home);

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "{stdout}");
    assert!(
        stdout.contains("Sphinx of black quartz, judge my vow."),
        "{stdout}"
    );
    assert!(stdout.contains("Bzip2"), "{stdout}");
}
