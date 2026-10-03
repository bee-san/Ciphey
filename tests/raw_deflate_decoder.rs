//! End-to-end tests for the Raw DEFLATE decoder (<https://github.com/bee-san/Ciphey/issues/1022>):
//! the whole search, as the CLI runs it, has to find the plaintext through Raw DEFLATE.
//!
//! The streams are Python 3.9's raw DEFLATE,
//! `d = zlib.compressobj(9, zlib.DEFLATED, -15); d.compress(data) + d.flush()`.
//!
//! The tests run one at a time: every search uses all cores, and side by side on a slow
//! CI runner they would slow each other down.

use ciphey::config::Config;
use ciphey::perform_cracking;
use ciphey::storage::database::DB_PATH;
use ciphey::DecoderResult;
use serial_test::serial;

const FOX: &str = "The quick brown fox jumps over the lazy dog";
/// FOX as raw DEFLATE, in hex
const FOX_HEX: &str =
    "0bc94855282ccd4cce56482aca2fcf5348cbaf50c82acd2d2856c82f4b2d5228014ae72456552aa4e4a70300";

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
    // optimisations, and a 2-4 core CI runner is slow. The config is global to the
    // process, so every test here gets the same one.
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
fn raw_deflate_as_base64_is_cracked() {
    let result = crack("C8lIVSgszUzOVkgqyi/PU0jLr1DIKs0tKFbIL0stUigBSuckVlUqpOSnAwA=");
    assert_eq!(result.text[0], FOX);
    assert_eq!(path(&result), ["Raw DEFLATE"]);
}

#[test]
#[serial]
fn raw_deflate_as_hex_is_cracked() {
    let result = crack(FOX_HEX);
    assert_eq!(result.text[0], FOX);
    assert_eq!(path(&result), ["Raw DEFLATE"]);
}

#[test]
#[serial]
fn raw_deflate_flag_is_cracked() {
    let result = crack("S8tJTK8uSiyPT0lNy0ksSY3PSCyOz8uPz0hNTEktqgUA");
    assert_eq!(result.text[0], "flag{raw_deflate_has_no_header}");
    assert_eq!(path(&result), ["Raw DEFLATE"]);
}

#[test]
#[serial]
fn raw_deflate_hex_inside_base64_is_cracked() {
    // base64.b64encode of FOX_HEX
    let result = crack("MGJjOTQ4NTUyODJjY2Q0Y2NlNTY0ODJhY2EyZmNmNTM0OGNiYWY1MGM4MmFjZDJkMjg1NmM4MmY0YjJkNTIyODAxNGFlNzI0NTY1NTJhYTRlNGE3MDMwMA==");
    assert_eq!(result.text[0], FOX);
    assert_eq!(path(&result), ["Base64", "Raw DEFLATE"]);
}

#[test]
#[serial]
fn raw_deflate_as_binary_is_cracked() {
    // The bits of the fox stream. The Binary decoder turns them into bytes, which are not
    // UTF-8, so it passes them on as Latin-1 text and Raw DEFLATE reads them from that.
    let bits: Vec<String> = (0..FOX_HEX.len())
        .step_by(2)
        .map(|i| {
            format!(
                "{:08b}",
                u8::from_str_radix(&FOX_HEX[i..i + 2], 16).unwrap()
            )
        })
        .collect();
    let result = crack(&bits.join(" "));
    assert_eq!(result.text[0], FOX);
    assert_eq!(path(&result), ["Binary", "Raw DEFLATE"]);
}

#[test]
#[serial]
#[cfg(unix)] // ciphey can't be given a temporary home directory on Windows
fn issue_example_is_cracked_with_a_crib() {
    // The default checkers don't take "Sphinx of black quartz, judge my vow." for English
    // (#1031), so without a crib the search goes on past it. The config is global to a
    // process, so this runs the ciphey binary to give the search a regex.
    let home = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("ciphey-raw-deflate-{}", std::process::id()));
    // An empty config file skips the first-run setup
    std::fs::create_dir_all(home.join(".ciphey")).unwrap();
    std::fs::write(home.join(".ciphey").join("config.toml"), "").unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_ciphey"))
        .args(["-d", "-r", "^Sphinx", "-t"])
        // The example in https://github.com/bee-san/Ciphey/issues/1022
        .arg("Cy7IyMyrUMhPU0jKSUzOVigsTSwqqdJRyCpNSU9VyK1UKMsv1wMA")
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
    assert!(stdout.contains("Raw DEFLATE"), "{stdout}");
}
