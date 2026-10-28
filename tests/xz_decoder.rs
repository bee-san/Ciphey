//! End-to-end tests for the XZ decoder (<https://github.com/bee-san/Ciphey/issues/1024>):
//! the whole search, as the CLI runs it, has to find the plaintext through XZ.
//!
//! The files are Python 3.9's `lzma.compress(data)` (XZ) or
//! `lzma.compress(data, format=lzma.FORMAT_ALONE)` (LZMA-alone), and decompress to the
//! same text with xz 5.2.5 (`xz -dc`).
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
    // optimisations, and CI runners have 2-4 cores. The config is global to the process,
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
fn xz_as_base64_is_cracked() {
    let result = crack("/Td6WFoAAATm1rRGAgAhARYAAAB0L+WjAQAqVGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZwAAxKFK5cK4XlsAAUMrrVBuVx+2830BAAAAAARZWg==");
    assert_eq!(result.text[0], FOX);
    assert_eq!(path(&result), ["XZ"]);
    assert_eq!(result.path[0].key, None);
}

#[test]
#[serial]
fn lzma_alone_as_base64_is_cracked() {
    let result = crack(
        "XQAAgAD//////////wAqGgiiAyVm8Ut4xaIF/y7m2dIgGq00+OId6EE2+twGabs85BA0Jwnrs2bsGhcv//zOkAA=",
    );
    assert_eq!(result.text[0], FOX);
    assert_eq!(path(&result), ["XZ"]);
    assert_eq!(result.path[0].key.as_deref(), Some("LZMA-alone"));
}

#[test]
#[serial]
fn xz_as_hex_is_cracked() {
    let result = crack("fd377a585a000004e6d6b4460200210116000000742fe5a301002a54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f670000c4a14ae5c2b85e5b0001432bad506e571fb6f37d010000000004595a");
    assert_eq!(result.text[0], FOX);
    assert_eq!(path(&result), ["XZ"]);
}

#[test]
#[serial]
fn xz_flag_is_cracked() {
    let result = crack("/Td6WFoAAATm1rRGAgAhARYAAAB0L+WjAQATZmxhZ3t4el91dGlsc19sem1hMn0ARd5h+uGe/UYAASwU+AptAx+2830BAAAAAARZWg==");
    assert_eq!(result.text[0], "flag{xz_utils_lzma2}");
    assert_eq!(path(&result), ["XZ"]);
}

#[test]
#[serial]
fn xz_hex_inside_base64_is_cracked() {
    // base64.b64encode(lzma.compress(FOX).hex().encode())
    let result = crack("ZmQzNzdhNTg1YTAwMDAwNGU2ZDZiNDQ2MDIwMDIxMDExNjAwMDAwMDc0MmZlNWEzMDEwMDJhNTQ2ODY1MjA3MTc1Njk2MzZiMjA2MjcyNmY3NzZlMjA2NjZmNzgyMDZhNzU2ZDcwNzMyMDZmNzY2NTcyMjA3NDY4NjUyMDZjNjE3YTc5MjA2NDZmNjcwMDAwYzRhMTRhZTVjMmI4NWU1YjAwMDE0MzJiYWQ1MDZlNTcxZmI2ZjM3ZDAxMDAwMDAwMDAwNDU5NWE=");
    assert_eq!(result.text[0], FOX);
    assert_eq!(path(&result), ["Base64", "XZ"]);
}

#[test]
#[serial]
fn xz_inside_xz_is_cracked() {
    // base64.b64encode(lzma.compress(lzma.compress(FOX))): the first step hands the inner
    // file on as raw bytes, the second decompresses it
    let result = crack("/Td6WFoAAATm1rRGAgAhARYAAAB0L+WjAQBj/Td6WFoAAATm1rRGAgAhARYAAAB0L+WjAQAqVGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZwAAxKFK5cK4XlsAAUMrrVBuVx+2830BAAAAAARZWgClhZHk7FObSAABfGSQJtPpH7bzfQEAAAAABFla");
    assert_eq!(result.text[0], FOX);
    assert_eq!(path(&result), ["XZ", "XZ"]);
}

#[test]
#[serial]
#[cfg(unix)] // ciphey can't be given a temporary home directory on Windows
fn issue_examples_are_cracked_with_a_crib() {
    // The default checkers don't take "Sphinx of black quartz, judge my vow." for English
    // (#1031), so without a crib the search goes on past it. The config is global to a
    // process, so this runs the ciphey binary to give the search a regex.
    let home = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("ciphey-xz-{}", std::process::id()));
    // An empty config file skips the first-run setup
    std::fs::create_dir_all(home.join(".ciphey")).unwrap();
    std::fs::write(home.join(".ciphey").join("config.toml"), "").unwrap();
    // The XZ and .lzma examples in https://github.com/bee-san/Ciphey/issues/1024
    let examples = [
        "/Td6WFoAAATm1rRGAgAhARYAAAB0L+WjAQAkU3BoaW54IG9mIGJsYWNrIHF1YXJ0eiwganVkZ2UgbXkgdm93LgAAAABuPeHCKPDVhAABPSXSKWoBH7bzfQEAAAAABFla",
        "XQAAgAD//////////wApnAkGs6iqYK0+rdZrCbrHCjNiT/hoUVL3L+59llK2C4kmTlnCHFQNG///xv0AAA==",
    ];
    let outputs: Vec<std::process::Output> = examples
        .iter()
        .map(|example| {
            std::process::Command::new(env!("CARGO_BIN_EXE_ciphey"))
                .args(["-d", "-r", "^Sphinx", "-t", example])
                .env("HOME", &home)
                .stdin(std::process::Stdio::null())
                .output()
                .expect("could not run ciphey")
        })
        .collect();
    let _ = std::fs::remove_dir_all(&home);

    for output in outputs {
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(output.status.success(), "{stdout}");
        assert!(
            stdout.contains("Sphinx of black quartz, judge my vow."),
            "{stdout}"
        );
        assert!(stdout.contains("XZ"), "{stdout}");
    }
}
