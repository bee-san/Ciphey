//! End-to-end tests for the Gzip decoder (<https://github.com/bee-san/Ciphey/issues/1020>):
//! the whole search, as the CLI runs it, has to find the plaintext through Gzip.
//!
//! The gzip data is Python 3's `gzip.compress(data, mtime=0)` unless noted otherwise.
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
    // The default config apart from the timeout. 5 seconds is plenty for a release
    // build, but `cargo test` builds without optimisations, and on a 2-4 core CI runner
    // the Binary -> Gzip search took just over 5 seconds. The config is global to the
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
fn gzip_as_base64_is_cracked() {
    let result = crack(
        "H4sIAAAAAAAC/wvJSFUoLM1MzlZIKsovz1NIy69QyCrNLShWyC9LLVIoAUrnJFZVKqTkpwMAOaNPQSsAAAA=",
    );
    assert_eq!(result.text[0], FOX);
    assert_eq!(path(&result), ["Gzip"]);
}

#[test]
#[serial]
fn gzip_as_hex_is_cracked() {
    let result = crack("1f8b08000000000002ff0bc94855282ccd4cce56482aca2fcf5348cbaf50c82acd2d2856c82f4b2d5228014ae72456552aa4e4a7030039a34f412b000000");
    assert_eq!(result.text[0], FOX);
    assert_eq!(path(&result), ["Gzip"]);
}

#[test]
#[serial]
fn gzip_with_a_file_name_is_cracked() {
    // gzip.GzipFile(filename="flag.txt", mode="wb", mtime=0) around b"flag{gunzip_me}"
    let result = crack("H4sICAAAAAAC/2ZsYWcudHh0AEvLSUyvTi/Nq8osiM9NrQUA3xCTdA8AAAA=");
    assert_eq!(result.text[0], "flag{gunzip_me}");
    assert_eq!(path(&result), ["Gzip"]);
    assert_eq!(result.path[0].key.as_deref(), Some("flag.txt"));
}

#[test]
#[serial]
fn gzip_inside_gzip_is_cracked() {
    // base64.b64encode(gzip.compress(gzip.compress(FOX, mtime=0), mtime=0))
    let result = crack("H4sIAAAAAAAC/5Pv5mAAAab/3Cc9QjV0zvqcC/PQOqV/Ptjj9PqAE1pndTXCTuh76wZpMHo9VwkL1VryZDkzg+Vif0dtoC4AOcZqCD4AAAA=");
    assert_eq!(result.text[0], FOX);
    assert_eq!(path(&result), ["Gzip", "Gzip"]);
}

#[test]
#[serial]
fn gzip_hex_inside_base64_is_cracked() {
    // base64.b64encode(gzip.compress(FOX, mtime=0).hex().encode())
    let result = crack("MWY4YjA4MDAwMDAwMDAwMDAyZmYwYmM5NDg1NTI4MmNjZDRjY2U1NjQ4MmFjYTJmY2Y1MzQ4Y2JhZjUwYzgyYWNkMmQyODU2YzgyZjRiMmQ1MjI4MDE0YWU3MjQ1NjU1MmFhNGU0YTcwMzAwMzlhMzRmNDEyYjAwMDAwMA==");
    assert_eq!(result.text[0], FOX);
    assert_eq!(path(&result), ["Base64", "Gzip"]);
}

#[test]
#[serial]
fn gzip_as_binary_is_cracked() {
    // The bits of the gzip data. The Binary decoder turns them into bytes, which are not
    // UTF-8, so it passes them on as Latin-1 text and Gzip reads them from that.
    let result = crack("00011111 10001011 00001000 00000000 00000000 00000000 00000000 00000000 00000010 11111111 00001011 11001001 01001000 01010101 00101000 00101100 11001101 01001100 11001110 01010110 01001000 00101010 11001010 00101111 11001111 01010011 01001000 11001011 10101111 01010000 11001000 00101010 11001101 00101101 00101000 01010110 11001000 00101111 01001011 00101101 01010010 00101000 00000001 01001010 11100111 00100100 01010110 01010101 00101010 10100100 11100100 10100111 00000011 00000000 00111001 10100011 01001111 01000001 00101011 00000000 00000000 00000000");
    assert_eq!(result.text[0], FOX);
    assert_eq!(path(&result), ["Binary", "Gzip"]);
}

#[test]
#[serial]
#[cfg(unix)] // ciphey can't be given a temporary home directory on Windows
fn issue_example_is_cracked_with_a_crib() {
    // The default checkers don't take "Sphinx of black quartz, judge my vow." for English
    // (#1031), so without a crib the search goes on past it. The config is global to a
    // process, so this runs the ciphey binary to give the search a regex.
    let home = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("ciphey-gzip-{}", std::process::id()));
    // An empty config file skips the first-run setup
    std::fs::create_dir_all(home.join(".ciphey")).unwrap();
    std::fs::write(home.join(".ciphey").join("config.toml"), "").unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_ciphey"))
        .args(["-d", "-r", "^Sphinx", "-t"])
        // The example in https://github.com/bee-san/Ciphey/issues/1020
        .arg("H4sIAAAAAAACAwsuyMjMq1DIT1NIyklMzlYoLE0sKqnSUcgqTUlPVcitVCjLL9cDAN+jOaglAAAA")
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
    assert!(stdout.contains("Gzip"), "{stdout}");
}
