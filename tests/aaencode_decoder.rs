//! End-to-end tests for the AAEncode decoder (<https://github.com/bee-san/Ciphey/issues/988>):
//! the whole search, as the CLI runs it, has to find the plaintext through AAEncode.
//!
//! The programs are the reference vectors in `tests/test_fixtures/aaencode_npm.tsv` (npm
//! aaencode-cli 0.0.2) and `aaencode_utf8jp.tsv` (the utf-8.jp encoder). The example in the
//! issue decodes to `console.log("hi")`, which Athena doesn't take for plaintext, so it
//! only has a unit test.
//!
//! The tests run one at a time: every search uses all cores, and side by side on a slow
//! CI runner they would slow each other down.

use base64::Engine;
use ciphey::config::Config;
use ciphey::perform_cracking;
use ciphey::storage::database::DB_PATH;
use ciphey::DecoderResult;
use serial_test::serial;

/// `plaintext<TAB>program` per line, made by npm aaencode-cli 0.0.2
const NPM_VECTORS: &str = include_str!("test_fixtures/aaencode_npm.tsv");
/// The same plaintexts, made by the utf-8.jp encoder
const UTF8JP_VECTORS: &str = include_str!("test_fixtures/aaencode_utf8jp.tsv");

/// The 84-character plaintext of the benchmarks
const MEDIUM: &str =
    "Meet me at the old lighthouse after midnight and bring the map, the key and a torch.";

/// The program for `plaintext` in a vector file
fn program<'a>(vectors: &'a str, plaintext: &str) -> &'a str {
    vectors
        .lines()
        .find_map(|line| line.strip_prefix(plaintext)?.strip_prefix('\t'))
        .unwrap_or_else(|| panic!("no vector for {plaintext:?}"))
}

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
    // optimisations, and CI runners have few cores. The Base64 of the medium program is
    // 9,224 characters, and every decoder's candidates of it are checked in turn, which
    // takes an unoptimised build several seconds. The config is global to the process, so
    // every test here gets the same one; a search that finds its answer stops there.
    let config = Config {
        timeout: 60,
        ..Config::default()
    };
    perform_cracking(text, config)
        .unwrap_or_else(|error| panic!("searching {:.80?} failed: {error}", text))
        .unwrap_or_else(|| panic!("the search found nothing for {:.80?}", text))
}

/// The names of the decoders the search used, in order.
fn path(result: &DecoderResult) -> Vec<&str> {
    result.path.iter().map(|step| step.decoder).collect()
}

#[test]
#[serial]
fn hello_world_is_cracked() {
    // 1,405 characters for an 11-character answer. The search drops results under 5% of
    // the input's length unless a decoder tagged `program`, as AAEncode is, is in the path.
    for vectors in [NPM_VECTORS, UTF8JP_VECTORS] {
        let result = crack(program(vectors, "hello world"));
        assert_eq!(result.text[0], "hello world");
        assert_eq!(path(&result), ["AAEncode"]);
    }
}

#[test]
#[serial]
fn javascript_source_is_cracked() {
    let source = r#"console.log("hello world")"#;
    let result = crack(program(NPM_VECTORS, source));
    assert_eq!(result.text[0], source);
    assert_eq!(path(&result), ["AAEncode"]);
}

#[test]
#[serial]
fn flag_is_cracked() {
    let result = crack(program(UTF8JP_VECTORS, "flag{aaencode}"));
    assert_eq!(result.text[0], "flag{aaencode}");
    assert_eq!(path(&result), ["AAEncode"]);
}

#[test]
#[serial]
fn base64_inside_a_program_is_cracked() {
    // aaencode("aGVsbG8gd29ybGQ="), 1,611 characters. The answer is under 5% of that, but
    // a step tagged `program` is in the path, so the search keeps it.
    let result = crack(program(NPM_VECTORS, "aGVsbG8gd29ybGQ="));
    assert_eq!(result.text[0], "hello world");
    assert_eq!(path(&result), ["AAEncode", "Base64"]);
}

#[test]
#[serial]
fn program_inside_base64_is_cracked() {
    // The program for the 84-character plaintext is 4,333 characters, 6,917 bytes, and
    // its Base64 is 9,224 characters (the same as GNU base64's). The search drops
    // intermediate texts of 821 to 5,000 bytes, so a shorter program, such as the 2,217
    // bytes of aaencode("hello world"), isn't found inside Base64.
    let program = program(NPM_VECTORS, MEDIUM);
    assert_eq!(program.len(), 6917);
    let base64 = base64::engine::general_purpose::STANDARD.encode(program);
    assert_eq!(base64.len(), 9224);
    assert!(base64.starts_with("776fz4nvvp/vvok9IC/vvYDvvY3CtO+8ie++iSB+"));
    let result = crack(&base64);
    assert_eq!(result.text[0], MEDIUM);
    assert_eq!(path(&result), ["Base64", "AAEncode"]);
}
