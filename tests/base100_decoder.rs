//! End-to-end tests for the Base100 decoder (<https://github.com/bee-san/Ciphey/issues/928>):
//! the whole search, as the CLI runs it, has to find the plaintext through Base100.
//!
//! The emoji were made with PyPI `pybase100` 0.3.1 (`pybase100.encode`) and the Base64 with
//! Python 3's `base64.b64encode`.
//!
//! The tests run one at a time: every search uses all cores, and side by side on a slow
//! CI runner they would slow each other down.

use ciphey::config::Config;
use ciphey::perform_cracking;
use ciphey::storage::database::DB_PATH;
use ciphey::DecoderResult;
use serial_test::serial;

/// The plaintext of the bench fixtures
const MEDIUM: &str =
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
    // optimisations and CI runners have 2-4 cores. The config is global to the process,
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
fn issue_example_is_cracked() {
    // Without Base100, rot47 reads each emoji as its low byte and the search ends on a
    // `rot47 -> atbash -> rot47` false positive
    let result = crack("👟👜👣👣👦🐗👮👦👩👣👛");
    assert_eq!(result.text[0], "hello world");
    assert_eq!(path(&result), ["Base100"]);
}

#[test]
#[serial]
fn sentence_is_cracked() {
    let result = crack("👄👜👜👫🐗👤👜🐗👘👫🐗👫👟👜🐗👦👣👛🐗👣👠👞👟👫👟👦👬👪👜🐗👘👝👫👜👩🐗👤👠👛👥👠👞👟👫🐗👘👥👛🐗👙👩👠👥👞🐗👫👟👜🐗👤👘👧🐣🐗👫👟👜🐗👢👜👰🐗👘👥👛🐗👘🐗👫👦👩👚👟🐥");
    assert_eq!(result.text[0], MEDIUM);
    assert_eq!(path(&result), ["Base100"]);
}

#[test]
#[serial]
fn base100_inside_base64_is_cracked() {
    // base64.b64encode of the emoji in `sentence_is_cracked`, as UTF-8
    let result = crack("8J+RhPCfkZzwn5Gc8J+Rq/CfkJfwn5Gk8J+RnPCfkJfwn5GY8J+Rq/CfkJfwn5Gr8J+Rn/CfkZzwn5CX8J+RpvCfkaPwn5Gb8J+Ql/CfkaPwn5Gg8J+RnvCfkZ/wn5Gr8J+Rn/Cfkabwn5Gs8J+RqvCfkZzwn5CX8J+RmPCfkZ3wn5Gr8J+RnPCfkanwn5CX8J+RpPCfkaDwn5Gb8J+RpfCfkaDwn5Ge8J+Rn/Cfkavwn5CX8J+RmPCfkaXwn5Gb8J+Ql/CfkZnwn5Gp8J+RoPCfkaXwn5Ge8J+Ql/Cfkavwn5Gf8J+RnPCfkJfwn5Gk8J+RmPCfkafwn5Cj8J+Ql/Cfkavwn5Gf8J+RnPCfkJfwn5Gi8J+RnPCfkbDwn5CX8J+RmPCfkaXwn5Gb8J+Ql/CfkZjwn5CX8J+Rq/Cfkabwn5Gp8J+RmvCfkZ/wn5Cl");
    assert_eq!(result.text[0], MEDIUM);
    assert_eq!(path(&result), ["Base64", "Base100"]);
}
