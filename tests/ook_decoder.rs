//! End-to-end tests for the Ook! decoder (<https://github.com/bee-san/Ciphey/issues/984>):
//! the whole search, as the CLI runs it, has to find the plaintext by running the program.
//!
//! The programs use the table on <https://esolangs.org/wiki/Ook!>. Their outputs were
//! checked with a separate Ook!-to-Brainfuck translator and Brainfuck interpreter in Python.
//!
//! The tests run one at a time: every search uses all cores, and side by side on a slow
//! CI runner they would slow each other down.

use ciphey::config::Config;
use ciphey::perform_cracking;
use ciphey::storage::database::DB_PATH;
use ciphey::DecoderResult;
use serial_test::serial;

/// The Hello World program on <https://esolangs.org/wiki/Ook!>, with its 18 lines
const ESOLANGS_HELLO_WORLD: &str = "\
    Ook. Ook? Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook.\n\
    Ook. Ook. Ook. Ook. Ook! Ook? Ook? Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook.\n\
    Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook? Ook! Ook! Ook? Ook! Ook? Ook.\n\
    Ook! Ook. Ook. Ook? Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook.\n\
    Ook. Ook. Ook! Ook? Ook? Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook?\n\
    Ook! Ook! Ook? Ook! Ook? Ook. Ook. Ook. Ook! Ook. Ook. Ook. Ook. Ook. Ook. Ook.\n\
    Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook! Ook. Ook! Ook. Ook. Ook. Ook. Ook.\n\
    Ook. Ook. Ook! Ook. Ook. Ook? Ook. Ook? Ook. Ook? Ook. Ook. Ook. Ook. Ook. Ook.\n\
    Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook! Ook? Ook? Ook. Ook. Ook.\n\
    Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook? Ook! Ook! Ook? Ook! Ook? Ook. Ook! Ook.\n\
    Ook. Ook? Ook. Ook? Ook. Ook? Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook.\n\
    Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook! Ook? Ook? Ook. Ook. Ook.\n\
    Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook.\n\
    Ook. Ook? Ook! Ook! Ook? Ook! Ook? Ook. Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook.\n\
    Ook? Ook. Ook? Ook. Ook? Ook. Ook? Ook. Ook! Ook. Ook. Ook. Ook. Ook. Ook. Ook.\n\
    Ook! Ook. Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook.\n\
    Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook!\n\
    Ook! Ook. Ook. Ook? Ook. Ook? Ook. Ook. Ook! Ook.";

/// `><++++++++[>+++++++++++++<-]>.---.+++++++..+++.[-]<++++[>++++++++<-]>.[-]<++++++++++[>++++++++++++<-]>-.--------.+++.------.--------.`
/// in Ook!, one space between tokens. It prints `hello world`.
const HELLO_WORLD: &str = "\
    Ook. Ook? Ook? Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. \
    Ook. Ook. Ook. Ook. Ook! Ook? Ook. Ook? Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. \
    Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. \
    Ook. Ook. Ook? Ook. Ook! Ook! Ook? Ook! Ook. Ook? Ook! Ook. Ook! Ook! Ook! Ook! \
    Ook! Ook! Ook! Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. \
    Ook. Ook. Ook! Ook. Ook! Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook! Ook. Ook! Ook? \
    Ook! Ook! Ook? Ook! Ook? Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook! Ook? \
    Ook. Ook? Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. \
    Ook. Ook. Ook? Ook. Ook! Ook! Ook? Ook! Ook. Ook? Ook! Ook. Ook! Ook? Ook! Ook! \
    Ook? Ook! Ook? Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. \
    Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook! Ook? Ook. Ook? Ook. Ook. Ook. Ook. \
    Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. \
    Ook. Ook. Ook. Ook. Ook? Ook. Ook! Ook! Ook? Ook! Ook. Ook? Ook! Ook! Ook! Ook. \
    Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! \
    Ook! Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook! Ook. Ook! Ook! Ook! Ook! Ook! Ook! \
    Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook. Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! \
    Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook.";

/// Base64 (Python's `base64.b64encode`) of the 709 characters of Ook! for
/// `><++++++++[>+++++++++++++<-]>.---.+++++++..+++.[-]<++++[>++++++++<-]>+.`, which prints
/// `hello!`
const HELLO_IN_BASE64: &str = "T29rLiBPb2s/IE9vaz8gT29rLiBPb2suIE9vay4gT29rLiBPb2suIE9vay4gT29rLiBPb2suIE9vay4gT29rLiBPb2suIE9vay4gT29rLiBPb2suIE9vay4gT29rLiBPb2suIE9vayEgT29rPyBPb2suIE9vaz8gT29rLiBPb2suIE9vay4gT29rLiBPb2suIE9vay4gT29rLiBPb2suIE9vay4gT29rLiBPb2suIE9vay4gT29rLiBPb2suIE9vay4gT29rLiBPb2suIE9vay4gT29rLiBPb2suIE9vay4gT29rLiBPb2suIE9vay4gT29rLiBPb2suIE9vaz8gT29rLiBPb2shIE9vayEgT29rPyBPb2shIE9vay4gT29rPyBPb2shIE9vay4gT29rISBPb2shIE9vayEgT29rISBPb2shIE9vayEgT29rISBPb2suIE9vay4gT29rLiBPb2suIE9vay4gT29rLiBPb2suIE9vay4gT29rLiBPb2suIE9vay4gT29rLiBPb2suIE9vay4gT29rLiBPb2shIE9vay4gT29rISBPb2suIE9vay4gT29rLiBPb2suIE9vay4gT29rLiBPb2suIE9vayEgT29rLiBPb2shIE9vaz8gT29rISBPb2shIE9vaz8gT29rISBPb2s/IE9vay4gT29rLiBPb2suIE9vay4gT29rLiBPb2suIE9vay4gT29rLiBPb2suIE9vayEgT29rPyBPb2suIE9vaz8gT29rLiBPb2suIE9vay4gT29rLiBPb2suIE9vay4gT29rLiBPb2suIE9vay4gT29rLiBPb2suIE9vay4gT29rLiBPb2suIE9vay4gT29rLiBPb2s/IE9vay4gT29rISBPb2shIE9vaz8gT29rISBPb2suIE9vaz8gT29rLiBPb2suIE9vayEgT29rLg==";

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
fn hello_world_is_cracked() {
    // 1,329 characters print 11, under the 5% of the input the search accepts from other
    // decoders. On master the search exhausted without an answer.
    let result = crack(HELLO_WORLD);
    assert_eq!(result.text[0], "hello world");
    assert_eq!(path(&result), ["Ook!"]);
}

#[test]
#[serial]
fn short_ook_hello_world_is_cracked() {
    // The same program with only the punctuation. On master simplesubstitution's
    // `T TTTTTTTTTTTTTTTTTE T ...` was accepted by the English checker.
    let short = HELLO_WORLD.replace("Ook", "");
    assert_eq!(short.len(), 531);
    let result = crack(&short);
    assert_eq!(result.text[0], "hello world");
    assert_eq!(path(&result), ["Ook!"]);
}

#[test]
#[serial]
fn esolangs_hello_world_is_cracked() {
    // On master the search timed out on this one
    let result = crack(ESOLANGS_HELLO_WORLD);
    assert_eq!(result.text[0], "Hello World!");
    assert_eq!(path(&result), ["Ook!"]);
}

#[test]
#[serial]
fn ook_inside_base64_is_cracked() {
    // On master the search returned Vigenère's reading of the decoded Ook! program
    let result = crack(HELLO_IN_BASE64);
    assert_eq!(result.text[0], "hello!");
    assert_eq!(path(&result), ["Base64", "Ook!"]);
}
