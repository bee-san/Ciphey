//! End-to-end tests for the DNA Codon decoder (<https://github.com/bee-san/Ciphey/issues/966>):
//! the whole search, as the CLI runs it, has to find the plaintext through DNA Codon.
//!
//! The vectors encode each letter as its alphabetically first codon in the standard
//! genetic code and a space as the stop codon `TAA`. They decode back to the same text
//! with Biopython 1.85's `Seq(...).translate()` (standard table, stops as spaces).
//!
//! The tests run one at a time: every search uses all cores, and side by side on a slow
//! CI runner they would slow each other down.

use ciphey::config::Config;
use ciphey::perform_cracking;
use ciphey::storage::database::DB_PATH;
use ciphey::DecoderResult;
use serial_test::serial;

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
fn meet_me_at_dawn_is_cracked() {
    // On master (58ffcae3) the search settled on Vigenere junk for codon inputs like this
    let result = crack("ATG GAA GAA ACA TAA ATG GAA TAA GCA ACA TAA GAC GCA TGG AAC");
    assert_eq!(result.text[0], "MEET ME AT DAWN");
    assert_eq!(path(&result), ["DNA Codon"]);
}

#[test]
#[serial]
fn secret_message_is_cracked() {
    let result = crack("ACA CAC ATA AGC TAA ATA AGC TAA GCA TAA AGC GAA TGC AGA GAA ACA TAA ATG GAA AGC AGC GCA GGA GAA");
    assert_eq!(result.text[0], "THIS IS A SECRET MESSAGE");
    assert_eq!(path(&result), ["DNA Codon"]);
}

#[test]
#[serial]
fn rna_is_cracked() {
    // The secret message as RNA, U for T
    let result = crack("ACA CAC AUA AGC UAA AUA AGC UAA GCA UAA AGC GAA UGC AGA GAA ACA UAA AUG GAA AGC AGC GCA GGA GAA");
    assert_eq!(result.text[0], "THIS IS A SECRET MESSAGE");
    assert_eq!(path(&result), ["DNA Codon"]);
}

#[test]
#[serial]
fn codons_inside_base64_are_cracked() {
    // Python 3: base64.b64encode() of the THIS IS A SECRET MESSAGE codons. (The Base64 of
    // the MEET ME AT DAWN codons isn't used: Vigenere turns that Base64 string itself into
    // junk the English checker accepts, one step before Base64 -> DNA Codon is reached.)
    let result = crack("QUNBIENBQyBBVEEgQUdDIFRBQSBBVEEgQUdDIFRBQSBHQ0EgVEFBIEFHQyBHQUEgVEdDIEFHQSBHQUEgQUNBIFRBQSBBVEcgR0FBIEFHQyBBR0MgR0NBIEdHQSBHQUE=");
    assert_eq!(result.text[0], "THIS IS A SECRET MESSAGE");
    assert_eq!(path(&result), ["Base64", "DNA Codon"]);
}
