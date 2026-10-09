//! End-to-end tests for the Base32 Variants decoder
//! (<https://github.com/bee-san/Ciphey/issues/921>): the whole search, as the CLI runs it,
//! has to find the plaintext through base32hex, Crockford's Base32 and z-base-32, and leave
//! standard Base32 to the Base32 decoder.

use ciphey::checkers::athena::Athena;
use ciphey::checkers::checker_type::{Check, Checker};
use ciphey::checkers::CheckerTypes;
use ciphey::config::Config;
use ciphey::decoders::base32_variants_decoder::Base32VariantsDecoder;
use ciphey::decoders::interface::{Crack, Decoder};
use ciphey::perform_cracking;
use ciphey::storage::database::DB_PATH;
use ciphey::DecoderResult;

const FOX: &str = "The quick brown fox jumps over the lazy dog";

/// Runs the whole search on `text` and returns what it found.
fn crack(text: &str) -> DecoderResult {
    // With no database path every connection is a fresh in-memory database, so the search
    // doesn't read the cache in ~/.ciphey (an answer cached by another build would stand
    // in for the search under test) and doesn't write to it.
    let _ = DB_PATH.set(None);
    perform_cracking(text, Config::default())
        .unwrap_or_else(|error| panic!("searching {text:?} failed: {error}"))
        .unwrap_or_else(|| panic!("the search found nothing for {text:?}"))
}

/// The names of the decoders the search used, in order.
fn path(result: &DecoderResult) -> Vec<&str> {
    result.path.iter().map(|step| step.decoder).collect()
}

#[test]
fn fox_is_cracked_in_each_alphabet() {
    // Python: base64.b32hexencode, and base64.b32encode translated onto the alphabet
    for (text, key) in [
        (
            "AHK6A83HELKM6QP0C9P6UTRE41J6UU10D9QMQS3J41NNCPBI41Q6GP90DHGNKU90CHNME===",
            "base32hex",
        ),
        (
            "AHM6A83HENMP6TS0C9S6YXVE41K6YY10D9TPTW3K41QQCSBJ41T6GS90DHGQMY90CHQPE",
            "Crockford",
        ),
        (
            "ktwgkedtqiwsg43ycj3g675qrbug66bypj4s4hdurbzzc3m1rb4go3jyptozw6jyctzsq",
            "z-base-32",
        ),
    ] {
        let result = crack(text);
        assert_eq!(result.text[0], FOX, "{text:?}");
        assert_eq!(path(&result), ["Base32 Variants"], "{text:?}");
        assert_eq!(result.path[0].key.as_deref(), Some(key), "{text:?}");
    }
}

#[test]
fn standard_base32_is_still_base32() {
    let result = crack("NBSWY3DPEB3W64TMMQ======");
    assert_eq!(result.text[0], "hello world");
    assert_eq!(path(&result), ["Base32"]);
}

/// The `input` of every `[[case]]` in a bench fixture file, with its decoder or name.
fn fixture_inputs(file: &str) -> Vec<(String, String)> {
    let path = format!("{}/benches/data/{file}", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let table: toml::Table = text.parse().unwrap_or_else(|e| panic!("{path}: {e}"));
    let mut inputs: Vec<(String, String)> = table["case"]
        .as_array()
        .unwrap()
        .iter()
        .map(|case| {
            let label = case
                .get("decoder")
                .or_else(|| case.get("name"))
                .and_then(|v| v.as_str())
                .unwrap()
                .to_string();
            (label, case["input"].as_str().unwrap().to_string())
        })
        .collect();
    if let Some(miss) = table.get("miss").and_then(|v| v.as_str()) {
        inputs.push(("miss".to_string(), miss.to_string()));
    }
    inputs
}

#[test]
fn other_bench_inputs_get_no_candidate() {
    // Every other decoder's fixtures and every search input that isn't Base32 Variants'
    let decoder = Decoder::<Base32VariantsDecoder>::new();
    let checker = CheckerTypes::CheckAthena(Checker::<Athena>::new());
    let ours = ["Base32 Variants", "base32hex"];
    let inputs: Vec<(String, String)> = ["decoders.toml", "search.toml"]
        .iter()
        .flat_map(|file| fixture_inputs(file))
        .filter(|(label, _)| !ours.contains(&label.as_str()))
        .collect();
    assert!(inputs.len() > 100, "only {} inputs", inputs.len());
    for (label, input) in &inputs {
        let result = decoder.crack(input, &checker);
        assert!(
            result.unencrypted_text.is_none(),
            "{label}: {:?}",
            result.unencrypted_text
        );
    }
}
