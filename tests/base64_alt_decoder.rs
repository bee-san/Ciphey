//! End-to-end tests for the Base64 Alt decoder (<https://github.com/bee-san/Ciphey/issues/933>):
//! the whole search, as the CLI runs it, has to find the plaintext through Base64 with a
//! non-standard alphabet, and leave ordinary Base64 to the Base64 decoder.

use ciphey::checkers::athena::Athena;
use ciphey::checkers::checker_type::{Check, Checker};
use ciphey::checkers::CheckerTypes;
use ciphey::config::Config;
use ciphey::decoders::base64_alt_decoder::Base64AltDecoder;
use ciphey::decoders::interface::{Crack, Decoder};
use ciphey::perform_cracking;
use ciphey::storage::database::DB_PATH;
use ciphey::DecoderResult;

const MEDIUM: &str =
    "Meet me at the old lighthouse after midnight and bring the map, the key and a torch.";

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
fn itoa64_fox_is_cracked() {
    // Python: base64.b64encode(...) translated onto ./0-9A-Za-z
    let result = crack("J4VZ653pOKBf647mPrRi64NjS0/eRKpkQm/jRaJm65FcNG/gMLdt64FjNk==");
    assert_eq!(
        result.text[0],
        "The quick brown fox jumps over the lazy dog"
    );
    assert_eq!(path(&result), ["Base64 Alt"]);
    assert_eq!(result.path[0].key.as_deref(), Some("itoa64 / crypt(3)"));
}

#[test]
fn itoa64_bench_text_is_cracked() {
    // Railfence turns this into text with a `.` that LemmeKnow takes for a URL, in the
    // same search step
    let result = crack("HKJZR0/hNG/VR0/oO4IUPqlY64ldNqVoO4xpQqIUMKNoNL6UPKZYPaZbO5EUMKtY647mOKtb65FcNG/hML.g65FcNG/fNLYUMKtY642UR4xmMqUi");
    assert_eq!(result.text[0], MEDIUM);
    assert_eq!(path(&result), ["Base64 Alt"]);
}

#[test]
fn y64_padding_beats_base64() {
    // The Base64 decoder reads the `-` as data and finds `hello world>`
    let result = crack("aGVsbG8gd29ybGQ-");
    assert_eq!(result.text[0], "hello world");
    assert_eq!(path(&result), ["Base64 Alt"]);
    assert_eq!(result.path[0].key.as_deref(), Some("y64"));
}

#[test]
fn atom128_inside_base64_is_cracked() {
    // Standard Base64 of the Atom128 form of the bench text
    let result = crack("ZmlINjAyMTlMRDFYMDIxSk1JZ1crbHI1UElyQkxsWEpNSWNrbmxnV0tpTEpMalBXK2k2NSt4NnlNb2JXS2l1NVBJUXNNaXV5UG9BekxEMTlLai8zUG9BekxEMT1MajVXS2l1NVBJR1cwSWNzS2xXVg==");
    assert_eq!(result.text[0], MEDIUM);
    assert_eq!(path(&result), ["Base64", "Base64 Alt"]);
    assert_eq!(result.path[1].key.as_deref(), Some("Atom128"));
}

#[test]
fn standard_base64_is_still_base64() {
    let result = crack("aGVsbG8gd29ybGQ=");
    assert_eq!(result.text[0], "hello world");
    assert_eq!(path(&result), ["Base64"]);
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
    // Every other decoder's fixtures and every search input that isn't Base64 Alt's
    let decoder = Decoder::<Base64AltDecoder>::new();
    let checker = CheckerTypes::CheckAthena(Checker::<Athena>::new());
    let ours = ["Base64 Alt", "base64_itoa64", "base64_alt_base64"];
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
