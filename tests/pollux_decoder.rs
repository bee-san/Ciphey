//! End-to-end tests for the Pollux cracker (<https://github.com/bee-san/Ciphey/issues/1000>):
//! the whole search, as the CLI runs it, has to find the plaintext through Pollux, and
//! Pollux must not claim the other decoders' inputs.

use ciphey::checkers::athena::Athena;
use ciphey::checkers::checker_type::{Check, Checker};
use ciphey::checkers::CheckerTypes;
use ciphey::config::Config;
use ciphey::decoders::interface::{Crack, Decoder};
use ciphey::decoders::pollux_decoder::PolluxDecoder;
use ciphey::perform_cracking;
use ciphey::storage::database::DB_PATH;
use ciphey::DecoderResult;

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
fn issue_example_is_cracked() {
    let result = crack("7774640754467514028890485358201240751738773");
    assert_eq!(result.text[0], "HELLO WORLD");
    assert_eq!(path(&result), ["Pollux"]);
    assert_eq!(
        result.path[0].key.as_deref(),
        Some(". = 1 4 7, - = 2 5 8, x = 3 6 9 0")
    );
}

#[test]
fn bench_sentence_is_cracked() {
    // benches/data/search.toml, pollux
    let result = crack(
        "253164980325679018326950471437698250184732146975140713824671479501471382564789147013642971540837612490583716247951047382164714950378621954703814761249710543827695014713469820753182469507147316984207351826945087321469750386258912405781347146",
    );
    assert_eq!(
        result.text[0],
        "MEET ME AT THE OLD LIGHTHOUSE AFTER MIDNIGHT AND BRING THE MAP THE KEY AND A TORCH"
    );
    assert_eq!(path(&result), ["Pollux"]);
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
fn other_bench_inputs_are_not_cracked() {
    // Every other decoder's fixtures and every search input that isn't Pollux's, digit
    // strings among them (Decimal, Big integer, DTMF, Multi-tap, T9 ...)
    let decoder = Decoder::<PolluxDecoder>::new();
    let checker = CheckerTypes::CheckAthena(Checker::<Athena>::new());
    let inputs: Vec<(String, String)> = ["decoders.toml", "search.toml"]
        .iter()
        .flat_map(|file| fixture_inputs(file))
        .filter(|(label, _)| !label.eq_ignore_ascii_case("pollux"))
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
