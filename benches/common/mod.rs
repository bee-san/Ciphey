//! Helpers shared by the benchmark binaries: fixture loading and process-wide setup.
//!
//! Ciphey keeps its config and database path in process-wide `OnceCell`s that can only be
//! set once, so each bench binary picks one configuration at startup with [`init`] and
//! keeps it. That is also why the regex/wordlist checkers live in their own binary.

// Each bench binary uses a different subset of these helpers.
#![allow(dead_code)]

use ciphey::config::{set_global_config, Config};
use gibberish_or_not::Sensitivity;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Path of a file in `benches/data`.
pub fn data_path(file: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("benches")
        .join("data")
        .join(file)
}

/// Reads and parses a TOML fixture from `benches/data`.
pub fn load<T: DeserializeOwned>(file: &str) -> T {
    let path = data_path(file);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("could not read {}: {e}", path.display()));
    toml::from_str(&text).unwrap_or_else(|e| panic!("could not parse {}: {e}", path.display()))
}

/// The config every bench runs with: no prompts, nothing printed.
pub fn bench_config() -> Config {
    Config {
        api_mode: true,
        human_checker_on: false,
        verbose: 0,
        ..Config::default()
    }
}

/// Installs `config` as the process-wide config and keeps the cache database in memory.
///
/// With an in-memory database every `perform_cracking` call is a cache miss (each
/// connection gets a fresh, empty database) and nothing under `~/.ciphey` is touched.
/// Call once, before anything else reads the config.
pub fn init(config: Config) {
    ciphey::storage::database::DB_PATH
        .set(None)
        .expect("the database path was already set");
    set_global_config(config);
    assert!(
        ciphey::config::get_config().api_mode,
        "the global config was already initialised"
    );
}

/// Call before every timed search.
///
/// The A* search keeps per-decoder success statistics for the life of the process and
/// uses them in its edge costs, so without this a search's path, and so its time,
/// depends on how many searches ran before it in the same process (and so on how fast
/// the code is). A real `ciphey` run always starts with empty statistics.
pub fn fresh_search() {
    ciphey::reset_decoder_stats();
}

/// Parses a sensitivity name from the fixtures, defaulting to Medium.
pub fn sensitivity(name: Option<&str>) -> Sensitivity {
    match name {
        None | Some("Medium") => Sensitivity::Medium,
        Some("Low") => Sensitivity::Low,
        Some("High") => Sensitivity::High,
        Some(other) => panic!("unknown sensitivity {other:?}"),
    }
}

/// Turns a decoder name like "Base58 Bitcoin" into a benchmark id like "base58_bitcoin".
pub fn slug(name: &str) -> String {
    name.to_ascii_lowercase().replace([' ', '-'], "_")
}

/// `benches/data/decoders.toml`
#[derive(Deserialize)]
pub struct DecoderFixtures {
    /// Gibberish that no decoder accepts, run through every decoder.
    pub miss: String,
    /// One entry per decoder and input size.
    pub case: Vec<DecoderCase>,
}

/// One decoder input.
#[derive(Deserialize)]
pub struct DecoderCase {
    /// Key into `ciphey::decoders::DECODER_MAP`.
    pub decoder: String,
    /// "medium" or "long".
    pub size: String,
    /// Whether `crack` reports success with the Athena checker.
    pub success: bool,
    /// Encoded text.
    pub input: String,
    /// One of the strings `crack` returns.
    pub expected: String,
}

/// `benches/data/checkers.toml`
#[derive(Deserialize)]
pub struct CheckerFixtures {
    /// Named input texts.
    pub inputs: BTreeMap<String, String>,
    /// One entry per checker and input.
    pub case: Vec<CheckerCase>,
}

impl CheckerFixtures {
    /// Text of a named input.
    pub fn input(&self, name: &str) -> &str {
        self.inputs
            .get(name)
            .unwrap_or_else(|| panic!("no input named {name:?} in checkers.toml"))
    }
}

/// One checker run.
#[derive(Deserialize)]
pub struct CheckerCase {
    /// Which checker to run.
    pub checker: String,
    /// Sensitivity, defaults to Medium.
    #[serde(default)]
    pub sensitivity: Option<String>,
    /// Name of the input in `[inputs]`.
    pub input: String,
    /// Expected `is_identified`.
    pub identified: bool,
    /// Needs the regex/wordlist config, so runs in `crib.rs` instead of `checkers.rs`.
    #[serde(default)]
    pub crib: bool,
}

impl CheckerCase {
    /// Benchmark function name, e.g. "english" or "english_low".
    pub fn bench_name(&self) -> String {
        match &self.sensitivity {
            Some(s) => format!("{}_{}", self.checker, s.to_ascii_lowercase()),
            None => self.checker.clone(),
        }
    }
}

/// `benches/data/search.toml`
#[derive(Deserialize)]
pub struct SearchFixtures {
    /// The corpus.
    pub case: Vec<SearchCase>,
}

/// One end-to-end search.
#[derive(Deserialize)]
pub struct SearchCase {
    /// "plaintext", "single", "multi" or "no_solution".
    pub kind: String,
    /// Benchmark id.
    pub name: String,
    /// Encodings applied to the plaintext, innermost first. Documentation only.
    #[serde(default)]
    pub layers: Vec<String>,
    /// Text passed to `perform_cracking`.
    pub input: String,
    /// Expected plaintext, empty for no_solution cases.
    pub expected: String,
    /// How a no_solution search ends: "exhausted", "false_positive" or "timeout".
    #[serde(default)]
    pub outcome: Option<String>,
}
