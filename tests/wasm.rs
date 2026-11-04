//! The library's core, checked on every target: natively by `cargo test`, and on
//! WebAssembly under Node.js by
//!
//! ```text
//! cargo test --target wasm32-unknown-unknown --test wasm
//! ```
//!
//! On WebAssembly the search runs on the caller's thread and stops at its timeout by
//! itself, time comes from JavaScript's clock, there is no cache, and the human checker
//! never asks (docs/wasm.md). The answers have to be the same as on native targets.
//!
//! Two tests run the benchmark fixtures, which were recorded natively: every decoder on
//! its inputs (`benches/data/decoders.toml`) and the whole search corpus
//! (`benches/data/search.toml`). Anything that reads std's clock or waits on a thread,
//! even inside std or a dependency, panics on wasm32-unknown-unknown, and these find it.
//! Natively they are ignored: `cargo bench -- --test` checks the same fixtures there, in
//! optimised builds.
//!
//! The config is global to the process and the first search's config is kept for the rest
//! of it (see `perform_cracking`), so every search here uses [`config`].

// Under wasm-bindgen-test-runner only tests marked `wasm_bindgen_test` run, so on
// wasm32-unknown-unknown `#[test]` means that one
#[cfg(all(target_family = "wasm", target_os = "unknown"))]
use wasm_bindgen_test::wasm_bindgen_test as test;

use std::collections::{BTreeSet, HashSet};

use ciphey::checkers::athena::Athena;
use ciphey::checkers::checker_type::{Check, Checker};
use ciphey::checkers::english::EnglishChecker;
use ciphey::checkers::CheckerTypes;
use ciphey::config::Config;
use ciphey::decoders::DECODER_MAP;
use ciphey::detection::{detect_plaintext, CheckerKind, DetectOptions};
use ciphey::{decode_with, decoders, list_decoders, perform_cracking, DecodeOptions};
use ciphey::{CipheyError, DecoderResult};
use serde::Deserialize;

/// Seconds a search may take. Each search here takes under a second unoptimised, natively
/// and on WebAssembly under Node.js, so this leaves room for slow CI runners. The timeout
/// test waits this long.
const TIMEOUT: u32 = 10;

/// The config of every search in this file.
fn config() -> Config {
    Config {
        timeout: TIMEOUT,
        human_checker_on: false,
        api_mode: true,
        ..Config::default()
    }
}

/// Runs the whole search on `text`, as the CLI does.
fn search(text: &str) -> Result<Option<DecoderResult>, CipheyError> {
    // Natively, keep the search away from the cache in ~/.ciphey: with no database path
    // every connection is a fresh in-memory database. WebAssembly has no cache.
    #[cfg(not(target_family = "wasm"))]
    let _ = ciphey::storage::database::DB_PATH.set(None);
    perform_cracking(text, config())
}

/// What the search found for `text`, which has to have a plaintext.
fn crack(text: &str) -> DecoderResult {
    search(text)
        .unwrap_or_else(|error| panic!("searching {text:?} failed: {error}"))
        .unwrap_or_else(|| panic!("the search found nothing for {text:?}"))
}

/// The names of the decoders a result's path went through, in order.
fn path(result: &DecoderResult) -> Vec<&str> {
    result.path.iter().map(|step| step.decoder).collect()
}

#[test]
fn search_decodes_base64() {
    let result = crack("aGVsbG8gdGhlcmUgZ2VuZXJhbA==");
    assert_eq!(result.text[0], "hello there general");
    assert_eq!(path(&result), ["Base64"]);
}

#[test]
fn search_peels_three_layers() {
    // The README's ROT13 -> hex -> Base64
    let result = crack("NTA3NjYzNzU3MjZjMjA3NjY2MjA2OTcyNjU2YzIwNzM2ZTY2Njc=");
    assert_eq!(result.text[0], "Ciphey is very fast");
    assert_eq!(path(&result), ["Base64", "Hexadecimal", "caesar"]);
    assert_eq!(result.path[2].key.as_deref(), Some("13"));
}

#[test]
fn search_cracks_caesar() {
    let result = crack("Ebgngr zr 13 cynprf!");
    assert_eq!(result.text[0], "Rotate me 13 places!");
}

#[test]
fn search_returns_plaintext_input_at_once() {
    let result = crack("Hello, World!");
    assert_eq!(result.text[0], "Hello, World!");
    assert_eq!(path(&result), ["Default decoder"]);

    let result = crack("192.168.0.1");
    assert_eq!(result.path.len(), 1);
    assert_eq!(result.path[0].checker_name, "LemmeKnow Checker");
}

#[test]
fn search_with_nothing_to_decode_is_ok_none() {
    assert!(matches!(search(""), Ok(None)));
}

#[test]
fn search_with_an_invalid_regex_is_an_error() {
    // Rejected before the config is set, so it doesn't change the other tests' config
    let config = Config {
        regex: Some("(unclosed".to_string()),
        ..config()
    };
    let result = perform_cracking("aGVsbG8=", config);
    assert!(matches!(result, Err(CipheyError::InvalidRegex(_))));
}

/// On WebAssembly the search itself checks the clock and stops at the timeout. Natively a
/// timer thread stops it; `searchers::search_until`'s unit tests check the WebAssembly
/// way there, so this doesn't spend [`TIMEOUT`] seconds of every core on native test runs.
#[cfg(target_family = "wasm")]
#[test]
fn search_stops_at_the_timeout() {
    // `AAAA` has no plaintext: without the timeout the search would go on until memory
    // runs out
    assert!(matches!(
        search("AAAA"),
        Err(CipheyError::Timeout { secs: TIMEOUT })
    ));
}

#[test]
fn single_decoders_decode_and_crack() {
    let decoded = decoders::base64("aGVsbG8gd29ybGQ=");
    assert_eq!(decoded.candidates[0].text, "hello world");

    let cracked = decoders::caesar("Uryyb jbeyq");
    let plaintext = cracked.plaintext().expect("a shift reads as English");
    assert_eq!(plaintext.text, "Hello world");
    assert_eq!(plaintext.key.as_deref(), Some("13"));

    let decrypted = decoders::vigenere_with_key("Rijvs uyvjn", "KEY").unwrap();
    assert_eq!(decrypted.candidates[0].text, "Hello world");

    let cracked = decode_with("rot13", "Uryyb jbeyq", &DecodeOptions::default()).unwrap();
    assert_eq!(cracked.plaintext().unwrap().text, "Hello world");

    let decrypted = decode_with(
        "affine",
        "IHHWVC SWFRCP",
        &DecodeOptions::with_key("a=5, b=8"),
    )
    .unwrap();
    assert_eq!(decrypted.candidates[0].text, "AFFINE CIPHER");

    let names: Vec<&str> = list_decoders().iter().map(|d| d.name).collect();
    assert!(names.contains(&"Base64"), "{names:?}");
    assert!(names.contains(&"Vigenere"), "{names:?}");
}

#[test]
fn vigenere_is_cracked_with_the_built_in_bigrams() {
    // The key search scores letter pairs from a table that used to be read from the source
    // directory at run time, which doesn't exist on WebAssembly
    let cracked = decoders::vigenere(
        "Altd hlbe tg lrncmwxpo kpxs evl ztrsuicp qptspf. Ivplyprr th pw clhoic pozc",
    );
    let plaintext = cracked.plaintext().expect("the key should be found");
    assert_eq!(
        plaintext.text,
        "This text is encrypted with the vigenere cipher. Breaking it is rather easy"
    );
    assert_eq!(plaintext.key.as_deref(), Some("HELLO"));
}

#[test]
fn playfair_is_cracked_within_its_time_limit() {
    // The square search has a time limit, measured with the clock that works on
    // WebAssembly (std::time::Instant::now() panics there)
    let cracked = decoders::playfair(
        "RGROSKIQDSTFCYCAMRIREAYRTSRETOROCPFTCEQKQEOXOPCQSRLRRPCPRGAEOPLEATRGCIKRHERPUARDIS\
         XRMRMXAEHOSKGVYDFISTINLFRASICQIZIQXRKDPBRGROEDAWQCYDHORPUAIRORVEHOTRRPEGTSRHKSDICP\
         HKQBFGQLGKHIRSPBRGCIDYRSHOINSGAYBTTFHOHUMENRGEKBESRWDBSGSTTATSPBRGSCNEOTETREASOGMH\
         FHXEPCBSPNRGSISCRTINFGCAEHFTRSEVRGACXENERGCIDYRSHOEKOT",
    );
    let plaintext = cracked.plaintext().expect("the square should be found");
    assert!(
        plaintext
            .text
            .starts_with("THENALLOFASUDXDENTHEREWASATREMENDOUSEXPLOSION"),
        "{}",
        plaintext.text
    );
    assert_eq!(plaintext.key.as_deref(), Some("TREASUBCDFGHIKLMNOPQVWXYZ"));
}

#[test]
fn plaintext_detection_names_what_it_found() {
    let found = detect_plaintext("192.168.0.1", &DetectOptions::default()).unwrap();
    assert_eq!(found.checker, CheckerKind::LemmeKnow);
    assert_eq!(
        found.description,
        "Internet Protocol (IP) Address Version 4"
    );
    assert_eq!(found.confidence, Some(0.7));

    let found = detect_plaintext(
        "hello there general kenobi, how are you today?",
        &DetectOptions::default(),
    )
    .unwrap();
    assert_eq!(found.checker, CheckerKind::English);

    assert!(detect_plaintext("vjkrerkdnxhrfjekfdjexk", &DetectOptions::default()).is_none());

    // A crib, and a wordlist given as words: there are no files to read on WebAssembly
    let crib = DetectOptions::new().regex(r"^flag\{").unwrap();
    assert!(detect_plaintext("flag{wasm}", &crib).is_some());
    assert!(detect_plaintext("hello there general kenobi", &crib).is_none());
    let words = HashSet::from(["swordfish".to_string()]);
    let wordlist = DetectOptions::new()
        .checkers([CheckerKind::Wordlist])
        .wordlist(words);
    assert_eq!(
        detect_plaintext("swordfish", &wordlist).unwrap().checker,
        CheckerKind::Wordlist
    );
}

#[test]
fn checkers_run_on_their_own() {
    let english = Checker::<EnglishChecker>::new();
    assert!(english.check("this is a sentence in English").is_identified);
    assert!(!english.check("qwfpgjluyarstdhneiozxcvbkm").is_identified);
}

#[test]
fn invisible_characters_are_built_in() {
    // Read from the source directory at run time before, so empty on WebAssembly
    assert!(ciphey::storage::INVISIBLE_CHARS.contains(&'\u{200B}'));
    assert!(ciphey::storage::INVISIBLE_CHARS.len() >= 50);
}

#[test]
fn substitution_is_cracked_through_its_search_cache() {
    // The cracker's cache used to wait with Condvar::wait_timeout_while, which reads std's
    // clock: every text it searched panicked on wasm32-unknown-unknown. It has no bench
    // fixture, so it is checked here.
    let cracked = decoders::monoalphabetic_substitution(
        "Qaxeiw ar pf pvcdopcaq giqkwxcadf cddn. Wdv masi ac ifqkwxcig cizc pfg ac ckair cd \
         tdkl dvc tepc tpr gdfi cd ac, ceif redtr wdv cei xnpafcizc. Ac lfdtr opfw ifqdgafmr \
         pfg qnprraqpn qaxeikr, pfg ac liixr nipkfafm fit dfir.",
    );
    let plaintext = cracked.plaintext().expect("the key should be found");
    assert!(
        plaintext
            .text
            .starts_with("Ciphey is an automatic decryption tool."),
        "{}",
        plaintext.text
    );
    assert_eq!(plaintext.key.as_deref(), Some("P?QGI?MEA?LNOFDX?KRCVSTZW?"));
}

/// `benches/data/decoders.toml`: inputs for every decoder.
#[derive(Deserialize)]
struct DecoderFixtures {
    /// Gibberish that no decoder accepts
    miss: String,
    /// One entry per decoder and input size
    case: Vec<DecoderCase>,
}

/// One decoder input, and what the decoder made of it natively.
#[derive(Deserialize)]
struct DecoderCase {
    /// Key into `DECODER_MAP`
    decoder: String,
    /// "medium" or "long"
    size: String,
    /// Whether the Athena checker accepted one of the outputs
    success: bool,
    /// Encoded text
    input: String,
    /// One of the outputs
    expected: String,
}

#[test]
#[cfg_attr(
    not(target_family = "wasm"),
    ignore = "natively `cargo bench --bench decoders -- --test` checks these fixtures"
)]
fn every_decoder_gives_its_native_results() {
    let fixtures: DecoderFixtures =
        toml::from_str(include_str!("../benches/data/decoders.toml")).unwrap();
    let checker = CheckerTypes::CheckAthena(Checker::<Athena>::new());
    let mut names = BTreeSet::new();
    for case in &fixtures.case {
        let decoder = DECODER_MAP
            .get(case.decoder.as_str())
            .unwrap_or_else(|| panic!("no decoder named {:?}", case.decoder))
            .get::<()>();
        let result = decoder.crack(&case.input, &checker);
        let outputs = result.unencrypted_text.unwrap_or_default();
        assert_eq!(
            result.success, case.success,
            "{} {}: outputs {outputs:?}",
            case.decoder, case.size
        );
        assert!(
            outputs.contains(&case.expected),
            "{} {}: expected {:?} among {outputs:?}",
            case.decoder,
            case.size,
            case.expected
        );
        names.insert(case.decoder.as_str());
    }
    for name in names {
        let miss = DECODER_MAP[name]
            .get::<()>()
            .crack(&fixtures.miss, &checker);
        assert!(!miss.success, "{name} accepted the miss input");
    }
}

/// `benches/data/search.toml`: the search benchmark's corpus.
#[derive(Deserialize)]
struct SearchFixtures {
    /// The inputs
    case: Vec<SearchCase>,
}

/// One search, and its plaintext.
#[derive(Deserialize)]
struct SearchCase {
    /// "plaintext", "single", "multi" or "no_solution"
    kind: String,
    /// Benchmark id
    name: String,
    /// What the search is given
    input: String,
    /// The plaintext it finds natively
    expected: String,
}

#[test]
#[cfg_attr(
    not(target_family = "wasm"),
    ignore = "natively `cargo bench --bench search -- --test` checks these fixtures"
)]
fn search_corpus_gives_the_native_plaintexts() {
    // Inputs with no plaintext are left out: most run until the timeout, and how they end
    // depends on search order (on native targets, on thread timing)
    let fixtures: SearchFixtures =
        toml::from_str(include_str!("../benches/data/search.toml")).unwrap();
    let mut wrong = Vec::new();
    let mut searched = 0;
    for case in fixtures
        .case
        .iter()
        .filter(|case| case.kind != "no_solution")
    {
        // As the benchmark does: every search explores as in a fresh process
        ciphey::reset_decoder_stats();
        searched += 1;
        match search(&case.input) {
            Ok(Some(found)) if found.text[0] == case.expected => {}
            Ok(Some(found)) => wrong.push(format!(
                "{}/{}: {:?} via {:?}",
                case.kind,
                case.name,
                found.text[0],
                path(&found)
            )),
            other => wrong.push(format!("{}/{}: {other:?}", case.kind, case.name)),
        }
    }
    assert!(searched > 100, "only {searched} searches");
    assert!(
        wrong.is_empty(),
        "{} of {searched}: {wrong:#?}",
        wrong.len()
    );
}
