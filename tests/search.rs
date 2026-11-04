//! `ciphey::search`, the search a step at a time, on every target: natively by
//! `cargo test`, and on WebAssembly under Node.js by
//!
//! ```text
//! cargo test --target wasm32-unknown-unknown --test search
//! ```
//!
//! A search sets the config every check reads while it runs, so searches with different
//! options mustn't run at the same time. The checks are therefore one test, run in order.

// Under wasm-bindgen-test-runner only tests marked `wasm_bindgen_test` run
#[cfg(all(target_family = "wasm", target_os = "unknown"))]
use wasm_bindgen_test::wasm_bindgen_test as test;

use std::time::Duration;

use ciphey::detection::{CheckerKind, Sensitivity};
use ciphey::search::{Progress, Search, SearchNode, SearchOptions, SearchResult, SearchState};
use ciphey::{perform_cracking, CipheyError};

/// Runs a search on `input` to its end, a step of `budget` at a time, and returns it with
/// its progress reports.
fn steps(input: &str, options: SearchOptions, budget: Duration) -> (Search, Vec<Progress>) {
    let mut search = Search::new(input, options).unwrap();
    let mut steps = Vec::new();
    while search.state() == SearchState::Running {
        steps.push(search.step(budget));
        assert!(steps.len() < 100_000, "the search doesn't end");
    }
    (search, steps)
}

/// Options with a timeout long enough for unoptimised builds
fn options() -> SearchOptions {
    SearchOptions::default().timeout(Duration::from_secs(30))
}

#[test]
fn search_api() {
    // The cache in ~/.ciphey must not answer for perform_cracking below
    #[cfg(not(target_family = "wasm"))]
    let _ = ciphey::storage::database::DB_PATH.set(None);

    layered_plaintext_is_found_and_the_tree_reported();
    plaintext_input_is_found_in_the_first_step();
    nothing_to_search_is_exhausted();
    a_timeout_is_timed_out();
    each_search_has_its_own_options();
    interleaved_searches_keep_their_own_options();
    top_results_collects_every_plaintext();
    sensitivity_changes_what_the_english_checker_accepts();
    perform_cracking_after_a_search_uses_its_own_config();
}

fn layered_plaintext_is_found_and_the_tree_reported() {
    let input = "NTA3NjYzNzU3MjZjMjA3NjY2MjA2OTcyNjU2YzIwNzM2ZTY2Njc=";
    let (search, steps) = steps(input, options(), Duration::ZERO);
    assert_eq!(search.state(), SearchState::Found);
    let found = search.result().unwrap();
    assert_eq!(found.plaintext, "Ciphey is very fast");
    let path: Vec<&str> = found.path.iter().map(|step| step.decoder).collect();
    assert_eq!(path, ["Base64", "Hexadecimal", "caesar"]);
    assert_eq!(found.path[2].key.as_deref(), Some("13"));
    assert_eq!(found.path[2].checker, Some(CheckerKind::English));
    assert!(found.path[..2].iter().all(|step| step.checker.is_none()));
    assert_eq!(
        found.detection.as_ref().unwrap().checker,
        CheckerKind::English
    );
    assert!(found.nodes_expanded > 0);
    assert!(found.elapsed <= search.elapsed());

    // A zero budget is one batch of nodes per step, so the tree shows up as it grows,
    // starting with the input
    assert!(steps.len() > 1, "{} steps", steps.len());
    let expanded: Vec<&SearchNode> = steps.iter().flat_map(|s| &s.expanded).collect();
    assert!(expanded[0].path.is_empty());
    assert_eq!(expanded[0].text, input);
    assert_eq!(expanded[0].text_chars, input.len());
    assert!(expanded
        .iter()
        .any(|node| node.path.len() == 1 && node.path[0].decoder == "Base64"));
    // Every node's parent was expanded before it
    for (i, node) in expanded.iter().enumerate() {
        if let Some((_, parent_path)) = node.path.split_last() {
            assert!(
                expanded[..i]
                    .iter()
                    .any(|parent| parent.path == parent_path),
                "{:?} has no parent before it",
                node.path
            );
        }
    }
    let last = steps.last().unwrap();
    assert_eq!(last.state, SearchState::Found);
    assert_eq!(last.found, search.results());
    assert_eq!(last.nodes_queued, 0);
    assert!(last.nodes_expanded >= expanded.len() && last.depth >= 2);
    // The counters only grow
    for pair in steps.windows(2) {
        assert!(pair[0].nodes_expanded <= pair[1].nodes_expanded);
        assert!(pair[0].elapsed <= pair[1].elapsed);
    }
}

fn plaintext_input_is_found_in_the_first_step() {
    let mut search = Search::new("192.168.0.1", options()).unwrap();
    let progress = search.step(Duration::from_secs(1));
    assert_eq!(progress.state, SearchState::Found);
    assert!(progress.expanded.is_empty());
    let found = &progress.found[0];
    assert_eq!(found.plaintext, "192.168.0.1");
    assert!(found.path.is_empty());
    let detection = found.detection.as_ref().unwrap();
    assert_eq!(detection.checker, CheckerKind::LemmeKnow);
    assert_eq!(
        detection.description,
        "Internet Protocol (IP) Address Version 4"
    );
    // Once it is over, a step does nothing
    let again = search.step(Duration::from_secs(1));
    assert_eq!(again.state, SearchState::Found);
    assert!(again.found.is_empty() && again.expanded.is_empty());
}

fn nothing_to_search_is_exhausted() {
    let (search, _) = steps("", options(), Duration::from_secs(1));
    assert_eq!(search.state(), SearchState::Exhausted);
    assert!(search.results().is_empty());
    assert!(Search::new("", options()).unwrap().run().unwrap().is_none());
}

fn a_timeout_is_timed_out() {
    // `AAAA` has no plaintext: without the timeout the search would go on until memory
    // runs out
    let options = SearchOptions::default().timeout(Duration::from_millis(500));
    let (search, steps) = steps("AAAA", options.clone(), Duration::from_millis(50));
    assert_eq!(search.state(), SearchState::TimedOut);
    assert!(
        search.elapsed() < Duration::from_secs(60),
        "{:?}",
        search.elapsed()
    );
    // Short steps: the search was reported on several times before its timeout
    assert!(steps.len() >= 2, "{} steps", steps.len());
    assert!(matches!(
        Search::new("AAAA", options).unwrap().run(),
        Err(CipheyError::Timeout { .. })
    ));
}

fn each_search_has_its_own_options() {
    let input = "aGVsbG8gdGhlcmUgZ2VuZXJhbA==";
    // With a crib only text it matches is plaintext: here the Base64 itself
    let crib = options().regex("^aGVs").unwrap();
    let found = Search::new(input, crib.clone())
        .unwrap()
        .run()
        .unwrap()
        .unwrap();
    assert_eq!(found.plaintext, input);
    assert_eq!(found.detection.unwrap().checker, CheckerKind::Regex);

    // The next search, without it, decodes the Base64, and the one after that, with it,
    // doesn't
    let found = Search::new(input, options())
        .unwrap()
        .run()
        .unwrap()
        .unwrap();
    assert_eq!(found.plaintext, "hello there general");
    let found = Search::new(input, crib).unwrap().run().unwrap().unwrap();
    assert_eq!(found.plaintext, input);

    // A crib that doesn't compile
    let mut bad = options();
    bad.regex = Some("(unclosed".to_string());
    assert!(matches!(
        Search::new(input, bad),
        Err(CipheyError::InvalidRegex(_))
    ));
    assert!(SearchOptions::new().regex("(unclosed").is_err());
}

fn interleaved_searches_keep_their_own_options() {
    let input = "aGVsbG8gdGhlcmUgZ2VuZXJhbA==";
    let mut crib = Search::new(input, options().regex("^aGVs").unwrap()).unwrap();
    let mut plain = Search::new(input, options()).unwrap();
    while crib.state() == SearchState::Running || plain.state() == SearchState::Running {
        plain.step(Duration::ZERO);
        crib.step(Duration::ZERO);
    }
    assert_eq!(crib.result().unwrap().plaintext, input);
    assert_eq!(plain.result().unwrap().plaintext, "hello there general");
}

fn top_results_collects_every_plaintext() {
    // The search goes on after each plaintext until the timeout or the end of the tree
    let options = SearchOptions::default()
        .timeout(Duration::from_millis(1500))
        .top_results(true);
    let (search, steps) = steps(
        "aGVsbG8gdGhlcmUgZ2VuZXJhbA==",
        options,
        Duration::from_millis(100),
    );
    assert_eq!(search.state(), SearchState::Found);
    assert_eq!(search.result().unwrap().plaintext, "hello there general");
    let reported: Vec<SearchResult> = steps.into_iter().flat_map(|s| s.found).collect();
    assert_eq!(reported, search.results());
}

fn sensitivity_changes_what_the_english_checker_accepts() {
    // English with typos: only the most lenient sensitivity takes it as it is
    let typos = "Tihs is a sentnce wtih smoe tyops in it"; // codespell:ignore tihs,wtih,smoe
    let first_check = |sensitivity| {
        let mut search = Search::new(typos, options().sensitivity(sensitivity)).unwrap();
        search.step(Duration::ZERO).found
    };
    let lenient = first_check(Sensitivity::High);
    assert_eq!(lenient.len(), 1);
    assert!(lenient[0].path.is_empty());
    assert_eq!(
        lenient[0].detection.as_ref().unwrap().checker,
        CheckerKind::English
    );
    assert!(first_check(Sensitivity::Low).is_empty());
    assert!(first_check(Sensitivity::Medium).is_empty());
}

fn perform_cracking_after_a_search_uses_its_own_config() {
    // A search with a crib leaves its config in place; perform_cracking goes back to the
    // global one (here the default, so it decodes the Base64)
    let input = "aGVsbG8gdGhlcmUgZ2VuZXJhbA==";
    Search::new(input, options().regex("^aGVs").unwrap())
        .unwrap()
        .step(Duration::from_secs(5));
    let config = ciphey::config::Config {
        timeout: 30,
        human_checker_on: false,
        api_mode: true,
        ..ciphey::config::Config::default()
    };
    let found = perform_cracking(input, config).unwrap().unwrap();
    assert_eq!(found.text[0], "hello there general");
}
