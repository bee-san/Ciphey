//! The crib checkers, which need their own process because they read the global config:
//! runs as if the CLI was started with `--regex 'flag\{[^}]*\}'` and
//! `--wordlist benches/data/wordlist.txt` (5,000 words).
//!
//! With a regex set, Athena runs only the regex checker, so `crib/search` also shows what
//! a `--regex` search costs end to end.
//!
//! Run: `cargo bench --bench crib`

mod common;

use ciphey::checkers::athena::Athena;
use ciphey::checkers::checker_type::{Check, Checker};
use ciphey::checkers::regex_checker::RegexChecker;
use ciphey::checkers::wordlist::WordlistChecker;
use ciphey::checkers::CheckerTypes;
use ciphey::config::{load_wordlist, Config};
use ciphey::perform_cracking;
use common::CheckerFixtures;
use criterion::{
    criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, SamplingMode, Throughput,
};
use std::hint::black_box;
use std::time::Duration;

/// The crib, a typical CTF flag format.
const CRIB_REGEX: &str = r"flag\{[^}]*\}";

/// End-to-end `--regex` searches: (bench name, input name). Both decode to `flag_sentence`.
const CRIB_SEARCHES: &[(&str, &str)] = &[
    ("base64", "flag_base64"),
    ("rot13_base64", "flag_rot13_base64"),
];

/// Same timeout as `search.rs`.
const TIMEOUT_SECS: u32 = 1;

fn crib_config() -> Config {
    Config {
        regex: Some(CRIB_REGEX.to_string()),
        timeout: TIMEOUT_SECS,
        ..common::bench_config()
    }
}

fn crib(c: &mut Criterion) {
    let mut config = crib_config();
    config.wordlist = Some(
        load_wordlist(common::data_path("wordlist.txt")).expect("could not load wordlist.txt"),
    );
    common::init(config);
    let fixtures: CheckerFixtures = common::load("checkers.toml");

    let mut group = c.benchmark_group("crib");
    group
        .warm_up_time(Duration::from_millis(500))
        .measurement_time(Duration::from_secs(2));
    for case in fixtures.case.iter().filter(|c| c.crib) {
        let text = fixtures.input(&case.input);
        let checker = match case.checker.as_str() {
            "regex" => CheckerTypes::CheckRegex(Checker::<RegexChecker>::new()),
            "wordlist" => CheckerTypes::CheckWordlist(Checker::<WordlistChecker>::new()),
            "athena" => CheckerTypes::CheckAthena(Checker::<Athena>::new()),
            other => panic!("unknown crib checker {other:?} in checkers.toml"),
        };
        let name = case.bench_name();
        assert_eq!(
            checker.check(text).is_identified,
            case.identified,
            "{name} on {}: is_identified changed",
            case.input
        );
        group.throughput(Throughput::Bytes(text.len() as u64));
        group.bench_with_input(BenchmarkId::new(name, &case.input), text, |b, text| {
            b.iter(|| checker.check(black_box(text)))
        });
    }
    group.finish();

    let mut group = c.benchmark_group("crib/search");
    group
        .sampling_mode(SamplingMode::Flat)
        .sample_size(20)
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(4));
    let expected = fixtures.input("flag_sentence");
    for (name, input) in CRIB_SEARCHES {
        let input = fixtures.input(input);
        // Unoptimised builds (`cargo test --benches`) may not finish within the timeout.
        if !cfg!(debug_assertions) {
            common::fresh_search();
            let result = perform_cracking(input, crib_config())
                .unwrap_or_else(|e| panic!("crib search {name} failed: {e}"))
                .unwrap_or_else(|| panic!("crib search {name} found nothing"));
            assert_eq!(
                result.text[0], expected,
                "crib search {name}: wrong plaintext"
            );
        }
        group.bench_function(*name, |b| {
            b.iter_batched(
                || {
                    common::fresh_search();
                    crib_config()
                },
                |config| perform_cracking(black_box(input), config),
                BatchSize::PerIteration,
            )
        });
    }
    group.finish();
}

criterion_group!(benches, crib);
criterion_main!(benches);
