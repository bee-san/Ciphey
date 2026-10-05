//! The A* search end to end, through `ciphey::perform_cracking`, on the corpus in
//! `benches/data/search.toml`:
//!
//! * `search/plaintext`: input that is already plaintext (early exit),
//! * `search/single`: one encoding or cipher,
//! * `search/multi`: two or three stacked layers,
//! * `search/no_solution`: input with no plaintext to find. These end when the decoders
//!   run out of candidates, when the search settles on a false positive, or when the
//!   fixed 1 second timeout fires, so each sample is bounded by the timeout.
//!
//! The cache database is in memory (see `common::init`), so every iteration is a
//! cache miss and does the full search.
//!
//! Run: `cargo bench --bench search` (add `-- search/multi` to run one group).

mod common;

use ciphey::config::Config;
use ciphey::{perform_cracking, CipheyError};
use common::{SearchCase, SearchFixtures};
use criterion::{criterion_group, criterion_main, BatchSize, Criterion, SamplingMode};
use std::hint::black_box;
use std::time::Duration;

/// Search timeout. The timer counts whole seconds, so 1 is the smallest useful value.
const TIMEOUT_SECS: u32 = 1;

/// Unoptimised builds (`cargo test --benches`) are too slow to finish some searches
/// within the timeout, so they only smoke-run the benchmarks without checking results.
const VERIFY: bool = !cfg!(debug_assertions);

fn search_config() -> Config {
    Config {
        timeout: TIMEOUT_SECS,
        ..common::bench_config()
    }
}

/// Per-iteration setup: a fresh config, and decoder statistics cleared so every search
/// explores in the same order a fresh `ciphey` process would (see `common::fresh_search`).
fn setup() -> Config {
    common::fresh_search();
    search_config()
}

fn search(c: &mut Criterion) {
    common::init(search_config());
    let fixtures: SearchFixtures = common::load("search.toml");

    for kind in ["plaintext", "single", "multi", "no_solution"] {
        let mut group = c.benchmark_group(format!("search/{kind}"));
        group.sampling_mode(SamplingMode::Flat);
        if kind == "no_solution" {
            // Up to ~1 s per iteration.
            group
                .sample_size(10)
                .warm_up_time(Duration::from_secs(1))
                .measurement_time(Duration::from_secs(8));
        } else {
            group
                .sample_size(20)
                .warm_up_time(Duration::from_secs(1))
                .measurement_time(Duration::from_secs(3));
        }

        for case in fixtures.case.iter().filter(|c| c.kind == kind) {
            verify(case);
            group.bench_function(&case.name, |b| {
                b.iter_batched(
                    setup,
                    |config| perform_cracking(black_box(&case.input), config),
                    BatchSize::PerIteration,
                )
            });
        }
        group.finish();
    }
}

/// Checks the search still ends the way the fixture says before timing it.
fn verify(case: &SearchCase) {
    if !VERIFY {
        return;
    }
    let result = perform_cracking(&case.input, setup());
    match (case.kind.as_str(), case.outcome.as_deref()) {
        ("no_solution", Some("exhausted")) => assert!(
            matches!(result, Ok(None)),
            "{}: expected the search to exhaust, got {result:?}",
            case.name
        ),
        ("no_solution", Some("timeout")) => assert!(
            matches!(result, Err(CipheyError::Timeout { .. })),
            "{}: expected a timeout, got {result:?}",
            case.name
        ),
        ("no_solution", _) => {}
        _ => {
            let found = result
                .unwrap_or_else(|e| panic!("{}: search failed: {e}", case.name))
                .unwrap_or_else(|| panic!("{}: search found nothing", case.name));
            assert_eq!(
                found.text[0],
                case.expected,
                "{}: wrong plaintext via {:?}",
                case.name,
                found.path.iter().map(|p| p.decoder).collect::<Vec<_>>()
            );
        }
    }
}

criterion_group!(benches, search);
criterion_main!(benches);
