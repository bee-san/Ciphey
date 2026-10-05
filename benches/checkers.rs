//! The plaintext checkers: English (gibberish detection), LemmeKnow (regex database of
//! known formats), the common-password list, and Athena, which runs them in turn and is
//! what every decoder calls on every candidate.
//!
//! Misses matter most: during a search almost every candidate is rejected, and a
//! rejected candidate pays for every checker Athena runs.
//!
//! The regex and wordlist checkers need a different global config, see `crib.rs`.
//!
//! Run: `cargo bench --bench checkers` (add `-- athena` to run one checker).

mod common;

use ciphey::checkers::athena::Athena;
use ciphey::checkers::checker_type::{Check, Checker};
use ciphey::checkers::english::EnglishChecker;
use ciphey::checkers::lemmeknow_checker::LemmeKnow;
use ciphey::checkers::password::PasswordChecker;
use ciphey::checkers::CheckerTypes;
use common::CheckerFixtures;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::hint::black_box;
use std::time::Duration;

fn checkers(c: &mut Criterion) {
    common::init(common::bench_config());
    let fixtures: CheckerFixtures = common::load("checkers.toml");

    let mut group = c.benchmark_group("checkers");
    group
        .warm_up_time(Duration::from_millis(500))
        .measurement_time(Duration::from_secs(2));

    for case in fixtures.case.iter().filter(|c| !c.crib) {
        let text = fixtures.input(&case.input);
        let checker = match case.checker.as_str() {
            "english" => CheckerTypes::CheckEnglish(Checker::<EnglishChecker>::new()),
            "lemmeknow" => CheckerTypes::CheckLemmeKnow(Checker::<LemmeKnow>::new()),
            "password" => CheckerTypes::CheckPassword(Checker::<PasswordChecker>::new()),
            "athena" => CheckerTypes::CheckAthena(Checker::<Athena>::new()),
            other => panic!("unknown checker {other:?} in checkers.toml"),
        }
        .with_sensitivity(common::sensitivity(case.sensitivity.as_deref()));

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
}

criterion_group!(benches, checkers);
criterion_main!(benches);
