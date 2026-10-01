//! Every decoder on realistic input.
//!
//! For each decoder in `benches/data/decoders.toml`:
//! * `medium` / `long`: an 84 / 576 character English text encoded with that decoder,
//! * `miss`: a gibberish string the decoder rejects, which is what most decoders see
//!   during a search.
//!
//! `crack` runs with the Athena checker, the same as during a search, so the times
//! include checking the candidates it produces.
//!
//! Run: `cargo bench --bench decoders` (add `-- caesar` to run one decoder).

mod common;

use ciphey::checkers::athena::Athena;
use ciphey::checkers::checker_type::{Check, Checker};
use ciphey::checkers::CheckerTypes;
use ciphey::decoders::DECODER_MAP;
use common::{DecoderCase, DecoderFixtures};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::hint::black_box;
use std::time::Duration;

fn decoders(c: &mut Criterion) {
    common::init(common::bench_config());
    let fixtures: DecoderFixtures = common::load("decoders.toml");
    let checker = CheckerTypes::CheckAthena(Checker::<Athena>::new());

    let mut names: Vec<&str> = fixtures.case.iter().map(|c| c.decoder.as_str()).collect();
    names.dedup();

    let mut group = c.benchmark_group("decoders");
    group
        .warm_up_time(Duration::from_millis(500))
        .measurement_time(Duration::from_secs(2));

    for name in names {
        let decoder = DECODER_MAP
            .get(name)
            .unwrap_or_else(|| panic!("no decoder named {name:?} in DECODER_MAP"))
            .get::<()>();
        let id = common::slug(name);

        for case in fixtures.case.iter().filter(|c| c.decoder == name) {
            verify(case, decoder.crack(&case.input, &checker));
            group.throughput(Throughput::Bytes(case.input.len() as u64));
            group.bench_with_input(
                BenchmarkId::new(&id, &case.size),
                case.input.as_str(),
                |b, input| b.iter(|| decoder.crack(black_box(input), &checker)),
            );
        }

        let miss = decoder.crack(&fixtures.miss, &checker);
        assert!(!miss.success, "{name} accepted the miss input: {miss:?}");
        group.throughput(Throughput::Bytes(fixtures.miss.len() as u64));
        group.bench_with_input(
            BenchmarkId::new(&id, "miss"),
            fixtures.miss.as_str(),
            |b, input| b.iter(|| decoder.crack(black_box(input), &checker)),
        );
    }
    group.finish();
}

/// Panics if the decoder no longer behaves the way the fixture recorded, so a
/// behaviour change can't hide behind a timing change.
fn verify(case: &DecoderCase, result: ciphey::decoders::crack_results::CrackResult) {
    let outputs = result.unencrypted_text.unwrap_or_default();
    assert_eq!(
        result.success, case.success,
        "{} {}: success changed (outputs {:?})",
        case.decoder, case.size, outputs
    );
    assert!(
        outputs.contains(&case.expected),
        "{} {}: expected {:?} among outputs {:?}",
        case.decoder,
        case.size,
        case.expected,
        outputs
    );
}

criterion_group!(benches, decoders);
criterion_main!(benches);
