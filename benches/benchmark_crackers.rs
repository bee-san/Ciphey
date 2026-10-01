use ciphey::checkers::athena::Athena;
use ciphey::checkers::checker_type::{Check, Checker};
use ciphey::checkers::CheckerTypes;
use ciphey::config::{set_global_config, Config};
use ciphey::decoders::base64_decoder::Base64Decoder;
use ciphey::decoders::interface::{Crack, Decoder};
use criterion::{criterion_group, criterion_main, Criterion};
use env_logger::Builder;
use log::LevelFilter;
use std::hint::black_box;

pub fn criterion_benchmark(c: &mut Criterion) {
    // Initialize logger with only error level to suppress debug messages
    let mut builder = Builder::new();
    builder.filter_level(LevelFilter::Error);
    builder.init();

    // Setup global config to suppress output
    let config = Config {
        api_mode: true,
        verbose: 0,
        ..Config::default()
    };
    set_global_config(config);

    let decode_base64 = Decoder::<Base64Decoder>::new();
    let athena_checker = Checker::<Athena>::new();
    let checker = CheckerTypes::CheckAthena(athena_checker);
    c.bench_function("base64 successful decoding", |b| {
        b.iter(|| decode_base64.crack(black_box("aGVsbG8gd29ybGQ="), &checker))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
