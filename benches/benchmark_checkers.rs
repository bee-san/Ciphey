use ciphey::checkers::athena::Athena;
use ciphey::checkers::checker_type::{Check, Checker};
use ciphey::checkers::CheckerTypes;
use ciphey::decoders::base64_decoder::Base64Decoder;
use ciphey::decoders::interface::{Crack, Decoder};
use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;

pub fn criterion_benchmark(c: &mut Criterion) {
    let decode_base64 = Decoder::<Base64Decoder>::new();
    let athena_checker = Checker::<Athena>::new();
    let checker = CheckerTypes::CheckAthena(athena_checker);
    c.bench_function("base64 successful decoding", |b| {
        b.iter(|| decode_base64.crack(black_box("aGVsbG8gd29ybGQ="), &checker))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
