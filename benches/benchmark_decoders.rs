use ciphey::checkers::athena::Athena;
use ciphey::checkers::checker_type::{Check, Checker};
use ciphey::checkers::CheckerTypes;
use ciphey::config::{set_global_config, Config};
use ciphey::decoders::{
    base32_decoder::Base32Decoder,
    base58_bitcoin_decoder::Base58BitcoinDecoder,
    base58_flickr_decoder::Base58FlickrDecoder,
    base64_decoder::Base64Decoder,
    binary_decoder::BinaryDecoder,
    hexadecimal_decoder::HexadecimalDecoder,
    interface::{Crack, Decoder},
};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use env_logger::Builder;
use log::LevelFilter;
use std::hint::black_box;
use std::time::Duration;

// Test cases for different decoders
struct DecoderTestCase<'a> {
    encoded: &'a str,
    // Documents the expected plaintext; not asserted on, this is a benchmark not a test.
    #[allow(dead_code)]
    expected: &'a str,
    description: &'a str,
}

// Test data for benchmarking each decoder
const BASE64_TESTS: &[DecoderTestCase] = &[
    DecoderTestCase {
        encoded: "aGVsbG8gd29ybGQ=",
        expected: "hello world",
        description: "simple",
    },
    DecoderTestCase {
        encoded: "TXV0bGV5LCB5b3Ugc25pY2tlcmluZywgZmxvcHB5IGVhcmVkIGhvdW5kLiBXaGVuIGNvdXJhZ2UgaXMgbmVlZGVkLCB5b3XigJlyZSBuZXZlciBhcm91bmQu",
        expected: "Mutley, you snickering, floppy eared hound. When courage is needed, you're never around.",
        description: "medium",
    },
];

const BASE32_TESTS: &[DecoderTestCase] = &[DecoderTestCase {
    encoded: "NBSWY3DPEB3W64TMMQ======",
    expected: "hello world",
    description: "simple",
}];

const HEX_TESTS: &[DecoderTestCase] = &[DecoderTestCase {
    encoded: "68656c6c6f20776f726c64",
    expected: "hello world",
    description: "simple",
}];

const BINARY_TESTS: &[DecoderTestCase] = &[
    DecoderTestCase {
        encoded: "01101000 01100101 01101100 01101100 01101111 00100000 01110111 01101111 01110010 01101100 01100100",
        expected: "hello world",
        description: "simple",
    },
];

const BASE58_BITCOIN_TESTS: &[DecoderTestCase] = &[DecoderTestCase {
    encoded: "StV1DL6CwTryKyV",
    expected: "hello world",
    description: "simple",
}];

const BASE58_FLICKR_TESTS: &[DecoderTestCase] = &[DecoderTestCase {
    encoded: "rTu1dk6cWsRYjYu",
    expected: "hello world",
    description: "simple",
}];

pub fn benchmark_decoders(c: &mut Criterion) {
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

    // Create a benchmark group with appropriate measurement time
    let mut group = c.benchmark_group("decoder_performance");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(50); // More samples for better statistical significance

    // Create a checker to use for all decoders
    let athena_checker = Checker::<Athena>::new();
    let checker = CheckerTypes::CheckAthena(athena_checker);

    // Base64 decoder benchmarks
    benchmark_decoder::<Base64Decoder>(&mut group, "base64", BASE64_TESTS, &checker);

    // Base32 decoder benchmarks
    benchmark_decoder::<Base32Decoder>(&mut group, "base32", BASE32_TESTS, &checker);

    // Hex decoder benchmarks
    benchmark_decoder::<HexadecimalDecoder>(&mut group, "hexadecimal", HEX_TESTS, &checker);

    // Binary decoder benchmarks
    benchmark_decoder::<BinaryDecoder>(&mut group, "binary", BINARY_TESTS, &checker);

    // Base58 Bitcoin decoder benchmarks
    benchmark_decoder::<Base58BitcoinDecoder>(
        &mut group,
        "base58_bitcoin",
        BASE58_BITCOIN_TESTS,
        &checker,
    );

    // Base58 Flickr decoder benchmarks
    benchmark_decoder::<Base58FlickrDecoder>(
        &mut group,
        "base58_flickr",
        BASE58_FLICKR_TESTS,
        &checker,
    );

    group.finish();
}

// Generic function to benchmark any decoder with its test cases
fn benchmark_decoder<T>(
    group: &mut criterion::BenchmarkGroup<criterion::measurement::WallTime>,
    decoder_name: &str,
    test_cases: &[DecoderTestCase],
    checker: &CheckerTypes,
) where
    Decoder<T>: Crack,
{
    let decoder = Decoder::<T>::new();

    for test in test_cases {
        let id = BenchmarkId::new(
            format!("{}_{}", decoder_name, test.description),
            test.encoded.len(),
        );

        group.bench_with_input(id, test.encoded, |b, encoded| {
            b.iter_batched_ref(
                || {
                    let _test_db = ciphey::TestDatabase::default();
                    ciphey::set_test_db_path();
                },
                |_| decoder.crack(black_box(encoded), checker),
                criterion::BatchSize::SmallInput,
            )
        });
    }
}

criterion_group!(benches, benchmark_decoders);
criterion_main!(benches);
