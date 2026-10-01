use ciphey::config::Config;
use ciphey::perform_cracking;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use env_logger::Builder;
use log::LevelFilter;
use std::hint::black_box;
use std::time::Duration;

// Test cases with different encodings/encryptions and varying complexity
const TEST_CASES: &[(&str, &str)] = &[
    // Format: (encoded_text, description)
    // Base64 encoded text (simple)
    (
        "aGVsbG8gd29ybGQ=",
        "base64_simple",
    ),
    // Base64 encoded longer text
    (
        "TXV0bGV5LCB5b3Ugc25pY2tlcmluZywgZmxvcHB5IGVhcmVkIGhvdW5kLiBXaGVuIGNvdXJhZ2UgaXMgbmVlZGVkLCB5b3XigJlyZSBuZXZlciBhcm91bmQu",
        "base64_medium",
    ),
    // Long Base64 encoded text (from integration test)
    (
        "TXV0bGV5LCB5b3Ugc25pY2tlcmluZywgZmxvcHB5IGVhcmVkIGhvdW5kLiBXaGVuIGNvdXJhZ2UgaXMgbmVlZGVkLCB5b3XigJlyZSBuZXZlciBhcm91bmQuIFRob3NlIG1lZGFscyB5b3Ugd2VhciBvbiB5b3VyIG1vdGgtZWF0ZW4gY2hlc3Qgc2hvdWxkIGJlIHRoZXJlIGZvciBidW5nbGluZyBhdCB3aGljaCB5b3UgYXJlIGJlc3QuIFNvLCBzdG9wIHRoYXQgcGlnZW9uLCBzdG9wIHRoYXQgcGlnZW9uLCBzdG9wIHRoYXQgcGlnZW9uLCBzdG9wIHRoYXQgcGlnZW9uLCBzdG9wIHRoYXQgcGlnZW9uLCBzdG9wIHRoYXQgcGlnZW9uLCBzdG9wIHRoYXQgcGlnZW9uLiBIb3d3d3chIE5hYiBoaW0sIGphYiBoaW0sIHRhYiBoaW0sIGdyYWIgaGltLCBzdG9wIHRoYXQgcGlnZW9uIG5vdy4g",
        "base64_long",
    ),
    // Base32 encoded text
    (
        "NBSWY3DPEB3W64TMMQ======",
        "base32",
    ),
    // Hex encoded text
    (
        "68656c6c6f20776f726c64",
        "hex",
    ),
    // Binary encoded text
    (
        "01101000 01100101 01101100 01101100 01101111 00100000 01110111 01101111 01110010 01101100 01100100",
        "binary",
    ),
    // Plain text (early exit case)
    (
        "This is just plain text 123",
        "plaintext",
    ),
    // Empty string (failure case)
    (
        "",
        "empty_string",
    ),
];

pub fn criterion_benchmark(c: &mut Criterion) {
    // Initialize logger with only error level to suppress debug messages
    let mut builder = Builder::new();
    builder.filter_level(LevelFilter::Error);
    builder.init();

    // Create a benchmark group with longer measurement times for more accurate results
    let mut group = c.benchmark_group("program_performance");

    // Configure the benchmark group for better statistics
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(30);

    // Run benchmarks with different configurations
    benchmark_with_config(&mut group, false, 5); // Default config
    benchmark_with_config(&mut group, false, 1); // Fast config

    group.finish();
}

fn benchmark_with_config(
    group: &mut criterion::BenchmarkGroup<criterion::measurement::WallTime>,
    top_results: bool,
    timeout: u32,
) {
    let config_name = if top_results {
        "top_results"
    } else {
        "default"
    };
    let timeout_str = format!("timeout_{}", timeout);

    for (text, description) in TEST_CASES {
        let id = BenchmarkId::new(
            format!("{}_{}_{}", config_name, timeout_str, description),
            text.len(),
        );
        group.bench_with_input(id, text, |b, text| {
            b.iter_batched_ref(
                || {
                    let _test_db = ciphey::TestDatabase::default();
                    ciphey::set_test_db_path();
                },
                |_| {
                    // Create config and set necessary parameters
                    let config = Config {
                        timeout,
                        top_results,
                        verbose: 0,
                        human_checker_on: false,
                        api_mode: true, // Set to true to suppress output
                        ..Config::default()
                    };

                    // Use perform_cracking with the configuration
                    perform_cracking(black_box(text), config)
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
