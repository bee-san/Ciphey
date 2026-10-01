//! Startup and per-call overhead outside the search itself.
//!
//! * `startup/config`: building the default config, loading `~/.ciphey/config.toml`
//!   (the fixture copy, see below) and loading a 5,000 word wordlist.
//! * `startup/cache`: the SQLite cache every `perform_cracking` call goes through, on a
//!   database file in a scratch dir: schema setup, cache lookups, and an insert.
//! * `startup/perform_cracking`: plaintext input end to end against that file, as a
//!   cache hit and as a cache miss (the miss includes writing the result to the cache).
//! * `startup/cli` (Unix only): the real `ciphey` binary started as a subprocess, which
//!   adds process start, argument parsing, logger setup and every lazy `static` the run
//!   touches (LemmeKnow compiles its ~130 regexes on first use).
//!
//! `HOME` is pointed at a scratch dir under `target/tmp` holding `benches/data/config.toml`,
//! so nothing reads or writes your real `~/.ciphey` and the first-run wizard never starts.
//! The scratch dir is removed afterwards.
//!
//! Run: `cargo bench --bench startup`

mod common;

use ciphey::config::{load_wordlist, Config};
use ciphey::decoders::crack_results::CrackResult;
use ciphey::decoders::interface::{Decoder, DefaultDecoder};
use ciphey::perform_cracking;
use ciphey::storage::database::{self, CacheEntry};
use criterion::{criterion_group, criterion_main, BatchSize, Criterion, SamplingMode};
use std::hint::black_box;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Already plaintext, so `perform_cracking` returns before searching.
const PLAINTEXT: &str =
    "Meet me at the old lighthouse after midnight and bring the map, the key and a torch.";
/// `PLAINTEXT` in base64: one search step.
const BASE64: &str = "TWVldCBtZSBhdCB0aGUgb2xkIGxpZ2h0aG91c2UgYWZ0ZXIgbWlkbmlnaHQgYW5kIGJyaW5nIHRoZSBtYXAsIHRoZSBrZXkgYW5kIGEgdG9yY2gu";
/// Never inserted, for cache misses.
const NOT_CACHED: &str = "this text is never written to the cache";

/// Scratch dir under `target/`, removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        // CARGO_TARGET_TMPDIR is Cargo's scratch space for benches and integration tests,
        // fixed at compile time (`target/tmp`).
        let path = Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("ciphey-bench-startup-{}", std::process::id()));
        std::fs::create_dir_all(path.join(".ciphey")).expect("could not create scratch dir");
        std::fs::copy(
            common::data_path("config.toml"),
            path.join(".ciphey").join("config.toml"),
        )
        .expect("could not copy config.toml");
        TempDir(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn startup(c: &mut Criterion) {
    let home = TempDir::new();
    // Safe here: nothing else is running yet. `dirs::home_dir` reads HOME on Unix.
    std::env::set_var("HOME", &home.0);
    let db_path = home.0.join("bench.sqlite");
    database::DB_PATH
        .set(Some(db_path.clone()))
        .expect("the database path was already set");
    ciphey::config::set_global_config(common::bench_config());

    config_benches(c);
    cache_benches(c, &db_path);
    #[cfg(unix)]
    cli_benches(c, &home.0);
    #[cfg(not(unix))]
    eprintln!("skipping startup/cli: HOME can only be redirected on Unix");
}

fn config_benches(c: &mut Criterion) {
    let mut group = c.benchmark_group("startup/config");
    group
        .warm_up_time(Duration::from_millis(500))
        .measurement_time(Duration::from_secs(2));

    group.bench_function("default", |b| b.iter(Config::default));

    // What the CLI does first: read and parse ~/.ciphey/config.toml (HOME is the scratch dir).
    #[cfg(unix)]
    {
        let loaded = ciphey::config::get_config_file_into_struct();
        assert_eq!(loaded.timeout, 5, "did not read benches/data/config.toml");
        group.bench_function("load_config_file", |b| {
            b.iter(ciphey::config::get_config_file_into_struct)
        });
    }

    let wordlist = common::data_path("wordlist.txt");
    assert_eq!(load_wordlist(&wordlist).unwrap().len(), 5000);
    group.bench_function("load_wordlist_5k", |b| {
        b.iter(|| load_wordlist(black_box(&wordlist)).unwrap())
    });
    group.finish();
}

fn cache_entry(text: &str) -> CacheEntry {
    let mut step = CrackResult::new(&Decoder::<DefaultDecoder>::default(), text.to_string());
    step.unencrypted_text = Some(vec![text.to_string()]);
    CacheEntry {
        uuid: uuid::Uuid::new_v4(),
        encoded_text: text.to_string(),
        decoded_text: text.to_string(),
        path: vec![step],
        execution_time_ms: 1,
    }
}

fn cache_benches(c: &mut Criterion, db_path: &Path) {
    database::setup_database().expect("could not create the cache database");
    database::insert_cache(&cache_entry(PLAINTEXT)).expect("could not seed the cache");

    let mut group = c.benchmark_group("startup/cache");
    group
        .warm_up_time(Duration::from_millis(500))
        .measurement_time(Duration::from_secs(2));
    group.bench_function("setup_database", |b| {
        b.iter(|| database::setup_database().unwrap())
    });
    let missing = NOT_CACHED.to_string();
    assert!(database::read_cache(&missing).unwrap().is_none());
    group.bench_function("read_miss", |b| {
        b.iter(|| database::read_cache(black_box(&missing)).unwrap())
    });
    let present = PLAINTEXT.to_string();
    assert!(database::read_cache(&present).unwrap().is_some());
    group.bench_function("read_hit", |b| {
        b.iter(|| database::read_cache(black_box(&present)).unwrap())
    });
    // A new row each iteration, committed (and synced) like a real run.
    group.bench_function("insert", |b| {
        b.iter_batched(
            || cache_entry(NOT_CACHED),
            |entry| database::insert_cache(&entry).unwrap(),
            BatchSize::SmallInput,
        )
    });
    database::delete_cache(NOT_CACHED).unwrap();
    group.finish();

    let mut group = c.benchmark_group("startup/perform_cracking");
    group
        .warm_up_time(Duration::from_millis(500))
        .measurement_time(Duration::from_secs(3));
    let hit = perform_cracking(PLAINTEXT, common::bench_config()).unwrap();
    assert_eq!(hit.unwrap().text[0], PLAINTEXT);
    group.bench_function("plaintext_cache_hit", |b| {
        b.iter_batched(
            common::bench_config,
            |config| perform_cracking(black_box(PLAINTEXT), config),
            BatchSize::SmallInput,
        )
    });
    // Remove the row before every iteration so each one misses and writes it back.
    group.bench_function("plaintext_cache_miss", |b| {
        b.iter_batched(
            || {
                database::delete_cache(PLAINTEXT).unwrap();
                common::bench_config()
            },
            |config| perform_cracking(black_box(PLAINTEXT), config),
            BatchSize::PerIteration,
        )
    });
    group.finish();
    let _ = std::fs::remove_file(db_path);
}

#[cfg(unix)]
fn cli_benches(c: &mut Criterion, home: &Path) {
    use std::process::{Command, Stdio};

    let db = home.join(".ciphey").join("database.sqlite");
    let run = |text: &str| {
        let status = Command::new(env!("CARGO_BIN_EXE_ciphey"))
            .args(["--disable-human-checker", "--text", text])
            .env("HOME", home)
            .env_remove("RUST_LOG")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("could not start the ciphey binary");
        assert!(status.success(), "ciphey exited with {status}");
    };
    let output = Command::new(env!("CARGO_BIN_EXE_ciphey"))
        .args(["--disable-human-checker", "--text", BASE64])
        .env("HOME", home)
        .env("NO_COLOR", "1")
        .env_remove("RUST_LOG")
        .stdin(Stdio::null())
        .output()
        .expect("could not start the ciphey binary");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(PLAINTEXT),
        "unexpected CLI output: {stdout}"
    );

    let mut group = c.benchmark_group("startup/cli");
    group
        .sampling_mode(SamplingMode::Flat)
        .sample_size(20)
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(4));
    // Cache hit: the cheapest possible run.
    run(PLAINTEXT);
    group.bench_function("plaintext_cache_hit", |b| b.iter(|| run(PLAINTEXT)));
    // Fresh database: create the schema, check the input, store the result.
    group.bench_function("plaintext_fresh_db", |b| {
        b.iter_batched(
            || {
                let _ = std::fs::remove_file(&db);
            },
            |()| run(PLAINTEXT),
            BatchSize::PerIteration,
        )
    });
    // Fresh database plus a one-step search.
    group.bench_function("base64_fresh_db", |b| {
        b.iter_batched(
            || {
                let _ = std::fs::remove_file(&db);
            },
            |()| run(BASE64),
            BatchSize::PerIteration,
        )
    });
    group.finish();
}

criterion_group!(benches, startup);
criterion_main!(benches);
