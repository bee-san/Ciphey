//! End-to-end tests that run the `ciphey` binary.
//!
//! Every test gets its own temporary home directory containing a ciphey config file,
//! so the interactive first-run setup is skipped and the cache starts out empty.
//!
//! On Windows `dirs::home_dir()` ignores `HOME`, so ciphey can't be pointed at a
//! temporary home directory there and these tests only run on Unix.
#![cfg(unix)]

use std::fmt;
use std::fs;
use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

/// How long a single ciphey run may take before the test fails.
/// Generous because CI runners are slow; the timeouts used below are 1-2 seconds.
const DEADLINE: Duration = Duration::from_secs(60);

/// A temporary home directory with a ciphey config file, removed when dropped.
struct TempHome {
    /// Path to the temporary home directory
    path: PathBuf,
}

impl TempHome {
    /// Creates a home directory whose `.ciphey/config.toml` is empty, so every setting
    /// has its default value.
    fn new(name: &str) -> Self {
        Self::with_config(name, "")
    }

    /// Creates a home directory whose `.ciphey/config.toml` contains `config`.
    /// It lives in Cargo's scratch directory for integration tests (`target/tmp`).
    fn with_config(name: &str, config: &str) -> Self {
        let dir_name = format!("ciphey-cli-{}-{}", name, std::process::id());
        let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(dir_name);
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(path.join(".ciphey")).expect("Could not create temporary home");
        fs::write(path.join(".ciphey").join("config.toml"), config)
            .expect("Could not create config file");
        TempHome { path }
    }
}

impl Drop for TempHome {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// What a finished ciphey run printed.
struct Output {
    /// Exit code, or None if ciphey was killed by a signal
    code: Option<i32>,
    /// Everything printed to stdout
    stdout: String,
    /// Everything printed to stderr
    stderr: String,
}

impl fmt::Display for Output {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "exit code: {:?}\n--- stdout ---\n{}\n--- stderr ---\n{}",
            self.code, self.stdout, self.stderr
        )
    }
}

/// Reads a pipe to the end on another thread, so ciphey never blocks on a full pipe.
fn read_in_background(mut pipe: impl Read + Send + 'static) -> thread::JoinHandle<String> {
    thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = pipe.read_to_end(&mut bytes);
        String::from_utf8_lossy(&bytes).into_owned()
    })
}

/// Runs ciphey with `args` and no stdin, failing the test if it doesn't exit within
/// [`DEADLINE`].
fn run(home: &TempHome, args: &[&str]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_ciphey"))
        .args(args)
        .env("HOME", &home.path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Could not run ciphey");
    let stdout = read_in_background(child.stdout.take().expect("stdout is piped"));
    let stderr = read_in_background(child.stderr.take().expect("stderr is piped"));

    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().expect("Could not wait for ciphey") {
            break status;
        }
        if started.elapsed() > DEADLINE {
            let _ = child.kill();
            let _ = child.wait();
            panic!("ciphey {args:?} was still running after {DEADLINE:?}");
        }
        thread::sleep(Duration::from_millis(20));
    };

    Output {
        code: status.code(),
        stdout: stdout.join().expect("stdout reader panicked"),
        stderr: stderr.join().expect("stderr reader panicked"),
    }
}

#[test]
fn top_results_mode_exits_when_the_timer_expires() {
    // Used to hang forever: the search thread blocked sending a result into a full
    // channel while the main thread waited for it to finish.
    let home = TempHome::new("top-results-exits");
    let output = run(
        &home,
        &["--top-results", "-c", "1", "-t", "SGVsbG8sIFdvcmxkIQ=="],
    );
    assert_eq!(output.code, Some(0), "{output}");
    assert!(
        output.stdout.contains("List of Possible Plaintexts"),
        "{output}"
    );
    assert!(output.stdout.contains("Hello, World!"), "{output}");
}

#[test]
fn cli_options_apply_with_enhanced_detection() {
    // --enable-enhanced-detection prints a message before the config is set, which used
    // to lock in the default config so every other CLI option was silently ignored.
    let home = TempHome::new("api-mode-enhanced-detection");
    let output = run(
        &home,
        &[
            "-a",
            "true",
            "-d",
            "--enable-enhanced-detection",
            "-t",
            "aGVsbG8gd29ybGQ=",
        ],
    );
    assert_eq!(output.code, Some(0), "{output}");
    assert_eq!(
        output.stdout, "",
        "API mode must not print to stdout\n{output}"
    );
}

#[test]
fn cli_options_apply_with_unknown_config_keys() {
    // Same bug, triggered by the warning about an unknown key in config.toml
    let home = TempHome::with_config("api-mode-unknown-key", "not_a_real_key = 1\n");
    let output = run(&home, &["-a", "true", "-d", "-t", "aGVsbG8gd29ybGQ="]);
    assert_eq!(output.code, Some(0), "{output}");
    assert!(output.stderr.contains("not_a_real_key"), "{output}");
    assert_eq!(
        output.stdout, "",
        "API mode must not print to stdout\n{output}"
    );
}

#[test]
fn regex_crib_is_respected() {
    // The simplesubstitution decoder used to declare success without asking the checker,
    // so the search returned junk like "W T" even though it doesn't match the crib.
    let home = TempHome::new("regex-crib");
    let output = run(
        &home,
        &["-d", "-c", "2", "--regex", "^xyz", "-t", "aGVsbG8gd29ybGQ="],
    );
    assert_eq!(output.code, Some(0), "{output}");
    assert!(!output.stdout.contains("The plaintext is"), "{output}");
    assert!(output.stdout.contains("failed to decode"), "{output}");
}

#[test]
fn human_checker_rejection_is_final() {
    // stdin is empty, so every prompt is answered "no". Caesar finds the plaintext first
    // and it's rejected; when Vigenere found the same text later the human checker used
    // to accept it without asking, because that prompt had already been shown.
    let home = TempHome::new("human-checker-rejection");
    let output = run(
        &home,
        &[
            "-c",
            "2",
            "-t",
            "Uryyb jbeyq, guvf vf n grfg bs gur uhzna purpxre",
        ],
    );
    assert_eq!(output.code, Some(0), "{output}");
    assert!(output.stdout.contains("Possible plaintext"), "{output}");
    assert!(!output.stdout.contains("The plaintext is"), "{output}");
}

#[test]
fn missing_input_is_a_usage_error() {
    // Used to panic ("Error. No input was provided") and exit with 101
    let home = TempHome::new("missing-input");
    let output = run(&home, &[]);
    assert_eq!(output.code, Some(2), "{output}");
    assert!(output.stderr.contains("--text"), "{output}");
    assert!(!output.stderr.contains("panicked"), "{output}");
}

#[test]
fn malformed_config_file_falls_back_to_defaults() {
    // A value of the wrong type in config.toml used to panic at startup
    let home = TempHome::with_config("malformed-config", "timeout = \"ten\"\n");
    let output = run(&home, &["-d", "-t", "aGVsbG8gd29ybGQ="]);
    assert_eq!(output.code, Some(0), "{output}");
    assert!(
        output.stderr.contains("Error parsing config file"),
        "{output}"
    );
    assert!(!output.stderr.contains("panicked"), "{output}");
    assert!(output.stdout.contains("hello world"), "{output}");
}

#[test]
fn wordlist_words_after_a_line_that_is_not_utf8_are_used() {
    // Loading a wordlist used to stop at the first line that isn't UTF-8 (rockyou.txt
    // has some), silently dropping every word after it. This word is only identified
    // as plaintext through the wordlist.
    let home = TempHome::new("wordlist-not-utf8");
    let wordlist = home.path.join("wordlist.txt");
    fs::write(&wordlist, b"\xe9t\xe9\nzqxjvkwpfb\n").expect("Could not write wordlist");
    let wordlist = wordlist.to_str().expect("temporary path is UTF-8");

    // "zqxjvkwpfb" in Base64
    let output = run(
        &home,
        &[
            "-d",
            "-c",
            "2",
            "--wordlist",
            wordlist,
            "-t",
            "enF4anZrd3BmYg==",
        ],
    );
    assert_eq!(output.code, Some(0), "{output}");
    assert!(output.stdout.contains("zqxjvkwpfb"), "{output}");
}

#[test]
fn top_results_can_be_set_in_the_config_file() {
    // The CLI used to overwrite the config file's top_results with the --top-results
    // flag, so `top_results = true` (what the first-run setup offers) had no effect.
    let home = TempHome::with_config("top-results-config", "top_results = true\n");
    let output = run(&home, &["-c", "1", "-t", "SGVsbG8sIFdvcmxkIQ=="]);
    assert_eq!(output.code, Some(0), "{output}");
    assert!(
        output.stdout.contains("List of Possible Plaintexts"),
        "{output}"
    );
}

#[test]
fn top_results_mode_lists_results_when_the_input_is_cached() {
    let home = TempHome::new("top-results-cached");
    // Decode normally first so the plaintext is in the cache
    let first = run(&home, &["-d", "-t", "SGVsbG8sIFdvcmxkIQ=="]);
    assert!(first.stdout.contains("Hello, World!"), "{first}");

    // Used to return the cached result straight away, and as top results mode only
    // prints when the search timer expires, nothing at all was printed
    let second = run(
        &home,
        &["--top-results", "-c", "1", "-t", "SGVsbG8sIFdvcmxkIQ=="],
    );
    assert_eq!(second.code, Some(0), "{second}");
    assert!(
        second.stdout.contains("List of Possible Plaintexts"),
        "{second}"
    );
    assert!(second.stdout.contains("Hello, World!"), "{second}");
}

#[test]
fn cached_plaintext_must_match_the_regex_crib() {
    let home = TempHome::new("regex-crib-cached");
    // Decode normally first so the plaintext is in the cache
    let first = run(&home, &["-d", "-t", "aGVsbG8gd29ybGQ="]);
    assert!(first.stdout.contains("hello world"), "{first}");

    // "hello world" doesn't match the crib, but used to be returned from the cache
    let second = run(
        &home,
        &["-d", "-c", "1", "--regex", "^xyz", "-t", "aGVsbG8gd29ybGQ="],
    );
    assert_eq!(second.code, Some(0), "{second}");
    assert!(!second.stdout.contains("The plaintext is"), "{second}");
}

#[test]
fn ascii85_issue_example_is_cracked_with_a_crib() {
    // The example from https://github.com/bee-san/Ciphey/issues/926. Athena doesn't
    // recognise this pangram as English, so the crib is what identifies the plaintext.
    let home = TempHome::new("ascii85-crib");
    let output = run(
        &home,
        &[
            "-d",
            "--regex",
            "^Sphinx",
            "-t",
            r#"<~;fHDaDKm:BAftQ!@:O'qEHP]1FF#J\C3='"AKYi8+Eh[I/c~>"#,
        ],
    );
    assert_eq!(output.code, Some(0), "{output}");
    assert!(
        output
            .stdout
            .contains("Sphinx of black quartz, judge my vow."),
        "{output}"
    );
    assert!(output.stdout.contains("Ascii85"), "{output}");
}
