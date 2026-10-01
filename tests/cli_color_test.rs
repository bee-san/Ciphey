//! End-to-end tests for coloured CLI output.
//! Regression tests for https://github.com/bee-san/Ciphey/issues/903
//!
//! On Windows `dirs::home_dir()` ignores `HOME`, so these tests can't point ciphey
//! at a temporary config directory and would start the interactive first-run setup.
#![cfg(unix)]

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};

/// A temporary home directory with a ciphey config file, removed when dropped.
/// Having a config file means ciphey skips the interactive first-run setup.
struct TempHome {
    /// Path to the temporary home directory
    path: PathBuf,
}

impl TempHome {
    /// Creates a new temporary home directory inside Cargo's scratch directory for
    /// integration tests (`target/tmp`). The path is fixed at compile time rather
    /// than read from the environment at runtime.
    fn new(name: &str) -> Self {
        let dir_name = format!("ciphey-{}-{}", name, std::process::id());
        let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(dir_name);
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(path.join(".ciphey")).expect("Could not create temporary home");
        fs::write(path.join(".ciphey").join("config.toml"), "")
            .expect("Could not create config file");
        TempHome { path }
    }
}

impl Drop for TempHome {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// Runs ciphey on plaintext input and returns everything it printed to stdout and stderr.
/// `--enable-enhanced-detection` prints the message from the bug report to stderr.
fn run_ciphey(no_color: Option<&str>) -> String {
    let home = TempHome::new(&format!("color-test-{}", no_color.unwrap_or("unset")));
    let mut command = Command::new(env!("CARGO_BIN_EXE_ciphey"));
    command
        .args([
            "-t",
            "Hello, World!",
            "--disable-human-checker",
            "--enable-enhanced-detection",
        ])
        .env("HOME", &home.path)
        .env_remove("NO_COLOR")
        .stdin(Stdio::null());
    if let Some(value) = no_color {
        command.env("NO_COLOR", value);
    }

    let output = command.output().expect("Could not run ciphey");
    let printed = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.status.success(), "ciphey failed:\n{printed}");
    printed
}

#[test]
fn test_no_color_disables_ansi_escape_codes() {
    let printed = run_ciphey(Some("1"));
    assert!(printed.contains("Enhanced detection enabled."));
    assert!(printed.contains("Hello, World!"));
    assert!(
        !printed.contains('\x1b'),
        "Found ANSI escape codes with NO_COLOR set:\n{printed:?}"
    );
}

#[test]
fn test_colors_are_used_by_default() {
    let printed = run_ciphey(None);
    assert!(printed.contains("Hello, World!"));
    assert!(
        printed.contains("\x1b[38;2;"),
        "Expected coloured output:\n{printed:?}"
    );
}
