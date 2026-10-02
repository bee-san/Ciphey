//! End-to-end tests for the live display, run in a real pseudo-terminal.
//!
//! `script` from util-linux gives ciphey a terminal for stdin and stdout, so it shows
//! the live display; the test reads what ciphey draws and types keys into it.
//! util-linux is only on Linux, so these tests are too. They are skipped if `script`
//! isn't installed.
#![cfg(target_os = "linux")]

use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// How long to wait for ciphey to show something. Generous for slow CI runners and
/// unoptimised builds.
const DEADLINE: Duration = Duration::from_secs(60);
/// Sent when the live display takes the terminal
const HIDE_CURSOR: &str = "\x1b[?25l";
/// Sent when it gives the terminal back
const SHOW_CURSOR: &str = "\x1b[?25h";

/// A temporary home directory with an empty ciphey config, removed when dropped
struct TempHome {
    /// Path to the directory
    path: PathBuf,
}

impl TempHome {
    /// Creates `target/tmp/ciphey-live-<name>-<pid>` with `.ciphey/config.toml`
    fn new(name: &str) -> Self {
        let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "ciphey-live-{}-{}",
            name,
            std::process::id()
        ));
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

/// ciphey running in a pseudo-terminal
struct Terminal {
    /// The `script` process
    child: Child,
    /// `script` has exited and been waited for
    exited: bool,
    /// Keys typed into the terminal
    keys: ChildStdin,
    /// Everything ciphey has written so far, escape codes included
    screen: Arc<Mutex<Vec<u8>>>,
    /// The home directory ciphey runs with, kept until the run is over
    home: TempHome,
}

impl Terminal {
    /// Starts ciphey with `args` in an 80×24 terminal, or returns None if `script`
    /// isn't available
    fn start(name: &str, args: &[&str]) -> Option<Self> {
        // timeout ends ciphey even if this test process dies without cleaning up
        let mut command = format!(
            "stty cols 80 rows 24 && exec timeout --foreground -k 5 {} '{}'",
            DEADLINE.as_secs() + 30,
            env!("CARGO_BIN_EXE_ciphey")
        );
        for arg in args {
            command.push_str(&format!(" '{}'", arg.replace('\'', r"'\''")));
        }
        Self::spawn(name, &command)
    }

    /// Starts an interactive bash with job control, prompt `$ `, in the terminal
    fn shell(name: &str) -> Option<Self> {
        Self::spawn(name, "PS1='$ ' exec bash --norc --noprofile -i")
    }

    /// Runs `command` with `sh` in a new pseudo-terminal under `script`
    fn spawn(name: &str, command: &str) -> Option<Self> {
        if Command::new("script").arg("--version").output().is_err() {
            eprintln!("skipping: util-linux script is not installed");
            return None;
        }
        let home = TempHome::new(name);
        let mut child = Command::new("script")
            .args(["-qec", command, "/dev/null"])
            .env("HOME", &home.path)
            .env("TERM", "xterm-256color")
            .env_remove("NO_COLOR")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("Could not run script");
        let keys = child.stdin.take().expect("stdin is piped");
        let mut out = child.stdout.take().expect("stdout is piped");
        let screen = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&screen);
        thread::spawn(move || {
            let mut buffer = [0; 4096];
            while let Ok(n) = out.read(&mut buffer) {
                if n == 0 {
                    break;
                }
                sink.lock().unwrap().extend_from_slice(&buffer[..n]);
            }
        });
        Some(Terminal {
            child,
            exited: false,
            keys,
            screen,
            home,
        })
    }

    /// Kills everything running in the pseudo-terminal, then `script`. Children go
    /// first: once `script` is gone they would no longer be found under it.
    fn kill_all(&mut self) {
        if self.exited {
            return;
        }
        kill_descendants(self.child.id());
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.exited = true;
    }

    /// Everything shown so far, as text
    fn screen(&self) -> String {
        String::from_utf8_lossy(&self.screen.lock().unwrap()).into_owned()
    }

    /// Waits until `text` appears on screen
    fn wait_for(&self, text: &str) {
        let started = Instant::now();
        while !self.screen().contains(text) {
            assert!(
                started.elapsed() < DEADLINE,
                "{text:?} never appeared. The screen showed:\n{}",
                self.screen()
            );
            thread::sleep(Duration::from_millis(20));
        }
    }

    /// How many times `text` has been shown so far
    fn count(&self, text: &str) -> usize {
        self.screen().matches(text).count()
    }

    /// Waits until `text` has been shown more than `before` times
    fn wait_for_more(&self, text: &str, before: usize) {
        let started = Instant::now();
        while self.count(text) <= before {
            assert!(
                started.elapsed() < DEADLINE,
                "{text:?} wasn't shown again. The screen showed:\n{}",
                self.screen()
            );
            thread::sleep(Duration::from_millis(20));
        }
    }

    /// Types `keys`
    fn press(&mut self, keys: &str) {
        self.keys.write_all(keys.as_bytes()).unwrap();
        self.keys.flush().unwrap();
    }

    /// Waits for ciphey to exit and returns its exit code and everything it showed
    fn finish(mut self) -> (Option<i32>, String) {
        let started = Instant::now();
        let status = loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                self.exited = true;
                break status;
            }
            if started.elapsed() > DEADLINE {
                self.kill_all();
                panic!("ciphey didn't exit. The screen showed:\n{}", self.screen());
            }
            thread::sleep(Duration::from_millis(20));
        };
        // Let the reader thread catch up with the last output
        thread::sleep(Duration::from_millis(200));
        (status.code(), self.screen())
    }
}

impl Drop for Terminal {
    /// A test that fails half way must not leave ciphey running
    fn drop(&mut self) {
        self.kill_all();
    }
}

/// Sends SIGKILL to every descendant of `pid`, deepest first
fn kill_descendants(pid: u32) {
    for child in children(pid) {
        kill_descendants(child);
        let _ = Command::new("kill")
            .args(["-KILL", &child.to_string()])
            .status();
    }
}

/// The processes whose parent is `pid`
fn children(pid: u32) -> Vec<u32> {
    let Ok(output) = Command::new("pgrep")
        .args(["-P", &pid.to_string()])
        .output()
    else {
        return Vec::new();
    };
    String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .filter_map(|child| child.parse().ok())
        .collect()
}

/// The ciphey process somewhere under `pid`
fn find_ciphey(pid: u32) -> Option<u32> {
    children(pid).into_iter().find_map(|child| {
        let comm = fs::read_to_string(format!("/proc/{child}/comm")).unwrap_or_default();
        if comm.trim() == "ciphey" {
            Some(child)
        } else {
            find_ciphey(child)
        }
    })
}

/// Whether `pid` is running: it exists and isn't a zombie
fn is_running(pid: u32) -> bool {
    !matches!(process_state(pid), Some('Z' | 'X') | None)
}

/// The state letter of `pid` from `/proc/<pid>/stat` (R, S, T, Z, ...) and its
/// process group
fn process_stat(pid: u32) -> Option<(char, u32)> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // The fields after the command name, which is in parentheses
    let mut fields = stat.rsplit(')').next()?.split_whitespace();
    let state = fields.next()?.chars().next()?;
    let _parent = fields.next()?;
    let group = fields.next()?.parse().ok()?;
    Some((state, group))
}

/// The state letter of `pid`, if it exists
fn process_state(pid: u32) -> Option<char> {
    process_stat(pid).map(|(state, _)| state)
}

/// Waits until `pid` is in `state`
fn wait_for_state(pid: u32, state: char, screen: impl Fn() -> String) {
    let started = Instant::now();
    while process_state(pid) != Some(state) {
        assert!(
            started.elapsed() < DEADLINE,
            "ciphey never reached state {state}. The screen showed:\n{}",
            screen()
        );
        thread::sleep(Duration::from_millis(20));
    }
}

/// The terminal has to be given back: cursor shown again, nothing left in raw mode
fn assert_terminal_restored(screen: &str) {
    assert!(
        screen.contains(SHOW_CURSOR),
        "the cursor was never shown again:\n{screen}"
    );
}

#[test]
fn answering_yes_shows_the_plaintext_and_how_it_was_decoded() {
    let Some(mut terminal) = Terminal::start("yes", &["-t", "aGVsbG8gdGhlcmUgZ2VuZXJhbA=="]) else {
        return;
    };
    terminal.wait_for("Is this the plaintext?");
    terminal.press("y");
    let (code, screen) = terminal.finish();
    assert_eq!(code, Some(0), "{screen}");
    assert!(screen.contains("Plaintext found"), "{screen}");
    assert!(screen.contains("hello there general"), "{screen}");
    assert!(screen.contains("Base64"), "{screen}");
    assert!(screen.contains("you said yes"), "{screen}");
    assert_terminal_restored(&screen);
}

#[test]
fn q_stops_the_search() {
    let Some(mut terminal) = Terminal::start(
        "stop",
        &["-d", "-c", "60", "-r", "^xyz", "-t", "aGVsbG8gd29ybGQ="],
    ) else {
        return;
    };
    terminal.wait_for("Searching");
    let pressed = Instant::now();
    terminal.press("q");
    let (code, screen) = terminal.finish();
    assert_eq!(code, Some(0), "{screen}");
    assert!(pressed.elapsed() < Duration::from_secs(30), "{screen}");
    assert!(screen.contains("No plaintext found"), "{screen}");
    assert!(screen.contains("you stopped it"), "{screen}");
    assert_terminal_restored(&screen);
}

#[test]
fn ctrl_c_quits_and_gives_the_terminal_back() {
    let Some(mut terminal) = Terminal::start(
        "ctrl-c",
        &["-d", "-c", "60", "-r", "^xyz", "-t", "aGVsbG8gd29ybGQ="],
    ) else {
        return;
    };
    terminal.wait_for("Searching");
    terminal.press("\x03");
    let (code, screen) = terminal.finish();
    assert_eq!(code, Some(130), "{screen}");
    assert!(!screen.contains("No plaintext found"), "{screen}");
    assert_terminal_restored(&screen);
}

#[test]
fn plain_flag_keeps_the_line_output() {
    let Some(terminal) = Terminal::start(
        "plain",
        &["--plain", "-d", "-t", "aGVsbG8gdGhlcmUgZ2VuZXJhbA=="],
    ) else {
        return;
    };
    let (code, screen) = terminal.finish();
    assert_eq!(code, Some(0), "{screen}");
    assert!(screen.contains("The plaintext is:"), "{screen}");
    assert!(screen.contains("the decoder used is"), "{screen}");
    // No live region: the cursor is never hidden
    assert!(!screen.contains(HIDE_CURSOR), "{screen}");
}

#[test]
fn sigterm_gives_the_terminal_back_and_exits() {
    let Some(terminal) = Terminal::start(
        "sigterm",
        &["-d", "-c", "60", "-r", "^xyz", "-t", "aGVsbG8gd29ybGQ="],
    ) else {
        return;
    };
    terminal.wait_for("Searching");
    let ciphey = find_ciphey(terminal.child.id()).expect("ciphey should be running");
    let _ = Command::new("kill")
        .args(["-TERM", &ciphey.to_string()])
        .status();
    let (code, screen) = terminal.finish();
    assert_eq!(code, Some(128 + 15), "{screen}");
    assert_terminal_restored(&screen);
}

#[test]
fn closing_the_terminal_ends_ciphey() {
    // Regression test: when its terminal went away during the live display, ciphey
    // ignored SIGHUP and SIGTERM and spun at full speed for ever
    let Some(mut terminal) = Terminal::start("hangup", &["-t", "aGVsbG8gdGhlcmUgZ2VuZXJhbA=="])
    else {
        return;
    };
    terminal.wait_for("Is this the plaintext?");
    let ciphey = find_ciphey(terminal.child.id()).expect("ciphey should be running");

    // Killing script closes the pseudo-terminal, like closing a terminal window
    let _ = terminal.child.kill();
    let _ = terminal.child.wait();
    terminal.exited = true;

    let started = Instant::now();
    while is_running(ciphey) {
        if started.elapsed() > Duration::from_secs(10) {
            let _ = Command::new("kill")
                .args(["-KILL", &ciphey.to_string()])
                .status();
            panic!("ciphey was still running 10 s after its terminal closed");
        }
        thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn ctrl_z_without_job_control_carries_on() {
    // Under `script` there is no job-control shell, so nothing could continue a
    // stopped ciphey and the kernel discards the stop. ciphey has to carry on rather
    // than hang.
    let Some(mut terminal) = Terminal::start(
        "ctrl-z-orphan",
        &["-d", "-c", "60", "-r", "^xyz", "-t", "aGVsbG8gd29ybGQ="],
    ) else {
        return;
    };
    terminal.wait_for("Searching");
    let ciphey = find_ciphey(terminal.child.id()).expect("ciphey should be running");
    let hidden = terminal.count(HIDE_CURSOR);

    terminal.press("\x1a");
    // It gave the terminal back, wasn't stopped, and took the terminal again
    terminal.wait_for_more(HIDE_CURSOR, hidden);
    assert_ne!(process_state(ciphey), Some('T'));

    terminal.press("q");
    let (code, screen) = terminal.finish();
    assert_eq!(code, Some(0), "{screen}");
    assert!(screen.contains("you stopped it"), "{screen}");
    assert_terminal_restored(&screen);
}

#[test]
fn ctrl_z_suspends_and_fg_carries_on() {
    let Some(mut terminal) = Terminal::shell("ctrl-z") else {
        return;
    };
    terminal.wait_for("$ ");
    terminal.press("stty cols 80 rows 24\r");
    terminal.press(&format!(
        "timeout --foreground -k 5 {} '{}' -d -c 60 -r '^xyz' -t aGVsbG8gd29ybGQ=\r",
        DEADLINE.as_secs() + 30,
        env!("CARGO_BIN_EXE_ciphey")
    ));
    terminal.wait_for("Searching");
    let ciphey = find_ciphey(terminal.child.id()).expect("ciphey should be running");
    let buffer = Arc::clone(&terminal.screen);
    let screen = move || String::from_utf8_lossy(&buffer.lock().unwrap()).into_owned();

    // Ctrl-Z stops the job, and the shell says so
    terminal.press("\x1a");
    wait_for_state(ciphey, 'T', &screen);
    terminal.wait_for("Stopped");

    // fg continues it, and it takes the terminal back and redraws
    let hidden = terminal.count(HIDE_CURSOR);
    terminal.press("fg\r");
    terminal.wait_for_more(HIDE_CURSOR, hidden);
    assert_ne!(process_state(ciphey), Some('T'));

    // Keys still work
    terminal.press("q");
    terminal.wait_for("you stopped it");
    terminal.press("exit\r");
    let (_, screen) = terminal.finish();
    assert_terminal_restored(&screen);
}

#[test]
fn background_job_prints_plain_lines() {
    // In the background ciphey can't take the terminal: raw mode would stop it with
    // SIGTTOU, and reading keys would fail for ever
    let Some(mut terminal) = Terminal::shell("background") else {
        return;
    };
    terminal.wait_for("$ ");
    terminal.press("stty cols 80 rows 24\r");
    terminal.press(&format!(
        "timeout -k 5 {} '{}' -d -t aGVsbG8gdGhlcmUgZ2VuZXJhbA== < /dev/tty & wait $!; echo exit=$?\r",
        DEADLINE.as_secs() + 30,
        env!("CARGO_BIN_EXE_ciphey")
    ));
    terminal.wait_for("exit=");
    terminal.press("exit\r");
    let (_, screen) = terminal.finish();
    assert!(screen.contains("exit=0"), "{screen}");
    assert!(screen.contains("The plaintext is:"), "{screen}");
    assert!(!screen.contains(HIDE_CURSOR), "{screen}");
}

#[test]
fn mostly_invisible_plaintext_is_saved_to_a_new_file() {
    // "hello    world    this    is    a    test": spaces count as invisible, so
    // ciphey offers to save it to a file instead of printing it
    let plaintext = "hello    world    this    is    a    test";
    let Some(mut terminal) = Terminal::start(
        "save",
        &[
            "-d",
            "-t",
            "aGVsbG8gICAgd29ybGQgICAgdGhpcyAgICBpcyAgICBhICAgIHRlc3Q=",
        ],
    ) else {
        return;
    };
    // A file from before must not be overwritten
    let existing = terminal.home.path.join("ciphey_text.txt");
    fs::write(&existing, "keep me").unwrap();

    terminal.wait_for("invisible characters");
    terminal.press("y\r");
    // Printed once the file has been written
    terminal.wait_for("Saved to");
    let saved = terminal.home.path.join("ciphey_text-2.txt");
    assert_eq!(fs::read_to_string(&saved).unwrap(), plaintext);
    assert_eq!(fs::read_to_string(&existing).unwrap(), "keep me");

    let (code, screen) = terminal.finish();
    assert_eq!(code, Some(0), "{screen}");
    assert!(screen.contains("ciphey_text-2.txt"), "{screen}");
}
