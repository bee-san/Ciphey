//! Runs `decode` requests in worker processes.
//!
//! [`ProcessCracker`] starts this executable again with `--worker`, writes a [`CrackRequest`]
//! as one line of JSON to its stdin and reads the [`WorkerResponse`] JSON from the last line of
//! its stdout. The worker ([`run`]) configures the library for that one request, cracks, and
//! exits.

use std::io::Read;
use std::path::PathBuf;
use std::process::{ExitCode, Output, Stdio};
use std::sync::{Mutex, PoisonError};
use std::thread;
use std::time::Duration;

use ciphey::config::Config;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;
use tokio::sync::Semaphore;

use crate::server::{BoxFuture, Cracker, DecodeOutput, DecodeStatus};

/// How long a worker may run past its `timeout_secs` before it is killed. Covers process
/// start-up and the search thread noticing that the library's own timer went off.
const KILL_GRACE: Duration = Duration::from_secs(5);
/// Decodes allowed to run at once. Each worker already spreads its search over every core.
const MAX_CONCURRENT_DECODES: usize = 2;
/// How long a decode waits for a free slot. With the 30 s search limit and [`KILL_GRACE`] a
/// call takes at most 45 s, under the ~60 s tool-call timeout of many MCP clients.
const QUEUE_TIMEOUT: Duration = Duration::from_secs(10);
/// How much of a failed worker's stderr to put in the error message.
const STDERR_TAIL_CHARS: usize = 1_000;
/// How often a worker checks its memory use.
const MEMORY_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// A validated decode request, sent from the server to a worker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrackRequest {
    /// The text to decode.
    pub text: String,
    /// Seconds the search may run.
    pub timeout_secs: u32,
    /// Only accept plaintext that matches this regex.
    pub regex: Option<String>,
    /// Resident memory, in bytes, at which the worker gives up.
    pub max_memory_bytes: u64,
}

/// What a worker prints: the decode result, or a message saying why it failed.
type WorkerResponse = Result<DecodeOutput, String>;

/// Entry point of `ciphey-mcp --worker`: reads one [`CrackRequest`] line from stdin and prints
/// one [`WorkerResponse`] line to stdout.
///
/// The server keeps stdin open until the worker is done, so the worker exits as soon as it
/// sees EOF: the server is gone, and nobody would read the result.
pub fn run() -> ExitCode {
    let mut line = String::new();
    let response: WorkerResponse = match std::io::stdin().read_line(&mut line) {
        Ok(_) => {
            exit_on_eof();
            serde_json::from_str(&line)
                .map_err(|error| format!("invalid worker request: {error}"))
                .and_then(crack)
        }
        Err(error) => Err(format!("could not read the worker request: {error}")),
    };
    respond(&response)
}

/// Ends the worker once stdin reaches EOF (see [`run`]).
fn exit_on_eof() {
    thread::spawn(|| {
        let mut buffer = [0; 64];
        // Nothing follows the request, so this blocks until the server closes stdin.
        while matches!(std::io::stdin().read(&mut buffer), Ok(read) if read > 0) {}
        std::process::exit(1);
    });
}

/// Prints `response` as the worker's one line of output. Only the first call prints: the
/// memory watchdog can race the search to respond.
fn respond(response: &WorkerResponse) -> ExitCode {
    static RESPONDED: Mutex<bool> = Mutex::new(false);
    let mut responded = RESPONDED.lock().unwrap_or_else(PoisonError::into_inner);
    if std::mem::replace(&mut *responded, true) {
        return ExitCode::SUCCESS;
    }
    match serde_json::to_string(response) {
        Ok(line) => {
            println!("{line}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("could not encode the worker response: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Runs the library on `request`. Works once per process: the library's config can only be
/// set once.
fn crack(request: CrackRequest) -> WorkerResponse {
    watch_memory(request.max_memory_bytes);
    // Without a database path every connection opens a new, empty in-memory database, so the
    // cache is effectively off and the worker never touches ~/.ciphey/database.sqlite.
    let _ = ciphey::storage::database::DB_PATH.set(None);
    let config = Config {
        timeout: request.timeout_secs,
        regex: request.regex,
        // Keeps the library from printing to stdout, which carries our response.
        api_mode: true,
        human_checker_on: false,
        ..Config::default()
    };
    DecodeOutput::from_crack(
        ciphey::perform_cracking(&request.text, config),
        request.timeout_secs,
    )
}

/// Ends the worker with an error once its resident memory passes `limit` bytes.
///
/// A search that finds nothing keeps every open node in memory until its timeout, which can
/// reach several gigabytes for inputs a few kilobytes long.
fn watch_memory(limit: u64) {
    thread::spawn(move || loop {
        let resident = memory_stats::memory_stats().map(|usage| usage.physical_mem as u64);
        if resident.is_some_and(|resident| resident > limit) {
            let code = respond(&Err(format!(
                "the search used more than {} MiB of memory without finding plaintext. Try a \
                 smaller `timeout_secs`, a `regex` crib, or a shorter part of the text",
                limit >> 20
            )));
            // Stops the search threads too.
            std::process::exit(if code == ExitCode::SUCCESS { 0 } else { 1 });
        }
        thread::sleep(MEMORY_POLL_INTERVAL);
    });
}

/// Runs each request in a new worker process.
pub struct ProcessCracker {
    /// The executable started with `--worker`.
    exe: PathBuf,
    /// Limits how many workers run at once.
    slots: Semaphore,
    /// How long a request waits for a slot before giving up.
    queue_timeout: Duration,
}

impl ProcessCracker {
    /// Uses the running executable as the worker.
    pub fn for_current_exe() -> std::io::Result<Self> {
        Ok(Self::new(std::env::current_exe()?))
    }

    /// Uses `exe` as the worker.
    pub fn new(exe: PathBuf) -> Self {
        Self {
            exe,
            slots: Semaphore::new(MAX_CONCURRENT_DECODES),
            queue_timeout: QUEUE_TIMEOUT,
        }
    }

    /// Runs `request` in a worker, killing it if it overruns its timeout.
    async fn run(&self, request: CrackRequest) -> WorkerResponse {
        // The semaphore is never closed, so the only failure is the timeout.
        let Ok(Ok(_slot)) = tokio::time::timeout(self.queue_timeout, self.slots.acquire()).await
        else {
            return Err(format!(
                "ciphey is already running {MAX_CONCURRENT_DECODES} decodes; try again when one \
                 has finished"
            ));
        };
        let timeout_secs = request.timeout_secs;
        let mut input = serde_json::to_vec(&request)
            .map_err(|error| format!("could not encode the worker request: {error}"))?;
        input.push(b'\n');

        let mut command = tokio::process::Command::new(&self.exe);
        command
            .arg("--worker")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            // Dropping the child (timeout, cancellation, disconnect) kills the worker.
            .kill_on_drop(true);
        #[cfg(windows)]
        {
            // Don't pop up a console window when the MCP client is a GUI app.
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            command.creation_flags(CREATE_NO_WINDOW);
        }
        let mut child = command.spawn().map_err(|error| {
            format!(
                "could not start the ciphey worker {}: {error}",
                self.exe.display()
            )
        })?;

        // Held open until the worker is done: the worker exits when its stdin closes, which
        // also happens if this server dies.
        let mut stdin = child.stdin.take();
        let send = async {
            // A failed write means the worker already exited, which its output reports.
            if let Some(stdin) = stdin.as_mut() {
                let _ = stdin.write_all(&input).await;
            }
        };
        let deadline = Duration::from_secs(u64::from(timeout_secs)) + KILL_GRACE;
        let finished = tokio::time::timeout(deadline, async {
            tokio::join!(send, child.wait_with_output()).1
        })
        .await;
        drop(stdin);
        match finished {
            Ok(Ok(output)) => parse_output(&output),
            Ok(Err(error)) => Err(format!("the ciphey worker failed: {error}")),
            // The library stops at `timeout_secs` by itself; a worker this late is stuck
            // inside a decoder. It has been killed.
            Err(_) => Ok(DecodeOutput::without_plaintext(
                DecodeStatus::TimedOut,
                timeout_secs,
            )),
        }
    }
}

impl Cracker for ProcessCracker {
    fn crack(&self, request: CrackRequest) -> BoxFuture<'_, WorkerResponse> {
        Box::pin(self.run(request))
    }
}

/// Reads a worker's response from the last non-empty line of its stdout.
fn parse_output(output: &Output) -> WorkerResponse {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let response = stdout
        .lines()
        .rev()
        .find(|line| !line.trim().is_empty())
        .and_then(|line| serde_json::from_str::<WorkerResponse>(line).ok());
    response.unwrap_or_else(|| {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stderr = stderr.trim();
        // Keep the end, where panic messages are.
        let tail_start = stderr
            .char_indices()
            .rev()
            .nth(STDERR_TAIL_CHARS - 1)
            .map_or(0, |(index, _)| index);
        let mut message = format!(
            "the ciphey worker exited without a result ({})",
            output.status
        );
        if !stderr.is_empty() {
            message.push_str(": ");
            message.push_str(&stderr[tail_start..]);
        }
        Err(message)
    })
}

#[cfg(test)]
mod tests {
    use std::process::ExitStatus;

    use super::*;

    fn output(stdout: &str, stderr: &str) -> Output {
        Output {
            status: ExitStatus::default(),
            stdout: stdout.as_bytes().to_vec(),
            stderr: stderr.as_bytes().to_vec(),
        }
    }

    #[test]
    fn parse_output_reads_the_last_line() {
        let response: WorkerResponse =
            Ok(DecodeOutput::without_plaintext(DecodeStatus::NotFound, 5));
        let line = serde_json::to_string(&response).unwrap();
        // Stray output from a dependency must not break the protocol.
        let stdout = format!("some library noise\n{line}\n\n");

        assert_eq!(parse_output(&output(&stdout, "")), response);
    }

    #[test]
    fn parse_output_passes_on_worker_errors() {
        let line = serde_json::to_string(&WorkerResponse::Err("bad regex".to_string())).unwrap();

        assert_eq!(
            parse_output(&output(&line, "")),
            Err("bad regex".to_string())
        );
    }

    #[test]
    fn parse_output_reports_a_crash_with_the_end_of_stderr() {
        let stderr = format!(
            "{}thread 'main' panicked at src/lib.rs:1:1",
            "x".repeat(5_000)
        );

        let error = parse_output(&output("", &stderr)).unwrap_err();

        assert!(error.starts_with("the ciphey worker exited without a result"));
        assert!(error.ends_with("thread 'main' panicked at src/lib.rs:1:1"));
        assert!(error.len() < STDERR_TAIL_CHARS + 100, "{}", error.len());
    }

    #[tokio::test]
    async fn crack_reports_a_missing_worker_executable() {
        let cracker = ProcessCracker::new(PathBuf::from("no-such-dir/ciphey-mcp-worker"));

        let error = cracker.crack(request()).await.unwrap_err();

        assert!(
            error.starts_with("could not start the ciphey worker"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn crack_gives_up_when_every_slot_stays_busy() {
        let mut cracker = ProcessCracker::new(PathBuf::from("no-such-dir/ciphey-mcp-worker"));
        cracker.queue_timeout = Duration::from_millis(50);
        let _busy = cracker
            .slots
            .acquire_many(MAX_CONCURRENT_DECODES as u32)
            .await
            .unwrap();

        let error = cracker.crack(request()).await.unwrap_err();

        assert!(error.contains("already running 2 decodes"), "{error}");
    }

    fn request() -> CrackRequest {
        CrackRequest {
            text: "aGVsbG8=".to_string(),
            timeout_secs: 1,
            regex: None,
            max_memory_bytes: 1 << 30,
        }
    }
}
