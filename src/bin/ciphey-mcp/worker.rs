//! Runs tool calls in worker processes.
//!
//! [`ProcessRunner`] starts this executable again with `--worker`, writes a [`WorkerRequest`]
//! as one line of JSON to its stdin and reads the response, `{"Ok": <result>}` or
//! `{"Err": <message>}`, from the last line of its stdout. The worker ([`run`]) configures
//! the library for that one request, runs it, and exits.

use std::io::Read;
use std::path::PathBuf;
use std::process::{ExitCode, Output, Stdio};
use std::sync::{Mutex, PoisonError};
use std::thread;
use std::time::Duration;

use ciphey::config::Config;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;
use tokio::sync::Semaphore;

use crate::decode_with::{self, DecodeWithOutput, DecodeWithRequest};
use crate::detect::{self, DetectOutput, DetectRequest};
use crate::server::{BoxFuture, DecodeOutput, DecodeStatus, Runner};

/// How long a worker may run past its time limit before it is killed. Covers process
/// start-up and a worker too stuck to stop itself.
const KILL_GRACE: Duration = Duration::from_secs(5);
/// Decodes allowed to run at once. Each worker already spreads its search over every core.
const MAX_CONCURRENT_DECODES: usize = 2;
/// `decode_with` and `detect_plaintext` calls allowed to run at once. They have slots of
/// their own, so that two long decodes don't hold them up.
const MAX_CONCURRENT_QUICK_CALLS: usize = 4;
/// How long a call waits for a free slot. With the 30 s search limit and [`KILL_GRACE`] a
/// call takes at most 45 s, under the ~60 s tool-call timeout of many MCP clients.
const QUEUE_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a `decode_with` call may run. The slowest crackers, the rail fence and ROT47,
/// take up to 10 s on 65,536 characters in a release build.
pub const DECODE_WITH_TIME_LIMIT: Duration = Duration::from_secs(30);
/// How long a `detect_plaintext` call may run. The checks take well under a second on
/// 65,536 characters.
pub const DETECT_TIME_LIMIT: Duration = Duration::from_secs(10);
/// Resident memory a decode may use before it is stopped. A search that finds nothing grows
/// until its timeout: a few kilobytes of input can otherwise reach several gigabytes.
const DECODE_MEMORY_LIMIT: u64 = 1 << 30;
/// Resident memory a `decode_with` or `detect_plaintext` call may use before it is stopped.
/// The most any decoder used on 65,536 characters was 40 MiB, cracking ROT47.
const QUICK_CALL_MEMORY_LIMIT: u64 = 256 << 20;
/// How much of a failed worker's stderr to put in the error message.
const STDERR_TAIL_CHARS: usize = 1_000;
/// How often a worker checks its memory use.
const MEMORY_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// What the server sends a worker: one job, and the limits it runs under.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerRequest {
    /// The tool call to run.
    pub job: Job,
    /// Resident memory, in bytes, at which the worker gives up.
    pub max_memory_bytes: u64,
    /// Milliseconds after which the worker gives up. `None` for a decode, which the
    /// library's own timer stops.
    pub time_limit_ms: Option<u64>,
}

/// A tool call for a worker to run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "tool", rename_all = "snake_case")]
pub enum Job {
    /// `decode`: the whole search.
    Decode(CrackRequest),
    /// `decode_with`: one decoder.
    DecodeWith(DecodeWithRequest),
    /// `detect_plaintext`: the plaintext checks.
    DetectPlaintext(DetectRequest),
}

impl Job {
    /// The tool the job is for, for messages.
    fn tool(&self) -> &'static str {
        match self {
            Job::Decode(_) => "decode",
            Job::DecodeWith(_) => "decode_with",
            Job::DetectPlaintext(_) => "detect_plaintext",
        }
    }
}

/// A validated `decode` call, sent from the server to a worker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrackRequest {
    /// The text to decode.
    pub text: String,
    /// Seconds the search may run.
    pub timeout_secs: u32,
    /// Only accept plaintext that matches this regex.
    pub regex: Option<String>,
}

/// What a worker prints: the job's result, or a message saying why it failed.
type WorkerResponse<T> = Result<T, String>;

/// Entry point of `ciphey-mcp --worker`: reads one [`WorkerRequest`] line from stdin and
/// prints one response line to stdout.
///
/// The server keeps stdin open until the worker is done, so the worker exits as soon as it
/// sees EOF: the server is gone, and nobody would read the result.
pub fn run() -> ExitCode {
    let mut line = String::new();
    match std::io::stdin().read_line(&mut line) {
        Ok(_) => {
            exit_on_eof();
            match serde_json::from_str::<WorkerRequest>(&line) {
                Ok(request) => run_job(request),
                Err(error) => fail(format!("invalid worker request: {error}")),
            }
        }
        Err(error) => fail(format!("could not read the worker request: {error}")),
    }
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

/// Runs `request`'s job under its limits and prints the result. Works once per process: the
/// library's config can only be set once.
fn run_job(request: WorkerRequest) -> ExitCode {
    watch_memory(
        request.max_memory_bytes,
        over_memory(&request.job, request.max_memory_bytes),
    );
    if let Some(limit) = request.time_limit_ms {
        watch_time(request.job.tool(), Duration::from_millis(limit));
    }
    // Without a database path every connection opens a new, empty in-memory database, so the
    // cache is effectively off and the worker never touches ~/.ciphey/database.sqlite.
    let _ = ciphey::storage::database::DB_PATH.set(None);
    match request.job {
        Job::Decode(request) => respond(&crack(request)),
        Job::DecodeWith(request) => {
            // The decoders' checks follow the config's crib, as they do in a search.
            ciphey::config::set_global_config(Config {
                regex: request.regex.clone(),
                ..quiet_config()
            });
            respond(&decode_with::run(&request))
        }
        Job::DetectPlaintext(request) => {
            // detect_plaintext takes its crib from the request, not the config.
            ciphey::config::set_global_config(quiet_config());
            respond(&detect::run(&request))
        }
    }
}

/// Prints `response` as the worker's one line of output. Only the first call prints: the
/// watchdogs can race the job to respond.
fn respond<T: Serialize>(response: &WorkerResponse<T>) -> ExitCode {
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

/// Prints `message` as the worker's error response. It reads as an error whatever result
/// the server expects.
fn fail(message: String) -> ExitCode {
    respond(&WorkerResponse::<()>::Err(message))
}

/// Prints `message` as the worker's error response, and ends the worker and its search.
fn fail_and_exit(message: String) -> ! {
    let code = fail(message);
    std::process::exit(if code == ExitCode::SUCCESS { 0 } else { 1 });
}

/// The library settings every worker uses.
fn quiet_config() -> Config {
    Config {
        // Keeps the library from printing to stdout, which carries our response.
        api_mode: true,
        human_checker_on: false,
        ..Config::default()
    }
}

/// Runs the whole search on `request`.
fn crack(request: CrackRequest) -> WorkerResponse<DecodeOutput> {
    let config = Config {
        timeout: request.timeout_secs,
        regex: request.regex,
        ..quiet_config()
    };
    DecodeOutput::from_crack(
        ciphey::perform_cracking(&request.text, config),
        request.timeout_secs,
    )
}

/// Ends the worker with the error `message` once its resident memory passes `limit` bytes.
///
/// A search that finds nothing keeps every open node in memory until its timeout, which can
/// reach several gigabytes for inputs a few kilobytes long.
fn watch_memory(limit: u64, message: String) {
    thread::spawn(move || loop {
        let resident = memory_stats::memory_stats().map(|usage| usage.physical_mem as u64);
        if resident.is_some_and(|resident| resident > limit) {
            fail_and_exit(message);
        }
        thread::sleep(MEMORY_POLL_INTERVAL);
    });
}

/// The error for `job` stopped at `limit` bytes of memory.
fn over_memory(job: &Job, limit: u64) -> String {
    let mib = limit >> 20;
    match job {
        Job::Decode(_) => format!(
            "the search used more than {mib} MiB of memory without finding plaintext. Try a \
             smaller `timeout_secs`, a `regex` crib, or a shorter part of the text"
        ),
        _ => format!(
            "`{}` used more than {mib} MiB of memory without finishing. Try a shorter `text`",
            job.tool()
        ),
    }
}

/// Ends the worker with an error once it has run `tool` for `limit`.
fn watch_time(tool: &'static str, limit: Duration) {
    thread::spawn(move || {
        thread::sleep(limit);
        fail_and_exit(format!(
            "`{tool}` stopped after {} without finishing. Try a shorter `text`",
            describe(limit)
        ));
    });
}

/// `duration` in whole seconds, or in milliseconds if it isn't a whole number of seconds.
fn describe(duration: Duration) -> String {
    if duration.subsec_millis() == 0 && duration.as_secs() > 0 {
        format!("{} s", duration.as_secs())
    } else {
        format!("{} ms", duration.as_millis())
    }
}

/// A number of workers that may run at once, for one kind of call.
struct Slots {
    /// One permit per worker.
    semaphore: Semaphore,
    /// The error for a call that found no free slot in time.
    busy: String,
}

impl Slots {
    /// `count` slots for `calls` (such as "decodes"), for the busy message.
    fn new(count: usize, calls: &str) -> Self {
        Self {
            semaphore: Semaphore::new(count),
            busy: format!(
                "ciphey is already running {count} {calls}; try again when one has finished"
            ),
        }
    }
}

/// Runs each call in a new worker process.
pub struct ProcessRunner {
    /// The executable started with `--worker`.
    exe: PathBuf,
    /// Limits how many decodes run at once.
    decodes: Slots,
    /// Limits how many `decode_with` and `detect_plaintext` calls run at once.
    quick_calls: Slots,
    /// How long a call waits for a slot before giving up.
    queue_timeout: Duration,
}

impl ProcessRunner {
    /// Uses the running executable as the worker.
    pub fn for_current_exe() -> std::io::Result<Self> {
        Ok(Self::new(std::env::current_exe()?))
    }

    /// Uses `exe` as the worker.
    pub fn new(exe: PathBuf) -> Self {
        Self {
            exe,
            decodes: Slots::new(MAX_CONCURRENT_DECODES, "decodes"),
            quick_calls: Slots::new(
                MAX_CONCURRENT_QUICK_CALLS,
                "decode_with and detect_plaintext calls",
            ),
            queue_timeout: QUEUE_TIMEOUT,
        }
    }

    /// Runs a `decode_with` or `detect_plaintext` job, which the worker stops after
    /// `time_limit`.
    async fn run_quick<T: DeserializeOwned>(
        &self,
        job: Job,
        time_limit: Duration,
    ) -> WorkerResponse<T> {
        let tool = job.tool();
        let request = WorkerRequest {
            job,
            max_memory_bytes: QUICK_CALL_MEMORY_LIMIT,
            time_limit_ms: Some(u64::try_from(time_limit.as_millis()).unwrap_or(u64::MAX)),
        };
        // The worker stops itself at its time limit; this is for one that can't.
        let deadline = time_limit + KILL_GRACE;
        match self
            .run_worker(&request, &self.quick_calls, deadline)
            .await?
        {
            Some(output) => parse_output(&output),
            None => Err(format!(
                "`{tool}` didn't finish within {} and was stopped. Try a shorter `text`",
                describe(deadline)
            )),
        }
    }

    /// Runs `request` in a worker once one of `slots` is free. `None` if the worker was
    /// still running after `deadline`, and has been killed.
    async fn run_worker(
        &self,
        request: &WorkerRequest,
        slots: &Slots,
        deadline: Duration,
    ) -> Result<Option<Output>, String> {
        // The semaphore is never closed, so the only failure is the timeout.
        let Ok(Ok(_slot)) =
            tokio::time::timeout(self.queue_timeout, slots.semaphore.acquire()).await
        else {
            return Err(slots.busy.clone());
        };
        let mut input = serde_json::to_vec(request)
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
        let finished = tokio::time::timeout(deadline, async {
            tokio::join!(send, child.wait_with_output()).1
        })
        .await;
        drop(stdin);
        match finished {
            Ok(Ok(output)) => Ok(Some(output)),
            Ok(Err(error)) => Err(format!("the ciphey worker failed: {error}")),
            Err(_) => Ok(None),
        }
    }
}

impl Runner for ProcessRunner {
    fn decode(&self, request: CrackRequest) -> BoxFuture<'_, WorkerResponse<DecodeOutput>> {
        Box::pin(async move {
            let timeout_secs = request.timeout_secs;
            let deadline = Duration::from_secs(u64::from(timeout_secs)) + KILL_GRACE;
            let request = WorkerRequest {
                job: Job::Decode(request),
                max_memory_bytes: DECODE_MEMORY_LIMIT,
                time_limit_ms: None,
            };
            match self.run_worker(&request, &self.decodes, deadline).await? {
                Some(output) => parse_output(&output),
                // The library stops at `timeout_secs` by itself; a worker this late is stuck
                // inside a decoder. It has been killed.
                None => Ok(DecodeOutput::without_plaintext(
                    DecodeStatus::TimedOut,
                    timeout_secs,
                )),
            }
        })
    }

    fn decode_with(
        &self,
        request: DecodeWithRequest,
    ) -> BoxFuture<'_, WorkerResponse<DecodeWithOutput>> {
        Box::pin(self.run_quick(Job::DecodeWith(request), DECODE_WITH_TIME_LIMIT))
    }

    fn detect_plaintext(
        &self,
        request: DetectRequest,
    ) -> BoxFuture<'_, WorkerResponse<DetectOutput>> {
        Box::pin(self.run_quick(Job::DetectPlaintext(request), DETECT_TIME_LIMIT))
    }
}

/// Reads a worker's response from the last non-empty line of its stdout.
fn parse_output<T: DeserializeOwned>(output: &Output) -> WorkerResponse<T> {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let response = stdout
        .lines()
        .rev()
        .find(|line| !line.trim().is_empty())
        .and_then(|line| serde_json::from_str::<WorkerResponse<T>>(line).ok());
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

    use serde_json::json;

    use super::*;
    use crate::detect::SensitivityChoice;

    fn output(stdout: &str, stderr: &str) -> Output {
        Output {
            status: ExitStatus::default(),
            stdout: stdout.as_bytes().to_vec(),
            stderr: stderr.as_bytes().to_vec(),
        }
    }

    #[test]
    fn parse_output_reads_the_last_line() {
        let response: WorkerResponse<DecodeOutput> =
            Ok(DecodeOutput::without_plaintext(DecodeStatus::NotFound, 5));
        let line = serde_json::to_string(&response).unwrap();
        // Stray output from a dependency must not break the protocol.
        let stdout = format!("some library noise\n{line}\n\n");

        assert_eq!(parse_output(&output(&stdout, "")), response);
    }

    #[test]
    fn parse_output_passes_on_worker_errors() {
        // What `fail` prints, whatever result the server expects.
        let line =
            serde_json::to_string(&WorkerResponse::<()>::Err("bad regex".to_string())).unwrap();

        assert_eq!(
            parse_output::<DecodeWithOutput>(&output(&line, "")),
            Err("bad regex".to_string())
        );
    }

    #[test]
    fn parse_output_reports_a_crash_with_the_end_of_stderr() {
        let stderr = format!(
            "{}thread 'main' panicked at src/lib.rs:1:1",
            "x".repeat(5_000)
        );

        let error = parse_output::<DetectOutput>(&output("", &stderr)).unwrap_err();

        assert!(error.starts_with("the ciphey worker exited without a result"));
        assert!(error.ends_with("thread 'main' panicked at src/lib.rs:1:1"));
        assert!(error.len() < STDERR_TAIL_CHARS + 100, "{}", error.len());
    }

    #[test]
    fn requests_are_tagged_with_their_tool() {
        let request = WorkerRequest {
            job: Job::DetectPlaintext(DetectRequest {
                text: "hi".to_string(),
                checkers: None,
                sensitivity: SensitivityChoice::High,
                regex: None,
            }),
            max_memory_bytes: 1 << 30,
            time_limit_ms: Some(10_000),
        };
        let value = serde_json::to_value(&request).unwrap();
        assert_eq!(
            value,
            json!({
                "job": {
                    "tool": "detect_plaintext",
                    "text": "hi",
                    "checkers": null,
                    "sensitivity": "high",
                    "regex": null,
                },
                "max_memory_bytes": 1u64 << 30,
                "time_limit_ms": 10_000,
            })
        );
        assert_eq!(
            serde_json::from_value::<WorkerRequest>(value).unwrap(),
            request
        );
    }

    #[test]
    fn durations_are_described_in_seconds_or_milliseconds() {
        assert_eq!(describe(Duration::from_secs(30)), "30 s");
        assert_eq!(describe(Duration::from_millis(1_500)), "1500 ms");
        assert_eq!(describe(Duration::from_millis(1)), "1 ms");
    }

    #[test]
    fn memory_errors_say_what_to_try() {
        let decode = over_memory(&Job::Decode(crack_request()), DECODE_MEMORY_LIMIT);
        assert!(
            decode.starts_with("the search used more than 1024 MiB of memory"),
            "{decode}"
        );
        assert!(decode.contains("`timeout_secs`"), "{decode}");

        let detect = over_memory(
            &Job::DetectPlaintext(detect_request()),
            QUICK_CALL_MEMORY_LIMIT,
        );
        assert_eq!(
            detect,
            "`detect_plaintext` used more than 256 MiB of memory without finishing. Try a \
             shorter `text`"
        );
    }

    #[tokio::test]
    async fn calls_report_a_missing_worker_executable() {
        let runner = ProcessRunner::new(PathBuf::from("no-such-dir/ciphey-mcp-worker"));

        let error = runner.decode(crack_request()).await.unwrap_err();
        assert!(
            error.starts_with("could not start the ciphey worker"),
            "{error}"
        );
        let error = runner.detect_plaintext(detect_request()).await.unwrap_err();
        assert!(
            error.starts_with("could not start the ciphey worker"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn calls_give_up_when_every_slot_stays_busy() {
        let mut runner = ProcessRunner::new(PathBuf::from("no-such-dir/ciphey-mcp-worker"));
        runner.queue_timeout = Duration::from_millis(50);
        let _busy = runner
            .decodes
            .semaphore
            .acquire_many(MAX_CONCURRENT_DECODES as u32)
            .await
            .unwrap();

        let error = runner.decode(crack_request()).await.unwrap_err();
        assert!(error.contains("already running 2 decodes"), "{error}");
        // The other tools have slots of their own, so a busy search doesn't hold them up.
        let error = runner.detect_plaintext(detect_request()).await.unwrap_err();
        assert!(
            error.starts_with("could not start the ciphey worker"),
            "{error}"
        );

        let _busy = runner
            .quick_calls
            .semaphore
            .acquire_many(MAX_CONCURRENT_QUICK_CALLS as u32)
            .await
            .unwrap();
        let error = runner.detect_plaintext(detect_request()).await.unwrap_err();
        assert!(
            error.contains("already running 4 decode_with and detect_plaintext calls"),
            "{error}"
        );
    }

    fn crack_request() -> CrackRequest {
        CrackRequest {
            text: "aGVsbG8=".to_string(),
            timeout_secs: 1,
            regex: None,
        }
    }

    fn detect_request() -> DetectRequest {
        DetectRequest {
            text: "hello".to_string(),
            checkers: None,
            sensitivity: SensitivityChoice::Medium,
            regex: None,
        }
    }
}
