//! The MCP server: its tools (`decode`, `decode_with`, `detect_plaintext`, `list_decoders`),
//! the `decode` tool's arguments and results, and the input limits the tools share.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use ciphey::decoders::crack_results::CrackResult;
use ciphey::decoders::interface::{Decoder, DefaultDecoder};
use ciphey::{CipheyError, DecoderResult};
use rmcp::handler::server::wrapper::{Json, Parameters};
use rmcp::service::RequestContext;
use rmcp::{schemars, tool, tool_handler, tool_router, RoleServer, ServerHandler, ServiceExt};
use serde::{Deserialize, Serialize};

use crate::decode_with::{DecodeWithOutput, DecodeWithParams, DecodeWithRequest, DecoderList};
use crate::detect::{DetectOutput, DetectParams, DetectRequest};
use crate::worker::{CrackRequest, ProcessRunner};

/// Longest `text` the tools accept, in characters.
pub const MAX_INPUT_CHARS: usize = 65_536;
/// Longest `regex` the tools accept, in characters.
pub const MAX_REGEX_CHARS: usize = 1_000;
/// `timeout_secs` used when the caller doesn't pass one.
pub const DEFAULT_TIMEOUT_SECS: u32 = 10;
/// Largest `timeout_secs` that `decode` accepts. Leaves headroom under the ~60 s tool-call
/// timeout that many MCP clients apply.
pub const MAX_TIMEOUT_SECS: u32 = 30;

/// Runs the MCP server on stdin/stdout until the client disconnects.
pub fn serve_stdio() -> Result<(), Box<dyn std::error::Error>> {
    let server = CipheyMcp::new(Arc::new(ProcessRunner::for_current_exe()?));
    // One thread is plenty: the server only moves JSON around and waits on worker processes.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let service = server.serve(rmcp::transport::stdio()).await?;
        service.waiting().await?;
        Ok(())
    })
}

/// A boxed future that can move between threads, as [`Runner`]'s methods return.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Runs validated tool calls to completion.
///
/// The server uses [`ProcessRunner`], which runs every call in a worker process. Tests
/// substitute fakes. An `Err` is a message for the caller and becomes a tool error.
pub trait Runner: Send + Sync + 'static {
    /// Runs the whole search on `request`.
    fn decode(&self, request: CrackRequest) -> BoxFuture<'_, Result<DecodeOutput, String>>;
    /// Runs one decoder on `request`.
    fn decode_with(
        &self,
        request: DecodeWithRequest,
    ) -> BoxFuture<'_, Result<DecodeWithOutput, String>>;
    /// Runs the plaintext checks on `request`.
    fn detect_plaintext(
        &self,
        request: DetectRequest,
    ) -> BoxFuture<'_, Result<DetectOutput, String>>;
}

/// Checks that the argument `name` is at most `limit` characters long.
pub fn check_length(name: &str, value: &str, limit: usize) -> Result<(), String> {
    let chars = value.chars().count();
    if chars > limit {
        return Err(format!(
            "`{name}` is {chars} characters long; the limit is {limit}"
        ));
    }
    Ok(())
}

/// Checks an optional `regex` argument: `None` if it's missing or empty (clients often send
/// "" for an optional argument they don't use), otherwise a valid pattern of at most
/// [`MAX_REGEX_CHARS`] characters.
pub fn check_regex(regex: Option<String>) -> Result<Option<String>, String> {
    let Some(pattern) = regex.filter(|pattern| !pattern.is_empty()) else {
        return Ok(None);
    };
    check_length("regex", &pattern, MAX_REGEX_CHARS)?;
    if let Err(error) = regex::Regex::new(&pattern) {
        return Err(format!(
            "`regex` is not a valid regular expression: {error}"
        ));
    }
    Ok(Some(pattern))
}

/// Arguments of the `decode` tool.
#[derive(Debug, Default, Deserialize, schemars::JsonSchema)]
pub struct DecodeParams {
    /// The encoded or encrypted text to decode (at most 65536 characters).
    #[schemars(length(min = 1, max = MAX_INPUT_CHARS))]
    pub text: String,
    /// Seconds to search before giving up: 1 to 30, default 10.
    #[schemars(range(min = 1, max = MAX_TIMEOUT_SECS))]
    pub timeout_secs: Option<u32>,
    /// A regex or crib the plaintext must match, such as a flag format like `flag\{` (at most
    /// 1000 characters). When set, only text matching it is accepted as plaintext.
    #[schemars(length(max = MAX_REGEX_CHARS))]
    pub regex: Option<String>,
}

impl DecodeParams {
    /// Checks the input limits and fills in defaults. An `Err` tells the caller what to fix.
    pub fn into_request(self) -> Result<CrackRequest, String> {
        if self.text.trim().is_empty() {
            return Err("`text` is empty: pass the encoded text to decode".to_string());
        }
        check_length("text", &self.text, MAX_INPUT_CHARS)?;
        let timeout_secs = self.timeout_secs.unwrap_or(DEFAULT_TIMEOUT_SECS);
        if !(1..=MAX_TIMEOUT_SECS).contains(&timeout_secs) {
            return Err(format!(
                "`timeout_secs` must be between 1 and {MAX_TIMEOUT_SECS}, got {timeout_secs}"
            ));
        }
        Ok(CrackRequest {
            text: self.text,
            timeout_secs,
            regex: check_regex(self.regex)?,
        })
    }
}

/// How a `decode` call ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DecodeStatus {
    /// Plaintext was found.
    Decoded,
    /// The search finished without finding plaintext.
    NotFound,
    /// `timeout_secs` ran out before plaintext was found.
    TimedOut,
}

/// Result of the `decode` tool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DecodeOutput {
    /// `decoded`, `not_found` or `timed_out`.
    pub status: DecodeStatus,
    /// The plaintext, or null if none was found.
    pub plaintext: Option<String>,
    /// Decoders applied to the input, in order. Empty if the input already looked like
    /// plaintext.
    pub path: Vec<DecodeStep>,
    /// The check that accepted the plaintext, such as "English Checker" or "Regex Checker".
    /// Null unless `status` is `decoded`.
    pub checker: Option<String>,
    /// How long the search was allowed to run, in seconds.
    pub timeout_secs: u32,
}

/// One decoder applied on the way to the plaintext.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DecodeStep {
    /// Decoder name, as listed by `list_decoders`.
    pub decoder: String,
    /// The key the decoder used, for keyed ciphers such as the Caesar shift.
    pub key: Option<String>,
}

impl DecodeOutput {
    /// A result without plaintext, for `not_found` and `timed_out`.
    pub fn without_plaintext(status: DecodeStatus, timeout_secs: u32) -> Self {
        Self {
            status,
            plaintext: None,
            path: Vec::new(),
            checker: None,
            timeout_secs,
        }
    }

    /// Converts what [`ciphey::perform_cracking`] returned. Errors other than a timeout become
    /// an `Err` message.
    pub fn from_crack(
        result: Result<Option<DecoderResult>, CipheyError>,
        timeout_secs: u32,
    ) -> Result<Self, String> {
        let decoded = match result {
            Ok(Some(decoded)) => decoded,
            Ok(None) => {
                return Ok(Self::without_plaintext(
                    DecodeStatus::NotFound,
                    timeout_secs,
                ))
            }
            Err(CipheyError::Timeout { .. }) => {
                return Ok(Self::without_plaintext(
                    DecodeStatus::TimedOut,
                    timeout_secs,
                ))
            }
            Err(error) => return Err(error.to_string()),
        };
        let Some(plaintext) = decoded.text.into_iter().next() else {
            return Ok(Self::without_plaintext(
                DecodeStatus::NotFound,
                timeout_secs,
            ));
        };
        // Only report plaintext that one of ciphey's checkers accepted. A decoder that reports
        // success without asking a checker (as `simplesubstitution` did before #1033) would
        // otherwise have its guesses returned as plaintext, even ones that don't match the
        // `regex` crib.
        let Some(checker) = decoded
            .path
            .last()
            .map(|step| step.checker_name)
            .filter(|name| !name.is_empty())
        else {
            return Ok(Self::without_plaintext(
                DecodeStatus::NotFound,
                timeout_secs,
            ));
        };
        // If the input already is plaintext, the library reports one "Default decoder" step.
        let default_decoder = Decoder::<DefaultDecoder>::default().name;
        let path = decoded
            .path
            .iter()
            .filter(|step| step.decoder != default_decoder)
            .map(DecodeStep::from)
            .collect();
        Ok(Self {
            status: DecodeStatus::Decoded,
            plaintext: Some(plaintext),
            path,
            checker: Some(checker.to_string()),
            timeout_secs,
        })
    }
}

impl From<&CrackResult> for DecodeStep {
    fn from(step: &CrackResult) -> Self {
        Self {
            decoder: step.decoder.to_string(),
            key: step.key.clone(),
        }
    }
}

/// Validates `params`, then decodes until done or until `cancelled` completes.
pub async fn run_decode(
    runner: &dyn Runner,
    params: DecodeParams,
    cancelled: impl Future<Output = ()>,
) -> Result<DecodeOutput, String> {
    let request = params.into_request()?;
    until_cancelled(runner.decode(request), cancelled).await
}

/// Validates `params`, then runs the decoder until done or until `cancelled` completes.
pub async fn run_decode_with(
    runner: &dyn Runner,
    params: DecodeWithParams,
    cancelled: impl Future<Output = ()>,
) -> Result<DecodeWithOutput, String> {
    let request = params.into_request()?;
    until_cancelled(runner.decode_with(request), cancelled).await
}

/// Validates `params`, then runs the checks until done or until `cancelled` completes.
pub async fn run_detect(
    runner: &dyn Runner,
    params: DetectParams,
    cancelled: impl Future<Output = ()>,
) -> Result<DetectOutput, String> {
    let request = params.into_request()?;
    until_cancelled(runner.detect_plaintext(request), cancelled).await
}

/// Waits for `work`, unless `cancelled` completes first (the client cancelled the request
/// or went away). Dropping `work` kills its worker.
async fn until_cancelled<T>(
    work: impl Future<Output = Result<T, String>>,
    cancelled: impl Future<Output = ()>,
) -> Result<T, String> {
    tokio::select! {
        result = work => result,
        () = cancelled => Err("the call was cancelled".to_string()),
    }
}

/// The MCP server.
#[derive(Clone)]
pub struct CipheyMcp {
    /// Runs the tool calls that need a worker.
    runner: Arc<dyn Runner>,
}

#[tool_router]
impl CipheyMcp {
    /// Creates a server that runs tool calls with `runner`.
    pub fn new(runner: Arc<dyn Runner>) -> Self {
        Self { runner }
    }

    #[tool(
        title = "Decode text",
        description = "Automatically decode or decrypt text when you don't know how it was \
            encoded. ciphey detects and peels layered encodings (for example Base64, then \
            ROT13, then hex) and breaks classical ciphers without a key (Caesar, Vigenère, rail \
            fence, Atbash, ...). Returns the plaintext and the decoders applied, in order. \
            `status` is `decoded`, `not_found` (the search ended without plaintext) or \
            `timed_out` (retry with a larger `timeout_secs`, or pass a `regex` crib). An empty \
            `path` means the input already looked like plaintext. If you know the encoding or \
            cipher, or have its key, use `decode_with` instead; to check text without decoding \
            it, use `detect_plaintext`.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn decode(
        &self,
        Parameters(params): Parameters<DecodeParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<Json<DecodeOutput>, String> {
        run_decode(self.runner.as_ref(), params, context.ct.cancelled())
            .await
            .map(Json)
    }

    #[tool(
        title = "Decode with a chosen decoder",
        description = "Run one decoder or cipher that you choose by name, instead of searching. \
            Use it when you know or suspect how the text was encoded (\"this is Base32\", \"try \
            ROT47\"), when you have the key (a Vigenère keyword, a Caesar shift, an XOR key, the \
            number of rails), or to see every decoding a decoder gives. Without `key`, encodings \
            are decoded and ciphers cracked by trying every key; with `key`, the text is \
            decrypted with it. Returns the candidate decodings, each with `is_plaintext` \
            (whether ciphey's plaintext checks accept it) and `detection` (what they \
            recognised). `status` is `plaintext_found`, `no_plaintext` (judge the candidates \
            yourself) or `no_candidates` (the text isn't in that decoder's format). It decodes \
            one layer: for layered or unknown encodings use `decode`. Call `list_decoders` for \
            the decoder ids, aliases and key formats.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn decode_with(
        &self,
        Parameters(params): Parameters<DecodeWithParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<Json<DecodeWithOutput>, String> {
        run_decode_with(self.runner.as_ref(), params, context.ct.cancelled())
            .await
            .map(Json)
    }

    #[tool(
        title = "Detect plaintext",
        description = "Check whether text is already plaintext, and identify what it is, \
            without decoding anything. Runs ciphey's plaintext checks: LemmeKnow, which \
            recognises over 100 formats (IP and email addresses, URLs, API keys and tokens, \
            crypto wallets, credit card numbers, CTF flags, ...), a list of common passwords, \
            and an English checker. Returns `is_plaintext` and the `detection`: which `checker` \
            accepted the text, its `description` (such as `Internet Protocol (IP) Address \
            Version 4` or `Words` for English) and, for LemmeKnow, a `confidence` from 0 to 1. \
            Use it to check a decoding, to choose between candidates, or to see whether text \
            needs decoding at all.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn detect_plaintext(
        &self,
        Parameters(params): Parameters<DetectParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<Json<DetectOutput>, String> {
        run_detect(self.runner.as_ref(), params, context.ct.cancelled())
            .await
            .map(Json)
    }

    #[tool(
        title = "List decoders",
        description = "List the encodings and ciphers ciphey can decode, with a short \
            description of each, the `id` and aliases `decode_with` accepts, and the key format \
            of the ciphers that take a key.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    fn list_decoders(&self) -> Json<DecoderList> {
        Json(DecoderList::all())
    }
}

#[tool_handler(
    name = "ciphey",
    instructions = "ciphey decodes encoded or encrypted text. Call `decode` with the ciphertext \
        when you don't know how it was encoded: it searches chains of decoders by itself. If \
        you know (or want to try) a particular encoding or cipher, or have its key, call \
        `decode_with`; `list_decoders` lists the decoder ids, aliases and key formats. Call \
        `detect_plaintext` to check whether text is already plaintext and what it is \
        (English, an IP address, a URL, an API key, ...). If you know part of the plaintext, \
        such as a CTF flag format like `flag\\{`, pass it as `regex`."
)]
impl ServerHandler for CipheyMcp {}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use ciphey::decoders::base64_decoder::Base64Decoder;
    use ciphey::decoders::caesar_decoder::CaesarDecoder;
    use ciphey::decoders::interface::Crack;
    use ciphey::decoders::substitution_generic_decoder::SubstitutionGenericDecoder;
    use serde_json::{json, Value};

    use super::*;
    use crate::decode_with::DecodeWithStatus;
    use crate::detect::SensitivityChoice;
    use crate::worker::Job;

    /// Returns canned responses and records the calls it was given.
    #[derive(Default)]
    struct FakeRunner {
        decode: Option<Result<DecodeOutput, String>>,
        decode_with: Option<Result<DecodeWithOutput, String>>,
        detect: Option<Result<DetectOutput, String>>,
        jobs: Mutex<Vec<Job>>,
    }

    impl FakeRunner {
        fn decoding(response: Result<DecodeOutput, String>) -> Self {
            Self {
                decode: Some(response),
                ..Self::default()
            }
        }

        fn jobs(&self) -> Vec<Job> {
            self.jobs.lock().unwrap().clone()
        }

        /// Records `job` and returns `response`, which the test must have set.
        fn respond<T: Clone + Send + 'static>(
            &self,
            job: Job,
            response: &Option<Result<T, String>>,
        ) -> BoxFuture<'_, Result<T, String>> {
            self.jobs.lock().unwrap().push(job);
            let response = response.clone().expect("unexpected call");
            Box::pin(async move { response })
        }
    }

    impl Runner for FakeRunner {
        fn decode(&self, request: CrackRequest) -> BoxFuture<'_, Result<DecodeOutput, String>> {
            self.respond(Job::Decode(request), &self.decode)
        }

        fn decode_with(
            &self,
            request: DecodeWithRequest,
        ) -> BoxFuture<'_, Result<DecodeWithOutput, String>> {
            self.respond(Job::DecodeWith(request), &self.decode_with)
        }

        fn detect_plaintext(
            &self,
            request: DetectRequest,
        ) -> BoxFuture<'_, Result<DetectOutput, String>> {
            self.respond(Job::DetectPlaintext(request), &self.detect)
        }
    }

    /// Never finishes, like a long search.
    struct StuckRunner;

    impl Runner for StuckRunner {
        fn decode(&self, _: CrackRequest) -> BoxFuture<'_, Result<DecodeOutput, String>> {
            Box::pin(std::future::pending())
        }

        fn decode_with(
            &self,
            _: DecodeWithRequest,
        ) -> BoxFuture<'_, Result<DecodeWithOutput, String>> {
            Box::pin(std::future::pending())
        }

        fn detect_plaintext(
            &self,
            _: DetectRequest,
        ) -> BoxFuture<'_, Result<DetectOutput, String>> {
            Box::pin(std::future::pending())
        }
    }

    fn params(text: &str) -> DecodeParams {
        DecodeParams {
            text: text.to_string(),
            ..DecodeParams::default()
        }
    }

    fn decoded(plaintext: &str) -> DecodeOutput {
        DecodeOutput {
            status: DecodeStatus::Decoded,
            plaintext: Some(plaintext.to_string()),
            path: vec![DecodeStep {
                decoder: "Base64".to_string(),
                key: None,
            }],
            checker: Some("English Checker".to_string()),
            timeout_secs: DEFAULT_TIMEOUT_SECS,
        }
    }

    #[test]
    fn into_request_applies_defaults() {
        let request = params("aGVsbG8=").into_request().unwrap();
        assert_eq!(
            request,
            CrackRequest {
                text: "aGVsbG8=".to_string(),
                timeout_secs: DEFAULT_TIMEOUT_SECS,
                regex: None,
            }
        );
    }

    #[test]
    fn into_request_keeps_timeout_and_regex() {
        let request = DecodeParams {
            timeout_secs: Some(MAX_TIMEOUT_SECS),
            regex: Some(r"flag\{".to_string()),
            ..params("aGVsbG8=")
        }
        .into_request()
        .unwrap();
        assert_eq!(request.timeout_secs, MAX_TIMEOUT_SECS);
        assert_eq!(request.regex.as_deref(), Some(r"flag\{"));
    }

    #[test]
    fn into_request_rejects_empty_text() {
        for text in ["", "  \n\t"] {
            let error = params(text).into_request().unwrap_err();
            assert!(error.contains("`text` is empty"), "{error}");
        }
    }

    #[test]
    fn into_request_limits_text_length_in_characters() {
        // Multi-byte characters count once, matching the schema's maxLength.
        assert!(params(&"é".repeat(MAX_INPUT_CHARS)).into_request().is_ok());
        let error = params(&"é".repeat(MAX_INPUT_CHARS + 1))
            .into_request()
            .unwrap_err();
        assert!(error.contains("the limit is 65536"), "{error}");
    }

    #[test]
    fn into_request_limits_timeout() {
        for timeout_secs in [1, MAX_TIMEOUT_SECS] {
            let request = DecodeParams {
                timeout_secs: Some(timeout_secs),
                ..params("aGVsbG8=")
            };
            assert!(request.into_request().is_ok(), "{timeout_secs}");
        }
        for timeout_secs in [0, MAX_TIMEOUT_SECS + 1, u32::MAX] {
            let request = DecodeParams {
                timeout_secs: Some(timeout_secs),
                ..params("aGVsbG8=")
            };
            let error = request.into_request().unwrap_err();
            assert!(
                error.contains("`timeout_secs` must be between 1 and 30"),
                "{error}"
            );
        }
    }

    #[test]
    fn into_request_rejects_invalid_regex() {
        let error = DecodeParams {
            regex: Some("(unclosed".to_string()),
            ..params("aGVsbG8=")
        }
        .into_request()
        .unwrap_err();
        assert!(error.contains("not a valid regular expression"), "{error}");
    }

    #[test]
    fn into_request_limits_regex_length() {
        let at_limit = DecodeParams {
            regex: Some("a".repeat(MAX_REGEX_CHARS)),
            ..params("aGVsbG8=")
        };
        assert!(at_limit.into_request().is_ok());
        let error = DecodeParams {
            regex: Some("a".repeat(MAX_REGEX_CHARS + 1)),
            ..params("aGVsbG8=")
        }
        .into_request()
        .unwrap_err();
        assert!(
            error.contains("`regex` is 1001 characters long; the limit is 1000"),
            "{error}"
        );
    }

    #[test]
    fn into_request_ignores_empty_regex() {
        let request = DecodeParams {
            regex: Some(String::new()),
            ..params("aGVsbG8=")
        };
        assert_eq!(request.into_request().unwrap().regex, None);
    }

    #[tokio::test]
    async fn decode_forwards_the_request_and_returns_the_result() {
        let runner = FakeRunner::decoding(Ok(decoded("hello")));
        let params = DecodeParams {
            timeout_secs: Some(3),
            regex: Some("^h.*o$".to_string()),
            ..params("aGVsbG8=")
        };

        let output = run_decode(&runner, params, std::future::pending()).await;

        assert_eq!(output, Ok(decoded("hello")));
        assert_eq!(
            runner.jobs(),
            vec![Job::Decode(CrackRequest {
                text: "aGVsbG8=".to_string(),
                timeout_secs: 3,
                regex: Some("^h.*o$".to_string()),
            })]
        );
    }

    #[tokio::test]
    async fn decode_rejects_bad_input_without_cracking() {
        let runner = FakeRunner::decoding(Ok(decoded("unused")));

        let output = run_decode(&runner, params(""), std::future::pending()).await;

        assert!(output.unwrap_err().contains("`text` is empty"));
        assert!(runner.jobs().is_empty());
    }

    #[tokio::test]
    async fn decode_passes_on_runner_errors() {
        let runner = FakeRunner::decoding(Err("worker crashed".to_string()));

        let output = run_decode(&runner, params("aGVsbG8="), std::future::pending()).await;

        assert_eq!(output, Err("worker crashed".to_string()));
    }

    #[tokio::test]
    async fn calls_stop_when_cancelled() {
        let cancelled = || std::future::ready(());
        let cancelled_message = "the call was cancelled";

        let output = run_decode(&StuckRunner, params("aGVsbG8="), cancelled()).await;
        assert_eq!(output.unwrap_err(), cancelled_message);

        let decode_with = DecodeWithParams {
            decoder: "base64".to_string(),
            text: "aGk=".to_string(),
            ..DecodeWithParams::default()
        };
        let output = run_decode_with(&StuckRunner, decode_with, cancelled()).await;
        assert_eq!(output.unwrap_err(), cancelled_message);

        let detect = DetectParams {
            text: "hi".to_string(),
            ..DetectParams::default()
        };
        let output = run_detect(&StuckRunner, detect, cancelled()).await;
        assert_eq!(output.unwrap_err(), cancelled_message);
    }

    #[tokio::test]
    async fn decode_with_forwards_the_resolved_decoder() {
        let response = DecodeWithOutput {
            decoder: "caesar".to_string(),
            status: DecodeWithStatus::NoCandidates,
            candidates: Vec::new(),
            total_candidates: 0,
        };
        let runner = FakeRunner {
            decode_with: Some(Ok(response.clone())),
            ..FakeRunner::default()
        };
        let params = DecodeWithParams {
            decoder: "ROT13".to_string(),
            text: "Uryyb".to_string(),
            key: Some("13".to_string()),
            regex: Some(String::new()),
        };

        let output = run_decode_with(&runner, params, std::future::pending()).await;

        assert_eq!(output, Ok(response));
        assert_eq!(
            runner.jobs(),
            vec![Job::DecodeWith(DecodeWithRequest {
                decoder: "caesar".to_string(),
                text: "Uryyb".to_string(),
                key: Some("13".to_string()),
                regex: None,
            })]
        );

        // Bad arguments never reach a worker.
        let unknown = DecodeWithParams {
            decoder: "rot1300".to_string(),
            text: "Uryyb".to_string(),
            ..DecodeWithParams::default()
        };
        let error = run_decode_with(&runner, unknown, std::future::pending())
            .await
            .unwrap_err();
        assert!(error.starts_with("no decoder is called"), "{error}");
        assert_eq!(runner.jobs().len(), 1);
    }

    #[tokio::test]
    async fn detect_forwards_the_request() {
        let response = DetectOutput {
            is_plaintext: false,
            detection: None,
            checkers: vec!["english".to_string()],
        };
        let runner = FakeRunner {
            detect: Some(Ok(response.clone())),
            ..FakeRunner::default()
        };
        let params = DetectParams {
            text: "192.168.0.1".to_string(),
            checkers: Some(vec![crate::detect::CheckerChoice::English]),
            sensitivity: Some(SensitivityChoice::Low),
            regex: None,
        };

        let output = run_detect(&runner, params, std::future::pending()).await;

        assert_eq!(output, Ok(response));
        assert_eq!(
            runner.jobs(),
            vec![Job::DetectPlaintext(DetectRequest {
                text: "192.168.0.1".to_string(),
                checkers: Some(vec![crate::detect::CheckerChoice::English]),
                sensitivity: SensitivityChoice::Low,
                regex: None,
            })]
        );
    }

    #[test]
    fn from_crack_reports_plaintext_path_and_checker() {
        let mut base64 = CrackResult::new(&Decoder::<Base64Decoder>::new(), "x".to_string());
        base64.checker_name = "";
        let mut caesar = CrackResult::new(&Decoder::<CaesarDecoder>::new(), "y".to_string());
        caesar.key = Some("13".to_string());
        caesar.checker_name = "English Checker";
        let result = DecoderResult {
            text: vec!["hello world".to_string()],
            path: vec![base64, caesar],
        };

        let output = DecodeOutput::from_crack(Ok(Some(result)), 7).unwrap();

        assert_eq!(
            output,
            DecodeOutput {
                status: DecodeStatus::Decoded,
                plaintext: Some("hello world".to_string()),
                path: vec![
                    DecodeStep {
                        decoder: "Base64".to_string(),
                        key: None,
                    },
                    DecodeStep {
                        decoder: "caesar".to_string(),
                        key: Some("13".to_string()),
                    },
                ],
                checker: Some("English Checker".to_string()),
                timeout_secs: 7,
            }
        );
    }

    #[test]
    fn from_crack_reports_input_that_already_is_plaintext() {
        let mut step = CrackResult::new(&Decoder::<DefaultDecoder>::default(), "hi".to_string());
        step.checker_name = "LemmeKnow Checker";
        let result = DecoderResult {
            text: vec!["192.168.0.1".to_string()],
            path: vec![step],
        };

        let output = DecodeOutput::from_crack(Ok(Some(result)), 5).unwrap();

        assert_eq!(output.status, DecodeStatus::Decoded);
        assert_eq!(output.plaintext.as_deref(), Some("192.168.0.1"));
        assert!(output.path.is_empty());
        assert_eq!(output.checker.as_deref(), Some("LemmeKnow Checker"));
    }

    #[test]
    fn from_crack_ignores_results_no_checker_accepted() {
        // What `simplesubstitution` returned before #1033: success, but no checker involved.
        let step = CrackResult::new(
            &Decoder::<SubstitutionGenericDecoder>::new(),
            "aaaa".to_string(),
        );
        let result = DecoderResult {
            text: vec!["E T".to_string()],
            path: vec![step],
        };

        assert_eq!(
            DecodeOutput::from_crack(Ok(Some(result)), 5),
            Ok(DecodeOutput::without_plaintext(DecodeStatus::NotFound, 5))
        );
    }

    #[test]
    fn from_crack_reports_not_found_and_timeouts() {
        assert_eq!(
            DecodeOutput::from_crack(Ok(None), 5),
            Ok(DecodeOutput::without_plaintext(DecodeStatus::NotFound, 5))
        );
        assert_eq!(
            DecodeOutput::from_crack(Err(CipheyError::Timeout { secs: 5 }), 5),
            Ok(DecodeOutput::without_plaintext(DecodeStatus::TimedOut, 5))
        );
    }

    #[test]
    fn from_crack_turns_other_errors_into_messages() {
        // Deliberately invalid, to get a `regex::Error`.
        #[allow(clippy::invalid_regex)]
        let regex_error = regex::Regex::new("(").unwrap_err();
        let error =
            DecodeOutput::from_crack(Err(CipheyError::InvalidRegex(regex_error)), 5).unwrap_err();
        assert!(error.starts_with("invalid regex"), "{error}");
    }

    #[test]
    fn decode_output_serializes_with_snake_case_status() {
        let output = DecodeOutput::without_plaintext(DecodeStatus::TimedOut, 5);
        assert_eq!(
            serde_json::to_value(&output).unwrap(),
            json!({
                "status": "timed_out",
                "plaintext": null,
                "path": [],
                "checker": null,
                "timeout_secs": 5,
            })
        );
    }

    #[test]
    fn list_decoders_lists_the_library_api() {
        let server = CipheyMcp::new(Arc::new(StuckRunner));

        let Json(list) = server.list_decoders();

        assert_eq!(list.decoders.len(), ciphey::list_decoders().len());
        let ids: Vec<&str> = list.decoders.iter().map(|d| d.id.as_str()).collect();
        for expected in ["base64", "caesar", "vigenere", "morse", "brainfuck"] {
            assert!(ids.contains(&expected), "{expected} missing from {ids:?}");
        }
    }

    /// The advertised tools, by name.
    fn tools() -> Vec<rmcp::model::Tool> {
        let mut tools = CipheyMcp::tool_router().list_all();
        tools.sort_by(|a, b| a.name.cmp(&b.name));
        tools
    }

    /// The input schema of the tool called `name`.
    fn input_schema(name: &str) -> Value {
        let tool = tools().into_iter().find(|tool| tool.name == name).unwrap();
        Value::Object((*tool.input_schema).clone())
    }

    #[test]
    fn tools_are_advertised_with_schemas_and_annotations() {
        let tools = tools();
        let names: Vec<&str> = tools.iter().map(|tool| tool.name.as_ref()).collect();
        assert_eq!(
            names,
            ["decode", "decode_with", "detect_plaintext", "list_decoders"]
        );

        for tool in &tools {
            let annotations = tool.annotations.as_ref().expect("annotations");
            assert_eq!(annotations.read_only_hint, Some(true), "{}", tool.name);
            assert_eq!(annotations.open_world_hint, Some(false), "{}", tool.name);
            assert!(tool.output_schema.is_some(), "{}", tool.name);
            let description = tool.description.as_deref().unwrap_or_default();
            assert!(description.len() > 80, "{}: {description}", tool.name);
        }

        let decode = input_schema("decode");
        assert_eq!(decode["required"], json!(["text"]));
        assert_eq!(
            decode["properties"]["text"]["maxLength"],
            json!(MAX_INPUT_CHARS)
        );
        assert_eq!(
            decode["properties"]["timeout_secs"]["maximum"],
            json!(MAX_TIMEOUT_SECS)
        );
        assert_eq!(
            decode["properties"]["regex"]["maxLength"],
            json!(MAX_REGEX_CHARS)
        );
    }

    #[test]
    fn decode_with_schema_describes_its_arguments() {
        let schema = input_schema("decode_with");
        assert_eq!(schema["required"], json!(["decoder", "text"]));
        let properties = &schema["properties"];
        assert_eq!(properties["text"]["maxLength"], json!(MAX_INPUT_CHARS));
        assert_eq!(properties["decoder"]["minLength"], json!(1));
        assert_eq!(properties["key"]["type"], json!(["string", "null"]));
        assert_eq!(properties["regex"]["maxLength"], json!(MAX_REGEX_CHARS));
        for argument in ["decoder", "text", "key", "regex"] {
            let description = properties[argument]["description"].as_str().unwrap();
            assert!(!description.is_empty(), "{argument}");
        }
        assert!(properties["key"]["description"]
            .as_str()
            .unwrap()
            .contains("key_format"));
    }

    #[test]
    fn detect_plaintext_schema_lists_the_checkers() {
        let schema = input_schema("detect_plaintext");
        assert_eq!(schema["required"], json!(["text"]));
        let properties = &schema["properties"];
        // Plain enums, inlined: no `$ref` or `oneOf` for clients to resolve.
        let items = &properties["checkers"]["items"];
        assert_eq!(items["type"], json!("string"));
        assert_eq!(items["enum"], json!(["lemmeknow", "password", "english"]));
        assert_eq!(
            properties["sensitivity"]["enum"],
            json!(["low", "medium", "high", null])
        );
        assert!(schema.get("$defs").is_none(), "{schema}");
    }
}
