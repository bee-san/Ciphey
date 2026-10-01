//! The MCP tools (`decode`, `list_decoders`), their input limits and their result types.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use ciphey::decoders::crack_results::CrackResult;
use ciphey::decoders::interface::{Decoder, DefaultDecoder};
use ciphey::decoders::{DecoderType, DECODER_MAP};
use ciphey::{CipheyError, DecoderResult};
use rmcp::handler::server::wrapper::{Json, Parameters};
use rmcp::service::RequestContext;
use rmcp::{schemars, tool, tool_handler, tool_router, RoleServer, ServerHandler, ServiceExt};
use serde::{Deserialize, Serialize};

use crate::worker::{CrackRequest, ProcessCracker};

/// Longest `text` that `decode` accepts, in characters.
pub const MAX_INPUT_CHARS: usize = 65_536;
/// `timeout_secs` used when the caller doesn't pass one.
pub const DEFAULT_TIMEOUT_SECS: u32 = 10;
/// Largest `timeout_secs` that `decode` accepts. Leaves headroom under the ~60 s tool-call
/// timeout that many MCP clients apply.
pub const MAX_TIMEOUT_SECS: u32 = 30;
/// Resident memory a decode may use before it is stopped. A search that finds nothing grows
/// until its timeout: a few kilobytes of input can otherwise reach several gigabytes.
pub const MAX_MEMORY_BYTES: u64 = 1 << 30;

/// Runs the MCP server on stdin/stdout until the client disconnects.
pub fn serve_stdio() -> Result<(), Box<dyn std::error::Error>> {
    let server = CipheyMcp::new(Arc::new(ProcessCracker::for_current_exe()?));
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

/// A boxed future that can move between threads, as returned by [`Cracker::crack`].
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Runs a validated decode request to completion.
///
/// The server uses [`ProcessCracker`], which runs every request in a worker process. Tests
/// substitute fakes.
pub trait Cracker: Send + Sync + 'static {
    /// Decodes `request`. An `Err` is a message for the caller and becomes a tool error.
    fn crack(&self, request: CrackRequest) -> BoxFuture<'_, Result<DecodeOutput, String>>;
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
    /// A regex or crib the plaintext must match, such as a flag format like `flag\{`. When set,
    /// only text matching it is accepted as plaintext.
    pub regex: Option<String>,
}

impl DecodeParams {
    /// Checks the input limits and fills in defaults. An `Err` tells the caller what to fix.
    pub fn into_request(self) -> Result<CrackRequest, String> {
        if self.text.trim().is_empty() {
            return Err("`text` is empty: pass the encoded text to decode".to_string());
        }
        let chars = self.text.chars().count();
        if chars > MAX_INPUT_CHARS {
            return Err(format!(
                "`text` is {chars} characters long; the limit is {MAX_INPUT_CHARS}"
            ));
        }
        let timeout_secs = self.timeout_secs.unwrap_or(DEFAULT_TIMEOUT_SECS);
        if !(1..=MAX_TIMEOUT_SECS).contains(&timeout_secs) {
            return Err(format!(
                "`timeout_secs` must be between 1 and {MAX_TIMEOUT_SECS}, got {timeout_secs}"
            ));
        }
        // Clients often send "" for an optional argument they don't use.
        let regex = self.regex.filter(|pattern| !pattern.is_empty());
        if let Some(pattern) = &regex {
            if let Err(error) = regex::Regex::new(pattern) {
                return Err(format!(
                    "`regex` is not a valid regular expression: {error}"
                ));
            }
        }
        Ok(CrackRequest {
            text: self.text,
            timeout_secs,
            regex,
            max_memory_bytes: MAX_MEMORY_BYTES,
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

/// Result of the `list_decoders` tool.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DecoderList {
    /// Every decoder ciphey tries, sorted by name.
    pub decoders: Vec<DecoderInfo>,
}

/// A decoder ciphey can apply.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DecoderInfo {
    /// Name, as used in `decode` paths.
    pub name: String,
    /// What the decoder handles.
    pub description: String,
    /// Where to read more.
    pub link: String,
    /// Categories such as `base` or `cipher`.
    pub tags: Vec<String>,
}

impl DecoderList {
    /// Every decoder in the library's registry.
    pub fn all() -> Self {
        let default_decoder = Decoder::<DefaultDecoder>::default().name;
        let mut decoders: Vec<DecoderInfo> = DECODER_MAP
            .values()
            .map(|entry| entry.get::<DecoderType>())
            .filter(|decoder| decoder.get_name() != default_decoder)
            .map(|decoder| DecoderInfo {
                name: decoder.get_name().to_string(),
                description: decoder.get_description().to_string(),
                link: decoder.get_link().to_string(),
                tags: decoder
                    .get_tags()
                    .iter()
                    .map(|tag| tag.to_string())
                    .collect(),
            })
            .collect();
        decoders.sort_by_key(|decoder| decoder.name.to_lowercase());
        Self { decoders }
    }
}

/// Validates `params`, then decodes until done or until `cancelled` completes (the client
/// cancelled the request or went away). Dropping the decode future kills its worker.
pub async fn run_decode(
    cracker: &dyn Cracker,
    params: DecodeParams,
    cancelled: impl Future<Output = ()>,
) -> Result<DecodeOutput, String> {
    let request = params.into_request()?;
    tokio::select! {
        result = cracker.crack(request) => result,
        () = cancelled => Err("the decode was cancelled".to_string()),
    }
}

/// The MCP server.
#[derive(Clone)]
pub struct CipheyMcp {
    /// Runs `decode` requests.
    cracker: Arc<dyn Cracker>,
}

#[tool_router]
impl CipheyMcp {
    /// Creates a server that runs decodes with `cracker`.
    pub fn new(cracker: Arc<dyn Cracker>) -> Self {
        Self { cracker }
    }

    #[tool(
        title = "Decode text",
        description = "Automatically decode or decrypt text without knowing how it was encoded. \
            ciphey detects and peels layered encodings (for example Base64, then ROT13, then \
            hex) and breaks classical ciphers without a key (Caesar, Vigenère, rail fence, \
            Atbash, ...). Returns the plaintext and the decoders applied, in order. `status` is \
            `decoded`, `not_found` (the search ended without plaintext) or `timed_out` (retry \
            with a larger `timeout_secs`, or pass a `regex` crib). An empty `path` means the \
            input already looked like plaintext.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn decode(
        &self,
        Parameters(params): Parameters<DecodeParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<Json<DecodeOutput>, String> {
        run_decode(self.cracker.as_ref(), params, context.ct.cancelled())
            .await
            .map(Json)
    }

    #[tool(
        title = "List decoders",
        description = "List the encodings and ciphers ciphey can decode, with a short \
            description of each.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    fn list_decoders(&self) -> Json<DecoderList> {
        Json(DecoderList::all())
    }
}

#[tool_handler(
    name = "ciphey",
    instructions = "ciphey decodes encoded or encrypted text automatically: call `decode` with \
        the ciphertext. If you know part of the plaintext, such as a CTF flag format like \
        `flag\\{`, pass it as `regex`. Call `list_decoders` to see the supported encodings and \
        ciphers."
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

    /// Returns a canned response and records the requests it was given.
    struct FakeCracker {
        response: Result<DecodeOutput, String>,
        requests: Mutex<Vec<CrackRequest>>,
    }

    impl FakeCracker {
        fn new(response: Result<DecodeOutput, String>) -> Self {
            Self {
                response,
                requests: Mutex::new(Vec::new()),
            }
        }

        fn requests(&self) -> Vec<CrackRequest> {
            self.requests.lock().unwrap().clone()
        }
    }

    impl Cracker for FakeCracker {
        fn crack(&self, request: CrackRequest) -> BoxFuture<'_, Result<DecodeOutput, String>> {
            self.requests.lock().unwrap().push(request);
            let response = self.response.clone();
            Box::pin(async move { response })
        }
    }

    /// Never finishes, like a long search.
    struct StuckCracker;

    impl Cracker for StuckCracker {
        fn crack(&self, _: CrackRequest) -> BoxFuture<'_, Result<DecodeOutput, String>> {
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
                max_memory_bytes: MAX_MEMORY_BYTES,
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
    fn into_request_ignores_empty_regex() {
        let request = DecodeParams {
            regex: Some(String::new()),
            ..params("aGVsbG8=")
        };
        assert_eq!(request.into_request().unwrap().regex, None);
    }

    #[tokio::test]
    async fn decode_forwards_the_request_and_returns_the_result() {
        let cracker = FakeCracker::new(Ok(decoded("hello")));
        let params = DecodeParams {
            timeout_secs: Some(3),
            regex: Some("^h.*o$".to_string()),
            ..params("aGVsbG8=")
        };

        let output = run_decode(&cracker, params, std::future::pending()).await;

        assert_eq!(output, Ok(decoded("hello")));
        assert_eq!(
            cracker.requests(),
            vec![CrackRequest {
                text: "aGVsbG8=".to_string(),
                timeout_secs: 3,
                regex: Some("^h.*o$".to_string()),
                max_memory_bytes: MAX_MEMORY_BYTES,
            }]
        );
    }

    #[tokio::test]
    async fn decode_rejects_bad_input_without_cracking() {
        let cracker = FakeCracker::new(Ok(decoded("unused")));

        let output = run_decode(&cracker, params(""), std::future::pending()).await;

        assert!(output.unwrap_err().contains("`text` is empty"));
        assert!(cracker.requests().is_empty());
    }

    #[tokio::test]
    async fn decode_passes_on_cracker_errors() {
        let cracker = FakeCracker::new(Err("worker crashed".to_string()));

        let output = run_decode(&cracker, params("aGVsbG8="), std::future::pending()).await;

        assert_eq!(output, Err("worker crashed".to_string()));
    }

    #[tokio::test]
    async fn decode_stops_when_cancelled() {
        let output = run_decode(&StuckCracker, params("aGVsbG8="), std::future::ready(())).await;

        assert_eq!(output, Err("the decode was cancelled".to_string()));
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
    fn list_decoders_lists_the_registry() {
        let server = CipheyMcp::new(Arc::new(StuckCracker));

        let Json(list) = server.list_decoders();

        let names: Vec<&str> = list.decoders.iter().map(|d| d.name.as_str()).collect();
        // Everything in the registry except the placeholder "Default decoder".
        assert_eq!(names.len(), DECODER_MAP.len() - 1);
        assert!(!names.contains(&"Default decoder"));
        for expected in ["Base64", "caesar", "Vigenere", "Morse Code", "Brainfuck"] {
            assert!(
                names.contains(&expected),
                "{expected} missing from {names:?}"
            );
        }
        let mut sorted = names.clone();
        sorted.sort_by_key(|name| name.to_lowercase());
        assert_eq!(names, sorted);
        assert!(list.decoders.iter().all(|d| !d.description.is_empty()));
    }

    #[test]
    fn tools_are_advertised_with_schemas_and_annotations() {
        let tools = CipheyMcp::tool_router().list_all();
        let mut names: Vec<&str> = tools.iter().map(|tool| tool.name.as_ref()).collect();
        names.sort_unstable();
        assert_eq!(names, ["decode", "list_decoders"]);

        for tool in &tools {
            let annotations = tool.annotations.as_ref().expect("annotations");
            assert_eq!(annotations.read_only_hint, Some(true), "{}", tool.name);
            assert_eq!(annotations.open_world_hint, Some(false), "{}", tool.name);
            assert!(tool.output_schema.is_some(), "{}", tool.name);
        }

        let decode = tools.iter().find(|tool| tool.name == "decode").unwrap();
        let input = Value::Object((*decode.input_schema).clone());
        assert_eq!(input["required"], json!(["text"]));
        assert_eq!(
            input["properties"]["text"]["maxLength"],
            json!(MAX_INPUT_CHARS)
        );
        assert_eq!(
            input["properties"]["timeout_secs"]["maximum"],
            json!(MAX_TIMEOUT_SECS)
        );
        assert!(input["properties"]["regex"].is_object());
    }
}
