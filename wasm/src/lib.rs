//! Ciphey in the browser: the JavaScript API of the ciphey library, for WebAssembly.
//!
//! Build it with wasm-bindgen into a JavaScript package. `docs/wasm.md` has the commands,
//! the API and an example for a Web Worker:
//!
//! - `new Search(input, options)` and `search.step(budgetMs)` run the search a step at a
//!   time and report the search tree as it grows, so a page can show it live;
//! - `decode(input, options)` runs a whole search and returns its answer;
//! - `listDecoders()` lists the decoders;
//! - `detectPlaintext(text, options)` says whether a text is plaintext, and what it is;
//! - `cipheyVersion()` is the library's version.
//!
//! The JavaScript names don't collide with those of pyWhat's and gibberish-or-not's
//! WebAssembly bindings (`identify`, `tags`, `version`, `detect`, `score`, ...), so one
//! module can link all three.
//!
//! Every function here works on plain Rust values ([`JsSearchOptions`] in,
//! [`JsSearchProgress`] and the like out), and only the `#[wasm_bindgen]` wrappers convert
//! them to and from JavaScript, so the conversions are tested natively too.

use std::time::Duration;

use ciphey::detection::{CheckerKind, DetectOptions, Detection, Sensitivity};
use ciphey::search::{
    PathStep, Progress, Search, SearchNode, SearchOptions, SearchResult, SearchState,
};
use ciphey::{detect_plaintext, list_decoders as decoders, DecoderInfo};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(typescript_custom_section)]
const TYPES: &'static str = r#"
/** Where a search is. */
export type SearchStatus = "running" | "decoded" | "not_found" | "timed_out";

/** How readily the English checker takes text for English: "low" is the strictest. */
export type EnglishSensitivity = "low" | "medium" | "high";

/** A plaintext checker, by id. */
export type CheckerId = "regex" | "wordlist" | "lemmeknow" | "json" | "password" | "english" | "code" | "jwt_structure";

/** Options for `new Search` and `decode`. Every field is optional. */
export interface SearchOptions {
  /** How long the search may run, in seconds, counted from `new Search`. Default 5. */
  timeout?: number;
  /** The same in milliseconds. Give one of `timeout` and `timeoutMs`. */
  timeoutMs?: number;
  /** A crib: only text this regular expression (Rust syntax) matches is plaintext, and the other checkers are off. */
  regex?: string;
  /** Keep searching after the first plaintext, until the timeout or the end, and report every one. Default false. */
  topResults?: boolean;
  /** The English checker's sensitivity, for the input and the decoders that don't choose (the ciphers do). Default "medium". */
  sensitivity?: EnglishSensitivity;
  /** How many characters (code points) of each node's text `SearchNode.text` keeps. Default 120. */
  previewChars?: number;
}

/** One decoder in the path from the input to a result. */
export interface PathStep {
  /** The decoder's name, as in `listDecoders()`, such as "Base64" or "caesar". */
  decoder: string;
  /** The key it decoded with, such as "13" for a Caesar shift, or null. */
  key: string | null;
  /** The checker that accepted the decoder's output as plaintext. Only the last step has one. */
  checker: CheckerId | null;
  /** That checker's name, such as "English Checker". */
  checkerName: string | null;
  /** What it took the output for, such as "Words". */
  description: string | null;
  /** For pyWhat's formats, how sure it is, from 0 to 1. */
  confidence: number | null;
}

/** Plaintext a search found. */
export interface SearchResult {
  plaintext: string;
  /** The decoders that turned the input into the plaintext, in order. Empty if the input was already plaintext. */
  path: PathStep[];
  /** The checker that accepted the plaintext. */
  checker: CheckerId | null;
  /** Its name, such as "English Checker", "LemmeKnow Checker" or "Regex Checker". */
  checkerName: string | null;
  /** What it took the plaintext for, such as "Words" or "Internet Protocol (IP) Address Version 4". */
  description: string | null;
  /** For pyWhat's formats, how sure the checker is, from 0 to 1, else null. */
  confidence: number | null;
  /** When it was found, in milliseconds since `new Search`. */
  elapsedMs: number;
  /** The id of the node it was decoded from, the end of the winning branch. null if the input was plaintext. */
  nodeId: number | null;
}

/**
 * A node of the search tree that the search expanded: a text the decoders made from the
 * input. The input is node 0; every other node's `parent` is the node it was decoded
 * from, which was expanded, and reported, before it.
 */
export interface SearchNode {
  id: number;
  parent: number | null;
  /** How many decoders turned the input into this text. */
  depth: number;
  /** The decoder that made this text from its parent's, null for the input. */
  decoder: string | null;
  key: string | null;
  /** The start of the text, at most `previewChars` characters (code points: an emoji is one, though its JavaScript `length` is 2). */
  text: string;
  /** How many characters (code points) the whole text has. */
  length: number;
  /** The search's priority for the node (f = g + h): it expands the lowest first. */
  cost: number;
  /** How many children expanding it queued. */
  children: number;
}

/** What one `search.step()` did. */
export interface SearchProgress {
  status: SearchStatus;
  /** Milliseconds since `new Search`. */
  elapsedMs: number;
  /** Nodes expanded so far. */
  expanded: number;
  /** Nodes waiting to be expanded. */
  queued: number;
  /** Texts the search has seen: it doesn't queue a text twice. */
  seen: number;
  /** The number of decoders in the deepest node expanded so far. */
  depth: number;
  /** The nodes this step expanded, in order. */
  nodes: SearchNode[];
  /** The plaintexts this step found: more than one only with `topResults`. */
  results: SearchResult[];
  /** The search's first plaintext, from this step or an earlier one, or null. */
  result: SearchResult | null;
}

/** A decoder, as `listDecoders()` lists it. */
export interface DecoderInfo {
  name: string;
  /** Its name in the Rust library, such as "base64". */
  id: string;
  aliases: string[];
  tags: string[];
  description: string;
  link: string;
  /** The key it can decrypt with and how to write it, or null if it takes none. */
  keyFormat: string | null;
}

/** Options for `detectPlaintext`. Every field is optional. */
export interface DetectOptions {
  /** The checkers to run, in Ciphey's order. Default: lemmeknow, json, password, english, code. */
  checkers?: CheckerId[];
  /** The English checker's sensitivity. Default "medium". */
  sensitivity?: EnglishSensitivity;
  /** A crib: only text this regular expression matches is plaintext, and the other checkers are off. */
  regex?: string;
}

/** What a checker took a text for. */
export interface PlaintextDetection {
  checker: CheckerId;
  checkerName: string;
  description: string;
  /** For pyWhat's formats, how sure the checker is, from 0 to 1, else null. */
  confidence: number | null;
}
"#;

/// Logs a panic's message to the console before the module aborts. Without it a panic
/// only shows as "RuntimeError: unreachable". Every entry point installs it, rather than a
/// `#[wasm_bindgen(start)]` function, so this module can share a bundle with other
/// bindings that have their own.
fn install_panic_hook() {
    #[cfg(target_family = "wasm")]
    {
        static INSTALLED: std::sync::Once = std::sync::Once::new();
        INSTALLED.call_once(|| {
            std::panic::set_hook(Box::new(|info| console_error(&format!("ciphey: {info}"))));
        });
    }
}

#[cfg(target_family = "wasm")]
#[wasm_bindgen]
extern "C" {
    /// `console.error`
    #[wasm_bindgen(js_namespace = console, js_name = error)]
    fn console_error(message: &str);
}

#[wasm_bindgen]
extern "C" {
    /// The options of `new Search` and `decode`, as JavaScript passes them
    #[wasm_bindgen(typescript_type = "SearchOptions")]
    pub type SearchOptionsArg;

    /// The options of `detectPlaintext`, as JavaScript passes them
    #[wasm_bindgen(typescript_type = "DetectOptions")]
    pub type DetectOptionsArg;
}

/// The version of the ciphey library in this module, such as "0.12.1".
#[wasm_bindgen(js_name = cipheyVersion)]
pub fn ciphey_version() -> String {
    ciphey::VERSION.to_string()
}

/// Searches for the plaintext of `input` to the end and returns the first plaintext it
/// found, or null if it found none (nothing left to try, or the timeout). It blocks until
/// then, up to the timeout, so call it in a Web Worker, or use `Search`.
///
/// # Errors
///
/// Throws if the options aren't valid: an unknown field, a negative timeout, a regex that
/// doesn't compile.
#[wasm_bindgen(unchecked_return_type = "SearchResult | null")]
pub fn decode(input: &str, options: Option<SearchOptionsArg>) -> Result<JsValue, JsError> {
    install_panic_hook();
    to_js(&decode_with_options(
        input,
        from_js(options.map(JsValue::from))?,
    )?)
}

/// A search for the plaintext of one input, run a step at a time.
#[wasm_bindgen(js_name = Search)]
pub struct JsSearch {
    /// The search
    search: Search,
}

#[wasm_bindgen(js_class = Search)]
impl JsSearch {
    /// A search for the plaintext of `input`. Nothing is searched until `step`; the
    /// timeout counts from here.
    ///
    /// # Errors
    ///
    /// Throws if the options aren't valid.
    #[wasm_bindgen(constructor)]
    pub fn new(input: &str, options: Option<SearchOptionsArg>) -> Result<JsSearch, JsError> {
        install_panic_hook();
        let options = search_options(from_js(options.map(JsValue::from))?)?;
        Ok(JsSearch {
            search: Search::new(input, options).map_err(Error::from)?,
        })
    }

    /// Searches for about `budgetMs` milliseconds and reports what it did. A step can run
    /// longer: it ends between two batches of up to ten nodes, and one batch can take a
    /// while on long text. `Infinity` runs it to its end. Once the search is over, it
    /// returns at once.
    ///
    /// # Errors
    ///
    /// Throws if `budgetMs` is negative or not a number.
    #[wasm_bindgen(unchecked_return_type = "SearchProgress")]
    pub fn step(
        &mut self,
        #[wasm_bindgen(js_name = budgetMs)] budget_ms: f64,
    ) -> Result<JsValue, JsError> {
        let budget = if budget_ms == f64::INFINITY {
            Duration::MAX
        } else {
            millis(budget_ms, "budgetMs")?
        };
        let progress = self.search.step(budget);
        to_js(&JsSearchProgress::new(&self.search, progress))
    }

    /// Where the search is.
    #[wasm_bindgen(getter, unchecked_return_type = "SearchStatus")]
    pub fn status(&self) -> String {
        status(self.search.state()).to_string()
    }

    /// The plaintexts found so far, in order.
    ///
    /// # Errors
    ///
    /// Only if a result can't be converted to JavaScript.
    #[wasm_bindgen(unchecked_return_type = "SearchResult[]")]
    pub fn results(&self) -> Result<JsValue, JsError> {
        let results: Vec<JsSearchResult> = self
            .search
            .results()
            .iter()
            .map(JsSearchResult::from)
            .collect();
        to_js(&results)
    }
}

/// Every decoder Ciphey has.
///
/// # Errors
///
/// Only if the list can't be converted to JavaScript.
#[wasm_bindgen(js_name = listDecoders, unchecked_return_type = "DecoderInfo[]")]
pub fn list_decoders() -> Result<JsValue, JsError> {
    install_panic_hook();
    to_js(&decoder_list())
}

/// Runs Ciphey's plaintext checkers on `text` and returns what the first one that accepts
/// it took it for, or null.
///
/// # Errors
///
/// Throws if the options aren't valid: an unknown checker or field, a regex that doesn't
/// compile.
#[wasm_bindgen(js_name = detectPlaintext, unchecked_return_type = "PlaintextDetection | null")]
pub fn detect_plaintext_js(
    text: &str,
    options: Option<DetectOptionsArg>,
) -> Result<JsValue, JsError> {
    install_panic_hook();
    to_js(&detect_with_options(
        text,
        from_js(options.map(JsValue::from))?,
    )?)
}

/// The options of `new Search` and `decode`, as JavaScript passes them.
#[derive(Debug, Default, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields, default)]
pub struct JsSearchOptions {
    /// `timeout`, in seconds
    pub timeout: Option<f64>,
    /// `timeoutMs`
    pub timeout_ms: Option<f64>,
    /// `regex`
    pub regex: Option<String>,
    /// `topResults`
    pub top_results: Option<bool>,
    /// `sensitivity`
    pub sensitivity: Option<Sensitivity>,
    /// `previewChars`
    pub preview_chars: Option<usize>,
}

/// The options of `detectPlaintext`, as JavaScript passes them.
#[derive(Debug, Default, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields, default)]
pub struct JsDetectOptions {
    /// `checkers`
    pub checkers: Option<Vec<String>>,
    /// `sensitivity`
    pub sensitivity: Option<Sensitivity>,
    /// `regex`
    pub regex: Option<String>,
}

/// A `PathStep`, as JavaScript gets it.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct JsPathStep {
    /// `decoder`
    pub decoder: &'static str,
    /// `key`
    pub key: Option<String>,
    /// `checker`
    pub checker: Option<&'static str>,
    /// `checkerName`
    pub checker_name: Option<&'static str>,
    /// `description`
    pub description: Option<String>,
    /// `confidence`
    pub confidence: Option<f32>,
}

impl JsPathStep {
    /// `step`, with `detection` if it is the last step of a result.
    fn new(step: &PathStep, detection: Option<&Detection>) -> Self {
        JsPathStep {
            decoder: step.decoder,
            key: step.key.clone(),
            checker: step.checker.map(CheckerKind::id),
            checker_name: step.checker.map(CheckerKind::name),
            description: detection.map(|d| d.description.clone()),
            confidence: detection.and_then(|d| d.confidence),
        }
    }
}

/// A `SearchResult`, as JavaScript gets it.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct JsSearchResult {
    /// `plaintext`
    pub plaintext: String,
    /// `path`
    pub path: Vec<JsPathStep>,
    /// `checker`
    pub checker: Option<&'static str>,
    /// `checkerName`
    pub checker_name: Option<&'static str>,
    /// `description`
    pub description: Option<String>,
    /// `confidence`
    pub confidence: Option<f32>,
    /// `elapsedMs`
    pub elapsed_ms: f64,
    /// `nodeId`
    pub node_id: Option<u64>,
}

impl From<&SearchResult> for JsSearchResult {
    fn from(result: &SearchResult) -> Self {
        let detection = result.detection.as_ref();
        let last = result.path.len().saturating_sub(1);
        JsSearchResult {
            plaintext: result.plaintext.clone(),
            path: result
                .path
                .iter()
                .enumerate()
                .map(|(i, step)| JsPathStep::new(step, detection.filter(|_| i == last)))
                .collect(),
            checker: detection.map(|d| d.checker.id()),
            checker_name: detection.map(|d| d.checker.name()),
            description: detection.map(|d| d.description.clone()),
            confidence: detection.and_then(|d| d.confidence),
            elapsed_ms: as_millis(result.elapsed),
            node_id: result.node_id,
        }
    }
}

/// A `SearchNode`, as JavaScript gets it.
#[derive(Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct JsSearchNode {
    /// `id`
    pub id: u64,
    /// `parent`
    pub parent: Option<u64>,
    /// `depth`
    pub depth: u32,
    /// `decoder`
    pub decoder: Option<&'static str>,
    /// `key`
    pub key: Option<String>,
    /// `text`
    pub text: String,
    /// `length`
    pub length: usize,
    /// `cost`
    pub cost: f32,
    /// `children`
    pub children: usize,
}

impl From<SearchNode> for JsSearchNode {
    fn from(node: SearchNode) -> Self {
        JsSearchNode {
            id: node.id,
            parent: node.parent,
            depth: node.depth,
            decoder: node.decoder,
            key: node.key,
            text: node.text,
            length: node.text_chars,
            // JSON has no infinities; a node's cost is always finite, but be safe
            cost: if node.cost.is_finite() {
                node.cost
            } else {
                f32::MAX
            },
            children: node.children,
        }
    }
}

/// A `Progress`, as JavaScript gets it.
#[derive(Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct JsSearchProgress {
    /// `status`
    pub status: &'static str,
    /// `elapsedMs`
    pub elapsed_ms: f64,
    /// `expanded`
    pub expanded: usize,
    /// `queued`
    pub queued: usize,
    /// `seen`
    pub seen: usize,
    /// `depth`
    pub depth: u32,
    /// `nodes`
    pub nodes: Vec<JsSearchNode>,
    /// `results`
    pub results: Vec<JsSearchResult>,
    /// `result`
    pub result: Option<JsSearchResult>,
}

impl JsSearchProgress {
    /// What `search` reports after the step that returned `progress`.
    fn new(search: &Search, progress: Progress) -> Self {
        JsSearchProgress {
            status: status(progress.state),
            elapsed_ms: as_millis(progress.elapsed),
            expanded: progress.nodes_expanded,
            queued: progress.nodes_queued,
            seen: progress.nodes_seen,
            depth: progress.depth,
            nodes: progress
                .expanded
                .into_iter()
                .map(JsSearchNode::from)
                .collect(),
            results: progress.found.iter().map(JsSearchResult::from).collect(),
            result: search.result().map(JsSearchResult::from),
        }
    }
}

/// A `DecoderInfo`, as JavaScript gets it.
#[derive(Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct JsDecoderInfo {
    /// `name`
    pub name: &'static str,
    /// `id`
    pub id: &'static str,
    /// `aliases`
    pub aliases: &'static [&'static str],
    /// `tags`
    pub tags: Vec<&'static str>,
    /// `description`
    pub description: &'static str,
    /// `link`
    pub link: &'static str,
    /// `keyFormat`
    pub key_format: Option<&'static str>,
}

impl From<&DecoderInfo> for JsDecoderInfo {
    fn from(info: &DecoderInfo) -> Self {
        JsDecoderInfo {
            name: info.name,
            id: info.function,
            aliases: info.aliases,
            tags: info.tags.clone(),
            description: info.description,
            link: info.link,
            key_format: info.key_format,
        }
    }
}

/// A `Detection`, as JavaScript gets it.
#[derive(Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct JsPlaintextDetection {
    /// `checker`
    pub checker: &'static str,
    /// `checkerName`
    pub checker_name: &'static str,
    /// `description`
    pub description: String,
    /// `confidence`
    pub confidence: Option<f32>,
}

impl From<Detection> for JsPlaintextDetection {
    fn from(detection: Detection) -> Self {
        JsPlaintextDetection {
            checker: detection.checker.id(),
            checker_name: detection.checker.name(),
            description: detection.description,
            confidence: detection.confidence,
        }
    }
}

/// `decode`, on Rust values.
///
/// # Errors
///
/// If the options aren't valid.
pub fn decode_with_options(
    input: &str,
    options: JsSearchOptions,
) -> Result<Option<JsSearchResult>, Error> {
    let mut search = Search::new(input, search_options(options)?)?;
    while search.state() == SearchState::Running {
        search.step(Duration::MAX);
    }
    Ok(search.result().map(JsSearchResult::from))
}

/// `detectPlaintext`, on Rust values.
///
/// # Errors
///
/// If the options aren't valid.
pub fn detect_with_options(
    text: &str,
    options: JsDetectOptions,
) -> Result<Option<JsPlaintextDetection>, Error> {
    let mut detect = DetectOptions::new();
    if let Some(checkers) = options.checkers {
        let checkers = checkers
            .iter()
            .map(|id| id.parse::<CheckerKind>())
            .collect::<Result<Vec<_>, _>>()?;
        detect = detect.checkers(checkers);
    }
    if let Some(sensitivity) = options.sensitivity {
        detect = detect.sensitivity(sensitivity);
    }
    if let Some(regex) = options.regex {
        detect = detect.regex(&regex)?;
    }
    Ok(detect_plaintext(text, &detect).map(JsPlaintextDetection::from))
}

/// `listDecoders`, on Rust values.
pub fn decoder_list() -> Vec<JsDecoderInfo> {
    decoders().iter().map(JsDecoderInfo::from).collect()
}

/// The [`SearchOptions`] `options` asks for.
///
/// # Errors
///
/// If both `timeout` and `timeoutMs` are given, the timeout isn't a number of seconds or
/// milliseconds, or the regex doesn't compile.
pub fn search_options(options: JsSearchOptions) -> Result<SearchOptions, Error> {
    let mut search = SearchOptions::new().top_results(options.top_results.unwrap_or(false));
    let timeout = match (options.timeout, options.timeout_ms) {
        (Some(_), Some(_)) => {
            return Err(Error(
                "give timeout (seconds) or timeoutMs (milliseconds), not both".to_string(),
            ))
        }
        (Some(secs), None) => Some(millis(secs * 1000.0, "timeout")?),
        (None, Some(ms)) => Some(millis(ms, "timeoutMs")?),
        (None, None) => None,
    };
    if let Some(timeout) = timeout {
        search = search.timeout(timeout);
    }
    if let Some(regex) = options.regex {
        search = search.regex(&regex)?;
    }
    if let Some(sensitivity) = options.sensitivity {
        search = search.sensitivity(sensitivity);
    }
    if let Some(chars) = options.preview_chars {
        search = search.preview_chars(chars);
    }
    Ok(search)
}

/// `ms` milliseconds, which JavaScript passed as `name`.
fn millis(ms: f64, name: &str) -> Result<Duration, Error> {
    Duration::try_from_secs_f64(ms / 1000.0)
        .map_err(|_| Error(format!("{name}: {ms} isn't a number of milliseconds")))
}

/// `duration` in milliseconds.
fn as_millis(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}

/// The JavaScript name of `state`.
fn status(state: SearchState) -> &'static str {
    match state {
        SearchState::Running => "running",
        SearchState::Found => "decoded",
        SearchState::Exhausted => "not_found",
        SearchState::TimedOut => "timed_out",
        _ => "unknown",
    }
}

/// Why options or arguments from JavaScript were rejected. It becomes the message of the
/// `Error` thrown in JavaScript.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(pub String);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

impl From<ciphey::CipheyError> for Error {
    fn from(error: ciphey::CipheyError) -> Self {
        Error(error.to_string())
    }
}

/// `value` as a JavaScript value, through JSON: objects for structs, `null` for `None`.
fn to_js<T: Serialize>(value: &T) -> Result<JsValue, JsError> {
    let json = serde_json::to_string(value).map_err(|e| JsError::new(&e.to_string()))?;
    js_sys::JSON::parse(&json).map_err(|_| JsError::new("couldn't make a JavaScript value"))
}

/// The options JavaScript passed, through JSON (`JSON.stringify`), so that unknown fields
/// are errors: `undefined` and `null` are the defaults.
///
/// Only a plain object is options: an array, a `Map` or a number throws. So does a field
/// that is `NaN` or ±`Infinity`, which `JSON.stringify` would turn into `null`, the
/// default.
fn from_js<T: for<'de> Deserialize<'de> + Default>(value: Option<JsValue>) -> Result<T, JsError> {
    let Some(value) = value.filter(|value| !value.is_undefined() && !value.is_null()) else {
        return Ok(T::default());
    };
    if !is_plain_object(&value) {
        return Err(JsError::new("options: not a plain object"));
    }
    for entry in js_sys::Object::entries(value.unchecked_ref()).iter() {
        let entry: js_sys::Array = entry.unchecked_into();
        if entry.get(1).as_f64().is_some_and(|n| !n.is_finite()) {
            let field = entry.get(0).as_string().unwrap_or_default();
            return Err(JsError::new(&format!(
                "options: {field} isn't a finite number"
            )));
        }
    }
    let json =
        js_sys::JSON::stringify(&value).map_err(|_| JsError::new("options: not a plain object"))?;
    serde_json::from_str(&String::from(json)).map_err(|e| JsError::new(&format!("options: {e}")))
}

/// Whether `value` is a plain object, `{...}`: its prototype is null or an object without
/// a prototype of its own, `Object.prototype` of any realm.
fn is_plain_object(value: &JsValue) -> bool {
    if !value.is_object() || js_sys::Array::is_array(value) || value.is_function() {
        return false;
    }
    let prototype = js_sys::Object::get_prototype_of(value);
    prototype.is_null() || js_sys::Object::get_prototype_of(&prototype).is_null()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_returns_the_answer_with_its_path() {
        let found = decode_with_options(
            "NTA3NjYzNzU3MjZjMjA3NjY2MjA2OTcyNjU2YzIwNzM2ZTY2Njc=",
            JsSearchOptions {
                timeout: Some(30.0),
                ..JsSearchOptions::default()
            },
        )
        .unwrap()
        .expect("decoded");
        assert_eq!(found.plaintext, "Ciphey is very fast");
        let path: Vec<&str> = found.path.iter().map(|step| step.decoder).collect();
        assert_eq!(path, ["Base64", "Hexadecimal", "caesar"]);
        assert_eq!(found.path[2].key.as_deref(), Some("13"));
        assert_eq!(found.path[2].checker, Some("english"));
        assert_eq!(found.path[2].checker_name, Some("English Checker"));
        assert_eq!(found.path[2].description.as_deref(), Some("Words"));
        assert!(found.path[..2]
            .iter()
            .all(|step| step.checker.is_none() && step.description.is_none()));
        assert_eq!(found.checker, Some("english"));
        assert_eq!(found.description.as_deref(), Some("Words"));
        assert!(found.node_id.is_some());

        // The JSON JavaScript gets
        let json = serde_json::to_value(&found).unwrap();
        assert_eq!(json["path"][0]["key"], serde_json::Value::Null);
        assert_eq!(json["checkerName"], "English Checker");
        assert!(json["elapsedMs"].is_number() && json["nodeId"].is_number());

        // Nothing to decode
        assert!(decode_with_options("", JsSearchOptions::default())
            .unwrap()
            .is_none());
    }

    #[test]
    fn options_are_checked() {
        let options: JsSearchOptions = serde_json::from_str(
            r#"{"timeoutMs": 1500, "regex": "^flag", "topResults": true, "sensitivity": "low", "previewChars": 40}"#,
        )
        .unwrap();
        let search = search_options(options).unwrap();
        assert_eq!(search.timeout, Duration::from_millis(1500));
        assert_eq!(search.regex.as_deref(), Some("^flag"));
        assert!(search.top_results);
        assert_eq!(search.sensitivity, Sensitivity::Low);
        assert_eq!(search.preview_chars, 40);

        let seconds: JsSearchOptions = serde_json::from_str(r#"{"timeout": 2.5}"#).unwrap();
        assert_eq!(
            search_options(seconds).unwrap().timeout,
            Duration::from_millis(2500)
        );
        let both: JsSearchOptions =
            serde_json::from_str(r#"{"timeout": 2, "timeoutMs": 2000}"#).unwrap();
        assert!(search_options(both).is_err());

        assert!(serde_json::from_str::<JsSearchOptions>(r#"{"timout": 5}"#).is_err()); // codespell:ignore timout
        assert!(serde_json::from_str::<JsSearchOptions>(r#"{"sensitivity": "max"}"#).is_err());
        for bad in [-1.0, f64::NAN, f64::INFINITY] {
            let options = JsSearchOptions {
                timeout_ms: Some(bad),
                ..JsSearchOptions::default()
            };
            assert!(search_options(options).is_err(), "{bad}");
        }
        let options = JsSearchOptions {
            regex: Some("(unclosed".to_string()),
            ..JsSearchOptions::default()
        };
        let error = search_options(options).unwrap_err();
        assert!(error.0.contains("regex"), "{error}");
    }

    #[test]
    fn progress_reports_the_tree() {
        let mut search = Search::new(
            "aGVsbG8gdGhlcmUgZ2VuZXJhbA==",
            SearchOptions::new().timeout(Duration::from_secs(30)),
        )
        .unwrap();
        let mut nodes = Vec::new();
        let mut last = None;
        while search.state() == SearchState::Running {
            let step = search.step(Duration::ZERO);
            let progress = JsSearchProgress::new(&search, step);
            nodes.extend(progress.nodes.iter().map(|node| (node.id, node.parent)));
            last = Some(progress);
        }
        let last = last.unwrap();
        assert_eq!(last.status, "decoded");
        let result = last.result.clone().expect("the answer");
        assert_eq!(result.plaintext, "hello there general");
        assert_eq!(last.results, std::slice::from_ref(&result));
        assert_eq!(nodes[0], (0, None));
        assert!(nodes.iter().any(|&(id, _)| Some(id) == result.node_id));
        let json = serde_json::to_value(&last).unwrap();
        for field in [
            "status",
            "elapsedMs",
            "expanded",
            "queued",
            "seen",
            "depth",
            "nodes",
            "results",
            "result",
        ] {
            assert!(json.get(field).is_some(), "{field}");
        }
    }

    #[test]
    fn detect_plaintext_names_what_it_found() {
        let found = detect_with_options("192.168.0.1", JsDetectOptions::default())
            .unwrap()
            .unwrap();
        assert_eq!(found.checker, "lemmeknow");
        assert_eq!(found.checker_name, "LemmeKnow Checker");
        assert_eq!(
            found.description,
            "Internet Protocol (IP) Address Version 4"
        );
        assert_eq!(found.confidence, Some(0.7));

        let english_only = JsDetectOptions {
            checkers: Some(vec!["english".to_string()]),
            ..JsDetectOptions::default()
        };
        assert!(detect_with_options("192.168.0.1", english_only)
            .unwrap()
            .is_none());

        let unknown = JsDetectOptions {
            checkers: Some(vec!["nope".to_string()]),
            ..JsDetectOptions::default()
        };
        assert!(detect_with_options("hello", unknown).is_err());
    }

    #[test]
    fn decoders_are_listed_with_their_ids() {
        let list = decoder_list();
        let base64 = list.iter().find(|d| d.name == "Base64").unwrap();
        assert_eq!(base64.id, "base64");
        assert!(base64.aliases.contains(&"b64"));
        let caesar = list.iter().find(|d| d.id == "caesar").unwrap();
        assert!(caesar.key_format.is_some());
    }
}
