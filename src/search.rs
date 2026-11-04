//! Ciphey's search, a step at a time.
//!
//! [`perform_cracking`](crate::perform_cracking) runs a whole search and returns when it
//! ends. A [`Search`] runs the same search in steps. [`Search::step`] works for about as
//! long as it is given, then reports what the search expanded and found meanwhile, so a
//! caller can show the search as it goes, or give up, between steps. A web page runs it
//! this way in a Web Worker (`docs/wasm.md`). Each search has its own [`SearchOptions`],
//! unlike `perform_cracking`, whose config is set once for the process.
//!
//! ```
//! use std::time::Duration;
//! use ciphey::search::{Search, SearchOptions, SearchState};
//!
//! let mut search = Search::new("aGVsbG8gdGhlcmUgZ2VuZXJhbA==", SearchOptions::default())?;
//! while search.state() == SearchState::Running {
//!     let progress = search.step(Duration::from_millis(50));
//!     for node in &progress.expanded {
//!         // node.path holds the decoders that turned the input into node.text
//!     }
//! }
//! let found = search.result().expect("the Base64 should be decoded");
//! assert_eq!(found.plaintext, "hello there general");
//! assert_eq!(found.path[0].decoder, "Base64");
//! # Ok::<(), ciphey::CipheyError>(())
//! ```
//!
//! A search never asks a human, uses no cache and prints nothing.
//!
//! While a search runs, the library's checkers read the config made from its options.
//! Run one search at a time, or several with the same options. Interleaving the steps of
//! several searches on one thread is fine, because each step puts its own options back in
//! place. [`perform_cracking`](crate::perform_cracking) goes back to the global config.

use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::clock::{Deadline, Instant};
use crate::config::{self, Config, SearchConfig};
use crate::detection::{self, CheckerKind, Detection, Sensitivity};
use crate::searchers::astar::{AStar, StepEnd};
use crate::{CipheyError, CrackResult, DecoderResult};

/// How much of a node's text [`SearchNode::text`] keeps, in characters.
pub const NODE_TEXT_CHARS: usize = 256;

/// Options for one [`Search`].
///
/// ```
/// use std::time::Duration;
/// use ciphey::detection::Sensitivity;
/// use ciphey::search::SearchOptions;
///
/// let options = SearchOptions::new()
///     .timeout(Duration::from_secs(10))
///     .regex(r"flag\{")?
///     .top_results(true)
///     .sensitivity(Sensitivity::Low);
/// # Ok::<(), ciphey::CipheyError>(())
/// ```
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct SearchOptions {
    /// How long the search may run, counted from [`Search::new`]. 5 seconds by default,
    /// like `ciphey`.
    pub timeout: Duration,
    /// A crib: only text this regular expression matches is plaintext, and the other
    /// checkers are off, like `ciphey --regex`. None by default.
    pub regex: Option<String>,
    /// Keep searching after the first plaintext, until the timeout or until there is
    /// nothing left to search, and report every plaintext found, like
    /// `ciphey --top-results`. Off by default.
    pub top_results: bool,
    /// How strict the English checker is, for the decoders that don't choose for
    /// themselves (the ciphers do), and for the input itself. Medium by default.
    pub sensitivity: Sensitivity,
}

impl Default for SearchOptions {
    fn default() -> Self {
        SearchOptions {
            timeout: Duration::from_secs(5),
            regex: None,
            top_results: false,
            sensitivity: Sensitivity::Medium,
        }
    }
}

impl SearchOptions {
    /// The default options.
    pub fn new() -> Self {
        SearchOptions::default()
    }

    /// Sets [`SearchOptions::timeout`].
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Sets [`SearchOptions::regex`].
    ///
    /// # Errors
    ///
    /// [`CipheyError::InvalidRegex`] if `pattern` doesn't compile.
    pub fn regex(mut self, pattern: &str) -> Result<Self, CipheyError> {
        regex::Regex::new(pattern).map_err(CipheyError::InvalidRegex)?;
        self.regex = Some(pattern.to_string());
        Ok(self)
    }

    /// Sets [`SearchOptions::top_results`].
    pub fn top_results(mut self, top_results: bool) -> Self {
        self.top_results = top_results;
        self
    }

    /// Sets [`SearchOptions::sensitivity`].
    pub fn sensitivity(mut self, sensitivity: Sensitivity) -> Self {
        self.sensitivity = sensitivity;
        self
    }
}

/// Where a [`Search`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SearchState {
    /// There is more to search: call [`Search::step`].
    Running,
    /// The search is over and found plaintext: [`Search::results`]. Without `top_results`
    /// it ends at the first plaintext.
    Found,
    /// The search is over: there was nothing left to try, and nothing was plaintext.
    Exhausted,
    /// The search is over: the timeout passed before any plaintext was found.
    TimedOut,
}

/// One decoder in the path from the input to a text.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct PathStep {
    /// The decoder's name, as in [`DecoderInfo::name`](crate::DecoderInfo::name), such
    /// as `Base64` or `caesar`.
    pub decoder: &'static str,
    /// The key it decoded with, such as `13` for a Caesar shift, if it takes one.
    pub key: Option<String>,
    /// The checker that accepted the decoder's output as plaintext, if one did. Only the
    /// last step of a result has one.
    pub checker: Option<CheckerKind>,
}

impl PathStep {
    /// The step that `result` describes.
    fn new(result: &CrackResult) -> Self {
        PathStep {
            decoder: result.decoder,
            key: result.key.clone(),
            checker: if result.success {
                CheckerKind::from_name(result.checker_name)
            } else {
                None
            },
        }
    }
}

/// A node of the search tree that [`Search::step`] expanded: a text the decoders made from
/// the input, which every decoder then ran on.
///
/// Nodes form a tree by their paths: a node's parent is the node whose path is its path
/// without the last step. The input itself has an empty path.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct SearchNode {
    /// The decoders that turned the input into this text, in order.
    pub path: Vec<PathStep>,
    /// The text, cut to its first [`NODE_TEXT_CHARS`] characters.
    pub text: String,
    /// How many characters the whole text has.
    pub text_chars: usize,
    /// The A* search's cost of the path to this node: the lower it is, the more
    /// promising the search found it. It grows with the path.
    pub cost: f32,
}

impl SearchNode {
    /// The node at `state`, with path cost `cost`.
    fn new(state: &DecoderResult, cost: f32) -> Self {
        let text = state.text.first().map(String::as_str).unwrap_or_default();
        SearchNode {
            path: state.path.iter().map(PathStep::new).collect(),
            text: text.chars().take(NODE_TEXT_CHARS).collect(),
            text_chars: text.chars().count(),
            cost,
        }
    }
}

/// Plaintext that a [`Search`] found.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct SearchResult {
    /// The plaintext.
    pub plaintext: String,
    /// The decoders that turned the input into the plaintext, in order. Empty if the input
    /// was already plaintext.
    pub path: Vec<PathStep>,
    /// What the checker that accepted the plaintext took it for, and for pyWhat's formats,
    /// how sure it is (`confidence`).
    pub detection: Option<Detection>,
    /// How long after [`Search::new`] it was found.
    pub elapsed: Duration,
    /// How many nodes the search had expanded by then.
    pub nodes_expanded: usize,
}

/// What one [`Search::step`] did.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct Progress {
    /// Where the search is now.
    pub state: SearchState,
    /// The nodes this step expanded, in order.
    pub expanded: Vec<SearchNode>,
    /// The plaintexts this step found, in order. More than one only with `top_results`.
    pub found: Vec<SearchResult>,
    /// How many nodes the search has expanded so far.
    pub nodes_expanded: usize,
    /// How many nodes are waiting to be expanded.
    pub nodes_queued: usize,
    /// The depth of the deepest node expanded so far: the number of decoders in its path.
    pub depth: u32,
    /// How long the search has run, counted from [`Search::new`].
    pub elapsed: Duration,
}

/// Where a [`Search`] is in its work.
enum Phase {
    /// The input hasn't been checked yet.
    Start(String),
    /// The A* search is running.
    Searching(AStar),
    /// The search is over.
    Done,
}

/// Ciphey's search for the plaintext of one input, run a step at a time. See the
/// [module documentation](self).
pub struct Search {
    /// The config the checkers read while this search runs
    config: &'static SearchConfig,
    /// What it is doing
    phase: Phase,
    /// The English checker's sensitivity
    sensitivity: gibberish_or_not::Sensitivity,
    /// When it started
    started: Instant,
    /// When it times out
    deadline: Deadline,
    /// Where it is
    state: SearchState,
    /// What it found
    results: Vec<SearchResult>,
    /// How many nodes it expanded, how many are queued, and the deepest node's depth
    counts: (usize, usize, u32),
    /// Set by the A* search once it found its result
    stop: Arc<AtomicBool>,
}

impl Search {
    /// A search for the plaintext of `input`. Nothing is searched until
    /// [`Search::step`]. The timeout counts from here.
    ///
    /// # Errors
    ///
    /// [`CipheyError::InvalidRegex`] if `options.regex` doesn't compile.
    pub fn new(input: &str, options: SearchOptions) -> Result<Search, CipheyError> {
        let config = search_config(&options)?;
        config::use_search_config(config);
        // The decoders' statistics, which the search's edge costs use, start empty, so
        // the search explores like a new `ciphey` process
        crate::reset_decoder_stats();
        if options.top_results {
            crate::storage::wait_athena_storage::clear_plaintext_results();
        }
        Ok(Search {
            config,
            phase: Phase::Start(input.to_string()),
            sensitivity: options.sensitivity.into(),
            started: Instant::now(),
            deadline: Deadline::after(options.timeout),
            state: SearchState::Running,
            results: Vec::new(),
            counts: (0, 0, 0),
            stop: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Searches for about `budget`, then reports what it did.
    ///
    /// The search expands its tree up to ten nodes at a time, and this returns once
    /// `budget` has passed after one of those batches, so a step can run longer than
    /// `budget`: as long as the slowest batch (Playfair's cracker allows itself 1.5 s), or
    /// until the timeout, which the search checks before every decoder. The first step
    /// also checks whether the input is already plaintext. Once the search is over, this
    /// returns at once.
    pub fn step(&mut self, budget: Duration) -> Progress {
        let mut expanded = Vec::new();
        let first_new_result = self.results.len();
        if self.state == SearchState::Running {
            config::use_search_config(self.config);
            let step_ends = Deadline::after(budget);
            self.search_until(step_ends, &mut expanded);
        }
        self.progress(expanded, first_new_result)
    }

    /// Steps until the search is over, and returns its first result.
    ///
    /// # Errors
    ///
    /// [`CipheyError::Timeout`] if the timeout passes before any plaintext is found.
    pub fn run(mut self) -> Result<Option<SearchResult>, CipheyError> {
        while self.state == SearchState::Running {
            self.step(Duration::MAX);
        }
        match self.state {
            SearchState::TimedOut => Err(CipheyError::Timeout {
                secs: self.config.config.timeout,
            }),
            _ => Ok(self.results.into_iter().next()),
        }
    }

    /// Where the search is.
    pub fn state(&self) -> SearchState {
        self.state
    }

    /// The plaintexts found so far, in the order they were found.
    pub fn results(&self) -> &[SearchResult] {
        &self.results
    }

    /// The first plaintext found, if any.
    pub fn result(&self) -> Option<&SearchResult> {
        self.results.first()
    }

    /// How long the search has run, counted from [`Search::new`].
    pub fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }

    /// Searches until `step_ends`, the search's own deadline or its end, recording the
    /// nodes it expands in `expanded`.
    fn search_until(&mut self, step_ends: Deadline, expanded: &mut Vec<SearchNode>) {
        if let Phase::Start(_) = self.phase {
            let Phase::Start(input) = std::mem::replace(&mut self.phase, Phase::Done) else {
                unreachable!("the phase was just matched");
            };
            if self.check_input(&input) {
                return;
            }
            self.phase = Phase::Searching(AStar::new(input, self.sensitivity));
        }
        let Phase::Searching(astar) = &mut self.phase else {
            return;
        };
        loop {
            let mut found = Vec::new();
            let mut send = |result: Option<DecoderResult>| found.extend(result);
            let mut watch = |state: &DecoderResult, _depth: u32, cost: f32| {
                expanded.push(SearchNode::new(state, cost));
            };
            let end = astar.step(&self.stop, self.deadline, &mut send, Some(&mut watch));
            let nodes_expanded = astar.expanded_nodes();
            self.counts = (nodes_expanded, astar.queued_nodes(), astar.depth());
            for result in found {
                let elapsed = self.started.elapsed();
                self.results
                    .push(search_result(result, elapsed, nodes_expanded));
            }
            let over = match end {
                // The deadline may have passed during the batch: the next step says so
                StepEnd::Running if self.deadline.has_passed() => continue,
                StepEnd::Running if step_ends.has_passed() => return,
                StepEnd::Running => continue,
                StepEnd::Found => SearchState::Found,
                StepEnd::Exhausted => SearchState::Exhausted,
                StepEnd::Stopped => SearchState::TimedOut,
            };
            self.finish(over);
            return;
        }
    }

    /// Checks the input itself, as `perform_cracking` does, and ends the search if it is
    /// already plaintext. Returns whether it was.
    fn check_input(&mut self, input: &str) -> bool {
        let check = crate::check_input(input, self.sensitivity);
        if !check.is_identified {
            return false;
        }
        let detection = detection::from_check_result(check, input);
        self.results.push(SearchResult {
            plaintext: input.to_string(),
            path: Vec::new(),
            detection,
            elapsed: self.started.elapsed(),
            nodes_expanded: 0,
        });
        self.finish(SearchState::Found);
        true
    }

    /// Ends the search. A search that found plaintext is [`SearchState::Found`], whatever
    /// ended it (in `top_results` mode the timeout or running out of nodes does).
    fn finish(&mut self, state: SearchState) {
        self.state = if self.results.is_empty() {
            state
        } else {
            SearchState::Found
        };
        self.phase = Phase::Done;
        // Nothing is queued any more
        self.counts.1 = 0;
    }

    /// The [`Progress`] after a step that expanded `expanded` and found the results from
    /// `first_new_result` on.
    fn progress(&self, expanded: Vec<SearchNode>, first_new_result: usize) -> Progress {
        let (nodes_expanded, nodes_queued, depth) = self.counts;
        Progress {
            state: self.state,
            expanded,
            found: self.results[first_new_result..].to_vec(),
            nodes_expanded,
            nodes_queued,
            depth,
            elapsed: self.started.elapsed(),
        }
    }
}

/// The [`SearchResult`] for `result`, found after `elapsed`, with `nodes_expanded` nodes
/// expanded.
fn search_result(result: DecoderResult, elapsed: Duration, nodes_expanded: usize) -> SearchResult {
    let plaintext = result.text.into_iter().next().unwrap_or_default();
    let detection = result.path.last().and_then(|last| {
        detection::for_accepted_decoding(last.checker_name, last.checker_description, &plaintext)
    });
    SearchResult {
        path: result.path.iter().map(PathStep::new).collect(),
        plaintext,
        detection,
        elapsed,
        nodes_expanded,
    }
}

/// The config for a search with `options`. The last search's is used again if its
/// options were the same: a config lives as long as the process.
fn search_config(options: &SearchOptions) -> Result<&'static SearchConfig, CipheyError> {
    /// The last config made, and the options it was made for
    static LAST: Mutex<Option<(SearchOptions, &'static SearchConfig)>> = Mutex::new(None);

    let regex = options
        .regex
        .as_deref()
        .map(regex::Regex::new)
        .transpose()
        .map_err(CipheyError::InvalidRegex)?;
    let mut last = LAST
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    // Sensitivity isn't part of the config
    let key = SearchOptions {
        sensitivity: Sensitivity::Medium,
        ..options.clone()
    };
    if let Some((last_options, config)) = last.as_ref() {
        if *last_options == key {
            return Ok(config);
        }
    }
    let config = Config {
        timeout: u32::try_from(options.timeout.as_secs()).unwrap_or(u32::MAX),
        regex: options.regex.clone(),
        top_results: options.top_results,
        human_checker_on: false,
        api_mode: true,
        ..Config::default()
    };
    let config: &'static SearchConfig = Box::leak(Box::new(SearchConfig { config, regex }));
    *last = Some((key, config));
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    // The searches themselves are tested in tests/search.rs: a search sets the config the
    // whole process reads, which would disturb the other unit tests running beside it.

    #[test]
    fn options_are_reused_only_when_they_match() {
        let a = search_config(&SearchOptions::default()).unwrap();
        let b = search_config(&SearchOptions::default().sensitivity(Sensitivity::Low)).unwrap();
        assert!(std::ptr::eq(a, b));
        let c = search_config(&SearchOptions::default().top_results(true)).unwrap();
        assert!(!std::ptr::eq(a, c));
        assert!(c.config.top_results && !c.config.human_checker_on && c.config.api_mode);
    }
}
