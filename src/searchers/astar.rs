//! A* search over decoder sequences.
//!
//! Each node is a piece of text plus the decoder path that produced it. Expanding a node
//! runs every applicable decoder on the text; each output becomes a child, and outputs the
//! decoder's own checker flagged as plaintext become result nodes.
//!
//! Nodes are ordered by `f = g + h`, where `g` is the summed [`edge_cost`] of the path and
//! `h` is [`generate_heuristic`]. Ties go to the deeper node. Up to `PARALLEL_BATCH_SIZE`
//! nodes are expanded concurrently per iteration, and within a node all decoders run
//! concurrently.

use crate::cli_pretty_printing::decoded_how_many_times;
use crate::decoders::interface::Crack;
use crate::decoders::DECODER_MAP;
use crate::filtration_system::get_all_decoders;
use crossbeam::channel::Sender;

use log::{debug, trace};
use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::sync::{Arc, Mutex};

use dashmap::DashSet;
use rayon::prelude::*;

use crate::checkers::athena::Athena;
use crate::checkers::checker_type::{Check, Checker};
use crate::checkers::english::EnglishChecker;
use crate::checkers::CheckerTypes;
use crate::config::get_config;
use crate::searchers::helper_functions::{
    calculate_string_worth, check_if_string_cant_be_decoded, edge_cost, generate_heuristic,
    is_common_sequence, update_decoder_stats,
};
use crate::storage::wait_athena_storage;
use crate::DecoderResult;
use gibberish_or_not::Sensitivity;

/// Clear the seen-set once it grows past this many entries.
const PRUNE_THRESHOLD: usize = 200_000;

/// Number of nodes to expand in parallel per iteration of the main loop.
const PARALLEL_BATCH_SIZE: usize = 10;

/// A search that ends with at least this many queued nodes frees them on another
/// thread, see [`free_leftovers`].
const FREE_IN_BACKGROUND_MIN_NODES: usize = 1_000;

/// Frees what a finished search leaves behind (`queued_nodes` nodes and the seen-sets).
///
/// The caller gets its answer, or its timeout, only once the search thread has finished,
/// and a search can end with hundreds of thousands of queued nodes, each holding its
/// text and decoder path: freeing them took up to a quarter of a second. Big leftovers
/// are therefore freed on a new thread. Small ones are freed here, which is cheaper than
/// starting a thread, and so are big ones if the thread can't be started.
fn free_leftovers<T: Send + 'static>(leftovers: T, queued_nodes: usize) {
    if queued_nodes < FREE_IN_BACKGROUND_MIN_NODES {
        return;
    }
    // If the thread can't be started the closure, and with it `leftovers`, is dropped here.
    let _ = std::thread::Builder::new()
        .name("ciphey-free-search".to_string())
        .spawn(move || drop(leftovers));
}

/// Hash for the seen-set.
fn calculate_hash(text: &str) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    text.hash(&mut hasher);
    hasher.finish()
}

/// A search node.
#[derive(Debug)]
struct AStarNode {
    /// Text at this node (exactly one string) and the decoder path to it.
    state: DecoderResult,
    /// Number of decoders applied.
    depth: u32,
    /// g: summed `edge_cost` along the path.
    cost: f32,
    /// f = g + h.
    total_cost: f32,
    /// The last decoder's checker identified `state.text` as plaintext.
    is_result: bool,
}

impl Ord for AStarNode {
    fn cmp(&self, other: &Self) -> Ordering {
        // Min-heap on f; deeper node wins ties.
        other
            .total_cost
            .partial_cmp(&self.total_cost)
            .unwrap_or(Ordering::Equal)
            .then_with(|| self.depth.cmp(&other.depth))
    }
}

impl PartialOrd for AStarNode {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for AStarNode {
    fn eq(&self, other: &Self) -> bool {
        self.total_cost == other.total_cost && self.depth == other.depth
    }
}

impl Eq for AStarNode {}

/// The open set.
struct ThreadSafePriorityQueue {
    /// Backing heap.
    queue: Mutex<BinaryHeap<AStarNode>>,
}

impl ThreadSafePriorityQueue {
    /// Empty queue.
    fn new() -> Self {
        ThreadSafePriorityQueue {
            queue: Mutex::new(BinaryHeap::new()),
        }
    }

    /// Push one node.
    fn push(&self, node: AStarNode) {
        self.queue.lock().unwrap().push(node);
    }

    /// Whether the queue is empty.
    fn is_empty(&self) -> bool {
        self.queue.lock().unwrap().is_empty()
    }

    /// Number of queued nodes.
    fn len(&self) -> usize {
        self.queue.lock().unwrap().len()
    }

    /// Pop up to `batch_size` nodes.
    fn extract_batch(&self, batch_size: usize) -> Vec<AStarNode> {
        let mut queue = self.queue.lock().unwrap();
        let mut batch = Vec::with_capacity(batch_size);
        for _ in 0..batch_size {
            match queue.pop() {
                Some(node) => batch.push(node),
                None => break,
            }
        }
        batch
    }
}

/// Skip edges that cannot make progress: a reciprocal decoder applied twice is the
/// identity, and two consecutive Caesar shifts (or substitutions, etc.) collapse into one.
/// Binary-to-text encodings are exempt since `base64(base64(x))` is a common layering.
fn should_try_decoder(decoder: &(dyn Crack + Sync), last: Option<&crate::CrackResult>) -> bool {
    let Some(last) = last else {
        return true;
    };
    let name = decoder.get_name();
    if last.decoder != name {
        return true;
    }
    if decoder.get_tags().contains(&"reciprocal") {
        return false;
    }
    is_common_sequence(last.decoder, name)
}

/// Whether the decoder of `step` is tagged `program`: its output can be a tiny part of its
/// input by design. A steganography decoder (Zero-width) returns the hidden message
/// without its cover text, which can be any length, and an interpreter prints less than
/// its program.
fn shrinks_by_design(step: &crate::CrackResult) -> bool {
    DECODER_MAP
        .get(step.decoder)
        .is_some_and(|decoder| decoder.get::<()>().get_tags().contains(&"program"))
}

/// Reject results no correct answer could look like: under 3 chars, mostly non-printable,
/// under 5% of the input length (no decoder shrinks text that much, except the ones in
/// [`shrinks_by_design`], wherever they are in the path), or an English-checker hit that
/// is more than a third punctuation.
fn result_passes_sanity(node: &AStarNode, original_input_len: usize) -> bool {
    let Some(text) = node.state.text.first() else {
        return false;
    };
    if check_if_string_cant_be_decoded(text) {
        return false;
    }
    // The steps after a program-tagged one can't undo its shrinking: in
    // AAEncode -> Base64 the answer is a fraction of the Base64 the program printed.
    if original_input_len >= 40
        && text.chars().count() * 20 < original_input_len
        && !node.state.path.iter().any(shrinks_by_design)
    {
        return false;
    }
    // gibberish_or_not at Medium passes strings like `-t{)-+&it|{})h"#/,")isoe'$h` on bigrams.
    if let Some(last) = node.state.path.last() {
        if last.checker_name == "English Checker" {
            let total = text.chars().count().max(1);
            let symbols = text
                .chars()
                .filter(|c| !c.is_alphanumeric() && !c.is_whitespace())
                .count();
            if symbols * 3 > total {
                return false;
            }
        }
    }
    true
}

/// Run every applicable decoder on the node's text and return the children.
fn expand_node(
    current_node: &AStarNode,
    seen_strings: &DashSet<u64>,
    stop: &Arc<AtomicBool>,
) -> Vec<AStarNode> {
    if stop.load(AtomicOrdering::Relaxed) {
        return Vec::new();
    }

    let Some(text) = current_node.state.text.first() else {
        return Vec::new();
    };
    let last_decoder = current_node.state.path.last();
    let decoders = get_all_decoders();

    decoders
        .components
        .par_iter()
        .filter(|d| should_try_decoder(d.as_ref(), last_decoder))
        .flat_map_iter(|decoder| {
            let mut children = Vec::new();
            if stop.load(AtomicOrdering::Relaxed) {
                return children;
            }

            let checker = CheckerTypes::CheckAthena(Checker::<Athena>::new());
            let mut result = decoder.crack(text, &checker);

            // Taken out so the per-candidate clones below don't copy every candidate.
            let Some(candidates) = result.unencrypted_text.take() else {
                update_decoder_stats(decoder.get_name(), false);
                return children;
            };

            if result.success {
                let plaintext = candidates.first().cloned().unwrap_or_default();
                if !plaintext.is_empty() {
                    result.unencrypted_text = Some(candidates);
                    let mut path = current_node.state.path.clone();
                    path.push(result);
                    children.push(AStarNode {
                        state: DecoderResult {
                            text: vec![plaintext],
                            path,
                        },
                        depth: current_node.depth + 1,
                        cost: current_node.cost + 1.0,
                        total_cost: f32::NEG_INFINITY,
                        is_result: true,
                    });
                    update_decoder_stats(decoder.get_name(), true);
                }
                return children;
            }

            let step_cost = edge_cost(decoder.as_ref(), candidates.len());
            let mut produced_any = false;
            for candidate in candidates {
                if candidate.is_empty() || !calculate_string_worth(&candidate) {
                    continue;
                }
                if !seen_strings.insert(calculate_hash(&candidate)) {
                    continue;
                }
                produced_any = true;

                let mut path = current_node.state.path.clone();
                let mut step = result.clone();
                step.unencrypted_text = Some(vec![candidate.clone()]);
                path.push(step);

                let cost = current_node.cost + step_cost;
                let heuristic = generate_heuristic(&candidate, &path, Some(decoder.as_ref()));
                children.push(AStarNode {
                    state: DecoderResult {
                        text: vec![candidate],
                        path,
                    },
                    depth: current_node.depth + 1,
                    cost,
                    total_cost: cost + heuristic,
                    is_result: false,
                });
            }
            update_decoder_stats(decoder.get_name(), produced_any);
            children
        })
        .collect()
}

/// Sort key for competing results from one batch: regex-style checker hits and strict
/// English hits first, lenient English hits second, then cheaper paths. Without this a
/// Vigenere output that scrapes past the Medium English check can beat a correct Reverse.
fn result_confidence(node: &AStarNode) -> (u8, f32) {
    let Some(text) = node.state.text.first() else {
        return (u8::MAX, f32::INFINITY);
    };
    let Some(last) = node.state.path.last() else {
        return (u8::MAX, f32::INFINITY);
    };
    let class = if last.checker_name == "English Checker" {
        let strict = Checker::<EnglishChecker>::new().with_sensitivity(Sensitivity::Low);
        if strict.check(text).is_identified {
            0
        } else {
            1
        }
    } else {
        0
    };
    (class, node.cost)
}

/// Search for a decoder sequence that turns `input` into plaintext. Sends `Some(result)`
/// on success (repeatedly in `top_results` mode), `None` if the space is exhausted.
pub fn astar(input: String, result_sender: Sender<Option<DecoderResult>>, stop: Arc<AtomicBool>) {
    let original_input_len = input.chars().count();
    let initial = DecoderResult {
        text: vec![input],
        path: vec![],
    };

    let seen_strings: DashSet<u64> = DashSet::new();
    let seen_results: DashSet<u64> = DashSet::new();
    let open_set = ThreadSafePriorityQueue::new();
    // Like the seen-sets, Athena's memory of rejected candidates starts empty.
    crate::checkers::athena::forget_rejections();

    open_set.push(AStarNode {
        state: initial,
        depth: 0,
        cost: 0.0,
        total_cost: 0.0,
        is_result: false,
    });

    let mut curr_depth: u32 = 0;
    let mut expanded_nodes: usize = 0;

    while !open_set.is_empty() && !stop.load(AtomicOrdering::Relaxed) {
        let batch = open_set.extract_batch(PARALLEL_BATCH_SIZE);
        if let Some(deepest) = batch.iter().map(|n| n.depth).max() {
            curr_depth = curr_depth.max(deepest);
        }
        expanded_nodes += batch.len();
        trace!(
            "Expanding batch of {} nodes (depth {}, open set {}, seen {}, expanded {})",
            batch.len(),
            curr_depth,
            open_set.len(),
            seen_strings.len(),
            expanded_nodes
        );

        let new_nodes: Vec<AStarNode> = batch
            .par_iter()
            .flat_map(|node| expand_node(node, &seen_strings, &stop))
            .collect();

        let (mut results, children): (Vec<AStarNode>, Vec<AStarNode>) =
            new_nodes.into_iter().partition(|n| n.is_result);

        if results.len() > 1 {
            results.sort_by(|a, b| {
                result_confidence(a)
                    .partial_cmp(&result_confidence(b))
                    .unwrap_or(Ordering::Equal)
            });
        }

        for node in results {
            let Some(text) = node.state.text.first() else {
                continue;
            };
            if !seen_results.insert(calculate_hash(text)) {
                debug!("Skipping duplicate result: {:?}", text);
                continue;
            }
            if !result_passes_sanity(&node, original_input_len) {
                debug!(
                    "Rejected implausible result {:?} from path {:?}; continuing search",
                    text,
                    node.state
                        .path
                        .iter()
                        .map(|p| p.decoder)
                        .collect::<Vec<_>>()
                );
                if seen_strings.insert(calculate_hash(text)) {
                    let heuristic = generate_heuristic(text, &node.state.path, None);
                    open_set.push(AStarNode {
                        total_cost: node.cost + heuristic,
                        is_result: false,
                        ..node
                    });
                }
                continue;
            }

            debug!(
                "Found result after expanding {} nodes: {:?}",
                expanded_nodes, node.state.text
            );
            decoded_how_many_times(node.depth);

            if get_config().top_results {
                if let Some(last) = node.state.path.last() {
                    if !last.checker_name.is_empty() {
                        wait_athena_storage::add_plaintext_result(
                            text.clone(),
                            format!("Decoded successfully at depth {}", node.depth),
                            last.checker_name.to_string(),
                            last.decoder.to_string(),
                        );
                    }
                }
            }

            result_sender
                .send(Some(node.state.clone()))
                .expect("Should successfully send the result");

            if !get_config().top_results {
                stop.store(true, AtomicOrdering::Relaxed);
                let queued_nodes = open_set.len() + children.len();
                free_leftovers(
                    (open_set, children, seen_strings, seen_results),
                    queued_nodes,
                );
                return;
            }
        }

        for node in children {
            open_set.push(node);
        }

        if seen_strings.len() > PRUNE_THRESHOLD {
            debug!("Seen-set exceeded {} entries; clearing", PRUNE_THRESHOLD);
            seen_strings.clear();
        }
    }

    if !stop.load(AtomicOrdering::Relaxed) {
        result_sender
            .send(None)
            .expect("Should successfully send the result");
    }
    let queued_nodes = open_set.len();
    free_leftovers((open_set, seen_strings, seen_results), queued_nodes);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossbeam::channel::bounded;

    #[test]
    fn astar_handles_empty_input() {
        let (sender, receiver) = bounded::<Option<DecoderResult>>(1);
        let stop = Arc::new(AtomicBool::new(false));
        astar("".to_string(), sender, stop);
        let result = receiver.recv().unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn astar_prevents_cycles() {
        let (sender, receiver) = bounded::<Option<DecoderResult>>(1);
        let stop = Arc::new(AtomicBool::new(false));
        astar("AAAA".to_string(), sender, stop);
        let _ = receiver.recv().unwrap();
    }

    #[test]
    fn test_parallel_astar() {
        let (sender, receiver) = bounded::<Option<DecoderResult>>(1);
        let stop = Arc::new(AtomicBool::new(false));
        let input = "SGVsbG8gV29ybGQ=".to_string();
        let stop_clone = stop.clone();
        std::thread::spawn(move || {
            astar(input, sender, stop_clone);
        });
        let result = receiver.recv().unwrap();
        assert!(result.is_some());
        if let Some(decoder_result) = result {
            assert!(!decoder_result.path.is_empty());
        }
    }

    #[test]
    fn reciprocal_decoder_is_not_applied_twice() {
        let decoders = get_all_decoders();
        let rot47 = decoders
            .components
            .iter()
            .find(|d| d.get_name() == "rot47")
            .unwrap();
        let base64 = decoders
            .components
            .iter()
            .find(|d| d.get_name() == "Base64")
            .unwrap();

        let mut last = crate::CrackResult::new(&crate::Decoder::default(), String::new());
        last.decoder = "rot47";
        assert!(!should_try_decoder(rot47.as_ref(), Some(&last)));
        assert!(should_try_decoder(base64.as_ref(), Some(&last)));

        // Stackable encodings may repeat.
        last.decoder = "Base64";
        assert!(should_try_decoder(base64.as_ref(), Some(&last)));
    }

    #[test]
    fn quoted_printable_may_be_applied_twice() {
        // Layered Quoted-Printable: `=3D41` -> `=41` -> `A`
        let decoders = get_all_decoders();
        let quoted_printable = decoders
            .components
            .iter()
            .find(|d| d.get_name() == "Quoted-Printable")
            .unwrap();

        let mut last = crate::CrackResult::new(&crate::Decoder::default(), String::new());
        last.decoder = "Quoted-Printable";
        assert!(should_try_decoder(quoted_printable.as_ref(), Some(&last)));
    }

    /// Reports the thread it is dropped on.
    struct DropProbe(crossbeam::channel::Sender<std::thread::ThreadId>);

    impl Drop for DropProbe {
        fn drop(&mut self) {
            let _ = self.0.send(std::thread::current().id());
        }
    }

    #[test]
    fn big_leftovers_are_freed_on_another_thread() {
        let (sender, receiver) = bounded(2);
        free_leftovers(DropProbe(sender.clone()), FREE_IN_BACKGROUND_MIN_NODES - 1);
        assert_eq!(receiver.recv().unwrap(), std::thread::current().id());

        free_leftovers(DropProbe(sender), FREE_IN_BACKGROUND_MIN_NODES);
        let dropped_on = receiver
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("the leftovers should be freed");
        assert_ne!(dropped_on, std::thread::current().id());
    }

    #[test]
    fn sanity_rejects_tiny_outputs_from_long_inputs() {
        let node = AStarNode {
            state: DecoderResult {
                text: vec!["\u{2}".to_string()],
                path: vec![],
            },
            depth: 1,
            cost: 1.0,
            total_cost: 0.0,
            is_result: true,
        };
        assert!(!result_passes_sanity(&node, 800));

        let node = AStarNode {
            state: DecoderResult {
                text: vec!["Hello World".to_string()],
                path: vec![],
            },
            depth: 1,
            cost: 1.0,
            total_cost: 0.0,
            is_result: true,
        };
        assert!(result_passes_sanity(&node, 16));
    }

    /// A result node whose path is one step by `decoder`, checked by `checker_name`
    fn result_node(text: &str, decoder: &'static str, checker_name: &'static str) -> AStarNode {
        let mut step = crate::CrackResult::new(&crate::Decoder::default(), String::new());
        step.decoder = decoder;
        step.checker_name = checker_name;
        AStarNode {
            state: DecoderResult {
                text: vec![text.to_string()],
                path: vec![step],
            },
            depth: 1,
            cost: 1.0,
            total_cost: 0.0,
            is_result: true,
        }
    }

    #[test]
    fn sanity_lets_program_decoders_shrink_text() {
        // A 23-character flag hidden in a 615-character cover: 23 * 20 < 615
        let flag = "flag{zero_width_is_fun}";
        assert!(result_passes_sanity(
            &result_node(flag, "Zero-width", "LemmeKnow Checker"),
            615
        ));
        // The same result from a decoder without the tag is still too short
        assert!(!result_passes_sanity(
            &result_node(flag, "Base64", "LemmeKnow Checker"),
            615
        ));
        // The tag only skips the length rule: unprintable and tiny results are still
        // rejected, and so is an English-checker hit that is mostly punctuation
        assert!(!result_passes_sanity(
            &result_node("\u{2}\u{3}\u{4}\u{5}", "Zero-width", "LemmeKnow Checker"),
            615
        ));
        assert!(!result_passes_sanity(
            &result_node("hi", "Zero-width", "LemmeKnow Checker"),
            615
        ));
        assert!(!result_passes_sanity(
            &result_node(
                "-t{)-+&it|{})h\"#/,\")isoe'$h",
                "Zero-width",
                "English Checker"
            ),
            615
        ));
    }

    #[test]
    fn sanity_lets_ook_print_much_less_than_its_program() {
        // 1,329 characters of Ook! print `hello world`, 11: under 5% of the input. Fine for
        // an interpreter (tag `program`), not for Base64.
        assert!(result_passes_sanity(
            &result_node("hello world", "Ook!", "English Checker"),
            1_329
        ));
        assert!(!result_passes_sanity(
            &result_node("hello world", "Base64", "English Checker"),
            1_329
        ));
        // Two characters are still too few
        assert!(!result_passes_sanity(
            &result_node("hi", "Ook!", "English Checker"),
            299
        ));
    }

    #[test]
    fn sanity_lets_steps_after_a_program_decoder_shrink_text() {
        // An 11-character answer from a 1,405-character AAEncode program: 11 * 20 < 1,405
        let path = |decoders: &[&'static str]| {
            let mut node = result_node("hello world", "AAEncode", "English Checker");
            node.state.path = decoders
                .iter()
                .map(|&decoder| {
                    let mut step =
                        crate::CrackResult::new(&crate::Decoder::default(), String::new());
                    step.decoder = decoder;
                    step.checker_name = "English Checker";
                    step
                })
                .collect();
            node
        };
        assert!(result_passes_sanity(&path(&["AAEncode"]), 1405));
        assert!(!result_passes_sanity(&path(&["Base64"]), 1405));
        // The program printed Base64, which the next step decoded
        assert!(result_passes_sanity(&path(&["AAEncode", "Base64"]), 1405));
        assert!(result_passes_sanity(&path(&["Base64", "AAEncode"]), 1405));
        assert!(!result_passes_sanity(&path(&["Base64", "Base64"]), 1405));
    }

    #[test]
    fn sanity_lets_jsfuck_shrink_text() {
        // jsfuck.js 0.4.0 writes `hello world` in 4,103 characters: 11 * 20 < 4,103
        assert!(result_passes_sanity(
            &result_node("hello world", "JSFuck", "English Checker"),
            4103
        ));
        assert!(!result_passes_sanity(
            &result_node("hello world", "Base64", "English Checker"),
            4103
        ));
    }
}
