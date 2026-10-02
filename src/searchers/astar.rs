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
use crate::checkers::lemmeknow_checker::{is_ctf_flag_shaped, is_unmarked_ctf_flag};
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

/// An open set larger than this is freed on another thread when the search ends. A search
/// that runs until the timeout can queue over half a million nodes, and freeing them took
/// up to 0.9 s, which the caller waited for before it got its answer.
const BACKGROUND_FREE_NODES: usize = 10_000;

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

impl Drop for ThreadSafePriorityQueue {
    fn drop(&mut self) {
        let queue = self
            .queue
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if queue.len() > BACKGROUND_FREE_NODES {
            let nodes = std::mem::take(queue);
            std::thread::spawn(move || drop(nodes));
        }
    }
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

/// Reject results no correct answer could look like: under 3 chars, mostly non-printable,
/// under 5% of the input length (no decoder shrinks text that much), an English-checker
/// hit that is more than a third punctuation, or a CTF flag without a flag word in its
/// prefix (`SEKAI{...}`) when the input was already shaped like a flag: Caesar, Atbash,
/// Vigenère and their combinations with Reverse keep that shape, so such a result is just
/// the input with its letters changed.
fn result_passes_sanity(node: &AStarNode, original_input_len: usize, input_is_flag: bool) -> bool {
    let Some(text) = node.state.text.first() else {
        return false;
    };
    if check_if_string_cant_be_decoded(text) {
        return false;
    }
    if input_is_flag && is_unmarked_ctf_flag(text) {
        return false;
    }
    if original_input_len >= 40 && text.chars().count() * 20 < original_input_len {
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
                        // Results that tie on confidence go to the cheaper path, so this
                        // has to depend on the decoder: with a flat cost the tie fell back
                        // to decoder order, and Vigenere is first.
                        cost: current_node.cost + edge_cost(decoder.as_ref(), 1),
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

/// Keeps only the first result for each text, in the order the decoders are listed.
///
/// When two decoders find the same plaintext in one step, the list order says which one
/// describes it (Quoted-Printable before Hexadecimal for `=48=65`). Results are then
/// sorted by path cost, which depends on the decoder, so a duplicate from a cheaper
/// decoder must not get the chance to come first.
fn keep_first_of_each_text(results: &mut Vec<AStarNode>) {
    let mut seen = std::collections::HashSet::new();
    results.retain(|node| {
        node.state
            .text
            .first()
            .is_none_or(|text| seen.insert(calculate_hash(text)))
    });
}

/// Search for a decoder sequence that turns `input` into plaintext. Sends `Some(result)`
/// on success (repeatedly in `top_results` mode), `None` if the space is exhausted.
pub fn astar(input: String, result_sender: Sender<Option<DecoderResult>>, stop: Arc<AtomicBool>) {
    let original_input_len = input.chars().count();
    // With a crib the crib decides what the flag looks like
    let input_is_flag = is_ctf_flag_shaped(&input) && get_config().regex.is_none();
    let initial = DecoderResult {
        text: vec![input],
        path: vec![],
    };

    let seen_strings: DashSet<u64> = DashSet::new();
    let seen_results: DashSet<u64> = DashSet::new();
    let open_set = ThreadSafePriorityQueue::new();

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
            keep_first_of_each_text(&mut results);
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
            if !result_passes_sanity(&node, original_input_len, input_is_flag) {
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
        // `AAAA` is a fixpoint of several decoders and has no plaintext. The search used to
        // end on a false positive (`pppp` via ROT47); now nothing is accepted, and without
        // the timer `perform_cracking` sets, it would search until memory runs out. So
        // stop it after a second, as the timer would.
        let (sender, receiver) = bounded::<Option<DecoderResult>>(1);
        let stop = Arc::new(AtomicBool::new(false));
        let stopper = {
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_secs(1));
                stop.store(true, AtomicOrdering::Relaxed);
            })
        };
        let started = std::time::Instant::now();
        astar("AAAA".to_string(), sender, stop);
        assert!(
            started.elapsed() < std::time::Duration::from_secs(60),
            "the search didn't stop"
        );
        if let Ok(Some(result)) = receiver.try_recv() {
            panic!("junk accepted as the plaintext of AAAA: {:?}", result.text);
        }
        stopper.join().unwrap();
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
        assert!(!result_passes_sanity(&node, 800, false));

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
        assert!(result_passes_sanity(&node, 16, false));
    }

    #[test]
    fn a_large_open_set_is_freed_without_waiting() {
        let queue = ThreadSafePriorityQueue::new();
        for i in 0..=BACKGROUND_FREE_NODES {
            queue.push(AStarNode {
                state: DecoderResult::_new(&i.to_string()),
                depth: 1,
                cost: 1.0,
                total_cost: 1.0,
                is_result: false,
            });
        }
        let started = std::time::Instant::now();
        drop(queue);
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
    }

    #[test]
    fn the_first_decoder_to_find_a_text_describes_it() {
        let result = |decoder: &'static str, text: &str, cost: f32| {
            let mut step = crate::CrackResult::new(&crate::Decoder::default(), String::new());
            step.decoder = decoder;
            AStarNode {
                state: DecoderResult {
                    text: vec![text.to_string()],
                    path: vec![step],
                },
                depth: 1,
                cost,
                total_cost: f32::NEG_INFINITY,
                is_result: true,
            }
        };
        let mut results = vec![
            result("Quoted-Printable", "Hello World", 2.0),
            result("Hexadecimal", "Hello World", 1.5),
            result("Base64", "something else", 1.0),
        ];
        keep_first_of_each_text(&mut results);
        let decoders: Vec<&str> = results.iter().map(|n| n.state.path[0].decoder).collect();
        assert_eq!(decoders, ["Quoted-Printable", "Base64"]);
    }

    #[test]
    fn sanity_rejects_unmarked_flags_from_flag_shaped_input() {
        let flag = |text: &str| AStarNode {
            state: DecoderResult {
                text: vec![text.to_string()],
                path: vec![],
            },
            depth: 3,
            cost: 3.0,
            total_cost: 0.0,
            is_result: true,
        };
        // e.g. Reverse -> Atbash -> Reverse of FRXNV{l0h_s0haq_z3}
        assert!(!result_passes_sanity(
            &flag("UICME{o0s_h0szj_a3}"),
            19,
            true
        ));
        // From input that wasn't a flag (Base64, hex ...) it may be the answer
        assert!(result_passes_sanity(
            &flag("SEKAI{y0u_f0und_m3}"),
            28,
            false
        ));
        // A flag word in the prefix is always fine
        assert!(result_passes_sanity(
            &flag("flag{this_is_the_flag}"),
            22,
            true
        ));
    }
}
