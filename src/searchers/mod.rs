//! The search algorithm decides what encryptions to do next
//! And also runs the decryption modules
//! Click here to find out more:
//! https://broadleaf-angora-7db.notion.site/Search-Nodes-Edges-What-should-they-look-like-b74c43ca7ac341a1a5cfdbeb84a7eef0

use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::thread;

use crossbeam::channel::{bounded, Receiver};

use crate::checkers::athena::Athena;
use crate::checkers::checker_type::{Check, Checker};
use crate::checkers::CheckerTypes;
use crate::config::get_config;
use crate::filtration_system::{filter_and_get_decoders, MyResults};
use crate::{timer, CipheyError, DecoderResult};
/// This module provides access to the A* search algorithm
/// which uses a heuristic to prioritize decoders.
mod astar;
/// This module provides access to the breadth first search
/// which searches for the plaintext.
mod bfs;
/// This module contains helper functions used by the A* search algorithm.
mod helper_functions;

/*pub struct Tree <'a> {
    // Wrap in a box because
    // https://doc.rust-lang.org/error-index.html#E0072
    parent: &'a Box<Option<Tree<'a>>>,
    value: String
}*/

/// Performs the search algorithm.
///
/// When we perform the decryptions, we will get a vector of Some<String>
/// We need to loop through these and determine:
/// 1. Did we reach our exit condition?
/// 2. If not, create new nodes out of them and add them to the queue.
///
/// Returns `Ok(None)` if the search space is exhausted, or
/// [`CipheyError::Timeout`] if the timer expires first. In `top_results` mode
/// the search always runs until the timer and returns the first result, if any.
pub fn search_for_plaintext(input: String) -> Result<Option<DecoderResult>, CipheyError> {
    let config = get_config();
    let timeout = config.timeout;
    let timer = timer::start(timeout);

    let (result_sender, result_recv) = bounded::<Option<DecoderResult>>(1);
    // For stopping the thread
    let stop = Arc::new(AtomicBool::new(false));
    let s = stop.clone();
    // Use A* search algorithm instead of BFS
    let handle = thread::spawn(move || astar::astar(input, result_sender, s));

    wait_for_search_result(
        result_recv,
        timer,
        stop,
        handle,
        config.top_results,
        timeout,
    )
}

/// Waits for the search thread to send a result or for the timer to expire.
///
/// Split out of [`search_for_plaintext`] so it can be tested with hand-built channels.
fn wait_for_search_result(
    result_recv: Receiver<Option<DecoderResult>>,
    timer: Receiver<()>,
    stop: Arc<AtomicBool>,
    handle: thread::JoinHandle<()>,
    // In top_results mode, we don't need to return a result immediately
    // as the timer will display all results when it expires
    top_results_mode: bool,
    timeout: u32,
) -> Result<Option<DecoderResult>, CipheyError> {
    // If we're in top_results mode, we'll store the first result to return
    // at the end of the timer
    let mut first_result = None;

    loop {
        if let Ok(res) = result_recv.try_recv() {
            log::info!("Found potential plaintext result");
            log::trace!("Result details: {:?}", res);

            // In top_results mode, we store the first result but don't stop the search
            if top_results_mode {
                if first_result.is_none() {
                    first_result = res;
                }
                // Continue searching for more results
            } else {
                // In normal mode, we stop the search and return the result
                stop.store(true, std::sync::atomic::Ordering::Relaxed);
                // Wait for the thread to finish
                handle.join().unwrap();
                return Ok(res);
            }
        }

        if timer.try_recv().is_ok() {
            stop.store(true, std::sync::atomic::Ordering::Relaxed);
            log::info!("Search timer expired");
            // Wait for the thread to finish to ensure any ongoing human checker interaction completes
            handle.join().unwrap();

            // In top_results mode, return the first result we found (if any)
            if top_results_mode {
                return Ok(first_result);
            }

            return Err(CipheyError::Timeout { secs: timeout });
        }

        // Small sleep to prevent CPU spinning
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

/// Performs the decodings by getting all of the decoders
/// and calling `.run` which in turn loops through them and calls
/// `.crack()`.
#[allow(dead_code)]
fn perform_decoding(text: &DecoderResult) -> MyResults {
    let decoders = filter_and_get_decoders(text);
    let athena_checker = Checker::<Athena>::new();
    let checker = CheckerTypes::CheckAthena(athena_checker);
    decoders.run(&text.text[0], checker)
}

#[cfg(test)]
mod tests {
    use super::*;

    // https://github.com/bee-san/ciphey/pull/14/files#diff-b8829c7e292562666c7fa5934de7b478c4a5de46d92e42c46215ac4d9ff89db2R37
    // Only used for tests!
    fn exit_condition(input: &str) -> bool {
        // use Athena Checker from checkers module
        // call check(input)
        let athena_checker = Checker::<Athena>::new();
        let checker = CheckerTypes::CheckAthena(athena_checker);
        checker.check(input).is_identified
    }

    #[test]
    fn exit_condition_succeeds() {
        let result = exit_condition("https://www.google.com");
        assert!(result);
    }
    #[test]
    fn exit_condition_fails() {
        let result = exit_condition("vjkrerkdnxhrfjekfdjexk");
        assert!(!result);
    }

    #[test]
    fn perform_decoding_succeeds() {
        let dc = DecoderResult::_new("aHR0cHM6Ly93d3cuZ29vZ2xlLmNvbQ==");
        let result = perform_decoding(&dc);
        assert!(
            result
                ._break_value()
                .expect("expected successful value, none found")
                .success
        );
        //TODO assert that the plaintext is correct by looping over the vector
    }
    #[test]
    fn perform_decoding_succeeds_empty_string() {
        // Some decoders like base64 return even when the string is empty.
        let dc = DecoderResult::_new("");
        let result = perform_decoding(&dc);
        assert!(result._break_value().is_none());
    }

    #[test]
    fn timer_expiry_is_a_timeout_error() {
        let (_result_tx, result_rx) = bounded(1);
        let (timer_tx, timer_rx) = bounded(1);
        timer_tx.send(()).unwrap();
        let stop = Arc::new(AtomicBool::new(false));

        let result = wait_for_search_result(
            result_rx,
            timer_rx,
            Arc::clone(&stop),
            thread::spawn(|| {}),
            false,
            7,
        );

        assert!(matches!(result, Err(CipheyError::Timeout { secs: 7 })));
        assert!(stop.load(std::sync::atomic::Ordering::Relaxed));
    }

    #[test]
    fn exhausted_search_is_ok_none() {
        let (result_tx, result_rx) = bounded(1);
        let (_timer_tx, timer_rx) = bounded(1);
        result_tx.send(None).unwrap();

        let result = wait_for_search_result(
            result_rx,
            timer_rx,
            Arc::default(),
            thread::spawn(|| {}),
            false,
            7,
        );

        assert!(matches!(result, Ok(None)));
    }

    #[test]
    fn top_results_mode_returns_first_result_when_timer_expires() {
        let (result_tx, result_rx) = bounded(1);
        let (timer_tx, timer_rx) = bounded(1);
        result_tx.send(Some(DecoderResult::_new("first"))).unwrap();
        timer_tx.send(()).unwrap();

        let result = wait_for_search_result(
            result_rx,
            timer_rx,
            Arc::default(),
            thread::spawn(|| {}),
            true,
            7,
        );

        assert_eq!(result.unwrap().unwrap().text[0], "first");
    }
}
