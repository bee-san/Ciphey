//! The search algorithm decides what encryptions to do next
//! And also runs the decryption modules
//! Click here to find out more:
//! <https://broadleaf-angora-7db.notion.site/Search-Nodes-Edges-What-should-they-look-like-b74c43ca7ac341a1a5cfdbeb84a7eef0>

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

pub(crate) use helper_functions::reset_decoder_stats;

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
                stop_search(&stop, handle, &result_recv);
                return Ok(res);
            }
        }

        if timer.try_recv().is_ok() {
            log::info!("Search timer expired");
            // Wait for the thread to finish to ensure any ongoing human checker interaction completes
            let late_result = stop_search(&stop, handle, &result_recv);

            // In top_results mode, return the first result we found (if any)
            if top_results_mode {
                return Ok(first_result.or(late_result));
            }

            // A result sent while the search was stopping (for example one the user
            // accepted at the human checker prompt) is still a result.
            return match late_result {
                Some(res) => Ok(Some(res)),
                None => Err(CipheyError::Timeout { secs: timeout }),
            };
        }

        // Small sleep to prevent CPU spinning
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

/// Tells the search thread to stop, waits for it to finish and returns the first result
/// it sent in the meantime.
///
/// The result channel is drained while waiting. In `top_results` mode the search thread
/// can be blocked sending a result into the bounded channel, so joining it without
/// receiving would deadlock.
fn stop_search(
    stop: &AtomicBool,
    handle: thread::JoinHandle<()>,
    result_recv: &Receiver<Option<DecoderResult>>,
) -> Option<DecoderResult> {
    stop.store(true, std::sync::atomic::Ordering::Relaxed);

    let mut late_result = None;
    while !handle.is_finished() {
        if let Ok(Some(res)) = result_recv.recv_timeout(std::time::Duration::from_millis(10)) {
            late_result.get_or_insert(res);
        }
    }
    handle.join().unwrap();

    // Anything sent just before the thread finished is still buffered
    late_result.or_else(|| result_recv.try_iter().flatten().next())
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

    /// Runs `wait_for_search_result` on another thread so a deadlock fails the test
    /// instead of hanging it.
    fn wait_with_deadline(
        result_rx: Receiver<Option<DecoderResult>>,
        timer_rx: Receiver<()>,
        handle: thread::JoinHandle<()>,
        top_results_mode: bool,
    ) -> Result<Option<DecoderResult>, CipheyError> {
        let (done_tx, done_rx) = bounded(1);
        thread::spawn(move || {
            let result = wait_for_search_result(
                result_rx,
                timer_rx,
                Arc::default(),
                handle,
                top_results_mode,
                7,
            );
            done_tx.send(result).unwrap();
        });
        done_rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("wait_for_search_result deadlocked")
    }

    #[test]
    fn top_results_mode_does_not_deadlock_when_search_is_blocked_sending() {
        // In top_results mode A* sends every result it finds. Once the timer has fired
        // nobody receives any more, so the second send into the bounded(1) channel
        // blocks, and joining the search thread used to hang forever.
        let (result_tx, result_rx) = bounded(1);
        let (timer_tx, timer_rx) = bounded(1);
        timer_tx.send(()).unwrap();
        let search = thread::spawn(move || {
            for i in 0..3 {
                result_tx
                    .send(Some(DecoderResult::_new(&format!("result {i}"))))
                    .unwrap();
            }
        });

        let result = wait_with_deadline(result_rx, timer_rx, search, true);

        assert_eq!(result.unwrap().unwrap().text[0], "result 0");
    }

    #[test]
    fn result_sent_while_stopping_is_returned_instead_of_timeout() {
        // e.g. the user accepted a plaintext at the human checker prompt just as the
        // timer expired
        let (result_tx, result_rx) = bounded(1);
        let (timer_tx, timer_rx) = bounded(1);
        timer_tx.send(()).unwrap();
        let search = thread::spawn(move || {
            thread::sleep(std::time::Duration::from_millis(50));
            result_tx.send(Some(DecoderResult::_new("late"))).unwrap();
        });

        let result = wait_with_deadline(result_rx, timer_rx, search, false);

        assert_eq!(result.unwrap().unwrap().text[0], "late");
    }
}
