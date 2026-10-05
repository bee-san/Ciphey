use crossbeam::channel::{bounded, Receiver};
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering::Relaxed;
use std::{
    thread::{self, sleep},
    time::Duration,
};

use crate::cli_pretty_printing::{countdown_until_program_ends, display_top_results};
use crate::config::get_config;
use crate::storage::wait_athena_storage;

/// How often a paused timer checks whether it has been resumed
const PAUSED_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Counts calls to [`pause`] that haven't been matched by [`resume`] yet.
///
/// Several search threads can be waiting on the human checker at once, so the timer
/// only runs again once all of them have resumed it.
struct PauseCount(AtomicUsize);

impl PauseCount {
    /// A count with nothing paused
    const fn new() -> Self {
        PauseCount(AtomicUsize::new(0))
    }

    /// Pauses until the matching [`PauseCount::resume`]
    fn pause(&self) {
        self.0.fetch_add(1, Relaxed);
    }

    /// Undoes one [`PauseCount::pause`]. Extra calls are ignored.
    fn resume(&self) {
        // A compare-exchange loop rather than `fetch_update`, which is deprecated in
        // newer Rust while its replacement `try_update` doesn't exist in older ones
        let mut count = self.0.load(Relaxed);
        while count > 0 {
            match self
                .0
                .compare_exchange_weak(count, count - 1, Relaxed, Relaxed)
            {
                Ok(_) => return,
                Err(current) => count = current,
            }
        }
    }

    /// Whether any pause is still outstanding
    fn is_paused(&self) -> bool {
        self.0.load(Relaxed) > 0
    }
}

/// Indicate whether timer is paused
static PAUSED: PauseCount = PauseCount::new();

/// Start the timer with duration in seconds
pub fn start(duration: u32) -> Receiver<()> {
    let (sender, recv) = bounded(1);
    thread::spawn(move || {
        let mut time_spent = 0;

        while time_spent < duration {
            if PAUSED.is_paused() {
                // Waiting for the human checker. Sleep rather than spin on a CPU core.
                sleep(PAUSED_POLL_INTERVAL);
                continue;
            }
            sleep(Duration::from_secs(1));
            time_spent += 1;
            // Some pretty printing support
            countdown_until_program_ends(time_spent, duration);
        }

        // When the timer expires, display all collected plaintext results
        // Only if we're in top_results mode
        let config = get_config();
        log::trace!("Timer expired. top_results mode: {}", config.top_results);

        if config.top_results {
            log::info!("Displaying all collected plaintext results");
            filter_and_display_results();
        } else {
            log::info!("Not in top_results mode, skipping display_wait_athena_results()");
        }

        // Replace the existing expect with a match that logs errors in case of send failure
        match sender.send(()) {
            Ok(_) => log::debug!("Timer signal sent successfully"),
            Err(e) => {
                // Just log the error instead of panicking
                log::warn!(
                    "Failed to send timer signal: {:?}. This is expected in benchmarks.",
                    e
                );
            }
        }
    });

    recv
}

/// Filter and display all plaintext results collected by WaitAthena
fn filter_and_display_results() {
    let results = wait_athena_storage::get_plaintext_results();

    log::trace!(
        "Retrieved {} results from wait_athena_storage",
        results.len()
    );

    // Use the cli_pretty_printing function to display the results
    display_top_results(&results);
}

/// Pause timer
pub fn pause() {
    PAUSED.pause();
}

/// Resume timer
pub fn resume() {
    PAUSED.resume();
}

#[cfg(test)]
mod tests {
    use super::PauseCount;

    #[test]
    fn timer_stays_paused_until_every_pause_is_resumed() {
        // Two search threads can wait on the human checker at once. The first one
        // resuming used to restart the timer while the second was still prompting.
        let paused = PauseCount::new();
        paused.pause();
        paused.pause();
        paused.resume();
        assert!(paused.is_paused());
        paused.resume();
        assert!(!paused.is_paused());
    }

    #[test]
    fn unmatched_resume_is_ignored() {
        let paused = PauseCount::new();
        paused.resume();
        assert!(!paused.is_paused());
        paused.pause();
        assert!(paused.is_paused());
        paused.resume();
        assert!(!paused.is_paused());
    }
}
