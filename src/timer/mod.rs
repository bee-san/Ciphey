use crossbeam::channel::{bounded, Receiver};
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::{
    thread::{self, sleep},
    time::{Duration, Instant},
};

use crate::cli_pretty_printing::countdown_until_program_ends;

/// How often the timer wakes up to count time, check for [`pause`] and [`expire_now`],
/// and publish [`elapsed`] for the live display
const TICK: Duration = Duration::from_millis(50);
/// The most one tick counts. Generous for a loaded machine, short enough that a
/// process stopped with Ctrl-Z resumes with nearly the time it had left.
const MAX_TICK: Duration = Duration::from_millis(500);

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

/// What one timer shares with the rest of the program
#[derive(Default)]
struct TimerState {
    /// Search time counted so far, in milliseconds. Time spent paused doesn't count.
    elapsed_ms: AtomicU64,
    /// Fire now instead of waiting for the duration to pass
    expired: AtomicBool,
}

/// The newest timer started by [`start`], which [`elapsed`] and [`expire_now`] are
/// about. A timer whose search already finished keeps running until its duration is
/// up, but nobody looks at it any more.
static CURRENT: Mutex<Option<Arc<TimerState>>> = Mutex::new(None);

/// Start the timer with duration in seconds.
///
/// The returned channel receives a message once `duration` seconds of search time have
/// passed, or soon after [`expire_now`] is called. Time while the timer is paused (see
/// [`pause`]) doesn't count.
pub fn start(duration: u32) -> Receiver<()> {
    let state = Arc::new(TimerState::default());
    *CURRENT.lock().unwrap_or_else(|e| e.into_inner()) = Some(Arc::clone(&state));
    run(duration, state)
}

/// Runs a timer for `duration` seconds on its own thread, reporting through `state`
fn run(duration: u32, state: Arc<TimerState>) -> Receiver<()> {
    let (sender, recv) = bounded(1);
    let limit = Duration::from_secs(u64::from(duration));

    thread::spawn(move || {
        let mut elapsed = Duration::ZERO;
        let mut whole_seconds = 0;
        let mut last_tick = Instant::now();

        while elapsed < limit {
            if state.expired.load(Ordering::SeqCst) {
                log::info!("Timer stopped early");
                break;
            }
            // The last tick is shortened so the timer fires on time
            sleep(TICK.min(limit - elapsed));
            let now = Instant::now();
            if !PAUSED.is_paused() {
                // A tick takes a few milliseconds longer than it slept. Much longer
                // means the process was stopped (Ctrl-Z), and that isn't search time.
                elapsed += (now - last_tick).min(MAX_TICK);
            }
            last_tick = now;
            state
                .elapsed_ms
                .store(elapsed.as_millis() as u64, Ordering::Relaxed);

            // Some pretty printing support, once per whole second
            let seconds = elapsed.as_secs().min(u64::from(duration)) as u32;
            if seconds > whole_seconds {
                whole_seconds = seconds;
                countdown_until_program_ends(seconds, duration);
            }
        }

        // In top_results mode the results are listed once the search has stopped,
        // see `perform_cracking`. Listing them here used to ask questions on stdin
        // while the search kept running.
        match sender.send(()) {
            Ok(_) => log::debug!("Timer signal sent successfully"),
            Err(e) => {
                // Just log the error instead of panicking
                log::debug!(
                    "Failed to send timer signal: {:?}. The search finished first.",
                    e
                );
            }
        }
    });

    recv
}

/// Search time counted by the newest timer, excluding time spent paused
pub fn elapsed() -> Duration {
    let current = CURRENT.lock().unwrap_or_else(|e| e.into_inner());
    current.as_ref().map_or(Duration::ZERO, |state| {
        Duration::from_millis(state.elapsed_ms.load(Ordering::Relaxed))
    })
}

/// Makes the newest timer fire within one tick, even while it is paused.
/// Used when the user asks the live display to stop searching.
pub fn expire_now() {
    if let Some(state) = CURRENT.lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
        state.expired.store(true, Ordering::SeqCst);
    }
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
    use super::*;

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

    #[test]
    fn timer_fires_after_its_duration_and_counts_elapsed_time() {
        // Its own state rather than `start`, which other tests' searches replace
        let state = Arc::new(TimerState::default());
        let started = Instant::now();
        let timer = run(1, Arc::clone(&state));
        timer
            .recv_timeout(Duration::from_secs(30))
            .expect("the timer should fire");
        let took = started.elapsed();
        // Other tests running at the same time can pause it, which only makes it later
        assert!(took >= Duration::from_millis(990), "fired after {took:?}");
        let counted = Duration::from_millis(state.elapsed_ms.load(Ordering::Relaxed));
        assert!(counted >= Duration::from_millis(990), "{counted:?}");
        assert!(counted < Duration::from_millis(1500), "{counted:?}");
    }

    #[test]
    fn expired_timer_fires_early() {
        let state = Arc::new(TimerState::default());
        let started = Instant::now();
        let timer = run(30, Arc::clone(&state));
        state.expired.store(true, Ordering::SeqCst);
        timer
            .recv_timeout(Duration::from_secs(10))
            .expect("the timer should fire early");
        assert!(started.elapsed() < Duration::from_secs(5));
    }
}
