use crate::checkers::checker_result::CheckResult;
use crate::cli_pretty_printing::human_checker_check;
use crate::config::get_config;
use crate::storage::database;
use crate::{cli_pretty_printing, timer};
use dashmap::DashSet;
use std::cell::Cell;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use text_io::read;

thread_local! {
    /// Whether [`human_checker`] accepts candidates without asking on this thread, see
    /// [`without_prompts`].
    static PROMPTS_OFF: Cell<bool> = const { Cell::new(false) };
}

/// Runs `f` with the human checker turned off on this thread: every candidate the other
/// checkers identify is accepted without asking, as in API mode. The library's
/// single-decoder functions use it so they never read from stdin, whatever the config.
pub(crate) fn without_prompts<T>(f: impl FnOnce() -> T) -> T {
    /// Puts the previous setting back when dropped, even if `f` panics.
    struct Restore {
        /// The setting before `without_prompts` was called
        previous: bool,
    }
    impl Drop for Restore {
        fn drop(&mut self) {
            PROMPTS_OFF.with(|off| off.set(self.previous));
        }
    }
    let _restore = Restore {
        previous: PROMPTS_OFF.with(|off| off.replace(true)),
    };
    f()
}

/// Prompts already shown in this process so repeated candidates do not ask again.
static SEEN_PROMPTS: OnceLock<DashSet<String>> = OnceLock::new();
// if human checker is called, we set this to true
// so we dont call it again
/// Indicates whether a human has already accepted a candidate in this process.
static HUMAN_CONFIRMED: AtomicBool = AtomicBool::new(false);
// Mutex to ensure only one thread prompts the user at a time
/// Serializes interactive prompts so concurrent searches do not overlap on stdin/stdout.
static PROMPT_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

/// Returns the process-wide set of prompts that have already been shown.
fn get_seen_prompts() -> &'static DashSet<String> {
    SEEN_PROMPTS.get_or_init(DashSet::new)
}

/// Returns the mutex used to serialize access to the human prompt.
fn get_prompt_lock() -> &'static Mutex<()> {
    PROMPT_LOCK.get_or_init(|| Mutex::new(()))
}

/// The Human Checker asks humans if the expected plaintext is real plaintext
/// We can use all the automated checkers in the world, but sometimes they get false positives
/// Humans have the last say.
/// TODO: Add a way to specify a list of checkers to use in the library. This checker is not library friendly!
// compile this if we are not running tests
pub fn human_checker(input: &CheckResult) -> bool {
    // The library's single-decoder functions never ask, see `without_prompts`
    if PROMPTS_OFF.with(Cell::get) {
        return true;
    }
    // Check if a human has already confirmed a result (fast path)
    if HUMAN_CONFIRMED.load(Ordering::Acquire) {
        return true;
    }
    timer::pause();
    // wait instead of get so it waits for config being set
    let config = get_config();
    // We still call human checker, just if config is false we return True
    if !config.human_checker_on || config.api_mode {
        timer::resume();
        return true;
    }

    let result = ask_once(input, prompt_user);
    timer::resume();

    cli_pretty_printing::success(&format!("DEBUG: Human checker returning: {}", result));
    result
}

/// Asks the human about `input` with `ask`, unless they were already asked about it.
///
/// Only one prompt is shown at a time. Accepting a candidate ends the search, so a
/// candidate that was already asked about was rejected and is rejected again without
/// asking.
fn ask_once(input: &CheckResult, ask: impl FnOnce(&CheckResult) -> bool) -> bool {
    // Acquire the lock to ensure only one thread prompts the user at a time
    let lock_result = get_prompt_lock().lock();
    let _guard = match lock_result {
        Ok(guard) => guard,
        Err(poisoned) => {
            cli_pretty_printing::warning(
                "DEBUG: Prompt lock was poisoned; proceeding with recovered lock guard",
            );
            // Recover the inner guard even though the mutex is poisoned
            poisoned.into_inner()
        }
    };

    // Double-check HUMAN_CONFIRMED after acquiring the lock
    // Another thread might have confirmed while we were waiting for the lock
    if HUMAN_CONFIRMED.load(Ordering::Acquire) {
        return true;
    }

    // Check if we've already prompted for this text
    let prompt_key = format!("{}{}", input.description, input.text);
    if !get_seen_prompts().insert(prompt_key) {
        // The human already rejected it; returning true here used to accept it anyway
        return false;
    }

    let result = ask(input);
    // If the user confirmed, set the atomic boolean to true
    if result {
        HUMAN_CONFIRMED.store(true, Ordering::Release);
        cli_pretty_printing::success(
            "DEBUG: Human confirmed a result, future checks will be skipped",
        );
    }
    // Lock is released here when _guard goes out of scope
    result
}

/// Shows the prompt for `input` and reads the answer from stdin.
/// Rejections are recorded in the database.
fn prompt_user(input: &CheckResult) -> bool {
    human_checker_check(&input.description, &input.text);

    let reply: String = read!("{}\n");
    cli_pretty_printing::success(&format!("DEBUG: Human checker received reply: '{}'", reply));
    let result = reply.to_ascii_lowercase().starts_with('y');

    if !result {
        let fd_result = database::insert_human_rejection(uuid::Uuid::new_v4(), &input.text, input);
        match fd_result {
            Ok(_) => (),
            Err(e) => {
                cli_pretty_printing::warning(&format!(
                    "DEBUG: Failed to write human checker rejection due to error: {}",
                    e
                ));
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkers::checker_type::{Check, Checker};
    use crate::checkers::english::EnglishChecker;

    /// A candidate plaintext as the English checker would report it
    fn candidate(text: &str) -> CheckResult {
        let mut result = CheckResult::new(&Checker::<EnglishChecker>::new());
        result.is_identified = true;
        result.text = text.to_string();
        result.description = "Words".to_string();
        result
    }

    #[test]
    fn without_prompts_accepts_and_restores_the_setting() {
        assert!(!PROMPTS_OFF.with(Cell::get));
        let accepted = without_prompts(|| {
            // Nested calls keep prompts off until the outermost one returns
            without_prompts(|| assert!(PROMPTS_OFF.with(Cell::get)));
            assert!(PROMPTS_OFF.with(Cell::get));
            human_checker(&candidate("human checker test: never asked about"))
        });
        assert!(accepted);
        assert!(!PROMPTS_OFF.with(Cell::get));

        // Other threads still ask as the config says
        without_prompts(|| {
            std::thread::spawn(|| assert!(!PROMPTS_OFF.with(Cell::get)))
                .join()
                .unwrap();
        });
    }

    #[test]
    fn rejected_candidate_is_not_accepted_when_seen_again() {
        // The prompt history is global, so use text no other test checks
        let rejected = candidate("human checker test: candidate seen twice");
        let mut prompts = 0;

        assert!(!ask_once(&rejected, |_| {
            prompts += 1;
            false
        }));
        // Used to return true, accepting the candidate the human had just rejected
        assert!(!ask_once(&rejected, |_| {
            prompts += 1;
            false
        }));
        assert_eq!(prompts, 1, "the human should only be asked once");

        // Other candidates are still asked about
        let other = candidate("human checker test: a different candidate");
        assert!(!ask_once(&other, |_| {
            prompts += 1;
            false
        }));
        assert_eq!(prompts, 2);
    }
}
