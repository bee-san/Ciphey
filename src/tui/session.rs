//! The live session: a thread that draws the live screens and reacts to keys while
//! the search runs.
//!
//! The terminal is in raw mode for the whole session, so keys arrive one at a time
//! without being echoed. The human checker hands its questions to the display thread
//! with [`ask_about_candidate`] and waits for the key press that answers them.
//!
//! Whatever happens, the session ends and ciphey exits instead of hanging:
//!
//! * The search ends: the live region is cleared, the cursor shown again and raw mode
//!   turned off before the result is printed.
//! * Ctrl-C, SIGINT, SIGTERM or SIGHUP: the same, then ciphey exits with 128 + the
//!   signal number. A dedicated thread handles the signals, and if the display thread
//!   hasn't exited half a second later (say the terminal has gone), it exits itself.
//! * The terminal goes away without a signal: writing to it fails, which stops the
//!   search, so ciphey finishes and exits.
//!
//! Keys are read on a thread of their own. crossterm's reader spins forever once the
//! terminal has hung up; on its own thread that can't hold up anything else, and
//! nothing waits for it for long.

use super::live::{self, LiveRegion};
use super::screens::{self, PromptView, SearchView};
use super::theme::Theme;
use crate::checkers::checker_result::CheckResult;
use crate::searchers::progress;
use crate::storage::wait_athena_storage;
use crate::timer;
use crossbeam::channel::{bounded, unbounded, Receiver, RecvTimeoutError, Sender};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::terminal;
use std::io::{self, Stdout, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Once};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// How often the search screen is redrawn. Drawing happens on the display thread
/// only, so the search never waits for the terminal.
const FRAME: Duration = Duration::from_millis(100);
/// Nothing is drawn before this, so answers that come back at once (most of them)
/// don't flash a search screen first
const FIRST_FRAME: Duration = Duration::from_millis(150);
/// The longest the display thread waits for a key before it looks for questions,
/// signals and the end of the session
const POLL: Duration = Duration::from_millis(25);
/// How long the end of the session waits for the display thread
const FINISH_WAIT: Duration = Duration::from_secs(2);
/// How long anything waits for the key reader or for the terminal to be restored.
/// Both can block on a terminal that has gone away.
const SHORT_WAIT: Duration = Duration::from_millis(300);

/// A session is running: questions go to it and nothing else may print
static LIVE: AtomicBool = AtomicBool::new(false);
/// A session has been started in this process
static STARTED: AtomicBool = AtomicBool::new(false);
/// Where the human checker sends its questions while a session runs
static QUESTIONS: Mutex<Option<Sender<Question>>> = Mutex::new(None);

/// The answer to "is this the plaintext?"
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    /// It is the plaintext
    Yes,
    /// It isn't, keep searching
    No,
    /// The user stopped the search; this candidate wasn't judged
    Stop,
}

/// A question from the human checker, waiting for a key press
struct Question {
    /// The candidate plaintext
    text: String,
    /// The checker that found it
    checker: &'static str,
    /// What the checker said about it
    description: String,
    /// Where the answer goes
    reply: Sender<Answer>,
}

/// Whether a live session is running now. While it is, everything that would print
/// to the terminal has to go through it.
pub fn is_live() -> bool {
    LIVE.load(Ordering::SeqCst)
}

/// Whether a live session was started at some point in this process
pub fn live_display_started() -> bool {
    STARTED.load(Ordering::SeqCst)
}

/// Asks the user about a candidate plaintext with a key press in the live display.
///
/// Blocks until the user answers. Returns None if no live session is running, in
/// which case the caller asks on stdin as before.
pub fn ask_about_candidate(candidate: &CheckResult) -> Option<Answer> {
    if !is_live() {
        return None;
    }
    let sender = QUESTIONS.lock().ok()?.as_ref()?.clone();
    let (reply, answer) = bounded(1);
    sender
        .send(Question {
            text: candidate.text.clone(),
            checker: candidate.checker_name,
            description: candidate.description.clone(),
            reply,
        })
        .ok()?;
    // Dropped unanswered (the session ended): ask on stdin instead
    answer.recv().ok()
}

/// What the search screen needs to know about the search
#[derive(Debug, Clone)]
pub struct SearchInfo {
    /// The time limit in seconds
    pub timeout: u32,
    /// Top results mode, where every possible plaintext is collected
    pub top_results: bool,
    /// The regex crib, if there is one
    pub regex: Option<String>,
    /// How many decoders are tried on each text
    pub decoders: usize,
}

/// What happened during a session
#[derive(Debug, Clone, Default)]
pub struct Report {
    /// The user pressed q to stop the search
    pub stopped: bool,
    /// Candidates the user said no to
    pub rejected: usize,
    /// The user said yes to a candidate
    pub accepted: bool,
    /// Time spent with a question on the screen, which doesn't count as search time
    pub answering: Duration,
}

/// A running live session. [`Session::finish`] ends it.
pub struct Session {
    /// The display thread
    thread: Option<JoinHandle<()>>,
    /// The display thread's report, sent when it has given the terminal back
    report: Receiver<Report>,
    /// Tells the display thread to clean up and stop
    finish: Arc<AtomicBool>,
}

impl Session {
    /// Puts the terminal in raw mode and starts drawing.
    ///
    /// # Errors
    ///
    /// Returns an error if the terminal can't be put in raw mode or a thread can't be
    /// started. The terminal is left as it was.
    pub fn start(theme: Theme, info: SearchInfo) -> io::Result<Session> {
        terminal::enable_raw_mode()?;
        let keys = match Keys::start() {
            Ok(keys) => keys,
            Err(e) => {
                let _ = terminal::disable_raw_mode();
                return Err(e);
            }
        };
        install_panic_hook();
        signals::watch();

        let (questions, incoming) = unbounded();
        *QUESTIONS.lock().unwrap_or_else(|e| e.into_inner()) = Some(questions);
        progress::enable();
        STARTED.store(true, Ordering::SeqCst);
        LIVE.store(true, Ordering::SeqCst);

        let finish = Arc::new(AtomicBool::new(false));
        let (report_tx, report) = bounded(1);
        let ui = Ui::new(theme, info, incoming, keys);
        let spawned = thread::Builder::new().name("ciphey-display".into()).spawn({
            let finish = Arc::clone(&finish);
            move || {
                let report = ui.run(&finish);
                let _ = report_tx.send(report);
            }
        });
        match spawned {
            Ok(thread) => Ok(Session {
                thread: Some(thread),
                report,
                finish,
            }),
            Err(e) => {
                end_session();
                restore_terminal();
                Err(e)
            }
        }
    }

    /// Clears the live region, gives the terminal back and reports what the user did
    pub fn finish(mut self) -> Report {
        self.stop()
    }

    /// Stops the display thread and waits for it, but not for ever
    fn stop(&mut self) -> Report {
        let Some(thread) = self.thread.take() else {
            return Report::default();
        };
        self.finish.store(true, Ordering::SeqCst);
        let report = match self.report.recv_timeout(FINISH_WAIT) {
            Ok(report) => {
                // It has finished, so this returns at once
                let _ = thread.join();
                Some(report)
            }
            // It panicked, or it is stuck on a terminal that has gone away
            Err(_) => None,
        };
        end_session();
        if report.is_none() {
            restore_terminal_briefly();
        }
        report.unwrap_or_default()
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Marks the session as over: questions go back to stdin and printing is allowed
fn end_session() {
    *QUESTIONS.lock().unwrap_or_else(|e| e.into_inner()) = None;
    LIVE.store(false, Ordering::SeqCst);
    progress::disable();
}

/// Turns raw mode off and shows the cursor
fn restore_terminal() {
    let _ = terminal::disable_raw_mode();
    let mut out = io::stdout();
    let _ = out.write_all(live::SHOW_CURSOR.as_bytes());
    let _ = out.flush();
}

/// [`restore_terminal`] on a thread of its own, waiting for it only briefly: writing
/// to a terminal that has gone away can block
fn restore_terminal_briefly() {
    let (done, restored) = bounded(1);
    let spawned = thread::Builder::new()
        .name("ciphey-restore".into())
        .spawn(move || {
            restore_terminal();
            let _ = done.send(());
        });
    if spawned.is_ok() {
        let _ = restored.recv_timeout(SHORT_WAIT);
    }
}

/// Makes a panic during a session restore the terminal before the message is printed
fn install_panic_hook() {
    /// The hook is installed once per process
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if is_live() {
                restore_terminal_briefly();
                let _ = io::stdout().write_all(b"\r\n");
            }
            previous(info);
        }));
    });
}

/// What the key reader passes on
enum Input {
    /// A key press, a resize or another terminal event
    Event(Event),
    /// The terminal can't be read any more
    Closed,
}

/// The thread that reads keys
struct Keys {
    /// What it read
    events: Receiver<Input>,
    /// Tells it to stop
    stop: Arc<AtomicBool>,
    /// Receives a message when it has stopped
    stopped: Receiver<()>,
}

impl Keys {
    /// Starts reading keys
    fn start() -> io::Result<Keys> {
        let (send, events) = unbounded();
        let (done, stopped) = bounded(1);
        let stop = Arc::new(AtomicBool::new(false));
        let stop_flag = Arc::clone(&stop);
        thread::Builder::new()
            .name("ciphey-keys".into())
            .spawn(move || {
                while !stop_flag.load(Ordering::SeqCst) {
                    let input = match event::poll(POLL) {
                        Ok(false) => continue,
                        Ok(true) => event::read().map_or(Input::Closed, Input::Event),
                        Err(_) => Input::Closed,
                    };
                    let closed = matches!(input, Input::Closed);
                    if send.send(input).is_err() || closed {
                        break;
                    }
                }
                let _ = done.send(());
            })?;
        Ok(Keys {
            events,
            stop,
            stopped,
        })
    }

    /// Stops reading keys, so that whatever reads the terminal next gets them. Waits
    /// for that only briefly: on a terminal that has gone away, the reader is stuck.
    fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = self.stopped.recv_timeout(SHORT_WAIT);
    }
}

impl Drop for Keys {
    fn drop(&mut self) {
        // Without waiting: it stops within one poll
        self.stop.store(true, Ordering::SeqCst);
    }
}

/// The display thread's state
struct Ui {
    /// Colours and symbols
    theme: Theme,
    /// What is being searched for
    info: SearchInfo,
    /// Questions from the human checker
    incoming: Receiver<Question>,
    /// Key presses
    keys: Keys,
    /// Keys can still be read
    keys_open: bool,
    /// The terminal can't be written to any more, so nothing is drawn
    gone: bool,
    /// The lines being redrawn
    region: LiveRegion<Stdout>,
    /// When the session started
    started: Instant,
    /// The question on screen, and when it was asked
    question: Option<(Question, Instant)>,
    /// How many questions have been asked
    asked: usize,
    /// The keys are shown
    help: bool,
    /// The user asked to stop
    stopping: bool,
    /// What to report at the end
    report: Report,
    /// Frames drawn so far, for the spinner
    frame: usize,
    /// When the last frame was drawn
    last_draw: Option<Instant>,
    /// Something changed that should be shown now rather than at the next frame
    dirty: bool,
}

impl Ui {
    /// The state at the start of a session
    fn new(theme: Theme, info: SearchInfo, incoming: Receiver<Question>, keys: Keys) -> Ui {
        Ui {
            theme,
            info,
            incoming,
            keys,
            keys_open: true,
            gone: false,
            region: LiveRegion::new(io::stdout()),
            started: Instant::now(),
            question: None,
            asked: 0,
            help: false,
            stopping: false,
            report: Report::default(),
            frame: 0,
            last_draw: None,
            dirty: false,
        }
    }

    /// Draws and reacts to keys until `finish` is set, then gives the terminal back
    fn run(mut self, finish: &AtomicBool) -> Report {
        if let Err(e) = self.region.write_raw(live::HIDE_CURSOR) {
            self.output_failed(&e);
        }
        while !finish.load(Ordering::SeqCst) {
            if let Some(code) = signals::pending_exit_code() {
                self.quit(code);
            }
            if self.stopping {
                // A timer started after q was pressed has to stop too
                timer::expire_now();
            }
            self.take_questions();
            if self.keys_open {
                match self.keys.events.recv_timeout(POLL) {
                    Ok(Input::Event(event)) => self.handle(event),
                    Ok(Input::Closed) | Err(RecvTimeoutError::Disconnected) => self.keys_closed(),
                    Err(RecvTimeoutError::Timeout) => {}
                }
            } else {
                thread::sleep(POLL);
            }
            self.draw_if_due();
        }
        self.close();
        self.report
    }

    /// Picks up the next question, answering it straight away if the user is stopping
    fn take_questions(&mut self) {
        while self.question.is_none() {
            let Ok(question) = self.incoming.try_recv() else {
                return;
            };
            if self.stopping {
                let _ = question.reply.send(Answer::Stop);
                continue;
            }
            self.asked += 1;
            self.question = Some((question, Instant::now()));
            self.dirty = true;
            if !self.keys_open {
                // Nobody can answer, which is a no, as it was on stdin at end of input
                self.answer(Answer::No);
            }
        }
    }

    /// The terminal can't be read any more
    fn keys_closed(&mut self) {
        self.keys_open = false;
        if self.question.is_some() {
            self.answer(Answer::No);
        }
    }

    /// Writing to the terminal failed. Unless the write was merely interrupted, the
    /// terminal has gone away: nobody can see or answer anything, so stop the search
    /// and let ciphey finish.
    fn output_failed(&mut self, error: &io::Error) {
        if error.kind() == io::ErrorKind::Interrupted || self.gone {
            return;
        }
        log::debug!("The terminal can't be written to ({error}), stopping the search");
        self.gone = true;
        self.stop();
    }

    /// Reacts to a key press or a resize
    fn handle(&mut self, event: Event) {
        match event {
            // Windows reports releases too; holding a key mustn't answer twice
            Event::Key(key) if key.kind == KeyEventKind::Press => self.key(key),
            Event::Resize(..) => self.dirty = true,
            _ => {}
        }
    }

    /// Reacts to a key press
    fn key(&mut self, key: KeyEvent) {
        let asking = self.question.is_some();
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            KeyCode::Char('c') if ctrl => self.quit(130),
            KeyCode::Char('z') if ctrl => self.suspend(),
            KeyCode::Char('?') => {
                self.help = !self.help;
                self.dirty = true;
            }
            KeyCode::Char('q') | KeyCode::Esc => self.stop(),
            KeyCode::Char('y' | 'Y') if asking => self.answer(Answer::Yes),
            KeyCode::Char('n' | 'N') | KeyCode::Enter if asking => self.answer(Answer::No),
            _ => {}
        }
    }

    /// Answers the question on screen
    fn answer(&mut self, answer: Answer) {
        let Some((question, asked_at)) = self.question.take() else {
            return;
        };
        self.report.answering += asked_at.elapsed();
        match answer {
            Answer::Yes => self.report.accepted = true,
            Answer::No => {
                self.report.rejected += 1;
                if !self.gone {
                    // Keep a trace of it above the live region
                    let (cols, _) = terminal_size();
                    let line = screens::rejected(&question.text, &self.theme, text_width(cols));
                    if let Err(e) = self.region.print_above(&[line], cols) {
                        self.output_failed(&e);
                    }
                }
            }
            Answer::Stop => {}
        }
        let _ = question.reply.send(answer);
        self.dirty = true;
    }

    /// Stops the search, as if the time limit had run out
    fn stop(&mut self) {
        if self.stopping {
            return;
        }
        self.stopping = true;
        self.report.stopped = true;
        timer::expire_now();
        if self.question.is_some() {
            self.answer(Answer::Stop);
        }
        self.dirty = true;
    }

    /// Draws a frame if one is due
    fn draw_if_due(&mut self) {
        if self.gone {
            return;
        }
        let now = Instant::now();
        let due = match self.last_draw {
            None => self.question.is_some() || now - self.started >= FIRST_FRAME,
            Some(last) => self.dirty || now - last >= FRAME,
        };
        if due {
            self.draw();
            self.last_draw = Some(now);
            self.dirty = false;
        }
    }

    /// Draws the search screen or the question, with the keys if they're shown
    fn draw(&mut self) {
        let (cols, rows) = terminal_size();
        let width = text_width(cols);
        let max_lines = usize::from(rows.saturating_sub(1)).max(1);

        let mut lines = match &self.question {
            Some((question, _)) => screens::prompt(
                &PromptView {
                    text: &question.text,
                    checker: question.checker,
                    description: &question.description,
                    number: self.asked,
                },
                &self.theme,
                width,
                max_lines,
            ),
            None => {
                let progress = progress::snapshot();
                let view = SearchView {
                    elapsed: timer::elapsed(),
                    timeout: self.info.timeout,
                    progress: &progress,
                    decoders: self.info.decoders,
                    found: self
                        .info
                        .top_results
                        .then(wait_athena_storage::plaintext_result_count),
                    regex: self.info.regex.as_deref(),
                    stopping: self.stopping,
                    frame: self.frame,
                };
                screens::searching(&view, &self.theme, width)
            }
        };
        if self.help {
            let keys = screens::keys(&self.theme, width);
            if lines.len() + keys.len() <= max_lines {
                lines.extend(keys);
            }
        }
        if lines.len() > max_lines {
            // Keep the key hints on the last line
            let last = lines.pop();
            lines.truncate(max_lines.saturating_sub(1));
            lines.extend(last);
        }

        self.frame += 1;
        if let Err(e) = self.region.draw(&lines, cols) {
            self.output_failed(&e);
        }
    }

    /// Stops reading keys, clears the live region and gives the terminal back
    fn close(&mut self) {
        // First, so nothing it has read is lost to whatever reads the terminal next
        self.keys.stop();
        if !self.gone {
            let (cols, _) = terminal_size();
            let _ = self.region.clear(cols);
        }
        let _ = self.region.write_raw(live::SHOW_CURSOR);
        let _ = terminal::disable_raw_mode();
    }

    /// Gives the terminal back and exits straight away, for Ctrl-C and signals
    fn quit(&mut self, code: i32) -> ! {
        self.close();
        LIVE.store(false, Ordering::SeqCst);
        std::process::exit(code);
    }

    /// Ctrl-Z: gives the terminal back and stops, the way the terminal would stop
    /// ciphey if it weren't in raw mode. `fg` carries on where it left off; the time
    /// stopped doesn't count against the time limit.
    #[cfg(unix)]
    fn suspend(&mut self) {
        if self.gone {
            return;
        }
        let (cols, _) = terminal_size();
        let _ = self.region.clear(cols);
        let _ = self.region.write_raw(live::SHOW_CURSOR);
        let _ = terminal::disable_raw_mode();
        signals::suspend();
        if let Err(e) = terminal::enable_raw_mode() {
            self.output_failed(&e);
            return;
        }
        let _ = self.region.write_raw(live::HIDE_CURSOR);
        // Draw the whole region again below whatever the shell printed meanwhile
        self.dirty = true;
    }

    /// Ctrl-Z is just a key on Windows, which has no job control
    #[cfg(not(unix))]
    fn suspend(&mut self) {}
}

/// The terminal's size in columns and rows, or 80×24 if it can't be found
fn terminal_size() -> (u16, u16) {
    terminal::size().unwrap_or((80, 24))
}

/// Columns the screens may use: one less than the terminal, because writing the last
/// column leaves some terminals waiting to wrap and the next line would be misplaced
pub(super) fn text_width(cols: u16) -> usize {
    usize::from(cols.saturating_sub(1)).max(1)
}

/// SIGINT, SIGTERM and SIGHUP. During a session the display thread clears the screen
/// and exits; if it hasn't within half a second, the signal thread exits itself.
/// Outside a session they do what they always did.
#[cfg(unix)]
mod signals {
    use signal_hook::consts::{SIGCONT, SIGHUP, SIGINT, SIGTERM};
    use signal_hook::flag;
    use signal_hook::iterator::Signals;
    use signal_hook::low_level;
    use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
    use std::sync::{Arc, Once, OnceLock};
    use std::thread;
    use std::time::{Duration, Instant};

    /// A signal received during the session, or 0
    static PENDING: AtomicI32 = AtomicI32::new(0);
    /// How long the display thread gets to tidy up and exit after a signal
    const GRACE: Duration = Duration::from_millis(500);
    /// How long [`suspend`] waits for the stop to take effect
    const STOP_WAIT: Duration = Duration::from_millis(250);

    /// Set when SIGCONT arrives, which is how `fg` continues ciphey after Ctrl-Z
    fn continued() -> &'static Arc<AtomicBool> {
        /// Created on first use
        static CONTINUED: OnceLock<Arc<AtomicBool>> = OnceLock::new();
        CONTINUED.get_or_init(|| Arc::new(AtomicBool::new(false)))
    }

    /// Stops ciphey's process group, as Ctrl-Z does when the terminal isn't in raw
    /// mode, and returns once ciphey has been continued (`fg`). Give the terminal
    /// back before calling it.
    ///
    /// The whole group, as the terminal does: stopping ciphey alone would leave a
    /// wrapper such as `timeout` running and the shell waiting for it. When nothing
    /// could continue the group (an orphaned process group, as under a shell without
    /// job control) the kernel discards the stop, and this returns after a moment.
    /// SIGSTOP instead would stop ciphey for ever there.
    pub fn suspend() {
        let continued = continued();
        continued.store(false, Ordering::SeqCst);
        // SAFETY: kill only sends a signal; 0 means our own process group
        unsafe {
            libc::kill(0, libc::SIGTSTP);
        }
        // The group stops a moment after kill returns, once the signal is delivered.
        // Carrying on before that would put the terminal back in raw mode under the
        // shell. Once stopped, this loop resumes after `fg`, and SIGCONT ends it.
        let started = Instant::now();
        while !continued.load(Ordering::SeqCst) && started.elapsed() < STOP_WAIT {
            thread::sleep(Duration::from_millis(5));
        }
    }

    /// Starts the thread that handles the signals, once per process
    pub fn watch() {
        /// The thread is started once
        static ONCE: Once = Once::new();
        ONCE.call_once(|| {
            if let Err(e) = flag::register(SIGCONT, Arc::clone(continued())) {
                log::debug!("Could not watch SIGCONT: {e}");
            }
            let mut signals = match Signals::new([SIGINT, SIGTERM, SIGHUP]) {
                Ok(signals) => signals,
                Err(e) => {
                    log::debug!("Could not watch signals: {e}");
                    return;
                }
            };
            // If the thread can't start, dropping `signals` puts the defaults back
            let spawned = thread::Builder::new()
                .name("ciphey-signals".into())
                .spawn(move || {
                    for signal in signals.forever() {
                        if !super::is_live() {
                            let _ = low_level::emulate_default_handler(signal);
                            continue;
                        }
                        PENDING.store(signal, Ordering::SeqCst);
                        thread::sleep(GRACE);
                        // Still running: the display thread is stuck, so don't wait for it
                        super::restore_terminal_briefly();
                        std::process::exit(128 + signal);
                    }
                });
            if let Err(e) = spawned {
                log::debug!("Could not watch signals: {e}");
            }
        });
    }

    /// The exit code for a signal received during the session, if there was one
    pub fn pending_exit_code() -> Option<i32> {
        match PENDING.load(Ordering::SeqCst) {
            0 => None,
            signal => Some(128 + signal),
        }
    }
}

/// On Windows, raw mode turns Ctrl-C into a key press, which the display thread handles
#[cfg(not(unix))]
mod signals {
    /// Nothing to install
    pub fn watch() {}

    /// Signals aren't watched
    pub fn pending_exit_code() -> Option<i32> {
        None
    }
}
