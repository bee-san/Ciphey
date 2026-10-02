//! Running a search for the `ciphey` binary: with the live display when stdin and
//! stdout are a terminal, with the plain line output everywhere else.

use super::live;
use super::screens::{self, Ending, FailureView, SuccessView};
use super::session::{self, SearchInfo, Session};
use super::text;
use super::theme::Theme;
use crate::checkers::checker_type::{Check, Checker};
use crate::checkers::lemmeknow_checker::LemmeKnow;
use crate::cli_pretty_printing::{
    ansi_supported, failed_to_decode, invisible_char_ratio, program_exiting_successful_decoding,
    top_results_file, INVISIBLE_CHARS_DETECTION_RATIO,
};
use crate::config::Config;
use crate::searchers::progress;
use crate::storage::wait_athena_storage;
use crate::{perform_cracking, CipheyError};
use crossterm::terminal;
use ratatui::text::{Line, Span};
use std::env;
use std::io::{self, IsTerminal, Write};
use std::time::{Duration, Instant};

/// Searches for the plaintext of `text` and prints what was found, the way the
/// `ciphey` binary does. Returns the process exit code.
///
/// In a terminal (stdin and stdout both a terminal, no `--plain`, `-v` or API mode,
/// `TERM` not `dumb`) the search shows the live display. Otherwise the output is the
/// same plain lines as before, so scripts that read it keep working.
pub fn run(text: &str, config: Config) -> i32 {
    if !live_display_wanted(&config) {
        return run_plain(text, config);
    }

    let theme = Theme::detect(&config.colourscheme);
    let info = SearchInfo {
        timeout: config.timeout,
        top_results: config.top_results,
        regex: config.regex.clone(),
        decoders: crate::filtration_system::get_all_decoders()
            .components
            .len(),
    };
    let session = match Session::start(theme.clone(), info) {
        Ok(session) => session,
        Err(e) => {
            log::debug!("Could not start the live display: {e}");
            return run_plain(text, config);
        }
    };
    let regex = config.regex.clone();
    let timeout = config.timeout;
    let top_results = config.top_results;

    let started = Instant::now();
    let result = perform_cracking(text, config);
    let wall_time = started.elapsed();
    let report = session.finish();

    let elapsed = wall_time.saturating_sub(report.answering);
    let progress = progress::snapshot();
    let width = output_width();
    let failure = |ending: Ending| {
        let ending = if report.stopped {
            Ending::Stopped
        } else {
            ending
        };
        let view = FailureView {
            ending,
            elapsed,
            timeout,
            progress: &progress,
            rejected: report.rejected,
            regex: regex.as_deref(),
        };
        print(&screens::failure(&view, &theme, width));
    };

    match result {
        // Top results mode lists what it collected, unless the input was the plaintext
        // already and nothing was searched
        Ok(found)
            if top_results
                && !found
                    .as_ref()
                    .is_some_and(|found| text::is_input_plaintext(&found.path)) =>
        {
            show_top_results(elapsed, &theme, width)
        }
        Ok(Some(found)) => {
            let view = SuccessView {
                result: &found,
                elapsed,
                progress: &progress,
                confirmed: report.accepted,
                recognised_as: None,
                regex: regex.as_deref(),
                saved_to: None,
            };
            show_success(view, &theme, width);
        }
        Ok(None) => failure(Ending::Exhausted),
        Err(CipheyError::Timeout { .. }) => failure(Ending::TimedOut),
        Err(e) => {
            eprintln!("Error: {e}");
            return 1;
        }
    }
    0
}

/// Whether to use the live display rather than plain lines
fn live_display_wanted(config: &Config) -> bool {
    !config.api_mode
        // -v prints log lines on stderr, which would tear through the live region
        && config.verbose == 0
        && !config.plain_output
        && io::stdin().is_terminal()
        && io::stdout().is_terminal()
        && in_foreground()
        && env::var_os("TERM").is_none_or(|term| term != "dumb")
        && terminal::size().is_ok_and(|(cols, rows)| cols >= 20 && rows >= 6)
        // Needed to move the cursor, even with NO_COLOR
        && ansi_supported()
}

/// Whether ciphey owns the terminal. In the background (`ciphey ... &`, or under
/// `timeout` without `--foreground`) it can't read keys or change the terminal's
/// mode, so it prints plain lines as it always has.
#[cfg(unix)]
fn in_foreground() -> bool {
    // SAFETY: both only read process state; fd 0 is stdin, which is a terminal here
    unsafe { libc::tcgetpgrp(0) == libc::getpgrp() }
}

/// Windows consoles have no background jobs
#[cfg(not(unix))]
fn in_foreground() -> bool {
    true
}

/// The plain line output, exactly as `ciphey` printed it before the live display
fn run_plain(text: &str, config: Config) -> i32 {
    let api_mode = config.api_mode;
    match perform_cracking(text, config) {
        Ok(Some(result)) => program_exiting_successful_decoding(result),
        Ok(None) => failed_to_decode(),
        Err(CipheyError::Timeout { secs }) => {
            failed_to_decode();
            if !api_mode {
                eprintln!("Timed out after {secs}s, try a longer --cracking-timeout");
            }
        }
        Err(e) => {
            eprintln!("Error: {e}");
            return 1;
        }
    }
    0
}

/// Columns the printed screens may use
fn output_width() -> usize {
    session::text_width(terminal::size().map_or(80, |(cols, _)| cols))
}

/// Prints lines to stdout
fn print(lines: &[Line<'_>]) {
    let _ = live::print_lines(&mut io::stdout(), lines);
}

/// Asks a yes/no question on one line, as ciphey always has after the search; the
/// answer is no unless it starts with y
fn ask_yes_no(question: &str, theme: &Theme) -> bool {
    let line = Line::from(vec![
        Span::styled(format!("{} {question}", theme.glyphs.ask), theme.question),
        Span::styled(" (y/N) ", theme.muted),
    ]);
    print!("{}", live::to_ansi(&line));
    let _ = io::stdout().flush();
    read_line().to_ascii_lowercase().starts_with('y')
}

/// Asks where to save something, defaulting to `~/ciphey_text.txt`
fn ask_file_name(theme: &Theme) -> String {
    let default = format!("{}/ciphey_text.txt", env::var("HOME").unwrap_or_default());
    let line = Line::from(vec![
        Span::styled(format!("{} File name", theme.glyphs.ask), theme.question),
        Span::styled(
            format!(" (default {}): ", text::sanitize(&default)),
            theme.muted,
        ),
    ]);
    print!("{}", live::to_ansi(&line));
    let _ = io::stdout().flush();
    let name = read_line();
    if name.is_empty() {
        default
    } else {
        name
    }
}

/// One line from stdin without the newline, or nothing at the end of input
fn read_line() -> String {
    let mut line = String::new();
    let _ = io::stdin().read_line(&mut line);
    line.trim().to_string()
}

/// Prints a found plaintext. Plaintext that is mostly invisible characters can be
/// saved to a file instead, as before.
fn show_success(view: SuccessView<'_>, theme: &Theme, width: usize) {
    let plaintext = view.result.text.first().cloned().unwrap_or_default();

    // The finished result only names the checker. What LemmeKnow recognised is worth
    // showing, so ask it again; this runs once, after the search.
    let recognised = match view.result.path.last() {
        Some(last) if last.checker_name == "LemmeKnow Checker" => {
            let check = Checker::<LemmeKnow>::new().check(&plaintext);
            Some(check.description).filter(|d| !d.is_empty())
        }
        _ => None,
    };

    let invisible = invisible_char_ratio(&plaintext);
    let mut saved_to = None;
    if invisible > INVISIBLE_CHARS_DETECTION_RATIO {
        let question = format!(
            "{:.0}% of the plaintext is invisible characters. Save it to a file instead?",
            invisible * 100.0
        );
        if ask_yes_no(&question, theme) {
            let path = ask_file_name(theme);
            match std::fs::write(&path, &plaintext) {
                Ok(()) => saved_to = Some(path),
                Err(e) => print(&[Line::from(Span::styled(
                    format!(
                        "{} Couldn't write {}: {e}",
                        theme.glyphs.failed,
                        text::sanitize(&path)
                    ),
                    theme.failure,
                ))]),
            }
        }
    }

    let view = SuccessView {
        recognised_as: recognised.as_deref(),
        saved_to: saved_to.as_deref(),
        ..view
    };
    print(&screens::success(&view, theme, width));
}

/// Lists everything top results mode collected, or saves it to a file if the user
/// prefers when there is a lot of it, as before
fn show_top_results(elapsed: Duration, theme: &Theme, width: usize) {
    let results = wait_athena_storage::get_plaintext_results();
    if results.len() > 10 {
        let question = format!(
            "Save all {} to a file instead of listing them?",
            text::thousands(results.len() as u64)
        );
        if ask_yes_no(&question, theme) {
            let path = ask_file_name(theme);
            let saved = match std::fs::write(&path, top_results_file(&results)) {
                Ok(()) => Span::styled(
                    format!(
                        "{} Saved {} possible plaintexts to {}",
                        theme.glyphs.found,
                        text::thousands(results.len() as u64),
                        text::sanitize(&path)
                    ),
                    theme.success,
                ),
                Err(e) => Span::styled(
                    format!(
                        "{} Couldn't write {}: {e}",
                        theme.glyphs.failed,
                        text::sanitize(&path)
                    ),
                    theme.failure,
                ),
            };
            print(&[Line::from(saved)]);
            return;
        }
    }
    print(&screens::top_results(&results, elapsed, theme, width));
}
