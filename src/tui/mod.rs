//! The live terminal display for the `ciphey` binary.
//!
//! When stdin and stdout are both a terminal, `ciphey` shows a few lines at the bottom
//! of the terminal while it searches: the time used against the time limit, the
//! decoders it is trying and how far it has got. When the human checker wants to
//! know whether a candidate is the plaintext, the question appears there and is
//! answered with one key. At the end the live lines are replaced by the result,
//! printed as ordinary lines so it stays in the scrollback: the plaintext, each
//! decoder with the text it produced, and the checker that recognised it.
//!
//! Pipes, `--plain`, `-v` and API mode get the plain line output from
//! [`crate::cli_pretty_printing`] instead, unchanged so scripts keep working.
//!
//! The search never draws anything. It updates a few atomic counters once per batch
//! of nodes (`searchers::progress`), and the display's own thread reads them at most
//! ten times a second.

/// Styled lines to ANSI text, and the region that is redrawn in place
mod live;
/// Running a search with the live display or plain output
mod run;
/// The screens, as lists of styled lines
mod screens;
/// The UI thread: drawing, keys and questions from the human checker
mod session;
/// Safe, short text for the screens
mod text;
/// Colours and symbols
mod theme;

pub use run::run;
pub(crate) use session::{ask_about_candidate, is_live, live_display_started, Answer};
