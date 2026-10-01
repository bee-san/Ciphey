// First-run configuration module
mod first_run;
pub use first_run::run_first_time_setup;

use std::{fs::File, io::Read};

use crate::cli_pretty_printing;
use crate::cli_pretty_printing::panic_failure_both_input_and_fail_provided;
use crate::config::{get_config_file_into_struct, load_wordlist, Config};
/// This doc string acts as a help message when the uses run '--help' in CLI mode
/// as do all doc strings on fields
use clap::Parser;
use log::trace;

/// The struct for Clap CLI arguments
#[derive(Parser)]
#[command(author = "Bee <bee@skerritt.blog>", about, long_about = None)]
pub struct Opts {
    /// Some input. Because this isn't an Option<T> it's required to be used
    #[arg(short, long)]
    text: Option<String>,

    /// A level of verbosity, and can be used multiple times
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Turn off human checker, perfect for APIs where you don't want input from humans
    #[arg(short, long)]
    disable_human_checker: bool,

    /// Set timeout, if it is not decrypted after this time, it will return an error.
    /// Default is 5 seconds.
    // If we want to call it `timeout`, the short argument contends with the one for Text `ciphey -t`.
    // I propose we just call it `cracking_timeout`.
    #[arg(short, long)]
    cracking_timeout: Option<u32>,
    /// Run in API mode, this will return the results instead of printing them.
    /// Default is false
    #[arg(short, long)]
    api_mode: Option<bool>,
    /// Opens a file for decoding
    /// Use instead of `--text`
    #[arg(short, long)]
    file: Option<String>,
    /// If you have a crib (you know a piece of information in the plaintext)
    /// Or you want to create a custom regex to check against, you can use the Regex checker below.
    /// This turns off other checkers (English, LemmeKnow)
    #[arg(short, long)]
    regex: Option<String>,
    /// Path to a wordlist file containing newline-separated words
    /// The checker will match input against these words exactly
    /// Takes precedence over config file if both specify a wordlist
    #[arg(
        long,
        help = "Path to a wordlist file with newline-separated words for exact matching"
    )]
    wordlist: Option<String>,
    /// Show all potential plaintexts found instead of exiting after the first one
    /// Automatically disables the human checker
    #[arg(long)]
    top_results: bool,
    /// Enables enhanced plaintext detection with BERT model.
    #[arg(long)]
    enable_enhanced_detection: bool,
}

/// Parse CLI Arguments turns a Clap Opts struct, seen above
/// Into a library Struct for use within the program
/// The library struct can be found in the [config](../config) folder.
/// # Panics
/// This function can panic when it gets both a file and text input at the same time.
pub fn parse_cli_args() -> (String, Config) {
    let mut opts: Opts = Opts::parse();
    let min_log_level = match opts.verbose {
        0 => "Warn",
        1 => "Info",
        2 => "Debug",
        _ => "Trace",
    };
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, min_log_level),
    );

    let input_text: String = match (opts.file.take(), opts.text.take()) {
        (Some(_), Some(_)) => {
            panic_failure_both_input_and_fail_provided();
            unreachable!("panic helper should terminate the process");
        }
        (Some(file), None) => read_and_parse_file(file),
        (None, Some(text)) => text,
        (None, None) => {
            panic!("Error. No input was provided. Please use ciphey --help")
        }
    };

    trace!("Program was called with CLI 😉");
    trace!("Parsed the arguments");
    trace!("The inputted text is {}", input_text);

    cli_args_into_config_struct(opts, input_text)
}

/// When the CLI is called with `-f` to open a file
/// this function opens it
pub fn read_and_parse_file(file_path: String) -> String {
    let mut file = File::open(&file_path).unwrap_or_else(|err| {
        eprintln!("Error: Cannot open file '{}': {}", file_path, err);
        std::process::exit(1);
    });

    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap_or_else(|err| {
        eprintln!("Error: Cannot read file '{}': {}", file_path, err);
        std::process::exit(1);
    });
    // We can just put the file into the `Opts.text` and the program will work as normal
    // On Unix systems a line is defined as "\n{text}\n"
    // https://stackoverflow.com/a/729795
    // Which means if a user creates a file on Unix, it'll have a new line appended.
    // This is probably not what they wanted to decode (it is not what I wanted) so we are removing them
    contents.trim_end_matches(['\n', '\r']).to_owned()
}

/// Turns our CLI arguments into a config struct
fn cli_args_into_config_struct(opts: Opts, text: String) -> (String, Config) {
    // Get configuration from file first
    let mut config = get_config_file_into_struct();

    // Update config with CLI arguments when they're explicitly set
    config.verbose = opts.verbose;
    config.human_checker_on = !opts.disable_human_checker;

    if let Some(timeout) = opts.cracking_timeout {
        config.timeout = timeout;
    }

    if let Some(api_mode) = opts.api_mode {
        config.api_mode = api_mode;
    }

    if let Some(regex) = opts.regex {
        config.regex = Some(regex);
    }

    // Handle wordlist if provided via CLI (takes precedence over config file)
    if let Some(wordlist_path) = opts.wordlist {
        config.wordlist_path = Some(wordlist_path.clone());

        // Load the wordlist here in the CLI layer
        match load_wordlist(&wordlist_path) {
            Ok(wordlist) => {
                config.wordlist = Some(wordlist);
            }
            Err(e) => {
                // Critical error - exit if wordlist is specified but can't be loaded
                eprintln!("Can't load wordlist at '{}': {}", wordlist_path, e);
                std::process::exit(1);
            }
        }
    }

    // Set top_results mode if the flag is present
    config.top_results = opts.top_results;

    // If top_results is enabled, automatically disable the human checker
    if config.top_results {
        config.human_checker_on = false;
    }

    // Handle enhanced detection if enabled via CLI
    if opts.enable_enhanced_detection {
        // Simply enable enhanced detection without downloading a model
        // since the current version of gibberish-or-not doesn't support model downloading
        config.enhanced_detection = true;
        eprintln!(
            "{}",
            cli_pretty_printing::statement("Enhanced detection enabled.", None)
        );
    }

    (text, config)
}
