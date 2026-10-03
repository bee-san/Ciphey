//! `ciphey-mcp`: a [Model Context Protocol](https://modelcontextprotocol.io) server that lets
//! AI assistants call ciphey. It speaks MCP over stdin/stdout and is only built with
//! `--features mcp`. Its tools are `decode` (the whole search), `decode_with` (one decoder,
//! chosen by name), `detect_plaintext` (the plaintext checks) and `list_decoders`.
//!
//! The library keeps its settings (timeout, regex, ...) in a process-wide `OnceCell` that can
//! only be set once, so one process can't run decodes with different settings. Every call
//! except `list_decoders` therefore runs in a short-lived worker: this same executable started
//! with the hidden `--worker` flag (see [`worker`]). A panic (release builds use
//! `panic = "abort"`) or a call that overruns its time limit then only takes down the worker,
//! never the server.

mod decode_with;
mod detect;
mod server;
mod worker;

use std::process::ExitCode;

use clap::Parser;

/// MCP server for ciphey, the automatic decoder.
///
/// Speaks the Model Context Protocol over stdin/stdout. Start it from an MCP client
/// (Claude Desktop, Kiro, ...) instead of running it by hand.
#[derive(Parser)]
#[command(name = "ciphey-mcp", version)]
struct Args {
    /// Internal: run one tool call read from stdin, print the result and exit.
    #[arg(long, hide = true)]
    worker: bool,
}

fn main() -> ExitCode {
    let args = Args::parse();
    if args.worker {
        return worker::run();
    }
    match server::serve_stdio() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            // stdout belongs to the protocol, so diagnostics go to stderr.
            eprintln!("ciphey-mcp: {error}");
            ExitCode::FAILURE
        }
    }
}
