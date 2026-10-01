//! `ciphey-mcp`: a [Model Context Protocol](https://modelcontextprotocol.io) server that lets
//! AI assistants call ciphey. It speaks MCP over stdin/stdout and is only built with
//! `--features mcp`.
//!
//! The library keeps its settings (timeout, regex, ...) in a process-wide `OnceCell` that can
//! only be set once, so one process can't run decodes with different settings. Every `decode`
//! call therefore runs in a short-lived worker: this same executable started with the hidden
//! `--worker` flag (see [`worker`]). A panic (release builds use `panic = "abort"`) or a search
//! that overruns its timeout then only takes down the worker, never the server.

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
    /// Internal: run one decode request read from stdin, print the result and exit.
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
