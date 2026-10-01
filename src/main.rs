use ciphey::cli::parse_cli_args;
use ciphey::cli_pretty_printing::{program_exiting_successful_decoding, success};
use ciphey::{perform_cracking, CipheyError};

fn main() {
    // Turn CLI arguments into a library object
    let (text, config) = parse_cli_args();
    let api_mode = config.api_mode;
    let result = perform_cracking(&text, config);
    success(&format!(
        "DEBUG: main.rs - Result from perform_cracking: {:?}",
        result.as_ref().map(Option::is_some)
    ));
    match result {
        // TODO: As result have array of CrackResult used,
        // we can print in better way with more info
        Ok(Some(result)) => {
            success(&format!(
                "DEBUG: main.rs - Got successful result with {} decoders in path",
                result.path.len()
            ));
            program_exiting_successful_decoding(result);
        }
        Ok(None) => {
            success("DEBUG: main.rs - Got None result, calling failed_to_decode");
            ciphey::cli_pretty_printing::failed_to_decode()
        }
        Err(CipheyError::Timeout { secs }) => {
            ciphey::cli_pretty_printing::failed_to_decode();
            if !api_mode {
                eprintln!("Timed out after {secs}s, try a longer --cracking-timeout");
            }
        }
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    }
}
