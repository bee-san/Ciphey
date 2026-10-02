use ciphey::cli::parse_cli_args;

fn main() {
    // Turn CLI arguments into a library object
    let (text, config) = parse_cli_args();
    // Search, showing the live display in a terminal and plain lines elsewhere
    let code = ciphey::tui::run(&text, config);
    if code != 0 {
        std::process::exit(code);
    }
}
