//! End-to-end test for the Cisco Type 7 decoder (<https://github.com/bee-san/Ciphey/issues/949>)
//! with a crib, as `ciphey -r S3cret` runs it.
//!
//! The issue's example decodes to `Sup3rS3cret!`, which none of Ciphey's checkers takes for
//! plaintext: it isn't English, a known format or a common password. The decoder hands it on
//! to the search unconfirmed, and the default search keeps looking. With a crib only the
//! regex checker runs, and it accepts the password. The config is global to the process, so
//! this test is in its own file, apart from the default-config ones in
//! `tests/cisco_type7_decoder.rs`.

use ciphey::config::Config;
use ciphey::perform_cracking;
use ciphey::storage::database::DB_PATH;

#[test]
fn issue_example_is_cracked_with_a_crib() {
    // With no database path every connection is a fresh in-memory database, so nothing
    // in ~/.ciphey is read or written.
    let _ = DB_PATH.set(None);
    let config = Config {
        regex: Some("S3cret".to_string()),
        ..Config::default()
    };
    let result = perform_cracking("073C345C1D1B2A5614000E1845", config)
        .expect("the search should not fail")
        .expect("the search should find the plaintext");
    assert_eq!(result.text[0], "Sup3rS3cret!");
    let path: Vec<&str> = result.path.iter().map(|step| step.decoder).collect();
    assert_eq!(path, ["Cisco Type 7"]);
}
