//! End-to-end test for the Hill cracker (<https://github.com/bee-san/Ciphey/issues/1011>)
//! with a crib, as `ciphey -r SHORT` runs it.
//!
//! The issue's example is 20 unspaced letters. The Hill cracker finds its plaintext,
//! `SHORTMESSAGEFORHILLX`, but the English checker doesn't accept it, and with the default
//! checkers the search settles on a Vigenère decryption it does accept,
//! `STNINTETNFEEEATHEETH`. With a crib only the regex checker runs, and it accepts the
//! Hill decryption. The config is global to the process, so this test is in its own file,
//! apart from the default-config ones in `tests/hill_decoder.rs`.

use ciphey::config::Config;
use ciphey::perform_cracking;
use ciphey::storage::database::DB_PATH;

#[test]
fn issue_example_is_cracked_with_a_crib() {
    // With no database path every connection is a fresh in-memory database, so nothing
    // in ~/.ciphey is read or written.
    let _ = DB_PATH.set(None);
    let config = Config {
        timeout: 20,
        regex: Some("SHORT".to_string()),
        ..Config::default()
    };
    let result = perform_cracking("XTPJPUOUCKEGFCURFTYH", config)
        .expect("the search should not fail")
        .expect("the search should find the plaintext");
    assert_eq!(result.text[0], "SHORTMESSAGEFORHILLX");
    let path: Vec<&str> = result.path.iter().map(|step| step.decoder).collect();
    assert_eq!(path, ["Hill"]);
    assert_eq!(result.path[0].key.as_deref(), Some("[[3,3],[2,5]]"));
}
