//! End-to-end test for the JSFuck decoder (<https://github.com/bee-san/Ciphey/issues/987>)
//! with a crib, as `ciphey -r '^fun$'` runs it.
//!
//! The issue's example decodes to `fun`, which the default checkers don't accept as
//! plaintext: a three-letter word isn't enough English, and without a crib the search
//! settles on a railfence -> rot47 reading LemmeKnow takes for something. With a crib only
//! the regex checker runs. The config is global to the process, so this test is in its own
//! file, apart from the default-config ones in `tests/jsfuck_decoder.rs`.

use ciphey::config::Config;
use ciphey::perform_cracking;
use ciphey::storage::database::DB_PATH;

#[test]
fn issue_example_is_cracked_with_a_crib() {
    // With no database path every connection is a fresh in-memory database, so nothing
    // in ~/.ciphey is read or written.
    let _ = DB_PATH.set(None);
    ciphey::reset_decoder_stats();
    let config = Config {
        timeout: 10,
        regex: Some("^fun$".to_string()),
        ..Config::default()
    };
    // "false"[0] + "undefined"[0] + "undefined"[1]. On master the search timed out.
    let result = perform_cracking("(![]+[])[+[]]+([][[]]+[])[+[]]+([][[]]+[])[+!+[]]", config)
        .expect("the search doesn't fail")
        .expect("the search finds the plaintext");
    assert_eq!(result.text[0], "fun");
    let path: Vec<&str> = result.path.iter().map(|step| step.decoder).collect();
    assert_eq!(path, ["JSFuck"]);
}
