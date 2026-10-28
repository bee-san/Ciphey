//! End-to-end test for the Vigenère autokey cracker
//! (<https://github.com/bee-san/Ciphey/issues/1003>) with a crib, as
//! `ciphey -r 'utflag\{'` runs it, on UTCTF 2025's "Autokey Cipher"
//! (<https://raw.githubusercontent.com/utisss/UTCTF-25/main/crypto-autokey/challenge.yml>).
//!
//! The cracker finds the primer, but Athena doesn't take the flag for English at the
//! sensitivities the cracker checks at: its words are joined by underscores. A crib on the
//! flag format matches it. The config is global to the process, so this test is in its
//! own file.

use ciphey::config::Config;
use ciphey::perform_cracking;
use ciphey::storage::database::DB_PATH;

#[test]
fn utctf_flag_is_cracked_with_a_crib() {
    // With no database path every connection is a fresh in-memory database, so nothing
    // in ~/.ciphey is read or written.
    let _ = DB_PATH.set(None);
    let config = Config {
        timeout: 10,
        regex: Some(r"utflag\{".to_string()),
        ..Config::default()
    };
    let result = perform_cracking(
        "lpqwma{rws_ywpqaauad_rrqfcfkq_wuey_ifwo_xlkvxawjh_pkbgrzf}",
        config,
    )
    .expect("the search finishes before the timeout")
    .expect("the search finds the flag");
    assert_eq!(
        result.text[0],
        "utflag{why_frequency_analysis_when_know_beginning_letters}"
    );
    let path: Vec<&str> = result.path.iter().map(|step| step.decoder).collect();
    assert_eq!(path, ["Vigenere Autokey"]);
    assert_eq!(result.path[0].key.as_deref(), Some("RWLLMUVP"));
}
