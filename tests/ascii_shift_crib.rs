//! End-to-end test for the ASCII shift cracker (<https://github.com/bee-san/Ciphey/issues/994>)
//! with a crib, as `ciphey -r 'encryptCTF\{'` runs it.
//!
//! encryptCTF 2019's "Julius" is Base64 of a flag with 0x18 added to every byte. The bytes
//! aren't UTF-8, so the Base64 decoder drops them and the cracker reads the Base64 itself. The
//! flag reads too little like English for the default checkers to take it, and LemmeKnow only
//! knows `flag{}`, `ctf{}` and `ctfa{}` flags, so without a crib the search accepts something
//! else first (#1031). With one, only the regex checker runs and the flag is found in the first
//! step. The config is global to the process, so this test is in its own file, apart from the
//! default-config ones in `tests/ascii_shift_decoder.rs`.

use ciphey::config::Config;
use ciphey::perform_cracking;
use ciphey::storage::database::DB_PATH;

#[test]
fn julius_with_a_crib() {
    // https://raw.githubusercontent.com/zst-ctf/encryptctf-2019-writeups/master/Solved/Julius/README.md
    let ciphertext = "fYZ7ipGIjFtsXpNLbHdPbXdaam1PS1c5lQ";
    // With no database path every connection is a fresh in-memory database, so nothing in
    // ~/.ciphey is read or written.
    let _ = DB_PATH.set(None);
    let config = Config {
        timeout: 30,
        regex: Some(r"encryptCTF\{".to_string()),
        ..Config::default()
    };
    let result = perform_cracking(ciphertext, config)
        .unwrap_or_else(|error| panic!("searching {ciphertext:?} failed: {error}"))
        .unwrap_or_else(|| panic!("the search found nothing for {ciphertext:?}"));
    assert_eq!(result.text[0], "encryptCTF{3T_7U_BRU73?!}");
    let path: Vec<&str> = result.path.iter().map(|step| step.decoder).collect();
    assert_eq!(path, ["ASCII shift"]);
    assert_eq!(result.path[0].key.as_deref(), Some("24 (mod 256)"));
}
