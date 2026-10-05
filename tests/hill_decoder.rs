//! End-to-end tests for the Hill cracker (<https://github.com/bee-san/Ciphey/issues/1011>):
//! the whole search, as the CLI runs it, has to find the plaintext through Hill.
//!
//! Without the Hill cracker the search returns a wrong answer for these inputs: Vigenère
//! gibberish for the 2×2 vector, `Reverse → Vigenere` gibberish for the 3×3 one, and
//! `Base64 → Vigenere` gibberish for the Base64 one.

use ciphey::config::Config;
use ciphey::perform_cracking;
use ciphey::storage::database::DB_PATH;
use ciphey::DecoderResult;

/// The letters of `Meet me at the old lighthouse after midnight and bring the map, the
/// key and a torch.`
const LIGHTHOUSE: &str = "MEETMEATTHEOLDLIGHTHOUSEAFTERMIDNIGHTANDBRINGTHEMAPTHEKEYANDATORCH";

/// Runs the whole search on `text` and returns what it found.
fn crack(text: &str) -> DecoderResult {
    // With no database path every connection is a fresh in-memory database, so the search
    // doesn't read the cache in ~/.ciphey (an answer cached by another build would stand
    // in for the search under test) and doesn't write to it.
    let _ = DB_PATH.set(None);
    // The longer timeout is headroom for slow CI runners. The config is process-wide, so
    // every test uses the same one.
    let config = Config {
        timeout: 20,
        ..Config::default()
    };
    perform_cracking(text, config)
        .unwrap_or_else(|error| panic!("searching {text:?} failed: {error}"))
        .unwrap_or_else(|| panic!("the search found nothing for {text:?}"))
}

/// The names of the decoders the search used, in order.
fn path(result: &DecoderResult) -> Vec<&str> {
    result.path.iter().map(|step| step.decoder).collect()
}

#[test]
fn hill_2x2_is_cracked() {
    // LIGHTHOUSE encrypted with Wikipedia's key [[3,3],[2,5]]
    let result = crack("WSRZWSFRAVCAQLFKNVAVYYOEPZRGJQHFLONVFMWPCJLDXDHIKYYVHIQOUWWPFRPJBN");
    assert_eq!(result.text[0], LIGHTHOUSE);
    assert_eq!(path(&result), ["Hill"]);
    assert_eq!(result.path[0].key.as_deref(), Some("[[3,3],[2,5]]"));
}

#[test]
fn hill_3x3_is_cracked() {
    // LIGHTHOUSE encrypted with Wikipedia's 3×3 key GYBNQKURP
    let result = crack("QAEQLUHAKWJCTPURKDKFHKQMJKGCCDDWQRKDXNDHRUCIDAJNJUXAJNYSEDEGCCNBLL");
    assert_eq!(result.text[0], LIGHTHOUSE);
    assert_eq!(path(&result), ["Hill"]);
    assert_eq!(
        result.path[0].key.as_deref(),
        Some("[[6,24,1],[13,16,10],[20,17,15]]")
    );
}

#[test]
fn hill_inside_base64_is_cracked() {
    // Python 3: base64.b64encode(b"WSRZWSFRAVCAQLFKNVAVYYOEPZRGJQHFLONVFMWPCJLDXDHIKYYVHIQOUWWPFRPJBN")
    let result = crack(
        "V1NSWldTRlJBVkNBUUxGS05WQVZZWU9FUFpSR0pRSEZMT05WRk1XUENKTERYREhJS1lZVkhJUU9VV1dQRlJQSkJO",
    );
    assert_eq!(result.text[0], LIGHTHOUSE);
    assert_eq!(path(&result), ["Base64", "Hill"]);
}

#[test]
fn ctf_flag_is_cracked() {
    // JerseyCTF III "jack-and-jill" (https://ctftime.org/writeup/36829). The challenge gave
    // the key, but 30 letters are enough to find it. The letters keep the ciphertext's
    // case, as the submitted flag jctf{hiTHEREwelcomeTOlinearALGEBRAZ} did.
    let result = crack("pgQVJFCohpccuyBSbwxcxpVZCAATRT");
    assert_eq!(result.text[0], "hiTHEREwelcomeTOlinearALGEBRAZ");
    assert_eq!(path(&result), ["Hill"]);
    assert_eq!(result.path[0].key.as_deref(), Some("[[3,9],[4,7]]"));
}

#[test]
fn spaced_hill_ciphertext_keeps_its_layout() {
    // The bench plaintext encrypted with [[3,3],[2,5]], keeping its case, spaces and
    // punctuation
    let result = crack(
        "Wsrz ws fr avc aql fknvavyyoe pzrgj qhflonvf mwp cjldx dhi kyy, vhi qou wwp f rpjbn.",
    );
    assert_eq!(
        result.text[0],
        "Meet me at the old lighthouse after midnight and bring the map, the key and a torch."
    );
    assert_eq!(path(&result), ["Hill"]);
}
