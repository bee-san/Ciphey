//! End-to-end tests for the Base92 decoder (<https://github.com/bee-san/Ciphey/issues/927>):
//! the whole search, as the CLI runs it, has to find the plaintext through Base92.
//!
//! Every input was made with `base92.encode` from the `base92` 2.0.0 package on PyPI.
//! Without the Base92 decoder the search returns a wrong answer for each of them
//! (Vigenere, railfence → rot47 or rot47 → Vigenere false positives).

use ciphey::config::Config;
use ciphey::perform_cracking;
use ciphey::storage::database::DB_PATH;
use ciphey::DecoderResult;

/// Runs the whole search on `text` and returns what it found.
fn crack(text: &str) -> DecoderResult {
    // With no database path every connection is a fresh in-memory database, so the search
    // doesn't read the cache in ~/.ciphey (an answer cached by another build would stand
    // in for the search under test) and doesn't write to it.
    let _ = DB_PATH.set(None);
    // Each search takes 0.5-1.2 s in a debug build; the longer timeout is headroom for
    // slow CI runners. The config is process-wide, so every test uses the same one.
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

/// The bench suite's medium plaintext.
const MEDIUM: &str =
    "Meet me at the old lighthouse after midnight and bring the map, the key and a torch.";

#[test]
fn quick_brown_fox_is_cracked() {
    let result = crack("?a&JO[d]VmnA*]UqK}gxX'e.$@uWBEWlI3j{iP6LQ78l*UmM-ESuI");
    assert_eq!(
        result.text[0],
        "The quick brown fox jumps over the lazy dog"
    );
    assert_eq!(path(&result), ["Base92"]);
}

#[test]
fn bench_medium_text_is_cracked() {
    // Without Base92 the search settles on a railfence → rot47 string that LemmeKnow
    // matches
    let result = crack("=5^dl?57>ogS$p[GEU&taJ'bhnke,79eK=H4OSb$:es:+Z<HHn1kZu'b*&iH*]UkHms3ld3j$FgR%s#;Fc[a_%e>$.p\\$p%1JxvkSl**");
    assert_eq!(result.text[0], MEDIUM);
    assert_eq!(path(&result), ["Base92"]);
}

#[test]
fn base92_inside_base64_is_cracked() {
    // Python 3: base64.b64encode(base92.encode(MEDIUM))
    let result = crack("PTVeZGw/NTc+b2dTJHBbR0VVJnRhSidiaG5rZSw3OWVLPUg0T1NiJDplczorWjxISG4xa1p1J2IqJmlIKl1Va0htczNsZDNqJEZnUiVzIztGY1thXyVlPiQucFwkcCUxSnh2a1NsKio=");
    assert_eq!(result.text[0], MEDIUM);
    assert_eq!(path(&result), ["Base64", "Base92"]);
}

#[test]
fn base92_twice_is_cracked() {
    // base92.encode(base92.encode(b"The quick brown fox jumps over the lazy dog")). The
    // search only runs a decoder twice in a row if it is in `STACKABLE`
    // (src/searchers/helper_functions.rs).
    let result = crack("8<.x0O_):T^jB4%;Bm_820b4Py=c<U-zK9ta)Pc&UhmsoiOY<o/_rC)J@RX;>XXf;_");
    assert_eq!(
        result.text[0],
        "The quick brown fox jumps over the lazy dog"
    );
    assert_eq!(path(&result), ["Base92", "Base92"]);
}
