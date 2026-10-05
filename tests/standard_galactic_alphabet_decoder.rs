//! End-to-end tests for the Standard Galactic Alphabet decoder
//! (<https://github.com/bee-san/Ciphey/issues/968>): the whole search, as the CLI runs it,
//! has to find the plaintext through the Standard Galactic Alphabet.
//!
//! The vectors are from the issue's implementation plan: the issue example uses Python
//! Ciphey's table (cipheydists), the sentence is real output of LingoJam's translator
//! (<https://lingojam.com/StandardGalacticAlphabet>), and the Base64 is Python 3's
//! `base64.b64encode` of the UTF-8. Without this decoder the search settles on false
//! positives for all of them: `V.cF` (rot47 → Base91 → Reverse → rot47) for the issue
//! example, `rEv(s` (rot47 → Hexadecimal → atbash → rot47) for the LingoJam sentence.
//!
//! The tests run one at a time: every search uses all cores, and side by side on a slow
//! CI runner they would slow each other down.

use ciphey::config::Config;
use ciphey::perform_cracking;
use ciphey::storage::database::DB_PATH;
use ciphey::DecoderResult;
use serial_test::serial;

/// The plaintext of the bench fixtures
const MEDIUM: &str =
    "Meet me at the old lighthouse after midnight and bring the map, the key and a torch.";

/// Runs the whole search on `text` and returns what it found.
fn crack(text: &str) -> DecoderResult {
    // With no database path every connection is a fresh in-memory database, so the search
    // doesn't read the cache in ~/.ciphey (an answer cached by another build would stand
    // in for the search under test) and doesn't write to it.
    let _ = DB_PATH.set(None);
    // The decoder statistics the search uses in its edge costs live as long as the
    // process. Clearing them makes every search explore like a fresh `ciphey` run, so
    // the result doesn't depend on which tests ran before.
    ciphey::reset_decoder_stats();
    // The default config apart from the timeout: `cargo test` builds without
    // optimisations and CI runners have few cores. The config is global to the process,
    // so every test here gets the same one.
    let config = Config {
        timeout: 30,
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
#[serial]
fn issue_example_is_cracked() {
    let result = crack("⍑ᒷꖎꖎ𝙹 ∴𝙹∷ꖎ↸");
    assert_eq!(result.text[0], "hello world");
    assert_eq!(path(&result), ["Standard Galactic Alphabet"]);
}

#[test]
#[serial]
fn lingojam_sentence_is_cracked() {
    let result = crack("Sꖎ╎↸ᒷ ℸ ̣ ⍑ᒷ ʖ╎ꖎꖎ ʖᒷℸ ̣ ∴ᒷᒷリ ℸ ̣ ⍑ᒷ ℸ ̣ ∴𝙹 ꖎᒷᔑ⍊ᒷᓭ. T⍑ᒷ ᓭ⍑ᔑꖌ|| ʖᔑ∷リ ⎓ᒷꖎꖎ ∴╎ℸ ̣ ⍑ ᔑ ꖎ𝙹⚍↸ ᓵ∷ᔑᓭ⍑.");
    assert_eq!(
        result.text[0],
        "Slide the bill between the two leaves. The shaky barn fell with a loud crash."
    );
    assert_eq!(path(&result), ["Standard Galactic Alphabet"]);
}

#[test]
#[serial]
fn lingojam_fox_pangram_is_cracked() {
    // p, t, x and y all in their multi-character LingoJam forms
    let result = crack("ℸ ̣ ⍑ᒷ ᑑ⚍╎ᓵꖌ ʖ∷𝙹∴リ ⎓𝙹 ̇/ ⋮⚍ᒲ!¡ᓭ 𝙹⍊ᒷ∷ ℸ ̣ ⍑ᒷ ꖎᔑ⨅|| ↸𝙹⊣");
    assert_eq!(
        result.text[0],
        "the quick brown fox jumps over the lazy dog"
    );
    assert_eq!(path(&result), ["Standard Galactic Alphabet"]);
}

#[test]
#[serial]
fn sentence_is_cracked() {
    // The bench `medium` plaintext in LingoJam's forms. On master the search returned the
    // Password Checker's `222333` for it.
    let result = crack("Mᒷᒷℸ ̣  ᒲᒷ ᔑℸ ̣  ℸ ̣ ⍑ᒷ 𝙹ꖎ↸ ꖎ╎⊣⍑ℸ ̣ ⍑𝙹⚍ᓭᒷ ᔑ⎓ℸ ̣ ᒷ∷ ᒲ╎↸リ╎⊣⍑ℸ ̣  ᔑリ↸ ʖ∷╎リ⊣ ℸ ̣ ⍑ᒷ ᒲᔑ!¡, ℸ ̣ ⍑ᒷ ꖌᒷ|| ᔑリ↸ ᔑ ℸ ̣ 𝙹∷ᓵ⍑.");
    assert_eq!(result.text[0], MEDIUM);
    assert_eq!(path(&result), ["Standard Galactic Alphabet"]);
}

#[test]
#[serial]
fn galactic_inside_base64_is_cracked() {
    // base64.b64encode of the text in `sentence_is_cracked`, as UTF-8
    let result = crack("TeGSt+GSt+KEuCDMoyAg4ZKy4ZK3IOGUkeKEuCDMoyAg4oS4IMyjIOKNkeGStyDwnZm56paO4oa4IOqWjuKVjuKKo+KNkeKEuCDMoyDijZHwnZm54pqN4ZOt4ZK3IOGUkeKOk+KEuCDMoyDhkrfiiLcg4ZKy4pWO4oa444Oq4pWO4oqj4o2R4oS4IMyjICDhlJHjg6rihrggypbiiLfilY7jg6riiqMg4oS4IMyjIOKNkeGStyDhkrLhlJEhwqEsIOKEuCDMoyDijZHhkrcg6paM4ZK3fHwg4ZSR44Oq4oa4IOGUkSDihLggzKMg8J2ZueKIt+GTteKNkS4=");
    assert_eq!(result.text[0], MEDIUM);
    assert_eq!(path(&result), ["Base64", "Standard Galactic Alphabet"]);
}
