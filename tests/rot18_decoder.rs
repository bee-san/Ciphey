//! End-to-end tests for the ROT5 / ROT18 cracker
//! (<https://github.com/bee-san/Ciphey/issues/992>): the whole search, as the CLI runs it,
//! has to find the plaintext through rot18, with the digits rotated back. On master
//! (2256b4c6) Vigenere or Caesar answered first with the letters decrypted and the digits
//! still rotated (`The meeting is at 6785 in room 959 ...`).
//!
//! The vectors were made with CyberChef 10.24 (`ROT13` on the letters with amount k, then
//! `ROT13` with "Rotate numbers" only, amount 5) and independently with a Python 3 `rot()`,
//! and decrypted back to the plaintext. The last two tests check the other side: ROT13 text
//! with ordinary numbers in it is still Caesar's, with its digits left alone.
//!
//! The tests run one at a time: every search uses all cores, and side by side on a slow
//! CI runner they would slow each other down.

use ciphey::config::Config;
use ciphey::perform_cracking;
use ciphey::storage::database::DB_PATH;
use ciphey::DecoderResult;
use serial_test::serial;

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
    // optimisations, and CI runners have few cores. The config is global to the process,
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

/// The key the rot18 step reported.
fn rot18_key(result: &DecoderResult) -> Option<&str> {
    result
        .path
        .iter()
        .find(|step| step.decoder == "rot18")
        .and_then(|step| step.key.as_deref())
}

#[test]
#[serial]
fn rot18_sentence_is_cracked() {
    let result = crack("Gur zrrgvat vf ng 6785 va ebbz 959 ba gur frpbaq sybbe");
    assert_eq!(
        result.text[0],
        "The meeting is at 1230 in room 404 on the second floor"
    );
    assert_eq!(path(&result), ["rot18"]);
    assert_eq!(rot18_key(&result), Some("letters 13, digits 5"));
}

#[test]
#[serial]
fn rot5_with_another_letter_shift_is_cracked() {
    let result = crack("Aol tllapun pz ha 6785 pu yvvt 959 vu aol zljvuk msvvy");
    assert_eq!(
        result.text[0],
        "The meeting is at 1230 in room 404 on the second floor"
    );
    assert_eq!(path(&result), ["rot18"]);
    assert_eq!(rot18_key(&result), Some("letters 7, digits 5"));
}

#[test]
#[serial]
fn rot18_flag_is_cracked() {
    // On master Caesar returned flag{r5t63_6s_n5t_r5t68}, which LemmeKnow also takes for
    // a flag
    let result = crack("synt{e5g63_6f_a5g_e5g68}");
    assert_eq!(result.text[0], "flag{r0t18_1s_n0t_r0t13}");
    assert_eq!(path(&result), ["rot18"]);
}

#[test]
#[serial]
fn rot18_inside_base64_is_cracked() {
    // Python 3: base64.b64encode() of the sentence in rot18_sentence_is_cracked
    let result = crack("R3VyIHpycmd2YXQgdmYgbmcgNjc4NSB2YSBlYmJ6IDk1OSBiYSBndXIgZnJwYmFxIHN5YmJl");
    assert_eq!(
        result.text[0],
        "The meeting is at 1230 in room 404 on the second floor"
    );
    assert_eq!(path(&result), ["Base64", "rot18"]);
}

#[test]
#[serial]
fn rot13_with_a_number_is_still_caesar() {
    // TryHackMe c4ptur3-th3-fl4g, "Translation & Shifting": rot18 would read 13 as 68
    let result = crack("Ebgngr zr 13 cynprf!");
    assert_eq!(result.text[0], "Rotate me 13 places!");
    assert!(!path(&result).contains(&"rot18"), "{:?}", path(&result));
}

#[test]
#[serial]
fn rot13_flag_with_digits_is_still_caesar() {
    // IceCTF 2015 "ROT13": rot18 would read the flag as rot_68_isnt_secure
    let result = crack(
        "V srry yvxr guvf vf n tbbq cynpr gb fgber nyy zl frpher syntf.\nVasnpg, urer'f gur synt: ebg_13_vfag_frpher",
    );
    assert!(
        result.text[0].ends_with("here's the flag: rot_13_isnt_secure"),
        "{:?} via {:?}",
        result.text[0],
        path(&result)
    );
    assert!(!path(&result).contains(&"rot18"), "{:?}", path(&result));
}
