//! End-to-end tests for the Vigenère autokey cracker
//! (<https://github.com/bee-san/Ciphey/issues/1003>): the whole search, as the CLI runs
//! it, has to find the plaintext through Vigenere Autokey.

use ciphey::config::Config;
use ciphey::perform_cracking;
use ciphey::storage::database::DB_PATH;
use ciphey::DecoderResult;

/// The plaintext of the KEY vector.
const LIGHTHOUSE: &str =
    "Meet me at the old lighthouse after midnight and bring the map, the key and a torch.";

/// [`LIGHTHOUSE`] enciphered with the autokey primer KEY (checked against pycipher 0.5.2's
/// `Autokey("KEY")` on the letters).
const LIGHTHOUSE_KEY: &str =
    "Wicf qi tf xhx hsh ztjsbnvnzs uxxew fmuzqjub guw belox buk fht, fht dlc krb a grrvv.";

/// Runs the whole search on `text` and returns what it found.
fn crack(text: &str) -> DecoderResult {
    // With no database path every connection is a fresh in-memory database, so the search
    // doesn't read the cache in ~/.ciphey (an answer cached by another build would stand
    // in for the search under test) and doesn't write to it.
    let _ = DB_PATH.set(None);
    perform_cracking(text, Config::default())
        .unwrap_or_else(|error| panic!("searching {text:?} failed: {error}"))
        .unwrap_or_else(|| panic!("the search found nothing for {text:?}"))
}

/// The names of the decoders the search used, in order.
fn path(result: &DecoderResult) -> Vec<&str> {
    result.path.iter().map(|step| step.decoder).collect()
}

#[test]
fn autokey_ciphertext_is_cracked() {
    // Without the autokey cracker the search took a Vigenère decryption of this for English
    let result = crack(LIGHTHOUSE_KEY);
    assert_eq!(result.text[0], LIGHTHOUSE);
    assert_eq!(path(&result), ["Vigenere Autokey"]);
    assert_eq!(result.path[0].key.as_deref(), Some("KEY"));
}

#[test]
fn autokey_inside_base64_is_cracked() {
    // base64.b64encode of LIGHTHOUSE_KEY. Without the autokey cracker the search settled on
    // a LemmeKnow false positive through caesar and rot47.
    let result = crack(
        "V2ljZiBxaSB0ZiB4aHggaHNoIHp0anNibnZuenMgdXh4ZXcgZm11enFqdWIgZ3V3IGJlbG94IGJ1ayBmaHQsIGZodCBkbGMga3JiIGEgZ3JydnYu",
    );
    assert_eq!(result.text[0], LIGHTHOUSE);
    assert_eq!(path(&result), ["Base64", "Vigenere Autokey"]);
}

#[test]
fn unspaced_autokey_ciphertext_is_cracked() {
    // The issue's longer example, primer CIPHEY. It used to time out.
    let result = crack(
        "KBLHWRPXXEKMVJUMEXGNMEMWLPXSOJLASBHZEXGNMEMWLPXWGWHMAIYHCREBODGFPXWGWHMJOUPWXMBSDAAAJEKLPXAPGVOSJQSNPSKJXHIWYPXAPGVOSJXBEYSICYKKCLNHILRPXOESLVRGJLAUUHNEEGZMPXOESLVRGJDSFXBJVS",
    );
    assert_eq!(
        result.text[0],
        "ITWASTHEBESTOFTIMESITWASTHEWORSTOFTIMESITWASTHEAGEOFWISDOMITWASTHEAGEOFFOOLISHNESSITWASTHEEPOCHOFBELIEFITWASTHEEPOCHOFINCREDULITYITWASTHESEASONOFLIGHTITWASTHESEASONOFDARKNESS"
    );
    assert_eq!(path(&result), ["Vigenere Autokey"]);
    assert_eq!(result.path[0].key.as_deref(), Some("CIPHEY"));
}
