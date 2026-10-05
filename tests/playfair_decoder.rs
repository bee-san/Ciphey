//! End-to-end tests for the Playfair cracker (<https://github.com/bee-san/Ciphey/issues/1006>):
//! the whole search, as the CLI runs it, has to find the plaintext through Playfair.

use ciphey::config::Config;
use ciphey::perform_cracking;
use ciphey::storage::database::DB_PATH;
use ciphey::DecoderResult;

/// 300 letters of Treasure Island, encrypted with pycipher 0.5.2's Playfair and the square
/// of the keyword TREASURE.
const TREASURE_CIPHERTEXT: &str = "RGROSKIQDSTFCYCAMRIREAYRTSRETOROCPFTCEQKQEOXOPCQSRLRRPCPRGAEOPLEATRGCIKRHERPUARDISXRMRMXAEHOSKGVYDFISTINLFRASICQIZIQXRKDPBRGROEDAWQCYDHORPUAIRORVEHOTRRPEGTSRHKSDICPHKQBFGQLGKHIRSPBRGCIDYRSHOINSGAYBTTFHOHUMENRGEKBESRWDBSGSTTATSPBRGSCNEOTETREASOGMHFHXEPCBSPNRGSISCRTINFGCAEHFTRSEVRGACXENERGCIDYRSHOEKOT";

/// Its plaintext, as Playfair leaves it: upper case, with an X between doubled letters
/// (SUDXDEN, FOLXLOWED) and J as I (IUST).
const TREASURE_PLAINTEXT: &str = "THENALLOFASUDXDENTHEREWASATREMENDOUSEXPLOSIONOFOATHSANDOTHERNOISESTHECHAIRANDTABLEWENTOVERINALUMPACLASHOFSTEELFOLXLOWEDANDTHENACRYOFPAINANDTHENEXTINSTANTISAWBLACKDOGINFULLFLIGHTANDTHECAPTAINHOTLYPURSUINGBOTHWITHDRAWNCUTLASSESANDTHEFORMERSTREAMINGBLOXODFROMTHELEFTSHOULDERIUSTATXTHEDOXORTHECAPTAINAIME";

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
fn treasure_island_is_cracked() {
    // Master took this for Reverse -> railfence at depth 2, which LemmeKnow accepted; the
    // Playfair answer comes at depth 1, before any depth-2 node is expanded
    let result = crack(TREASURE_CIPHERTEXT);
    assert_eq!(result.text[0], TREASURE_PLAINTEXT);
    assert_eq!(path(&result), ["Playfair"]);
    assert_eq!(
        result.path[0].key.as_deref(),
        Some("TREASUBCDFGHIKLMNOPQVWXYZ")
    );
}

#[test]
fn grouped_lower_case_ciphertext_is_cracked() {
    let grouped: Vec<String> = TREASURE_CIPHERTEXT
        .to_ascii_lowercase()
        .as_bytes()
        .chunks(5)
        .map(|group| String::from_utf8_lossy(group).into_owned())
        .collect();
    let result = crack(&grouped.join(" "));
    assert_eq!(result.text[0], TREASURE_PLAINTEXT);
    assert_eq!(path(&result), ["Playfair"]);
}
