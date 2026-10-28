//! Real CTF strings, run through the full search.
//!
//! `tests/data/ctf_corpus.json` holds encoded and enciphered strings from real CTF challenges:
//! for each one the event, the challenge, the public writeup it was copied from, the plaintext
//! it decodes to and the decoders a solver used. `corpus_entries_crack` checks that every entry
//! not in [`KNOWN_FAILURES`] still cracks, and prints the recall:
//!
//! ```text
//! cargo test --test ctf_corpus -- --nocapture
//! ```
//!
//! The known failures take a few minutes, so they are behind `--ignored`. Running them shows
//! what each one returns, and fails if one of them cracks now:
//!
//! ```text
//! cargo test --release --test ctf_corpus -- --ignored --nocapture
//! ```
//!
//! `CIPHEY_CTF_TIMEOUT` sets the per-entry timeout in seconds (default 10) and `CIPHEY_CTF_ONLY`
//! runs only the entries whose id contains it.
//!
//! To add an entry, copy the ciphertext exactly as a public writeup (or the published challenge
//! files) shows it, and link that page in `source_url`. `plaintext` is what decoding the whole
//! ciphertext gives, `flag` the flag that was submitted, if any. Skip anything that needs hash or
//! password cracking, files, or non-text steganography.

use std::collections::HashSet;
use std::time::{Duration, Instant};

use ciphey::config::Config;
use ciphey::{perform_cracking, CipheyError};
use serde::Deserialize;
use serial_test::serial;

/// The corpus: a JSON array of [`Entry`]
const CORPUS: &str = include_str!("data/ctf_corpus.json");

/// How long each search may run, in seconds, unless `CIPHEY_CTF_TIMEOUT` says otherwise.
/// The entries that crack take under a second even in a debug build; the margin is for slow
/// CI runners.
const DEFAULT_TIMEOUT_SECS: u32 = 10;

// Why the entries below fail. Most are named after the decoder that would crack them.
const DETECTION: &str = "plaintext detection accepts a wrong decoding first (#1031)";
const LONG_TEXT: &str = "texts over 820 bytes are dropped by calculate_string_quality";
const SHORT_VIGENERE: &str = "Vigenère: too few letters to recover the key";
const SHORT_SUBSTITUTION: &str = "substitution too short to break by frequency analysis";
const SUBSTITUTION_CRACKER: &str = "the substitution cracker doesn't find the exact key";
const XOR_SHORT: &str = "XOR: too little text to rank the right key first";
const XOR_PRINTABLE: &str = "single-byte XOR isn't tried on text that is already printable";
const FLAG_WRAPPER: &str = "only the text inside the flag braces is enciphered";
const FLAG_BRACES: &str = "flag braces inside Morse code / A1Z26 numbers";
const TRITHEMIUS: &str = "needs Trithemius / progressive Caesar (#995)";
const POLYBIUS: &str = "needs Polybius square (#963)";
const PLAYFAIR: &str = "needs Playfair (#1006)";
const SCYTALE: &str = "needs Scytale (#997)";
const MULTITAP: &str = "needs multi-tap phone keypad (#960)";
const KEYBOARD_SHIFT: &str = "needs keyboard shift (#976)";
const KEYBOARD_LAYOUT: &str = "needs keyboard layout swap, Dvorak to QWERTY (#977)";
const SHIFTED_DIGITS: &str = "needs !@#$%^&*() read as the digits under them";
const NATO: &str = "needs NATO phonetic alphabet (#964)";
const LEET: &str = "needs leetspeak (#969)";
const PERIODIC: &str = "needs periodic table atomic numbers (#975)";
const MALBOLGE: &str = "needs Malbolge (#990)";
const OOK: &str = "needs Ook! (#984)";
const AUTOKEY: &str = "needs Vigenère Autokey (#1003)";
const HILL: &str = "needs Hill, key given in the challenge (#1011)";
const COLUMNAR: &str = "needs columnar transposition (#1014)";
const BASE62: &str = "needs Base62 (#924)";
const DNA: &str = "needs DNA nucleotide 2-bit encoding (#967)";
const LONG_TO_BYTES: &str = "needs big integer to bytes (#952)";
const ASCII_SHIFT: &str = "needs ASCII shift (#994)";
const HEXDUMP: &str = "needs od / hexdump parsing (#946)";
const CCIR476: &str = "needs CCIR 476 (7-bit radio teletype)";
const BYTES_LITERAL: &str = "needs Python bytes literal b'...' unwrapping";
const UTF16_PACKED: &str = "needs UTF-16 code units read as byte pairs";
const BLOCK_TRANSPOSITION: &str = "needs fixed-block transposition";
const CAESAR_ALPHANUM: &str = "needs Caesar over a-z0-9";
const AFFINE_27: &str = "needs Affine over a 27-symbol alphabet (a-z and _)";
const A1Z26_VARIANT: &str = "needs A1Z26 with 0-based two-digit codes";
const BACON_VARIANT: &str = "Bacon variant the decoder doesn't read";
const BINARY_SYMBOLS: &str = "binary written with other symbols isn't read as binary";
const BASE64_LAYOUT: &str = "Base64 broken across lines";
const LABEL_PREFIX: &str = "needs to drop a 'b64: ' label before decoding";
const BRAINFUCK_NO_OUTPUT: &str =
    "the Brainfuck program builds the flag in memory but never prints it";
const ONE_OFF: &str = "one-off scheme described in the challenge text";

/// Entries the search doesn't crack yet, and why. When a change makes one crack,
/// `corpus_known_failures` fails until it is removed from this list.
const KNOWN_FAILURES: &[(&str, &str)] = &[
    // The decoders reach the answer (a crib that only matches it finds it), but the search accepts
    // another decoder's output first, mostly Vigenère's.
    ("otw-krypton-level0", DETECTION),
    ("otw-krypton-level2", DETECTION),
    ("pragyan-ctf-2015-roman", DETECTION),
    ("sctf-2015-cipherception", DETECTION),
    ("abctf-2016-ceasar-salad", DETECTION),
    ("icectf-2016-rotated", DETECTION),
    ("otw-natas-level8", DETECTION),
    ("tjctf-2016-znzarmt-mvd-hproo", DETECTION),
    ("angstromctf-2018-back-to-base-ics", DETECTION),
    ("angstromctf-2018-back-to-base-ics-2", DETECTION),
    ("angstromctf-2018-back-to-base-ics-3", DETECTION),
    ("angstromctf-2018-warmup", DETECTION),
    ("angstromctf-2018-xor", DETECTION),
    ("easyctf-iv-2018-soupreme-encoder", DETECTION),
    ("easyctf-iv-2018-the-oldest-trick-in-the-book", DETECTION),
    (
        "neverlanctf-2018-how-much-can-you-throw-on-a-caesar-salad",
        DETECTION,
    ),
    ("picoctf-2018-caesar-cipher-2", DETECTION),
    ("angstromctf-2019-classy-cipher", DETECTION),
    ("picoctf-2019-13", DETECTION),
    ("picoctf-2019-bases", DETECTION),
    ("sunshinectf-2019-welcome-crypto", DETECTION),
    ("sunshinectf-2019-welcome-crypto-2", DETECTION),
    ("tjctf-2019-double-duty", DETECTION),
    ("tjctf-2019-touch-base", DETECTION),
    ("cyberyoddha-ctf-2020-beware-the-ides-of-march", DETECTION),
    ("otw-bandit-level11", DETECTION),
    ("thm-c4ptur3-th3-fl4g-rot47", DETECTION),
    ("ctflearn-character-encoding", DETECTION),
    ("ctflearn-morse-code", DETECTION),
    ("ctflearn-otpyrc", DETECTION),
    ("cybergrabs-0x02-2021-w4rm-up", DETECTION),
    ("hacktivitycon-2021-six-four-over-two", DETECTION),
    ("imaginaryctf-2021-chicken-caesar-salad", DETECTION),
    ("metactf-2021-a-to-z", DETECTION),
    ("nahamcon-2021-esab64", DETECTION),
    ("picoctf-2021-crackme-py", DETECTION),
    ("picoctf-2021-mod-26", DETECTION),
    ("picoctf-2021-nice-netcat", DETECTION),
    ("tfcctf-2021-sea-language-1", DETECTION),
    ("knightctf-2022-404-not-found", DETECTION),
    ("picoctf-2022-rail-fence", DETECTION),
    ("deadface-2023-off-the-rails", DETECTION),
    ("picoctf-2023-hidetosee", DETECTION),
    ("picoctf-2023-rotation", DETECTION),
    ("picogym-ascii-numbers", DETECTION),
    ("wolvctf-2023-switcharoo", DETECTION),
    ("wolvctf-2023-switcharoo-2", DETECTION),
    ("picoctf-2025-cookie-monster-secret-recipe", DETECTION),
    // `calculate_string_quality` scores a text 1 - |len - 100| / 900, below the 0.2 cut-off from
    // 821 to 5000 bytes, so longer results and intermediate texts are thrown away.
    ("ctflearn-encryption-master", LONG_TEXT),
    ("davincictf-2021-substitution", LONG_TEXT),
    ("otw-krypton-level4", SHORT_VIGENERE),
    ("otw-krypton-level5", SHORT_VIGENERE),
    ("picoctf-2018-crypto-warmup-1", SHORT_VIGENERE),
    ("picoctf-2019-easy1", SHORT_VIGENERE),
    ("thm-ctf-collection-vol1-uncrackable", SHORT_VIGENERE),
    ("ctflearn-vigenere-cipher", SHORT_VIGENERE),
    ("shakti-ctf-2021-classicaly-easy", SHORT_VIGENERE),
    ("picoctf-2022-vigenere", SHORT_VIGENERE),
    ("wolvctf-2022-anything", SHORT_VIGENERE),
    ("n00bzctf-2024-vinegar", SHORT_VIGENERE),
    ("otw-krypton-level3", SHORT_SUBSTITUTION),
    ("nahamcon-2021-car-keys", SHORT_SUBSTITUTION),
    ("byuctf-2023-poem", SHORT_SUBSTITUTION),
    ("neverlanctf-2019-alphabet-soup", SUBSTITUTION_CRACKER),
    ("picoctf-2022-substitution1", SUBSTITUTION_CRACKER),
    ("otw-natas-level11", XOR_SHORT),
    ("thm-ctf-collection-vol1-an-exclusive", XOR_SHORT),
    ("htb-cyber-apocalypse-2021-phasestream-1", XOR_SHORT),
    ("ctflearn-bruxor", XOR_PRINTABLE),
    ("deadface-2021-to-be-xor-not-to-be", XOR_PRINTABLE),
    ("picoctf-2018-caesar-cipher-1", FLAG_WRAPPER),
    ("picoctf-2019-caesar", FLAG_WRAPPER),
    ("picoctf-2019-tapping", FLAG_BRACES),
    ("picoctf-2019-the-numbers", FLAG_BRACES),
    ("downunderctf-2020-rot-i", TRITHEMIUS),
    ("htb-cyber-apocalypse-2024-dynastic", TRITHEMIUS),
    ("easyctf-2015-i-love-sleeping", POLYBIUS),
    ("ctflearn-5x5-crypto", POLYBIUS),
    ("pragyan-ctf-2015-crack-this", PLAYFAIR),
    ("hackvent-2014-day03-candle-1", SCYTALE),
    ("moectf-2023-base-band", SCYTALE),
    ("ibteam-blackvalentine-2015-crypto2", MULTITAP),
    ("htb-challenge-bank-heist", MULTITAP),
    ("ctflearn-modern-gaius-julius-caesar", KEYBOARD_SHIFT),
    ("tjctf-2022-flimsy-fingered-latin-teacher", KEYBOARD_SHIFT),
    ("deconstructf-2023-move", KEYBOARD_SHIFT),
    ("hackvent-2016-day02-free-giveaway", KEYBOARD_LAYOUT),
    ("dawgctf-2020-qwerky-qwerty", KEYBOARD_LAYOUT),
    ("ctflearn-symbolic-decimals", SHIFTED_DIGITS),
    ("tfcctf-2023-mayday", NATO),
    ("thm-c4ptur3-th3-fl4g-leet", LEET),
    ("nullcon-hackim-2015-crypto-1", PERIODIC),
    ("breakin-ctf-2016-eighth-circles-of-hell", MALBOLGE),
    ("pragyan-ctf-2016-k", OOK),
    ("utctf-2025-autokey-cipher", AUTOKEY),
    ("jerseyctf-2023-jack-and-jill", HILL),
    ("jerseyctf-2023-roko-cipher-in-the-console", COLUMNAR),
    ("ideh-v4-fundatur", BASE62),
    ("killerqueen-2021-deoxyencoded-nucleic-acid", DNA),
    ("thm-ctf-collection-vol1-small-bases", LONG_TO_BYTES),
    ("encryptctf-2019-julius", ASCII_SHIFT),
    ("internetwache-ctf-2016-the-hidden-message", HEXDUMP),
    ("downunderctf-2024-intercepted-transmissions", CCIR476),
    ("picoctf-2024-interencdec", BYTES_LITERAL),
    ("picoctf-2021-transformation", UTF16_PACKED),
    ("picoctf-2022-transposition-trial", BLOCK_TRANSPOSITION),
    ("pactf-2018-straight-from-the-emperor", CAESAR_ALPHANUM),
    ("school-ctf-2015-affine-cipher", AFFINE_27),
    ("icectf-2015-numb3rs", A1Z26_VARIANT),
    ("sctf-2015-i-like-bacon", BACON_VARIANT),
    ("utctf-2021-sizzling-bacon", BACON_VARIANT),
    ("encryptctf-2019-hard-looks", BINARY_SYMBOLS),
    ("tfcctf-2021-sea-language-2", BINARY_SYMBOLS),
    ("htb-cyber-apocalypse-2021-nintendo-base64", BASE64_LAYOUT),
    ("picoctf-2023-repetitions", BASE64_LAYOUT),
    ("angstromctf-2016-what-the-hex", LABEL_PREFIX),
    ("n00bzctf-2024-brain", BRAINFUCK_NO_OUTPUT),
    ("bcactf-2021-cipher-mishap", ONE_OFF),
];

/// One CTF string and where it came from
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    /// Unique slug: event-year-challenge
    id: String,
    /// The CTF, wargame or platform, e.g. "picoCTF 2019"
    event: String,
    /// The year of the event
    year: u16,
    /// The challenge name
    challenge: String,
    /// The challenge category in the CTF
    category: String,
    /// A public writeup (or the published challenge files) containing the ciphertext verbatim
    source_url: String,
    /// The string the challenge gave
    ciphertext: String,
    /// What decoding all of `chain` gives
    plaintext: String,
    /// The flag that was submitted, if any, when it isn't the whole plaintext
    flag: String,
    /// The decoding steps a solver used, outermost first
    chain: Vec<String>,
    /// Keys, alphabets and other details of the solution
    notes: String,
}

/// What the search did with an entry
enum Outcome {
    /// Returned the expected plaintext
    Cracked,
    /// Returned something else
    Wrong(String),
    /// Searched everything it could without accepting anything
    NotFound,
    /// Ran out of time
    TimedOut,
    /// Any other error
    Error(String),
}

/// The result of running the search on one entry
struct Run<'a> {
    /// The entry
    entry: &'a Entry,
    /// What happened
    outcome: Outcome,
    /// The decoders on the path the search returned
    path: Vec<&'static str>,
    /// Wall-clock time of the search
    elapsed: Duration,
}

impl Run<'_> {
    /// Whether the search returned the expected plaintext
    fn cracked(&self) -> bool {
        matches!(self.outcome, Outcome::Cracked)
    }

    /// One line for the test output
    fn describe(&self) -> String {
        let status = if self.cracked() { "ok  " } else { "FAIL" };
        let what = match &self.outcome {
            Outcome::Cracked => String::new(),
            Outcome::Wrong(text) => format!(" returned {:?}", truncate(text, 80)),
            Outcome::NotFound => " found nothing".to_string(),
            Outcome::TimedOut => " timed out".to_string(),
            Outcome::Error(e) => format!(" error: {e}"),
        };
        let path = if self.path.is_empty() {
            String::new()
        } else {
            format!(" via {}", self.path.join(" -> "))
        };
        format!(
            "[{status}] {:5.1}s {}{what}{path}",
            self.elapsed.as_secs_f64(),
            self.entry.id
        )
    }
}

/// `text` cut to at most `max` characters
fn truncate(text: &str, max: usize) -> String {
    match text.char_indices().nth(max) {
        Some((end, _)) => format!("{}...", &text[..end]),
        None => text.to_string(),
    }
}

/// Lowercase with all whitespace removed, so Morse code's capitals and a decoder's spacing
/// don't count as differences
fn normalise(text: &str) -> String {
    text.chars()
        .filter(|c| !c.is_whitespace())
        .flat_map(char::to_lowercase)
        .collect()
}

/// Whether `found` is the entry's plaintext, or contains its flag when the flag is part of
/// the plaintext (some writeups stop at the flag and leave the text around it half-decoded)
fn is_expected(entry: &Entry, found: &str) -> bool {
    let found = normalise(found);
    let plaintext = normalise(&entry.plaintext);
    let flag = normalise(&entry.flag);
    found == plaintext || (!flag.is_empty() && plaintext.contains(&flag) && found.contains(&flag))
}

/// The parsed corpus
fn corpus() -> Vec<Entry> {
    serde_json::from_str(CORPUS).expect("tests/data/ctf_corpus.json should parse")
}

/// The ids in [`KNOWN_FAILURES`]
fn known_failure_ids() -> HashSet<&'static str> {
    KNOWN_FAILURES.iter().map(|(id, _)| *id).collect()
}

/// The per-entry timeout
fn timeout_secs() -> u32 {
    std::env::var("CIPHEY_CTF_TIMEOUT")
        .ok()
        .and_then(|secs| secs.parse().ok())
        .unwrap_or(DEFAULT_TIMEOUT_SECS)
}

/// Whether `CIPHEY_CTF_ONLY` (if set) selects `entry`
fn selected(entry: &Entry) -> bool {
    std::env::var("CIPHEY_CTF_ONLY").map_or(true, |only| entry.id.contains(&only))
}

/// Runs the full search on one entry, as if from a fresh process
fn run(entry: &Entry) -> Run<'_> {
    // An in-memory cache, so an answer cached by an earlier search can't help. Only the first
    // call in the process takes effect, like the config below.
    let _ = ciphey::storage::database::DB_PATH.set(None);
    // The search learns which decoders succeed, which would make the order entries run in matter
    ciphey::reset_decoder_stats();
    let config = Config {
        timeout: timeout_secs(),
        api_mode: true,
        human_checker_on: false,
        ..Config::default()
    };

    let start = Instant::now();
    let result = perform_cracking(&entry.ciphertext, config);
    let elapsed = start.elapsed();

    let (outcome, path) = match result {
        Ok(Some(result)) => {
            let path = result.path.iter().map(|step| step.decoder).collect();
            let text = result.text.first().cloned().unwrap_or_default();
            if is_expected(entry, &text) {
                (Outcome::Cracked, path)
            } else {
                (Outcome::Wrong(text), path)
            }
        }
        Ok(None) => (Outcome::NotFound, Vec::new()),
        Err(CipheyError::Timeout { .. }) => (Outcome::TimedOut, Vec::new()),
        Err(e) => (Outcome::Error(e.to_string()), Vec::new()),
    };
    Run {
        entry,
        outcome,
        path,
        elapsed,
    }
}

/// Runs the search on each entry in turn, printing a line per entry
fn run_all<'a>(entries: &[&'a Entry]) -> Vec<Run<'a>> {
    entries
        .iter()
        .map(|entry| {
            let run = run(entry);
            println!("{}", run.describe());
            run
        })
        .collect()
}

#[test]
fn corpus_is_well_formed() {
    let entries = corpus();
    assert!(!entries.is_empty());

    let mut ids = HashSet::new();
    for entry in &entries {
        assert!(ids.insert(entry.id.as_str()), "duplicate id {}", entry.id);
        assert!(
            entry
                .id
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'),
            "{}: ids are kebab-case",
            entry.id
        );
        for (field, value) in [
            ("event", &entry.event),
            ("challenge", &entry.challenge),
            ("category", &entry.category),
            ("ciphertext", &entry.ciphertext),
            ("plaintext", &entry.plaintext),
            ("notes", &entry.notes),
        ] {
            assert!(!value.trim().is_empty(), "{}: empty {field}", entry.id);
        }
        assert!(
            (2010..=2030).contains(&entry.year),
            "{}: year {}",
            entry.id,
            entry.year
        );
        assert!(
            entry.source_url.starts_with("https://"),
            "{}: source_url should be an https URL",
            entry.id
        );
        assert!(!entry.chain.is_empty(), "{}: empty chain", entry.id);
        assert!(
            entry.ciphertext.chars().count() <= 1500,
            "{}: keep the ciphertexts short",
            entry.id
        );
        assert_ne!(
            normalise(&entry.ciphertext),
            normalise(&entry.plaintext),
            "{}: the ciphertext is the plaintext",
            entry.id
        );
    }

    let mut listed = HashSet::new();
    for (id, reason) in KNOWN_FAILURES {
        assert!(
            ids.contains(id),
            "KNOWN_FAILURES lists {id}, which isn't in the corpus"
        );
        assert!(listed.insert(*id), "KNOWN_FAILURES lists {id} twice");
        assert!(!reason.is_empty(), "{id}: give a reason");
    }
}

/// Prints the recall: how many of the `total` entries crack, and for the rest how many fail
/// for each reason in [`KNOWN_FAILURES`]
fn print_recall(total: usize, cracked: usize, failing: &[(&str, &str)]) {
    println!(
        "CTF corpus recall: {cracked}/{total} cracked ({:.0}%), with a {} s timeout per entry",
        100.0 * cracked as f64 / total as f64,
        timeout_secs()
    );
    // Reasons in the order they first appear in KNOWN_FAILURES
    let mut reasons: Vec<(&str, usize)> = Vec::new();
    for (_, reason) in failing {
        match reasons.iter_mut().find(|(r, _)| r == reason) {
            Some((_, count)) => *count += 1,
            None => reasons.push((reason, 1)),
        }
    }
    for (reason, count) in reasons {
        println!("{count:4}  {reason}");
    }
}

#[test]
#[serial]
fn corpus_entries_crack() {
    let entries = corpus();
    let known_failures = known_failure_ids();
    let expected: Vec<&Entry> = entries
        .iter()
        .filter(|entry| !known_failures.contains(entry.id.as_str()) && selected(entry))
        .collect();

    let runs = run_all(&expected);
    let failed: Vec<&Run> = runs.iter().filter(|run| !run.cracked()).collect();
    assert!(
        failed.is_empty(),
        "{} of {} corpus entries no longer crack:\n{}\nIf that is expected, add them to \
         KNOWN_FAILURES with the reason.",
        failed.len(),
        runs.len(),
        failed
            .iter()
            .map(|run| format!("{}  ({})", run.describe(), run.entry.source_url))
            .collect::<Vec<_>>()
            .join("\n")
    );

    if expected.len() + known_failures.len() == entries.len() {
        print_recall(entries.len(), runs.len(), KNOWN_FAILURES);
        println!("Run the known failures with `cargo test --test ctf_corpus -- --ignored`.");
    }
}

#[test]
#[serial]
#[ignore = "runs the known failures, which mostly fail slowly; use it to measure recall"]
fn corpus_known_failures() {
    let entries = corpus();
    let failures: Vec<(&Entry, &str)> = KNOWN_FAILURES
        .iter()
        .filter_map(|(id, reason)| {
            let entry = entries.iter().find(|entry| entry.id == *id)?;
            Some((entry, *reason))
        })
        .filter(|(entry, _)| selected(entry))
        .collect();

    let runs = run_all(&failures.iter().map(|(entry, _)| *entry).collect::<Vec<_>>());
    let now_crack: Vec<&str> = runs
        .iter()
        .filter(|run| run.cracked())
        .map(|run| run.entry.id.as_str())
        .collect();

    if failures.len() == KNOWN_FAILURES.len() {
        let still_failing: Vec<(&str, &str)> = KNOWN_FAILURES
            .iter()
            .filter(|(id, _)| !now_crack.contains(id))
            .copied()
            .collect();
        print_recall(
            entries.len(),
            entries.len() - still_failing.len(),
            &still_failing,
        );
    }
    assert!(
        now_crack.is_empty(),
        "these known failures crack now, remove them from KNOWN_FAILURES: {now_crack:?}"
    );
}
