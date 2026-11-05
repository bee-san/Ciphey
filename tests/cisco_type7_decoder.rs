//! End-to-end tests for the Cisco Type 7 decoder
//! (<https://github.com/bee-san/Ciphey/issues/949>): the whole search, as the CLI runs it,
//! has to find type 7 passwords that Ciphey's checks recognise, and leave everything else
//! alone. The issue's own example, `Sup3rS3cret!`, isn't one the checks recognise: it is
//! found with a crib in `tests/cisco_type7_decoder_crib.rs`.
//!
//! The vectors were made or decoded with PyPI passlib 1.7.4's `cisco_type7`.

use ciphey::checkers::athena::Athena;
use ciphey::checkers::checker_type::{Check, Checker};
use ciphey::checkers::CheckerTypes;
use ciphey::config::Config;
use ciphey::decoders::cisco_type7_decoder::CiscoType7Decoder;
use ciphey::decoders::interface::{Crack, Decoder};
use ciphey::storage::database::DB_PATH;
use serde::Deserialize;

/// Searches `encoded` as `ciphey -d` would, without the cache in ~/.ciphey (with no database
/// path every connection is a fresh in-memory database), and returns the plaintext and the
/// decoders on its path.
fn search(encoded: &str) -> (String, Vec<&'static str>) {
    let _ = DB_PATH.set(None);
    let found = match ciphey::perform_cracking(encoded, Config::default()) {
        Ok(Some(found)) => found,
        other => panic!("no plaintext for {encoded:?}: {other:?}"),
    };
    let decoders = found.path.iter().map(|step| step.decoder).collect();
    (found.text[0].clone(), decoders)
}

/// Asserts that the search finds `plaintext` in `encoded` with this decoder alone.
#[track_caller]
fn assert_found(encoded: &str, plaintext: &str) {
    assert_eq!(
        search(encoded),
        (plaintext.to_string(), vec!["Cisco Type 7"]),
        "{encoded:?}"
    );
}

#[test]
fn published_vector_is_cracked() {
    // `cisco` is a common password, so the checks accept it
    assert_found("02050D480809", "cisco");
    assert_found("password 7 02050D480809", "cisco");
    assert_found("key 7 0822455D0A16", "cisco");
}

#[test]
fn sentence_is_cracked() {
    // One of passlib's test vectors
    assert_found(
        "153B1F1F443E22292D73212D5300194315591954465A0D0B59",
        "Its time to go to lunch!",
    );
}

#[test]
fn flag_is_cracked() {
    // passlib: cisco_type7.using(salt=4).hash("flag{type_7_is_not_encryption}")
    assert_found(
        "045D0707083A5857191C3A402D021F3B24243017363B21011E061708595745",
        "flag{type_7_is_not_encryption}",
    );
}

/// The parts of `benches/data/decoders.toml` and `search.toml` read here.
#[derive(Deserialize)]
struct Fixtures {
    /// The gibberish every decoder is timed on (decoders.toml only)
    miss: Option<String>,
    /// The cases
    case: Vec<FixtureCase>,
}

/// One fixture: decoders.toml names its decoder, search.toml its benchmark.
#[derive(Deserialize)]
struct FixtureCase {
    decoder: Option<String>,
    name: Option<String>,
    input: String,
}

#[test]
fn other_bench_inputs_get_no_candidate() {
    // Every other decoder's fixtures, every search input that isn't Cisco Type 7's, and `miss`
    let decoder = Decoder::<CiscoType7Decoder>::new();
    let checker = CheckerTypes::CheckAthena(Checker::<Athena>::new());
    let mut checked = 0;
    for file in [
        include_str!("../benches/data/decoders.toml"),
        include_str!("../benches/data/search.toml"),
    ] {
        let fixtures: Fixtures = toml::from_str(file).expect("bench fixtures parse");
        let cases = fixtures
            .case
            .iter()
            .filter(|case| case.decoder.as_deref() != Some("Cisco Type 7"))
            .filter(|case| case.name.as_deref() != Some("cisco_type7"))
            .map(|case| case.input.as_str());
        for input in cases.chain(fixtures.miss.as_deref()) {
            let candidates = decoder.crack(input, &checker).unencrypted_text;
            assert_eq!(candidates, None, "{input:?}");
            checked += 1;
        }
    }
    assert!(checked > 250, "only {checked} inputs");
}

/// xorshift64*, with a fixed seed so every run makes the same strings.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// How many of `strings` the decoder hands on, and how many of those the checker accepts.
fn count(strings: impl Iterator<Item = String>) -> (usize, usize) {
    let decoder = Decoder::<CiscoType7Decoder>::new();
    let checker = CheckerTypes::CheckAthena(Checker::<Athena>::new());
    let (mut candidates, mut accepted) = (0, 0);
    for text in strings {
        let result = decoder.crack(&text, &checker);
        if result.unencrypted_text.is_some() {
            candidates += 1;
        }
        if result.success {
            accepted += 1;
            eprintln!("accepted {text:?}: {:?}", result.unencrypted_text);
        }
    }
    (candidates, accepted)
}

#[test]
fn random_strings_are_not_taken_for_plaintext() {
    const STRINGS: usize = 10_000;
    const HEX: &[u8] = b"0123456789ABCDEF";
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let mut total_accepted = 0;

    // Strings in the format: an offset of 00 to 15, then random bytes in hex. Each gets to
    // the printable-ASCII check, and the passwords that pass it go to the checker.
    eprintln!("type 7 strings: bytes, candidates, accepted (of {STRINGS} each)");
    for bytes in 3..=16 {
        let strings: Vec<String> = (0..STRINGS)
            .map(|_| {
                let mut text = format!("{:02}", rng.below(16));
                for _ in 0..bytes {
                    text.push_str(&format!("{:02X}", rng.below(256)));
                }
                text
            })
            .collect();
        let (candidates, accepted) = count(strings.into_iter());
        eprintln!("{bytes:>3} {candidates:>6} {accepted:>3}");
        total_accepted += accepted;
    }

    // Random strings of hex digits, most of which don't start with an offset of 15 or less
    eprintln!("hex digits: length, candidates, accepted (of {STRINGS} each)");
    for len in [8, 9, 10, 12, 16, 20, 24, 32, 48, 64] {
        let strings: Vec<String> = (0..STRINGS)
            .map(|_| {
                (0..len)
                    .map(|_| char::from(HEX[rng.below(16) as usize]))
                    .collect()
            })
            .collect();
        let (candidates, accepted) = count(strings.into_iter());
        eprintln!("{len:>3} {candidates:>6} {accepted:>3}");
        total_accepted += accepted;
    }

    // Random strings of 0s and 1s, the alphabet of binary written without spaces
    eprintln!("binary digits: length, candidates, accepted (of {STRINGS} each)");
    for len in [8, 16, 24, 32, 56, 64, 80] {
        let strings: Vec<String> = (0..STRINGS)
            .map(|_| {
                (0..len)
                    .map(|_| if rng.below(2) == 0 { '0' } else { '1' })
                    .collect()
            })
            .collect();
        let (candidates, accepted) = count(strings.into_iter());
        eprintln!("{len:>3} {candidates:>6} {accepted:>3}");
        assert_eq!(candidates, 0, "binary of length {len}");
        total_accepted += accepted;
    }

    assert_eq!(total_accepted, 0);
}
