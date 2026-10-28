//! Decode text typed on one keyboard layout and read as another.
//!
//! The keys of a keyboard carry different legends on each layout, so text typed on one
//! layout while the computer is set to another is a fixed substitution. `hello world`
//! typed on QWERTY keys that are read as Dvorak comes out as `d.nnr ,rpne`: the key
//! labelled H on QWERTY is D on Dvorak, E is `.`, and so on. All 47 character keys are
//! mapped, with and without Shift, so upper case stays upper case and punctuation moves
//! too (`;` typed on QWERTY is `s` on Dvorak). The decoder tries eight tables, named
//! `X→Y` for text typed on layout X and read as layout Y:
//!
//! * `QWERTY→Dvorak` and `Dvorak→QWERTY`,
//! * `QWERTY→Colemak` and `Colemak→QWERTY`,
//! * `QWERTY→AZERTY` and `AZERTY→QWERTY`, the French layout. Its keys also carry
//!   `²éèçà°¨£µù§`, and its digits need Shift, so digits swap with `&é"'(-è_çà`,
//! * `ABC→QWE` and `QWE→ABC`, the CTF keyboard cipher that writes the alphabet as the
//!   QWERTY key order (A is Q, B is W, ..., so `itssg vgksr` is `hello world`), or the
//!   QWERTY key order as the alphabet (Q is A, W is B, ...). Only letters change.
//!
//! The legends are xkeyboard-config 2.41's: `symbols/us` (`basic`, `dvorak`, `colemak`)
//! and `symbols/fr` (`basic`). QWERTZ is left out on purpose: it differs from QWERTY only
//! in Y and Z and a few symbols, so its ciphertext still reads as English and the search
//! accepts it before any decoder runs, and the checker accepts English with Y and Z
//! swapped, so this decoder would "crack" plain English.
//!
//! # Ranking
//!
//! Ciphey runs every decoder on every text the search expands, so the decodings are
//! ranked before anything is checked. Text that can't have been typed on these layouts,
//! or that changes case inside its words as often as Base64 does (the tables keep each
//! letter's case), is turned away first. Each decoding is scored by the mean English
//! log-probability of its adjacent letter pairs, from
//! `src/storage/ngrams/english_bigrams.txt`: pairs across whitespace are skipped and pairs
//! with any other character score −10. Only decodings that score more than 0.2 above the
//! input itself are kept. Plain English, and most of what the search sees, gets no closer
//! to English under any table, so most texts cost a few passes over the characters and no
//! checker call. The best two decodings kept are checked, with Low sensitivity for
//! gibberish detection like the Caesar cracker, and the first one identified is returned
//! with its table as the key. If neither is, the best three go back to the search.
//!
//! # Known limits
//!
//! * Many layout ciphertexts still look like English, such as `hello zorld` (`hello world`
//!   typed on QWERTY and read as AZERTY), and the search takes them for plaintext before
//!   any decoder runs. `crack` itself decodes them.
//! * Short texts that change little can fall under the 0.2 gate: `Hello, World!` typed on
//!   AZERTY and read as QWERTY is lost, but text that short usually reads as plaintext
//!   anyway.
//! * Flags with many digits, `_` and braces: those score −10 in the input and in the
//!   decoding alike, so the few letter pairs that change are diluted, and
//!   `flag{th1s_1s_4_fl4g}` falls under the gate for most tables.
//! * AZERTY has no `` ` ``, `@`, `#`, `[`, `]`, `{`, `}`, `\`, `|`, `<` or `>` on these
//!   keys, so text with them can't have been typed on it, and reading as AZERTY leaves
//!   them as they are.
//! * Typing one key to the side on the same layout (`jr;;p ept;f`) is a different cipher,
//!   the keyboard shift, which the Keyboard shift decoder cracks.
//!
//! References: <https://www.dcode.fr/keyboard-change-cipher>,
//! <https://en.wikipedia.org/wiki/Dvorak_keyboard_layout>, <https://colemak.com/> and
//! xkeyboard-config (<https://gitlab.freedesktop.org/xkeyboard-config/xkeyboard-config>).

use crate::checkers::CheckerTypes;
use crate::decoders::affine_decoder::BIGRAM_LOG_PROBS;
use gibberish_or_not::Sensitivity;
use once_cell::sync::Lazy;

use super::crack_results::CrackResult;
use super::interface::Crack;
use super::interface::Decoder;

use log::trace;

/// QWERTY's legends on the 47 character keys, unshifted then with Shift (xkeyboard-config
/// `us(basic)`). Every layout lists its keys in the same order, by their xkeyboard-config
/// names: `TLDE` (left of 1), `AE01`–`AE12` (the number row), `AD01`–`AD12` (the top
/// letter row), `BKSL` (above Enter), `AC01`–`AC11` (the home row), `AB01`–`AB10` (the
/// bottom row).
const QWERTY: &str = concat!(
    "`1234567890-=qwertyuiop[]\\asdfghjkl;'zxcvbnm,./",
    "~!@#$%^&*()_+QWERTYUIOP{}|ASDFGHJKL:\"ZXCVBNM<>?",
);

/// Dvorak's legends, in the order of [`QWERTY`] (xkeyboard-config `us(dvorak)`).
const DVORAK: &str = concat!(
    "`1234567890[]',.pyfgcrl/=\\aoeuidhtns-;qjkxbmwvz",
    "~!@#$%^&*(){}\"<>PYFGCRL?+|AOEUIDHTNS_:QJKXBMWVZ",
);

/// Colemak's legends, in the order of [`QWERTY`] (xkeyboard-config `us(colemak)`).
const COLEMAK: &str = concat!(
    "`1234567890-=qwfpgjluy;[]\\arstdhneio'zxcvbkm,./",
    "~!@#$%^&*()_+QWFPGJLUY:{}|ARSTDHNEIO\"ZXCVBKM<>?",
);

/// French AZERTY's legends, in the order of [`QWERTY`] (xkeyboard-config `fr(basic)`). The
/// two dead keys right of P are written as the accents they type, `^` and `¨`.
const AZERTY: &str = concat!(
    "²&é\"'(-è_çà)=azertyuiop^$*qsdfghjklmùwxcvbn,;:!",
    "~1234567890°+AZERTYUIOP¨£µQSDFGHJKLM%WXCVBN?./§",
);

/// The letters in QWERTY key order, lower then upper case, for the keyboard cipher.
const QWE: &str = "qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM";

/// The alphabet, lower then upper case, in the order of [`QWE`].
const ABC: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

/// Every legend of these layouts that isn't ASCII. They are all AZERTY's.
const NON_ASCII: [char; 11] = ['²', 'é', 'è', 'ç', 'à', '°', '¨', '£', 'µ', 'ù', '§'];

/// One way of misreading a keyboard: text typed on one layout and read as another. Each
/// legend of `read` decodes to the legend of `typed` on the same key.
struct Table {
    /// `typed→read`, the key reported for a decoding
    name: &'static str,
    /// The legends of the layout the text was typed on: what the decoding is written in
    typed: &'static str,
    /// The legends of the layout the text was read as: what the ciphertext is written in
    read: &'static str,
}

/// Every table the decoder tries. Decodings that score the same keep this order.
const TABLES: [Table; 8] = [
    Table {
        name: "QWERTY→Dvorak",
        typed: QWERTY,
        read: DVORAK,
    },
    Table {
        name: "Dvorak→QWERTY",
        typed: DVORAK,
        read: QWERTY,
    },
    Table {
        name: "QWERTY→Colemak",
        typed: QWERTY,
        read: COLEMAK,
    },
    Table {
        name: "Colemak→QWERTY",
        typed: COLEMAK,
        read: QWERTY,
    },
    Table {
        name: "QWERTY→AZERTY",
        typed: QWERTY,
        read: AZERTY,
    },
    Table {
        name: "AZERTY→QWERTY",
        typed: AZERTY,
        read: QWERTY,
    },
    Table {
        name: "QWE→ABC",
        typed: QWE,
        read: ABC,
    },
    Table {
        name: "ABC→QWE",
        typed: ABC,
        read: QWE,
    },
];

/// Pre-check: the fewest characters other than whitespace worth decoding.
const MIN_NON_WHITESPACE: usize = 4;

/// Pre-check: with at least [`MIN_PAIRS_FOR_CASE_CHECK`] pairs of adjacent letters, at
/// most one pair in this many may be a lower-case letter followed by an upper-case one
/// (`aB`). Every table keeps the case of the letters it maps to letters, so a decoding
/// changes case inside its words about as often as the text does. English does
/// it at most one pair in 11 (the Affine cracker's measurement on Project Gutenberg books
/// and Ciphey's docs), Base64 and its relatives about one pair in four. Without this they
/// pass the gate under a table or two, which costs two checks for every such search node.
const MAX_LOWER_UPPER_PAIRS_ONE_IN: usize = 8;

/// Pre-check: the fewest pairs of adjacent letters that [`MAX_LOWER_UPPER_PAIRS_ONE_IN`]
/// is applied to. Shorter texts are cheap to decode anyway.
const MIN_PAIRS_FOR_CASE_CHECK: usize = 20;

/// The score of a pair of adjacent characters that aren't both ASCII letters.
const OTHER_PAIR_SCORE: f32 = -10.0;

/// Gate: how much higher than the input's own score (the mean log-probability per pair,
/// see [`mean_pair_score`]) a decoding has to score to be checked or handed on.
///
/// From a prototype of this scorer on 10 English texts of 11 to 576 characters under all
/// 8 tables: the true decoding was never less than 0.38 better than its ciphertext
/// (`hello zorld`, AZERTY), and 0.61 for the Dvorak, Colemak and QWE/ABC tables. The best
/// wrong decoding of 22 English sentences was at most 0.16 better than the sentence, and
/// that of the decoder benchmarks' gibberish `miss` input 0.16.
const MIN_IMPROVEMENT: f32 = 0.2;

/// How many of the best-scoring decodings are run through the checker.
const CHECKED: usize = 2;

/// How many of the best-scoring decodings are handed back to the search when none of the
/// checked ones is identified.
const RETURNED: usize = 3;

/// A [`Table`] as a lookup from each character of a ciphertext to its decoding.
struct LayoutMap {
    /// The table's name, reported as the key
    name: &'static str,
    /// What each ASCII character decodes to, indexed by its code
    ascii: [char; 128],
    /// What each character of [`NON_ASCII`] decodes to, in the same order
    non_ascii: [char; NON_ASCII.len()],
}

impl LayoutMap {
    /// Builds the lookup for `table`. Characters that aren't legends of the layout the
    /// text was read as decode to themselves.
    fn new(table: &Table) -> Self {
        let mut ascii = ['\0'; 128];
        for (code, decoded) in (0u8..).zip(ascii.iter_mut()) {
            *decoded = char::from(code);
        }
        let mut non_ascii = NON_ASCII;
        for (read, typed) in table.read.chars().zip(table.typed.chars()) {
            if read.is_ascii() {
                ascii[usize::from(read as u8)] = typed;
            } else if let Some(index) = non_ascii_index(read) {
                non_ascii[index] = typed;
            }
        }
        LayoutMap {
            name: table.name,
            ascii,
            non_ascii,
        }
    }

    /// What `c` decodes to.
    fn decode(&self, c: char) -> char {
        if c.is_ascii() {
            self.ascii[usize::from(c as u8)]
        } else {
            non_ascii_index(c).map_or(c, |index| self.non_ascii[index])
        }
    }
}

/// The lookups for [`TABLES`], in the same order, built on first use.
static MAPS: Lazy<Vec<LayoutMap>> = Lazy::new(|| TABLES.iter().map(LayoutMap::new).collect());

/// The Keyboard layout decoder, call:
/// `let keyboard_layout_decoder = Decoder::<KeyboardLayoutDecoder>::new()` to create a new instance
/// And then call:
/// `result = keyboard_layout_decoder.crack(input, &checker)` to decode text typed on the wrong layout
/// The struct generated by new() comes from interface.rs
/// ```
/// use ciphey::decoders::keyboard_layout_decoder::KeyboardLayoutDecoder;
/// use ciphey::decoders::interface::{Crack, Decoder};
/// use ciphey::checkers::{athena::Athena, CheckerTypes, checker_type::{Check, Checker}};
///
/// let decode_keyboard_layout = Decoder::<KeyboardLayoutDecoder>::new();
/// let athena_checker = Checker::<Athena>::new();
/// let checker = CheckerTypes::CheckAthena(athena_checker);
///
/// // `hello world` typed on QWERTY keys and read as Dvorak
/// let result = decode_keyboard_layout.crack("d.nnr ,rpne", &checker);
/// assert!(result.success);
/// assert_eq!(result.unencrypted_text.unwrap()[0], "hello world");
/// assert_eq!(result.key.unwrap(), "QWERTY→Dvorak");
///
/// // The alphabet written as the QWERTY key order: A is Q, B is W, ...
/// let result = decode_keyboard_layout.crack("itssg vgksr", &checker);
/// assert_eq!(result.unencrypted_text.unwrap()[0], "hello world");
/// assert_eq!(result.key.unwrap(), "ABC→QWE");
///
/// // Plain English gets no closer to English under any layout, so nothing is checked
/// let result = decode_keyboard_layout.crack("hello world", &checker);
/// assert!(result.unencrypted_text.is_none());
/// ```
pub struct KeyboardLayoutDecoder;

impl Crack for Decoder<KeyboardLayoutDecoder> {
    fn new() -> Decoder<KeyboardLayoutDecoder> {
        Decoder {
            name: "Keyboard layout",
            description: "Text typed on one keyboard layout and read on another (QWERTY, Dvorak, Colemak, AZERTY), or the QWERTY key order substituted for the alphabet. Uses Low sensitivity for gibberish detection.",
            link: "https://www.dcode.fr/keyboard-change-cipher",
            tags: vec!["keyboard", "substitution", "decryption", "classic"],
            popularity: 0.4,
            phantom: std::marker::PhantomData,
        }
    }

    /// Ranks the decodings, checks the best `CHECKED` and returns the first one the
    /// checker identifies, with its table as the key. Otherwise returns the best
    /// `RETURNED`, unidentified, or nothing if no decoding is more English-like than the
    /// text itself.
    fn crack(&self, text: &str, checker: &CheckerTypes) -> CrackResult {
        trace!("Trying keyboard layouts with text {:?}", text);
        let mut results = CrackResult::new(self, text.to_string());

        let mut ranked = rank_candidates(text);
        if ranked.is_empty() {
            trace!("Keyboard layout: not worth decoding, or no layout makes it more English-like");
            return results;
        }

        // Use the checker with Low sensitivity, like the Caesar cracker
        let checker_with_sensitivity = checker.with_sensitivity(Sensitivity::Low);
        let identified =
            ranked
                .iter()
                .take(CHECKED)
                .enumerate()
                .find_map(|(index, (_, _, decoded))| {
                    let checker_result = checker_with_sensitivity.check(decoded);
                    checker_result
                        .is_identified
                        .then_some((index, checker_result))
                });
        if let Some((index, checker_result)) = identified {
            let (_, name, decoded) = ranked.swap_remove(index);
            trace!("Found a match with keyboard layout {}", name);
            results.unencrypted_text = Some(vec![decoded]);
            results.update_checker(&checker_result);
            results.key = Some(name.to_string());
            return results;
        }

        ranked.truncate(RETURNED);
        results.unencrypted_text =
            Some(ranked.into_iter().map(|(_, _, decoded)| decoded).collect());
        results
    }
    /// Gets all tags for this decoder
    fn get_tags(&self) -> &Vec<&str> {
        &self.tags
    }
    /// Gets the name for the current decoder
    fn get_name(&self) -> &str {
        self.name
    }
    /// Gets the popularity for the current decoder
    fn get_popularity(&self) -> f32 {
        self.popularity
    }
    /// Gets the description for the current decoder
    fn get_description(&self) -> &str {
        self.description
    }
    /// Gets the link for the current decoder
    fn get_link(&self) -> &str {
        self.link
    }
}

/// The decodings worth checking, best first, as (score, table name, decoding): those that
/// score more than [`MIN_IMPROVEMENT`] above `text` itself (see [`mean_pair_score`]), each
/// once. A decoding that changes nothing scores the same as `text`, so it is never kept.
///
/// Empty if `text` fails the pre-checks (see [`passes_pre_checks`]) or no table makes it
/// more English-like.
fn rank_candidates(text: &str) -> Vec<(f32, &'static str, String)> {
    if !passes_pre_checks(text) {
        return Vec::new();
    }
    let threshold = mean_pair_score(text.chars()) + MIN_IMPROVEMENT;

    let mut ranked: Vec<(f32, &'static str, String)> = Vec::new();
    for map in MAPS.iter() {
        // Scored without building the decoding: most of them don't pass
        let score = mean_pair_score(text.chars().map(|c| map.decode(c)));
        if score <= threshold {
            continue;
        }
        let decoded = decode_with(text, map);
        if ranked.iter().any(|(_, _, seen)| *seen == decoded) {
            continue;
        }
        ranked.push((score, map.name, decoded));
    }
    // A stable sort, so decodings that score the same keep the order of TABLES
    ranked.sort_by(|left, right| right.0.total_cmp(&left.0));
    ranked
}

/// Decodes `text` with one table: every legend of the layout it was read as becomes the
/// legend on the same key of the layout it was typed on, and anything else (whitespace,
/// other characters) is copied.
fn decode_with(text: &str, map: &LayoutMap) -> String {
    text.chars().map(|c| map.decode(c)).collect()
}

/// Whether `text` is worth decoding: every character is printable ASCII, a space, tab or
/// line break, or one of AZERTY's [`NON_ASCII`] legends; it has at least one ASCII letter
/// and at least [`MIN_NON_WHITESPACE`] characters other than whitespace; and it doesn't
/// change case inside words as often as Base64 does (see
/// [`MAX_LOWER_UPPER_PAIRS_ONE_IN`]). One pass, which stops at the first character that
/// can't have been typed on these layouts.
fn passes_pre_checks(text: &str) -> bool {
    let mut has_letter = false;
    let mut non_whitespace = 0usize;
    let mut letter_pairs = 0usize;
    let mut lower_upper_pairs = 0usize;
    // Whether the previous character is a lower-case letter, if it is a letter
    let mut previous_letter: Option<bool> = None;
    for c in text.chars() {
        let is_letter = match c {
            ' ' | '\t' | '\n' | '\r' => {
                previous_letter = None;
                continue;
            }
            '!'..='~' => c.is_ascii_alphabetic(),
            _ if non_ascii_index(c).is_some() => false,
            _ => return false,
        };
        non_whitespace += 1;
        if !is_letter {
            previous_letter = None;
            continue;
        }
        has_letter = true;
        if let Some(previous_lowercase) = previous_letter {
            letter_pairs += 1;
            if previous_lowercase && c.is_ascii_uppercase() {
                lower_upper_pairs += 1;
            }
        }
        previous_letter = Some(c.is_ascii_lowercase());
    }
    let changes_case_like_base64 = letter_pairs >= MIN_PAIRS_FOR_CASE_CHECK
        && lower_upper_pairs * MAX_LOWER_UPPER_PAIRS_ONE_IN > letter_pairs;
    has_letter && non_whitespace >= MIN_NON_WHITESPACE && !changes_case_like_base64
}

/// The mean score of the pairs of adjacent characters in `chars`: `ln P` of the pair from
/// the English letter-pair frequencies (`BIGRAM_LOG_PROBS`, case-folded) when both are
/// ASCII letters, [`OTHER_PAIR_SCORE`] when either is anything else. Pairs with
/// whitespace in them are skipped. Text with no pairs scores [`OTHER_PAIR_SCORE`].
fn mean_pair_score(chars: impl Iterator<Item = char>) -> f32 {
    let log_probs = &*BIGRAM_LOG_PROBS;
    // The previous character's letter index, or `None` at the start and after whitespace
    let mut previous: Option<Option<usize>> = None;
    let mut total = 0.0f64;
    let mut pairs = 0u32;
    for c in chars {
        if c.is_ascii_whitespace() {
            previous = None;
            continue;
        }
        let current = letter_index(c);
        if let Some(first) = previous {
            total += f64::from(match (first, current) {
                (Some(first), Some(second)) => log_probs[first][second],
                _ => OTHER_PAIR_SCORE,
            });
            pairs += 1;
        }
        previous = Some(current);
    }
    if pairs == 0 {
        OTHER_PAIR_SCORE
    } else {
        (total / f64::from(pairs)) as f32
    }
}

/// The position in the alphabet (0..26) of an ASCII letter, in either case.
fn letter_index(c: char) -> Option<usize> {
    if c.is_ascii_alphabetic() {
        Some(usize::from(c.to_ascii_lowercase() as u8 - b'a'))
    } else {
        None
    }
}

/// The position of `c` in [`NON_ASCII`], if it is one of AZERTY's non-ASCII legends.
fn non_ascii_index(c: char) -> Option<usize> {
    NON_ASCII.iter().position(|&legend| legend == c)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkers::{
        athena::Athena,
        checker_type::{Check, Checker},
        CheckerTypes,
    };
    use crate::decoders::interface::{Crack, Decoder};
    use std::collections::HashSet;

    // helper for tests
    fn get_athena_checker() -> CheckerTypes {
        let athena_checker = Checker::<Athena>::new();
        CheckerTypes::CheckAthena(athena_checker)
    }

    /// The lookup for the table called `name`.
    fn lookup(name: &str) -> &'static LayoutMap {
        MAPS.iter()
            .find(|map| map.name == name)
            .unwrap_or_else(|| panic!("no table named {name:?}"))
    }

    /// The bench `medium` plaintext, used by the search benchmarks too.
    const MEDIUM: &str =
        "Meet me at the old lighthouse after midnight and bring the map, the key and a torch.";

    /// The bench `long` plaintext.
    const LONG: &str = "Ciphey is an automated decoding tool. You give it encrypted or encoded text and it tries to work out what was done to it, without you having to know the key or even the cipher. It searches through many possible decodings, checks each candidate to see whether it looks like English or matches a known pattern such as an email address, and stops when it finds something that reads like plaintext. Most of the time this takes less than a second, which makes it handy for capture the flag challenges, puzzle hunts and for anyone who stumbles across a strange string in a log file.";

    /// [`LONG`] typed on QWERTY and read as Dvorak (the decoder benchmarks' `long` input).
    const LONG_DVORAK: &str = "Jcld.f co ab agyrmay.e e.jrecbi yrrnv Frg ick. cy .bjpfly.e rp .bjre.e y.qy abe cy ypc.o yr ,rpt rgy ,day ,ao erb. yr cyw ,cydrgy frg dakcbi yr tbr, yd. t.f rp .k.b yd. jcld.pv Cy o.apjd.o ydprgid mabf lroocxn. e.jrecbiow jd.jto .ajd jabeceay. yr o.. ,d.yd.p cy nrrto nct. >bincod rp mayjd.o a tbr,b layy.pb ogjd ao ab .macn aeep.oow abe oyrlo ,d.b cy ucbeo orm.ydcbi yday p.aeo nct. lnacby.qyv Mroy ru yd. ycm. ydco yat.o n.oo ydab a o.jrbew ,dcjd mat.o cy dabef urp jalygp. yd. unai jdann.bi.ow lg;;n. dgbyo abe urp abfrb. ,dr oygmxn.o ajproo a oypabi. oypcbi cb a nri ucn.v";

    /// (ciphertext, table, plaintext). Made with a Python 3 prototype of these tables
    /// (copied from xkeyboard-config 2.41) and decoded back with the opposite table; the
    /// first two are the examples in <https://github.com/bee-san/Ciphey/issues/977>. Athena
    /// identifies every plaintext at Low sensitivity, and the search doesn't take any of
    /// the ciphertexts for plaintext.
    const VECTORS: [(&str, &str, &str); 12] = [
        ("d.nnr ,rpne", "QWERTY→Dvorak", "hello world"),
        ("itssg vgksr", "ABC→QWE", "hello world"),
        ("pcssi bidsm", "QWE→ABC", "hello world"),
        ("jdpps ,soph", "Dvorak→QWERTY", "hello world"),
        ("hfiiy wypis", "QWERTY→Colemak", "hello world"),
        ("hkuu; w;sug", "Colemak→QWERTY", "hello world"),
        (
            "unai?,prbi{nafrgy{aiacb+",
            "QWERTY→Dvorak",
            "flag{wrong_layout_again}",
        ),
        (
            "ghf gpfarlpf ur blpufs lksfp ghf yis yae gpff",
            "QWERTY→Colemak",
            "the treasure is buried under the old oak tree",
        ),
        (
            "Fgziofu zg ltt itkt, dgct qsgfu hstqlt",
            "ABC→QWE",
            "Nothing to see here, move along please",
        ),
        (
            "G kjglv kjd ra;;,soh g; jghhdl gl rpagl ;gujk",
            "Dvorak→QWERTY",
            "I think the password is hidden in plain sight",
        ),
        (
            "Q,qwing jqww zqs ,y ,o,ùs qnthe,",
            "QWERTY→AZERTY",
            "Amazing jazz was my mom's anthem",
        ),
        (
            "M..y m. ay yd. rne ncidydrgo. auy.p mcebcidy abe xpcbi yd. malw yd. t.f abe a yrpjdv",
            "QWERTY→Dvorak",
            MEDIUM,
        ),
    ];

    /// Ciphertexts that read as English already: the search returns them unchanged before
    /// any decoder runs, so only `crack` can show that they decode.
    const PRE_IDENTIFIED: [(&str, &str, &str); 2] = [
        ("hello zorld", "QWERTY→AZERTY", "hello world"),
        (
            "Dttz dt qz zit gsr souizigxlt qyztk dorfouiz qfr wkofu zit dqh, zit atn qfr q zgkei.",
            "ABC→QWE",
            MEDIUM,
        ),
    ];

    /// Every vector: [`VECTORS`], [`PRE_IDENTIFIED`] and [`LONG_DVORAK`].
    fn all_vectors() -> Vec<(&'static str, &'static str, &'static str)> {
        let mut vectors = VECTORS.to_vec();
        vectors.extend(PRE_IDENTIFIED);
        vectors.push((LONG_DVORAK, "QWERTY→Dvorak", LONG));
        vectors
    }

    /// The table that undoes `table`: typed and read swapped.
    fn opposite(table: &Table) -> &'static Table {
        TABLES
            .iter()
            .find(|other| other.typed == table.read && other.read == table.typed)
            .unwrap_or_else(|| panic!("{} has no opposite", table.name))
    }

    #[test]
    fn layouts_have_47_keys_with_distinct_legends() {
        let printable: HashSet<char> = ('!'..='~').collect();
        for (name, layout) in [
            ("QWERTY", QWERTY),
            ("Dvorak", DVORAK),
            ("Colemak", COLEMAK),
            ("AZERTY", AZERTY),
        ] {
            let legends: Vec<char> = layout.chars().collect();
            assert_eq!(legends.len(), 94, "{name}");
            let distinct: HashSet<char> = legends.iter().copied().collect();
            assert_eq!(distinct.len(), 94, "{name} has a legend twice");
            // Shift turns each letter key's letter upper case
            for (unshifted, shifted) in legends[..47].iter().zip(&legends[47..]) {
                if unshifted.is_ascii_lowercase() {
                    assert_eq!(*shifted, unshifted.to_ascii_uppercase(), "{name}");
                }
            }
            if name == "AZERTY" {
                let non_ascii: HashSet<char> =
                    distinct.iter().copied().filter(|c| !c.is_ascii()).collect();
                assert_eq!(
                    non_ascii,
                    NON_ASCII.into_iter().collect::<HashSet<char>>(),
                    "{name}"
                );
            } else {
                // The US layouts are permutations of the printable ASCII characters
                assert_eq!(distinct, printable, "{name}");
            }
        }
        let letters: HashSet<char> = ('a'..='z').chain('A'..='Z').collect();
        for order in [QWE, ABC] {
            assert_eq!(order.chars().count(), 52);
            assert_eq!(order.chars().collect::<HashSet<char>>(), letters);
        }
        // AZERTY doesn't have these, so text with them can't be typed on it
        let missing: String = QWERTY.chars().filter(|&c| !AZERTY.contains(c)).collect();
        assert_eq!(missing, "`[]\\@#{}|<>");
    }

    #[test]
    fn eight_tables_each_with_its_opposite() {
        assert_eq!(MAPS.len(), 8);
        let names: HashSet<&str> = TABLES.iter().map(|table| table.name).collect();
        assert_eq!(names.len(), 8);
        for table in &TABLES {
            let opposite = opposite(table);
            assert_ne!(opposite.name, table.name);
            // QWERTZ is left out on purpose (see the module docs)
            assert!(!table.name.contains("QWERTZ"));
        }
    }

    #[test]
    fn decode_with_round_trips_every_table() {
        for table in &TABLES {
            let map = lookup(table.name);
            // Every legend the text was read as decodes to the legend typed on its key
            let decoded = decode_with(table.read, map);
            assert_eq!(decoded, table.typed, "{}", table.name);
            // and the opposite table reads it back
            let opposite = opposite(table);
            assert_eq!(
                decode_with(&decoded, lookup(opposite.name)),
                table.read,
                "{}",
                table.name
            );
        }
    }

    #[test]
    fn issue_examples_decode() {
        assert_eq!(
            decode_with("d.nnr ,rpne", lookup("QWERTY→Dvorak")),
            "hello world"
        );
        assert_eq!(decode_with("itssg vgksr", lookup("ABC→QWE")), "hello world");
    }

    #[test]
    fn vectors_decode_and_encode() {
        for (ciphertext, name, plaintext) in all_vectors() {
            assert_eq!(decode_with(ciphertext, lookup(name)), plaintext, "{name}");
            let opposite = opposite(TABLES.iter().find(|t| t.name == name).unwrap());
            assert_eq!(
                decode_with(plaintext, lookup(opposite.name)),
                ciphertext,
                "{name}"
            );
        }
    }

    #[test]
    fn plaintext_ranks_in_the_top_two() {
        for (ciphertext, name, plaintext) in all_vectors() {
            let ranked = rank_candidates(ciphertext);
            let rank = ranked
                .iter()
                .position(|(_, _, decoded)| decoded == plaintext)
                .unwrap_or_else(|| panic!("{ciphertext:?} lost {plaintext:?}: {ranked:?}"));
            assert!(rank < CHECKED, "{ciphertext:?}: ranked {rank}: {ranked:?}");
            assert_eq!(ranked[rank].1, name, "{ciphertext:?}");
        }
    }

    #[test]
    fn ranking_is_sorted_and_without_repeats() {
        for (ciphertext, _, _) in all_vectors() {
            let ranked = rank_candidates(ciphertext);
            assert!(ranked.windows(2).all(|pair| pair[0].0 >= pair[1].0));
            let decodings: HashSet<&String> = ranked.iter().map(|(_, _, d)| d).collect();
            assert_eq!(decodings.len(), ranked.len(), "{ranked:?}");
            assert!(ranked.iter().all(|(_, _, decoded)| decoded != ciphertext));
            let threshold = mean_pair_score(ciphertext.chars()) + MIN_IMPROVEMENT;
            assert!(ranked.iter().all(|(score, _, _)| *score > threshold));
        }
    }

    #[test]
    fn vectors_are_cracked_with_their_table_as_key() {
        let decoder = Decoder::<KeyboardLayoutDecoder>::new();
        let mut vectors = VECTORS.to_vec();
        vectors.extend(PRE_IDENTIFIED);
        for (ciphertext, name, plaintext) in vectors {
            let result = decoder.crack(ciphertext, &get_athena_checker());
            assert!(result.success, "{ciphertext:?} was not cracked: {result:?}");
            assert_eq!(result.unencrypted_text.unwrap(), vec![plaintext]);
            assert_eq!(result.key.as_deref(), Some(name), "{ciphertext:?}");
            assert_eq!(result.decoder, "Keyboard layout");
        }
    }

    #[test]
    fn long_text_is_cracked() {
        let decoder = Decoder::<KeyboardLayoutDecoder>::new();
        let result = decoder.crack(LONG_DVORAK, &get_athena_checker());
        assert!(result.success, "{result:?}");
        assert_eq!(result.unencrypted_text.unwrap(), vec![LONG]);
        assert_eq!(result.key.as_deref(), Some("QWERTY→Dvorak"));
    }

    #[test]
    fn flag_is_identified_by_lemmeknow() {
        let decoder = Decoder::<KeyboardLayoutDecoder>::new();
        let result = decoder.crack("unai?,prbi{nafrgy{aiacb+", &get_athena_checker());
        assert!(result.success);
        assert_eq!(
            result.unencrypted_text.unwrap()[0],
            "flag{wrong_layout_again}"
        );
        assert_eq!(result.checker_name, "LemmeKnow Checker");
    }

    #[test]
    fn case_is_kept() {
        assert_eq!(decode_with("M..y", lookup("QWERTY→Dvorak")), "Meet");
        assert_eq!(decode_with("Q,qwing", lookup("QWERTY→AZERTY")), "Amazing");
        assert_eq!(
            decode_with("Fgziofu HSTQLT", lookup("ABC→QWE")),
            "Nothing PLEASE"
        );
        assert_eq!(decode_with("PCSSI bidsm", lookup("QWE→ABC")), "HELLO world");
    }

    #[test]
    fn digits_only_change_with_azerty() {
        let digits = "0123456789";
        for name in [
            "QWERTY→Dvorak",
            "Dvorak→QWERTY",
            "QWERTY→Colemak",
            "Colemak→QWERTY",
            "QWE→ABC",
            "ABC→QWE",
        ] {
            assert_eq!(decode_with(digits, lookup(name)), digits, "{name}");
        }
        // AZERTY's number row gives `&é"'(-è_çà` without Shift and the digits with it
        assert_eq!(
            decode_with("1234567890", lookup("AZERTY→QWERTY")),
            "&é\"'(-è_çà"
        );
        assert_eq!(
            decode_with("&é\"'(-è_çà", lookup("QWERTY→AZERTY")),
            "1234567890"
        );
        assert_eq!(
            decode_with("1234567890", lookup("QWERTY→AZERTY")),
            "!@#$%^&*()"
        );
    }

    #[test]
    fn letters_only_tables_leave_everything_else_alone() {
        let others = "0123456789 `~!@#$%^&*()-_=+[]{}\\|;:'\",.<>/?\t\n²éù";
        for name in ["QWE→ABC", "ABC→QWE"] {
            assert_eq!(decode_with(others, lookup(name)), others, "{name}");
        }
    }

    #[test]
    fn whitespace_and_other_characters_are_copied() {
        let text = "a b\tc\nd\r\n日本 😀";
        assert_eq!(
            decode_with(text, lookup("QWERTY→Dvorak")),
            "a n\ti\nh\r\n日本 😀"
        );
        // Reading as AZERTY leaves alone what AZERTY can't type
        assert_eq!(decode_with("{[@#]}", lookup("QWERTY→AZERTY")), "{[@#]}");
    }

    #[test]
    fn non_ascii_legends_decode_both_ways() {
        // Typed on AZERTY, read as QWERTY: the output has AZERTY's accents
        assert_eq!(decode_with("2'7;", lookup("AZERTY→QWERTY")), "éùèm");
        // Typed on QWERTY, read as AZERTY: the accents are the ciphertext
        assert_eq!(decode_with("éùèm", lookup("QWERTY→AZERTY")), "2'7;");
        assert_eq!(decode_with("²°¨£µ§", lookup("QWERTY→AZERTY")), "`_{}|?");
    }

    #[test]
    fn pre_checks_reject_what_cannot_be_typed_on_these_layouts() {
        let decoder = Decoder::<KeyboardLayoutDecoder>::new();
        for text in [
            "",
            "😀",
            "ab",
            "日本",
            "abc",
            "a b c",
            "    ",
            "\n\t\r",
            // no ASCII letter
            "1234",
            "!?!?.,",
            "éèàù",
            // characters no layout here has
            "héllo wörld",
            "hello 😀 world",
            "hello\u{0}world",
            "hello\u{c}world",
            "hello\u{a0}world",
            "日本語のテキスト",
        ] {
            assert!(!passes_pre_checks(text), "{text:?} passed the pre-checks");
            assert!(rank_candidates(text).is_empty(), "{text:?}");
            let result = decoder.crack(text, &get_athena_checker());
            assert!(!result.success, "{text:?}");
            assert!(result.unencrypted_text.is_none(), "{text:?}");
            assert!(result.key.is_none(), "{text:?}");
        }
        for text in [
            "abcd",
            "a1!2",
            "a b c d",
            "Q,qwing",
            "çàéa",
            "line\r\nbreaks\tand tabs",
        ] {
            assert!(passes_pre_checks(text), "{text:?} failed the pre-checks");
        }
    }

    #[test]
    fn plain_english_is_never_checked() {
        // No table makes English more English-like: the gate stops it, so the checker
        // isn't run and nothing is returned
        let decoder = Decoder::<KeyboardLayoutDecoder>::new();
        for text in [
            "hello world",
            "Hello, World!",
            "The quick brown fox jumps over the lazy dog",
            MEDIUM,
            LONG,
            "Nothing to see here, move along please",
            "I think the password is hidden in plain sight",
            "the treasure is buried under the old oak tree",
            "Amazing jazz was my mom's anthem",
            "It was the best of times, it was the worst of times",
            "Sphinx of black quartz, judge my vow.",
            "We attack at dawn",
            "Lorem ipsum dolor sit amet, consectetur adipiscing elit",
            "To be or not to be, that is the question",
            "Never gonna give you up, never gonna let you down",
            "flag{keyboard_layout}",
        ] {
            assert!(passes_pre_checks(text), "{text:?}");
            assert!(rank_candidates(text).is_empty(), "{text:?} passed the gate");
            let result = decoder.crack(text, &get_athena_checker());
            assert!(!result.success, "{text:?}");
            assert!(result.unencrypted_text.is_none(), "{text:?}");
        }
    }

    #[test]
    fn gate_skips_other_encodings() {
        let decoder = Decoder::<KeyboardLayoutDecoder>::new();
        for text in [
            // Atbash of `hello world`
            "svool dliow",
            // ROT13 of MEDIUM
            "Zrrg zr ng gur byq yvtugubhfr nsgre zvqavtug naq oevat gur znc, gur xrl naq n gbepu.",
            // hex of `hello world`
            "68656c6c6f20776f726c64",
        ] {
            assert!(passes_pre_checks(text), "{text:?}");
            assert!(rank_candidates(text).is_empty(), "{text:?} passed the gate");
            let result = decoder.crack(text, &get_athena_checker());
            assert!(result.unencrypted_text.is_none(), "{text:?}");
        }
    }

    #[test]
    fn unidentified_text_returns_the_three_best_decodings() {
        // A keyboard shift (#976), not a layout change: four decodings pass the gate, the
        // best two aren't identified, and the best three go back to the search
        let decoder = Decoder::<KeyboardLayoutDecoder>::new();
        let text = "jr;;p ept;f";
        let ranked = rank_candidates(text);
        assert!(ranked.len() > RETURNED, "{ranked:?}");
        let result = decoder.crack(text, &get_athena_checker());
        assert!(!result.success, "{result:?}");
        assert!(result.key.is_none());
        let expected: Vec<String> = ranked
            .into_iter()
            .take(RETURNED)
            .map(|(_, _, decoded)| decoded)
            .collect();
        assert_eq!(result.unencrypted_text.unwrap(), expected);

        // ROT13 of a short phrase passes the gate too, but isn't identified either
        let result = decoder.crack("Zrrg zr ng gur byq yvtugubhfr", &get_athena_checker());
        assert!(!result.success, "{result:?}");
        assert!(result.unencrypted_text.unwrap().len() <= RETURNED);
    }

    #[test]
    fn base64_like_case_changes_are_turned_away() {
        let decoder = Decoder::<KeyboardLayoutDecoder>::new();
        for text in [
            // Base64 of MEDIUM: 23 of 86 letter pairs are `aB`. Without this pre-check it
            // passes the gate under ABC→QWE and QWE→ABC, which costs two checks
            "TWVldCBtZSBhdCB0aGUgb2xkIGxpZ2h0aG91c2UgYWZ0ZXIgbWlkbmlnaHQgYW5kIGJyaW5nIHRoZSBtYXAsIHRoZSBrZXkgYW5kIGEgdG9yY2gu",
            // Base64 of the Dvorak ciphertext of MEDIUM: the search decodes the Base64 first
            "TS4ueSBtLiBheSB5ZC4gcm5lIG5jaWR5ZHJnby4gYXV5LnAgbWNlYmNpZHkgYWJlIHhwY2JpIHlkLiBtYWx3IHlkLiB0LmYgYWJlIGEgeXJwamR2",
            // The decoder benchmarks' miss input (benches/data/decoders.toml): 7 of 23
            "T00 l3= ox+#G WKyV pajU6j qxH@ %B4+a 5Pn^ 7p_v1q 9sLvu *+36i R5rL&3 mVJZI iO0 Ut8_m COTV",
            // Base58 (Bitcoin) of MEDIUM, the search benchmarks' base58_bitcoin input
            "6X6FW9Fv3pE3p6JtGkbStCFRnzXNxB2FpZzj3qrCm9DJAyJXHm7eixRZfy9rkN8nTwk8SRHWUDmeoc7qJTrURpjgfxQqR3oSt9wR67mGcrjWXhrx2Zb",
        ] {
            assert!(!passes_pre_checks(text), "{text:?} passed the pre-checks");
            let result = decoder.crack(text, &get_athena_checker());
            assert!(result.unencrypted_text.is_none(), "{text:?}");
        }
        // Short texts aren't checked for it: too few pairs to tell
        assert!(passes_pre_checks("aGVsbG8gd29ybGQ="));
        // Ciphertexts of English change case at the start of sentences, and where the
        // plaintext's punctuation is a capital on the other layout (`:` typed on QWERTY is
        // `S` on Dvorak), far less often than one pair in eight. The DawgCTF 2020 "Qwerky
        // Qwerty" ciphertext (tests/keyboard_layout_decoder.rs) has 3 in 122.
        assert!(passes_pre_checks(LONG_DVORAK));
        assert!(passes_pre_checks(
            "Oh no... whays.. ,dats hall.bing yr me... nr br brw ,df M>vv ,df BR<vvvvv Xgy \
             ,day-o ydcovv yd.p. co a bry. cb mf dabeS U.ap bry e.ap jdcnew ydco co rbnf a \
             ep.amvv A ep.am yday dao x..b jago.e xf JRKCE[19v Mabf 'g.oycrbo frg dak.w ,dcn. \
             frg-k. x..b aon..lv D.p.cb ydco bry. nc.o yd. abo,.p frg o..tS Ea,iJYU?L4ydu1be3p+"
        ));
        assert!(passes_pre_checks(&MEDIUM.to_uppercase()));
        // One `aB` pair in eight is allowed (4 in 32 here), more isn't
        assert!(passes_pre_checks("abcdefghI abcdefghI abcdefghI abcdefghI"));
        assert!(!passes_pre_checks(
            "abcdEfghI abcdefghI abcdefghI abcdefghI"
        ));
    }

    #[test]
    fn known_misses_fall_under_the_gate() {
        // `Hello, World!` typed on AZERTY and read as QWERTY scores lower than its
        // ciphertext, and so does a flag of mostly digits under QWERTY→Dvorak
        for (ciphertext, name, plaintext) in [
            ("Hellom Zorld/", "AZERTY→QWERTY", "Hello, World!"),
            (
                "unai?yd1o{1o{4{un4i+",
                "QWERTY→Dvorak",
                "flag{th1s_1s_4_fl4g}",
            ),
        ] {
            assert_eq!(decode_with(ciphertext, lookup(name)), plaintext);
            assert!(!rank_candidates(ciphertext)
                .iter()
                .any(|(_, _, decoded)| decoded == plaintext));
        }
    }

    #[test]
    fn pair_scores() {
        let log_probs = &*BIGRAM_LOG_PROBS;
        let th = log_probs[19][7];
        assert_eq!(mean_pair_score("".chars()), OTHER_PAIR_SCORE);
        assert_eq!(mean_pair_score("t".chars()), OTHER_PAIR_SCORE);
        assert_eq!(mean_pair_score("th".chars()), th);
        // Case-folded
        assert_eq!(mean_pair_score("TH".chars()), th);
        assert_eq!(mean_pair_score("tH".chars()), th);
        // Pairs across whitespace are skipped
        assert_eq!(mean_pair_score("t h".chars()), OTHER_PAIR_SCORE);
        assert_eq!(mean_pair_score("th th\nth\tth".chars()), th);
        // Pairs with anything but letters score OTHER_PAIR_SCORE
        assert_eq!(mean_pair_score("t1".chars()), OTHER_PAIR_SCORE);
        assert_eq!(mean_pair_score("é!".chars()), OTHER_PAIR_SCORE);
        assert!((mean_pair_score("th1".chars()) - (th + OTHER_PAIR_SCORE) / 2.0).abs() < 1e-5);
        // English scores higher than its decodings
        assert!(
            mean_pair_score("hello world".chars())
                > mean_pair_score("d.nnr ,rpne".chars()) + MIN_IMPROVEMENT
        );
    }

    #[test]
    fn decoder_metadata() {
        let decoder = Decoder::<KeyboardLayoutDecoder>::new();
        assert_eq!(decoder.get_name(), "Keyboard layout");
        assert_eq!(decoder.get_popularity(), 0.4);
        assert_eq!(
            decoder.get_link(),
            "https://www.dcode.fr/keyboard-change-cipher"
        );
        assert!(decoder.get_description().contains("Low sensitivity"));
        // It ranks candidates, so it isn't tagged "decoder", and it isn't reciprocal:
        // Dvorak→QWERTY twice is not the identity
        let tags = decoder.get_tags();
        assert_eq!(
            tags,
            &vec!["keyboard", "substitution", "decryption", "classic"]
        );
        let twice = decode_with(
            &decode_with("hello world", lookup("Dvorak→QWERTY")),
            lookup("Dvorak→QWERTY"),
        );
        assert_ne!(twice, "hello world");
    }

    #[test]
    fn registered_once() {
        let decoders = crate::filtration_system::get_decoder_by_name("Keyboard layout");
        assert_eq!(decoders.components.len(), 1);
        assert_eq!(decoders.components[0].get_name(), "Keyboard layout");
        let decoder = crate::decoders::DECODER_MAP
            .get("Keyboard layout")
            .expect("Keyboard layout is in DECODER_MAP")
            .get::<()>();
        assert_eq!(decoder.get_name(), "Keyboard layout");
    }
}
