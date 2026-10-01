//! Vigenère cipher decoder with automated key detection
//! Uses Index of Coincidence (IoC) for key length detection and frequency analysis for key discovery
//! Returns Option<String> with the decrypted text if successful
//! Uses Medium sensitivity for gibberish detection as the default.

use super::crack_results::CrackResult;
use super::interface::{Crack, Decoder};
use crate::checkers::CheckerTypes;
use gibberish_or_not::Sensitivity;
use log::{debug, trace};
use once_cell::sync::Lazy;
use std::fs;
use std::path::Path;

/// Vigenere square where the first index is ciphertext and the second index
/// is the key
static VIGENERE_SQUARE: Lazy<Vec<Vec<char>>> = Lazy::new(|| {
    let mut square = vec![vec![' '; 26]; 26];
    for (i, row) in square.iter_mut().enumerate() {
        for (j, element) in row.iter_mut().enumerate() {
            *element = (((((i as i32) - (j as i32) + 26) % 26) as u8) + b'A') as char;
        }
    }
    square
});

/// English bigrams for determining fitness
static ENGLISH_BIGRAMS: Lazy<Vec<Vec<i64>>> = Lazy::new(|| {
    let mut bigrams_vec = vec![vec![0; 26]; 26];

    // Path to english bigrams file
    let f_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("storage")
        .join("ngrams")
        .join("english_bigrams.txt");

    // Read the file content
    if let Ok(content) = fs::read_to_string(&f_path) {
        let content_lines = content.split('\n');
        for line in content_lines {
            if line.is_empty() {
                continue;
            }
            let line_split: Vec<&str> = line.split_ascii_whitespace().collect();
            if line_split.is_empty() {
                continue;
            }
            let mut chars_itr = line_split[0].chars();
            let char1: char = chars_itr
                .next()
                .expect("Could not retrieve first char")
                .to_ascii_uppercase();
            let char2: char = chars_itr
                .next()
                .expect("Could not retrieve second char")
                .to_ascii_uppercase();

            let fitness = line_split[1]
                .parse::<i64>()
                .expect("Could not parse fitness value");

            bigrams_vec[(char1 as u8 - b'A') as usize][(char2 as u8 - b'A') as usize] = fitness;
        }
    }

    bigrams_vec
});

/// The Vigenère decoder struct
pub struct VigenereDecoder;

impl Crack for Decoder<VigenereDecoder> {
    fn new() -> Decoder<VigenereDecoder> {
        Decoder {
            name: "Vigenere",
            description: "A polyalphabetic substitution cipher using a keyword to shift each letter. This implementation automatically detects the key length and breaks the cipher. Uses Medium sensitivity for gibberish detection.",
            link: "https://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher",
            tags: vec!["substitution", "classical"],
            popularity: 0.6,
            phantom: std::marker::PhantomData,
        }
    }

    fn crack(&self, text: &str, checker: &CheckerTypes) -> CrackResult {
        trace!("Attempting Vigenère decryption on text: {:?}", text);
        let mut results = CrackResult::new(self, text.to_string());

        // Clean the input text (remove non-alphabetic characters)
        let clean_text: String = text.chars().filter(|c| c.is_ascii_alphabetic()).collect();

        if clean_text.is_empty() {
            debug!("No valid characters found in input text");
            return results;
        }

        let checker_with_sensitivity = checker.with_sensitivity(Sensitivity::Medium);
        let mut checker_result = checker_with_sensitivity.check(text);

        for key_length in 3..30 {
            // Use Medium sensitivity for Vigenere decoder
            let key = break_vigenere(text, key_length);
            let key_str = key.as_str().trim();
            if key_str.is_empty() {
                continue;
            }
            let decode_attempt = decrypt(text, key_str);
            checker_result = checker_with_sensitivity.check(&decode_attempt);
            if checker_result.is_identified {
                results.unencrypted_text = Some(vec![decode_attempt]);
                results.update_checker(&checker_result);
                results.key = Some(key);
                return results;
            }
        }

        results.unencrypted_text = Some(vec![String::new()]);
        results.update_checker(&checker_result);
        results
    }

    fn get_tags(&self) -> &Vec<&str> {
        &self.tags
    }

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

/// Ported from the PHP implementation shown in https://www.guballa.de/bits-and-bytes/implementierung-des-vigenere-solvers
/// Attempts to break the Vigenere cipher using bigrams
fn break_vigenere(text: &str, key_length: usize) -> String {
    let mut cipher_text: Vec<usize> = Vec::new();
    for c in text.chars() {
        // Must be ASCII: `is_alphabetic` also accepts e.g. 'À', whose
        // `to_ascii_uppercase() as u8 - b'A'` lands outside the 26-entry
        // VIGENERE_SQUARE and panics. `decrypt` below uses the same filter.
        if c.is_ascii_alphabetic() {
            cipher_text.push(((c.to_ascii_uppercase() as u8) - b'A') as usize);
        }
    }

    let mut best_fitness = 0;
    let mut best_key_ch2 = ' ';
    let mut best_score_0 = 0;
    let mut best_key_ch1_0 = ' ';
    let mut prev_best_score = 0;
    let mut prev_best_key_ch2 = ' ';

    let mut key = vec![' '; key_length];
    for (key_idx, key_char) in key.iter_mut().enumerate().take(key_length) {
        let mut best_key_ch1 = ' ';
        best_fitness = 0;

        for key_ch1 in 0..26 {
            for key_ch2 in 0..26 {
                let mut fitness = 0;
                for text_idx in (key_idx..(cipher_text.len() - 1)).step_by(key_length) {
                    let clear_ch1 = (VIGENERE_SQUARE[cipher_text[text_idx]][key_ch1] as u8) - b'A';
                    let clear_ch2 =
                        (VIGENERE_SQUARE[cipher_text[text_idx + 1]][key_ch2] as u8) - b'A';
                    fitness += ENGLISH_BIGRAMS[clear_ch1 as usize][clear_ch2 as usize];
                }
                if fitness > best_fitness {
                    best_fitness = fitness;
                    best_key_ch1 = ((key_ch1 as u8) + b'A') as char;
                    best_key_ch2 = ((key_ch2 as u8) + b'A') as char;
                }
            }
        }
        if key_idx == 0 {
            best_score_0 = best_fitness;
            best_key_ch1_0 = best_key_ch1;
        } else {
            *key_char = if prev_best_score > best_fitness {
                prev_best_key_ch2
            } else {
                best_key_ch1
            };
        }
        prev_best_score = best_fitness;
        prev_best_key_ch2 = best_key_ch2
    }
    key[0] = if best_fitness > best_score_0 {
        best_key_ch2
    } else {
        best_key_ch1_0
    };
    key.into_iter().collect()
}

/// Decrypt text using the found key
fn decrypt(text: &str, key: &str) -> String {
    let key_bytes: Vec<u8> = key.bytes().collect();
    let mut result = String::with_capacity(text.len());
    let mut key_idx = 0;

    for c in text.chars() {
        if c.is_ascii_alphabetic() {
            let shift = (key_bytes[key_idx % key_bytes.len()] - b'A') as i8;
            let base = if c.is_ascii_uppercase() { b'A' } else { b'a' };
            let pos = ((c as u8) - base) as i8;
            let new_pos = ((pos - shift + 26) % 26) as u8;
            result.push((base + new_pos) as char);
            key_idx += 1;
        } else {
            result.push(c);
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkers::{
        athena::Athena,
        checker_type::{Check, Checker},
        CheckerTypes,
    };

    fn get_athena_checker() -> CheckerTypes {
        let athena_checker = Checker::<Athena>::new();
        CheckerTypes::CheckAthena(athena_checker)
    }

    #[test]
    fn test_vigenere_decoding_long() {
        let vigenere_decoder = Decoder::<VigenereDecoder>::new();
        let result = vigenere_decoder
            .crack(
                "eznwxg kce yjmwuckgrttta ucixkb ceb sxkwfv tpkqwwj rnima qw ccvwlgu mg xvktpnixl bgor, xgktwugcz (jcv emi equkkcs mw) Jcjc64, Wxfifvaxfit, Erchtz kkgftk, ZWV13, LPA xvkqugcz, ivf dycr uwtv. Gi namu rbktvkgu yazwzkkfbl ivf ycjkqavzah mw qfvlibng vyc tgkwfzlv mgxg rls txxnp rwx ixrimekqivv btvwlkee bxbpqu, mummv jrlseqvi dsamqxnv jprmzu fd tgkwfzlv tcbqdyibkincw.",
                &get_athena_checker(),
            )
            .unencrypted_text.expect("No unencrypted text for Vigenere decoder");

        let decoded_text = result
            .first()
            .expect("No unencrypted text for Vigenere decoder");

        assert_eq!(decoded_text, "ciphey can automatically detect and decode various types of encoded or encrypted text, including (but not limited to) Base64, Hexadecimal, Caesar cipher, ROT13, URL encoding, and many more. It uses advanced algorithms and heuristics to identify the encoding type and apply the appropriate decoding method, often handling multiple layers of encoding automatically.");
    }

    #[test]
    fn test_vigenere_decoding_long_correct_key() {
        let vigenere_decoder = Decoder::<VigenereDecoder>::new();
        let result = vigenere_decoder
            .crack(
                "eznwxg kce yjmwuckgrttta ucixkb ceb sxkwfv tpkqwwj rnima qw ccvwlgu mg xvktpnixl bgor, xgktwugcz (jcv emi equkkcs mw) Jcjc64, Wxfifvaxfit, Erchtz kkgftk, ZWV13, LPA xvkqugcz, ivf dycr uwtv. Gi namu rbktvkgu yazwzkkfbl ivf ycjkqavzah mw qfvlibng vyc tgkwfzlv mgxg rls txxnp rwx ixrimekqivv btvwlkee bxbpqu, mummv jrlseqvi dsamqxnv jprmzu fd tgkwfzlv tcbqdyibkincw.",
                &get_athena_checker(),
            )
            .key.expect("No key for Vigenere decoder");

        assert_eq!(result, "CRYPTII");
    }

    #[test]
    fn test_vigenere_decoding_special_chars() {
        let vigenere_decoder = Decoder::<VigenereDecoder>::new();
        let result = vigenere_decoder
            .crack(
                "Ck jdp tqiyr, p vib'u gsebta gonpgl bq tmkxz uqjr dy bpg vvehamf jsgyikg fd xma mavq. Iam lqdchmqk err wta zckftk xwqi adewz xzqxhv ipu mceg byf rnima qw adgm kgcjh, hxbkdgoxl nqi qtgaqvztxmg bq sjjx ivf pcaewekjf vkmmp; zrh tjqnzrn mw lkjrxgockjf qxbegvl gxl ipu egxmv kj jxfqbgu.",
                &get_athena_checker(),
            )
            .unencrypted_text.expect("No unencrypted text for Vigenere decoder");

        let decoded_text = result
            .first()
            .expect("No unencrypted text for Vigenere decoder");

        assert_eq!(decoded_text, "At low light, a cat's pupils expand to cover most of the exposed surface of its eyes. The domestic cat has rather poor color vision and only two types of cone cells, optimized for sensitivity to blue and yellowish green; its ability to distinguish between red and green is limited.");
    }

    #[test]
    fn test_vigenere_decoding_special_chars_correct_key() {
        let vigenere_decoder = Decoder::<VigenereDecoder>::new();
        let result = vigenere_decoder
            .crack(
                "Ck jdp tqiyr, p vib'u gsebta gonpgl bq tmkxz uqjr dy bpg vvehamf jsgyikg fd xma mavq. Iam lqdchmqk err wta zckftk xwqi adewz xzqxhv ipu mceg byf rnima qw adgm kgcjh, hxbkdgoxl nqi qtgaqvztxmg bq sjjx ivf pcaewekjf vkmmp; zrh tjqnzrn mw lkjrxgockjf qxbegvl gxl ipu egxmv kj jxfqbgu.",
                &get_athena_checker(),
            )
            .key.expect("No key for Vigenere decoder");

        assert_eq!(result, "CRYPTII");
    }

    #[test]
    fn test_vigenere_cat_wikipedia() {
        let vigenere_decoder = Decoder::<VigenereDecoder>::new();
        let result = vigenere_decoder
            .crack(
                "Err xgbmncgvxvkg zq toqlger xg bpgzp puqtkkw ih ilcgr, axizp kfghcoj fzhxzdckgdg, ivf jmaom xtfzaxua, yzrw kmagrpra apqngcz bpgp ndlamuj qikwvi dcbhzqgj, cmaqjkk ltnzwrcyhmqkkkw, pgl lkjnatg kqxlxmqdg jixeta efketzidcc ih i gqllv vpqnu. Apm kwodscbkivzmc bvknlbtl umqngcz, xctigcz, bzkcjxgo, pkjqxgo, otfuabvo, iiscmqvi, rls uwla cyczciiv. Gi viv jvyg lwcpuq ihw nczli hz bqf fxzp qp wptjcmptw uhz pwdyc xizu, jsra ia vymhx uifv zn luinc kpfuinj. Gi lmktvrtl ivf gcgvmqxvq eamzqdmcxa. ",
                &get_athena_checker(),
            )
            .unencrypted_text
            .expect("No unencrypted text for Vigenere decoder");

        let decoded_text = result
            .first()
            .expect("No unencrypted text for Vigenere decoder");

        assert_eq!(decoded_text, "Cat intelligence is evident in their ability to adapt, learn through observation, and solve problems, with research showing they possess strong memories, exhibit neuroplasticity, and display cognitive skills comparable to a young child. Cat communication includes meowing, purring, trilling, hissing, growling, grunting, and body language. It can hear sounds too faint or too high in frequency for human ears, such as those made by small mammals. It secretes and perceives pheromones. ");
    }

    #[test]
    fn test_vigenere_cat_wikipedia_correct_key() {
        let vigenere_decoder = Decoder::<VigenereDecoder>::new();
        let result = vigenere_decoder
            .crack(
                "Err xgbmncgvxvkg zq toqlger xg bpgzp puqtkkw ih ilcgr, axizp kfghcoj fzhxzdckgdg, ivf jmaom xtfzaxua, yzrw kmagrpra apqngcz bpgp ndlamuj qikwvi dcbhzqgj, cmaqjkk ltnzwrcyhmqkkkw, pgl lkjnatg kqxlxmqdg jixeta efketzidcc ih i gqllv vpqnu. Apm kwodscbkivzmc bvknlbtl umqngcz, xctigcz, bzkcjxgo, pkjqxgo, otfuabvo, iiscmqvi, rls uwla cyczciiv. Gi viv jvyg lwcpuq ihw nczli hz bqf fxzp qp wptjcmptw uhz pwdyc xizu, jsra ia vymhx uifv zn luinc kpfuinj. Gi lmktvrtl ivf gcgvmqxvq eamzqdmcxa. ",
                &get_athena_checker(),
            )
            .key.expect("No key for Vigenere decoder");

        assert_eq!(result, "CRYPTII");
    }

    #[test]
    fn test_vigenere_easy_short() {
        let vigenere_decoder = Decoder::<VigenereDecoder>::new();
        let result = vigenere_decoder
            .crack(
                "Altd hlbe tg lrncmwxpo kpxs evl ztrsuicp qptspf. Ivplyprr th pw clhoic pozc",
                &get_athena_checker(),
            )
            .unencrypted_text
            .expect("No unencrypted text for Vigenere decoder");

        let decoded_text = result
            .first()
            .expect("No unencrypted text for Vigenere decoder");

        assert_eq!(
            decoded_text,
            "This text is encrypted with the vigenere cipher. Breaking it is rather easy"
        );
    }

    #[test]
    fn test_vigenere_easy_short_correct_key() {
        let vigenere_decoder = Decoder::<VigenereDecoder>::new();
        let result = vigenere_decoder
            .crack(
                "Altd hlbe tg lrncmwxpo kpxs evl ztrsuicp qptspf. Ivplyprr th pw clhoic pozc",
                &get_athena_checker(),
            )
            .key
            .expect("No key for Vigenere decoder");

        assert_eq!(result, "HELLO");
    }

    #[test]
    fn test_empty_input() {
        let vigenere_decoder = Decoder::<VigenereDecoder>::new();
        let result = vigenere_decoder
            .crack("", &get_athena_checker())
            .unencrypted_text;
        assert!(result.is_none());
    }

    #[test]
    fn test_non_alphabetic_input() {
        let vigenere_decoder = Decoder::<VigenereDecoder>::new();
        let result = vigenere_decoder
            .crack("12345!@#$%", &get_athena_checker())
            .unencrypted_text;
        assert!(result.is_none());
    }

    #[test]
    fn test_hex_decoded_latin1_input_does_not_panic() {
        // Regression test for https://github.com/bee-san/ciphey/issues/908
        // `ciphey -t "Mjc1NjI2ZDY1N2U2ZjU1NjY3OTY2Ng=="` base64 decodes to
        // "275626d657e6f556679666", which the hexadecimal decoder turns into this string.
        // 'Ö' (U+00D6) used to become index 149 into VIGENERE_SQUARE and panic.
        let vigenere_decoder = Decoder::<VigenereDecoder>::new();
        let result = vigenere_decoder.crack("'V&ÖWæõVg\u{96}f", &get_athena_checker());
        assert!(result.unencrypted_text.is_some());
    }

    #[test]
    fn test_non_ascii_letters_are_ignored_when_breaking_key() {
        // Regression test for https://github.com/bee-san/ciphey/issues/908 and #902
        // Non-ASCII letters are not part of the Vigenère alphabet. They used to be fed
        // into the key search, indexing past VIGENERE_SQUARE ('Ö' -> 149, 'ż' -> 59) or
        // underflowing ('Ā', 'Ж'). They must be skipped like `decrypt` skips them, so
        // they neither panic nor shift the key alignment.
        let text =
            "Altd hlbe Ö tg lrncmwxpo kpxs ż evl ztrsuicp Ā qptspf. Ivplyprr Ж th pw clhoic pozc";
        let key = break_vigenere(text, 5);
        assert_eq!(key, "HELLO");
        assert_eq!(
            decrypt(text, &key),
            "This text Ö is encrypted with ż the vigenere Ā cipher. Breaking Ж it is rather easy"
        );
    }

    #[test]
    fn test_vigenere_square_aa() {
        assert_eq!(VIGENERE_SQUARE[0][0], 'A');
    }

    #[test]
    fn test_vigenere_square_az() {
        assert_eq!(VIGENERE_SQUARE[0][25], 'B');
    }

    #[test]
    fn test_vigenere_square_za() {
        assert_eq!(VIGENERE_SQUARE[25][0], 'Z');
    }

    #[test]
    fn test_vigenere_square_zz() {
        assert_eq!(VIGENERE_SQUARE[25][25], 'A');
    }

    #[test]
    fn test_vigenere_square_mt() {
        assert_eq!(VIGENERE_SQUARE[12][19], 'T');
    }
}
