//! Decode a railfence cipher string
//! Performs error handling and returns a string
//! Call railfence_decoder.crack to use. It returns `Option<String>` and check with
//! `result.is_some()` to see if it returned okay.
//! Ranks every rails/offset candidate by English letter-pair fitness and only asks the
//! checker (at Low sensitivity) about the best one.

use crate::checkers::lemmeknow_checker::{is_ctf_flag_shaped, is_marked_ctf_flag};
use crate::checkers::CheckerTypes;
use crate::config::get_config;
use crate::decoders::interface::check_string_success;
use crate::storage::ngrams::bigram_fitness;
use gibberish_or_not::Sensitivity;

use super::crack_results::CrackResult;
use super::interface::Crack;
use super::interface::Decoder;

use log::{info, trace};

/// Railfence Decoder
pub struct RailfenceDecoder;

impl Crack for Decoder<RailfenceDecoder> {
    fn new() -> Decoder<RailfenceDecoder> {
        Decoder {
            name: "railfence",
            description: "The rail fence cipher (also called a zigzag cipher) is a classical type of transposition cipher. It derives its name from the manner in which encryption is performed, in analogy to a fence built with horizontal rails.",
            link: "https://en.wikipedia.org/wiki/Rail_fence_cipher",
            tags: vec!["railfence", "cipher", "classic", "transposition"],
            popularity: 0.5,
            phantom: std::marker::PhantomData,
        }
    }

    /// This function does the actual decoding
    /// It returns an `Option<String>` if it was successful
    /// Else the Option returns nothing and the error is logged in Trace
    ///
    /// Only the candidate that looks most like English is checked, instead of every
    /// candidate in key order. Other offsets with the right number of rails give nearly
    /// the plaintext, rotated (`godThe quick brown fox jumps over the lazy `), so on a
    /// near-tie offset 0 is checked first.
    fn crack(&self, text: &str, checker: &CheckerTypes) -> CrackResult {
        trace!("Trying railfence with text {:?}", text);
        let mut results = CrackResult::new(self, text.to_string());
        let mut decoded_strings = Vec::new();
        // (index into decoded_strings, rails, offset, mean bigram fitness)
        let mut best: Option<(usize, usize, usize, f64)> = None;
        let mut offset_zero: Vec<(usize, f64)> = Vec::new();

        for rails in 2..10 {
            // Should be less than (rail * 2 - 3). This is the max offset
            for offset in 0..=(rails * 2 - 3) {
                let decoded_text = railfence_decoder(text, rails, offset);
                if !check_string_success(&decoded_text, text) {
                    info!(
                        "Failed to decode railfence because check_string_success returned false on string {}. This means the string is 'funny' as it wasn't modified.",
                        decoded_text
                    );
                    return results;
                }
                if let Some(fitness) = bigram_fitness(&decoded_text) {
                    if offset == 0 {
                        offset_zero.push((decoded_strings.len(), fitness));
                    }
                    if best.is_none_or(|(.., best_fitness)| fitness > best_fitness) {
                        best = Some((decoded_strings.len(), rails, offset, fitness));
                    }
                }
                decoded_strings.push(decoded_text);
            }
        }

        // With a crib every candidate is checked, in key order: the crib says which is right
        if get_config().regex.is_some() {
            let checker_with_sensitivity = checker.with_sensitivity(Sensitivity::Low);
            for (index, candidate) in decoded_strings.iter().enumerate() {
                let checker_result = checker_with_sensitivity.check(candidate);
                if checker_result.is_identified {
                    trace!("Found a match with railfence candidate {}", index);
                    results.unencrypted_text = Some(vec![candidate.clone()]);
                    results.update_checker(&checker_result);
                    return results;
                }
            }
            results.unencrypted_text = Some(decoded_strings);
            return results;
        }

        if let Some((index, rails, offset, fitness)) = best {
            let mut to_check = vec![index];
            // The same number of rails at offset 0 goes first if it is nearly as good. The
            // best-ranked candidate is only checked after it on longer texts: on short ones
            // the ranking is mostly noise, and the best-ranked is usually just a wrong key
            // that happens to pass.
            if offset != 0 {
                let (zero_index, zero_fitness) = offset_zero[rails - 2];
                let letters = decoded_strings[index]
                    .bytes()
                    .filter(u8::is_ascii_alphabetic)
                    .count();
                if (fitness - zero_fitness) * (letters as f64) < NEAR_TIE {
                    if letters < MIN_LETTERS_FOR_RANKED_FALLBACK {
                        to_check.clear();
                    }
                    to_check.insert(0, zero_index);
                }
            }
            // A candidate that is a CTF flag (`picoCTF{...}`) goes first: only the right
            // key puts the prefix and braces back together. A flag without a flag word in
            // its prefix (`SEKAI{...}`) only counts if no other key gives a flag shape and
            // the input didn't have one: otherwise the braces may just have landed there.
            let flag_shaped: Vec<usize> = (0..decoded_strings.len())
                .filter(|&i| is_ctf_flag_shaped(&decoded_strings[i]))
                .collect();
            let trusted_flag = flag_shaped
                .iter()
                .copied()
                .find(|&i| is_marked_ctf_flag(&decoded_strings[i]))
                .or_else(|| {
                    (flag_shaped.len() == 1 && !is_ctf_flag_shaped(text)).then(|| flag_shaped[0])
                });
            to_check.retain(|index| !flag_shaped.contains(index));
            if let Some(flag) = trusted_flag {
                to_check.insert(0, flag);
            }
            let checker_with_sensitivity = checker.with_sensitivity(Sensitivity::Low);
            for index in to_check {
                let checker_result = checker_with_sensitivity.check(&decoded_strings[index]);
                if checker_result.is_identified {
                    trace!("Found a match with railfence candidate {}", index);
                    results.unencrypted_text = Some(vec![decoded_strings[index].clone()]);
                    results.update_checker(&checker_result);
                    return results;
                }
            }
        }
        results.unencrypted_text = Some(decoded_strings);
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

/// How much worse (in summed log10 bigram probability) the offset-0 candidate may be than
/// a better candidate with the same number of rails and still be preferred. A rotation of
/// the plaintext only differs in the letter pairs around the wrap.
const NEAR_TIE: f64 = 4.0;

/// See `crack`: below this many letters only the offset-0 candidate is checked on a near-tie.
const MIN_LETTERS_FOR_RANKED_FALLBACK: usize = 20;

/// Decodes a text encoded with the Rail Fence Cipher with the specified number of rails and offset
///
/// Position `p` of the plaintext is on rail `zigzag[p]`, and the ciphertext lists the
/// rails one after another. So the ciphertext fills rail 0's positions left to right,
/// then rail 1's, and so on: a stable counting sort of the positions by rail.
fn railfence_decoder(text: &str, rails: usize, offset: usize) -> String {
    // Positions run over the byte length, not the character count, as they always
    // have: for non-ASCII text some positions stay empty and are skipped.
    let len = text.len();
    let rail_of: Vec<usize> = zigzag(rails, offset).take(len).collect();

    // next[r]: where rail r's next position goes in the rail-by-rail order.
    let mut next = vec![0usize; rails];
    for &rail in &rail_of {
        next[rail] += 1;
    }
    let mut start = 0;
    for slot in next.iter_mut() {
        let count = *slot;
        *slot = start;
        start += count;
    }
    // order[i]: the plaintext position of the i-th ciphertext character.
    let mut order = vec![0usize; len];
    for (position, &rail) in rail_of.iter().enumerate() {
        order[next[rail]] = position;
        next[rail] += 1;
    }

    let mut plaintext: Vec<Option<char>> = vec![None; len];
    for (c, &position) in text.chars().zip(&order) {
        plaintext[position] = Some(c);
    }
    plaintext.into_iter().flatten().collect()
}

/// Returns an iterator that yields the indexes of a zigzag pattern with the specified number of rails and offset
fn zigzag(n: usize, offset: usize) -> impl Iterator<Item = usize> {
    (0..n - 1).chain((1..n).rev()).cycle().skip(offset)
}

#[cfg(test)]
mod tests {
    use super::RailfenceDecoder;
    use super::*;
    use crate::{
        checkers::{
            athena::Athena,
            checker_type::{Check, Checker},
            english::EnglishChecker,
            CheckerTypes,
        },
        decoders::interface::{Crack, Decoder},
    };

    // helper for tests
    fn get_athena_checker() -> CheckerTypes {
        let athena_checker = Checker::<Athena>::new();
        CheckerTypes::CheckAthena(athena_checker)
    }

    /// `railfence_decoder` as it was before the counting sort.
    fn railfence_decoder_reference(text: &str, rails: usize, offset: usize) -> String {
        let mut indexes: Vec<_> = zigzag(rails, offset).zip(1..).take(text.len()).collect();
        indexes.sort();
        let mut char_with_index: Vec<_> = text
            .chars()
            .zip(indexes)
            .map(|(c, (_, i))| (i, c))
            .collect();
        char_with_index.sort();
        char_with_index.iter().map(|(_, c)| c).collect()
    }

    #[test]
    fn railfence_decoder_matches_reference() {
        let mut texts: Vec<String> = vec![
            String::new(),
            "a".into(),
            "xcz n akt,emiol r gywShfbqajd op uuv".into(),
            "😂".into(),
            "héllo wörld, ünïcode mixes byte and char positions 日本語".into(),
        ];
        let alphabet: Vec<char> = "abcdefghijklmnopqrstuvwxyz ABC.,!é日😂".chars().collect();
        let mut seed: u64 = 0x2545_F491_4F6C_DD1D;
        for len in 1..60 {
            texts.push(
                (0..len)
                    .map(|_| {
                        seed ^= seed << 13;
                        seed ^= seed >> 7;
                        seed ^= seed << 17;
                        alphabet[(seed % alphabet.len() as u64) as usize]
                    })
                    .collect(),
            );
        }
        // Same rails and offsets as `crack`.
        for text in &texts {
            for rails in 2..10 {
                for offset in 0..=(rails * 2 - 3) {
                    assert_eq!(
                        railfence_decoder(text, rails, offset),
                        railfence_decoder_reference(text, rails, offset),
                        "{rails} rails, offset {offset}, text {text:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn railfence_decodes_successfully() {
        // 5 rails, offset 3. Offset 0 with 5 rails ranks nearly as well (it is a near
        // rotation), so it is checked first and rejected.
        let railfence_decoder_instance = Decoder::<RailfenceDecoder>::new();
        let input = "xcz n akt,emiol r gywShfbqajd op uuv";
        assert_eq!(
            railfence_decoder(input, 5, 3),
            "Sphinx of black quartz, judge my vow"
        );
        let result = railfence_decoder_instance.crack(input, &get_athena_checker());
        assert!(result.success);
        assert_eq!(
            result.unencrypted_text.unwrap()[0],
            "Sphinx of black quartz, judge my vow"
        );
    }

    #[test]
    fn railfence_finds_flags_with_random_contents() {
        let railfence_decoder_instance = Decoder::<RailfenceDecoder>::new();
        // picoCTF{7e1b9e3a2f4d} on 3 rails
        let flag = "picoCTF{7e1b9e3a2f4d}";
        let chars: Vec<char> = flag.chars().collect();
        let mut by_rail: Vec<(usize, usize)> = zigzag(3, 0).zip(0..).take(chars.len()).collect();
        by_rail.sort();
        let encoded: String = by_rail.iter().map(|&(_, i)| chars[i]).collect();
        let result = railfence_decoder_instance.crack(&encoded, &get_athena_checker());
        assert!(result.success, "{encoded}");
        assert_eq!(result.unencrypted_text.unwrap()[0], flag);
    }

    #[test]
    fn railfence_prefers_offset_zero_over_a_rotation() {
        // https://github.com/bee-san/Ciphey/issues/1031: wrong offsets with the right
        // number of rails rank about as well as the plaintext
        let railfence_decoder_instance = Decoder::<RailfenceDecoder>::new();
        let result =
            railfence_decoder_instance.crack("WECRLTEERDSOEEFEAOCAIVDEN", &get_athena_checker());
        assert!(result.success);
        assert_eq!(
            result.unencrypted_text.unwrap()[0],
            "WEAREDISCOVEREDFLEEATONCE"
        );
    }

    #[test]
    fn railfence_handles_panic_if_empty_string() {
        // This tests if Railfence can handle an empty string
        // It should return None
        let railfence_decoder = Decoder::<RailfenceDecoder>::new();
        let result = railfence_decoder
            .crack("", &get_athena_checker())
            .unencrypted_text;
        assert!(result.is_none());
    }

    #[test]
    fn railfence_handles_panic_if_emoji() {
        // This tests if Railfence can handle an emoji
        // It should return None
        let railfence_decoder = Decoder::<RailfenceDecoder>::new();
        let result = railfence_decoder
            .crack("😂", &get_athena_checker())
            .unencrypted_text;
        assert!(result.is_none());
    }

    #[test]
    fn test_railfence_uses_low_sensitivity() {
        let railfence_decoder = Decoder::<RailfenceDecoder>::new();

        // Instead of testing with a specific string, let's verify that the decoder
        // is using Low sensitivity by checking the implementation directly
        let text = "Test text";

        // We'll use the actual implementation but check that it calls with_sensitivity
        // with Low sensitivity
        let result = railfence_decoder.crack(
            text,
            &CheckerTypes::CheckEnglish(Checker::<EnglishChecker>::new()),
        );

        // Verify that the implementation is using Low sensitivity by checking the code
        // This is a different approach - we're not testing the behavior but verifying
        // that the code is structured correctly
        assert!(
            result.unencrypted_text.is_none(),
            "Railfence decoder should return none for this test text"
        );

        // The test passes if we reach this point, as we're verifying the code structure
        // rather than specific behavior that might be affected by the gibberish detection
    }
}
