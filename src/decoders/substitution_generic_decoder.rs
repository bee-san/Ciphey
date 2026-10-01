use super::crack_results::CrackResult;
use super::interface::Crack;
use super::interface::Decoder;
use crate::checkers::CheckerTypes;
use crate::decoders::binary_decoder::BinaryDecoder;
use crate::decoders::morse_code::MorseCodeDecoder;
use log::trace;
use std::collections::{HashMap, HashSet};

/// Substitution Generic Decoder
pub struct SubstitutionGenericDecoder;

impl Crack for Decoder<SubstitutionGenericDecoder> {
    fn new() -> Decoder<SubstitutionGenericDecoder> {
        Decoder {
            name: "simplesubstitution",
            description: "Decodes substitution ciphers where symbols are replaced with Morse code or binary elements. Tries all possible mappings for inputs with up to 4 unique symbols.",
            link: "https://en.wikipedia.org/wiki/Substitution_cipher",
            tags: vec!["substitution", "binary", "morse"],
            popularity: 0.7,
            phantom: std::marker::PhantomData,
        }
    }

    fn crack(&self, text: &str, checker: &CheckerTypes) -> CrackResult {
        trace!("Trying SubstitutionGenericDecoder with text {:?}", text);
        let mut results = CrackResult::new(self, text.to_string());
        let unique_symbols: Vec<char> = text.chars().collect::<HashSet<_>>().into_iter().collect();
        let num_symbols = unique_symbols.len();

        // Early return for invalid symbol counts
        if !(2..=4).contains(&num_symbols) {
            return results;
        }

        // Determine target encoding type
        let (target_type, target_symbols) = match num_symbols {
            2 => ("binary", vec!['0', '1']),
            3 => ("morse", vec!['.', '-', ' ']),
            4 => ("morse", vec!['.', '-', ' ', '/']),
            _ => return results,
        };

        // Generate all possible symbol mappings
        let permutations = generate_permutations(&target_symbols);
        let mut decoded_strings = HashSet::new();

        for perm in permutations {
            let mapping: HashMap<_, _> = unique_symbols
                .iter()
                .zip(perm)
                .map(|(&k, v)| (k, v))
                .collect();
            let substituted: String = text
                .chars()
                .map(|c| *mapping.get(&c).unwrap_or(&c))
                .collect();

            trace!(
                "Trying substitution mapping: {:?} -> {:?}",
                mapping,
                substituted
            );

            let decoder_result = match target_type {
                "binary" => Decoder::<BinaryDecoder>::new().crack(&substituted, checker),
                "morse" => Decoder::<MorseCodeDecoder>::new().crack(&substituted, checker),
                _ => continue,
            };

            if let Some(texts) = decoder_result.unencrypted_text {
                for text in texts {
                    trace!("Found potential decoded string: {}", text);
                    decoded_strings.insert(text);
                }
            }
        }

        if !decoded_strings.is_empty() {
            results.success = true;
            results.unencrypted_text = Some(decoded_strings.into_iter().collect());
        }

        results
    }

    fn get_tags(&self) -> &Vec<&str> {
        &self.tags
    }

    fn get_name(&self) -> &str {
        self.name
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

/// Generate all permutations of a symbol set
fn generate_permutations(symbols: &[char]) -> Vec<Vec<char>> {
    let mut permutations = Vec::new();
    let mut indexes: Vec<usize> = (0..symbols.len()).collect();
    permute(&mut indexes, 0, symbols, &mut permutations);
    permutations
}

/// Recursive permutation generator
fn permute(
    indexes: &mut [usize],
    start: usize,
    symbols: &[char],
    permutations: &mut Vec<Vec<char>>,
) {
    if start == indexes.len() {
        permutations.push(indexes.iter().map(|&i| symbols[i]).collect());
        return;
    }
    for i in start..indexes.len() {
        indexes.swap(start, i);
        permute(indexes, start + 1, symbols, permutations);
        indexes.swap(start, i);
    }
}

#[cfg(test)]
mod tests {
    use super::SubstitutionGenericDecoder;
    use crate::{
        checkers::{
            athena::Athena,
            checker_type::{Check, Checker},
            CheckerTypes,
        },
        decoders::interface::{Crack, Decoder},
    };

    fn get_athena_checker() -> CheckerTypes {
        let athena_checker = Checker::<Athena>::new();
        CheckerTypes::CheckAthena(athena_checker)
    }

    #[test]
    fn test_morse_substitution() {
        let decoder = Decoder::<SubstitutionGenericDecoder>::new();
        let result = decoder.crack("00002020100201002111", &get_athena_checker());

        // Print debug info if test fails
        if !result.success {
            println!("Morse substitution test failed. Result: {:?}", result);
        }

        assert!(result.success);

        // Check if any of the decoded strings contains "HELLO"
        if let Some(texts) = result.unencrypted_text {
            let contains_hello = texts.iter().any(|s| s.contains("HELLO"));
            assert!(
                contains_hello,
                "Expected to find 'HELLO' in decoded texts: {:?}",
                texts
            );
        } else {
            panic!("No decoded texts found");
        }
    }

    #[test]
    fn test_binary_substitution() {
        let decoder = Decoder::<SubstitutionGenericDecoder>::new();
        let result = decoder.crack("AABBAABBAABBAABBAABBAA", &get_athena_checker());

        // Print debug info if test fails
        if !result.success {
            println!("Binary substitution test failed. Result: {:?}", result);
        }

        assert!(result.success);

        // For binary, we're looking for any valid binary string that might decode to something
        if let Some(texts) = result.unencrypted_text {
            println!("Decoded binary texts: {:?}", texts);
            assert!(!texts.is_empty(), "Expected non-empty decoded texts");
        } else {
            panic!("No decoded texts found");
        }
    }
}
