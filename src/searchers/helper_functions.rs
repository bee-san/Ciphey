//! # Helper Functions for A* Search
//!
//! This module contains helper functions used by the A* search algorithm
//! for decoding encrypted or encoded text.

use crate::decoders::interface::Crack;
use crate::CrackResult;
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::sync::Mutex;

/// Track decoder success rates for adaptive learning
pub static DECODER_SUCCESS_RATES: Lazy<Mutex<HashMap<String, (usize, usize)>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// Update decoder statistics based on success or failure
///
/// # Arguments
///
/// * `decoder` - The name of the decoder
/// * `success` - Whether the decoder was successful
pub fn update_decoder_stats(decoder: &str, success: bool) {
    let mut stats = DECODER_SUCCESS_RATES.lock().unwrap();
    let (successes, total) = stats.entry(decoder.to_string()).or_insert((0, 0));

    if success {
        *successes += 1;
    }
    *total += 1;

    // TODO: Write this data to a file for persistence
}

/// Get the success rate of a decoder
///
/// # Arguments
///
/// * `decoder` - The name of the decoder
///
/// # Returns
///
/// * The success rate as a float between 0.0 and 1.0
pub fn get_decoder_success_rate(decoder: &str) -> f32 {
    let stats = DECODER_SUCCESS_RATES.lock().unwrap();
    if let Some((successes, total)) = stats.get(decoder) {
        if *total > 0 {
            return *successes as f32 / *total as f32;
        }
    }

    // Default for unknown decoders
    0.5
}

/// Check if a decoder and cipher form a common sequence
///
/// # Arguments
///
/// * `prev_decoder` - The name of the previous decoder
/// * `current_cipher` - The name of the current cipher
///
/// # Returns
///
/// * `true` if the sequence is common, `false` otherwise
pub fn is_common_sequence(prev_decoder: &str, current_cipher: &str) -> bool {
    // Any two binary-to-text encodings stack, including the same one twice.
    const STACKABLE: &[&str] = &[
        "Base64",
        "Base32",
        "Base58 Bitcoin",
        "Base58 Ripple",
        "Base58 Monero",
        "Base58 Flickr",
        "Base91",
        "Base65536",
        "Z85",
        "Hexadecimal",
        "Binary",
        "URL",
    ];
    STACKABLE.contains(&prev_decoder) && STACKABLE.contains(&current_cipher)
}

/// Calculate the quality of a string for pruning
///
/// # Arguments
///
/// * `s` - The string to evaluate
///
/// # Returns
///
/// * A quality score between 0.0 and 1.0
pub fn calculate_string_quality(s: &str) -> f32 {
    // Check for high percentage of invisible characters
    let non_printable_ratio = calculate_non_printable_ratio(s);
    if non_printable_ratio > 0.5 {
        return 0.0; // Return lowest quality for strings with >50% invisible chars
    }

    // Factors to consider:
    // 1. Length (not too short, not too long
    if s.len() < 3 {
        0.1
    } else if s.len() > 5000 {
        0.3
    } else {
        1.0 - (s.len() as f32 - 100.0).abs() / 900.0
    }
}

/// Check if string is worth being decoded
pub fn calculate_string_worth(s: &str) -> bool {
    // check if string is less than 3 chars
    if calculate_string_quality(s) < 0.2 {
        return false;
    }

    true
}

/// Calculate the ratio of non-printable characters in a string
/// Returns a value between 0.0 (all printable) and 1.0 (all non-printable)
pub fn calculate_non_printable_ratio(text: &str) -> f32 {
    if text.is_empty() {
        return 1.0;
    }

    let non_printable_count = text
        .chars()
        .filter(|&c| {
            // Only count control characters (except common whitespace) and non-ASCII as non-printable
            (c.is_control() && c != '\n' && c != '\r' && c != '\t') || !c.is_ascii()
        })
        .count();

    non_printable_count as f32 / text.len() as f32
}

/// Whether every character of `text` fits the alphabet of a common binary-to-text encoding.
/// Needs at least 8 characters; short words fit the Base64 alphabet trivially.
pub fn looks_like_known_encoding(text: &str) -> bool {
    let trimmed = text.trim();
    if trimmed.chars().count() < 8 {
        return false;
    }
    let alphabets: [&dyn Fn(char) -> bool; 7] = [
        // Base64, standard and URL-safe
        &|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '-' | '_' | '='),
        // Base32
        &|c| c.is_ascii_uppercase() || matches!(c, '2'..='7' | '='),
        // Hex
        &|c| c.is_ascii_hexdigit() || c.is_whitespace() || matches!(c, ':' | '-'),
        // Binary
        &|c| matches!(c, '0' | '1') || c.is_whitespace(),
        // Morse
        &|c| matches!(c, '.' | '-' | '/' | '·' | '−') || c.is_whitespace(),
        // a1z26 and other numeric encodings
        &|c| c.is_ascii_digit() || c.is_whitespace() || matches!(c, '-' | ',' | '.'),
        // Braille
        &|c| ('\u{2800}'..='\u{28FF}').contains(&c) || c.is_whitespace(),
    ];
    alphabets
        .iter()
        .any(|alphabet| trimmed.chars().all(alphabet))
}

/// g increment for an edge produced by `decoder`. Unpopular decoders, decoders that have not
/// produced useful output this run, and decoders that return many candidates (Caesar 25,
/// railfence 72) all cost more; the `ln(n)` term is what keeps one railfence expansion from
/// flooding the frontier.
pub fn edge_cost(decoder: &(dyn Crack + Sync), num_candidates: usize) -> f32 {
    let popularity = decoder.get_popularity().clamp(0.0, 1.0);
    let success_rate = get_decoder_success_rate(decoder.get_name());
    1.0 + (1.0 - popularity) * 0.5
        + (1.0 - success_rate) * 0.25
        + (num_candidates.max(1) as f32).ln() * 0.5
}

/// h: estimated distance from `text` to plaintext. Text inside a known encoding alphabet is
/// assumed one step away; anything else, at least two. Adds penalties for poor string
/// quality, depth, and an uncommon decoder pairing. `path` includes `next_decoder`.
pub fn generate_heuristic(
    text: &str,
    path: &[CrackResult],
    next_decoder: Option<&(dyn Crack + Sync)>,
) -> f32 {
    let mut base_score = 0.0;

    if !looks_like_known_encoding(text) {
        base_score += 1.0;
    }

    let quality = calculate_string_quality(text);
    base_score += (1.0 - quality) * 0.5;

    let depth_coefficient = 0.05 * (1.0 + (path.len() as f32 / 20.0));
    base_score += (depth_coefficient * path.len() as f32).powi(2);

    if path.len() > 1 {
        if let Some(next_decoder) = next_decoder {
            let previous_decoder = &path[path.len() - 2];
            if !is_common_sequence(previous_decoder.decoder, next_decoder.get_name()) {
                base_score += 0.25;
            }
        }
    }

    base_score
}

/// Determines if a string is too short to be meaningfully decoded
/// or is of too low quality to be worth decoding
///
/// ## Decision Criteria
///
/// A string is considered undecodeble if:
/// - It has 2 or fewer characters
/// - It has more than 30% non-printable characters
/// - Its overall quality score is below 0.2
///
/// ## Rationale
///
/// 1. The gibberish_or_not library requires at least 3 characters to work effectively
/// 2. LemmeKnow and other pattern matchers perform poorly on very short strings
/// 3. Most encoding schemes produce output of at least 3 characters
/// 4. Strings with high percentages of non-printable characters are unlikely to be valid encodings
/// 5. Very low quality strings waste computational resources and rarely yield useful results
///
/// Filtering out these strings early saves computational resources and
/// prevents the search from exploring unproductive paths.
pub fn check_if_string_cant_be_decoded(text: &str) -> bool {
    // Check for strings that are too short
    if text.len() <= 2 {
        return true;
    }

    // Check for strings with high non-printable character ratio
    let non_printable_ratio = calculate_non_printable_ratio(text);
    if non_printable_ratio > 0.3 {
        return true;
    }

    // Check for overall string quality
    let quality = calculate_string_quality(text);
    if quality < 0.2 {
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Decoder;

    #[test]
    fn test_generate_heuristic() {
        // Create some CrackResults for path testing
        let crack_result = CrackResult::new(&Decoder::default(), "test".to_string());

        // Test with different path lengths
        let depth_0 = generate_heuristic("test", &[], None);
        let depth_5 = generate_heuristic("test", &vec![crack_result.clone(); 5], None);
        let depth_10 = generate_heuristic("test", &vec![crack_result.clone(); 10], None);

        // Verify that deeper paths have higher scores
        assert!(depth_0 < depth_5);
        assert!(depth_5 < depth_10);

        // Verify that the depth penalty is approximately (0.05 * depth)^2
        assert!((depth_5 - depth_0 - 0.0625).abs() < 0.1);

        // Verify base case isn't negative
        assert!(depth_0 >= 0.0);
    }

    #[test]
    fn test_calculate_non_printable_ratio() {
        // Test normal text
        assert_eq!(calculate_non_printable_ratio("Hello World"), 0.0);
        assert_eq!(calculate_non_printable_ratio("123!@#\n\t"), 0.0);

        // Test mixed content
        let mixed = "Hello\u{0}World\u{1}".to_string(); // 2 non-printable in 12 chars
        assert!((calculate_non_printable_ratio(&mixed) - 0.1666).abs() < 0.001);

        // Test all non-printable
        assert_eq!(calculate_non_printable_ratio("\u{0}\u{1}\u{2}"), 1.0);

        // Test empty string
        assert_eq!(calculate_non_printable_ratio(""), 1.0);
    }

    #[test]
    fn test_calculate_string_quality_with_invisible_chars() {
        // Test normal text
        let normal_quality = calculate_string_quality("Hello World");
        assert!(normal_quality > 0.0);

        // Test text with 40% invisible characters
        let text_with_some_invisible = "Hello\u{0}\u{0}\u{0}\u{0}World"; // 4 out of 14 chars are invisible
        let some_invisible_quality = calculate_string_quality(text_with_some_invisible);
        assert!(some_invisible_quality > 0.0);

        // Test text with 60% invisible characters (should return 0.0)
        let text_with_many_invisible = "\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}Hello"; // 7 out of 12 chars are invisible
        let many_invisible_quality = calculate_string_quality(text_with_many_invisible);
        assert_eq!(many_invisible_quality, 0.0);

        // Test text with 100% invisible characters
        let all_invisible = "\u{0}\u{0}\u{0}\u{0}\u{0}";
        let all_invisible_quality = calculate_string_quality(all_invisible);
        assert_eq!(all_invisible_quality, 0.0);
    }

    #[test]
    fn test_check_if_string_cant_be_decoded() {
        // Test strings that are too short
        assert!(
            check_if_string_cant_be_decoded(""),
            "Empty string should be rejected"
        );
        assert!(
            check_if_string_cant_be_decoded("a"),
            "Single character should be rejected"
        );
        assert!(
            check_if_string_cant_be_decoded("ab"),
            "Two characters should be rejected"
        );

        // Test strings with high non-printable character ratio
        let high_non_printable = "abc\u{0}\u{1}\u{2}"; // 3 out of 6 chars are non-printable (50%)
        assert!(
            check_if_string_cant_be_decoded(high_non_printable),
            "String with 50% non-printable characters should be rejected"
        );

        // Test strings with low quality
        // Create a string with >50% non-printable characters to ensure quality is 0.0
        let low_quality = "\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}abc"; // 7 out of 10 chars are non-printable (70%)
        assert!(
            check_if_string_cant_be_decoded(low_quality),
            "Low quality string should be rejected"
        );

        // Test valid strings
        assert!(
            !check_if_string_cant_be_decoded("Hello World"),
            "Normal text should be accepted"
        );
        assert!(
            !check_if_string_cant_be_decoded("SGVsbG8gV29ybGQ="), // Base64 for "Hello World"
            "Valid Base64 should be accepted"
        );
    }
}
