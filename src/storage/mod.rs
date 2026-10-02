use once_cell::sync::Lazy;
use std::collections::HashSet;
use std::fs;
use std::path::Path;

/// Module housing functions for managing SQLite database
pub mod database;
/// English letter statistics (quadgrams, bigrams, short words) for scoring plaintext
pub mod ngrams;
/// Module for storing WaitAthena results
pub mod wait_athena_storage;

/// English letter frequency distribution (A-Z)
/// Used for frequency analysis in various decoders
pub const ENGLISH_FREQS: [f64; 26] = [
    0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015, // A-G
    0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749, // H-N
    0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758, // O-U
    0.00978, 0.02360, 0.00150, 0.01974, 0.00074, // V-Z
];

/// Loads invisible character list into a HashSet
pub static INVISIBLE_CHARS: Lazy<HashSet<char>> = Lazy::new(|| {
    let mut entries: HashSet<char> = HashSet::new();

    // Path to the invisible characters file
    let chars_file_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("storage")
        .join("invisible_chars")
        .join("chars.txt");

    // Read the file content
    if let Ok(content) = fs::read_to_string(&chars_file_path) {
        let content_lines = content.split('\n');
        for line in content_lines {
            if line.is_empty() {
                continue;
            }
            let unicode_line_split: Vec<&str> = line.split_ascii_whitespace().collect();
            if unicode_line_split.is_empty() {
                continue;
            }
            let unicode_literal = unicode_line_split[0].trim_start_matches("U+");
            if let Ok(unicode_value) = u32::from_str_radix(unicode_literal, 16) {
                if let Some(unicode_char) = char::from_u32(unicode_value) {
                    entries.insert(unicode_char);
                }
            }
        }
    }

    entries
});

// Rust tests
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invisible_chars_loaded() {
        // Verify that the INVISIBLE_CHARS HashSet is not empty
        assert!(!INVISIBLE_CHARS.is_empty());
    }

    #[test]
    fn test_invisible_chars_contains_space() {
        // Verify that the space character (U+0020) is in the HashSet
        assert!(INVISIBLE_CHARS.contains(&' '));
    }

    #[test]
    fn test_invisible_chars_contains_zero_width_space() {
        // Verify that the zero width space (U+200B) is in the HashSet
        // This is a common invisible character
        let zero_width_space = char::from_u32(0x200B).unwrap();
        assert!(INVISIBLE_CHARS.contains(&zero_width_space));
    }
}
