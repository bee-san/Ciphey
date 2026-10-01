/// import general checker
use lemmeknow::Identifier;
use memmap2::Mmap;
use once_cell::sync::{Lazy, OnceCell};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io;
use std::io::{Read, Write};
use std::path::Path;

/// Library input is the default API input
/// The CLI turns its arguments into a LibraryInput struct
/// The Config object is a default configuration object
/// For the entire program
/// It's access using a variable like configuration
/// ```rust
/// use ciphey::config::get_config;
/// let config = get_config();
/// assert_eq!(config.verbose, 0);
/// ```
#[derive(Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// A level of verbosity to determine.
    /// How much we print in logs.
    pub verbose: u8,
    /// The lemmeknow config to use
    #[serde(skip)]
    pub lemmeknow_config: Identifier,
    /// lemmeknow_config serialization fields
    #[serde(default)]
    pub lemmeknow_min_rarity: f32,
    /// Maximum rarity threshold for lemmeknow detection
    #[serde(default)]
    pub lemmeknow_max_rarity: f32,
    /// List of lemmeknow tags to include in detection
    #[serde(default)]
    pub lemmeknow_tags: Vec<String>,
    /// List of lemmeknow tags to exclude from detection
    #[serde(default)]
    pub lemmeknow_exclude_tags: Vec<String>,
    /// Whether to use boundaryless mode in lemmeknow detection
    #[serde(default)]
    pub lemmeknow_boundaryless: bool,
    /// Should the human checker be on?
    /// This asks yes/no for plaintext. Turn off for API
    pub human_checker_on: bool,
    /// The timeout threshold before ciphey quits
    /// This is in seconds
    pub timeout: u32,
    /// Whether to collect all plaintexts until timeout expires
    /// instead of exiting after finding the first valid plaintext
    pub top_results: bool,
    /// Is the program being run in API mode?
    /// This is used to determine if we should print to stdout
    /// Or return the values
    pub api_mode: bool,
    /// Regex enables the user to search for a specific regex or crib
    pub regex: Option<String>,
    /// Path to the wordlist file. Will be overridden by CLI argument if provided.
    pub wordlist_path: Option<String>,
    /// Wordlist data structure (loaded from file). CLI takes precedence if both config and CLI specify a wordlist.
    #[serde(skip)]
    pub wordlist: Option<HashSet<String>>,
    /// Colourscheme hashmap
    pub colourscheme: HashMap<String, String>,
    /// Enables enhanced plaintext detection using a BERT model.
    pub enhanced_detection: bool,
    /// Path to the enhanced detection model. If None, will use the default path.
    pub model_path: Option<String>,
}

/// Cell for storing global Config
static CONFIG: OnceCell<Config> = OnceCell::new();

/// Returned by [`get_config`] until [`set_global_config`] is called
static DEFAULT_CONFIG: Lazy<Config> = Lazy::new(Config::default);

/// To initialize global config with custom values
pub fn set_global_config(config: Config) {
    CONFIG.set(config).ok(); // ok() used to make compiler happy about using Result
}

/// Get the global config.
///
/// Until [`set_global_config`] is called this returns the default config, without
/// stopping a later [`set_global_config`] call from taking effect:
/// ```rust
/// use ciphey::config::{get_config, set_global_config, Config};
///
/// assert_eq!(get_config().timeout, 5);
///
/// let mut config = Config::default();
/// config.timeout = 42;
/// set_global_config(config);
/// assert_eq!(get_config().timeout, 42);
/// ```
pub fn get_config() -> &'static Config {
    // Don't initialise CONFIG here: anything printed before the real config is set
    // (e.g. a warning while parsing the config file) would otherwise lock in the
    // defaults and silently discard every CLI option.
    CONFIG.get().unwrap_or_else(|| &DEFAULT_CONFIG)
}

/// Creates a default lemmeknow config
const LEMMEKNOW_DEFAULT_CONFIG: Identifier = Identifier {
    min_rarity: 0.0_f32,
    max_rarity: 0.0_f32,
    tags: vec![],
    exclude_tags: vec![],
    file_support: false,
    boundaryless: false,
};

/// Convert Config fields into an Identifier
fn make_identifier_from_config(config: &Config) -> Identifier {
    Identifier {
        min_rarity: config.lemmeknow_min_rarity,
        max_rarity: config.lemmeknow_max_rarity,
        tags: config.lemmeknow_tags.clone(),
        exclude_tags: config.lemmeknow_exclude_tags.clone(),
        file_support: false, // Always false as per LEMMEKNOW_DEFAULT_CONFIG
        boundaryless: config.lemmeknow_boundaryless,
    }
}

/// Update Config's Identifier field from its serialization fields
fn update_identifier_in_config(config: &mut Config) {
    config.lemmeknow_config = make_identifier_from_config(config);
}

impl Default for Config {
    fn default() -> Self {
        let mut config = Config {
            verbose: 0,
            lemmeknow_config: LEMMEKNOW_DEFAULT_CONFIG,
            lemmeknow_min_rarity: 0.0_f32,
            lemmeknow_max_rarity: 0.0_f32,
            lemmeknow_tags: vec![],
            lemmeknow_exclude_tags: vec![],
            lemmeknow_boundaryless: false,
            human_checker_on: false,
            timeout: 5,
            top_results: false,
            api_mode: false,
            regex: None,
            wordlist_path: None,
            wordlist: None,
            enhanced_detection: false,
            model_path: None,
            colourscheme: HashMap::new(),
        };

        // Set default colors
        config
            .colourscheme
            .insert(String::from("informational"), String::from("255,215,0")); // Gold yellow
        config
            .colourscheme
            .insert(String::from("warning"), String::from("255,0,0")); // Red
        config
            .colourscheme
            .insert(String::from("success"), String::from("0,255,0")); // Green
        config
            .colourscheme
            .insert(String::from("error"), String::from("255,0,0")); // Red

        config
            .colourscheme
            .insert(String::from("question"), String::from("255,215,0")); // Gold yellow (same as informational)
        config
    }
}

/// Get the path to the ciphey config file
///
/// # Panics
///
/// This function will panic if:
/// - The home directory cannot be found
/// - The ciphey directory cannot be created
pub fn get_config_file_path() -> std::path::PathBuf {
    let mut path = dirs::home_dir().expect("Could not find home directory");
    path.push(".ciphey");
    fs::create_dir_all(&path).expect("Could not create ciphey directory");
    path.push("config.toml");
    path
}

/// Create a default config file at the specified path
///
/// # Errors
///
/// This function returns an error if the config file cannot be created, serialized, or written.
///
/// # Panics
///
/// This function will panic if the config file path cannot be determined
/// (see `get_config_file_path`).
pub fn create_default_config_file() -> std::io::Result<()> {
    let config = Config::default();
    let toml_string = toml::to_string_pretty(&config)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    let path = get_config_file_path();
    let mut file = File::create(path)?;
    file.write_all(toml_string.as_bytes())?;
    Ok(())
}

/// Read and parse the config file
fn read_config_file() -> std::io::Result<String> {
    let path = get_config_file_path();
    let mut file = File::open(&path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    Ok(contents)
}

/// Parse a TOML string into a Config struct, warning about unknown keys
///
/// Returns an error if `contents` isn't valid TOML or a setting has the wrong type.
fn parse_toml_with_unknown_keys(contents: &str) -> Result<Config, toml::de::Error> {
    // First parse into a generic Value to check for unknown keys
    let parsed_value: toml::Value = toml::from_str(contents)?;

    // Check for unknown keys at the root level
    if let toml::Value::Table(table) = &parsed_value {
        let known_keys = [
            "verbose",
            "lemmeknow_min_rarity",
            "enhanced_detection",
            "model_path",
            "lemmeknow_max_rarity",
            "lemmeknow_tags",
            "lemmeknow_exclude_tags",
            "lemmeknow_boundaryless",
            "human_checker_on",
            "timeout",
            "top_results",
            "api_mode",
            "regex",
            "wordlist_path",
            "question",
            "colourscheme",
        ];
        for key in table.keys() {
            if !known_keys.contains(&key.as_str()) {
                crate::cli_pretty_printing::warning_unknown_config_key(key);
            }
        }
    }

    // Parse into Config struct
    let mut config: Config = toml::from_str(contents)?;
    update_identifier_in_config(&mut config);
    Ok(config)
}

/// Loads a wordlist from a file into a HashSet for efficient lookups
/// Uses memory mapping for large files to improve performance and memory usage
///
/// Lines that aren't valid UTF-8 are skipped: decoded text is always valid UTF-8, so
/// they could never match. Real wordlists such as rockyou.txt contain some.
///
/// # Arguments
/// * `path` - Path to the wordlist file
///
/// # Returns
/// * `Ok(HashSet<String>)` - The loaded wordlist as a HashSet for O(1) lookups
/// * `Err(io::Error)` - If the file cannot be opened or read
///
/// # Errors
/// This function will return an error if:
/// * The file does not exist
/// * The file cannot be opened due to permissions
/// * The file cannot be read or memory-mapped
///
/// # Safety
/// This implementation uses memory mapping for large files.
/// `unsafe { Mmap::map(&file) }` is required because the map could become invalid
/// if the underlying file is modified while the mapping is in use.
pub fn load_wordlist<P: AsRef<Path>>(path: P) -> io::Result<HashSet<String>> {
    let mut file = File::open(path)?;
    let file_size = file.metadata()?.len();

    // For small files (under 10MB), use regular file reading
    // This threshold was chosen because:
    // 1. Most wordlists under 10MB can be loaded quickly with minimal memory overhead
    // 2. Memory mapping has overhead that may not be worth it for small files
    // 3. 10MB allows for roughly 1 million words (assuming average word length of 10 chars)
    if file_size < 10_000_000 {
        // 10MB threshold
        let mut contents = Vec::new();
        file.read_to_end(&mut contents)?;
        Ok(parse_wordlist(&contents))
    } else {
        // For large files, use memory mapping
        let mmap = unsafe { Mmap::map(&file)? };
        Ok(parse_wordlist(&mmap))
    }
}

/// Collects the trimmed, non-empty lines of a wordlist, skipping lines that aren't
/// valid UTF-8
fn parse_wordlist(contents: &[u8]) -> HashSet<String> {
    let mut wordlist = HashSet::new();
    let mut skipped = 0;
    for line in contents.split(|&byte| byte == b'\n') {
        match std::str::from_utf8(line) {
            Ok(line) => {
                let word = line.trim();
                if !word.is_empty() {
                    wordlist.insert(word.to_string());
                }
            }
            Err(_) => skipped += 1,
        }
    }
    if skipped > 0 {
        log::warn!("Skipped {skipped} wordlist lines that aren't valid UTF-8");
    }
    wordlist
}

/// Get configuration from file or create default if it doesn't exist
pub fn get_config_file_into_struct() -> Config {
    let path = get_config_file_path();

    if !path.exists() {
        // First run - get user preferences
        let mut config = config_from_first_run(crate::cli::run_first_time_setup());

        // Load the wordlist if one was chosen
        if let Some(wordlist_path) = config.wordlist_path.clone() {
            match load_wordlist(&wordlist_path) {
                Ok(wordlist) => {
                    config.wordlist = Some(wordlist);
                }
                Err(e) => {
                    eprintln!(
                        "Warning: Could not load wordlist at '{}': {}",
                        wordlist_path, e
                    );
                    // Don't exit - just continue without the wordlist
                }
            }
        }

        // Save the config to file
        save_config_to_file(&config, &path);
        config
    } else {
        // Existing config - read and parse it
        match read_config_file() {
            Ok(contents) => {
                let mut config = match parse_toml_with_unknown_keys(&contents) {
                    Ok(config) => config,
                    Err(e) => {
                        eprintln!(
                            "Error parsing config file '{}'. Using defaults.\n{}",
                            path.display(),
                            e.to_string().trim_end()
                        );
                        return Config::default();
                    }
                };

                // If wordlist is specified in config file, set it in the config struct
                if let Some(wordlist_path) = &config.wordlist_path {
                    // Load the wordlist here in the config layer
                    match load_wordlist(wordlist_path) {
                        Ok(wordlist) => {
                            config.wordlist = Some(wordlist);
                        }
                        Err(_e) => {
                            // Critical error - exit if config specifies wordlist but can't load it
                            eprintln!("Can't load wordlist at '{}'. Either fix or remove wordlist from config file at '{}'", 
                                wordlist_path, path.display());
                            std::process::exit(1);
                        }
                    }
                }

                config
            }
            Err(e) => {
                eprintln!("Error reading config file: {}. Using defaults.", e);
                Config::default()
            }
        }
    }
}

/// Builds the config from the answers to the first-run setup.
///
/// The setup returns everything in one map, so the settings are taken out of it
/// and the colour roles that are left become the colour scheme.
fn config_from_first_run(mut answers: HashMap<String, String>) -> Config {
    let mut config = Config::default();
    if let Some(timeout) = answers.remove("timeout") {
        config.timeout = timeout.parse().unwrap_or(config.timeout);
    }
    if let Some(top_results) = answers.remove("top_results") {
        config.top_results = top_results == "true";
    }
    if let Some(enhanced_detection) = answers.remove("enhanced_detection") {
        config.enhanced_detection = enhanced_detection == "true";
    }
    config.model_path = answers.remove("model_path");
    config.wordlist_path = answers.remove("wordlist_path");
    config.colourscheme = answers;
    config
}

/// Save a Config struct to a file
fn save_config_to_file(config: &Config, path: &std::path::Path) {
    let toml_string = toml::to_string_pretty(config).expect("Could not serialize config");
    let mut file = File::create(path).expect("Could not create config file");
    file.write_all(toml_string.as_bytes())
        .expect("Could not write to config file");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_file_is_parsed() {
        let config = parse_toml_with_unknown_keys("timeout = 10\ntop_results = true\n").unwrap();
        assert_eq!(config.timeout, 10);
        assert!(config.top_results);
    }

    #[test]
    fn malformed_config_file_is_an_error_not_a_panic() {
        // Invalid TOML
        assert!(parse_toml_with_unknown_keys("timeout = ").is_err());
        // Valid TOML, but the wrong type for a setting
        assert!(parse_toml_with_unknown_keys("timeout = \"ten\"").is_err());
    }

    #[test]
    fn first_run_answers_become_settings() {
        // These answers used to be saved as entries in the colour scheme, so choosing
        // top results mode or enhanced detection during the first run did nothing.
        let answers: HashMap<String, String> = [
            ("informational", "255,215,0"),
            ("warning", "255,0,0"),
            ("success", "0,255,0"),
            ("question", "255,215,0"),
            ("statement", "255,255,255"),
            ("top_results", "true"),
            ("timeout", "3"),
            ("enhanced_detection", "true"),
            ("model_path", "/models/model.bin"),
            ("wordlist_path", "/wordlists/words.txt"),
        ]
        .into_iter()
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect();

        let config = config_from_first_run(answers);

        assert!(config.top_results);
        assert_eq!(config.timeout, 3);
        assert!(config.enhanced_detection);
        assert_eq!(config.model_path.as_deref(), Some("/models/model.bin"));
        assert_eq!(
            config.wordlist_path.as_deref(),
            Some("/wordlists/words.txt")
        );
        let mut roles: Vec<&str> = config.colourscheme.keys().map(String::as_str).collect();
        roles.sort_unstable();
        assert_eq!(
            roles,
            [
                "informational",
                "question",
                "statement",
                "success",
                "warning"
            ]
        );
    }

    #[test]
    fn wordlist_lines_that_are_not_utf8_are_skipped() {
        let wordlist = parse_wordlist(b"hello\n\xff\xfe \xe9t\xe9\nworld\r\n\n  spaced  \n");
        let mut words: Vec<&str> = wordlist.iter().map(String::as_str).collect();
        words.sort_unstable();
        assert_eq!(words, ["hello", "spaced", "world"]);
    }
}
