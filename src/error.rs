use thiserror::Error;

/// Errors returned by the library API: [`perform_cracking`](crate::perform_cracking),
/// [`decode_with`](crate::decode_with), the `*_with_key` functions in
/// [`decoders`](crate::decoders) and [`DetectOptions`](crate::DetectOptions).
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CipheyError {
    /// The timeout expired before the search finished, so a longer timeout may still succeed.
    #[error("search timed out after {secs}s")]
    Timeout {
        /// The configured timeout in seconds.
        secs: u32,
    },
    /// `Config::regex`, or the pattern given to `DetectOptions::regex`, is not a valid
    /// regular expression.
    #[error("invalid regex: {0}")]
    InvalidRegex(regex::Error),
    /// No decoder has this name or alias. [`list_decoders`](crate::list_decoders) lists them.
    #[error("no decoder is called {name:?}")]
    UnknownDecoder {
        /// The name that was asked for.
        name: String,
    },
    /// A key was given to a decoder that doesn't take one.
    #[error("{decoder} doesn't take a key")]
    KeyNotSupported {
        /// The decoder's name.
        decoder: &'static str,
    },
    /// The key isn't one the decoder can use.
    #[error("invalid key for {decoder}: {reason}")]
    InvalidKey {
        /// The decoder's name.
        decoder: &'static str,
        /// What is wrong with the key.
        reason: String,
    },
    /// No plaintext checker has this name.
    #[error("no checker is called {name:?}")]
    UnknownChecker {
        /// The name that was asked for.
        name: String,
    },
}
