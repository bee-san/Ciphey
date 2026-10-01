use thiserror::Error;

/// Errors returned by [`perform_cracking`](crate::perform_cracking).
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CipheyError {
    /// The timeout expired before the search finished, so a longer timeout may still succeed.
    #[error("search timed out after {secs}s")]
    Timeout {
        /// The configured timeout in seconds.
        secs: u32,
    },
    /// `Config::regex` is not a valid regular expression.
    #[error("invalid regex: {0}")]
    InvalidRegex(regex::Error),
}
