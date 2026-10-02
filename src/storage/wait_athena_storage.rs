use lazy_static::lazy_static;
use log::{trace, warn};
use std::sync::Mutex;

/// Represents a plaintext result with its description, checker name, and decoder name
#[derive(Debug, Clone)]
pub struct PlaintextResult {
    /// The plaintext text
    pub text: String,
    /// The description of the result
    pub description: String,
    /// The name of the checker used to generate the result
    pub checker_name: String,
    /// The name of the decoder used to generate the result
    pub decoder_name: String,
}

lazy_static! {
    static ref PLAINTEXT_RESULTS: Mutex<Vec<PlaintextResult>> = Mutex::new(Vec::new());
}

/// Adds a plaintext result to the storage
pub fn add_plaintext_result(
    text: String,
    description: String,
    checker_name: String,
    decoder_name: String,
) {
    let result = PlaintextResult {
        text: text.clone(),
        description: description.clone(),
        checker_name: checker_name.clone(),
        decoder_name: decoder_name.clone(),
    };

    trace!(
        "Adding plaintext result: [{}] {} (decoder: {})",
        checker_name,
        text,
        decoder_name
    );

    let mut results = match PLAINTEXT_RESULTS.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            warn!("Mutex was poisoned, recovering");
            poisoned.into_inner()
        }
    };

    results.push(result);
    trace!("Storage now has {} results", results.len());
}

/// Retrieves all plaintext results from the storage
pub fn get_plaintext_results() -> Vec<PlaintextResult> {
    let results = match PLAINTEXT_RESULTS.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            warn!("Mutex was poisoned, recovering");
            poisoned.into_inner()
        }
    };

    trace!("Retrieving {} plaintext results", results.len());
    results.clone()
}

/// Number of plaintext results stored so far, without copying them
pub fn plaintext_result_count() -> usize {
    match PLAINTEXT_RESULTS.lock() {
        Ok(guard) => guard.len(),
        Err(poisoned) => poisoned.into_inner().len(),
    }
}

/// Clears all plaintext results from the storage
pub fn clear_plaintext_results() {
    let mut results = match PLAINTEXT_RESULTS.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            warn!("Mutex was poisoned, recovering");
            poisoned.into_inner()
        }
    };

    trace!("Clearing plaintext results (had {} results)", results.len());
    results.clear();
}
