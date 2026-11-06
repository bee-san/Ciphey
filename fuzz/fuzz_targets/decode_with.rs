//! Runs one of Ciphey's decoders on arbitrary input.
//!
//! The first byte picks the decoder from `ciphey::list_decoders()` and the rest is the
//! text. Run with `cargo +nightly fuzz run decode_with` from the repository root.
#![no_main]

use ciphey::{decode_with, list_decoders, DecodeOptions};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&selector, rest)) = data.split_first() else {
        return;
    };
    let decoders = list_decoders();
    let decoder = &decoders[usize::from(selector) % decoders.len()];
    let text = String::from_utf8_lossy(rest);
    // Errors are fine; panics, hangs and crashes are what the fuzzer is looking for.
    let _ = decode_with(decoder.name, &text, &DecodeOptions::default());
});
