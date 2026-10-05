//! Runs single Ciphey decoders and the plaintext detector through the library API.
//!
//! ```sh
//! cargo run --example decode                                # a short tour
//! cargo run --example decode -- list                        # every decoder and its key
//! cargo run --example decode -- caesar 'Uryyb jbeyq'        # crack with one decoder
//! cargo run --example decode -- vigenere 'Rijvs uyvjn' KEY  # decrypt with a key
//! cargo run --example decode -- detect 192.168.0.1          # is it plaintext?
//! ```

use std::process::ExitCode;

use ciphey::detection::{detect_plaintext, DetectOptions, Detection};
use ciphey::{decode_with, decoders, list_decoders, CipheyError, DecodeOptions, Decoded};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let result = match args.as_slice() {
        [] => tour(),
        ["list"] => {
            list();
            Ok(())
        }
        ["detect", text] => {
            detect(text);
            Ok(())
        }
        [decoder, text] => decode(decoder, text, None),
        [decoder, text, key] => decode(decoder, text, Some(key)),
        _ => {
            eprintln!("usage: decode [list | detect <text> | <decoder> <text> [<key>]]");
            return ExitCode::from(2);
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Shows each part of the API once.
fn tour() -> Result<(), CipheyError> {
    println!("An encoding, with its function:");
    show(&decoders::base64("aGVsbG8gd29ybGQ="));

    println!("\nA cipher without its key, cracked:");
    show(&decoders::caesar("Uryyb jbeyq"));

    println!("\nThe same cipher with its key:");
    show(&decoders::caesar_with_key("Uryyb jbeyq", 13));

    println!("\nA decoder picked by name (an alias here), with a key:");
    show(&decode_with(
        "vigenère",
        "Rijvs uyvjn",
        &DecodeOptions::with_key("KEY"),
    )?);

    println!("\nWhen no decoding passes the checks, you get them all:");
    let decoded = decoders::caesar("xkcd");
    println!(
        "  {} candidates from {}, none marked as plaintext",
        decoded.candidates.len(),
        decoded.decoder
    );

    println!("\nPlaintext detection:");
    for text in ["192.168.0.1", "hello there general", "aGVsbG8gdGhlcmU="] {
        detect(text);
    }

    println!(
        "\n{} decoders in all: cargo run --example decode -- list",
        list_decoders().len()
    );
    Ok(())
}

/// Lists every decoder, with its aliases and the key it takes.
fn list() {
    for decoder in list_decoders() {
        let mut names = vec![decoder.function];
        names.extend(decoder.aliases);
        println!("{} ({})", decoder.name, names.join(", "));
        if let Some(key) = decoder.key_format {
            println!("    key: {key}");
        }
    }
}

/// Runs one decoder by name, cracking or decrypting with `key`.
fn decode(decoder: &str, text: &str, key: Option<&str>) -> Result<(), CipheyError> {
    let options = match key {
        Some(key) => DecodeOptions::with_key(key),
        None => DecodeOptions::default(),
    };
    show(&decode_with(decoder, text, &options)?);
    Ok(())
}

/// Says whether `text` is plaintext and what it is.
fn detect(text: &str) {
    match detect_plaintext(text, &DetectOptions::default()) {
        Some(detection) => println!("  {text:?}: {}", describe(&detection)),
        None => println!("  {text:?}: not plaintext"),
    }
}

/// Prints a decoder's candidates, the accepted one marked with a tick.
fn show(decoded: &Decoded) {
    if decoded.is_empty() {
        println!(
            "  {}: nothing, the text isn't in its format",
            decoded.decoder
        );
    }
    for candidate in decoded.candidates.iter().take(5) {
        let mark = if candidate.is_plaintext() { '✓' } else { ' ' };
        print!("  {mark} {}: {:?}", decoded.decoder, candidate.text);
        if let Some(key) = &candidate.key {
            print!(" (key {key})");
        }
        if let Some(detection) = &candidate.detection {
            print!(", {}", describe(detection));
        }
        println!();
    }
    if decoded.candidates.len() > 5 {
        println!("    and {} more", decoded.candidates.len() - 5);
    }
}

/// What a checker found, in words.
fn describe(detection: &Detection) -> String {
    match detection.confidence {
        Some(confidence) => format!(
            "{} (by the {}, confidence {confidence})",
            detection.description, detection.checker
        ),
        None => format!("{} (by the {})", detection.description, detection.checker),
    }
}
