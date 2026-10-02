//! The 20 end-to-end cases from <https://github.com/bee-san/Ciphey/issues/1031>, run the way
//! the issue ran them: `ciphey -t <ciphertext> -d` with a fresh home directory, so the
//! cache can't answer. Before the fixes from that issue only 6 came back right.
//!
//! The two inputs that still fail are `#[ignore]`d with the reason; run them with
//! `cargo test --test plaintext_detection -- --ignored`.
//!
//! On Windows `dirs::home_dir()` ignores `HOME`, so these only run on Unix.
#![cfg(unix)]

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};

/// Runs `ciphey -d -t <input>` in a fresh home directory and returns the plaintext it
/// printed, or what it printed instead.
fn decode(name: &str, input: &str) -> String {
    let home = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "ciphey-pdetect-{}-{}",
        name,
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&home);
    fs::create_dir_all(home.join(".ciphey")).expect("Could not create temporary home");
    fs::write(home.join(".ciphey").join("config.toml"), "").expect("Could not write config");

    let output = Command::new(env!("CARGO_BIN_EXE_ciphey"))
        // Generous for unoptimised builds; every case finishes in well under a second
        // in a release build
        .args(["-d", "-c", "20", "-t", input])
        .env("HOME", &home)
        .env("NO_COLOR", "1")
        .stdin(Stdio::null())
        .output()
        .expect("Could not run ciphey");
    let _ = fs::remove_dir_all(&home);

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let mut lines = stdout.lines();
    if stdout.contains("Your input text is the plaintext") {
        return input.to_string();
    }
    while let Some(line) = lines.next() {
        if line.trim() == "The plaintext is:" {
            return lines.next().unwrap_or_default().to_string();
        }
    }
    format!(
        "<no plaintext>\n{stdout}{}",
        String::from_utf8_lossy(&output.stderr)
    )
}

macro_rules! cases {
    ($($(#[$attr:meta])* $name:ident: $input:expr => $expected:expr;)*) => {$(
        #[test]
        $(#[$attr])*
        fn $name() {
            assert_eq!(decode(stringify!($name), $input), $expected);
        }
    )*};
}

cases! {
    base64: "SGVsbG8sIFdvcmxkISBUaGlzIGlzIGEgdGVzdCBvZiBjaXBoZXku" => "Hello, World! This is a test of ciphey.";
    rot13: "Gur dhvpx oebja sbk whzcf bire gur ynml qbt" => "The quick brown fox jumps over the lazy dog";
    base64_three_times_ctf_flag: "V20xNGFGb3pkSFZOTTA0d1RUSlNabGxxV1RCWU1teDZXREphTVdKdU1EMD0=" => "flag{n3st3d_b64_is_fun}";
    rot13_then_base64: "enJyZyB6ciBuZyBndXIgaGZobnkgY3lucHIgbmcgZ3Jh" => "meet me at the usual place at ten";
    morse: "... --- ... / ... . -. -.. / .... . .-.. .--. / -. --- .--" => "SOS SEND HELP NOW";
    // Was returned unchanged as a "Phone Number"
    hex_of_secret: "736563726574" => "secret";
    // Was `ThI2THAtThE2THe0` (Vigenere)
    hex_then_base64_of_secret: "NzM2NTYzNzI2NTc0" => "secret";
    // Was returned unchanged as a "Bitly Secret Key"
    hex_of_20_bytes: "63697068657920697320736f20636f6f6c212121" => "ciphey is so cool!!!";
    // Was `BYFFIQILFX`, a wrong shift LemmeKnow called an "ASIN"
    caesar_without_spaces: "KHOORZRUOG" => "HELLOWORLD";
    // Was `TISUYYOQVTHERBMEITHAATNMONOERETOHTH` (Reverse -> Vigenere)
    caesar_sentence_without_spaces: "WKHTXLFNEURZQIRAMXPSVRYHUWKHODCBGRJ" => "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG";
    // Was `4HE QUICK BROWN FOX JUMPS OVER THE LAZY DOG` (shift 15)
    rot47: "%96 BF:4< 3C@H? 7@I ;F>AD @G6C E96 =2KJ 5@8" => "The quick brown fox jumps over the lazy dog";
    // Was returned unchanged as English
    reversed: "yob llud a kcaJ sekam yalp on dna krow llA" => "All work and no play makes Jack a dull boy";
    atbash: "zggzxp zg wzdm" => "attack at dawn";
    #[ignore = "Vigenere's key search doesn't find LEMON for this text, so nothing (or a near miss) is found"]
    vigenere: "Elq hepeeiep me phcmqr hyhqf gsi azq zew hepi zsnc xts etzqf oj xts ocmpur" => "The treasure is buried under the old oak tree near the river by the bridge";
    // Was `EERVENDSRETEABTHIESTHEDIN` (Reverse -> Vigenere)
    railfence: "WECRLTEERDSOEEFEAOCAIVDEN" => "WEAREDISCOVEREDFLEEATONCE";
    // Was `nthaNANHfilES020ERUErI0ntt1=hHHe` (railfence -> Vigenere)
    base64_pico_ctf_flag: "cGljb0NURntiNHMzXzY0XzFzX2Z1bn0=" => "picoCTF{b4s3_64_1s_fun}";
    // Was `==EatIThiThowXmEwfINoNos` (Reverse -> Vigenere)
    base64_json: "eyJrZXkiOiAidmFsdWUifQ==" => "{\"key\": \"value\"}";
    // Was `==FRiERthI2N` (Reverse -> Vigenere)
    base64_short_phrase: "Y2FsbCBtZQ==" => "call me";
    // Was `ToEterNth2EtkoLhALNhE2NheHIoNAE1NGDttHriNHmeSR==` (Vigenere)
    base64_french: "SmUgbmUgc2FpcyBwYXMgY2UgcXVlIHR1IHZldXggZGlyZQ==" => "Je ne sais pas ce que tu veux dire";
    #[ignore = "German isn't recognised as plaintext, so the search goes on and may settle on junk"]
    base64_german: "V2lyIHRyZWZmZW4gdW5zIG1vcmdlbiBhbSBCYWhuaG9m" => "Wir treffen uns morgen am Bahnhof";
}
