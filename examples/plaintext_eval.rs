//! Plaintext-detection evaluation harness, from <https://github.com/bee-san/Ciphey/issues/1031>.
//!
//! Measures how well the checkers tell plaintext from the junk a decoder search produces:
//! recall per kind of plaintext, false positives per kind of junk, and time per check.
//! Rerun it whenever a checker, threshold or decoder sensitivity changes.
//!
//! Run:   cargo run --release --example plaintext_eval
//! Modes: PDETECT_HELDOUT=examples/data/heldout_pride_and_prejudice.txt
//!                              -> build the corpus from that file's lines instead (held-out
//!                                 text the thresholds were not tuned on)
//!        PDETECT_EXAMPLES=1    -> print misclassified examples per category
//!        PDETECT_DUMP=1        -> print every sample as TSV (category, positive, quadgram
//!                                 score, Athena at Low/Medium/High), for tuning thresholds
//!        PDETECT_CHECK_FILE=path -> classify each line of `path`
//!        PDETECT_REGEX='pat'   -> config.regex = Some(pat); only times the Regex checker
//! Deterministic: fixed corpus + xorshift PRNG with a fixed seed.

use std::collections::BTreeMap;
use std::hint::black_box;
use std::time::Instant;

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use ciphey::checkers::{
    athena::Athena,
    checker_type::{Check, Checker},
    english::EnglishChecker,
    json_checker::JsonChecker,
    lemmeknow_checker::LemmeKnow,
    password::PasswordChecker,
    regex_checker::RegexChecker,
    CheckerTypes,
};
use ciphey::config::{set_global_config, Config};
use ciphey::decoders::{
    caesar_decoder::CaesarDecoder,
    interface::{Crack, Decoder},
    railfence_decoder::RailfenceDecoder,
    rot47_decoder::ROT47Decoder,
    vigenere_decoder::VigenereDecoder,
};
use ciphey::storage::ngrams::quadgram_score;
use data_encoding::{BASE32, HEXLOWER, HEXUPPER};
use gibberish_or_not::{is_gibberish, Sensitivity};

// ---------------------------------------------------------------- corpus --

const LONG: [&str; 20] = [
    "The quick brown fox jumps over the lazy dog",
    "Hello, my name is Bee and I like to decode things",
    "It was the best of times, it was the worst of times",
    "We hold these truths to be self-evident, that all men are created equal",
    "To be or not to be, that is the question",
    "The meeting has been moved to Thursday afternoon at three o'clock",
    "Please remember to bring your laptop and charger to the workshop",
    "Cryptography is the practice and study of techniques for secure communication",
    "The treasure is buried under the old oak tree near the river",
    "All work and no play makes Jack a dull boy",
    "I think we should leave before the storm arrives tonight",
    "Never gonna give you up, never gonna let you down",
    "The password for the server is stored in the blue notebook",
    "Sometimes the simplest solution is the one that works best",
    "This is a secret message that nobody else should be able to read",
    "Attack the north gate at dawn and hold the bridge until noon",
    "She sells sea shells by the sea shore every summer morning",
    "The museum will be closed for renovations until next spring",
    "Can you send me the report by the end of the day please",
    "Ciphey is an automated decoding tool written in Rust",
];

const SHORT: [&str; 20] = [
    "hello",
    "hello world",
    "attack at dawn",
    "meet me at noon",
    "it is in the box",
    "I love you",
    "thank you",
    "good morning",
    "the end",
    "open sesame",
    "top secret",
    "send help",
    "see you soon",
    "call me",
    "hi there",
    "yes",
    "no way",
    "secret",
    "computer",
    "elephant",
];

const CLASSIC_NOSPACE: [&str; 2] = ["WEAREDISCOVEREDFLEEATONCE", "DEFENDTHEEASTWALLOFTHECASTLE"];

const PUNCT: [&str; 15] = [
    "Don't stop believing!",
    "It's a well-known fact.",
    "E-mail me at noon, OK?",
    "Hello,world!How are you?",
    "Wait... what?!",
    "This is state-of-the-art technology.",
    "Rock'n'roll isn't dead; it's evolving.",
    "\"Help!\" she shouted, \"I'm stuck!\"",
    "We can't, won't, and shouldn't do that.",
    "Q: What's up? A: Not much.",
    "Mr. Smith's dog-walking service (est. 1999)",
    "The cost is $5.99 - a bargain!",
    "You're welcome :)",
    "Item #42: 'fragile' - handle with care.",
    "Ready? Set... go!",
];

const FLAGS: [&str; 12] = [
    "flag{this_is_the_flag}",
    "FLAG{HELLO_WORLD}",
    "CTF{c4es4r_1s_e4sy}",
    "picoCTF{b4s3_64_1s_fun}",
    "HTB{s0m3_fl4g_h3r3}",
    "THM{tryh4ckm3_r0cks}",
    "DUCTF{d0wn_und3r}",
    "flag{w3lc0me_t0_th3_g4me}",
    "csawctf{n0t_s0_h4rd}",
    "uiuctf{rust_is_great}",
    "CTF{the_quick_brown_fox}",
    "picoCTF{the_answer_is_42}",
];

const URLS: [&str; 10] = [
    "https://github.com/bee-san/Ciphey",
    "http://example.com/index.html?q=1",
    "www.google.com",
    "https://skerritt.blog/introducing-ciphey/",
    "bee@skerritt.blog",
    "user.name+tag@example.co.uk",
    "192.168.0.1",
    "10.0.0.254",
    "ftp://files.example.org/pub/readme.txt",
    "s3://my-bucket/path/to/key",
];

const JSON: [&str; 8] = [
    "{\"name\": \"ciphey\", \"version\": 1}",
    "{\"user\":\"admin\",\"pass\":\"hunter2\"}",
    "[1, 2, 3, 4]",
    "{\"key\": \"value\"}",
    "{\"flag\": \"you found it\", \"points\": 100}",
    "{\"error\": null, \"ok\": true}",
    "[{\"id\": 1, \"title\": \"hello world\"}]",
    "{\"message\": \"meet at the usual place\"}",
];

const CODE: [&str; 8] = [
    "print(\"hello world\")",
    "def add(a, b): return a + b",
    "int main() { return 0; }",
    "SELECT * FROM users WHERE id = 1;",
    "console.log('hi');",
    "#include <stdio.h>",
    "fn main() { println!(\"Hello, world!\"); }",
    "for i in range(10): print(i)",
];

const NON_EN: [&str; 12] = [
    "Bonjour, comment allez-vous aujourd'hui ?",
    "Le chat est sur la table",
    "Je ne sais pas ce que tu veux dire",
    "Rendez-vous demain matin devant la gare",
    "Guten Morgen, wie geht es dir?",
    "Ich liebe dich",
    "Das Wetter ist heute sehr schön",
    "Wir treffen uns morgen am Bahnhof",
    "Hola, ¿cómo estás?",
    "La casa es muy grande",
    "Nos vemos mañana en la estación",
    "El tesoro está debajo del árbol",
];

const PASSWORDS: [&str; 10] = [
    "123456", "password", "qwerty", "letmein", "iloveyou", "dragon", "monkey", "sunshine",
    "trustno1", "football",
];

/// md5/sha1/sha256/sha512 of: password, hello, ciphey, flag{not_a_flag}, admin, "The quick brown fox"
const HASHES: [&str; 24] = [
    "5f4dcc3b5aa765d61d8327deb882cf99",
    "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8",
    "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
    "b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86",
    "5d41402abc4b2a76b9719d911017c592",
    "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",
    "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
    "9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043",
    "65aceb62e48136baaad4c3df3cc89bdf",
    "4ae6e6b0d2cc66305737df35a08b4d5d7b034290",
    "e17ca16299cb5c965a4dbc69b719a22ba18fdf483bced1823f79d13432cc9904",
    "7a189be7dba0ba1d11d1a4dc8b26f2c2119d17f3fe0add06a911f8a9969abe7e424face8f09cf8c121de4f8a8a4d8864c3c5b736e9fa7fd8e690b1a5541e6d8a",
    "190fdafb8465b9898fceb3ab6203d60d",
    "ef6c5ba73bc1de2fb2edc27786ec70ab16073494",
    "bdaa6a309d94419d2cb3bf9a1600223f0794fc711b55c14acae9ed6d776f2c00",
    "e325fcf60e6aef1e57cc69706857cfc1eac59c0878781805d73c6327080fa07c2601c5a96ddf6cc8526fd9954c7d48a1d7da033a13b73c01f275376243afb529",
    "21232f297a57a5a743894a0e4a801fc3",
    "d033e22ae348aeb5660fc2140aec35850c4da997",
    "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918",
    "c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec",
    "a2004f37730b9445670a738fa0fc9ee5",
    "c519c1a06cdbeb2bc499e22137fb48683858b345",
    "5cac4f980fedc3d3f1f99b4be3472c9b30d56523e632d151237ec9309048bda9",
    "015e6d23e760f612cca616c54f110cb12dd54213f1e046c7607081372402eff4936b379296ed549236020afb37bd3e728a044a4243754f095498c98bc24f77e0",
];

const VIG_KEYS: [&str; 4] = ["LEMON", "KEY", "CIPHEY", "SECRETKEY"];

// ------------------------------------------------------------- utilities --

/// xorshift64* so the corpus does not depend on the `rand` crate version.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    /// inclusive range
    fn range(&mut self, lo: usize, hi: usize) -> usize {
        lo + (self.next() % (hi - lo + 1) as u64) as usize
    }
    fn pick(&mut self, alphabet: &[u8]) -> char {
        alphabet[self.range(0, alphabet.len() - 1)] as char
    }
}

fn caesar(s: &str, k: u8) -> String {
    s.chars()
        .map(|c| match c {
            'a'..='z' => (((c as u8 - b'a' + k) % 26) + b'a') as char,
            'A'..='Z' => (((c as u8 - b'A' + k) % 26) + b'A') as char,
            _ => c,
        })
        .collect()
}

fn atbash(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'a'..='z' => (b'z' - (c as u8 - b'a')) as char,
            'A'..='Z' => (b'Z' - (c as u8 - b'A')) as char,
            _ => c,
        })
        .collect()
}

fn rot47(s: &str) -> String {
    s.chars()
        .map(|c| {
            let b = c as u32;
            if (33..=126).contains(&b) {
                char::from_u32(((b - 33 + 47) % 94) + 33).unwrap()
            } else {
                c
            }
        })
        .collect()
}

fn nospace_caps(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphabetic())
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

fn vig(s: &str, key: &str, decrypt: bool) -> String {
    let k: Vec<u8> = key.bytes().map(|b| b - b'A').collect();
    let mut i = 0;
    s.chars()
        .map(|c| {
            if c.is_ascii_alphabetic() {
                let base = if c.is_ascii_uppercase() { b'A' } else { b'a' };
                let shift = if decrypt {
                    26 - k[i % k.len()]
                } else {
                    k[i % k.len()]
                };
                i += 1;
                (((c as u8 - base + shift) % 26) + base) as char
            } else {
                c
            }
        })
        .collect()
}

/// Same zigzag as src/decoders/railfence_decoder.rs
fn zigzag(n: usize, offset: usize) -> impl Iterator<Item = usize> {
    (0..n - 1).chain((1..n).rev()).cycle().skip(offset)
}

fn rail_enc(text: &str, rails: usize) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut idx: Vec<(usize, usize)> = zigzag(rails, 0).zip(0..).take(chars.len()).collect();
    idx.sort();
    idx.iter().map(|&(_, p)| chars[p]).collect()
}

/// Copy of ciphey's railfence_decoder() so we can generate *wrong* decryptions.
fn rail_dec(text: &str, rails: usize, offset: usize) -> String {
    let mut indexes: Vec<_> = zigzag(rails, offset).zip(1..).take(text.len()).collect();
    indexes.sort();
    let mut cwi: Vec<_> = text
        .chars()
        .zip(indexes)
        .map(|(c, (_, i))| (i, c))
        .collect();
    cwi.sort();
    cwi.iter().map(|(_, c)| c).collect()
}

fn pct(a: usize, b: usize) -> String {
    if b == 0 {
        "-".into()
    } else {
        format!("{:.1}%", 100.0 * a as f64 / b as f64)
    }
}

fn fmt_ns(ns: f64) -> String {
    if ns < 1000.0 {
        format!("{ns:.0} ns")
    } else {
        format!("{:.1} µs", ns / 1000.0)
    }
}

fn short(s: &str) -> String {
    let s = s.replace('\n', "\\n").replace('|', "\\|");
    if s.chars().count() > 70 {
        format!("{}…", s.chars().take(70).collect::<String>())
    } else {
        s
    }
}

// ---------------------------------------------------------------- corpus --

struct Sample {
    text: String,
    pos: bool,
    cat: &'static str,
}

/// The texts the corpus is built from: the built-in lists, or the lines of a held-out file.
struct Texts {
    /// Sentences
    long: Vec<String>,
    /// Phrases of 1 to 4 words
    short: Vec<String>,
}

impl Texts {
    fn builtin() -> Self {
        Texts {
            long: LONG.iter().map(|s| s.to_string()).collect(),
            short: SHORT.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// Lines of `path`; `#` starts a comment. Lines of up to 4 words are phrases.
    fn from_file(path: &str) -> Self {
        let content = std::fs::read_to_string(path).expect("held-out file");
        let lines: Vec<String> = content
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(String::from)
            .collect();
        let (short, long) = lines
            .into_iter()
            .partition(|l| l.split_whitespace().count() <= 4);
        Texts { long, short }
    }

    /// Half of each list, as CAPS and NOSPACECAPS variants
    fn halves(&self) -> impl Iterator<Item = &String> {
        self.long[..self.long.len() / 2]
            .iter()
            .chain(self.short[..self.short.len() / 2].iter())
    }

    fn nospace_set(&self, builtin: bool) -> Vec<String> {
        let mut v: Vec<String> = self
            .halves()
            .map(|s| nospace_caps(s))
            .filter(|s| !s.is_empty())
            .collect();
        if builtin {
            v.extend(CLASSIC_NOSPACE.iter().map(|s| s.to_string()));
        }
        v
    }
}

fn build_corpus(texts: &Texts, builtin: bool, rng: &mut Rng) -> Vec<Sample> {
    let mut c: Vec<Sample> = Vec::new();
    let mut add = |cat: &'static str, pos: bool, text: String| c.push(Sample { text, pos, cat });

    // ---- positives
    texts
        .long
        .iter()
        .for_each(|s| add("en_long", true, s.clone()));
    texts
        .short
        .iter()
        .for_each(|s| add("en_short", true, s.clone()));
    texts
        .halves()
        .for_each(|s| add("en_caps", true, s.to_uppercase()));
    texts
        .nospace_set(builtin)
        .into_iter()
        .for_each(|s| add("en_nospace", true, s));
    if builtin {
        PUNCT
            .iter()
            .for_each(|s| add("en_punct", true, s.to_string()));
        FLAGS
            .iter()
            .for_each(|s| add("ctf_flag", true, s.to_string()));
        URLS.iter()
            .for_each(|s| add("url_email_ip", true, s.to_string()));
        JSON.iter().for_each(|s| add("json", true, s.to_string()));
        CODE.iter().for_each(|s| add("code", true, s.to_string()));
        NON_EN
            .iter()
            .for_each(|s| add("non_english", true, s.to_string()));
        PASSWORDS
            .iter()
            .for_each(|s| add("password", true, s.to_string()));
    }

    // ---- negatives
    let base: Vec<String> = texts
        .long
        .iter()
        .chain(texts.short.iter())
        .cloned()
        .collect();
    for p in base.iter().chain(texts.nospace_set(builtin).iter()) {
        for k in 1..=25 {
            add("caesar_wrong", false, caesar(p, k));
        }
    }
    base.iter().for_each(|p| add("atbash", false, atbash(p)));
    base.iter()
        .for_each(|p| add("reversed", false, p.chars().rev().collect()));
    let punct: Vec<String> = if builtin {
        PUNCT.iter().map(|s| s.to_string()).collect()
    } else {
        vec![]
    };
    base.iter()
        .chain(punct.iter())
        .for_each(|p| add("rot47", false, rot47(p)));
    for p in texts.long.iter().cloned().chain(texts.nospace_set(builtin)) {
        let ct = rail_enc(&p, 3);
        for (r, o) in [(2, 0), (2, 1), (4, 0), (5, 3)] {
            let d = rail_dec(&ct, r, o);
            // The issue's corpus keeps the rare wrong key that happens to decode correctly
            if builtin || d != p {
                add("railfence_wrong", false, d);
            }
        }
    }
    for (i, p) in texts.long.iter().enumerate() {
        let key = VIG_KEYS[i % VIG_KEYS.len()];
        let ct = vig(p, key, false);
        for _ in 0..3 {
            let len = rng.range(3, 8);
            let wrong: String = (0..len)
                .map(|_| rng.pick(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"))
                .collect();
            add("vigenere_wrong", false, vig(&ct, &wrong, true));
        }
        // partially decoded: last key letter wrong by one
        let mut partial: Vec<u8> = key.bytes().collect();
        let last = partial.len() - 1;
        partial[last] = b'A' + ((partial[last] - b'A' + 1) % 26);
        add(
            "vigenere_partial",
            false,
            vig(&ct, std::str::from_utf8(&partial).unwrap(), true),
        );
    }
    let flags: Vec<String> = if builtin {
        FLAGS.iter().map(|s| s.to_string()).collect()
    } else {
        vec![]
    };
    base.iter()
        .chain(punct.iter())
        .chain(flags.iter())
        .for_each(|p| add("base64", false, B64.encode(p.as_bytes())));
    for _ in 0..60 {
        let n = rng.range(1, 60);
        let bytes: Vec<u8> = (0..n).map(|_| rng.next() as u8).collect();
        add("base64", false, B64.encode(&bytes));
    }
    base.iter()
        .for_each(|p| add("base32", false, BASE32.encode(p.as_bytes())));
    base.iter()
        .for_each(|p| add("hex", false, HEXLOWER.encode(p.as_bytes())));
    texts
        .halves()
        .for_each(|p| add("hex", false, HEXUPPER.encode(p.as_bytes())));
    if builtin {
        HASHES
            .iter()
            .for_each(|h| add("hash", false, h.to_string()));
    }
    let ascii: Vec<u8> = (0x20u8..=0x7e).collect();
    let alnum = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    for _ in 0..100 {
        let n = rng.range(8, 80);
        add(
            "rand_ascii",
            false,
            (0..n).map(|_| rng.pick(&ascii)).collect(),
        );
    }
    for _ in 0..100 {
        let n = rng.range(8, 64);
        add(
            "rand_alnum",
            false,
            (0..n).map(|_| rng.pick(alnum)).collect(),
        );
    }
    for _ in 0..60 {
        let n = rng.range(8, 40);
        add(
            "rand_upper",
            false,
            (0..n).map(|_| rng.pick(&alnum[..26])).collect(),
        );
    }
    for _ in 0..50 {
        let n = rng.range(8, 60);
        let s: String = (0..n)
            .map(|_| {
                if rng.next().is_multiple_of(2) {
                    rng.pick(&ascii)
                } else {
                    char::from_u32(0xA0 + (rng.next() % 0x60) as u32).unwrap()
                }
            })
            .collect();
        add("rand_latin1", false, s);
    }
    for _ in 0..50 {
        let n = rng.range(8, 60);
        let bytes: Vec<u8> = (0..n).map(|_| rng.next() as u8).collect();
        add(
            "rand_bytes",
            false,
            String::from_utf8_lossy(&bytes).into_owned(),
        );
    }
    for _ in 0..60 {
        let n = rng.range(4, 20);
        add(
            "digits",
            false,
            (0..n).map(|_| rng.pick(b"0123456789")).collect(),
        );
    }
    c
}

// -------------------------------------------------------------- checkers --

type CheckFn = Box<dyn Fn(&str) -> (bool, String)>;

fn sens_list() -> [(&'static str, Sensitivity); 3] {
    [
        ("Low", Sensitivity::Low),
        ("Medium", Sensitivity::Medium),
        ("High", Sensitivity::High),
    ]
}

fn checker_configs() -> Vec<(String, CheckFn)> {
    let mut v: Vec<(String, CheckFn)> = Vec::new();
    for (n, s) in sens_list() {
        let a = Checker::<Athena>::new().with_sensitivity(s);
        v.push((
            format!("Athena@{n}"),
            Box::new(move |t: &str| {
                let r = a.check(t);
                (
                    r.is_identified,
                    format!("{}: {}", r.checker_name, r.description),
                )
            }),
        ));
    }
    for (n, s) in sens_list() {
        let e = Checker::<EnglishChecker>::new().with_sensitivity(s);
        v.push((
            format!("English@{n}"),
            Box::new(move |t: &str| (e.check(t).is_identified, "English".to_string())),
        ));
    }
    // What the English checker was before #1031, for comparison
    for (n, s) in [("Low", Sensitivity::Low), ("Medium", Sensitivity::Medium)] {
        v.push((
            format!("raw gibberish-or-not@{n}"),
            Box::new(move |t: &str| (!is_gibberish(t, s), "raw".to_string())),
        ));
    }
    let l = Checker::<LemmeKnow>::new();
    v.push((
        "LemmeKnow".into(),
        Box::new(move |t: &str| {
            let r = l.check(t);
            (r.is_identified, r.description)
        }),
    ));
    let j = Checker::<JsonChecker>::new();
    v.push((
        "JSON".into(),
        Box::new(move |t: &str| (j.check(t).is_identified, "JSON".into())),
    ));
    let p = Checker::<PasswordChecker>::new();
    v.push((
        "Password".into(),
        Box::new(move |t: &str| (p.check(t).is_identified, "Password".into())),
    ));
    v
}

#[derive(Default)]
struct Res {
    tp: usize,
    fnn: usize,
    fp: usize,
    tn: usize,
    lat: Vec<u64>,
    cat: BTreeMap<&'static str, (usize, usize)>,
    miss: BTreeMap<&'static str, Vec<(String, String)>>,
    why_fp: BTreeMap<String, (usize, String)>,
}

fn evaluate(corpus: &[Sample], f: &CheckFn) -> Res {
    let mut r = Res::default();
    for s in corpus.iter().take(60) {
        black_box(f(&s.text)); // build the lazily compiled regexes and tables first
    }
    for s in corpus {
        let t0 = Instant::now();
        let (hit, why) = f(&s.text);
        r.lat.push(t0.elapsed().as_nanos() as u64);
        let e = r.cat.entry(s.cat).or_insert((0, 0));
        e.1 += 1;
        if hit {
            e.0 += 1;
        }
        match (s.pos, hit) {
            (true, true) => r.tp += 1,
            (true, false) => {
                r.fnn += 1;
                r.miss
                    .entry(s.cat)
                    .or_default()
                    .push((s.text.clone(), String::new()));
            }
            (false, true) => {
                r.fp += 1;
                r.miss
                    .entry(s.cat)
                    .or_default()
                    .push((s.text.clone(), why.clone()));
                let w = r.why_fp.entry(why).or_insert((0, s.text.clone()));
                w.0 += 1;
            }
            (false, false) => r.tn += 1,
        }
    }
    r.lat.sort_unstable();
    r
}

// --------------------------------------------------------- decoder level --

#[derive(Default)]
struct DecRes {
    n: usize,
    correct: usize,
    wrong: usize,
    none: usize,
    gate_fp: usize,
    total_ns: u128,
    wrong_ex: Vec<String>,
    gate_ex: Vec<String>,
}

fn decoder_eval<T>(dec: &Decoder<T>, cases: &[(String, String)]) -> DecRes
where
    Decoder<T>: Crack,
{
    let athena = CheckerTypes::CheckAthena(Checker::<Athena>::new());
    let gate = Checker::<Athena>::new(); // what lib.rs runs on the raw input (Medium)
    let mut r = DecRes::default();
    for (p, c) in cases {
        r.n += 1;
        let g = gate.check(c);
        if g.is_identified {
            r.gate_fp += 1;
            if r.gate_ex.len() < 4 {
                r.gate_ex.push(format!(
                    "`{}` accepted as-is by {} ({})",
                    short(c),
                    g.checker_name,
                    g.description
                ));
            }
        }
        let t0 = Instant::now();
        let res = dec.crack(c, &athena);
        r.total_ns += t0.elapsed().as_nanos();
        let got = if res.success {
            res.unencrypted_text
                .as_ref()
                .and_then(|v| v.first())
                .cloned()
        } else {
            None
        };
        match got {
            Some(g) if &g == p => r.correct += 1,
            Some(g) => {
                r.wrong += 1;
                if r.wrong_ex.len() < 6 {
                    r.wrong_ex.push(format!(
                        "`{}` → expected `{}` → got `{}` ({})",
                        short(c),
                        short(p),
                        short(&g),
                        res.checker_name
                    ));
                }
            }
            None => r.none += 1,
        }
    }
    r
}

fn decoder_level(texts: &Texts, builtin: bool) {
    println!("\n## Decoder-level (real decoders, Athena checker as used by A*)\n");
    let ns = texts.nospace_set(builtin);
    let mut caesar_cases_cat: Vec<(&'static str, String, String)> = Vec::new();
    let typed: Vec<(&'static str, String)> = texts
        .long
        .iter()
        .map(|s| ("prose", s.clone()))
        .chain(texts.short.iter().map(|s| ("short (1-4 words)", s.clone())))
        .chain(texts.halves().map(|s| ("ALL CAPS", s.to_uppercase())))
        .chain(ns.iter().map(|s| ("NOSPACECAPS", s.clone())))
        .collect();
    for (cat, p) in &typed {
        for k in [3u8, 13, 23] {
            caesar_cases_cat.push((cat, p.clone(), caesar(p, k)));
        }
    }
    let caesar_cases: Vec<(String, String)> = caesar_cases_cat
        .iter()
        .map(|(_, p, c)| (p.clone(), c.clone()))
        .collect();
    let punct: Vec<String> = if builtin {
        PUNCT.iter().map(|s| s.to_string()).collect()
    } else {
        vec![]
    };
    let rot47_cases: Vec<(String, String)> = texts
        .long
        .iter()
        .chain(texts.short.iter())
        .chain(punct.iter())
        .map(|p| (p.clone(), rot47(p)))
        .collect();
    let mut rail_cases = Vec::new();
    for p in texts.long.iter().cloned().chain(ns.iter().cloned()) {
        for r in [2usize, 3, 5] {
            rail_cases.push((p.clone(), rail_enc(&p, r)));
        }
    }
    let mut vig_cases = Vec::new();
    for p in texts.long.iter() {
        for k in VIG_KEYS {
            vig_cases.push((p.clone(), vig(p, k, false)));
        }
    }
    println!("| decoder | cases | correct | wrong plaintext accepted | nothing found | ciphertext itself accepted by input check (Athena@Medium) | mean crack time |");
    println!("|---|---|---|---|---|---|---|");
    let dec_runs: Vec<(&str, DecRes)> = vec![
        (
            "Caesar",
            decoder_eval(&Decoder::<CaesarDecoder>::new(), &caesar_cases),
        ),
        (
            "ROT47",
            decoder_eval(&Decoder::<ROT47Decoder>::new(), &rot47_cases),
        ),
        (
            "Railfence",
            decoder_eval(&Decoder::<RailfenceDecoder>::new(), &rail_cases),
        ),
        (
            "Vigenère",
            decoder_eval(&Decoder::<VigenereDecoder>::new(), &vig_cases),
        ),
    ];
    for (name, r) in &dec_runs {
        println!(
            "| {name} | {} | {} | {} | {} | {} | {} |",
            r.n,
            pct(r.correct, r.n),
            pct(r.wrong, r.n),
            pct(r.none, r.n),
            pct(r.gate_fp, r.n),
            fmt_ns(r.total_ns as f64 / r.n as f64)
        );
    }
    for (name, r) in &dec_runs {
        if !r.wrong_ex.is_empty() || !r.gate_ex.is_empty() {
            println!("\n{name} examples:");
            for e in r.wrong_ex.iter().chain(r.gate_ex.iter()) {
                println!("- {e}");
            }
        }
    }

    println!("\n### Caesar (real decoder) by plaintext type\n");
    println!("| plaintext type | cases | correct | wrong plaintext accepted | nothing found |\n|---|---|---|---|---|");
    let athena_ct = CheckerTypes::CheckAthena(Checker::<Athena>::new());
    let cdec = Decoder::<CaesarDecoder>::new();
    for cat in ["prose", "short (1-4 words)", "ALL CAPS", "NOSPACECAPS"] {
        let (mut n, mut ok, mut bad, mut none) = (0, 0, 0, 0);
        for (c_cat, p, c) in &caesar_cases_cat {
            if *c_cat != cat {
                continue;
            }
            n += 1;
            let r = cdec.crack(c, &athena_ct);
            match r.unencrypted_text.as_ref().and_then(|v| v.first()) {
                Some(g) if r.success && g == p => ok += 1,
                Some(_) if r.success => bad += 1,
                _ => none += 1,
            }
        }
        println!(
            "| {cat} | {n} | {} | {} | {} |",
            pct(ok, n),
            pct(bad, n),
            pct(none, n)
        );
    }
}

// ------------------------------------------------------------ benchmarks --

fn bench(label: &str, iters: u32, mut f: impl FnMut()) {
    for _ in 0..(iters / 10).max(10) {
        f();
    }
    let t = Instant::now();
    for _ in 0..iters {
        f();
    }
    let ns = t.elapsed().as_nanos() as f64 / iters as f64;
    println!("| {label} | {} |", fmt_ns(ns));
}

fn regex_mode(pat: &str) {
    println!("## Regex mode (config.regex = {pat:?})\n");
    println!("| operation | time / call |\n|---|---|");
    let text = "The quick brown fox jumps over the lazy dog";
    let rc = Checker::<RegexChecker>::new();
    bench("RegexChecker::check", 20_000, || {
        black_box(rc.check(black_box(text)));
    });
    let re = regex::Regex::new(pat).unwrap();
    bench("prebuilt Regex::is_match", 20_000, || {
        black_box(re.is_match(black_box(text)));
    });
    let a = Checker::<Athena>::new();
    bench("Athena::check (regex path)", 20_000, || {
        black_box(a.check(black_box(text)));
    });
}

fn micro_benchmarks() {
    println!("\n## Micro-benchmarks\n");
    println!("| operation | time / call |\n|---|---|");
    let en = "The quick brown fox jumps over the lazy dog";
    let b64_40 = B64.encode(b"ciphey decodes things for me!!");
    let lk = Checker::<LemmeKnow>::new();
    bench("LemmeKnow::check (English sentence)", 20_000, || {
        black_box(lk.check(black_box(en)));
    });
    bench("LemmeKnow::check (40-char base64)", 20_000, || {
        black_box(lk.check(black_box(&b64_40)));
    });
    let js = Checker::<JsonChecker>::new();
    bench("JSON::check (English sentence)", 200_000, || {
        black_box(js.check(black_box(en)));
    });
    bench("JSON::check (JSON object)", 200_000, || {
        black_box(js.check(black_box("{\"key\": \"value\"}")));
    });
    let pw = Checker::<PasswordChecker>::new();
    bench("Password::check", 200_000, || {
        black_box(pw.check(black_box(en)));
    });
    bench("quadgram_score (35 letters)", 200_000, || {
        black_box(quadgram_score(black_box(
            "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG",
        )));
    });
    let ec = Checker::<EnglishChecker>::new();
    bench("English::check @Medium, English sentence", 50_000, || {
        black_box(ec.check(black_box(en)));
    });
    bench("English::check @Medium, space-less letters", 50_000, || {
        black_box(ec.check(black_box("WKHTXLFNEURZQIRAMXPSVRYHUWKHODCBGRJ")));
    });
    bench("raw is_gibberish @Medium, English sentence", 50_000, || {
        black_box(is_gibberish(black_box(en), Sensitivity::Medium));
    });
    let am = Checker::<Athena>::new();
    bench(
        "Athena::check @Medium, English sentence (positive path)",
        20_000,
        || {
            black_box(am.check(black_box(en)));
        },
    );
    let junk = "q8Zr1Xk0pLm3Vb7Nc5Tw9Hd2Fg4Js6Ky1Ue8Ri0Oa3";
    bench(
        "Athena::check @Medium, random alnum (negative path)",
        20_000,
        || {
            black_box(am.check(black_box(junk)));
        },
    );
    let spaced_junk = "Max mkxtlnkx bl unkbxw ngwxk max hew htd mkxx gxtk max kboxk";
    bench(
        "Athena::check @Medium, wrong Caesar shift (negative path)",
        20_000,
        || {
            black_box(am.check(black_box(spaced_junk)));
        },
    );
}

// ------------------------------------------------------------------ main --

fn main() {
    let regex = std::env::var("PDETECT_REGEX").ok();
    let show_examples = std::env::var("PDETECT_EXAMPLES")
        .map(|v| v == "1")
        .unwrap_or(false);
    let dump = std::env::var("PDETECT_DUMP")
        .map(|v| v == "1")
        .unwrap_or(false);

    let cfg = Config {
        api_mode: true,
        human_checker_on: false,
        regex: regex.clone(),
        ..Config::default()
    };
    set_global_config(cfg);

    if let Some(p) = regex {
        regex_mode(&p);
        return;
    }

    if let Ok(path) = std::env::var("PDETECT_CHECK_FILE") {
        let configs = checker_configs();
        let content = std::fs::read_to_string(path).expect("check file");
        for line in content.lines().filter(|l| !l.is_empty()) {
            println!("`{}`", short(line));
            for (n, f) in configs
                .iter()
                .filter(|(n, _)| n.starts_with("Athena") || n == "LemmeKnow")
            {
                let (hit, why) = f(line);
                println!("  {n}: {hit} {}", if hit { why } else { String::new() });
            }
        }
        return;
    }

    let heldout = std::env::var("PDETECT_HELDOUT").ok();
    let builtin = heldout.is_none();
    let texts = match &heldout {
        Some(path) => Texts::from_file(path),
        None => Texts::builtin(),
    };
    let mut rng = Rng(0x00C1_FE7E_5EED_2026);
    let corpus = build_corpus(&texts, builtin, &mut rng);

    if dump {
        let athena: Vec<Checker<Athena>> = sens_list()
            .iter()
            .map(|(_, s)| Checker::<Athena>::new().with_sensitivity(*s))
            .collect();
        println!("category\tpositive\tspaceless_letters\tquadgram\tathena_low\tathena_medium\tathena_high\ttext");
        for s in &corpus {
            let trimmed = s.text.trim();
            let letters = trimmed.chars().filter(char::is_ascii_alphabetic).count();
            let spaceless = !trimmed.contains(char::is_whitespace)
                && letters >= 8
                && letters * 10 >= trimmed.chars().count() * 9;
            let q = quadgram_score(trimmed)
                .map(|q| format!("{q:.3}"))
                .unwrap_or_default();
            let a: Vec<u8> = athena
                .iter()
                .map(|c| u8::from(c.check(&s.text).is_identified))
                .collect();
            println!(
                "{}\t{}\t{}\t{q}\t{}\t{}\t{}\t{}",
                s.cat,
                u8::from(s.pos),
                u8::from(spaceless),
                a[0],
                a[1],
                a[2],
                s.text.replace(['\t', '\n'], " ")
            );
        }
        return;
    }

    let n_pos = corpus.iter().filter(|s| s.pos).count();
    let n_neg = corpus.len() - n_pos;
    let mut cats: Vec<(&'static str, bool, usize)> = Vec::new();
    for s in &corpus {
        match cats.iter_mut().find(|c| c.0 == s.cat) {
            Some(c) => c.2 += 1,
            None => cats.push((s.cat, s.pos, 1)),
        }
    }
    let prose = ["en_long", "en_short", "en_caps", "en_nospace", "en_punct"];

    println!(
        "# ciphey plaintext-detection eval ({})\n",
        heldout.as_deref().unwrap_or("issue #1031 corpus")
    );
    println!(
        "corpus: {n_pos} positives, {n_neg} negatives, {} categories\n",
        cats.len()
    );

    let configs = checker_configs();
    let results: Vec<(String, Res)> = configs
        .iter()
        .map(|(n, f)| (n.clone(), evaluate(&corpus, f)))
        .collect();

    // ---- overall table
    println!("## Overall\n");
    println!("| checker | recall (all pos) | recall (English prose) | FPR (micro) | FPR (macro over neg. categories) | precision | F1 | mean | p50 | p99 |");
    println!("|---|---|---|---|---|---|---|---|---|---|");
    for (name, r) in &results {
        let (pt, pn) = prose.iter().fold((0, 0), |a, c| {
            let v = r.cat.get(c).copied().unwrap_or((0, 0));
            (a.0 + v.0, a.1 + v.1)
        });
        let neg_cats: Vec<f64> = cats
            .iter()
            .filter(|c| !c.1)
            .map(|c| {
                let v = r.cat[c.0];
                v.0 as f64 / v.1 as f64
            })
            .collect();
        let macro_fpr = neg_cats.iter().sum::<f64>() / neg_cats.len() as f64;
        let precision = r.tp as f64 / (r.tp + r.fp).max(1) as f64;
        let recall = r.tp as f64 / (r.tp + r.fnn).max(1) as f64;
        let f1 = if precision + recall > 0.0 {
            2.0 * precision * recall / (precision + recall)
        } else {
            0.0
        };
        let mean = r.lat.iter().sum::<u64>() as f64 / r.lat.len() as f64;
        let p50 = r.lat[r.lat.len() / 2] as f64;
        let p99 = r.lat[r.lat.len() * 99 / 100] as f64;
        println!(
            "| {name} | {} ({}/{}) | {} | {} ({}/{}) | {:.1}% | {:.1}% | {:.2} | {} | {} | {} |",
            pct(r.tp, r.tp + r.fnn),
            r.tp,
            r.tp + r.fnn,
            pct(pt, pn),
            pct(r.fp, r.fp + r.tn),
            r.fp,
            r.fp + r.tn,
            macro_fpr * 100.0,
            precision * 100.0,
            f1,
            fmt_ns(mean),
            fmt_ns(p50),
            fmt_ns(p99)
        );
    }

    // ---- per-category tables
    for (title, pos) in [
        ("Recall per positive category", true),
        ("False-positive rate per negative category", false),
    ] {
        println!("\n## {title}\n");
        print!("| category (n) |");
        for (n, _) in &results {
            print!(" {n} |");
        }
        println!();
        print!("|---|");
        for _ in &results {
            print!("---|");
        }
        println!();
        for (cat, _, n) in cats.iter().filter(|c| c.1 == pos) {
            print!("| {cat} ({n}) |");
            for (_, r) in &results {
                let v = r.cat[cat];
                print!(" {} |", pct(v.0, v.1));
            }
            println!();
        }
    }

    // ---- attribution of false positives
    for (name, r) in results
        .iter()
        .filter(|(n, _)| n.starts_with("Athena") || n == "LemmeKnow")
    {
        println!("\n## What fired on negatives: {name} ({} FPs)\n", r.fp);
        println!("| reason | count | example |\n|---|---|---|");
        let mut v: Vec<_> = r.why_fp.iter().collect();
        v.sort_by_key(|entry| std::cmp::Reverse(entry.1 .0));
        for (why, (cnt, ex)) in v.iter().take(15) {
            println!("| {why} | {cnt} | `{}` |", short(ex));
        }
    }

    if show_examples {
        for (name, r) in results.iter().filter(|(n, _)| n.starts_with("Athena")) {
            println!("\n## Misclassified examples: {name}\n");
            for (cat, pos, _) in &cats {
                if let Some(m) = r.miss.get(cat) {
                    let kind = if *pos { "FN" } else { "FP" };
                    for (t, why) in m.iter().take(5) {
                        println!("- {kind} [{cat}] `{}` {}", short(t), why);
                    }
                }
            }
        }
    }

    decoder_level(&texts, builtin);
    micro_benchmarks();
}
