use super::checker_type::{Check, Checker};
use crate::checkers::checker_result::CheckResult;
use crate::checkers::english::is_known_word as is_english_word;
use gibberish_or_not::Sensitivity;
use lemmeknow::{Data, Identifier};

/// The LemmeKnow Checker checks if the text matches a known Regex pattern.
/// This is the struct for it.
pub struct LemmeKnow;

/// LemmeKnow patterns rarer than this are ignored.
const MIN_RARITY: f32 = 0.1;

/// LemmeKnow tags whose patterns only check which characters the text uses and how long
/// it is, so they match decoder junk: every 10 to 13 digit number is a "Phone Number",
/// every SHA-1 hash a "Bitly Secret Key" and a "Visual Studio App Center API Token", and
/// digit strings are card numbers and Turkish ID numbers.
/// See <https://github.com/bee-san/Ciphey/issues/1031>.
///
/// Matches with these tags are dropped after matching. That is what
/// `Identifier::exclude_tags` does too, but lemmeknow compares every excluded tag with
/// every pattern's tags on each call, which made each check about 1 µs slower.
const EXCLUDED_TAGS: [&str; 5] = ["Credit Card", "Phone", "Bitly", "Visual Studio", "Turkish"];

/// LemmeKnow patterns that only check the character set and length but share a tag with
/// patterns worth keeping, so they are dropped by name instead. For example the ASIN
/// pattern (`B` and 9 capitals or digits) is tagged "Amazon" like the SNS topic ARN, and
/// matches Caesar shifts such as `BYFFIQILFX`. A match is only dropped if no other
/// pattern matched too.
const EXCLUDED_NAMES: [&str; 10] = [
    "Amazon Standard Identification Number (ASIN)",
    "Bitcoin Cash (BCH) Wallet Address",
    "Litecoin (LTC) Wallet Address",
    "Ripple (XRP) Wallet Address",
    "Dogecoin (DOGE) Wallet Address",
    "Google ReCaptcha API Key",
    // Two letters and then letters and digits: `EA` and 190 or more, `AC` or `AP` and 32,
    // `o-` and 10 to 32. A Vigenère key that happened to start a long Base64-like string
    // with `EA` ended a search as a "Facebook Access Token".
    "Facebook Access Token",
    "Twilio Account SID",
    "Twilio Application SID",
    "Amazon Web Services Organization Identifier",
];

/// LemmeKnow's name for its URL pattern. It also matches anything shaped like a domain,
/// such as `L.bo?>HoPMP` or `flag{...}`, so a URL is only accepted with a scheme or `www.`.
const URL: &str = "Uniform Resource Locator (URL)";

/// Shown for the generic CTF flag pattern; the same name as LemmeKnow's own flag pattern.
const CTF_FLAG: &str = "Capture The Flag (CTF) Flag";

/// Whether `text` is a flag in any CTF's format, such as `picoCTF{...}` or `DUCTF{...}`:
/// `^[A-Za-z][A-Za-z0-9_]{1,19}\{[^{}\n]{1,200}\}$`. LemmeKnow only knows `flag{}`,
/// `ctf{}`, `htb{}` and `thm{}`.
///
/// Written out by hand because the regex crate compiles a bounded repeat of a Unicode
/// class like `[^{}\n]{1,200}` into hundreds of states, which took longer than the rest of
/// a short search.
fn matches_flag_pattern(text: &str) -> bool {
    let Some((prefix, rest)) = text.split_once('{') else {
        return false;
    };
    let Some(contents) = rest.strip_suffix('}') else {
        return false;
    };
    let mut prefix_chars = prefix.chars();
    prefix_chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && (2..=20).contains(&prefix.len())
        && prefix_chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
        && !contents.contains(['{', '}', '\n'])
        && (1..=200).contains(&contents.chars().count())
}

/// Flag prefixes that are a flag word on their own (lower case).
const FLAG_PREFIXES: [&str; 5] = ["htb", "thm", "hackthebox", "tryhackme", "flag"];

/// Whether `text` is shaped like a CTF flag, `prefix{...}`, whatever its prefix.
pub fn is_ctf_flag_shaped(text: &str) -> bool {
    matches_flag_pattern(text.trim())
}

/// Whether `text` is shaped like a CTF flag, `prefix{...}`, and its prefix has a flag word,
/// like `picoCTF{...}`, `HTB{...}` or `flag{...}`. Decoders with few keys check such a
/// candidate first.
pub(crate) fn is_marked_ctf_flag(text: &str) -> bool {
    let text = text.trim();
    matches_flag_pattern(text) && flag_prefix_has_marker(&flag_prefix(text))
}

/// Whether `text` is shaped like a CTF flag but its prefix has no flag word (see
/// `flag_prefix_has_marker`), like `SEKAI{...}`.
///
/// Such a flag can't be told apart from a Caesar shift, Atbash or Vigenère encryption of
/// one (`FRXNV{...}` is ROT13 of `SEKAI{...}`), since those keep a flag's shape. So the
/// input itself, and the output of those ciphers, isn't taken as a flag on its shape
/// alone; a crib (`--regex 'SEKAI\{'`) finds these.
pub fn is_unmarked_ctf_flag(text: &str) -> bool {
    let text = text.trim();
    matches_flag_pattern(text) && !flag_prefix_has_marker(&flag_prefix(text))
}

/// Symbols, besides ASCII letters and digits, that a flag without a flag word in its
/// prefix may contain.
const FLAG_CONTENT_SYMBOLS: &str = "_-!?.@$#&+'";

/// Whether `text` is a CTF flag in any format.
///
/// A Caesar shift or Atbash keeps the shape of a flag, so `synt{guvf_vf_gur_synt}` (ROT13
/// of `flag{this_is_the_flag}`) matches the pattern too. A prefix that is a shift, an
/// Atbash, or a shift of an Atbash of a flag word is taken as an encoded flag and
/// rejected, so the search goes on and the decoder finds the real one.
///
/// Without a flag word in the prefix, the contents may only be letters, digits and
/// [`FLAG_CONTENT_SYMBOLS`]: ROT47 turns letters into braces and other symbols, so its
/// junk often has a flag's shape (`zw{~|~vw|}`).
fn is_ctf_flag(text: &str) -> bool {
    let text = text.trim();
    if !matches_flag_pattern(text) {
        return false;
    }
    let prefix = flag_prefix(text);
    if flag_prefix_has_marker(&prefix) {
        return true;
    }
    let contents = &text[prefix.len() + 1..text.len() - 1];
    if !contents
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || FLAG_CONTENT_SYMBOLS.contains(c))
    {
        return false;
    }
    let atbash: String = prefix.chars().map(|c| map_letter(c, |l| 25 - l)).collect();
    let encoded_marker = [&prefix, &atbash].iter().any(|prefix| {
        (1..26).any(|shift| {
            let rotated: String = prefix
                .chars()
                .map(|c| map_letter(c, |l| (l + shift) % 26))
                .collect();
            flag_prefix_has_marker(&rotated)
        }) || flag_prefix_has_marker(prefix)
    });
    !encoded_marker && flag_contents_are_words(contents)
}

/// Whether a flag's contents read as words once leetspeak is undone, and better than any
/// Caesar shift or Atbash of them: `y0u_f0und_m3` is "you found me", `sp4rkl3s`
/// "sparkles", `w3ll_d0ne!` "well done".
///
/// A flag without a flag word in its prefix needs this: a Caesar shift, Atbash or
/// Vigenère of one keeps its shape but not its words (`QCIYG{u3ja0kc_r0_q3i41}` is a
/// Caesar shift of `SEKAI{y0u_f0und_m3}`; `NZFVD{t0p_a0piy_h3}` another, with two words by
/// chance), and wrong ROT47 and railfence keys make flag-shaped junk out of digits
/// (`wyv{wxwwwyvvyzyvxvy}`). Contents that are random or hex (`SECCON{7e1b9e3a}`) don't
/// pass; a crib (`--regex 'SECCON\{'`) finds those.
fn flag_contents_are_words(contents: &str) -> bool {
    let score = word_letters(contents);
    if score * 2 < letters_in(contents) || !has_long_word(contents) {
        return false;
    }
    let atbash: String = contents
        .chars()
        .map(|c| map_any_letter(c, |l| 25 - l))
        .collect();
    [contents, &atbash].iter().all(|variant| {
        (1..26).all(|shift| {
            let shifted: String = variant
                .chars()
                .map(|c| map_any_letter(c, |l| (l + shift) % 26))
                .collect();
            word_letters(&shifted) <= score
        }) && (*variant == contents || word_letters(variant) <= score)
    })
}

/// The parts of flag contents between `_`, `-`, `.`, `!`, `?` and spaces, except numbers.
fn flag_parts(contents: &str) -> impl Iterator<Item = &str> {
    contents
        .split(['_', '-', '.', '!', '?', ' '])
        .filter(|part| !part.is_empty() && !part.bytes().all(|b| b.is_ascii_digit()))
}

/// The leetspeak reading of `part` that is a word, if any (`1` is `i` or `l`).
fn part_as_word(part: &str) -> Option<String> {
    ['i', 'l']
        .iter()
        .map(|&one| unleet(part, one))
        .find(|word| is_english_word(word))
}

/// How many characters of the parts of `contents` are in parts that are words.
fn word_letters(contents: &str) -> usize {
    flag_parts(contents)
        .filter(|part| part_as_word(part).is_some())
        .map(|part| part.chars().count())
        .sum()
}

/// How many characters the parts of `contents` have.
fn letters_in(contents: &str) -> usize {
    flag_parts(contents).map(|part| part.chars().count()).sum()
}

/// Whether one of the parts of `contents` is a word of three letters or more: short words
/// alone are chance (`spovwuot{my}` came out of a wrong railfence key).
fn has_long_word(contents: &str) -> bool {
    flag_parts(contents)
        .filter_map(part_as_word)
        .any(|word| word.chars().count() >= 3)
}

/// Applies `f` to the alphabet position (0 to 25) of an ASCII letter of either case.
fn map_any_letter(c: char, f: impl Fn(u8) -> u8) -> char {
    match c {
        'a'..='z' => (b'a' + f(c as u8 - b'a')) as char,
        'A'..='Z' => (b'A' + f(c as u8 - b'A')) as char,
        _ => c,
    }
}

/// `part` in lower case with leetspeak digits and symbols turned into the letters they
/// stand for, `1` into `one`.
fn unleet(part: &str, one: char) -> String {
    part.chars()
        .map(|c| match c {
            '0' => 'o',
            '1' => one,
            '3' => 'e',
            '4' | '@' => 'a',
            '5' | '$' => 's',
            '7' => 't',
            '8' => 'b',
            '9' => 'g',
            c => c.to_ascii_lowercase(),
        })
        .collect()
}

/// The lower-cased part of a flag before its `{`.
fn flag_prefix(flag: &str) -> String {
    flag.split('{')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase()
}

/// Whether a lower-case flag prefix has a flag word: it ends in `ctf` (`picoctf`,
/// `ductf`, `ctf2024`) or `flag`, starts with `flag`, or is one of [`FLAG_PREFIXES`].
/// Only whole prefixes and their ends count: `htb` inside `ohtbj00m3` is chance.
fn flag_prefix_has_marker(prefix: &str) -> bool {
    let word = prefix.trim_end_matches(|c: char| c.is_ascii_digit() || c == '_');
    word.ends_with("ctf")
        || word.ends_with("flag")
        || word.starts_with("flag")
        || FLAG_PREFIXES.contains(&word)
}

/// Applies `f` to the alphabet position (0 to 25) of a lower-case ASCII letter.
fn map_letter(c: char, f: impl Fn(u8) -> u8) -> char {
    if c.is_ascii_lowercase() {
        (b'a' + f(c as u8 - b'a')) as char
    } else {
        c
    }
}

impl Check for Checker<LemmeKnow> {
    fn new() -> Self {
        Checker {
            // TODO: Update fields with proper values
            name: "LemmeKnow Checker",
            description: "Uses LemmeKnow to check for regex matches",
            link: "https://swanandx.github.io/lemmeknow-frontend/",
            tags: vec!["lemmeknow", "regex"],
            expected_runtime: 0.01,
            popularity: 1.0,
            lemmeknow_config: Identifier::default().min_rarity(MIN_RARITY),
            sensitivity: Sensitivity::Medium, // Default to Medium sensitivity
            _phantom: std::marker::PhantomData,
        }
    }

    fn check(&self, text: &str) -> CheckResult {
        let description = identify(&self.lemmeknow_config, text);
        CheckResult {
            is_identified: description.is_some(),
            text: text.to_owned(),
            checker_name: self.name,
            checker_description: self.description,
            description: description.unwrap_or_default(),
            link: self.link,
        }
    }

    fn with_sensitivity(mut self, sensitivity: Sensitivity) -> Self {
        self.sensitivity = sensitivity;
        self
    }

    fn get_sensitivity(&self) -> Sensitivity {
        self.sensitivity
    }
}

/// What `identifier` (LemmeKnow) or the CTF flag pattern identify `text` as, if anything.
///
/// Text with control characters other than tabs and line breaks isn't plaintext of any
/// format, and is a fifth of what a search checks (wrong decoders' bytes), so it skips
/// LemmeKnow's hundred-odd regexes.
pub(crate) fn identify(identifier: &Identifier, text: &str) -> Option<String> {
    if has_control_characters(text) {
        return None;
    }
    identifier
        .identify(text)
        .iter()
        .map(|found| &found.data)
        .find(|data| is_trusted_match(data, text))
        .map(format_data_result)
        .or_else(|| is_ctf_flag(text).then(|| CTF_FLAG.to_string()))
}

/// Whether `text` has a control character other than a tab or line break: C0 controls,
/// DEL, or C1 controls (U+0080 to U+009F, which decoders' bytes become as Latin-1).
fn has_control_characters(text: &str) -> bool {
    text.as_bytes()
        .windows(2)
        .any(|pair| pair[0] == 0xC2 && (0x80..0xA0).contains(&pair[1]))
        || text
            .bytes()
            .any(|b| (b < 0x20 && !matches!(b, b'\t' | b'\n' | b'\r')) || b == 0x7F)
}

/// Whether a LemmeKnow match on `text` says something about it, rather than only that it
/// has the right characters and length.
fn is_trusted_match(data: &Data, text: &str) -> bool {
    if EXCLUDED_NAMES.contains(&data.name)
        || data.tags.iter().any(|tag| EXCLUDED_TAGS.contains(tag))
    {
        return false;
    }
    if data.name == URL {
        let text = text.trim_start().to_ascii_lowercase();
        return text.contains("://") || text.starts_with("www.");
    }
    match data.name {
        EC2_INSTANCE_ID => is_ec2_instance_id(text),
        ARN => is_arn(text),
        EMAIL => has_known_tld(text),
        _ => true,
    }
}

/// LemmeKnow's name for EC2 instance IDs. Its pattern, `(?i)^i-[a-z0-9]{8}$` (or 17), takes
/// `I-NHyontTe`; real IDs are `i-` and 8 or 17 lower-case hex digits.
const EC2_INSTANCE_ID: &str = "Amazon Web Services EC2 Instance ID";

/// Whether `text` is an EC2 instance ID: see [`EC2_INSTANCE_ID`].
fn is_ec2_instance_id(text: &str) -> bool {
    text.trim().strip_prefix("i-").is_some_and(|id| {
        matches!(id.len(), 8 | 17) && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    })
}

/// LemmeKnow's name for ARNs. Its pattern is case-insensitive and allows anything between
/// the colons, so decoder junk such as `Arn:?n8A;m:p>oo:...` matches; real ARNs start
/// with `arn:`, a partition and a service in lower case (`arn:aws:sns:...`).
const ARN: &str = "Amazon Resource Name (ARN)";

/// Whether `text` starts like an ARN: see [`ARN`].
fn is_arn(text: &str) -> bool {
    let mut fields = text.trim().split(':');
    let lower_name = |field: Option<&str>| {
        field.is_some_and(|f| {
            f.bytes().next().is_some_and(|b| b.is_ascii_lowercase())
                && f.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
    };
    fields.next() == Some("arn") && lower_name(fields.next()) && lower_name(fields.next())
}

/// LemmeKnow's name for email addresses.
const EMAIL: &str = "Email Address";

/// Top-level domains an email address may end in: the common generic ones and the
/// country codes most used. LemmeKnow takes any, and a Caesar shift of an address is still
/// shaped like one (`uryyb@jbeyq.pbz` is ROT13 of `hello@world.com`), so a shifted address
/// was taken as plaintext and the search stopped at the ciphertext.
const EMAIL_TLDS: [&str; 112] = [
    "ac", "academy", "ae", "agency", "ai", "app", "ar", "art", "asia", "at", "au", "be", "bg",
    "biz", "blog", "br", "by", "ca", "cat", "cc", "ch", "cl", "cloud", "club", "cn", "co", "com",
    "company", "cz", "de", "design", "dev", "digital", "dk", "edu", "ee", "email", "es", "eu",
    "fi", "fm", "fr", "gg", "global", "gov", "gr", "group", "hk", "hr", "hu", "id", "ie", "il",
    "in", "info", "int", "io", "ir", "is", "it", "jobs", "jp", "kr", "life", "link", "live", "lt",
    "lu", "lv", "ly", "mail", "me", "media", "mil", "mobi", "museum", "mx", "my", "name", "net",
    "network", "news", "nl", "no", "nz", "online", "org", "page", "ph", "pk", "pl", "pro", "pt",
    "ro", "rs", "ru", "se", "sg", "sh", "site", "sk", "space", "store", "studio", "tech", "tv",
    "uk", "us", "website", "xyz", "za", "zone",
];

/// Whether the address `text` ends in one of [`EMAIL_TLDS`], or in an IP address in
/// brackets (`john.smith@[123.123.123.123]`).
fn has_known_tld(text: &str) -> bool {
    let text = text.trim();
    if text.ends_with(']') {
        return true;
    }
    let tld = text.rsplit('.').next().unwrap_or_default();
    EMAIL_TLDS
        .binary_search(&tld.to_ascii_lowercase().as_str())
        .is_ok()
}

/// Formats the data result to a string
/// This is used to display the result in the UI
fn format_data_result(input: &Data) -> String {
    input.name.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkers::checker_type::{Check, Checker};
    use gibberish_or_not::Sensitivity;

    fn identify(text: &str) -> Option<String> {
        let result = Checker::<LemmeKnow>::new().check(text);
        result.is_identified.then_some(result.description)
    }

    #[test]
    fn test_url_exact_match() {
        let checker = Checker::<LemmeKnow>::new().with_sensitivity(Sensitivity::Low);
        assert!(checker.check("https://google.com").is_identified);
    }

    #[test]
    fn test_url_with_extra_text_fails() {
        let checker = Checker::<LemmeKnow>::new().with_sensitivity(Sensitivity::Low);
        assert!(
            !checker
                .check("https://google.com and some text")
                .is_identified
        );
    }

    #[test]
    fn test_ip_exact_match() {
        let checker = Checker::<LemmeKnow>::new().with_sensitivity(Sensitivity::Low);
        assert!(checker.check("192.168.1.1").is_identified);
    }

    #[test]
    fn test_ip_with_extra_text_fails() {
        let checker = Checker::<LemmeKnow>::new().with_sensitivity(Sensitivity::Low);
        assert!(!checker.check("IP is 192.168.1.1").is_identified);
    }

    #[test]
    fn test_s3_path() {
        let checker = Checker::<LemmeKnow>::new().with_sensitivity(Sensitivity::Low);
        assert!(checker.check("s3://bucket/path/key").is_identified);
    }

    // Lemmeknow can only match if its an EXACT match
    // So this should fail
    #[test]
    fn test_bitcoin_with_extra_text_fails() {
        let checker = Checker::<LemmeKnow>::new().with_sensitivity(Sensitivity::Low);
        assert!(
            !checker
                .check("BTC address: 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2")
                .is_identified
        );
    }

    #[test]
    fn charset_and_length_patterns_do_not_match() {
        // All from https://github.com/bee-san/Ciphey/issues/1031
        for junk in [
            "736563726574",                               // hex of "secret": "Phone Number"
            "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8",   // SHA-1: "Bitly Secret Key"
            "63697068657920697320736f20636f6f6c212121",   // hex of "ciphey is so cool!!!"
            "BYFFIQILFX",                                 // Caesar shift: "ASIN"
            "38239407528649",                             // "Diners Club Card Number"
            "2544331120942583",                           // "MasterCard Number"
            "10000000146",                                // "Turkish Identification Number"
            "q8Zr1Xk0pLm3Vb7Nc5Tw9Hd2Fg4Js6Ky1Ue8Ri0Oa3", // "Bitcoin Cash Wallet Address"
            "6f2c9b0e8a7d4f1e3c5b9a8d7e6f5a4b3c2d1e0f",   // SHA-1 starting with 6: "ReCaptcha"
        ] {
            assert_eq!(identify(junk), None, "{junk}");
        }
    }

    #[test]
    fn dropping_excluded_tags_after_matching_equals_exclude_tags() {
        let excluding = lemmeknow::Identifier::default()
            .min_rarity(MIN_RARITY)
            .exclude_tags(&EXCLUDED_TAGS.map(String::from));
        let all = lemmeknow::Identifier::default().min_rarity(MIN_RARITY);
        for text in [
            "8888888888",
            "+1 (555) 123-4567",
            "4111111111111111",
            "378282246310005",
            "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8",
            "10000000146",
            "34ABC123",
            "192.168.0.1",
            "https://github.com/bee-san/Ciphey",
            "bee@skerritt.blog",
            "736563726574",
        ] {
            let expected: Vec<&str> = excluding
                .identify(text)
                .iter()
                .map(|m| m.data.name)
                .collect();
            let filtered: Vec<&str> = all
                .identify(text)
                .iter()
                .filter(|m| !m.data.tags.iter().any(|tag| EXCLUDED_TAGS.contains(tag)))
                .map(|m| m.data.name)
                .collect();
            assert_eq!(filtered, expected, "{text}");
        }
    }

    #[test]
    fn urls_need_a_scheme_or_www() {
        assert_eq!(identify("www.google.com").as_deref(), Some(URL));
        assert_eq!(identify("WWW.GOOGLE.COM").as_deref(), Some(URL));
        assert_eq!(
            identify("http://example.com/index.html?q=1").as_deref(),
            Some(URL)
        );
        // Shaped like a domain, but decoder junk
        assert_eq!(
            identify("L.bo?>HoPMPcPM0]tM1p?=-lsctbr_R^rIRSOM^kq=5c"),
            None
        );
        assert_eq!(identify("example.com"), None);
    }

    #[test]
    fn other_patterns_still_match() {
        assert!(identify("bee@skerritt.blog").is_some());
        assert!(identify("192.168.0.1").is_some());
        assert!(identify("arn:aws:sns:us-east-1:123456789012:my-topic").is_some());
        assert_eq!(
            identify("flag{this_is_the_flag}").as_deref(),
            Some(CTF_FLAG),
            "LemmeKnow's own flag pattern"
        );
    }

    #[test]
    fn caesar_shifted_and_atbashed_flags_are_not_flags() {
        // Shifts and Atbash keep a flag's shape. Accepting these stopped the search at the
        // ciphertext instead of letting Caesar or Atbash find the flag.
        for encoded in [
            "synt{guvf_vf_gur_synt}",  // ROT13 of flag{this_is_the_flag}
            "cvpbPGS{o4f3_64_1f_sha}", // ROT13 of picoCTF{...}
            "UGO{f0z3_sy4t_u3e3}",     // ROT13 of HTB{...}
            "GSN{gibs4xpn3_i0xph}",    // ROT13 of THM{...}
            "krxlXGU{y4h3_64_1h_ufm}", // Atbash of picoCTF{...}
            "uozt{gsrh_rh_gsv_uozt}",  // Atbash of flag{...}
            "galf{sedt_dt_seh_galf}",  // a Caesar shift of that Atbash
        ] {
            assert_eq!(identify(encoded), None, "{encoded}");
        }
        // Prefixes without a flag word are kept unless they are an encoded one
        assert_eq!(identify("SEKAI{y0u_f0und_m3}").as_deref(), Some(CTF_FLAG));
        assert_eq!(identify("dice{sp4rkl3s}").as_deref(), Some(CTF_FLAG));
        assert_eq!(identify("ENO{w3ll_d0ne!}").as_deref(), Some(CTF_FLAG));
        // ...as long as the contents look like a flag's. These are ROT47 junk from the
        // search.
        for junk in [
            "zw{~|~vw|}",
            "U9SB{4@<5eN}",
            "Om{HUkOiVJPgvtmo4]^j4onpX\\k95}",
        ] {
            assert_eq!(identify(junk), None, "{junk}");
        }
        // A flag word makes any contents fine
        assert_eq!(identify("flag{~|~}").as_deref(), Some(CTF_FLAG));
    }

    #[test]
    fn shape_only_matches_need_the_real_format() {
        // Matched LemmeKnow's patterns, but are decoder junk or Caesar shifts
        for junk in [
            "I-NHyontTe",                                                       // EC2 ID
            "Arn:?n8A;m:p>oo:o;n?8:<9pr<9<=nm8o899@:<:=>>:;=@@8?<or?@9nm:A9?9", // ARN
            "uryyb@jbeyq.pbz",                    // ROT13 of hello@world.com
            "lyl.cwsdr@mywzkxi.ybq",              // a Caesar shift of an email address
            "ACq8Zr1Xk0pLm3Vb7Nc5Tw9Hd2Fg4Js6Ky", // "Twilio Account SID": AC and 32 characters
        ] {
            assert_eq!(identify(junk), None, "{junk}");
        }
        let facebook = format!("EA{}", "AbCd12".repeat(40));
        assert_eq!(
            identify(&facebook),
            None,
            "two letters and 190 letters or digits"
        );
        for (text, name) in [
            ("i-1234567890abcdef0", EC2_INSTANCE_ID),
            ("arn:aws:iam::123456789012:user/bee", ARN),
            ("hello@world.com", EMAIL),
            ("first.last@university.ac.uk", EMAIL),
            ("john.smith@[123.123.123.123]", EMAIL),
        ] {
            assert_eq!(identify(text).as_deref(), Some(name), "{text}");
        }
    }

    #[test]
    fn text_with_control_characters_is_not_a_format() {
        assert_eq!(identify("192.168.0.1\u{1}"), None);
        assert_eq!(identify("flag{a\u{7f}b}"), None);
        assert!(identify("flag{tabs\tare fine}").is_some());
    }

    #[test]
    fn email_tlds_are_sorted() {
        assert!(EMAIL_TLDS.windows(2).all(|pair| pair[0] < pair[1]));
    }

    #[test]
    fn flags_without_a_flag_word_need_words_inside() {
        for flag in [
            "SEKAI{y0u_f0und_m3}",
            "dice{sp4rkl3s}",
            "ENO{w3ll_d0ne!}",
            "DEADFACE{d34d_f4c3}",
            "SECCON{j4p4n3s3_fl4g}",
        ] {
            assert_eq!(identify(flag).as_deref(), Some(CTF_FLAG), "{flag}");
        }
        for junk in [
            "QCIYG{u3ja0kc_r0_q3i41}", // a Caesar shift of SEKAI{y0u_f0und_m3}
            "NZFVD{t0p_a0piy_h3}",     // another, with two words by chance
            "wyv{wxwwwyvvyzyvxvy}",    // wrong ROT47 and railfence keys on digits
            "spovwuot{my}",
            "SECCON{7e1b9e3a}", // hex: can't tell it from a shift of it
        ] {
            assert_eq!(identify(junk), None, "{junk}");
        }
        // A flag word makes any contents fine
        assert_eq!(identify("flag{7e1b9e3a}").as_deref(), Some(CTF_FLAG));
    }

    #[test]
    fn marked_and_unmarked_flags() {
        assert!(is_marked_ctf_flag("picoCTF{b4s3_64_1s_fun}"));
        assert!(is_marked_ctf_flag("flag{x}"));
        assert!(!is_marked_ctf_flag("SEKAI{x}"));
        assert!(!is_marked_ctf_flag("synt{x}"));
        assert!(is_unmarked_ctf_flag("SEKAI{x}"));
        assert!(is_unmarked_ctf_flag("pCb_1uioT{436_sfncFs4_}"));
        assert!(!is_unmarked_ctf_flag("DUCTF{x}"));
        assert!(!is_unmarked_ctf_flag("hello"));
        // A flag word by chance inside a prefix doesn't count
        assert!(is_unmarked_ctf_flag("ohTBJ00m3_ddRN{_wv}"));
        assert!(is_marked_ctf_flag("ctf2024{x}"));
        assert!(is_marked_ctf_flag("TryHackMe{x}"));
    }

    #[test]
    fn flag_pattern_matches_the_regex() {
        let regex = regex::Regex::new(r"^[A-Za-z][A-Za-z0-9_]{1,19}\{[^{}\n]{1,200}\}$").unwrap();
        let mut texts: Vec<String> = [
            "flag{x}",
            "a{b}",
            "ab{}",
            "ab{c}",
            "1b{c}",
            "a-{c}",
            "ab{c}d",
            "ab{c{d}",
            "ab{c}}",
            "ab{\n}",
            "ab{é}",
            "é{a}",
            "abcdefghijklmnopqrst{x}",
            "abcdefghijklmnopqrstu{x}",
            "{x}",
            "ab",
            "",
            "ab{{}",
            "a_{x}",
            "a__{ü😂}",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        texts.push(format!("ab{{{}}}", "x".repeat(200)));
        texts.push(format!("ab{{{}}}", "x".repeat(201)));
        texts.push(format!("ab{{{}}}", "é".repeat(200)));
        let alphabet: Vec<char> = "aZ09_{}-\n é".chars().collect();
        let mut seed: u64 = 0x1031;
        for len in 0..40 {
            for _ in 0..50 {
                texts.push(
                    (0..len)
                        .map(|_| {
                            seed ^= seed << 13;
                            seed ^= seed >> 7;
                            seed ^= seed << 17;
                            alphabet[(seed % alphabet.len() as u64) as usize]
                        })
                        .collect(),
                );
            }
        }
        for text in &texts {
            assert_eq!(matches_flag_pattern(text), regex.is_match(text), "{text:?}");
        }
    }

    #[test]
    fn flags_in_any_ctf_format() {
        for flag in [
            "picoCTF{b4s3_64_1s_fun}",
            "DUCTF{d0wn_und3r}",
            "csawctf{n0t_s0_h4rd}",
            "uiuctf{rust_is_great}",
            "picoCTF{the_answer_is_42}\n",
        ] {
            assert_eq!(identify(flag).as_deref(), Some(CTF_FLAG), "{flag:?}");
        }
        for not_a_flag in [
            "{\"key\": \"value\"}",
            "a{b}",
            "int main() { return 0; }",
            "x{a{b}}",
        ] {
            assert_eq!(identify(not_a_flag), None, "{not_a_flag:?}");
        }
    }
}
