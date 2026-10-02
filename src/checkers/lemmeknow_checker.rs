use super::checker_type::{Check, Checker};
use crate::checkers::checker_result::CheckResult;
use gibberish_or_not::Sensitivity;
use lemmeknow::{Data, Identifier};
use once_cell::sync::Lazy;
use regex::Regex;

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
const EXCLUDED_NAMES: [&str; 6] = [
    "Amazon Standard Identification Number (ASIN)",
    "Bitcoin Cash (BCH) Wallet Address",
    "Litecoin (LTC) Wallet Address",
    "Ripple (XRP) Wallet Address",
    "Dogecoin (DOGE) Wallet Address",
    "Google ReCaptcha API Key",
];

/// LemmeKnow's name for its URL pattern. It also matches anything shaped like a domain,
/// such as `L.bo?>HoPMP` or `flag{...}`, so a URL is only accepted with a scheme or `www.`.
const URL: &str = "Uniform Resource Locator (URL)";

/// Shown for the generic CTF flag pattern; the same name as LemmeKnow's own flag pattern.
const CTF_FLAG: &str = "Capture The Flag (CTF) Flag";

/// A flag in any CTF's format, such as `picoCTF{...}` or `DUCTF{...}`. LemmeKnow only
/// knows `flag{}`, `ctf{}`, `htb{}` and `thm{}`.
static CTF_FLAG_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[A-Za-z][A-Za-z0-9_]{1,19}\{[^{}\n]{1,200}\}$").expect("valid flag regex")
});

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
        let matches = self.lemmeknow_config.identify(text);
        let description = matches
            .iter()
            .map(|found| &found.data)
            .find(|data| is_trusted_match(data, text))
            .map(format_data_result)
            .or_else(|| {
                CTF_FLAG_PATTERN
                    .is_match(text.trim())
                    .then(|| CTF_FLAG.to_string())
            });

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
    true
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
