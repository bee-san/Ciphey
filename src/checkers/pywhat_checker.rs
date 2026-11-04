use super::checker_type::{Check, Checker};
use crate::checkers::checker_result::CheckResult;
use crate::checkers::english::is_known_word as is_english_word;
use crate::config::{get_config, is_global_config_set, Config};
use gibberish_or_not::Sensitivity;
use once_cell::sync::{Lazy, OnceCell};
use pywhat::{Identifier, Match, CHARSET_ONLY};

/// Regexes rarer than this are never used: they match too much ordinary text (timestamps,
/// `key:value` pairs). The `pywhat_min_rarity` setting can only raise it.
pub const MIN_RARITY: f64 = 0.1;

/// pyWhat's regexes as the checker uses them: those of rarity [`MIN_RARITY`] to 1, without
/// those tagged "Charset Only", narrowed by the `pywhat_*` settings of a config (see
/// [`Config::pywhat_min_rarity`] and [`identifiers_for`]).
///
/// pyWhat tags a regex "Charset Only" when it only checks which characters a text has and
/// how long it is: more than 1 in 1,000 random strings of a common alphabet and the right
/// length match it, after its checksum. Decoder junk matches those all the time: every 10
/// to 13 digit number was a "Phone Number" to LemmeKnow, every SHA-1 hash a "Bitly Secret
/// Key" (<https://github.com/bee-san/Ciphey/issues/1031>). The checksum validators
/// (Luhn for card numbers, Base58Check and CashAddr for wallets) are part of pyWhat's
/// default processors.
#[derive(Clone, Debug)]
pub struct Identifiers {
    /// Every regex the settings select but the URL regex.
    others: Identifier,
    /// The URL regex, if the settings select it. It is by far the slowest of pyWhat's
    /// regexes (18 KB, run by fancy-regex), and the checker only takes a URL with a scheme
    /// or `www.` (see [`URL`]), so it only runs on text that has one: what it matches
    /// otherwise would be rejected anyway.
    url: Option<Identifier>,
}

impl Identifiers {
    /// The matches of the regexes whose match is the whole of `text`, in pyWhat's
    /// database order, as one identifier with both parts would give them.
    pub fn identify_whole(&self, text: &str) -> Vec<Match> {
        let mut found = self.others.identify_whole(text);
        if let Some(url) = self.url.as_ref().filter(|_| has_scheme_or_www(text)) {
            let urls = url.identify_whole(text);
            if !urls.is_empty() {
                found.extend(urls);
                found.sort_by_key(|found| found.regex.index);
            }
        }
        found
    }

    /// Whether the settings select pyWhat's regex called `name` (any name that isn't one of
    /// pyWhat's is selected).
    fn uses(&self, name: &str) -> bool {
        if name == URL {
            return self.url.is_some();
        }
        pywhat::regexes()
            .iter()
            .find(|entry| entry.name == name)
            .is_none_or(|entry| self.others.filter().contains(entry))
    }

    /// Compiles every regex now, see [`warm_up`].
    fn warm_up(&self) {
        self.others.warm_up();
        if let Some(url) = &self.url {
            url.warm_up();
        }
    }
}

/// [`Identifiers`] for the `pywhat_*` settings of `config`.
pub fn identifiers_for(config: &Config) -> Identifiers {
    let min = f64::from(config.pywhat_min_rarity).max(MIN_RARITY);
    // 0 was the default of `lemmeknow_max_rarity` before pyWhat, and selects nothing
    let max = match f64::from(config.pywhat_max_rarity) {
        max if max <= 0.0 => 1.0,
        max => max,
    };
    let mut all = Identifier::default()
        .min_rarity(min)
        .max_rarity(max)
        .exclude_tags(&[CHARSET_ONLY]);
    if !config.pywhat_tags.is_empty() {
        all = all.include_tags(&config.pywhat_tags);
    }
    if !config.pywhat_exclude_tags.is_empty() {
        all = all.exclude_tags(&config.pywhat_exclude_tags);
    }
    let url_entry = pywhat::regexes().iter().find(|entry| entry.name == URL);
    let url = url_entry
        .filter(|entry| all.filter().contains(entry))
        .map(|_| Identifier::default().min_rarity(0.0).include_tags(&[URL]));
    Identifiers {
        others: all.exclude_tags(&[URL]),
        url,
    }
}

/// The [`Identifiers`] for the global config, see [`identifiers_for`]. Until the global
/// config is set (a library caller that never sets one), they are those of the default
/// config; once it is set, they are built from it on first use.
pub(crate) fn identifiers() -> &'static Identifiers {
    static CONFIGURED: OnceCell<Identifiers> = OnceCell::new();
    static DEFAULT: Lazy<Identifiers> = Lazy::new(|| identifiers_for(&Config::default()));
    if is_global_config_set() {
        CONFIGURED.get_or_init(|| identifiers_for(get_config()))
    } else {
        &DEFAULT
    }
}

/// Whether `text` starts with `www.` or has `://` in it, as a URL needs to (see [`URL`]).
fn has_scheme_or_www(text: &str) -> bool {
    let text = text.trim_start();
    text.contains("://")
        || text
            .get(..4)
            .is_some_and(|start| start.eq_ignore_ascii_case("www."))
}

/// Starts compiling pyWhat's regexes on the rayon pool and returns at once.
///
/// pyWhat compiles a regex the first time a check needs it, so the first checks in a
/// process would compile them one after another: tens of milliseconds, most of a
/// `ciphey` run on a new input. A check that needs a regex that isn't compiled yet
/// compiles it itself, as before: this only changes when and on which thread the regexes
/// are compiled, not what is matched.
///
/// WebAssembly has no other thread to compile them on, so there this does nothing and
/// each regex is compiled when a check first needs it.
pub fn warm_up() {
    #[cfg(not(target_family = "wasm"))]
    {
        static STARTED: std::sync::Once = std::sync::Once::new();
        STARTED.call_once(|| rayon::spawn(|| identifiers().warm_up()));
    }
}

/// The pyWhat Checker checks if the text is, as a whole, a format pyWhat knows (an IP
/// address, an API key, a CTF flag, ...). This is the struct for it.
pub struct PyWhat;

/// pyWhat regexes whose matches aren't plaintext for Ciphey, by name. A match is only
/// dropped if no other regex matched too.
const EXCLUDED_NAMES: [&str; 4] = [
    // Ciphey's JWT decoder decodes a token: its payload is the plaintext, not the token
    "JSON Web Token (JWT)",
    // `6L` and 38 letters, digits, `-` or `_`. Wrong decoders on a SHA-1 hash (40 hex
    // digits) make strings of that length all the time, and one in 4,000 starts with `6L`:
    // `6L85I67MIB85M476LBRI5E947559OCRL5I4O6CML` (atbash, rot47 and keyboard shift of one)
    // ended a search as a "Google ReCaptcha API Key".
    "Google ReCaptcha API Key",
    // `EA` and 190 or more letters and digits. pyWhat's validator wants a lower-case
    // letter, an upper-case letter and a digit, which Base64 has, and so has a Vigenère
    // decryption of it: a wrong key that happened to start one with `EA` ended a search as
    // a "Facebook Access Token".
    "Facebook Access Token",
    // `o-` and 10 to 32 lower-case letters and digits
    "Amazon Web Services Organization Identifier",
];

/// pyWhat's name for its URL regex. It also matches anything shaped like a domain, such as
/// `example.com` or a Caesar shift of one, so a URL is only accepted with a scheme or
/// `www.`.
const URL: &str = "Uniform Resource Locator (URL)";

/// Shown for the generic CTF flag pattern; the same name as pyWhat's own flag regex.
const CTF_FLAG: &str = "Capture The Flag (CTF) Flag";

/// Whether `text` is a flag in any CTF's format, such as `picoCTF{...}` or `DUCTF{...}`:
/// `^[A-Za-z][A-Za-z0-9_]{1,19}\{[^{}\n]{1,200}\}$`. pyWhat only knows `flag{}`,
/// `ctf{}`, `ctfa{}`, `htb{}`, `hackthebox{}`, `thm{}` and `tryhackme{}`.
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

impl Check for Checker<PyWhat> {
    fn new() -> Self {
        Checker {
            name: "pyWhat Checker",
            description: "Uses pyWhat to identify known formats and CTF flags",
            link: "https://github.com/bee-san/pyWhat",
            tags: vec!["pywhat", "regex"],
            expected_runtime: 0.01,
            popularity: 1.0,
            sensitivity: Sensitivity::Medium, // Default to Medium sensitivity
            _phantom: std::marker::PhantomData,
        }
    }

    fn check(&self, text: &str) -> CheckResult {
        let description = identify(identifiers(), text);
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

/// What pyWhat's `identifiers` or the CTF flag pattern identify `text` as, if anything:
/// the name of the first regex whose match is the whole of `text` and says something about
/// it (see [`is_accepted_match`]).
///
/// Text with control characters other than tabs and line breaks isn't plaintext of any
/// format, and is a fifth of what a search checks (wrong decoders' bytes), so it skips
/// pyWhat's regexes.
pub(crate) fn identify(identifiers: &Identifiers, text: &str) -> Option<String> {
    if has_control_characters(text) {
        return None;
    }
    first_accepted_match(identifiers, text)
        .map(|found| found.regex.name.clone())
        .or_else(|| (is_ctf_flag(text) && identifiers.uses(CTF_FLAG)).then(|| CTF_FLAG.to_string()))
        .or_else(|| identify_idn(text).filter(|name| identifiers.uses(name)))
}

/// The first match of `identifiers` that is the whole of `text` and that
/// [`is_accepted_match`] keeps. The checker's own rules report what they find under the
/// name of a pyWhat regex (the generic CTF flag pattern as "Capture The Flag (CTF) Flag",
/// an internationalised address as "Email Address"), so a `pywhat_*` setting that leaves
/// that regex out (`pywhat_exclude_tags = ["CTF Flag"]`, say) leaves out the rule too.
pub(crate) fn first_accepted_match(identifiers: &Identifiers, text: &str) -> Option<Match> {
    identifiers
        .identify_whole(text)
        .into_iter()
        .find(|found| is_accepted_match(found, text))
}

/// Whether `text` has a control character other than a tab or line break: C0 controls,
/// DEL, or C1 controls (U+0080 to U+009F, which decoders' bytes become as Latin-1).
pub(crate) fn has_control_characters(text: &str) -> bool {
    text.as_bytes()
        .windows(2)
        .any(|pair| pair[0] == 0xC2 && (0x80..0xA0).contains(&pair[1]))
        || text
            .bytes()
            .any(|b| (b < 0x20 && !matches!(b, b'\t' | b'\n' | b'\r')) || b == 0x7F)
}

/// Whether a pyWhat match on `text` says something about it for Ciphey. "Charset Only"
/// regexes are left out already (see [`Identifiers`]); these are the
/// rules on top:
///
/// * [`EXCLUDED_NAMES`];
/// * a URL needs a scheme or `www.` (see [`URL`]);
/// * a CTF flag has one pair of braces: pyWhat's `(?i)^(thm\{.*\})$` takes junk with more
///   braces inside, like `THM{UyLgUqMJU}LjUkM^U}` from a chain of wrong decoders;
/// * an email address needs a known top-level domain (see [`EMAIL_TLDS`]);
/// * an IPv6 address must be in a range that is assigned (see [`is_assigned_ipv6`]).
fn is_accepted_match(found: &Match, text: &str) -> bool {
    let name = found.regex.name.as_str();
    if EXCLUDED_NAMES.contains(&name) {
        return false;
    }
    if name == URL {
        return has_scheme_or_www(text);
    }
    if found.tags.iter().any(|tag| tag == "CTF Flag") {
        return matches_flag_pattern(text.trim());
    }
    match name {
        EMAIL => has_known_tld(text),
        IPV6 => is_assigned_ipv6(text),
        _ => true,
    }
}

/// pyWhat's name for IPv6 addresses.
const IPV6: &str = "Internet Protocol (IP) Address Version 6";

/// Whether the IPv6 address `text` (which pyWhat's regex matched) is in a range IANA has
/// assigned: global unicast (`2000::/3`, the first group `2000` to `3fff`), unique local
/// (`fc00::/7`), link-local (`fe80::/10`), multicast (`ff00::/8`), NAT64 (`64:ff9b::`), or
/// an address starting with `::` (`::1`, `::ffff:192.0.2.1`). pyWhat takes any groups of
/// hex digits with colons, so decoder junk such as `DB:F::E9` and `1:6189::7823`, and a
/// reversed address (`4337:0730:e2a8:...`), were IPv6 addresses to it. A port or a zone
/// after the address doesn't change its first group.
fn is_assigned_ipv6(text: &str) -> bool {
    let address = text.trim().trim_start_matches('[');
    if address.starts_with("::") {
        return true;
    }
    let Some(first) = address.split(':').next() else {
        return false;
    };
    if first.eq_ignore_ascii_case("64") {
        return address
            .get(3..)
            .is_some_and(|rest| rest.to_ascii_lowercase().starts_with("ff9b:"));
    }
    match u16::from_str_radix(first, 16) {
        Ok(group) => {
            (0x2000..=0x3fff).contains(&group)
                || (0xfc00..=0xfdff).contains(&group)
                || (0xfe80..=0xfebf).contains(&group)
                || group >= 0xff00
        }
        Err(_) => false,
    }
}

/// pyWhat's name for email addresses.
const EMAIL: &str = "Email Address";

/// Top-level domains an email address may end in: the common generic ones and the
/// country codes most used. pyWhat takes any, and a Caesar shift of an address is still
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

/// pyWhat's name for its phone number regex.
const PHONE_NUMBER: &str = "Phone Number";

/// Whether `keys`, digits pressed on a telephone keypad, are a phone number to pyWhat once
/// a `+` is put in front: 10 to 15 digits, not starting with 0. pyWhat's phone number
/// regex wants a `+` and a country code, which a keypad can't dial; without it, every run
/// of digits in decoder junk would be a phone number. The DTMF decoder uses this for the
/// number dialled.
pub(crate) fn is_phone_number(keys: &str) -> bool {
    static PHONE: Lazy<Identifier> = Lazy::new(|| {
        Identifier::default()
            .min_rarity(0.0)
            .include_tags(&[PHONE_NUMBER])
    });
    !keys.is_empty()
        && keys.bytes().all(|b| b.is_ascii_digit())
        && PHONE
            .identify_whole(&format!("+{keys}"))
            .iter()
            .any(|found| found.regex.name == PHONE_NUMBER)
}

/// Shown for an internationalised domain name such as `bücher.example.com`.
const IDN: &str = "Internationalized Domain Name (IDN)";

/// What `text` is if it is a domain name or email address with a non-ASCII letter in it,
/// such as `hello.müller.example.com` or `müller@example.com`: what the Punycode decoder
/// turns `xn--` labels into. pyWhat's email regex is ASCII-only, and its URL regex wants a
/// scheme here (see [`URL`]). Like an email address,
/// the domain has to end in one of [`EMAIL_TLDS`], which a Caesar shift of it doesn't.
/// ASCII domains without a scheme aren't URLs (see [`URL`]), so these need a non-ASCII
/// letter too.
fn identify_idn(text: &str) -> Option<String> {
    let text = text.trim();
    if text.is_ascii() {
        return None;
    }
    let (local, domain) = match text.split_once('@') {
        Some((local, domain)) => (Some(local), domain),
        None => (None, text),
    };
    if let Some(local) = local {
        let is_local_char = |c: char| c.is_alphanumeric() || "._%+-".contains(c);
        if local.is_empty() || local.len() > 64 || !local.chars().all(is_local_char) {
            return None;
        }
    }
    let labels: Vec<&str> = domain.split('.').collect();
    let is_label = |label: &&str| {
        (1..=63).contains(&label.chars().count())
            && label.chars().all(|c| {
                c.is_ascii_alphanumeric() || c == '-' || (!c.is_ascii() && c.is_alphabetic())
            })
            && !label.starts_with('-')
            && !label.ends_with('-')
    };
    let is_domain = labels.len() >= 2 && labels.iter().all(is_label) && has_known_tld(domain);
    is_domain.then(|| if local.is_some() { EMAIL } else { IDN }.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkers::checker_type::{Check, Checker};
    use gibberish_or_not::Sensitivity;

    fn identify(text: &str) -> Option<String> {
        let result = Checker::<PyWhat>::new().check(text);
        result.is_identified.then_some(result.description)
    }

    #[test]
    fn test_url_exact_match() {
        let checker = Checker::<PyWhat>::new().with_sensitivity(Sensitivity::Low);
        assert!(checker.check("https://google.com").is_identified);
    }

    #[test]
    fn test_url_with_extra_text_fails() {
        let checker = Checker::<PyWhat>::new().with_sensitivity(Sensitivity::Low);
        assert!(
            !checker
                .check("https://google.com and some text")
                .is_identified
        );
    }

    #[test]
    fn test_ip_exact_match() {
        let checker = Checker::<PyWhat>::new().with_sensitivity(Sensitivity::Low);
        assert!(checker.check("192.168.1.1").is_identified);
    }

    #[test]
    fn test_ip_with_extra_text_fails() {
        let checker = Checker::<PyWhat>::new().with_sensitivity(Sensitivity::Low);
        assert!(!checker.check("IP is 192.168.1.1").is_identified);
    }

    #[test]
    fn test_s3_path() {
        let checker = Checker::<PyWhat>::new().with_sensitivity(Sensitivity::Low);
        assert!(checker.check("s3://bucket/path/key").is_identified);
    }

    // The whole text has to be the match, so this should fail
    #[test]
    fn test_bitcoin_with_extra_text_fails() {
        let checker = Checker::<PyWhat>::new().with_sensitivity(Sensitivity::Low);
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
            "4111111111111111",                           // passes Luhn, but Charset Only
            "8888888888",                                 // ten digits: no + for pyWhat
        ] {
            assert_eq!(identify(junk), None, "{junk}");
        }
    }

    #[test]
    fn charset_only_regexes_are_left_out_of_the_identifier() {
        // Matched by pyWhat, but only by their characters and length
        let all = Identifier::default().min_rarity(MIN_RARITY);
        for text in [
            "4111111111111111",
            "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8",
            "BYFFIQILFX",
            "10000000146",
        ] {
            let found = all.identify_whole(text);
            assert!(!found.is_empty(), "pyWhat should match {text}");
            assert!(found.iter().all(|m| m.regex.charset_only()), "{text}");
            assert!(identifiers().identify_whole(text).is_empty(), "{text}");
        }
        // Checksums are checked: a card number failing Luhn and a Bitcoin Cash address with a
        // wrong checksum aren't matched at all
        for text in [
            "4111111111111112",
            "qzlg6uvceehgzgtz6phmvy8gtdqyt6vf359at4n3lr",
        ] {
            assert!(all.identify_whole(text).is_empty(), "{text}");
        }
    }

    #[test]
    fn formats_lemmeknow_did_not_have() {
        // LemmeKnow 0.8 dropped the regexes the regex crate can't compile
        for (text, name) in [
            ("2001:db8::1", "Internet Protocol (IP) Address Version 6"),
            (
                "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
                "Bitcoin (₿) Wallet Address",
            ),
            ("AKIAIOSFODNN7EXAMPLE", "Amazon Web Services Access Key"),
        ] {
            assert_eq!(identify(text).as_deref(), Some(name), "{text}");
        }
    }

    #[test]
    fn ipv6_addresses_must_be_in_an_assigned_range() {
        for address in [
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            "2001:db8::1",
            "fe80::1ff:fe23:4567:890a",
            "fd12:3456:789a::1",
            "ff02::1",
            "::1",
            "::ffff:192.0.2.1",
            "64:ff9b::192.0.2.33",
            "2a03:2880:f12f:83:face:b00c::25de",
        ] {
            assert_eq!(identify(address).as_deref(), Some(IPV6), "{address}");
        }
        // Junk from searches, and a reversed address
        for junk in [
            "DB:F::E9",
            "1:6189::7823",
            "4337:0730:e2a8:0000:0000:3a58:8bd0:1002",
            "64:abcd::1",
        ] {
            assert_eq!(identify(junk), None, "{junk}");
        }
        assert!(is_assigned_ipv6("[2001:db8::1]"));
        assert!(!is_assigned_ipv6(""));
    }

    #[test]
    fn recaptcha_keys_are_not_plaintext() {
        // pyWhat's regex takes it; decoder junk of SHA-1 hashes is shaped like it
        let junk = "6L85I67MIB85M476LBRI5E947559OCRL5I4O6CML";
        assert!(Identifier::default()
            .identify_whole(junk)
            .iter()
            .any(|m| m.regex.name == "Google ReCaptcha API Key"));
        assert_eq!(identify(junk), None);
    }

    #[test]
    fn jwts_are_left_to_the_jwt_decoder() {
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        assert!(identifiers()
            .identify_whole(jwt)
            .iter()
            .any(|m| m.regex.name == "JSON Web Token (JWT)"));
        assert_eq!(identify(jwt), None);
    }

    #[test]
    fn the_url_regex_only_runs_on_text_with_a_scheme_or_www() {
        // The same matches, in the same order, as one identifier with every regex
        let one = Identifier::default()
            .min_rarity(MIN_RARITY)
            .exclude_tags(&[pywhat::CHARSET_ONLY]);
        let split = identifiers_for(&Config::default());
        let webhook = discord_webhook();
        for text in [
            "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
            webhook.as_str(),
            "http://10.10.10.5/secret/flag.txt",
            "s3://bucket/path/key",
            "www.google.com",
            "WWW.GOOGLE.COM",
            "192.168.0.1",
            "bee@skerritt.blog",
        ] {
            let names = |found: Vec<Match>| -> Vec<String> {
                found.into_iter().map(|m| m.regex.name.clone()).collect()
            };
            assert_eq!(
                names(split.identify_whole(text)),
                names(one.identify_whole(text)),
                "{text}"
            );
        }
        // Without a scheme or `www.` the URL regex isn't run: the checker wouldn't take
        // its match
        assert!(one
            .identify_whole("example.com")
            .iter()
            .any(|m| m.regex.name == URL));
        assert!(split.identify_whole("example.com").is_empty());
        assert!(has_scheme_or_www("  https://x.org") && has_scheme_or_www("Www.x.org"));
        assert!(!has_scheme_or_www("example.com") && !has_scheme_or_www("ww"));
        // Settings that leave the URL regex out leave it out of both
        let no_urls = identifiers_for(&Config {
            pywhat_exclude_tags: vec!["URL".to_string()],
            ..Config::default()
        });
        assert!(no_urls.url.is_none());
        assert_eq!(super::identify(&no_urls, "https://google.com"), None);
    }

    #[test]
    fn settings_narrow_the_identifier() {
        let mut config = Config::default();
        assert!(super::identify(&identifiers_for(&config), "192.168.0.1").is_some());

        // The defaults of LemmeKnow's settings, still in older config files, change nothing
        config.pywhat_min_rarity = 0.0;
        config.pywhat_max_rarity = 0.0;
        let old_defaults = identifiers_for(&config);
        for text in ["192.168.0.1", "flag{x}", "bee@skerritt.blog"] {
            assert!(super::identify(&old_defaults, text).is_some(), "{text}");
        }
        // ...and Charset Only regexes stay out whatever the rarity
        assert_eq!(super::identify(&old_defaults, "4111111111111111"), None);

        config.pywhat_min_rarity = 0.8;
        let rare = identifiers_for(&config);
        assert_eq!(super::identify(&rare, "192.168.0.1"), None, "rarity 0.7");
        assert!(super::identify(&rare, "flag{x}").is_some(), "rarity 1");

        let no_flags = identifiers_for(&Config {
            pywhat_exclude_tags: vec!["CTF Flag".to_string()],
            ..Config::default()
        });
        assert_eq!(super::identify(&no_flags, "flag{x}"), None);
        // The generic flag pattern goes too
        assert_eq!(super::identify(&no_flags, "picoCTF{b4s3_64_1s_fun}"), None);
        assert!(super::identify(&no_flags, "192.168.0.1").is_some());

        let only_ip = identifiers_for(&Config {
            pywhat_tags: vec!["IP".to_string()],
            ..Config::default()
        });
        assert!(super::identify(&only_ip, "192.168.0.1").is_some());
        assert_eq!(super::identify(&only_ip, "bee@skerritt.blog"), None);
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
        // Matched LemmeKnow's patterns (pyWhat's EC2 and ARN regexes are strict now), but are
        // decoder junk or Caesar shifts
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
            ("i-1234567890abcdef0", "Amazon Web Services EC2 Instance ID"),
            (
                "arn:aws:iam::123456789012:user/bee",
                "Amazon Resource Name (ARN)",
            ),
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

    #[test]
    fn internationalised_domains_and_addresses_are_identified() {
        // What the Punycode decoder makes of `xn--` labels
        for (text, name) in [
            ("bücher.example.com", IDN),
            ("hello.müller.example.com", IDN),
            ("müller@example.com", EMAIL),
            ("пример.рф.com", IDN),
        ] {
            assert_eq!(identify(text).as_deref(), Some(name), "{text}");
        }
        for junk in [
            // An unknown top-level domain, as a Caesar shift gives
            "oüpure.rknzcyr.pbz",
            // Not a domain
            "loginsbücherse)amplescom",
            "bücher",
            "bücher..com",
            "-bücher.com",
        ] {
            assert_eq!(identify(junk), None, "{junk}");
        }
        // ASCII domains without a scheme still aren't URLs
        assert_eq!(identify("example.com"), None);
    }

    #[test]
    fn lemmeknow_flag_formats_need_one_pair_of_braces() {
        // `(?i)^(thm\{.*\})$` takes this chain of wrong decodings
        assert_eq!(identify("THM{UyLgUqMJU}LjUkM^U}"), None);
        assert!(identify("THM{h4ck_th3_pl4n3t}").is_some());
        assert!(identify("flag{a_b}").is_some());
    }

    #[test]
    fn phone_numbers_are_recognised_but_not_identified() {
        // Keys dialled on a keypad: a number once a + is put in front
        assert!(is_phone_number("18005551234"));
        assert!(is_phone_number("442079460958"));
        for not_a_number in [
            "hello",
            "",
            "123456789",
            "0123456789",
            "+18005551234",
            "1800 555",
        ] {
            assert!(!is_phone_number(not_a_number), "{not_a_number:?}");
        }
        // The checker itself doesn't take digits for a phone number, only an international
        // number written with its +
        assert_eq!(identify("18005551234"), None);
        assert_eq!(identify("+1 800 555 1234").as_deref(), Some(PHONE_NUMBER));
    }

    /// A Discord webhook URL of made-up digits and letters, built at run time: secret scanners
    /// (SonarCloud, GitHub) take a committed one for a leaked webhook.
    fn discord_webhook() -> String {
        let token: String = ('a'..='z').chain('A'..='Z').chain('0'..='9').collect();
        format!(
            "https://{}/api/webhooks/{}/{token}-_abcd",
            "discord.com",
            "1234567890".repeat(2).get(..18).unwrap_or_default()
        )
    }

    /// Texts pyWhat identifies, across rarities and tags, including the slowest regexes to
    /// compile (URL; with [`discord_webhook`], Discord Webhook).
    const IDENTIFIABLE: [&str; 10] = [
        "https://google.com",
        "192.168.1.1",
        "bee@skerritt.blog",
        "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
        "UC11L3JDgDQMyH8iolKkVZ4w",
        "4111111111111111",
        "s3://bucket/path/key",
        "+1 800 555 1234",
        "ghp_0123456789abcdefghijklmnopqrstuvwxyz",
        "arn:aws:iam::123456789012:user/bee",
    ];

    /// The texts in [`IDENTIFIABLE`] that pyWhat matches only with "Charset Only" regexes (a
    /// card number), which the checker leaves out.
    const CHARSET_ONLY: [&str; 1] = ["4111111111111111"];

    #[test]
    fn checks_after_warm_up_match_as_before() {
        warm_up();
        // A second call does nothing
        warm_up();
        let checker = Checker::<PyWhat>::new();
        let webhook = discord_webhook();
        for text in IDENTIFIABLE.into_iter().chain([webhook.as_str()]) {
            assert!(
                !Identifier::default()
                    .min_rarity(MIN_RARITY)
                    .identify_whole(text)
                    .is_empty(),
                "pyWhat should identify {text:?}"
            );
            assert_eq!(
                checker.check(text).is_identified,
                !CHARSET_ONLY.contains(&text),
                "{text:?}"
            );
        }
        assert!(!checker.check("hello my name is bee").is_identified);
    }
}
