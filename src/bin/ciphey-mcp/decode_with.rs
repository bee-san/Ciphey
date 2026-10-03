//! The `list_decoders` and `decode_with` tools: list the decoders, and run one of them,
//! chosen by name, with [`ciphey::list_decoders`] and [`ciphey::decode_with`].

use ciphey::{Candidate, DecodeOptions, Decoded};
use rmcp::schemars;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

use crate::detect::DetectionOutput;
use crate::server::{check_length, check_regex, MAX_INPUT_CHARS, MAX_REGEX_CHARS};

/// Longest `decoder` that `decode_with` accepts, in characters. The longest name is far
/// shorter.
pub const MAX_DECODER_NAME_CHARS: usize = 100;
/// Most candidates a `decode_with` result lists. The ROT47 cracker returns the most, 93.
pub const MAX_CANDIDATES: usize = 100;
/// Most characters of candidate text in a `decode_with` result, all candidates together, as
/// they are written in JSON (see [`json_chars`]). Without a limit, cracking ROT47 on 65,536
/// characters would return 6 million.
pub const MAX_OUTPUT_CHARS: usize = 65_536;

/// Result of the `list_decoders` tool.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DecoderList {
    /// Every decoder ciphey has, sorted by `id`.
    pub decoders: Vec<DecoderInfo>,
}

/// A decoder ciphey can apply.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DecoderInfo {
    /// What to pass to `decode_with` as `decoder`, such as `base64` or `caesar`.
    pub id: String,
    /// The decoder's name, as `decode` paths and `decode_with` results show it, such as
    /// `Base64` or `caesar`. `decode_with` accepts it too.
    pub name: String,
    /// Other names `decode_with` accepts, such as `b64` or `rot13`.
    pub aliases: Vec<String>,
    /// What the decoder handles.
    pub description: String,
    /// Where to read more.
    pub link: String,
    /// Categories such as `base`, `substitution`, `classic` or `decoder`.
    pub tags: Vec<String>,
    /// The key `decode_with` can decrypt with and how to write it, or null if the decoder
    /// takes no key. Without a key, ciphers are cracked and encodings decoded.
    pub key_format: Option<String>,
}

impl DecoderList {
    /// Every decoder the library can run on its own.
    pub fn all() -> Self {
        Self {
            decoders: ciphey::list_decoders()
                .iter()
                .map(DecoderInfo::from)
                .collect(),
        }
    }
}

impl From<&ciphey::DecoderInfo> for DecoderInfo {
    fn from(info: &ciphey::DecoderInfo) -> Self {
        Self {
            id: info.function.to_string(),
            name: info.name.to_string(),
            aliases: info.aliases.iter().map(|alias| alias.to_string()).collect(),
            description: info.description.to_string(),
            link: info.link.to_string(),
            tags: info.tags.iter().map(|tag| tag.to_string()).collect(),
            key_format: info.key_format.map(str::to_string),
        }
    }
}

/// Arguments of the `decode_with` tool.
#[derive(Debug, Default, Deserialize, schemars::JsonSchema)]
pub struct DecodeWithParams {
    /// The decoder or cipher to run: an `id` from `list_decoders`, or its name or an alias,
    /// in any case, such as `base64`, `hexadecimal`, `morse`, `caesar`, `rot13`, `vigenere`,
    /// `xor_single_byte` or `railfence`.
    #[schemars(length(min = 1, max = MAX_DECODER_NAME_CHARS))]
    pub decoder: String,
    /// The text to decode, decrypt or crack (at most 65536 characters).
    #[schemars(length(min = 1, max = MAX_INPUT_CHARS))]
    pub text: String,
    /// Decrypt with this key instead of cracking (at most 65536 characters). Only for
    /// decoders whose `key_format` in `list_decoders` isn't null, written as it says: `13`
    /// for caesar, `LEMON` for vigenere, `a=5, b=8` for affine, `rails=3, offset=1` for
    /// railfence, `0x58` for xor_single_byte. Leave it out to crack the cipher (every key is
    /// tried) or to decode an encoding.
    #[serde(default, deserialize_with = "string_or_number")]
    #[schemars(with = "Option<String>", length(max = MAX_INPUT_CHARS))]
    pub key: Option<String>,
    /// A regex or crib, such as a flag format like `flag\{` (at most 1000 characters). When
    /// set, only decodings that match it pass the plaintext check, which helps crack a cipher
    /// whose plaintext isn't English.
    #[schemars(length(max = MAX_REGEX_CHARS))]
    pub regex: Option<String>,
}

/// Reads an optional key given as a string or, as models often send a Caesar shift, as a
/// number (`13`).
fn string_or_number<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    match Option::<Value>::deserialize(deserializer)? {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(key)) => Ok(Some(key)),
        Some(Value::Number(key)) => Ok(Some(key.to_string())),
        Some(other) => Err(serde::de::Error::custom(format!(
            "`key` must be a string, such as \"13\" or \"LEMON\", not {other}"
        ))),
    }
}

impl DecodeWithParams {
    /// Checks the input limits, finds the decoder and checks that it takes the key, if there
    /// is one. An `Err` tells the caller what to fix.
    pub fn into_request(self) -> Result<DecodeWithRequest, String> {
        let name = self.decoder.trim();
        if name.is_empty() {
            return Err(format!(
                "`decoder` is empty: pass the id of a decoder, one of {}",
                decoder_ids(|_| true)
            ));
        }
        check_length("decoder", name, MAX_DECODER_NAME_CHARS)?;
        let Some(info) = ciphey::decoder_info(name) else {
            return Err(format!(
                "no decoder is called {name:?}. Pass one of these ids, or a name or alias from \
                 `list_decoders`: {}",
                decoder_ids(|_| true)
            ));
        };
        if self.text.is_empty() {
            return Err("`text` is empty: pass the text to decode".to_string());
        }
        check_length("text", &self.text, MAX_INPUT_CHARS)?;
        // Clients often send "" for an optional argument they don't use.
        let key = self.key.filter(|key| !key.is_empty());
        if let Some(key) = &key {
            if !info.accepts_key() {
                return Err(format!(
                    "{} doesn't take a key: leave `key` out to decode or crack the text. These \
                     decoders take one: {}",
                    info.name,
                    decoder_ids(ciphey::DecoderInfo::accepts_key)
                ));
            }
            check_length("key", key, MAX_INPUT_CHARS)?;
        }
        Ok(DecodeWithRequest {
            decoder: info.function.to_string(),
            text: self.text,
            key,
            regex: check_regex(self.regex)?,
        })
    }
}

/// The ids of the decoders `wanted` picks, for error messages.
fn decoder_ids(wanted: impl Fn(&ciphey::DecoderInfo) -> bool) -> String {
    let ids: Vec<&str> = ciphey::list_decoders()
        .iter()
        .filter(|info| wanted(info))
        .map(|info| info.function)
        .collect();
    ids.join(", ")
}

/// A validated `decode_with` call, sent from the server to a worker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecodeWithRequest {
    /// The decoder's id, as [`ciphey::decode_with`] takes it.
    pub decoder: String,
    /// The text to decode.
    pub text: String,
    /// Decrypt with this key instead of cracking.
    pub key: Option<String>,
    /// Only accept plaintext that matches this regex. The worker puts it in the library's
    /// config, which the decoders' checks follow.
    pub regex: Option<String>,
}

/// Runs the decoder `request` asks for. Called in a worker, which has put `request.regex`
/// in the library's config.
pub fn run(request: &DecodeWithRequest) -> Result<DecodeWithOutput, String> {
    let options = match &request.key {
        Some(key) => DecodeOptions::with_key(key.clone()),
        None => DecodeOptions::default(),
    };
    ciphey::decode_with(&request.decoder, &request.text, &options)
        .map(DecodeWithOutput::from_decoded)
        .map_err(|error| error.to_string())
}

/// How a `decode_with` call ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DecodeWithStatus {
    /// A candidate passed the plaintext check. It comes first.
    PlaintextFound,
    /// The decoder gave candidates, but none passed the plaintext check: judge them
    /// yourself.
    NoPlaintext,
    /// The decoder gave nothing, usually because the text isn't in its format.
    NoCandidates,
}

/// Result of the `decode_with` tool.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DecodeWithOutput {
    /// The decoder that ran, by name, as `list_decoders` and `decode` paths show it.
    pub decoder: String,
    /// `plaintext_found`, `no_plaintext` or `no_candidates`.
    pub status: DecodeWithStatus,
    /// The decodings, the one that passed the plaintext check first. Without a key, a
    /// decoder whose check accepts a decoding returns only that one. Otherwise it returns
    /// what it would hand on to ciphey's search, unfiltered: all 25 Caesar shifts, say, or
    /// the best few keys of crackers with many keys.
    pub candidates: Vec<CandidateOutput>,
    /// How many candidates the decoder returned. More than are listed if some were left out
    /// to keep the result to 100 candidates and 65536 characters of text (as JSON writes it,
    /// so an escaped control character such as `\u0001` counts as 6).
    pub total_candidates: usize,
}

/// One decoding of the text.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CandidateOutput {
    /// The decoded text.
    pub text: String,
    /// Whether `text` was cut short to keep the result to 65536 characters of text.
    pub truncated: bool,
    /// The key that gave this text, such as the Caesar shift `13`, if the decoder reports
    /// one. A few decoders report other details here: the JWT header, the gzip file name,
    /// the UTF-16 byte order.
    pub key: Option<String>,
    /// Whether ciphey's plaintext checks accept this text.
    pub is_plaintext: bool,
    /// What the plaintext check found. Null unless `is_plaintext` is true.
    pub detection: Option<DetectionOutput>,
}

impl DecodeWithOutput {
    /// Converts what [`ciphey::decode_with`] returned, keeping it within the output limits.
    pub fn from_decoded(decoded: Decoded) -> Self {
        let status = if decoded.plaintext().is_some() {
            DecodeWithStatus::PlaintextFound
        } else if decoded.is_empty() {
            DecodeWithStatus::NoCandidates
        } else {
            DecodeWithStatus::NoPlaintext
        };
        let total_candidates = decoded.candidates.len();
        Self {
            decoder: decoded.decoder.to_string(),
            status,
            candidates: limit_candidates(decoded.candidates.into_iter().map(CandidateOutput::from)),
            total_candidates,
        }
    }
}

impl From<Candidate> for CandidateOutput {
    fn from(candidate: Candidate) -> Self {
        Self {
            is_plaintext: candidate.is_plaintext(),
            detection: candidate.detection.as_ref().map(DetectionOutput::from),
            text: candidate.text,
            truncated: false,
            key: candidate.key,
        }
    }
}

/// The candidates that fit in a result: at most [`MAX_CANDIDATES`], with at most
/// [`MAX_OUTPUT_CHARS`] characters of text between them, counted as [`json_chars`] does. The
/// candidate that crosses the character limit is cut short, and the ones after it are left
/// out.
fn limit_candidates(candidates: impl IntoIterator<Item = CandidateOutput>) -> Vec<CandidateOutput> {
    let mut budget = MAX_OUTPUT_CHARS;
    let mut kept = Vec::new();
    for mut candidate in candidates.into_iter().take(MAX_CANDIDATES) {
        let mut used = 0;
        let cut = candidate.text.char_indices().find_map(|(index, c)| {
            used += json_chars(c);
            (used > budget).then_some(index)
        });
        match cut {
            // Not even its first character fits.
            Some(0) => break,
            Some(cut) => {
                candidate.text.truncate(cut);
                candidate.truncated = true;
                kept.push(candidate);
                break;
            }
            None => {
                budget -= used;
                kept.push(candidate);
            }
        }
    }
    kept
}

/// How many characters `c` takes in the JSON of a result, as serde_json writes it: 2 for
/// `\"`, `\\` and the short escapes such as `\n`, 6 for other control characters (`\u0001`),
/// and 1 for anything else. Binary decodings are full of control characters, so counting
/// them as one each would let a result grow to six times the limit.
fn json_chars(c: char) -> usize {
    match c {
        '"' | '\\' | '\u{8}' | '\u{c}' | '\n' | '\r' | '\t' => 2,
        '\0'..='\u{1f}' => 6,
        _ => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(decoder: &str, text: &str) -> DecodeWithParams {
        DecodeWithParams {
            decoder: decoder.to_string(),
            text: text.to_string(),
            ..DecodeWithParams::default()
        }
    }

    fn with_key(decoder: &str, text: &str, key: &str) -> DecodeWithParams {
        DecodeWithParams {
            key: Some(key.to_string()),
            ..params(decoder, text)
        }
    }

    fn candidate(text: &str) -> CandidateOutput {
        CandidateOutput {
            text: text.to_string(),
            truncated: false,
            key: None,
            is_plaintext: false,
            detection: None,
        }
    }

    /// Runs `params` as a worker would, in this process. The tests don't set the library's
    /// config, so there is no crib.
    fn decode(params: DecodeWithParams) -> DecodeWithOutput {
        run(&params.into_request().unwrap()).unwrap()
    }

    #[test]
    fn into_request_resolves_names_and_aliases_to_ids() {
        for (name, id) in [
            ("base64", "base64"),
            ("Base64", "base64"),
            ("b64", "base64"),
            (" ROT13 ", "caesar"),
            ("Vigenère", "vigenere"),
            ("Single-byte XOR", "xor_single_byte"),
        ] {
            let request = params(name, "aGk=").into_request().unwrap();
            assert_eq!(request.decoder, id, "{name}");
        }
    }

    #[test]
    fn into_request_rejects_unknown_decoders_and_lists_the_ids() {
        let error = params("rot1300", "hi").into_request().unwrap_err();
        assert!(
            error.starts_with(r#"no decoder is called "rot1300""#),
            "{error}"
        );
        assert!(error.contains("base64, "), "{error}");

        let error = params("  ", "hi").into_request().unwrap_err();
        assert!(error.contains("`decoder` is empty"), "{error}");

        let error = params(&"x".repeat(MAX_DECODER_NAME_CHARS + 1), "hi")
            .into_request()
            .unwrap_err();
        assert!(error.contains("the limit is 100"), "{error}");
    }

    #[test]
    fn into_request_checks_text_and_regex() {
        let error = params("base64", "").into_request().unwrap_err();
        assert!(error.contains("`text` is empty"), "{error}");

        assert!(params("base64", &"A".repeat(MAX_INPUT_CHARS))
            .into_request()
            .is_ok());
        let error = params("base64", &"A".repeat(MAX_INPUT_CHARS + 1))
            .into_request()
            .unwrap_err();
        assert!(error.contains("the limit is 65536"), "{error}");

        let request = DecodeWithParams {
            regex: Some(String::new()),
            ..params("base64", "aGk=")
        };
        assert_eq!(request.into_request().unwrap().regex, None);
        let error = DecodeWithParams {
            regex: Some("(unclosed".to_string()),
            ..params("base64", "aGk=")
        }
        .into_request()
        .unwrap_err();
        assert!(error.contains("not a valid regular expression"), "{error}");
    }

    #[test]
    fn into_request_only_passes_keys_to_decoders_that_take_them() {
        let request = with_key("caesar", "Uryyb", "13").into_request().unwrap();
        assert_eq!(request.key.as_deref(), Some("13"));

        // "" means no key.
        let request = with_key("base64", "aGk=", "").into_request().unwrap();
        assert_eq!(request.key, None);

        let error = with_key("base64", "aGk=", "13").into_request().unwrap_err();
        assert!(error.starts_with("Base64 doesn't take a key"), "{error}");
        assert!(error.contains("caesar"), "{error}");
        assert!(!error.contains("base64"), "{error}");
    }

    #[test]
    fn keys_can_be_numbers() {
        let params: DecodeWithParams = serde_json::from_value(serde_json::json!({
            "decoder": "caesar",
            "text": "Khoor zruog",
            "key": 23,
        }))
        .unwrap();
        assert_eq!(params.key.as_deref(), Some("23"));

        let params: DecodeWithParams =
            serde_json::from_value(serde_json::json!({ "decoder": "caesar", "text": "x" }))
                .unwrap();
        assert_eq!(params.key, None);

        let error = serde_json::from_value::<DecodeWithParams>(serde_json::json!({
            "decoder": "caesar",
            "text": "x",
            "key": [1, 2],
        }))
        .unwrap_err();
        assert!(
            error.to_string().contains("`key` must be a string"),
            "{error}"
        );
    }

    #[test]
    fn cracks_ciphers_and_decodes_encodings() {
        let output = decode(params("rot13", "Uryyb jbeyq"));
        assert_eq!(output.decoder, "caesar");
        assert_eq!(output.status, DecodeWithStatus::PlaintextFound);
        assert_eq!(output.total_candidates, 1);
        let plaintext = &output.candidates[0];
        assert_eq!(plaintext.text, "Hello world");
        assert_eq!(plaintext.key.as_deref(), Some("13"));
        assert!(plaintext.is_plaintext);
        assert_eq!(plaintext.detection.as_ref().unwrap().checker, "english");

        let output = decode(params("hexadecimal", "3139322e3136382e302e31"));
        assert_eq!(output.status, DecodeWithStatus::PlaintextFound);
        let detection = output.candidates[0].detection.as_ref().unwrap();
        assert_eq!(
            detection.description,
            "Internet Protocol (IP) Address Version 4"
        );
        assert_eq!(detection.confidence, Some(0.7));
    }

    #[test]
    fn decrypts_with_a_key() {
        let output = decode(with_key("vigenere", "Rijvs uyvjn", "key"));
        assert_eq!(output.candidates[0].text, "Hello world");
        assert_eq!(output.candidates[0].key.as_deref(), Some("KEY"));

        let output = decode(with_key("affine", "IHHWVC SWFRCP", "a=5, b=8"));
        assert_eq!(output.candidates[0].text, "AFFINE CIPHER");

        let error = run(&with_key("affine", "IHHWVC", "a=2, b=8")
            .into_request()
            .unwrap())
        .unwrap_err();
        assert!(error.starts_with("invalid key for Affine"), "{error}");
    }

    #[test]
    fn reports_candidates_no_check_accepted() {
        let output = decode(params("caesar", "xqzjv kplmw"));
        assert_eq!(output.status, DecodeWithStatus::NoPlaintext);
        assert_eq!(output.total_candidates, 25);
        assert_eq!(output.candidates.len(), 25);
        assert!(output
            .candidates
            .iter()
            .all(|candidate| !candidate.is_plaintext && candidate.detection.is_none()));

        let output = decode(params("base64", "!!!"));
        assert_eq!(output.status, DecodeWithStatus::NoCandidates);
        assert!(output.candidates.is_empty());
    }

    #[test]
    fn limit_candidates_keeps_whole_candidates_under_the_limits() {
        let half = "a".repeat(MAX_OUTPUT_CHARS / 2);
        let kept = limit_candidates([candidate(&half), candidate(&half), candidate("b")]);
        // The second one uses up the budget exactly, so the third is left out.
        assert_eq!(kept.len(), 2);
        assert!(kept.iter().all(|candidate| !candidate.truncated));

        let many = limit_candidates((0..MAX_CANDIDATES + 10).map(|_| candidate("x")));
        assert_eq!(many.len(), MAX_CANDIDATES);
    }

    #[test]
    fn limit_candidates_cuts_the_one_that_crosses_the_limit() {
        // Multi-byte characters count once and are never split.
        let long = "é".repeat(MAX_OUTPUT_CHARS - 10);
        let kept = limit_candidates([candidate(&long), candidate(&"ü".repeat(50)), candidate("z")]);

        assert_eq!(kept.len(), 2);
        assert!(!kept[0].truncated);
        assert!(kept[1].truncated);
        assert_eq!(kept[1].text, "ü".repeat(10));
        let chars: usize = kept.iter().map(|c| c.text.chars().count()).sum();
        assert_eq!(chars, MAX_OUTPUT_CHARS);

        let huge = limit_candidates([candidate(&"q".repeat(MAX_OUTPUT_CHARS * 3))]);
        assert_eq!(huge[0].text.len(), MAX_OUTPUT_CHARS);
        assert!(huge[0].truncated);
    }

    #[test]
    fn limit_candidates_counts_characters_as_json_writes_them() {
        // Binary decodings are full of control characters, which JSON writes as `\u0001`.
        let binary = "\u{1}".repeat(20_000);
        let kept = limit_candidates([candidate(&binary), candidate("next")]);

        assert_eq!(kept.len(), 1);
        assert!(kept[0].truncated);
        assert_eq!(kept[0].text.chars().count(), MAX_OUTPUT_CHARS / 6);
        assert!(json_len(&kept[0].text) <= MAX_OUTPUT_CHARS);

        assert_eq!(json_chars('a'), 1);
        assert_eq!(json_chars('é'), 1);
        assert_eq!(json_chars('"'), 2);
        assert_eq!(json_chars('\n'), 2);
        assert_eq!(json_chars('\u{7}'), 6);
        for c in ['"', '\\', '\n', '\t', '\u{0}', '\u{1f}', '\u{7f}', 'x'] {
            assert_eq!(json_chars(c), json_len(&c.to_string()), "{c:?}");
        }
    }

    /// How many characters `text` takes in JSON, without the quotes. For ASCII text only:
    /// it counts bytes.
    fn json_len(text: &str) -> usize {
        serde_json::to_string(text).unwrap().len() - 2
    }

    #[test]
    fn large_results_are_limited() {
        // ROT47 cracking returns 93 candidates of 1,000 characters each.
        let text: String = "Gur dhvpx oebja sbk whzcf bire gur ynml qbt. "
            .chars()
            .cycle()
            .take(1_000)
            .collect();
        let output = decode(params("rot47", &text));
        assert_eq!(output.total_candidates, 93);
        let (last, whole) = output.candidates.split_last().unwrap();
        assert!(whole.len() > 60, "{}", whole.len());
        assert!(whole.iter().all(|candidate| !candidate.truncated));
        assert!(last.truncated);
        // Some rotations contain `"` and `\`, which JSON escapes.
        let chars: usize = output.candidates.iter().map(|c| json_len(&c.text)).sum();
        assert!(
            (MAX_OUTPUT_CHARS - 1..=MAX_OUTPUT_CHARS).contains(&chars),
            "{chars}"
        );
    }

    #[test]
    fn list_decoders_lists_the_library_api() {
        let list = DecoderList::all();

        assert_eq!(list.decoders.len(), ciphey::list_decoders().len());
        let caesar = list.decoders.iter().find(|d| d.id == "caesar").unwrap();
        assert_eq!(caesar.name, "caesar");
        assert!(caesar.aliases.iter().any(|alias| alias == "rot13"));
        assert!(caesar.key_format.is_some());
        let base64 = list.decoders.iter().find(|d| d.id == "base64").unwrap();
        assert_eq!(base64.name, "Base64");
        assert_eq!(base64.key_format, None);
        for expected in ["hexadecimal", "vigenere", "morse", "brainfuck"] {
            assert!(
                list.decoders.iter().any(|d| d.id == expected),
                "{expected} missing"
            );
        }
        let ids: Vec<&str> = list.decoders.iter().map(|d| d.id.as_str()).collect();
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        assert_eq!(ids, sorted);
        assert!(list.decoders.iter().all(|d| !d.description.is_empty()));
    }
}
