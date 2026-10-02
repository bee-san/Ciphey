//! Turning search data into short, safe text for the screens.

use crate::decoders::crack_results::CrackResult;
use std::borrow::Cow;
use std::fmt::Write;
use std::time::Duration;
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

/// Display width of `text` in terminal columns
pub fn width(text: &str) -> usize {
    UnicodeWidthStr::width(text)
}

/// Whether `c` has to be escaped before it is shown: control characters, which would
/// move the cursor or change the terminal's state, and the bidirectional overrides,
/// which reorder the text around them.
fn needs_escape(c: char) -> bool {
    c.is_control() || matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}

/// One piece of a line of decoded text: either text that can be printed as it is, or a
/// visible escape such as `\x1b` standing for a character that can't.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Piece {
    /// Printable text
    Text(String),
    /// An escape sequence standing for an unprintable character
    Escape(String),
}

/// Splits one line of decoded text into printable pieces and escapes.
///
/// Decoded text can contain anything, including escape sequences that would recolour
/// or clear the terminal, so it is never printed raw. Newlines are not handled here:
/// split the text into lines first.
pub fn pieces(line: &str) -> Vec<Piece> {
    let mut pieces = Vec::new();
    let mut plain = String::new();
    for c in line.chars() {
        if !needs_escape(c) {
            plain.push(c);
            continue;
        }
        if !plain.is_empty() {
            pieces.push(Piece::Text(std::mem::take(&mut plain)));
        }
        let escape = match c {
            '\t' => "\\t".to_string(),
            '\r' => "\\r".to_string(),
            '\n' => "\\n".to_string(),
            '\0' => "\\0".to_string(),
            c if (c as u32) < 0x100 => format!("\\x{:02x}", c as u32),
            c => format!("\\u{{{:x}}}", c as u32),
        };
        pieces.push(Piece::Escape(escape));
    }
    if !plain.is_empty() {
        pieces.push(Piece::Text(plain));
    }
    pieces
}

/// `text` with every unprintable character replaced by its escape, on one line
pub fn sanitize(text: &str) -> Cow<'_, str> {
    if !text.chars().any(needs_escape) {
        return Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len() + 8);
    for piece in pieces(text) {
        match piece {
            Piece::Text(t) | Piece::Escape(t) => out.push_str(&t),
        }
    }
    Cow::Owned(out)
}

/// Cuts `text` to at most `max` columns, ending it with `ellipsis` if anything was cut.
pub fn truncate(text: &str, max: usize, ellipsis: &str) -> String {
    if width(text) <= max {
        return text.to_string();
    }
    let room = max.saturating_sub(width(ellipsis));
    let mut out = String::new();
    let mut used = 0;
    for c in text.chars() {
        let w = c.width().unwrap_or(0);
        if used + w > room {
            break;
        }
        used += w;
        out.push(c);
    }
    if max >= width(ellipsis) {
        out.push_str(ellipsis);
    }
    out
}

/// Splits `text` into lines of at most `max` columns, breaking at spaces where it can.
pub fn wrap(text: &str, max: usize) -> Vec<String> {
    let max = max.max(1);
    let mut lines = Vec::new();
    let mut line = String::new();
    for word in text.split(' ').filter(|w| !w.is_empty()) {
        let needed = if line.is_empty() {
            width(word)
        } else {
            width(&line) + 1 + width(word)
        };
        if needed <= max {
            if !line.is_empty() {
                line.push(' ');
            }
            line.push_str(word);
            continue;
        }
        if !line.is_empty() {
            lines.push(std::mem::take(&mut line));
        }
        // A word longer than the whole line is split wherever it has to be
        let mut rest = word;
        while width(rest) > max {
            let mut used = 0;
            let cut = rest
                .char_indices()
                .find(|(_, c)| {
                    used += c.width().unwrap_or(0);
                    used > max
                })
                .map_or(rest.len(), |(i, _)| i);
            let cut = if cut == 0 {
                rest.chars().next().map_or(rest.len(), char::len_utf8)
            } else {
                cut
            };
            lines.push(rest[..cut].to_string());
            rest = &rest[cut..];
        }
        line.push_str(rest);
    }
    if !line.is_empty() || lines.is_empty() {
        lines.push(line);
    }
    lines
}

/// `12408` as `12,408`
pub fn thousands(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// A short, human reading of a duration: `8 ms`, `0.16 s`, `2.4 s`, `14 s`, `2 min 5 s`
pub fn duration(d: Duration) -> String {
    let ms = d.as_millis();
    let secs = d.as_secs_f64();
    if ms < 100 {
        format!("{ms} ms")
    } else if secs < 1.0 {
        format!("{secs:.2} s")
    } else if secs < 10.0 {
        format!("{secs:.1} s")
    } else if secs < 60.0 {
        format!("{} s", secs as u64)
    } else {
        let whole = d.as_secs();
        format!("{} min {} s", whole / 60, whole % 60)
    }
}

/// A time limit in whole seconds: `5 s`, `90 s`
pub fn seconds(secs: u32) -> String {
    format!("{secs} s")
}

/// The decoder's name as people write it. Decoders call themselves `caesar`,
/// `rot47`, `Vigenere` and so on; unknown names get a capital letter.
pub fn decoder_name(name: &str) -> Cow<'_, str> {
    let pretty = match name {
        "caesar" => "Caesar",
        "rot47" => "ROT47",
        "atbash" => "Atbash",
        "railfence" => "Rail fence",
        "a1z26" => "A1Z26",
        "simplesubstitution" => "Substitution",
        "Vigenere" => "Vigenère",
        "Citrix Ctx1" => "Citrix CTX1",
        "Morse Code" => "Morse code",
        _ => {
            let mut chars = name.chars();
            return match chars.next() {
                Some(first) if first.is_lowercase() => {
                    Cow::Owned(first.to_uppercase().chain(chars).collect())
                }
                _ => Cow::Borrowed(name),
            };
        }
    };
    Cow::Borrowed(pretty)
}

/// The key a decoder used, as people would describe it. Caesar records the shift that
/// decodes the text; the text was encoded with the opposite shift, which is the one
/// people know it by (ROT13 is 13 either way).
pub fn key_label(step: &CrackResult) -> Option<String> {
    let key = step.key.as_deref()?.trim();
    if key.is_empty() {
        return None;
    }
    if step.decoder == "caesar" {
        if let Ok(decode_shift) = key.parse::<u32>() {
            let shift = (26 - decode_shift % 26) % 26;
            return Some(if shift == 13 {
                "ROT13".to_string()
            } else {
                format!("shift {shift}")
            });
        }
    }
    Some(format!("key {}", sanitize(key)))
}

/// A decoder and its key: `Base64`, `Caesar (shift 3)`, `Vigenère (key LEMON)`
pub fn step_name(step: &CrackResult) -> String {
    let mut name = decoder_name(step.decoder).into_owned();
    if let Some(key) = key_label(step) {
        let _ = write!(name, " ({key})");
    }
    name
}

/// The text a step of the path produced, if the path recorded it
pub fn step_output(step: &CrackResult) -> Option<&str> {
    step.unencrypted_text
        .as_ref()
        .and_then(|texts| texts.first())
        .map(String::as_str)
}

/// Whether the "path" is the placeholder `perform_cracking` returns when the input
/// was already plaintext
pub fn is_input_plaintext(path: &[CrackResult]) -> bool {
    matches!(path, [only] if only.decoder == "Default decoder")
}

/// What a checker found, in words: "looks like English", "recognised as an IPv4
/// address" and so on. Reads after [`checker_name`]: "Regex · matches flag\{".
///
/// `description` is what the checker reported, if known (the human checker sees it;
/// a finished result only keeps the checker's name).
pub fn identification(checker: &str, description: Option<&str>) -> Option<String> {
    let description = description.map(str::trim).filter(|d| !d.is_empty());
    let text = match checker {
        "" => return None,
        "English Checker" => "looks like English".to_string(),
        "LemmeKnow Checker" => match description {
            Some(d) => format!("recognised as {}", sanitize(d)),
            None => "recognised it".to_string(),
        },
        "Regex Checker" => match description.and_then(|d| d.strip_prefix("Regex matched: ")) {
            Some(regex) => format!("matches {}", sanitize(regex)),
            None => "matches your regex".to_string(),
        },
        "Wordlist Checker" => "is in your wordlist".to_string(),
        "Password Checker" => "is a common password".to_string(),
        _ => match description {
            Some(d) => sanitize(d).into_owned(),
            None => "recognised it".to_string(),
        },
    };
    Some(text)
}

/// The checker's name for people: "English checker", "LemmeKnow", "Regex"
pub fn checker_name(checker: &str) -> &str {
    match checker {
        "English Checker" => "English checker",
        "LemmeKnow Checker" => "LemmeKnow",
        "Regex Checker" => "Regex",
        "Wordlist Checker" => "Wordlist",
        "Password Checker" => "Password list",
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decoders::interface::Decoder;

    fn step(decoder: &'static str, key: Option<&str>) -> CrackResult {
        let mut step = CrackResult::new(&Decoder::default(), String::new());
        step.decoder = decoder;
        step.key = key.map(str::to_string);
        step
    }

    #[test]
    fn control_characters_are_escaped() {
        assert_eq!(sanitize("plain text"), "plain text");
        assert_eq!(sanitize("\x1b[2Jbell\x07"), "\\x1b[2Jbell\\x07");
        assert_eq!(sanitize("tab\there\r"), "tab\\there\\r");
        // Bidi overrides would reorder what is shown
        assert_eq!(sanitize("abc\u{202e}def"), "abc\\u{202e}def");
        // Other non-ASCII text is left alone
        assert_eq!(sanitize("Vigenère → 攻"), "Vigenère → 攻");
        assert_eq!(
            pieces("a\x1bb"),
            vec![
                Piece::Text("a".into()),
                Piece::Escape("\\x1b".into()),
                Piece::Text("b".into())
            ]
        );
    }

    #[test]
    fn truncate_counts_columns() {
        assert_eq!(truncate("hello", 10, "…"), "hello");
        assert_eq!(truncate("hello world", 8, "…"), "hello w…");
        assert_eq!(truncate("hello world", 8, "..."), "hello...");
        // Wide characters take two columns each
        assert_eq!(truncate("攻攻攻攻", 5, "…"), "攻攻…");
    }

    #[test]
    fn wrap_breaks_at_spaces_and_splits_long_words() {
        assert_eq!(wrap("the quick brown fox", 9), ["the quick", "brown fox"]);
        assert_eq!(wrap("abcdefghij", 4), ["abcd", "efgh", "ij"]);
        assert_eq!(wrap("", 4), [""]);
    }

    #[test]
    fn numbers_and_durations_are_short() {
        assert_eq!(thousands(0), "0");
        assert_eq!(thousands(999), "999");
        assert_eq!(thousands(12408), "12,408");
        assert_eq!(thousands(1234567), "1,234,567");
        assert_eq!(duration(Duration::from_millis(8)), "8 ms");
        assert_eq!(duration(Duration::from_millis(157)), "0.16 s");
        assert_eq!(duration(Duration::from_millis(2420)), "2.4 s");
        assert_eq!(duration(Duration::from_secs(14)), "14 s");
        assert_eq!(duration(Duration::from_secs(125)), "2 min 5 s");
    }

    #[test]
    fn decoders_get_their_usual_names() {
        assert_eq!(decoder_name("caesar"), "Caesar");
        assert_eq!(decoder_name("Base64"), "Base64");
        assert_eq!(decoder_name("brandnew"), "Brandnew");
        assert_eq!(step_name(&step("Base64", None)), "Base64");
        assert_eq!(
            step_name(&step("Vigenere", Some("lemon"))),
            "Vigenère (key lemon)"
        );
    }

    #[test]
    fn caesar_shows_the_shift_the_text_was_encoded_with() {
        // "Khoor" is "Hello" shifted by 3; the decoder records the decoding shift, 23
        assert_eq!(step_name(&step("caesar", Some("23"))), "Caesar (shift 3)");
        assert_eq!(step_name(&step("caesar", Some("13"))), "Caesar (ROT13)");
    }

    #[test]
    fn checkers_are_described_in_words() {
        assert_eq!(
            identification("English Checker", Some("Words")).as_deref(),
            Some("looks like English")
        );
        assert_eq!(
            identification(
                "LemmeKnow Checker",
                Some("Internet Protocol (IP) Address Version 4")
            )
            .as_deref(),
            Some("recognised as Internet Protocol (IP) Address Version 4")
        );
        assert_eq!(
            identification("Regex Checker", Some("Regex matched: flag\\{")).as_deref(),
            Some("matches flag\\{")
        );
        assert_eq!(identification("", None), None);
    }
}
