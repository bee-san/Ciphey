use crate::checkers::checker_result::CheckResult;
use gibberish_or_not::Sensitivity;
use lemmeknow::Identifier;

use crate::checkers::checker_type::{Check, Checker};
use crate::checkers::english::is_known_word;

/// Checks if the text is a line or snippet of source code or a shell command, such as
/// `import os`, `int main() { return 0; }` or `curl -s https://example.com/api`.
///
/// The English checker rejects most code: too few of its words are English words. This
/// checker runs after it, so English text is still reported as words, and only accepts
/// text that starts like code (a keyword, a function call or a common command) and has
/// code's symbols, balanced brackets and printable ASCII. Decoder junk rarely starts with
/// a keyword: a Caesar shift of `import os` is `vzcbeg bf`.
pub struct CodeChecker;

impl Check for Checker<CodeChecker> {
    fn new() -> Self {
        Checker {
            name: "Code Checker",
            description: "Checks if the text is source code or a shell command",
            link: "",
            tags: vec!["code", "structured"],
            expected_runtime: 0.01,
            popularity: 1.0,
            lemmeknow_config: Identifier::default(),
            sensitivity: Sensitivity::Medium,
            _phantom: std::marker::PhantomData,
        }
    }

    fn check(&self, text: &str) -> CheckResult {
        let mut result = CheckResult::new(self);
        result.text = text.to_string();
        if let Some(description) = identify(text) {
            result.is_identified = true;
            result.description = description;
        }
        result
    }

    fn with_sensitivity(mut self, sensitivity: Sensitivity) -> Self {
        self.sensitivity = sensitivity;
        self
    }

    fn get_sensitivity(&self) -> Sensitivity {
        self.sensitivity
    }
}

/// What the code checker identifies `text` as, if anything.
pub(crate) fn identify(text: &str) -> Option<String> {
    if is_code(text) {
        Some("Source code or shell command".to_string())
    } else if is_query_string(text) {
        Some("URL query string or form data".to_string())
    } else {
        None
    }
}

/// How lines of code start: keywords, function calls and markup, each followed by what
/// must come next (a space or a bracket is part of the prefix).
const CODE_STARTS: [&str; 64] = [
    "#!/bin/",
    "#!/usr/bin/",
    "#!/usr/local/bin/",
    "#define ",
    "#include ",
    "#include<",
    "<!DOCTYPE",
    "<?php",
    "<?xml",
    "<a href",
    "<div",
    "<html",
    "<script",
    "ALTER TABLE ",
    "CREATE TABLE ",
    "DELETE FROM ",
    "DROP TABLE ",
    "INSERT INTO ",
    "SELECT ",
    "System.out.",
    "UPDATE ",
    "alert(",
    "async ",
    "class ",
    "console.log(",
    "const ",
    "def ",
    "document.",
    "echo ",
    "elif ",
    "else {",
    "eval(",
    "exec(",
    "export ",
    "fn ",
    "for (",
    "foreach ",
    "from ",
    "func ",
    "function ",
    "if (",
    "import ",
    "int main",
    "let ",
    "namespace ",
    "package ",
    "print ",
    "print(",
    "printf(",
    "private ",
    "pub fn ",
    "public ",
    "puts ",
    "require(",
    "return ",
    "static ",
    "struct ",
    "try:",
    "try {",
    "use ",
    "using ",
    "var ",
    "while ",
    "window.",
];

/// Common commands, which must be followed by a space and an argument.
const COMMANDS: [&str; 56] = [
    "apt",
    "apt-get",
    "awk",
    "base64",
    "bash",
    "cargo",
    "cat",
    "cd",
    "chmod",
    "chown",
    "cp",
    "crontab",
    "curl",
    "dig",
    "docker",
    "file",
    "find",
    "gcc",
    "gdb",
    "git",
    "grep",
    "hexdump",
    "java",
    "kill",
    "ls",
    "make",
    "mkdir",
    "mount",
    "mv",
    "nc",
    "ncat",
    "net",
    "nmap",
    "node",
    "npm",
    "nslookup",
    "openssl",
    "perl",
    "php",
    "ping",
    "pip",
    "pip3",
    "powershell",
    "python",
    "python3",
    "rm",
    "ruby",
    "scp",
    "sed",
    "sh",
    "ssh",
    "strings",
    "sudo",
    "tar",
    "wget",
    "xxd",
];

/// Symbols code has and English hardly ever does. A line that starts with a keyword
/// (`from `, `use `, `return `, many of them English words) needs one of these somewhere in
/// the text.
const CODE_SYMBOLS: &str = "()[]{}=;<>|&$\\\"*+`";

/// Whether `text` looks like source code or a shell command: see [`CodeChecker`].
pub(crate) fn is_code(text: &str) -> bool {
    let text = text.trim();
    if !(6..=20_000).contains(&text.len()) {
        return false;
    }
    // Cheapest first: almost no text a search checks starts like code
    let (mut keyword, mut command) = (false, false);
    for line in text.lines().map(str::trim_start) {
        keyword |= CODE_STARTS.iter().any(|start| line.starts_with(start));
        command |= starts_with_command(line);
    }
    if !keyword && !command {
        return false;
    }
    let (mut plain, mut symbols) = (0usize, false);
    let (mut round, mut square, mut curly, mut quotes) = (0i32, 0i32, 0i32, 0usize);
    for b in text.bytes() {
        if !((0x20..0x7f).contains(&b) || matches!(b, b'\n' | b'\r' | b'\t')) {
            return false;
        }
        match b {
            b'(' => round += 1,
            b')' => round -= 1,
            b'[' => square += 1,
            b']' => square -= 1,
            b'{' => curly += 1,
            b'}' => curly -= 1,
            b'"' => quotes += 1,
            _ => {}
        }
        plain += usize::from(b.is_ascii_alphanumeric() || b.is_ascii_whitespace());
        symbols |= CODE_SYMBOLS.as_bytes().contains(&b);
    }
    // Brackets and double quotes balance, and the text is mostly identifiers and spaces,
    // like code, not symbol soup
    round == 0
        && square == 0
        && curly == 0
        && quotes % 2 == 0
        && plain * 10 >= text.len() * 6
        && (command || symbols)
}

/// Whether `text` is a URL query string or form data with at least two fields, like
/// `number_1=1&number_2=0&operation=/` (a CTF's request, decoded from URL encoding).
/// Names are identifiers of two or more characters, and values are letters, digits and
/// `._~:/+,@-`: no spaces, quotes, brackets or `%` (still URL-encoded: the URL decoder
/// goes first).
pub(crate) fn is_query_string(text: &str) -> bool {
    let text = text.trim().trim_start_matches('?');
    let mut fields = 0;
    for field in text.split('&') {
        let Some((name, value)) = field.split_once('=') else {
            return false;
        };
        let mut name_chars = name.chars();
        let name_ok = name.len() >= 2
            && name_chars
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            && name_chars.all(|c| c.is_ascii_alphanumeric() || c == '_');
        let value_ok = value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._~:/+,@-".contains(c));
        if !name_ok || !value_ok {
            return false;
        }
        fields += 1;
    }
    fields >= 2
}

/// Whether a line starts with one of [`COMMANDS`] and an argument: an option (`-la`), a
/// path, a quoted string or a variable for two-letter commands (`ls -la`, `cd /tmp`), also
/// an English word or any argument on a line with a shell symbol for longer ones
/// (`git commit`, `sudo apt-get install`).
fn starts_with_command(line: &str) -> bool {
    let mut parts = line.splitn(2, ' ');
    let (Some(command), Some(rest)) = (parts.next(), parts.next()) else {
        return false;
    };
    if !COMMANDS.contains(&command) {
        return false;
    }
    let argument = rest.trim_start();
    match argument.bytes().next() {
        None => false,
        Some(b'-' | b'/' | b'.' | b'~' | b'$' | b'"' | b'\'') => true,
        // `git commit`, `make install`; but not `gcc uz rdr hymsjzck`, a wrong Vigenère key:
        // a word argument must be an English word unless the line has a shell symbol
        Some(b) => {
            command.len() > 2
                && b.is_ascii_alphanumeric()
                && (rest.contains(['-', '/', '.', '=', '|', '&', ';', '<', '>', '$', '"', '\''])
                    || argument
                        .split_whitespace()
                        .next()
                        .is_some_and(|word| is_known_word(&word.to_ascii_lowercase())))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_and_commands_are_code() {
        for code in [
            "import os\nprint(os.getcwd())",
            "#include <stdio.h>",
            "int main() { return 0; }",
            "fn main() { println!(\"Hello, world!\"); }",
            "const sum = (a, b) => a + b;",
            "curl -s https://example.com/api/v1/status",
            "ls -la /home/user",
            "nc -lvnp 4444",
            "git commit -m \"fix the parser\"",
            "SELECT * FROM users WHERE id = 1;",
            "var xhr = new XMLHttpRequest();\nxhr.open(\"GET\", \"/user/0\", true);",
            "#!/bin/bash\nfor f in *.txt; do wc -l \"$f\"; done",
            "<?php echo 'Hello World'; ?>",
        ] {
            assert!(is_code(code), "{code}");
        }
    }

    #[test]
    fn english_and_junk_are_not_code() {
        for text in [
            "let me know when you get home",
            "from the river to the sea",
            "Find the key in the garden",
            "vzcbeg bf\ncevag(bf.trgpjq())",
            "))(dwcteg.so(tnirp\nso tropmi",
            "cd zw{~|~vw|}",
            "ls is a command",
            "print(\"unbalanced\"",
            "import os ±",
            "SGVsbG8gV29ybGQ=",
            // A Caesar shift of a shell script
            "#!/nuz/nmet\nrad r uz *.fjf; pa io -x \"$r\"; pazq",
            "use the force.",
            "return to sender, address unknown",
            "git",
            // A wrong Vigenère key
            "gcc uz rdr hymsjzck",
        ] {
            assert!(!is_code(text), "{text}");
        }
    }

    #[test]
    fn query_strings() {
        for query in [
            "number_1=1&number_2=0&operation=/",
            "?user=admin&pass=hunter2",
            "id=5&page=",
        ] {
            assert!(is_query_string(query), "{query}");
        }
        for text in [
            "a=1",
            "ab=1&cd",
            "1a=1&bc=2",
            "ab=1 &cd=2",
            "ab==1&cd=2",
            "hello world",
            "number_1=1&number_2=0&operation=%2F",
            "Y=SoCAH6.&ll=[TLL8\"",
            "l=&f=ig-Z)",
        ] {
            assert!(!is_query_string(text), "{text}");
        }
    }

    #[test]
    fn the_result_says_what_it_is() {
        let result = Checker::<CodeChecker>::new().check("ls -la");
        assert!(result.is_identified);
        assert_eq!(result.description, "Source code or shell command");
        assert_eq!(result.text, "ls -la");
    }
}
