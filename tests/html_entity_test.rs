//! End-to-end tests for the HTML Entities decoder: the full search has to find it.
//! See <https://github.com/bee-san/Ciphey/issues/939>.

use ciphey::config::Config;
use ciphey::perform_cracking;
use ciphey::{set_test_db_path, TestDatabase};
use serial_test::serial;

/// `Hello, World!` as decimal references. Checked with CyberChef, Python 3 `html.unescape`
/// and html-escape 0.2.15 in the plan in issue #939.
const HELLO_DECIMAL: &str =
    "&#72;&#101;&#108;&#108;&#111;&#44;&#32;&#87;&#111;&#114;&#108;&#100;&#33;";

/// `HELLO_DECIMAL` escaped a second time, so every `&` became `&amp;`. One
/// `html.unescape` gives `HELLO_DECIMAL`, a second gives `Hello, World!`.
const HELLO_DOUBLE_ESCAPED: &str = "&amp;#72;&amp;#101;&amp;#108;&amp;#108;&amp;#111;&amp;#44;&amp;#32;&amp;#87;&amp;#111;&amp;#114;&amp;#108;&amp;#100;&amp;#33;";

/// Runs the full search on `text` and returns the plaintext and the decoders used.
fn crack(text: &str) -> (String, Vec<&'static str>) {
    let _test_db = TestDatabase::default();
    set_test_db_path();

    let result = perform_cracking(text, Config::default())
        .expect("the search should not time out")
        .expect("the search should find the plaintext");
    let path = result.path.iter().map(|step| step.decoder).collect();
    (result.text[0].clone(), path)
}

#[test]
#[serial]
fn search_cracks_html_entities() {
    let (plaintext, path) = crack(HELLO_DECIMAL);
    assert_eq!(plaintext, "Hello, World!");
    assert_eq!(path, ["HTML Entities"]);
}

#[test]
#[serial]
fn search_cracks_double_escaped_html_entities() {
    // Needs "HTML Entities" in STACKABLE: the search only applies a decoder twice in a row
    // when the pair stacks.
    let (plaintext, path) = crack(HELLO_DOUBLE_ESCAPED);
    assert_eq!(plaintext, "Hello, World!");
    assert_eq!(path, ["HTML Entities", "HTML Entities"]);
}
