//! The JavaScript API itself, under Node.js:
//! `cargo test -p ciphey-wasm --target wasm32-unknown-unknown --test node`.
//!
//! The values go through JavaScript (`JsValue`) and come back as JSON, so these check what
//! a page gets: field names, `null`s, numbers.
#![cfg(all(target_family = "wasm", target_os = "unknown"))]

use ciphey_wasm::{ciphey_version, decode, detect_plaintext_js, list_decoders, JsSearch};
use serde_json::{json, Value};
use wasm_bindgen::JsValue;
use wasm_bindgen_test::wasm_bindgen_test as test;

/// `value` as JSON, through `JSON.stringify`
fn json(value: JsValue) -> Value {
    let text = js_sys::JSON::stringify(&value).unwrap();
    serde_json::from_str(&String::from(text)).unwrap()
}

/// JavaScript options from JSON
fn options(value: Value) -> JsValue {
    js_sys::JSON::parse(&value.to_string()).unwrap()
}

#[test]
fn search_steps_report_the_tree_and_the_answer() {
    let mut search = JsSearch::new(
        "NTA3NjYzNzU3MjZjMjA3NjY2MjA2OTcyNjU2YzIwNzM2ZTY2Njc=",
        options(json!({"timeout": 30, "previewChars": 20})),
    )
    .unwrap();
    assert_eq!(search.status(), "running");
    let mut nodes = Vec::new();
    let mut update;
    loop {
        update = json(search.step(40.0).unwrap());
        nodes.extend(update["nodes"].as_array().unwrap().iter().cloned());
        if update["status"] != "running" {
            break;
        }
    }
    assert_eq!(update["status"], "decoded");
    assert_eq!(search.status(), "decoded");
    let result = &update["result"];
    assert_eq!(result["plaintext"], "Ciphey is very fast");
    assert_eq!(result["checker"], "english");
    assert_eq!(result["checkerName"], "English Checker");
    assert_eq!(result["description"], "Words");
    assert_eq!(result["confidence"], Value::Null);
    let path: Vec<&str> = result["path"]
        .as_array()
        .unwrap()
        .iter()
        .map(|step| step["decoder"].as_str().unwrap())
        .collect();
    assert_eq!(path, ["Base64", "Hexadecimal", "caesar"]);
    assert_eq!(result["path"][2]["key"], "13");
    assert_eq!(result["path"][0]["key"], Value::Null);

    // The tree: the input is node 0, every node's parent came before it, and the answer's
    // node is in it
    assert_eq!(nodes[0]["id"], 0);
    assert_eq!(nodes[0]["parent"], Value::Null);
    assert_eq!(nodes[0]["decoder"], Value::Null);
    assert_eq!(nodes[0]["text"], "NTA3NjYzNzU3MjZjMjA3");
    assert_eq!(nodes[0]["length"], 52);
    for (i, node) in nodes.iter().enumerate().skip(1) {
        assert!(
            nodes[..i]
                .iter()
                .any(|earlier| earlier["id"] == node["parent"]),
            "{node}"
        );
    }
    assert!(nodes.iter().any(|node| node["id"] == result["nodeId"]));
    for field in [
        "elapsedMs",
        "expanded",
        "queued",
        "seen",
        "depth",
        "results",
    ] {
        assert!(update.get(field).is_some(), "{field}");
    }
    assert_eq!(json(search.results().unwrap())[0], *result);
}

#[test]
fn decode_returns_the_answer_or_null() {
    let found = json(decode("aGVsbG8gdGhlcmUgZ2VuZXJhbA==", JsValue::UNDEFINED).unwrap());
    assert_eq!(found["plaintext"], "hello there general");
    assert_eq!(found["path"][0]["decoder"], "Base64");
    assert_eq!(json(decode("", JsValue::NULL).unwrap()), Value::Null);
    let timed_out = decode("AAAA", options(json!({"timeoutMs": 300}))).unwrap();
    assert_eq!(json(timed_out), Value::Null);
}

#[test]
fn bad_options_throw() {
    assert!(JsSearch::new("aGVsbG8=", options(json!({"regex": "(unclosed"}))).is_err());
    assert!(JsSearch::new("aGVsbG8=", options(json!({"timeout": -1}))).is_err());
    assert!(JsSearch::new("aGVsbG8=", options(json!({"timout": 5}))).is_err()); // codespell:ignore timout
    assert!(JsSearch::new("aGVsbG8=", options(json!({"sensitivity": "max"}))).is_err());
    let mut search = JsSearch::new("aGVsbG8=", JsValue::UNDEFINED).unwrap();
    assert!(search.step(-5.0).is_err());
    assert!(search.step(f64::NAN).is_err());
}

#[test]
fn detect_plaintext_and_the_decoder_list() {
    let found = json(detect_plaintext_js("192.168.0.1", JsValue::UNDEFINED).unwrap());
    assert_eq!(
        found,
        json!({
            "checker": "lemmeknow",
            "checkerName": "LemmeKnow Checker",
            "description": "Internet Protocol (IP) Address Version 4",
            // JSON writes the f32 0.7 as 0.7, not 0.699999988...
            "confidence": 0.7,
        })
    );
    let none = detect_plaintext_js(
        "192.168.0.1",
        options(json!({"checkers": ["english"], "sensitivity": "low"})),
    )
    .unwrap();
    assert_eq!(json(none), Value::Null);
    assert!(detect_plaintext_js("x", options(json!({"checkers": ["nope"]}))).is_err());

    let decoders = json(list_decoders().unwrap());
    let base64 = decoders
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["name"] == "Base64")
        .unwrap();
    assert_eq!(base64["id"], "base64");
    assert!(base64["keyFormat"].is_null());
    assert!(!ciphey_version().is_empty());
}
