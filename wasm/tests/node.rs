//! The JavaScript API itself, under Node.js:
//! `cargo test -p ciphey-wasm --target wasm32-unknown-unknown --test node`.
//!
//! The values go through JavaScript (`JsValue`) and come back as JSON, so these check what
//! a page gets: field names, `null`s, numbers.
#![cfg(all(target_family = "wasm", target_os = "unknown"))]

use ciphey_wasm::{
    ciphey_version, decode, detect_plaintext_js, list_decoders, DetectOptionsArg, JsSearch,
    SearchOptionsArg,
};
use serde_json::{json, Value};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_test::wasm_bindgen_test as test;

/// `value` as JSON, through `JSON.stringify`
fn json(value: JsValue) -> Value {
    let text = js_sys::JSON::stringify(&value).unwrap();
    serde_json::from_str(&String::from(text)).unwrap()
}

/// JavaScript options from JSON
fn options(value: Value) -> Option<SearchOptionsArg> {
    Some(raw(js_sys::JSON::parse(&value.to_string()).unwrap()))
}

/// `detectPlaintext` options from JSON
fn detect_options(value: Value) -> Option<DetectOptionsArg> {
    Some(raw(js_sys::JSON::parse(&value.to_string()).unwrap()))
}

/// Any JavaScript value passed as options, as a page could
fn raw<T: JsCast>(value: JsValue) -> T {
    value.unchecked_into()
}

/// `{name: value}`, for values JSON can't hold
fn object_with(name: &str, value: JsValue) -> JsValue {
    let object = js_sys::Object::new();
    js_sys::Reflect::set(&object, &name.into(), &value).unwrap();
    object.into()
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
    let found = json(decode("aGVsbG8gdGhlcmUgZ2VuZXJhbA==", None).unwrap());
    assert_eq!(found["plaintext"], "hello there general");
    assert_eq!(found["path"][0]["decoder"], "Base64");
    assert_eq!(
        json(decode("", Some(raw(JsValue::NULL))).unwrap()),
        Value::Null
    );
    let timed_out = decode("AAAA", options(json!({"timeoutMs": 300}))).unwrap();
    assert_eq!(json(timed_out), Value::Null);
}

#[test]
fn bad_options_throw() {
    assert!(JsSearch::new("aGVsbG8=", options(json!({"regex": "(unclosed"}))).is_err());
    assert!(JsSearch::new("aGVsbG8=", options(json!({"timeout": -1}))).is_err());
    assert!(JsSearch::new("aGVsbG8=", options(json!({"timout": 5}))).is_err()); // codespell:ignore timout
    assert!(JsSearch::new("aGVsbG8=", options(json!({"sensitivity": "max"}))).is_err());
    // Numbers JSON can't hold, which JSON.stringify would turn into null (the default)
    for bad in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        for field in ["timeout", "timeoutMs", "previewChars"] {
            let options = raw(object_with(field, JsValue::from_f64(bad)));
            assert!(
                JsSearch::new("aGVsbG8=", Some(options)).is_err(),
                "{field}: {bad}"
            );
        }
    }
    // Only a plain object is options
    let array = js_sys::Array::of1(&JsValue::from_f64(5.0));
    assert!(JsSearch::new("aGVsbG8=", Some(raw(array.into()))).is_err());
    assert!(JsSearch::new("aGVsbG8=", Some(raw(JsValue::from_f64(5.0)))).is_err());
    let map = js_sys::Map::new();
    assert!(JsSearch::new("aGVsbG8=", Some(raw(map.into()))).is_err());
    // null fields are the defaults
    let nulls = options(json!({"timeout": null, "topResults": null, "sensitivity": null}));
    assert!(JsSearch::new("aGVsbG8=", nulls).is_ok());

    let mut search = JsSearch::new("aGVsbG8=", None).unwrap();
    assert!(search.step(-5.0).is_err());
    assert!(search.step(f64::NAN).is_err());
    assert!(search.step(f64::NEG_INFINITY).is_err());
}

#[test]
fn statuses_and_character_counts() {
    // Infinity runs the search to its end in one step; nothing to search is "not_found"
    let mut search = JsSearch::new("", None).unwrap();
    let update = json(search.step(f64::INFINITY).unwrap());
    assert_eq!(update["status"], "not_found");
    assert_eq!(search.status(), "not_found");
    let mut search = JsSearch::new("AAAA", options(json!({"timeoutMs": 200}))).unwrap();
    assert_eq!(
        json(search.step(f64::INFINITY).unwrap())["status"],
        "timed_out"
    );

    // Lengths and previews count characters (code points), not UTF-16 units or bytes
    let input = "Ünïcödé 😀😀 日本語";
    let mut search = JsSearch::new(input, options(json!({"previewChars": 9}))).unwrap();
    let root = json(search.step(0.0).unwrap())["nodes"][0].clone();
    assert_eq!(root["text"], "Ünïcödé 😀");
    assert_eq!(root["length"], input.chars().count());
}

#[test]
fn detect_plaintext_and_the_decoder_list() {
    let found = json(detect_plaintext_js("192.168.0.1", None).unwrap());
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
        detect_options(json!({"checkers": ["english"], "sensitivity": "low"})),
    )
    .unwrap();
    assert_eq!(json(none), Value::Null);
    assert!(detect_plaintext_js("x", detect_options(json!({"checkers": ["nope"]}))).is_err());

    let decoders = json(list_decoders().unwrap());
    let base64 = decoders
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["name"] == "Base64")
        .unwrap();
    assert_eq!(base64["id"], "base64");
    assert!(base64["keyFormat"].is_null());
    assert_eq!(ciphey_version(), ciphey::VERSION);
}
