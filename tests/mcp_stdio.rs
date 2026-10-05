//! Drives the `ciphey-mcp` binary over stdio with raw JSON-RPC, the way an MCP client does:
//! initialize → tools/list → tools/call. Only built with `--features mcp`.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

/// Generous, because debug builds and shared CI machines are slow.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(90);

/// A minimal MCP client speaking newline-delimited JSON-RPC to a `ciphey-mcp` child process.
struct McpClient {
    child: Child,
    stdin: Option<ChildStdin>,
    lines: Receiver<String>,
    next_id: u64,
}

impl McpClient {
    fn start() -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_ciphey-mcp"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("failed to start ciphey-mcp");
        let stdout = child.stdout.take().expect("stdout is piped");
        let (sender, lines) = mpsc::channel();
        // Read on a thread so a hung server fails the test instead of blocking it forever.
        thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if sender.send(line).is_err() {
                    break;
                }
            }
        });
        let stdin = child.stdin.take();
        Self {
            child,
            stdin,
            lines,
            next_id: 1,
        }
    }

    fn send(&mut self, message: &Value) {
        let stdin = self.stdin.as_mut().expect("stdin is open");
        writeln!(stdin, "{message}").expect("failed to write to ciphey-mcp");
        stdin.flush().expect("failed to flush ciphey-mcp's stdin");
    }

    fn notify(&mut self, method: &str) {
        self.send(&json!({ "jsonrpc": "2.0", "method": method }));
    }

    /// Sends a request and waits for the response with the same id.
    fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        self.send(&json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }));
        loop {
            let line = self
                .lines
                .recv_timeout(RESPONSE_TIMEOUT)
                .unwrap_or_else(|error| panic!("no response to {method}: {error}"));
            // stdout is the protocol channel: every line on it must be a JSON-RPC message.
            let message: Value = serde_json::from_str(&line)
                .unwrap_or_else(|error| panic!("stdout line is not JSON ({error}): {line}"));
            assert_eq!(message["jsonrpc"], "2.0", "{message}");
            if message["id"] == json!(id) {
                return message;
            }
        }
    }

    /// Calls a tool and returns the `CallToolResult`.
    fn call_tool(&mut self, name: &str, arguments: Value) -> Value {
        let response = self.request(
            "tools/call",
            json!({ "name": name, "arguments": arguments }),
        );
        assert!(
            response.get("error").is_none(),
            "tools/call {name} failed: {response}"
        );
        response["result"].clone()
    }

    /// Closes stdin, which ends the session, and waits for the server to exit.
    fn shut_down(mut self) -> ExitStatus {
        drop(self.stdin.take());
        let deadline = Instant::now() + RESPONSE_TIMEOUT;
        loop {
            if let Some(status) = self.child.try_wait().expect("failed to poll ciphey-mcp") {
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "ciphey-mcp did not exit after stdin closed"
            );
            thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Drop for McpClient {
    fn drop(&mut self) {
        // Don't leave a server behind if an assertion failed.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Starts a server and completes the `initialize` handshake.
fn initialized_client() -> McpClient {
    let mut client = McpClient::start();
    let response = client.request(
        "initialize",
        json!({
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": { "name": "ciphey-mcp-tests", "version": "0.0.0" },
        }),
    );
    let result = &response["result"];
    assert_eq!(result["protocolVersion"], "2025-11-25", "{response}");
    assert_eq!(result["serverInfo"]["name"], "ciphey", "{response}");
    assert_eq!(
        result["serverInfo"]["version"],
        env!("CARGO_PKG_VERSION"),
        "{response}"
    );
    assert!(result["capabilities"]["tools"].is_object(), "{response}");
    assert!(result["instructions"].is_string(), "{response}");
    client.notify("notifications/initialized");
    client
}

#[test]
fn initialize_list_tools_and_decode() {
    let mut client = initialized_client();

    let response = client.request("tools/list", json!({}));
    let tools = response["result"]["tools"]
        .as_array()
        .unwrap_or_else(|| panic!("no tools in {response}"));
    let mut names: Vec<&str> = tools
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect();
    names.sort_unstable();
    assert_eq!(
        names,
        ["decode", "decode_with", "detect_plaintext", "list_decoders"]
    );
    for tool in tools {
        assert_eq!(tool["annotations"]["readOnlyHint"], true, "{tool}");
        assert!(tool["outputSchema"].is_object(), "{tool}");
        assert!(tool["description"].is_string(), "{tool}");
    }
    let required = |name: &str| {
        let tool = tools.iter().find(|tool| tool["name"] == name).unwrap();
        tool["inputSchema"]["required"].clone()
    };
    assert_eq!(required("decode"), json!(["text"]));
    assert_eq!(required("decode_with"), json!(["decoder", "text"]));
    assert_eq!(required("detect_plaintext"), json!(["text"]));

    let result = client.call_tool("decode", json!({ "text": "aGVsbG8gdGhlcmUgZ2VuZXJhbA==" }));
    assert_eq!(result["isError"], false, "{result}");
    let output = &result["structuredContent"];
    assert_eq!(output["status"], "decoded", "{result}");
    assert_eq!(output["plaintext"], "hello there general", "{result}");
    assert_eq!(
        output["path"],
        json!([{ "decoder": "Base64", "key": null }]),
        "{result}"
    );
    // Clients without structured output support read the same JSON from the text block.
    let text: Value = serde_json::from_str(result["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(&text, output);

    assert_eq!(client.shut_down().code(), Some(0));
}

#[test]
fn each_decode_gets_its_own_settings() {
    let mut client = initialized_client();

    // base64("the flag is ctf{m4k3_1t_s1mpl3}"), found through the crib.
    let result = client.call_tool(
        "decode",
        json!({ "text": "dGhlIGZsYWcgaXMgY3Rme200azNfMXRfczFtcGwzfQ==", "regex": r"ctf\{" }),
    );
    let output = &result["structuredContent"];
    assert_eq!(output["status"], "decoded", "{result}");
    assert_eq!(
        output["plaintext"], "the flag is ctf{m4k3_1t_s1mpl3}",
        "{result}"
    );
    assert_eq!(output["checker"], "Regex Checker", "{result}");

    // The library's config can only be set once per process. The crib from the previous call
    // must not leak into this one, or "hello there general" would never be accepted.
    let result = client.call_tool(
        "decode",
        json!({ "text": "aGVsbG8gdGhlcmUgZ2VuZXJhbA==", "timeout_secs": 7 }),
    );
    let output = &result["structuredContent"];
    assert_eq!(output["plaintext"], "hello there general", "{result}");
    assert_ne!(output["checker"], "Regex Checker", "{result}");
    assert_eq!(output["timeout_secs"], 7, "{result}");

    assert_eq!(client.shut_down().code(), Some(0));
}

#[test]
fn invalid_arguments_are_tool_errors() {
    let mut client = initialized_client();

    // Tool errors (isError) rather than JSON-RPC errors, so the model sees what to fix.
    for (arguments, expected) in [
        (json!({ "text": "" }), "`text` is empty"),
        (
            json!({ "text": "aGk=", "timeout_secs": 3600 }),
            "`timeout_secs` must be between 1 and 30",
        ),
        (
            json!({ "text": "aGk=", "regex": "(unclosed" }),
            "not a valid regular expression",
        ),
        (json!({ "text": "a".repeat(65_537) }), "the limit is 65536"),
    ] {
        let result = client.call_tool("decode", arguments);
        assert_eq!(result["isError"], true, "{result}");
        let message = result["content"][0]["text"].as_str().unwrap();
        assert!(message.contains(expected), "{message}");
    }

    // Arguments that don't fit the schema are tool errors as well.
    let result = client.call_tool("decode", json!({ "timeout_secs": 5 }));
    assert_eq!(result["isError"], true, "{result}");
    let message = result["content"][0]["text"].as_str().unwrap();
    assert!(message.contains("missing field `text`"), "{message}");

    assert_eq!(client.shut_down().code(), Some(0));
}

#[test]
fn list_decoders_describes_each_decoder() {
    let mut client = initialized_client();

    let result = client.call_tool("list_decoders", json!({}));
    assert_eq!(result["isError"], false, "{result}");
    let decoders = result["structuredContent"]["decoders"]
        .as_array()
        .unwrap_or_else(|| panic!("no decoders in {result}"));
    let find = |id: &str| {
        decoders
            .iter()
            .find(|decoder| decoder["id"] == id)
            .unwrap_or_else(|| panic!("{id} missing from {result}"))
    };
    for (id, name) in [
        ("base64", "Base64"),
        ("caesar", "caesar"),
        ("vigenere", "Vigenere"),
        ("morse", "Morse Code"),
    ] {
        let decoder = find(id);
        assert_eq!(decoder["name"], name, "{decoder}");
        assert!(decoder["description"].is_string(), "{decoder}");
        assert!(decoder["tags"].is_array(), "{decoder}");
        assert!(decoder["aliases"].is_array(), "{decoder}");
    }
    // What decode_with needs to know: other names, and the key a cipher takes.
    let caesar = find("caesar");
    assert!(
        caesar["aliases"]
            .as_array()
            .unwrap()
            .contains(&json!("rot13")),
        "{caesar}"
    );
    assert!(caesar["key_format"].is_string(), "{caesar}");
    assert_eq!(find("base64")["key_format"], Value::Null);

    assert_eq!(client.shut_down().code(), Some(0));
}

/// Calls `decode_with`, expecting success, and returns its structured result.
fn decode_with(client: &mut McpClient, arguments: Value) -> Value {
    successful_call(client, "decode_with", arguments)
}

/// Calls `detect_plaintext`, expecting success, and returns its structured result.
fn detect(client: &mut McpClient, arguments: Value) -> Value {
    successful_call(client, "detect_plaintext", arguments)
}

/// Calls `tool`, checks that it succeeded, and returns its structured result.
fn successful_call(client: &mut McpClient, tool: &str, arguments: Value) -> Value {
    let result = client.call_tool(tool, arguments);
    assert_eq!(result["isError"], false, "{result}");
    // Clients without structured output support read the same JSON from the text block.
    let text: Value = serde_json::from_str(result["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(text, result["structuredContent"]);
    text
}

#[test]
fn decode_with_cracks_decodes_and_decrypts() {
    let mut client = initialized_client();

    // Cracked: every shift is tried, and the one that reads as English passes the check.
    let output = decode_with(
        &mut client,
        json!({ "decoder": "rot13", "text": "Uryyb jbeyq" }),
    );
    assert_eq!(
        output,
        json!({
            "decoder": "caesar",
            "status": "plaintext_found",
            "candidates": [{
                "text": "Hello world",
                "truncated": false,
                "key": "13",
                "is_plaintext": true,
                "detection": { "checker": "english", "description": "Words", "confidence": null },
            }],
            "total_candidates": 1,
        })
    );

    // Decoded, and recognised by LemmeKnow, which says how sure it is.
    let output = decode_with(
        &mut client,
        json!({ "decoder": "hex", "text": "3139322e3136382e302e31" }),
    );
    let candidate = &output["candidates"][0];
    assert_eq!(candidate["text"], "192.168.0.1", "{output}");
    assert_eq!(
        candidate["detection"],
        json!({
            "checker": "lemmeknow",
            "description": "Internet Protocol (IP) Address Version 4",
            "confidence": 0.7,
        })
    );

    // Decrypted with a key: a keyword, two parameters, and a shift sent as a number.
    for (arguments, plaintext, key) in [
        (
            json!({ "decoder": "vigenere", "text": "Rijvs uyvjn", "key": "key" }),
            "Hello world",
            "KEY",
        ),
        (
            json!({ "decoder": "affine", "text": "IHHWVC SWFRCP", "key": "a=5, b=8" }),
            "AFFINE CIPHER",
            "a=5, b=8",
        ),
        (
            json!({ "decoder": "caesar", "text": "Khoor zruog", "key": 23 }),
            "Hello world",
            "23",
        ),
    ] {
        let output = decode_with(&mut client, arguments);
        assert_eq!(output["candidates"][0]["text"], plaintext, "{output}");
        assert_eq!(output["candidates"][0]["key"], key, "{output}");
    }

    assert_eq!(client.shut_down().code(), Some(0));
}

#[test]
fn decode_with_says_whether_each_candidate_is_plaintext() {
    let mut client = initialized_client();

    // No shift reads as English, so all 25 come back for the caller to judge.
    let output = decode_with(
        &mut client,
        json!({ "decoder": "caesar", "text": "xqzjv kplmw" }),
    );
    assert_eq!(output["status"], "no_plaintext", "{output}");
    assert_eq!(output["total_candidates"], 25, "{output}");
    let candidates = output["candidates"].as_array().unwrap();
    assert_eq!(candidates.len(), 25);
    for candidate in candidates {
        assert_eq!(candidate["is_plaintext"], false, "{candidate}");
        assert_eq!(candidate["detection"], Value::Null, "{candidate}");
    }

    // Not Base64 at all.
    let output = decode_with(&mut client, json!({ "decoder": "base64", "text": "!!!" }));
    assert_eq!(output["status"], "no_candidates", "{output}");
    assert_eq!(output["candidates"], json!([]), "{output}");

    // A crib lets the cracker accept a flag that isn't English...
    let output = decode_with(
        &mut client,
        json!({ "decoder": "caesar", "text": "synt{ebg_guvegrra}", "regex": r"^flag\{" }),
    );
    let candidate = &output["candidates"][0];
    assert_eq!(candidate["text"], "flag{rot_thirteen}", "{output}");
    assert_eq!(candidate["detection"]["checker"], "regex", "{output}");
    // ...and only applies to its own call.
    let output = decode_with(
        &mut client,
        json!({ "decoder": "caesar", "text": "Uryyb jbeyq" }),
    );
    assert_eq!(
        output["candidates"][0]["detection"]["checker"], "english",
        "{output}"
    );

    assert_eq!(client.shut_down().code(), Some(0));
}

#[test]
fn decode_with_keeps_results_small() {
    let mut client = initialized_client();

    // Cracking ROT47 gives 93 candidates: 93,000 characters for this text. A result holds at
    // most 65,536 characters of text, so the candidate that crosses the limit is cut short
    // and the rest are left out.
    let text: String = "Gur dhvpx oebja sbk whzcf bire gur ynml qbt. "
        .chars()
        .cycle()
        .take(1_000)
        .collect();
    let output = decode_with(&mut client, json!({ "decoder": "rot47", "text": text }));
    assert_eq!(output["total_candidates"], 93, "{}", output["status"]);
    let candidates = output["candidates"].as_array().unwrap();
    let (last, whole) = candidates.split_last().unwrap();
    assert!(whole.len() > 60, "{}", whole.len());
    assert!(whole
        .iter()
        .all(|candidate| candidate["truncated"] == false));
    assert_eq!(last["truncated"], true);
    // Counted as JSON writes the text: some rotations contain `"` and `\`, which take two
    // characters each. The text is ASCII, so this counts bytes.
    let chars: usize = candidates
        .iter()
        .map(|candidate| candidate["text"].to_string().len() - 2)
        .sum();
    assert!((65_535..=65_536).contains(&chars), "{chars}");

    assert_eq!(client.shut_down().code(), Some(0));
}

#[test]
fn detect_plaintext_identifies_text() {
    let mut client = initialized_client();

    let output = detect(&mut client, json!({ "text": "192.168.0.1" }));
    assert_eq!(
        output,
        json!({
            "is_plaintext": true,
            "detection": {
                "checker": "lemmeknow",
                "description": "Internet Protocol (IP) Address Version 4",
                "confidence": 0.7,
            },
            "checkers": ["lemmeknow", "password", "english"],
        })
    );

    let output = detect(&mut client, json!({ "text": "hello there general" }));
    assert_eq!(
        output["detection"],
        json!({ "checker": "english", "description": "Words", "confidence": null })
    );

    // Base64 isn't plaintext until it's decoded.
    let output = detect(
        &mut client,
        json!({ "text": "aGVsbG8gdGhlcmUgZ2VuZXJhbA==" }),
    );
    assert_eq!(output["is_plaintext"], false, "{output}");
    assert_eq!(output["detection"], Value::Null, "{output}");

    // Only the chosen checkers run.
    let output = detect(
        &mut client,
        json!({ "text": "192.168.0.1", "checkers": ["english"] }),
    );
    assert_eq!(output["is_plaintext"], false, "{output}");
    assert_eq!(output["checkers"], json!(["english"]), "{output}");

    // A crib on its own is the only check.
    let output = detect(
        &mut client,
        json!({ "text": "picoCTF{b4s3_64_1s_fun}", "regex": r"^picoCTF\{" }),
    );
    assert_eq!(output["detection"]["checker"], "regex", "{output}");
    assert_eq!(output["checkers"], json!(["regex"]), "{output}");

    // One English word in gibberish: only `high` sensitivity takes it for English.
    let noisy = "Rcl maocr otmwi lit dnoen oehc 13 iron seah.";
    for (sensitivity, is_plaintext) in [("low", false), ("high", true)] {
        let output = detect(
            &mut client,
            json!({ "text": noisy, "sensitivity": sensitivity }),
        );
        assert_eq!(
            output["is_plaintext"], is_plaintext,
            "{sensitivity}: {output}"
        );
    }

    assert_eq!(client.shut_down().code(), Some(0));
}

#[test]
fn decode_with_and_detect_plaintext_reject_bad_arguments() {
    let mut client = initialized_client();

    for (tool, arguments, expected) in [
        (
            "decode_with",
            json!({ "decoder": "rot1300", "text": "hi" }),
            r#"no decoder is called "rot1300""#,
        ),
        (
            "decode_with",
            json!({ "decoder": "base64", "text": "aGk=", "key": "13" }),
            "Base64 doesn't take a key",
        ),
        // Only the decoder can tell, so this one comes back from a worker.
        (
            "decode_with",
            json!({ "decoder": "affine", "text": "IHHWVC", "key": "a=2, b=8" }),
            "invalid key for Affine",
        ),
        (
            "decode_with",
            json!({ "decoder": "base64", "text": "" }),
            "`text` is empty",
        ),
        (
            "decode_with",
            json!({ "decoder": "base64", "text": "A".repeat(65_537) }),
            "the limit is 65536",
        ),
        (
            "decode_with",
            json!({ "decoder": "base64", "text": "aGk=", "regex": "(unclosed" }),
            "not a valid regular expression",
        ),
        (
            "decode_with",
            json!({ "text": "aGk=" }),
            "missing field `decoder`",
        ),
        ("detect_plaintext", json!({ "text": "" }), "`text` is empty"),
        (
            "detect_plaintext",
            json!({ "text": "hi", "checkers": [] }),
            "no checkers to run",
        ),
        (
            "detect_plaintext",
            json!({ "text": "hi", "checkers": ["gibberish"] }),
            "unknown variant `gibberish`",
        ),
        (
            "detect_plaintext",
            json!({ "text": "hi", "sensitivity": "extreme" }),
            "unknown variant `extreme`",
        ),
        (
            "detect_plaintext",
            json!({ "text": "hi", "regex": "a".repeat(1_001) }),
            "the limit is 1000",
        ),
    ] {
        let result = client.call_tool(tool, arguments);
        assert_eq!(result["isError"], true, "{tool}: {result}");
        let message = result["content"][0]["text"].as_str().unwrap();
        assert!(message.contains(expected), "{tool}: {message}");
    }

    assert_eq!(client.shut_down().code(), Some(0));
}

/// Runs `ciphey-mcp --worker` on one request, holding its stdin open as the server does,
/// and returns its response.
fn run_worker(request: &Value) -> Value {
    let mut worker = Command::new(env!("CARGO_BIN_EXE_ciphey-mcp"))
        .arg("--worker")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("failed to start ciphey-mcp --worker");
    let mut stdin = worker.stdin.take().unwrap();
    writeln!(stdin, "{request}").unwrap();
    // Closing stdin would tell the worker the server is gone, so keep it open.
    let output = worker.wait_with_output().unwrap();
    drop(stdin);

    assert!(output.status.success(), "{:?}", output.status);
    let stdout = String::from_utf8(output.stdout).unwrap();
    serde_json::from_str(stdout.trim()).unwrap()
}

#[test]
fn worker_stops_a_call_at_its_time_limit() {
    // decode_with and detect_plaintext calls have no timer of their own, so the worker stops
    // them. Cracking the rail fence on 65,536 characters takes seconds, even in a release
    // build.
    let request = json!({
        "job": {
            "tool": "decode_with",
            "decoder": "railfence",
            "text": random_looking_text(65_536),
            "key": null,
            "regex": null,
        },
        "max_memory_bytes": 1u64 << 30,
        "time_limit_ms": 200,
    });
    let started = Instant::now();

    let response = run_worker(&request);

    assert!(
        started.elapsed() < Duration::from_secs(15),
        "{:?}",
        started.elapsed()
    );
    let message = response["Err"]
        .as_str()
        .unwrap_or_else(|| panic!("{response}"));
    assert!(
        message.contains("`decode_with` stopped after 200 ms"),
        "{message}"
    );
}

#[test]
fn worker_stops_when_over_its_memory_budget() {
    // Each call runs in `ciphey-mcp --worker`. A one-byte budget is exceeded at the
    // watchdog's first check, and this search can't finish within its 20 seconds.
    let request = json!({
        "job": {
            "tool": "decode",
            "text": random_looking_text(512),
            "timeout_secs": 20,
            "regex": "^impossible crib [0-9]{40}$",
        },
        "max_memory_bytes": 1,
        "time_limit_ms": null,
    });
    let started = Instant::now();

    let response = run_worker(&request);

    assert!(
        started.elapsed() < Duration::from_secs(15),
        "{:?}",
        started.elapsed()
    );
    let message = response["Err"]
        .as_str()
        .unwrap_or_else(|| panic!("{response}"));
    assert!(message.contains("MiB of memory"), "{message}");
}

/// `len` letters and digits that decode to nothing, from a fixed-seed generator, so a search
/// over them runs until its timeout.
fn random_looking_text(len: usize) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut state: u32 = 1;
    (0..len)
        .map(|_| {
            state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            char::from(ALPHABET[(state >> 16) as usize % ALPHABET.len()])
        })
        .collect()
}

#[test]
fn worker_exits_when_the_server_goes_away() {
    // The server holds the worker's stdin open; EOF means the server died or gave up.
    let mut worker = Command::new(env!("CARGO_BIN_EXE_ciphey-mcp"))
        .arg("--worker")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("failed to start ciphey-mcp --worker");
    let mut stdin = worker.stdin.take().unwrap();
    let request = json!({
        "job": {
            "tool": "decode",
            "text": random_looking_text(512),
            "timeout_secs": 30,
            "regex": "^impossible crib [0-9]{40}$",
        },
        "max_memory_bytes": 1u64 << 30,
        "time_limit_ms": null,
    });
    writeln!(stdin, "{request}").unwrap();
    thread::sleep(Duration::from_millis(500));
    assert!(
        worker.try_wait().unwrap().is_none(),
        "the search should still be running"
    );
    let started = Instant::now();
    drop(stdin);

    let status = loop {
        if let Some(status) = worker.try_wait().unwrap() {
            break status;
        }
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "worker kept running after stdin closed"
        );
        thread::sleep(Duration::from_millis(20));
    };
    // It gave up without answering, rather than finishing the search.
    assert!(!status.success(), "{status:?}");
    let output = worker.wait_with_output().unwrap();
    assert!(
        output.stdout.is_empty(),
        "{:?}",
        String::from_utf8_lossy(&output.stdout)
    );
}
