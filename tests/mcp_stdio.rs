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
    assert_eq!(names, ["decode", "list_decoders"]);
    let decode = tools.iter().find(|tool| tool["name"] == "decode").unwrap();
    assert_eq!(
        decode["inputSchema"]["required"],
        json!(["text"]),
        "{decode}"
    );
    assert_eq!(decode["annotations"]["readOnlyHint"], true, "{decode}");
    assert!(decode["outputSchema"].is_object(), "{decode}");

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
    for name in ["Base64", "caesar", "Vigenere", "Morse Code"] {
        let decoder = decoders
            .iter()
            .find(|decoder| decoder["name"] == name)
            .unwrap_or_else(|| panic!("{name} missing from {result}"));
        assert!(decoder["description"].is_string(), "{decoder}");
        assert!(decoder["tags"].is_array(), "{decoder}");
    }

    assert_eq!(client.shut_down().code(), Some(0));
}

#[test]
fn worker_stops_when_over_its_memory_budget() {
    // Each decode runs in `ciphey-mcp --worker`. A one-byte budget is exceeded at the
    // watchdog's first check, and this search can't finish within its 20 seconds.
    let request = json!({
        "text": random_looking_text(512),
        "timeout_secs": 20,
        "regex": "^impossible crib [0-9]{40}$",
        "max_memory_bytes": 1,
    });
    let started = Instant::now();
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
    assert!(
        started.elapsed() < Duration::from_secs(15),
        "{:?}",
        started.elapsed()
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let response: Value = serde_json::from_str(stdout.trim()).unwrap();
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
        "text": random_looking_text(512),
        "timeout_secs": 30,
        "regex": "^impossible crib [0-9]{40}$",
        "max_memory_bytes": 1u64 << 30,
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
