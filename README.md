<p align="center">
  <a href="https://cdn.jsdelivr.net/gh/bee-san/Ciphey@d41d19946234477346fede14dadf8c351cc469e6/media/tui-video/out/ciphey-tui-promo.mp4"><img src="https://cdn.jsdelivr.net/gh/bee-san/Ciphey@d41d19946234477346fede14dadf8c351cc469e6/media/tui-video/out/preview.gif" alt="Ciphey in a terminal: four layers of Base64 go in, Ciphey asks whether 'Ciphey peels back every layer of encoding' is the plaintext, then prints it with the path Base64 → Base64 → Base64 → Base64. Click to watch the one-minute tour."></a>
</p>

<h1 align="center">Ciphey</h1>

<p align="center">
  <b>Paste in text that's been encoded or encrypted. Ciphey works out how and hands you the plaintext.</b><br>
  No key, no cipher name, no hints. Base64, hex, Caesar/ROT13, Vigenère, Morse code and 19 more, several layers deep.
</p>

<p align="center">
  <a href="https://crates.io/crates/ciphey"><img alt="crates.io" src="https://img.shields.io/crates/v/ciphey"></a>
  <a href="https://docs.rs/ciphey"><img alt="docs.rs" src="https://img.shields.io/docsrs/ciphey"></a>
  <a href="LICENSE"><img alt="MIT license" src="https://img.shields.io/badge/license-MIT-blue"></a>
</p>

<p align="center">
  <a href="#install">Install</a> ·
  <a href="#quick-start">Quick start</a> ·
  <a href="#features">Features</a> ·
  <a href="#use-it-as-a-library">Library</a> ·
  <a href="#mcp-server-ai-assistants">MCP</a> ·
  <a href="#documentation">Docs</a> ·
  <a href="http://discord.skerritt.blog">Discord</a>
  <br><sub>▶ <a href="https://cdn.jsdelivr.net/gh/bee-san/Ciphey@d41d19946234477346fede14dadf8c351cc469e6/media/tui-video/out/ciphey-tui-promo.mp4">Watch the one-minute tour</a> (MP4, 61 s)</sub>
</p>

## Install

```bash
cargo install ciphey
```

Prebuilt binaries for Linux (x86_64), macOS (Intel and Apple silicon) and Windows (x86_64) are on the [releases page](https://github.com/bee-san/Ciphey/releases/latest), each with a `.sha256` checksum.

To build from source, you need a Rust toolchain:

```bash
git clone https://github.com/bee-san/Ciphey
cd Ciphey
cargo build --release    # the binary is target/release/ciphey
```

Or skip installing: join the [Discord server](http://discord.skerritt.blog), go to `#bots` and type `$ciphey <your text>` (`$help` lists the commands).

## Quick start

```console
$ ciphey -t 'aGVsbG8gdGhlcmUgZ2VuZXJhbA=='
🕵️ I think the plaintext is Words.
Possible plaintext: 'hello there general' (y/N):
y

🥳 ciphey has decoded 64 times.

The plaintext is:
hello there general
the decoder used is Base64
```

The first time you run it, a short setup asks for a colour theme, how you want results shown and whether to use a wordlist, and saves your answers to `~/.ciphey/config.toml`.

```bash
ciphey -t 'NTA3NjYzNzU3MjZjMjA3NjY2MjA2OTcyNjU2YzIwNzM2ZTY2Njc='   # ROT13 → hex → Base64, nothing else needed
ciphey -f secret.txt                    # read the input from a file
ciphey -d -t '...'                      # no y/N prompt: take the first plaintext found (handy in scripts)
ciphey -c 15 -t '...'                   # keep searching for up to 15 seconds (the default is 5)
ciphey -r 'flag\{' -t '...'             # only accept plaintext that matches a regex (a crib)
ciphey --wordlist words.txt -t '...'    # also accept any exact match from a wordlist
```

`ciphey --help` lists every option.

## Features

### ⚡ Fast

<a href="https://cdn.jsdelivr.net/gh/bee-san/Ciphey@d41d19946234477346fede14dadf8c351cc469e6/media/tui-video/out/fast.mp4"><img src="https://cdn.jsdelivr.net/gh/bee-san/Ciphey@d41d19946234477346fede14dadf8c351cc469e6/media/tui-video/out/fast.gif" alt="A terminal runs time ciphey -d on a Base64 string. Ciphey prints 'Ciphey is very fast' and the path Base64 → Hexadecimal → caesar, and bash reports real 0m0.157s. A chart then compares Ciphey's 0.19 s (the median of 10 runs) with no answer after 60 s for Python Ciphey 5.14.0 on the same input."></a>

<sub>▶ <a href="https://cdn.jsdelivr.net/gh/bee-san/Ciphey@d41d19946234477346fede14dadf8c351cc469e6/media/tui-video/out/fast.mp4">Watch the clip</a> (16 s)</sub>

Three layers (ROT13, then hex, then Base64) come off in 0.16 s, measured by bash's `time` in a real recording. Here is the same comparison for more inputs, against Python Ciphey 5.14, the version Ciphey replaces:

| Input | Ciphey | Python Ciphey 5.14 |
| --- | --- | --- |
| Base64 | 0.11 s | 0.92 s |
| Hex → Base64 | 0.14 s | 1.02 s |
| ROT13 → Hex → Base64 | 0.19 s | no answer within 60 s |
| URL → Base64 → Hex | 0.24 s | 1.15 s |
| Base64 ×4 | 0.41 s | 0.78 s |
| Hex → Base32 → Base64 → Hex | 0.54 s | 0.72 s, wrong answer |
| ROT13 → Hex → Base64 → Base32 | 1.15 s | no answer within 60 s |

<sub>Wall-clock median of 10 runs per input (Python Ciphey: 3) on a shared 16-CPU Linux machine, Ciphey at 47bd16d6 with the y/N prompt off and a fresh <code>$HOME</code> per run so its cache can't help. Every run was capped at 60 s. The script and raw numbers are in <a href="https://github.com/bee-san/Ciphey/tree/media/readme-videos/media/tui-video/bench"><code>media/tui-video/bench</code></a> on the <code>media/readme-videos</code> branch.</sub>

Where both get the right answer, Ciphey is 1.9 to 8.6 times faster. Where does the speed come from?

- It's Rust.
- An A* search tries the most promising chains of decoders first.
- Every decoder runs in parallel with [Rayon](https://github.com/rayon-rs/rayon), on up to 10 candidate texts at a time.
- Answers are cached in `~/.ciphey/database.sqlite`, so the same input a second time comes back in milliseconds.

### 🧅 Layer after layer, no key needed

Ciphey doesn't need to be told what it's looking at. It searches chains of decoders (Base64 inside hex inside ROT13, four layers of Base64, and so on) and stops at the first candidate that looks like plaintext. By default it shows you that candidate and asks before accepting it (`-d` turns this off). The clip at the top of this page shows a four-layer decode.

There is also a timer: if Ciphey hasn't found anything after 5 seconds, it stops and says so (`-c` changes the limit).

It knows 24 decoders and crackers:

| Kind | Decoders |
| --- | --- |
| Base encodings | Base64 (standard and URL-safe), Base32, Base58 (Bitcoin, Flickr, Monero, Ripple), Base91, Base65536, Z85 |
| Other encodings | Hexadecimal, binary, URL (percent-encoding), Morse code, Braille, A1Z26, Citrix CTX1 |
| Ciphers | Caesar (including ROT13), ROT47, Atbash, Vigenère (it works out the key itself), rail fence, reversed text |
| Oddities | Brainfuck (it runs the program), Morse or binary written with other symbols |

More are on the way: [#1030](https://github.com/bee-san/Ciphey/issues/1030) tracks 109 decoders that aren't in yet.

### 🕵️ Knows what it found

<a href="https://cdn.jsdelivr.net/gh/bee-san/Ciphey@d41d19946234477346fede14dadf8c351cc469e6/media/tui-video/out/lemmeknow.mp4"><img src="https://cdn.jsdelivr.net/gh/bee-san/Ciphey@d41d19946234477346fede14dadf8c351cc469e6/media/tui-video/out/lemmeknow.gif" alt="Three Ciphey runs. Base64 decodes to 'mount -o username=bee,password=hunter2', identified as a Mount Command With Clear Credentials. Base64 decodes to an otpauth:// link, identified as a Time-Based One-Time Password (TOTP) URI. Hex decodes to 192.168.0.1, identified as an Internet Protocol (IP) Address Version 4."></a>

<sub>▶ <a href="https://cdn.jsdelivr.net/gh/bee-san/Ciphey@d41d19946234477346fede14dadf8c351cc469e6/media/tui-video/out/lemmeknow.mp4">Watch the clip</a> (21 s)</sub>

Every candidate plaintext also goes through [LemmeKnow](https://github.com/swanandx/lemmeknow), the Rust port of [pyWhat](https://github.com/bee-san/pyWhat), which recognises more than 120 formats. So Ciphey doesn't just decode the string, it tells you what it is: a password in a `mount` or `sshpass` command, a TOTP secret, a GitHub token or Stripe key, an IP or MAC address, an email address or URL, a card number, a crypto wallet, an AWS ARN or a CTF flag.

```console
$ ciphey -t '3139322e3136382e302e31'
🕵️ I think the plaintext is Internet Protocol (IP) Address Version 4.
Possible plaintext: '192.168.0.1' (y/N):
```

### 🎯 Crib and regex mode

<a href="https://cdn.jsdelivr.net/gh/bee-san/Ciphey@d41d19946234477346fede14dadf8c351cc469e6/media/tui-video/out/crib.mp4"><img src="https://cdn.jsdelivr.net/gh/bee-san/Ciphey@d41d19946234477346fede14dadf8c351cc469e6/media/tui-video/out/crib.gif" alt="A terminal runs ciphey -t on a Base64 string with -r 'picoCTF\{'. Ciphey reports 'Regex matched: picoCTF\{', asks about 'picoCTF{b4s3_64_1s_fun}', and prints it as the plaintext, decoded with Base64."></a>

<sub>▶ <a href="https://cdn.jsdelivr.net/gh/bee-san/Ciphey@d41d19946234477346fede14dadf8c351cc469e6/media/tui-video/out/crib.mp4">Watch the clip</a> (14.5 s)</sub>

If you know part of the answer (the flag format, a word that has to be in there, how it starts), give it to Ciphey as a regex with `-r`. The other checkers switch off and only text that matches is accepted. This finds plaintext the English detection would pass over: Base64-encoded `picoCTF{b4s3_64_1s_fun}` comes back as gibberish by default, but with `-r 'picoCTF\{'` it's the first match.

`--wordlist words.txt` works the same way for exact matches: a candidate that is a line in the file counts as plaintext.

### 🎨 Made for your terminal

The first-run setup lets you pick a colour theme (Capptucin, Darcula, GirlyPop, the default, or your own RGB values) and choose between being asked about each plaintext or getting a list of candidates at the end. You can see it [in the tour](https://cdn.jsdelivr.net/gh/bee-san/Ciphey@d41d19946234477346fede14dadf8c351cc469e6/media/tui-video/out/ciphey-tui-promo.mp4) from 0:32. Everything is saved to `~/.ciphey/config.toml`, which you can edit later.

### 📚 Library first

The `ciphey` binary is a thin wrapper around the `ciphey` crate. The [Discord bot](https://github.com/bee-san/discord-bot) uses it as well, and so can your code.

## Use it as a library

`perform_cracking` runs the whole search, as the `ciphey` binary does:

```rust
use ciphey::config::Config;
use ciphey::{perform_cracking, CipheyError};

fn main() {
    let mut config = Config::default();
    config.timeout = 5; // seconds
    config.human_checker_on = false; // never prompt on stdin
    config.api_mode = true; // don't print progress to stdout
    // config.regex = Some(r"flag\{".to_string()); // only accept plaintext matching a crib

    match perform_cracking("aGVsbG8gdGhlcmUgZ2VuZXJhbA==", config) {
        Ok(Some(result)) => {
            let path: Vec<&str> = result.path.iter().map(|step| step.decoder).collect();
            println!("{} (via {})", result.text[0], path.join(" → "));
        }
        Ok(None) => println!("no plaintext found"),
        Err(CipheyError::Timeout { secs }) => println!("gave up after {secs}s"),
        Err(e) => eprintln!("error: {e}"),
    }
}
```

This prints `hello there general (via Base64)`.

### One decoder

If you know what you're looking at, call that decoder. Each one is a function in `ciphey::decoders`: encodings come back decoded, ciphers are cracked, and the ones that take a key can decrypt with yours.

```rust
use ciphey::decoders;

let decoded = decoders::base64("aGVsbG8gd29ybGQ=");
assert_eq!(decoded.candidates[0].text, "hello world");

// No key: Ciphey tries every shift and marks the one its checks accept
let cracked = decoders::caesar("Uryyb jbeyq");
let plaintext = cracked.plaintext().expect("a shift reads as English");
assert_eq!(plaintext.text, "Hello world");
assert_eq!(plaintext.key.as_deref(), Some("13"));

// With the key
let decrypted = decoders::vigenere_with_key("Rijvs uyvjn", "KEY")?;
assert_eq!(decrypted.candidates[0].text, "Hello world");
```

To choose the decoder at run time, `decode_with` takes its name or an alias, and `list_decoders` lists them all with their aliases, tags and the key they take:

```rust
use ciphey::{decode_with, list_decoders, DecodeOptions};

let cracked = decode_with("rot13", "Uryyb jbeyq", &DecodeOptions::default())?;
let decrypted = decode_with("affine", "IHHWVC SWFRCP", &DecodeOptions::with_key("a=5, b=8"))?;

for decoder in list_decoders() {
    println!("{}: {}", decoder.name, decoder.key_format.unwrap_or("no key"));
}
```

Nothing is filtered out: you get what the decoder hands on to the search. The candidate Ciphey's plaintext checks accept comes first and carries a `detection`; if they accept none, you get the decodings unmarked, for you to judge (all 25 Caesar shifts, say, though crackers with many keys hand on only their best few).

### Is it plaintext?

`detect_plaintext` runs the checks the search uses (a regex crib, a wordlist, LemmeKnow, common passwords and English) and says which one accepted the text and what it took it for:

```rust
use ciphey::detection::{detect_plaintext, CheckerKind, DetectOptions, Sensitivity};

let found = detect_plaintext("192.168.0.1", &DetectOptions::default()).unwrap();
assert_eq!(found.checker, CheckerKind::LemmeKnow);
assert_eq!(found.description, "Internet Protocol (IP) Address Version 4");
assert_eq!(found.confidence, Some(0.7)); // the format's rarity in pyWhat

// Pick the checkers and how strict the English checker is, or give a crib
let english_only = DetectOptions::new()
    .checkers([CheckerKind::English])
    .sensitivity(Sensitivity::Low);
let crib = DetectOptions::new().regex(r"^flag\{")?;
```

`cargo run --example decode` tours all of this, and `cargo run --example decode -- list` lists the decoders.

- `perform_cracking` returns `Result<Option<DecoderResult>, CipheyError>` on `master` ([#915](https://github.com/bee-san/Ciphey/pull/915)), and the single-decoder and detection functions are only on `master` so far. The last release on crates.io (0.12.0) still returns `Option<DecoderResult>`, so until the next release use the git version: `ciphey = { git = "https://github.com/bee-san/Ciphey" }`.
- The config is global to the process. The first call's `Config` is used for every later call, and the single decoders follow it too (a `regex` crib, a wordlist). They never prompt.
- The API is documented on [docs.rs](https://docs.rs/ciphey).

## MCP server (AI assistants)

<a href="https://cdn.jsdelivr.net/gh/bee-san/Ciphey@5aa9760b2912611755d037c01b9d2ed14fd3bf81/media/mcp-video/out/ciphey-mcp.mp4"><img src="https://cdn.jsdelivr.net/gh/bee-san/Ciphey@5aa9760b2912611755d037c01b9d2ed14fd3bf81/media/mcp-video/out/ciphey-mcp.gif" alt="An AI assistant (Kiro CLI) is asked to decode a Base64 string from a CTF challenge. It calls ciphey's decode tool over MCP, which returns the plaintext flag{ciphey_speaks_mcp} and the decoders it used, Base64 → Hexadecimal → caesar with key 13. The assistant then answers with the flag. Click to watch the 30-second video."></a>

<sub>▶ <a href="https://cdn.jsdelivr.net/gh/bee-san/Ciphey@5aa9760b2912611755d037c01b9d2ed14fd3bf81/media/mcp-video/out/ciphey-mcp.mp4">Watch the video</a> (29.5 s). The chat replays a real Kiro CLI session with ciphey-mcp.</sub>

`ciphey-mcp` is a [Model Context Protocol](https://modelcontextprotocol.io) server, so AI assistants such as Claude Desktop and Kiro can decode text with Ciphey. It's behind the `mcp` feature, so the normal `ciphey` build doesn't include it:

```sh
cargo install ciphey --features mcp --bin ciphey-mcp
# or, from a clone of this repository:
cargo install --path . --features mcp --bin ciphey-mcp
```

The `mcp` feature isn't in a crates.io release yet (0.12.0 is the latest), so until the next one, install from git: `cargo install --git https://github.com/bee-san/Ciphey ciphey --features mcp --bin ciphey-mcp`.

It provides two tools:

- `decode` decodes `text` and returns the `plaintext` and the `path` of decoders used, with keys such as the Caesar shift. Optional arguments: `timeout_secs` (1 to 30, default 10) and `regex`, a crib the plaintext must match, such as `flag\{`.
- `list_decoders` lists the encodings and ciphers Ciphey supports.

A `decode` result looks like this. `status` is `decoded`, `not_found` or `timed_out`.

```json
{
  "status": "decoded",
  "plaintext": "hello there general",
  "path": [{ "decoder": "Base64", "key": null }],
  "checker": "English Checker",
  "timeout_secs": 10
}
```

Each decode runs in its own short-lived process. Input is limited to 65,536 characters, the search to 30 seconds and memory to 1 GiB, and at most two decodes run at once. The server doesn't read or write `~/.ciphey`, so there's no config file and no cache.

### Claude Desktop

Open Settings → Developer → Edit Config, add the server to `claude_desktop_config.json`, then restart Claude Desktop. Use the full path printed by `which ciphey-mcp` (`where ciphey-mcp` on Windows, for example `C:\\Users\\you\\.cargo\\bin\\ciphey-mcp.exe`), because Claude Desktop may not see your shell's `PATH`.

```json
{
  "mcpServers": {
    "ciphey": {
      "command": "/Users/you/.cargo/bin/ciphey-mcp"
    }
  }
}
```

### Kiro

```sh
kiro-cli mcp add --name ciphey --command ciphey-mcp
```

Or add the entry below to `~/.kiro/settings/mcp.json` (all projects) or `.kiro/settings/mcp.json` (one project).

### Other clients

Most MCP clients take the same `mcpServers` entry: a stdio server started by `ciphey-mcp` with no arguments.

```json
{
  "mcpServers": {
    "ciphey": {
      "command": "ciphey-mcp",
      "args": []
    }
  }
}
```

## Good to know

- Plaintext detection isn't perfect. Very short phrases, text that isn't English, JSON and unusual flag formats can be missed or mistaken for something else. [#1031](https://github.com/bee-san/Ciphey/issues/1031) has the details and the planned fixes. If you know anything about the answer, a crib (`-r`) or a wordlist helps a lot.
- If a cached answer is wrong, delete `~/.ciphey/database.sqlite` to clear the cache.
- If you're stuck, ask in `#coded-messages` on [Discord](http://discord.skerritt.blog).

## Documentation

- [API docs on docs.rs](https://docs.rs/ciphey)
- [The `docs/` folder](docs/), including an [overview](docs/ares_overview.md), the [architecture](docs/ares_architecture.md), [how the A* search works](docs/astar.md) and [how plaintext is identified](docs/plaintext_identification.md)
- [Ciphey 2 documentation](https://broadleaf-angora-7db.notion.site/Ciphey2-32d5eea5d38b40c5b95a9442b4425710) on Notion
- [Introducing Ares](https://skerritt.blog/introducing-ares/), the blog post about the Rust rewrite (it was called Ares before it became Ciphey)

## Contributing

Bug reports, ideas and pull requests are welcome in [issues](https://github.com/bee-san/Ciphey/issues). A new decoder is a good first contribution: pick one from [#1030](https://github.com/bee-san/Ciphey/issues/1030), and copy the shape of an existing one in [`src/decoders/`](src/decoders/). You can also [sponsor the project](https://github.com/sponsors/bee-san).

<a href="https://github.com/bee-san/Ciphey/graphs/contributors"><img src="https://contrib.rocks/image?repo=bee-san/Ciphey" alt="Avatars of the people who have contributed to Ciphey"></a>

## Credits

- [LemmeKnow](https://github.com/swanandx/lemmeknow) by [@swanandx](https://github.com/swanandx) identifies what Ciphey finds, and [gibberish-or-not](https://github.com/bee-san/gibberish-or-not) decides whether it's English.
- [Rayon](https://github.com/rayon-rs/rayon) runs the decoders in parallel.
- Ciphey started as a Python project; Python Ciphey 5.x is still on [PyPI](https://pypi.org/project/ciphey/). Thank you to everyone who worked on it.
- The videos are made with [HyperFrames](https://hyperframes.heygen.com/) from real terminal recordings. The source, recordings and build script are in [`media/tui-video`](https://github.com/bee-san/Ciphey/tree/media/readme-videos/media/tui-video) on the `media/readme-videos` branch.

## AI use

We use AI for 2 things:

1. The TUI is entirely vibe coded.
2. I made AI spend hours researching every single CTF challenge out there. It created a list of 15,071 CTFs. It then went through every single CTF and looked for writeups. In those writeups it looked for anything related to encoding / decoding. It then created tests out of those. This enabled us to increase our testing coverage and make sure all CTF encoding / decoding challenges are solvable with this tool.

## License

MIT. See [LICENSE](LICENSE).
