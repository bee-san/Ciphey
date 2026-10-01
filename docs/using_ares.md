# Using ciphey: A Comprehensive Guide

## Introduction

This guide provides detailed instructions on how to use ciphey, the next-generation automatic decoding tool. Whether you're using the CLI, the library API, or the Discord bot, this document will help you get the most out of ciphey.

## Installation Options

### CLI Installation

The recommended way to install ciphey is through Cargo, Rust's package manager:

```bash
cargo install ciphey
```

This will install the `ciphey` command-line tool, which you can use from your terminal.

### Building from Source

To build ciphey from source:

```bash
git clone https://github.com/bee-san/ciphey
cd ciphey
cargo build --release
```

The compiled binary will be available at `target/release/ciphey`.

### Docker

You can also use Docker to run ciphey:

```bash
git clone https://github.com/bee-san/ciphey
cd ciphey
docker build -t ciphey .
docker run -it ciphey
```

### Discord Bot

For casual use, you can access ciphey through the Discord bot:

1. Join the [Discord Server](http://discord.skerritt.blog)
2. Navigate to the #bots channel
3. Use the `$ciphey` command followed by your encoded text

## Basic Usage

### CLI

The basic syntax for using ciphey from the command line is:

```bash
ciphey "your encoded text here"
```

For example:

```bash
ciphey "SGVsbG8sIFdvcmxkIQ=="
```

This will attempt to decode the text and output the result:

```
Decoded text: Hello, World!
Decoders used: Base64
```

### Library API

To use ciphey as a library in your Rust project, add it to your `Cargo.toml`:

```toml
[dependencies]
ciphey = "0.1.0"  # Replace with the current version
```

Then, in your code:

```rust
use ciphey::perform_cracking;
use ciphey::config::Config;

fn main() {
    let config = Config::default();
    let result = perform_cracking("SGVsbG8sIFdvcmxkIQ==", config);
    
    match result {
        Ok(Some(decoder_result)) => {
            println!("Decoded text: {}", decoder_result.text[0]);
            println!("Decoders used: {}", 
                decoder_result.path
                    .iter()
                    .map(|cr| cr.decoder.clone())
                    .collect::<Vec<String>>()
                    .join(" → ")
            );
        },
        Ok(None) => println!("Failed to decode the text"),
        Err(e) => eprintln!("Error: {e}"),
    }
}
```

### Discord Bot

To use the Discord bot:

```
$ciphey SGVsbG8sIFdvcmxkIQ==
```

The bot will respond with the decoded text and the decoders used.

## Advanced Usage

### CLI Options

ciphey CLI supports several options:

```bash
# Set a timeout (in seconds)
ciphey --timeout 10 "your encoded text"

# Specify a regex pattern to match against decoded text
ciphey --regex "flag\{.*\}" "your encoded text"

# Enable human verification
ciphey --human "your encoded text"

# Increase verbosity for debugging
ciphey --verbose "your encoded text"

# Read input from a file
ciphey --file input.txt

# Save output to a file
ciphey --output result.txt "your encoded text"
```

### Configuration

When using the library API, you can customize the configuration:

```rust
use ciphey::perform_cracking;
use ciphey::config::Config;

fn main() {
    let mut config = Config::default();
    
    // Set timeout to 10 seconds
    config.timeout = 10;
    
    // Disable human checker
    config.human_checker_on = false;
    
    // Set verbosity level
    config.verbose = 1;
    
    // Specify a regex pattern
    config.regex = Some("flag\\{.*\\}".to_string());
    
    let result = perform_cracking("your encoded text", config);
    // ...
}
```

## Common Use Cases

### Decoding Base64

Base64 is one of the most common encodings. To decode Base64 with ciphey:

```bash
ciphey "SGVsbG8sIFdvcmxkIQ=="
# Output: Hello, World!
```

### Decoding Hexadecimal

To decode hexadecimal:

```bash
ciphey "48656c6c6f2c20576f726c6421"
# Output: Hello, World!
```

### Decoding URL Encoding

To decode URL-encoded text:

```bash
ciphey "Hello%2C%20World%21"
# Output: Hello, World!
```

### Decoding Caesar Cipher

To decode text encrypted with a Caesar cipher:

```bash
ciphey "Khoor, Zruog!"
# Output: Hello, World!
```

### Multi-level Decoding

ciphey can handle multiple levels of encoding automatically:

```bash
# Base64 → Hex → ROT13
ciphey "NTc2ODY1NmM2YzZmMmMyMDU3NmY3MjZjNjQyMQ=="
# Output: Hello, World!
```

### CTF Challenges

For Capture The Flag challenges, you can use the regex option to look for specific flag formats:

```bash
ciphey --regex "flag\{.*\}" "encoded text containing a flag"
```

### Detecting Invisible Characters

When dealing with steganography that uses invisible Unicode characters:

```bash
ciphey "text with invisible characters"
```

If ciphey detects a significant percentage of invisible characters, it will offer to save the result to a file for better analysis.

## Troubleshooting

### Timeout Issues

If ciphey times out before finding a solution:

1. Increase the timeout value:
   ```bash
   ciphey --timeout 30 "your encoded text"
   ```

2. Try to narrow down the possible encoding types and use a more specific approach.

### False Positives

If ciphey returns incorrect results:

1. Enable human verification:
   ```bash
   ciphey --human "your encoded text"
   ```

2. Use a regex pattern to match the expected format:
   ```bash
   ciphey --regex "expected pattern" "your encoded text"
   ```

### False Negatives

If ciphey fails to decode text that you know is encoded:

1. Check if the encoding is supported by ciphey
2. Try decoding with a specific tool for that encoding
3. Consider contributing a new decoder to ciphey

## Performance Tips

1. **Provide Context**: If you know what kind of encoding you're dealing with, you can narrow down the search space.

2. **Use Appropriate Timeout**: Set a timeout that makes sense for your use case. Longer timeouts allow for more thorough searches but take more time.

3. **Check Input Format**: Ensure your input is properly formatted. Extra whitespace or newlines can sometimes cause issues.

4. **Use Regex When Possible**: If you know the format of the expected output, using a regex pattern can significantly speed up the process.

## Examples

### Example 1: Basic Decoding

```bash
ciphey "SGVsbG8sIFdvcmxkIQ=="
```

Output:
```
Decoded text: Hello, World!
Decoders used: Base64
```

### Example 2: Multi-level Decoding

```bash
ciphey "726f743133286261736536342864656328225a6d7868655841674d5449674d7a51674e6a6373494449774d6a4d3d222929"
```

Output:
```
Decoded text: flag{12 34 67, 2023}
Decoders used: Hexadecimal → Base64 → ROT13
```

### Example 3: Using Regex

```bash
ciphey --regex "flag\{.*\}" "SGxhZXtjcnlwdG9fMTIzfQ=="
```

Output:
```
Decoded text: flag{crypto_123}
Decoders used: Base64
```

### Example 4: Using the Library API

```rust
use ciphey::perform_cracking;
use ciphey::config::Config;

fn main() {
    let config = Config::default();
    let result = perform_cracking("SGVsbG8sIFdvcmxkIQ==", config);
    
    if let Ok(Some(decoder_result)) = result {
        println!("Decoded: {}", decoder_result.text[0]);
    } else {
        println!("Failed to decode");
    }
}
```

Output:
```
Decoded: Hello, World!
```

## Conclusion

ciphey is a powerful tool for automatic decoding, capable of handling a wide range of encoding schemes and even multi-level encodings. Whether you're working on CTF challenges, analyzing suspicious data, or just playing around with encodings, ciphey can save you time and effort by automatically detecting and decoding the text.

For more information, check out the [GitHub repository](https://github.com/bee-san/ciphey) and the [documentation](https://broadleaf-angora-7db.notion.site/Ciphey2-32d5eea5d38b40c5b95a9442b4425710).