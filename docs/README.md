# ciphey Documentation

Welcome to the ciphey documentation! This repository contains comprehensive documentation for ciphey, the next-generation automatic decoding and cracking tool.

## Table of Contents

### General Documentation

- [ciphey Overview](ciphey_overview.md) - A high-level overview of ciphey, its features, and capabilities
- [Using ciphey](using_ciphey.md) - A comprehensive guide on how to use ciphey, with examples and common use cases

### Technical Documentation

- [ciphey Architecture](ciphey_architecture.md) - Detailed explanation of ciphey's internal architecture and components
- [Plaintext Detection](plaintext-detection.md) - How ciphey decides a candidate is the plaintext: every checker and threshold, the quadgram model, the benchmark and its numbers

### Feature-Specific Documentation

- [Invisible Characters Detection](invisible_characters.md) - Information about ciphey's capability to detect and handle invisible Unicode characters
- [Package Managers](package-managers.md) - Guidelines for packaging ciphey for different package managers

## About ciphey

ciphey is the next generation of decoding tools, built by the same people that brought you [Ciphey](https://github.com/ciphey/ciphey). It's designed to automatically detect and decode various types of encoded or encrypted text, including (but not limited to) Base64, Hexadecimal, Caesar cipher, ROT13, URL encoding, and many more.

Key features include:

- Significantly faster performance (up to 700% faster than Ciphey)
- Library-first architecture for easy integration
- Advanced search algorithms for efficient decoding
- Built-in timeout mechanism
- Comprehensive documentation and testing
- Support for multi-level encodings

## Getting Started

The quickest way to get started with ciphey is to install it via Cargo:

```bash
cargo install ciphey
```

Then use it with the `ciphey` command:

```bash
ciphey "your encoded text here"
```

For more detailed instructions, see the [Using ciphey](using_ciphey.md) guide.

## Contributing

Contributions to ciphey are welcome! Whether it's adding new decoders, improving existing ones, enhancing documentation, or fixing bugs, your help is appreciated. Check the [GitHub repository](https://github.com/bee-san/ciphey) for more information on how to contribute.

## Additional Resources

- [GitHub Repository](https://github.com/bee-san/ciphey)
- [Discord Server](http://discord.skerritt.blog)
- [Blog Post: Introducing ciphey](https://skerritt.blog/introducing-ciphey/)
- [Ciphey2 Documentation](https://broadleaf-angora-7db.notion.site/Ciphey2-32d5eea5d38b40c5b95a9442b4425710)