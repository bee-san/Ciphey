# Plaintext Identification in ciphey

## Overview

One of the most critical components of ciphey is its ability to identify when encoded text has been successfully decoded into plaintext. This document explains the mechanisms and strategies ciphey uses to determine whether a given string is valid plaintext.

## The Importance of Plaintext Detection

Accurate plaintext detection serves several crucial purposes in ciphey:

1. **Termination Condition**: It tells the search algorithm when to stop decoding
2. **Result Validation**: It confirms that the decoded output is meaningful
3. **Efficiency**: It prevents unnecessary decoding attempts on already-decoded text
4. **Accuracy**: It helps avoid false positives (incorrectly identifying gibberish as plaintext)

## The Checker System

ciphey uses a modular system of "checkers" to identify plaintext. Each checker specializes in recognizing different types of plaintext:

### Athena Checker

The Athena checker (`src/checkers/athena.rs`) is the main orchestrator that coordinates other checkers. When asked to check if text is plaintext, it:

1. Checks if a regex pattern is provided in the configuration
   - If yes, it uses only the RegexChecker to see if the text matches
   - If the text matches, it optionally verifies with the human checker

2. If no regex is provided, it tries, in this order:
   - the Wordlist checker, if a wordlist was given
   - the LemmeKnow checker (known formats such as URLs, IPs and API keys, and CTF flags)
   - the JSON checker
   - the Password checker (common passwords)
   - the English checker
   - For each, if they identify the text as plaintext, it optionally verifies with the human checker

The Athena checker returns as soon as any of its sub-checkers identifies the text as plaintext, or returns a negative result if none do. WaitAthena (used for `--top-results`) runs the same checkers in the same order, without the human checker.

### LemmeKnow Checker

The LemmeKnow checker (`src/checkers/lemmeknow_checker.rs`) uses the [LemmeKnow](https://github.com/swanandx/lemmeknow) library, which is a Rust implementation of [PyWhat](https://github.com/bee-san/pyWhat). This library can identify over 100 different types of data formats and patterns, including:

- IP addresses (IPv4, IPv6)
- Email addresses
- URLs
- Credit card numbers
- Cryptocurrency addresses
- API keys and tokens
- File paths
- MAC addresses
- And many more

The checker works by:
1. Configuring LemmeKnow with a minimum rarity threshold (0.1)
2. Passing the text to LemmeKnow's identify function
3. Ignoring matches from patterns that only check which characters the text uses and how long it is, because decoder junk matches them (every 10 to 13 digit number is a "Phone Number", every SHA-1 hash a "Bitly Secret Key"):
   - every pattern tagged `Credit Card`, `Phone`, `Bitly`, `Visual Studio` or `Turkish`
   - by name: ASIN, the Bitcoin Cash, Litecoin, Ripple and Dogecoin wallet addresses, and the Google ReCaptcha API key
   - URLs without `://` or a leading `www.`
4. If no match is left, checking for a CTF flag in any format, `^[A-Za-z][A-Za-z0-9_]{1,19}\{[^{}\n]{1,200}\}$` (`picoCTF{...}`, `DUCTF{...}`); LemmeKnow itself only knows `flag{}`, `ctf{}`, `htb{}` and `thm{}`
5. If anything is left, marking the text as identified plaintext

Caesar shifts, Atbash and Vigenère keep a flag's shape: ROT13 of `flag{this_is_the_flag}` is `synt{guvf_vf_gur_synt}`, which the pattern matches too. So:

- A flag whose prefix is a shift or Atbash of a flag word (`synt`, `uozt`, `cvpbPGS`) is not a flag; the search goes on and finds the real one. A flag word is a prefix ending in `ctf` or `flag` (digits after it allowed), starting with `flag`, or one of `htb`, `thm`, `hackthebox`, `tryhackme`.
- A flag without a flag word in its prefix (`SEKAI{...}`) can't be told apart from its own shifts. Its contents may only be letters, digits and `_-!?.@$#&+'` (ROT47 junk is often flag-shaped), and it is not taken as plaintext when it is the input itself, when Caesar, Atbash or Vigenère produced it, or when the input was already shaped like a flag; it is when another decoder produced it (Base64, hex, a railfence key that is the only one giving a flag shape). Use a crib (`-r 'SEKAI\{'`) for those.
- Caesar and railfence check a candidate that is a flag with a flag word first, since a flag's hex or random contents needn't make the right key rank best.

This checker is particularly useful for identifying structured data that might not be natural language but is still valid plaintext.

A fork of LemmeKnow would let these rules live in its data instead: generating it from pyWhat's `regex.json` in CI (it is behind pyWhat and silently drops patterns Rust's `regex` can't compile), a per-pattern "charset only" flag, and checksum validators (Luhn for cards, base58check/bech32 for wallets) so those patterns could stay on.

### JSON Checker

The JSON checker (`src/checkers/json_checker.rs`) accepts a JSON object or array with at least one entry, such as `{"key": "value"}`. Bare values (`1`, `"x"`, `true`) are valid JSON too but say nothing, so they are rejected.

Caesar, Atbash and Vigenère only change letters, so every key of theirs turns JSON into JSON. When their input is JSON they don't ask the checkers about their candidates (without a crib).

### English Checker

The English checker (`src/checkers/english.rs`) determines if text is valid English language. It uses the [gibberish-or-not](https://crates.io/crates/gibberish-or-not) library to distinguish meaningful English text from random character sequences, with configurable sensitivity levels.

The process works as follows:

1. **Normalization**: The text is lowercased, ASCII punctuation becomes a space (so `Hello,world!How` is three words, not `helloworldhow`) except for apostrophes inside words (`don't`, `o'clock`), and runs of spaces are collapsed. The result is only used for detection: `CheckResult.text` is the text as given, which is what the human checker shows.

2. **Classification by shape**:
   - **Space-less letters** (no whitespace, at least 8 letters, at least 90% letters), the usual output of classical ciphers: the text must be one dictionary word, or the mean log10 probability of its letter quadgrams must be at least -5.1 (Low), -5.3 (Medium) or -5.6 (High). Up to 12 letters it must also split into known words (`HELLOWORLD`, but not the railfence shuffle `HWORLDELLO`) unless its quadgram score is at least -4.4, because the dictionary can't be asked about single words of 10 or more letters. The quadgram table (`src/storage/ngrams`) is counted from 85 public-domain books.
   - **Mostly known words**: two or more words, at least one of three or more letters, of which more than 80% are English words. Words of one to three letters (`a`, `is`, `me`), which gibberish-or-not's dictionary lacks, come from a list built from the same books.
   - **Other space-less text** (digits or symbols mixed in, like `ThI2THAtThE2THe0`): only a single dictionary word passes.
   - **Everything else** goes to gibberish-or-not's `is_gibberish` at the checker's sensitivity, unless no word at all is an English word, or the quadgram score is below -6.5 (-7.5 at High), far from any natural language.

The thresholds were picked with `examples/plaintext_eval.rs` (the harness from [#1031](https://github.com/bee-san/Ciphey/issues/1031)) and checked on held-out text from Pride and Prejudice: `PDETECT_HELDOUT=examples/data/heldout_pride_and_prejudice.txt cargo run --release --example plaintext_eval`.

#### Sensitivity Levels

The English checker supports three sensitivity levels:

- **Low Sensitivity**: Most strict classification, requires very high confidence to classify text as English. Used by Caesar, railfence, ROT47 and Vigenère. Caesar, railfence and ROT47 rank their candidates by letter-pair fitness and only check the best one (ROT47 checks shift 47 first); Vigenère only checks candidates with spaces whose words are at least 75% English words, or without spaces that have at least 85% of their letters inside known words, because its key search optimises the letter statistics the other checks look at. With a `--regex` crib all of them check every key in order, so the crib decides.

- **Medium Sensitivity (Default)**: Balanced approach for general use, suitable for most applications. Used by most decoders in ciphey, and for the check of the input itself.

- **High Sensitivity**: Most lenient classification, favors classifying text as English. Nothing in ciphey uses it.

The old `enhanced_detection` setting switched every check to High; it never loaded a model and was removed. See [sensitivity.md](sensitivity.md).

The English checker is effective for detecting natural language text but may struggle with specialized technical content or very short texts. The sensitivity level can be adjusted based on the specific decoder's needs.

### Regex Checker

The Regex checker (`src/checkers/regex_checker.rs`) allows users to provide a custom regular expression pattern to match against decoded text. This is useful when looking for specific formats or patterns in the output.

The checker simply:
1. Takes the regex pattern from the configuration
2. Attempts to match it against the input text
3. Returns true if there's a match, false otherwise

This checker is typically used when the user knows what they're looking for and can provide a specific pattern.

### Human Checker

The Human checker (`src/checkers/human_checker.rs`) provides a way to involve human judgment in the plaintext detection process. It's particularly useful for ambiguous cases or specialized content that automated checkers might not recognize correctly.

When enabled (off by default), it:
1. Displays the decoded text to the user
2. Asks if the text looks like valid plaintext
3. Returns the user's response

This checker is optional and can be enabled or disabled through the configuration.

## Plaintext Detection Process

The overall plaintext detection process in ciphey follows these steps:

1. **Initial Check**: When `perform_cracking` is called, ciphey first checks if the input is already plaintext using the Athena checker
   - If it is, ciphey returns early with the input as the result
   - This prevents unnecessary processing of already-decoded text

2. **During Search**: As the search algorithm explores possible decodings, each result is checked:
   - The Athena checker is used to determine if the result is plaintext
   - If it is, the search terminates and returns the result
   - If not, the result is added to the search queue for further decoding

3. **Result Validation**: Before returning the final result, ciphey ensures it's valid plaintext
   - This helps prevent returning partially decoded or incorrect results

## Handling Edge Cases

ciphey includes several mechanisms to handle edge cases in plaintext detection:

### Very Short Strings

Very short strings are difficult to classify reliably. A single word must be a dictionary word of four or more letters (`yes` is not enough), and a phrase like `call me` passes because all of its words are known.

### Specialized Content

Some valid plaintext might not be natural language (e.g., JSON, XML, code). ciphey addresses this through:
- The LemmeKnow checker, which can identify many structured data formats and CTF flags
- The JSON checker
- The regex checker, which allows users to provide custom patterns
- The human checker, which can be enabled for manual verification

Text that isn't English (French, German, Spanish ...) is often missed.

### False Positives

To reduce false positives (incorrectly identifying gibberish as plaintext), ciphey:
- Uses multiple checkers with different approaches
- Configures the LemmeKnow checker with a minimum rarity threshold and ignores its patterns that only check the character set and length
- Has ciphers with few keys check only their best-ranked candidate instead of the first one any check accepts
- Checks a cached plaintext again before returning it
- Allows for human verification in ambiguous cases

### False Negatives

To reduce false negatives (failing to identify valid plaintext), ciphey:
- Normalizes text before checking (punctuation to spaces, converting to lowercase)
- Scores space-less text with quadgrams and counts short words gibberish-or-not's dictionary lacks
- Uses multiple checkers with different strengths
- Provides configuration options to adjust the detection sensitivity

## Customizing Plaintext Detection

Users can customize the plaintext detection process through several configuration options:

- **Regex Pattern**: Provide a custom regex pattern to match against decoded text
- **Human Checker**: Enable or disable human verification of results
- **Timeout**: Adjust the maximum time spent trying to decode
- **Sensitivity Level**: Different decoders use different sensitivity levels based on their characteristics

These options allow users to tailor the plaintext detection to their specific needs and expectations.

## Future Improvements

The plaintext detection system in ciphey is continuously evolving. Planned improvements include:

1. **Better English Detection**: Enhancing the English checker to better handle technical content and edge cases
2. **More Specialized Checkers**: Adding checkers for specific formats like XML
3. **Other Languages**: Recognising text that isn't English without accepting more junk
4. **Context-Aware Detection**: Taking into account the context and expected output format
5. **User Feedback Integration**: Learning from user feedback to improve detection accuracy over time

Models were evaluated in [#1031](https://github.com/bee-san/Ciphey/issues/1031#issuecomment-5938256908): at 5 ms to 140 ms per check (a search makes hundreds to thousands of checks) none was worth it next to the quadgram score.

## Conclusion

Plaintext identification is a fundamental component of ciphey that enables it to automatically decode text without requiring explicit knowledge of the encoding method. The modular checker system provides flexibility and extensibility, allowing ciphey to handle a wide range of plaintext formats and continuously improve its detection capabilities.