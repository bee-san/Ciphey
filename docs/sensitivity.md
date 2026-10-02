# Sensitivity Levels in Gibberish Detection

## Overview

ciphey uses the `gibberish_or_not` library to detect whether decoded text is meaningful English. This library provides three sensitivity levels to fine-tune gibberish detection:

### Low Sensitivity
- Most strict classification
- Requires very high confidence to classify text as English
- Best for detecting texts that appear English-like but are actually gibberish
- Used by the classical ciphers (Caesar, railfence, ROT47 and Vigenère), whose wrong keys produce English-like results

### Medium Sensitivity (Default)
- Balanced approach for general use
- Combines dictionary and n-gram analysis
- Default mode suitable for most applications
- Used by most decoders in ciphey

### High Sensitivity
- Most lenient classification
- Favors classifying text as English
- Best when input is mostly gibberish and any English-like patterns are significant
- Not used by ciphey itself. The removed `enhanced_detection` setting used to force it on every check, which more than quadrupled false positives ([#1031](https://github.com/bee-san/Ciphey/issues/1031)).

Note that gibberish-or-not's own documentation for `Sensitivity` and `is_gibberish` has High and Low the wrong way round: in its code, Low uses the highest threshold (0.35) and High the lowest (0.15). The descriptions here match the code.

## Implementation in ciphey

In ciphey, different decoders use different sensitivity levels based on their characteristics:

1. **Caesar, railfence and ROT47**: Use Low sensitivity because classical ciphers often produce text that can appear English-like even when the key is incorrect. They also rank all their candidates by letter-pair fitness and only check the best one (ROT47 checks shift 47, ROT47 itself, first), instead of returning the first candidate any check accepts.

2. **Vigenère**: Uses Low sensitivity, and only checks a candidate with spaces if at least 75% of its words are English words, or one without spaces if at least 85% of its letters are inside known words. Its key search maximises letter-pair fitness, which is what the statistical checks reward, so wrong keys look English to them.

3. **Other Decoders**: Use Medium sensitivity by default, which provides a balanced approach for most types of encoded text. So does the check of the input itself.

Besides gibberish-or-not's thresholds, the sensitivity picks the English checker's quadgram threshold for space-less text such as `THEQUICKBROWNFOX`:

| Sensitivity | Minimum mean log10 quadgram probability (space-less text) | Rejected below (other text) |
|---|---|---|
| Low | -5.1 | -6.5 |
| Medium | -5.3 | -6.5 |
| High | -5.6 | -7.5 |

## Customizing Sensitivity

Decoders can override the default sensitivity level when needed. The `CheckerTypes` enum provides a `with_sensitivity` method that allows changing the sensitivity level:

```rust
// Example: Using a checker with a custom sensitivity level
let checker_with_sensitivity = checker.with_sensitivity(Sensitivity::High);
let result = checker_with_sensitivity.check(text);
```

## Technical Details

The sensitivity level affects the thresholds used for n-gram analysis and dictionary checks:

- **Low Sensitivity**: Stricter thresholds, requiring more evidence to classify text as English
- **Medium Sensitivity**: Balanced thresholds suitable for most applications
- **High Sensitivity**: Lenient thresholds, more likely to classify text as English

For more details on how the sensitivity levels work, see the [gibberish_or_not documentation](https://crates.io/crates/gibberish-or-not).