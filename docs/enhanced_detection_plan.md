> **Status: removed.** This plan was never finished: no model was ever loaded, and
> `enhanced_detection = true` only switched the English checker to its most lenient
> sensitivity, which more than quadrupled false positives. The flag, the first-run prompt
> and the model download were removed in
> [#1031](https://github.com/bee-san/Ciphey/issues/1031); a quadgram score
> (`src/storage/ngrams`) handles the space-less text a model was meant to help with. The
> `enhanced_detection` and `model_path` config keys are still read, and ignored, so old
> config files keep working. The plan is kept for reference.

Okay, here's a detailed plan for integrating enhanced plaintext detection using BERT into the ciphey project, along with a CLI argument for enabling it and a first-run user experience:

```markdown
# Plan: Integrating Enhanced Plaintext Detection with BERT into ciphey

## Goal

To enhance ciphey's plaintext detection capabilities by integrating a BERT-based gibberish detection model from the `gibberish-or-not` crate, provide a user-friendly first-run experience for downloading the model, and offer a CLI argument to enable enhanced detection later.

## 1. Update Cargo.toml

- Add `rpassword` as a dependency to handle token input securely.
- Ensure `gibberish-or-not` is on version 4.1.1 or greater.

```toml
[dependencies]
# Existing dependencies...
rpassword = "0.13.0"
gibberish-or-not = "4.1.1"
```

## 2. Modify Config Struct (`src/config/mod.rs`)

- Add a boolean field `enhanced_detection` to the `Config` struct, defaulting to `false`.
- Add a field `model_path` for the location of the downloaded model. Make it optional.
- Implement `Default` for the new fields.

```rust
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(default)]
pub struct Config {
    // ... existing fields ...
    /// Enables enhanced plaintext detection using a BERT model.
    pub enhanced_detection: bool,
    /// Path to the enhanced detection model. If None, will use the default path.
    pub model_path: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            // ... existing defaults ...
            enhanced_detection: false,
            model_path: None,
        }
    }
}
```

## 3. First-Run Experience (`src/cli/first_run.rs`)

- Implement the first-run TUI to prompt the user about enabling enhanced detection.

   - Display a message explaining the benefits of enhanced detection, the download size, and the requirement for a Hugging Face account and token.
   - Provide links to create a Hugging Face account and generate a READ token.
   - Use `ask_yes_no_question()` to get the user's response.
   - If the user chooses "Yes":
      - Use `rpassword::read_password_from_tty()` to securely prompt the user for their Hugging Face token without echoing it to the terminal.
      - Implement download logic using `download_model_with_progress_bar()` from `gibberish-or-not`
      - Store the Hugging Face token (temporarily in memory - *do not save to disk!*).
      - Store the model path in the config `model_path = Some(config_dir_path)`
      - Store that enhanced_detection = true in config
      - Handle errors during download and provide informative messages to the user.
- Add new hashmap value in `run_first_time_setup()` to store this value and add it to the file.

```rust
// src/cli/first_run.rs

use rpassword::read_password_from_tty;
use gibberish_or_not::{download_model_with_progress_bar, default_model_path};
use std::path::{Path, PathBuf};

// ... existing code ...

pub fn run_first_time_setup() -> std::collections::HashMap<String, String> {
    // ... existing code ...

    let mut config = /* ... existing config hashmap ... */;

    if ask_yes_no_question(
        "Would you like to enable Enhanced Plaintext Detection?\n\nThis will increase accuracy by around 40%, and you will be asked less frequently if something is plaintext or not.\n\nThis will download a 500mb AI model.\n\nYou will need to follow these steps to download it.\n1. Make a HuggingFace account https://huggingface.co/\n2. Make a READ Token https://huggingface.co/settings/tokens\n\nNote: You will be able to do this later by running `ciphey --enable-enhanced-detection`\n\nWe will prompt you for the token if you click Yes. We will not store this token, only use it to download the model and then throw away on reboot (y/N)",
        false,
    ) {
        let token = read_password_from_tty(Some("Hugging Face Token: ")).expect("Failed to read token from TTY");

        // Define the path to store models
        let mut config_dir_path = get_config_file_path();
        config_dir_path.pop();
        config_dir_path.push("models");

        // Create folder if it doesn't exist
        std::fs::create_dir_all(&config_dir_path).expect("Could not create models directory");

        let model_path: PathBuf = default_model_path();
    
        if let Err(e) = download_model_with_progress_bar(&model_path, Some(&token)) {
            println!("{}", print_warning(format!("Error downloading model: {}", e)));
        } else {
            println!("{}", print_statement("Enhanced detection enabled."));
            config.insert("enhanced_detection".to_string(), "true".to_string());
            config.insert("model_path".to_string(), model_path.display().to_string());
        }
    }

    // ... existing code ...
    config
}
```

## 4. CLI Argument (`src/cli/mod.rs`)

- Add a `--enable-enhanced-detection` CLI argument.
- When the argument is present:
   - Prompt the user for their Hugging Face token using `rpassword::read_password_from_tty()`.
   - Implement download logic using `download_model_with_progress_bar()`.
   - Update enhanced_detection in the config to be true.

```rust
// src/cli/mod.rs
use rpassword::read_password_from_tty;
use gibberish_or_not::{download_model_with_progress_bar, default_model_path};

// ... existing code ...

#[derive(Parser)]
#[command(author = "Bee <bee@skerritt.blog>", about, long_about = None)]
pub struct Opts {
    // ... existing fields ...
    /// Enables enhanced plaintext detection with BERT model.
    #[arg(long)]
    enable_enhanced_detection: bool,
}

fn cli_args_into_config_struct(opts: Opts, text: String) -> (String, Config) {
   // ... existing code ...
    if opts.enable_enhanced_detection {
        let token = read_password_from_tty(Some("Hugging Face Token: ")).expect("Failed to read token from TTY");
    
        let mut config_dir_path = config::get_config_file_path();
        config_dir_path.pop();
        config_dir_path.push("models");

        // Create folder if it doesn't exist
        std::fs::create_dir_all(&config_dir_path).expect("Could not create models directory");

        let model_path: PathBuf = default_model_path();

        if let Err(e) = download_model_with_progress_bar(&model_path, Some(&token)) {
            eprintln!("{}", cli_pretty_printing::warning(format!("Error downloading model: {}", e).as_str()));
        } else {
            config.enhanced_detection = true;
            config.model_path = Some(model_path.display().to_string());
        }
    }
    (text, config)
}
```

## 5. Implement Enhanced Detection in English Checker (`src/checkers/english.rs`)

- Modify the `EnglishChecker` to use the `GibberishDetector::with_model()` to load the model.
- If `config.enhanced_detection` is true, and a `config.model_path` exists, use that path and sensitivity.
- If `config.enhanced_detection` is true, but `config.model_path` is `None`, then display warning and skip.
- If `config.enhanced_detection` is false, then we do the standard code we have now.

```rust
// src/checkers/english.rs
use gibberish_or_not::{is_gibberish, Sensitivity, GibberishDetector};

impl Check for Checker<EnglishChecker> {
    fn new() -> Self {
        let config = get_config();
        let detector = if config.enhanced_detection {
            match &config.model_path {
                Some(path) => {
                    println!("{}", cli_pretty_printing::statement(&format!("Using Enhanced Detection model at {}", path), None));
                    // Enhanced detection is enabled but no model path provided
                    // The program should not proceed without the model path being valid
                    if let Ok(detector) = GibberishDetector::with_model(path) {
                        Some(detector)
                    } else {
                       println!("{}", cli_pretty_printing::warning("Enhanced detection was enabled in config, but no model found."));
                       None
                    }
                }
                None => {
                    //Enhanced detection is enabled but no model path provided
                    println!("{}", cli_pretty_printing::warning("Enhanced detection was enabled in config, but no model found."));
                    None
                }
            }
        } else {
            None
        };
        Checker {
            // ... existing fields ...
            enhanced_detector: detector,
            sensitivity: Sensitivity::Medium, // Default to Medium sensitivity
            _phantom: std::marker::PhantomData,
        }
    }

    fn check(&self, text: &str) -> CheckResult {
        // Normalize before checking
        let text = normalise_string(text);

        let mut result = CheckResult {
            is_identified: match &self.enhanced_detector {
                Some(detector) => !detector.is_gibberish(&text, self.sensitivity),
                None => !is_gibberish(&text, self.sensitivity), // Fallback to basic if model is not available.
            },
            text: text.to_string(),
            checker_name: self.name,
            checker_description: self.description,
            description: "Words".to_string(),
            link: self.link,
        };

        // Handle edge case of very short strings after normalization
        if text.len() < 2 {
            // Reduced from 3 since normalization may remove punctuation
            result.is_identified = false;
        }

        result
    }
}

```

## 6. Error Handling

- Implement robust error handling throughout the new functionality.
- Provide informative error messages to the user in case of download failures, invalid tokens, or other issues.

## 7. Testing

- Add integration tests to verify the enhanced detection flow:
   - Ensure the model is downloaded correctly.
   - Check that enhanced detection is enabled and used when configured.
   - Test with various inputs to confirm improved accuracy.
   - Verify that it all falls back to the existing mode without enhanced settings.
- Test the CLI argument.
- Test error handling scenarios.

## 8. Documentation

- Update the `README.md` and other relevant documentation to describe the new enhanced detection feature, its benefits, and how to enable it.

```

This plan covers the implementation, user experience, and testing aspects of integrating BERT-based enhanced plaintext detection into ciphey.