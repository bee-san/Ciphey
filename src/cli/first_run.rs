//! First-run configuration module for ciphey
//!
//! This module handles the initial setup of ciphey, including color scheme configuration
//! and user preferences. It provides functionality for creating and managing color schemes,
//! handling user input, and converting between different color formats.

use crate::cli_pretty_printing::{color_enabled, colorize};
use gibberish_or_not::download_model_with_progress_bar;
use rpassword;
use std::collections::HashMap;
use std::fmt::Display;
use std::io::{self, Write};
use std::path::Path;
use termcolor::{Color, ColorSpec};

/// Represents a color scheme with RGB values for different message types and roles.
/// Each color is stored as a comma-separated RGB string in the format "r,g,b"
/// where r, g, and b are values between 0 and 255.
#[derive(Debug)]
pub struct ColorScheme {
    /// RGB color value for informational messages in format "r,g,b"
    /// Used for general information and status updates
    pub informational: String,
    /// RGB color value for warning messages in format "r,g,b"
    /// Used for non-critical warnings and cautions
    pub warning: String,
    /// RGB color value for success messages in format "r,g,b"
    /// Used for successful operations and confirmations
    pub success: String,
    /// RGB color value for question prompts in format "r,g,b"
    /// Used for interactive prompts and user queries
    pub question: String,
    /// RGB color value for general statements in format "r,g,b"
    /// Used for standard output and neutral messages
    pub statement: String,
}

/// Prints a statement in white color.
///
/// # Arguments
/// * `text` - Any type that implements Display trait to be printed in white
///
/// # Returns
/// * `String` - The input text formatted in white color
fn print_statement<T: Display>(text: T) -> String {
    apply_color(&text.to_string(), Color::White)
}

/// Prints a warning message in red color.
///
/// # Arguments
/// * `text` - Any type that implements Display trait to be printed in red
///
/// # Returns
/// * `String` - The input text formatted in red color
fn print_warning<T: Display>(text: T) -> String {
    apply_color(&text.to_string(), Color::Red)
}

/// Prints a question prompt in yellow color.
///
/// # Arguments
/// * `text` - Any type that implements Display trait to be printed in yellow
///
/// # Returns
/// * `String` - The input text formatted in yellow color
fn print_question<T: Display>(text: T) -> String {
    apply_color(&text.to_string(), Color::Yellow)
}

/// Prints a success message in green color.
///
/// # Arguments
/// * `text` - Any type that implements Display trait to be printed in green
///
/// # Returns
/// * `String` - The input text formatted in green color
fn print_success<T: Display>(text: T) -> String {
    apply_color(&text.to_string(), Color::Green)
}

/// Prints text in a specified RGB color.
///
/// # Arguments
/// * `text` - The text to be colored
/// * `rgb` - RGB color string in format "r,g,b" where r,g,b are 0-255
///
/// # Returns
/// * `String` - The text colored with the specified RGB values, or uncolored if RGB format is invalid
fn print_rgb(text: &str, rgb: &str) -> String {
    let parts: Vec<&str> = rgb.split(',').collect();
    if parts.len() != 3 {
        return text.to_string();
    }

    if let (Ok(r), Ok(g), Ok(b)) = (
        parts[0].trim().parse::<u8>(),
        parts[1].trim().parse::<u8>(),
        parts[2].trim().parse::<u8>(),
    ) {
        apply_color_with_rgb(text, r, g, b)
    } else {
        text.to_string()
    }
}

/// Helper function to apply a basic color to text using termcolor.
///
/// # Arguments
/// * `text` - The text to be colored
/// * `color` - The color to apply
///
/// # Returns
/// * `String` - The text with ANSI color codes applied, or the plain text if colours are disabled
fn apply_color(text: &str, color: Color) -> String {
    let mut color_spec = ColorSpec::new();
    color_spec.set_fg(Some(color));

    colorize(text, &color_spec, color_enabled())
}

/// Helper function to apply RGB color to text using termcolor.
///
/// # Arguments
/// * `text` - The text to be colored
/// * `r` - Red value (0-255)
/// * `g` - Green value (0-255)
/// * `b` - Blue value (0-255)
///
/// # Returns
/// * `String` - The text with ANSI color codes applied, or the plain text if colours are disabled
fn apply_color_with_rgb(text: &str, r: u8, g: u8, b: u8) -> String {
    let mut color_spec = ColorSpec::new();
    color_spec.set_fg(Some(Color::Rgb(r, g, b)));

    colorize(text, &color_spec, color_enabled())
}

/// Returns the Capptucin color scheme with warm, muted colors.
///
/// # Returns
/// * `ColorScheme` - A color scheme with Capptucin's signature warm colors
fn get_capptucin_scheme() -> ColorScheme {
    ColorScheme {
        informational: "238,212,159".to_string(), // rgb(238, 212, 159)
        warning: "237,135,150".to_string(),       // rgb(237, 135, 150)
        success: "166,218,149".to_string(),       // rgb(166, 218, 149)
        question: "202,211,245".to_string(),      // rgb(202, 211, 245)
        statement: "244,219,214".to_string(),     // rgb(244, 219, 214)
    }
}

/// Returns the Darcula color scheme matching JetBrains Darcula theme.
///
/// # Returns
/// * `ColorScheme` - A color scheme with Darcula's signature colors
fn get_darcula_scheme() -> ColorScheme {
    ColorScheme {
        informational: "241,250,140".to_string(), // rgb(241, 250, 140)
        warning: "255,85,85".to_string(),         // rgb(255, 85, 85)
        success: "80,250,123".to_string(),        // rgb(80, 250, 123)
        question: "139,233,253".to_string(),      // rgb(139, 233, 253)
        statement: "248,248,242".to_string(),     // rgb(248, 248, 242)
    }
}

/// Returns Autumn's personal Girly Pop theme with pink and pastel colors.
///
/// # Returns
/// * `ColorScheme` - A color scheme with Girly Pop's signature pastel colors
fn get_girly_pop_scheme() -> ColorScheme {
    ColorScheme {
        informational: "237,69,146".to_string(), // rgb(237,69,146)
        warning: "241,218,165".to_string(),      // rgb(241, 218, 165)
        success: "243,214,243".to_string(),      // rgb(243, 214, 243)
        question: "255,128,177".to_string(),     // rgb(255, 128, 177)
        statement: "255,148,219".to_string(),    // rgb(255, 148, 219)
    }
}

/// Returns the default color scheme with standard terminal colors.
///
/// # Returns
/// * `ColorScheme` - A color scheme with standard, high-contrast colors
fn get_default_scheme() -> ColorScheme {
    ColorScheme {
        informational: "255,215,0".to_string(), // Gold yellow
        warning: "255,0,0".to_string(),         // Red
        success: "0,255,0".to_string(),         // Green
        question: "255,215,0".to_string(),      // Gold yellow (same as informational)
        statement: "255,255,255".to_string(),   // White
    }
}

/// Runs the first-time setup wizard for ciphey, allowing users to configure their color scheme.
///
/// This function presents users with color scheme options and handles their selection,
/// including support for custom color schemes. It guides users through the setup process
/// with clear prompts and visual examples of each color scheme.
///
/// # Returns
/// * `HashMap<String, String>` - A mapping of role names to their RGB color values
///
/// # Panics
/// This function can panic if stdout cannot be flushed during an interactive prompt.
pub fn run_first_time_setup() -> HashMap<String, String> {
    println!(
        "\n{}",
        print_statement("🤠 Howdy! This is your first time running ciphey.")
    );
    println!("{}", print_statement("Let me help you configure ciphey."));

    // ask if user wants a tutorial
    if ask_yes_no_question("Do you want a tutorial?", true) {
        println!("ciphey -t 'encoded text here' to decode.");
        println!("Have a crib you know is in the plaintext? use --regex 'crib here'");
        println!("yah that's it. Will write more when we add more :-D\n");
    }

    // Ask if the user wants a custom color scheme
    let want_custom = ask_yes_no_question(
        "Do you want a custom colour scheme? Will be applied after we're done configuring",
        false,
    );

    let mut config = if !want_custom {
        // User doesn't want a custom color scheme, use default
        color_scheme_to_hashmap(get_default_scheme())
    } else {
        // Show color scheme options
        println!(
            "\n{}",
            print_statement("What colour scheme looks best to you?")
        );

        println!("1. Capptucin");
        let capptucin = get_capptucin_scheme();
        print!("   ");
        print!(
            "{} | ",
            print_rgb("Informational", &capptucin.informational)
        );
        print!("{} | ", print_rgb("Warning", &capptucin.warning));
        print!("{} | ", print_rgb("Success", &capptucin.success));
        print!("{} | ", print_rgb("Questions", &capptucin.question));
        println!("{}\n", print_rgb("Statements", &capptucin.statement));

        println!("2. Darcula");
        let darcula = get_darcula_scheme();
        print!("   ");
        print!("{} | ", print_rgb("Informational", &darcula.informational));
        print!("{} | ", print_rgb("Warning", &darcula.warning));
        print!("{} | ", print_rgb("Success", &darcula.success));
        print!("{} | ", print_rgb("Questions", &darcula.question));
        println!("{}\n", print_rgb("Statements", &darcula.statement));

        println!("3. 💖✨💐 GirlyPop");
        let girly = get_girly_pop_scheme();
        print!("   ");
        print!("{} | ", print_rgb("Informational", &girly.informational));
        print!("{} | ", print_rgb("Warning", &girly.warning));
        print!("{} | ", print_rgb("Success", &girly.success));
        print!("{} | ", print_rgb("Questions", &girly.question));
        println!("{}\n", print_rgb("Statements", &girly.statement));

        println!("4. Default");
        let default = get_default_scheme();
        print!("   ");
        print!("{} | ", print_rgb("Informational", &default.informational));
        print!("{} | ", print_rgb("Warning", &default.warning));
        print!("{} | ", print_rgb("Success", &default.success));
        print!("{} | ", print_rgb("Questions", &default.question));
        println!("{}\n", print_rgb("Statements", &default.statement));

        // For the Custom option, show format instructions
        println!("5. Custom");
        println!("   Format: r,g,b (e.g., 255,0,0 for red)");
        println!("   Values must be between 0 and 255");
        println!("   You'll be prompted to enter RGB values for each color.\n");

        // Get user's choice
        let choice = get_user_input_range("Enter your choice (1-5): ", 1, 5);

        match choice {
            1 => color_scheme_to_hashmap(get_capptucin_scheme()),
            2 => color_scheme_to_hashmap(get_darcula_scheme()),
            3 => color_scheme_to_hashmap(get_girly_pop_scheme()),
            4 => color_scheme_to_hashmap(get_default_scheme()),
            5 => {
                // Custom color scheme
                println!(
                    "\n{}",
                    print_statement("Enter RGB values for each color (format: r,g,b)")
                );

                let informational = get_user_input_rgb("Informational: ");
                let warning = get_user_input_rgb("Warning: ");
                let success = get_user_input_rgb("Success: ");
                let question = get_user_input_rgb("Questions: ");
                let statement = get_user_input_rgb("Statements: ");

                let custom_scheme = ColorScheme {
                    informational,
                    warning,
                    success,
                    question,
                    statement,
                };

                color_scheme_to_hashmap(custom_scheme)
            }
            _ => unreachable!(),
        }
    };

    // ask about top_results
    println!("\n{}", print_question("What sounds better to you?"));
    println!(
        "\n{}",
        print_statement("1. ciphey will ask you every time it detects plaintext if it is plaintext.\n2. ciphey stores all possible plaintext in a list, and at the end of the program presents it to you.")
    );
    let wait_athena_choice = get_user_input_range("Enter your choice", 1, 2);

    // Store the top_results choice in the config
    let top_results = wait_athena_choice == 2;
    config.insert("top_results".to_string(), top_results.to_string());

    // Set the default timeout
    let mut timeout = 5; // Default timeout

    if top_results {
        // user has chosen to use top_results mode
        println!(
            "\n{}",
            print_statement("ciphey by default runs for 5 seconds. For this mode we suggest 3 seconds. Please do not complain if you choose too high of a number and your PC freezes up.\n")
        );
        timeout = get_user_input_range(
            "How many seconds do you want ciphey to run? (3 suggested) seconds",
            1,
            500,
        );
    }

    // Store the timeout in the config
    config.insert("timeout".to_string(), timeout.to_string());

    // Wordlist configuration
    println!(
        "{}",
        print_question("\nWould you like ciphey to use custom wordlists to detect plaintext?")
    );
    println!(
        "{}",
        print_statement(
            "ciphey can use custom wordlists to detect plaintext by checking for exact matches."
        )
    );
    println!(
        "{}",
        print_warning("Note: If your wordlist is very large, this can generate excessive matches.")
    );

    if ask_yes_no_question("", false) {
        if let Some(wordlist_path) = get_wordlist_path() {
            config.insert("wordlist_path".to_string(), wordlist_path);
        }
    }

    // Enhanced detection section
    println!(
        "{}",
        print_question("\nWould you like to enable Enhanced Plaintext Detection?")
    );
    println!("{}", print_statement("This will increase accuracy by around 40%, and you will be asked less frequently if something is plaintext or not."));
    println!(
        "{}",
        print_statement("This will download a 500mb AI model.")
    );
    println!(
        "{}",
        print_statement("You will need to follow these steps to download it:")
    );
    println!(
        "{}",
        print_statement("1. Make a HuggingFace account https://huggingface.co/")
    );
    println!(
        "{}",
        print_statement("2. Make a READ Token https://huggingface.co/settings/tokens")
    );
    println!(
        "{}",
        print_warning(
            "Note: You will be able to do this later by running `ciphey --enable-enhanced-detection`"
        )
    );
    println!("{}", print_statement("We will prompt you for the token if you click Yes. We will not store this token, just use it to download a model."));

    if ask_yes_no_question("", false) {
        // Enable enhanced detection
        config.insert("enhanced_detection".to_string(), "true".to_string());

        // Set a default model path
        let mut config_dir_path = crate::config::get_config_file_path();
        config_dir_path.pop();
        config_dir_path.push("models");

        // Create the models directory if it doesn't exist
        std::fs::create_dir_all(&config_dir_path).unwrap_or_else(|_| {
            println!(
                "{}",
                print_warning(
                    "Could not create models directory. Enhanced detection may not work."
                )
            );
        });

        config_dir_path.push("model.bin");

        config.insert(
            "model_path".to_string(),
            config_dir_path.display().to_string(),
        );

        // Prompt for HuggingFace token
        println!(
            "{}",
            print_statement("Please enter your HuggingFace token:")
        );
        print!(
            "{}",
            print_question("Token [invisible for privacy reasons]: ")
        );
        io::stdout().flush().unwrap();

        // Use rpassword to hide the token input
        let token = rpassword::read_password().unwrap_or_else(|_| String::new());

        // Download the model using the token
        if let Err(e) = download_model_with_progress_bar(&config_dir_path, Some(&token)) {
            println!(
                "{}",
                print_warning(format!("Failed to download model: {}", e))
            );
            println!(
                "{}",
                print_warning("Enhanced detection may not work properly.")
            );
        } else {
            println!("{}", print_success("Model downloaded successfully!"));
        }
    }

    // show cute cat
    if ask_yes_no_question("Do you want to see a cute cat?", false) {
        println!(
            r#"
        /\_/\
        ( o.o )
        o( ( ))
        "#
        );
    }

    config
}

/// Prompts the user with a yes/no question and returns their response.
///
/// # Arguments
/// * `question` - The question to display to the user
/// * `default_yes` - Whether the default answer (when user presses enter) should be yes
///
/// # Returns
/// * `bool` - true for yes, false for no
fn ask_yes_no_question(question: &str, default_yes: bool) -> bool {
    // Only print the question if it's not empty (for formatted sequences)
    if !question.is_empty() {
        println!("\n{}", print_question(question));
    }

    // Create the prompt
    let prompt = if default_yes { "(Y/n): " } else { "(y/N): " };

    print!("{}", print_question(prompt));
    io::stdout().flush().unwrap();

    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();

    let input = input.trim().to_lowercase();

    if input.is_empty() {
        return default_yes;
    }

    match input.as_str() {
        "y" | "yes" => true,
        "n" | "no" => false,
        _ => {
            println!(
                "{}",
                print_warning("Invalid input. Please enter 'y' or 'n'.")
            );
            ask_yes_no_question(question, default_yes)
        }
    }
}

/// Gets user input within a specified numeric range.
///
/// # Arguments
/// * `prompt` - The prompt to display to the user
/// * `min` - The minimum acceptable value (inclusive)
/// * `max` - The maximum acceptable value (inclusive)
///
/// # Returns
/// * `u32` - The user's input within the specified range
fn get_user_input_range(prompt: &str, min: u32, max: u32) -> u32 {
    // Create the input prompt with the provided prompt text
    let input_prompt = format!("{} ({}-{}): ", prompt, min, max);
    print!("{}", print_question(input_prompt));
    io::stdout().flush().unwrap();

    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();

    let input = input.trim();

    match input.parse::<u32>() {
        Ok(num) if num >= min && num <= max => num,
        _ => {
            println!(
                "{}",
                print_warning(format!(
                    "Invalid input. Please enter a number between {} and {}.",
                    min, max
                ))
            );
            get_user_input_range(prompt, min, max)
        }
    }
}

/// Gets user input for RGB color values.
///
/// # Arguments
/// * `prompt` - The prompt to display to the user
///
/// # Returns
/// * `String` - A validated RGB color string in format "r,g,b"
fn get_user_input_rgb(prompt: &str) -> String {
    print!("{}", print_question(prompt));
    io::stdout().flush().unwrap();

    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();

    let input = input.trim();

    // Validate RGB format (r,g,b)
    if let Some(rgb) = parse_rgb_input(input) {
        rgb
    } else {
        println!(
            "{}",
            print_warning("Invalid RGB format. Please use the format 'r,g,b' (e.g., '255,0,0').")
        );
        get_user_input_rgb(prompt)
    }
}

/// Parses and validates an RGB input string.
///
/// # Arguments
/// * `input` - The RGB string to parse in format "r,g,b"
///
/// # Returns
/// * `Option<String>` - Some(rgb) if valid, None if invalid
fn parse_rgb_input(input: &str) -> Option<String> {
    let parts: Vec<&str> = input.split(',').collect();

    if parts.len() != 3 {
        return None;
    }

    let r = parts[0].trim().parse::<u8>().ok()?;
    let g = parts[1].trim().parse::<u8>().ok()?;
    let b = parts[2].trim().parse::<u8>().ok()?;

    Some(format!("{},{},{}", r, g, b))
}

/// Converts a ColorScheme struct to a HashMap for configuration storage.
///
/// # Arguments
/// * `scheme` - The ColorScheme to convert
///
/// # Returns
/// * `HashMap<String, String>` - A mapping of role names to their RGB values
fn color_scheme_to_hashmap(scheme: ColorScheme) -> HashMap<String, String> {
    let mut map = HashMap::new();
    map.insert("informational".to_string(), scheme.informational);
    map.insert("warning".to_string(), scheme.warning);
    map.insert("success".to_string(), scheme.success);
    map.insert("question".to_string(), scheme.question);
    map.insert("statement".to_string(), scheme.statement);
    map
}

/// Prompts the user for a wordlist file path and validates that the file exists
/// Returns the path if valid, or None if the user cancels
fn get_wordlist_path() -> Option<String> {
    println!(
        "\n{}",
        print_statement("Enter the path to your wordlist file:")
    );
    println!("{}", print_statement("(Leave empty to cancel)"));

    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .expect("Failed to read input");
    let input = input.trim();

    if input.is_empty() {
        println!("{}", print_statement("No wordlist will be used."));
        return None;
    }

    // Check if the file exists
    if !Path::new(input).exists() {
        println!("{}", print_warning("File does not exist!"));
        return get_wordlist_path(); // Recursively prompt until valid or cancelled
    }

    // Check if the file is readable
    match std::fs::File::open(input) {
        Ok(_) => Some(input.to_string()),
        Err(e) => {
            println!("{}", print_warning(format!("Cannot read file: {}", e)));
            get_wordlist_path() // Recursively prompt until valid or cancelled
        }
    }
}
