//! Colours and glyphs for the display.
//!
//! The default colour scheme uses the terminal's own 16-colour palette, so it follows
//! the user's light or dark terminal theme. A scheme picked in the first-run setup
//! (Capptucin, Darcula, GirlyPop or custom RGB) is used as it is, reduced to 256
//! colours where the terminal can't show 24-bit colour.
//!
//! Colour never carries meaning on its own: every status also has a symbol and words.
//! With `NO_COLOR` the display keeps its layout, symbols, bold and dim text.

use crate::cli_pretty_printing::parse_rgb_quiet;
use ratatui::style::{Color, Modifier, Style};
use std::collections::HashMap;
use std::env;

/// How many colours the terminal can show
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ColorDepth {
    /// No colour at all because `NO_COLOR` is set. Bold and dim are still used.
    None,
    /// The terminal's 16-colour palette
    Ansi16,
    /// The 256-colour palette
    Ansi256,
    /// 24-bit colour
    TrueColor,
}

impl ColorDepth {
    /// Works out the colour depth from `NO_COLOR`, `COLORTERM`, `TERM` and
    /// `TERM_PROGRAM`
    pub fn detect() -> Self {
        if crate::cli_pretty_printing::no_color_env() {
            return ColorDepth::None;
        }
        Self::from_env(|name| env::var(name).ok())
    }

    /// [`ColorDepth::detect`] without `NO_COLOR`, reading variables through `var`
    fn from_env(var: impl Fn(&str) -> Option<String>) -> Self {
        let colorterm = var("COLORTERM").unwrap_or_default().to_ascii_lowercase();
        if colorterm == "truecolor" || colorterm == "24bit" {
            return ColorDepth::TrueColor;
        }
        // Terminal.app before macOS 26 can't show 24-bit colour
        if var("TERM_PROGRAM").as_deref() == Some("Apple_Terminal") {
            return ColorDepth::Ansi256;
        }
        let term = var("TERM").unwrap_or_default();
        if term == "linux" || term.starts_with("vt") {
            return ColorDepth::Ansi16;
        }
        // Ciphey has always sent 24-bit colour, and terminals that don't support it
        // (tmux among them) generally map it to the nearest colour they have
        ColorDepth::TrueColor
    }
}

/// The symbols the display draws with, in Unicode or plain ASCII
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Glyphs {
    /// Marks a plaintext that was found
    pub found: &'static str,
    /// Marks a search that found nothing, or a rejected candidate
    pub failed: &'static str,
    /// Marks a question
    pub ask: &'static str,
    /// Joins the decoders of a path
    pub arrow: &'static str,
    /// Separates items on one line
    pub sep: &'static str,
    /// Ends text that was cut short
    pub ellipsis: &'static str,
    /// The used part of the time bar
    pub bar_done: &'static str,
    /// The rest of the time bar
    pub bar_todo: &'static str,
    /// Starts a list item
    pub bullet: &'static str,
    /// Frames of the spinner
    pub spinner: &'static [&'static str],
}

impl Glyphs {
    /// Symbols for terminals and fonts with Unicode. All of them are one column wide;
    /// emoji are avoided because terminals disagree on how wide they are. The spinner
    /// uses block elements rather than the usual braille dots: JetBrains Mono, DejaVu
    /// Sans Mono, Menlo and Cascadia all have them, so no fallback font is needed.
    pub const UNICODE: Glyphs = Glyphs {
        found: "✓",
        failed: "✗",
        ask: "?",
        arrow: "→",
        sep: "·",
        ellipsis: "…",
        bar_done: "━",
        bar_todo: "─",
        bullet: "•",
        spinner: &["▁", "▂", "▃", "▄", "▅", "▆", "▇", "▆", "▅", "▄", "▃", "▂"],
    };

    /// ASCII stand-ins, for the classic Windows console, the Linux console and
    /// non-UTF-8 locales
    pub const ASCII: Glyphs = Glyphs {
        found: "+",
        failed: "x",
        ask: "?",
        arrow: "->",
        sep: "|",
        ellipsis: "...",
        bar_done: "#",
        bar_todo: "-",
        bullet: "*",
        spinner: &["|", "/", "-", "\\"],
    };

    /// Picks Unicode or ASCII symbols for this terminal
    pub fn detect() -> Glyphs {
        if Self::unicode_ok(|name| env::var(name).ok(), cfg!(windows)) {
            Glyphs::UNICODE
        } else {
            Glyphs::ASCII
        }
    }

    /// Whether the terminal described by the variables in `var` can show
    /// [`Glyphs::UNICODE`]
    fn unicode_ok(var: impl Fn(&str) -> Option<String>, windows: bool) -> bool {
        let term = var("TERM").unwrap_or_default();
        if term == "linux" {
            return false;
        }
        if windows {
            // The classic console's fonts lack most of the symbols. Windows Terminal,
            // VS Code and mintty (which sets TERM) have them.
            return var("WT_SESSION").is_some()
                || var("TERM_PROGRAM").is_some()
                || !term.is_empty();
        }
        // The first locale variable that is set decides, as in `setlocale`
        let locale = ["LC_ALL", "LC_CTYPE", "LANG"]
            .iter()
            .filter_map(|name| var(name))
            .find(|value| !value.is_empty());
        match locale {
            Some(locale) => {
                let locale = locale.to_ascii_lowercase();
                locale.contains("utf-8") || locale.contains("utf8")
            }
            // Nothing set: assume a modern UTF-8 terminal
            None => true,
        }
    }
}

/// The colours for each role, before styles are applied
#[derive(Clone, Copy, Debug)]
struct Palette {
    /// Spinner, time bar, key names
    accent: Color,
    /// Found plaintext
    success: Color,
    /// Nothing found
    failure: Color,
    /// Escapes in decoded text, hints
    warning: Color,
    /// Questions
    question: Color,
    /// Decoder names, what a checker recognised
    info: Color,
}

impl Palette {
    /// The terminal's own colours
    const ANSI: Palette = Palette {
        accent: Color::Magenta,
        success: Color::Green,
        failure: Color::Red,
        warning: Color::Yellow,
        question: Color::Cyan,
        info: Color::Cyan,
    };

    /// No colours at all
    const NONE: Palette = Palette {
        accent: Color::Reset,
        success: Color::Reset,
        failure: Color::Reset,
        warning: Color::Reset,
        question: Color::Reset,
        info: Color::Reset,
    };

    /// The palette for a config colour scheme (role name to `r,g,b`)
    fn from_scheme(scheme: &HashMap<String, String>, depth: ColorDepth) -> Palette {
        if depth == ColorDepth::None {
            return Palette::NONE;
        }
        if depth == ColorDepth::Ansi16 || is_default_scheme(scheme) {
            return Palette::ANSI;
        }
        let role = |name: &str, fallback: Color| {
            scheme
                .get(name)
                .and_then(|rgb| parse_rgb_quiet(rgb))
                .map_or(fallback, |(r, g, b)| rgb_color(r, g, b, depth))
        };
        Palette {
            accent: role("question", Palette::ANSI.accent),
            success: role("success", Palette::ANSI.success),
            failure: role("warning", Palette::ANSI.failure),
            warning: role("warning", Palette::ANSI.warning),
            question: role("question", Palette::ANSI.question),
            info: role("informational", Palette::ANSI.info),
        }
    }
}

/// Whether `scheme` is ciphey's default colour scheme (pure gold, red and green).
/// That scheme was never chosen for looks, so the display uses the terminal's own
/// palette instead, which also works on light backgrounds.
fn is_default_scheme(scheme: &HashMap<String, String>) -> bool {
    let is = |role: &str, rgb: (u8, u8, u8)| {
        scheme
            .get(role)
            .and_then(|value| parse_rgb_quiet(value))
            .is_none_or(|value| value == rgb)
    };
    is("informational", (255, 215, 0)) && is("warning", (255, 0, 0)) && is("success", (0, 255, 0))
}

/// An RGB colour as the terminal can show it
fn rgb_color(r: u8, g: u8, b: u8, depth: ColorDepth) -> Color {
    match depth {
        ColorDepth::TrueColor => Color::Rgb(r, g, b),
        ColorDepth::Ansi256 => Color::Indexed(rgb_to_256(r, g, b)),
        ColorDepth::Ansi16 | ColorDepth::None => Color::Reset,
    }
}

/// The nearest colour in the xterm 256-colour palette: the 6×6×6 cube or the grey ramp
fn rgb_to_256(r: u8, g: u8, b: u8) -> u8 {
    /// The channel values of the colour cube
    const LEVELS: [i32; 6] = [0, 95, 135, 175, 215, 255];
    let nearest_level = |v: u8| {
        (0..6)
            .min_by_key(|&i| (LEVELS[i] - i32::from(v)).abs())
            .unwrap_or(0)
    };
    let distance = |(r2, g2, b2): (i32, i32, i32)| {
        let (dr, dg, db) = (i32::from(r) - r2, i32::from(g) - g2, i32::from(b) - b2);
        dr * dr + dg * dg + db * db
    };

    let (ri, gi, bi) = (nearest_level(r), nearest_level(g), nearest_level(b));
    let cube_index = 16 + 36 * ri + 6 * gi + bi;
    let cube_distance = distance((LEVELS[ri], LEVELS[gi], LEVELS[bi]));

    // The grey ramp runs from 8 to 238 in steps of 10
    let average = (i32::from(r) + i32::from(g) + i32::from(b)) / 3;
    let grey_step = ((average - 8 + 5) / 10).clamp(0, 23);
    let grey = 8 + grey_step * 10;
    let grey_distance = distance((grey, grey, grey));

    if grey_distance < cube_distance {
        (232 + grey_step) as u8
    } else {
        cube_index as u8
    }
}

/// The styles every screen uses
#[derive(Clone, Debug)]
pub struct Theme {
    /// Spinner, time bar and step numbers
    pub accent: Style,
    /// The "plaintext found" heading
    pub success: Style,
    /// The plaintext itself
    pub plaintext: Style,
    /// The "no plaintext found" heading
    pub failure: Style,
    /// Escapes in decoded text
    pub escape: Style,
    /// Questions
    pub question: Style,
    /// Decoder names and what a checker recognised
    pub info: Style,
    /// Labels in front of values
    pub label: Style,
    /// Secondary text and separators
    pub muted: Style,
    /// Key names in key hints
    pub key: Style,
    /// Bold text in the terminal's own colour
    pub strong: Style,
    /// Unicode or ASCII symbols
    pub glyphs: Glyphs,
}

impl Theme {
    /// The theme for a config colour scheme on a terminal with `depth` colours
    pub fn new(scheme: &HashMap<String, String>, depth: ColorDepth, glyphs: Glyphs) -> Theme {
        let palette = Palette::from_scheme(scheme, depth);
        // Reset would only add escape codes that change nothing
        let fg = |color: Color| match color {
            Color::Reset => Style::default(),
            color => Style::default().fg(color),
        };
        let bold = Modifier::BOLD;
        let dim = Style::default().add_modifier(Modifier::DIM);
        Theme {
            accent: fg(palette.accent),
            success: fg(palette.success).add_modifier(bold),
            plaintext: fg(palette.success).add_modifier(bold),
            failure: fg(palette.failure).add_modifier(bold),
            escape: fg(palette.warning),
            question: fg(palette.question).add_modifier(bold),
            info: fg(palette.info),
            label: dim,
            muted: dim,
            key: fg(palette.accent).add_modifier(bold),
            strong: Style::default().add_modifier(bold),
            glyphs,
        }
    }

    /// The theme for this terminal and config colour scheme
    pub fn detect(scheme: &HashMap<String, String>) -> Theme {
        Theme::new(scheme, ColorDepth::detect(), Glyphs::detect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env<'a>(vars: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |name| {
            vars.iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| value.to_string())
        }
    }

    fn scheme(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn colour_depth_follows_the_terminal() {
        assert_eq!(
            ColorDepth::from_env(env(&[("COLORTERM", "truecolor")])),
            ColorDepth::TrueColor
        );
        assert_eq!(
            ColorDepth::from_env(env(&[("TERM_PROGRAM", "Apple_Terminal")])),
            ColorDepth::Ansi256
        );
        assert_eq!(
            ColorDepth::from_env(env(&[("TERM", "linux")])),
            ColorDepth::Ansi16
        );
        assert_eq!(
            ColorDepth::from_env(env(&[("TERM", "xterm-256color")])),
            ColorDepth::TrueColor
        );
    }

    #[test]
    fn ascii_glyphs_where_unicode_is_unlikely_to_work() {
        assert!(Glyphs::unicode_ok(env(&[("LANG", "en_GB.UTF-8")]), false));
        assert!(Glyphs::unicode_ok(env(&[]), false));
        assert!(!Glyphs::unicode_ok(env(&[("LANG", "C")]), false));
        // LC_ALL wins over LANG
        assert!(!Glyphs::unicode_ok(
            env(&[("LC_ALL", "POSIX"), ("LANG", "en_US.utf8")]),
            false
        ));
        assert!(!Glyphs::unicode_ok(env(&[("TERM", "linux")]), false));
        // The classic Windows console, then Windows Terminal
        assert!(!Glyphs::unicode_ok(env(&[]), true));
        assert!(Glyphs::unicode_ok(env(&[("WT_SESSION", "1")]), true));
    }

    #[test]
    fn default_scheme_uses_the_terminal_palette() {
        let default = scheme(&[
            ("informational", "255,215,0"),
            ("warning", "255,0,0"),
            ("success", "0,255,0"),
            ("question", "255,215,0"),
            ("statement", "255,255,255"),
        ]);
        let theme = Theme::new(&default, ColorDepth::TrueColor, Glyphs::UNICODE);
        assert_eq!(theme.plaintext.fg, Some(Color::Green));
        assert_eq!(theme.failure.fg, Some(Color::Red));
    }

    #[test]
    fn chosen_scheme_keeps_its_colours() {
        let capptucin = scheme(&[
            ("informational", "238,212,159"),
            ("warning", "237,135,150"),
            ("success", "166,218,149"),
            ("question", "202,211,245"),
            ("statement", "244,219,214"),
        ]);
        let theme = Theme::new(&capptucin, ColorDepth::TrueColor, Glyphs::UNICODE);
        assert_eq!(theme.plaintext.fg, Some(Color::Rgb(166, 218, 149)));
        let theme = Theme::new(&capptucin, ColorDepth::Ansi256, Glyphs::UNICODE);
        assert!(matches!(theme.plaintext.fg, Some(Color::Indexed(_))));
    }

    #[test]
    fn no_color_keeps_bold_but_drops_colours() {
        let theme = Theme::new(&HashMap::new(), ColorDepth::None, Glyphs::UNICODE);
        for style in [theme.plaintext, theme.failure, theme.key, theme.accent] {
            assert!(matches!(style.fg, None | Some(Color::Reset)), "{style:?}");
        }
        assert!(theme.plaintext.add_modifier.contains(Modifier::BOLD));
    }

    #[test]
    fn rgb_is_reduced_to_the_nearest_256_colour() {
        assert_eq!(rgb_to_256(0, 0, 0), 16);
        assert_eq!(rgb_to_256(255, 255, 255), 231);
        assert_eq!(rgb_to_256(255, 0, 0), 196);
        // Greys go to the grey ramp
        assert_eq!(rgb_to_256(128, 128, 128), 244);
        // Capptucin green
        assert_eq!(rgb_to_256(166, 218, 149), 150);
    }

    #[test]
    fn all_glyphs_are_one_column_wide() {
        use unicode_width::UnicodeWidthStr;
        let g = Glyphs::UNICODE;
        for glyph in [
            g.found, g.failed, g.ask, g.arrow, g.sep, g.ellipsis, g.bar_done, g.bar_todo, g.bullet,
        ]
        .iter()
        .chain(g.spinner)
        {
            assert_eq!(glyph.width(), 1, "{glyph}");
        }
    }
}
