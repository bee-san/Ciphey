//! Writing styled lines to the terminal, and the live region at the bottom of it.
//!
//! The live region is a few lines that are redrawn in place while the search runs:
//! the cursor goes back to the region's first line, each line is overwritten and the
//! rest of the screen below is cleared. Nothing else on the screen is touched, so the
//! output above it and the scrollback stay as they were, and the final result is
//! printed as ordinary lines.

use super::text;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Line;
use std::fmt::Write as _;
use std::io::{self, Write};

/// Control Sequence Introducer
const CSI: &str = "\x1b[";
/// Starts a synchronized update, so the terminal shows a redraw all at once.
/// Terminals that don't know it ignore it.
const SYNC_START: &str = "\x1b[?2026h";
/// Ends a synchronized update
const SYNC_END: &str = "\x1b[?2026l";
/// Hides the cursor
pub const HIDE_CURSOR: &str = "\x1b[?25l";
/// Shows the cursor
pub const SHOW_CURSOR: &str = "\x1b[?25h";

/// Appends the SGR parameters for a colour to `sgr`. `base` is 30 for foreground
/// colours and 40 for background colours.
fn push_color(sgr: &mut String, color: Color, base: u8) {
    let named = |offset: u8| u16::from(base) + u16::from(offset);
    let code = match color {
        Color::Reset => return,
        Color::Black => named(0),
        Color::Red => named(1),
        Color::Green => named(2),
        Color::Yellow => named(3),
        Color::Blue => named(4),
        Color::Magenta => named(5),
        Color::Cyan => named(6),
        Color::Gray => named(7),
        Color::DarkGray => named(60),
        Color::LightRed => named(61),
        Color::LightGreen => named(62),
        Color::LightYellow => named(63),
        Color::LightBlue => named(64),
        Color::LightMagenta => named(65),
        Color::LightCyan => named(66),
        Color::White => named(67),
        Color::Indexed(i) => {
            let _ = write!(sgr, ";{};5;{i}", base + 8);
            return;
        }
        Color::Rgb(r, g, b) => {
            let _ = write!(sgr, ";{};2;{r};{g};{b}", base + 8);
            return;
        }
    };
    let _ = write!(sgr, ";{code}");
}

/// The escape code that sets `style`, starting from no style at all
fn sgr(style: Style) -> String {
    let mut params = String::from("0");
    let modifiers = style.add_modifier;
    for (modifier, code) in [
        (Modifier::BOLD, 1),
        (Modifier::DIM, 2),
        (Modifier::ITALIC, 3),
        (Modifier::UNDERLINED, 4),
        (Modifier::REVERSED, 7),
    ] {
        if modifiers.contains(modifier) {
            let _ = write!(params, ";{code}");
        }
    }
    if let Some(fg) = style.fg {
        push_color(&mut params, fg, 30);
    }
    if let Some(bg) = style.bg {
        push_color(&mut params, bg, 40);
    }
    format!("{CSI}{params}m")
}

/// One line as text with ANSI escape codes. Styles are only written where they
/// change, and the line ends with everything reset.
pub fn to_ansi(line: &Line<'_>) -> String {
    let mut out = String::new();
    let mut current = Style::default();
    for span in &line.spans {
        let style = line.style.patch(span.style);
        if style != current {
            out.push_str(&sgr(style));
            current = style;
        }
        out.push_str(&span.content);
    }
    if current != Style::default() {
        let _ = write!(out, "{CSI}0m");
    }
    out
}

/// Display width of a line in columns
pub fn line_width(line: &Line<'_>) -> usize {
    line.spans
        .iter()
        .map(|span| text::width(&span.content))
        .sum()
}

/// Prints `lines` as ordinary output, one per line, for the result screens.
///
/// # Errors
///
/// Returns an error if writing to `out` fails.
pub fn print_lines(out: &mut impl Write, lines: &[Line<'_>]) -> io::Result<()> {
    let mut buffer = String::new();
    for line in lines {
        buffer.push_str(&to_ansi(line));
        buffer.push('\n');
    }
    out.write_all(buffer.as_bytes())?;
    out.flush()
}

/// The lines at the bottom of the terminal that are redrawn while the search runs
pub struct LiveRegion<W: Write> {
    /// Where the region is drawn, normally stdout
    out: W,
    /// Width of each line currently on screen, top to bottom
    drawn: Vec<usize>,
}

impl<W: Write> LiveRegion<W> {
    /// An empty region starting at the cursor, which must be at the start of a line
    pub fn new(out: W) -> Self {
        LiveRegion {
            out,
            drawn: Vec::new(),
        }
    }

    /// Terminal rows the drawn lines take up at `width` columns. Lines are drawn
    /// narrower than the terminal, but if it has been made narrower since, terminals
    /// that re-wrap long lines will have spread them over more rows.
    fn rows(&self, width: u16) -> usize {
        let width = usize::from(width.max(1));
        self.drawn.iter().map(|&w| w.max(1).div_ceil(width)).sum()
    }

    /// Escape codes that move the cursor from the end of the region to its start
    fn to_top(&self, width: u16, out: &mut String) {
        out.push('\r');
        let up = self.rows(width).saturating_sub(1);
        if up > 0 {
            let _ = write!(out, "{CSI}{up}A");
        }
    }

    /// Replaces what the region shows with `lines`. Every line must be narrower than
    /// `width`, the terminal's width. The cursor is left at the end of the last line.
    ///
    /// # Errors
    ///
    /// Returns an error if writing to the terminal fails.
    pub fn draw(&mut self, lines: &[Line<'_>], width: u16) -> io::Result<()> {
        let mut out = String::from(SYNC_START);
        self.to_top(width, &mut out);
        for (i, line) in lines.iter().enumerate() {
            if i > 0 {
                out.push_str("\r\n");
            }
            out.push_str(&to_ansi(line));
            // Clear what is left of the line from the previous frame
            let _ = write!(out, "{CSI}K");
        }
        // Clear lines left over from a taller previous frame
        let _ = write!(out, "{CSI}J");
        out.push_str(SYNC_END);
        self.out.write_all(out.as_bytes())?;
        self.out.flush()?;
        self.drawn = lines.iter().map(line_width).collect();
        Ok(())
    }

    /// Removes the region from the screen, leaving the cursor where it started
    ///
    /// # Errors
    ///
    /// Returns an error if writing to the terminal fails.
    pub fn clear(&mut self, width: u16) -> io::Result<()> {
        if self.drawn.is_empty() {
            return Ok(());
        }
        let mut out = String::new();
        self.to_top(width, &mut out);
        let _ = write!(out, "{CSI}J");
        self.out.write_all(out.as_bytes())?;
        self.out.flush()?;
        self.drawn.clear();
        Ok(())
    }

    /// Prints `lines` permanently above the region. The region is cleared and must be
    /// drawn again afterwards.
    ///
    /// # Errors
    ///
    /// Returns an error if writing to the terminal fails.
    pub fn print_above(&mut self, lines: &[Line<'_>], width: u16) -> io::Result<()> {
        self.clear(width)?;
        let mut out = String::new();
        for line in lines {
            out.push_str(&to_ansi(line));
            // The terminal is in raw mode, where a newline doesn't return the cursor
            out.push_str("\r\n");
        }
        self.out.write_all(out.as_bytes())?;
        self.out.flush()
    }

    /// Writes raw text, such as cursor visibility codes, straight to the terminal
    ///
    /// # Errors
    ///
    /// Returns an error if writing to the terminal fails.
    pub fn write_raw(&mut self, raw: &str) -> io::Result<()> {
        self.out.write_all(raw.as_bytes())?;
        self.out.flush()
    }

    /// The writer, for tests
    #[cfg(test)]
    fn into_inner(self) -> W {
        self.out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::text::Span;

    #[test]
    fn styles_become_sgr_codes() {
        let line = Line::from(vec![
            Span::styled(
                "ok",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" then "),
            Span::styled("rgb", Style::default().fg(Color::Rgb(1, 2, 3))),
            Span::styled("256", Style::default().fg(Color::Indexed(150))),
        ]);
        assert_eq!(
            to_ansi(&line),
            "\x1b[0;1;32mok\x1b[0m then \x1b[0;38;2;1;2;3mrgb\x1b[0;38;5;150m256\x1b[0m"
        );
    }

    #[test]
    fn unstyled_lines_have_no_escape_codes() {
        assert_eq!(to_ansi(&Line::from("plain")), "plain");
    }

    #[test]
    fn redraw_returns_to_the_top_and_clears_leftovers() {
        let mut region = LiveRegion::new(Vec::new());
        region
            .draw(
                &[Line::from("one"), Line::from("two"), Line::from("three")],
                80,
            )
            .unwrap();
        region.draw(&[Line::from("four")], 80).unwrap();
        let written = String::from_utf8(region.into_inner()).unwrap();
        assert_eq!(
            written,
            "\x1b[?2026h\rone\x1b[K\r\ntwo\x1b[K\r\nthree\x1b[K\x1b[J\x1b[?2026l\
             \x1b[?2026h\r\x1b[2Afour\x1b[K\x1b[J\x1b[?2026l"
        );
    }

    #[test]
    fn shrinking_terminal_counts_rewrapped_rows() {
        let mut region = LiveRegion::new(Vec::new());
        let long = "x".repeat(70);
        region
            .draw(&[Line::from(long.as_str()), Line::from("short")], 80)
            .unwrap();
        // At 40 columns the 70 column line now takes two rows
        assert_eq!(region.rows(40), 3);
        assert_eq!(region.rows(80), 2);
    }

    #[test]
    fn clearing_an_empty_region_writes_nothing() {
        let mut region = LiveRegion::new(Vec::new());
        region.clear(80).unwrap();
        assert!(region.into_inner().is_empty());
    }
}
