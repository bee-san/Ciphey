//! The screens, as lists of styled lines.
//!
//! Live screens, redrawn while the search runs: [`searching`], [`prompt`] (a question
//! about a candidate plaintext) and [`keys`]. Every line of them fits the width given.
//!
//! Printed screens, which stay in the scrollback: [`success`], [`failure`] and
//! [`top_results`]. The plaintext in them is never wrapped by ciphey: the terminal
//! wraps it, so selecting and copying it gives back exactly the text.

use super::text::{self, Piece};
use super::theme::Theme;
use crate::decoders::crack_results::CrackResult;
use crate::searchers::progress::Snapshot;
use crate::storage::wait_athena_storage::PlaintextResult;
use crate::DecoderResult;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use std::time::Duration;

/// Spaces in front of the lines under a heading
const INDENT: &str = "  ";
/// Columns for the labels in front of values ("Explored  ")
const LABEL_WIDTH: usize = 10;
/// The widest the time bar gets
const BAR_MAX: usize = 32;

/// What the search screen shows
#[derive(Debug, Clone)]
pub struct SearchView<'a> {
    /// Search time so far, not counting time spent answering questions
    pub elapsed: Duration,
    /// The time limit in seconds
    pub timeout: u32,
    /// What the search has done so far
    pub progress: &'a Snapshot,
    /// How many decoders are tried on each text
    pub decoders: usize,
    /// In top results mode, how many possible plaintexts were collected so far
    pub found: Option<usize>,
    /// The regex crib, if there is one
    pub regex: Option<&'a str>,
    /// The user asked to stop and the search is winding down
    pub stopping: bool,
    /// Animation frame for the spinner
    pub frame: usize,
}

/// A candidate plaintext the human checker asks about
#[derive(Debug, Clone)]
pub struct PromptView<'a> {
    /// The candidate
    pub text: &'a str,
    /// Name of the checker that found it
    pub checker: &'a str,
    /// What the checker said about it
    pub description: &'a str,
    /// 1 for the first candidate asked about, 2 for the second, ...
    pub number: usize,
}

/// A found plaintext and how it was found
#[derive(Debug, Clone)]
pub struct SuccessView<'a> {
    /// The plaintext and the decoders that produced it
    pub result: &'a DecoderResult,
    /// How long the search took, not counting time spent answering questions
    pub elapsed: Duration,
    /// What the search did
    pub progress: &'a Snapshot,
    /// The user said yes to it
    pub confirmed: bool,
    /// What LemmeKnow recognised the plaintext as, when it was LemmeKnow that found it
    pub recognised_as: Option<&'a str>,
    /// The regex crib, if there is one
    pub regex: Option<&'a str>,
    /// Where the plaintext was saved instead of being printed
    pub saved_to: Option<&'a str>,
}

/// Why a search ended without a plaintext
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ending {
    /// The time limit ran out
    TimedOut,
    /// Every decoder was tried on everything the search found
    Exhausted,
    /// The user pressed q
    Stopped,
}

/// A search that found nothing
#[derive(Debug, Clone)]
pub struct FailureView<'a> {
    /// Why it ended
    pub ending: Ending,
    /// How long it ran, not counting time spent answering questions
    pub elapsed: Duration,
    /// The time limit in seconds
    pub timeout: u32,
    /// What the search did
    pub progress: &'a Snapshot,
    /// Candidates the user said no to
    pub rejected: usize,
    /// The regex crib, if there is one
    pub regex: Option<&'a str>,
}

/// `n` and the word for it, singular or plural: "1 layer", "3 layers"
fn count(n: u64, one: &str, many: &str) -> String {
    format!("{} {}", text::thousands(n), if n == 1 { one } else { many })
}

/// An empty line
fn blank() -> Line<'static> {
    Line::default()
}

/// Cuts a line down to `width` columns, ending it with an ellipsis if anything was cut
fn fit(line: Line<'static>, width: usize, ellipsis: &str) -> Line<'static> {
    let total: usize = line.spans.iter().map(|s| text::width(&s.content)).sum();
    if total <= width {
        return line;
    }
    // Too narrow even for the ellipsis: just cut
    let ellipsis = if text::width(ellipsis) < width {
        ellipsis
    } else {
        ""
    };
    let room = width - text::width(ellipsis);
    let mut used = 0;
    let mut spans = Vec::new();
    for span in line.spans {
        let w = text::width(&span.content);
        if used + w <= room {
            used += w;
            spans.push(span);
            continue;
        }
        let cut = text::truncate(&span.content, room - used, "");
        if !cut.is_empty() {
            spans.push(Span::styled(cut, span.style));
        }
        break;
    }
    if !ellipsis.is_empty() {
        spans.push(Span::raw(ellipsis.to_string()));
    }
    Line::from(spans)
}

/// A value with a label in front of it, indented: `  Explored  1,204 texts`
fn labelled(label: &str, value: Vec<Span<'static>>, theme: &Theme) -> Line<'static> {
    let mut spans = vec![
        Span::raw(INDENT),
        Span::styled(format!("{label:<LABEL_WIDTH$}"), theme.label),
    ];
    spans.extend(value);
    Line::from(spans)
}

/// Columns taken by [`labelled`]'s indent and label
const LABELLED_WIDTH: usize = INDENT.len() + LABEL_WIDTH;

/// A labelled value that wraps onto at most `max_lines` lines, continuation lines
/// lined up under the value. `lead` (a name in its own style) starts the value.
fn labelled_wrapped(
    label: &str,
    lead: Option<Span<'static>>,
    rest: &str,
    theme: &Theme,
    width: usize,
    max_lines: usize,
) -> Vec<Line<'static>> {
    let value_width = width.saturating_sub(LABELLED_WIDTH).max(8);
    let lead_text = lead
        .as_ref()
        .map(|s| s.content.to_string())
        .unwrap_or_default();
    let mut rows = text::wrap(&format!("{lead_text}{rest}"), value_width);
    if rows.len() > max_lines {
        rows.truncate(max_lines);
        if let Some(last) = rows.last_mut() {
            let cut = text::truncate(last, value_width.saturating_sub(1), "");
            *last = format!("{cut}{}", theme.glyphs.ellipsis);
        }
    }
    rows.into_iter()
        .enumerate()
        .map(|(i, row)| {
            let mut value = Vec::new();
            match &lead {
                // The name keeps its style if wrapping left it whole on the first row
                Some(lead) if i == 0 && row.starts_with(lead.content.as_ref()) => {
                    value.push(lead.clone());
                    value.push(Span::raw(row[lead.content.len()..].to_string()));
                }
                _ => value.push(Span::raw(row)),
            }
            labelled(if i == 0 { label } else { "" }, value, theme)
        })
        .collect()
}

/// Key hints, `q stop · ? help`
fn hints(keys: &[(&str, &str)], theme: &Theme) -> Line<'static> {
    let mut spans = vec![Span::raw(INDENT)];
    for (i, (key, what)) in keys.iter().enumerate() {
        if i > 0 {
            spans.push(Span::styled(format!(" {} ", theme.glyphs.sep), theme.muted));
        }
        spans.push(Span::styled(key.to_string(), theme.key));
        spans.push(Span::styled(format!(" {what}"), theme.muted));
    }
    Line::from(spans)
}

/// The time bar, `width` columns wide: used time against the time limit
fn time_bar(elapsed: Duration, timeout: u32, width: usize, theme: &Theme) -> Vec<Span<'static>> {
    let fraction = if timeout == 0 {
        1.0
    } else {
        (elapsed.as_secs_f64() / f64::from(timeout)).clamp(0.0, 1.0)
    };
    let done = ((fraction * width as f64).round() as usize).min(width);
    vec![
        Span::styled(theme.glyphs.bar_done.repeat(done), theme.accent),
        Span::styled(theme.glyphs.bar_todo.repeat(width - done), theme.muted),
    ]
}

/// Decoder names joined by arrows. If they don't fit in `width` columns, the first
/// ones are left out: the last layers are the interesting ones.
fn path_spans(names: &[String], width: usize, theme: &Theme) -> Vec<Span<'static>> {
    let arrow = format!(" {} ", theme.glyphs.arrow);
    let mut start = 0;
    let total = |from: usize| {
        let names_width: usize = names[from..].iter().map(|n| text::width(n)).sum();
        let arrows = names.len() - from - 1;
        let skipped = if from > 0 {
            text::width(theme.glyphs.ellipsis) + text::width(&arrow)
        } else {
            0
        };
        names_width + arrows * text::width(&arrow) + skipped
    };
    while start + 1 < names.len() && total(start) > width {
        start += 1;
    }
    let mut spans = Vec::new();
    if start > 0 {
        spans.push(Span::styled(theme.glyphs.ellipsis.to_string(), theme.muted));
        spans.push(Span::styled(arrow.clone(), theme.muted));
    }
    for (i, name) in names[start..].iter().enumerate() {
        if i > 0 {
            spans.push(Span::styled(arrow.clone(), theme.muted));
        }
        spans.push(Span::styled(name.clone(), theme.info));
    }
    spans
}

/// The search screen: time used, the decoders being tried, how far the search got
pub fn searching(view: &SearchView<'_>, theme: &Theme, width: usize) -> Vec<Line<'static>> {
    let glyphs = &theme.glyphs;
    let spinner = glyphs.spinner[view.frame % glyphs.spinner.len()];
    let title = if view.stopping {
        "Stopping"
    } else if view.found.is_some() {
        "Collecting plaintexts"
    } else {
        "Searching"
    };
    let time = format!(
        "{} of {}",
        text::duration(view.elapsed),
        text::seconds(view.timeout)
    );

    let mut head = vec![
        Span::styled(spinner.to_string(), theme.accent),
        Span::raw(" "),
        Span::styled(title.to_string(), theme.strong),
        Span::raw("  "),
        Span::raw(time.clone()),
    ];
    let head_width = text::width(spinner) + 1 + title.len() + 2 + text::width(&time);
    let mut lines = Vec::new();
    // The bar goes on the first line if there is room, otherwise on a line of its own
    let room = width.saturating_sub(head_width + 2).min(BAR_MAX);
    if room >= 10 {
        head.push(Span::raw("  "));
        head.extend(time_bar(view.elapsed, view.timeout, room, theme));
        lines.push(Line::from(head));
    } else {
        lines.push(Line::from(head));
        let room = width.saturating_sub(INDENT.len()).min(BAR_MAX);
        if room >= 4 {
            let mut bar = vec![Span::raw(INDENT)];
            bar.extend(time_bar(view.elapsed, view.timeout, room, theme));
            lines.push(Line::from(bar));
        }
    }

    let trying = if view.progress.trying.is_empty() {
        vec![Span::raw(format!(
            "all {} decoders on your input",
            view.decoders
        ))]
    } else {
        let names: Vec<String> = view
            .progress
            .trying
            .iter()
            .map(|name| text::decoder_name(name).into_owned())
            .collect();
        path_spans(&names, width.saturating_sub(LABELLED_WIDTH), theme)
    };
    lines.push(labelled("Trying", trying, theme));

    let explored = if view.progress.expanded == 0 {
        "nothing yet".to_string()
    } else {
        format!(
            "{} {} {} deep",
            count(view.progress.expanded, "text", "texts"),
            glyphs.sep,
            count(u64::from(view.progress.layers()), "layer", "layers")
        )
    };
    lines.push(labelled("Explored", vec![Span::raw(explored)], theme));

    if let Some(found) = view.found {
        lines.push(labelled(
            "Found",
            vec![Span::raw(count(
                found as u64,
                "possible plaintext",
                "possible plaintexts",
            ))],
            theme,
        ));
    }
    if let Some(regex) = view.regex {
        lines.push(labelled(
            "Regex",
            vec![Span::styled(text::sanitize(regex).into_owned(), theme.info)],
            theme,
        ));
    }

    if view.stopping {
        lines.push(Line::from(vec![
            Span::raw(INDENT),
            Span::styled(
                format!("Stopping the search{}", glyphs.ellipsis),
                theme.muted,
            ),
        ]));
    } else {
        lines.push(hints(&[("q", "stop"), ("?", "help")], theme));
    }

    lines
        .into_iter()
        .map(|line| fit(line, width, glyphs.ellipsis))
        .collect()
}

/// Who found a candidate and what they made of it, as the checker's name and the
/// rest: (`English checker`, ` · looks like English`)
fn found_by(
    checker: &str,
    description: Option<&str>,
    theme: &Theme,
) -> Option<(Span<'static>, String)> {
    let what = text::identification(checker, description)?;
    Some((
        Span::styled(text::checker_name(checker).to_string(), theme.info),
        format!(" {} {what}", theme.glyphs.sep),
    ))
}

/// Adds `extra` to the end of `spans` if the line still fits in `width` columns
fn push_if_fits(spans: &mut Vec<Span<'static>>, extra: Span<'static>, width: usize) {
    let used: usize = spans.iter().map(|s| text::width(&s.content)).sum();
    if used + text::width(&extra.content) <= width {
        spans.push(extra);
    }
}

/// The question about a candidate plaintext, in at most `max_lines` lines
pub fn prompt(
    view: &PromptView<'_>,
    theme: &Theme,
    width: usize,
    max_lines: usize,
) -> Vec<Line<'static>> {
    let glyphs = &theme.glyphs;
    let mut title = vec![Span::styled(
        format!("{} Is this the plaintext?", glyphs.ask),
        theme.question,
    )];
    if view.number > 1 {
        push_if_fits(
            &mut title,
            Span::styled(
                format!(" {} candidate {}", glyphs.sep, view.number),
                theme.muted,
            ),
            width,
        );
    }
    push_if_fits(
        &mut title,
        Span::styled(format!(" {} timer paused", glyphs.sep), theme.muted),
        width,
    );

    let found: Vec<Line<'static>> = found_by(view.checker, Some(view.description), theme)
        .map(|(lead, rest)| labelled_wrapped("Found by", Some(lead), &rest, theme, width, 2))
        .unwrap_or_default();
    let keys = hints(
        &[("y", "yes"), ("n", "no, keep looking"), ("q", "stop")],
        theme,
    );

    // Title, blank, candidate, blank, found by, keys
    let fixed = 4 + found.len();
    let room = max_lines.saturating_sub(fixed).max(1);
    let text_width = width.saturating_sub(INDENT.len()).max(1);
    let mut candidate: Vec<String> = view
        .text
        .lines()
        .flat_map(|line| text::wrap(&text::sanitize(line), text_width))
        .collect();
    if candidate.is_empty() {
        candidate.push(String::new());
    }
    let hidden = candidate.len().saturating_sub(room);
    if hidden > 0 {
        candidate.truncate(room);
        if let Some(last) = candidate.last_mut() {
            let shortened = text::truncate(last, text_width.saturating_sub(1), "");
            *last = format!("{shortened}{}", glyphs.ellipsis);
        }
    }

    let mut lines = vec![Line::from(title), blank()];
    lines.extend(
        candidate
            .into_iter()
            .map(|line| Line::from(vec![Span::raw(INDENT), Span::styled(line, theme.strong)])),
    );
    lines.push(blank());
    lines.extend(found);
    lines.push(keys);
    lines
        .into_iter()
        .map(|line| fit(line, width, glyphs.ellipsis))
        .collect()
}

/// The keys, shown under the search screen or the question when `?` is pressed
pub fn keys(theme: &Theme, width: usize) -> Vec<Line<'static>> {
    let key = |keys: &str, what: &str| {
        Line::from(vec![
            Span::raw(INDENT),
            Span::styled(format!("{keys:<LABEL_WIDTH$}"), theme.key),
            Span::raw(what.to_string()),
        ])
    };
    let heading = |title: &str| {
        Line::from(vec![
            Span::raw(INDENT),
            Span::styled(title.to_string(), theme.strong),
        ])
    };
    [
        blank(),
        heading("While searching"),
        key("q, Esc", "stop and show what was found"),
        key("?", "show or hide these keys"),
        key("Ctrl-C", "quit straight away"),
        key("Ctrl-Z", "pause ciphey; fg carries on"),
        heading("When asked about a plaintext"),
        key("y", "yes, that's the plaintext"),
        key("n, Enter", "no, keep searching"),
    ]
    .into_iter()
    .map(|line| fit(line, width, theme.glyphs.ellipsis))
    .collect()
}

/// A line kept in the scrollback for a candidate the user said no to
pub fn rejected(candidate: &str, theme: &Theme, width: usize) -> Line<'static> {
    let first_line = candidate.lines().next().unwrap_or_default();
    let line = Line::from(vec![
        Span::styled(format!("{} ", theme.glyphs.failed), theme.muted),
        Span::styled("Not it  ", theme.muted),
        Span::styled(text::sanitize(first_line).into_owned(), theme.muted),
    ]);
    fit(line, width, theme.glyphs.ellipsis)
}

/// One line of decoded text with its escapes styled, unwrapped
fn decoded_line(line: &str, style: Style, theme: &Theme) -> Vec<Span<'static>> {
    text::pieces(line)
        .into_iter()
        .map(|piece| match piece {
            Piece::Text(t) => Span::styled(t, style),
            Piece::Escape(e) => Span::styled(e, theme.escape),
        })
        .collect()
}

/// The plaintext block: indented when every line fits, otherwise flush left so the
/// terminal's own wrapping keeps it in one piece
fn plaintext_block(plaintext: &str, theme: &Theme, width: usize) -> Vec<Line<'static>> {
    let lines: Vec<&str> = if plaintext.is_empty() {
        vec![""]
    } else {
        plaintext.lines().collect()
    };
    let fits = lines
        .iter()
        .all(|line| text::width(&text::sanitize(line)) + INDENT.len() <= width);
    lines
        .into_iter()
        .map(|line| {
            let mut spans = Vec::new();
            if fits {
                spans.push(Span::raw(INDENT));
            }
            spans.extend(decoded_line(line, theme.plaintext, theme));
            Line::from(spans)
        })
        .collect()
}

/// The decoders of a path, one per row with the text each one produced:
///
/// ```text
/// 1  Base64          → 50766375726c20766620…
/// 2  Hexadecimal     → Pvcurl vf irel snfg
/// ```
fn steps(path: &[CrackResult], theme: &Theme, width: usize) -> Vec<Vec<Span<'static>>> {
    let glyphs = &theme.glyphs;
    let names: Vec<String> = path.iter().map(text::step_name).collect();
    let name_width = names
        .iter()
        .map(|n| text::width(n))
        .max()
        .unwrap_or(0)
        .min(24);
    let number_width = path.len().to_string().len();
    let arrow = format!("{} ", glyphs.arrow);
    // The row starts after the label column
    let used = LABELLED_WIDTH + number_width + 2 + name_width + 2 + text::width(&arrow);
    let output_room = width.saturating_sub(used);

    path.iter()
        .zip(names)
        .enumerate()
        .map(|(i, (step, name))| {
            let name = text::truncate(&name, name_width, glyphs.ellipsis);
            let padding = name_width.saturating_sub(text::width(&name));
            let mut row = vec![
                Span::styled(format!("{:>number_width$}  ", i + 1), theme.accent),
                Span::styled(name, theme.info),
            ];
            let output = text::step_output(step)
                .map(|out| out.lines().next().unwrap_or_default())
                .filter(|out| !out.is_empty());
            if let (Some(output), true) = (output, output_room >= 8) {
                row.push(Span::raw(" ".repeat(padding + 2)));
                row.push(Span::styled(arrow.clone(), theme.muted));
                row.push(Span::raw(text::truncate(
                    &text::sanitize(output),
                    output_room,
                    glyphs.ellipsis,
                )));
            }
            row
        })
        .collect()
}

/// The screen for a found plaintext: the text, the decoders that produced it and the
/// checker that recognised it
pub fn success(view: &SuccessView<'_>, theme: &Theme, width: usize) -> Vec<Line<'static>> {
    let glyphs = &theme.glyphs;
    let result = view.result;
    let plaintext = result.text.first().map(String::as_str).unwrap_or_default();
    let input_was_plaintext = text::is_input_plaintext(&result.path);
    let path: &[CrackResult] = if input_was_plaintext {
        &[]
    } else {
        &result.path
    };

    let mut heading = vec![Span::styled(
        format!(
            "{} {}",
            glyphs.found,
            if input_was_plaintext {
                "Your input is already plaintext"
            } else {
                "Plaintext found"
            }
        ),
        theme.success,
    )];
    if !input_was_plaintext && !view.progress.cache_hit {
        heading.push(Span::raw(format!(" in {}", text::duration(view.elapsed))));
    }
    if view.progress.cache_hit {
        heading.push(Span::styled(
            format!(" {} from the cache", glyphs.sep),
            theme.muted,
        ));
    }
    if path.len() > 1 {
        heading.push(Span::styled(
            format!(
                " {} {}",
                glyphs.sep,
                count(path.len() as u64, "layer", "layers")
            ),
            theme.muted,
        ));
    }

    let mut lines = vec![fit(Line::from(heading), width, glyphs.ellipsis), blank()];
    // Rows left as they are, however wide: the plaintext, or where it was saved.
    // The terminal wraps them, so they can be copied whole.
    let kept_rows = match view.saved_to {
        Some(path) => {
            lines.push(labelled(
                "Saved to",
                vec![Span::styled(
                    text::sanitize(path).into_owned(),
                    theme.strong,
                )],
                theme,
            ));
            lines.len() - 1..lines.len()
        }
        None => {
            let block = plaintext_block(plaintext, theme, width);
            let rows = lines.len()..lines.len() + block.len();
            lines.extend(block);
            rows
        }
    };
    lines.push(blank());

    match path {
        [] => {}
        [only] => lines.push(labelled(
            "Decoded",
            vec![Span::styled(text::step_name(only), theme.info)],
            theme,
        )),
        _ => {
            for (i, row) in steps(path, theme, width).into_iter().enumerate() {
                let label = if i == 0 { "Decoded" } else { "" };
                lines.push(labelled(label, row, theme));
            }
        }
    }

    if let Some(last) = result.path.last() {
        let regex_description = view.regex.map(|regex| format!("Regex matched: {regex}"));
        let description = match last.checker_name {
            "LemmeKnow Checker" => view.recognised_as,
            "Regex Checker" => regex_description.as_deref(),
            _ => None,
        };
        if let Some((lead, mut rest)) = found_by(last.checker_name, description, theme) {
            if view.confirmed {
                rest.push_str(&format!(" {} you said yes", glyphs.sep));
            }
            lines.extend(labelled_wrapped(
                "Found by",
                Some(lead),
                &rest,
                theme,
                width,
                3,
            ));
        }
    }

    if view.progress.cache_hit {
        lines.extend(labelled_wrapped(
            "Cached",
            None,
            "from an earlier run; delete ~/.ciphey/database.sqlite to forget it",
            theme,
            width,
            3,
        ));
    } else if !input_was_plaintext && view.progress.expanded > 0 {
        let searched = format!(
            "{}, up to {} deep",
            count(view.progress.expanded, "text", "texts"),
            count(u64::from(view.progress.layers()), "layer", "layers"),
        );
        lines.extend(labelled_wrapped(
            "Searched", None, &searched, theme, width, 2,
        ));
    }

    // The plaintext block is left as it is, everything else has to fit
    lines
        .into_iter()
        .enumerate()
        .map(|(i, line)| {
            if kept_rows.contains(&i) {
                line
            } else {
                fit(line, width, glyphs.ellipsis)
            }
        })
        .collect()
}

/// The screen for a search that found nothing, with things to try next
pub fn failure(view: &FailureView<'_>, theme: &Theme, width: usize) -> Vec<Line<'static>> {
    let glyphs = &theme.glyphs;
    let why = match view.ending {
        Ending::TimedOut => format!("the {} time limit ran out", text::seconds(view.timeout)),
        Ending::Exhausted => "there was nothing left to try".to_string(),
        Ending::Stopped => format!("you stopped it after {}", text::duration(view.elapsed)),
    };
    let title = format!("{} No plaintext found", glyphs.failed);
    let reason = format!(" {} {why}", glyphs.sep);
    let mut lines = Vec::new();
    if text::width(&title) + text::width(&reason) <= width {
        lines.push(Line::from(vec![
            Span::styled(title, theme.failure),
            Span::styled(reason, theme.muted),
        ]));
    } else {
        // Too narrow for one line: the reason goes underneath
        lines.push(Line::from(Span::styled(title, theme.failure)));
        let reason = format!("{}{}", INDENT, capitalise(&why));
        lines.push(Line::from(Span::styled(reason, theme.muted)));
    }
    lines.push(blank());

    let looking_for = match view.regex {
        Some(regex) => format!("matches your regex {}", text::sanitize(regex)),
        None => "looks like plaintext".to_string(),
    };
    let mut summary = format!(
        "Ciphey explored {}, up to {} deep, and nothing it found {looking_for}.",
        count(view.progress.expanded, "text", "texts"),
        count(u64::from(view.progress.layers().max(1)), "layer", "layers"),
    );
    if view.rejected > 0 {
        summary.push_str(&format!(
            " You said no to {}.",
            count(view.rejected as u64, "candidate", "candidates")
        ));
    }
    let body_width = width.saturating_sub(INDENT.len()).max(20);
    lines.extend(
        text::wrap(&summary, body_width)
            .into_iter()
            .map(|line| Line::from(vec![Span::raw(INDENT), Span::raw(line)])),
    );
    lines.push(blank());
    lines.push(Line::from(vec![
        Span::raw(INDENT),
        Span::styled("Things to try", theme.strong),
    ]));

    let mut tips: Vec<(String, &str)> = Vec::new();
    if view.ending == Ending::TimedOut {
        let longer = view.timeout.saturating_mul(3).max(15);
        tips.push((format!("-c {longer}"), "search for longer"));
    }
    if view.regex.is_some() {
        tips.push(("-r".to_string(), "loosen the regex, or try without it"));
    } else {
        tips.push((
            "-r 'REGEX'".to_string(),
            "if you know part of the plaintext, such as flag\\{",
        ));
    }
    tips.push((
        "--wordlist FILE".to_string(),
        "accept exact matches from a wordlist",
    ));
    let option_width = tips.iter().map(|(o, _)| text::width(o)).max().unwrap_or(0);
    // "  • " then the option column, then the description
    let lead = INDENT.len() + text::width(glyphs.bullet) + 1;
    let what_column = lead + option_width + 2;
    for (option, what) in tips {
        let bullet = vec![
            Span::raw(INDENT),
            Span::styled(format!("{} ", glyphs.bullet), theme.muted),
        ];
        if width >= what_column + 16 {
            let rows = text::wrap(what, width - what_column);
            for (i, row) in rows.into_iter().enumerate() {
                let mut spans = if i == 0 {
                    let mut first = bullet.clone();
                    first.push(Span::styled(
                        format!("{option:<option_width$}  "),
                        theme.key,
                    ));
                    first
                } else {
                    vec![Span::raw(" ".repeat(what_column))]
                };
                spans.push(Span::raw(row));
                lines.push(Line::from(spans));
            }
        } else {
            // Narrow: the option on its own line, the description under it
            let mut first = bullet;
            first.push(Span::styled(option, theme.key));
            lines.push(Line::from(first));
            for row in text::wrap(what, width.saturating_sub(lead).max(8)) {
                lines.push(Line::from(vec![
                    Span::raw(" ".repeat(lead)),
                    Span::raw(row),
                ]));
            }
        }
    }

    // The link is never cut short
    let ask = "ask in #coded-messages on Discord:";
    let link = "http://discord.skerritt.blog";
    let mut discord = vec![
        Span::raw(INDENT),
        Span::styled(format!("{} ", glyphs.bullet), theme.muted),
        Span::raw(ask),
    ];
    if lead + text::width(ask) + 1 + text::width(link) <= width {
        discord.push(Span::raw(" "));
        discord.push(Span::styled(link, theme.info));
        lines.push(Line::from(discord));
    } else {
        lines.push(Line::from(discord));
        lines.push(Line::from(vec![
            Span::raw(" ".repeat(lead)),
            Span::styled(link, theme.info),
        ]));
    }

    lines
        .into_iter()
        .map(|line| fit(line, width, glyphs.ellipsis))
        .collect()
}

/// `text` with a capital first letter
fn capitalise(text: &str) -> String {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

/// The list of possible plaintexts collected in top results mode, one per line
pub fn top_results(
    results: &[PlaintextResult],
    elapsed: Duration,
    theme: &Theme,
    width: usize,
) -> Vec<Line<'static>> {
    let glyphs = &theme.glyphs;
    let collected = format!(" {} collected for {}", glyphs.sep, text::duration(elapsed));
    if results.is_empty() {
        return vec![
            fit(
                Line::from(vec![
                    Span::styled(
                        format!("{} No possible plaintexts found", glyphs.failed),
                        theme.failure,
                    ),
                    Span::styled(collected, theme.muted),
                ]),
                width,
                glyphs.ellipsis,
            ),
            blank(),
        ];
    }

    let heading = Line::from(vec![
        Span::styled(
            format!(
                "{} {}",
                glyphs.found,
                count(
                    results.len() as u64,
                    "possible plaintext",
                    "possible plaintexts"
                )
            ),
            theme.success,
        ),
        Span::styled(collected, theme.muted),
    ]);
    let mut lines = vec![fit(heading, width, glyphs.ellipsis), blank()];

    let number_width = results.len().to_string().len();
    let details: Vec<String> = results
        .iter()
        .map(|r| {
            let checker = text::checker_name(&r.checker_name);
            format!(
                "{} {} {checker}",
                text::decoder_name(&r.decoder_name),
                glyphs.sep
            )
        })
        .collect();
    let details_width = details
        .iter()
        .map(|d| text::width(d))
        .max()
        .unwrap_or(0)
        .min(width / 3);
    let text_width = width
        .saturating_sub(INDENT.len() + number_width + 2 + 2 + details_width)
        .max(10);

    for (i, (result, detail)) in results.iter().zip(details).enumerate() {
        let shown = text::truncate(
            &text::sanitize(result.text.lines().next().unwrap_or_default()),
            text_width,
            glyphs.ellipsis,
        );
        let padding = text_width.saturating_sub(text::width(&shown));
        let line = Line::from(vec![
            Span::raw(INDENT),
            Span::styled(format!("{:>number_width$}  ", i + 1), theme.accent),
            Span::styled(shown, theme.strong),
            Span::raw(" ".repeat(padding + 2)),
            Span::styled(
                text::truncate(&detail, details_width, glyphs.ellipsis),
                theme.muted,
            ),
        ]);
        lines.push(fit(line, width, glyphs.ellipsis));
    }
    lines.push(blank());
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decoders::interface::Decoder;
    use crate::tui::theme::{ColorDepth, Glyphs};
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use std::collections::HashMap;
    use unicode_width::UnicodeWidthChar;

    /// The theme the snapshots use. Colours don't show in snapshots, so it is the
    /// default scheme without them.
    fn theme(glyphs: Glyphs) -> Theme {
        Theme::new(&HashMap::new(), ColorDepth::None, glyphs)
    }

    /// Lays `lines` out the way a terminal `width` columns wide shows them, wrapping
    /// long lines at the edge, and returns the screen as text from ratatui's test
    /// backend
    fn screen(lines: &[Line<'_>], width: u16) -> String {
        let mut rows: Vec<Line<'static>> = Vec::new();
        for line in lines {
            let mut row: Vec<Span<'static>> = Vec::new();
            let mut used = 0;
            for span in &line.spans {
                let mut piece = String::new();
                for c in span.content.chars() {
                    let w = c.width().unwrap_or(0);
                    if used + w > usize::from(width) {
                        row.push(Span::styled(std::mem::take(&mut piece), span.style));
                        rows.push(Line::from(std::mem::take(&mut row)));
                        used = 0;
                    }
                    piece.push(c);
                    used += w;
                }
                row.push(Span::styled(piece, span.style));
            }
            rows.push(Line::from(row));
        }

        let height = u16::try_from(rows.len()).unwrap().max(1);
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal
            .draw(|frame| {
                for (y, row) in rows.iter().enumerate() {
                    frame.buffer_mut().set_line(0, y as u16, row, width);
                }
            })
            .unwrap();
        terminal.backend().to_string()
    }

    /// A step of a decoding path that produced `output`
    fn step(decoder: &'static str, output: &str, key: Option<&str>) -> CrackResult {
        let mut step = CrackResult::new(&Decoder::default(), String::new());
        step.decoder = decoder;
        step.unencrypted_text = Some(vec![output.to_string()]);
        step.key = key.map(str::to_string);
        step
    }

    /// The path for "Ciphey is very fast" under ROT13, hex and Base64
    fn three_layers() -> DecoderResult {
        let mut last = step("caesar", "Ciphey is very fast", Some("13"));
        last.checker_name = "English Checker";
        DecoderResult {
            text: vec!["Ciphey is very fast".to_string()],
            path: vec![
                step("Base64", "50766375726c207666206972656c20736e6667", None),
                step("Hexadecimal", "Pvcurl vf irel snfg", None),
                last,
            ],
        }
    }

    fn progress() -> Snapshot {
        Snapshot {
            expanded: 1204,
            depth: 2,
            trying: vec!["Base64", "Hexadecimal"],
            cache_hit: false,
        }
    }

    fn search_view(progress: &Snapshot) -> SearchView<'_> {
        SearchView {
            elapsed: Duration::from_millis(1300),
            timeout: 5,
            progress,
            decoders: 24,
            found: None,
            regex: None,
            stopping: false,
            frame: 3,
        }
    }

    #[test]
    fn searching_at_80_columns() {
        let progress = progress();
        let lines = searching(&search_view(&progress), &theme(Glyphs::UNICODE), 79);
        insta::assert_snapshot!(screen(&lines, 80));
    }

    #[test]
    fn searching_at_40_columns() {
        let progress = progress();
        let lines = searching(&search_view(&progress), &theme(Glyphs::UNICODE), 39);
        insta::assert_snapshot!(screen(&lines, 40));
    }

    #[test]
    fn searching_with_help_in_ascii() {
        let progress = progress();
        let theme = theme(Glyphs::ASCII);
        let mut lines = searching(&search_view(&progress), &theme, 79);
        lines.extend(keys(&theme, 79));
        insta::assert_snapshot!(screen(&lines, 80));
    }

    #[test]
    fn searching_before_the_first_layer_with_a_crib_and_top_results() {
        let progress = Snapshot::default();
        let view = SearchView {
            found: Some(12),
            regex: Some("picoCTF\\{"),
            ..search_view(&progress)
        };
        let lines = searching(&view, &theme(Glyphs::UNICODE), 79);
        insta::assert_snapshot!(screen(&lines, 80));
    }

    #[test]
    fn long_paths_keep_their_last_decoders() {
        let progress = Snapshot {
            trying: vec!["Base64"; 12],
            ..progress()
        };
        let lines = searching(&search_view(&progress), &theme(Glyphs::UNICODE), 39);
        insta::assert_snapshot!(screen(&lines, 40));
    }

    #[test]
    fn prompt_for_a_candidate() {
        let view = PromptView {
            text: "Ciphey is very fast",
            checker: "English Checker",
            description: "Words",
            number: 1,
        };
        let lines = prompt(&view, &theme(Glyphs::UNICODE), 79, 23);
        insta::assert_snapshot!(screen(&lines, 80));
    }

    #[test]
    fn prompt_for_a_long_candidate_in_a_short_terminal() {
        let text = "the quick brown fox jumps over the lazy dog \x1b[31m ".repeat(20);
        let view = PromptView {
            text: &text,
            checker: "LemmeKnow Checker",
            description: "Internet Protocol (IP) Address Version 4",
            number: 3,
        };
        let lines = prompt(&view, &theme(Glyphs::UNICODE), 39, 10);
        assert!(lines.len() <= 10);
        insta::assert_snapshot!(screen(&lines, 40));
    }

    #[test]
    fn success_with_three_layers() {
        let result = three_layers();
        let progress = progress();
        let view = SuccessView {
            result: &result,
            elapsed: Duration::from_millis(410),
            progress: &progress,
            confirmed: true,
            recognised_as: None,
            regex: None,
            saved_to: None,
        };
        let lines = success(&view, &theme(Glyphs::UNICODE), 79);
        insta::assert_snapshot!(screen(&lines, 80));
    }

    #[test]
    fn success_with_three_layers_at_40_columns() {
        let result = three_layers();
        let progress = progress();
        let view = SuccessView {
            result: &result,
            elapsed: Duration::from_millis(410),
            progress: &progress,
            confirmed: false,
            recognised_as: None,
            regex: None,
            saved_to: None,
        };
        let lines = success(&view, &theme(Glyphs::UNICODE), 39);
        insta::assert_snapshot!(screen(&lines, 40));
    }

    #[test]
    fn success_from_the_cache_recognised_by_lemmeknow() {
        let mut only = step("Hexadecimal", "192.168.0.1", None);
        only.checker_name = "LemmeKnow Checker";
        let result = DecoderResult {
            text: vec!["192.168.0.1".to_string()],
            path: vec![only],
        };
        let progress = Snapshot {
            cache_hit: true,
            ..Snapshot::default()
        };
        let view = SuccessView {
            result: &result,
            elapsed: Duration::from_millis(8),
            progress: &progress,
            confirmed: false,
            recognised_as: Some("Internet Protocol (IP) Address Version 4"),
            regex: None,
            saved_to: None,
        };
        let lines = success(&view, &theme(Glyphs::UNICODE), 79);
        insta::assert_snapshot!(screen(&lines, 80));
    }

    #[test]
    fn success_with_a_long_plaintext_is_not_wrapped_by_ciphey() {
        let plaintext = "The main function to call which performs the cracking. \
                         It is longer than the terminal is wide, so the terminal wraps it."
            .to_string();
        let mut only = step("Base64", &plaintext, None);
        only.checker_name = "English Checker";
        let result = DecoderResult {
            text: vec![plaintext.clone()],
            path: vec![only],
        };
        let progress = progress();
        let view = SuccessView {
            result: &result,
            elapsed: Duration::from_millis(110),
            progress: &progress,
            confirmed: false,
            recognised_as: None,
            regex: None,
            saved_to: None,
        };
        let lines = success(&view, &theme(Glyphs::UNICODE), 59);
        // One line of output for the whole plaintext, unindented
        assert!(lines.iter().any(|line| line
            .spans
            .iter()
            .map(|s| s.content.as_ref())
            .collect::<String>()
            == plaintext));
        insta::assert_snapshot!(screen(&lines, 60));
    }

    #[test]
    fn success_shows_escapes_for_control_characters() {
        let mut only = step("Base64", "", None);
        only.checker_name = "Regex Checker";
        let result = DecoderResult {
            text: vec!["flag{\x1b[2J}\nsecond line".to_string()],
            path: vec![only],
        };
        let progress = progress();
        let view = SuccessView {
            result: &result,
            elapsed: Duration::from_millis(110),
            progress: &progress,
            confirmed: false,
            recognised_as: None,
            regex: Some("flag\\{"),
            saved_to: None,
        };
        let lines = success(&view, &theme(Glyphs::UNICODE), 79);
        let printed: String = lines
            .iter()
            .flat_map(|l| l.spans.iter().map(|s| s.content.to_string()))
            .collect();
        assert!(!printed.contains('\x1b'), "{printed:?}");
        insta::assert_snapshot!(screen(&lines, 80));
    }

    #[test]
    fn saved_to_a_file_shows_the_whole_path() {
        let mut only = step("Base64", "hello    world", None);
        only.checker_name = "English Checker";
        let result = DecoderResult {
            text: vec!["hello    world".to_string()],
            path: vec![only],
        };
        let progress = progress();
        let path = "/home/someone/a/rather/long/home/directory/ciphey_text-2.txt";
        let view = SuccessView {
            result: &result,
            elapsed: Duration::from_millis(110),
            progress: &progress,
            confirmed: false,
            recognised_as: None,
            regex: None,
            saved_to: Some(path),
        };
        let lines = success(&view, &theme(Glyphs::UNICODE), 39);
        let printed: String = lines
            .iter()
            .flat_map(|l| l.spans.iter().map(|s| s.content.to_string()))
            .collect();
        assert!(printed.contains(path), "{printed:?}");
        assert!(!printed.contains("hello"), "the plaintext went to the file");
        insta::assert_snapshot!(screen(&lines, 40));
    }

    #[test]
    fn input_that_is_already_plaintext() {
        let mut only = CrackResult::new(&Decoder::default(), "Hello, World!".to_string());
        only.checker_name = "English Checker";
        let result = DecoderResult {
            text: vec!["Hello, World!".to_string()],
            path: vec![only],
        };
        let progress = Snapshot::default();
        let view = SuccessView {
            result: &result,
            elapsed: Duration::from_millis(20),
            progress: &progress,
            confirmed: true,
            recognised_as: None,
            regex: None,
            saved_to: None,
        };
        let lines = success(&view, &theme(Glyphs::UNICODE), 79);
        insta::assert_snapshot!(screen(&lines, 80));
    }

    #[test]
    fn failure_after_the_time_limit() {
        let progress = Snapshot {
            expanded: 12408,
            depth: 6,
            ..Snapshot::default()
        };
        let view = FailureView {
            ending: Ending::TimedOut,
            elapsed: Duration::from_secs(5),
            timeout: 5,
            progress: &progress,
            rejected: 3,
            regex: None,
        };
        let lines = failure(&view, &theme(Glyphs::UNICODE), 79);
        insta::assert_snapshot!(screen(&lines, 80));
    }

    #[test]
    fn failure_with_a_crib_at_40_columns() {
        let progress = Snapshot {
            expanded: 96,
            depth: 2,
            ..Snapshot::default()
        };
        let view = FailureView {
            ending: Ending::Stopped,
            elapsed: Duration::from_millis(1400),
            timeout: 5,
            progress: &progress,
            rejected: 0,
            regex: Some("^xyz"),
        };
        let lines = failure(&view, &theme(Glyphs::UNICODE), 39);
        insta::assert_snapshot!(screen(&lines, 40));
    }

    #[test]
    fn failure_when_nothing_is_left_to_try_in_ascii() {
        let progress = Snapshot {
            expanded: 1,
            depth: 1,
            ..Snapshot::default()
        };
        let view = FailureView {
            ending: Ending::Exhausted,
            elapsed: Duration::from_millis(30),
            timeout: 5,
            progress: &progress,
            rejected: 1,
            regex: None,
        };
        let lines = failure(&view, &theme(Glyphs::ASCII), 79);
        insta::assert_snapshot!(screen(&lines, 80));
    }

    #[test]
    fn top_results_list() {
        let result = |text: &str, decoder: &str, checker: &str| PlaintextResult {
            text: text.to_string(),
            description: String::new(),
            checker_name: checker.to_string(),
            decoder_name: decoder.to_string(),
        };
        let results = vec![
            result("Hello, World!", "Base64", "English Checker"),
            result("Uryyb, Jbeyq!", "rot47", "English Checker"),
            result(
                "a very long candidate that will not fit in the space left for it",
                "Vigenere",
                "LemmeKnow Checker",
            ),
        ];
        let lines = top_results(
            &results,
            Duration::from_secs(2),
            &theme(Glyphs::UNICODE),
            79,
        );
        insta::assert_snapshot!(screen(&lines, 80));
        let empty = top_results(&[], Duration::from_secs(2), &theme(Glyphs::UNICODE), 79);
        insta::assert_snapshot!("top_results_empty", screen(&empty, 80));
    }

    #[test]
    fn live_screens_fit_every_width() {
        let progress = progress();
        let theme = theme(Glyphs::UNICODE);
        let candidate = PromptView {
            text: "Ciphey is very fast",
            checker: "LemmeKnow Checker",
            description: "Internet Protocol (IP) Address Version 4",
            number: 12,
        };
        for width in 10..=120 {
            let mut lines = searching(&search_view(&progress), &theme, width);
            lines.extend(prompt(&candidate, &theme, width, 12));
            lines.extend(keys(&theme, width));
            lines.push(rejected("x".repeat(200).as_str(), &theme, width));
            for ending in [Ending::TimedOut, Ending::Exhausted, Ending::Stopped] {
                let view = FailureView {
                    ending,
                    elapsed: Duration::from_secs(5),
                    timeout: 5,
                    progress: &progress,
                    rejected: 2,
                    regex: Some("^xyz"),
                };
                lines.extend(failure(&view, &theme, width));
            }
            for line in &lines {
                assert!(
                    crate::tui::live::line_width(line) <= width,
                    "{width}: {line:?}"
                );
            }
        }
    }
}
