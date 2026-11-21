//! Terminal backend: aligned plain text, with ANSI color when enabled.
//!
//! Every span is sanitized before it is written. Findings, paths and reviewer
//! output come from repositories and models, so control characters (including
//! ESC) and bidirectional overrides are removed; they could otherwise rewrite
//! the terminal or disguise text.

use crate::view::{Block, Cell, Span, Style, Tone, View};
use anstyle::{AnsiColor, Effects, Style as AnsiStyle};

/// Renders `view` for a terminal. With `color` false the output contains no
/// escape sequences and still carries every status through its symbol.
pub fn render(view: &View, color: bool) -> String {
    let painter = Painter { color };
    let mut out = String::new();
    for block in &view.blocks {
        let rendered = painter.block(block);
        if rendered.is_empty() {
            continue;
        }
        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str(&rendered);
    }
    out
}

pub fn symbol(tone: Tone) -> &'static str {
    match tone {
        Tone::Success => "✔",
        Tone::Danger => "✖",
        Tone::Warning => "▲",
        Tone::Info => "●",
        Tone::Neutral => "·",
    }
}

fn tone_color(tone: Tone) -> AnsiStyle {
    let color = match tone {
        Tone::Success => AnsiColor::Green,
        Tone::Danger => AnsiColor::Red,
        Tone::Warning => AnsiColor::Yellow,
        Tone::Info => AnsiColor::Blue,
        Tone::Neutral => AnsiColor::BrightBlack,
    };
    AnsiStyle::new().fg_color(Some(color.into()))
}

/// Removes control characters and bidirectional formatting from untrusted
/// text; newlines and tabs become spaces so one span stays on one line.
pub fn sanitize(text: &str) -> String {
    text.chars()
        .filter_map(|character| match character {
            '\n' | '\r' | '\t' => Some(' '),
            '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{200E}' | '\u{200F}' => None,
            character if character.is_control() => None,
            character => Some(character),
        })
        .collect()
}

struct Painter {
    color: bool,
}

impl Painter {
    fn paint(&self, style: AnsiStyle, text: &str) -> String {
        if !self.color || text.is_empty() {
            return text.to_owned();
        }
        format!("{}{text}{}", style.render(), style.render_reset())
    }

    fn span(&self, span: &Span) -> (String, usize) {
        let text = sanitize(&span.text);
        match span.style {
            Style::Plain => {
                let width = width(&text);
                (text, width)
            }
            Style::Strong => {
                let width = width(&text);
                (
                    self.paint(AnsiStyle::new().effects(Effects::BOLD), &text),
                    width,
                )
            }
            Style::Muted => {
                let width = width(&text);
                (
                    self.paint(AnsiStyle::new().effects(Effects::DIMMED), &text),
                    width,
                )
            }
            Style::Code => {
                let width = width(&text);
                (
                    self.paint(
                        AnsiStyle::new().fg_color(Some(AnsiColor::Cyan.into())),
                        &text,
                    ),
                    width,
                )
            }
            Style::Badge(tone) => {
                let label = format!("{} {text}", symbol(tone));
                let width = width(&label);
                (
                    self.paint(tone_color(tone).effects(Effects::BOLD), &label),
                    width,
                )
            }
        }
    }

    /// The rendered cell and its visible width.
    fn cell(&self, cell: &Cell) -> (String, usize) {
        cell.spans.iter().map(|span| self.span(span)).fold(
            (String::new(), 0),
            |(mut text, total), (part, width)| {
                text.push_str(&part);
                (text, total + width)
            },
        )
    }

    fn block(&self, block: &Block) -> String {
        match block {
            Block::Title { text, badge } => {
                let title = self.paint(AnsiStyle::new().effects(Effects::BOLD), &sanitize(text));
                match badge {
                    Some(badge) => format!("{title}  {}\n", self.cell(badge).0),
                    None => format!("{title}\n"),
                }
            }
            Block::Section(name) => format!(
                "{}\n",
                self.paint(
                    AnsiStyle::new().effects(Effects::BOLD | Effects::UNDERLINE),
                    &sanitize(name)
                )
            ),
            Block::Fields(fields) => {
                let label_width = fields
                    .iter()
                    .map(|(label, _)| width(&sanitize(label)))
                    .max()
                    .unwrap_or(0);
                fields
                    .iter()
                    .map(|(label, value)| {
                        let label = sanitize(label);
                        let padding = " ".repeat(label_width - width(&label));
                        format!(
                            "  {}{padding}  {}\n",
                            self.paint(AnsiStyle::new().effects(Effects::DIMMED), &label),
                            self.cell(value).0
                        )
                    })
                    .collect()
            }
            Block::Table { headers, rows } => self.table(headers, rows),
            Block::List(items) => items
                .iter()
                .map(|item| format!("  • {}\n", self.cell(item).0))
                .collect(),
            Block::Paragraph(cell) => format!("{}\n", self.cell(cell).0),
            Block::Note { tone, text } => format!(
                "{} {}\n",
                self.paint(tone_color(*tone).effects(Effects::BOLD), symbol(*tone)),
                self.cell(text).0
            ),
            Block::NextStep(command) => format!(
                "{} {}\n",
                self.paint(AnsiStyle::new().effects(Effects::DIMMED), "→"),
                self.paint(
                    AnsiStyle::new().fg_color(Some(AnsiColor::Cyan.into())),
                    &sanitize(command)
                )
            ),
        }
    }

    fn table(&self, headers: &[String], rows: &[Vec<Cell>]) -> String {
        if rows.is_empty() {
            return String::new();
        }
        let rendered: Vec<Vec<(String, usize)>> = rows
            .iter()
            .map(|row| row.iter().map(|cell| self.cell(cell)).collect())
            .collect();
        let columns = headers.len();
        let mut widths: Vec<usize> = headers.iter().map(|header| width(header)).collect();
        for row in &rendered {
            for (index, (_, cell_width)) in row.iter().enumerate().take(columns) {
                widths[index] = widths[index].max(*cell_width);
            }
        }
        let mut out = String::new();
        let header_line: Vec<String> = headers
            .iter()
            .enumerate()
            .map(|(index, header)| {
                pad(
                    &self.paint(AnsiStyle::new().effects(Effects::DIMMED), header),
                    width(header),
                    widths[index],
                    index + 1 == columns,
                )
            })
            .collect();
        out.push_str(&format!("  {}\n", header_line.join("  ")));
        for row in &rendered {
            let line: Vec<String> = row
                .iter()
                .enumerate()
                .take(columns)
                .map(|(index, (text, cell_width))| {
                    pad(text, *cell_width, widths[index], index + 1 == columns)
                })
                .collect();
            out.push_str(&format!("  {}\n", line.join("  ")));
        }
        out
    }
}

/// Visible width in characters. Wide East Asian characters count as one, so
/// such columns can misalign; the text itself is unaffected.
fn width(text: &str) -> usize {
    text.chars().count()
}

fn pad(text: &str, text_width: usize, column_width: usize, last: bool) -> String {
    if last {
        return text.to_owned();
    }
    format!(
        "{text}{}",
        " ".repeat(column_width.saturating_sub(text_width))
    )
}
