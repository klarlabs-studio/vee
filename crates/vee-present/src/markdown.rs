//! Markdown backend, used for MCP text content and `vee review --markdown`.
//!
//! Untrusted text is escaped so a finding cannot add headings, links, HTML or
//! table cells; code spans use a fence longer than any backtick run inside.

use crate::ansi::sanitize;
use crate::view::{Block, Cell, Span, Style, Tone, View};

pub fn render(view: &View) -> String {
    let mut out = String::new();
    for block in &view.blocks {
        let rendered = block_markdown(block);
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

pub fn marker(tone: Tone) -> &'static str {
    match tone {
        Tone::Success => "🟢",
        Tone::Danger => "🔴",
        Tone::Warning => "🟡",
        Tone::Info => "🔵",
        Tone::Neutral => "⚪",
    }
}

/// Escapes Markdown and HTML syntax in untrusted inline text and keeps it on one line.
///
/// Only characters that can start markup where they stand are escaped, so
/// prose and identifiers stay readable (and cheap for agents): `snake_case`,
/// `v1.2`, and `(see above)` pass through unchanged.
pub fn inline(value: &str) -> String {
    let text = sanitize(value);
    let chars: Vec<char> = text.chars().collect();
    let first = chars
        .iter()
        .position(|character| !character.is_whitespace());
    let mut escaped = String::with_capacity(text.len());
    for (index, &character) in chars.iter().enumerate() {
        let previous = index.checked_sub(1).map(|at| chars[at]);
        let next = chars.get(index + 1).copied();
        let at_start = first == Some(index);
        let escape = match character {
            // Emphasis, code, links, raw HTML and entities, table cells, strikethrough.
            '\\' | '`' | '*' | '[' | ']' | '<' | '>' | '&' | '|' | '~' => true,
            // GFM ignores intraword underscores, so only boundary ones can emphasize.
            '_' => {
                !(previous.is_some_and(char::is_alphanumeric)
                    && next.is_some_and(char::is_alphanumeric))
            }
            // Headings, list items, block quotes, and setext underlines start a line.
            '#' | '-' | '+' | '=' => at_start,
            // `1.` or `1)` at the start of a line opens an ordered list.
            '.' | ')' => first.is_some_and(|start| {
                start < index && chars[start..index].iter().all(char::is_ascii_digit)
            }),
            // Bare `scheme://` and `www.` become links under GFM autolinking.
            ':' => next == Some('/') && chars.get(index + 2) == Some(&'/'),
            _ => false,
        } || (character == '.'
            && index >= 3
            && chars[index - 3..index]
                .iter()
                .collect::<String>()
                .eq_ignore_ascii_case("www"));
        if escape {
            escaped.push('\\');
        }
        escaped.push(character);
    }
    escaped
}

/// A code span whose fence is longer than any backtick run in `value`.
pub fn code(value: &str) -> String {
    let value = sanitize(value);
    let mut longest = 0;
    let mut current = 0;
    for character in value.chars() {
        if character == '`' {
            current += 1;
            longest = longest.max(current);
        } else {
            current = 0;
        }
    }
    let fence = "`".repeat(longest + 1);
    let padding = if value.starts_with('`') || value.ends_with('`') {
        " "
    } else {
        ""
    };
    // A `|` inside a code span still splits a GFM table cell.
    let value = value.replace('|', "\\|");
    format!("{fence}{padding}{value}{padding}{fence}")
}

fn span(span: &Span) -> String {
    if span.text.is_empty() {
        return String::new();
    }
    match span.style {
        Style::Plain => inline(&span.text),
        Style::Strong => format!("**{}**", inline(&span.text)),
        Style::Muted => format!("_{}_", inline(&span.text)),
        Style::Code | Style::Id => code(&span.text),
        Style::Badge(tone) => format!("{} **{}**", marker(tone), inline(&span.text)),
    }
}

fn cell(cell: &Cell) -> String {
    cell.spans
        .iter()
        .map(|item| {
            if item.style == Style::Plain && item.text == " " {
                " ".to_owned()
            } else {
                span(item)
            }
        })
        .collect()
}

fn block_markdown(block: &Block) -> String {
    match block {
        Block::Title { text, badge } => match badge {
            Some(badge) => format!("## {} · {}\n", inline(text), cell(badge)),
            None => format!("## {}\n", inline(text)),
        },
        Block::Section(name) => format!("### {}\n", inline(name)),
        Block::Fields(fields) => fields
            .iter()
            .map(|(label, value)| format!("- **{}:** {}\n", inline(label), cell(value)))
            .collect(),
        Block::Table { headers, rows } => {
            if rows.is_empty() {
                return String::new();
            }
            let mut out = format!(
                "| {} |\n|{}|\n",
                headers
                    .iter()
                    .map(|header| inline(header))
                    .collect::<Vec<_>>()
                    .join(" | "),
                headers.iter().map(|_| "---").collect::<Vec<_>>().join("|"),
            );
            for row in rows {
                out.push_str(&format!(
                    "| {} |\n",
                    row.iter().map(cell).collect::<Vec<_>>().join(" | ")
                ));
            }
            out
        }
        Block::List(items) => items
            .iter()
            .map(|item| format!("- {}\n", cell(item)))
            .collect(),
        Block::Paragraph(content) => format!("{}\n", cell(content)),
        Block::Note { tone, text } => format!("> {} {}\n", marker(*tone), cell(text)),
        Block::NextStep(action) => match &action.tool {
            Some(tool) => format!(
                "Next: call {} with {} (CLI: {})\n",
                code(&tool.name),
                code(&tool.arguments.to_string()),
                code(&action.command)
            ),
            None => format!("Next: {}\n", code(&action.command)),
        },
    }
}
