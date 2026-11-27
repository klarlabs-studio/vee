//! HTML backend: one self-contained page for a view, such as the team
//! analytics report. Every value is escaped, the page loads nothing from
//! elsewhere, and it runs no script, so it can be opened or published as a
//! CI artifact as it is.

use crate::ansi::sanitize;
use crate::view::{Block, Cell, Style, Tone, View};

const STYLE: &str = "\
:root{--bg:#fbfaf7;--fg:#1f2328;--muted:#5d6670;--line:#dcd8ce;--ok:#1a7f37;--bad:#c2362b;--warn:#9a6700;--info:#0969da}\
@media (prefers-color-scheme:dark){:root{--bg:#16181c;--fg:#e6e3dc;--muted:#9aa3ad;--line:#33373e;--ok:#4cc46a;--bad:#ff7b72;--warn:#e3b341;--info:#58a6ff}}\
body{background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,'Segoe UI',sans-serif;margin:0;padding:24px max(16px,4vw);max-width:1100px}\
h1{font-size:1.6em;margin:0 0 16px}h2{font-size:1.15em;margin:28px 0 8px;border-bottom:1px solid var(--line);padding-bottom:4px}\
dl{display:grid;grid-template-columns:max-content 1fr;gap:4px 16px;margin:0}dt{color:var(--muted)}dd{margin:0}\
.table{overflow-x:auto}table{border-collapse:collapse;min-width:100%}th,td{text-align:left;padding:6px 10px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--muted);font-weight:600}\
code{font:0.92em ui-monospace,SFMono-Regular,Menlo,monospace}.muted{color:var(--muted)}\
.badge{display:inline-block;border:1px solid currentColor;border-radius:999px;padding:0 8px;font-size:0.85em}\
.success{color:var(--ok)}.danger{color:var(--bad)}.warning{color:var(--warn)}.info{color:var(--info)}.neutral{color:var(--muted)}\
.note{border-left:3px solid currentColor;padding:4px 12px;margin:12px 0}";

fn escape(text: &str) -> String {
    sanitize(text)
        .chars()
        .map(|character| match character {
            '&' => "&amp;".to_owned(),
            '<' => "&lt;".to_owned(),
            '>' => "&gt;".to_owned(),
            '"' => "&quot;".to_owned(),
            '\'' => "&#39;".to_owned(),
            other => other.to_string(),
        })
        .collect()
}

fn tone_class(tone: Tone) -> &'static str {
    match tone {
        Tone::Success => "success",
        Tone::Danger => "danger",
        Tone::Warning => "warning",
        Tone::Info => "info",
        Tone::Neutral => "neutral",
    }
}

fn cell(cell: &Cell) -> String {
    cell.spans
        .iter()
        .map(|span| {
            let text = escape(&span.text);
            match span.style {
                Style::Plain => text,
                Style::Strong => format!("<strong>{text}</strong>"),
                Style::Muted => format!("<span class=\"muted\">{text}</span>"),
                Style::Code | Style::Id => format!("<code>{text}</code>"),
                Style::Badge(tone) => {
                    format!("<span class=\"badge {}\">{text}</span>", tone_class(tone))
                }
            }
        })
        .collect()
}

/// A complete HTML document for `view`, titled `title`.
pub fn render(view: &View, title: &str) -> String {
    let mut body = String::new();
    for block in &view.blocks {
        match block {
            Block::Title { text, badge } => {
                body.push_str(&format!("<h1>{}", escape(text)));
                if let Some(badge) = badge {
                    body.push_str(&format!(" {}", cell(badge)));
                }
                body.push_str("</h1>\n");
            }
            Block::Section(name) => body.push_str(&format!("<h2>{}</h2>\n", escape(name))),
            Block::Fields(fields) => {
                body.push_str("<dl>");
                for (name, value) in fields {
                    body.push_str(&format!(
                        "<dt>{}</dt><dd>{}</dd>",
                        escape(name),
                        cell(value)
                    ));
                }
                body.push_str("</dl>\n");
            }
            Block::Table { headers, rows } => {
                body.push_str("<div class=\"table\"><table><thead><tr>");
                for header in headers {
                    body.push_str(&format!("<th>{}</th>", escape(header)));
                }
                body.push_str("</tr></thead><tbody>");
                for row in rows {
                    body.push_str("<tr>");
                    for value in row {
                        body.push_str(&format!("<td>{}</td>", cell(value)));
                    }
                    body.push_str("</tr>");
                }
                body.push_str("</tbody></table></div>\n");
            }
            Block::List(items) => {
                body.push_str("<ul>");
                for item in items {
                    body.push_str(&format!("<li>{}</li>", cell(item)));
                }
                body.push_str("</ul>\n");
            }
            Block::Paragraph(text) => body.push_str(&format!("<p>{}</p>\n", cell(text))),
            Block::Note { tone, text } => body.push_str(&format!(
                "<p class=\"note {}\">{}</p>\n",
                tone_class(*tone),
                cell(text)
            )),
            Block::NextStep(action) => body.push_str(&format!(
                "<p>Next: <code>{}</code></p>\n",
                escape(&action.command)
            )),
        }
    }
    format!(
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\"><title>{}</title><style>{STYLE}</style></head><body>\n{body}</body></html>\n",
        escape(title)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_value_is_escaped_and_the_page_loads_nothing() {
        let view = View::new()
            .title(
                "<script>alert(1)</script>",
                Some(Cell::badge(Tone::Success, "ok")),
            )
            .fields(vec![("a&b".into(), Cell::code("\"x\" <y>"))])
            .table(&["<th>"], vec![vec![Cell::plain("<img src=x onerror=1>")]]);
        let html = render(&view, "T<itle>");
        assert!(!html.contains("<script>"));
        assert!(!html.contains("<img"));
        assert!(html.contains("&lt;script&gt;"));
        assert!(html.contains("<title>T&lt;itle&gt;</title>"));
        assert!(html.contains("default-src 'none'"));
        assert!(!html.contains("http://") && !html.contains("https://"));
    }
}
