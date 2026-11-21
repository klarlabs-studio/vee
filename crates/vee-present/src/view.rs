//! The view model: what a result document looks like, independent of where it
//! is shown. Backends turn a [`View`] into terminal text or Markdown.

/// The meaning a piece of output carries. Backends map it to a color, a
/// symbol, or both, so meaning survives when color is off.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tone {
    Success,
    Danger,
    Warning,
    Info,
    Neutral,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Style {
    Plain,
    Strong,
    Muted,
    /// Identifiers, paths and commands.
    Code,
    /// A status label shown with the tone's symbol.
    Badge(Tone),
    /// A record identifier the reader may copy: dimmed in a terminal, code in Markdown.
    Id,
}

/// A run of text with one style. Text may come from repositories or models,
/// so backends must neutralize it; views never pre-escape.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Span {
    pub text: String,
    pub style: Style,
}

impl Span {
    pub fn new(text: impl Into<String>, style: Style) -> Self {
        Self {
            text: text.into(),
            style,
        }
    }
}

/// A line of inline content: a table cell, a field value, a list item.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Cell {
    pub spans: Vec<Span>,
}

impl Cell {
    pub fn plain(text: impl Into<String>) -> Self {
        Self::from(Span::new(text, Style::Plain))
    }

    pub fn strong(text: impl Into<String>) -> Self {
        Self::from(Span::new(text, Style::Strong))
    }

    pub fn muted(text: impl Into<String>) -> Self {
        Self::from(Span::new(text, Style::Muted))
    }

    pub fn code(text: impl Into<String>) -> Self {
        Self::from(Span::new(text, Style::Code))
    }

    pub fn id(text: impl Into<String>) -> Self {
        Self::from(Span::new(text, Style::Id))
    }

    pub fn badge(tone: Tone, label: impl Into<String>) -> Self {
        Self::from(Span::new(label, Style::Badge(tone)))
    }

    /// Appends a span, separated from the existing content by one space.
    pub fn then(mut self, span: Span) -> Self {
        if !self.spans.is_empty() {
            self.spans.push(Span::new(" ", Style::Plain));
        }
        self.spans.push(span);
        self
    }

    pub fn is_empty(&self) -> bool {
        self.spans.iter().all(|span| span.text.is_empty())
    }
}

impl From<Span> for Cell {
    fn from(span: Span) -> Self {
        Self { spans: vec![span] }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Block {
    /// The document heading, with an optional overall status.
    Title {
        text: String,
        badge: Option<Cell>,
    },
    /// A named part of the document.
    Section(String),
    /// Label and value pairs.
    Fields(Vec<(String, Cell)>),
    Table {
        headers: Vec<String>,
        rows: Vec<Vec<Cell>>,
    },
    List(Vec<Cell>),
    Paragraph(Cell),
    /// A toned message, such as a warning about incomplete analysis.
    Note {
        tone: Tone,
        text: Cell,
    },
    /// What the reader can do next.
    NextStep(Action),
}

/// A next step, as a CLI command and, when one exists, the equivalent MCP
/// tool call. Each backend shows the form its reader can act on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Action {
    pub command: String,
    pub tool: Option<ToolCall>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToolCall {
    pub name: String,
    pub arguments: serde_json::Value,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct View {
    pub blocks: Vec<Block>,
}

impl View {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn title(mut self, text: impl Into<String>, badge: Option<Cell>) -> Self {
        self.blocks.push(Block::Title {
            text: text.into(),
            badge,
        });
        self
    }

    pub fn section(mut self, name: impl Into<String>) -> Self {
        self.blocks.push(Block::Section(name.into()));
        self
    }

    pub fn fields(mut self, fields: Vec<(String, Cell)>) -> Self {
        let fields: Vec<_> = fields
            .into_iter()
            .filter(|(_, value)| !value.is_empty())
            .collect();
        if !fields.is_empty() {
            self.blocks.push(Block::Fields(fields));
        }
        self
    }

    pub fn table(mut self, headers: &[&str], rows: Vec<Vec<Cell>>) -> Self {
        self.blocks.push(Block::Table {
            headers: headers.iter().map(|header| (*header).to_owned()).collect(),
            rows,
        });
        self
    }

    pub fn list(mut self, items: Vec<Cell>) -> Self {
        if !items.is_empty() {
            self.blocks.push(Block::List(items));
        }
        self
    }

    pub fn paragraph(mut self, cell: Cell) -> Self {
        self.blocks.push(Block::Paragraph(cell));
        self
    }

    pub fn note(mut self, tone: Tone, text: impl Into<Cell>) -> Self {
        self.blocks.push(Block::Note {
            tone,
            text: text.into(),
        });
        self
    }

    /// A next step that only the CLI offers.
    pub fn next_step(mut self, command: impl Into<String>) -> Self {
        self.blocks.push(Block::NextStep(Action {
            command: command.into(),
            tool: None,
        }));
        self
    }

    /// A next step offered by both transports.
    pub fn next_action(
        mut self,
        command: impl Into<String>,
        tool: &str,
        arguments: serde_json::Value,
    ) -> Self {
        self.blocks.push(Block::NextStep(Action {
            command: command.into(),
            tool: Some(ToolCall {
                name: tool.to_owned(),
                arguments,
            }),
        }));
        self
    }

    /// Appends `other`'s blocks.
    pub fn extend(mut self, other: View) -> Self {
        self.blocks.extend(other.blocks);
        self
    }
}

impl From<String> for Cell {
    fn from(text: String) -> Self {
        Cell::plain(text)
    }
}

impl From<&str> for Cell {
    fn from(text: &str) -> Self {
        Cell::plain(text)
    }
}

/// A result document that has a human view. Both transports build their text
/// output from this, so the CLI and MCP show the same thing.
pub trait ToView {
    fn to_view(&self) -> View;
}

/// The first line of `text`, shortened to at most `max` characters, for table
/// cells. Full text belongs in a detail view.
pub fn summary(text: &str, max: usize) -> String {
    let line = text
        .lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("")
        .trim();
    if line.chars().count() <= max {
        return line.to_owned();
    }
    let mut shortened: String = line.chars().take(max.saturating_sub(1)).collect();
    shortened = shortened.trim_end().to_owned();
    shortened.push('…');
    shortened
}
