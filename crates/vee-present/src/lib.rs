//! Shared presentation for Vee result documents.
//!
//! Every transport shows a result the same way: an operation returns a
//! document, [`ToView`] turns it into a [`View`], and a backend renders that
//! view. The CLI uses [`ansi`]; MCP text content and Markdown reports use
//! [`markdown`]. This crate does no I/O.

pub mod ansi;
pub mod markdown;
pub mod tone;
pub mod view;
mod views;

pub use views::review::review_report;
pub use views::BEST_RESULTS_GUIDE;

pub use view::{summary, Action, Block, Cell, Span, Style, ToView, Tone, ToolCall, View};
