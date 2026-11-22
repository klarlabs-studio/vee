# ADR 0011: One presentation layer for the CLI and MCP

- **Status:** Accepted
- **Date:** 2026-11-21

## Context

[ADR 0001](0001-shared-operations-and-domain-layering.md) made both
transports return the same JSON document for every shared operation. What
each transport *showed* still differed, and neither was readable:

- **CLI text.** About 290 ad hoc `println!` calls in `main.rs`. Enums were
  printed with `{:?}`, `reviews show` printed JSON-quoted strings, and
  `vee review` did not list its findings at all. There was no color.
- **MCP text.** Every tool's text content was the compact JSON document, so an
  agent or a person reading an MCP client saw no summary at all.
- **Markdown report.** `vee review --markdown` had a third renderer of its own
  in the application crate.

## Decision

1. **A `vee-present` crate.** It turns result documents into a `View` and
   renders views. It does no I/O. Every shared document implements `ToView`.
   A view is built from headings, fields, tables, lists, notes and next steps,
   and its spans carry a style and a tone (success, danger, warning, info,
   neutral).
2. **Two backends render the same view:**
   - **`ansi`**, for the CLI. Columns are aligned. Tones are shown as both a
     color and a symbol (`✔ ✖ ▲ ● ·`), so meaning survives without color and for
     color-blind readers.
   - **`markdown`**, for MCP text content and `vee review --markdown`. It uses
     GFM tables and colored markers (🟢 🔴 🟡 🔵 ⚪).
3. **The CLI's `--color auto|always|never`.** The flag is global and defaults
   to `auto`. `auto` colors only a terminal and honors `NO_COLOR`, `CLICOLOR`
   and `CLICOLOR_FORCE`. `--output json` is unchanged.
4. **MCP tools with a shared view.** Their text content is that view as
   Markdown. `structuredContent` carries the full document, validated against
   the tool's output schema as before. Tools without an output schema keep
   JSON text until they get one, so no tool loses machine-readable output.
5. **Next steps.** A next step carries both the CLI command and, when one
   exists, the MCP tool call. The terminal shows the command; Markdown shows
   the tool call and the command.
6. **The Markdown report.** `vee review --markdown` writes the shared review
   view, extended with each finding in full and every reviewer's report on
   disputed findings. It has no interactive next step.
7. **Untrusted text.** Findings, paths and reviewer output come from
   repositories and models. The terminal backend strips control characters,
   including ESC, and bidirectional overrides. The Markdown backend escapes
   Markdown and HTML syntax and uses code spans that cannot be closed early.
8. **Parity.** `tests/transport_parity.rs` rebuilds each covered document from
   the MCP structured content. It then requires that the MCP text equal the
   Markdown render, and that the CLI's `--color never` output equal the
   terminal render of the same view.

## Consequences

- **One source of truth for display.** A change to how a document reads is
  made once and shows up on both transports.
- **MCP clients that parsed the text content as JSON must read
  `structuredContent` instead.** The MCP specification recommends that, and
  the document there is unchanged.
- **CLI text output is not a stable interface.** Scripts should use
  `--output json`.
- **Covered documents derive `Deserialize`,** so the parity test can rebuild
  them. Fields that were `&'static str` (setup, finding task and package, rule
  candidate and acceptance statuses) are now `String`; they serialize the
  same.
- **Alignment counts characters,** so wide East Asian characters can misalign
  a column. The text itself is unaffected. No width dependency was added.
- **Coverage is staged.**
  - PR 1 covers the operations both transports share.
  - PR 2 routes the remaining divergent CLI paths through `operations`, types
    the two operations that still return untyped JSON, and adds output schemas
    to the six MCP tools that lack them.
  - Later changes give the CLI-only commands views.

## Alternatives considered

- **ANSI over MCP.** MCP clients do not interpret terminal escapes, so they
  would show raw codes.
- **Markdown and JSON both in the MCP text.** This roughly doubles the tokens
  of every result. The full document is already in `structuredContent`.
- **A rendering library** (tables, color). `anstyle` and `anstream` were
  already in the dependency tree through `clap`, and the view model needs only
  aligned columns.
