//! The one mapping from domain states to tones and labels, so a severity or a
//! gate status looks the same in every view and on every transport.

use crate::view::{Cell, Tone};
use vee_core::{FindingStatus, GateStatus, Severity};

pub fn severity(severity: Severity) -> Cell {
    let (tone, label) = match severity {
        Severity::Critical => (Tone::Danger, "critical"),
        Severity::High => (Tone::Danger, "high"),
        Severity::Medium => (Tone::Warning, "medium"),
        Severity::Low => (Tone::Info, "low"),
        Severity::Info => (Tone::Neutral, "info"),
    };
    Cell::badge(tone, label)
}

pub fn gate(status: GateStatus) -> Cell {
    match status {
        GateStatus::Pass => Cell::badge(Tone::Success, "pass"),
        GateStatus::Block => Cell::badge(Tone::Danger, "block"),
        GateStatus::Incomplete => Cell::badge(Tone::Warning, "incomplete"),
    }
}

pub fn finding_status(status: FindingStatus) -> Cell {
    let (tone, label) = match status {
        FindingStatus::Open => (Tone::Warning, "open"),
        FindingStatus::Verified => (Tone::Danger, "verified"),
        FindingStatus::Refuted => (Tone::Neutral, "refuted"),
        FindingStatus::Resolved => (Tone::Success, "resolved"),
        FindingStatus::Waived => (Tone::Neutral, "waived"),
    };
    Cell::badge(tone, label)
}

/// Review and reviewer statuses are open strings in the documents; known
/// values get a tone and anything else is shown neutrally as reported.
pub fn status_text(status: &str) -> Cell {
    let tone = match status {
        "pass" | "completed" | "cached" | "complete" | "passed" | "owned" | "used" => Tone::Success,
        "block"
        | "failed"
        | "invalid_findings"
        | "invalid_finding_location"
        | "invalid_rule_attribution"
        | "configuration_changed_during_review"
        | "configuration_revalidation_failed"
        | "snapshot_revalidation_failed"
        | "source_changed_during_review"
        | "version_probe_failed" => Tone::Danger,
        "incomplete"
        | "rate_limited"
        | "partial"
        | "context_limited"
        | "context_budget_exceeded"
        | "not_reviewed"
        | "needs_human_review"
        | "requires_human_review"
        | "package_unresolved"
        | "unavailable"
        | "modified" => Tone::Warning,
        _ => Tone::Neutral,
    };
    Cell::badge(tone, status)
}

/// Text form of a confidence value.
pub fn confidence(confidence: Option<u8>) -> Cell {
    match confidence {
        Some(value) => Cell::plain(format!("{value}%")),
        None => Cell::muted("unknown"),
    }
}

/// `path:line`, or a placeholder when the finding has no location.
pub fn location(path: Option<&str>, line: Option<u32>) -> Cell {
    match (path, line) {
        (Some(path), Some(line)) => Cell::code(format!("{path}:{line}")),
        (Some(path), None) => Cell::code(path),
        (None, _) => Cell::muted("no location"),
    }
}
