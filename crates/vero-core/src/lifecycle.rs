//! Lifecycle invariants for findings and rule approvals, and the bounded text
//! values that record who changed them and why.
//!
//! Transports construct these values from user input; the repository ports
//! accept only the constructed values, so every transport gets the same rules.

use crate::{FindingStatus, RuleApproval};
use serde::{Deserialize, Serialize};

/// Upper bound on a human-supplied reason, in characters.
pub const MAX_REASON_CHARS: usize = 4_000;
/// Upper bound on an actor (reviewer, approver) name, in characters.
pub const MAX_ACTOR_NAME_CHARS: usize = 200;

fn bounded_text(field: &str, value: &str, max_chars: usize) -> Result<String, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || value.chars().count() > max_chars {
        return Err(format!("{field} must contain 1 to {max_chars} characters"));
    }
    Ok(trimmed.to_owned())
}

/// Why a person changed something: trimmed, non-empty, at most
/// [`MAX_REASON_CHARS`] characters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reason(String);

impl Reason {
    pub fn new(value: &str) -> Result<Self, String> {
        bounded_text("reason", value, MAX_REASON_CHARS).map(Self)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Who made a change: trimmed, non-empty, at most [`MAX_ACTOR_NAME_CHARS`]
/// characters. `field` names the role in error messages (reviewer, approver, actor).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActorName(String);

impl ActorName {
    pub fn new(field: &str, value: &str) -> Result<Self, String> {
        bounded_text(field, value, MAX_ACTOR_NAME_CHARS).map(Self)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A manual change to a finding's lifecycle status. Waiving is not a status
/// change: a waiver needs a snapshot scope, author, and expiry, so it has its
/// own workflow and record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FindingStatusChange {
    status: FindingStatus,
    reason: Reason,
}

impl FindingStatusChange {
    pub fn new(status: FindingStatus, reason: Reason) -> Result<Self, String> {
        if status == FindingStatus::Waived {
            return Err("waivers require a scoped snapshot, author, and expiry; use the waiver workflow (`vero waivers create`)".into());
        }
        Ok(Self { status, reason })
    }

    pub fn status(&self) -> FindingStatus {
        self.status
    }

    pub fn reason(&self) -> &Reason {
        &self.reason
    }
}

/// Where a rule approval is in its lifecycle. Derived from its append-only
/// events and expiry; see [`RuleApproval::status_at`].
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuleApprovalStatus {
    #[default]
    Active,
    Revoked,
    Superseded,
    Expired,
}

impl RuleApprovalStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Revoked => "revoked",
            Self::Superseded => "superseded",
            Self::Expired => "expired",
        }
    }
}

impl RuleApproval {
    /// The approval's status at `now_unix`. Revocation wins over supersession,
    /// and both win over expiry, so the recorded human decision is reported.
    pub fn status_at(&self, now_unix: i64) -> RuleApprovalStatus {
        let has_event = |kind: &str| self.events.iter().any(|event| event.event == kind);
        if has_event("revoked") {
            RuleApprovalStatus::Revoked
        } else if has_event("superseded") {
            RuleApprovalStatus::Superseded
        } else if self
            .expires_at_unix
            .is_some_and(|expiry| expiry <= now_unix)
        {
            RuleApprovalStatus::Expired
        } else {
            RuleApprovalStatus::Active
        }
    }

    pub fn is_active(&self) -> bool {
        self.status == RuleApprovalStatus::Active
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FindingFeedbackLabel, RuleApprovalEvent};

    #[test]
    fn reasons_and_actor_names_are_trimmed_and_bounded() {
        assert_eq!(
            Reason::new("  flaky test  ").unwrap().as_str(),
            "flaky test"
        );
        assert!(Reason::new("   ").is_err());
        assert!(Reason::new(&"x".repeat(MAX_REASON_CHARS)).is_ok());
        assert!(Reason::new(&"x".repeat(MAX_REASON_CHARS + 1)).is_err());
        // Characters, not bytes, are counted.
        assert!(Reason::new(&"é".repeat(MAX_REASON_CHARS)).is_ok());

        let error = ActorName::new("approver", "").unwrap_err();
        assert_eq!(error, "approver must contain 1 to 200 characters");
        assert!(ActorName::new("actor", &"a".repeat(MAX_ACTOR_NAME_CHARS + 1)).is_err());
        assert_eq!(ActorName::new("actor", " ci ").unwrap().as_str(), "ci");
    }

    #[test]
    fn a_status_change_cannot_waive_a_finding() {
        let reason = Reason::new("accepted risk").unwrap();
        let error = FindingStatusChange::new(FindingStatus::Waived, reason.clone()).unwrap_err();
        assert!(error.contains("waiver workflow"), "{error}");
        for status in [
            FindingStatus::Open,
            FindingStatus::Verified,
            FindingStatus::Refuted,
            FindingStatus::Resolved,
        ] {
            let change = FindingStatusChange::new(status, reason.clone()).unwrap();
            assert_eq!(change.status(), status);
            assert_eq!(change.reason(), &reason);
        }
    }

    fn approval(expires_at_unix: Option<i64>, events: &[&str]) -> RuleApproval {
        RuleApproval {
            schema_version: 2,
            approval_id: "approval".into(),
            version: 1,
            candidate_id: "candidate".into(),
            evidence_digest: String::new(),
            source_feedback_ids: Vec::new(),
            activated_at_unix: Some(100),
            category: "correctness".into(),
            feedback_label: FindingFeedbackLabel::Confirmed,
            scope: ".".into(),
            instruction: "Check bounds.".into(),
            approver: "maintainer".into(),
            approval_reason: "Recurring issue.".into(),
            supersedes_approval_id: None,
            expires_at_unix,
            created_at: String::new(),
            status: RuleApprovalStatus::Active,
            events: events
                .iter()
                .map(|event| RuleApprovalEvent {
                    event_id: (*event).into(),
                    event: (*event).into(),
                    actor: "maintainer".into(),
                    reason: "r".into(),
                    created_at: String::new(),
                })
                .collect(),
        }
    }

    #[test]
    fn approval_status_follows_events_then_expiry() {
        assert_eq!(
            approval(None, &["activated"]).status_at(1_000),
            RuleApprovalStatus::Active
        );
        assert_eq!(
            approval(Some(1_000), &["activated"]).status_at(999),
            RuleApprovalStatus::Active
        );
        assert_eq!(
            approval(Some(1_000), &["activated"]).status_at(1_000),
            RuleApprovalStatus::Expired
        );
        assert_eq!(
            approval(Some(1_000), &["activated", "superseded"]).status_at(2_000),
            RuleApprovalStatus::Superseded
        );
        assert_eq!(
            approval(None, &["activated", "superseded", "revoked"]).status_at(0),
            RuleApprovalStatus::Revoked
        );
    }

    #[test]
    fn approval_status_serializes_as_the_published_enum() {
        for (status, name) in [
            (RuleApprovalStatus::Active, "active"),
            (RuleApprovalStatus::Revoked, "revoked"),
            (RuleApprovalStatus::Superseded, "superseded"),
            (RuleApprovalStatus::Expired, "expired"),
        ] {
            assert_eq!(serde_json::to_value(status).unwrap(), name);
            assert_eq!(status.as_str(), name);
        }
    }
}
