//! Provider-neutral contract for optional Git hosting integrations.
//!
//! This crate contains no HTTP client, credentials, or provider SDK. Adapters
//! translate GitHub/GitLab/etc. records into these validated identities and
//! execute the port. Review policy and gate decisions stay in Vee's core.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub mod azure_devops;
pub mod bitbucket;
pub mod conversation;
pub mod gerrit;
pub mod github;
pub mod gitlab;
pub mod trackers;
pub use conversation::{
    Approval, ConversationComment, ConversationKind, PullRequestConversationProvider,
    PullRequestOrigin, PullRequestReview, PullRequestSummary, Reaction, ReplyTarget,
    RepositoryPermission,
};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct RepositoryRef {
    /// Stable provider namespace, e.g. `github.com` or a self-hosted hostname.
    pub host: String,
    /// Stable provider owner/group and repository path, normalized by adapter.
    pub full_name: String,
}

impl RepositoryRef {
    pub fn validate(&self) -> Result<(), String> {
        let valid_host = !self.host.trim().is_empty()
            && self.host.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b':' | b'[' | b']')
            });
        let valid_path = self.full_name.split('/').all(|part| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        });
        if !valid_host
            || self.full_name.trim().is_empty()
            || self.full_name.starts_with('/')
            || self.full_name.ends_with('/')
            || !valid_path
        {
            return Err("invalid Git hosting repository identity".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct PullRequestRef {
    pub repository: RepositoryRef,
    pub number: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct WorkItemRef {
    pub repository: RepositoryRef,
    pub number: u64,
}

impl WorkItemRef {
    pub fn validate(&self) -> Result<(), String> {
        self.repository.validate()?;
        if self.number == 0 {
            return Err("work item number must be positive".into());
        }
        Ok(())
    }
}

/// Bounded, source-attributed issue/specification context from a hosting system.
/// The text is untrusted and must not become gate evidence by itself.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkItemSnapshot {
    pub schema_version: u32,
    pub reference: WorkItemRef,
    pub provider: String,
    pub api_base: String,
    pub title: String,
    #[serde(default)]
    pub body: Option<String>,
    /// Provider-native acceptance criteria, retained separately from description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acceptance_criteria: Option<String>,
    pub url: String,
    pub state: String,
    pub updated_at: String,
    #[serde(default)]
    pub labels: Vec<String>,
    pub content_digest: String,
}

impl WorkItemSnapshot {
    pub fn validate(&self) -> Result<(), String> {
        self.reference.validate()?;
        if self.schema_version != 1
            || self.provider.trim().is_empty()
            || self.api_base.trim().is_empty()
            || self.title.trim().is_empty()
            || self.url.trim().is_empty()
            || self.state.trim().is_empty()
            || self.updated_at.trim().is_empty()
            || self.content_digest.len() != 64
            || !self
                .content_digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(
                "work item source, title, state, update time, URL, and digest are required".into(),
            );
        }
        if self.title.len() > 16_384
            || self.body.as_ref().is_some_and(|body| body.len() > 131_072)
            || self
                .acceptance_criteria
                .as_ref()
                .is_some_and(|criteria| criteria.len() > 131_072)
            || self.labels.len() > 100
            || self.labels.iter().any(|label| label.len() > 512)
        {
            return Err("work item context exceeds configured size bounds".into());
        }
        let expected = work_item_digest(self);
        if self.content_digest != expected {
            return Err("work item content digest does not match its fields".into());
        }
        Ok(())
    }
}

pub fn work_item_digest(item: &WorkItemSnapshot) -> String {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    let number = item.reference.number.to_string();
    hash.update(item.schema_version.to_be_bytes());
    hash.update([u8::from(item.body.is_some())]);
    for value in [
        item.provider.as_bytes(),
        item.api_base.as_bytes(),
        item.reference.repository.host.as_bytes(),
        item.reference.repository.full_name.as_bytes(),
        number.as_bytes(),
        item.title.as_bytes(),
        item.body.as_deref().unwrap_or("").as_bytes(),
        item.url.as_bytes(),
        item.state.as_bytes(),
        item.updated_at.as_bytes(),
    ] {
        hash.update((value.len() as u64).to_be_bytes());
        hash.update(value);
    }
    // Preserve digests for existing providers/records that omit this field.
    if let Some(criteria) = &item.acceptance_criteria {
        hash.update(b"acceptance_criteria\0");
        hash.update((criteria.len() as u64).to_be_bytes());
        hash.update(criteria.as_bytes());
    }
    let mut labels: Vec<_> = item.labels.iter().map(String::as_str).collect();
    labels.sort_unstable();
    for label in labels {
        hash.update((label.len() as u64).to_be_bytes());
        hash.update(label.as_bytes());
    }
    format!("{:x}", hash.finalize())
}

impl PullRequestRef {
    pub fn validate(&self) -> Result<(), String> {
        self.repository.validate()?;
        if self.number == 0 {
            return Err("pull request number must be positive".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PullRequestSnapshot {
    pub pull_request: PullRequestRef,
    pub base_oid: String,
    pub head_oid: String,
    pub title: String,
    #[serde(default)]
    pub body: Option<String>,
    pub state: PullRequestState,
    /// Provider update token (etag/version), used to detect stale publication.
    pub revision: String,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PullRequestState {
    Open,
    Closed,
    Merged,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PullRequestFile {
    pub path: String,
    pub change: FileChange,
    #[serde(default)]
    pub previous_path: Option<String>,
    pub patch: Option<String>,
    pub additions: u64,
    pub deletions: u64,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FileChange {
    Added,
    Modified,
    Deleted,
    Renamed,
    Copied,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CheckRun {
    pub pull_request: PullRequestRef,
    pub external_id: String,
    pub name: String,
    pub status: CheckStatus,
    pub conclusion: Option<CheckConclusion>,
    pub title: String,
    pub summary: String,
    /// Vee review/snapshot identity, retained as the provider check's source.
    pub snapshot_id: String,
    /// Adapter maps this to provider-specific idempotent upsert semantics.
    pub idempotency_key: String,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    Queued,
    InProgress,
    Completed,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CheckConclusion {
    Success,
    Failure,
    Neutral,
    Cancelled,
    TimedOut,
    ActionRequired,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReviewThread {
    pub pull_request: PullRequestRef,
    /// Vee stable fingerprint; adapters persist its mapping to provider IDs.
    pub fingerprint: String,
    pub path: String,
    pub line: u64,
    pub side: DiffSide,
    pub body: String,
    pub resolution: ThreadResolution,
    pub snapshot_id: String,
    pub idempotency_key: String,
    /// A replacement for lines `line..=end_line` on the new side, checked
    /// against the pull request's diff, which the adapter renders in its
    /// host's suggestion syntax.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suggestion: Option<ThreadSuggestion>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ThreadSuggestion {
    /// Last replaced line; the thread's `line` is the first.
    pub end_line: u64,
    /// The replaced lines as the pull request's head has them.
    pub original: Vec<String>,
    /// Their replacement, without a trailing newline; empty deletes them.
    pub replacement: String,
}

/// How a host shows a suggested change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SuggestionStyle {
    /// A ```` ```suggestion ```` block on a comment spanning the replaced lines.
    GitHub,
    /// A ```` ```suggestion:-0+N ```` block on a comment at the first line.
    GitLab,
    /// A plain diff for hosts without committable suggestions.
    Diff,
}

impl ThreadSuggestion {
    /// A code fence longer than any backtick run in the suggestion, so
    /// suggested code holding a fence cannot end the block early.
    fn fence(&self) -> String {
        let longest = std::iter::once(self.replacement.as_str())
            .chain(self.original.iter().map(String::as_str))
            .flat_map(|text| text.split(|c| c != '`'))
            .map(str::len)
            .max()
            .unwrap_or(0);
        "`".repeat(longest.max(2) + 1)
    }

    fn lines_with_prefix(text: &[String], prefix: char) -> String {
        text.iter()
            .map(|line| format!("{prefix}{line}\n"))
            .collect()
    }

    /// The suggestion as `style` writes it, for a thread starting at `line`.
    pub fn markdown(&self, line: u64, style: SuggestionStyle) -> String {
        let fence = self.fence();
        let replacement = if self.replacement.is_empty() {
            String::new()
        } else {
            format!("{}\n", self.replacement)
        };
        match style {
            SuggestionStyle::GitHub => format!("{fence}suggestion\n{replacement}{fence}"),
            SuggestionStyle::GitLab => format!(
                "{fence}suggestion:-0+{}\n{replacement}{fence}",
                self.end_line.saturating_sub(line)
            ),
            SuggestionStyle::Diff => {
                let added = self
                    .replacement
                    .lines()
                    .map(str::to_owned)
                    .collect::<Vec<_>>();
                format!(
                    "{fence}diff\n{}{}{fence}",
                    Self::lines_with_prefix(&self.original, '-'),
                    Self::lines_with_prefix(&added, '+')
                )
            }
        }
    }
}

impl ReviewThread {
    /// The thread's text followed by its suggestion, if it has one.
    pub fn body_with_suggestion(&self, style: SuggestionStyle) -> String {
        match &self.suggestion {
            Some(suggestion) => format!(
                "{}\n\nSuggested change:\n\n{}",
                self.body,
                suggestion.markdown(self.line, style)
            ),
            None => self.body.clone(),
        }
    }

    /// The last line the thread's comment covers.
    pub fn end_line(&self) -> u64 {
        self.suggestion
            .as_ref()
            .map_or(self.line, |suggestion| suggestion.end_line.max(self.line))
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DiffSide {
    Old,
    New,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ThreadResolution {
    Open,
    Resolved,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WebhookEnvelope {
    pub provider: String,
    pub event_id: String,
    pub event_type: String,
    pub delivery_attempt: u32,
    pub pull_request: Option<PullRequestRef>,
    #[serde(default)]
    pub action: Option<String>,
    #[serde(default)]
    pub base_oid: Option<String>,
    #[serde(default)]
    pub head_oid: Option<String>,
    /// Adapter-verified signature result. Invalid signatures must be rejected
    /// before constructing this trusted application-level envelope.
    pub signature_verified: bool,
}

impl WebhookEnvelope {
    pub fn validate(&self) -> Result<(), String> {
        if self.provider.trim().is_empty()
            || self.event_id.trim().is_empty()
            || self.event_type.trim().is_empty()
            || self.delivery_attempt == 0
        {
            return Err("webhook identity and positive delivery attempt are required".into());
        }
        if !self.signature_verified {
            return Err("unverified webhook signature".into());
        }
        if let Some(pr) = &self.pull_request {
            pr.validate()?;
        }
        if self.base_oid.is_some() && self.head_oid.is_none() {
            return Err("webhook base OID requires a head OID".into());
        }
        for oid in [&self.base_oid, &self.head_oid].into_iter().flatten() {
            if !matches!(oid.len(), 40 | 64) || !oid.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err("webhook pull request contains an invalid commit OID".into());
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReviewPublication {
    pub pull_request: PullRequestRef,
    pub expected_revision: String,
    pub check: CheckRun,
    /// Desired state keyed by Vee finding fingerprint. Omission does not mean
    /// resolution: adapters must close only threads Vee explicitly marks.
    pub threads: Vec<ReviewThread>,
}

impl ReviewPublication {
    pub fn validate(&self) -> Result<(), String> {
        self.pull_request.validate()?;
        self.check.pull_request.validate()?;
        if self.check.pull_request != self.pull_request {
            return Err("check run targets a different pull request".into());
        }
        if self.expected_revision.trim().is_empty()
            || self.check.snapshot_id.trim().is_empty()
            || self.check.idempotency_key.trim().is_empty()
        {
            return Err("publication revision, snapshot, and idempotency key are required".into());
        }
        if (self.check.status == CheckStatus::Completed) != self.check.conclusion.is_some() {
            return Err("only completed checks have a conclusion".into());
        }
        let mut fingerprints = std::collections::BTreeSet::new();
        for thread in &self.threads {
            thread.pull_request.validate()?;
            if thread.pull_request != self.pull_request {
                return Err("review thread targets a different pull request".into());
            }
            if thread.fingerprint.trim().is_empty()
                || !valid_marker_token(&thread.fingerprint)
                || thread.path.trim().is_empty()
                || thread.line == 0
                || thread.snapshot_id != self.check.snapshot_id
                || thread.idempotency_key.trim().is_empty()
                || !valid_marker_token(&thread.idempotency_key)
            {
                return Err("review thread has invalid identity or snapshot binding".into());
            }
            if !fingerprints.insert(&thread.fingerprint) {
                return Err("publication repeats a finding fingerprint".into());
            }
        }
        Ok(())
    }
}

fn valid_marker_token(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || b":._-".contains(&byte))
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PublicationReceipt {
    pub provider_check_id: String,
    /// Map of Vee fingerprint to provider-native review thread ID.
    pub thread_ids: BTreeMap<String, String>,
    pub resulting_revision: String,
}

/// Adapter port. Implementations must be idempotent for repeated publication
/// keys and reject a changed PR revision instead of publishing stale results.
pub trait GitHostingProvider: Send + Sync {
    fn provider_id(&self) -> &'static str;
    fn get_pull_request(
        &self,
        reference: &PullRequestRef,
    ) -> Result<PullRequestSnapshot, HostingError>;
    fn list_changed_files(
        &self,
        reference: &PullRequestRef,
        expected_revision: &str,
    ) -> Result<Vec<PullRequestFile>, HostingError>;
    fn publish_review(
        &self,
        publication: ReviewPublication,
    ) -> Result<PublicationReceipt, HostingError>;
    fn verify_webhook(
        &self,
        headers: &BTreeMap<String, String>,
        body: &[u8],
    ) -> Result<WebhookEnvelope, HostingError>;
}

/// Read-only pull request context for agent investigation workflows. Providers
/// can implement this before they support review publication or webhooks.
pub trait PullRequestContextProvider: Send + Sync {
    fn context_provider_id(&self) -> &'static str;
    fn get_pull_request_context(
        &self,
        reference: &PullRequestRef,
    ) -> Result<PullRequestSnapshot, HostingError>;
    fn list_pull_request_context_files(
        &self,
        reference: &PullRequestRef,
        expected_revision: &str,
    ) -> Result<Vec<PullRequestFile>, HostingError>;
}

/// Read-only, untrusted review discussions for agent remediation workflows.
/// A returned issue is context only and must never enter gate evaluation as a
/// verified Vee finding without independent review and evidence.
pub trait PullRequestReviewIssuesProvider: Send + Sync {
    fn list_pull_request_review_issues(
        &self,
        reference: &PullRequestRef,
    ) -> Result<PullRequestReviewIssues, HostingError>;
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PullRequestReviewIssues {
    pub schema_version: u32,
    pub provider: String,
    pub pull_request: PullRequestRef,
    pub revision: String,
    pub complete: bool,
    pub gate_eligible: bool,
    pub issues: Vec<PullRequestReviewIssue>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PullRequestReviewIssue {
    pub external_id: String,
    pub author: Option<String>,
    pub body: String,
    pub path: Option<String>,
    pub line: Option<u64>,
    pub side: Option<DiffSide>,
    pub source_url: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub classification: String,
}

impl PullRequestContextProvider for github::GitHubAdapter {
    fn context_provider_id(&self) -> &'static str {
        "github"
    }

    fn get_pull_request_context(
        &self,
        reference: &PullRequestRef,
    ) -> Result<PullRequestSnapshot, HostingError> {
        GitHostingProvider::get_pull_request(self, reference)
    }

    fn list_pull_request_context_files(
        &self,
        reference: &PullRequestRef,
        expected_revision: &str,
    ) -> Result<Vec<PullRequestFile>, HostingError> {
        GitHostingProvider::list_changed_files(self, reference, expected_revision)
    }
}

impl PullRequestContextProvider for gitlab::GitLabAdapter {
    fn context_provider_id(&self) -> &'static str {
        "gitlab"
    }
    fn get_pull_request_context(
        &self,
        reference: &PullRequestRef,
    ) -> Result<PullRequestSnapshot, HostingError> {
        GitHostingProvider::get_pull_request(self, reference)
    }
    fn list_pull_request_context_files(
        &self,
        reference: &PullRequestRef,
        expected_revision: &str,
    ) -> Result<Vec<PullRequestFile>, HostingError> {
        GitHostingProvider::list_changed_files(self, reference, expected_revision)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PullRequestContextReport {
    pub schema_version: u32,
    pub provider: String,
    pub snapshot: PullRequestSnapshot,
    pub changed_files: Vec<PullRequestFile>,
    pub limitations: Vec<String>,
}

/// Optional issue/specification lookup. Work item text is returned as attributed
/// context; callers decide how to include it in a review and policy evaluation.
pub trait WorkItemProvider: Send + Sync {
    fn work_item_provider_id(&self) -> &'static str;
    fn get_work_item(&self, reference: &WorkItemRef) -> Result<WorkItemSnapshot, HostingError>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostingError {
    NotFound,
    Unauthorized,
    AuthorizationDenied {
        provider: String,
        detail: Option<String>,
        required_permissions: Option<String>,
    },
    RateLimited {
        retry_after_seconds: Option<u64>,
    },
    StaleRevision {
        expected: String,
        actual: String,
    },
    InvalidResponse(String),
    Transport(String),
}

impl std::fmt::Display for HostingError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => formatter.write_str("hosting resource not found"),
            Self::Unauthorized => formatter.write_str(
                "hosting authorization failed; check that the credential is valid, can access this repository, and has the permissions required for this operation",
            ),
            Self::AuthorizationDenied {
                provider,
                detail,
                required_permissions,
            } => {
                write!(formatter, "{provider} authorization failed")?;
                if let Some(detail) = detail {
                    write!(formatter, ": {detail}")?;
                }
                if let Some(required_permissions) = required_permissions {
                    write!(formatter, "; API requires {required_permissions}")?;
                }
                Ok(())
            }
            Self::RateLimited {
                retry_after_seconds,
            } => {
                write!(
                    formatter,
                    "hosting rate limit reached ({retry_after_seconds:?})"
                )
            }
            Self::StaleRevision { expected, actual } => {
                write!(
                    formatter,
                    "pull request revision changed from {expected} to {actual}"
                )
            }
            Self::InvalidResponse(message) => {
                write!(formatter, "invalid hosting response: {message}")
            }
            Self::Transport(message) => write!(formatter, "hosting transport failed: {message}"),
        }
    }
}

impl std::error::Error for HostingError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn suggested(original: &[&str], replacement: &str) -> ThreadSuggestion {
        ThreadSuggestion {
            end_line: 11 + original.len() as u64 - 1,
            original: original.iter().map(|line| (*line).to_owned()).collect(),
            replacement: replacement.into(),
        }
    }

    #[test]
    fn suggestions_render_in_each_hosts_syntax() {
        let two_lines = suggested(&["    let x = a;", "    let y = b;"], "    let x = b;");
        assert_eq!(
            two_lines.markdown(11, SuggestionStyle::GitHub),
            "```suggestion\n    let x = b;\n```"
        );
        assert_eq!(
            two_lines.markdown(11, SuggestionStyle::GitLab),
            "```suggestion:-0+1\n    let x = b;\n```"
        );
        assert_eq!(
            two_lines.markdown(11, SuggestionStyle::Diff),
            "```diff\n-    let x = a;\n-    let y = b;\n+    let x = b;\n```"
        );
        let deletion = suggested(&["dbg!(x);"], "");
        assert_eq!(
            deletion.markdown(11, SuggestionStyle::GitHub),
            "```suggestion\n```"
        );
        assert_eq!(
            deletion.markdown(11, SuggestionStyle::GitLab),
            "```suggestion:-0+0\n```"
        );
    }

    #[test]
    fn suggested_code_holding_a_fence_cannot_close_the_block() {
        let fenced = suggested(&["/// ```"], "/// ````text");
        assert_eq!(
            fenced.markdown(11, SuggestionStyle::GitHub),
            "`````suggestion\n/// ````text\n`````"
        );
    }

    fn pr() -> PullRequestRef {
        PullRequestRef {
            repository: RepositoryRef {
                host: "github.example.test".into(),
                full_name: "team/service".into(),
            },
            number: 42,
        }
    }

    #[test]
    fn repository_identity_is_host_aware_and_rejects_path_traversal() {
        assert!(pr().validate().is_ok());
        let mut invalid = pr();
        invalid.repository.full_name = "team/../other".into();
        assert!(invalid.validate().is_err());
        let mut different_host = pr();
        different_host.repository.host = "gitlab.example.test".into();
        assert_ne!(pr(), different_host);
    }

    #[test]
    fn authorization_errors_explain_what_to_check() {
        let message = HostingError::Unauthorized.to_string();
        assert!(message.contains("credential is valid"));
        assert!(message.contains("access this repository"));
        assert!(message.contains("permissions required"));
    }

    #[test]
    fn webhook_requires_verified_signature_and_stable_event_identity() {
        let envelope = WebhookEnvelope {
            provider: "github".into(),
            event_id: "delivery-123".into(),
            event_type: "pull_request".into(),
            delivery_attempt: 1,
            pull_request: Some(pr()),
            action: None,
            base_oid: None,
            head_oid: None,
            signature_verified: false,
        };
        assert!(envelope.validate().is_err());
        let verified = WebhookEnvelope {
            signature_verified: true,
            ..envelope
        };
        assert!(verified.validate().is_ok());
        assert_eq!(verified.event_id, "delivery-123");
        let gerrit_patchset = WebhookEnvelope {
            base_oid: None,
            head_oid: Some("a".repeat(40)),
            ..verified.clone()
        };
        assert!(gerrit_patchset.validate().is_ok());
        let invalid_range = WebhookEnvelope {
            base_oid: Some("b".repeat(40)),
            head_oid: None,
            ..verified
        };
        assert!(invalid_range.validate().is_err());
    }

    #[test]
    fn publication_contract_roundtrips_without_provider_specific_fields() {
        let check = CheckRun {
            pull_request: pr(),
            external_id: "rev_abc".into(),
            name: "Vee assurance".into(),
            status: CheckStatus::Completed,
            conclusion: Some(CheckConclusion::Failure),
            title: "Review blocked".into(),
            summary: "One high-severity issue".into(),
            snapshot_id: "sha256:abc".into(),
            idempotency_key: "review:sha256:abc".into(),
        };
        let publication = ReviewPublication {
            pull_request: pr(),
            expected_revision: "head:abc".into(),
            check,
            threads: vec![],
        };
        let json = serde_json::to_string(&publication).unwrap();
        let decoded: ReviewPublication = serde_json::from_str(&json).unwrap();
        assert_eq!(publication, decoded);
        assert!(decoded.validate().is_ok());
        let invalid = ReviewPublication {
            expected_revision: String::new(),
            ..decoded
        };
        assert!(invalid.validate().is_err());
    }
}
