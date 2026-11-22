use anyhow::Context;
use sha2::{Digest, Sha256};
use std::{io::Write, path::Path};
use vee_core::FindingFeedbackLabel;

const MAX_RESULTS: usize = 100;

/// `imported-review-search-v3`: imported history matching a query. Every
/// match is untrusted historical context and never gate eligible.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ImportedHistorySearch {
    pub schema_version: u32,
    pub query: String,
    pub matches: Vec<ImportedMatch>,
    pub trust: String,
    pub gate_eligible: bool,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum ImportedMatch {
    Finding(ImportedFindingMatch),
    Discussion(ImportedDiscussionMatch),
}

/// A finding from an imported Vee review.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportedFindingMatch {
    pub archive_digest: String,
    pub review_id: String,
    pub snapshot_id: String,
    pub finding: vee_core::Finding,
    pub relevance_score: u32,
    pub matched_fields: Vec<String>,
    pub trust: String,
    pub gate_eligible: bool,
}

/// A comment from an archived provider pull-request discussion.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportedDiscussionMatch {
    pub archive_digest: String,
    pub provider: String,
    pub pull_request: vee_hosting::PullRequestRef,
    pub revision: String,
    pub issue: vee_hosting::PullRequestReviewIssue,
    pub relevance_score: u32,
    pub matched_fields: Vec<String>,
    pub trust: String,
    pub gate_eligible: bool,
}

impl ImportedMatch {
    pub fn relevance_score(&self) -> u32 {
        match self {
            Self::Finding(item) => item.relevance_score,
            Self::Discussion(item) => item.relevance_score,
        }
    }

    pub fn archive_digest(&self) -> &str {
        match self {
            Self::Finding(item) => &item.archive_digest,
            Self::Discussion(item) => &item.archive_digest,
        }
    }

    fn order_key(&self) -> (std::cmp::Reverse<u32>, &str, Option<&str>, Option<&str>) {
        let (fingerprint, external_id) = match self {
            Self::Finding(item) => (Some(item.finding.fingerprint.as_str()), None),
            Self::Discussion(item) => (None, Some(item.issue.external_id.as_str())),
        };
        (
            std::cmp::Reverse(self.relevance_score()),
            self.archive_digest(),
            fingerprint,
            external_id,
        )
    }
}

const UNTRUSTED_EXTERNAL: &str = "untrusted_external";

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExternalReviewFeedback {
    pub schema_version: u32,
    pub feedback_id: String,
    pub archive_digest: String,
    pub provider: String,
    pub pull_request: vee_hosting::PullRequestRef,
    pub revision: String,
    pub external_id: String,
    pub category: String,
    pub label: FindingFeedbackLabel,
    pub reason: String,
    pub reviewer: String,
    pub recorded_at_unix: i64,
}

impl ExternalReviewFeedback {
    pub fn label_text(&self) -> &'static str {
        match self.label {
            FindingFeedbackLabel::Confirmed => "confirmed",
            FindingFeedbackLabel::FalsePositive => "false_positive",
            FindingFeedbackLabel::Actionable => "actionable",
            FindingFeedbackLabel::NotActionable => "not_actionable",
        }
    }
}

pub struct FeedbackRecordInput<'a> {
    pub archive_digest: &'a str,
    pub external_id: &'a str,
    pub category: &'a str,
    pub label: FindingFeedbackLabel,
    pub reason: &'a str,
    pub reviewer: &'a str,
    pub recorded_at_unix: i64,
}

pub fn record_feedback(
    root: &Path,
    input: FeedbackRecordInput<'_>,
) -> Result<ExternalReviewFeedback, String> {
    let FeedbackRecordInput {
        archive_digest,
        external_id,
        category,
        label,
        reason,
        reviewer,
        recorded_at_unix,
    } = input;
    let reason = reason.trim();
    let reviewer = reviewer.trim();
    let category = category.trim();
    if reason.is_empty() || reason.chars().count() > 4000 {
        return Err("reason must contain 1 to 4000 characters".into());
    }
    if reviewer.is_empty() || reviewer.chars().count() > 200 {
        return Err("reviewer must contain 1 to 200 characters".into());
    }
    if external_id.is_empty() || external_id.len() > 500 {
        return Err("external comment ID must contain 1 to 500 bytes".into());
    }
    if category.is_empty() || category.chars().count() > 120 {
        return Err("category must contain 1 to 120 characters".into());
    }
    let digest_hex = archive_digest
        .strip_prefix("sha256:")
        .unwrap_or(archive_digest)
        .to_ascii_lowercase();
    if digest_hex.len() != 64 || !digest_hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("archive digest must be a SHA-256 hex digest".into());
    }
    let digest = format!("sha256:{digest_hex}");
    let archive_dir = imported_reviews_dir(root, false).map_err(|error| error.to_string())?;
    let archive_path = archive_dir.join(format!("{digest_hex}.json"));
    let archive_meta = std::fs::symlink_metadata(&archive_path)
        .map_err(|_| "imported review archive entry was not found".to_owned())?;
    if !archive_meta.is_file()
        || archive_meta.file_type().is_symlink()
        || archive_meta.len() > MAX_IMPORTED_REVIEW_BYTES
    {
        return Err("invalid imported review archive entry".into());
    }
    let bytes = std::fs::read(&archive_path).map_err(|error| error.to_string())?;
    if hex_digest(&Sha256::digest(&bytes)) != digest_hex {
        return Err("imported archive entry failed integrity check".into());
    }
    let discussion: vee_hosting::PullRequestReviewIssues = serde_json::from_slice(&bytes)
        .map_err(|_| "archive does not contain provider review discussions".to_owned())?;
    if discussion.schema_version != 1 || discussion.gate_eligible {
        return Err(
            "provider discussion archive has an unsupported or gate-eligible contract".into(),
        );
    }
    if !discussion
        .issues
        .iter()
        .any(|issue| issue.external_id == external_id)
    {
        return Err("external comment ID is not present in the selected archive".into());
    }
    let mut feedback = ExternalReviewFeedback {
        schema_version: 1,
        feedback_id: String::new(),
        archive_digest: digest,
        provider: discussion.provider,
        pull_request: discussion.pull_request,
        revision: discussion.revision,
        external_id: external_id.to_owned(),
        category: category.to_owned(),
        label,
        reason: reason.to_owned(),
        reviewer: reviewer.to_owned(),
        recorded_at_unix,
    };
    feedback.feedback_id = external_feedback_identity(&feedback)?;
    persist_feedback(root, &feedback).map_err(|error| error.to_string())?;
    Ok(feedback)
}

pub fn list_feedback(
    root: &Path,
    archive_digest: Option<&str>,
) -> Result<Vec<ExternalReviewFeedback>, String> {
    if !root.join(".vee/imported-feedback").exists() {
        return Ok(Vec::new());
    }
    let directory = feedback_dir(root, false)?;
    let selected = archive_digest.map(|value| {
        value
            .strip_prefix("sha256:")
            .unwrap_or(value)
            .to_ascii_lowercase()
    });
    if let Some(digest) = &selected {
        if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err("archive digest must be a SHA-256 hex digest".into());
        }
    }
    let mut records = Vec::new();
    for entry in std::fs::read_dir(directory).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        if entry.path().extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let meta = std::fs::symlink_metadata(entry.path()).map_err(|error| error.to_string())?;
        if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > 16 * 1024 {
            continue;
        }
        let bytes = std::fs::read(entry.path()).map_err(|error| error.to_string())?;
        let Ok(item) = serde_json::from_slice::<ExternalReviewFeedback>(&bytes) else {
            continue;
        };
        if item.schema_version != 1
            || entry.file_name().to_string_lossy()
                != format!("{}.json", item.feedback_id.trim_start_matches("sha256:"))
            || external_feedback_identity(&item).ok().as_deref() != Some(item.feedback_id.as_str())
        {
            continue;
        }
        if selected
            .as_deref()
            .is_none_or(|value| item.archive_digest == format!("sha256:{value}"))
        {
            records.push(item);
            if records.len() >= 10_000 {
                break;
            }
        }
    }
    records.sort_by(|left, right| {
        left.archive_digest
            .cmp(&right.archive_digest)
            .then_with(|| left.external_id.cmp(&right.external_id))
            .then_with(|| left.feedback_id.cmp(&right.feedback_id))
    });
    Ok(records)
}

fn external_feedback_identity(feedback: &ExternalReviewFeedback) -> Result<String, String> {
    let identity = serde_json::to_vec(&serde_json::json!({
        "archive_digest": &feedback.archive_digest,
        "external_id": &feedback.external_id,
        "category": &feedback.category,
        "label": feedback.label,
        "reason": &feedback.reason,
        "reviewer": &feedback.reviewer,
        "recorded_at_unix": feedback.recorded_at_unix
    }))
    .map_err(|error| error.to_string())?;
    Ok(format!("sha256:{}", hex_digest(&Sha256::digest(identity))))
}

fn persist_feedback(root: &Path, feedback: &ExternalReviewFeedback) -> Result<(), String> {
    let directory = feedback_dir(root, true)?;
    let bytes = serde_json::to_vec(feedback).map_err(|error| error.to_string())?;
    let digest_hex = feedback.feedback_id.trim_start_matches("sha256:");
    let target = directory.join(format!("{digest_hex}.json"));
    if let Ok(existing) = std::fs::read(&target) {
        return if existing == bytes {
            Ok(())
        } else {
            Err("feedback identity collision".into())
        };
    }
    let temporary = directory.join(format!(".{digest_hex}.{}.tmp", std::process::id()));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|error| error.to_string())?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| error.to_string())?;
    drop(file);
    let result = std::fs::hard_link(&temporary, &target);
    let _ = std::fs::remove_file(&temporary);
    match result {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let existing = std::fs::read(&target).map_err(|error| error.to_string())?;
            if existing == bytes {
                Ok(())
            } else {
                Err("feedback identity collision".into())
            }
        }
        Err(error) => Err(error.to_string()),
    }
}

fn feedback_dir(root: &Path, create: bool) -> Result<std::path::PathBuf, String> {
    let state = root.join(".vee");
    if create && !state.exists() {
        std::fs::create_dir(&state).map_err(|error| error.to_string())?;
    }
    let state_meta = std::fs::symlink_metadata(&state).map_err(|error| error.to_string())?;
    if !state_meta.is_dir() || state_meta.file_type().is_symlink() {
        return Err(".vee must be a real directory".into());
    }
    let directory = state.join("imported-feedback");
    if create && !directory.exists() {
        std::fs::create_dir(&directory).map_err(|error| error.to_string())?;
    }
    let meta = std::fs::symlink_metadata(&directory).map_err(|error| error.to_string())?;
    if !meta.is_dir() || meta.file_type().is_symlink() {
        return Err("imported feedback storage must be a real directory".into());
    }
    Ok(directory)
}

pub fn search(root: &Path, query: &str, limit: usize) -> Result<ImportedHistorySearch, String> {
    let terms = query
        .to_lowercase()
        .split(|character: char| !character.is_alphanumeric())
        .filter(|term| !term.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if terms.is_empty() {
        return Err("search query must not be empty".into());
    }
    if !(1..=MAX_RESULTS).contains(&limit) {
        return Err(format!("limit must be between 1 and {MAX_RESULTS}"));
    }
    let archive = imported_reviews_dir(root, false).map_err(|error| error.to_string())?;
    let mut matches = Vec::new();
    for entry in std::fs::read_dir(&archive).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        if entry.path().extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let metadata =
            std::fs::symlink_metadata(entry.path()).map_err(|error| error.to_string())?;
        if !metadata.file_type().is_file() || metadata.len() > MAX_IMPORTED_REVIEW_BYTES {
            continue;
        }
        let bytes = std::fs::read(entry.path()).map_err(|error| error.to_string())?;
        let hash = hex_digest(&Sha256::digest(&bytes));
        if entry.file_name().to_string_lossy() != format!("{hash}.json") {
            continue;
        }
        let review = match parse_portable_review(&bytes) {
            Ok(review) => review,
            Err(_) => {
                let discussion: vee_hosting::PullRequestReviewIssues =
                    match serde_json::from_slice(&bytes) {
                        Ok(discussion) => discussion,
                        Err(_) => continue,
                    };
                if discussion.schema_version != 1 || discussion.gate_eligible {
                    continue;
                }
                for issue in discussion.issues {
                    let fields = [
                        ("body", issue.body.to_lowercase(), 5_u32),
                        (
                            "path",
                            issue.path.as_deref().unwrap_or_default().to_lowercase(),
                            6,
                        ),
                        (
                            "author",
                            issue.author.as_deref().unwrap_or_default().to_lowercase(),
                            2,
                        ),
                        ("classification", issue.classification.to_lowercase(), 3),
                    ];
                    let mut score = 0_u32;
                    let mut all_terms_matched = true;
                    let mut matched_fields = Vec::new();
                    for term in &terms {
                        let matching = fields
                            .iter()
                            .filter(|(_, value, _)| value.contains(term))
                            .collect::<Vec<_>>();
                        let Some(best) = matching.iter().map(|(_, _, weight)| *weight).max() else {
                            all_terms_matched = false;
                            break;
                        };
                        score += best;
                        for (name, _, _) in matching {
                            if !matched_fields.contains(name) {
                                matched_fields.push(*name);
                            }
                        }
                    }
                    if all_terms_matched {
                        matched_fields.sort_unstable();
                        matches.push(ImportedMatch::Discussion(ImportedDiscussionMatch {
                            archive_digest: format!("sha256:{hash}"),
                            provider: discussion.provider.clone(),
                            pull_request: discussion.pull_request.clone(),
                            revision: discussion.revision.clone(),
                            issue,
                            relevance_score: score,
                            matched_fields: matched_fields
                                .iter()
                                .map(|field| (*field).to_owned())
                                .collect(),
                            trust: UNTRUSTED_EXTERNAL.to_owned(),
                            gate_eligible: false,
                        }));
                    }
                }
                continue;
            }
        };
        for finding in review.findings {
            let fields = [
                ("category", finding.category.to_lowercase(), 8_u32),
                (
                    "path",
                    finding.path.as_deref().unwrap_or_default().to_lowercase(),
                    6,
                ),
                (
                    "severity",
                    format!("{:?}", finding.severity).to_lowercase(),
                    4,
                ),
                ("rationale", finding.rationale.to_lowercase(), 3),
                ("provenance", finding.provenance.to_lowercase(), 1),
            ];
            let mut score = 0_u32;
            let mut all_terms_matched = true;
            let mut matched_fields = Vec::new();
            for term in &terms {
                let matching = fields
                    .iter()
                    .filter(|(_, value, _)| value.contains(term))
                    .collect::<Vec<_>>();
                let Some(best) = matching.iter().map(|(_, _, weight)| *weight).max() else {
                    all_terms_matched = false;
                    break;
                };
                score += best;
                for (name, _, _) in matching {
                    if !matched_fields.contains(name) {
                        matched_fields.push(*name);
                    }
                }
            }
            if all_terms_matched {
                matched_fields.sort_unstable();
                matches.push(ImportedMatch::Finding(ImportedFindingMatch {
                    archive_digest: format!("sha256:{hash}"),
                    review_id: review.review_id.clone(),
                    snapshot_id: review.snapshot_id.clone(),
                    finding: finding.clone(),
                    relevance_score: score,
                    matched_fields: matched_fields
                        .iter()
                        .map(|field| (*field).to_owned())
                        .collect(),
                    trust: UNTRUSTED_EXTERNAL.to_owned(),
                    gate_eligible: false,
                }));
            }
        }
    }
    matches.sort_by(|left, right| left.order_key().cmp(&right.order_key()));
    matches.truncate(limit);
    Ok(ImportedHistorySearch {
        schema_version: 3,
        query: terms.join(" "),
        matches,
        trust: UNTRUSTED_EXTERNAL.to_owned(),
        gate_eligible: false,
    })
}

fn hex_digest(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Upper bound on one imported review archive entry.
pub const MAX_IMPORTED_REVIEW_BYTES: u64 = 10 * 1024 * 1024;
static IMPORT_TEMP_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Parse and integrity-check a portable Vee review (output schema v2).
pub fn parse_portable_review(bytes: &[u8]) -> anyhow::Result<crate::ReviewResult> {
    let text = std::str::from_utf8(bytes).context("import file must be UTF-8")?;
    let payload: serde_json::Value =
        serde_json::from_str(text).context("import file is not valid JSON")?;
    anyhow::ensure!(
        payload
            .get("schema_version")
            .and_then(serde_json::Value::as_u64)
            == Some(2),
        "only Vee review output schema v2 can be imported"
    );
    let review = crate::deserialize_review_result(text).map_err(anyhow::Error::msg)?;
    anyhow::ensure!(
        review.snapshot_id == review.change_set.digest,
        "review snapshot ID does not match its change set digest"
    );
    anyhow::ensure!(
        review.gate.snapshot_id == review.snapshot_id,
        "gate decision is bound to a different snapshot"
    );
    Ok(review)
}

/// Archive an imported review under `.vee/imports` by content digest; returns the digest.
pub fn store_imported_history(root: &std::path::Path, bytes: &[u8]) -> anyhow::Result<String> {
    anyhow::ensure!(
        bytes.len() as u64 <= MAX_IMPORTED_REVIEW_BYTES,
        "import file exceeds 10 MiB limit"
    );
    let digest = format!(
        "sha256:{}",
        vee_core::digest(bytes).trim_start_matches("sha256:")
    );
    let archive = imported_reviews_dir(root, true)?;
    let digest_hex = digest.trim_start_matches("sha256:");
    let target = archive.join(format!("{digest_hex}.json"));
    let temporary = archive.join(format!(
        ".{digest_hex}.{}.{}.tmp",
        std::process::id(),
        IMPORT_TEMP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let result = match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
    {
        Ok(mut file) => {
            let result = file
                .write_all(bytes)
                .context("could not write imported review archive")
                .and_then(|()| {
                    file.sync_all()
                        .context("could not sync imported review archive")
                });
            drop(file);
            result
        }
        Err(error) => {
            Err(error).context("could not create temporary imported review archive entry")
        }
    };
    if let Err(error) = result {
        let _ = std::fs::remove_file(&temporary);
        return Err(error);
    }
    match std::fs::rename(&temporary, &target) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let existing = std::fs::read(&target)
                .context("could not inspect existing imported review archive entry")?;
            let _ = std::fs::remove_file(&temporary);
            anyhow::ensure!(
                existing == bytes,
                "archive digest collision or corrupted archive entry"
            );
        }
        Err(error) => {
            let _ = std::fs::remove_file(&temporary);
            return Err(error).context("could not publish imported review archive entry");
        }
    }
    Ok(digest)
}

/// The imported review archive directory, which must be a real directory.
pub fn imported_reviews_dir(
    root: &std::path::Path,
    create: bool,
) -> anyhow::Result<std::path::PathBuf> {
    let state = root.join(".vee");
    if create && !state.exists() {
        std::fs::create_dir(&state).context("could not create .vee state directory")?;
    }
    let state_meta =
        std::fs::symlink_metadata(&state).context(".vee state directory is missing")?;
    anyhow::ensure!(
        state_meta.is_dir() && !state_meta.file_type().is_symlink(),
        ".vee must be a real directory"
    );
    let archive = state.join("imports");
    if create && !archive.exists() {
        std::fs::create_dir(&archive).context("could not create imported review archive")?;
    }
    let archive_meta =
        std::fs::symlink_metadata(&archive).context("imported review archive is missing")?;
    anyhow::ensure!(
        archive_meta.is_dir() && !archive_meta.file_type().is_symlink(),
        "import archive must be a real directory"
    );
    Ok(archive)
}

/// One archived entry: a portable Vee review or a provider discussion export.
pub enum ImportedArchive {
    Review(Box<crate::ReviewResult>),
    Discussions(vee_hosting::PullRequestReviewIssues),
}

/// Parse an archive entry by its schema version, validating that it stays gate-ineligible.
pub fn parse_imported_archive(bytes: &[u8]) -> anyhow::Result<ImportedArchive> {
    let payload: serde_json::Value =
        serde_json::from_slice(bytes).context("imported archive is not valid JSON")?;
    match payload
        .get("schema_version")
        .and_then(serde_json::Value::as_u64)
    {
        Some(2) => Ok(ImportedArchive::Review(Box::new(parse_portable_review(
            bytes,
        )?))),
        Some(1) => {
            let discussion: vee_hosting::PullRequestReviewIssues =
                serde_json::from_slice(bytes).context("invalid provider discussion archive")?;
            anyhow::ensure!(
                !discussion.gate_eligible,
                "provider discussion archive must remain gate-ineligible"
            );
            discussion
                .pull_request
                .validate()
                .map_err(anyhow::Error::msg)?;
            anyhow::ensure!(
                discussion
                    .issues
                    .iter()
                    .all(|issue| issue.classification == "untrusted_external_review"),
                "provider discussion archive contains an unsupported issue classification"
            );
            Ok(ImportedArchive::Discussions(discussion))
        }
        _ => anyhow::bail!("unsupported imported archive schema"),
    }
}

/// The result of `vee reviews import`: the archived review and its trust level.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ImportedReview {
    pub schema_version: u32,
    pub archive_digest: String,
    pub review_id: String,
    pub snapshot_id: String,
    pub status: String,
    pub trust: String,
    pub gate_eligible: bool,
}

/// `vee reviews import`: archive a portable review file as untrusted history.
pub fn import_review_archive(root: &Path, source: &Path) -> anyhow::Result<ImportedReview> {
    use std::io::Read;
    let source_metadata = std::fs::symlink_metadata(source)
        .with_context(|| format!("could not inspect import file {}", source.display()))?;
    anyhow::ensure!(
        source_metadata.file_type().is_file(),
        "import path must be a regular, non-symlink file"
    );
    #[cfg(unix)]
    let file = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(source)
    };
    #[cfg(not(unix))]
    let file = std::fs::File::open(source);
    let file =
        file.with_context(|| format!("could not inspect import file {}", source.display()))?;
    let metadata = file
        .metadata()
        .context("could not inspect opened import file")?;
    anyhow::ensure!(metadata.is_file(), "import path must be a regular file");
    anyhow::ensure!(
        metadata.len() <= MAX_IMPORTED_REVIEW_BYTES,
        "import file exceeds 10 MiB limit"
    );
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_IMPORTED_REVIEW_BYTES + 1)
        .read_to_end(&mut bytes)
        .context("could not read import file")?;
    anyhow::ensure!(
        bytes.len() as u64 <= MAX_IMPORTED_REVIEW_BYTES,
        "import file exceeds 10 MiB limit"
    );
    let review = parse_portable_review(&bytes)?;
    let archive_digest = store_imported_history(root, &bytes)?;
    Ok(ImportedReview {
        schema_version: 1,
        archive_digest,
        review_id: review.review_id,
        snapshot_id: review.snapshot_id,
        status: review.status,
        trust: UNTRUSTED_EXTERNAL.to_owned(),
        gate_eligible: false,
    })
}

/// The result of `vee reviews imported list`, ordered by archive digest.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ImportedArchiveList {
    pub schema_version: u32,
    pub reviews: Vec<ImportedArchiveEntry>,
}

/// One archive entry's identity; never gate eligible.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "archive_type", rename_all = "snake_case")]
pub enum ImportedArchiveEntry {
    Review {
        archive_digest: String,
        review_id: String,
        snapshot_id: String,
        status: String,
        trust: String,
        gate_eligible: bool,
    },
    ProviderDiscussions {
        archive_digest: String,
        provider: String,
        pull_request: vee_hosting::PullRequestRef,
        revision: String,
        complete: bool,
        issue_count: usize,
        trust: String,
        gate_eligible: bool,
    },
}

impl ImportedArchiveEntry {
    pub fn archive_digest(&self) -> &str {
        match self {
            Self::Review { archive_digest, .. }
            | Self::ProviderDiscussions { archive_digest, .. } => archive_digest,
        }
    }
}

/// `vee reviews imported list`: every intact archive entry. Entries that are
/// oversized, unparsable or not named by their content digest are skipped.
pub fn list_imported_archives(root: &Path) -> anyhow::Result<ImportedArchiveList> {
    let archive = imported_reviews_dir(root, true)?;
    let mut reviews = Vec::new();
    for entry in std::fs::read_dir(&archive)? {
        let entry = entry?;
        if entry.path().extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let metadata = entry.metadata()?;
        if !metadata.is_file() || metadata.len() > MAX_IMPORTED_REVIEW_BYTES {
            continue;
        }
        let bytes = std::fs::read(entry.path())?;
        let Ok(imported) = parse_imported_archive(&bytes) else {
            continue;
        };
        let hash = hex_digest(&Sha256::digest(&bytes));
        if entry.file_name().to_string_lossy() != format!("{hash}.json") {
            continue;
        }
        let archive_digest = format!("sha256:{hash}");
        reviews.push(match imported {
            ImportedArchive::Review(review) => ImportedArchiveEntry::Review {
                archive_digest,
                review_id: review.review_id,
                snapshot_id: review.snapshot_id,
                status: review.status,
                trust: UNTRUSTED_EXTERNAL.to_owned(),
                gate_eligible: false,
            },
            ImportedArchive::Discussions(discussion) => ImportedArchiveEntry::ProviderDiscussions {
                archive_digest,
                provider: discussion.provider,
                pull_request: discussion.pull_request,
                revision: discussion.revision,
                complete: discussion.complete,
                issue_count: discussion.issues.len(),
                trust: UNTRUSTED_EXTERNAL.to_owned(),
                gate_eligible: false,
            },
        });
    }
    reviews.sort_by(|left, right| left.archive_digest().cmp(right.archive_digest()));
    Ok(ImportedArchiveList {
        schema_version: 1,
        reviews,
    })
}

/// `vee reviews imported show`: one integrity-checked archive entry as stored,
/// annotated with its archive type and untrusted, gate-ineligible status.
pub fn show_imported_archive(root: &Path, digest: &str) -> anyhow::Result<serde_json::Value> {
    let archive = imported_reviews_dir(root, false)?;
    let raw_digest = digest.strip_prefix("sha256:").unwrap_or(digest);
    anyhow::ensure!(
        raw_digest.len() == 64 && raw_digest.bytes().all(|b| b.is_ascii_hexdigit()),
        "digest must be a SHA-256 hex digest"
    );
    let normalized_digest = raw_digest.to_ascii_lowercase();
    let path = archive.join(format!("{normalized_digest}.json"));
    let metadata = std::fs::metadata(&path).context("imported review not found")?;
    anyhow::ensure!(
        metadata.is_file() && metadata.len() <= MAX_IMPORTED_REVIEW_BYTES,
        "invalid imported review archive entry"
    );
    let bytes = std::fs::read(&path)?;
    anyhow::ensure!(
        hex_digest(&Sha256::digest(&bytes)) == normalized_digest,
        "imported archive entry failed integrity check"
    );
    let (mut value, archive_type) = match parse_imported_archive(&bytes)? {
        ImportedArchive::Review(review) => (serde_json::to_value(review)?, "review"),
        ImportedArchive::Discussions(discussion) => {
            (serde_json::to_value(discussion)?, "provider_discussions")
        }
    };
    value["archive_type"] = serde_json::json!(archive_type);
    value["trust"] = serde_json::json!(UNTRUSTED_EXTERNAL);
    value["gate_eligible"] = serde_json::json!(false);
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn searches_archived_provider_discussions_as_non_gating_context() {
        let root = tempfile::tempdir().unwrap();
        let report = vee_hosting::PullRequestReviewIssues {
            schema_version: 1,
            provider: "github".into(),
            pull_request: vee_hosting::PullRequestRef {
                repository: vee_hosting::RepositoryRef {
                    host: "github.com".into(),
                    full_name: "acme/service".into(),
                },
                number: 42,
            },
            revision: "abc123".into(),
            complete: true,
            gate_eligible: false,
            issues: vec![vee_hosting::PullRequestReviewIssue {
                external_id: "comment-7".into(),
                author: Some("reviewer".into()),
                body: "Handle the null response before parsing".into(),
                path: Some("src/api.rs".into()),
                line: Some(18),
                side: None,
                source_url: Some("https://example.test/comment/7".into()),
                created_at: None,
                updated_at: None,
                classification: "review_comment".into(),
            }],
        };
        let bytes = serde_json::to_vec(&report).unwrap();
        super::store_imported_history(root.path(), &bytes).unwrap();

        let result =
            serde_json::to_value(search(root.path(), "null response", 10).unwrap()).unwrap();
        assert_eq!(result["matches"][0]["provider"], "github");
        assert_eq!(result["matches"][0]["revision"], "abc123");
        assert_eq!(result["matches"][0]["issue"]["external_id"], "comment-7");
        assert_eq!(result["matches"][0]["trust"], "untrusted_external");
        assert_eq!(result["matches"][0]["gate_eligible"], false);
        let schema: Value = serde_json::from_str(include_str!(
            "../../../schemas/imported-review-search-v3.schema.json"
        ))
        .unwrap();
        assert!(jsonschema::validator_for(&schema)
            .unwrap()
            .is_valid(&result));
    }

    #[test]
    fn external_comment_feedback_is_append_only_idempotent_and_archive_bound() {
        let root = tempfile::tempdir().unwrap();
        let discussion = vee_hosting::PullRequestReviewIssues {
            schema_version: 1,
            provider: "github".into(),
            pull_request: vee_hosting::PullRequestRef {
                repository: vee_hosting::RepositoryRef {
                    host: "github.com".into(),
                    full_name: "acme/service".into(),
                },
                number: 42,
            },
            revision: "abc123".into(),
            complete: true,
            gate_eligible: false,
            issues: vec![vee_hosting::PullRequestReviewIssue {
                external_id: "comment-7".into(),
                author: Some("reviewer".into()),
                body: "False positive for generated files".into(),
                path: Some("src/api.rs".into()),
                line: Some(18),
                side: None,
                source_url: None,
                created_at: None,
                updated_at: None,
                classification: "review_comment".into(),
            }],
        };
        let bytes = serde_json::to_vec(&discussion).unwrap();
        let digest = super::store_imported_history(root.path(), &bytes).unwrap();
        let first = record_feedback(
            root.path(),
            FeedbackRecordInput {
                archive_digest: &digest,
                external_id: "comment-7",
                category: "correctness",
                label: FindingFeedbackLabel::FalsePositive,
                reason: "The path is generated and excluded by policy",
                reviewer: "maintainer",
                recorded_at_unix: 100,
            },
        )
        .unwrap();
        let repeated = record_feedback(
            root.path(),
            FeedbackRecordInput {
                archive_digest: &digest,
                external_id: "comment-7",
                category: "correctness",
                label: FindingFeedbackLabel::FalsePositive,
                reason: "The path is generated and excluded by policy",
                reviewer: "maintainer",
                recorded_at_unix: 100,
            },
        )
        .unwrap();
        assert_eq!(first.feedback_id, repeated.feedback_id);
        let conflicting = record_feedback(
            root.path(),
            FeedbackRecordInput {
                archive_digest: &digest,
                external_id: "comment-7",
                category: "correctness",
                label: FindingFeedbackLabel::Confirmed,
                reason: "The issue reproduces in the current implementation",
                reviewer: "maintainer",
                recorded_at_unix: 101,
            },
        )
        .unwrap();
        let records = list_feedback(root.path(), Some(&digest)).unwrap();
        assert_eq!(records.len(), 2);
        assert_ne!(first.feedback_id, conflicting.feedback_id);
        assert!(record_feedback(
            root.path(),
            FeedbackRecordInput {
                archive_digest: &digest,
                external_id: "missing",
                category: "correctness",
                label: FindingFeedbackLabel::Actionable,
                reason: "Cannot find comment",
                reviewer: "maintainer",
                recorded_at_unix: 102,
            }
        )
        .is_err());
        let schema: Value = serde_json::from_str(include_str!(
            "../../../schemas/external-review-feedback-v1.schema.json"
        ))
        .unwrap();
        assert!(jsonschema::validator_for(&schema)
            .unwrap()
            .is_valid(&serde_json::to_value(first).unwrap()));
    }
}
