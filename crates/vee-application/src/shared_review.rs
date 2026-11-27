//! Review once, reuse in CI (ADR 0043).
//!
//! `vee reviews share` signs a saved local review of committed changes with
//! an Ed25519 key and stores it as a Git note on the reviewed head, under
//! [`NOTES_REF`]. On a pull request whose head has such a note, `vee ci run`
//! verifies it with the keys `review_signers` lists in the base branch's
//! `.vee.yaml`, and hands the review to the incremental review as the earlier
//! one. Carrying then decides what is reused: only files whose base and head
//! content are the same, and only under the same effective configuration and
//! standards. Anything else is reviewed again. CI still runs its own required
//! verifications and evaluates the gate itself.

use crate::failure::usage_failure;
use crate::operations::Workspace;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::Path;

pub const PREDICATE_TYPE: &str = "https://vee.klarlabs.de/attestations/shared-review/v1";
/// Where shared reviews are kept, one note per reviewed head.
pub const NOTES_REF: &str = "refs/notes/vee-reviews";
/// The largest signed review CI reads.
const MAX_SHARED_REVIEW_BYTES: usize = 4 * 1024 * 1024;

/// `shared-review-v1`: a review signed and stored for CI to reuse.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SharedReview {
    pub schema_version: u32,
    pub review_id: String,
    pub base_oid: String,
    pub head_oid: String,
    pub key_id: String,
    pub notes_ref: String,
    /// How to make the note available to CI.
    pub push_command: String,
}

/// A signed review CI reused, as its output reports it.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReusedReview {
    /// The local review that was signed.
    pub review_id: String,
    /// The `review_signers` entry whose key verified the signature.
    pub signer: String,
    /// Changed files whose findings were reused rather than reviewed again.
    pub reused_files: usize,
}

fn git(root: &Path, args: &[&str]) -> Result<String> {
    crate::steward::git(root, args)
}

/// `vee reviews share`: sign a saved review of committed changes and store
/// it as a Git note on its head.
pub fn share(
    workspace: &Workspace,
    review_id: &str,
    private_key: &Path,
    key_id: &str,
) -> Result<SharedReview> {
    if key_id.trim().is_empty() {
        return Err(usage_failure("--key-id cannot be empty"));
    }
    let root = workspace.root();
    let store = workspace.store()?;
    let payload = store
        .get(review_id)
        .map_err(anyhow::Error::msg)?
        .ok_or_else(|| usage_failure(format!("review {review_id} was not found")))?;
    let review = crate::deserialize_review_result(&payload).map_err(anyhow::Error::msg)?;
    if review.gate.status == vee_core::GateStatus::Incomplete || !review.analysis_complete {
        return Err(usage_failure(
            "the review is incomplete; share a complete review",
        ));
    }
    let change_set = &review.change_set;
    let (Some(base_oid), Some(head_oid)) =
        (change_set.base_oid.clone(), change_set.head_oid.clone())
    else {
        return Err(usage_failure(
            "share a review of committed changes, made with --base or --commit",
        ));
    };
    if crate::attestation::attested_commit(root, change_set)?.as_deref() != Some(head_oid.as_str())
    {
        return Err(usage_failure(
            "the review covers uncommitted changes; commit them, review again with --base, and share that review",
        ));
    }
    let files = crate::incremental::reviewed_files(root, change_set).map_err(anyhow::Error::msg)?;
    let findings = review
        .policy_findings
        .clone()
        .unwrap_or_else(|| review.findings.clone());
    let statement = json!({
        "_type": crate::attestation::STATEMENT_TYPE,
        "subject": [{ "name": format!("git-commit:{head_oid}"), "digest": { "gitCommit": head_oid } }],
        "predicateType": PREDICATE_TYPE,
        "predicate": {
            "verifier": { "id": "https://vee.klarlabs.de/vee", "version": env!("CARGO_PKG_VERSION") },
            "review_id": review.review_id,
            "snapshot_id": review.snapshot_id,
            "base_oid": base_oid,
            "head_oid": head_oid,
            "config_digest": review.effective_config_digest,
            "standards_digest": review.standards_digest,
            "files": files,
            "findings": findings,
        }
    });
    let key = crate::signing::load_private_key(private_key)?;
    let envelope = crate::attestation::sign(&statement, &key, key_id)?;
    let bytes = serde_json::to_vec(&envelope)?;
    if bytes.len() > MAX_SHARED_REVIEW_BYTES {
        return Err(usage_failure(format!(
            "the signed review is over {} MiB, more than CI reads",
            MAX_SHARED_REVIEW_BYTES / 1024 / 1024
        )));
    }
    let file = tempfile::NamedTempFile::new().context("creating the note file")?;
    std::fs::write(file.path(), &bytes).context("writing the note file")?;
    let file_path = file.path().to_string_lossy().into_owned();
    let mut args: Vec<&str> = Vec::new();
    // Git records who wrote a note. The signature, not that name, is what CI
    // trusts, so a machine without a Git identity uses a neutral one.
    if git(root, &["var", "GIT_COMMITTER_IDENT"]).is_err() {
        args.extend([
            "-c",
            "user.name=Vee",
            "-c",
            "user.email=vee@localhost.invalid",
        ]);
    }
    args.extend([
        "notes", "--ref", NOTES_REF, "add", "--force", "--file", &file_path, &head_oid,
    ]);
    git(root, &args)?;
    Ok(SharedReview {
        schema_version: 1,
        review_id: review.review_id,
        base_oid,
        head_oid,
        key_id: key_id.to_owned(),
        notes_ref: NOTES_REF.to_owned(),
        push_command: format!("git push origin {NOTES_REF}"),
    })
}

/// The review signers the base commit's `.vee.yaml` lists. A base without
/// the file, or whose file does not parse, lists none.
fn base_signers(root: &Path, base_oid: &str) -> Vec<vee_core::ReviewSigner> {
    let Ok(text) = git(root, &["show", &format!("{base_oid}:.vee.yaml")]) else {
        return Vec::new();
    };
    serde_yaml::from_str::<vee_core::RepositoryConfig>(&text)
        .map(|config| config.review_signers)
        .unwrap_or_default()
}

/// Fetch the shared reviews from `origin`, quietly: a remote without them
/// is the common case.
fn fetch_notes(root: &Path) {
    let _ = git(
        root,
        &[
            "fetch",
            "--quiet",
            "--no-tags",
            "origin",
            &format!("+{NOTES_REF}:{NOTES_REF}"),
        ],
    );
}

/// Whether a signed review's base matches the pull request's: the same
/// commit, or the merge base of the pull request's base and head.
fn base_matches(root: &Path, signed_base: &str, base_oid: &str, head_oid: &str) -> bool {
    signed_base == base_oid
        || vee_git::merge_base_of(root, base_oid, head_oid).as_deref() == Some(signed_base)
}

/// Check a shared review's envelope against the trusted signers, for
/// `head_oid` reviewed from `base_oid`. Returns the signer's ID and the
/// record to carry.
pub(crate) fn verify_shared(
    root: &Path,
    envelope: &Value,
    signers: &[vee_core::ReviewSigner],
    repository: &str,
    number: u64,
    base_oid: &str,
    head_oid: &str,
) -> std::result::Result<(String, crate::incremental::ReviewRecord), String> {
    let (signer, statement) = signers
        .iter()
        .find_map(|signer| {
            let key = signer.key_bytes()?;
            crate::attestation::signed_statement(envelope, &key)
                .ok()
                .map(|(_, statement)| (signer.id.clone(), statement))
        })
        .ok_or("no key in the base branch's review_signers verifies its signature")?;
    if statement["predicateType"] != PREDICATE_TYPE {
        return Err(format!("the signed statement is not a {PREDICATE_TYPE}"));
    }
    let predicate = &statement["predicate"];
    let subject_commit = statement["subject"][0]["digest"]["gitCommit"].as_str();
    if subject_commit != Some(head_oid) || predicate["head_oid"].as_str() != Some(head_oid) {
        return Err("it was signed for another head".into());
    }
    let signed_base = predicate["base_oid"].as_str().unwrap_or_default();
    if !base_matches(root, signed_base, base_oid, head_oid) {
        return Err("it was reviewed from another base".into());
    }
    let field = |name: &str| -> std::result::Result<String, String> {
        predicate[name]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| format!("the signed review has no {name}"))
    };
    let record = crate::incremental::ReviewRecord {
        schema_version: 1,
        repository: repository.to_owned(),
        number,
        head_oid: head_oid.to_owned(),
        review_id: field("review_id")?,
        config_digest: field("config_digest")?,
        standards_digest: predicate["standards_digest"].as_str().map(str::to_owned),
        files: serde_json::from_value(predicate["files"].clone())
            .map_err(|error| format!("the signed review's files do not read: {error}"))?,
        findings: serde_json::from_value(predicate["findings"].clone())
            .map_err(|error| format!("the signed review's findings do not read: {error}"))?,
        approvals: Vec::new(),
    };
    Ok((signer, record))
}

/// The shared review of `head_oid` CI may reuse, if one is stored and a
/// signer the base branch trusts signed it. `Ok(None)` when the base lists
/// no signers or the head has no note; `Err` says why a note was refused.
pub(crate) fn reusable(
    root: &Path,
    repository: &str,
    number: u64,
    base_oid: &str,
    head_oid: &str,
) -> std::result::Result<Option<(String, crate::incremental::ReviewRecord)>, String> {
    let signers = base_signers(root, base_oid);
    if signers.is_empty() {
        return Ok(None);
    }
    fetch_notes(root);
    let Ok(note) = git(root, &["notes", "--ref", NOTES_REF, "show", head_oid]) else {
        return Ok(None);
    };
    if note.len() > MAX_SHARED_REVIEW_BYTES {
        return Err("the signed review is too large".into());
    }
    let envelope: Value =
        serde_json::from_str(&note).map_err(|_| "the note is not a signed review".to_owned())?;
    verify_shared(
        root,
        &envelope,
        signers.as_slice(),
        repository,
        number,
        base_oid,
        head_oid,
    )
    .map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    fn key() -> (ring::signature::Ed25519KeyPair, String) {
        let rng = ring::rand::SystemRandom::new();
        let document = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let pair = ring::signature::Ed25519KeyPair::from_pkcs8(document.as_ref()).unwrap();
        let public = base64::engine::general_purpose::STANDARD
            .encode(ring::signature::KeyPair::public_key(&pair).as_ref());
        (pair, public)
    }

    fn statement(head: &str, base: &str) -> Value {
        json!({
            "_type": crate::attestation::STATEMENT_TYPE,
            "subject": [{ "name": format!("git-commit:{head}"), "digest": { "gitCommit": head } }],
            "predicateType": PREDICATE_TYPE,
            "predicate": {
                "review_id": "rev_local", "base_oid": base, "head_oid": head,
                "config_digest": "sha256:config", "standards_digest": null,
                "files": {}, "findings": [],
            }
        })
    }

    #[test]
    fn only_a_trusted_signature_for_the_same_head_and_base_is_reused() {
        let root = tempfile::tempdir().unwrap();
        let (pair, public) = key();
        let (_, other_public) = key();
        let trusted = vec![vee_core::ReviewSigner {
            id: "alice".into(),
            public_key: public,
        }];
        let untrusted = vec![vee_core::ReviewSigner {
            id: "bob".into(),
            public_key: other_public,
        }];
        let (head, base) = ("h".repeat(40), "b".repeat(40));
        let envelope = crate::attestation::sign(&statement(&head, &base), &pair, "laptop").unwrap();

        let (signer, record) = verify_shared(
            root.path(),
            &envelope,
            &trusted,
            "team/repo",
            9,
            &base,
            &head,
        )
        .unwrap();
        assert_eq!(signer, "alice");
        assert_eq!((record.review_id.as_str(), record.number), ("rev_local", 9));

        let refused = |signers: &[vee_core::ReviewSigner], base: &str, head: &str| {
            verify_shared(root.path(), &envelope, signers, "team/repo", 9, base, head).unwrap_err()
        };
        assert!(refused(&untrusted, &base, &head).contains("verifies its signature"));
        assert!(refused(&trusted, &base, &"c".repeat(40)).contains("another head"));
        assert!(refused(&trusted, &"d".repeat(40), &head).contains("another base"));

        // A gate attestation signed by the same key is not a shared review.
        let mut gate = statement(&head, &base);
        gate["predicateType"] = crate::attestation::PREDICATE_TYPE.into();
        let gate = crate::attestation::sign(&gate, &pair, "laptop").unwrap();
        assert!(
            verify_shared(root.path(), &gate, &trusted, "team/repo", 9, &base, &head)
                .unwrap_err()
                .contains("is not a")
        );
    }
}
