//! Supply-chain provenance: a saved review's gate decision as an in-toto
//! Statement v1, optionally signed in a DSSE envelope with an Ed25519 key.
//!
//! The statement's subjects are the reviewed Git commit (only when the reviewed
//! snapshot is exactly a commit's content) and Vee's snapshot digest. The
//! predicate (`https://vee.klarlabs.de/attestations/review-gate/v1`) records the gate
//! decision and what it was based on, and links to the evidence bundle by its
//! manifest digest, so the full evidence can be verified separately.

use crate::failure::usage_failure;
use crate::imported_history::MAX_IMPORTED_REVIEW_BYTES;
use crate::operations::Workspace;
use anyhow::{Context, Result};
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::Read;
use std::path::Path;
use vee_core::ChangeSet;

pub const STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";
pub const PREDICATE_TYPE: &str = "https://vee.klarlabs.de/attestations/review-gate/v1";
pub const PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";

/// Build the in-toto statement for `review` (whose `gate` is the selected decision).
/// `commit` is the commit whose content equals the reviewed snapshot, if any.
pub fn statement(
    review: &crate::ReviewResult,
    bundle_manifest_digest: &str,
    commit: Option<&str>,
) -> Result<Value> {
    let snapshot_hex = review
        .snapshot_id
        .strip_prefix("sha256:")
        .context("review snapshot ID is not a sha256 digest")?;
    let mut subjects = Vec::new();
    if let Some(commit) = commit {
        subjects.push(
            json!({ "name": format!("git-commit:{commit}"), "digest": { "gitCommit": commit } }),
        );
    }
    subjects.push(json!({ "name": format!("vee-snapshot:{}", review.snapshot_id), "digest": { "sha256": snapshot_hex } }));
    let gate = &review.gate;
    let inputs = gate.replay_inputs.as_ref();
    let time_verified = inputs
        .map(|inputs| rfc3339_utc(inputs.evaluation_time_unix))
        .transpose()?;
    let reviewers: Vec<Value> = review
        .reviewer_outcomes
        .iter()
        .map(|outcome| {
            json!({
                "reviewer_id": outcome.reviewer_id,
                "provider_kind": outcome.provider_kind,
                "model": outcome.model,
                "provider_version": outcome.provider_version,
                "status": outcome.status,
            })
        })
        .collect();
    let verifications: Vec<Value> = inputs
        .map(|inputs| {
            inputs
                .verification_runs
                .iter()
                .filter(|run| gate.verification_run_ids.contains(&run.run_id))
                .map(|run| {
                    json!({
                        "run_id": run.run_id,
                        "profile_id": run.profile_id,
                        "status": run.status,
                        "command_digest": run.command_digest,
                        "stdout_digest": run.stdout_digest,
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    let analyzers: Vec<Value> = inputs
        .map(|inputs| {
            inputs
                .analyzer_reports
                .iter()
                .map(|report| {
                    json!({
                        "profile_id": report.profile_id,
                        "run_id": report.run_id,
                        "tools": report.tools,
                        "results_on_changed_lines": report.findings.len(),
                        "blocking_findings": gate.blocking_findings.iter().filter(|id| report.findings.iter().any(|finding| finding.id == **id)).collect::<Vec<_>>(),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    let change_set = &review.change_set;
    Ok(json!({
        "_type": STATEMENT_TYPE,
        "subject": subjects,
        "predicateType": PREDICATE_TYPE,
        "predicate": {
            "verifier": { "id": "https://vee.klarlabs.de/vee", "version": env!("CARGO_PKG_VERSION") },
            "timeVerified": time_verified,
            "review": {
                "review_id": review.review_id,
                "snapshot_id": review.snapshot_id,
                "scope": change_set.scope,
                "base_oid": change_set.base_oid,
                "head_oid": change_set.head_oid,
                "changed_files": change_set.files.len(),
            },
            "decision": {
                "decision_id": gate.decision_id,
                "status": gate.status,
                "blocking_findings": gate.blocking_findings,
                "reasons": gate.reasons,
                "evidence_digest": gate.evidence_digest,
            },
            "policy": {
                "policy_digest": gate.policy_digest,
                "effective_config_digest": gate.effective_config_digest,
            },
            "reviewers": reviewers,
            "verifications": verifications,
            "analyzers": analyzers,
            "evidence_bundle": { "manifest_digest": bundle_manifest_digest },
        }
    }))
}

/// DSSE pre-authentication encoding: `DSSEv1 SP len(type) SP type SP len(body) SP body`.
pub fn pre_authentication_encoding(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut encoded = format!(
        "DSSEv1 {} {payload_type} {} ",
        payload_type.len(),
        payload.len()
    )
    .into_bytes();
    encoded.extend_from_slice(payload);
    encoded
}

/// Sign `statement` into a DSSE envelope with an Ed25519 key.
pub fn sign(
    statement: &Value,
    key: &ring::signature::Ed25519KeyPair,
    key_id: &str,
) -> Result<Value> {
    let payload = serde_json::to_vec(statement)?;
    let signature = key.sign(&pre_authentication_encoding(PAYLOAD_TYPE, &payload));
    let standard = base64::engine::general_purpose::STANDARD;
    Ok(json!({
        "payloadType": PAYLOAD_TYPE,
        "payload": standard.encode(&payload),
        "signatures": [{ "keyid": key_id, "sig": standard.encode(signature.as_ref()) }],
    }))
}

/// `attestation-verification-v1`: the result of `vee reviews verify-attestation`.
/// The verified details are present only when a signature verifies.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AttestationVerification {
    pub schema_version: u32,
    pub valid: bool,
    pub message: String,
    #[serde(flatten, default, skip_serializing_if = "Option::is_none")]
    pub verified: Option<VerifiedAttestation>,
}

/// What a verified attestation states, as signed.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerifiedAttestation {
    pub key_id: String,
    /// The statement's in-toto subjects, as signed.
    pub subjects: Value,
    pub gate_status: Value,
    pub decision_id: Value,
    /// The full in-toto statement.
    pub statement: Value,
}

impl AttestationVerification {
    fn invalid(message: String) -> Self {
        Self {
            schema_version: 1,
            valid: false,
            message,
            verified: None,
        }
    }
}

/// Verify a DSSE envelope with a raw 32-byte Ed25519 public key. The statement
/// is returned only when a signature verifies.
pub fn verify(envelope: &Value, public_key: &[u8]) -> AttestationVerification {
    let invalid = AttestationVerification::invalid;
    let standard = base64::engine::general_purpose::STANDARD;
    if envelope["payloadType"].as_str() != Some(PAYLOAD_TYPE) {
        return invalid(format!("payloadType must be {PAYLOAD_TYPE}"));
    }
    let Some(payload) = envelope["payload"]
        .as_str()
        .and_then(|payload| standard.decode(payload).ok())
    else {
        return invalid("payload is not base64".into());
    };
    let signatures = envelope["signatures"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    if signatures.is_empty() {
        return invalid("envelope has no signatures".into());
    }
    let verifier = ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, public_key);
    let message = pre_authentication_encoding(PAYLOAD_TYPE, &payload);
    let key_id = signatures.iter().find_map(|signature| {
        let bytes = signature["sig"]
            .as_str()
            .and_then(|sig| standard.decode(sig).ok())?;
        verifier
            .verify(&message, &bytes)
            .ok()
            .map(|()| signature["keyid"].as_str().unwrap_or_default().to_owned())
    });
    let Some(key_id) = key_id else {
        return invalid("no signature verifies with the supplied public key".into());
    };
    let Ok(statement) = serde_json::from_slice::<Value>(&payload) else {
        return invalid("signed payload is not JSON".into());
    };
    if statement["_type"] != STATEMENT_TYPE || statement["predicateType"] != PREDICATE_TYPE {
        return invalid(format!(
            "signed payload is not a {STATEMENT_TYPE} with predicate {PREDICATE_TYPE}"
        ));
    }
    AttestationVerification {
        schema_version: 1,
        valid: true,
        message: "signature verified; trust in the signer is determined by the supplied public key"
            .into(),
        verified: Some(VerifiedAttestation {
            key_id,
            subjects: statement["subject"].clone(),
            gate_status: statement["predicate"]["decision"]["status"].clone(),
            decision_id: statement["predicate"]["decision"]["decision_id"].clone(),
            statement,
        }),
    }
}

/// `vee reviews verify-attestation`: verify the DSSE envelope file at `path`
/// with the raw Ed25519 public key file at `public_key`.
pub fn verify_file(path: &Path, public_key: &Path) -> Result<AttestationVerification> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("opening attestation {}", path.display()))?;
    let mut bytes = Vec::new();
    file.take(MAX_IMPORTED_REVIEW_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("reading attestation {}", path.display()))?;
    anyhow::ensure!(
        bytes.len() as u64 <= MAX_IMPORTED_REVIEW_BYTES,
        "attestation exceeds 10 MiB"
    );
    let envelope: Value = serde_json::from_slice(&bytes)
        .map_err(|_| usage_failure("attestation is not valid JSON"))?;
    let key = std::fs::read(public_key)
        .with_context(|| format!("reading public key {}", public_key.display()))?;
    Ok(verify(&envelope, &key))
}

/// How `vee reviews attest` packages the statement.
pub enum AttestationFormat<'a> {
    /// The unsigned in-toto Statement, for signing with external tools.
    Statement,
    /// An Ed25519-signed DSSE envelope.
    Dsse {
        private_key: &'a Path,
        key_id: &'a str,
    },
}

/// `vee reviews attest`: the in-toto statement (or signed DSSE envelope) for a
/// saved review's selected gate decision.
pub fn attest(
    workspace: &Workspace,
    review_id: &str,
    decision_id: Option<&str>,
    format: AttestationFormat<'_>,
) -> Result<Value> {
    let store = workspace.store()?;
    let review =
        crate::evidence_bundle::review_with_decision(store.as_ref(), review_id, decision_id)?;
    let bundle = crate::evidence_bundle::bundle(&review)?;
    let commit = attested_commit(workspace.root(), &review.change_set)?;
    let statement = statement(&review, &bundle.manifest_digest, commit.as_deref())?;
    match format {
        AttestationFormat::Statement => Ok(statement),
        AttestationFormat::Dsse {
            private_key,
            key_id,
        } => {
            if key_id.trim().is_empty() {
                return Err(usage_failure("--key-id cannot be empty"));
            }
            let key = crate::signing::load_private_key(private_key)?;
            sign(&statement, &key, key_id)
        }
    }
}

/// The commit an attestation can name as its subject: only when the reviewed
/// snapshot is exactly that commit's change, so a verifier binding the
/// attestation to a revision attests what was actually reviewed.
pub fn attested_commit(root: &Path, change_set: &ChangeSet) -> Result<Option<String>> {
    Ok(match change_set.scope.as_str() {
        scope if scope.starts_with("commit:") || scope.starts_with("commit_range:") => {
            change_set.head_oid.clone()
        }
        "base_and_worktree" => committed_snapshot_matches_review(root, change_set)
            .map_err(anyhow::Error::msg)?
            .then(|| change_set.head_oid.clone())
            .flatten(),
        _ => None,
    })
}

/// Whether a base-and-worktree review's content is exactly the committed range
/// from its captured base to its captured head.
pub fn committed_snapshot_matches_review(
    root: &Path,
    reviewed: &ChangeSet,
) -> Result<bool, String> {
    let base_oid = reviewed
        .base_oid
        .as_deref()
        .ok_or("base-and-worktree review is missing its captured base OID")?;
    let head_oid = reviewed
        .head_oid
        .as_deref()
        .ok_or("base-and-worktree review is missing its captured head OID")?;
    let committed = crate::capture_change_set(
        root,
        vee_git::ChangeScope::CommitRange {
            from: base_oid.to_owned(),
            to: head_oid.to_owned(),
        },
    )?;
    let normalize_mode = |mode: u32| {
        if mode & 0o170000 == 0o100000 {
            mode & 0o777
        } else {
            mode
        }
    };
    Ok(reviewed.files.len() == committed.files.len()
        && reviewed
            .files
            .iter()
            .zip(&committed.files)
            .all(|(left, right)| {
                left.path == right.path
                    && normalize_mode(left.mode) == normalize_mode(right.mode)
                    && left.content_digest == right.content_digest
                    && left.status == right.status
            }))
}

/// Format Unix seconds as an RFC 3339 UTC timestamp.
pub fn rfc3339_utc(unix: i64) -> Result<String> {
    anyhow::ensure!(
        (0..=253_402_300_799).contains(&unix),
        "timestamp {unix} is outside 1970..=9999"
    );
    let days = unix.div_euclid(86_400);
    let seconds = unix.rem_euclid(86_400);
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    Ok(format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        seconds / 3_600,
        seconds % 3_600 / 60,
        seconds % 60
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_formats_known_instants() {
        assert_eq!(rfc3339_utc(0).unwrap(), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339_utc(951_782_400).unwrap(), "2000-02-29T00:00:00Z");
        assert_eq!(rfc3339_utc(1_794_945_881).unwrap(), "2026-11-17T20:04:41Z");
        assert_eq!(
            rfc3339_utc(253_402_300_799).unwrap(),
            "9999-12-31T23:59:59Z"
        );
        assert!(rfc3339_utc(-1).is_err());
    }

    #[test]
    fn pae_matches_the_dsse_specification_example() {
        // From the DSSE protocol specification.
        assert_eq!(
            pre_authentication_encoding("http://example.com/HelloWorld", b"hello world"),
            b"DSSEv1 29 http://example.com/HelloWorld 11 hello world".to_vec()
        );
    }

    #[test]
    fn envelopes_verify_only_with_the_signing_key_and_untampered_payload() {
        let rng = ring::rand::SystemRandom::new();
        let generate = || {
            let document = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
            ring::signature::Ed25519KeyPair::from_pkcs8(document.as_ref()).unwrap()
        };
        let (key, other) = (generate(), generate());
        let public = ring::signature::KeyPair::public_key(&key).as_ref().to_vec();
        let statement = json!({"_type": STATEMENT_TYPE, "predicateType": PREDICATE_TYPE, "subject": [], "predicate": {"decision": {"status": "pass", "decision_id": "d"}}});

        let envelope = sign(&statement, &key, "team-key").unwrap();
        let report = verify(&envelope, &public);
        assert!(report.valid, "{report:?}");
        let verified = report.verified.unwrap();
        assert_eq!(verified.key_id, "team-key");
        assert_eq!(verified.gate_status, "pass");

        let wrong_key = sign(&statement, &other, "other").unwrap();
        assert!(!verify(&wrong_key, &public).valid);

        let mut tampered = envelope.clone();
        let mut altered = statement.clone();
        altered["predicate"]["decision"]["status"] = json!("block");
        tampered["payload"] =
            json!(base64::engine::general_purpose::STANDARD
                .encode(serde_json::to_vec(&altered).unwrap()));
        assert!(!verify(&tampered, &public).valid);
    }
}
