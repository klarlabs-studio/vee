//! SQLite adapter for Vero's local review store: reviews, findings, evidence,
//! gate decisions, waivers, verification runs, rule approvals, provider cache,
//! and hosted-provider delivery state, in `.vero/vero.sqlite`.

use rusqlite::OptionalExtension;
use std::path::Path;
use vero_core::ports::*;
use vero_core::*;

pub struct ReviewStore {
    connection: rusqlite::Connection,
}

fn validate_snapshot_manifest(snapshot_id: &str, manifest_json: &str) -> Result<(), String> {
    if manifest_json == "{}" {
        return Ok(());
    }
    let (schema_version, base_oid, head_oid, scope, files): (
        u32,
        Option<String>,
        Option<String>,
        String,
        Vec<SnapshotFile>,
    ) = serde_json::from_str(manifest_json)
        .map_err(|error| format!("invalid snapshot manifest: {error}"))?;
    let canonical = serde_json::to_vec(&(
        schema_version,
        base_oid.as_deref(),
        head_oid.as_deref(),
        scope.as_str(),
        &files,
    ))
    .map_err(|error| error.to_string())?;
    if digest(&canonical) != snapshot_id {
        return Err("snapshot manifest does not match its content digest".into());
    }
    Ok(())
}

const STORAGE_SCHEMA_VERSION: u32 = 13;

fn migrate_storage(connection: &mut rusqlite::Connection) -> Result<(), String> {
    use rusqlite::TransactionBehavior;

    connection
        .execute_batch("PRAGMA foreign_keys=ON")
        .map_err(|error| error.to_string())?;
    let mut version: u32 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|error| error.to_string())?;
    if version > STORAGE_SCHEMA_VERSION {
        return Err(format!(
            "database schema version {version} is newer than supported version {STORAGE_SCHEMA_VERSION}"
        ));
    }

    if version < 1 {
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        tx.execute_batch(
            "CREATE TABLE IF NOT EXISTS reviews (id TEXT PRIMARY KEY, snapshot_id TEXT NOT NULL, config_digest TEXT NOT NULL, status TEXT NOT NULL, payload TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
            CREATE TABLE IF NOT EXISTS findings (id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL UNIQUE, category TEXT NOT NULL, severity TEXT NOT NULL, confidence INTEGER, status TEXT NOT NULL CHECK(status IN ('open','verified','refuted','resolved','waived')), status_reason TEXT, finding_json TEXT NOT NULL, first_seen TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, last_seen TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
            CREATE TABLE IF NOT EXISTS finding_occurrences (review_id TEXT NOT NULL REFERENCES reviews(id) ON DELETE CASCADE, finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE, snapshot_id TEXT NOT NULL, finding_json TEXT NOT NULL, observed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, occurrence_order INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(review_id, finding_id));
            CREATE TABLE IF NOT EXISTS evidence (review_id TEXT NOT NULL REFERENCES reviews(id) ON DELETE CASCADE, evidence_id TEXT NOT NULL, payload TEXT NOT NULL, PRIMARY KEY(review_id,evidence_id));
            CREATE TABLE IF NOT EXISTS verification_runs (run_id TEXT PRIMARY KEY, snapshot_id TEXT NOT NULL, profile_id TEXT NOT NULL, command_digest TEXT NOT NULL, status TEXT NOT NULL, exit_code INTEGER, stdout_digest TEXT NOT NULL, stderr_digest TEXT NOT NULL, payload TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
            CREATE TABLE IF NOT EXISTS gate_decisions (decision_id TEXT NOT NULL, review_id TEXT NOT NULL REFERENCES reviews(id) ON DELETE CASCADE, snapshot_id TEXT NOT NULL, policy_digest TEXT NOT NULL, evidence_digest TEXT NOT NULL, status TEXT NOT NULL, payload TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY(review_id,decision_id));
            CREATE TABLE IF NOT EXISTS waivers (id TEXT PRIMARY KEY, finding_fingerprint TEXT NOT NULL, snapshot_id TEXT NOT NULL, reason TEXT NOT NULL, author TEXT NOT NULL, provenance TEXT NOT NULL, created_at_unix INTEGER NOT NULL, expires_at_unix INTEGER NOT NULL);
            CREATE INDEX IF NOT EXISTS idx_waivers_snapshot ON waivers(snapshot_id,expires_at_unix);
            CREATE INDEX IF NOT EXISTS idx_gate_decisions_review ON gate_decisions(review_id,created_at);
            CREATE INDEX IF NOT EXISTS idx_findings_severity_status ON findings(severity, status);
            CREATE INDEX IF NOT EXISTS idx_occurrences_finding ON finding_occurrences(finding_id, observed_at);",
        )
        .map_err(|error| error.to_string())?;
        tx.pragma_update(None, "user_version", 1u32)
            .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        version = 1;
    }

    if version < 2 {
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        let mut statement = tx
            .prepare("PRAGMA table_info(verification_runs)")
            .map_err(|error| error.to_string())?;
        let columns = statement
            .query_map([], |row| row.get::<_, String>(1))
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?;
        drop(statement);
        if !columns.iter().any(|column| column == "finding_id") {
            tx.execute(
                "ALTER TABLE verification_runs ADD COLUMN finding_id TEXT",
                [],
            )
            .map_err(|error| error.to_string())?;
        }
        tx.execute(
            "CREATE INDEX IF NOT EXISTS idx_verification_finding ON verification_runs(finding_id, snapshot_id, created_at)",
            [],
        )
        .map_err(|error| error.to_string())?;
        tx.pragma_update(None, "user_version", 2u32)
            .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        version = 2;
    }

    if version < 3 {
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        tx.execute(
            "ALTER TABLE gate_decisions ADD COLUMN effective_config_digest TEXT NOT NULL DEFAULT ''",
            [],
        )
        .map_err(|error| error.to_string())?;
        tx.execute(
            "UPDATE gate_decisions SET effective_config_digest=(SELECT config_digest FROM reviews WHERE reviews.id=gate_decisions.review_id)",
            [],
        )
        .map_err(|error| error.to_string())?;
        tx.pragma_update(None, "user_version", 3u32)
            .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        version = 3;
    }

    if version < 4 {
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        tx.execute_batch(
            "CREATE TABLE IF NOT EXISTS artifacts (digest TEXT PRIMARY KEY, path TEXT NOT NULL, size_bytes INTEGER NOT NULL CHECK(size_bytes >= 0));
            CREATE TABLE IF NOT EXISTS verification_artifacts (run_id TEXT NOT NULL REFERENCES verification_runs(run_id) ON DELETE CASCADE, stream TEXT NOT NULL CHECK(stream IN ('stdout','stderr')), digest TEXT NOT NULL REFERENCES artifacts(digest), PRIMARY KEY(run_id,stream));
            CREATE INDEX IF NOT EXISTS idx_verification_artifacts_digest ON verification_artifacts(digest);",
        )
        .map_err(|error| error.to_string())?;
        tx.pragma_update(None, "user_version", 4u32)
            .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        version = 4;
    }

    if version < 5 {
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        tx.execute_batch(
            "CREATE TABLE IF NOT EXISTS provider_cache (request_key TEXT PRIMARY KEY, provider_version TEXT NOT NULL, stdout_digest TEXT NOT NULL, stdout BLOB NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);",
        )
        .map_err(|error| error.to_string())?;
        tx.pragma_update(None, "user_version", 5u32)
            .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        version = 5;
    }

    if version < 6 {
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        tx.execute_batch(
            "CREATE TABLE IF NOT EXISTS snapshots (snapshot_id TEXT PRIMARY KEY, manifest_json TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
            CREATE TABLE IF NOT EXISTS evidence_records (evidence_id TEXT NOT NULL, review_id TEXT NOT NULL REFERENCES reviews(id) ON DELETE CASCADE, kind TEXT NOT NULL, provenance TEXT NOT NULL, source_path TEXT NOT NULL, content_digest TEXT NOT NULL, classification TEXT NOT NULL, verification TEXT NOT NULL, payload TEXT NOT NULL, PRIMARY KEY(review_id,evidence_id));
            CREATE INDEX IF NOT EXISTS idx_evidence_review ON evidence_records(review_id,evidence_id);",
        )
        .map_err(|error| error.to_string())?;
        let review_columns = {
            let mut statement = tx
                .prepare("PRAGMA table_info(reviews)")
                .map_err(|error| error.to_string())?;
            let columns = statement
                .query_map([], |row| row.get::<_, String>(1))
                .map_err(|error| error.to_string())?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| error.to_string())?;
            columns
        };
        if review_columns.iter().any(|column| column == "snapshot_id") {
            tx.execute(
                "INSERT OR IGNORE INTO snapshots(snapshot_id,manifest_json) SELECT DISTINCT snapshot_id,'{}' FROM reviews",
                [],
            )
            .map_err(|error| error.to_string())?;
            if review_columns.iter().any(|column| column == "payload") {
                let legacy_reviews = {
                    let mut statement = tx
                        .prepare("SELECT snapshot_id,payload FROM reviews")
                        .map_err(|error| error.to_string())?;
                    let rows = statement
                        .query_map([], |row| {
                            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                        })
                        .map_err(|error| error.to_string())?;
                    rows.collect::<Result<Vec<_>, _>>()
                        .map_err(|error| error.to_string())?
                };
                for (snapshot_id, payload) in legacy_reviews {
                    let Ok(value) = serde_json::from_str::<serde_json::Value>(&payload) else {
                        continue;
                    };
                    let Some(change_set_value) = value.get("change_set") else {
                        continue;
                    };
                    let Ok(change_set) =
                        serde_json::from_value::<ChangeSet>(change_set_value.clone())
                    else {
                        continue;
                    };
                    let manifest = serde_json::to_string(&(
                        change_set.schema_version,
                        change_set.base_oid.as_deref(),
                        change_set.head_oid.as_deref(),
                        change_set.scope.as_str(),
                        &change_set.files,
                    ))
                    .map_err(|error| error.to_string())?;
                    if validate_snapshot_manifest(&snapshot_id, &manifest).is_ok() {
                        tx.execute(
                            "UPDATE snapshots SET manifest_json=?1 WHERE snapshot_id=?2 AND manifest_json='{}'",
                            rusqlite::params![manifest, snapshot_id],
                        )
                        .map_err(|error| error.to_string())?;
                    }
                }
            }
        }
        let evidence_table_exists: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='evidence')",
                [],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        let legacy_evidence = if evidence_table_exists {
            let mut statement = tx
                .prepare("SELECT review_id,evidence_id,payload FROM evidence")
                .map_err(|error| error.to_string())?;
            let rows = statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                })
                .map_err(|error| error.to_string())?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(|error| error.to_string())?
        } else {
            Vec::new()
        };
        for (review_id, evidence_id, payload) in legacy_evidence {
            let evidence: Evidence = serde_json::from_str(&payload)
                .map_err(|error| format!("cannot migrate evidence {evidence_id}: {error}"))?;
            let kind = serde_json::to_value(evidence.kind)
                .map_err(|error| error.to_string())?
                .as_str()
                .unwrap_or("unknown")
                .to_string();
            let classification = serde_json::to_value(evidence.classification)
                .map_err(|error| error.to_string())?
                .as_str()
                .unwrap_or("unknown")
                .to_string();
            let verification = serde_json::to_value(evidence.verification)
                .map_err(|error| error.to_string())?
                .as_str()
                .unwrap_or("unknown")
                .to_string();
            tx.execute(
                "INSERT OR IGNORE INTO evidence_records(evidence_id,review_id,kind,provenance,source_path,content_digest,classification,verification,payload) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                rusqlite::params![evidence_id, review_id, kind, evidence.provenance, evidence.source_path, evidence.content_digest, classification, verification, payload],
            )
            .map_err(|error| error.to_string())?;
        }
        tx.pragma_update(None, "user_version", 6u32)
            .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
    }
    if version < 7 {
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        tx.execute_batch(
            "CREATE TABLE IF NOT EXISTS webhook_deliveries (
                provider TEXT NOT NULL,
                event_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                delivery_attempt INTEGER NOT NULL CHECK(delivery_attempt > 0),
                payload_digest TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN ('received','processing','processed')),
                lease_token TEXT,
                lease_expires_at_unix INTEGER NOT NULL DEFAULT 0,
                received_at_unix INTEGER NOT NULL,
                processed_at_unix INTEGER,
                PRIMARY KEY(provider,event_id)
            );
            CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_state ON webhook_deliveries(state,lease_expires_at_unix);",
        )
        .map_err(|error| error.to_string())?;
        tx.pragma_update(None, "user_version", 7u32)
            .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        version = 7;
    }
    if version < 8 {
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        tx.execute_batch(
            "CREATE TABLE IF NOT EXISTS finding_feedback (
                feedback_id TEXT PRIMARY KEY,
                finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
                snapshot_id TEXT NOT NULL,
                label TEXT NOT NULL CHECK(label IN ('confirmed','false_positive','actionable','not_actionable')),
                reason TEXT NOT NULL,
                reviewer TEXT NOT NULL,
                payload TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE INDEX IF NOT EXISTS idx_finding_feedback_finding ON finding_feedback(finding_id,created_at);
            CREATE INDEX IF NOT EXISTS idx_finding_feedback_snapshot ON finding_feedback(snapshot_id);",
        )
        .map_err(|error| error.to_string())?;
        tx.pragma_update(None, "user_version", 8u32)
            .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        version = 8;
    }
    if version < 9 {
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        tx.execute_batch(
            "CREATE TABLE IF NOT EXISTS rule_approvals (
                approval_id TEXT PRIMARY KEY,
                candidate_id TEXT NOT NULL,
                evidence_digest TEXT NOT NULL,
                payload TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS rule_approval_events (
                event_id TEXT PRIMARY KEY,
                approval_id TEXT NOT NULL REFERENCES rule_approvals(approval_id),
                event TEXT NOT NULL CHECK(event IN ('activated','revoked')),
                actor TEXT NOT NULL,
                reason TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE INDEX IF NOT EXISTS idx_rule_approval_events_approval ON rule_approval_events(approval_id,created_at,event_id);",
        )
        .map_err(|error| error.to_string())?;
        tx.pragma_update(None, "user_version", 9u32)
            .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        version = 9;
    }
    if version < 10 {
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        tx.execute_batch(
            "ALTER TABLE rule_approval_events RENAME TO rule_approval_events_v9;
            CREATE TABLE rule_approval_events (
                event_id TEXT PRIMARY KEY,
                approval_id TEXT NOT NULL REFERENCES rule_approvals(approval_id),
                event TEXT NOT NULL CHECK(event IN ('activated','revoked','superseded')),
                actor TEXT NOT NULL,
                reason TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            INSERT INTO rule_approval_events(event_id,approval_id,event,actor,reason,created_at)
                SELECT event_id,approval_id,event,actor,reason,created_at FROM rule_approval_events_v9;
            DROP TABLE rule_approval_events_v9;
            CREATE INDEX IF NOT EXISTS idx_rule_approval_events_approval ON rule_approval_events(approval_id,created_at,event_id);",
        )
        .map_err(|error| error.to_string())?;
        tx.pragma_update(None, "user_version", 10u32)
            .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
    }
    if version < 11 {
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        tx.execute_batch("CREATE TABLE IF NOT EXISTS finding_assessments (review_id TEXT NOT NULL REFERENCES reviews(id) ON DELETE CASCADE, finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE, snapshot_id TEXT NOT NULL, assessment_digest TEXT NOT NULL, finding_json TEXT NOT NULL, PRIMARY KEY(review_id,finding_id,assessment_digest)); CREATE INDEX IF NOT EXISTS idx_assessments_finding ON finding_assessments(finding_id,review_id);").map_err(|error| error.to_string())?;
        let has_occurrences: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='finding_occurrences')",
                [],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        let legacy_assessments = if has_occurrences {
            let mut statement = tx
                .prepare("SELECT review_id,finding_id,snapshot_id,finding_json FROM finding_occurrences ORDER BY review_id,finding_id")
                .map_err(|error| error.to_string())?;
            let rows = statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                })
                .map_err(|error| error.to_string())?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(|error| error.to_string())?
        } else {
            Vec::new()
        };
        for (review_id, finding_id, snapshot_id, finding_json) in legacy_assessments {
            let assessment_digest = digest(finding_json.as_bytes());
            tx.execute(
                "INSERT OR IGNORE INTO finding_assessments(review_id,finding_id,snapshot_id,assessment_digest,finding_json) VALUES (?1,?2,?3,?4,?5)",
                rusqlite::params![review_id,finding_id,snapshot_id,assessment_digest,finding_json],
            ).map_err(|error| error.to_string())?;
        }
        tx.pragma_update(None, "user_version", 11u32)
            .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
    }
    if version < 12 {
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        tx.execute_batch("CREATE TABLE IF NOT EXISTS hosted_finding_threads (target_key TEXT NOT NULL, fingerprint TEXT NOT NULL, PRIMARY KEY(target_key,fingerprint));")
            .map_err(|error| error.to_string())?;
        tx.pragma_update(None, "user_version", 12u32)
            .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
    }
    if version < 13 {
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        let has_occurrences: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='finding_occurrences')",
                [],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        if has_occurrences {
            let has_order: bool = tx
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM pragma_table_info('finding_occurrences') WHERE name='occurrence_order')",
                    [],
                    |row| row.get(0),
                )
                .map_err(|error| error.to_string())?;
            if !has_order {
                tx.execute_batch("ALTER TABLE finding_occurrences ADD COLUMN occurrence_order INTEGER NOT NULL DEFAULT 0;")
                    .map_err(|error| error.to_string())?;
                tx.execute_batch("UPDATE finding_occurrences SET occurrence_order=rowid;")
                    .map_err(|error| error.to_string())?;
            }
        }
        tx.pragma_update(None, "user_version", 13u32)
            .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
    }
    Ok(())
}

struct ReviewPersistence<'a> {
    id: &'a str,
    snapshot_id: &'a str,
    config_digest: &'a str,
    status: &'a str,
    payload: &'a str,
    findings: &'a [Finding],
    evidence: &'a [Evidence],
    snapshot_manifest: &'a str,
    decision: Option<&'a GateDecision>,
}

fn consolidated_findings(findings: &[Finding]) -> Vec<Finding> {
    let mut unique = std::collections::BTreeMap::<String, Finding>::new();
    for finding in findings {
        unique
            .entry(finding.fingerprint.clone())
            .and_modify(|saved| {
                let severity_rank = |severity| match severity {
                    Severity::Critical => 5,
                    Severity::High => 4,
                    Severity::Medium => 3,
                    Severity::Low => 2,
                    Severity::Info => 1,
                };
                if (
                    severity_rank(finding.severity),
                    finding.confidence.unwrap_or(0),
                ) > (severity_rank(saved.severity), saved.confidence.unwrap_or(0))
                {
                    saved.severity = finding.severity;
                    saved.confidence = finding.confidence;
                    saved.rationale = finding.rationale.clone();
                }
                saved
                    .reviewer_ids
                    .extend(finding.reviewer_ids.iter().cloned());
                saved.reviewer_ids.sort();
                saved.reviewer_ids.dedup();
                saved
                    .evidence_ids
                    .extend(finding.evidence_ids.iter().cloned());
                saved.evidence_ids.sort();
                saved.evidence_ids.dedup();
                saved
                    .rule_attributions
                    .extend(finding.rule_attributions.iter().cloned());
                saved.rule_attributions.sort();
                saved.rule_attributions.dedup();
            })
            .or_insert_with(|| finding.clone());
    }
    unique.into_values().collect()
}

impl ReviewStore {
    pub fn open(path: &Path) -> Result<Self, String> {
        let mut connection = rusqlite::Connection::open(path).map_err(|e| e.to_string())?;
        migrate_storage(&mut connection)?;
        Ok(Self { connection })
    }

    pub fn save(
        &mut self,
        id: &str,
        snapshot_id: &str,
        config_digest: &str,
        status: &str,
        payload: &str,
    ) -> Result<(), String> {
        let tx = self.connection.transaction().map_err(|e| e.to_string())?;
        tx.execute(
            "INSERT OR IGNORE INTO snapshots(snapshot_id,manifest_json) VALUES (?1,'{}')",
            [snapshot_id],
        )
        .map_err(|e| e.to_string())?;
        tx.execute("INSERT INTO reviews(id,snapshot_id,config_digest,status,payload) VALUES (?1,?2,?3,?4,?5)", rusqlite::params![id,snapshot_id,config_digest,status,payload]).map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())
    }

    pub fn save_review(
        &mut self,
        id: &str,
        snapshot_id: &str,
        config_digest: &str,
        status: &str,
        payload: &str,
        findings: &[Finding],
    ) -> Result<(), String> {
        self.save_review_inner(ReviewPersistence {
            id,
            snapshot_id,
            config_digest,
            status,
            payload,
            findings,
            evidence: &[],
            snapshot_manifest: "{}",
            decision: None,
        })
    }

    fn save_review_inner(&mut self, record: ReviewPersistence<'_>) -> Result<(), String> {
        validate_snapshot_manifest(record.snapshot_id, record.snapshot_manifest)?;
        let tx = self.connection.transaction().map_err(|e| e.to_string())?;
        tx.execute(
            "INSERT OR IGNORE INTO snapshots(snapshot_id,manifest_json) VALUES (?1,?2)",
            rusqlite::params![record.snapshot_id, record.snapshot_manifest],
        )
        .map_err(|e| e.to_string())?;
        let saved_manifest: String = tx
            .query_row(
                "SELECT manifest_json FROM snapshots WHERE snapshot_id=?1",
                [record.snapshot_id],
                |row| row.get(0),
            )
            .map_err(|e| e.to_string())?;
        if saved_manifest == "{}" && record.snapshot_manifest != "{}" {
            tx.execute(
                "UPDATE snapshots SET manifest_json=?2 WHERE snapshot_id=?1 AND manifest_json='{}'",
                rusqlite::params![record.snapshot_id, record.snapshot_manifest],
            )
            .map_err(|e| e.to_string())?;
        } else if saved_manifest != record.snapshot_manifest {
            return Err("snapshot ID was previously stored with a different manifest".into());
        }
        tx.execute("INSERT INTO reviews(id,snapshot_id,config_digest,status,payload) VALUES (?1,?2,?3,?4,?5)", rusqlite::params![record.id,record.snapshot_id,record.config_digest,record.status,record.payload]).map_err(|e| e.to_string())?;
        let occurrence_order: i64 = tx
            .query_row(
                "SELECT COALESCE(MAX(occurrence_order),0)+1 FROM finding_occurrences",
                [],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        for finding in consolidated_findings(record.findings).iter() {
            let severity = match finding.severity {
                Severity::Critical => "critical",
                Severity::High => "high",
                Severity::Medium => "medium",
                Severity::Low => "low",
                Severity::Info => "info",
            };
            let finding_json = serde_json::to_string(finding).map_err(|e| e.to_string())?;
            tx.execute("INSERT INTO findings(id,fingerprint,category,severity,confidence,status,finding_json) VALUES (?1,?2,?3,?4,?5,'open',?6)
                ON CONFLICT(fingerprint) DO UPDATE SET category=excluded.category,severity=excluded.severity,confidence=excluded.confidence,finding_json=excluded.finding_json,last_seen=CURRENT_TIMESTAMP,
                status=CASE WHEN findings.status IN ('resolved','waived') THEN 'open' ELSE findings.status END,
                status_reason=CASE WHEN findings.status IN ('resolved','waived') THEN 'reappeared in a later review' ELSE findings.status_reason END",
                rusqlite::params![finding.id,finding.fingerprint,finding.category,severity,finding.confidence,finding_json]).map_err(|e| e.to_string())?;
            tx.execute("INSERT INTO finding_occurrences(review_id,finding_id,snapshot_id,finding_json,occurrence_order) VALUES (?1,?2,?3,?4,?5)", rusqlite::params![record.id,finding.id,record.snapshot_id,finding_json,occurrence_order]).map_err(|e| e.to_string())?;
        }
        for assessment in record.findings {
            let finding_id: String = tx
                .query_row(
                    "SELECT id FROM findings WHERE fingerprint=?1",
                    [&assessment.fingerprint],
                    |row| row.get(0),
                )
                .map_err(|error| error.to_string())?;
            let payload = serde_json::to_string(assessment).map_err(|error| error.to_string())?;
            let assessment_digest = digest(payload.as_bytes());
            tx.execute("INSERT OR IGNORE INTO finding_assessments(review_id,finding_id,snapshot_id,assessment_digest,finding_json) VALUES (?1,?2,?3,?4,?5)", rusqlite::params![record.id,finding_id,record.snapshot_id,assessment_digest,payload]).map_err(|error| error.to_string())?;
        }
        for evidence in record.evidence {
            let payload = serde_json::to_string(evidence).map_err(|error| error.to_string())?;
            tx.execute(
                "INSERT INTO evidence(review_id,evidence_id,payload) VALUES (?1,?2,?3)",
                rusqlite::params![record.id, evidence.id, payload],
            )
            .map_err(|error| error.to_string())?;
            let kind = serde_json::to_value(evidence.kind)
                .map_err(|error| error.to_string())?
                .as_str()
                .unwrap_or("unknown")
                .to_string();
            let classification = serde_json::to_value(evidence.classification)
                .map_err(|error| error.to_string())?
                .as_str()
                .unwrap_or("unknown")
                .to_string();
            let verification = serde_json::to_value(evidence.verification)
                .map_err(|error| error.to_string())?
                .as_str()
                .unwrap_or("unknown")
                .to_string();
            tx.execute(
                "INSERT INTO evidence_records(evidence_id,review_id,kind,provenance,source_path,content_digest,classification,verification,payload) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                rusqlite::params![evidence.id, record.id, kind, evidence.provenance, evidence.source_path, evidence.content_digest, classification, verification, payload],
            )
            .map_err(|error| error.to_string())?;
        }
        if let Some(decision) = record.decision {
            save_gate_decision_tx(&tx, record.id, decision)?;
        }
        tx.commit().map_err(|e| e.to_string())
    }

    fn load_assessments(
        &self,
        finding_id: &str,
        review_id: Option<&str>,
    ) -> Result<Vec<Finding>, String> {
        let mut statement = self.connection.prepare("SELECT finding_json FROM finding_assessments WHERE finding_id=?1 AND (?2 IS NULL OR review_id=?2) ORDER BY review_id,assessment_digest").map_err(|error| error.to_string())?;
        let rows = statement
            .query_map(rusqlite::params![finding_id, review_id], |row| {
                row.get::<_, String>(0)
            })
            .map_err(|error| error.to_string())?;
        rows.map(|row| {
            serde_json::from_str(&row.map_err(|error| error.to_string())?)
                .map_err(|error| error.to_string())
        })
        .collect()
    }

    fn load_occurrences(&self, finding_id: &str) -> Result<Vec<FindingOccurrence>, String> {
        let mut statement = self.connection.prepare("SELECT review_id,snapshot_id,observed_at FROM finding_occurrences WHERE finding_id=?1 ORDER BY observed_at,review_id").map_err(|e| e.to_string())?;
        let rows = statement
            .query_map([finding_id], |row| {
                Ok(FindingOccurrence {
                    review_id: row.get(0)?,
                    snapshot_id: row.get(1)?,
                    observed_at: row.get(2)?,
                })
            })
            .map_err(|e| e.to_string())?;
        rows.map(|row| row.map_err(|e| e.to_string())).collect()
    }
}

impl ReviewRepository for ReviewStore {
    fn get(&self, id: &str) -> Result<Option<String>, String> {
        self.connection
            .query_row("SELECT payload FROM reviews WHERE id=?1", [id], |row| {
                row.get(0)
            })
            .optional()
            .map_err(|e| e.to_string())
    }

    fn record_snapshot_manifest(
        &mut self,
        snapshot_id: &str,
        manifest_json: &str,
    ) -> Result<(), String> {
        validate_snapshot_manifest(snapshot_id, manifest_json)?;
        self.connection
            .execute(
                "INSERT OR IGNORE INTO snapshots(snapshot_id,manifest_json) VALUES (?1,?2)",
                rusqlite::params![snapshot_id, manifest_json],
            )
            .map_err(|error| error.to_string())?;
        // Legacy rows hold an empty placeholder; replace it with the real manifest.
        self.connection
            .execute(
                "UPDATE snapshots SET manifest_json=?2 WHERE snapshot_id=?1 AND manifest_json='{}'",
                rusqlite::params![snapshot_id, manifest_json],
            )
            .map_err(|error| error.to_string())?;
        Ok(())
    }

    fn snapshot_manifest(&self, snapshot_id: &str) -> Result<Option<String>, String> {
        self.connection
            .query_row(
                "SELECT manifest_json FROM snapshots WHERE snapshot_id=?1",
                [snapshot_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())
    }

    fn list_reviews(&self) -> Result<Vec<ReviewSummary>, String> {
        let mut statement = self
            .connection
            .prepare("SELECT id,snapshot_id,status,created_at FROM reviews ORDER BY created_at DESC,id DESC")
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map([], |row| {
                Ok(ReviewSummary {
                    review_id: row.get(0)?,
                    snapshot_id: row.get(1)?,
                    status: row.get(2)?,
                    created_at: row.get(3)?,
                })
            })
            .map_err(|error| error.to_string())?;
        rows.map(|row| row.map_err(|error| error.to_string()))
            .collect()
    }

    fn save_review_with_decision(&mut self, write: ReviewWrite<'_>) -> Result<(), String> {
        self.save_review_inner(ReviewPersistence {
            id: write.id,
            snapshot_id: write.snapshot_id,
            config_digest: write.config_digest,
            status: write.status,
            payload: write.payload,
            findings: write.findings,
            evidence: write.evidence,
            snapshot_manifest: write.snapshot_manifest,
            decision: Some(write.decision),
        })
    }

    fn evidence_for_review(&self, review_id: &str) -> Result<Vec<Evidence>, String> {
        let mut statement = self
            .connection
            .prepare("SELECT payload FROM evidence_records WHERE review_id=?1 ORDER BY evidence_id")
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map([review_id], |row| {
                let payload: String = row.get(0)?;
                serde_json::from_str(&payload).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Text,
                        Box::new(error),
                    )
                })
            })
            .map_err(|error| error.to_string())?;
        rows.map(|row| row.map_err(|error| error.to_string()))
            .collect()
    }
}

impl FindingRepository for ReviewStore {
    fn set_finding_status(
        &mut self,
        id: &str,
        status: FindingStatus,
        reason: &str,
    ) -> Result<(), String> {
        if status == FindingStatus::Waived {
            return Err(
                "waivers require a scoped snapshot, provenance, author, and expiry; use the waiver workflow"
                    .into(),
            );
        }
        if reason.trim().is_empty() {
            return Err("finding status reason must not be empty".into());
        }
        let changed = self.connection.execute("UPDATE findings SET status=?2,status_reason=?3,last_seen=CURRENT_TIMESTAMP WHERE id=?1", rusqlite::params![id,status.as_str(),reason]).map_err(|e| e.to_string())?;
        if changed == 0 {
            return Err(format!("finding {id} was not found"));
        }
        Ok(())
    }

    fn add_finding_feedback(
        &mut self,
        finding_id: &str,
        snapshot_id: &str,
        label: FindingFeedbackLabel,
        reason: &str,
        reviewer: &str,
    ) -> Result<FindingFeedback, String> {
        if reason.trim().is_empty() || reviewer.trim().is_empty() {
            return Err("finding feedback requires a non-empty reason and reviewer".into());
        }
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        let occurrence_exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM finding_occurrences WHERE finding_id=?1 AND snapshot_id=?2)",
            rusqlite::params![finding_id, snapshot_id],
            |row| row.get(0),
        ).map_err(|error| error.to_string())?;
        if !occurrence_exists {
            return Err(
                "finding feedback must reference a snapshot where the finding occurred".into(),
            );
        }
        let feedback_id = digest(
            format!(
                "{finding_id}\0{snapshot_id}\0{}\0{}\0{}",
                label.as_str(),
                reviewer.trim(),
                reason.trim()
            )
            .as_bytes(),
        );
        let created_at: String = tx
            .query_row("SELECT CURRENT_TIMESTAMP", [], |row| row.get(0))
            .map_err(|error| error.to_string())?;
        let feedback = FindingFeedback {
            schema_version: 1,
            feedback_id: feedback_id.clone(),
            finding_id: finding_id.to_owned(),
            snapshot_id: snapshot_id.to_owned(),
            label,
            reason: reason.trim().to_owned(),
            reviewer: reviewer.trim().to_owned(),
            created_at,
        };
        let payload = serde_json::to_string(&feedback).map_err(|error| error.to_string())?;
        tx.execute(
            "INSERT OR IGNORE INTO finding_feedback(feedback_id,finding_id,snapshot_id,label,reason,reviewer,payload,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            rusqlite::params![feedback.feedback_id, finding_id, snapshot_id, label.as_str(), feedback.reason, feedback.reviewer, payload, feedback.created_at],
        ).map_err(|error| error.to_string())?;
        let persisted = tx
            .query_row(
                "SELECT payload FROM finding_feedback WHERE feedback_id=?1",
                [&feedback_id],
                |row| row.get::<_, String>(0),
            )
            .map_err(|error| error.to_string())?;
        let persisted = serde_json::from_str(&persisted).map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(persisted)
    }

    fn list_finding_feedback(&self) -> Result<Vec<FindingFeedback>, String> {
        let mut statement = self
            .connection
            .prepare("SELECT payload FROM finding_feedback ORDER BY created_at,feedback_id")
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map([], |row| {
                let payload: String = row.get(0)?;
                serde_json::from_str(&payload).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Text,
                        Box::new(error),
                    )
                })
            })
            .map_err(|error| error.to_string())?;
        rows.map(|row| row.map_err(|error| error.to_string()))
            .collect()
    }

    fn finding(&self, id: &str) -> Result<Option<FindingRecord>, String> {
        let mut record = self.connection.query_row("SELECT f.finding_json,f.status,f.status_reason,(SELECT COUNT(*) FROM finding_occurrences o WHERE o.finding_id=f.id),f.first_seen,f.last_seen FROM findings f WHERE f.id=?1", [id], finding_record_from_row).optional().map_err(|e| e.to_string())?;
        if let Some(record) = &mut record {
            record.occurrences = self.load_occurrences(&record.finding.id)?;
            record.assessments = self.load_assessments(&record.finding.id, None)?;
        }
        Ok(record)
    }

    fn list_findings(
        &self,
        severity: Option<Severity>,
        status: Option<FindingStatus>,
        review_id: Option<&str>,
    ) -> Result<Vec<FindingRecord>, String> {
        let severity = severity.map(severity_name);
        let status = status.map(FindingStatus::as_str);
        let mut statement = self.connection.prepare("SELECT f.finding_json,f.status,f.status_reason,(SELECT COUNT(*) FROM finding_occurrences o WHERE o.finding_id=f.id),f.first_seen,f.last_seen FROM findings f WHERE (?1 IS NULL OR ((?3 IS NULL AND f.severity=?1) OR EXISTS(SELECT 1 FROM finding_assessments a WHERE a.finding_id=f.id AND ((?3 IS NOT NULL AND a.review_id=?3) OR (?3 IS NULL AND a.review_id=(SELECT o.review_id FROM finding_occurrences o WHERE o.finding_id=f.id ORDER BY o.occurrence_order DESC,o.review_id DESC LIMIT 1))) AND json_extract(a.finding_json,'$.severity')=?1))) AND (?2 IS NULL OR f.status=?2) AND (?3 IS NULL OR EXISTS(SELECT 1 FROM finding_occurrences x WHERE x.finding_id=f.id AND x.review_id=?3)) ORDER BY f.last_seen DESC,f.id").map_err(|e| e.to_string())?;
        let records = statement
            .query_map(
                rusqlite::params![severity, status, review_id],
                finding_record_from_row,
            )
            .map_err(|e| e.to_string())?;
        let mut records: Vec<FindingRecord> = records
            .map(|record| record.map_err(|e| e.to_string()))
            .collect::<Result<_, _>>()?;
        for record in &mut records {
            record.occurrences = self.load_occurrences(&record.finding.id)?;
            record.assessments = self.load_assessments(&record.finding.id, review_id)?;
        }
        Ok(records)
    }

    fn list_findings_page(
        &self,
        severity: Option<Severity>,
        status: Option<FindingStatus>,
        review_id: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> Result<(Vec<FindingRecord>, usize), String> {
        if limit == 0 {
            return Err("finding page limit must be positive".into());
        }
        let limit = i64::try_from(limit).map_err(|error| error.to_string())?;
        let offset = i64::try_from(offset).map_err(|error| error.to_string())?;
        let severity = severity.map(severity_name);
        let status = status.map(FindingStatus::as_str);
        let total: i64 = self
            .connection
            .query_row(
                "SELECT COUNT(*) FROM findings f WHERE (?1 IS NULL OR ((?3 IS NULL AND f.severity=?1) OR EXISTS(SELECT 1 FROM finding_assessments a WHERE a.finding_id=f.id AND ((?3 IS NOT NULL AND a.review_id=?3) OR (?3 IS NULL AND a.review_id=(SELECT o.review_id FROM finding_occurrences o WHERE o.finding_id=f.id ORDER BY o.occurrence_order DESC,o.review_id DESC LIMIT 1))) AND json_extract(a.finding_json,'$.severity')=?1))) AND (?2 IS NULL OR f.status=?2) AND (?3 IS NULL OR EXISTS(SELECT 1 FROM finding_occurrences x WHERE x.finding_id=f.id AND x.review_id=?3))",
                rusqlite::params![severity, status, review_id],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        let total = usize::try_from(total).map_err(|error| error.to_string())?;
        let mut statement = self
            .connection
            .prepare("SELECT f.finding_json,f.status,f.status_reason,(SELECT COUNT(*) FROM finding_occurrences o WHERE o.finding_id=f.id),f.first_seen,f.last_seen FROM findings f WHERE (?1 IS NULL OR ((?3 IS NULL AND f.severity=?1) OR EXISTS(SELECT 1 FROM finding_assessments a WHERE a.finding_id=f.id AND ((?3 IS NOT NULL AND a.review_id=?3) OR (?3 IS NULL AND a.review_id=(SELECT o.review_id FROM finding_occurrences o WHERE o.finding_id=f.id ORDER BY o.occurrence_order DESC,o.review_id DESC LIMIT 1))) AND json_extract(a.finding_json,'$.severity')=?1))) AND (?2 IS NULL OR f.status=?2) AND (?3 IS NULL OR EXISTS(SELECT 1 FROM finding_occurrences x WHERE x.finding_id=f.id AND x.review_id=?3)) ORDER BY f.last_seen DESC,f.id LIMIT ?4 OFFSET ?5")
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map(
                rusqlite::params![severity, status, review_id, limit, offset],
                finding_record_from_row,
            )
            .map_err(|error| error.to_string())?;
        let mut records: Vec<FindingRecord> = rows
            .map(|record| record.map_err(|error| error.to_string()))
            .collect::<Result<_, _>>()?;
        for record in &mut records {
            record.occurrences = self.load_occurrences(&record.finding.id)?;
            record.assessments = self.load_assessments(&record.finding.id, review_id)?;
        }
        Ok((records, total))
    }
}

impl GateRepository for ReviewStore {
    fn save_gate_decision(
        &mut self,
        review_id: &str,
        decision: &GateDecision,
    ) -> Result<(), String> {
        save_gate_decision_connection(&self.connection, review_id, decision)
    }

    fn gate_decisions_for_review(&self, review_id: &str) -> Result<Vec<GateDecision>, String> {
        let mut statement = self
            .connection
            .prepare("SELECT payload,effective_config_digest FROM gate_decisions WHERE review_id=?1 ORDER BY rowid")
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map([review_id], |row| {
                let payload: String = row.get(0)?;
                let config_digest: String = row.get(1)?;
                let mut decision: GateDecision =
                    serde_json::from_str(&payload).map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            0,
                            rusqlite::types::Type::Text,
                            Box::new(error),
                        )
                    })?;
                if decision.effective_config_digest.is_empty() {
                    decision.effective_config_digest = config_digest;
                }
                Ok(decision)
            })
            .map_err(|error| error.to_string())?;
        rows.map(|row| row.map_err(|error| error.to_string()))
            .collect()
    }

    fn create_waiver(&mut self, waiver: &Waiver) -> Result<(), String> {
        if waiver.schema_version != 1 {
            return Err(format!(
                "unsupported waiver schema version {}",
                waiver.schema_version
            ));
        }
        if waiver.id.trim().is_empty()
            || waiver.finding_fingerprint.trim().is_empty()
            || waiver.snapshot_id.trim().is_empty()
            || waiver.reason.trim().is_empty()
            || waiver.author.trim().is_empty()
            || waiver.provenance.trim().is_empty()
        {
            return Err("waiver fields must not be empty".into());
        }
        if waiver.expires_at_unix <= waiver.created_at_unix {
            return Err("waiver expiry must be after creation".into());
        }
        self.connection
            .execute(
                "INSERT INTO waivers(id,finding_fingerprint,snapshot_id,reason,author,provenance,created_at_unix,expires_at_unix) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
                rusqlite::params![
                    waiver.id,
                    waiver.finding_fingerprint,
                    waiver.snapshot_id,
                    waiver.reason,
                    waiver.author,
                    waiver.provenance,
                    waiver.created_at_unix,
                    waiver.expires_at_unix,
                ],
            )
            .map_err(|error| error.to_string())?;
        Ok(())
    }

    fn waivers_for_snapshot(&self, snapshot_id: &str) -> Result<Vec<Waiver>, String> {
        let mut statement = self.connection.prepare(
            "SELECT id,finding_fingerprint,snapshot_id,reason,author,provenance,created_at_unix,expires_at_unix FROM waivers WHERE snapshot_id=?1 ORDER BY id",
        ).map_err(|error| error.to_string())?;
        let rows = statement
            .query_map([snapshot_id], |row| {
                Ok(Waiver {
                    schema_version: 1,
                    id: row.get(0)?,
                    finding_fingerprint: row.get(1)?,
                    snapshot_id: row.get(2)?,
                    reason: row.get(3)?,
                    author: row.get(4)?,
                    provenance: row.get(5)?,
                    created_at_unix: row.get(6)?,
                    expires_at_unix: row.get(7)?,
                })
            })
            .map_err(|error| error.to_string())?;
        rows.map(|row| row.map_err(|error| error.to_string()))
            .collect()
    }
}

impl VerificationRepository for ReviewStore {
    fn save_verification(&mut self, run: &VerificationRun) -> Result<(), String> {
        self.save_verification_with_artifacts(run)
    }

    fn save_verification_with_artifacts(&mut self, run: &VerificationRun) -> Result<(), String> {
        let payload = serde_json::to_string(run).map_err(|error| error.to_string())?;
        let tx = self
            .connection
            .transaction()
            .map_err(|error| error.to_string())?;
        tx.execute(
            "INSERT OR IGNORE INTO verification_runs(run_id,snapshot_id,profile_id,finding_id,command_digest,status,exit_code,stdout_digest,stderr_digest,payload) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
            rusqlite::params![run.run_id, run.snapshot_id, run.profile_id, run.finding_id, run.command_digest, match run.status { VerificationStatus::Passed => "passed", VerificationStatus::Failed => "failed", VerificationStatus::TimedOut => "timed_out", VerificationStatus::Incomplete => "incomplete" }, run.exit_code, run.stdout_digest, run.stderr_digest, payload],
        ).map_err(|error| error.to_string())?;
        for (stream, reference) in [
            ("stdout", run.stdout_artifact.as_ref()),
            ("stderr", run.stderr_artifact.as_ref()),
        ] {
            if let Some(reference) = reference {
                let expected_digest = if stream == "stdout" {
                    &run.stdout_digest
                } else {
                    &run.stderr_digest
                };
                if &reference.digest != expected_digest
                    || !reference.path.starts_with(".vero/artifacts/sha256/")
                    || reference.path.contains("..")
                {
                    return Err(format!("invalid {stream} verification artifact reference"));
                }
                tx.execute(
                    "INSERT OR IGNORE INTO artifacts(digest,path,size_bytes) VALUES (?1,?2,?3)",
                    rusqlite::params![
                        reference.digest,
                        reference.path,
                        i64::try_from(reference.size_bytes)
                            .map_err(|error| format!("artifact size is too large: {error}"))?,
                    ],
                )
                .map_err(|error| error.to_string())?;
                tx.execute(
                    "INSERT OR IGNORE INTO verification_artifacts(run_id,stream,digest) VALUES (?1,?2,?3)",
                    rusqlite::params![run.run_id, stream, reference.digest],
                )
                .map_err(|error| error.to_string())?;
            }
        }
        tx.commit().map_err(|error| error.to_string())?;
        Ok(())
    }

    fn verification_artifact(
        &self,
        run_id: &str,
        stream: &str,
    ) -> Result<Option<ArtifactReference>, String> {
        if !matches!(stream, "stdout" | "stderr") {
            return Err("verification artifact stream must be stdout or stderr".into());
        }
        self.connection
            .query_row(
                "SELECT artifacts.digest,artifacts.path,artifacts.size_bytes FROM verification_artifacts JOIN artifacts USING(digest) WHERE run_id=?1 AND stream=?2",
                rusqlite::params![run_id, stream],
                |row| {
                    let size_bytes: i64 = row.get(2)?;
                    let size_bytes = u64::try_from(size_bytes).map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            2,
                            rusqlite::types::Type::Integer,
                            Box::new(error),
                        )
                    })?;
                    Ok(ArtifactReference {
                        digest: row.get(0)?,
                        path: row.get(1)?,
                        size_bytes,
                    })
                },
            )
            .optional()
            .map_err(|error| error.to_string())
    }

    fn verification(&self, run_id: &str) -> Result<Option<VerificationRun>, String> {
        self.connection
            .query_row(
                "SELECT payload FROM verification_runs WHERE run_id=?1",
                [run_id],
                |row| {
                    let payload: String = row.get(0)?;
                    serde_json::from_str(&payload).map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            0,
                            rusqlite::types::Type::Text,
                            Box::new(error),
                        )
                    })
                },
            )
            .optional()
            .map_err(|error| error.to_string())
    }

    fn verifications_for_snapshot(
        &self,
        snapshot_id: &str,
    ) -> Result<Vec<VerificationRun>, String> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT payload FROM verification_runs WHERE snapshot_id=?1 ORDER BY rowid DESC",
            )
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map([snapshot_id], |row| {
                let payload: String = row.get(0)?;
                serde_json::from_str(&payload).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Text,
                        Box::new(error),
                    )
                })
            })
            .map_err(|error| error.to_string())?;
        rows.map(|row| row.map_err(|error| error.to_string()))
            .collect()
    }

    fn verifications_for_finding(&self, finding_id: &str) -> Result<Vec<VerificationRun>, String> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT payload FROM verification_runs WHERE finding_id=?1 ORDER BY rowid DESC",
            )
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map([finding_id], |row| {
                let payload: String = row.get(0)?;
                serde_json::from_str(&payload).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Text,
                        Box::new(error),
                    )
                })
            })
            .map_err(|error| error.to_string())?;
        rows.map(|row| row.map_err(|error| error.to_string()))
            .collect()
    }

    fn recent_verification_summaries(
        &self,
        limit: usize,
    ) -> Result<(Vec<VerificationSummary>, usize), String> {
        let total: i64 = self
            .connection
            .query_row("SELECT COUNT(*) FROM verification_runs", [], |row| {
                row.get(0)
            })
            .map_err(|error| error.to_string())?;
        let mut statement = self
            .connection
            .prepare("SELECT run_id,snapshot_id,profile_id,status,created_at FROM verification_runs ORDER BY rowid DESC LIMIT ?1")
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map([limit.min(i64::MAX as usize) as i64], |row| {
                Ok(VerificationSummary {
                    run_id: row.get(0)?,
                    snapshot_id: row.get(1)?,
                    profile_id: row.get(2)?,
                    status: row.get(3)?,
                    created_at: row.get(4)?,
                })
            })
            .map_err(|error| error.to_string())?;
        let mut summaries = Vec::new();
        for row in rows {
            summaries.push(row.map_err(|error| error.to_string())?);
        }
        Ok((summaries, total.max(0) as usize))
    }
}

impl RuleApprovalRepository for ReviewStore {
    fn create_rule_approval(&mut self, approval: &RuleApproval) -> Result<(), String> {
        if approval.schema_version != 2 || approval.approval_id.trim().is_empty() {
            return Err("rule approval requires schema version 2 and a non-empty ID".into());
        }
        if [
            approval.candidate_id.as_str(),
            approval.evidence_digest.as_str(),
            approval.category.as_str(),
            approval.scope.as_str(),
            approval.instruction.as_str(),
            approval.approver.as_str(),
            approval.approval_reason.as_str(),
        ]
        .iter()
        .any(|value| value.trim().is_empty())
        {
            return Err("rule approval fields must not be empty".into());
        }
        let scope_path = Path::new(approval.scope.trim());
        if scope_path.is_absolute()
            || approval
                .scope
                .trim()
                .chars()
                .any(|c| matches!(c, '*' | '?' | '[' | ']'))
            || scope_path.components().any(|component| {
                matches!(
                    component,
                    std::path::Component::ParentDir
                        | std::path::Component::RootDir
                        | std::path::Component::Prefix(_)
                )
            })
        {
            return Err("rule approval scope must be a repository-relative file or directory path without glob or parent components".into());
        }
        if approval.instruction.len() > 20_000 || approval.scope.len() > 1_024 {
            return Err("rule approval scope or instruction exceeds the storage limit".into());
        }
        if !is_sha256_digest(&approval.evidence_digest) {
            return Err(
                "rule approval evidence digest must use sha256:<64 hexadecimal characters>".into(),
            );
        }
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|error| error.to_string())?
            .as_secs() as i64;
        if approval
            .expires_at_unix
            .is_some_and(|expiry| expiry <= now_unix)
        {
            return Err("rule approval expiry must be in the future".into());
        }
        let created_at: String = self
            .connection
            .query_row("SELECT CURRENT_TIMESTAMP", [], |row| row.get(0))
            .map_err(|e| e.to_string())?;
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        let mut statement = tx
            .prepare("SELECT approval_id,payload FROM rule_approvals WHERE candidate_id=?1")
            .map_err(|e| e.to_string())?;
        let existing = statement
            .query_map([&approval.candidate_id], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|e| e.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?;
        drop(statement);
        let mut active_same_scope = Vec::new();
        let mut latest_same_scope: Option<RuleApproval> = None;
        for (id, payload) in existing {
            let prior: RuleApproval = serde_json::from_str(&payload).map_err(|e| e.to_string())?;
            if prior.scope.trim() != approval.scope.trim() {
                continue;
            }
            if latest_same_scope
                .as_ref()
                .is_none_or(|latest| prior.version > latest.version)
            {
                latest_same_scope = Some(prior.clone());
            }
            let terminal: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM rule_approval_events WHERE approval_id=?1 AND event IN ('revoked','superseded'))", [&id], |row| row.get(0)).map_err(|e| e.to_string())?;
            if !terminal
                && !prior
                    .expires_at_unix
                    .is_some_and(|expiry| expiry <= now_unix)
            {
                active_same_scope.push((id, prior));
            }
        }
        let version = if let Some(supersedes_id) = approval.supersedes_approval_id.as_deref() {
            let Some(_) = active_same_scope.iter().find(|(id, _)| id == supersedes_id) else {
                return Err(
                    "superseded approval must be active and have the same candidate and scope"
                        .into(),
                );
            };
            if active_same_scope.len() != 1 {
                return Err("candidate and scope have ambiguous active approvals; revoke extras before superseding".into());
            }
            latest_same_scope
                .as_ref()
                .map_or(1, |latest| latest.version.saturating_add(1))
        } else {
            if !active_same_scope.is_empty() {
                return Err(format!("active version {} already exists for this candidate and scope; specify --supersedes", active_same_scope[0].1.version));
            }
            latest_same_scope
                .as_ref()
                .map_or(1, |latest| latest.version.saturating_add(1))
        };
        let activation_event_id = digest(
            format!(
                "{}\0activated\0{}\0{}",
                approval.approval_id, approval.approver, now_unix
            )
            .as_bytes(),
        );
        let mut stored = approval.clone();
        stored.version = version;
        stored.created_at = created_at.clone();
        stored.activated_at_unix = Some(now_unix);
        stored.status = "active".into();
        stored.events = vec![RuleApprovalEvent {
            event_id: activation_event_id.clone(),
            event: "activated".into(),
            actor: approval.approver.clone(),
            reason: approval.approval_reason.clone(),
            created_at: created_at.clone(),
        }];
        let payload = serde_json::to_string(&stored).map_err(|e| e.to_string())?;
        if let Some((superseded_id, _)) = active_same_scope.first() {
            let event_id = digest(
                format!(
                    "{superseded_id}\0superseded\0{}\0{}",
                    approval.approval_id, now_unix
                )
                .as_bytes(),
            );
            tx.execute("INSERT INTO rule_approval_events(event_id,approval_id,event,actor,reason,created_at) VALUES (?1,?2,'superseded',?3,?4,?5)", rusqlite::params![event_id, superseded_id, approval.approver, format!("Superseded by approval {} version {version}", approval.approval_id), created_at]).map_err(|e| e.to_string())?;
        }
        tx.execute("INSERT INTO rule_approvals(approval_id,candidate_id,evidence_digest,payload,created_at) VALUES (?1,?2,?3,?4,?5)", rusqlite::params![stored.approval_id, stored.candidate_id, stored.evidence_digest, payload, created_at]).map_err(|e| e.to_string())?;
        tx.execute("INSERT INTO rule_approval_events(event_id,approval_id,event,actor,reason,created_at) VALUES (?1,?2,'activated',?3,?4,?5)", rusqlite::params![activation_event_id, stored.approval_id, stored.approver, stored.approval_reason, created_at]).map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())
    }

    fn revoke_rule_approval(
        &mut self,
        approval_id: &str,
        actor: &str,
        reason: &str,
    ) -> Result<(), String> {
        if actor.trim().is_empty() || reason.trim().is_empty() {
            return Err("revocation requires a non-empty actor and reason".into());
        }
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        let active: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM rule_approvals a WHERE a.approval_id=?1 AND NOT EXISTS(SELECT 1 FROM rule_approval_events e WHERE e.approval_id=a.approval_id AND e.event IN ('revoked','superseded')))", [approval_id], |row| row.get(0)).map_err(|e| e.to_string())?;
        if !active {
            return Err(format!("active rule approval {approval_id} was not found"));
        }
        let created_at: String = tx
            .query_row("SELECT CURRENT_TIMESTAMP", [], |row| row.get(0))
            .map_err(|e| e.to_string())?;
        let event_id = digest(
            format!(
                "{approval_id}\0revoked\0{}\0{}\0{}",
                actor.trim(),
                reason.trim(),
                created_at
            )
            .as_bytes(),
        );
        tx.execute("INSERT INTO rule_approval_events(event_id,approval_id,event,actor,reason,created_at) VALUES (?1,?2,'revoked',?3,?4,?5)", rusqlite::params![event_id, approval_id, actor.trim(), reason.trim(), created_at]).map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())
    }

    fn list_rule_approvals(&self) -> Result<Vec<RuleApproval>, String> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT approval_id,payload FROM rule_approvals ORDER BY created_at,approval_id",
            )
            .map_err(|e| e.to_string())?;
        let approvals = statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|e| e.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?;
        approvals.into_iter().map(|(id,payload)| {
            let mut approval: RuleApproval = serde_json::from_str(&payload).map_err(|e| e.to_string())?;
            let mut events_statement = self.connection.prepare("SELECT event_id,event,actor,reason,created_at FROM rule_approval_events WHERE approval_id=?1 ORDER BY rowid").map_err(|e| e.to_string())?;
            approval.events = events_statement.query_map([&id], |row| Ok(RuleApprovalEvent { event_id: row.get(0)?, event: row.get(1)?, actor: row.get(2)?, reason: row.get(3)?, created_at: row.get(4)? })).map_err(|e| e.to_string())?.collect::<Result<Vec<_>,_>>().map_err(|e| e.to_string())?;
            approval.schema_version = 2;
            approval.version = approval.version.max(1);
            approval.status = if approval.events.iter().any(|event| event.event == "revoked") {
                "revoked".into()
            } else if approval.events.iter().any(|event| event.event == "superseded") {
                "superseded".into()
            } else if approval.expires_at_unix.is_some_and(|expiry| expiry <= std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|duration| duration.as_secs() as i64).unwrap_or(i64::MAX)) {
                "expired".into()
            } else {
                "active".into()
            };
            Ok(approval)
        }).collect()
    }
}

impl ProviderResponseCache for ReviewStore {
    fn provider_cache_get(&self, request_key: &str) -> Result<Option<Vec<u8>>, String> {
        let cached: Option<(String, Vec<u8>)> = self
            .connection
            .query_row(
                "SELECT stdout_digest,stdout FROM provider_cache WHERE request_key=?1",
                [request_key],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        match cached {
            Some((expected, stdout)) if digest(&stdout) == expected => Ok(Some(stdout)),
            Some(_) => Err("provider cache response failed its content digest check".into()),
            None => Ok(None),
        }
    }

    fn provider_cache_put(
        &mut self,
        request_key: &str,
        provider_version: &str,
        stdout: &[u8],
    ) -> Result<(), String> {
        if !is_sha256_digest(request_key) {
            return Err("provider cache key must be a SHA-256 digest".into());
        }
        if provider_version.trim().is_empty() {
            return Err("provider cache requires a known provider version".into());
        }
        self.connection
            .execute(
                "INSERT OR IGNORE INTO provider_cache(request_key,provider_version,stdout_digest,stdout) VALUES (?1,?2,?3,?4)",
                rusqlite::params![request_key, provider_version, digest(stdout), stdout],
            )
            .map_err(|error| error.to_string())?;
        Ok(())
    }
}

impl HostedDeliveryRepository for ReviewStore {
    fn hosted_finding_threads(
        &self,
        target_key: &str,
    ) -> Result<std::collections::BTreeSet<String>, String> {
        if target_key.trim().is_empty() {
            return Err("hosting target identity is required".into());
        }
        let mut statement = self.connection
            .prepare("SELECT fingerprint FROM hosted_finding_threads WHERE target_key=?1 ORDER BY fingerprint")
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map([target_key], |row| row.get::<_, String>(0))
            .map_err(|error| error.to_string())?;
        rows.collect::<Result<std::collections::BTreeSet<_>, _>>()
            .map_err(|error| error.to_string())
    }

    fn replace_hosted_finding_threads(
        &mut self,
        target_key: &str,
        fingerprints: &std::collections::BTreeSet<String>,
    ) -> Result<(), String> {
        if target_key.trim().is_empty() {
            return Err("hosting target identity is required".into());
        }
        let tx = self
            .connection
            .transaction()
            .map_err(|error| error.to_string())?;
        tx.execute(
            "DELETE FROM hosted_finding_threads WHERE target_key=?1",
            [target_key],
        )
        .map_err(|error| error.to_string())?;
        for fingerprint in fingerprints {
            tx.execute(
                "INSERT INTO hosted_finding_threads(target_key,fingerprint) VALUES (?1,?2)",
                rusqlite::params![target_key, fingerprint],
            )
            .map_err(|error| error.to_string())?;
        }
        tx.commit().map_err(|error| error.to_string())
    }

    fn claim_webhook_delivery(
        &mut self,
        provider: &str,
        event_id: &str,
        event_type: &str,
        delivery_attempt: u32,
        payload_digest: &str,
        now_unix: i64,
        lease_seconds: i64,
    ) -> Result<WebhookClaim, String> {
        if provider.trim().is_empty()
            || event_id.trim().is_empty()
            || event_type.trim().is_empty()
            || delivery_attempt == 0
            || !is_sha256_digest(payload_digest)
            || lease_seconds <= 0
        {
            return Err(
                "webhook delivery identity, digest, and positive lease are required".into(),
            );
        }
        use rusqlite::TransactionBehavior;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        tx.execute(
            "INSERT OR IGNORE INTO webhook_deliveries(provider,event_id,event_type,delivery_attempt,payload_digest,state,received_at_unix) VALUES (?1,?2,?3,?4,?5,'received',?6)",
            rusqlite::params![provider,event_id,event_type,delivery_attempt,payload_digest,now_unix],
        ).map_err(|error| error.to_string())?;
        let (stored_digest, state, lease_expiry): (String,String,i64) = tx.query_row(
            "SELECT payload_digest,state,lease_expires_at_unix FROM webhook_deliveries WHERE provider=?1 AND event_id=?2",
            rusqlite::params![provider,event_id],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)),
        ).map_err(|error| error.to_string())?;
        if stored_digest != payload_digest {
            return Err("webhook event ID was reused with a different payload digest".into());
        }
        if state == "processed" {
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(WebhookClaim::AlreadyProcessed);
        }
        if state == "processing" && lease_expiry > now_unix {
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(WebhookClaim::InProgress);
        }
        static LEASE_SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let sequence = LEASE_SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let lease_token = format!("{}:{now_unix}:{sequence}", std::process::id());
        tx.execute(
            "UPDATE webhook_deliveries SET event_type=?1,delivery_attempt=MAX(delivery_attempt,?2),state='processing',lease_token=?3,lease_expires_at_unix=?4 WHERE provider=?5 AND event_id=?6",
            rusqlite::params![event_type,delivery_attempt,lease_token,now_unix.saturating_add(lease_seconds),provider,event_id],
        ).map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(WebhookClaim::Acquired { lease_token })
    }

    fn renew_webhook_delivery(
        &mut self,
        provider: &str,
        event_id: &str,
        lease_token: &str,
        now_unix: i64,
        lease_seconds: i64,
    ) -> Result<(), String> {
        if provider.trim().is_empty()
            || event_id.trim().is_empty()
            || lease_token.trim().is_empty()
            || lease_seconds <= 0
        {
            return Err("webhook lease identity and positive duration are required".into());
        }
        let changed = self.connection.execute(
            "UPDATE webhook_deliveries SET lease_expires_at_unix=?1 WHERE provider=?2 AND event_id=?3 AND state='processing' AND lease_token=?4 AND lease_expires_at_unix>?5",
            rusqlite::params![now_unix.saturating_add(lease_seconds), provider, event_id, lease_token, now_unix],
        ).map_err(|error| error.to_string())?;
        if changed != 1 {
            return Err("webhook delivery lease is no longer owned by this worker".into());
        }
        Ok(())
    }

    fn complete_webhook_delivery(
        &mut self,
        provider: &str,
        event_id: &str,
        lease_token: &str,
        now_unix: i64,
    ) -> Result<(), String> {
        let changed = self.connection.execute(
            "UPDATE webhook_deliveries SET state='processed',processed_at_unix=?1,lease_token=NULL,lease_expires_at_unix=0 WHERE provider=?2 AND event_id=?3 AND state='processing' AND lease_token=?4 AND lease_expires_at_unix>?5",
            rusqlite::params![now_unix,provider,event_id,lease_token,now_unix],
        ).map_err(|error| error.to_string())?;
        if changed != 1 {
            return Err("webhook delivery lease is no longer owned by this worker".into());
        }
        Ok(())
    }

    fn prune_processed_webhook_deliveries_before(
        &mut self,
        cutoff_unix: i64,
        apply: bool,
    ) -> Result<u64, String> {
        if cutoff_unix < 0 {
            return Err("webhook retention cutoff must be a non-negative timestamp".into());
        }
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        let count: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM webhook_deliveries WHERE state='processed' AND processed_at_unix IS NOT NULL AND processed_at_unix<?1",
                [cutoff_unix],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        if apply {
            tx.execute(
                "DELETE FROM webhook_deliveries WHERE state='processed' AND processed_at_unix IS NOT NULL AND processed_at_unix<?1",
                [cutoff_unix],
            )
            .map_err(|error| error.to_string())?;
        }
        tx.commit().map_err(|error| error.to_string())?;
        u64::try_from(count).map_err(|error| error.to_string())
    }

    fn release_webhook_delivery(
        &mut self,
        provider: &str,
        event_id: &str,
        lease_token: &str,
    ) -> Result<(), String> {
        let changed = self.connection.execute(
            "UPDATE webhook_deliveries SET state='received',lease_token=NULL,lease_expires_at_unix=0 WHERE provider=?1 AND event_id=?2 AND state='processing' AND lease_token=?3",
            rusqlite::params![provider,event_id,lease_token],
        ).map_err(|error| error.to_string())?;
        if changed != 1 {
            return Err("webhook delivery lease is no longer owned by this worker".into());
        }
        Ok(())
    }
}

fn save_gate_decision_tx(
    tx: &rusqlite::Transaction<'_>,
    review_id: &str,
    decision: &GateDecision,
) -> Result<(), String> {
    let status = match decision.status {
        GateStatus::Pass => "pass",
        GateStatus::Block => "block",
        GateStatus::Incomplete => "incomplete",
    };
    let payload = serde_json::to_string(decision).map_err(|error| error.to_string())?;
    tx.execute(
        "INSERT OR IGNORE INTO gate_decisions(decision_id,review_id,snapshot_id,effective_config_digest,policy_digest,evidence_digest,status,payload) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
        rusqlite::params![decision.decision_id, review_id, decision.snapshot_id, decision.effective_config_digest, decision.policy_digest, decision.evidence_digest, status, payload],
    )
    .map_err(|error| error.to_string())?;
    Ok(())
}

fn save_gate_decision_connection(
    connection: &rusqlite::Connection,
    review_id: &str,
    decision: &GateDecision,
) -> Result<(), String> {
    let status = match decision.status {
        GateStatus::Pass => "pass",
        GateStatus::Block => "block",
        GateStatus::Incomplete => "incomplete",
    };
    let payload = serde_json::to_string(decision).map_err(|error| error.to_string())?;
    connection
        .execute(
            "INSERT OR IGNORE INTO gate_decisions(decision_id,review_id,snapshot_id,effective_config_digest,policy_digest,evidence_digest,status,payload) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            rusqlite::params![decision.decision_id, review_id, decision.snapshot_id, decision.effective_config_digest, decision.policy_digest, decision.evidence_digest, status, payload],
        )
        .map_err(|error| error.to_string())?;
    Ok(())
}

fn severity_name(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Info => "info",
    }
}

fn finding_record_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<FindingRecord> {
    let finding_json: String = row.get(0)?;
    let status: String = row.get(1)?;
    let status_reason: Option<String> = row.get(2)?;
    let occurrence_count: i64 = row.get(3)?;
    let first_seen: String = row.get(4)?;
    let last_seen: String = row.get(5)?;
    let finding = serde_json::from_str(&finding_json).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(error))
    })?;
    let status = FindingStatus::parse(&status).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(1, rusqlite::types::Type::Text, error.into())
    })?;
    Ok(FindingRecord {
        finding,
        assessments: Vec::new(),
        status,
        status_reason,
        occurrence_count: occurrence_count.max(0) as u64,
        first_seen,
        last_seen,
        occurrences: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(id: &str, severity: Severity, confidence: Option<u8>) -> Finding {
        Finding {
            id: id.into(),
            fingerprint: id.into(),
            category: "correctness".into(),
            severity,
            confidence,
            rationale: String::new(),
            path: Some("src/lib.rs".into()),
            line: Some(1),
            provenance: "model_inference".into(),
            reviewer_ids: Vec::new(),
            evidence_ids: Vec::new(),
            rule_attributions: Vec::new(),
        }
    }

    fn passed_run_for_test() -> VerificationRun {
        VerificationRun {
            schema_version: 1,
            run_id: "run-1".into(),
            snapshot_id: "snapshot-1".into(),
            profile_id: "unit".into(),
            finding_id: None,
            targets: Vec::new(),
            command_digest: digest(b"unit-command"),
            status: VerificationStatus::Passed,
            exit_code: Some(0),
            stdout_digest: digest(b""),
            stderr_digest: digest(b""),
            stdout_artifact: None,
            stderr_artifact: None,
        }
    }

    #[test]
    fn webhook_delivery_claims_are_durable_leased_and_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("webhooks.sqlite");
        let mut first = ReviewStore::open(&db).unwrap();
        let body_digest = digest(b"verified webhook body");
        let claim = first
            .claim_webhook_delivery(
                "github",
                "delivery-1",
                "pull_request",
                1,
                &body_digest,
                100,
                30,
            )
            .unwrap();
        let WebhookClaim::Acquired { lease_token } = claim else {
            panic!("first delivery should be claimed");
        };
        let mut second = ReviewStore::open(&db).unwrap();
        assert_eq!(
            second
                .claim_webhook_delivery(
                    "github",
                    "delivery-1",
                    "pull_request",
                    2,
                    &body_digest,
                    101,
                    30
                )
                .unwrap(),
            WebhookClaim::InProgress
        );
        first
            .renew_webhook_delivery("github", "delivery-1", &lease_token, 120, 30)
            .unwrap();
        assert_eq!(
            second
                .claim_webhook_delivery(
                    "github",
                    "delivery-1",
                    "pull_request",
                    2,
                    &body_digest,
                    131,
                    30,
                )
                .unwrap(),
            WebhookClaim::InProgress
        );
        assert!(second
            .renew_webhook_delivery("github", "delivery-1", "stale-lease", 132, 30)
            .is_err());
        assert!(second
            .complete_webhook_delivery("github", "delivery-1", "stale-lease", 102)
            .is_err());
        first
            .release_webhook_delivery("github", "delivery-1", &lease_token)
            .unwrap();
        let WebhookClaim::Acquired { lease_token } = second
            .claim_webhook_delivery(
                "github",
                "delivery-1",
                "pull_request",
                2,
                &body_digest,
                103,
                30,
            )
            .unwrap()
        else {
            panic!("released delivery should be retriable");
        };
        second
            .complete_webhook_delivery("github", "delivery-1", &lease_token, 104)
            .unwrap();
        drop(second);

        let mut reopened = ReviewStore::open(&db).unwrap();
        assert_eq!(
            reopened
                .claim_webhook_delivery(
                    "github",
                    "delivery-1",
                    "pull_request",
                    3,
                    &body_digest,
                    105,
                    30
                )
                .unwrap(),
            WebhookClaim::AlreadyProcessed
        );
        assert!(reopened
            .claim_webhook_delivery(
                "github",
                "delivery-1",
                "pull_request",
                3,
                &digest(b"different body"),
                105,
                30
            )
            .is_err());
    }

    #[test]
    fn hosted_finding_threads_are_isolated_by_pull_request_and_persisted() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("hosted-threads.sqlite");
        let mut store = ReviewStore::open(&db).unwrap();
        let first = std::collections::BTreeSet::from(["sha256:first".to_owned()]);
        store
            .replace_hosted_finding_threads("github:repo#1", &first)
            .unwrap();
        assert_eq!(
            store.hosted_finding_threads("github:repo#1").unwrap(),
            first
        );
        assert!(store
            .hosted_finding_threads("github:repo#2")
            .unwrap()
            .is_empty());
        drop(store);
        let mut reopened = ReviewStore::open(&db).unwrap();
        let next = std::collections::BTreeSet::from(["sha256:next".to_owned()]);
        reopened
            .replace_hosted_finding_threads("github:repo#1", &next)
            .unwrap();
        assert_eq!(
            reopened.hosted_finding_threads("github:repo#1").unwrap(),
            next
        );
    }

    #[test]
    fn expired_webhook_lease_can_be_reclaimed_after_restart() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("webhook-expiry.sqlite");
        let mut store = ReviewStore::open(&db).unwrap();
        let payload_digest = digest(b"body");
        let WebhookClaim::Acquired {
            lease_token: old_token,
        } = store
            .claim_webhook_delivery(
                "github",
                "delivery-expired",
                "push",
                1,
                &payload_digest,
                10,
                5,
            )
            .unwrap()
        else {
            panic!("expected claim");
        };
        assert!(store
            .complete_webhook_delivery("github", "delivery-expired", &old_token, 15)
            .is_err());
        let WebhookClaim::Acquired {
            lease_token: new_token,
        } = store
            .claim_webhook_delivery(
                "github",
                "delivery-expired",
                "push",
                2,
                &payload_digest,
                15,
                5,
            )
            .unwrap()
        else {
            panic!("expired lease should be reclaimed");
        };
        assert_ne!(old_token, new_token);
        assert!(store
            .complete_webhook_delivery("github", "delivery-expired", &old_token, 16)
            .is_err());
        store
            .complete_webhook_delivery("github", "delivery-expired", &new_token, 16)
            .unwrap();
    }

    #[test]
    fn webhook_retention_prunes_only_old_completed_receipts_and_supports_preview() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = ReviewStore::open(&dir.path().join("webhook-retention.sqlite")).unwrap();
        let add_delivery = |store: &mut ReviewStore, event: &str, at: i64, complete: bool| {
            let body_digest = digest(event.as_bytes());
            let WebhookClaim::Acquired { lease_token } = store
                .claim_webhook_delivery("github", event, "push", 1, &body_digest, at, 60)
                .unwrap()
            else {
                panic!("new event should be claimed");
            };
            if complete {
                store
                    .complete_webhook_delivery("github", event, &lease_token, at + 1)
                    .unwrap();
            }
        };
        add_delivery(&mut store, "old-processed", 10, true);
        add_delivery(&mut store, "recent-processed", 100, true);
        add_delivery(&mut store, "old-in-flight", 5, false);

        assert_eq!(
            store
                .prune_processed_webhook_deliveries_before(50, false)
                .unwrap(),
            1
        );
        assert_eq!(
            store
                .connection
                .query_row("SELECT COUNT(*) FROM webhook_deliveries", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            3
        );
        assert_eq!(
            store
                .prune_processed_webhook_deliveries_before(50, true)
                .unwrap(),
            1
        );
        assert_eq!(
            store
                .prune_processed_webhook_deliveries_before(50, true)
                .unwrap(),
            0
        );
        assert_eq!(
            store
                .connection
                .query_row("SELECT COUNT(*) FROM webhook_deliveries", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            2
        );
        assert_eq!(
            store
                .claim_webhook_delivery(
                    "github",
                    "recent-processed",
                    "push",
                    2,
                    &digest(b"recent-processed"),
                    200,
                    60,
                )
                .unwrap(),
            WebhookClaim::AlreadyProcessed
        );
    }

    #[test]
    fn gate_requires_snapshot_matching_successful_verification_evidence() {
        let policy = Policy {
            block_severities: vec![],
            minimum_confidence: 0,
            required_review_complete: true,
            required_verifications: vec!["unit".into()],
            analyzer_block_levels: Default::default(),
        };
        let run = VerificationRun {
            schema_version: 1,
            run_id: "run-1".into(),
            snapshot_id: "snapshot-1".into(),
            profile_id: "unit".into(),
            finding_id: None,
            targets: Vec::new(),
            command_digest: digest(b"unit-command"),
            status: VerificationStatus::Passed,
            exit_code: Some(0),
            stdout_digest: digest(b""),
            stderr_digest: digest(b""),
            stdout_artifact: None,
            stderr_artifact: None,
        };
        let mut finding_specific = run.clone();
        finding_specific.finding_id = Some("find_target".into());
        assert_eq!(
            evaluate_gate(
                "snapshot-1",
                "config",
                "policy",
                &[],
                &policy,
                true,
                GateEvidence {
                    verification_runs: &[finding_specific],
                    source_evidence: &[],
                    analyzer_reports: &[],
                },
            )
            .status,
            GateStatus::Incomplete,
            "a finding-scoped check must not satisfy a snapshot-wide policy requirement"
        );
        let missing = evaluate_gate(
            "snapshot-1",
            "config",
            "policy",
            &[],
            &policy,
            true,
            GateEvidence {
                verification_runs: &[],
                source_evidence: &[],
                analyzer_reports: &[],
            },
        );
        assert_eq!(missing.status, GateStatus::Incomplete);
        assert!(missing.reasons.iter().any(|reason| reason.contains("unit")));

        let passed = evaluate_gate(
            "snapshot-1",
            "config",
            "policy",
            &[],
            &policy,
            true,
            GateEvidence {
                verification_runs: std::slice::from_ref(&run),
                source_evidence: &[],
                analyzer_reports: &[],
            },
        );
        assert_eq!(passed.status, GateStatus::Pass);
        assert_eq!(passed.verification_run_ids, vec!["run-1"]);
        let stale = evaluate_gate(
            "snapshot-2",
            "config",
            "policy",
            &[],
            &policy,
            true,
            GateEvidence {
                verification_runs: &[run],
                source_evidence: &[],
                analyzer_reports: &[],
            },
        );
        assert_eq!(stale.status, GateStatus::Incomplete);
        assert_ne!(passed.evidence_digest, stale.evidence_digest);

        let mut failed_latest = VerificationRun {
            run_id: "run-2".into(),
            status: VerificationStatus::Failed,
            exit_code: Some(1),
            ..passed_run_for_test()
        };
        failed_latest.profile_id = "unit".into();
        let regression = evaluate_gate(
            "snapshot-1",
            "config",
            "policy",
            &[],
            &policy,
            true,
            GateEvidence {
                verification_runs: &[failed_latest, passed_run_for_test()],
                source_evidence: &[],
                analyzer_reports: &[],
            },
        );
        assert_eq!(regression.status, GateStatus::Incomplete);
        assert_eq!(regression.verification_run_ids, vec!["run-2"]);

        let dir = tempfile::tempdir().unwrap();
        let mut store = ReviewStore::open(&dir.path().join("decisions.sqlite")).unwrap();
        let evidence = Evidence {
            id: "ev_source-1".into(),
            kind: EvidenceKind::Source,
            provenance: "source_snapshot".into(),
            source_path: "src/lib.rs".into(),
            start_line: Some(3),
            end_line: Some(3),
            content_digest: digest(b"source"),
            classification: EvidenceClassification::Observed,
            verification: EvidenceVerification::Unverified,
        };
        store
            .save_review_with_decision(ReviewWrite {
                id: "rev-1",
                snapshot_id: "snapshot-1",
                config_digest: "config",
                status: "pass",
                payload: "{}",
                findings: &[],
                evidence: std::slice::from_ref(&evidence),
                snapshot_manifest: "{}",
                decision: &passed,
            })
            .unwrap();
        assert_eq!(store.evidence_for_review("rev-1").unwrap(), vec![evidence]);
        let manifest = store.snapshot_manifest("snapshot-1").unwrap().unwrap();
        assert_eq!(manifest, "{}");
        let evidence_row: (String, String, String) = store
            .connection
            .query_row(
                "SELECT kind,classification,verification FROM evidence_records WHERE evidence_id='ev_source-1'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(
            evidence_row,
            ("source".into(), "observed".into(), "unverified".into())
        );
        store.save_gate_decision("rev-1", &regression).unwrap();
        store
            .save_review_with_decision(ReviewWrite {
                id: "rev-2",
                snapshot_id: "snapshot-1",
                config_digest: "config",
                status: "pass",
                payload: "{}",
                findings: &[],
                evidence: &[],
                snapshot_manifest: "{}",
                decision: &passed,
            })
            .unwrap();
        let history = store.gate_decisions_for_review("rev-1").unwrap();
        assert_eq!(history.len(), 2);
        assert_eq!(history[0], passed);
        assert_eq!(history[1], regression);
        assert_eq!(
            store.gate_decisions_for_review("rev-2").unwrap(),
            vec![passed]
        );
    }

    #[test]
    fn verification_store_migrates_legacy_table_and_persists_finding_scope() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("legacy.sqlite");
        let legacy = rusqlite::Connection::open(&path).unwrap();
        legacy
            .execute_batch("CREATE TABLE verification_runs (run_id TEXT PRIMARY KEY, snapshot_id TEXT NOT NULL, profile_id TEXT NOT NULL, command_digest TEXT NOT NULL, status TEXT NOT NULL, exit_code INTEGER, stdout_digest TEXT NOT NULL, stderr_digest TEXT NOT NULL, payload TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);")
            .unwrap();
        let existing = VerificationRun {
            schema_version: 1,
            run_id: "legacy-run".into(),
            snapshot_id: "legacy-snapshot".into(),
            profile_id: "unit".into(),
            finding_id: None,
            targets: Vec::new(),
            command_digest: digest(b"legacy-command"),
            status: VerificationStatus::Passed,
            exit_code: Some(0),
            stdout_digest: digest(b"legacy-stdout"),
            stderr_digest: digest(b""),
            stdout_artifact: None,
            stderr_artifact: None,
        };
        legacy
            .execute(
                "INSERT INTO verification_runs(run_id,snapshot_id,profile_id,command_digest,status,exit_code,stdout_digest,stderr_digest,payload) VALUES (?1,?2,?3,?4,'passed',0,?5,?6,?7)",
                rusqlite::params![
                    existing.run_id,
                    existing.snapshot_id,
                    existing.profile_id,
                    existing.command_digest,
                    existing.stdout_digest,
                    existing.stderr_digest,
                    serde_json::to_string(&existing).unwrap(),
                ],
            )
            .unwrap();
        drop(legacy);

        let mut store = ReviewStore::open(&path).unwrap();
        assert_eq!(
            store.verification("legacy-run").unwrap(),
            Some(existing),
            "migration must preserve existing verification records"
        );
        let run = VerificationRun {
            schema_version: 1,
            run_id: "targeted-run".into(),
            snapshot_id: "snapshot".into(),
            profile_id: "unit".into(),
            finding_id: Some("find_123".into()),
            targets: Vec::new(),
            command_digest: digest(b"command"),
            status: VerificationStatus::Passed,
            exit_code: Some(0),
            stdout_digest: digest(b""),
            stderr_digest: digest(b""),
            stdout_artifact: None,
            stderr_artifact: None,
        };
        store.save_verification(&run).unwrap();
        assert_eq!(store.verification("targeted-run").unwrap(), Some(run));
        let version: u32 = store
            .connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, STORAGE_SCHEMA_VERSION);
    }

    #[test]
    fn invalid_verification_artifact_rolls_back_run_and_artifact_rows() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = ReviewStore::open(&dir.path().join("artifact-rollback.sqlite")).unwrap();
        let mut run = passed_run_for_test();
        run.stdout_artifact = Some(ArtifactReference {
            digest: digest(b"wrong bytes"),
            path: ".vero/artifacts/sha256/0000000000000000000000000000000000000000000000000000000000000000".into(),
            size_bytes: 10,
        });

        assert!(store.save_verification_with_artifacts(&run).is_err());
        assert_eq!(store.verification(&run.run_id).unwrap(), None);
        assert_eq!(
            store.verification_artifact(&run.run_id, "stdout").unwrap(),
            None
        );
    }

    #[test]
    fn artifact_size_outside_sqlite_integer_range_rejects_verification_run() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = ReviewStore::open(&dir.path().join("artifact-size.sqlite")).unwrap();
        let mut run = passed_run_for_test();
        run.stdout_artifact = Some(ArtifactReference {
            digest: run.stdout_digest.clone(),
            path: format!(
                ".vero/artifacts/sha256/{}",
                run.stdout_digest.strip_prefix("sha256:").unwrap()
            ),
            size_bytes: u64::MAX,
        });

        assert!(store.save_verification_with_artifacts(&run).is_err());
        assert_eq!(store.verification(&run.run_id).unwrap(), None);
        assert_eq!(
            store.verification_artifact(&run.run_id, "stdout").unwrap(),
            None
        );
    }

    #[test]
    fn provider_cache_persists_only_under_exact_request_fingerprint() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = ReviewStore::open(&dir.path().join("provider-cache.sqlite")).unwrap();
        let request_key = digest(b"exact provider request");
        assert_eq!(store.provider_cache_get(&request_key).unwrap(), None);

        store
            .provider_cache_put(&request_key, "codex 1.2.3", b"{\"findings\":[]}")
            .unwrap();

        assert_eq!(
            store.provider_cache_get(&request_key).unwrap(),
            Some(b"{\"findings\":[]}".to_vec())
        );
        assert_eq!(
            store
                .provider_cache_get(&digest(b"different request"))
                .unwrap(),
            None
        );
        store
            .connection
            .execute(
                "UPDATE provider_cache SET stdout=?1 WHERE request_key=?2",
                rusqlite::params![b"tampered".as_slice(), request_key],
            )
            .unwrap();
        assert!(store.provider_cache_get(&request_key).is_err());
        let version: u32 = store
            .connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, STORAGE_SCHEMA_VERSION);
    }

    #[test]
    fn review_store_rejects_a_database_from_a_newer_schema_version() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("future.sqlite");
        let future = rusqlite::Connection::open(&path).unwrap();
        future.pragma_update(None, "user_version", 99).unwrap();
        drop(future);

        let error = match ReviewStore::open(&path) {
            Ok(_) => panic!("future schema version should be rejected"),
            Err(error) => error,
        };

        assert!(error.contains("schema version 99"));
    }

    #[test]
    fn version_two_gate_history_migrates_config_digest_from_review() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v2.sqlite");
        let legacy = rusqlite::Connection::open(&path).unwrap();
        legacy
            .execute_batch(
                "CREATE TABLE reviews (id TEXT PRIMARY KEY, config_digest TEXT NOT NULL);
                CREATE TABLE verification_runs (run_id TEXT PRIMARY KEY);
                CREATE TABLE gate_decisions (decision_id TEXT NOT NULL, review_id TEXT NOT NULL, snapshot_id TEXT NOT NULL, policy_digest TEXT NOT NULL, evidence_digest TEXT NOT NULL, status TEXT NOT NULL, payload TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY(review_id,decision_id));
                INSERT INTO reviews(id,config_digest) VALUES ('rev-old','sha256:config');
                INSERT INTO gate_decisions(decision_id,review_id,snapshot_id,policy_digest,evidence_digest,status,payload) VALUES ('sha256:decision','rev-old','sha256:snapshot','sha256:policy','sha256:evidence','pass','{\"schema_version\":1,\"decision_id\":\"sha256:decision\",\"snapshot_id\":\"sha256:snapshot\",\"policy_digest\":\"sha256:policy\",\"status\":\"pass\",\"blocking_findings\":[],\"verification_run_ids\":[],\"evidence_digest\":\"sha256:evidence\",\"reasons\":[]}');
                PRAGMA user_version=2;",
            )
            .unwrap();
        drop(legacy);

        let store = ReviewStore::open(&path).unwrap();
        let decisions = store.gate_decisions_for_review("rev-old").unwrap();
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].effective_config_digest, "sha256:config");
    }

    #[test]
    fn failed_storage_migration_rolls_back_schema_changes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("invalid-v1.sqlite");
        let legacy = rusqlite::Connection::open(&path).unwrap();
        legacy
            .execute_batch(
                "CREATE TABLE verification_runs (run_id TEXT PRIMARY KEY);
                PRAGMA user_version=1;",
            )
            .unwrap();
        drop(legacy);

        assert!(ReviewStore::open(&path).is_err());
        let check = rusqlite::Connection::open(&path).unwrap();
        let version: u32 = check
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        let has_finding_id: bool = check
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM pragma_table_info('verification_runs') WHERE name='finding_id')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(version, 1);
        assert!(!has_finding_id, "failed migration must roll back its ALTER");
    }

    #[test]
    fn review_store_persists_payload_and_staleness_is_exact() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = ReviewStore::open(&dir.path().join("reviews.sqlite")).unwrap();
        store
            .save(
                "rev_1",
                "sha256:a",
                "sha256:c",
                "incomplete",
                "{\"status\":\"incomplete\"}",
            )
            .unwrap();
        assert_eq!(
            store.get("rev_1").unwrap().as_deref(),
            Some("{\"status\":\"incomplete\"}")
        );
        assert!(snapshot_is_current("sha256:a", "sha256:a"));
        assert!(!snapshot_is_current("sha256:a", "sha256:b"));
    }

    #[test]
    fn snapshot_manifest_is_immutable_per_snapshot_identity() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = ReviewStore::open(&dir.path().join("snapshot-manifest.sqlite")).unwrap();
        let change_set = ChangeSet::from_entries(None, None, "working_tree", vec![]);
        let manifest = serde_json::to_string(&(
            change_set.schema_version,
            change_set.base_oid.as_deref(),
            change_set.head_oid.as_deref(),
            change_set.scope.as_str(),
            &change_set.files,
        ))
        .unwrap();
        let decision = GateDecision {
            schema_version: 1,
            decision_id: "decision-b".into(),
            snapshot_id: change_set.digest.clone(),
            effective_config_digest: "config".into(),
            policy_digest: "policy".into(),
            status: GateStatus::Pass,
            blocking_findings: vec![],
            verification_run_ids: vec![],
            evidence_digest: "evidence".into(),
            reasons: vec![],
            replay_inputs: None,
        };
        store
            .save_review_with_decision(ReviewWrite {
                id: "rev-a",
                snapshot_id: &change_set.digest,
                config_digest: "config",
                status: "pass",
                payload: "{}",
                findings: &[],
                evidence: &[],
                snapshot_manifest: &manifest,
                decision: &decision,
            })
            .unwrap();
        let conflict = store.save_review_with_decision(ReviewWrite {
            id: "rev-b",
            snapshot_id: &change_set.digest,
            config_digest: "config",
            status: "pass",
            payload: "{}",
            findings: &[],
            evidence: &[],
            snapshot_manifest: "{}",
            decision: &decision,
        });
        assert!(conflict.unwrap_err().contains("different manifest"));
        assert!(store.get("rev-b").unwrap().is_none());
    }

    #[test]
    fn evidence_identity_can_recur_across_reviews_for_the_same_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = ReviewStore::open(&dir.path().join("evidence-occurrences.sqlite")).unwrap();
        let evidence = Evidence {
            id: "ev-stable".into(),
            kind: EvidenceKind::Source,
            provenance: "snapshot".into(),
            source_path: "src/lib.rs".into(),
            start_line: Some(1),
            end_line: Some(1),
            content_digest: digest(b"same source"),
            classification: EvidenceClassification::Observed,
            verification: EvidenceVerification::Unverified,
        };
        let decision = GateDecision {
            schema_version: 1,
            decision_id: "decision-1".into(),
            snapshot_id: "snapshot-1".into(),
            effective_config_digest: "config".into(),
            policy_digest: "policy".into(),
            status: GateStatus::Pass,
            blocking_findings: vec![],
            verification_run_ids: vec![],
            evidence_digest: "evidence".into(),
            reasons: vec![],
            replay_inputs: None,
        };
        for review_id in ["rev-1", "rev-2"] {
            store
                .save_review_with_decision(ReviewWrite {
                    id: review_id,
                    snapshot_id: "snapshot-1",
                    config_digest: "config",
                    status: "pass",
                    payload: "{}",
                    findings: &[],
                    evidence: std::slice::from_ref(&evidence),
                    snapshot_manifest: "{}",
                    decision: &decision,
                })
                .unwrap();
        }
        assert_eq!(
            store.evidence_for_review("rev-1").unwrap(),
            vec![evidence.clone()]
        );
        assert_eq!(store.evidence_for_review("rev-2").unwrap(), vec![evidence]);
    }

    #[test]
    fn schema_six_migration_backfills_normalized_evidence_records() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("evidence-v5.sqlite");
        let mut store = ReviewStore::open(&path).unwrap();
        let evidence = Evidence {
            id: "ev-legacy".into(),
            kind: EvidenceKind::Source,
            provenance: "snapshot".into(),
            source_path: "src/lib.rs".into(),
            start_line: Some(2),
            end_line: Some(2),
            content_digest: digest(b"legacy source"),
            classification: EvidenceClassification::Observed,
            verification: EvidenceVerification::Unverified,
        };
        let change_set = ChangeSet::from_entries(
            Some("base-oid".into()),
            Some("head-oid".into()),
            "base",
            vec![SnapshotFile {
                path: "src/lib.rs".into(),
                mode: 0o100644,
                content_digest: digest(b"legacy source"),
                status: "modified".into(),
            }],
        );
        let payload = serde_json::json!({ "change_set": change_set.clone() });
        let payload = serde_json::to_string(&payload).unwrap();
        let decision = GateDecision {
            schema_version: 1,
            decision_id: "decision-legacy".into(),
            snapshot_id: change_set.digest.clone(),
            effective_config_digest: "config".into(),
            policy_digest: "policy".into(),
            status: GateStatus::Pass,
            blocking_findings: vec![],
            verification_run_ids: vec![],
            evidence_digest: "evidence".into(),
            reasons: vec![],
            replay_inputs: None,
        };
        store
            .save_review_with_decision(ReviewWrite {
                id: "rev-legacy",
                snapshot_id: &change_set.digest,
                config_digest: "config",
                status: "pass",
                payload: &payload,
                findings: &[],
                evidence: std::slice::from_ref(&evidence),
                snapshot_manifest: "{}",
                decision: &decision,
            })
            .unwrap();
        drop(store);
        let legacy = rusqlite::Connection::open(&path).unwrap();
        legacy
            .execute_batch(
                "DROP TABLE evidence_records; DROP TABLE snapshots; PRAGMA user_version=5;",
            )
            .unwrap();
        drop(legacy);

        let upgraded = ReviewStore::open(&path).unwrap();
        assert_eq!(
            upgraded.evidence_for_review("rev-legacy").unwrap(),
            vec![evidence]
        );
        let expected_manifest = serde_json::to_string(&(
            change_set.schema_version,
            change_set.base_oid.as_deref(),
            change_set.head_oid.as_deref(),
            change_set.scope.as_str(),
            &change_set.files,
        ))
        .unwrap();
        assert_eq!(
            upgraded
                .snapshot_manifest(&change_set.digest)
                .unwrap()
                .as_deref(),
            Some(expected_manifest.as_str())
        );
    }

    #[test]
    fn finding_lifecycle_tracks_occurrences_filters_and_reopens_resolved_items() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = ReviewStore::open(&dir.path().join("lifecycle.sqlite")).unwrap();
        let mut item = finding("id-one", Severity::High, Some(95));
        item.fingerprint = "stable-fingerprint".into();
        item.rationale = "unsafe operation".into();
        store
            .save_review("rev-1", "snap-1", "cfg", "block", "{}", &[item.clone()])
            .unwrap();
        let feedback = store
            .add_finding_feedback(
                "id-one",
                "snap-1",
                FindingFeedbackLabel::Confirmed,
                "Reproduced the boundary defect",
                "reviewer@example.invalid",
            )
            .unwrap();
        assert_eq!(feedback.label, FindingFeedbackLabel::Confirmed);
        assert_eq!(
            store.list_finding_feedback().unwrap(),
            vec![feedback.clone()]
        );
        assert_eq!(
            store
                .add_finding_feedback(
                    "id-one",
                    "snap-1",
                    FindingFeedbackLabel::Confirmed,
                    "Reproduced the boundary defect",
                    "reviewer@example.invalid",
                )
                .unwrap(),
            feedback,
            "repeating the same label should be idempotent"
        );
        assert!(store
            .add_finding_feedback(
                "id-one",
                "unrelated-snapshot",
                FindingFeedbackLabel::FalsePositive,
                "No issue",
                "reviewer@example.invalid",
            )
            .is_err());
        let waiver = Waiver {
            schema_version: 1,
            id: "waiver-snap-1".into(),
            finding_fingerprint: item.fingerprint.clone(),
            snapshot_id: "snap-1".into(),
            reason: "Temporary accepted risk".into(),
            author: "maintainer".into(),
            provenance: "local_cli".into(),
            created_at_unix: 10,
            expires_at_unix: 20,
        };
        store.create_waiver(&waiver).unwrap();
        assert_eq!(store.waivers_for_snapshot("snap-1").unwrap(), vec![waiver]);
        store
            .set_finding_status(
                "id-one",
                FindingStatus::Verified,
                "reviewed source evidence",
            )
            .unwrap();
        let mut later_assessment = item.clone();
        later_assessment.rationale = "updated after the earlier review".into();
        store
            .save_review("rev-2", "snap-2", "cfg", "block", "{}", &[later_assessment])
            .unwrap();
        let verified = store.finding("id-one").unwrap().unwrap();
        assert_eq!(verified.status, FindingStatus::Verified);
        assert_eq!(verified.occurrence_count, 2);
        assert_eq!(verified.occurrences.len(), 2);
        assert_eq!(verified.occurrences[1].review_id, "rev-2");
        assert_eq!(verified.occurrences[1].snapshot_id, "snap-2");
        let first_review = store.list_findings(None, None, Some("rev-1")).unwrap();
        assert_eq!(first_review.len(), 1);
        assert_eq!(first_review[0].assessments.len(), 1);
        assert_eq!(first_review[0].assessments[0].rationale, "unsafe operation");
        let (first_page, first_total) = store
            .list_findings_page(None, None, Some("rev-1"), 10, 0)
            .unwrap();
        assert_eq!(first_total, 1);
        assert_eq!(first_page[0].assessments.len(), 1);
        assert_eq!(first_page[0].assessments[0].rationale, "unsafe operation");
        store
            .set_finding_status("id-one", FindingStatus::Resolved, "fixed in change")
            .unwrap();
        store
            .save_review("rev-3", "snap-3", "cfg", "block", "{}", &[item])
            .unwrap();
        let reopened = store.finding("id-one").unwrap().unwrap();
        assert_eq!(reopened.status, FindingStatus::Open);
        assert_eq!(reopened.occurrence_count, 3);
        assert_eq!(
            store
                .list_findings(Some(Severity::High), Some(FindingStatus::Open), None)
                .unwrap()
                .len(),
            1
        );
        assert!(store
            .list_findings(Some(Severity::Low), None, None)
            .unwrap()
            .is_empty());
        assert!(store
            .set_finding_status("id-one", FindingStatus::Waived, "ignore")
            .unwrap_err()
            .contains("use the waiver workflow"));
    }

    #[test]
    fn review_storage_consolidates_duplicate_fingerprint_occurrences() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = ReviewStore::open(&dir.path().join("duplicate-findings.sqlite")).unwrap();
        let mut first = finding("same-finding", Severity::Critical, Some(40));
        first.fingerprint = "same-fingerprint".into();
        first.rationale = "critical model rationale".into();
        first.reviewer_ids = vec!["correctness".into()];
        let mut second = finding("same-finding", Severity::High, Some(95));
        second.fingerprint = "same-fingerprint".into();
        second.rationale = "high model rationale".into();
        second.reviewer_ids = vec!["security".into()];
        store
            .save_review(
                "duplicate-review",
                "duplicate-snapshot",
                "config",
                "block",
                "{}",
                &[first, second],
            )
            .unwrap();
        let saved = store.finding("same-finding").unwrap().unwrap();
        assert_eq!(saved.occurrences.len(), 1);
        assert_eq!(saved.finding.severity, Severity::Critical);
        assert_eq!(saved.finding.confidence, Some(40));
        assert_eq!(saved.finding.rationale, "critical model rationale");
        assert!(saved
            .assessments
            .iter()
            .any(|entry| entry.severity == Severity::High
                && entry.confidence == Some(95)
                && entry.rationale == "high model rationale"));
        assert!(saved
            .assessments
            .iter()
            .any(|entry| entry.severity == Severity::Critical
                && entry.confidence == Some(40)
                && entry.rationale == "critical model rationale"));
        assert_eq!(saved.finding.reviewer_ids, vec!["correctness", "security"]);
        let high = store
            .list_findings(Some(Severity::High), None, Some("duplicate-review"))
            .unwrap();
        assert_eq!(high.len(), 1);
        assert!(high[0]
            .assessments
            .iter()
            .any(|assessment| assessment.severity == Severity::High));
        let (high_page, high_count) = store
            .list_findings_page(Some(Severity::High), None, Some("duplicate-review"), 1, 0)
            .unwrap();
        assert_eq!(high_count, 1);
        assert_eq!(high_page.len(), 1);
        let mut later = finding("same-finding", Severity::Low, Some(70));
        later.fingerprint = "same-fingerprint".into();
        store
            .save_review(
                "later-review",
                "later-snapshot",
                "config",
                "pass",
                "{}",
                &[later],
            )
            .unwrap();
        assert!(store
            .list_findings(Some(Severity::Low), None, Some("duplicate-review"))
            .unwrap()
            .is_empty());
        assert!(store
            .list_findings_page(Some(Severity::Low), None, Some("duplicate-review"), 1, 0)
            .unwrap()
            .0
            .is_empty());
        assert_eq!(
            store
                .list_findings(Some(Severity::Low), None, Some("later-review"))
                .unwrap()
                .len(),
            1
        );
        assert!(store
            .list_findings(Some(Severity::High), None, None)
            .unwrap()
            .is_empty());
        let (old_high_page, old_high_count) = store
            .list_findings_page(Some(Severity::High), None, None, 10, 0)
            .unwrap();
        assert!(old_high_page.is_empty());
        assert_eq!(old_high_count, 0);
        assert_eq!(
            store
                .list_findings(Some(Severity::Low), None, None)
                .unwrap()
                .len(),
            1
        );
        assert!(store
            .list_findings(Some(Severity::Critical), None, Some("later-review"))
            .unwrap()
            .is_empty());
    }

    #[test]
    fn global_severity_filter_uses_insertion_order_when_review_ids_sort_backwards() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = ReviewStore::open(&dir.path().join("occurrence-order.sqlite")).unwrap();
        let mut old = finding("ordered-finding", Severity::High, Some(90));
        old.fingerprint = "ordered-fingerprint".into();
        store
            .save_review("rev-z-old", "snapshot-old", "config", "block", "{}", &[old])
            .unwrap();
        let mut latest = finding("ordered-finding", Severity::Low, Some(70));
        latest.fingerprint = "ordered-fingerprint".into();
        store
            .save_review(
                "rev-a-new",
                "snapshot-new",
                "config",
                "pass",
                "{}",
                &[latest],
            )
            .unwrap();

        assert!(store
            .list_findings(Some(Severity::High), None, None)
            .unwrap()
            .is_empty());
        assert_eq!(
            store
                .list_findings(Some(Severity::Low), None, None)
                .unwrap()
                .len(),
            1
        );
        let (high_page, high_count) = store
            .list_findings_page(Some(Severity::High), None, None, 10, 0)
            .unwrap();
        assert!(high_page.is_empty());
        assert_eq!(high_count, 0);
    }

    #[test]
    fn review_storage_preserves_initial_assessment_when_later_severity_wins() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = ReviewStore::open(&dir.path().join("duplicate-order.sqlite")).unwrap();
        let mut first = finding("order-finding", Severity::High, Some(95));
        first.fingerprint = "order-fingerprint".into();
        first.rationale = "high model rationale".into();
        let mut second = finding("order-finding", Severity::Critical, Some(40));
        second.fingerprint = "order-fingerprint".into();
        second.rationale = "critical model rationale".into();
        store
            .save_review(
                "order-review",
                "order-snapshot",
                "config",
                "block",
                "{}",
                &[first, second],
            )
            .unwrap();
        let saved = store.finding("order-finding").unwrap().unwrap();
        assert_eq!(saved.finding.severity, Severity::Critical);
        assert_eq!(saved.finding.confidence, Some(40));
        assert_eq!(saved.finding.rationale, "critical model rationale");
        assert!(saved
            .assessments
            .iter()
            .any(|entry| entry.severity == Severity::High
                && entry.confidence == Some(95)
                && entry.rationale == "high model rationale"));
        assert!(saved
            .assessments
            .iter()
            .any(|entry| entry.severity == Severity::Critical
                && entry.confidence == Some(40)
                && entry.rationale == "critical model rationale"));
    }

    #[test]
    fn rule_approval_is_persisted_and_revocation_is_append_only() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = ReviewStore::open(&dir.path().join("rule-approvals.sqlite")).unwrap();
        let approval = RuleApproval {
            schema_version: 2,
            approval_id: "approval-1".into(),
            version: 1,
            candidate_id: "candidate-1".into(),
            evidence_digest: format!("sha256:{}", "a".repeat(64)),
            source_feedback_ids: vec!["feedback-1".into()],
            activated_at_unix: None,
            category: "correctness".into(),
            feedback_label: FindingFeedbackLabel::NotActionable,
            scope: "src/parser.rs".into(),
            instruction: "Require a reproducer for parser edge cases.".into(),
            approver: "maintainer".into(),
            approval_reason: "Repeated feedback supports this scoped guidance.".into(),
            supersedes_approval_id: None,
            expires_at_unix: None,
            created_at: String::new(),
            status: String::new(),
            events: Vec::new(),
        };
        store.create_rule_approval(&approval).unwrap();
        let saved = store.list_rule_approvals().unwrap();
        assert_eq!(saved.len(), 1);
        assert_eq!(saved[0].status, "active");
        assert_eq!(saved[0].events.len(), 1);
        assert_eq!(saved[0].version, 1);
        let replacement = RuleApproval {
            schema_version: 2,
            approval_id: "approval-2".into(),
            version: 1,
            supersedes_approval_id: Some("approval-1".into()),
            ..approval.clone()
        };
        store.create_rule_approval(&replacement).unwrap();
        let versions = store.list_rule_approvals().unwrap();
        assert_eq!(versions[0].status, "superseded");
        assert_eq!(versions[1].version, 2);
        store
            .revoke_rule_approval("approval-2", "maintainer", "Guidance is obsolete")
            .unwrap();
        let revoked = store.list_rule_approvals().unwrap();
        assert_eq!(revoked[1].status, "revoked");
        assert_eq!(revoked[1].events.len(), 2);
        assert_eq!(revoked[1].events[1].event, "revoked");
        assert!(store
            .revoke_rule_approval("approval-2", "maintainer", "duplicate")
            .is_err());
    }

    #[test]
    fn expired_rule_approval_is_inactive_and_version_numbers_continue() {
        let dir = tempfile::tempdir().unwrap();
        let database = dir.path().join("expired-rule-approval.sqlite");
        let mut store = ReviewStore::open(&database).unwrap();
        let approval = RuleApproval {
            schema_version: 2,
            approval_id: "approval-expiring".into(),
            version: 1,
            candidate_id: "candidate-expiring".into(),
            evidence_digest: format!("sha256:{}", "c".repeat(64)),
            source_feedback_ids: vec!["feedback-expiring".into()],
            activated_at_unix: None,
            category: "correctness".into(),
            feedback_label: FindingFeedbackLabel::NotActionable,
            scope: "src/parser.rs".into(),
            instruction: "Keep this reviewer guidance temporary.".into(),
            approver: "maintainer".into(),
            approval_reason: "Temporary experiment.".into(),
            supersedes_approval_id: None,
            expires_at_unix: Some(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64
                    + 3600,
            ),
            created_at: String::new(),
            status: String::new(),
            events: Vec::new(),
        };
        store.create_rule_approval(&approval).unwrap();
        let connection = &store.connection;
        let mut stored: RuleApproval = serde_json::from_str(
            &connection
                .query_row::<String, _, _>(
                    "SELECT payload FROM rule_approvals WHERE approval_id='approval-expiring'",
                    [],
                    |row| row.get(0),
                )
                .unwrap(),
        )
        .unwrap();
        stored.expires_at_unix = Some(0);
        connection
            .execute(
                "UPDATE rule_approvals SET payload=?1 WHERE approval_id='approval-expiring'",
                [serde_json::to_string(&stored).unwrap()],
            )
            .unwrap();
        let expired = store.list_rule_approvals().unwrap();
        assert_eq!(expired[0].status, "expired");
        let mut replacement = approval;
        replacement.approval_id = "approval-after-expiry".into();
        replacement.expires_at_unix = None;
        store.create_rule_approval(&replacement).unwrap();
        let versions = store.list_rule_approvals().unwrap();
        let replacement = versions
            .iter()
            .find(|item| item.approval_id == "approval-after-expiry")
            .unwrap();
        assert_eq!(replacement.version, 2);
        assert_eq!(replacement.status, "active");
    }

    #[test]
    fn finding_pages_apply_limit_and_offset_in_storage_and_return_filtered_total() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = ReviewStore::open(&dir.path().join("finding-pages.sqlite")).unwrap();
        let findings = [
            finding("id-one", Severity::High, Some(90)),
            finding("id-two", Severity::Low, Some(80)),
            finding("id-three", Severity::High, Some(70)),
        ];
        store
            .save_review("rev-pages", "snap-pages", "cfg", "block", "{}", &findings)
            .unwrap();

        let (page, total) = store
            .list_findings_page(None, None, Some("rev-pages"), 2, 1)
            .unwrap();
        assert_eq!(total, 3);
        assert_eq!(page.len(), 2);
        let (high_page, high_total) = store
            .list_findings_page(Some(Severity::High), None, Some("rev-pages"), 1, 1)
            .unwrap();
        assert_eq!(high_total, 2);
        assert_eq!(high_page.len(), 1);
        let (empty_page, total) = store
            .list_findings_page(None, None, Some("rev-pages"), 2, 9)
            .unwrap();
        assert_eq!(total, 3);
        assert!(empty_page.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn verification_runs_explicit_argv_and_records_deterministic_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let profile = VerificationProfile {
            egress: Default::default(),
            executable: "/bin/sh".into(),
            args: vec!["-c".into(), "printf ok; exit 7".into()],
            timeout_seconds: 2,
            output_limit_bytes: 64,
            env_allowlist: vec![],
            sarif: None,
        };
        let first = execute_verification("snapshot-1", "tests", dir.path(), &profile).unwrap();
        let second = execute_verification("snapshot-1", "tests", dir.path(), &profile).unwrap();
        assert_eq!(first.status, VerificationStatus::Failed);
        assert_eq!(first.exit_code, Some(7));
        assert_eq!(first.stdout_digest, second.stdout_digest);
        assert_eq!(first.command_digest, second.command_digest);
        assert_eq!(first.snapshot_id, "snapshot-1");
        let db = dir.path().join("verification.sqlite");
        let mut store = ReviewStore::open(&db).unwrap();
        store.save_verification(&first).unwrap();
        assert_eq!(store.verification(&first.run_id).unwrap(), Some(first));
    }
}
