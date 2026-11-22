//! Trusted static analyzers that emit SARIF 2.1.0.
//!
//! A verification profile with a `sarif` section is a trusted analyzer: Vee runs
//! its configured command, keeps stdout as a content-addressed artifact, and derives
//! an [`AnalyzerReport`] containing only results located on changed lines of the
//! verified snapshot. Results elsewhere are pre-existing and never block. The
//! report is deterministic for a given artifact and snapshot, and it is stored in
//! the gate's replay inputs, so a replayed decision does not re-run the analyzer.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use vee_core::{
    AnalyzerFinding, AnalyzerReport, ArtifactReference, ChangeSet, RepositoryConfig, SarifLevel,
    VerificationRun, VerificationStatus,
};

/// Upper bound on SARIF bytes read from one run.
const MAX_SARIF_BYTES: u64 = 16 * 1024 * 1024;
/// Upper bound on results inspected per run; further results make the report incomplete.
const MAX_RESULTS: usize = 20_000;
const MAX_MESSAGE_CHARS: usize = 1_000;
const MAX_DIFF_INPUT_BYTES: usize = 4 * 1024 * 1024;
const MAX_DIFF_OUTPUT_BYTES: usize = 8 * 1024 * 1024;

/// Blocking SARIF levels for each required verification profile that is an analyzer.
pub fn analyzer_block_levels(config: &RepositoryConfig) -> BTreeMap<String, Vec<SarifLevel>> {
    config
        .policy
        .required_verifications
        .iter()
        .filter_map(|profile_id| {
            let sarif = config.verification.get(profile_id)?.sarif.as_ref()?;
            let mut levels = sarif.block_levels.clone();
            levels.sort();
            levels.dedup();
            Some((profile_id.clone(), levels))
        })
        .collect()
}

/// Reports for the gate-eligible runs of analyzer profiles on `change_set`.
pub fn analyzer_reports(
    root: &Path,
    change_set: &ChangeSet,
    config: &RepositoryConfig,
    runs: &[VerificationRun],
) -> Vec<AnalyzerReport> {
    let analyzers = analyzer_block_levels(config);
    if analyzers.is_empty() {
        return Vec::new();
    }
    let changed = ChangedLines::compute(root, change_set);
    runs.iter()
        .filter(|run| {
            run.snapshot_id == change_set.digest
                && run.finding_id.is_none()
                && analyzers.contains_key(&run.profile_id)
        })
        .map(|run| report_with_changes(root, run, &changed))
        .collect()
}

/// Analyze one SARIF run against the snapshot it verified.
pub fn analyze_run(root: &Path, change_set: &ChangeSet, run: &VerificationRun) -> AnalyzerReport {
    if run.snapshot_id != change_set.digest {
        return failed(
            run,
            "verification run and change snapshot do not match".into(),
        );
    }
    report_with_changes(root, run, &ChangedLines::compute(root, change_set))
}

fn failed(run: &VerificationRun, problem: String) -> AnalyzerReport {
    AnalyzerReport {
        schema_version: 1,
        run_id: run.run_id.clone(),
        profile_id: run.profile_id.clone(),
        snapshot_id: run.snapshot_id.clone(),
        tools: Vec::new(),
        parsed: false,
        problem: Some(problem),
        findings: Vec::new(),
        results_total: 0,
        results_suppressed: 0,
        results_outside_changes: 0,
        limitations: Vec::new(),
    }
}

/// Changed (added or modified) line numbers per changed file, with each file's
/// current text for fingerprinting.
struct ChangedLines {
    files: BTreeMap<String, (BTreeSet<u64>, Vec<String>)>,
    limitations: Vec<String>,
}

impl ChangedLines {
    fn compute(root: &Path, change_set: &ChangeSet) -> Self {
        let mut files = BTreeMap::new();
        let mut limitations = Vec::new();
        for file in &change_set.files {
            if file.status == "deleted" {
                continue;
            }
            let relative = Path::new(&file.path);
            let current = match vee_git::read_snapshot_file(root, change_set, relative) {
                Ok(Some(bytes)) => bytes,
                Ok(None) => continue,
                Err(error) => {
                    limitations.push(format!("{}: {error}", file.path));
                    continue;
                }
            };
            let baseline = vee_git::read_snapshot_base_file(root, change_set, relative)
                .ok()
                .flatten();
            let too_large = current.len() > MAX_DIFF_INPUT_BYTES
                || baseline
                    .as_ref()
                    .is_some_and(|bytes| bytes.len() > MAX_DIFF_INPUT_BYTES);
            let current_text = std::str::from_utf8(&current).ok();
            let baseline_text = baseline
                .as_deref()
                .and_then(|bytes| std::str::from_utf8(bytes).ok());
            if too_large
                || current_text.is_none()
                || (baseline.is_some() && baseline_text.is_none())
            {
                limitations.push(format!(
                    "{}: changed lines are unavailable (binary or larger than the diff bound); its analyzer results cannot block",
                    file.path
                ));
                continue;
            }
            let lines = match crate::changed_line_numbers(
                baseline_text.map(str::as_bytes),
                current_text.map(str::as_bytes),
                MAX_DIFF_OUTPUT_BYTES,
            ) {
                Ok(Some(lines)) => lines,
                Ok(None) | Err(_) => {
                    limitations.push(format!(
                        "{}: changed lines could not be computed; its analyzer results cannot block",
                        file.path
                    ));
                    continue;
                }
            };
            let text = current_text
                .unwrap_or_default()
                .lines()
                .map(str::to_owned)
                .collect();
            files.insert(file.path.clone(), (lines, text));
        }
        Self { files, limitations }
    }
}

fn report_with_changes(
    root: &Path,
    run: &VerificationRun,
    changed: &ChangedLines,
) -> AnalyzerReport {
    if !matches!(
        run.status,
        VerificationStatus::Passed | VerificationStatus::Failed
    ) {
        return failed(
            run,
            format!("analyzer run did not finish ({:?})", run.status),
        );
    }
    let Some(artifact) = run.stdout_artifact.as_ref() else {
        return failed(run, "analyzer run has no stdout artifact".into());
    };
    let bytes = match read_verification_artifact(root, artifact, MAX_SARIF_BYTES) {
        Ok(bytes) => bytes,
        Err(error) => return failed(run, format!("SARIF artifact is unusable: {error}")),
    };
    let document: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(document) => document,
        Err(error) => return failed(run, format!("stdout is not SARIF JSON: {error}")),
    };
    if document["version"].as_str() != Some("2.1.0") {
        return failed(run, "SARIF version must be 2.1.0".into());
    }
    let Some(sarif_runs) = document["runs"].as_array() else {
        return failed(run, "SARIF document has no runs array".into());
    };
    let canonical_root = match vee_core::paths::canonicalize(root) {
        Ok(path) => path,
        Err(error) => return failed(run, format!("cannot resolve repository root: {error}")),
    };
    let mut report = AnalyzerReport {
        schema_version: 1,
        run_id: run.run_id.clone(),
        profile_id: run.profile_id.clone(),
        snapshot_id: run.snapshot_id.clone(),
        tools: Vec::new(),
        parsed: true,
        problem: None,
        findings: Vec::new(),
        results_total: 0,
        results_suppressed: 0,
        results_outside_changes: 0,
        limitations: changed.limitations.clone(),
    };
    let mut seen = BTreeSet::new();
    for sarif_run in sarif_runs {
        let driver = &sarif_run["tool"]["driver"];
        if let Some(name) = driver["name"].as_str() {
            let version = driver["semanticVersion"]
                .as_str()
                .or_else(|| driver["version"].as_str());
            report.tools.push(match version {
                Some(version) => format!("{name} {version}"),
                None => name.to_owned(),
            });
        }
        for result in sarif_run["results"].as_array().into_iter().flatten() {
            if report.results_total >= MAX_RESULTS {
                report.limitations.push(format!(
                    "only the first {MAX_RESULTS} results were inspected"
                ));
                report.parsed = false;
                report.problem = Some("too many SARIF results to evaluate completely".into());
                return report;
            }
            report.results_total += 1;
            if is_suppressed(result) {
                report.results_suppressed += 1;
                continue;
            }
            let Some((path, line)) = result_location(result, sarif_run, &canonical_root) else {
                report.results_outside_changes += 1;
                continue;
            };
            let Some((lines, text)) = changed.files.get(&path) else {
                report.results_outside_changes += 1;
                continue;
            };
            if !lines.contains(&line) {
                report.results_outside_changes += 1;
                continue;
            }
            let rule_id = result["ruleId"]
                .as_str()
                .or_else(|| result["rule"]["id"].as_str())
                .unwrap_or("unknown-rule")
                .to_owned();
            let level = result_level(result, sarif_run);
            let source_line = usize::try_from(line - 1)
                .ok()
                .and_then(|index| text.get(index))
                .map_or("", |line| line.trim());
            let fingerprint = vee_core::digest(
                format!("{}\0{rule_id}\0{path}\0{source_line}", run.profile_id).as_bytes(),
            );
            if !seen.insert(fingerprint.clone()) {
                continue;
            }
            let message: String = result["message"]["text"]
                .as_str()
                .unwrap_or_default()
                .chars()
                .take(MAX_MESSAGE_CHARS)
                .collect();
            report.findings.push(AnalyzerFinding {
                id: format!("analyzer:{}:{}", run.profile_id, &fingerprint[7..19]),
                fingerprint,
                rule_id,
                level,
                path,
                line,
                message,
            });
        }
    }
    report
        .findings
        .sort_by(|a, b| (&a.path, a.line, &a.rule_id).cmp(&(&b.path, b.line, &b.rule_id)));
    report
}

/// A result the producing tool suppressed (for example an inline `nosemgrep` or a
/// CodeQL dismissal). Suppressions under review or rejected do not count.
fn is_suppressed(result: &serde_json::Value) -> bool {
    result["suppressions"]
        .as_array()
        .is_some_and(|suppressions| {
            suppressions.iter().any(|suppression| {
                matches!(suppression["status"].as_str(), None | Some("accepted"))
            })
        })
}

/// SARIF level: the result's own level, else the rule's default, else `warning`.
fn result_level(result: &serde_json::Value, sarif_run: &serde_json::Value) -> SarifLevel {
    let rule_default = || {
        let index = result["ruleIndex"].as_u64()?;
        sarif_run["tool"]["driver"]["rules"].get(usize::try_from(index).ok()?)?
            ["defaultConfiguration"]["level"]
            .as_str()
            .map(str::to_owned)
    };
    match result["level"]
        .as_str()
        .map(str::to_owned)
        .or_else(rule_default)
        .as_deref()
    {
        Some("error") => SarifLevel::Error,
        Some("note") => SarifLevel::Note,
        Some("none") => SarifLevel::None,
        _ => SarifLevel::Warning,
    }
}

/// The repository-relative path and start line of a result's first physical location.
fn result_location(
    result: &serde_json::Value,
    sarif_run: &serde_json::Value,
    root: &Path,
) -> Option<(String, u64)> {
    let physical = &result["locations"].get(0)?["physicalLocation"];
    let line = physical["region"]["startLine"]
        .as_u64()
        .filter(|line| *line > 0)?;
    let location = &physical["artifactLocation"];
    let uri = location["uri"].as_str()?;
    let base = location["uriBaseId"]
        .as_str()
        .and_then(|id| sarif_run["originalUriBaseIds"][id]["uri"].as_str());
    let path = resolve_uri(uri, base, root)?;
    Some((path, line))
}

fn resolve_uri(uri: &str, base: Option<&str>, root: &Path) -> Option<String> {
    let root_url = url::Url::from_directory_path(root).ok()?;
    let base_url = match base {
        Some(base) => root_url.join(base).ok()?,
        None => root_url,
    };
    let absolute: PathBuf = base_url.join(uri).ok()?.to_file_path().ok()?;
    let relative = absolute.strip_prefix(root).ok()?;
    if relative
        .components()
        .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return None;
    }
    Some(relative.to_string_lossy().replace('\\', "/"))
}

/// Read a verification artifact from `.vee/artifacts/sha256/`, checking its
/// recorded path, size, and content digest.
pub fn read_verification_artifact(
    root: &Path,
    artifact: &ArtifactReference,
    max_bytes: u64,
) -> Result<Vec<u8>, String> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let hex = artifact
        .digest
        .strip_prefix("sha256:")
        .filter(|hex| hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or("invalid artifact digest")?;
    let relative = Path::new(".vee/artifacts/sha256").join(hex);
    if Path::new(&artifact.path) != relative {
        return Err("artifact path does not match content digest".into());
    }
    let root = vee_core::paths::canonicalize(root).map_err(|error| error.to_string())?;
    let path = root.join(&relative);
    let metadata = std::fs::symlink_metadata(&path).map_err(|error| error.to_string())?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() != artifact.size_bytes
        || metadata.len() > max_bytes
    {
        return Err("artifact is not a bounded regular file with the recorded size".into());
    }
    let mut bytes = Vec::new();
    std::fs::File::open(&path)
        .map_err(|error| error.to_string())?
        .take(max_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if format!("sha256:{:x}", Sha256::digest(&bytes)) != artifact.digest {
        return Err("artifact content digest mismatch".into());
    }
    Ok(bytes)
}

/// Percent-encode a repository path as a SARIF artifact URI reference.
fn sarif_uri_reference(path: &str) -> String {
    let mut encoded = String::with_capacity(path.len());
    for byte in path.bytes() {
        if byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'-' | b'.'
                    | b'_'
                    | b'~'
                    | b'/'
                    | b'!'
                    | b'$'
                    | b'&'
                    | b'\''
                    | b'('
                    | b')'
                    | b'*'
                    | b'+'
                    | b','
                    | b';'
                    | b'='
                    | b':'
                    | b'@'
            )
        {
            encoded.push(char::from(byte));
        } else {
            use std::fmt::Write;
            write!(encoded, "%{byte:02X}").expect("writing into String cannot fail");
        }
    }
    encoded
}

/// A saved review as a SARIF 2.1.0 log, for `vee reviews export --format sarif`.
pub fn review_log(review: &crate::ReviewResult) -> serde_json::Value {
    let mut rules = std::collections::BTreeMap::<String, serde_json::Value>::new();
    let mut findings: Vec<_> = review.findings.iter().collect();
    findings.sort_by(|left, right| {
        left.fingerprint
            .cmp(&right.fingerprint)
            .then_with(|| left.id.cmp(&right.id))
    });
    let results = findings
        .into_iter()
        .map(|finding| {
            rules.entry(finding.category.clone()).or_insert_with(|| {
                serde_json::json!({
                    "id": finding.category,
                    "name": finding.category,
                    "shortDescription": {"text": finding.category}
                })
            });
            let level = match finding.severity {
                vee_core::Severity::Critical | vee_core::Severity::High => "error",
                vee_core::Severity::Medium => "warning",
                vee_core::Severity::Low | vee_core::Severity::Info => "note",
            };
            let locations = match (finding.path.as_deref(), finding.line) {
                (Some(path), Some(line)) => serde_json::json!([{
                    "physicalLocation": {
                        "artifactLocation": {"uri": sarif_uri_reference(path)},
                        "region": {"startLine": line}
                    }
                }]),
                (Some(path), None) => serde_json::json!([{
                    "physicalLocation": {"artifactLocation": {"uri": sarif_uri_reference(path)}}
                }]),
                _ => serde_json::Value::Array(Vec::new()),
            };
            serde_json::json!({
                "ruleId": finding.category,
                "level": level,
                "message": {"text": finding.rationale},
                "partialFingerprints": {"vee/v1": finding.fingerprint},
                "locations": locations,
                "properties": {
                    "veeFindingId": finding.id,
                    "confidence": finding.confidence,
                    "provenance": finding.provenance,
                    "evidenceIds": finding.evidence_ids
                }
            })
        })
        .collect::<Vec<_>>();
    let rules = rules.into_values().collect::<Vec<_>>();
    serde_json::json!({
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "Vee",
                "semanticVersion": env!("CARGO_PKG_VERSION"),
                "rules": rules
            }},
            "results": results,
            "invocations": [{
                "executionSuccessful": review.analysis_complete,
                "properties": {
                    "veeReviewId": review.review_id,
                    "veeSnapshotId": review.snapshot_id,
                    "veeGateStatus": review.status
                }
            }]
        }]
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sarif_uri_encodes_spaces_and_uri_delimiters() {
        assert_eq!(
            sarif_uri_reference("src/my file#1?.rs"),
            "src/my%20file%231%3F.rs"
        );
        assert_eq!(sarif_uri_reference("src/naïve.rs"), "src/na%C3%AFve.rs");
    }

    #[test]
    fn uris_resolve_inside_the_repository_only() {
        let root = tempfile::tempdir().unwrap();
        let root = vee_core::paths::canonicalize(root.path()).unwrap();
        assert_eq!(
            resolve_uri("src/a%20b.rs", None, &root).as_deref(),
            Some("src/a b.rs")
        );
        assert_eq!(
            resolve_uri("./src/lib.rs", None, &root).as_deref(),
            Some("src/lib.rs")
        );
        let absolute = url::Url::from_file_path(root.join("src/lib.rs")).unwrap();
        assert_eq!(
            resolve_uri(absolute.as_str(), None, &root).as_deref(),
            Some("src/lib.rs")
        );
        assert_eq!(
            resolve_uri("lib.rs", Some("src/"), &root).as_deref(),
            Some("src/lib.rs")
        );
        assert_eq!(resolve_uri("../outside.rs", None, &root), None);
        assert_eq!(resolve_uri("file:///etc/passwd", None, &root), None);
    }

    #[test]
    fn only_accepted_suppressions_suppress() {
        let with =
            |suppressions: serde_json::Value| serde_json::json!({ "suppressions": suppressions });
        assert!(is_suppressed(&with(
            serde_json::json!([{"kind": "inSource"}])
        )));
        assert!(is_suppressed(&with(
            serde_json::json!([{"kind": "external", "status": "accepted"}])
        )));
        assert!(!is_suppressed(&with(
            serde_json::json!([{"kind": "external", "status": "underReview"}])
        )));
        assert!(!is_suppressed(&with(
            serde_json::json!([{"kind": "external", "status": "rejected"}])
        )));
        assert!(!is_suppressed(&with(serde_json::json!([]))));
        assert!(!is_suppressed(&serde_json::json!({})));
    }

    #[test]
    fn level_falls_back_to_rule_default_then_warning() {
        let run = serde_json::json!({"tool":{"driver":{"rules":[{"defaultConfiguration":{"level":"error"}}]}}});
        assert_eq!(
            result_level(&serde_json::json!({"ruleIndex":0}), &run),
            SarifLevel::Error
        );
        assert_eq!(
            result_level(&serde_json::json!({"level":"note","ruleIndex":0}), &run),
            SarifLevel::Note
        );
        assert_eq!(
            result_level(&serde_json::json!({}), &run),
            SarifLevel::Warning
        );
    }
}
