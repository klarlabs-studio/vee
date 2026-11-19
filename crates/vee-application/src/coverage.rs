//! Snapshot-bound file and changed-line coverage summaries from LCOV output.
//! Changed executable-line metrics are emitted only when a bounded textual diff
//! can be computed from the exact captured base and current snapshot contents.
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use vee_core::{ArtifactReference, ChangeSet, SnapshotFile, VerificationRun};

const MAX_BYTES: u64 = 16 * 1024 * 1024;
const MAX_RECORDS: usize = 100_000;
const MAX_DIFF_INPUT_BYTES: usize = 8 * 1024 * 1024;
const MAX_DIFF_OUTPUT_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct CoverageReport {
    pub schema_version: u32,
    pub run_id: String,
    pub snapshot_id: String,
    pub profile_id: String,
    pub stream: String,
    pub measured_scope: String,
    pub files: Vec<FileCoverage>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct FileCoverage {
    pub path: String,
    pub covered_lines: u64,
    pub executable_lines: u64,
    pub percent: Option<f64>,
    pub changed_line_count: Option<u64>,
    pub changed_executable_lines: Option<u64>,
    pub changed_covered_lines: Option<u64>,
    pub changed_percent: Option<f64>,
}

#[derive(Default)]
struct ChangedLineCoverage {
    changed_lines: Option<u64>,
    executable_lines: Option<u64>,
    covered_lines: Option<u64>,
}

pub fn report(
    root: &Path,
    store: &dyn vee_core::ports::Repositories,
    run: &VerificationRun,
    stream: &str,
) -> Result<CoverageReport, String> {
    if run.finding_id.is_some() {
        return Err("coverage reports require a snapshot-wide verification run".into());
    }
    let manifest = store
        .snapshot_manifest(&run.snapshot_id)?
        .ok_or_else(|| "verification snapshot manifest is missing".to_owned())?;
    let change_set = parse_manifest(&manifest, &run.snapshot_id)?;
    report_for_change_set(root, run, stream, &change_set)
}

pub fn report_for_change_set(
    root: &Path,
    run: &VerificationRun,
    stream: &str,
    change_set: &ChangeSet,
) -> Result<CoverageReport, String> {
    if run.finding_id.is_some() {
        return Err("coverage reports require a snapshot-wide verification run".into());
    }
    if run.snapshot_id != change_set.digest {
        return Err("verification run and supplied change snapshot do not match".into());
    }
    let (artifact, stream) = match stream {
        "stdout" => (run.stdout_artifact.as_ref(), "stdout"),
        "stderr" => (run.stderr_artifact.as_ref(), "stderr"),
        _ => return Err("stream must be stdout or stderr".into()),
    };
    let artifact = artifact.ok_or_else(|| format!("verification run has no {stream} artifact"))?;
    let bytes = read_artifact(root, artifact)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| "LCOV artifact is not UTF-8".to_owned())?;
    let changed: BTreeSet<&str> = change_set
        .files
        .iter()
        .map(|file| file.path.as_str())
        .collect();
    let records = parse_lcov(text, root)?;
    let mut files = Vec::new();
    let mut seen = BTreeSet::new();
    for (path, lines) in records {
        if !changed.contains(path.as_str()) {
            continue;
        }
        seen.insert(path.clone());
        let executable_lines = lines.len() as u64;
        let covered_lines = lines.values().filter(|hits| **hits > 0).count() as u64;
        let changed = changed_line_coverage(root, change_set, &path, &lines)?;
        files.push(FileCoverage {
            path,
            covered_lines,
            executable_lines,
            percent: (executable_lines > 0)
                .then(|| covered_lines as f64 * 100.0 / executable_lines as f64),
            changed_line_count: changed.changed_lines,
            changed_executable_lines: changed.executable_lines,
            changed_covered_lines: changed.covered_lines,
            changed_percent: changed
                .executable_lines
                .filter(|count| *count > 0)
                .zip(changed.covered_lines)
                .map(|(executable, covered)| covered as f64 * 100.0 / executable as f64),
        });
    }
    let mut limitations = vec![
        "LCOV data is verification output and remains untrusted until its content digest and exact change snapshot validate.".into(),
        "Changed-line coverage counts only added or modified executable lines represented in the diff and LCOV artifact; it does not measure branch coverage or prove behavioral adequacy.".into(),
        "Coverage reflects only the tests and execution represented by the selected profile and LCOV artifact.".into(),
    ];
    for file in &change_set.files {
        if !seen.contains(&file.path) {
            limitations.push(format!(
                "No LCOV record was present for changed path {}.",
                file.path
            ));
        }
    }
    Ok(CoverageReport {
        schema_version: 1,
        run_id: run.run_id.clone(),
        snapshot_id: run.snapshot_id.clone(),
        profile_id: run.profile_id.clone(),
        stream: stream.into(),
        measured_scope: "file_and_changed_executable_lines".into(),
        files,
        limitations,
    })
}

fn changed_line_coverage(
    root: &Path,
    change_set: &ChangeSet,
    path: &str,
    coverage_lines: &BTreeMap<u64, u64>,
) -> Result<ChangedLineCoverage, String> {
    if change_set.base_oid.is_none() {
        return Ok(ChangedLineCoverage::default());
    }
    let relative = Path::new(path);
    let baseline = vee_git::read_snapshot_base_file(root, change_set, relative)?;
    let current = vee_git::read_snapshot_file(root, change_set, relative)?;
    if baseline
        .as_ref()
        .is_some_and(|bytes| bytes.len() > MAX_DIFF_INPUT_BYTES)
        || current
            .as_ref()
            .is_some_and(|bytes| bytes.len() > MAX_DIFF_INPUT_BYTES)
    {
        return Ok(ChangedLineCoverage::default());
    }
    let baseline_text = baseline
        .as_deref()
        .filter(|bytes| !bytes.contains(&0) && std::str::from_utf8(bytes).is_ok());
    let current_text = current
        .as_deref()
        .filter(|bytes| !bytes.contains(&0) && std::str::from_utf8(bytes).is_ok());
    if baseline.is_some() && baseline_text.is_none() || current.is_some() && current_text.is_none()
    {
        return Ok(ChangedLineCoverage::default());
    }
    let Some(changed_lines) =
        crate::changed_line_numbers(baseline_text, current_text, MAX_DIFF_OUTPUT_BYTES)?
    else {
        return Ok(ChangedLineCoverage::default());
    };
    let changed_executable = changed_lines
        .iter()
        .filter(|line| coverage_lines.contains_key(line))
        .count() as u64;
    let changed_covered = changed_lines
        .iter()
        .filter(|line| coverage_lines.get(line).is_some_and(|hits| *hits > 0))
        .count() as u64;
    Ok(ChangedLineCoverage {
        changed_lines: Some(changed_lines.len() as u64),
        executable_lines: Some(changed_executable),
        covered_lines: Some(changed_covered),
    })
}

fn parse_lcov(text: &str, root: &Path) -> Result<BTreeMap<String, BTreeMap<u64, u64>>, String> {
    let mut records = BTreeMap::<String, BTreeMap<u64, u64>>::new();
    let mut current: Option<String> = None;
    let mut count = 0usize;
    let canonical_root = std::fs::canonicalize(root).map_err(|error| error.to_string())?;
    for line in text.lines() {
        if let Some(path) = line.strip_prefix("SF:") {
            if current.is_some() {
                return Err("LCOV source record is missing end_of_record".into());
            }
            let path = Path::new(path);
            let relative = if path.is_absolute() {
                let canonical_path = std::fs::canonicalize(path)
                    .map_err(|_| "LCOV absolute source path cannot be resolved")?;
                canonical_path
                    .strip_prefix(&canonical_root)
                    .map_err(|_| "LCOV source path is outside the repository")?
                    .to_path_buf()
            } else {
                path.to_path_buf()
            };
            let mut components = Vec::new();
            for component in relative.components() {
                match component {
                    std::path::Component::Normal(value) => {
                        components.push(value.to_string_lossy().into_owned())
                    }
                    std::path::Component::CurDir => {}
                    _ => return Err("LCOV contains an unsafe source path".into()),
                }
            }
            if components.is_empty() {
                return Err("LCOV source path is empty".into());
            }
            let path = components.join("/");
            current = Some(path.clone());
            records.entry(path).or_default();
        } else if let Some(data) = line.strip_prefix("DA:") {
            let path = current
                .as_ref()
                .ok_or_else(|| "LCOV DA record appears before SF".to_owned())?;
            let (line_no, hits) = data
                .split_once(',')
                .ok_or_else(|| "malformed LCOV DA record".to_owned())?;
            let line_no: u64 = line_no
                .parse()
                .map_err(|_| "invalid LCOV line number".to_owned())?;
            let hits: u64 = hits
                .split(',')
                .next()
                .unwrap_or_default()
                .parse()
                .map_err(|_| "invalid LCOV hit count".to_owned())?;
            if line_no == 0 {
                return Err("LCOV line numbers must be positive".into());
            }
            let lines = records.get_mut(path).expect("source record inserted");
            if lines.insert(line_no, hits).is_some() {
                return Err("LCOV repeats a line record".into());
            }
            count += 1;
            if count > MAX_RECORDS {
                return Err("LCOV line record limit exceeded".into());
            }
        } else if line == "end_of_record" {
            if current.is_none() {
                return Err("LCOV end_of_record appears without a source record".into());
            }
            current = None;
        }
    }
    if current.is_some() {
        return Err("LCOV source record is missing end_of_record".into());
    }
    Ok(records)
}

pub fn parse_manifest(manifest: &str, expected: &str) -> Result<ChangeSet, String> {
    let (version, base, head, scope, files): (
        u32,
        Option<String>,
        Option<String>,
        String,
        Vec<SnapshotFile>,
    ) = serde_json::from_str(manifest).map_err(|e| e.to_string())?;
    if version != 1 {
        return Err(format!("unsupported snapshot manifest version {version}"));
    }
    let snapshot = ChangeSet::from_entries(base, head, scope, files);
    if snapshot.digest != expected {
        return Err("snapshot manifest digest mismatch".into());
    }
    Ok(snapshot)
}

fn read_artifact(root: &Path, artifact: &ArtifactReference) -> Result<Vec<u8>, String> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let hex = artifact
        .digest
        .strip_prefix("sha256:")
        .ok_or("unsupported artifact digest")?;
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("invalid artifact digest".into());
    }
    let relative = Path::new(".vee/artifacts/sha256").join(hex);
    if Path::new(&artifact.path) != relative {
        return Err("artifact path does not match content digest".into());
    }
    let root = std::fs::canonicalize(root).map_err(|e| e.to_string())?;
    let path = root.join(relative);
    let metadata = std::fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() != artifact.size_bytes
        || metadata.len() > MAX_BYTES
    {
        return Err("artifact is not a bounded regular file with the recorded size".into());
    }
    let canonical = std::fs::canonicalize(&path).map_err(|e| e.to_string())?;
    if !canonical.starts_with(root.join(".vee/artifacts/sha256")) {
        return Err("artifact escaped repository artifact directory".into());
    }
    let mut bytes = Vec::new();
    std::fs::File::open(canonical)
        .map_err(|e| e.to_string())?
        .take(MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    let digest = format!("sha256:{:x}", Sha256::digest(&bytes));
    if digest != artifact.digest {
        return Err("artifact content digest mismatch".into());
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest;

    #[test]
    fn parses_records_and_rejects_unsafe_or_ambiguous_input() {
        let root = tempfile::tempdir().unwrap();
        let parsed = parse_lcov(
            "TN:\nSF:src/a.rs\nDA:1,0\nDA:2,4\nend_of_record\n",
            root.path(),
        )
        .unwrap();
        assert_eq!(parsed["src/a.rs"].len(), 2);
        assert!(parse_lcov("SF:../secret.rs\nend_of_record\n", root.path()).is_err());
        assert!(parse_lcov("SF:a.rs\nDA:1,0\nDA:1,1\nend_of_record\n", root.path()).is_err());
        assert!(parse_lcov("SF:a.rs\nDA:1,1\n", root.path()).is_err());
        assert!(parse_lcov("SF:/etc/passwd\nend_of_record\n", root.path()).is_err());
        std::fs::create_dir_all(root.path().join("src")).unwrap();
        std::fs::write(root.path().join("src/a.rs"), "\n\n\n").unwrap();
        let absolute = format!(
            "SF:{}/src/a.rs\nDA:1,3\nend_of_record\n",
            root.path().display()
        );
        assert_eq!(
            parse_lcov(&absolute, root.path()).unwrap()["src/a.rs"][&1],
            3
        );
    }

    #[test]
    fn report_uses_persisted_artifact_and_exact_snapshot_manifest() {
        use vee_core::ports::*;
        use vee_core::{GateDecision, GateStatus, ReviewWrite, VerificationStatus};
        use vee_store_sqlite::ReviewStore;

        let root = tempfile::tempdir().unwrap();
        let changed_path = "src/changed.rs";
        std::fs::create_dir_all(root.path().join("src")).unwrap();
        std::fs::write(root.path().join(changed_path), "fn changed() {}\n").unwrap();
        let change_set = ChangeSet::from_entries(
            None,
            None,
            "working_tree",
            vec![SnapshotFile {
                path: changed_path.into(),
                mode: 0o100644,
                content_digest: "sha256:source".into(),
                status: "modified".into(),
            }],
        );
        let manifest = serde_json::to_string(&(
            change_set.schema_version,
            change_set.base_oid.as_deref(),
            change_set.head_oid.as_deref(),
            change_set.scope.as_str(),
            &change_set.files,
        ))
        .unwrap();
        std::fs::create_dir_all(root.path().join(".vee")).unwrap();
        let decision = GateDecision {
            schema_version: 1,
            decision_id: "decision-test".into(),
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
        let mut store = ReviewStore::open(&root.path().join(".vee/vee.sqlite")).unwrap();
        store
            .save_review_with_decision(ReviewWrite {
                id: "rev-test",
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

        let lcov = b"TN:\nSF:src/changed.rs\nDA:1,0\nDA:2,3\nend_of_record\nSF:src/unchanged.rs\nDA:1,10\nend_of_record\n";
        let digest = format!("sha256:{:x}", sha2::Sha256::digest(lcov));
        let hex = digest.strip_prefix("sha256:").unwrap().to_owned();
        let artifacts = root.path().join(".vee/artifacts/sha256");
        std::fs::create_dir_all(&artifacts).unwrap();
        std::fs::write(artifacts.join(&hex), lcov).unwrap();
        let reference = ArtifactReference {
            digest: digest.clone(),
            path: format!(".vee/artifacts/sha256/{hex}"),
            size_bytes: lcov.len() as u64,
        };
        let run = VerificationRun {
            schema_version: 1,
            run_id: "run-test".into(),
            snapshot_id: change_set.digest.clone(),
            profile_id: "coverage".into(),
            finding_id: None,
            targets: vec![],
            command_digest: "command".into(),
            status: VerificationStatus::Passed,
            exit_code: Some(0),
            stdout_digest: digest,
            stderr_digest: "sha256:empty".into(),
            stdout_artifact: Some(reference),
            stderr_artifact: None,
        };
        store.save_verification_with_artifacts(&run).unwrap();

        let coverage_report = report(root.path(), &store, &run, "stdout").unwrap();
        assert_eq!(coverage_report.snapshot_id, change_set.digest);
        let mut wrong_snapshot = change_set.clone();
        wrong_snapshot.digest = "sha256:wrong-snapshot".into();
        assert!(report_for_change_set(root.path(), &run, "stdout", &wrong_snapshot).is_err());
        assert_eq!(
            coverage_report.measured_scope,
            "file_and_changed_executable_lines"
        );
        assert_eq!(coverage_report.files.len(), 1);
        assert_eq!(coverage_report.files[0].path, changed_path);
        assert_eq!(coverage_report.files[0].covered_lines, 1);
        assert_eq!(coverage_report.files[0].executable_lines, 2);
        assert_eq!(coverage_report.files[0].percent, Some(50.0));
        assert_eq!(coverage_report.files[0].changed_line_count, None);
        assert_eq!(coverage_report.files[0].changed_executable_lines, None);

        std::fs::write(artifacts.join(&hex), b"tampered").unwrap();
        assert!(report(root.path(), &store, &run, "stdout")
            .unwrap_err()
            .contains("regular file with the recorded size"));
    }
}
