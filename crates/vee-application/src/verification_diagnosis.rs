use serde::Serialize;
use std::path::{Component, Path, PathBuf};
use vee_core::{ChangeSet, SnapshotFile, VerificationRun, VerificationStatus};

const MAX_ARTIFACT_BYTES: u64 = 16 * 1024 * 1024;
const MAX_DIAGNOSTICS: usize = 200;
const MAX_DIAGNOSTIC_CHARS: usize = 1200;

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct VerificationDiagnosis {
    pub schema_version: u32,
    pub run_id: String,
    pub snapshot_id: String,
    pub profile_id: String,
    pub status: String,
    pub targets: Vec<String>,
    pub changed_paths: Vec<String>,
    pub diagnostics: Vec<ParsedDiagnostic>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct ParsedDiagnostic {
    pub provenance: String,
    pub stream: String,
    pub line: usize,
    pub kind: String,
    pub text: String,
    /// Exact changed paths appearing in this diagnostic line.
    pub referenced_changed_paths: Vec<String>,
}

pub fn diagnose(
    root: &Path,
    store: &dyn vee_core::ports::Repositories,
    run: &VerificationRun,
) -> Result<VerificationDiagnosis, String> {
    let mut limitations = vec![
        "Diagnosis uses deterministic log-pattern recognition; it does not establish root cause or prove a fix.".to_owned(),
        "Only exact changed-path strings present in a diagnostic line are linked; indirect impact is not inferred.".to_owned(),
    ];
    let changed_paths = match store.snapshot_manifest(&run.snapshot_id)? {
        Some(manifest) => match parse_manifest(&manifest, &run.snapshot_id) {
            Ok(change_set) => change_set
                .files
                .iter()
                .map(|file| file.path.clone())
                .collect(),
            Err(error) => {
                limitations.push(format!("Snapshot changed paths are unavailable: {error}"));
                Vec::new()
            }
        },
        None => {
            limitations
                .push("No immutable snapshot manifest is stored for this verification run.".into());
            Vec::new()
        }
    };

    let mut diagnostics = Vec::new();
    'streams: for (stream, artifact) in [
        ("stdout", run.stdout_artifact.as_ref()),
        ("stderr", run.stderr_artifact.as_ref()),
    ] {
        let Some(artifact) = artifact else {
            continue;
        };
        let bytes = match read_artifact(root, artifact) {
            Ok(bytes) => bytes,
            Err(error) => {
                limitations.push(format!("{stream} artifact was not interpreted: {error}"));
                continue;
            }
        };
        let text = match std::str::from_utf8(&bytes) {
            Ok(text) => text,
            Err(_) => {
                limitations.push(format!("{stream} artifact is not UTF-8 text."));
                continue;
            }
        };
        if text.trim_start().starts_with("<?xml") || text.trim_start().starts_with("<testsuite") {
            match parse_junit_failures(text) {
                Ok(parsed) => {
                    for (line, kind, diagnostic) in parsed {
                        let referenced_changed_paths = changed_paths
                            .iter()
                            .filter(|path| diagnostic.contains(path.as_str()))
                            .cloned()
                            .collect();
                        diagnostics.push(ParsedDiagnostic {
                            provenance: "untrusted_verification_output".into(),
                            stream: stream.into(),
                            line,
                            kind: kind.into(),
                            text: truncate_chars(&diagnostic, MAX_DIAGNOSTIC_CHARS),
                            referenced_changed_paths,
                        });
                        if diagnostics.len() >= MAX_DIAGNOSTICS {
                            limitations.push(format!(
                                "Parsed diagnostics were capped at {MAX_DIAGNOSTICS} records."
                            ));
                            break 'streams;
                        }
                    }
                }
                Err(error) => {
                    limitations.push(format!("{stream} XML was not interpreted: {error}"))
                }
            }
            continue;
        }
        for (index, line) in text.lines().enumerate() {
            let Some(kind) = classify_line(line).or_else(|| classify_json_test_event(line)) else {
                continue;
            };
            let referenced_changed_paths = changed_paths
                .iter()
                .filter(|path| line.contains(path.as_str()))
                .cloned()
                .collect();
            diagnostics.push(ParsedDiagnostic {
                provenance: "untrusted_verification_output".into(),
                stream: stream.into(),
                line: index + 1,
                kind: kind.into(),
                text: truncate_chars(line, MAX_DIAGNOSTIC_CHARS),
                referenced_changed_paths,
            });
            if diagnostics.len() >= MAX_DIAGNOSTICS {
                limitations.push(format!(
                    "Parsed diagnostics were capped at {MAX_DIAGNOSTICS} lines."
                ));
                break 'streams;
            }
        }
    }
    if run.status == VerificationStatus::TimedOut {
        limitations
            .push("The verification process timed out; captured output may be partial.".into());
    }
    if diagnostics.is_empty() {
        limitations.push(
            "No recognized compiler or test-failure patterns were found in the available logs."
                .into(),
        );
    }
    Ok(VerificationDiagnosis {
        schema_version: 2,
        run_id: run.run_id.clone(),
        snapshot_id: run.snapshot_id.clone(),
        profile_id: run.profile_id.clone(),
        status: match run.status {
            VerificationStatus::Passed => "passed",
            VerificationStatus::Failed => "failed",
            VerificationStatus::TimedOut => "timed_out",
            VerificationStatus::Incomplete => "incomplete",
        }
        .into(),
        targets: run.targets.clone(),
        changed_paths,
        diagnostics,
        limitations,
    })
}

fn parse_manifest(manifest: &str, expected_snapshot_id: &str) -> Result<ChangeSet, String> {
    let (version, base_oid, head_oid, scope, files): (
        u32,
        Option<String>,
        Option<String>,
        String,
        Vec<SnapshotFile>,
    ) = serde_json::from_str(manifest).map_err(|error| error.to_string())?;
    if version != 1 {
        return Err(format!("unsupported snapshot manifest version {version}"));
    }
    let change_set = ChangeSet::from_entries(base_oid, head_oid, scope, files);
    if change_set.digest != expected_snapshot_id {
        return Err("snapshot manifest digest does not match the verification snapshot".into());
    }
    Ok(change_set)
}

fn read_artifact(root: &Path, artifact: &vee_core::ArtifactReference) -> Result<Vec<u8>, String> {
    let digest_hex = artifact
        .digest
        .strip_prefix("sha256:")
        .ok_or("unsupported artifact digest")?;
    if digest_hex.len() != 64 || !digest_hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("invalid artifact digest".into());
    }
    let expected_relative = PathBuf::from(".vee/artifacts/sha256").join(digest_hex);
    if Path::new(&artifact.path) != expected_relative {
        return Err("artifact path does not match its content digest".into());
    }
    let canonical_root = std::fs::canonicalize(root).map_err(|error| error.to_string())?;
    let mut path = canonical_root.clone();
    for component in expected_relative.components() {
        let Component::Normal(name) = component else {
            return Err("invalid artifact path component".into());
        };
        path.push(name);
        let metadata = std::fs::symlink_metadata(&path).map_err(|error| error.to_string())?;
        if metadata.file_type().is_symlink() {
            return Err("artifact path contains a symlink".into());
        }
        if path != canonical_root.join(&expected_relative) && !metadata.is_dir() {
            return Err("artifact parent is not a directory".into());
        }
    }
    let canonical_artifact = std::fs::canonicalize(&path).map_err(|error| error.to_string())?;
    if canonical_artifact != canonical_root.join(&expected_relative) {
        return Err("artifact resolved outside its content-addressed path".into());
    }
    let metadata = std::fs::metadata(&canonical_artifact).map_err(|error| error.to_string())?;
    if !metadata.is_file()
        || metadata.len() > MAX_ARTIFACT_BYTES
        || metadata.len() != artifact.size_bytes
    {
        return Err("artifact is not a bounded regular file with the recorded size".into());
    }
    use std::io::Read;
    let file = std::fs::File::open(&canonical_artifact).map_err(|error| error.to_string())?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_ARTIFACT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() as u64 != artifact.size_bytes || bytes.len() as u64 > MAX_ARTIFACT_BYTES {
        return Err("artifact changed or exceeded the read limit".into());
    }
    if vee_core::digest(&bytes) != artifact.digest {
        return Err("artifact content digest mismatch".into());
    }
    Ok(bytes)
}

fn classify_line(line: &str) -> Option<&'static str> {
    let trimmed = line.trim_start();
    let minitest_failure = trimmed
        .split_once(") Failure:")
        .is_some_and(|(ordinal, _)| {
            !ordinal.is_empty() && ordinal.bytes().all(|b| b.is_ascii_digit())
        });
    if trimmed.starts_with("--- FAIL:")
        || trimmed.starts_with("FAIL:")
        || trimmed.starts_with("FAIL ")
        || trimmed.starts_with("FAIL\t")
        || trimmed.starts_with("FAILED ")
        || trimmed.starts_with("not ok ")
        || trimmed.starts_with("✖ ")
        || trimmed.starts_with("test result: FAILED")
        || trimmed.starts_with("Exception in thread ")
            && trimmed.contains("java.lang.AssertionError")
        || trimmed.starts_with("ERROR ")
        || minitest_failure
        || (trimmed.starts_with("test ") && trimmed.ends_with(" ... FAILED"))
        || trimmed.starts_with("---- ") && trimmed.ends_with(" stdout ----")
    {
        return Some("test_failure");
    }
    if trimmed.starts_with("error[E")
        || trimmed.starts_with("error TS")
        || trimmed.starts_with("error:")
        || (trimmed.starts_with('#') && trimmed.contains("build failed"))
        || trimmed.contains(": error")
    {
        return Some("compile_error");
    }
    if trimmed.starts_with("panicked at") || trimmed.starts_with("panic:") {
        return Some("runtime_failure");
    }
    None
}

/// Recognize Go's `go test -json` event envelope without interpreting package
// or test names as source paths. The complete event is retained as untrusted
/// diagnostic text for a human or agent to inspect.
fn classify_json_test_event(line: &str) -> Option<&'static str> {
    let event: serde_json::Value = serde_json::from_str(line).ok()?;
    let go_failure = event.get("Action").and_then(serde_json::Value::as_str) == Some("fail")
        && event
            .get("Package")
            .and_then(serde_json::Value::as_str)
            .is_some()
        && event
            .get("Test")
            .and_then(serde_json::Value::as_str)
            .is_some();
    let nextest_failure = event.get("type").and_then(serde_json::Value::as_str) == Some("test")
        && matches!(
            event.get("event").and_then(serde_json::Value::as_str),
            Some("failed" | "timeout")
        )
        && event
            .get("name")
            .and_then(serde_json::Value::as_str)
            .is_some();
    (go_failure || nextest_failure).then_some("test_failure")
}

/// Return the first recognized test failure from bounded verification output.
/// Compiler/build failures alone do not count as a killed mutant.
pub fn test_failure_signal(stdout: &[u8], stderr: &[u8]) -> Option<String> {
    for bytes in [stdout, stderr] {
        let output = String::from_utf8_lossy(bytes);
        let trimmed = output.trim_start();
        if trimmed.starts_with("<?xml") || trimmed.starts_with("<testsuite") {
            if let Ok(records) = parse_junit_failures(&output) {
                if let Some((_, kind, diagnostic)) = records.into_iter().find(|(_, kind, _)| {
                    matches!(*kind, "test_failure" | "test_flaky" | "test_retry_failure")
                }) {
                    let label = match kind {
                        "test_flaky" => "flaky test failure",
                        "test_retry_failure" => "retry test failure",
                        _ => "test failure",
                    };
                    return Some(format!(
                        "{label}: {}",
                        truncate_chars(&diagnostic, MAX_DIAGNOSTIC_CHARS)
                    ));
                }
            }
            continue;
        }
        for line in output.lines() {
            if classify_line(line) == Some("test_failure")
                || classify_json_test_event(line) == Some("test_failure")
            {
                return Some(truncate_chars(line.trim(), MAX_DIAGNOSTIC_CHARS));
            }
        }
    }
    None
}

/// Extract failure/error records from standard JUnit `<testsuite(s)>` reports.
/// DTDs and entity declarations are rejected; the parser does not resolve them.
fn parse_junit_failures(text: &str) -> Result<Vec<(usize, &'static str, String)>, String> {
    if text.len() as u64 > MAX_ARTIFACT_BYTES {
        return Err("XML report exceeds the parser size limit".into());
    }
    if text.contains("<!DOCTYPE") || text.contains("<!ENTITY") {
        return Err("DTD and entity declarations are not accepted".into());
    }
    let document = roxmltree::Document::parse(text).map_err(|error| error.to_string())?;
    let root = document.root_element();
    if !matches!(root.tag_name().name(), "testsuite" | "testsuites") {
        return Err("XML root is not a JUnit testsuite/testsuites element".into());
    }
    let mut failures = Vec::new();
    for testcase in root
        .descendants()
        .filter(|node| node.has_tag_name("testcase"))
    {
        let class = testcase.attribute("classname").unwrap_or("");
        let name = testcase.attribute("name").unwrap_or("(unnamed test)");
        for result in testcase.children().filter(|node| {
            node.is_element()
                && matches!(
                    node.tag_name().name(),
                    "failure"
                        | "error"
                        | "flakyFailure"
                        | "flakyError"
                        | "rerunFailure"
                        | "rerunError"
                )
        }) {
            let tag = result.tag_name().name();
            let (kind, label) = match tag {
                "flakyFailure" | "flakyError" => ("test_flaky", "flaky test attempt"),
                "rerunFailure" | "rerunError" => ("test_retry_failure", "retry failure"),
                _ => ("test_failure", "test failure"),
            };
            let message = result.attribute("message").unwrap_or("");
            let detail = result
                .descendants()
                .filter_map(|node| node.text())
                .collect::<Vec<_>>()
                .join(" ");
            let diagnostic = format!("JUnit {label} ({tag}): {class}#{name}: {message} {detail}")
                .trim()
                .to_owned();
            let line = document.text_pos_at(result.range().start).row as usize;
            failures.push((line.max(1), kind, diagnostic));
            if failures.len() > MAX_DIAGNOSTICS {
                return Err(format!(
                    "JUnit failure record limit {MAX_DIAGNOSTICS} exceeded"
                ));
            }
        }
    }
    Ok(failures)
}

fn truncate_chars(value: &str, maximum: usize) -> String {
    let mut chars = value.chars();
    let prefix: String = chars.by_ref().take(maximum).collect();
    if chars.next().is_some() {
        format!("{prefix}…")
    } else {
        prefix
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vee_core::ports::*;

    #[test]
    fn classifies_common_compiler_and_test_failure_lines() {
        assert_eq!(
            classify_line("--- FAIL: TestDecode (0.00s)"),
            Some("test_failure")
        );
        assert_eq!(
            classify_line("test api::tests::rejects_bad_input ... FAILED"),
            Some("test_failure")
        );
        assert_eq!(classify_line("  1) Failure:"), Some("test_failure"));
        assert_eq!(classify_line("1 runs, 1 assertions, 0 failures"), None);
        assert_eq!(
            classify_line(
                "Exception in thread \"main\" java.lang.AssertionError: target should be false"
            ),
            Some("test_failure")
        );
        assert_eq!(
            classify_line("error[E0308]: mismatched types"),
            Some("compile_error")
        );
        assert_eq!(
            classify_line("src/lib.rs:12:5: error: expected `;`"),
            Some("compile_error")
        );
        assert_eq!(classify_line("test result: ok. 2 passed"), None);
        assert_eq!(
            classify_json_test_event(
                r#"{"Action":"fail","Package":"example/internal/parser","Test":"TestRejectsInvalid"}"#
            ),
            Some("test_failure")
        );
        assert_eq!(
            classify_json_test_event(
                r#"{"Action":"pass","Package":"example/internal/parser","Test":"TestParsesValid"}"#
            ),
            None
        );
        assert_eq!(
            classify_json_test_event(
                r#"{"type":"test","event":"failed","name":"parser::rejects_bad_input","stdout":"assertion failed"}"#
            ),
            Some("test_failure")
        );
        assert_eq!(
            classify_json_test_event(
                r#"{"type":"test","event":"timeout","name":"parser::waits_forever"}"#
            ),
            Some("test_failure")
        );
        assert_eq!(
            classify_json_test_event(
                r#"{"type":"test","event":"ok","name":"parser::accepts_valid_input"}"#
            ),
            None
        );
        assert_eq!(classify_json_test_event("not json"), None);
    }

    #[test]
    fn effectiveness_failure_signals_recognize_framework_formats_but_not_build_failures() {
        let go = br#"{"Time":"2026-11-15T00:00:00Z","Action":"fail","Package":"example/pkg","Test":"TestChanged"}"#;
        let nextest = br#"{"type":"test","event":"failed","name":"crate::changed::test"}"#;
        let junit = br#"<testsuites><testsuite><testcase classname="pkg.Test" name="TestChanged"><failure message="expected true">assertion failed</failure></testcase></testsuite></testsuites>"#;
        assert!(test_failure_signal(go, b"")
            .unwrap()
            .contains("\"Test\":\"TestChanged\""));
        assert!(test_failure_signal(nextest, b"")
            .unwrap()
            .contains("crate::changed::test"));
        assert!(test_failure_signal(junit, b"")
            .unwrap()
            .contains("JUnit test failure"));
        assert!(test_failure_signal(b"--- FAIL: TestChanged (0.00s)", b"").is_some());
        assert!(
            test_failure_signal(b"FAIL: test_target (test_logic.LogicTest.test_target)", b"")
                .is_some()
        );
        assert!(
            test_failure_signal(b"TAP version 13\nnot ok 1 - target remains false", b"").is_some()
        );
        assert!(test_failure_signal("✖ target remains false".as_bytes(), b"").is_some());
        assert!(test_failure_signal(b"test result: FAILED", b"").is_some());
        assert_eq!(
            test_failure_signal(
                br#"{"Time":"2026-11-15T00:00:00Z","Action":"fail","Package":"example/pkg"}"#,
                b"error[E0001]: compilation failed"
            ),
            None
        );
        assert_eq!(test_failure_signal(b"command failed", b""), None);
    }

    #[test]
    fn parses_junit_failures_with_source_line_and_rejects_entities() {
        let xml = r#"<?xml version="1.0"?>
<testsuites><testsuite name="unit"><testcase classname="parser" name="rejects_bad_input">
<failure message="assertion failed">src/lib.rs:17: expected error</failure>
</testcase></testsuite></testsuites>"#;
        let parsed = parse_junit_failures(xml).unwrap();
        assert_eq!(parsed.len(), 1);
        assert!(parsed[0].0 > 1);
        assert_eq!(parsed[0].1, "test_failure");
        assert!(parsed[0].2.contains("parser#rejects_bad_input"));
        assert!(parsed[0].2.contains("src/lib.rs:17"));
        assert!(
            parse_junit_failures("<!DOCTYPE testsuite [<!ENTITY x 'y'>]><testsuite/>").is_err()
        );
        assert!(parse_junit_failures("<not-junit/>").is_err());
    }

    #[test]
    fn distinguishes_nextest_flaky_attempts_and_rerun_failures() {
        let xml = r#"<testsuites><testsuite><testcase classname="unit" name="intermittent">
<flakyFailure>first attempt failed</flakyFailure>
</testcase><testcase classname="unit" name="persistent">
<failure>final attempt failed</failure><rerunFailure>previous retry failed</rerunFailure>
</testcase></testsuite></testsuites>"#;
        let parsed = parse_junit_failures(xml).unwrap();
        let kinds: Vec<_> = parsed.iter().map(|item| item.1).collect();
        assert_eq!(kinds, ["test_flaky", "test_failure", "test_retry_failure"]);
        assert!(parsed[0].2.contains("intermittent"));
        assert!(parsed[2].2.contains("persistent"));
    }

    #[test]
    fn diagnostic_text_is_bounded_and_unicode_safe() {
        assert_eq!(truncate_chars("🦀🦀🦀🦀", 2), "🦀🦀…");
    }

    #[test]
    fn diagnosis_links_verified_log_lines_to_the_exact_snapshot() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        let mut store = vee_store_sqlite::ReviewStore::open(&root.join("vee.sqlite")).unwrap();
        let change_set = ChangeSet::from_entries(
            None,
            None,
            "working_tree",
            vec![SnapshotFile {
                path: "src/lib.rs".into(),
                mode: 0o100644,
                content_digest: vee_core::digest(b"source"),
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
        let decision = vee_core::GateDecision {
            schema_version: 1,
            decision_id: "decision-diagnosis".into(),
            snapshot_id: change_set.digest.clone(),
            effective_config_digest: "config".into(),
            policy_digest: "policy".into(),
            status: vee_core::GateStatus::Incomplete,
            blocking_findings: Vec::new(),
            verification_run_ids: Vec::new(),
            evidence_digest: "evidence".into(),
            reasons: Vec::new(),
            replay_inputs: None,
        };
        store
            .save_review_with_decision(vee_core::ReviewWrite {
                id: "review-diagnosis",
                snapshot_id: &change_set.digest,
                config_digest: "config",
                status: "complete",
                payload: "{}",
                findings: &[],
                evidence: &[],
                snapshot_manifest: &manifest,
                decision: &decision,
            })
            .unwrap();

        let stdout = b"test api::tests::rejects_bad_input ... FAILED\nsrc/lib.rs:12:5: error[E0308]: mismatched types\n";
        let stdout_digest = vee_core::digest(stdout);
        let artifact_path = format!(
            ".vee/artifacts/sha256/{}",
            stdout_digest.trim_start_matches("sha256:")
        );
        let full_artifact_path = root.join(&artifact_path);
        std::fs::create_dir_all(full_artifact_path.parent().unwrap()).unwrap();
        std::fs::write(&full_artifact_path, stdout).unwrap();
        let run = VerificationRun {
            schema_version: 1,
            run_id: "verify-diagnosis".into(),
            snapshot_id: change_set.digest.clone(),
            profile_id: "unit".into(),
            finding_id: None,
            targets: vec!["crate::api".into()],
            command_digest: "command".into(),
            status: VerificationStatus::Failed,
            exit_code: Some(101),
            stdout_digest: stdout_digest.clone(),
            stderr_digest: vee_core::digest(b""),
            stdout_artifact: Some(vee_core::ArtifactReference {
                digest: stdout_digest,
                path: artifact_path,
                size_bytes: stdout.len() as u64,
            }),
            stderr_artifact: None,
        };
        store.save_verification(&run).unwrap();
        let report = diagnose(root, &store, &run).unwrap();
        assert_eq!(report.changed_paths, vec!["src/lib.rs"]);
        assert_eq!(report.diagnostics.len(), 2);
        assert_eq!(report.diagnostics[0].kind, "test_failure");
        assert_eq!(report.diagnostics[1].kind, "compile_error");
        assert_eq!(
            report.diagnostics[1].referenced_changed_paths,
            vec!["src/lib.rs"]
        );
    }

    #[cfg(unix)]
    #[test]
    fn diagnosis_rejects_symlinked_artifact_paths() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        let bytes = b"error[E0001]: broken";
        let digest = vee_core::digest(bytes);
        let relative = format!(
            ".vee/artifacts/sha256/{}",
            digest.trim_start_matches("sha256:")
        );
        let link_path = root.join(&relative);
        std::fs::create_dir_all(link_path.parent().unwrap()).unwrap();
        let target = root.join("external.log");
        std::fs::write(&target, bytes).unwrap();
        std::os::unix::fs::symlink(&target, &link_path).unwrap();
        let artifact = vee_core::ArtifactReference {
            digest,
            path: relative,
            size_bytes: bytes.len() as u64,
        };
        assert!(read_artifact(root, &artifact)
            .unwrap_err()
            .contains("symlink"));
    }
}
