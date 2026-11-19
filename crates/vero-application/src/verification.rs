//! Verification context: trusted verification profiles, impacted-test selection, and stored output artifacts.

use super::*;

/// The persisted manifest form of a change snapshot.
pub fn snapshot_manifest_json(change_set: &ChangeSet) -> Result<String, String> {
    serde_json::to_string(&(
        change_set.schema_version,
        change_set.base_oid.as_deref(),
        change_set.head_oid.as_deref(),
        change_set.scope.as_str(),
        &change_set.files,
    ))
    .map_err(|error| error.to_string())
}

pub fn run_verification(
    root: &Path,
    snapshot: &ChangeSet,
    profile_id: &str,
    config: &RepositoryConfig,
    store: &mut dyn Repositories,
) -> Result<VerificationRun, String> {
    ensure_snapshot_current(root, snapshot, "before verification")?;
    store.record_snapshot_manifest(&snapshot.digest, &snapshot_manifest_json(snapshot)?)?;
    let profile = config
        .verification
        .get(profile_id)
        .ok_or_else(|| format!("unknown verification profile {profile_id}"))?;
    let mut execution =
        if snapshot.scope.starts_with("commit:") || snapshot.scope.starts_with("commit_range:") {
            let commit = snapshot
                .head_oid
                .as_deref()
                .ok_or("commit-scoped snapshot is missing its endpoint commit")?;
            let worktree = CommitVerificationWorktree::create(root, commit)?;
            let execution = vero_process::execute_verification_capture(
                &snapshot.digest,
                profile_id,
                &worktree.path,
                profile,
            )?;
            worktree.ensure_clean()?;
            execution
        } else {
            vero_process::execute_verification_capture(&snapshot.digest, profile_id, root, profile)?
        };
    if execution.run.status == vero_core::VerificationStatus::Passed
        && is_go_test_profile(profile)
        && go_test_output_reports_no_tests(&execution.stdout, &execution.stderr)
    {
        mark_verification_incomplete(
            &mut execution,
            profile.output_limit_bytes,
            "Vero: Go reported that no tests ran for this verification profile.\n",
        )?;
    }
    ensure_snapshot_current(root, snapshot, "during verification")?;
    let run = persist_verification_output(root, execution)?;
    store.save_verification_with_artifacts(&run)?;
    Ok(run)
}

pub(crate) fn is_go_test_profile(profile: &vero_core::VerificationProfile) -> bool {
    Path::new(&profile.executable)
        .file_name()
        .is_some_and(|name| name == "go" || name == "go.exe")
        && profile
            .args
            .first()
            .is_some_and(|argument| argument == "test")
}

/// Detect Go test commands that returned success after running no tests.
/// A broad `go test ./...` can include packages without tests, so one empty
/// package is insufficient: only treat the whole command as empty when its
/// output has no evidence that any individual test ran or passed.
pub(crate) fn go_test_output_reports_no_tests(stdout: &[u8], stderr: &[u8]) -> bool {
    let output = format!(
        "{}\n{}",
        String::from_utf8_lossy(stdout),
        String::from_utf8_lossy(stderr)
    );
    let reports_empty_test_set =
        output.contains("no tests to run") || output.contains("[no test files]");
    if !reports_empty_test_set {
        return false;
    }

    for line in output.lines() {
        if let Ok(event) = serde_json::from_str::<serde_json::Value>(line) {
            let action = event.get("Action").and_then(serde_json::Value::as_str);
            if matches!(action, Some("run" | "pass" | "fail" | "skip"))
                && event
                    .get("Test")
                    .and_then(serde_json::Value::as_str)
                    .is_some()
            {
                return false;
            }
        }
        let line = line.trim();
        if line.starts_with("--- PASS:")
            || line.starts_with("--- FAIL:")
            || line.starts_with("--- SKIP:")
            || line == "PASS"
            || (line.starts_with("ok ") && !line.contains("[no tests to run]"))
            || (line.starts_with("ok\t") && !line.contains("[no tests to run]"))
        {
            return false;
        }
    }
    true
}

pub(crate) fn mark_verification_incomplete(
    execution: &mut vero_core::VerificationExecution,
    output_limit_bytes: usize,
    diagnostic: &str,
) -> Result<(), String> {
    execution.run.status = vero_core::VerificationStatus::Incomplete;
    execution.run.exit_code = Some(2);
    if execution
        .stdout
        .len()
        .saturating_add(execution.stderr.len())
        .saturating_add(diagnostic.len())
        <= output_limit_bytes
    {
        execution.stderr.extend_from_slice(diagnostic.as_bytes());
    }
    execution.run.stderr_digest = digest(&execution.stderr);
    execution.run.run_id = digest(
        &serde_json::to_vec(&(
            execution.run.snapshot_id.as_str(),
            execution.run.profile_id.as_str(),
            execution.run.command_digest.as_str(),
            execution.run.status,
            execution.run.exit_code,
            execution.run.stdout_digest.as_str(),
            execution.run.stderr_digest.as_str(),
        ))
        .map_err(|error| error.to_string())?,
    );
    Ok(())
}

/// Commit snapshots are immutable Git objects, while verification commands run
/// against filesystem contents. Run them in a fresh detached worktree so dirty
/// files in the user's checkout cannot silently change what was tested.
pub(crate) struct CommitVerificationWorktree {
    pub(crate) repository: PathBuf,
    pub(crate) path: PathBuf,
    pub(crate) temporary: tempfile::TempDir,
}

impl CommitVerificationWorktree {
    fn create(repository: &Path, commit: &str) -> Result<Self, String> {
        let repository = vero_git::repository_root(repository)?;
        let temporary = tempfile::tempdir().map_err(|error| error.to_string())?;
        let hooks = temporary.path().join("empty-git-hooks");
        std::fs::create_dir(&hooks).map_err(|error| error.to_string())?;
        let global_config = temporary.path().join("empty-global-git-config");
        std::fs::File::create(&global_config).map_err(|error| error.to_string())?;
        let path = temporary.path().join("checkout");
        let hooks = hooks.to_string_lossy().to_string();
        let filter_keys = std::process::Command::new("git")
            .arg("-C")
            .arg(&repository)
            .args([
                "config",
                "--local",
                "--name-only",
                "--get-regexp",
                r"^filter\..*\.(smudge|process)$",
            ])
            .output()
            .map_err(|error| format!("checking local Git filters: {error}"))?;
        if !filter_keys.status.success() && filter_keys.status.code() != Some(1) {
            return Err("could not inspect local Git filters before verification".into());
        }
        let filter_keys = String::from_utf8_lossy(&filter_keys.stdout);
        let mut command = std::process::Command::new("git");
        command
            .arg("-C")
            .arg(&repository)
            .arg("-c")
            .arg(format!("core.hooksPath={hooks}"))
            .args(["-c", "core.fsmonitor=false"]);
        for key in filter_keys
            .lines()
            .filter_map(|line| line.split_whitespace().next())
        {
            command.arg("-c").arg(format!("{key}="));
        }
        command
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_ATTR_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", &global_config);
        let output = command
            .args(["worktree", "add", "--detach", "--quiet"])
            .arg(&path)
            .arg(commit)
            .output()
            .map_err(|error| format!("starting local commit verification worktree: {error}"))?;
        if !output.status.success() {
            return Err(format!(
                "creating local commit verification worktree: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        Ok(Self {
            repository,
            path,
            temporary,
        })
    }

    fn ensure_clean(&self) -> Result<(), String> {
        let output = std::process::Command::new("git")
            .arg("-C")
            .arg(&self.path)
            .args([
                "status",
                "--porcelain",
                "--untracked-files=all",
                "--ignore-submodules=none",
            ])
            .output()
            .map_err(|error| format!("checking verification worktree: {error}"))?;
        if !output.status.success() {
            return Err("could not confirm verification worktree remained intact".into());
        }
        if !output.stdout.is_empty() {
            return Err("verification modified its isolated commit worktree".into());
        }
        Ok(())
    }
}

impl Drop for CommitVerificationWorktree {
    fn drop(&mut self) {
        let _ = std::process::Command::new("git")
            .arg("-C")
            .arg(&self.repository)
            .args(["worktree", "remove", "--force"])
            .arg(&self.path)
            .status();
        let _ = &self.temporary;
    }
}

/// Run a configured test profile against likely affected targets. Go profiles
/// use `{impacted_test_packages}` and Rust/Cargo profiles use
/// `{impacted_rust_test_filters}` as standalone argv arguments.
pub fn run_impacted_test_verification(
    root: &Path,
    snapshot: &ChangeSet,
    profile_id: &str,
    config: &RepositoryConfig,
    store: &mut dyn Repositories,
) -> Result<VerificationRun, String> {
    ensure_snapshot_current(root, snapshot, "before impact-targeted verification")?;
    store.record_snapshot_manifest(&snapshot.digest, &snapshot_manifest_json(snapshot)?)?;
    let profile = config
        .verification
        .get(profile_id)
        .ok_or_else(|| format!("unknown verification profile {profile_id}"))?;
    let go_targeting = profile
        .args
        .iter()
        .any(|arg| arg == "{impacted_test_packages}");
    let rust_targeting = profile
        .args
        .iter()
        .any(|arg| arg == "{impacted_rust_test_filters}");
    if go_targeting == rust_targeting {
        return Err(format!(
            "verification profile {profile_id} must include exactly one standalone impact target placeholder"
        ));
    }
    let impact = analyze_impact(root, snapshot)?;
    if !impact.coverage_complete {
        return Err(
            "impact analysis is incomplete; refusing to claim targeted test coverage".into(),
        );
    }
    let targets = if go_targeting {
        impacted_go_test_packages(snapshot, &impact)?
    } else {
        rust_test_filters_for_impact(root, snapshot, &impact)?
    };
    if targets.is_empty() {
        return Err("impact analysis found no likely affected test targets".into());
    }
    let targets: Vec<String> = targets.into_iter().collect();
    if targets.len() > 128 {
        return Err(
            "impact analysis selected more than 128 test targets; refusing unbounded execution"
                .into(),
        );
    }
    let targets: Vec<String> = targets.into_iter().collect();
    let placeholder = if go_targeting {
        "{impacted_test_packages}"
    } else {
        "{impacted_rust_test_filters}"
    };
    let invocations: Vec<Vec<String>> = if go_targeting {
        vec![expand_target_args(&profile.args, placeholder, &targets)?]
    } else {
        targets
            .iter()
            .map(|target| {
                let (package, filter) = target.split_once("::").ok_or_else(|| {
                    format!("Rust impact target {target} is missing its Cargo package")
                })?;
                expand_rust_target_args(&profile.args, placeholder, package, filter)
                    .map(ensure_cargo_test_output_format)
            })
            .collect::<Result<_, _>>()?
    };
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut statuses = Vec::new();
    let mut exit_codes = Vec::new();
    let mut invocation_digests = Vec::new();
    for (index, args) in invocations.iter().enumerate() {
        let mut targeted_profile = profile.clone();
        targeted_profile.args = args.clone();
        let mut execution = vero_process::execute_verification_capture(
            &snapshot.digest,
            profile_id,
            root,
            &targeted_profile,
        )?;
        let target_was_run = if execution.run.status != vero_core::VerificationStatus::Passed {
            true
        } else if rust_targeting {
            let (_, filter) = targets[index]
                .split_once("::")
                .expect("validated Rust target includes package and filter");
            cargo_output_reports_executed_tests(&execution.stdout, &execution.stderr, filter)
        } else {
            go_output_reports_executed_tests(
                &execution.stdout,
                &execution.stderr,
                &targets,
                go_module_path(root).as_deref(),
            )
        };
        if !target_was_run {
            let diagnostic = if rust_targeting {
                format!(
                    "Vero: Cargo exited successfully without reporting any executed tests for target filter {}.\n",
                    targets[index]
                )
            } else {
                format!(
                    "Vero: Go exited successfully without JSON evidence of a passed individual test for every target package {}; configure `go test -json`.\n",
                    targets.join(", ")
                )
            };
            mark_verification_incomplete(&mut execution, profile.output_limit_bytes, &diagnostic)?;
        }
        statuses.push(execution.run.status);
        exit_codes.push(execution.run.exit_code);
        invocation_digests.push(execution.run.command_digest);
        append_bounded_output(
            &mut stdout,
            format!("===== target: {} =====\n", targets[index]).as_bytes(),
            &execution.stdout,
            profile.output_limit_bytes,
        )?;
        append_bounded_output(
            &mut stderr,
            format!("===== target: {} =====\n", targets[index]).as_bytes(),
            &execution.stderr,
            profile.output_limit_bytes,
        )?;
        if stdout.len().saturating_add(stderr.len()) > profile.output_limit_bytes {
            return Err(
                "combined impact-targeted verification output exceeded configured limit".into(),
            );
        }
        ensure_snapshot_current(root, snapshot, "during impact-targeted verification")?;
        if execution.run.status == vero_core::VerificationStatus::TimedOut {
            break;
        }
    }
    let status = if statuses.contains(&vero_core::VerificationStatus::TimedOut) {
        vero_core::VerificationStatus::TimedOut
    } else if statuses.contains(&vero_core::VerificationStatus::Incomplete) {
        vero_core::VerificationStatus::Incomplete
    } else if statuses.contains(&vero_core::VerificationStatus::Failed) {
        vero_core::VerificationStatus::Failed
    } else {
        vero_core::VerificationStatus::Passed
    };
    let exit_code = match status {
        vero_core::VerificationStatus::Passed => Some(0),
        vero_core::VerificationStatus::TimedOut | vero_core::VerificationStatus::Incomplete => {
            Some(2)
        }
        vero_core::VerificationStatus::Failed => {
            exit_codes.into_iter().flatten().find(|code| *code != 0)
        }
    };
    let stdout_digest = digest(&stdout);
    let stderr_digest = digest(&stderr);
    let command_digest = digest(
        &serde_json::to_vec(&(
            "vero-impact-targeted-command-v1",
            &invocation_digests,
            &targets,
        ))
        .map_err(|error| error.to_string())?,
    );
    let run_id = digest(
        &serde_json::to_vec(&(
            "vero-impact-targeted-verification-v1",
            snapshot.digest.as_str(),
            profile_id,
            &command_digest,
            status,
            exit_code,
            &stdout_digest,
            &stderr_digest,
        ))
        .map_err(|error| error.to_string())?,
    );
    let execution = vero_core::VerificationExecution {
        run: VerificationRun {
            schema_version: vero_core::SCHEMA_VERSION,
            run_id,
            snapshot_id: snapshot.digest.clone(),
            profile_id: profile_id.into(),
            finding_id: None,
            targets: targets.clone(),
            command_digest,
            status,
            exit_code,
            stdout_digest,
            stderr_digest,
            stdout_artifact: None,
            stderr_artifact: None,
        },
        stdout,
        stderr,
    };
    ensure_snapshot_current(root, snapshot, "during impact-targeted verification")?;
    let run = persist_verification_output(root, execution)?;
    store.save_verification_with_artifacts(&run)?;
    Ok(run)
}

/// Describe the bounded, impact-selected invocations for a trusted test profile
/// without executing its configured program.
pub fn plan_impacted_test_verification(
    root: &Path,
    snapshot: &ChangeSet,
    profile_id: &str,
    config: &RepositoryConfig,
) -> Result<ImpactedTestPlan, String> {
    ensure_snapshot_current(
        root,
        snapshot,
        "before planning impact-targeted verification",
    )?;
    let profile = config
        .verification
        .get(profile_id)
        .ok_or_else(|| format!("unknown verification profile {profile_id}"))?;
    let go_targeting = profile
        .args
        .iter()
        .any(|arg| arg == "{impacted_test_packages}");
    let rust_targeting = profile
        .args
        .iter()
        .any(|arg| arg == "{impacted_rust_test_filters}");
    if go_targeting == rust_targeting {
        return Err(format!(
            "verification profile {profile_id} must include exactly one standalone impact target placeholder"
        ));
    }
    let impact = analyze_impact(root, snapshot)?;
    if !impact.coverage_complete {
        return Err(
            "impact analysis is incomplete; refusing to claim targeted test coverage".into(),
        );
    }
    let targets = if go_targeting {
        impacted_go_test_packages(snapshot, &impact)?
    } else {
        rust_test_filters_for_impact(root, snapshot, &impact)?
    };
    if targets.is_empty() {
        return Err("impact analysis found no likely affected test targets".into());
    }
    if targets.len() > 128 {
        return Err(
            "impact analysis selected more than 128 test targets; refusing unbounded plan".into(),
        );
    }
    let targets: Vec<String> = targets.into_iter().collect();
    let placeholder = if go_targeting {
        "{impacted_test_packages}"
    } else {
        "{impacted_rust_test_filters}"
    };
    let invocations = if go_targeting {
        vec![expand_target_args(&profile.args, placeholder, &targets)?]
    } else {
        targets
            .iter()
            .map(|target| {
                let (package, filter) = target.split_once("::").ok_or_else(|| {
                    format!("Rust impact target {target} is missing its Cargo package")
                })?;
                expand_rust_target_args(&profile.args, placeholder, package, filter)
                    .map(ensure_cargo_test_output_format)
            })
            .collect::<Result<Vec<_>, _>>()?
    };
    ensure_snapshot_current(
        root,
        snapshot,
        "after planning impact-targeted verification",
    )?;
    Ok(ImpactedTestPlan {
        schema_version: 1,
        snapshot_id: snapshot.digest.clone(),
        profile_id: profile_id.to_owned(),
        profile_digest: digest(&serde_json::to_vec(profile).map_err(|error| error.to_string())?),
        executable: profile.executable.clone(),
        targets,
        invocations,
        impact_coverage_complete: impact.coverage_complete,
        limitations: impact.limitations,
        execution_performed: false,
    })
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImpactedTestPlan {
    pub schema_version: u32,
    pub snapshot_id: String,
    pub profile_id: String,
    pub profile_digest: String,
    pub executable: String,
    pub targets: Vec<String>,
    pub invocations: Vec<Vec<String>>,
    pub impact_coverage_complete: bool,
    pub limitations: Vec<String>,
    pub execution_performed: bool,
}

pub(crate) fn cargo_output_reports_executed_tests(
    stdout: &[u8],
    stderr: &[u8],
    filter: &str,
) -> bool {
    let expected_test_passed = [stdout, stderr].into_iter().any(|output| {
        String::from_utf8_lossy(output).lines().any(|line| {
            let Some(name_and_status) = line.strip_prefix("test ") else {
                return false;
            };
            let Some((name, status)) = name_and_status.rsplit_once(" ... ") else {
                return false;
            };
            status == "ok"
                && (filter.is_empty()
                    || name == filter
                    || name.ends_with(&format!("::{filter}"))
                    || name.starts_with(&format!("{filter}::"))
                    || name.contains(&format!("::{filter}::")))
        })
    });
    if !expected_test_passed {
        return false;
    }
    [stdout, stderr].into_iter().any(|output| {
        String::from_utf8_lossy(output).lines().any(|line| {
            let Some((_, result)) = line.split_once("test result: ok. ") else {
                return false;
            };
            let passed = result
                .split_once(" passed")
                .map(|(count, _)| count)
                .unwrap_or_default();
            let digits = passed
                .chars()
                .take_while(char::is_ascii_digit)
                .collect::<String>();
            !digits.is_empty() && digits.parse::<usize>().is_ok_and(|count| count > 0)
        })
    })
}

pub(crate) fn ensure_cargo_test_output_format(mut args: Vec<String>) -> Vec<String> {
    let harness_start = args.iter().position(|arg| arg == "--").unwrap_or_else(|| {
        args.push("--".into());
        args.len() - 1
    });
    let mut index = harness_start + 1;
    while index < args.len() {
        if args[index].starts_with("--format=") {
            args.remove(index);
        } else if args[index] == "--format" {
            args.remove(index);
            if index < args.len() {
                args.remove(index);
            }
        } else {
            index += 1;
        }
    }
    args.push("--format=pretty".into());
    args
}

pub(crate) fn go_output_reports_executed_tests(
    stdout: &[u8],
    stderr: &[u8],
    expected_packages: &[String],
    root_package: Option<&str>,
) -> bool {
    let outputs: Vec<String> = [stdout, stderr]
        .into_iter()
        .flat_map(|output| {
            String::from_utf8_lossy(output)
                .lines()
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .collect();
    let mut package_output = std::collections::BTreeMap::<String, String>::new();
    let mut passed_packages = std::collections::BTreeSet::<String>::new();
    let mut passed_test_packages = std::collections::BTreeSet::<String>::new();
    let mut saw_json = false;
    for line in &outputs {
        let Ok(event) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let Some(package) = event.get("Package").and_then(serde_json::Value::as_str) else {
            continue;
        };
        saw_json = true;
        match event.get("Action").and_then(serde_json::Value::as_str) {
            Some("output") => {
                if let Some(output) = event.get("Output").and_then(serde_json::Value::as_str) {
                    package_output
                        .entry(package.into())
                        .or_default()
                        .push_str(output);
                }
            }
            Some("pass") => {
                if event.get("Test").is_some() {
                    passed_test_packages.insert(package.into());
                } else {
                    passed_packages.insert(package.into());
                }
            }
            _ => {}
        }
    }
    let completed_test_packages = if saw_json {
        expected_packages.iter().all(|expected| {
            let expected = expected.strip_prefix("./").unwrap_or(expected);
            let Some(root) = root_package else {
                return false;
            };
            let expected_import_path = if expected.is_empty() {
                root.to_owned()
            } else {
                format!("{}/{expected}", root.trim_end_matches('/'))
            };
            let matching_packages = passed_packages
                .iter()
                .filter(|package| package.as_str() == expected_import_path);
            matching_packages.into_iter().any(|package| {
                passed_test_packages.contains(package)
                    && package_output.get(package).is_none_or(|output| {
                        !output.contains("no test files") && !output.contains("no tests to run")
                    })
            })
        })
    } else {
        false
    };
    !expected_packages.is_empty() && completed_test_packages
}

pub(crate) fn go_module_path(root: &Path) -> Option<String> {
    std::fs::read_to_string(root.join("go.mod"))
        .ok()?
        .lines()
        .find_map(|line| {
            let mut fields = line.split_whitespace();
            if fields.next()? == "module" {
                Some(fields.next()?.trim_matches('"').to_owned())
            } else {
                None
            }
        })
}

pub(crate) fn expand_target_args(
    args: &[String],
    placeholder: &str,
    targets: &[String],
) -> Result<Vec<String>, String> {
    if args
        .iter()
        .filter(|arg| arg.as_str() == placeholder)
        .count()
        != 1
    {
        return Err(format!(
            "{placeholder} must occur exactly once as a standalone argument"
        ));
    }
    let mut expanded = Vec::new();
    for arg in args {
        if arg == placeholder {
            expanded.extend(targets.iter().cloned());
        } else if arg.contains("{impacted_test_") {
            return Err("impact target placeholders must be standalone arguments".into());
        } else {
            expanded.push(arg.clone());
        }
    }
    Ok(expanded)
}

pub(crate) fn expand_rust_target_args(
    args: &[String],
    placeholder: &str,
    package: &str,
    filter: &str,
) -> Result<Vec<String>, String> {
    if args
        .iter()
        .filter(|arg| arg.as_str() == placeholder)
        .count()
        != 1
    {
        return Err(format!(
            "{placeholder} must occur exactly once as a standalone argument"
        ));
    }
    let mut expanded = Vec::new();
    for arg in args {
        if arg == placeholder {
            expanded.extend(["--package".into(), package.into(), filter.into()]);
        } else if arg.contains("{impacted_test_") {
            return Err("impact target placeholders must be standalone arguments".into());
        } else {
            expanded.push(arg.clone());
        }
    }
    Ok(expanded)
}

pub(crate) fn append_bounded_output(
    destination: &mut Vec<u8>,
    label: &[u8],
    output: &[u8],
    limit: usize,
) -> Result<(), String> {
    if destination
        .len()
        .saturating_add(label.len())
        .saturating_add(output.len())
        > limit
    {
        return Err(
            "combined impact-targeted verification output exceeded configured limit".into(),
        );
    }
    destination.extend_from_slice(label);
    destination.extend_from_slice(output);
    Ok(())
}

pub(crate) fn impacted_go_test_packages(
    snapshot: &ChangeSet,
    impact: &ImpactAssessment,
) -> Result<std::collections::BTreeSet<String>, String> {
    let mut targets = std::collections::BTreeSet::new();
    let mut add_test_package = |test_path: &str| -> Result<(), String> {
        let path = Path::new(test_path);
        if path.is_absolute()
            || path.components().any(|part| {
                matches!(
                    part,
                    std::path::Component::ParentDir | std::path::Component::RootDir
                )
            })
        {
            return Err("impact analysis returned an unsafe test path".into());
        }
        let directory = path.parent().unwrap_or_else(|| Path::new("."));
        let package = if directory.as_os_str().is_empty() || directory == Path::new(".") {
            "./".to_owned()
        } else {
            format!("./{}", directory.to_string_lossy().replace('\\', "/"))
        };
        targets.insert(package);
        Ok(())
    };
    for edge in impact.paths.iter().filter(|edge| {
        edge.relationship == "likely_test_reference" && edge.affected_path.ends_with(".go")
    }) {
        add_test_package(&edge.affected_path)?;
    }
    for file in snapshot
        .files
        .iter()
        .filter(|file| file.path.ends_with("_test.go") && file.status != "deleted")
    {
        add_test_package(&file.path)?;
    }
    Ok(targets)
}

pub(crate) fn rust_test_filters_for_impact(
    root: &Path,
    snapshot: &ChangeSet,
    impact: &ImpactAssessment,
) -> Result<std::collections::BTreeSet<String>, String> {
    let mut lines_by_path = std::collections::BTreeMap::<String, Vec<u32>>::new();
    for edge in impact.paths.iter().filter(|edge| {
        edge.relationship == "likely_test_reference" && edge.affected_path.ends_with(".rs")
    }) {
        lines_by_path
            .entry(edge.affected_path.clone())
            .or_default()
            .push(edge.evidence_line);
    }
    let changed_test_paths: std::collections::BTreeSet<_> = snapshot
        .files
        .iter()
        .filter(|file| file.path.ends_with(".rs") && file.status != "deleted")
        .map(|file| file.path.clone())
        .collect();
    let mut rust_source = std::collections::BTreeMap::new();
    let mut rust_paths: std::collections::BTreeSet<String> = impact
        .groups
        .iter()
        .filter(|group| group.package_id.starts_with("rust:"))
        .flat_map(|group| group.member_paths.iter().cloned())
        .filter(|path| path.ends_with(".rs"))
        .collect();
    rust_paths.extend(changed_test_paths.iter().cloned());
    for path in rust_paths {
        if let Some(bytes) = vero_git::read_snapshot_file(root, snapshot, Path::new(&path))? {
            if let Ok(text) = String::from_utf8(bytes) {
                rust_source.insert(path, text);
            }
        }
    }
    let rust_test_modules = rust_test_module_paths(&rust_source);
    for path in &changed_test_paths {
        lines_by_path.entry(path.clone()).or_default();
    }
    let mut filters = std::collections::BTreeSet::new();
    let mut helper_reference_needs_package_fallback = false;
    let mut helper_reference_paths = std::collections::BTreeSet::new();
    let mut conditional_test_paths = std::collections::BTreeSet::new();
    for (path, lines) in lines_by_path {
        let bytes = vero_git::read_snapshot_file(root, snapshot, Path::new(&path))?
            .ok_or_else(|| format!("impact test source {path} is missing from the snapshot"))?;
        let source = String::from_utf8(bytes)
            .map_err(|_| format!("impact test source {path} is not valid UTF-8"))?;
        let file = syn::parse_file(&source)
            .map_err(|error| format!("could not parse impacted Rust tests in {path}: {error}"))?;
        let test_module = rust_test_modules.get(&path);
        struct TestsAtLines<'a> {
            lines: &'a [u32],
            names: std::collections::BTreeSet<String>,
            all_names: std::collections::BTreeSet<String>,
            covered_lines: std::collections::BTreeSet<u32>,
            has_conditional_tests: bool,
            conditional_test_module_depth: usize,
            module_path: Vec<String>,
        }
        impl<'ast> syn::visit::Visit<'ast> for TestsAtLines<'_> {
            fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
                let conditional = has_non_test_cfg(&item.attrs);
                if conditional {
                    self.conditional_test_module_depth += 1;
                }
                if item.content.is_some() {
                    self.module_path.push(item.ident.to_string());
                }
                syn::visit::visit_item_mod(self, item);
                if item.content.is_some() {
                    self.module_path.pop();
                }
                if conditional {
                    self.conditional_test_module_depth -= 1;
                }
            }
            fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
                let start = item.sig.ident.span().start().line as u32;
                let end = item.block.brace_token.span.close().start().line as u32;
                if has_test_attribute(&item.attrs) {
                    if self.conditional_test_module_depth > 0 {
                        self.has_conditional_tests = true;
                    }
                    let mut module_path = self.module_path.clone();
                    module_path.push(item.sig.ident.to_string());
                    let name = module_path.join("::");
                    if has_non_test_cfg(&item.attrs) {
                        self.has_conditional_tests = true;
                    } else {
                        self.all_names.insert(name.clone());
                    }
                    if self
                        .lines
                        .iter()
                        .any(|line| (*line >= start) && (*line <= end))
                    {
                        self.names.insert(name);
                        self.covered_lines.extend(
                            self.lines
                                .iter()
                                .copied()
                                .filter(|line| *line >= start && *line <= end),
                        );
                    }
                }
                syn::visit::visit_item_fn(self, item);
            }
        }
        let mut visitor = TestsAtLines {
            lines: &lines,
            names: std::collections::BTreeSet::new(),
            all_names: std::collections::BTreeSet::new(),
            covered_lines: std::collections::BTreeSet::new(),
            has_conditional_tests: false,
            conditional_test_module_depth: 0,
            module_path: test_module
                .map(|context| context.module_path.clone())
                .unwrap_or_default(),
        };
        syn::visit::Visit::visit_file(&mut visitor, &file);
        if test_module.is_some_and(|context| context.conditional) {
            visitor.has_conditional_tests = true;
        }
        if visitor.has_conditional_tests {
            conditional_test_paths.insert(path.clone());
        }
        if changed_test_paths.contains(&path) {
            visitor.names = visitor.all_names.clone();
        }
        if !lines.is_empty()
            && lines
                .iter()
                .any(|line| !visitor.covered_lines.contains(line))
        {
            helper_reference_needs_package_fallback = true;
            helper_reference_paths.insert(path.clone());
            visitor.names = visitor.all_names;
        }
        if !visitor.names.is_empty() {
            if visitor.has_conditional_tests {
                continue;
            }
            let package = rust_package_name_for_path(impact, &path).ok_or_else(|| {
                format!("could not identify the Cargo package for impacted test source {path}")
            })?;
            filters.extend(
                visitor
                    .names
                    .into_iter()
                    .map(|name| format!("{package}::{name}")),
            );
        }
    }
    if !conditional_test_paths.is_empty() {
        // Rust cfg expressions depend on the Cargo feature/target invocation. When
        // affected files contain conditional tests, select their whole package so
        // Cargo evaluates cfg and executes every enabled test.
        let package_ids: std::collections::BTreeSet<_> = impact
            .groups
            .iter()
            .filter(|group| {
                group.package_id.starts_with("rust:")
                    && conditional_test_paths
                        .iter()
                        .any(|path| group.member_paths.contains(path))
            })
            .map(|group| group.package_id.clone())
            .collect();
        for package_id in package_ids {
            let package_name = package_id
                .rsplit(':')
                .next()
                .filter(|name| !name.is_empty())
                .ok_or_else(|| format!("could not identify Cargo package name in {package_id}"))?;
            let member_paths: std::collections::BTreeSet<_> = impact
                .groups
                .iter()
                .filter(|group| group.package_id == package_id)
                .flat_map(|group| group.member_paths.iter().cloned())
                .filter(|path| path.ends_with(".rs"))
                .collect();
            let mut conditional_tests = false;
            let mut package_test_names = std::collections::BTreeSet::new();
            struct PackageTests<'a> {
                conditional: &'a mut bool,
                names: &'a mut std::collections::BTreeSet<String>,
                module_path: Vec<String>,
            }
            impl<'ast> syn::visit::Visit<'ast> for PackageTests<'_> {
                fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
                    *self.conditional |= has_non_test_cfg(&item.attrs);
                    if item.content.is_some() {
                        self.module_path.push(item.ident.to_string());
                    }
                    syn::visit::visit_item_mod(self, item);
                    if item.content.is_some() {
                        self.module_path.pop();
                    }
                }
                fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
                    if has_test_attribute(&item.attrs) {
                        if has_non_test_cfg(&item.attrs) {
                            *self.conditional = true;
                        }
                        let mut module_path = self.module_path.clone();
                        module_path.push(item.sig.ident.to_string());
                        self.names.insert(module_path.join("::"));
                    }
                    syn::visit::visit_item_fn(self, item);
                }
            }
            for path in member_paths {
                let Some(bytes) = vero_git::read_snapshot_file(root, snapshot, Path::new(&path))?
                else {
                    continue;
                };
                let Ok(source) = String::from_utf8(bytes) else {
                    continue;
                };
                let Ok(file) = syn::parse_file(&source) else {
                    continue;
                };
                let module_path = rust_test_modules
                    .get(&path)
                    .map(|context| context.module_path.clone())
                    .unwrap_or_default();
                syn::visit::Visit::visit_file(
                    &mut PackageTests {
                        conditional: &mut conditional_tests,
                        names: &mut package_test_names,
                        module_path,
                    },
                    &file,
                );
            }
            filters.retain(|target| !target.starts_with(&format!("{package_name}::")));
            // Include conditional test names too: Cargo evaluates their cfgs for
            // the active feature/target set, while the package-qualified filters
            // retain precise test reporting and avoid invalid broad package args.
            if conditional_tests {
                filters.retain(|target| !target.starts_with(&format!("{package_name}::")));
                filters.insert(format!("{package_name}::"));
                continue;
            }
            filters.extend(
                package_test_names
                    .into_iter()
                    .map(|name| format!("{package_name}::{name}")),
            );
        }
    }
    if helper_reference_needs_package_fallback {
        // A changed symbol can be referenced from a test helper outside a test function.
        // The helper's callers may live in other files, so include every test in the
        // affected Rust package instead of silently narrowing to tests in the helper file.
        let package_ids: std::collections::BTreeSet<_> = impact
            .groups
            .iter()
            .filter(|group| {
                group.package_id.starts_with("rust:")
                    && helper_reference_paths
                        .iter()
                        .any(|path| group.member_paths.contains(path))
            })
            .map(|group| group.package_id.clone())
            .collect();
        for package_id in package_ids {
            let package_name = package_id
                .rsplit(':')
                .next()
                .filter(|name| !name.is_empty())
                .ok_or_else(|| format!("could not identify Cargo package name in {package_id}"))?;
            let members: std::collections::BTreeSet<_> = impact
                .groups
                .iter()
                .filter(|group| group.package_id == package_id)
                .flat_map(|group| group.member_paths.iter().cloned())
                .filter(|path| path.ends_with(".rs"))
                .collect();
            let mut conditional = false;
            let mut names = std::collections::BTreeSet::new();
            struct PackageTests<'a> {
                conditional: &'a mut bool,
                names: &'a mut std::collections::BTreeSet<String>,
                module_path: Vec<String>,
            }
            impl<'ast> syn::visit::Visit<'ast> for PackageTests<'_> {
                fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
                    *self.conditional |= has_non_test_cfg(&item.attrs);
                    if item.content.is_some() {
                        self.module_path.push(item.ident.to_string());
                    }
                    syn::visit::visit_item_mod(self, item);
                    if item.content.is_some() {
                        self.module_path.pop();
                    }
                }
                fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
                    if has_test_attribute(&item.attrs) {
                        *self.conditional |= has_non_test_cfg(&item.attrs);
                        let mut module_path = self.module_path.clone();
                        module_path.push(item.sig.ident.to_string());
                        self.names.insert(module_path.join("::"));
                    }
                    syn::visit::visit_item_fn(self, item);
                }
            }
            for path in members {
                let Some(bytes) = vero_git::read_snapshot_file(root, snapshot, Path::new(&path))?
                else {
                    continue;
                };
                let Ok(source) = String::from_utf8(bytes) else {
                    continue;
                };
                let Ok(file) = syn::parse_file(&source) else {
                    continue;
                };
                let module_path = rust_test_modules
                    .get(&path)
                    .map(|context| context.module_path.clone())
                    .unwrap_or_default();
                syn::visit::Visit::visit_file(
                    &mut PackageTests {
                        conditional: &mut conditional,
                        names: &mut names,
                        module_path,
                    },
                    &file,
                );
            }
            if conditional {
                filters.retain(|target| !target.starts_with(&format!("{package_name}::")));
                filters.insert(format!("{package_name}::"));
            } else {
                filters.extend(
                    names
                        .into_iter()
                        .map(|name| format!("{package_name}::{name}")),
                );
            }
        }
    }
    Ok(filters)
}

pub(crate) fn rust_package_name_for_path(impact: &ImpactAssessment, path: &str) -> Option<String> {
    impact
        .groups
        .iter()
        .find(|group| {
            group.package_id.starts_with("rust:")
                && group.member_paths.iter().any(|member| member == path)
        })
        .and_then(|group| group.package_id.rsplit(':').next())
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
}

pub(crate) fn ensure_snapshot_current(
    root: &Path,
    snapshot: &ChangeSet,
    phase: &str,
) -> Result<(), String> {
    if snapshot.scope == "staged" && !vero_git::working_tree_matches_index(root)? {
        return Err("staged verification requires a working tree matching the Git index".into());
    }
    let current = capture_current_change_set(root, snapshot)?;
    if current.digest != snapshot.digest {
        return Err(format!(
            "verification changed the reviewed source snapshot {phase}"
        ));
    }
    Ok(())
}

pub fn run_finding_verification(
    root: &Path,
    snapshot: &ChangeSet,
    finding_id: &str,
    profile_id: &str,
    config: &RepositoryConfig,
    store: &mut dyn Repositories,
) -> Result<VerificationRun, String> {
    ensure_snapshot_current(root, snapshot, "before finding verification")?;
    if finding_id.trim().is_empty() {
        return Err("finding ID must not be empty".into());
    }
    let finding = store
        .finding(finding_id)?
        .ok_or_else(|| format!("finding {finding_id} was not found"))?;
    if !finding
        .occurrences
        .iter()
        .any(|occurrence| occurrence.snapshot_id == snapshot.digest)
    {
        return Err(format!(
            "finding {finding_id} has no occurrence in snapshot {}",
            snapshot.digest
        ));
    }
    let profile = config
        .verification
        .get(profile_id)
        .ok_or_else(|| format!("unknown verification profile {profile_id}"))?;
    let execution =
        vero_process::execute_verification_capture(&snapshot.digest, profile_id, root, profile)?;
    ensure_snapshot_current(root, snapshot, "during finding verification")?;
    let mut run = persist_verification_output(root, execution)?;
    run.finding_id = Some(finding_id.into());
    run.run_id = digest(
        &serde_json::to_vec(&(
            "vero-finding-verification-v1",
            finding_id,
            run.snapshot_id.as_str(),
            run.profile_id.as_str(),
            run.command_digest.as_str(),
            run.status,
            run.exit_code,
            run.stdout_digest.as_str(),
            run.stderr_digest.as_str(),
        ))
        .map_err(|error| error.to_string())?,
    );
    store.save_verification_with_artifacts(&run)?;
    Ok(run)
}

pub(crate) fn persist_verification_output(
    root: &Path,
    mut execution: vero_core::VerificationExecution,
) -> Result<VerificationRun, String> {
    execution.run.stdout_artifact = Some(persist_artifact(
        root,
        &execution.stdout,
        &execution.run.stdout_digest,
    )?);
    execution.run.stderr_artifact = Some(persist_artifact(
        root,
        &execution.stderr,
        &execution.run.stderr_digest,
    )?);
    Ok(execution.run)
}

pub(crate) fn persist_artifact(
    root: &Path,
    bytes: &[u8],
    expected_digest: &str,
) -> Result<vero_core::ArtifactReference, String> {
    use std::io::Write;

    if digest(bytes) != expected_digest {
        return Err("verification output digest changed before artifact persistence".into());
    }
    let digest_hex = expected_digest
        .strip_prefix("sha256:")
        .ok_or("verification output has an unsupported digest format")?;
    if digest_hex.len() != 64 || !digest_hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("verification output has an invalid SHA-256 digest".into());
    }
    let mut directory = root.join(".vero");
    for component in ["artifacts", "sha256"] {
        ensure_local_directory(&directory)?;
        directory.push(component);
    }
    ensure_local_directory(&directory)?;
    let destination = directory.join(digest_hex);
    match std::fs::symlink_metadata(&destination) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            return Err("verification artifact destination is not a regular file".into());
        }
        Ok(_) => {
            let existing = std::fs::read(&destination).map_err(|error| error.to_string())?;
            if existing != bytes || digest(&existing) != expected_digest {
                return Err(
                    "content-addressed verification artifact failed integrity check".into(),
                );
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut temporary = tempfile::NamedTempFile::new_in(&directory)
                .map_err(|error| format!("creating verification artifact: {error}"))?;
            temporary
                .write_all(bytes)
                .map_err(|error| format!("writing verification artifact: {error}"))?;
            match temporary.persist_noclobber(&destination) {
                Ok(_) => {}
                Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
                    let existing =
                        std::fs::read(&destination).map_err(|error| error.to_string())?;
                    if existing != bytes || digest(&existing) != expected_digest {
                        return Err(
                            "content-addressed verification artifact failed integrity check".into(),
                        );
                    }
                }
                Err(error) => {
                    return Err(format!("persisting verification artifact: {}", error.error))
                }
            }
        }
        Err(error) => return Err(format!("checking verification artifact path: {error}")),
    }
    let path = format!(".vero/artifacts/sha256/{digest_hex}");
    Ok(vero_core::ArtifactReference {
        digest: expected_digest.into(),
        path,
        size_bytes: bytes.len() as u64,
    })
}

pub(crate) fn ensure_local_directory(path: &Path) -> Result<(), String> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => Ok(()),
        Ok(_) => Err(format!(
            "artifact directory is not a real directory: {}",
            path.display()
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => std::fs::create_dir(path)
            .map_err(|error| format!("creating {}: {error}", path.display())),
        Err(error) => Err(format!("checking {}: {error}", path.display())),
    }
}

#[cfg(test)]
#[path = "tests/verification.rs"]
mod tests;
