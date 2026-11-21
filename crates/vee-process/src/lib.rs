//! Process adapter: runs reviewer provider CLIs and trusted verification
//! commands as bounded subprocesses, with timeouts, cancellation, output
//! limits, secret redaction, and process-group cleanup.

use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use vee_core::paths::CanonicalPath as _;
use vee_core::*;

pub fn execute_verification(
    snapshot_id: &str,
    profile_id: &str,
    working_directory: &Path,
    profile: &VerificationProfile,
) -> Result<VerificationRun, String> {
    Ok(execute_verification_capture(snapshot_id, profile_id, working_directory, profile)?.run)
}

pub fn execute_verification_capture(
    snapshot_id: &str,
    profile_id: &str,
    working_directory: &Path,
    profile: &VerificationProfile,
) -> Result<VerificationExecution, String> {
    use std::{
        io::Read,
        process::{Command, Stdio},
        thread,
        time::{Duration, Instant},
    };
    if profile.executable.trim().is_empty() || profile.timeout_seconds == 0 {
        return Err("verification executable and positive timeout are required".into());
    }
    let environment =
        resolve_environment_allowlist(&profile.env_allowlist, |name| std::env::var(name).ok())?;
    let executable = resolve_verification_executable(&profile.executable, working_directory)?;
    let executable_digest = digest_file(&executable)?;
    let executable_identity = verification_executable_identity(&profile.executable, &executable);
    let environment_digests = environment
        .iter()
        .map(|(name, value)| (name, digest(value.as_bytes())))
        .collect::<Vec<_>>();
    let command_digest = verification_invocation_digest(
        profile,
        &executable_identity,
        &executable_digest,
        &environment_digests,
    )?;
    let mut command = Command::new(&executable);
    command.args(&profile.args);
    configure_process_group(&mut command);
    let mut child = command
        .env_clear()
        .envs(platform_environment())
        .envs(environment.iter().cloned())
        .current_dir(working_directory)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("starting verification profile {profile_id}: {error}"))?;
    let limit = profile.output_limit_bytes;
    let stdout = child.stdout.take().expect("piped stdout");
    let stderr = child.stderr.take().expect("piped stderr");
    let stdout_thread = thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = stdout.take((limit + 1) as u64).read_to_end(&mut bytes);
        bytes
    });
    let stderr_thread = thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = stderr.take((limit + 1) as u64).read_to_end(&mut bytes);
        bytes
    });
    let started = Instant::now();
    let mut status = loop {
        if let Some(status) = child.try_wait().map_err(|error| error.to_string())? {
            break if status.success() {
                VerificationStatus::Passed
            } else {
                VerificationStatus::Failed
            };
        }
        if started.elapsed() >= Duration::from_secs(profile.timeout_seconds) {
            terminate_process_tree(&mut child);
            break VerificationStatus::TimedOut;
        }
        thread::sleep(Duration::from_millis(10));
    };
    let exit_code = child
        .try_wait()
        .ok()
        .flatten()
        .and_then(|status| status.code());
    let mut stdout = stdout_thread
        .join()
        .map_err(|_| "verification stdout reader failed")?;
    let mut stderr = stderr_thread
        .join()
        .map_err(|_| "verification stderr reader failed")?;
    if status == VerificationStatus::Failed
        && is_known_incomplete_verification_output(&stdout, &stderr)
    {
        status = VerificationStatus::Incomplete;
    }
    if stdout.len().saturating_add(stderr.len()) > limit {
        return Err("verification output exceeded configured limit".into());
    }
    if digest_file(&executable)? != executable_digest {
        return Err("verification executable changed while the command was running".into());
    }
    let current_environment =
        resolve_environment_allowlist(&profile.env_allowlist, |name| std::env::var(name).ok())?;
    let current_environment_digests = current_environment
        .iter()
        .map(|(name, value)| (name, digest(value.as_bytes())))
        .collect::<Vec<_>>();
    if current_environment_digests != environment_digests {
        return Err("verification environment changed while the command was running".into());
    }
    redact_output_values(&mut stdout, &environment);
    redact_output_values(&mut stderr, &environment);
    let stdout_digest = digest(&stdout);
    let stderr_digest = digest(&stderr);
    let run_id = digest(
        &serde_json::to_vec(&(
            snapshot_id,
            profile_id,
            &command_digest,
            status,
            exit_code,
            &stdout_digest,
            &stderr_digest,
        ))
        .map_err(|error| error.to_string())?,
    );
    Ok(VerificationExecution {
        run: VerificationRun {
            schema_version: SCHEMA_VERSION,
            run_id,
            snapshot_id: snapshot_id.into(),
            profile_id: profile_id.into(),
            finding_id: None,
            targets: Vec::new(),
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
    })
}

/// Classify well-known offline dependency-resolution failures as incomplete
/// verification, not failing tests. Markers are deliberately narrow: generic
/// nonzero exits remain test failures, and the raw output remains available.
fn is_known_incomplete_verification_output(stdout: &[u8], stderr: &[u8]) -> bool {
    const MARKERS: [&str; 3] = [
        "module lookup disabled by GOPROXY",
        "module lookup disabled by GOSUMDB",
        "attempting to make an HTTP request, but --offline was specified",
    ];
    MARKERS.iter().any(|marker| {
        stdout
            .windows(marker.len())
            .any(|window| window == marker.as_bytes())
            || stderr
                .windows(marker.len())
                .any(|window| window == marker.as_bytes())
    })
}

/// Fingerprint the configured invocation together with the resolved executable bytes and
/// digests of present allowlisted environment values. Raw environment values are never returned.
pub fn verification_command_digest(
    profile: &VerificationProfile,
    working_directory: &Path,
) -> Result<String, String> {
    let environment =
        resolve_environment_allowlist(&profile.env_allowlist, |name| std::env::var(name).ok())?;
    let executable = resolve_verification_executable(&profile.executable, working_directory)?;
    let executable_digest = digest_file(&executable)?;
    let executable_identity = verification_executable_identity(&profile.executable, &executable);
    let environment_digests = environment
        .iter()
        .map(|(name, value)| (name, digest(value.as_bytes())))
        .collect::<Vec<_>>();
    verification_invocation_digest(
        profile,
        &executable_identity,
        &executable_digest,
        &environment_digests,
    )
}

fn verification_invocation_digest(
    profile: &VerificationProfile,
    executable_identity: &str,
    executable_digest: &str,
    environment_digests: &[(&String, String)],
) -> Result<String, String> {
    Ok(digest(
        &serde_json::to_vec(&(
            "vee-verification-invocation-v2",
            profile,
            executable_identity,
            executable_digest,
            environment_digests,
        ))
        .map_err(|error| error.to_string())?,
    ))
}

fn verification_executable_identity(requested: &str, resolved: &Path) -> String {
    let path = Path::new(requested);
    if path.is_absolute() || path.components().count() > 1 {
        requested.replace('\\', "/")
    } else {
        resolved.to_string_lossy().replace('\\', "/")
    }
}

fn resolve_verification_executable(
    executable: &str,
    working_directory: &Path,
) -> Result<PathBuf, String> {
    resolve_executable_with_path(
        "verification",
        executable,
        working_directory,
        std::env::var_os("PATH"),
    )
}

fn default_verification_search_path() -> std::ffi::OsString {
    #[cfg(unix)]
    {
        "/usr/bin:/bin".into()
    }
    #[cfg(windows)]
    {
        let system_root = std::env::var_os("SystemRoot")
            .or_else(|| std::env::var_os("WINDIR"))
            .unwrap_or_else(|| r"C:\Windows".into());
        let system32 = PathBuf::from(&system_root).join("System32");
        std::env::join_paths([system32, PathBuf::from(system_root)]).unwrap_or_default()
    }
    #[cfg(not(any(unix, windows)))]
    {
        std::ffi::OsString::new()
    }
}

/// The files that may run as `path`. On Windows a name without an extension
/// runs only with one of the `PATHEXT` extensions, never as itself, so an
/// extensionless shell shim beside `cargo.exe` is not chosen.
fn executable_candidates(path: &Path) -> Vec<PathBuf> {
    #[cfg(windows)]
    if path.extension().is_none() {
        let extensions =
            std::env::var_os("PATHEXT").unwrap_or_else(|| ".COM;.EXE;.BAT;.CMD".into());
        return extensions
            .to_string_lossy()
            .split(';')
            .filter(|extension| !extension.is_empty())
            .map(|extension| {
                let mut candidate = path.as_os_str().to_owned();
                candidate.push(extension);
                PathBuf::from(candidate)
            })
            .collect();
    }
    vec![path.to_path_buf()]
}

/// Resolves `executable` to an absolute path: relative to `working_directory`
/// when it has a path component, otherwise on `path` (the system default when
/// unset). Child processes start with a cleared environment, so bare names must
/// be resolved against this process's search path before spawning. `role`
/// names the executable in errors.
fn resolve_executable_with_path(
    role: &str,
    executable: &str,
    working_directory: &Path,
    path: Option<std::ffi::OsString>,
) -> Result<PathBuf, String> {
    let requested = Path::new(executable);
    let has_path_component = requested.components().count() > 1 || requested.is_absolute();
    let mut candidates = Vec::new();
    if has_path_component {
        let explicit_path = if requested.is_absolute() {
            requested.to_path_buf()
        } else {
            working_directory.join(requested)
        };
        candidates.extend(executable_candidates(&explicit_path));
    } else {
        let search_path = path.unwrap_or_else(default_verification_search_path);
        for directory in std::env::split_paths(&search_path) {
            let directory = if directory.is_absolute() {
                directory
            } else {
                working_directory.join(directory)
            };
            candidates.extend(executable_candidates(&directory.join(requested)));
        }
    }
    if let Some(candidate) = first_executable_candidate(candidates)? {
        let absolute = if candidate.is_absolute() {
            candidate
        } else {
            std::env::current_dir()
                .map_err(|error| error.to_string())?
                .join(candidate)
        };
        if std::fs::symlink_metadata(&absolute)
            .map_err(|error| error.to_string())?
            .file_type()
            .is_symlink()
        {
            // Preserve argv[0] for command-name-dispatching shims such as
            // rustup's `cargo` and `rustc` symlinks. File reads still follow
            // the link, so executable hashing binds the underlying bytes.
            return Ok(absolute);
        }
        return absolute.canonical().map_err(|error| {
            format!(
                "resolving {role} executable {}: {error}",
                absolute.display()
            )
        });
    }
    Err(format!(
        "{role} executable {executable:?} was not found as an executable file"
    ))
}

fn first_executable_candidate(
    candidates: impl IntoIterator<Item = PathBuf>,
) -> Result<Option<PathBuf>, String> {
    for candidate in candidates {
        if candidate.is_file() && is_executable_file(&candidate)? {
            return Ok(Some(candidate));
        }
    }
    Ok(None)
}

fn is_executable_file(path: &Path) -> Result<bool, String> {
    let metadata = std::fs::metadata(path).map_err(|error| error.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        Ok(metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
    }
    // Elsewhere any regular file may run; the candidate list already limits
    // Windows to PATHEXT extensions.
    #[cfg(not(unix))]
    {
        Ok(metadata.is_file())
    }
}

fn digest_file(path: &Path) -> Result<String, String> {
    use std::io::Read;
    let mut file = std::fs::File::open(path).map_err(|error| {
        format!(
            "reading verification executable {}: {error}",
            path.display()
        )
    })?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|error| error.to_string())?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let digest: String = hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    Ok(format!("sha256:{digest}"))
}

fn redact_output_values(output: &mut Vec<u8>, environment: &[(String, String)]) {
    let mut values: Vec<&[u8]> = environment
        .iter()
        .map(|(_, value)| value.as_bytes())
        .filter(|value| !value.is_empty())
        .collect();
    values.sort_by_key(|value| std::cmp::Reverse(value.len()));
    for secret in values {
        let mut redacted = Vec::with_capacity(output.len());
        let mut cursor = 0;
        while cursor < output.len() {
            if output[cursor..].starts_with(secret) {
                redacted.extend_from_slice(b"[REDACTED]");
                cursor += secret.len();
            } else {
                redacted.push(output[cursor]);
                cursor += 1;
            }
        }
        *output = redacted;
    }
}

pub fn execute_provider(request: &ProviderRequest) -> Result<ProviderResult, String> {
    execute_provider_cancellable(request, None)
}

pub fn execute_provider_cancellable(
    request: &ProviderRequest,
    cancellation: Option<&tokio_util::sync::CancellationToken>,
) -> Result<ProviderResult, String> {
    use std::{
        io::{Read, Write},
        process::{Command, Stdio},
        thread,
        time::{Duration, Instant},
    };
    if request.executable.trim().is_empty() {
        return Err("provider executable is empty".into());
    }
    if request.kind != ProviderKind::Cli {
        return Err("provider-specific requests must use their adapter".into());
    }
    let executable = resolve_executable_with_path(
        "provider",
        &request.executable,
        &request.working_directory,
        std::env::var_os("PATH"),
    )?;
    let isolated_directory = tempfile::tempdir()
        .map_err(|error| format!("creating provider working directory: {error}"))?;
    let mut command = Command::new(executable);
    command.args(&request.args);
    command.current_dir(isolated_directory.path());
    configure_process_group(&mut command);
    let mut child = command
        .env_clear()
        .envs(platform_environment())
        .envs(request.environment.iter().cloned())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("starting provider: {e}"))?;
    let mut input = child.stdin.take().expect("piped stdin");
    let request_input = request.stdin.clone();
    let input_thread = thread::spawn(move || input.write_all(&request_input));
    let stdout = child.stdout.take().expect("piped stdout");
    let stderr = child.stderr.take().expect("piped stderr");
    let limit = request.output_limit_bytes;
    let stdout_thread = thread::spawn(move || {
        let mut b = Vec::new();
        let _ = stdout.take((limit + 1) as u64).read_to_end(&mut b);
        b
    });
    let stderr_thread = thread::spawn(move || {
        let mut b = Vec::new();
        let _ = stderr.take((limit + 1) as u64).read_to_end(&mut b);
        b
    });
    let started = Instant::now();
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|e| format!("waiting for provider: {e}"))?
        {
            let _ = input_thread.join();
            let stdout = stdout_thread
                .join()
                .map_err(|_| "provider stdout reader failed")?;
            let stderr = stderr_thread
                .join()
                .map_err(|_| "provider stderr reader failed")?;
            if stdout.len() + stderr.len() > request.output_limit_bytes {
                return Err(format!(
                    "provider output exceeded configured limit (stdout {} bytes, stderr {} bytes, limit {} bytes)",
                    stdout.len(),
                    stderr.len(),
                    request.output_limit_bytes
                ));
            }
            if !status.success() {
                let mut stderr = stderr;
                redact_output_values(&mut stderr, &request.environment);
                let detail = String::from_utf8_lossy(&stderr);
                let detail = detail
                    .rsplit_once("Error:")
                    .map(|(_, message)| format!("Error:{}", message.trim()))
                    .unwrap_or_else(|| {
                        if detail.trim().is_empty() {
                            String::new()
                        } else {
                            format!("provider wrote {} bytes of stderr", stderr.len())
                        }
                    });
                let detail: String = detail.chars().take(2048).collect();
                let detail = if detail.is_empty() {
                    String::new()
                } else {
                    format!("; stderr: {detail}")
                };
                return Err(format!(
                    "provider exited with {}{detail}",
                    status.code().map_or("signal".into(), |c| c.to_string()),
                ));
            }
            return Ok(ProviderResult {
                stdout,
                stderr,
                exit_code: status.code(),
                usage: None,
            });
        }
        if cancellation.is_some_and(|token| token.is_cancelled()) {
            terminate_process_tree(&mut child);
            let _ = input_thread.join();
            let _ = stdout_thread.join();
            let _ = stderr_thread.join();
            return Err("provider execution cancelled".into());
        }
        if started.elapsed() >= Duration::from_secs(request.timeout_seconds) {
            terminate_process_tree(&mut child);
            let _ = input_thread.join();
            let _ = stdout_thread.join();
            let _ = stderr_thread.join();
            return Err("provider timed out".into());
        }
        thread::sleep(Duration::from_millis(20));
    }
}

/// Variables that Windows programs need to start (`SYSTEMROOT`), find
/// temporary and per-user directories (`TEMP`, `LOCALAPPDATA`, ...), and
/// resolve executables (`PATHEXT`). None carries credentials. Child processes
/// that otherwise start from an empty environment receive these, below any
/// explicitly allowed variables. Empty elsewhere, where `PATH` and `HOME` are
/// enough and are allowed explicitly.
pub const PLATFORM_ENVIRONMENT: &[&str] = if cfg!(windows) {
    &[
        "SYSTEMROOT",
        "SYSTEMDRIVE",
        "WINDIR",
        "COMSPEC",
        "PATHEXT",
        "TEMP",
        "TMP",
        "USERPROFILE",
        "HOMEDRIVE",
        "HOMEPATH",
        "APPDATA",
        "LOCALAPPDATA",
        "PROGRAMDATA",
        "PROGRAMFILES",
        "PROGRAMFILES(X86)",
        "PROGRAMW6432",
        "COMMONPROGRAMFILES",
        "NUMBER_OF_PROCESSORS",
        "PROCESSOR_ARCHITECTURE",
    ]
} else {
    &[]
};

/// The [`PLATFORM_ENVIRONMENT`] variables this process has, for
/// `Command::envs` right after `env_clear` and before explicitly allowed
/// variables.
pub fn platform_environment() -> Vec<(&'static str, std::ffi::OsString)> {
    PLATFORM_ENVIRONMENT
        .iter()
        .filter_map(|name| Some((*name, std::env::var_os(name)?)))
        .collect()
}

#[cfg(unix)]
fn configure_process_group(command: &mut std::process::Command) {
    use std::os::unix::process::CommandExt;
    command.process_group(0);
}

#[cfg(not(unix))]
fn configure_process_group(_command: &mut std::process::Command) {}

#[cfg(unix)]
fn terminate_process_tree(child: &mut std::process::Child) {
    let process_group = child.id() as i32;
    unsafe {
        libc::kill(-process_group, libc::SIGKILL);
    }
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(not(unix))]
fn terminate_process_tree(child: &mut std::process::Child) {
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    #[test]
    fn windows_verification_lookup_ignores_extensionless_shims() {
        let directory = tempfile::tempdir().unwrap();
        // A shell shim without an extension, as Git for Windows and some
        // toolchains install, must not shadow the real executable.
        std::fs::write(directory.path().join("tool"), "#!/bin/sh\n").unwrap();
        let system_root = std::env::var_os("SYSTEMROOT").unwrap();
        std::fs::copy(
            PathBuf::from(system_root)
                .join("System32")
                .join("where.exe"),
            directory.path().join("tool.exe"),
        )
        .unwrap();
        let resolved = resolve_executable_with_path(
            "verification",
            "tool",
            directory.path(),
            Some(directory.path().as_os_str().to_owned()),
        )
        .unwrap();
        assert_eq!(
            resolved.file_name().unwrap().to_ascii_lowercase(),
            "tool.exe"
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_children_receive_the_platform_environment() {
        let mut command = std::process::Command::new("cmd");
        command
            .args(["/C", "echo %SYSTEMROOT%"])
            .env_clear()
            .envs(platform_environment());
        let output = command.output().unwrap();
        let echoed = String::from_utf8_lossy(&output.stdout);
        assert!(!echoed.contains("%SYSTEMROOT%"), "{echoed}");
        assert!(echoed.to_ascii_lowercase().contains("windows"), "{echoed}");
    }

    #[cfg(unix)]
    #[test]
    fn unix_children_receive_no_implicit_environment() {
        let mut command = std::process::Command::new("/usr/bin/env");
        command.env_clear().envs(platform_environment());
        let output = command.output().unwrap();
        assert!(output.status.success());
        assert_eq!(String::from_utf8_lossy(&output.stdout), "");
    }

    #[cfg(unix)]
    #[test]
    fn verification_path_lookup_skips_non_executable_files() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let earlier = directory.path().join("earlier");
        let later = directory.path().join("later");
        std::fs::create_dir_all(&earlier).unwrap();
        std::fs::create_dir_all(&later).unwrap();
        let earlier_candidate = earlier.join("cargo");
        let later_candidate = later.join("cargo");
        std::fs::write(&earlier_candidate, "not executable").unwrap();
        std::fs::set_permissions(&earlier_candidate, std::fs::Permissions::from_mode(0o644))
            .unwrap();
        std::fs::write(&later_candidate, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&later_candidate, std::fs::Permissions::from_mode(0o755)).unwrap();

        let resolved =
            first_executable_candidate([earlier_candidate, later_candidate.clone()]).unwrap();
        assert_eq!(resolved, Some(later_candidate));
    }

    #[cfg(unix)]
    #[test]
    fn verification_executable_uses_platform_default_when_path_is_unset() {
        let directory = tempfile::tempdir().unwrap();
        let resolved =
            resolve_executable_with_path("verification", "sh", directory.path(), None).unwrap();
        assert!(resolved.ends_with("sh"), "resolved {resolved:?}");
        assert!(resolved.is_absolute());
    }

    #[cfg(unix)]
    #[test]
    fn provider_receives_stdin_without_shell_and_enforces_output_bound() {
        let working_dir = tempfile::tempdir().unwrap();
        let ok = ProviderRequest {
            kind: ProviderKind::Cli,
            executable: "/usr/bin/touch".into(),
            args: vec!["provider-relative-file".into()],
            model: None,
            working_directory: working_dir.path().into(),
            stdin: vec![],
            timeout_seconds: 2,
            output_limit_bytes: 4096,
            context_window_tokens: None,
            max_output_tokens: None,
            environment: vec![("VEE_TEST_ALLOWED".into(), "present".into())],
            sample: None,
        };
        let _result = execute_provider(&ok).unwrap();
        assert!(!working_dir.path().join("provider-relative-file").exists());
        let too_small = ProviderRequest {
            kind: ProviderKind::Cli,
            executable: "/bin/echo".into(),
            args: vec!["this output is too large".into()],
            model: None,
            working_directory: ".".into(),
            stdin: vec![],
            output_limit_bytes: 3,
            context_window_tokens: None,
            max_output_tokens: None,
            environment: vec![],
            timeout_seconds: 2,
            sample: None,
        };
        assert!(execute_provider(&too_small)
            .unwrap_err()
            .contains("output exceeded"));
    }

    #[cfg(unix)]
    #[test]
    fn relative_provider_executable_resolves_before_working_directory_isolation() {
        use std::os::unix::fs::PermissionsExt;

        let repository = tempfile::tempdir().unwrap();
        let executable = repository.path().join("tools/provider");
        std::fs::create_dir_all(executable.parent().unwrap()).unwrap();
        std::fs::write(&executable, "#!/bin/sh\nprintf provider-ok\n").unwrap();
        let mut permissions = std::fs::metadata(&executable).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&executable, permissions).unwrap();

        let result = execute_provider(&ProviderRequest {
            kind: ProviderKind::Cli,
            executable: "./tools/provider".into(),
            args: vec![],
            model: None,
            working_directory: repository.path().into(),
            stdin: vec![],
            timeout_seconds: 2,
            output_limit_bytes: 4096,
            context_window_tokens: None,
            max_output_tokens: None,
            environment: vec![],
            sample: None,
        })
        .unwrap();

        assert_eq!(result.stdout, b"provider-ok");
    }

    #[cfg(unix)]
    #[test]
    fn provider_failure_reports_bounded_redacted_stderr() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("provider");
        std::fs::write(
            &executable,
            "#!/bin/sh\nprintf 'Error: token=%s\\n' \"$API_TOKEN\" >&2\nexit 7\n",
        )
        .unwrap();
        let mut permissions = std::fs::metadata(&executable).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&executable, permissions).unwrap();

        let error = execute_provider(&ProviderRequest {
            kind: ProviderKind::Cli,
            executable: executable.to_string_lossy().into_owned(),
            args: vec![],
            model: None,
            working_directory: directory.path().into(),
            stdin: vec![],
            timeout_seconds: 2,
            output_limit_bytes: 4096,
            context_window_tokens: None,
            max_output_tokens: None,
            environment: vec![("API_TOKEN".into(), "secret-value".into())],
            sample: None,
        })
        .unwrap_err();

        assert!(error.contains("provider exited with 7"));
        assert!(error.contains("Error:token=[REDACTED]"));
        assert!(!error.contains("secret-value"));
    }

    #[cfg(unix)]
    #[test]
    fn provider_cancellation_terminates_child_process() {
        let cancellation = tokio_util::sync::CancellationToken::new();
        let child_cancellation = cancellation.clone();
        let cancel_thread = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(50));
            child_cancellation.cancel();
        });
        let request = ProviderRequest {
            kind: ProviderKind::Cli,
            executable: "/bin/sleep".into(),
            args: vec!["10".into()],
            model: None,
            working_directory: ".".into(),
            stdin: vec![],
            timeout_seconds: 20,
            output_limit_bytes: 128,
            context_window_tokens: None,
            max_output_tokens: None,
            environment: vec![],
            sample: None,
        };
        let error = execute_provider_cancellable(&request, Some(&cancellation)).unwrap_err();
        cancel_thread.join().unwrap();
        assert!(error.contains("cancelled"));
    }

    #[cfg(unix)]
    #[test]
    fn provider_timeout_terminates_descendant_processes() {
        let dir = tempfile::tempdir().unwrap();
        let pid_file = dir.path().join("provider-child.pid");
        let request = ProviderRequest {
            kind: ProviderKind::Cli,
            executable: "/bin/sh".into(),
            args: vec![
                "-c".into(),
                format!(
                    "sleep 30 >/dev/null 2>&1 & echo $! > '{}'; wait",
                    pid_file.display()
                ),
            ],
            model: None,
            working_directory: ".".into(),
            stdin: vec![],
            timeout_seconds: 1,
            output_limit_bytes: 128,
            context_window_tokens: None,
            max_output_tokens: None,
            environment: vec![],
            sample: None,
        };
        assert!(execute_provider(&request)
            .unwrap_err()
            .contains("timed out"));
        assert_descendant_stopped(&pid_file);
    }

    #[cfg(unix)]
    #[test]
    fn provider_cancellation_terminates_descendant_processes() {
        let dir = tempfile::tempdir().unwrap();
        let pid_file = dir.path().join("provider-cancelled-child.pid");
        let cancellation = tokio_util::sync::CancellationToken::new();
        let child_cancellation = cancellation.clone();
        let child_pid_file = pid_file.clone();
        let cancel_thread = std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while !child_pid_file.exists() && std::time::Instant::now() < deadline {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            child_cancellation.cancel();
        });
        let request = ProviderRequest {
            kind: ProviderKind::Cli,
            executable: "/bin/sh".into(),
            args: vec![
                "-c".into(),
                format!(
                    "sleep 30 >/dev/null 2>&1 & echo $! > '{}'; wait",
                    pid_file.display()
                ),
            ],
            model: None,
            working_directory: ".".into(),
            stdin: vec![],
            timeout_seconds: 10,
            output_limit_bytes: 128,
            context_window_tokens: None,
            max_output_tokens: None,
            environment: vec![],
            sample: None,
        };
        assert!(execute_provider_cancellable(&request, Some(&cancellation))
            .unwrap_err()
            .contains("cancelled"));
        cancel_thread.join().unwrap();
        assert_descendant_stopped(&pid_file);
    }

    #[cfg(unix)]
    #[test]
    fn offline_dependency_resolution_failure_is_incomplete() {
        let dir = tempfile::tempdir().unwrap();
        let profile = VerificationProfile {
            egress: Default::default(),
            executable: "/bin/sh".into(),
            args: vec![
                "-c".into(),
                "printf 'module lookup disabled by GOPROXY\\n' >&2; exit 1".into(),
            ],
            timeout_seconds: 2,
            output_limit_bytes: 256,
            env_allowlist: vec![],
            sarif: None,
        };
        let run = execute_verification("snapshot-1", "tests", dir.path(), &profile).unwrap();
        assert_eq!(run.status, VerificationStatus::Incomplete);
        assert_eq!(run.exit_code, Some(1));
    }

    #[cfg(unix)]
    #[test]
    fn cargo_offline_dependency_download_failure_is_incomplete() {
        let dir = tempfile::tempdir().unwrap();
        let profile = VerificationProfile {
            egress: Default::default(),
            executable: "/bin/sh".into(),
            args: vec![
                "-c".into(),
                "printf 'attempting to make an HTTP request, but --offline was specified\\n' >&2; exit 101".into(),
            ],
            timeout_seconds: 2,
            output_limit_bytes: 256,
            env_allowlist: vec![],
            sarif: None,
        };
        let run = execute_verification("snapshot-1", "cargo-tests", dir.path(), &profile).unwrap();
        assert_eq!(run.status, VerificationStatus::Incomplete);
        assert_eq!(run.exit_code, Some(101));
    }

    #[cfg(unix)]
    #[test]
    fn verification_uses_only_configured_environment() {
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("VEE_VERIFICATION_ALLOWED", "yes");
        let profile = VerificationProfile {
            egress: Default::default(),
            executable: "/usr/bin/env".into(),
            args: vec![],
            env_allowlist: vec!["VEE_VERIFICATION_ALLOWED".into()],
            timeout_seconds: 2,
            output_limit_bytes: 1024,
            sarif: None,
        };
        let run = execute_verification("snapshot", "env", dir.path(), &profile).unwrap();
        std::env::remove_var("VEE_VERIFICATION_ALLOWED");
        assert_eq!(run.status, VerificationStatus::Passed);
        assert_eq!(
            run.stdout_digest,
            digest(b"VEE_VERIFICATION_ALLOWED=[REDACTED]\n")
        );
    }

    #[cfg(unix)]
    #[test]
    fn verification_rejects_output_over_limit() {
        let dir = tempfile::tempdir().unwrap();
        let profile = VerificationProfile {
            egress: Default::default(),
            executable: "/bin/sh".into(),
            args: vec!["-c".into(), "printf 123456789".into()],
            timeout_seconds: 2,
            output_limit_bytes: 4,
            env_allowlist: vec![],
            sarif: None,
        };
        assert!(
            execute_verification("snap", "bounded", dir.path(), &profile)
                .unwrap_err()
                .contains("output exceeded")
        );
    }

    #[test]
    fn verification_logs_redact_allowlisted_environment_values_before_hashing() {
        let mut output = b"token=very-secret-value path=/bin".to_vec();
        redact_output_values(
            &mut output,
            &[
                ("API_TOKEN".into(), "very-secret-value".into()),
                ("PATH".into(), "/bin".into()),
            ],
        );
        assert_eq!(output, b"token=[REDACTED] path=[REDACTED]");
    }

    #[cfg(unix)]
    #[test]
    fn verification_times_out_and_binds_limits_into_command_digest() {
        let dir = tempfile::tempdir().unwrap();
        let profile = VerificationProfile {
            egress: Default::default(),
            executable: "/bin/sleep".into(),
            args: vec!["2".into()],
            timeout_seconds: 1,
            output_limit_bytes: 64,
            env_allowlist: vec![],
            sarif: None,
        };
        let run = execute_verification("snapshot", "slow", dir.path(), &profile).unwrap();
        assert_eq!(run.status, VerificationStatus::TimedOut);
        let changed_limit = VerificationProfile {
            egress: Default::default(),
            output_limit_bytes: 65,
            ..profile
        };
        let other = execute_verification("snapshot", "slow", dir.path(), &changed_limit).unwrap();
        assert_ne!(run.command_digest, other.command_digest);
        let local_profile = VerificationProfile {
            egress: ProviderEgress::Local,
            ..changed_limit
        };
        let local = execute_verification("snapshot", "slow", dir.path(), &local_profile).unwrap();
        assert_ne!(other.command_digest, local.command_digest);
    }

    #[cfg(unix)]
    #[test]
    fn verification_command_digest_tracks_executable_and_environment_without_exposing_values() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let executable = dir.path().join("verify.sh");
        std::fs::write(&executable, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755)).unwrap();
        let profile = VerificationProfile {
            egress: Default::default(),
            executable: "./verify.sh".into(),
            args: vec![],
            timeout_seconds: 5,
            output_limit_bytes: 64,
            env_allowlist: vec!["VEE_TEST_SECRET".into()],
            sarif: None,
        };
        let name = "VEE_TEST_SECRET".to_string();
        let executable_digest = digest_file(&executable).unwrap();
        let executable_identity =
            verification_executable_identity(&profile.executable, &executable);
        let first_environment = vec![(&name, digest(b"secret-one"))];
        let second_environment = vec![(&name, digest(b"secret-two"))];
        let first_with_environment = verification_invocation_digest(
            &profile,
            &executable_identity,
            &executable_digest,
            &first_environment,
        )
        .unwrap();
        let second_with_environment = verification_invocation_digest(
            &profile,
            &executable_identity,
            &executable_digest,
            &second_environment,
        )
        .unwrap();
        assert_ne!(first_with_environment, second_with_environment);
        assert!(!first_with_environment.contains("secret-one"));
        let first = verification_command_digest(&profile, dir.path()).unwrap();
        std::fs::write(&executable, "#!/bin/sh\nexit 1\n").unwrap();
        let second = verification_command_digest(&profile, dir.path()).unwrap();
        assert_ne!(first, second);
        assert!(first.starts_with("sha256:"));
        assert!(second.starts_with("sha256:"));
    }

    #[cfg(unix)]
    #[test]
    fn bare_provider_name_resolves_on_the_parent_path_despite_the_cleared_child_environment() {
        use std::os::unix::fs::PermissionsExt;
        let bin = tempfile::tempdir().unwrap();
        let provider = bin.path().join("fake-reviewer");
        std::fs::write(&provider, "#!/bin/sh\necho 1.2.3\n").unwrap();
        std::fs::set_permissions(&provider, std::fs::Permissions::from_mode(0o755)).unwrap();
        let working = tempfile::tempdir().unwrap();
        let search_path = std::env::join_paths([Path::new("/nonexistent"), bin.path()]).unwrap();
        let resolved = resolve_executable_with_path(
            "provider",
            "fake-reviewer",
            working.path(),
            Some(search_path.clone()),
        )
        .unwrap();
        assert_eq!(resolved, provider.canonical().unwrap());
        let missing = resolve_executable_with_path(
            "provider",
            "absent-reviewer",
            working.path(),
            Some(search_path),
        )
        .unwrap_err();
        assert!(
            missing.contains("provider executable \"absent-reviewer\" was not found"),
            "{missing}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn verification_timeout_terminates_descendant_processes() {
        let dir = tempfile::tempdir().unwrap();
        let pid_file = dir.path().join("verification-child.pid");
        let profile = VerificationProfile {
            egress: Default::default(),
            executable: "/bin/sh".into(),
            args: vec![
                "-c".into(),
                format!(
                    "sleep 30 >/dev/null 2>&1 & echo $! > '{}'; wait",
                    pid_file.display()
                ),
            ],
            timeout_seconds: 1,
            output_limit_bytes: 128,
            env_allowlist: vec![],
            sarif: None,
        };
        let run = execute_verification("snapshot", "descendant", dir.path(), &profile).unwrap();
        assert_eq!(run.status, VerificationStatus::TimedOut);
        assert_descendant_stopped(&pid_file);
    }

    #[cfg(unix)]
    fn assert_descendant_stopped(pid_file: &Path) {
        let pid: i32 = std::fs::read_to_string(pid_file)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            if !process_is_running(pid) {
                return;
            }
            if std::time::Instant::now() >= deadline {
                if process_is_running(pid) {
                    unsafe { libc::kill(pid, libc::SIGKILL) };
                }
                assert!(
                    !process_is_running(pid),
                    "descendant process {pid} survived timeout"
                );
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }

    #[cfg(target_os = "linux")]
    fn process_is_running(pid: i32) -> bool {
        // kill(pid, 0) also succeeds for zombies. Containers with a minimal
        // PID 1 may leave killed grandchildren unreaped, even though they
        // cannot execute or retain resources. Read the kernel state so the
        // process-tree termination assertion checks execution, not reaping.
        if let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            if let Some(state) = stat
                .rsplit_once(") ")
                .and_then(|(_, rest)| rest.chars().next())
            {
                return !matches!(state, 'Z' | 'X');
            }
        }
        unsafe { libc::kill(pid, 0) == 0 }
    }

    #[cfg(all(unix, not(target_os = "linux")))]
    fn process_is_running(pid: i32) -> bool {
        unsafe { libc::kill(pid, 0) == 0 }
    }
}
