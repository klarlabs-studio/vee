//! Shared helpers for the `vee` integration tests.

use std::path::PathBuf;
use std::process::Command;

/// A private, initially empty location for the per-user provider config.
fn private_user_config() -> PathBuf {
    static DIRECTORY: std::sync::OnceLock<tempfile::TempDir> = std::sync::OnceLock::new();
    DIRECTORY
        .get_or_init(|| tempfile::tempdir().unwrap())
        .path()
        .join("config.yaml")
}

/// Remove developer-specific overrides from this test process: the per-user
/// provider config points at [`private_user_config`] and an inherited
/// `VEE_OFFLINE` is dropped. Call it before using application code in-process
/// so that code agrees with the `vee` subprocesses on configuration digests.
#[allow(dead_code)] // Not every test binary runs application code in-process.
pub fn isolate_process_environment() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        std::env::set_var("VEE_CONFIG", private_user_config());
        std::env::remove_var("VEE_OFFLINE");
    });
}

/// The `vee` binary with no developer-specific overrides (see
/// [`isolate_process_environment`]), so a developer's own configuration cannot
/// change test results. `VEE_RUST_ANALYZER` and `VEE_TSSERVER` stay inherited
/// because they only locate analyzer tools. Tests that need a user config set
/// `VEE_CONFIG` on the returned command.
pub fn vee() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_vee"));
    command
        .env("VEE_CONFIG", private_user_config())
        .env_remove("VEE_OFFLINE");
    command
}
