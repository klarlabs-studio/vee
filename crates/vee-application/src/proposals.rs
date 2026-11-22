//! Immutable, digest-bound proposal artifacts under `.vee/proposals`.

use anyhow::{Context, Result};
use std::io::{Read, Write};

pub fn proposal_directory(root: &std::path::Path) -> Result<std::path::PathBuf> {
    let vee_dir = root.join(".vee");
    std::fs::create_dir_all(&vee_dir)?;
    anyhow::ensure!(
        std::fs::symlink_metadata(&vee_dir)?.file_type().is_dir(),
        ".vee must be a real directory"
    );
    let proposals = vee_dir.join("proposals");
    std::fs::create_dir_all(&proposals)?;
    anyhow::ensure!(
        std::fs::symlink_metadata(&proposals)?.file_type().is_dir(),
        ".vee/proposals must be a real directory"
    );
    Ok(proposals)
}

pub fn write_immutable_proposal_file(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
    {
        Ok(mut file) => file
            .write_all(bytes)
            .with_context(|| format!("writing proposal artifact {}", path.display()))?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let existing = read_proposal_file(path, bytes.len() as u64)?;
            anyhow::ensure!(
                existing == bytes,
                "refusing to replace a proposal artifact with different review or snapshot context"
            );
        }
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

pub fn read_proposal_file(path: &std::path::Path, max_bytes: u64) -> Result<Vec<u8>> {
    let metadata = std::fs::symlink_metadata(path)?;
    anyhow::ensure!(
        metadata.file_type().is_file(),
        "proposal artifact must be a regular file"
    );
    anyhow::ensure!(
        metadata.len() <= max_bytes,
        "proposal artifact exceeds its size limit"
    );
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options.open(path)?;
    let opened_metadata = file.metadata()?;
    anyhow::ensure!(
        opened_metadata.is_file() && !opened_metadata.file_type().is_symlink(),
        "proposal artifact must be a regular file"
    );
    anyhow::ensure!(
        opened_metadata.len() <= max_bytes,
        "proposal artifact exceeds its size limit"
    );
    let mut bytes = Vec::with_capacity(opened_metadata.len().min(max_bytes) as usize);
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)?;
    anyhow::ensure!(
        bytes.len() as u64 <= max_bytes,
        "proposal artifact exceeds its size limit"
    );
    Ok(bytes)
}

/// Replace a mutable proposal record in place, refusing to follow anything but
/// a regular file; creates it when absent.
pub fn write_proposal_file(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            anyhow::ensure!(
                metadata.file_type().is_file(),
                "proposal artifact must be a regular file"
            );
            std::fs::write(path, bytes)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)?;
            file.write_all(bytes)?;
        }
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

/// Create a proposal artifact that must not exist yet.
pub fn write_new_proposal_file(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| {
            format!(
                "refusing to overwrite existing proposal artifact {}",
                path.display()
            )
        })?;
    file.write_all(bytes)?;
    Ok(())
}

/// Exclusive hold on applying proposals in one repository; released on drop.
pub struct ProposalApplyLock(std::path::PathBuf);

impl Drop for ProposalApplyLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

pub fn acquire_proposal_apply_lock(directory: &std::path::Path) -> Result<ProposalApplyLock> {
    let path = directory.join("apply.lock");
    let mut file = match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            anyhow::bail!(
                "another Vee patch application is in progress ({}); if this lock is stale, verify no apply-patch process is running before removing it",
                path.display()
            )
        }
        Err(error) => return Err(error.into()),
    };
    writeln!(
        file,
        "pid={} started_unix={}",
        std::process::id(),
        crate::current_unix_time().map_err(anyhow::Error::msg)?
    )?;
    file.sync_all()?;
    Ok(ProposalApplyLock(path))
}

/// Recapture the change scope a proposal recorded (`staged`, `working_tree`,
/// `commit:<oid>`, `commit_range:<range>`, or base and worktree from `base_oid`).
pub fn capture_recorded_scope(
    root: &std::path::Path,
    base_oid: Option<&str>,
    scope: &str,
) -> Result<vee_core::ChangeSet> {
    let capture_scope = match scope {
        "staged" => vee_git::ChangeScope::Staged,
        "working_tree" => vee_git::ChangeScope::WorkingTree,
        value if value.starts_with("commit:") => {
            vee_git::commit_scope(value.trim_start_matches("commit:"))
                .map_err(anyhow::Error::msg)?
        }
        value if value.starts_with("commit_range:") => {
            vee_git::commit_scope(value.trim_start_matches("commit_range:"))
                .map_err(anyhow::Error::msg)?
        }
        _ => vee_git::ChangeScope::BaseAndWorktree {
            base_oid: base_oid.map(str::to_string),
        },
    };
    crate::capture_change_set(root, capture_scope).map_err(anyhow::Error::msg)
}
