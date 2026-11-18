//! Immutable, digest-bound proposal artifacts under `.vero/proposals`.

use anyhow::{Context, Result};
use std::io::{Read, Write};

pub fn proposal_directory(root: &std::path::Path) -> Result<std::path::PathBuf> {
    let vero_dir = root.join(".vero");
    std::fs::create_dir_all(&vero_dir)?;
    anyhow::ensure!(
        std::fs::symlink_metadata(&vero_dir)?.file_type().is_dir(),
        ".vero must be a real directory"
    );
    let proposals = vero_dir.join("proposals");
    std::fs::create_dir_all(&proposals)?;
    anyhow::ensure!(
        std::fs::symlink_metadata(&proposals)?.file_type().is_dir(),
        ".vero/proposals must be a real directory"
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
