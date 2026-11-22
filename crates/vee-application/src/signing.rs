//! Local Ed25519 signing keys for evidence bundles and attestations.
//!
//! Keys are written to files only: the private key as PKCS#8 DER readable by
//! its owner alone, the public key as the raw 32 bytes verifiers need. No key
//! material is ever part of a result document.

use crate::failure::{configuration_failure, usage_failure};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};

/// The result of `vee reviews keygen`: where the key pair was written. It names
/// the files as the caller gave them and never contains key material.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SigningKeyPair {
    pub algorithm: String,
    pub private_key: String,
    pub public_key: String,
}

/// Generate an Ed25519 key pair into two new files, refusing to overwrite.
pub fn generate_key_pair(private_key: &Path, public_key: &Path) -> Result<SigningKeyPair> {
    let private_target = resolve_new_file(private_key)?;
    let public_target = resolve_new_file(public_key)?;
    if private_target == public_target {
        return Err(usage_failure(
            "private and public key output paths must differ",
        ));
    }
    if private_target.exists() || public_target.exists() {
        return Err(usage_failure("key output paths must not already exist"));
    }
    let rng = ring::rand::SystemRandom::new();
    let document = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng)
        .map_err(|_| configuration_failure("could not generate Ed25519 key pair"))?;
    let pair = ring::signature::Ed25519KeyPair::from_pkcs8(document.as_ref())
        .map_err(|_| configuration_failure("generated Ed25519 key pair could not be loaded"))?;
    write_private_key(&private_target, document.as_ref())?;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&public_target)?
        .write_all(ring::signature::KeyPair::public_key(&pair).as_ref())?;
    Ok(SigningKeyPair {
        algorithm: "ed25519".into(),
        private_key: private_key.display().to_string(),
        public_key: public_key.display().to_string(),
    })
}

/// Load an Ed25519 PKCS#8 DER private key, as written by [`generate_key_pair`].
pub fn load_private_key(path: &Path) -> Result<ring::signature::Ed25519KeyPair> {
    let bytes =
        std::fs::read(path).with_context(|| format!("reading private key {}", path.display()))?;
    ring::signature::Ed25519KeyPair::from_pkcs8(&bytes)
        .map_err(|_| configuration_failure("private key must be a valid Ed25519 PKCS#8 DER file"))
}

/// The canonical location of a file to create, creating its parent directory.
fn resolve_new_file(path: &Path) -> Result<PathBuf> {
    let name = path
        .file_name()
        .context("key output path must name a file")?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent)?;
    Ok(vee_core::paths::canonicalize(parent)?.join(name))
}

fn write_private_key(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("creating private key {}", path.display()))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_a_loadable_pair_and_refuses_to_overwrite() {
        let directory = tempfile::tempdir().unwrap();
        let private = directory.path().join("keys/signing.der");
        let public = directory.path().join("keys/verify.bin");
        let pair = generate_key_pair(&private, &public).unwrap();
        assert_eq!(pair.algorithm, "ed25519");
        assert_eq!(pair.private_key, private.display().to_string());
        assert_eq!(std::fs::read(&public).unwrap().len(), 32);
        load_private_key(&private).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&private).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        assert!(generate_key_pair(&private, &public).is_err());
        assert!(generate_key_pair(&public, &public).is_err());
    }
}
