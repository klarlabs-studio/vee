//! TLS for the webhook server, so it can listen beyond loopback (ADR 0038).

use anyhow::Context;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Semaphore};
use tokio_rustls::rustls;
use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;

/// A client that has not finished its handshake by then is dropped.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Handshakes in progress at once; further connections wait to be accepted.
const MAX_PENDING_HANDSHAKES: usize = 64;

/// A PEM certificate chain and its private key.
#[derive(Clone, Debug)]
pub struct TlsFiles {
    pub certificate: PathBuf,
    pub private_key: PathBuf,
}

/// The server configuration for `files`: TLS 1.2 and 1.3 with rustls's safe
/// defaults, HTTP/1.1 only.
pub fn server_config(files: &TlsFiles) -> anyhow::Result<Arc<rustls::ServerConfig>> {
    check_private_key_permissions(&files.private_key)?;
    let chain = CertificateDer::pem_file_iter(&files.certificate)
        .with_context(|| format!("reading TLS certificate {}", files.certificate.display()))?
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("parsing TLS certificate {}", files.certificate.display()))?;
    anyhow::ensure!(
        !chain.is_empty(),
        "TLS certificate {} holds no certificate",
        files.certificate.display()
    );
    let key = PrivateKeyDer::from_pem_file(&files.private_key)
        .with_context(|| format!("reading TLS private key {}", files.private_key.display()))?;
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .context("configuring TLS protocol versions")?
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .context("the TLS private key does not match the certificate")?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// Refuse a private key that other users can read, as SSH does.
fn check_private_key_permissions(path: &Path) -> anyhow::Result<()> {
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("reading TLS private key {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode();
        anyhow::ensure!(
            mode & 0o077 == 0,
            "TLS private key {} is readable by other users (mode {:o}); run chmod 600 on it",
            path.display(),
            mode & 0o777
        );
    }
    #[cfg(not(unix))]
    let _ = metadata;
    Ok(())
}

/// Accepts TCP connections and completes their TLS handshakes concurrently,
/// so one slow client cannot hold up the others.
pub(crate) struct TlsListener {
    connections: mpsc::Receiver<(TlsStream<TcpStream>, SocketAddr)>,
    local: SocketAddr,
    accepting: tokio::task::JoinHandle<()>,
}

impl TlsListener {
    pub(crate) fn new(
        listener: TcpListener,
        config: Arc<rustls::ServerConfig>,
    ) -> std::io::Result<Self> {
        let local = listener.local_addr()?;
        let (sender, connections) = mpsc::channel(MAX_PENDING_HANDSHAKES);
        let acceptor = TlsAcceptor::from(config);
        let permits = Arc::new(Semaphore::new(MAX_PENDING_HANDSHAKES));
        let accepting = tokio::spawn(async move {
            loop {
                let Ok(permit) = permits.clone().acquire_owned().await else {
                    return;
                };
                let (stream, peer) = match listener.accept().await {
                    Ok(accepted) => accepted,
                    Err(error) => {
                        eprintln!("vee: accepting a webhook connection failed: {error}");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
                let acceptor = acceptor.clone();
                let sender = sender.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    // A failed or slow handshake is dropped; the client retries.
                    if let Ok(Ok(stream)) =
                        tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await
                    {
                        let _ = sender.send((stream, peer)).await;
                    }
                });
            }
        });
        Ok(Self {
            connections,
            local,
            accepting,
        })
    }
}

impl Drop for TlsListener {
    fn drop(&mut self) {
        self.accepting.abort();
    }
}

impl axum::serve::Listener for TlsListener {
    type Io = TlsStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        match self.connections.recv().await {
            Some(connection) => connection,
            None => std::future::pending().await,
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        Ok(self.local)
    }
}
