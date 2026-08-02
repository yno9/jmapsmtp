//! The certificate inbound STARTTLS presents.
//!
//! # This is opportunistic TLS, and unauthenticated on purpose
//!
//! A self-signed certificate is generated when none is configured. That is not
//! a weaker version of a real one — on port 25 the alternative to unverified
//! TLS is **plaintext**, not verified TLS, because a sending MX has no way to
//! authenticate an arbitrary recipient domain and will fall back rather than
//! refuse. Encrypting against a passive observer is the whole benefit, and it
//! is a real one.
//!
//! # A configured certificate is re-read as it changes
//!
//! `smtp_tls_cert` / `smtp_tls_key` usually point at files something else
//! renews (Caddy, certbot). They are re-read when their modification time
//! changes, so a renewal is picked up **without a restart** — a relay that had
//! to be restarted to serve a fresh certificate would serve an expired one for
//! however long nobody noticed.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use parking_lot::Mutex;

/// Where the generated self-signed pair lives.
pub fn self_signed_paths(data_dir: &Path) -> (PathBuf, PathBuf) {
    (
        data_dir.join("smtp-tls-cert.pem"),
        data_dir.join("smtp-tls-key.pem"),
    )
}

/// A certificate loaded from disk, reloaded when the file changes.
pub struct Reloader {
    cert_path: PathBuf,
    key_path: PathBuf,
    cached: Mutex<Option<(std::time::SystemTime, Arc<CertifiedKey>)>>,
}

/// A parsed certificate chain and its private key.
pub struct CertifiedKey {
    pub chain: Vec<rustls::pki_types::CertificateDer<'static>>,
    pub key: rustls::pki_types::PrivateKeyDer<'static>,
}

impl Reloader {
    pub fn new(cert_path: PathBuf, key_path: PathBuf) -> Reloader {
        Reloader {
            cert_path,
            key_path,
            cached: Mutex::new(None),
        }
    }

    /// The current certificate, re-reading if the file changed.
    ///
    /// A failed reload **serves the cached copy** rather than failing the
    /// handshake: a renewal caught mid-write is a transient state, and
    /// refusing TLS during it drops every sender to plaintext.
    pub fn load(&self) -> std::io::Result<Arc<CertifiedKey>> {
        let modified = std::fs::metadata(&self.cert_path)
            .and_then(|m| m.modified())
            .ok();
        {
            let cached = self.cached.lock();
            if let Some((cached_at, key)) = cached.as_ref()
                && modified == Some(*cached_at)
            {
                return Ok(key.clone());
            }
        }
        match read_pair(&self.cert_path, &self.key_path) {
            Ok(loaded) => {
                let loaded = Arc::new(loaded);
                if let Some(modified) = modified {
                    *self.cached.lock() = Some((modified, loaded.clone()));
                }
                Ok(loaded)
            }
            Err(e) => match self.cached.lock().as_ref() {
                Some((_, cached)) => Ok(cached.clone()),
                None => Err(e),
            },
        }
    }
}

fn read_pair(cert_path: &Path, key_path: &Path) -> std::io::Result<CertifiedKey> {
    let chain: Vec<_> = rustls_pemfile::certs(&mut std::io::BufReader::new(std::fs::File::open(
        cert_path,
    )?))
    .collect::<Result<_, _>>()?;
    if chain.is_empty() {
        return Err(std::io::Error::other(format!(
            "no certificates in {}",
            cert_path.display()
        )));
    }
    let key =
        rustls_pemfile::private_key(&mut std::io::BufReader::new(std::fs::File::open(key_path)?))?
            .ok_or_else(|| {
                std::io::Error::other(format!("no private key in {}", key_path.display()))
            })?;
    Ok(CertifiedKey { chain, key })
}

/// Build the server config for inbound STARTTLS.
///
/// A configured pair is used when it loads; otherwise the self-signed one is
/// generated (once) and used. A failure at every step leaves TLS unavailable,
/// which is answered `454` rather than stalling the sender.
pub fn server_config(
    cfg: &crate::config::Config,
    data_dir: &Path,
) -> Option<Arc<rustls::ServerConfig>> {
    install_crypto_provider();
    let reloader = if !cfg.tls_cert_file.is_empty() && !cfg.tls_key_file.is_empty() {
        let reloader = Reloader::new(
            PathBuf::from(&cfg.tls_cert_file),
            PathBuf::from(&cfg.tls_key_file),
        );
        // Verified once at startup, so a misconfigured path is a log line now
        // rather than a failed handshake later.
        match reloader.load() {
            Ok(_) => Some(reloader),
            Err(e) => {
                eprintln!(
                    "[smtp] configured cert {} did not load ({e}); falling back to self-signed",
                    cfg.tls_cert_file
                );
                None
            }
        }
    } else {
        None
    };

    let reloader = match reloader {
        Some(r) => r,
        None => {
            let (cert_path, key_path) = self_signed_paths(data_dir);
            if read_pair(&cert_path, &key_path).is_err()
                && let Err(e) = generate_self_signed(&cert_path, &key_path)
            {
                eprintln!("[smtp] could not generate a certificate: {e}");
                return None;
            }
            Reloader::new(cert_path, key_path)
        }
    };

    let loaded = reloader.load().ok()?;
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(loaded.chain.clone(), loaded.key.clone_key())
        .ok()?;
    Some(Arc::new(config))
}

/// Select rustls' cryptography backend.
///
/// Installed explicitly rather than left to feature unification: rustls panics
/// when it cannot pick one, and which features are enabled depends on every
/// other crate in the tree. An explicit choice fails the same way on every
/// build instead of on some of them.
///
/// Idempotent — a second call finds one installed and leaves it.
pub fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Generate a self-signed pair and write it, owner-readable.
pub fn generate_self_signed(cert_path: &Path, key_path: &Path) -> std::io::Result<()> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .map_err(|e| std::io::Error::other(format!("generating a certificate: {e}")))?;
    if let Some(parent) = cert_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(cert_path, cert.cert.pem())?;
    // The private key is a credential; the certificate is not.
    crate::write_private(key_path, cert.signing_key.serialize_pem().as_bytes())
}

#[cfg(test)]
mod tests;
