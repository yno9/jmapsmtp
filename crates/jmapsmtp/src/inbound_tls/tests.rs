//! The certificate inbound STARTTLS presents.

use super::*;
use pretty_assertions::assert_eq;

fn cfg(json: &str) -> crate::config::Config {
    serde_json::from_str(json).expect("config should parse")
}

fn plain() -> crate::config::Config {
    cfg(r#"{"domain":{"a.test":{}}}"#)
}

// ── the self-signed fallback ──────────────────────────────────────────────

/// With nothing configured, a pair is generated. On port 25 the alternative to
/// unverified TLS is plaintext — a sending MX cannot authenticate an arbitrary
/// recipient domain and falls back rather than refusing — so encrypting
/// against a passive observer is the whole benefit, and a real one.
#[test]
fn a_relay_with_no_certificate_generates_one() {
    let tmp = tempfile::tempdir().unwrap();
    assert!(server_config(&plain(), tmp.path()).is_some());

    let (cert, key) = self_signed_paths(tmp.path());
    assert!(cert.exists() && key.exists());
}

/// Generated once. Regenerating per start would present a different key on
/// every restart, which defeats any pinning a sender does.
#[test]
fn the_generated_certificate_is_reused_across_starts() {
    let tmp = tempfile::tempdir().unwrap();
    server_config(&plain(), tmp.path()).unwrap();
    let (cert_path, _) = self_signed_paths(tmp.path());
    let first = std::fs::read(&cert_path).unwrap();

    server_config(&plain(), tmp.path()).unwrap();
    assert_eq!(std::fs::read(&cert_path).unwrap(), first);
}

#[test]
fn the_generated_private_key_is_owner_only() {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = tempfile::tempdir().unwrap();
        server_config(&plain(), tmp.path()).unwrap();
        let (_, key_path) = self_signed_paths(tmp.path());
        let mode = std::fs::metadata(&key_path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "the key is a credential");
    }
}

// ── a configured certificate ──────────────────────────────────────────────

/// A configured pair that does not load falls back to self-signed rather than
/// leaving TLS off: a typo in a path should not silently drop every sender to
/// plaintext.
#[test]
fn a_configured_certificate_that_does_not_load_falls_back() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = cfg(r#"{"domain":{"a.test":{}},
            "smtp_tls_cert":"/nonexistent/cert.pem",
            "smtp_tls_key":"/nonexistent/key.pem"}"#);
    assert!(server_config(&cfg, tmp.path()).is_some());
    let (cert, _) = self_signed_paths(tmp.path());
    assert!(cert.exists(), "it fell back and generated one");
}

#[test]
fn a_configured_certificate_is_used_when_it_loads() {
    let tmp = tempfile::tempdir().unwrap();
    let managed = tempfile::tempdir().unwrap();
    let (cert_path, key_path) = (managed.path().join("c.pem"), managed.path().join("k.pem"));
    generate_self_signed(&cert_path, &key_path).unwrap();

    let cfg: crate::config::Config = serde_json::from_str(&format!(
        r#"{{"domain":{{"a.test":{{}}}},
            "smtp_tls_cert":"{}","smtp_tls_key":"{}"}}"#,
        cert_path.display(),
        key_path.display()
    ))
    .unwrap();

    assert!(server_config(&cfg, tmp.path()).is_some());
    let (fallback, _) = self_signed_paths(tmp.path());
    assert!(
        !fallback.exists(),
        "the configured pair was used, so nothing was generated"
    );
}

// ── reloading ─────────────────────────────────────────────────────────────

/// A renewal is picked up without a restart. A relay that had to be restarted
/// to serve a fresh certificate would serve an expired one for however long
/// nobody noticed.
#[test]
fn a_renewed_certificate_is_picked_up_without_a_restart() {
    let tmp = tempfile::tempdir().unwrap();
    let (cert_path, key_path) = (tmp.path().join("c.pem"), tmp.path().join("k.pem"));
    generate_self_signed(&cert_path, &key_path).unwrap();

    let reloader = Reloader::new(cert_path.clone(), key_path.clone());
    let first = reloader.load().unwrap();

    // Cached while the file is unchanged.
    assert!(Arc::ptr_eq(&first, &reloader.load().unwrap()));

    // Renewed: new bytes, and a new modification time.
    generate_self_signed(&cert_path, &key_path).unwrap();
    filetime::set_file_mtime(
        &cert_path,
        filetime::FileTime::from_unix_time(2_000_000_000, 0),
    )
    .unwrap();

    let second = reloader.load().unwrap();
    assert!(
        !Arc::ptr_eq(&first, &second),
        "the renewal was read rather than the cache served"
    );
}

/// A renewal caught mid-write is transient. Serving the cached copy keeps TLS
/// up; failing the handshake would drop every sender to plaintext during it.
#[test]
fn a_broken_reload_serves_the_cached_certificate() {
    let tmp = tempfile::tempdir().unwrap();
    let (cert_path, key_path) = (tmp.path().join("c.pem"), tmp.path().join("k.pem"));
    generate_self_signed(&cert_path, &key_path).unwrap();

    let reloader = Reloader::new(cert_path.clone(), key_path.clone());
    let good = reloader.load().unwrap();

    // Half-written.
    std::fs::write(&cert_path, b"-----BEGIN CERTIFICATE-----\ntrunc").unwrap();
    filetime::set_file_mtime(
        &cert_path,
        filetime::FileTime::from_unix_time(2_000_000_001, 0),
    )
    .unwrap();

    let served = reloader.load().expect("the cached copy is still served");
    assert!(Arc::ptr_eq(&good, &served));
}

/// With nothing cached there is nothing to fall back to, and the error is the
/// honest answer.
#[test]
fn a_reload_with_nothing_cached_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let reloader = Reloader::new(tmp.path().join("nope.pem"), tmp.path().join("nope.key"));
    assert!(reloader.load().is_err());
}

#[test]
fn a_certificate_file_with_no_certificate_in_it_is_an_error() {
    let tmp = tempfile::tempdir().unwrap();
    let (cert_path, key_path) = (tmp.path().join("c.pem"), tmp.path().join("k.pem"));
    generate_self_signed(&cert_path, &key_path).unwrap();
    std::fs::write(&cert_path, b"not a certificate").unwrap();

    let reloader = Reloader::new(cert_path, key_path);
    assert!(reloader.load().is_err());
}
