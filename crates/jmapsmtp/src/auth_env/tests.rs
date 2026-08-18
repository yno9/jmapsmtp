//! Login, and the file that decides whether an account exists.

use super::*;
use pretty_assertions::assert_eq;

fn cfg_with(localparts: &[&str]) -> Config {
    let accounts: String = localparts
        .iter()
        .map(|l| format!("\"{l}\":{{}}"))
        .collect::<Vec<_>>()
        .join(",");
    serde_json::from_str(&format!(
        r#"{{"domain":{{"example.com":{{"account":{{{accounts}}}}}}}}}"#
    ))
    .unwrap()
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// Give `alice@example.com` the static token `tok`, and return the data dir.
fn account_with_token(token: &[u8]) -> tempfile::TempDir {
    let tmp = tempfile::tempdir().unwrap();
    write_auth_hash(
        tmp.path(),
        "example.com",
        "alice",
        &jmapserver::hash_auth_token(token),
    )
    .unwrap();
    tmp
}

// ── existence ─────────────────────────────────────────────────────────────

/// An account provisioned by the signature flow never gets an envelope, so
/// treating `envelope.json` as the marker 404s it. SPEC.md §2.
#[test]
fn an_account_exists_by_its_auth_token_hash_not_its_envelope() {
    let tmp = tempfile::tempdir().unwrap();
    let (d, l) = ("example.com", "alice");
    assert!(!account_exists(tmp.path(), d, l));

    // An envelope alone is not an account.
    std::fs::create_dir_all(account_dir(tmp.path(), d, l)).unwrap();
    std::fs::write(envelope_file(tmp.path(), d, l), b"{}").unwrap();
    assert!(!account_exists(tmp.path(), d, l));

    write_auth_hash(tmp.path(), d, l, "abc").unwrap();
    assert!(account_exists(tmp.path(), d, l));
}

/// The file is one line, and anything that appends to it by hand or by shell
/// redirection leaves a newline. A stray `\n` must not fail every login.
#[test]
fn the_stored_hash_is_read_with_its_whitespace_trimmed() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(account_dir(tmp.path(), "example.com", "alice")).unwrap();
    std::fs::write(
        auth_hash_file(tmp.path(), "example.com", "alice"),
        b"  hash-value\n",
    )
    .unwrap();
    assert_eq!(
        read_auth_hash(tmp.path(), "example.com", "alice"),
        "hash-value"
    );
}

#[test]
fn credential_files_are_written_owner_only() {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = account_with_token(b"tok");
        let mode = std::fs::metadata(auth_hash_file(tmp.path(), "example.com", "alice"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}

// ── the static token ──────────────────────────────────────────────────────

#[test]
fn the_static_token_authenticates_a_configured_account() {
    let tmp = account_with_token(b"secret-token");
    let cfg = cfg_with(&["alice"]);
    let dynamic = DynAccounts::default();
    let token = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"secret-token");

    assert_eq!(
        authenticate(&cfg, &dynamic, tmp.path(), "alice@example.com", &token),
        Some(Id::from("alice@example.com"))
    );
    assert_eq!(
        authenticate(&cfg, &dynamic, tmp.path(), "ALICE@Example.COM", &token),
        Some(Id::from("alice@example.com")),
        "the username is folded, and the account id is the folded form"
    );
    assert_eq!(
        authenticate(&cfg, &dynamic, tmp.path(), "alice@example.com", "wrong"),
        None
    );
}

#[test]
fn a_username_without_a_domain_is_rejected() {
    let tmp = account_with_token(b"t");
    let cfg = cfg_with(&["alice"]);
    let dynamic = DynAccounts::default();
    assert_eq!(authenticate(&cfg, &dynamic, tmp.path(), "alice", "t"), None);
}

/// The order matters. If the hash file were consulted before the account was
/// known, any localpart that happened to have a directory on disk — a leftover,
/// a deleted account, one restored from a backup — would authenticate against
/// a domain it was never configured for.
#[test]
fn an_unknown_account_is_rejected_even_with_the_right_token() {
    let tmp = tempfile::tempdir().unwrap();
    write_auth_hash(
        tmp.path(),
        "example.com",
        "ghost",
        &jmapserver::hash_auth_token(b"tok"),
    )
    .unwrap();
    let token = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"tok");

    let cfg = cfg_with(&["alice"]); // ghost is not configured
    let dynamic = DynAccounts::default();
    assert_eq!(
        authenticate(&cfg, &dynamic, tmp.path(), "ghost@example.com", &token),
        None
    );

    // …until it is registered at runtime, at which point the same token works.
    dynamic.insert("ghost@example.com".into());
    assert_eq!(
        authenticate(&cfg, &dynamic, tmp.path(), "ghost@example.com", &token),
        Some(Id::from("ghost@example.com"))
    );
}

#[test]
fn a_configured_account_with_no_hash_file_cannot_log_in() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = cfg_with(&["alice"]);
    assert_eq!(
        authenticate(
            &cfg,
            &DynAccounts::default(),
            tmp.path(),
            "alice@example.com",
            ""
        ),
        None,
        "configured but never provisioned"
    );
}

// ── the session token ─────────────────────────────────────────────────────

#[test]
fn a_session_token_authenticates_without_the_static_one() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = account_dir(tmp.path(), "example.com", "alice");
    std::fs::create_dir_all(&dir).unwrap();
    let session = jmapserver::did::devicekeys::issue_session_token(&dir, "dev1", 3600, now()).unwrap();

    // No auth_token_hash at all: this account exists only through its device.
    let cfg = cfg_with(&["alice"]);
    assert_eq!(
        authenticate(
            &cfg,
            &DynAccounts::default(),
            tmp.path(),
            "alice@example.com",
            &session
        ),
        Some(Id::from("alice@example.com"))
    );
}

/// Revoking a device deletes its session files, and login has to notice
/// immediately — a revocation that only takes effect at expiry is not one.
#[test]
fn revoking_the_device_ends_the_session_at_once() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = account_dir(tmp.path(), "example.com", "alice");
    std::fs::create_dir_all(&dir).unwrap();
    let session = jmapserver::did::devicekeys::issue_session_token(&dir, "dev1", 3600, now()).unwrap();
    let cfg = cfg_with(&["alice"]);
    let dynamic = DynAccounts::default();
    assert!(authenticate(&cfg, &dynamic, tmp.path(), "alice@example.com", &session).is_some());

    jmapserver::did::devicekeys::remove_device_key(&dir, "dev1").unwrap();
    assert_eq!(
        authenticate(&cfg, &dynamic, tmp.path(), "alice@example.com", &session),
        None
    );
}

#[test]
fn an_expired_session_token_is_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = account_dir(tmp.path(), "example.com", "alice");
    std::fs::create_dir_all(&dir).unwrap();
    let session =
        jmapserver::did::devicekeys::issue_session_token(&dir, "dev1", 3600, now() - 7200).unwrap();
    assert_eq!(
        authenticate(
            &cfg_with(&["alice"]),
            &DynAccounts::default(),
            tmp.path(),
            "alice@example.com",
            &session
        ),
        None
    );
}

// ── envelopes ─────────────────────────────────────────────────────────────

#[test]
fn an_envelope_round_trips_through_disk() {
    let tmp = tempfile::tempdir().unwrap();
    // Cheap KDF parameters: this test is about the file, not about Argon2.
    let kdf = cryptenv::KdfParams {
        time: 1,
        memory: 8,
        threads: 1,
    };
    let (env, unsealed) = cryptenv::Envelope::new_with_kdf("passphrase", kdf).unwrap();
    write_envelope(tmp.path(), "example.com", "alice", &env).unwrap();

    let back = read_envelope(tmp.path(), "example.com", "alice").expect("readable");
    assert!(
        back.verify_auth(&unsealed.auth_token),
        "the token derived before the write still verifies after it"
    );
    assert!(
        back.unseal("passphrase").is_ok(),
        "and the same passphrase still opens it"
    );
}

/// A corrupt envelope reads as absent rather than as an error. The account is
/// still usable for everything that does not need the key; failing the whole
/// login would lock the user out of their mail over a file they could re-upload.
#[test]
fn a_corrupt_envelope_reads_as_absent() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(account_dir(tmp.path(), "example.com", "alice")).unwrap();
    std::fs::write(
        envelope_file(tmp.path(), "example.com", "alice"),
        b"not json",
    )
    .unwrap();
    assert!(read_envelope(tmp.path(), "example.com", "alice").is_none());

    // Well-formed JSON that is not a valid envelope is equally absent — this is
    // the validation added in SPEC.md §11.2, which the Go version skips.
    std::fs::write(
        envelope_file(tmp.path(), "example.com", "alice"),
        br#"{"version":99}"#,
    )
    .unwrap();
    assert!(read_envelope(tmp.path(), "example.com", "alice").is_none());
}

// ── the dynamic account set ───────────────────────────────────────────────

#[test]
fn dynamic_accounts_are_case_folded_in_both_directions() {
    let dynamic = DynAccounts::default();
    dynamic.insert("Bob@Example.COM".into());
    assert!(dynamic.contains("bob@example.com"));
    assert!(dynamic.contains("BOB@EXAMPLE.COM"));
    assert_eq!(dynamic.emails(), ["bob@example.com"]);
    assert!(dynamic.remove("BOB@example.com"));
    assert!(!dynamic.contains("bob@example.com"));
}
