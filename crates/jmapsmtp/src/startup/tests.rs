//! The startup sequence, and in particular the orderings SPEC.md §2 fixes.
//!
//! Two tests here are about *destruction*: the sweep deletes user mail, so its
//! keep-rules are the ones worth pinning hardest. Both reproduce a concrete
//! way the relay would eat data if the rule were dropped.

use super::*;
use crate::config::DomainConfig;
use pretty_assertions::assert_eq;

fn cfg(json: &str) -> Config {
    serde_json::from_str(json).expect("config should parse")
}

/// Create `data/<domain>/<localpart>/` with a marker file, and optionally the
/// `auth_token_hash` that makes it a real account.
fn account(data_dir: &Path, domain: &str, localpart: &str, with_hash: bool) {
    let dir = account_dir(data_dir, domain, localpart);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("mail.json"), b"precious").unwrap();
    if with_hash {
        crate::auth_env::write_auth_hash(data_dir, domain, localpart, "somehash").unwrap();
    }
}

fn exists(data_dir: &Path, domain: &str, localpart: &str) -> bool {
    account_dir(data_dir, domain, localpart).exists()
}

// ── the sweep ─────────────────────────────────────────────────────────────

#[test]
fn a_domain_that_is_no_longer_configured_is_removed() {
    let tmp = tempfile::tempdir().unwrap();
    account(tmp.path(), "kept.test", "alice", false);
    account(tmp.path(), "gone.test", "bob", true);

    let removed = cleanup_orphaned_data(
        &cfg(r#"{"domain":{"kept.test":{"account":{"alice":{}}}}}"#),
        &DynamicDomains::default(),
        tmp.path(),
    );

    assert!(exists(tmp.path(), "kept.test", "alice"));
    assert!(!tmp.path().join("gone.test").exists());
    assert_eq!(
        removed,
        ["data/gone.test"],
        "a whole unconfigured domain goes at once, hash or no hash"
    );
}

/// The ordering contract from SPEC.md §2, steps 5 and 6.
///
/// A custom domain verified in a previous run exists *only* in
/// `data/_domains/`. Sweeping before that file is read makes it look
/// orphaned, and the sweep is a `remove_dir_all` over every account on it.
#[test]
fn a_verified_custom_domain_survives_only_because_it_was_loaded_first() {
    let tmp = tempfile::tempdir().unwrap();
    account(tmp.path(), "byo.test", "carol", true);
    let reg = tmp.path().join("_domains").join("byo.test");
    std::fs::create_dir_all(&reg).unwrap();
    std::fs::write(reg.join("domain.json"), b"{}").unwrap();

    let config = cfg(r#"{"domain":{"static.test":{}}}"#);

    // The wrong order: sweep with an empty registry.
    let dynamic_domains = DynamicDomains::default();
    let removed = cleanup_orphaned_data(&config, &dynamic_domains, tmp.path());
    assert_eq!(
        removed,
        ["data/byo.test"],
        "this is the data loss the ordering exists to prevent"
    );

    // The right order, on a fresh copy.
    let tmp = tempfile::tempdir().unwrap();
    account(tmp.path(), "byo.test", "carol", true);
    let reg = tmp.path().join("_domains").join("byo.test");
    std::fs::create_dir_all(&reg).unwrap();
    std::fs::write(reg.join("domain.json"), b"{}").unwrap();

    let dynamic_domains = DynamicDomains::default();
    dynamic_domains.load(tmp.path());
    let removed = cleanup_orphaned_data(&config, &dynamic_domains, tmp.path());
    assert!(removed.is_empty());
    assert!(exists(tmp.path(), "byo.test", "carol"));
}

/// The other rule the sweep must not lose: an account is real if it has an
/// `auth_token_hash`, never if it has an `envelope.json`. A third-party or
/// DID-only account has no envelope at all, so an envelope-keyed sweep
/// deletes every one of them on the next restart.
#[test]
fn a_dynamic_account_with_no_envelope_is_kept() {
    let tmp = tempfile::tempdir().unwrap();
    account(tmp.path(), "a.test", "dynamic", true); // hash, no envelope
    account(tmp.path(), "a.test", "leftover", false); // neither
    account(tmp.path(), "a.test", "static", false); // configured, so kept

    let removed = cleanup_orphaned_data(
        &cfg(r#"{"domain":{"a.test":{"account":{"static":{}}}}}"#),
        &DynamicDomains::default(),
        tmp.path(),
    );

    assert!(exists(tmp.path(), "a.test", "dynamic"), "has a credential");
    assert!(exists(tmp.path(), "a.test", "static"), "in the config");
    assert!(!exists(tmp.path(), "a.test", "leftover"));
    assert_eq!(removed, ["data/a.test/leftover"]);
}

#[test]
fn the_reserved_directories_are_never_swept() {
    let tmp = tempfile::tempdir().unwrap();
    // `peers` sits exactly where an account directory would, and holds the
    // whole domain's Autocrypt keys.
    std::fs::create_dir_all(tmp.path().join("a.test").join("peers")).unwrap();
    std::fs::create_dir_all(tmp.path().join("_domains")).unwrap();

    let removed = cleanup_orphaned_data(
        &cfg(r#"{"domain":{"a.test":{}}}"#),
        &DynamicDomains::default(),
        tmp.path(),
    );

    assert!(removed.is_empty());
    assert!(tmp.path().join("a.test").join("peers").exists());
    assert!(tmp.path().join("_domains").exists());
}

#[test]
fn a_missing_data_directory_is_not_an_error() {
    let tmp = tempfile::tempdir().unwrap();
    let removed = cleanup_orphaned_data(
        &cfg(r#"{"domain":{"a.test":{}}}"#),
        &DynamicDomains::default(),
        &tmp.path().join("nope"),
    );
    assert!(removed.is_empty(), "a first run has no data/ yet");
}

#[test]
fn a_stray_file_in_the_data_directory_is_left_alone() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("README"), b"notes").unwrap();
    let removed = cleanup_orphaned_data(
        &cfg(r#"{"domain":{"a.test":{}}}"#),
        &DynamicDomains::default(),
        tmp.path(),
    );
    assert!(removed.is_empty());
    assert!(tmp.path().join("README").exists());
}

// ── recovering dynamic accounts ───────────────────────────────────────────

/// The scan and the sweep have to agree on what an account is. If they
/// disagree, one deletes what the other restores — in whichever direction,
/// every restart is destructive.
#[test]
fn the_scan_recovers_exactly_what_the_sweep_keeps() {
    let tmp = tempfile::tempdir().unwrap();
    account(tmp.path(), "a.test", "dynamic", true);
    account(tmp.path(), "a.test", "static", false);
    account(tmp.path(), "a.test", "leftover", false);
    std::fs::create_dir_all(tmp.path().join("a.test").join("peers")).unwrap();

    let config = cfg(r#"{"domain":{"a.test":{"account":{"static":{}}}}}"#);
    let dynamic_domains = DynamicDomains::default();
    cleanup_orphaned_data(&config, &dynamic_domains, tmp.path());

    let dynamic = DynAccounts::default();
    scan_dyn_accounts(&config, &dynamic_domains, &dynamic, tmp.path());

    assert_eq!(
        dynamic.emails(),
        ["dynamic@a.test"],
        "not the static one, not peers, not the swept leftover"
    );
}

#[test]
fn the_scan_covers_dynamic_domains_too() {
    let tmp = tempfile::tempdir().unwrap();
    account(tmp.path(), "byo.test", "carol", true);

    let dynamic_domains = DynamicDomains::default();
    dynamic_domains.insert("byo.test".into(), DomainConfig::default());
    let dynamic = DynAccounts::default();
    scan_dyn_accounts(
        &cfg(r#"{"domain":{"static.test":{}}}"#),
        &dynamic_domains,
        &dynamic,
        tmp.path(),
    );

    assert_eq!(dynamic.emails(), ["carol@byo.test"]);
}

// ── setup tokens ──────────────────────────────────────────────────────────

#[test]
fn an_unclaimed_account_gets_a_token_and_a_claimed_one_does_not() {
    let tmp = tempfile::tempdir().unwrap();
    let config = cfg(r#"{"domain":{"a.test":{"account":{"fresh":{},"claimed":{}}}}}"#);

    let kdf = cryptenv::KdfParams {
        time: 1,
        memory: 8,
        threads: 1,
    };
    let (env, _) = cryptenv::Envelope::new_with_kdf("pw", kdf).unwrap();
    crate::auth_env::write_envelope(tmp.path(), "a.test", "claimed", &env).unwrap();

    let invites = issue_setup_tokens(&config, tmp.path());
    assert_eq!(invites.len(), 1);
    assert_eq!(invites[0].localpart, "fresh");
    assert_eq!(invites[0].token.len(), 32, "16 random bytes as hex");
    assert_eq!(
        invites[0].url("https://mail.a.test"),
        format!("https://mail.a.test/setup?token={}", invites[0].token)
    );
}

/// A restart during onboarding must not invalidate the link the operator
/// already sent.
#[test]
fn an_existing_token_is_reused_across_restarts() {
    let tmp = tempfile::tempdir().unwrap();
    let config = cfg(r#"{"domain":{"a.test":{"account":{"fresh":{}}}}}"#);

    let first = issue_setup_tokens(&config, tmp.path());
    let second = issue_setup_tokens(&config, tmp.path());
    assert_eq!(first, second);
    assert_eq!(
        std::fs::read_to_string(token_file(tmp.path(), "a.test", "fresh")).unwrap(),
        first[0].token
    );
}

#[test]
fn setup_tokens_are_written_owner_only_and_are_not_all_the_same() {
    let tmp = tempfile::tempdir().unwrap();
    let invites = issue_setup_tokens(
        &cfg(r#"{"domain":{"a.test":{"account":{"one":{},"two":{}}}}}"#),
        tmp.path(),
    );
    assert_ne!(invites[0].token, invites[1].token);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(token_file(tmp.path(), "a.test", "one"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "the token is an account credential");
    }
}

// ── aliases ───────────────────────────────────────────────────────────────

#[test]
fn aliases_are_folded_and_bare_ones_take_their_domain() {
    let map = build_alias_map(&cfg(
        r#"{"domain":{"a.test":{"account":{"Alice":{"alias":["Postmaster","B@other.test"]}}}}}"#,
    ));
    assert_eq!(
        map,
        BTreeMap::from([
            ("alice@a.test".into(), "alice@a.test".into()),
            ("postmaster@a.test".into(), "alice@a.test".into()),
            ("b@other.test".into(), "alice@a.test".into()),
        ])
    );
}

#[test]
fn an_account_with_no_aliases_still_maps_to_itself() {
    let map = build_alias_map(&cfg(r#"{"domain":{"a.test":{"account":{"solo":{}}}}}"#));
    assert_eq!(map["solo@a.test"], "solo@a.test");
}
