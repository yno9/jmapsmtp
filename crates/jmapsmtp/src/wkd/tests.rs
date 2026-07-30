//! WKD lookups and the PGP key endpoints.
//!
//! The lookup tests are the ones with teeth: this directory is public by
//! design, so the question is not whether a stranger can read a key — they must
//! be able to — but whether they can read *the wrong one*.

use super::*;
use pretty_assertions::assert_eq;

fn cfg(json: &str) -> crate::config::Config {
    serde_json::from_str(json).expect("config should parse")
}

const PUBKEY: &str = include_str!("../../../../xtask/fixtures/pgp-public.asc");

// ── the hash ──────────────────────────────────────────────────────────────

/// The value every WKD client computes independently, so it is a fixed point,
/// not an implementation detail. Cross-checked against the Go implementation.
#[test]
fn the_wkd_hash_has_its_published_value() {
    assert_eq!(wkd_hash("alice"), "kei1q4tipxxu1yj79k9kfukdhfy631xe");
}

#[test]
fn the_hash_folds_case_because_addresses_do() {
    assert_eq!(wkd_hash("Alice"), wkd_hash("alice"));
    assert_eq!(wkd_hash("ALICE"), wkd_hash("alice"));
}

#[test]
fn different_localparts_hash_differently() {
    assert_ne!(wkd_hash("alice"), wkd_hash("bob"));
}

// ── lookups ───────────────────────────────────────────────────────────────

fn one_domain() -> crate::config::Config {
    cfg(r#"{"domain":{"a.test":{"account":{"alice":{},"bob":{}}}}}"#)
}

#[test]
fn a_matching_hash_and_localpart_resolve_to_that_accounts_key() {
    assert_eq!(
        resolve_wkd(&one_domain(), &wkd_hash("alice"), "alice", false, |_, _| {
            true
        }),
        WkdLookup::UserKey {
            domain: "a.test".into(),
            localpart: "alice".into()
        }
    );
}

/// The `l=` parameter is checked against the hash rather than trusted.
/// Honouring a mismatch would let a caller ask for one person's key under
/// another's hash — which is the whole attack this directory has to resist.
#[test]
fn a_localpart_that_does_not_match_the_hash_gets_nothing() {
    let cfg = one_domain();
    assert_eq!(
        resolve_wkd(&cfg, &wkd_hash("alice"), "bob", true, |_, _| true),
        WkdLookup::NotFound,
        "bob's l= under alice's hash must not serve either key"
    );
    assert_eq!(
        resolve_wkd(&cfg, "not-a-real-hash", "alice", true, |_, _| true),
        WkdLookup::NotFound
    );
}

/// With no `l=` there is nothing to look up per-account — a hash is not
/// reversible — so the request falls through to the relay-wide key. That is a
/// property of WKD, not a shortcut.
#[test]
fn no_localpart_falls_through_to_the_global_key() {
    let cfg = one_domain();
    assert_eq!(
        resolve_wkd(&cfg, &wkd_hash("alice"), "", true, |_, _| true),
        WkdLookup::GlobalKey
    );
    assert_eq!(
        resolve_wkd(&cfg, &wkd_hash("alice"), "", false, |_, _| true),
        WkdLookup::NotFound,
        "and to nothing when there is no global key"
    );
}

/// An account with no key of its own falls back to the relay-wide one, which is
/// what makes a relay-level key useful at all.
#[test]
fn an_account_with_no_key_falls_back_to_the_global_one() {
    let cfg = one_domain();
    assert_eq!(
        resolve_wkd(&cfg, &wkd_hash("alice"), "alice", true, |_, _| false),
        WkdLookup::GlobalKey
    );
    assert_eq!(
        resolve_wkd(&cfg, &wkd_hash("alice"), "alice", false, |_, _| false),
        WkdLookup::NotFound
    );
}

/// The divergence in `resolve_wkd`'s header: Go folds when hashing but not when
/// looking the account up, so a capitalised `l=` falls through to the
/// relay-wide key — handing the sender a key the relay can read with.
/// SPEC.md §11.15.
#[test]
fn a_capitalised_localpart_still_finds_that_accounts_own_key() {
    let cfg = one_domain();
    assert_eq!(
        resolve_wkd(&cfg, &wkd_hash("Alice"), "Alice", true, |_, _| true),
        WkdLookup::UserKey {
            domain: "a.test".into(),
            localpart: "alice".into()
        },
        "not the global key"
    );
    // And the resolved localpart is the folded one, since that is the account.
    assert_eq!(
        resolve_wkd(&cfg, &wkd_hash("ALICE"), "ALICE", true, |_, _| true),
        WkdLookup::UserKey {
            domain: "a.test".into(),
            localpart: "alice".into()
        }
    );
}

#[test]
fn an_unconfigured_localpart_never_resolves_to_a_user_key() {
    assert_eq!(
        resolve_wkd(
            &one_domain(),
            &wkd_hash("nobody"),
            "nobody",
            true,
            |_, _| true
        ),
        WkdLookup::GlobalKey,
        "the hash matches, but there is no such account"
    );
}

/// Go ranges over the domain map here, so with the same localpart on two
/// domains its answer varies between runs. Which key a stranger receives must
/// not. SPEC.md §11.5.
#[test]
fn the_same_localpart_on_two_domains_resolves_the_same_way_every_time() {
    let cfg =
        cfg(r#"{"domain":{"z.test":{"account":{"alice":{}}},"a.test":{"account":{"alice":{}}}}}"#);
    for _ in 0..20 {
        assert_eq!(
            resolve_wkd(&cfg, &wkd_hash("alice"), "alice", false, |_, _| true),
            WkdLookup::UserKey {
                domain: "a.test".into(),
                localpart: "alice".into()
            }
        );
    }
}

// ── the public key ────────────────────────────────────────────────────────

#[test]
fn a_valid_key_round_trips_and_is_served_as_binary() {
    let tmp = tempfile::tempdir().unwrap();
    assert_eq!(
        store_pubkey(tmp.path(), "a.test", "alice", PUBKEY.as_bytes()),
        Ok(())
    );

    // Stored as uploaded, so the user's own key comes back exactly as given.
    assert_eq!(
        std::fs::read_to_string(pubkey_file(tmp.path(), "a.test", "alice")).unwrap(),
        PUBKEY
    );

    // Served as binary packets: a WKD client fetching a directory expects
    // packets, not armor.
    let binary = serve_pubkey(tmp.path(), "a.test", "alice").expect("should serve");
    assert!(!binary.is_empty());
    assert!(
        !binary.starts_with(b"-----BEGIN"),
        "armor must not reach the wire here"
    );
    // …and the binary form parses back to the same key.
    assert!(crate::pgp::parse_public_key(&binary).is_ok());
}

/// Validated before writing, for the reason `store_peer_key` gives: a file that
/// cannot be read back is worse than no file, because the account looks like it
/// has a key and everything addressed to it silently goes out in the clear.
#[test]
fn an_unparseable_key_is_refused_before_anything_is_written() {
    let tmp = tempfile::tempdir().unwrap();
    for bad in [
        &b""[..],
        b"not a key at all",
        b"-----BEGIN PGP PUBLIC KEY BLOCK-----\n\ngarbage\n-----END PGP PUBLIC KEY BLOCK-----\n",
    ] {
        assert_eq!(
            store_pubkey(tmp.path(), "a.test", "alice", bad),
            Err(KeyError::InvalidKey),
            "{:?}",
            String::from_utf8_lossy(bad)
        );
    }
    assert!(
        !pubkey_file(tmp.path(), "a.test", "alice").exists(),
        "a refused upload must leave nothing behind"
    );
}

#[test]
fn an_absent_key_serves_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    assert!(serve_pubkey(tmp.path(), "a.test", "alice").is_none());
}

/// A file that is on disk but unparseable serves nothing rather than serving
/// garbage — a client that receives bytes it cannot parse has no way to tell
/// that from a corrupt transfer.
#[test]
fn an_unparseable_stored_key_serves_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = crate::auth_env::account_dir(tmp.path(), "a.test", "alice");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("pubkey.pgp"), b"corrupt").unwrap();
    assert!(serve_pubkey(tmp.path(), "a.test", "alice").is_none());
}

// ── the private key blob ──────────────────────────────────────────────────

/// Stored without inspection, unlike the public key: the relay cannot parse
/// what it cannot decrypt, and validating here would be a claim to understand
/// the contents that is not true.
#[test]
fn the_private_blob_is_stored_opaquely_and_byte_for_byte() {
    let tmp = tempfile::tempdir().unwrap();
    // Deliberately not a PGP key, and not even UTF-8.
    let blob = [0u8, 1, 2, 255, 254, b'{', b'}'];
    store_privkey(tmp.path(), "a.test", "alice", &blob).unwrap();
    assert_eq!(
        read_privkey(tmp.path(), "a.test", "alice").as_deref(),
        Some(&blob[..])
    );
}

#[test]
fn an_absent_private_blob_reads_as_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    assert!(read_privkey(tmp.path(), "a.test", "alice").is_none());
}

#[test]
fn both_key_files_are_written_owner_only() {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = tempfile::tempdir().unwrap();
        store_pubkey(tmp.path(), "a.test", "alice", PUBKEY.as_bytes()).unwrap();
        store_privkey(tmp.path(), "a.test", "alice", b"blob").unwrap();
        for path in [
            pubkey_file(tmp.path(), "a.test", "alice"),
            privkey_enc_file(tmp.path(), "a.test", "alice"),
        ] {
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "{path:?}");
        }
    }
}

// ── peer keys ─────────────────────────────────────────────────────────────

/// Peer keys live per **domain**, not per account: they are gathered from
/// incoming mail, and two accounts on one domain writing to the same person
/// should not each have to rediscover their key.
#[test]
fn peer_keys_are_shared_across_a_domain_and_folded() {
    let tmp = tempfile::tempdir().unwrap();
    let path = peer_key_path(tmp.path(), "a.test", "Bob@Other.test");
    assert_eq!(
        path,
        peer_key_path(tmp.path(), "a.test", "bob@other.test"),
        "folded"
    );
    assert!(
        path.starts_with(tmp.path().join("a.test").join("peers")),
        "under the domain, not an account: {path:?}"
    );
    assert_ne!(
        path,
        peer_key_path(tmp.path(), "b.test", "bob@other.test"),
        "but not shared between domains"
    );
}

// ── statuses ──────────────────────────────────────────────────────────────

#[test]
fn each_error_carries_the_status_the_client_expects() {
    for (err, status) in [
        (KeyError::InvalidKey, 400),
        (KeyError::AddrRequired, 400),
        (KeyError::Unauthorized, 401),
        (KeyError::NotFound, 404),
    ] {
        assert_eq!(err.status(), status, "{err:?}");
    }
}
