//! Web Key Directory and the PGP key endpoints, against the oracle.
//!
//! `/.well-known/openpgpkey/hu/` is **unauthenticated by design** — a stranger
//! has to be able to find your key before they can encrypt to you — so what it
//! answers is what anyone on the internet can learn. The tests here are about
//! whether the wrong key can be extracted, and whether the authenticated
//! routes stay authenticated.

use base64::Engine as _;
use jmapsmtp::wkd::{WkdLookup, resolve_wkd, wkd_hash};

mod oracle_harness;
use oracle_harness::Oracle;

/// The static credential for `alice`.
const AUTH_TOKEN: &[u8] = b"wkd-interop-token-00000000000000";

fn basic_auth(account: &str) -> String {
    let password = base64::engine::general_purpose::STANDARD.encode(AUTH_TOKEN);
    base64::engine::general_purpose::STANDARD.encode(format!("{account}:{password}"))
}

fn config_json(http_port: u16, smtp_port: u16) -> String {
    format!(
        r#"{{"listen_addr":"127.0.0.1:{http_port}","smtp_port":{smtp_port},
            "base_url":"http://127.0.0.1:{http_port}","hostname":"t.invalid",
            "domain":{{"a.test":{{"account":{{"alice":{{}},"bob":{{}}}}}}}}}}"#
    )
}

fn rust_config() -> jmapsmtp::config::Config {
    serde_json::from_str(&config_json(1, 1)).unwrap()
}

const PUBKEY: &str = include_str!("../../../xtask/fixtures/pgp-public.asc");
/// A *different* key, so "served the relay's key" and "served the account's
/// key" are distinguishable. Using one fixture for both makes every such
/// assertion vacuously true — which is how the case-folding behaviour below
/// stayed hidden.
const RELAY_KEY: &str = include_str!("../../../xtask/fixtures/pgp-public-relay.asc");

/// `alice` has a credential and a public key; `bob` has a credential and none.
/// One boot therefore covers both the per-account and the fallback path.
fn seed(root: &std::path::Path) {
    for lp in ["alice", "bob"] {
        let acct = root.join("data/a.test").join(lp);
        std::fs::create_dir_all(&acct).unwrap();
        std::fs::write(
            acct.join("auth_token_hash"),
            jmapserver::hash_auth_token(AUTH_TOKEN),
        )
        .unwrap();
    }
    std::fs::write(root.join("data/a.test/alice/pubkey.pgp"), PUBKEY).unwrap();
}

fn oracle() -> Option<Oracle> {
    Oracle::start_with("WKD_INTEROP", config_json, seed)
}

/// The same relay, but with a relay-wide key loaded from `BISET_PGP_KEY`.
///
/// A separate boot because the global key changes what *every* WKD lookup
/// answers: without it a miss is a 404, with it a miss falls through to the
/// relay's key. Both are worth testing, and the fall-through is where serving
/// the wrong key would happen.
fn oracle_with_global_key() -> Option<Oracle> {
    Oracle::start_with_env(
        "WKD_INTEROP",
        config_json,
        seed,
        &[("BISET_PGP_KEY", RELAY_KEY)],
    )
}

// ── the public directory ──────────────────────────────────────────────────

/// The policy file is a marker: an empty 200 *is* the answer, and a WKD client
/// treats its absence as "this domain does not do WKD".
#[test]
fn the_policy_marker_is_an_empty_two_hundred() {
    let Some(o) = oracle() else { return };
    let (status, body, _) = o.get("/.well-known/openpgpkey/policy");
    assert_eq!(status, 200);
    assert_eq!(body, "", "a marker, not a document");
}

/// A stranger asking for alice's key with the matching hash gets it, as binary
/// packets rather than armor.
#[test]
fn a_stranger_can_fetch_a_users_key_with_the_matching_hash() {
    let Some(o) = oracle() else { return };
    let (status, body, _) = o.get(&format!(
        "/.well-known/openpgpkey/hu/{}?l=alice",
        wkd_hash("alice")
    ));
    assert_eq!(status, 200, "{body:?}");
    assert!(!body.is_empty());
    assert!(
        !body.starts_with("-----BEGIN"),
        "WKD serves packets, not armor: {body:.40}"
    );

    // Same key, and this port resolves the same way.
    let ours = jmapsmtp::wkd::serve_pubkey(&o.data_dir(), "a.test", "alice")
        .expect("this port should serve it");
    assert_eq!(
        String::from_utf8_lossy(&ours),
        body,
        "byte-identical to what the oracle served"
    );
    assert_eq!(
        resolve_wkd(
            &rust_config(),
            &wkd_hash("alice"),
            "alice",
            false,
            |d, l| { jmapsmtp::wkd::pubkey_file(&o.data_dir(), d, l).exists() }
        ),
        WkdLookup::UserKey {
            domain: "a.test".into(),
            localpart: "alice".into()
        }
    );
}

/// The attack this directory has to resist: asking for one person's key under
/// another's hash. Both implementations must refuse rather than serve either.
#[test]
fn a_mismatched_localpart_and_hash_yields_nothing_on_either_implementation() {
    let Some(o) = oracle() else { return };
    let data = o.data_dir();
    let has_key = |d: &str, l: &str| jmapsmtp::wkd::pubkey_file(&data, d, l).exists();

    for (name, hash, l) in [
        ("bob's l= under alice's hash", wkd_hash("alice"), "bob"),
        ("alice's l= under bob's hash", wkd_hash("bob"), "alice"),
        ("a hash that is not one", "notahash".to_string(), "alice"),
    ] {
        let (status, body, _) = o.get(&format!("/.well-known/openpgpkey/hu/{hash}?l={l}"));
        assert_eq!(status, 404, "{name}: the oracle served {body:.60}");
        assert_eq!(
            resolve_wkd(&rust_config(), &hash, l, false, has_key),
            WkdLookup::NotFound,
            "{name}: this port disagreed"
        );
    }
}

/// An account with no key of its own, with no relay-wide key configured, is a
/// 404 — not somebody else's key.
#[test]
fn an_account_with_no_key_and_no_global_key_is_not_found() {
    let Some(o) = oracle() else { return };
    let (status, body, _) = o.get(&format!(
        "/.well-known/openpgpkey/hu/{}?l=bob",
        wkd_hash("bob")
    ));
    assert_eq!(status, 404, "{body:.60}");
    assert_eq!(
        resolve_wkd(&rust_config(), &wkd_hash("bob"), "bob", false, |_, _| false),
        WkdLookup::NotFound
    );
}

// ── the authenticated routes ──────────────────────────────────────────────

/// The private key blob leaves only against the account's own credential. It is
/// encrypted client-side, but it is still the private key.
#[test]
fn the_private_blob_needs_the_accounts_own_credential() {
    let Some(o) = oracle() else { return };

    // Unauthenticated: refused.
    let (status, _, _) = o.get("/pgp/privkey");
    assert_eq!(status, 401);

    // Stored opaquely and returned byte for byte, including bytes that are not
    // a PGP key and not UTF-8 — the relay cannot parse what it cannot decrypt.
    let blob = "\u{0}\u{1}\u{feff}{not a key}";
    let (status, body) = o.put_auth("/pgp/privkey", blob, &basic_auth("alice@a.test"));
    assert_eq!(status, 204, "{body:?}");

    let on_disk = jmapsmtp::wkd::read_privkey(&o.data_dir(), "a.test", "alice")
        .expect("stored where this port looks");
    assert_eq!(
        String::from_utf8_lossy(&on_disk),
        blob,
        "stored without inspection"
    );

    let (status, returned, _) = o.get_auth("/pgp/privkey", &basic_auth("alice@a.test"));
    assert_eq!(status, 200);
    assert_eq!(returned, blob, "returned byte for byte");
}

/// One account cannot read another's private blob, even with a valid credential
/// of its own — the credential names the account, and only that one.
#[test]
fn one_accounts_credential_does_not_reach_anothers_private_blob() {
    let Some(o) = oracle() else { return };
    o.put_auth("/pgp/privkey", "alice's blob", &basic_auth("alice@a.test"));

    // bob has a valid credential and asks for the same path.
    let (status, body, _) = o.get_auth("/pgp/privkey", &basic_auth("bob@a.test"));
    assert_ne!(
        body, "alice's blob",
        "the path is per-account, resolved from the credential"
    );
    assert_eq!(status, 404, "bob has no blob of his own");
}

/// An upload that does not parse is refused, and leaves the previous key in
/// place. A key file that cannot be read back is worse than none: the account
/// looks like it has one and mail to it silently goes out in the clear.
#[test]
fn an_unparseable_public_key_upload_is_refused_and_changes_nothing() {
    let Some(o) = oracle() else { return };
    let before = std::fs::read(o.data_dir().join("a.test/alice/pubkey.pgp")).unwrap();

    let (status, body) = o.put_auth("/pgp/pubkey", "not a key", &basic_auth("alice@a.test"));
    assert_eq!(status, 400, "{body:?}");
    assert_eq!(
        jmapsmtp::wkd::store_pubkey(&o.data_dir(), "a.test", "alice", b"not a key"),
        Err(jmapsmtp::wkd::KeyError::InvalidKey),
        "this port refuses it too"
    );

    assert_eq!(
        std::fs::read(o.data_dir().join("a.test/alice/pubkey.pgp")).unwrap(),
        before,
        "the existing key must survive a bad upload"
    );
}

/// A valid upload is stored as sent, so the user's key comes back exactly as
/// they provided it.
#[test]
fn a_valid_public_key_upload_is_stored_as_uploaded() {
    let Some(o) = oracle() else { return };
    let (status, body) = o.put_auth("/pgp/pubkey", PUBKEY, &basic_auth("bob@a.test"));
    assert_eq!(status, 204, "{body:?}");
    assert_eq!(
        std::fs::read_to_string(o.data_dir().join("a.test/bob/pubkey.pgp")).unwrap(),
        PUBKEY,
        "not a re-serialisation"
    );

    // And it is now findable in the public directory.
    let (status, _, _) = o.get(&format!(
        "/.well-known/openpgpkey/hu/{}?l=bob",
        wkd_hash("bob")
    ));
    assert_eq!(status, 200);
}

// ── the relay-wide key ────────────────────────────────────────────────────

/// With a relay-wide key, an account that has none of its own falls through to
/// it — which is what makes configuring one useful.
#[test]
fn an_account_with_no_key_falls_through_to_the_relay_wide_one() {
    let Some(o) = oracle_with_global_key() else {
        return;
    };
    let (status, body, _) = o.get(&format!(
        "/.well-known/openpgpkey/hu/{}?l=bob",
        wkd_hash("bob")
    ));
    assert_eq!(status, 200, "bob has no key of his own: {body:.60}");
    assert!(!body.is_empty());

    assert_eq!(
        resolve_wkd(&rust_config(), &wkd_hash("bob"), "bob", true, |_, _| false),
        WkdLookup::GlobalKey,
        "this port agrees"
    );
}

/// The fall-through must **not** happen for a mismatched `l=`. This is the case
/// the mutation testing exposed as untested: with no relay-wide key every
/// mismatch is a 404 anyway, so the branch that refuses one only becomes
/// observable once a global key exists.
#[test]
fn a_mismatched_localpart_does_not_fall_through_to_the_relay_wide_key() {
    let Some(o) = oracle_with_global_key() else {
        return;
    };
    for (name, hash, l) in [
        ("bob's l= under alice's hash", wkd_hash("alice"), "bob"),
        ("a hash that is not one", "notahash".to_string(), "alice"),
    ] {
        let (status, body, _) = o.get(&format!("/.well-known/openpgpkey/hu/{hash}?l={l}"));
        assert_eq!(
            status,
            404,
            "{name}: answered {status} with {} bytes — a caller that asked \
             inconsistently must not be handed a key anyway",
            body.len()
        );
        assert_eq!(
            resolve_wkd(&rust_config(), &hash, l, true, |_, _| false),
            WkdLookup::NotFound,
            "{name}: this port disagreed"
        );
    }
}

/// A per-account key still wins over the relay-wide one.
#[test]
fn a_users_own_key_outranks_the_relay_wide_one() {
    let Some(o) = oracle_with_global_key() else {
        return;
    };
    let (status, served, _) = o.get(&format!(
        "/.well-known/openpgpkey/hu/{}?l=alice",
        wkd_hash("alice")
    ));
    assert_eq!(status, 200);
    let own = jmapsmtp::wkd::serve_pubkey(&o.data_dir(), "a.test", "alice").unwrap();
    assert_eq!(
        String::from_utf8_lossy(&own),
        served,
        "alice's own key, not the relay's"
    );
}

/// The declared divergence, SPEC.md §11.15 — and a privacy bug in the Go
/// implementation, not a cosmetic difference.
///
/// `wkdHash` lowercases, so the hash comparison is case-insensitive. The Go
/// account lookup that follows is not: it indexes `domCfg.Accounts` with the raw
/// `l=`. So `?l=Alice` passes the hash check and then misses the account,
/// **falling through to the relay-wide key**.
///
/// A sender whose address book holds `Alice@a.test` therefore encrypts to a key
/// the relay holds and alice does not — silently, while believing the mail is
/// end-to-end encrypted.
///
/// This test needs a relay key that *differs* from alice's to see it at all.
/// With one fixture serving both, every assertion here is vacuously true, which
/// is how this stayed hidden until the fixtures were split.
#[test]
fn a_capitalised_localpart_gets_the_relays_key_from_the_oracle_and_alices_from_this_port() {
    let Some(o) = oracle_with_global_key() else {
        return;
    };
    let alices = jmapsmtp::wkd::serve_pubkey(&o.data_dir(), "a.test", "alice").unwrap();
    let alices = String::from_utf8_lossy(&alices).to_string();

    // The lowercase form works on both, and is the control: it proves the two
    // keys are distinguishable at all.
    let (status, body, _) = o.get(&format!(
        "/.well-known/openpgpkey/hu/{}?l=alice",
        wkd_hash("alice")
    ));
    assert_eq!(status, 200);
    assert_eq!(body, alices, "l=alice serves alice's key");

    // The capitalised form: the oracle serves the *relay's* key.
    let (status, body, _) = o.get(&format!(
        "/.well-known/openpgpkey/hu/{}?l=Alice",
        wkd_hash("Alice")
    ));
    assert_eq!(status, 200);
    assert_ne!(
        body, alices,
        "the oracle is expected to still serve the relay's key here — if it \
         now serves alice's, SPEC.md §11.15 is stale"
    );
    assert!(
        !body.is_empty(),
        "and it is a key, not an empty body: this is the silent part"
    );

    // This port resolves to alice's own account instead.
    let data = o.data_dir();
    assert_eq!(
        resolve_wkd(&rust_config(), &wkd_hash("Alice"), "Alice", true, |d, l| {
            jmapsmtp::wkd::pubkey_file(&data, d, l).exists()
        }),
        WkdLookup::UserKey {
            domain: "a.test".into(),
            localpart: "alice".into()
        },
        "this port folds before the account lookup"
    );
}

#[test]
fn peerkey_needs_an_address_and_a_credential() {
    let Some(o) = oracle() else { return };
    let (status, _, _) = o.get("/pgp/peerkey?addr=x@y.test");
    assert_eq!(status, 401, "unauthenticated");

    let (status, body, _) = o.get_auth("/pgp/peerkey", &basic_auth("alice@a.test"));
    assert_eq!(status, 400);
    assert_eq!(jmapsmtp::wkd::KeyError::AddrRequired.message(), body.trim());

    let (status, _, _) = o.get_auth(
        "/pgp/peerkey?addr=nobody@x.test",
        &basic_auth("alice@a.test"),
    );
    assert_eq!(status, 404, "no key gathered for that peer");
}
