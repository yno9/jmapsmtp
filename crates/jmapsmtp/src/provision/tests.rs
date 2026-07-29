//! Provisioning, which is where a DID becomes an account.
//!
//! The tests worth reading first are the ones about `did:webvh` on an
//! anchorless relay: that combination must be refused, because the SCID is a
//! hash of the identity's genesis log entry rather than a key and there is
//! nothing here to verify a vouch against (SPEC.md §10-A).

use super::*;
use pretty_assertions::assert_eq;

fn cfg(json: &str) -> Config {
    serde_json::from_str(json).expect("config should parse")
}

/// A relay with no anchor. The stricter mode: it can serve did:dht identities
/// and nothing else.
fn anchorless() -> Config {
    cfg(r#"{"domain":{"open.test":{"allow_provision":true}}}"#)
}

/// A relay with an anchor, which can bind any DID method.
fn anchored() -> Config {
    cfg(r#"{"domain":{"open.test":{"allow_provision":true}},
            "anchor_url":"https://anchor.test","anchor_token":"t"}"#)
}

const DID_DHT: &str = "did:dht:ybndrfg8ejkmcpqxot1uwisza345h769ybndrfg8ejkmcpqxot1uw";
const DID_WEBVH: &str =
    "did:webvh:QmSCIDPlaceholder1111111111111111111111111111:biset.md:dids:alice";

fn request(did: &str) -> ProvisionRequest {
    ProvisionRequest {
        username: "alice".into(),
        did: did.into(),
        did_sig: "c2ln".into(),
        bind_ts: 1_784_000_000,
        device_pub_key: "DEVKEY".into(),
        device_vouch_sig: "c2ln".into(),
        device_label: "Laptop".into(),
        device_vouch_ts: 1_784_000_000,
        ..Default::default()
    }
}

// ── usernames ─────────────────────────────────────────────────────────────

/// A username is a mail localpart *and* a directory name, so it is checked
/// rather than sanitised: a name mangled into something legal is a different
/// name than the one the DID signed for.
#[test]
fn usernames_are_narrow_and_checked_not_sanitised() {
    for ok in [
        "a",
        "alice",
        "0",
        "a_b-c",
        "a1234567890123456789012345678901",
    ] {
        assert_eq!(valid_username(ok), ok.len() <= 31, "{ok:?}");
    }
    for bad in [
        "",
        "Alice",  // uppercase
        "_alice", // must start alphanumeric
        "-alice",
        "alice.smith",  // no dots
        "alice@a.test", // not an address
        "ali ce",
        "../etc",                            // traversal
        "alice/bob",                         // path separator
        "a12345678901234567890123456789012", // 33
    ] {
        assert!(!valid_username(bad), "{bad:?} should be refused");
    }
}

/// Case is the one thing that *is* normalised, so an uppercase name succeeds
/// rather than being refused. `valid_username("Alice")` is false, but
/// `validate` never asks it that — it folds first.
#[test]
fn an_uppercase_username_is_folded_not_refused() {
    assert!(!valid_username("Alice"), "the predicate refuses it");

    let mut req = request(DID_DHT);
    req.username = "  Alice  ".into();
    assert_eq!(
        validate(&anchorless(), &req),
        Ok(()),
        "but the endpoint trims and folds before checking"
    );
}

#[test]
fn a_username_at_exactly_the_limit_is_allowed_and_one_over_is_not() {
    assert!(valid_username(&"a".repeat(31)));
    assert!(!valid_username(&"a".repeat(32)));
}

// ── the DID requirement ───────────────────────────────────────────────────

#[test]
fn a_request_with_no_did_is_refused() {
    let mut req = request(DID_DHT);
    req.did = String::new();
    assert_eq!(validate(&anchorless(), &req), Err(Refusal::DidRequired));
}

/// The device key *is* the credential in this flow, so a request without one
/// could only create an account nobody can log into.
#[test]
fn a_request_with_no_device_credential_is_refused() {
    for (field, req) in [
        ("device_pub_key", {
            let mut r = request(DID_DHT);
            r.device_pub_key = String::new();
            r
        }),
        ("device_vouch_sig", {
            let mut r = request(DID_DHT);
            r.device_vouch_sig = String::new();
            r
        }),
    ] {
        assert_eq!(
            validate(&anchorless(), &req),
            Err(Refusal::DeviceCredentialRequired),
            "{field}"
        );
    }
}

/// The DID signature proves control of the DID *to the anchor*. An anchorless
/// relay has nobody to prove it to, so demanding it would refuse accounts the
/// relay can serve perfectly well.
#[test]
fn the_did_signature_is_required_only_where_it_can_be_checked() {
    let mut req = request(DID_DHT);
    req.did_sig = String::new();

    assert_eq!(
        validate(&anchorless(), &req),
        Ok(()),
        "nobody to prove it to"
    );
    if cfg!(feature = "anchor") {
        assert_eq!(validate(&anchored(), &req), Err(Refusal::DidSigRequired));
    }
}

/// A request missing both hears about the username first: that is the field a
/// client can fix without re-deriving anything.
#[test]
fn the_username_is_reported_before_the_did() {
    let mut req = request("");
    req.username = "Bad Name".into();
    assert_eq!(validate(&anchorless(), &req), Err(Refusal::InvalidUsername));
}

// ── did:dht vs did:webvh ──────────────────────────────────────────────────

/// The heart of it. A did:dht identifier carries its own key, so an anchorless
/// relay verifies the vouch itself. A did:webvh SCID is a hash of the genesis
/// log entry — there is no key here — so without an anchor nothing can check
/// it, and the relay says exactly that instead of guessing.
#[test]
fn an_anchorless_relay_serves_did_dht_and_refuses_did_webvh() {
    let cfg = anchorless();
    assert_eq!(vouch_path(&cfg, DID_DHT), VouchPath::Local);
    assert_eq!(vouch_path(&cfg, DID_WEBVH), VouchPath::Impossible);

    // The refusal a client can act on: the vouch was fine, the relay cannot
    // check it. Distinct from a rejected vouch.
    assert_eq!(Refusal::DidMethodNeedsAnchor.status(), 401);
    assert_ne!(
        Refusal::DidMethodNeedsAnchor.message(),
        Refusal::DeviceVouchRejected.message()
    );
}

/// Checked before the anchor: a did:dht vouch is verified locally even on an
/// anchored relay, because the identifier already carries the key and a round
/// trip would add nothing.
#[test]
fn a_did_dht_vouch_stays_local_even_with_an_anchor_configured() {
    assert_eq!(vouch_path(&anchored(), DID_DHT), VouchPath::Local);
}

#[test]
fn an_anchored_relay_sends_other_methods_to_the_anchor() {
    if cfg!(feature = "anchor") {
        assert_eq!(vouch_path(&anchored(), DID_WEBVH), VouchPath::Anchor);
        assert_eq!(vouch_path(&anchored(), "did:key:z6Mk"), VouchPath::Anchor);
    }
}

/// An anchor URL alone is not enough — the noanchor build has no client to
/// reach it with, and must not claim it can bind.
#[test]
fn binding_needs_both_the_build_and_the_configuration() {
    assert!(!anchor_configured(&anchorless()), "configured: no");
    assert_eq!(anchor_configured(&anchored()), cfg!(feature = "anchor"));
}

#[test]
fn did_bound_is_reported_only_when_a_did_was_sent() {
    let mut req = request(DID_DHT);
    assert_eq!(did_bound(&anchored(), &req), cfg!(feature = "anchor"));
    assert!(!did_bound(&anchorless(), &req), "no anchor, no binding");

    req.did = String::new();
    assert!(!did_bound(&anchored(), &req));
}

// ── domain routing ────────────────────────────────────────────────────────

#[test]
fn an_empty_domain_falls_back_to_the_open_one() {
    let (domain, dom_cfg) = resolve_domain(&anchorless(), &DynamicDomains::default(), "").unwrap();
    assert_eq!(domain, "open.test");
    assert!(dom_cfg.allow_provision);
}

/// A named domain must exist. Falling back to the open one would put the
/// account somewhere the client did not ask for, under a name the DID signed
/// against a different domain.
#[test]
fn a_named_domain_that_does_not_exist_does_not_fall_back() {
    assert_eq!(
        resolve_domain(&anchorless(), &DynamicDomains::default(), "nope.test"),
        Err(Refusal::UnknownDomain)
    );
}

#[test]
fn a_named_domain_is_trimmed_and_folded() {
    let (domain, _) =
        resolve_domain(&anchorless(), &DynamicDomains::default(), "  Open.TEST ").unwrap();
    assert_eq!(domain, "open.test");
}

#[test]
fn a_registered_custom_domain_can_be_provisioned_onto() {
    let dynamic = DynamicDomains::default();
    dynamic.insert(
        "byo.test".into(),
        DomainConfig {
            provision_secret: "s3cret".into(),
            ..Default::default()
        },
    );
    let (domain, dom_cfg) = resolve_domain(&anchorless(), &dynamic, "byo.test").unwrap();
    assert_eq!(domain, "byo.test");
    assert_eq!(may_provision(&dom_cfg, "s3cret"), Ok(()));
}

#[test]
fn with_no_open_domain_and_no_named_one_there_is_nothing_to_do() {
    let closed = cfg(r#"{"domain":{"closed.test":{}}}"#);
    assert_eq!(
        resolve_domain(&closed, &DynamicDomains::default(), ""),
        Err(Refusal::NotAvailable)
    );
}

// ── the provisioning gate ─────────────────────────────────────────────────

#[test]
fn an_open_domain_needs_no_secret() {
    let open = DomainConfig {
        allow_provision: true,
        ..Default::default()
    };
    assert_eq!(may_provision(&open, ""), Ok(()));
}

#[test]
fn a_gated_domain_needs_the_right_secret() {
    let gated = DomainConfig {
        provision_secret: "s3cret".into(),
        ..Default::default()
    };
    assert_eq!(may_provision(&gated, "s3cret"), Ok(()));
    assert_eq!(may_provision(&gated, "wrong"), Err(Refusal::DomainNotOpen));
    assert_eq!(may_provision(&gated, ""), Err(Refusal::DomainNotOpen));
}

/// A domain with neither flag is privileged: configured that way so it is not
/// creatable from the UI at all. An empty configured secret must never match
/// an empty submitted one, which is what a bare `==` would do.
#[test]
fn a_domain_with_no_secret_and_no_flag_is_not_creatable() {
    let privileged = DomainConfig::default();
    assert_eq!(may_provision(&privileged, ""), Err(Refusal::DomainNotOpen));
    assert_eq!(
        may_provision(&privileged, "anything"),
        Err(Refusal::DomainNotOpen)
    );
}

// ── name collisions ───────────────────────────────────────────────────────

/// Both credential shapes mark an account, because they are different
/// generations of one: `auth_token_hash` is the older static credential and a
/// `devices/` entry is what this flow writes. Checking only one hands an
/// existing account to whoever asks for it.
#[test]
fn a_name_is_taken_by_either_credential_shape() {
    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path();
    let acct = crate::auth_env::account_dir(data, "a.test", "alice");

    assert!(
        !name_is_taken(&acct, data, "a.test", "alice", false),
        "nothing on disk"
    );

    // The older shape.
    crate::auth_env::write_auth_hash(data, "a.test", "alice", "hash").unwrap();
    assert!(name_is_taken(&acct, data, "a.test", "alice", false));

    // The newer shape, on a different name and with no hash at all.
    let acct_b = crate::auth_env::account_dir(data, "a.test", "bob");
    std::fs::create_dir_all(&acct_b).unwrap();
    jmapserver::devicekeys::write_device_key(
        &acct_b,
        &jmapserver::DeviceKey {
            id: "DEVKEY".into(),
            label: "Laptop".into(),
            created_at: 1,
        },
    )
    .unwrap();
    assert!(
        name_is_taken(&acct_b, data, "a.test", "bob", false),
        "a device key is a credential too — this flow writes no auth_token_hash"
    );
}

/// An account registered in this process but whose files are not where this
/// check looks — a name claimed moments ago — still counts.
#[test]
fn an_already_registered_name_is_taken_regardless_of_disk() {
    let tmp = tempfile::tempdir().unwrap();
    let acct = crate::auth_env::account_dir(tmp.path(), "a.test", "alice");
    assert!(name_is_taken(&acct, tmp.path(), "a.test", "alice", true));
}

// ── refusal statuses ──────────────────────────────────────────────────────

/// A client branches on these, so they are part of the contract.
#[test]
fn each_refusal_carries_the_status_the_client_expects() {
    for (refusal, status) in [
        (Refusal::InvalidUsername, 400),
        (Refusal::DeviceCredentialRequired, 400),
        (Refusal::DidRequired, 400),
        (Refusal::DidSigRequired, 400),
        (Refusal::UnknownDomain, 400),
        (Refusal::NotAvailable, 403),
        (Refusal::DomainNotOpen, 403),
        (Refusal::DidBindingRejected, 401),
        (Refusal::DeviceVouchRejected, 401),
        (Refusal::DidMethodNeedsAnchor, 401),
        (Refusal::UsernameTaken, 409),
        (Refusal::IdentityOwnedByAnother, 409),
        (Refusal::AnchorUnavailable, 503),
    ] {
        assert_eq!(refusal.status(), status, "{refusal:?}");
    }
}

/// 409 for "taken" and 409 for "owned by another key" are the same status but
/// different situations: the first means pick another name, the second means
/// this name is not yours. A client shows different things.
#[test]
fn the_two_conflicts_are_distinguishable_by_message() {
    assert_ne!(
        Refusal::UsernameTaken.message(),
        Refusal::IdentityOwnedByAnother.message()
    );
}

/// An unreachable anchor is 503, never a success. Creating the account anyway
/// would mean an unbound name that the anchor later hands to someone else.
#[test]
fn an_unreachable_anchor_refuses_rather_than_proceeding() {
    assert_eq!(Refusal::AnchorUnavailable.status(), 503);
}
