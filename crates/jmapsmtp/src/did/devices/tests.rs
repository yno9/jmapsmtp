//! Login and device vouching — the credential chain at runtime.
//!
//! The two tests to read first are `a_cold_recovery_needs_no_existing_credential`
//! and `every_login_failure_looks_the_same`: one is why these endpoints skip
//! `authenticate()`, the other is why they say so little when they refuse.

use super::*;
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};
use jmapserver::did::devicebind;
use jmapserver::did::session_nonce::SessionNonceStore;
use pretty_assertions::assert_eq;

fn cfg(json: &str) -> Config {
    serde_json::from_str(json).expect("config should parse")
}

fn anchorless() -> Config {
    cfg(r#"{"domain":{"a.test":{}}}"#)
}

fn anchored() -> Config {
    cfg(r#"{"domain":{"a.test":{}},"anchor_url":"https://anchor.test","anchor_token":"t"}"#)
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn b64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

const NOW: i64 = 1_785_000_000;
/// The host `login()` is called with below — this relay's own observation,
/// standing in for a real request's `Host` header.
const RELAY_HOST: &str = "mail.a.test";

/// A did:dht identity plus one device. The identifier is the root public key,
/// so nothing here needs an anchor.
struct Setup {
    root: SigningKey,
    device: SigningKey,
    did: String,
    device_id: String,
}

fn setup() -> Setup {
    let root = SigningKey::from_bytes(&[9u8; 32]);
    // A did:webvh SCID: a hash of the genesis log entry, carrying no key.
    // The fixture used to be a did:dht identifier — which *was* the key, so
    // the relay could verify a vouch from the string alone. Nothing can now,
    // which is why these tests go through the anchor.
    let did =
        "did:webvh:QmSCIDPlaceholder1111111111111111111111111111:biset.md:dids:alice".to_string();
    let device = SigningKey::from_bytes(&[10u8; 32]);
    let device_id = b64url(&device.verifying_key().to_bytes());
    Setup {
        root,
        device,
        did,
        device_id,
    }
}

impl Setup {
    fn vouch(&self, label: &str, ts: i64) -> VouchRequest {
        VouchRequest {
            username: "alice".into(),
            domain: "a.test".into(),
            did: self.did.clone(),
            device_pub_key: self.device_id.clone(),
            label: label.into(),
            bind_ts: ts,
            sig: b64(&self
                .root
                .sign(devicebind::vouch_statement(&self.did, &self.device_id, label, ts).as_bytes())
                .to_bytes()),
        }
    }

    /// `nonce` must have come from a real `SessionNonceStore::issue()` (or
    /// this method's own fresh-nonce convenience below) — a fabricated nonce
    /// would fail `login()` at the nonce-consume step regardless of an
    /// otherwise-valid signature, silently defeating whatever the test
    /// actually wants to check.
    fn session(&self, ts: i64, nonce: &str) -> SessionRequest {
        SessionRequest {
            username: "alice".into(),
            domain: "a.test".into(),
            did: self.did.clone(),
            device_pub_key: self.device_id.clone(),
            nonce: nonce.into(),
            ts,
            sig: b64(&self
                .device
                .sign(
                    devicebind::session_login_statement(
                        &self.did,
                        &self.device_id,
                        RELAY_HOST,
                        nonce,
                        ts,
                    )
                    .as_bytes(),
                )
                .to_bytes()),
        }
    }

    /// `session()` against a nonce freshly issued from `nonces` — the
    /// common case, where the test only cares that login succeeds or fails
    /// for a reason OTHER than nonce plumbing.
    fn session_fresh(&self, ts: i64, nonces: &SessionNonceStore) -> SessionRequest {
        self.session(ts, &nonces.issue())
    }
}

/// A data dir with `alice@a.test` holding one registered device.
fn with_device(s: &Setup) -> tempfile::TempDir {
    let tmp = tempfile::tempdir().unwrap();
    let acct = crate::auth_env::account_dir(tmp.path(), "a.test", "alice");
    std::fs::create_dir_all(&acct).unwrap();
    jmapserver::did::devicekeys::write_device_key(
        &acct,
        &jmapserver::DeviceKey {
            id: s.device_id.clone(),
            label: "Laptop".into(),
            created_at: NOW,
        },
    )
    .unwrap();
    tmp
}

// ── required fields ───────────────────────────────────────────────────────

/// One message naming all five, rather than one round trip per field: a client
/// missing one is usually missing several.
#[test]
fn all_five_fields_are_required_on_both_endpoints() {
    let s = setup();
    for (name, mut req) in [
        ("username", s.session(NOW, "n")),
        ("domain", s.session(NOW, "n")),
        ("did", s.session(NOW, "n")),
        ("device_pub_key", s.session(NOW, "n")),
        ("sig", s.session(NOW, "n")),
    ] {
        match name {
            "username" => req.username = "  ".into(),
            "domain" => req.domain = String::new(),
            "did" => req.did = String::new(),
            "device_pub_key" => req.device_pub_key = String::new(),
            _ => req.sig = String::new(),
        }
        assert_eq!(req.account(), Err(DeviceError::MissingFields), "{name}");
    }
    let mut vouch = s.vouch("Laptop", NOW);
    vouch.did = String::new();
    assert_eq!(vouch.account(), Err(DeviceError::MissingFields));
}

#[test]
fn the_account_is_trimmed_and_folded() {
    let s = setup();
    let mut req = s.session(NOW, "n");
    req.username = "  Alice ".into();
    req.domain = " A.TEST ".into();
    assert_eq!(req.account(), Ok(("alice".into(), "a.test".into())));
}

/// The label is *not* required, unlike the other five: a device with no name is
/// still a device, and the vouch signature covers the empty string just as
/// well.
#[test]
fn a_vouch_needs_no_label() {
    let s = setup();
    assert_eq!(
        s.vouch("", NOW).account(),
        Ok(("alice".into(), "a.test".into()))
    );
    // An anchored relay routes it to the anchor. It used to be checked here,
    // against the key inside a did:dht identifier; there is no such key in a
    // did:webvh SCID, so the answer is now *where to ask*, not *is it good*.
    assert_eq!(
        check_vouch(&anchored(), &s.vouch("", NOW), NOW),
        Ok(crate::did::provision::VouchPath::Anchor)
    );
    assert_eq!(
        check_vouch(&anchorless(), &s.vouch("", NOW), NOW),
        Err(DeviceError::AnchorRequired),
        "with no anchor there is nobody to ask"
    );
}

// ── login ─────────────────────────────────────────────────────────────────

#[test]
fn a_device_signature_alone_logs_in() {
    let s = setup();
    let tmp = with_device(&s);
    let nonces = SessionNonceStore::new();
    let res = login(
        tmp.path(),
        &s.session_fresh(NOW, &nonces),
        RELAY_HOST,
        &nonces,
        NOW,
    )
    .expect("should log in");
    assert_eq!(res.email, "alice@a.test");
    assert_eq!(res.expires_in, SESSION_TOKEN_TTL_SECS);
    assert!(!res.token.is_empty());

    // The token authenticates against JMAP straight away — the two paths have
    // to accept the same credential, and being out of step once locked
    // session-logged-in accounts out of JMAP entirely (auth_env.go's header).
    assert_eq!(
        crate::auth_env::authenticate(
            &cfg(r#"{"domain":{"a.test":{"account":{"alice":{}}}}}"#),
            &crate::auth_env::DynAccounts::default(),
            tmp.path(),
            "alice@a.test",
            &res.token,
        )
        .map(|id| id.as_str().to_string()),
        Some("alice@a.test".into())
    );
}

/// Every refusal is one message. Telling them apart would let an
/// unauthenticated caller enumerate which usernames and devices exist — this
/// endpoint takes no credential, so anyone on the internet can ask.
#[test]
fn every_login_failure_looks_the_same() {
    let s = setup();
    let tmp = with_device(&s);
    let nonces = SessionNonceStore::new();

    let unknown_account = {
        let mut r = s.session_fresh(NOW, &nonces);
        r.username = "nobody".into();
        r
    };
    let unregistered_device = {
        let other = SigningKey::from_bytes(&[77u8; 32]);
        let id = b64url(&other.verifying_key().to_bytes());
        let nonce = nonces.issue();
        let sig = b64(&other
            .sign(
                devicebind::session_login_statement(&s.did, &id, RELAY_HOST, &nonce, NOW)
                    .as_bytes(),
            )
            .to_bytes());
        SessionRequest {
            device_pub_key: id,
            nonce,
            sig,
            ..s.session_fresh(NOW, &nonces)
        }
    };
    let wrong_signature = SessionRequest {
        sig: b64(&[0u8; 64]),
        ..s.session_fresh(NOW, &nonces)
    };
    let stale = s.session_fresh(NOW - 10_000, &nonces);
    let from_the_future = s.session_fresh(NOW + 10_000, &nonces);
    let replayed_nonce = {
        let req = s.session_fresh(NOW, &nonces);
        login(tmp.path(), &req, RELAY_HOST, &nonces, NOW).expect("first use should succeed");
        req
    };

    for (name, req) in [
        ("an unknown account", unknown_account),
        ("an unregistered device", unregistered_device),
        ("a bad signature", wrong_signature),
        ("a stale timestamp", stale),
        ("a timestamp from the future", from_the_future),
        ("a nonce already spent (replay)", replayed_nonce),
    ] {
        assert_eq!(
            login(tmp.path(), &req, RELAY_HOST, &nonces, NOW).err(),
            Some(DeviceError::SessionRejected),
            "{name}"
        );
    }
}

/// A revoked device cannot log in again, and its existing tokens are gone too —
/// checked by `auth_env`'s tests. Revocation that only stopped *new* logins
/// would leave the device working until its token expired.
#[test]
fn a_revoked_device_cannot_log_in() {
    let s = setup();
    let tmp = with_device(&s);
    let nonces = SessionNonceStore::new();
    assert!(login(tmp.path(), &s.session_fresh(NOW, &nonces), RELAY_HOST, &nonces, NOW).is_ok());

    let acct = crate::auth_env::account_dir(tmp.path(), "a.test", "alice");
    jmapserver::did::devicekeys::remove_device_key(&acct, &s.device_id).unwrap();

    assert_eq!(
        login(tmp.path(), &s.session_fresh(NOW, &nonces), RELAY_HOST, &nonces, NOW).err(),
        Some(DeviceError::SessionRejected)
    );
}

// ── vouching a new device ─────────────────────────────────────────────────

/// Why `POST /account/devices` skips `authenticate()`: a fully cold recovery
/// has a mnemonic and nothing else — no session, no token, a fresh install.
/// Requiring an existing credential would make that path impossible.
#[test]
fn a_cold_recovery_needs_no_existing_credential() {
    let s = setup();
    let tmp = with_device(&s);

    // A second device, vouched by the same root key, with no session or token
    // anywhere in sight.
    let new_device = SigningKey::from_bytes(&[42u8; 32]);
    let new_id = b64url(&new_device.verifying_key().to_bytes());
    let req = VouchRequest {
        device_pub_key: new_id.clone(),
        sig: b64(&s
            .root
            .sign(devicebind::vouch_statement(&s.did, &new_id, "Phone", NOW).as_bytes())
            .to_bytes()),
        ..s.vouch("Phone", NOW)
    };

    assert_eq!(
        check_vouch(&anchored(), &req, NOW),
        Ok(crate::did::provision::VouchPath::Anchor)
    );
    write_device(tmp.path(), "a.test", "alice", &req, NOW).unwrap();

    // …and that device can now log in on its own.
    let nonces = SessionNonceStore::new();
    let nonce = nonces.issue();
    let session = SessionRequest {
        device_pub_key: new_id.clone(),
        nonce: nonce.clone(),
        sig: b64(&new_device
            .sign(
                devicebind::session_login_statement(&s.did, &new_id, RELAY_HOST, &nonce, NOW)
                    .as_bytes(),
            )
            .to_bytes()),
        ..s.session(NOW, "unused")
    };
    assert!(login(tmp.path(), &session, RELAY_HOST, &nonces, NOW).is_ok());
}

// ── what this relay no longer judges ──────────────────────────────────────
//
// Three tests used to live here: a vouch the root key did not sign, a vouch
// replayed under another label, and a stale one. All three were rejected
// *here*, because a did:dht identifier was the identity's ed25519 key and the
// relay could check the signature from the string alone.
//
// did:webvh has no key in the identifier, so the relay cannot check any of it
// and does not pretend to. The anchor does. What follows pins that as a
// statement rather than leaving it as an absence — the dangerous version of
// this change is the one where the checks quietly stop happening anywhere.

/// A vouch nobody could have signed still reaches the anchor: this relay
/// reports **where the answer comes from**, not what it is.
#[test]
fn a_forged_vouch_is_not_rejected_here_but_sent_to_the_anchor() {
    let s = setup();
    let impostor = SigningKey::from_bytes(&[123u8; 32]);
    let req = VouchRequest {
        sig: b64(&impostor
            .sign(devicebind::vouch_statement(&s.did, &s.device_id, "Laptop", NOW).as_bytes())
            .to_bytes()),
        ..s.vouch("Laptop", NOW)
    };
    assert_eq!(
        check_vouch(&anchored(), &req, NOW),
        Ok(crate::did::provision::VouchPath::Anchor),
        "the relay has no key to check this against; the anchor decides"
    );
    assert_eq!(
        check_vouch(&anchorless(), &req, NOW),
        Err(DeviceError::AnchorRequired),
        "and with no anchor it is refused rather than accepted unchecked"
    );
}

/// The same for a replayed label and a stale timestamp. Both were caught here
/// and are now the anchor's business; neither may be silently accepted by a
/// relay that cannot judge them.
#[test]
fn a_replayed_label_and_a_stale_timestamp_are_the_anchors_business() {
    let s = setup();
    let relabelled = VouchRequest {
        label: "Attacker's box".into(),
        ..s.vouch("Laptop", NOW)
    };
    assert_eq!(
        check_vouch(&anchored(), &relabelled, NOW),
        Ok(crate::did::provision::VouchPath::Anchor)
    );
    assert_eq!(
        check_vouch(&anchorless(), &relabelled, NOW),
        Err(DeviceError::AnchorRequired)
    );

    for ts in [NOW - 10_000, NOW + 10_000] {
        assert_eq!(
            check_vouch(&anchored(), &s.vouch("Laptop", ts), NOW),
            Ok(crate::did::provision::VouchPath::Anchor),
            "ts {ts}"
        );
        assert_eq!(
            check_vouch(&anchorless(), &s.vouch("Laptop", ts), NOW),
            Err(DeviceError::AnchorRequired),
            "ts {ts}"
        );
    }
}

// ── did:dht vs everything else ────────────────────────────────────────────

/// A did:webvh vouch on an anchorless relay is **503, not 401**. The vouch may
/// be perfectly valid — this relay cannot judge it, which is a condition of the
/// server, not of the request. Answering 401 would tell the client its
/// signature was wrong.
#[test]
fn a_non_did_dht_vouch_without_an_anchor_is_a_server_condition_not_a_rejection() {
    let s = setup();
    let req = VouchRequest {
        did: "did:webvh:QmSCID111111111111111111111111111111111111111:biset.md:dids:alice".into(),
        ..s.vouch("Laptop", NOW)
    };
    let err = check_vouch(&anchorless(), &req, NOW).unwrap_err();
    assert_eq!(err, DeviceError::AnchorRequired);
    assert_eq!(err.status(), 503);
    assert_ne!(err.status(), DeviceError::VouchRejected.status());
}

#[test]
fn with_an_anchor_a_non_did_dht_vouch_goes_to_it() {
    if cfg!(feature = "anchor") {
        let s = setup();
        let req = VouchRequest {
            did: "did:webvh:QmSCID111111111111111111111111111111111111111:biset.md:dids:alice"
                .into(),
            ..s.vouch("Laptop", NOW)
        };
        assert_eq!(
            check_vouch(&anchored(), &req, NOW),
            Ok(crate::did::provision::VouchPath::Anchor)
        );
    }
}

// ── existence, by either credential shape ─────────────────────────────────

/// A legacy account has an `auth_token_hash` and no device; an account from the
/// provisioning flow has the reverse and never writes a hash at all. Checking
/// only the hash 404s every post-redesign account the moment it vouches a
/// *second* device — which is how the Go comment records this being found live.
#[test]
fn an_account_exists_by_either_credential_shape() {
    let tmp = tempfile::tempdir().unwrap();
    assert!(!account_exists(tmp.path(), "a.test", "alice"));

    // Legacy: a hash, no devices.
    crate::auth_env::write_auth_hash(tmp.path(), "a.test", "legacy", "hash").unwrap();
    assert!(account_exists(tmp.path(), "a.test", "legacy"));

    // Post-redesign: a device, no hash.
    let s = setup();
    let acct = crate::auth_env::account_dir(tmp.path(), "a.test", "modern");
    std::fs::create_dir_all(&acct).unwrap();
    jmapserver::did::devicekeys::write_device_key(
        &acct,
        &jmapserver::DeviceKey {
            id: s.device_id.clone(),
            label: "Laptop".into(),
            created_at: NOW,
        },
    )
    .unwrap();
    assert!(
        !acct.join("auth_token_hash").exists(),
        "the newer flow writes no hash"
    );
    assert!(account_exists(tmp.path(), "a.test", "modern"));
}

// ── statuses ──────────────────────────────────────────────────────────────

#[test]
fn each_error_carries_the_status_the_client_expects() {
    for (err, status) in [
        (DeviceError::MissingFields, 400),
        (DeviceError::IdRequired, 400),
        (DeviceError::Unauthorized, 401),
        (DeviceError::SessionRejected, 401),
        (DeviceError::VouchRejected, 401),
        (DeviceError::NoSuchAccount, 404),
        (DeviceError::AnchorRequired, 503),
        (DeviceError::AnchorUnavailable, 503),
    ] {
        assert_eq!(err.status(), status, "{err:?}");
    }
}

/// 30 days. Long enough that a working device is not logging in constantly,
/// short enough that a stolen token stops working — the token is re-signed with
/// the device key well before expiry on next use, so the bound bites on a
/// stolen token rather than a live one.
#[test]
fn the_session_ttl_is_thirty_days() {
    assert_eq!(SESSION_TOKEN_TTL_SECS, 2_592_000);
}
