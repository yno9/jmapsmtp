//! `POST /account/session` and `/account/devices`, against the oracle.
//!
//! These two endpoints take **no credential** — a signature is the whole proof
//! — so they are reachable by anyone who can open the port. That makes their
//! exact answers part of the security boundary, not just the API: a status or
//! message that distinguishes "no such account" from "bad signature" hands out
//! a username oracle.
//!
//! The relay here is anchorless, which is where `did:dht` and `did:webvh`
//! diverge (SPEC.md §10-A).

use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};
use jmapserver::devicebind;
use jmapserver::zbase32;
use jmapsmtp::devices::{DeviceError, SessionRequest, VouchRequest, check_vouch};

mod oracle_harness;
use oracle_harness::Oracle;

fn config_json(http_port: u16, smtp_port: u16) -> String {
    format!(
        r#"{{"listen_addr":"127.0.0.1:{http_port}","smtp_port":{smtp_port},
            "base_url":"http://127.0.0.1:{http_port}","hostname":"t.invalid",
            "domain":{{"a.test":{{"account":{{"alice":{{}}}}}}}}}}"#
    )
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn b64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// The host `RELAY_HOST` names in every non-`legacy_session` signature —
/// this port's own session statement is host-bound (devicebind.rs's own
/// note); it plays no role in `legacy_session`, which has no host segment
/// at all.
const RELAY_HOST: &str = "a.test";

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

struct Setup {
    root: SigningKey,
    device: SigningKey,
    did: String,
    device_id: String,
}

fn setup(seed: u8) -> Setup {
    let root = SigningKey::from_bytes(&[seed; 32]);
    let did = format!(
        "did:dht:{}",
        zbase32::encode(&root.verifying_key().to_bytes())
    );
    let device = SigningKey::from_bytes(&[seed.wrapping_add(1); 32]);
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

    fn session(&self, ts: i64) -> SessionRequest {
        SessionRequest {
            username: "alice".into(),
            domain: "a.test".into(),
            did: self.did.clone(),
            device_pub_key: self.device_id.clone(),
            ts,
            sig: b64(&self
                .device
                .sign(
                    devicebind::session_login_statement(&self.did, &self.device_id, RELAY_HOST, ts)
                        .as_bytes(),
                )
                .to_bytes()),
        }
    }

    /// The Go oracle's session statement — `session:<did>:<devicePubKey>:<ts>`,
    /// with no host segment. This port's own statement grew one (2026-08-16,
    /// closing a cross-relay replay gap `bind:` already closed); the oracle
    /// was never updated to match, so a request that logs into the oracle
    /// successfully has to be signed the OLD way. Kept as its own method
    /// rather than a flag on `session` so every call site says outright which
    /// statement shape it means.
    fn legacy_session(&self, ts: i64) -> SessionRequest {
        SessionRequest {
            username: "alice".into(),
            domain: "a.test".into(),
            did: self.did.clone(),
            device_pub_key: self.device_id.clone(),
            ts,
            sig: b64(&self
                .device
                .sign(format!("session:{}:{}:{ts}", self.did, self.device_id).as_bytes())
                .to_bytes()),
        }
    }
}

fn vouch_body(r: &VouchRequest) -> String {
    serde_json::json!({
        "username": r.username, "domain": r.domain, "did": r.did,
        "device_pub_key": r.device_pub_key, "label": r.label,
        "bind_ts": r.bind_ts, "sig": r.sig,
    })
    .to_string()
}

fn session_body(r: &SessionRequest) -> String {
    serde_json::json!({
        "username": r.username, "domain": r.domain, "did": r.did,
        "device_pub_key": r.device_pub_key, "ts": r.ts, "sig": r.sig,
    })
    .to_string()
}

/// `alice@a.test` exists as a legacy account: a hash and no device. That is the
/// starting point for vouching a first device.
fn seed(root: &std::path::Path) {
    let acct = root.join("data/a.test/alice");
    std::fs::create_dir_all(&acct).unwrap();
    std::fs::write(
        acct.join("auth_token_hash"),
        jmapserver::hash_auth_token(b"devices-interop-token-0000000000"),
    )
    .unwrap();
}

fn oracle() -> Option<Oracle> {
    Oracle::start_with("DEVICES_ENDPOINT_INTEROP", config_json, seed)
}

// ── vouching ──────────────────────────────────────────────────────────────

/// A genuine did:dht vouch is accepted with no anchor and no credential, and
/// the device it registers can then log in. That whole sequence is the cold
/// recovery path.
/// The oracle accepts it; this port refuses, because the anchor it would have
/// to ask is not configured. Asserted as a difference rather than dropped —
/// SPEC.md §11.27.
#[test]
fn the_oracle_accepts_a_did_dht_vouch_where_this_port_needs_an_anchor() {
    let Some(o) = oracle() else { return };
    let s = setup(9);
    let ts = now();

    let (status, b) = o.post_json("/account/devices", &vouch_body(&s.vouch("Laptop", ts)));
    assert_eq!(status, 204, "the vouch should be accepted: {b:?}");
    assert_eq!(
        check_vouch(
            &serde_json::from_str(&config_json(1, 1)).unwrap(),
            &s.vouch("Laptop", ts),
            ts
        ),
        Err(jmapsmtp::devices::DeviceError::AnchorRequired),
        "the oracle verified it from the identifier; this port has no did:dht \
         path and no anchor, and says so rather than accepting it unchecked"
    );

    // The device is on disk under its own pubkey.
    let acct = o.data_dir().join("a.test/alice");
    let keys = jmapserver::devicekeys::list_device_keys(&acct);
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].id, s.device_id);
    assert_eq!(keys[0].label, "Laptop");

    // …and it logs in.
    let (status, body) = o.post_json("/account/session", &session_body(&s.legacy_session(now())));
    assert_eq!(status, 200, "{body}");
    let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(parsed["email"], "alice@a.test");
    assert_eq!(
        parsed["expires_in"],
        jmapsmtp::devices::SESSION_TOKEN_TTL_SECS,
        "the TTL is part of the response contract"
    );
    assert!(parsed["token"].as_str().is_some_and(|t| !t.is_empty()));

    // The token works against JMAP straight away. These two paths have to
    // accept the same credential — being out of step once locked
    // session-logged-in accounts out of JMAP entirely (auth_env.go's header).
    let token = parsed["token"].as_str().unwrap();
    let auth = base64::engine::general_purpose::STANDARD.encode(format!("alice@a.test:{token}"));
    let (status, b) = o.post_json_auth(
        "/jmap/api/",
        r#"{"using":["urn:ietf:params:jmap:core"],"methodCalls":[]}"#,
        &auth,
    );
    assert_eq!(
        status, 200,
        "the session token should authenticate JMAP: {b}"
    );
}

/// Every vouch refusal, compared. The signature cases matter most: each is a
/// genuine ed25519 signature over the *wrong* statement, so a port that
/// verified sloppily would accept them.
#[test]
fn this_port_refuses_the_vouches_the_oracle_refuses() {
    let Some(o) = oracle() else { return };
    let cfg: jmapsmtp::config::Config = serde_json::from_str(&config_json(1, 1)).unwrap();
    let s = setup(21);
    let ts = now();

    let impostor = SigningKey::from_bytes(&[123u8; 32]);
    let cases: Vec<(&str, VouchRequest, u16)> =
        vec![
        (
            "a signature from a key that is not the DID",
            VouchRequest {
                sig: b64(&impostor
                    .sign(
                        devicebind::vouch_statement(&s.did, &s.device_id, "Laptop", ts).as_bytes(),
                    )
                    .to_bytes()),
                ..s.vouch("Laptop", ts)
            },
            DeviceError::VouchRejected.status(),
        ),
        (
            "a vouch signed for a different label",
            VouchRequest {
                label: "Attacker's box".into(),
                ..s.vouch("Laptop", ts)
            },
            DeviceError::VouchRejected.status(),
        ),
        (
            "a vouch signed for a different device",
            VouchRequest {
                device_pub_key: b64url(&[3u8; 32]),
                ..s.vouch("Laptop", ts)
            },
            DeviceError::VouchRejected.status(),
        ),
        ("a stale timestamp", s.vouch("Laptop", ts - 10_000), DeviceError::VouchRejected.status()),
        (
            "a timestamp from the future",
            s.vouch("Laptop", ts + 10_000),
            DeviceError::VouchRejected.status(),
        ),
        (
            "a did:webvh with no anchor to resolve it",
            VouchRequest {
                did: "did:webvh:QmSCID111111111111111111111111111111111111111:biset.md:dids:alice"
                    .into(),
                ..s.vouch("Laptop", ts)
            },
            DeviceError::AnchorRequired.status(),
        ),
    ];

    // The oracle still judges a did:dht vouch — the identifier is the key —
    // and answers 401 for a bad one. This port has no such path and no anchor,
    // so it answers 503: "cannot judge", not "you are wrong". Both are
    // refusals and neither registers a device; the *reason* is what diverges.
    // SPEC.md §11.27.
    let mut deferred = 0;
    for (name, req, expected) in &cases {
        let (status, body) = o.post_json("/account/devices", &vouch_body(req));
        assert_eq!(
            status, *expected,
            "{name}: the oracle said {status} {body:?}"
        );
        let ours = check_vouch(&cfg, req, ts).unwrap_err().status();
        if req.did.starts_with("did:dht:") {
            assert_eq!(
                ours,
                DeviceError::AnchorRequired.status(),
                "{name}: this port must defer to the anchor, not invent a verdict"
            );
            deferred += 1;
            continue;
        }
        assert_eq!(ours, *expected, "{name}: this port disagreed");
    }
    assert!(
        deferred > 0,
        "no did:dht case ran, so the divergence this asserts was never observed"
    );

    // Nothing got registered by any of them.
    assert!(
        jmapserver::devicekeys::list_device_keys(&o.data_dir().join("a.test/alice")).is_empty(),
        "a refused vouch must not leave a device behind"
    );
}

/// A did:webvh vouch is **503, not 401**: the vouch may be valid, and this
/// relay simply cannot judge it. Answering 401 would tell the client its
/// signature was wrong.
#[test]
fn a_webvh_vouch_is_a_server_condition_not_a_rejection() {
    let Some(o) = oracle() else { return };
    let s = setup(31);
    let req = VouchRequest {
        did: "did:webvh:QmSCID111111111111111111111111111111111111111:biset.md:dids:alice".into(),
        ..s.vouch("Laptop", now())
    };
    let (status, body) = o.post_json("/account/devices", &vouch_body(&req));
    assert_eq!(status, 503, "{body:?}");
    assert!(
        body.contains("identity anchor"),
        "the message should name the anchor: {body:?}"
    );
    // The wording diverges: the oracle says "non-did:dht per-device credentials
    // require one", which describes a distinction this port no longer makes —
    // every method needs the anchor here. Asserted as different so the day one
    // of them changes, somebody is told. SPEC.md §11.27.
    assert!(
        body.trim().contains("identity anchor"),
        "both name the anchor: {body:?}"
    );
    assert_ne!(
        DeviceError::AnchorRequired.message(),
        body.trim(),
        "if these ever match again, the divergence was lost — check which side moved"
    );
    assert!(
        !DeviceError::AnchorRequired.message().contains("did:dht"),
        "this port must not mention a method it does not implement"
    );
}

// ── login refusals give nothing away ──────────────────────────────────────

/// The endpoint takes no credential, so anyone can ask it about any username.
/// Every failure must therefore look identical — otherwise it is a directory of
/// which accounts and devices exist.
#[test]
fn every_login_refusal_is_indistinguishable_on_both_implementations() {
    let Some(o) = oracle() else { return };
    let s = setup(41);
    let ts = now();

    // Register one device so "wrong signature for a real device" is reachable.
    let (status, _) = o.post_json("/account/devices", &vouch_body(&s.vouch("Laptop", ts)));
    assert_eq!(status, 204);

    let other = SigningKey::from_bytes(&[99u8; 32]);
    let other_id = b64url(&other.verifying_key().to_bytes());
    let cases: Vec<(&str, SessionRequest)> = vec![
        (
            "an account that does not exist",
            SessionRequest {
                username: "nobody".into(),
                ..s.legacy_session(ts)
            },
        ),
        (
            "a device that was never vouched",
            SessionRequest {
                device_pub_key: other_id.clone(),
                sig: b64(&other
                    .sign(format!("session:{}:{other_id}:{ts}", s.did).as_bytes())
                    .to_bytes()),
                ..s.legacy_session(ts)
            },
        ),
        (
            "a signature by the wrong key",
            SessionRequest {
                sig: b64(&other
                    .sign(format!("session:{}:{}:{ts}", s.did, s.device_id).as_bytes())
                    .to_bytes()),
                ..s.legacy_session(ts)
            },
        ),
        ("a stale timestamp", s.legacy_session(ts - 10_000)),
        ("a timestamp from the future", s.legacy_session(ts + 10_000)),
    ];

    let mut answers = std::collections::BTreeSet::new();
    for (name, req) in &cases {
        let (status, body) = o.post_json("/account/session", &session_body(req));
        assert_eq!(status, 401, "{name}: {body:?}");
        answers.insert(body.trim().to_string());
    }
    assert_eq!(
        answers.len(),
        1,
        "the oracle distinguishes these, which is a username oracle: {answers:?}"
    );
    assert_eq!(
        answers.into_iter().next().unwrap(),
        DeviceError::SessionRejected.message(),
        "this port sends the same one message"
    );
}

/// A revoked device stops working immediately, not at token expiry.
#[test]
fn revoking_a_device_is_immediate_on_both_implementations() {
    let Some(o) = oracle() else { return };
    let s = setup(51);
    let ts = now();

    o.post_json("/account/devices", &vouch_body(&s.vouch("Laptop", ts)));
    let (status, body) = o.post_json("/account/session", &session_body(&s.legacy_session(ts)));
    assert_eq!(status, 200, "{body}");
    let token = serde_json::from_str::<serde_json::Value>(&body).unwrap()["token"]
        .as_str()
        .unwrap()
        .to_string();

    // Revoke through the API, authenticated with the session token itself.
    let acct = o.data_dir().join("a.test/alice");
    jmapserver::devicekeys::remove_device_key(&acct, &s.device_id).unwrap();

    // The device cannot log in again…
    let (status, _) = o.post_json("/account/session", &session_body(&s.legacy_session(now())));
    assert_eq!(status, 401);

    // …and the token it already held is gone, not merely unrenewable.
    assert!(
        jmapserver::devicekeys::check_session_token(&acct, &token, now()).is_none(),
        "a revocation that leaves live tokens working is not a revocation"
    );
}

/// This port's session statement is host-bound (devicebind.rs's own note,
/// 2026-08-16); the oracle's is not, and was never updated to match. Asserted
/// as a difference rather than silently worked around everywhere else in
/// this file (which all sign the oracle's OLD statement via
/// `Setup::legacy_session` for exactly this reason) — SPEC.md needs a line
/// for it, same as every other declared divergence here.
#[test]
fn the_oracles_session_statement_has_no_host_and_this_port_now_diverges_on_purpose() {
    let Some(o) = oracle() else { return };
    let s = setup(61);
    let ts = now();

    o.post_json("/account/devices", &vouch_body(&s.vouch("Laptop", ts)));

    // The oracle accepts its own (host-less) statement…
    let (status, body) = o.post_json("/account/session", &session_body(&s.legacy_session(ts)));
    assert_eq!(status, 200, "{body}");

    // …and rejects this port's CURRENT statement (RELAY_HOST-bound) outright,
    // even though it's a genuine signature by the same device key over the
    // same did/ts. If the oracle ever starts accepting this, the two
    // implementations have re-converged and `legacy_session` can be retired.
    let (status, body) = o.post_json("/account/session", &session_body(&s.session(ts)));
    assert_eq!(
        status, 401,
        "the oracle unexpectedly accepted a host-bound statement: {body}"
    );
}
