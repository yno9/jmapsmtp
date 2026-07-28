//! Go ↔ Rust device-credential interoperability.
//!
//! The disk format here is a hard compatibility requirement (SPEC.md §5.2):
//! a session token issued before a binary swap has to keep working after it,
//! and a device authorised by one build has to be revocable by the other.
//! Both directions are checked by having each implementation write the files
//! and the other read them.
//!
//! `DEVICES_INTEROP=required` — set by `just test` — turns a missing helper
//! into an error rather than a silent pass.

use std::path::PathBuf;
use std::process::{Command, Stdio};

use jmapserver::DeviceKey;
use jmapserver::devicekeys;
use jmapserver::diddht;
use pretty_assertions::assert_eq;
use serde::{Deserialize, Serialize};

#[derive(Default, Serialize)]
struct Op {
    op: &'static str,
    #[serde(skip_serializing_if = "String::is_empty")]
    id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    label: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    token: String,
    #[serde(skip_serializing_if = "is_zero")]
    ttl_sec: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    did: String,
    #[serde(skip_serializing_if = "is_zero")]
    ts: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    sig: String,
}

fn is_zero(n: &i64) -> bool {
    *n == 0
}

#[derive(Debug, Default, Deserialize)]
struct OpResult {
    #[serde(default)]
    devices: Vec<DeviceKey>,
    #[serde(default)]
    token: String,
    #[serde(default)]
    device_id: String,
    #[serde(default)]
    ok: bool,
    #[serde(default)]
    err: String,
}

fn helper() -> Option<PathBuf> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../oracle/store-interop")
        .canonicalize()
        .ok()?;
    p.exists().then_some(p)
}

fn require_helper() -> Option<PathBuf> {
    if let Some(p) = helper() {
        return Some(p);
    }
    assert!(
        std::env::var_os("DEVICES_INTEROP").is_none(),
        "DEVICES_INTEROP is set but the Go interop helper is missing — run \
         `just interop`. Refusing to report a pass for a test that ran nothing."
    );
    eprintln!(
        "SKIPPED: Go device interop helper not built — run `just interop`. Set \
         DEVICES_INTEROP=required to make this an error instead."
    );
    None
}

fn go(bin: &PathBuf, dir: &std::path::Path, script: &[Op]) -> Vec<OpResult> {
    use std::io::Write as _;
    let mut child = Command::new(bin)
        .args(["devices", dir.to_str().unwrap()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawning the Go helper");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(&serde_json::to_vec(script).unwrap())
        .unwrap();
    let out = child.wait_with_output().expect("waiting for the Go helper");
    assert!(
        out.status.success(),
        "go devices failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("parsing go output")
}

/// A fixed ed25519 device key, so the ids in these tests are stable.
fn device_keypair() -> (ed25519_dalek::SigningKey, String) {
    use base64::Engine as _;
    let signing = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let id =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signing.verifying_key().to_bytes());
    (signing, id)
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn sign(signing: &ed25519_dalek::SigningKey, msg: &str) -> String {
    use base64::Engine as _;
    use ed25519_dalek::Signer as _;
    base64::engine::general_purpose::STANDARD.encode(signing.sign(msg.as_bytes()).to_bytes())
}

/// **The migration direction.** Devices authorised by the Go build must be
/// visible, and its session tokens must still authenticate.
#[test]
fn rust_reads_what_go_wrote() {
    let Some(bin) = require_helper() else { return };
    let dir = tempfile::tempdir().unwrap();
    let (_, id) = device_keypair();

    let results = go(
        &bin,
        dir.path(),
        &[
            Op {
                op: "write",
                id: id.clone(),
                label: "MacBook".into(),
                ts: 1_700_000_000,
                ..Default::default()
            },
            Op {
                op: "issue",
                id: id.clone(),
                ttl_sec: 3600,
                ..Default::default()
            },
        ],
    );
    assert!(results[0].ok, "{}", results[0].err);
    let token = results[1].token.clone();
    assert!(!token.is_empty());

    let listed = devicekeys::list_device_keys(dir.path());
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id, id);
    assert_eq!(listed[0].label, "MacBook");
    assert_eq!(listed[0].created_at, 1_700_000_000);

    assert_eq!(
        devicekeys::check_session_token(dir.path(), &token, now()).as_deref(),
        Some(id.as_str()),
        "a Go-issued session token must still authenticate"
    );
}

/// **The rollback direction.** A device authorised while the Rust build ran,
/// and its tokens, must survive a revert.
#[test]
fn go_reads_what_rust_wrote() {
    let Some(bin) = require_helper() else { return };
    let dir = tempfile::tempdir().unwrap();
    let (_, id) = device_keypair();

    devicekeys::write_device_key(
        dir.path(),
        &DeviceKey {
            id: id.clone(),
            label: "Phone".into(),
            created_at: 1_700_000_001,
        },
    )
    .unwrap();
    let token = devicekeys::issue_session_token(dir.path(), &id, 3600, now()).unwrap();

    let results = go(
        &bin,
        dir.path(),
        &[
            Op {
                op: "list",
                ..Default::default()
            },
            Op {
                op: "check",
                token,
                ..Default::default()
            },
        ],
    );
    assert_eq!(results[0].devices.len(), 1);
    assert_eq!(results[0].devices[0].id, id);
    assert_eq!(results[0].devices[0].label, "Phone");
    assert_eq!(results[0].devices[0].created_at, 1_700_000_001);
    assert!(results[1].ok, "a Rust-issued token must authenticate in Go");
    assert_eq!(results[1].device_id, id);
}

/// Revoking must kill the device's outstanding sessions too, or a "revoked"
/// device keeps working until its token happens to expire.
#[test]
fn revocation_kills_sessions_across_both_implementations() {
    let Some(bin) = require_helper() else { return };

    // Rust revokes what Go authorised.
    let dir = tempfile::tempdir().unwrap();
    let (_, id) = device_keypair();
    let results = go(
        &bin,
        dir.path(),
        &[
            Op {
                op: "write",
                id: id.clone(),
                ..Default::default()
            },
            Op {
                op: "issue",
                id: id.clone(),
                ttl_sec: 3600,
                ..Default::default()
            },
        ],
    );
    let token = results[1].token.clone();
    devicekeys::remove_device_key(dir.path(), &id).unwrap();
    assert!(
        devicekeys::check_session_token(dir.path(), &token, now()).is_none(),
        "the session must be gone with the device"
    );
    let after = go(
        &bin,
        dir.path(),
        &[Op {
            op: "check",
            token,
            ..Default::default()
        }],
    );
    assert!(!after[0].ok, "and Go must agree the token is dead");

    // And the other way round.
    let dir = tempfile::tempdir().unwrap();
    devicekeys::write_device_key(
        dir.path(),
        &DeviceKey {
            id: id.clone(),
            label: String::new(),
            created_at: 0,
        },
    )
    .unwrap();
    let token = devicekeys::issue_session_token(dir.path(), &id, 3600, now()).unwrap();
    let results = go(
        &bin,
        dir.path(),
        &[
            Op {
                op: "remove",
                id: id.clone(),
                ..Default::default()
            },
            Op {
                op: "check",
                token: token.clone(),
                ..Default::default()
            },
        ],
    );
    assert!(results[0].ok, "{}", results[0].err);
    assert!(!results[1].ok);
    assert!(
        devicekeys::check_session_token(dir.path(), &token, now()).is_none(),
        "Rust must agree the token is dead"
    );
}

/// A device-signed login must be judged the same by both.
#[test]
fn session_logins_are_judged_identically() {
    let Some(bin) = require_helper() else { return };
    let dir = tempfile::tempdir().unwrap();
    let (signing, id) = device_keypair();
    let did = "did:dht:abc";
    let ts = now();

    devicekeys::write_device_key(
        dir.path(),
        &DeviceKey {
            id: id.clone(),
            label: String::new(),
            created_at: 0,
        },
    )
    .unwrap();

    let good = sign(&signing, &diddht::session_login_statement(did, &id, ts));
    // Signed over a different timestamp than the one presented.
    let wrong = sign(&signing, &diddht::session_login_statement(did, &id, ts - 1));

    for (name, sig, ts, expected) in [
        ("a valid login", good.clone(), ts, true),
        ("a signature over other data", wrong, ts, false),
        ("a stale timestamp", good.clone(), ts - 10_000, false),
        ("a timestamp far in the future", good, ts + 10_000, false),
    ] {
        let results = go(
            &bin,
            dir.path(),
            &[Op {
                op: "session_login",
                id: id.clone(),
                did: did.into(),
                ts,
                sig: sig.clone(),
                ..Default::default()
            }],
        );
        let rust = devicekeys::verify_device_session(dir.path(), did, &id, ts, &sig, now());
        assert_eq!(results[0].ok, expected, "{name}: Go disagreed");
        assert_eq!(rust, expected, "{name}: Rust disagreed");
    }
}

/// An unknown device cannot log in however validly it signs — the whole
/// security boundary.
#[test]
fn an_unauthorised_device_cannot_log_in() {
    let Some(bin) = require_helper() else { return };
    let dir = tempfile::tempdir().unwrap();
    let (signing, id) = device_keypair();
    let did = "did:dht:abc";
    let ts = now();
    let sig = sign(&signing, &diddht::session_login_statement(did, &id, ts));

    // Nothing was ever written for this device.
    let results = go(
        &bin,
        dir.path(),
        &[Op {
            op: "session_login",
            id: id.clone(),
            did: did.into(),
            ts,
            sig: sig.clone(),
            ..Default::default()
        }],
    );
    assert!(!results[0].ok);
    assert!(!devicekeys::verify_device_session(
        dir.path(),
        did,
        &id,
        ts,
        &sig,
        now()
    ));
}

/// The anchor-free did:dht vouch path, which is what lets a relay with no
/// identity anchor still authorise a device.
#[test]
fn did_dht_vouches_are_judged_identically() {
    let Some(bin) = require_helper() else { return };
    let dir = tempfile::tempdir().unwrap();

    // A did:dht identifier IS its key, so the identity signs for itself.
    let identity = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
    let did = format!(
        "did:dht:{}",
        diddht::zbase32_encode(&identity.verifying_key().to_bytes())
    );
    let (_, device_id) = device_keypair();
    let ts = now();
    let label = "Laptop";
    let sig = sign(
        &identity,
        &diddht::vouch_statement(&did, &device_id, label, ts),
    );

    for (name, did_used, expected) in [
        ("the identity's own signature", did.clone(), true),
        ("a different identity", "did:dht:yyyy".into(), false),
        (
            "not a did:dht at all",
            "did:webvh:example.com".into(),
            false,
        ),
    ] {
        let results = go(
            &bin,
            dir.path(),
            &[Op {
                op: "vouch_local",
                id: device_id.clone(),
                label: label.into(),
                did: did_used.clone(),
                ts,
                sig: sig.clone(),
                ..Default::default()
            }],
        );
        let rust =
            diddht::verify_did_dht_vouch_local(&did_used, &device_id, label, ts, &sig, now());
        assert_eq!(results[0].ok, expected, "{name}: Go disagreed");
        assert_eq!(rust, expected, "{name}: Rust disagreed");
    }
}
