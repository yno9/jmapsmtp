//! Per-account, per-device credentials. Port of `go-jmapserver/devicekeys.go`.
//!
//! Each device that uses the relay holds its **own** ed25519 signing key,
//! never derived from the identity's seed, so one device can be revoked
//! without touching another and a later root-key rotation cannot invalidate a
//! device already authorised.
//!
//! Two different checks live here and are deliberately kept apart:
//!
//! * Authorising a **new** device touches DID material and is the caller's
//!   job; this module only stores the result once something has said yes.
//! * Verifying an **ongoing** login touches none: it checks a device-signed
//!   statement against the public key already on record. That is what makes
//!   routine login immune to root-key rotation.
//!
//! One file per thing, no shared index to race on:
//!
//! ```text
//! <dir>/devices/<deviceID>.json     {"id":…,"label":…,"created_at":…}
//! <dir>/sessions/<tokenHash>.json   {"device_id":…,"expires_at":…}
//! ```

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::devicebind;

/// One device's authorised signing key.
///
/// `id` is the device's ed25519 public key, base64url-encoded — the key is its
/// own identifier, so there is no separate index to keep in step with the key
/// material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceKey {
    pub id: String,
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SessionRecord {
    device_id: String,
    expires_at: i64,
}

fn devices_dir(dir: &Path) -> PathBuf {
    dir.join("devices")
}

fn device_file(dir: &Path, id: &str) -> PathBuf {
    devices_dir(dir).join(format!("{id}.json"))
}

fn sessions_dir(dir: &Path) -> PathBuf {
    dir.join("sessions")
}

fn session_file(dir: &Path, hash: &str) -> PathBuf {
    sessions_dir(dir).join(format!("{hash}.json"))
}

/// Durably authorise a device.
///
/// Call only once something has confirmed a valid vouch: this function trusts
/// its caller completely, the same division of labour the provisioning
/// handler already has with the credential it writes.
pub fn write_device_key(dir: &Path, key: &DeviceKey) -> io::Result<()> {
    fs::create_dir_all(devices_dir(dir))?;
    let bytes = jmap_types::go_json::to_vec(key)
        .map_err(|e| io::Error::other(format!("encoding device key: {e}")))?;
    write_private(&device_file(dir, &key.id), &bytes)
}

/// Every device currently authorised, for a "manage devices" view.
///
/// **Always a list, never absent**, even when `devices/` does not exist —
/// which is the ordinary state for every account predating the feature. A
/// null here reaches the client as `null`, and `null.length` throws: found
/// live, blanking the Devices view through an uncaught exception the moment a
/// real account with no vouched device opened it.
pub fn list_device_keys(dir: &Path) -> Vec<DeviceKey> {
    let Ok(entries) = fs::read_dir(devices_dir(dir)) else {
        return Vec::new();
    };
    let mut out: Vec<DeviceKey> = entries
        .flatten()
        .filter(|e| e.path().extension().is_some_and(|x| x == "json"))
        .filter_map(|e| fs::read(e.path()).ok())
        .filter_map(|b| serde_json::from_slice(&b).ok())
        .collect();
    // Go's order is the directory's; sorting makes it reproducible without
    // changing what the list means.
    out.sort_by(|a, b| a.id.cmp(&b.id));
    out
}

pub fn has_device_key(dir: &Path, id: &str) -> bool {
    device_file(dir, id).exists()
}

/// Revoke a device **and every session token it holds**.
///
/// Dropping only the authorisation would leave a not-yet-expired session
/// working until it happened to lapse, which defeats the whole point of being
/// able to kick out one device.
pub fn remove_device_key(dir: &Path, id: &str) -> io::Result<()> {
    match fs::remove_file(device_file(dir, id)) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let Ok(entries) = fs::read_dir(sessions_dir(dir)) else {
        return Ok(()); // no sessions yet — nothing to revoke
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if let Ok(bytes) = fs::read(&path)
            && let Ok(rec) = serde_json::from_slice::<SessionRecord>(&bytes)
            && rec.device_id == id
        {
            let _ = fs::remove_file(&path);
        }
    }
    Ok(())
}

/// Verify a device-signed login against the key already on file.
///
/// No DID resolution and no anchor call, so nothing here can be disturbed by
/// a **later** identity-key rotation. The DID is only part of the signed
/// statement, binding the login to one identity; the authorisation decision is
/// purely "is this device on file for this account".
#[must_use]
pub fn verify_device_session(
    dir: &Path,
    did: &str,
    device_pub_key_b64url: &str,
    ts: i64,
    sig_b64: &str,
    now_unix: i64,
) -> bool {
    if !devicebind::is_fresh(ts, now_unix) {
        return false;
    }
    if !has_device_key(dir, device_pub_key_b64url) {
        return false;
    }
    let Some(key) = devicebind::decode_device_key(device_pub_key_b64url) else {
        return false;
    };
    let statement = devicebind::session_login_statement(did, device_pub_key_b64url, ts);
    devicebind::verify_signature(&key, statement.as_bytes(), sig_b64)
}

/// Mint a bearer token for a device that has just proved itself.
///
/// The token itself is never stored, only its hash — the same "no stored
/// secret" shape the static credential uses.
pub fn issue_session_token(
    dir: &Path,
    device_id: &str,
    ttl_secs: i64,
    now_unix: i64,
) -> io::Result<String> {
    use rand::TryRngCore as _;
    let mut raw = [0u8; 32];
    rand::rngs::OsRng
        .try_fill_bytes(&mut raw)
        .map_err(|_| io::Error::other("rng failure"))?;

    let rec = SessionRecord {
        device_id: device_id.to_string(),
        expires_at: now_unix + ttl_secs,
    };
    let bytes = jmap_types::go_json::to_vec(&rec)
        .map_err(|e| io::Error::other(format!("encoding session: {e}")))?;
    fs::create_dir_all(sessions_dir(dir))?;
    write_private(&session_file(dir, &session_token_hash(&raw)), &bytes)?;

    Ok(base64::engine::general_purpose::STANDARD.encode(raw))
}

/// Check a presented bearer token, returning the device it was issued to.
///
/// Expired and unknown both report `None`: the caller has no use for the
/// difference, and this doubles as revocation — a removed device's session
/// files are gone, so its tokens fail here at once rather than lingering until
/// they lapse.
pub fn check_session_token(dir: &Path, token_b64: &str, now_unix: i64) -> Option<String> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(token_b64)
        .ok()?;
    let bytes = fs::read(session_file(dir, &session_token_hash(&raw))).ok()?;
    let rec: SessionRecord = serde_json::from_slice(&bytes).ok()?;
    (now_unix <= rec.expires_at).then_some(rec.device_id)
}

/// `base64url_nopad(sha256(token))` — the session file's name.
fn session_token_hash(raw: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(raw))
}

fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write as _;
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    opts.open(path)?.write_all(bytes)
}

#[cfg(test)]
mod tests;
