//! `POST /account/session` and `/account/devices`. Port of
//! `go-jmapsmtp/devices.go`.
//!
//! This is the DID credential chain at runtime (SPEC.md §10-A):
//!
//! - **`POST /account/session`** is login. It carries **no Basic Auth** — a
//!   device signature over `session:<did>:<devicePubKey>:<ts>` is the whole
//!   credential, checked against the pubkey this account already recorded from
//!   a prior vouch. That replaces a static bearer with something that expires
//!   and can be revoked per device.
//!
//! - **`POST /account/devices`** vouches a *new* device, and is deliberately
//!   **not** behind `authenticate()` either. The vouch signature is the proof.
//!   That is exactly how a fully cold recovery works — mnemonic only, fresh
//!   install, no prior session at all — so requiring an existing credential
//!   would make the recovery path impossible.
//!
//! - **`GET`/`DELETE /account/devices`** *are* behind `authenticate()`: listing
//!   and revoking act on an account that already exists, so the caller has to
//!   already hold one of its credentials.
//!
//! All three share one route pattern and dispatch on the method inside.
//! Splitting them is the production incident in `gomux.rs`'s header.

use crate::config::Config;

/// How long an issued session token lasts.
///
/// Re-signed with the device key well before expiry on next use, so the
/// practical effect of the bound is on a *stolen* token, not a working one.
pub const SESSION_TOKEN_TTL_SECS: i64 = 30 * 24 * 60 * 60;

/// `POST /account/session`.
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct SessionRequest {
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub domain: String,
    #[serde(default)]
    pub did: String,
    #[serde(default, rename = "device_pub_key")]
    pub device_pub_key: String,
    #[serde(default)]
    pub ts: i64,
    #[serde(default)]
    pub sig: String,
}

/// `POST /account/devices`.
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct VouchRequest {
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub domain: String,
    #[serde(default)]
    pub did: String,
    #[serde(default, rename = "device_pub_key")]
    pub device_pub_key: String,
    #[serde(default)]
    pub label: String,
    #[serde(default, rename = "bind_ts")]
    pub bind_ts: i64,
    #[serde(default)]
    pub sig: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceError {
    /// A required field was absent.
    MissingFields,
    /// The account does not exist — by *either* credential shape.
    NoSuchAccount,
    SessionRejected,
    VouchRejected,
    /// The DID's method needs an anchor and there is none configured.
    AnchorRequired,
    AnchorUnavailable,
    /// `DELETE` with no `id`.
    IdRequired,
    Unauthorized,
}

impl DeviceError {
    pub fn status(&self) -> u16 {
        match self {
            DeviceError::MissingFields | DeviceError::IdRequired => 400,
            DeviceError::Unauthorized
            | DeviceError::SessionRejected
            | DeviceError::VouchRejected => 401,
            DeviceError::NoSuchAccount => 404,
            DeviceError::AnchorRequired | DeviceError::AnchorUnavailable => 503,
        }
    }

    pub fn message(&self) -> &'static str {
        match self {
            DeviceError::MissingFields => "username, domain, did, device_pub_key and sig required",
            DeviceError::NoSuchAccount => "no such account",
            DeviceError::SessionRejected => "session login rejected",
            DeviceError::VouchRejected => "device vouch rejected",
            DeviceError::AnchorRequired => {
                "this relay has no identity anchor configured — non-did:dht \
                 per-device credentials require one"
            }
            DeviceError::AnchorUnavailable => "identity anchor unavailable",
            DeviceError::IdRequired => "id required",
            DeviceError::Unauthorized => "unauthorized",
        }
    }
}

/// The trimmed, folded `<localpart>, <domain>` pair, or [`DeviceError::MissingFields`].
///
/// Both endpoints require the same five fields and reject with one message
/// naming all of them: a client that is missing one is usually missing several,
/// and enumerating them one round trip at a time is worse than saying what the
/// shape is.
fn account_of(
    username: &str,
    domain: &str,
    did: &str,
    device_pub_key: &str,
    sig: &str,
) -> Result<(String, String), DeviceError> {
    let username = username.trim().to_lowercase();
    let domain = domain.trim().to_lowercase();
    if username.is_empty()
        || domain.is_empty()
        || did.is_empty()
        || device_pub_key.is_empty()
        || sig.is_empty()
    {
        return Err(DeviceError::MissingFields);
    }
    Ok((username, domain))
}

impl SessionRequest {
    pub fn account(&self) -> Result<(String, String), DeviceError> {
        account_of(
            &self.username,
            &self.domain,
            &self.did,
            &self.device_pub_key,
            &self.sig,
        )
    }
}

impl VouchRequest {
    pub fn account(&self) -> Result<(String, String), DeviceError> {
        account_of(
            &self.username,
            &self.domain,
            &self.did,
            &self.device_pub_key,
            &self.sig,
        )
    }
}

/// What a successful login returns.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct SessionResponse {
    pub email: String,
    pub token: String,
    #[serde(rename = "expires_in")]
    pub expires_in: i64,
}

/// Log in: verify the device's signature, then issue a token.
///
/// No credential is consulted beyond the device pubkey already on file, which
/// is the point — the signature *is* the credential.
pub fn login(
    data_dir: &std::path::Path,
    req: &SessionRequest,
    now_unix: i64,
) -> Result<SessionResponse, DeviceError> {
    let (username, domain) = req.account()?;
    let acct_dir = crate::auth_env::account_dir(data_dir, &domain, &username);

    if !jmapserver::devicekeys::verify_device_session(
        &acct_dir,
        &req.did,
        &req.device_pub_key,
        req.ts,
        &req.sig,
        now_unix,
    ) {
        // One message for every failure — unknown account, unregistered
        // device, bad signature, stale timestamp. Distinguishing them would
        // tell an unauthenticated caller which usernames and devices exist.
        return Err(DeviceError::SessionRejected);
    }

    let token = jmapserver::devicekeys::issue_session_token(
        &acct_dir,
        &req.device_pub_key,
        SESSION_TOKEN_TTL_SECS,
        now_unix,
    )
    .map_err(|_| DeviceError::VouchRejected)?;

    Ok(SessionResponse {
        email: format!("{username}@{domain}"),
        token,
        expires_in: SESSION_TOKEN_TTL_SECS,
    })
}

/// Whether the account exists, accepting **either** credential shape.
///
/// A legacy account has an `auth_token_hash` and no device yet; an account from
/// the device-vouch provisioning flow has the reverse and never writes a hash
/// at all. Checking only the hash 404s every post-redesign account the moment
/// it tries to vouch a *second* device — which is how the Go comment records
/// this being found live.
pub fn account_exists(data_dir: &std::path::Path, domain: &str, localpart: &str) -> bool {
    let acct_dir = crate::auth_env::account_dir(data_dir, domain, localpart);
    !crate::auth_env::read_auth_hash(data_dir, domain, localpart).is_empty()
        || !jmapserver::devicekeys::list_device_keys(&acct_dir).is_empty()
}

/// How a vouch for this DID can be checked, and what to answer when it cannot.
///
/// Deliberately the same asymmetry as provisioning: `did:dht` verifies locally
/// because the identifier is the key, anything else needs the anchor. The
/// difference here is the *status* for "no anchor": 503, not 401. The vouch may
/// be perfectly valid — this relay simply cannot judge it, which is a condition
/// of the server, not of the request.
pub fn check_vouch(
    cfg: &Config,
    req: &VouchRequest,
    now_unix: i64,
) -> Result<crate::provision::VouchPath, DeviceError> {
    match crate::provision::vouch_path(cfg, &req.did) {
        crate::provision::VouchPath::Local => {
            if jmapserver::diddht::verify_did_dht_vouch_local(
                &req.did,
                &req.device_pub_key,
                &req.label,
                req.bind_ts,
                &req.sig,
                now_unix,
            ) {
                Ok(crate::provision::VouchPath::Local)
            } else {
                Err(DeviceError::VouchRejected)
            }
        }
        crate::provision::VouchPath::Anchor => Ok(crate::provision::VouchPath::Anchor),
        crate::provision::VouchPath::Impossible => Err(DeviceError::AnchorRequired),
    }
}

/// Record a verified device.
pub fn write_device(
    data_dir: &std::path::Path,
    domain: &str,
    localpart: &str,
    req: &VouchRequest,
    now_unix: i64,
) -> std::io::Result<()> {
    let acct_dir = crate::auth_env::account_dir(data_dir, domain, localpart);
    jmapserver::devicekeys::write_device_key(
        &acct_dir,
        &jmapserver::DeviceKey {
            id: req.device_pub_key.clone(),
            label: req.label.clone(),
            created_at: now_unix,
        },
    )
}

#[cfg(test)]
mod tests;
