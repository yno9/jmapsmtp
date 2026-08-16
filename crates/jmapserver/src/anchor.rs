//! The identity anchor client. Port of `go-jmapserver/anchor/client.go`.
//!
//! # The relay forwards proofs; it does not check them
//!
//! A binding proof is a signature by a DID's root key. The relay hands it to
//! the anchor rather than verifying it, so the DID cryptography lives in **one
//! place** instead of in every relay — a relay that verified for itself would
//! have to be upgraded in lockstep with every DID method.
//!
//! The one exception is `did:dht`, which is self-certifying and verified
//! locally (see [`crate::devicebind`]). Everything else needs the anchor.
//!
//! # Every call is best-effort in one direction and fatal in the other
//!
//! An unreachable anchor must never block deleting an account — the user asked
//! to leave. It **must** block creating one, because an unbound name can be
//! claimed by somebody else later and the collision surfaces as the original
//! owner losing their address.

use std::time::Duration;

/// Where the anchor is, and the secret proving this relay may write to it.
///
/// The two always travel together: a URL without a token is a relay whose
/// writes are unauthenticated, which the config refuses to start with.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Ref {
    /// Empty means anchorless — this relay serves no DID identities.
    pub url: String,
    /// Shared with the anchor's `relay_token`.
    pub token: String,
}

impl Ref {
    pub fn is_configured(&self) -> bool {
        !self.url.is_empty()
    }

    /// The absolute URL for a path.
    pub fn endpoint(&self, path: &str) -> String {
        format!("{}{path}", self.url.trim_end_matches('/'))
    }
}

/// The verdict of an anchor call.
///
/// `Invalid` and `Error` are deliberately distinct: `Invalid` means the anchor
/// looked at the proof and rejected it, `Error` means it never looked. Merging
/// them would report "your DID proof was rejected" to a user whose relay is
/// simply being turned away.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Recorded, or already recorded the same way.
    Ok,
    /// The name is held by a different DID.
    Conflict,
    /// The anchor rejected the proof — bad signature, wrong host, or a stale
    /// timestamp.
    Invalid,
    /// Unreachable, refusing this relay, or an answer that made no sense.
    Error,
}

/// A client's root-key signature over `bind:<did>:<username>@<host>:<ts>`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BindingProof {
    /// Base64, standard alphabet.
    pub sig: String,
    /// Unix seconds. The anchor enforces the freshness window.
    pub ts: i64,
    /// **The host the client signed against, as this relay saw it on the
    /// transport — passed verbatim.**
    ///
    /// It is first-hand knowledge the anchor does not have, and it is what
    /// stops a signature captured on one relay being replayed against another.
    /// Normalising or substituting it removes that protection.
    pub host: String,
}

/// A root-key signature authorising one device.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeviceVouchProof {
    /// Base64url — **the device's own key**, not the DID's.
    pub device_pub_key: String,
    pub label: String,
    /// Base64, standard alphabet.
    pub sig: String,
    pub ts: i64,
}

/// One HTTP exchange with the anchor.
///
/// A trait so every verdict below is reachable from a test: the mapping from
/// status code to [`Verdict`] is the whole logic here, and it is not
/// observable through a real anchor without one to point at.
pub trait Transport: Send + Sync {
    /// `(status, body)`, or `None` when the request could not be made.
    fn send(
        &self,
        method: &str,
        url: &str,
        token: &str,
        body: Option<&[u8]>,
    ) -> Option<(u16, String)>;

    /// As [`Transport::send`], but keeping the response **bytes** and its
    /// `Content-Type`.
    ///
    /// A separate method rather than a wider `send`, because the two carry
    /// different things and conflating them would cost the callers that do not
    /// need it. [`claim`] and friends read a short diagnostic reason and are
    /// better served by a `String`; the Pkarr gateway forwards an opaque
    /// signed blob, and decoding that as UTF-8 would corrupt it silently —
    /// the bytes are a DHT record, not text.
    ///
    /// The default returns `None`, i.e. "gateway unreachable", so a transport
    /// written for the claim path cannot accidentally proxy anything.
    fn forward(
        &self,
        _method: &str,
        _url: &str,
        _token: &str,
        _body: Option<&[u8]>,
    ) -> Option<Relayed> {
        None
    }
}

/// A response passed through unchanged.
pub struct Relayed {
    pub status: u16,
    /// Copied through only when the far end set one, matching Go's
    /// `if ct := resp.Header.Get("Content-Type"); ct != ""`.
    pub content_type: Option<String>,
    pub body: Vec<u8>,
}

/// How long a call waits before giving up.
///
/// Short on purpose: these run inside a request a user is waiting on, and an
/// anchor that is slow is indistinguishable from one that is down.
pub const TIMEOUT: Duration = Duration::from_secs(5);

/// Ask the anchor to record which DID owns `localpart@domain`.
///
/// `domain` is the real address domain, distinct from the anchor's own host —
/// one anchor serves every domain a relay family provisions under.
pub fn claim(
    transport: &dyn Transport,
    anchor: &Ref,
    localpart: &str,
    domain: &str,
    did: &str,
    proof: &BindingProof,
) -> Verdict {
    if !anchor.is_configured() {
        return Verdict::Error;
    }
    let body = jmap_types::go_json::to_vec(&serde_json::json!({
        "domain": domain,
        "did": did,
        "did_sig": proof.sig,
        "bind_ts": proof.ts,
        "host": proof.host,
    }));
    let Ok(body) = body else {
        return Verdict::Error;
    };

    let url = anchor.endpoint(&format!("/_anchor/identity/{localpart}"));
    let Some((status, reason)) = transport.send("POST", &url, &anchor.token, Some(&body)) else {
        return Verdict::Error;
    };
    match status {
        200 | 201 => Verdict::Ok,
        409 => Verdict::Conflict,
        401 => {
            // The relay answers the client with a bare 401 — why a proof
            // failed is not the client's business — but the reason has to
            // survive somewhere, or the likeliest honest failure, a skewed
            // clock, becomes undiagnosable.
            eprintln!(
                "[anchor] rejected binding for {localpart}@{domain}: {}",
                reason.trim()
            );
            Verdict::Invalid
        }
        403 => {
            // This relay is the one being turned away, and the proof was never
            // looked at. Distinct from 401 precisely so it cannot reach a user
            // as "your DID proof was rejected".
            eprintln!(
                "[anchor] REFUSED THIS RELAY ({}) — check anchor_token against the anchor's relay_token",
                anchor.url
            );
            Verdict::Error
        }
        _ => Verdict::Error,
    }
}

/// Ask the anchor to verify a binding proof WITHOUT recording a claim —
/// the `authorized_did_domain` counterpart to [`claim`] (biset's ARC.md
/// §2a). A mail domain pinned 1:1 to one did-domain needs no registry to
/// enforce non-duplication: the did:webvh log store's own
/// append-only-per-(domain,username) shape already is that guarantee, and
/// the anchor's `/_anchor/verify-binding` route checks the DID's own webvh
/// path segment against `domain`/`username` directly instead of consulting
/// (or writing to) the claim registry.
///
/// Same verdict shape as [`claim`] minus `Conflict`: there is no registry
/// entry to conflict with, so that status never comes back from this route.
pub fn verify_binding(
    transport: &dyn Transport,
    anchor: &Ref,
    localpart: &str,
    domain: &str,
    did: &str,
    proof: &BindingProof,
) -> Verdict {
    if !anchor.is_configured() {
        return Verdict::Error;
    }
    let body = jmap_types::go_json::to_vec(&serde_json::json!({
        "domain": domain,
        "username": localpart,
        "did": did,
        "did_sig": proof.sig,
        "bind_ts": proof.ts,
        "host": proof.host,
    }));
    let Ok(body) = body else {
        return Verdict::Error;
    };

    let url = anchor.endpoint("/_anchor/verify-binding");
    let Some((status, reason)) = transport.send("POST", &url, &anchor.token, Some(&body)) else {
        return Verdict::Error;
    };
    match status {
        200 => Verdict::Ok,
        401 => {
            eprintln!(
                "[anchor] rejected binding for {localpart}@{domain}: {}",
                reason.trim()
            );
            Verdict::Invalid
        }
        403 => {
            eprintln!(
                "[anchor] REFUSED THIS RELAY ({}) — check anchor_token against the anchor's relay_token",
                anchor.url
            );
            Verdict::Error
        }
        _ => Verdict::Error,
    }
}

/// Ask whether `did`'s **current** root key authorises this device.
///
/// Stateless: nothing is recorded. The answer is cross-checked against the
/// same claim registry [`claim`] writes to — without that, a validly signed
/// vouch for a real DID could be presented against somebody else's mailbox,
/// which is why the username and domain travel with it.
pub fn vouch_device(
    transport: &dyn Transport,
    anchor: &Ref,
    username: &str,
    domain: &str,
    did: &str,
    proof: &DeviceVouchProof,
) -> Verdict {
    if !anchor.is_configured() {
        return Verdict::Error;
    }
    let body = jmap_types::go_json::to_vec(&serde_json::json!({
        "did": did,
        "device_pub_key": proof.device_pub_key,
        "label": proof.label,
        "bind_ts": proof.ts,
        "sig": proof.sig,
        "username": username,
        "domain": domain,
    }));
    let Ok(body) = body else {
        return Verdict::Error;
    };

    let url = anchor.endpoint("/_anchor/devices/vouch");
    let Some((status, reason)) = transport.send("POST", &url, &anchor.token, Some(&body)) else {
        return Verdict::Error;
    };
    match status {
        200 => Verdict::Ok,
        // 400 and 401 are both the anchor having looked and said no.
        400 | 401 => {
            eprintln!(
                "[anchor] device vouch rejected for {username}@{domain}: {}",
                reason.trim()
            );
            Verdict::Invalid
        }
        403 => {
            eprintln!(
                "[anchor] REFUSED THIS RELAY ({}) on device vouch for {username}@{domain} — check anchor_token",
                anchor.url
            );
            Verdict::Error
        }
        _ => Verdict::Error,
    }
}

/// Tell the anchor to forget a claim, reporting whether it confirmed.
///
/// Without this, a later registration of the same address — by anyone,
/// including its original owner under a new identity — is rejected as a false
/// "different key" conflict, because the deleted account's claim never goes
/// away.
///
/// Idempotent at the anchor: releasing an address that holds no claim is a
/// 2xx no-op, so a `true` means "clear at the anchor", not "there was a claim
/// and it was removed".
pub fn release_ok(transport: &dyn Transport, anchor: &Ref, localpart: &str, domain: &str) -> bool {
    if !anchor.is_configured() {
        return false;
    }
    let url = anchor.endpoint(&format!(
        "/_anchor/identity/{localpart}?domain={}",
        query_escape(domain)
    ));
    let Some((status, _)) = transport.send("DELETE", &url, &anchor.token, None) else {
        return false;
    };
    if status == 403 {
        eprintln!(
            "[anchor] REFUSED THIS RELAY ({}) on release of {localpart}@{domain} — check anchor_token",
            anchor.url
        );
        return false;
    }
    (200..300).contains(&status)
}

/// Release, discarding the outcome.
///
/// An unreachable anchor must never block deleting an account: the user asked
/// to leave, and the claim can be cleaned up later.
pub fn release(transport: &dyn Transport, anchor: &Ref, localpart: &str, domain: &str) {
    let _ = release_ok(transport, anchor, localpart, domain);
}

/// One name at the anchor.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Name {
    pub localpart: String,
    pub domain: String,
}

/// What an operator needs to know before turning a relay anchorless.
///
/// The split is the point. A name in `failed` **may still hold a claim**, and
/// a claim left behind blocks a legitimately different relay from ever taking
/// that name — so a partial drain is not a partial success, it is a reason to
/// stop. Both fields are always arrays, never null: Go initialises them, and a
/// client reading `.length` would break on the difference.
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct DrainReport {
    pub released: Vec<Name>,
    pub failed: Vec<Name>,
}

/// Withdraw the claim for every name given.
///
/// The bulk counterpart to [`release`], for the one reconciliation a relay can
/// drive on its own: going anchorless without stranding its names.
pub fn drain(transport: &dyn Transport, anchor: &Ref, names: &[Name]) -> DrainReport {
    let mut report = DrainReport::default();
    for name in names {
        if release_ok(transport, anchor, &name.localpart, &name.domain) {
            report.released.push(name.clone());
        } else {
            report.failed.push(name.clone());
        }
    }
    report
}

/// Percent-encode a query value, as `url.QueryEscape` does.
fn query_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests;
