//! `PUT /account/did` — binding a DID to an account that already exists.
//!
//! Port of `go-jmapsmtp/anchor_on.go`'s `registerDidUpdate`. This is the "lazy
//! migration on next login" path: an address provisioned before the relay knew
//! about DIDs registers one after the fact.
//!
//! # The target is never in the request
//!
//! Which account is being bound comes **only** from the Basic Auth credential.
//! Taking it from the body would let anyone with an account bind a DID to
//! somebody else's address. The request carries the DID and its proof, nothing
//! about who is asking.
//!
//! # Two different claims, two different checks
//!
//! Basic Auth proves the caller owns the **account**. It says nothing about
//! whether they own the **DID** they are naming. Without `did_sig` anyone with
//! a self-service account could have the anchor bind a stranger's DID to their
//! address — and publish a DNS record asserting it. So the signature is
//! required separately, and it is the anchor that judges it; this relay only
//! carries it.
//!
//! # Order is observable
//!
//! Each refusal below is reachable only when the ones before it passed, and a
//! client can tell them apart. Re-ordering the checks is a behavioural change
//! even though every individual answer stays the same — which is why
//! [`decide`] is one function with one order rather than checks scattered
//! through a handler.

use serde::Deserialize;

/// Go reads the body through `io.LimitReader(r.Body, 1<<12)`. A longer body is
/// **truncated, not rejected**, so it then fails to parse as JSON and comes
/// back as `did required` rather than a size error. Replicated exactly: the
/// distinction is visible to a client sending a large body.
pub const MAX_BODY: usize = 1 << 12;

#[derive(Debug, Deserialize, Default, PartialEq, Eq)]
pub struct BindRequest {
    #[serde(default)]
    pub did: String,
    #[serde(default)]
    pub bind_ts: i64,
    #[serde(default)]
    pub did_sig: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// Unparseable body, or no `did` in it.
    DidRequired,
    /// This relay has no anchor, so it cannot check a DID at all.
    ///
    /// **This used to answer 204** in an earlier Go version: it reported
    /// success for work it had not done and could not do. The caller treating
    /// the call as best-effort is not a licence to lie to it.
    NoAnchor,
    DidSigRequired,
    /// The anchor rejected the proof.
    BindingRejected,
    /// The anchor holds a different DID for this identity.
    Mismatch,
    AnchorUnavailable,
}

impl Refusal {
    pub fn status(&self) -> u16 {
        match self {
            Refusal::DidRequired | Refusal::NoAnchor | Refusal::DidSigRequired => 400,
            Refusal::BindingRejected => 401,
            Refusal::Mismatch => 409,
            Refusal::AnchorUnavailable => 503,
        }
    }

    pub fn message(&self) -> &'static str {
        match self {
            Refusal::DidRequired => "did required",
            Refusal::NoAnchor => "did not supported on this relay (no identity anchor)",
            Refusal::DidSigRequired => "did_sig required",
            Refusal::BindingRejected => "did binding rejected",
            Refusal::Mismatch => "did mismatch for this identity",
            Refusal::AnchorUnavailable => "identity anchor unavailable",
        }
    }
}

/// Everything decidable before the anchor is asked.
///
/// Note the order: the **anchor check comes before `did_sig`**. A relay with no
/// anchor answers `no identity anchor` even when the request is also missing
/// its signature, because the missing signature is not the caller's real
/// problem there — nothing they send would work.
pub fn decide(anchor_configured: bool, body: &[u8]) -> Result<BindRequest, Refusal> {
    let truncated = &body[..body.len().min(MAX_BODY)];
    let req: BindRequest = serde_json::from_slice(truncated).unwrap_or_default();
    if req.did.is_empty() {
        return Err(Refusal::DidRequired);
    }
    if !anchor_configured {
        return Err(Refusal::NoAnchor);
    }
    if req.did_sig.is_empty() {
        return Err(Refusal::DidSigRequired);
    }
    Ok(req)
}

/// The anchor's answer, translated into what the client is told.
///
/// `Invalid` becomes a bare 401: *why* a proof failed is not the client's
/// business, and [`jmapserver::anchor::claim`] has already logged the reason
/// where an operator can find it.
pub fn from_verdict(verdict: jmapserver::anchor::Verdict) -> Option<Refusal> {
    use jmapserver::anchor::Verdict;
    match verdict {
        Verdict::Ok => None,
        Verdict::Invalid => Some(Refusal::BindingRejected),
        Verdict::Conflict => Some(Refusal::Mismatch),
        Verdict::Error => Some(Refusal::AnchorUnavailable),
    }
}

#[cfg(test)]
mod tests;
