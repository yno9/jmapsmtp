//! The live transport for the identity anchor, and the relay's view of it.
//!
//! Compiled only into the anchor build. `cargo build --no-default-features`
//! is this port's `go build -tags noanchor`, and there the whole module is
//! absent — a relay with no anchor has no client for one, rather than a stub
//! that could be reached by mistake.

use std::sync::Arc;

use jmapserver::anchor::{Ref, Transport, Verdict};

/// A blocking HTTP transport.
///
/// Blocking rather than async because the callers are the synchronous decision
/// handlers, and because these calls are bounded by
/// [`jmapserver::anchor::TIMEOUT`] — a request a user is waiting on cannot be
/// allowed to hang regardless of which style it is written in.
pub struct HttpTransport;

impl HttpTransport {
    pub fn new() -> Arc<HttpTransport> {
        Arc::new(HttpTransport)
    }

    /// The process-wide client.
    ///
    /// Built on first use and never dropped. `reqwest::blocking` owns a
    /// background runtime, and dropping one inside an async context panics —
    /// which every relay constructed in an async test would otherwise do,
    /// whether or not it ever talked to an anchor.
    fn client() -> &'static reqwest::blocking::Client {
        static CLIENT: std::sync::OnceLock<reqwest::blocking::Client> = std::sync::OnceLock::new();
        CLIENT.get_or_init(|| {
            reqwest::blocking::Client::builder()
                .timeout(jmapserver::anchor::TIMEOUT)
                .build()
                .unwrap_or_default()
        })
    }
}

impl Transport for HttpTransport {
    fn send(
        &self,
        method: &str,
        url: &str,
        token: &str,
        body: Option<&[u8]>,
    ) -> Option<(u16, String)> {
        let method = reqwest::Method::from_bytes(method.as_bytes()).ok()?;
        let mut request = Self::client()
            .request(method, url)
            .header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"));
        if let Some(body) = body {
            request = request
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(body.to_vec());
        }
        let response = request.send().ok()?;
        let status = response.status().as_u16();
        // Bounded: the body is only ever a diagnostic reason, and an anchor
        // that answered with a stream would otherwise hold the request open.
        let reason = response
            .text()
            .map(|t| t.chars().take(512).collect())
            .unwrap_or_default();
        Some((status, reason))
    }
}

/// This relay's anchor, from its configuration.
pub fn anchor_ref(cfg: &crate::config::Config) -> Ref {
    Ref {
        url: cfg.anchor_url.clone(),
        token: cfg.anchor_token.clone(),
    }
}

/// Map an anchor verdict onto the refusal a provisioning request gets.
pub fn provision_refusal(verdict: Verdict) -> Option<crate::provision::Refusal> {
    match verdict {
        Verdict::Ok => None,
        Verdict::Conflict => Some(crate::provision::Refusal::IdentityOwnedByAnother),
        Verdict::Invalid => Some(crate::provision::Refusal::DidBindingRejected),
        // Never "proceed unanchored": an unbound name can be claimed by
        // somebody else later, and the collision surfaces as the original
        // owner losing their address.
        Verdict::Error => Some(crate::provision::Refusal::AnchorUnavailable),
    }
}

/// Map an anchor verdict onto the refusal a device vouch gets.
pub fn device_error(verdict: Verdict) -> Option<crate::devices::DeviceError> {
    match verdict {
        Verdict::Ok => None,
        Verdict::Invalid => Some(crate::devices::DeviceError::VouchRejected),
        // A conflict on a vouch means the claim registry disagrees, which is
        // the anchor rejecting it rather than being unreachable.
        Verdict::Conflict => Some(crate::devices::DeviceError::VouchRejected),
        Verdict::Error => Some(crate::devices::DeviceError::AnchorUnavailable),
    }
}

#[cfg(test)]
mod tests;
