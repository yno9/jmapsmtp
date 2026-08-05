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

    /// The process-wide client. Built on first use and never dropped —
    /// dropping one inside an async context panics, because it owns a
    /// background runtime.
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

/// Run a blocking HTTP call on a thread with **no tokio runtime attached**.
///
/// `reqwest::blocking` cannot be called from inside a runtime: both building a
/// client and sending a request go through `wait::enter`, which drops a
/// `Runtime` to probe for an async context, and that drop panics when blocking
/// is not permitted where it happens. Every caller here is a synchronous
/// decision handler running inside axum, so every call would be.
///
/// Whether it actually panics turns out to depend on the runtime **flavour** —
/// a multi-thread runtime permits the drop and a current-thread one does not.
/// The deployed relay is `#[tokio::main]`, i.e. multi-thread, and really does
/// reach a live anchor and answer correctly; this was found by an interop test
/// that built a current-thread runtime instead. That is not a difference worth
/// depending on: it makes "does the relay panic" a property of how the caller
/// built its runtime.
///
/// A thread per anchor call is affordable because anchor calls are rare — a
/// provision, a device vouch, a DID bind — and each already blocks the caller
/// for up to [`jmapserver::anchor::TIMEOUT`] either way. `scope` keeps the
/// borrow of the arguments rather than forcing every caller to hand over owned
/// copies.
fn off_runtime<T: Send>(f: impl FnOnce() -> T + Send) -> T {
    std::thread::scope(|s| s.spawn(f).join().expect("the HTTP call panicked"))
}

impl Transport for HttpTransport {
    fn send(
        &self,
        method: &str,
        url: &str,
        token: &str,
        body: Option<&[u8]>,
    ) -> Option<(u16, String)> {
        off_runtime(|| self.send_blocking(method, url, token, body))
    }

    fn forward(
        &self,
        method: &str,
        url: &str,
        token: &str,
        body: Option<&[u8]>,
    ) -> Option<jmapserver::anchor::Relayed> {
        off_runtime(|| self.forward_blocking(method, url, token, body))
    }
}

impl HttpTransport {
    /// The Pkarr gateway's own client, with its own timeout.
    ///
    /// **40 seconds, against [`jmapserver::anchor::TIMEOUT`]'s 5.** The other
    /// calls are decisions a user is waiting on, where slow and down are the
    /// same thing. This one is a DHT traversal at the far end, generous next
    /// to the anchor's own 30s: a traversal still going is worth waiting for,
    /// and the client already treats a failure as "try the next gateway".
    fn gateway_client() -> &'static reqwest::blocking::Client {
        static CLIENT: std::sync::OnceLock<reqwest::blocking::Client> = std::sync::OnceLock::new();
        CLIENT.get_or_init(|| {
            reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(40))
                .build()
                .unwrap_or_default()
        })
    }

    fn forward_blocking(
        &self,
        method: &str,
        url: &str,
        token: &str,
        body: Option<&[u8]>,
    ) -> Option<jmapserver::anchor::Relayed> {
        let method = reqwest::Method::from_bytes(method.as_bytes()).ok()?;
        let mut request = Self::gateway_client()
            .request(method, url)
            // Set unconditionally, as Go does — including on GET, where there
            // is no body to describe.
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
            // The anchor's /pkarr is for its own relays, not the world. This
            // route is the public face; forwarding without the token would
            // leave the anchor a gateway anyone could spend.
            .header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"));
        if let Some(body) = body {
            request = request.body(body.to_vec());
        }
        let response = request.send().ok()?;
        let status = response.status().as_u16();
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let body = response.bytes().ok()?.to_vec();
        Some(jmapserver::anchor::Relayed {
            status,
            content_type,
            body,
        })
    }

    fn send_blocking(
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
