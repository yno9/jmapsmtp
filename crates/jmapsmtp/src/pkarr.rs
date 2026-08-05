//! `/pkarr/` — the DHT gateway, which this relay does not run.
//!
//! Port of `go-jmapserver/anchor/pkarrproxy.go`. Every relay used to run its
//! own Mainline DHT node: its own UDP socket, its own routing table, its own
//! republish loop, all duplicated per relay and none of it the relay's job.
//! The anchor runs one now and this forwards to it.
//!
//! # Why the route stays even though the node is gone
//!
//! Because the **client's** route stays. biset derives its gateway URL from
//! the account's own relay (`serverUrl + "/pkarr"`, `src/did/publish.ts`), and
//! publishing goes to those relays only — the public fallbacks are for
//! resolving, never for publishing. Removing this would strand every
//! already-loaded client: nowhere to publish, no republishing from here, and
//! those identities fade off the DHT within hours.
//!
//! It also keeps the privacy story: the client asks its own relay, the relay
//! asks the anchor, and both belong to the same operator — which is the only
//! reason the anchor may see lookups at all. Resolving through a stranger's
//! relay leaks who-looks-up-whom.
//!
//! # Nothing here understands DIDs
//!
//! The key is an opaque path segment and the body an opaque blob. Validation,
//! signature checking and the DHT all live at the far end. That is why the
//! body travels as bytes: it is a signed DHT record, and decoding it as text
//! would corrupt it without any error to notice.

/// What to do with a request to this route, decided before any I/O.
#[derive(Debug, PartialEq, Eq)]
pub enum Action<'a> {
    /// A CORS preflight: 204 and nothing else.
    Preflight,
    /// Forward this key to the anchor.
    Forward {
        key: &'a str,
    },
    /// Go answers `http.NotFound` — not a 400. A key with a slash in it is
    /// simply not a key, and saying so any louder would describe the anchor's
    /// namespace to whoever asked.
    NotFound,
    MethodNotAllowed,
}

/// `GET` and `PUT` only: one to resolve, one to publish. Anything else is a
/// client bug, and a DELETE that silently did nothing would be worse.
pub fn decide<'a>(method: &str, path: &'a str) -> Action<'a> {
    if method == "OPTIONS" {
        return Action::Preflight;
    }
    let key = path.strip_prefix("/pkarr/").unwrap_or("");
    // Checked before the method, as Go does: a malformed key is not found
    // regardless of how it was asked for.
    if key.is_empty() || key.contains('/') {
        return Action::NotFound;
    }
    if method != "GET" && method != "PUT" {
        return Action::MethodNotAllowed;
    }
    Action::Forward { key }
}

/// The URL the request is forwarded to.
///
/// The anchor's base may or may not carry a trailing slash; Go trims it before
/// appending, and a `//pkarr/` would be a different path at the far end.
pub fn target(anchor_url: &str, key: &str) -> String {
    format!("{}/pkarr/{key}", anchor_url.trim_end_matches('/'))
}

#[cfg(test)]
mod tests;
