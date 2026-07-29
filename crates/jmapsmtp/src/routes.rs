//! The relay's route table.
//!
//! One list, in the order `main()` registers it, so a reader can see the whole
//! HTTP surface without chasing eight `register*` functions. Building it is
//! what enforces the no-duplicates rule — [`crate::gomux::GoMux::handle`]
//! panics, exactly as `ServeMux` does.
//!
//! Which routes exist depends on three things, and all three are represented
//! here rather than resolved at the call site:
//!
//! - the build (`anchor` feature)
//! - the config (`domain_verify_secret`, VAPID keys)
//! - the handler (whether it serves blobs)

use crate::config::Config;
use crate::gomux::GoMux;

/// What a route is for. The handlers come later; this is the shape of the
/// surface and what guards each part of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Guard {
    /// No credential. Anyone on the internet reaches this.
    Open,
    /// HTTP Basic, resolved by [`crate::auth_env::authenticate`].
    Account,
    /// A bearer token from the environment (`ADMIN_TOKEN` / `METRICS_TOKEN`).
    ///
    /// **An empty token disables the route rather than opening it** — see
    /// `bearer_auth`. Getting that backwards publishes every account's
    /// metadata.
    Bearer,
    /// The route authenticates by its own means: a setup token, a signature,
    /// a provisioning secret. Named separately so `Open` keeps meaning
    /// "genuinely unauthenticated".
    SelfAuth,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteSpec {
    pub pattern: &'static str,
    pub guard: Guard,
}

const fn r(pattern: &'static str, guard: Guard) -> RouteSpec {
    RouteSpec { pattern, guard }
}

/// Everything mounted unconditionally by `jmapserver.NewMux` plus the relay's
/// own always-on routes.
///
/// Order follows `main()`: the JMAP core first, then the relay's, because that
/// is the order a duplicate would be discovered in.
const ALWAYS: &[RouteSpec] = &[
    // ── jmapserver.NewMux ──
    r("/.well-known/jmap", Guard::Account),
    r("/jmap/api/", Guard::Account),
    r("/jmap/eventsource/", Guard::Account),
    // The VAPID public key is deliberately unauthenticated: it is a public
    // key, and the service worker needs it before it has a credential.
    r("/jmap/push/vapid-public-key", Guard::Open),
    r("/jmap/push/subscribe", Guard::Account),
    r("/jmap/push/unsubscribe", Guard::Account),
    // ── wkd.go ──
    r("/.well-known/openpgpkey/policy", Guard::Open),
    r("/.well-known/openpgpkey/hu/", Guard::Open),
    r("/pgp/pubkey", Guard::Open),
    // The private key leaves only against the account's own credential; it is
    // the client-side-encrypted blob, but it is still the key.
    r("/pgp/privkey", Guard::Account),
    r("/pgp/peerkey", Guard::Account),
    // ── main.go / auth_env.go / provision.go ──
    r("/setup", Guard::SelfAuth),
    r("/auth/envelope", Guard::Account),
    r("/auth/signup", Guard::SelfAuth),
    r("/account/provision", Guard::SelfAuth),
    // ── devices.go ──
    // One pattern, dispatching on the method inside. Splitting it is the
    // production incident in gomux.rs's header.
    r("/account/session", Guard::SelfAuth),
    r("/account/devices", Guard::SelfAuth),
    // ── contacts.go / provision.go / storage.go ──
    r("/contacts", Guard::Account),
    r("/contacts/", Guard::Account),
    r("/account/delete", Guard::Account),
    r("/account/storage", Guard::Account),
    r("/account/storage/messages", Guard::Account),
    r("/account/storage/export", Guard::Account),
    r("/account/storage/purge-messages", Guard::Account),
    // ── main.go ──
    r("/relay-info", Guard::Open),
    // ── metrics.go / admin.go ──
    r("/metrics", Guard::Bearer),
    // The dashboard is the HTML shell only; every call it makes carries the
    // bearer token, so the page itself needs no guard.
    r("/admin/dashboard", Guard::Open),
    r("/admin/accounts", Guard::Bearer),
    r("/admin/accounts/", Guard::Bearer),
];

/// Mounted in the `anchor` build regardless of whether an anchor is
/// configured. Both refuse at request time when `anchor_url` is empty; the
/// routes themselves exist so the refusal is a message rather than a 404.
const ANCHOR: &[RouteSpec] = &[
    r("/account/did", Guard::Account),
    r("/admin/drain-anchor", Guard::Bearer),
];

/// The Pkarr/did:dht gateway, which needs an anchor to forward *to* —
/// `RegisterPkarrProxy` returns without registering when `anchor_url` is
/// empty. Unlike the two above, this one is genuinely absent on an anchorless
/// relay rather than present-and-refusing.
///
/// The relay no longer runs a DHT node itself; the route stays because clients
/// derive their gateway URL from their own relay and publish only there.
const PKARR: &[RouteSpec] = &[r("/pkarr/", Guard::Open)];

/// Mounted only when `domain_verify_secret` is set. With no secret there is
/// nothing to key an ownership token with, so the flow does not exist.
const CUSTOM_DOMAIN: &[RouteSpec] = &[
    r("/domain/verify-token", Guard::Account),
    r("/domain/add", Guard::Account),
];

/// Mounted only when the handler serves blobs.
///
/// This relay's handler does **not** — confirmed against the oracle, which
/// 404s `/jmap/upload/`. The group stays because it is the jmapserver
/// library's behaviour, not the relay's, and the library is used elsewhere.
const BLOBS: &[RouteSpec] = &[
    r("/jmap/upload/", Guard::Account),
    r("/jmap/download/", Guard::Account),
];

/// The routes this build, config and handler produce.
pub fn route_specs(cfg: &Config, supports_blobs: bool) -> Vec<RouteSpec> {
    let mut specs: Vec<RouteSpec> = ALWAYS.to_vec();
    if supports_blobs {
        // Registered inside NewMux, right after /jmap/api/.
        let at = specs
            .iter()
            .position(|s| s.pattern == "/jmap/eventsource/")
            .expect("the eventsource route is always present");
        specs.splice(at..at, BLOBS.iter().copied());
    }
    if cfg!(feature = "anchor") {
        specs.extend_from_slice(ANCHOR);
        if !cfg.anchor_url.is_empty() {
            specs.extend_from_slice(PKARR);
        }
    }
    if !cfg.domain_verify_secret.is_empty() {
        specs.extend_from_slice(CUSTOM_DOMAIN);
    }
    specs
}

/// Build the mux for this configuration.
///
/// # Panics
///
/// If any pattern is registered twice — which is the point. This runs at
/// startup, before the listener opens, so a conflict is a refusal to start
/// rather than a half-served relay.
pub fn build_mux(cfg: &Config, supports_blobs: bool) -> GoMux<RouteSpec> {
    let mut mux = GoMux::new();
    for spec in route_specs(cfg, supports_blobs) {
        mux.handle(spec.pattern, spec);
    }
    mux
}

#[cfg(test)]
mod tests;
