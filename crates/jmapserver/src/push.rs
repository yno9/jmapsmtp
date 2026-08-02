//! Web Push subscriptions. Port of the subscription half of
//! `go-jmapserver/push.go`.
//!
//! **Sending** is not here yet: this is the registry a browser subscribes into
//! and the key it subscribes with. Delivery needs RFC 8291 encryption and a
//! VAPID JWT, and is a milestone of its own.
//!
//! # The VAPID public key cannot be rotated
//!
//! It is baked into every subscription a client has ever made. Changing it
//! does not re-key them — it invalidates all of them silently, and each client
//! only finds out when a push fails to arrive.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use jmap_types::Id;

/// A browser Web Push subscription (RFC 8291), as `PushManager.subscribe()`
/// returns it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushSubscription {
    pub endpoint: String,
    #[serde(default, rename = "p256dh")]
    pub p256dh: String,
    #[serde(default)]
    pub auth: String,
}

/// The VAPID identity a relay pushes under.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Vapid {
    pub public: String,
    pub private: String,
    /// The JWT `sub` claim: a bare email address or an `https:` URL.
    pub subscriber: String,
}

impl Vapid {
    /// Build from configuration, stripping a leading `mailto:`.
    ///
    /// The web-push library prepends `mailto:` itself, so a caller-supplied
    /// prefix doubles into `mailto:mailto:…` — which Apple's push service
    /// rejects outright with 403. Stripping defensively means either form
    /// works, and the failure it prevents is one that only shows up against
    /// one vendor.
    pub fn new(public: &str, private: &str, subscriber: &str) -> Vapid {
        let subscriber = match subscriber.get(..7) {
            Some(prefix) if prefix.eq_ignore_ascii_case("mailto:") => &subscriber[7..],
            _ => subscriber,
        };
        Vapid {
            public: public.to_string(),
            private: private.to_string(),
            subscriber: subscriber.to_string(),
        }
    }
}

/// Subscriptions, by account.
///
/// Persisted so a restart does not silently stop notifying every client —
/// a browser does not re-subscribe unprompted, so an in-memory-only registry
/// loses them permanently.
#[derive(Debug, Default)]
pub struct PushRegistry {
    subs: BTreeMap<Id, Vec<PushSubscription>>,
    dir: Option<PathBuf>,
}

impl PushRegistry {
    pub fn path(dir: &Path) -> PathBuf {
        dir.join("push_subs.json")
    }

    /// Enable persistence and load whatever is already there.
    pub fn set_persist_dir(&mut self, dir: &Path) {
        self.dir = Some(dir.to_path_buf());
        if let Ok(bytes) = std::fs::read(Self::path(dir))
            && let Ok(subs) = serde_json::from_slice(&bytes)
        {
            self.subs = subs;
        }
    }

    /// Register one subscription.
    ///
    /// An endpoint already present is left alone rather than appended: a
    /// client re-subscribing on every page load would otherwise accumulate
    /// duplicates and be notified once per copy.
    pub fn add(&mut self, account: &Id, sub: PushSubscription) {
        let list = self.subs.entry(account.clone()).or_default();
        if list.iter().any(|s| s.endpoint == sub.endpoint) {
            return;
        }
        list.push(sub);
        self.save();
    }

    pub fn remove(&mut self, account: &Id, endpoint: &str) {
        if let Some(list) = self.subs.get_mut(account) {
            list.retain(|s| s.endpoint != endpoint);
            if list.is_empty() {
                self.subs.remove(account);
            }
        }
        self.save();
    }

    pub fn for_account(&self, account: &Id) -> Vec<PushSubscription> {
        self.subs.get(account).cloned().unwrap_or_default()
    }

    pub fn count(&self) -> usize {
        self.subs.values().map(Vec::len).sum()
    }

    fn save(&self) {
        let Some(dir) = &self.dir else { return };
        if let Ok(bytes) = jmap_types::go_json::to_vec(&self.subs) {
            let _ = std::fs::write(Self::path(dir), bytes);
        }
    }
}

/// The event a state change sends down an open event-source stream.
///
/// The payload names the changed capability and **carries no state value** —
/// a client is told that something changed, not what, and fetches. That is
/// what keeps the stream from being a second, weaker copy of the store.
pub const STATE_EVENT: &str =
    "event: state\ndata: {\"changed\":{\"urn:ietf:params:jmap:mail\":null}}\n\n";

/// The keep-alive an idle stream sends, as an SSE comment.
pub const PING_EVENT: &str = ": ping\n\n";

/// How often an idle stream pings.
pub const PING_INTERVAL_SECS: u64 = 30;

#[cfg(test)]
mod tests;
