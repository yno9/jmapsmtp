//! Single-use nonces for `POST /account/session`.
//!
//! # Why this exists
//!
//! The session login statement (`devicebind.rs::session_login_statement`) got
//! a `relayHost` segment (SPEC.md §11.28) to stop a signature captured on one
//! relay being replayed against a DIFFERENT relay this device is also
//! registered with. That closed the cross-relay case, but not the same-relay
//! one: inside the freshness window (`devicebind::FRESHNESS_WINDOW`, 300s), a
//! genuine login request captured by an on-path observer still verifies if
//! POSTed again to the SAME relay — `ts` alone proves the signature isn't
//! stale, not that it hasn't already been used.
//!
//! A server-issued, single-use nonce closes that: the client can't produce a
//! valid signature without first asking this relay for one, and this relay
//! refuses to accept the same nonce twice. A captured-and-replayed request
//! now fails not because time ran out, but because the nonce it carries was
//! already consumed by the original request.
//!
//! # Deliberately NOT bound to an account
//!
//! `POST /account/session/challenge` takes no body and no credential — same
//! posture as `POST /account/session` itself (devices.rs's own file header:
//! neither endpoint sits behind `authenticate()`, because a cold recovery has
//! no existing credential to present). A nonce that named a specific
//! did/device up front would need the same "no credential" issuance path
//! anyway, so binding it to an account buys no extra protection — the
//! signature itself still names the did/device/host, and a nonce meant for
//! one login attempt stolen by an attacker is merely a nonce spent on
//! nothing (it does not by itself authorise anything without a valid
//! signature to go with it).
//!
//! # Not persisted
//!
//! A nonce's entire useful lifetime is `NONCE_TTL_SECS` (60s) — far shorter
//! than a restart's worth of downtime matters for. Losing the in-memory set
//! on restart just means every nonce issued in the last minute needs
//! reissuing, which is a normal retry, not a security or correctness gap.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use parking_lot::Mutex;
use rand::TryRngCore as _;

/// How long an issued nonce stays redeemable. Short — a client is expected to
/// sign and POST within seconds of asking, not to bank nonces for later.
pub const NONCE_TTL_SECS: i64 = 60;

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// The set of currently-valid, not-yet-consumed nonces. One instance lives on
/// `RelayState`, shared across every request this process serves.
#[derive(Default)]
pub struct SessionNonceStore {
    // nonce -> expires_at (unix seconds)
    live: Mutex<HashMap<String, i64>>,
}

impl SessionNonceStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Mint a fresh nonce and remember it as redeemable until
    /// `now + NONCE_TTL_SECS`. Also sweeps anything already expired, so this
    /// map never grows unbounded from clients that ask for a challenge and
    /// never redeem it.
    pub fn issue(&self) -> String {
        let now = now_unix();
        let mut live = self.live.lock();
        live.retain(|_, exp| *exp > now);

        let mut raw = [0u8; 18]; // 24 base64url chars, no padding
        // OS RNG failure here would mean the whole process's other RNG uses
        // are already in trouble; falling back silently would be worse than
        // panicking on a condition this rare.
        rand::rngs::OsRng
            .try_fill_bytes(&mut raw)
            .expect("OS RNG unavailable");
        let nonce =
            base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, raw);

        live.insert(nonce.clone(), now + NONCE_TTL_SECS);
        nonce
    }

    /// Redeem a nonce: true only if it was issued, not yet consumed, and not
    /// expired — and consumes it either way a matching entry is found, so a
    /// second attempt with the same nonce (a replay, or a client that
    /// mistakenly retries) always fails from here on.
    #[must_use]
    pub fn consume(&self, nonce: &str) -> bool {
        let now = now_unix();
        let mut live = self.live.lock();
        match live.remove(nonce) {
            Some(exp) => exp > now,
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_freshly_issued_nonce_redeems_once_and_never_again() {
        let store = SessionNonceStore::new();
        let nonce = store.issue();
        assert!(store.consume(&nonce), "a fresh nonce should redeem");
        assert!(
            !store.consume(&nonce),
            "the SAME nonce must never redeem twice — this is the whole point"
        );
    }

    #[test]
    fn an_unissued_nonce_never_redeems() {
        let store = SessionNonceStore::new();
        assert!(!store.consume("never-issued"));
    }

    #[test]
    fn two_issued_nonces_are_different_and_independently_redeemable() {
        let store = SessionNonceStore::new();
        let a = store.issue();
        let b = store.issue();
        assert_ne!(a, b);
        assert!(store.consume(&a));
        assert!(store.consume(&b), "consuming a must not affect b");
    }
}
