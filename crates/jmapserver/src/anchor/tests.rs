//! The anchor client.
//!
//! The whole logic here is the mapping from an HTTP status to a verdict, and
//! two of those verdicts must not be confused: `Invalid` means the anchor
//! looked at the proof and said no, `Error` means it never looked. Merging them
//! reports "your DID proof was rejected" to a user whose *relay* is being
//! turned away.

use super::*;
use pretty_assertions::assert_eq;

/// One recorded request: method, url, token, body.
type Recorded = (String, String, String, Option<String>);

/// A transport that answers from a script and records what it was asked.
#[derive(Default)]
struct Fake {
    reply: Option<(u16, String)>,
    seen: std::sync::Mutex<Vec<Recorded>>,
}

impl Fake {
    fn answering(status: u16, body: &str) -> Fake {
        Fake {
            reply: Some((status, body.to_string())),
            seen: Default::default(),
        }
    }

    /// A transport that cannot make the request at all.
    fn unreachable() -> Fake {
        Fake::default()
    }

    fn last(&self) -> Recorded {
        self.seen
            .lock()
            .unwrap()
            .last()
            .cloned()
            .expect("a request")
    }
}

impl Transport for Fake {
    fn send(
        &self,
        method: &str,
        url: &str,
        token: &str,
        body: Option<&[u8]>,
    ) -> Option<(u16, String)> {
        self.seen.lock().unwrap().push((
            method.to_string(),
            url.to_string(),
            token.to_string(),
            body.map(|b| String::from_utf8_lossy(b).into_owned()),
        ));
        self.reply.clone()
    }
}

fn anchor() -> Ref {
    Ref {
        url: "https://anchor.test/".into(),
        token: "relay-secret".into(),
    }
}

fn proof() -> BindingProof {
    BindingProof {
        sig: "c2ln".into(),
        ts: 1_785_000_000,
        host: "mail.a.test:8443".into(),
    }
}

// ── the request ───────────────────────────────────────────────────────────

/// The token authenticates the **relay**, not the user. Without it the anchor
/// would accept writes from anyone who can reach it.
#[test]
fn every_call_carries_the_relay_token() {
    let fake = Fake::answering(200, "");
    claim(&fake, &anchor(), "alice", "a.test", "did:dht:x", &proof());
    assert_eq!(fake.last().2, "relay-secret");

    release_ok(&fake, &anchor(), "alice", "a.test");
    assert_eq!(fake.last().2, "relay-secret");
}

/// A trailing slash on the configured URL must not produce `//identity/…`.
#[test]
fn the_url_is_joined_without_doubling_the_slash() {
    for url in ["https://anchor.test", "https://anchor.test/"] {
        let anchor = Ref {
            url: url.into(),
            token: "t".into(),
        };
        let fake = Fake::answering(200, "");
        claim(&fake, &anchor, "alice", "a.test", "did:dht:x", &proof());
        assert_eq!(fake.last().1, "https://anchor.test/identity/alice", "{url}");
    }
}

/// The host travels verbatim: it is what the client signed against and what
/// stops a signature captured on one relay being replayed against another.
#[test]
fn the_signed_host_is_forwarded_exactly_as_observed() {
    let fake = Fake::answering(200, "");
    claim(&fake, &anchor(), "alice", "a.test", "did:dht:x", &proof());
    let body: serde_json::Value = serde_json::from_str(&fake.last().3.unwrap()).unwrap();
    assert_eq!(
        body["host"], "mail.a.test:8443",
        "including the port — normalising it removes the replay protection"
    );
    assert_eq!(body["did"], "did:dht:x");
    assert_eq!(body["bind_ts"], 1_785_000_000i64);
}

#[test]
fn a_release_names_the_domain_as_an_escaped_query_value() {
    let fake = Fake::answering(204, "");
    release_ok(&fake, &anchor(), "alice", "a b.test");
    let (method, url, _, body) = fake.last();
    assert_eq!(method, "DELETE");
    assert_eq!(url, "https://anchor.test/identity/alice?domain=a+b.test");
    assert_eq!(body, None, "a DELETE carries no body");
}

// ── claim verdicts ────────────────────────────────────────────────────────

#[test]
fn a_recorded_claim_is_ok() {
    for status in [200, 201] {
        let fake = Fake::answering(status, "");
        assert_eq!(
            claim(&fake, &anchor(), "alice", "a.test", "did:dht:x", &proof()),
            Verdict::Ok,
            "{status}"
        );
    }
}

#[test]
fn a_name_held_by_another_did_is_a_conflict() {
    let fake = Fake::answering(409, "held by a different key");
    assert_eq!(
        claim(&fake, &anchor(), "alice", "a.test", "did:dht:x", &proof()),
        Verdict::Conflict
    );
}

/// 401 is the anchor having looked and rejected the proof.
#[test]
fn a_rejected_proof_is_invalid() {
    let fake = Fake::answering(401, "timestamp outside the freshness window");
    assert_eq!(
        claim(&fake, &anchor(), "alice", "a.test", "did:dht:x", &proof()),
        Verdict::Invalid
    );
}

/// 403 is **this relay** being turned away, and the proof was never looked at.
/// Reporting it as `Invalid` would tell a user their DID proof failed when
/// nothing of theirs was examined.
#[test]
fn a_refused_relay_is_an_error_not_an_invalid_proof() {
    let fake = Fake::answering(403, "unknown relay");
    assert_eq!(
        claim(&fake, &anchor(), "alice", "a.test", "did:dht:x", &proof()),
        Verdict::Error,
        "not Invalid"
    );
}

#[test]
fn an_unreachable_anchor_is_an_error() {
    let fake = Fake::unreachable();
    assert_eq!(
        claim(&fake, &anchor(), "alice", "a.test", "did:dht:x", &proof()),
        Verdict::Error
    );
}

#[test]
fn an_unexpected_status_is_an_error_rather_than_a_guess() {
    for status in [204, 301, 418, 500, 503] {
        let fake = Fake::answering(status, "");
        assert_eq!(
            claim(&fake, &anchor(), "alice", "a.test", "did:dht:x", &proof()),
            Verdict::Error,
            "{status}"
        );
    }
}

/// An anchorless relay makes no call at all — there is nothing to call.
#[test]
fn an_anchorless_relay_never_reaches_the_transport() {
    let fake = Fake::answering(200, "");
    let none = Ref::default();
    assert_eq!(
        claim(&fake, &none, "alice", "a.test", "did:dht:x", &proof()),
        Verdict::Error
    );
    assert_eq!(
        vouch_device(
            &fake,
            &none,
            "alice",
            "a.test",
            "did:dht:x",
            &Default::default()
        ),
        Verdict::Error
    );
    assert!(!release_ok(&fake, &none, "alice", "a.test"));
    assert!(
        fake.seen.lock().unwrap().is_empty(),
        "nothing was sent anywhere"
    );
}

// ── vouch verdicts ────────────────────────────────────────────────────────

#[test]
fn a_device_vouch_carries_the_account_it_is_for() {
    let fake = Fake::answering(200, "");
    let vouch = DeviceVouchProof {
        device_pub_key: "DEVKEY".into(),
        label: "Laptop".into(),
        sig: "c2ln".into(),
        ts: 1_785_000_000,
    };
    assert_eq!(
        vouch_device(&fake, &anchor(), "alice", "a.test", "did:dht:x", &vouch),
        Verdict::Ok
    );
    let (_, url, _, body) = fake.last();
    assert_eq!(url, "https://anchor.test/devices/vouch");

    let body: serde_json::Value = serde_json::from_str(&body.unwrap()).unwrap();
    // Without these the anchor cannot cross-check the claim registry, and a
    // validly signed vouch could be presented against somebody else's mailbox.
    assert_eq!(body["username"], "alice");
    assert_eq!(body["domain"], "a.test");
    assert_eq!(body["device_pub_key"], "DEVKEY");
}

/// A vouch is rejected with either 400 or 401, and both mean the anchor
/// looked.
#[test]
fn a_rejected_vouch_is_invalid_on_either_status() {
    for status in [400, 401] {
        let fake = Fake::answering(status, "stale");
        assert_eq!(
            vouch_device(
                &fake,
                &anchor(),
                "alice",
                "a.test",
                "did:dht:x",
                &Default::default()
            ),
            Verdict::Invalid,
            "{status}"
        );
    }
}

#[test]
fn a_refused_relay_on_a_vouch_is_also_an_error() {
    let fake = Fake::answering(403, "");
    assert_eq!(
        vouch_device(
            &fake,
            &anchor(),
            "alice",
            "a.test",
            "did:dht:x",
            &Default::default()
        ),
        Verdict::Error
    );
}

// ── release ───────────────────────────────────────────────────────────────

/// Idempotent at the anchor: releasing an address that holds no claim is a
/// 2xx no-op, so a `true` means "clear at the anchor", not "there was a claim".
#[test]
fn any_success_status_confirms_the_release() {
    for status in [200, 202, 204, 299] {
        let fake = Fake::answering(status, "");
        assert!(release_ok(&fake, &anchor(), "alice", "a.test"), "{status}");
    }
    for status in [400, 403, 404, 500] {
        let fake = Fake::answering(status, "");
        assert!(!release_ok(&fake, &anchor(), "alice", "a.test"), "{status}");
    }
}

/// The outcome is discarded on purpose: an unreachable anchor must not block
/// deleting an account. The user asked to leave.
#[test]
fn release_does_not_report_failure() {
    let fake = Fake::unreachable();
    release(&fake, &anchor(), "alice", "a.test");
}

#[test]
fn the_timeout_is_short_because_a_user_is_waiting() {
    assert_eq!(TIMEOUT, std::time::Duration::from_secs(5));
}

// ── drain ─────────────────────────────────────────────────────────────────
//
// `POST /admin/drain-anchor` releases **every** name this relay holds. It is
// the most destructive thing the relay can be asked to do — after it, another
// relay can claim those addresses — and it had no test at all. What follows
// pins the properties an operator is relying on when they run it.

/// Answers per name, so a partial failure can be built.
struct PerName {
    fail: Vec<String>,
    seen: std::sync::Mutex<Vec<String>>,
}

impl Transport for PerName {
    fn send(
        &self,
        method: &str,
        url: &str,
        _token: &str,
        _body: Option<&[u8]>,
    ) -> Option<(u16, String)> {
        assert_eq!(method, "DELETE", "a release is a DELETE");
        self.seen.lock().unwrap().push(url.to_string());
        if self.fail.iter().any(|f| url.contains(f)) {
            return Some((500, "no".into()));
        }
        Some((200, String::new()))
    }
}

fn names(pairs: &[(&str, &str)]) -> Vec<Name> {
    pairs
        .iter()
        .map(|(l, d)| Name {
            localpart: (*l).to_string(),
            domain: (*d).to_string(),
        })
        .collect()
}

#[test]
fn draining_releases_every_name_and_says_which() {
    let t = PerName {
        fail: vec![],
        seen: Default::default(),
    };
    let all = names(&[("alice", "a.test"), ("bob", "b.test"), ("carol", "a.test")]);
    let report = drain(&t, &anchor(), &all);

    assert_eq!(report.released, all, "every name should have been released");
    assert!(report.failed.is_empty());
    assert_eq!(
        t.seen.lock().unwrap().len(),
        3,
        "one request per name, not one for the batch"
    );
}

/// One name failing must not strand the rest. A drain that stopped at the
/// first refusal would leave an operator believing the relay had let go of
/// names it is still holding.
#[test]
fn a_failure_does_not_stop_the_rest() {
    let t = PerName {
        fail: vec!["bob".into()],
        seen: Default::default(),
    };
    let all = names(&[("alice", "a.test"), ("bob", "b.test"), ("carol", "a.test")]);
    let report = drain(&t, &anchor(), &all);

    assert_eq!(
        report.released,
        names(&[("alice", "a.test"), ("carol", "a.test")])
    );
    assert_eq!(report.failed, names(&[("bob", "b.test")]));
    assert_eq!(
        t.seen.lock().unwrap().len(),
        3,
        "the name after the failure was never attempted"
    );
}

/// An unreachable anchor releases nothing, and must say so rather than
/// reporting success — the caller's next move is usually "the names are free
/// now", and they would not be.
#[test]
fn an_unreachable_anchor_fails_every_name_rather_than_claiming_success() {
    let all = names(&[("alice", "a.test"), ("bob", "b.test")]);
    let report = drain(&Fake::unreachable(), &anchor(), &all);
    assert!(report.released.is_empty());
    assert_eq!(report.failed, all);
}

/// The domain travels in the query string, so a name is released from the
/// right domain — two accounts with the same localpart on different domains
/// are different claims.
#[test]
fn the_domain_is_part_of_the_release() {
    let t = PerName {
        fail: vec![],
        seen: Default::default(),
    };
    drain(
        &t,
        &anchor(),
        &names(&[("alice", "a.test"), ("alice", "b.test")]),
    );
    let seen = t.seen.lock().unwrap().clone();
    assert_eq!(
        seen,
        vec![
            "https://anchor.test/identity/alice?domain=a.test".to_string(),
            "https://anchor.test/identity/alice?domain=b.test".to_string(),
        ],
        "the same localpart on two domains must be two different releases"
    );
}

/// Nothing to drain is not an error, and must not be reported as a release.
#[test]
fn draining_nothing_releases_nothing() {
    let t = PerName {
        fail: vec![],
        seen: Default::default(),
    };
    let report = drain(&t, &anchor(), &[]);
    assert!(report.released.is_empty() && report.failed.is_empty());
    assert!(
        t.seen.lock().unwrap().is_empty(),
        "an empty drain must not talk to the anchor at all"
    );
}
