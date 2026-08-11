//! The push registry and the event-source payloads.

use super::*;
use jmap_types::Id;
use pretty_assertions::assert_eq;

fn sub(endpoint: &str) -> PushSubscription {
    PushSubscription {
        endpoint: endpoint.into(),
        p256dh: "key".into(),
        auth: "auth".into(),
    }
}

// ── VAPID ─────────────────────────────────────────────────────────────────

/// The web-push library prepends `mailto:` itself, so a caller-supplied prefix
/// doubles into `mailto:mailto:…`. Apple's push service rejects that with 403
/// while Google's accepts it — a failure that only appears against one vendor.
#[test]
fn a_mailto_prefix_is_stripped_so_either_form_works() {
    for given in [
        "you@example.com",
        "mailto:you@example.com",
        "MAILTO:you@example.com",
    ] {
        assert_eq!(
            Vapid::new("pub", "priv", given).subscriber,
            "you@example.com",
            "{given}"
        );
    }
}

#[test]
fn an_https_subscriber_is_left_alone() {
    assert_eq!(
        Vapid::new("pub", "priv", "https://example.com/contact").subscriber,
        "https://example.com/contact"
    );
    assert_eq!(Vapid::new("pub", "priv", "").subscriber, "");
}

/// A subscriber shorter than the prefix must not panic on the slice.
#[test]
fn a_short_subscriber_does_not_panic() {
    assert_eq!(Vapid::new("p", "k", "ab").subscriber, "ab");
}

// ── the registry ──────────────────────────────────────────────────────────

/// A client re-subscribing on every page load would otherwise accumulate
/// duplicates and be notified once per copy.
#[test]
fn the_same_endpoint_is_not_registered_twice() {
    let mut reg = PushRegistry::default();
    let account = Id::from("alice@a.test");
    reg.add(&account, sub("https://push.test/1"));
    reg.add(&account, sub("https://push.test/1"));
    reg.add(&account, sub("https://push.test/2"));
    assert_eq!(reg.for_account(&account).len(), 2);
    assert_eq!(reg.count(), 2);
}

#[test]
fn subscriptions_are_per_account() {
    let mut reg = PushRegistry::default();
    reg.add(&Id::from("alice@a.test"), sub("https://push.test/a"));
    reg.add(&Id::from("bob@a.test"), sub("https://push.test/b"));

    assert_eq!(
        reg.for_account(&Id::from("alice@a.test"))
            .iter()
            .map(|s| s.endpoint.as_str())
            .collect::<Vec<_>>(),
        ["https://push.test/a"],
        "one account's subscriptions are never another's"
    );
    assert!(reg.for_account(&Id::from("nobody@a.test")).is_empty());
}

#[test]
fn unsubscribing_removes_only_that_endpoint() {
    let mut reg = PushRegistry::default();
    let account = Id::from("alice@a.test");
    reg.add(&account, sub("https://push.test/1"));
    reg.add(&account, sub("https://push.test/2"));

    reg.remove(&account, "https://push.test/1");
    assert_eq!(
        reg.for_account(&account)
            .iter()
            .map(|s| s.endpoint.as_str())
            .collect::<Vec<_>>(),
        ["https://push.test/2"]
    );

    reg.remove(&account, "https://push.test/nope");
    assert_eq!(
        reg.for_account(&account).len(),
        1,
        "an unknown endpoint is a no-op"
    );
}

/// A browser does not re-subscribe unprompted, so subscriptions lost on
/// restart are lost permanently — the user simply stops being notified.
#[test]
fn subscriptions_survive_a_restart() {
    let tmp = tempfile::tempdir().unwrap();
    let account = Id::from("alice@a.test");

    let mut reg = PushRegistry::default();
    reg.set_persist_dir(tmp.path());
    reg.add(&account, sub("https://push.test/1"));
    assert!(PushRegistry::path(tmp.path()).exists());

    let mut restarted = PushRegistry::default();
    restarted.set_persist_dir(tmp.path());
    assert_eq!(
        restarted.for_account(&account),
        vec![sub("https://push.test/1")]
    );

    // …and a removal is persisted too, or a revoked device keeps being pushed
    // to after every restart.
    reg.remove(&account, "https://push.test/1");
    let mut again = PushRegistry::default();
    again.set_persist_dir(tmp.path());
    assert!(again.for_account(&account).is_empty());
}

/// Without a persist directory the registry is memory-only, and must not
/// error trying to write.
#[test]
fn a_registry_with_no_directory_writes_nothing() {
    let mut reg = PushRegistry::default();
    reg.add(&Id::from("alice@a.test"), sub("https://push.test/1"));
    assert_eq!(reg.count(), 1);
}

#[test]
fn a_corrupt_persisted_file_reads_as_empty() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(PushRegistry::path(tmp.path()), b"not json").unwrap();
    let mut reg = PushRegistry::default();
    reg.set_persist_dir(tmp.path());
    assert_eq!(reg.count(), 0, "a broken file must not stop the relay");
}

// ── the event-source payloads ─────────────────────────────────────────────

/// The event names the changed capability and carries **no state value**: a
/// client is told that something changed, not what, and fetches. Anything more
/// would make the stream a second, weaker copy of the store.
#[test]
fn the_state_event_carries_no_state() {
    assert_eq!(
        STATE_EVENT,
        "event: state\ndata: {\"changed\":{\"urn:ietf:params:jmap:mail\":null}}\n\n"
    );
    assert!(
        STATE_EVENT.ends_with("\n\n"),
        "SSE frames end with a blank line"
    );
}

#[test]
fn the_ping_is_an_sse_comment() {
    assert_eq!(PING_EVENT, ": ping\n\n");
    assert!(
        PING_EVENT.starts_with(':'),
        "a comment, so a client parses no event from it"
    );
    assert_eq!(PING_INTERVAL_SECS, 30);
}
