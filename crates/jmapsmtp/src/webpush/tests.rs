//! Web Push delivery.
//!
//! The first test is the one that matters: a notification is a *wake-up*, not
//! a message. Anything more in the payload hands metadata to the push service,
//! which is a third party the relay does not control and the user did not
//! choose.

use super::*;
use pretty_assertions::assert_eq;

/// A real P-256 VAPID key pair, in the base64url form the config holds — the
/// same encoding `webpush.GenerateVAPIDKeys()` produces, so an existing
/// deployment's keys work unchanged.
fn vapid() -> Vapid {
    Vapid::new(
        "BJxykIkE4WSXLbG0Yr8vGCa-LKyM8Wm5MCFCnT2VOwjSMBOR3kBLqEcRjfSnQFj_8ZMbXcNQ0EkNZaVAJIABmSs",
        "IQ9Ur0ykXoHS9gzfYX0aBjy9lvdrjx_PFUXmie9YRcY",
        "you@example.com",
    )
}

/// A subscription with real key material, so the encryption actually runs.
fn subscription() -> PushSubscription {
    PushSubscription {
        endpoint: "https://push.test/endpoint/abc".into(),
        p256dh: "BLMbF9ffKBiWQLCKvTHb6LO8Nb6dcUh6TItC455vu2kElga6PQvUmaFyCdykxY2nOSSL3yKgfbmFLRTUaGv4yV8"
            .into(),
        auth: "xKgKZByMS8LKGkC6TTvfSg".into(),
    }
}

// ── what a notification says ──────────────────────────────────────────────

/// The payload names the changed capability and no more. A client is told that
/// something changed and fetches over an authenticated connection.
#[test]
fn a_notification_carries_no_message_data() {
    assert_eq!(PAYLOAD, r#"{"changed":{"urn:ietf:params:jmap:mail":null}}"#);

    let parsed: serde_json::Value = serde_json::from_str(PAYLOAD).unwrap();
    assert_eq!(
        parsed.as_object().unwrap().keys().collect::<Vec<_>>(),
        ["changed"],
        "one key, and it names a capability rather than a message"
    );
    assert_eq!(
        parsed["changed"]["urn:ietf:params:jmap:mail"],
        serde_json::Value::Null
    );
}

/// Byte-identical to the event-source frame's data, so a client handles one
/// path for both.
#[test]
fn the_payload_matches_the_event_source_frame() {
    let frame = jmapserver::push::STATE_EVENT;
    let data = frame
        .lines()
        .find_map(|l| l.strip_prefix("data: "))
        .expect("the frame carries data");
    assert_eq!(data, PAYLOAD);
}

// ── the request ───────────────────────────────────────────────────────────

#[test]
fn a_request_is_encrypted_and_signed() {
    let request = build_request(&vapid(), &subscription()).expect("built");
    assert_eq!(request.endpoint, "https://push.test/endpoint/abc");

    assert_eq!(
        request.header("Content-Encoding"),
        Some("aes128gcm"),
        "RFC 8291"
    );
    assert_eq!(
        request.header("Content-Type"),
        Some("application/octet-stream")
    );
    assert_eq!(request.header("TTL"), Some(TTL_SECS.to_string().as_str()));
    assert!(
        request
            .header("Authorization")
            .is_some_and(|a| a.starts_with("vapid ")),
        "the VAPID JWT: {:?}",
        request.header("Authorization")
    );

    // The body is ciphertext, not the payload.
    assert!(!request.body.is_empty());
    assert!(
        !String::from_utf8_lossy(&request.body).contains("changed"),
        "the payload must not travel in the clear"
    );
}

/// The JWT's `sub` claim names a contact for the sender (RFC 8292 §2.1) so a
/// push service with a problem has somebody to reach. Apple rejects a missing
/// or malformed one outright with 403 while Google accepts it — a failure that
/// only appears against one vendor, which is why it is checked rather than
/// assumed.
#[test]
fn the_vapid_jwt_names_a_contact_for_the_sender() {
    let request = build_request(&vapid(), &subscription()).unwrap();
    let auth = request
        .header("Authorization")
        .expect("an Authorization header");

    // `vapid t=<jwt>,k=<public key>`
    let jwt = auth
        .strip_prefix("vapid ")
        .and_then(|rest| rest.split(',').find_map(|p| p.trim().strip_prefix("t=")))
        .unwrap_or_else(|| panic!("no JWT in {auth}"));
    let claims = jwt.split('.').nth(1).expect("a payload segment");

    use base64::Engine as _;
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(claims)
        .expect("base64url");
    let claims: serde_json::Value = serde_json::from_slice(&decoded).unwrap();

    assert_eq!(
        claims["sub"], "mailto:you@example.com",
        "exactly one mailto: prefix — a doubled one is what Apple rejects"
    );
    assert!(claims["exp"].is_number(), "and an expiry: {claims}");
}

/// A relay with no subscriber configured still signs, without a `sub` claim.
/// Emitting `mailto:` with nothing after it would be the malformed subject
/// itself.
#[test]
fn no_configured_subscriber_means_no_sub_claim_rather_than_an_empty_one() {
    let vapid = Vapid::new(
        "BJxykIkE4WSXLbG0Yr8vGCa-LKyM8Wm5MCFCnT2VOwjSMBOR3kBLqEcRjfSnQFj_8ZMbXcNQ0EkNZaVAJIABmSs",
        "IQ9Ur0ykXoHS9gzfYX0aBjy9lvdrjx_PFUXmie9YRcY",
        "",
    );
    let request = build_request(&vapid, &subscription()).expect("still signs");
    let auth = request.header("Authorization").unwrap();
    assert!(
        !auth.contains("mailto"),
        "no empty subject was emitted: {auth}"
    );
}

/// Content-Length is left to the HTTP client. Setting it here as well makes
/// reqwest send the header twice, which some push services reject.
#[test]
fn the_request_does_not_set_its_own_content_length() {
    let request = build_request(&vapid(), &subscription()).unwrap();
    assert!(
        request.header("Content-Length").is_none(),
        "{:?}",
        request.headers
    );
}

/// Each send is separately encrypted, so two are not byte-identical — the
/// ephemeral key is per message.
#[test]
fn two_notifications_do_not_produce_the_same_ciphertext() {
    let first = build_request(&vapid(), &subscription()).unwrap().body;
    let second = build_request(&vapid(), &subscription()).unwrap().body;
    assert_ne!(first, second, "a fresh ephemeral key each time");
}

#[test]
fn a_malformed_key_is_an_error_rather_than_a_panic() {
    let bad = Vapid::new("pub", "not-a-key", "you@example.com");
    assert!(build_request(&bad, &subscription()).is_err());

    let mut sub = subscription();
    sub.p256dh = "not-a-key".into();
    assert!(build_request(&vapid(), &sub).is_err());
}

// ── classifying the answer ────────────────────────────────────────────────

/// 404 and 410 are the service saying the subscription no longer exists. Every
/// other failure is transient as far as this relay can tell, and dropping a
/// subscription over one would silently stop notifying a working client.
#[test]
fn only_a_gone_subscription_is_pruned() {
    for status in [200, 201, 202, 204] {
        assert_eq!(classify(status, ""), Delivery::Sent, "{status}");
    }
    for status in [404, 410] {
        assert_eq!(classify(status, ""), Delivery::Gone, "{status}");
    }
    for status in [400, 401, 403, 413, 429, 500, 502, 503] {
        assert!(
            matches!(classify(status, "busy"), Delivery::Failed(_)),
            "{status} must not prune the subscription"
        );
    }
}

/// A 429 is the service asking for less, not for none. Treating it as Gone
/// would unsubscribe a working client the first time it was rate-limited.
#[test]
fn rate_limiting_does_not_unsubscribe_anyone() {
    assert_ne!(classify(429, "slow down"), Delivery::Gone);
}

#[test]
fn a_failure_carries_the_reason() {
    match classify(503, "  maintenance  ") {
        Delivery::Failed(reason) => assert_eq!(reason, "503: maintenance"),
        other => panic!("{other:?}"),
    }
}

// ── the TTL ───────────────────────────────────────────────────────────────

/// Long enough for a phone that is off overnight, short enough that a client
/// returning after days is not handed a queue of identical wake-ups.
#[test]
fn the_ttl_is_four_hours() {
    assert_eq!(TTL_SECS, 4 * 60 * 60);
}
