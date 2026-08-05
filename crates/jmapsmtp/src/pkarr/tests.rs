use super::*;
use pretty_assertions::assert_eq;

#[test]
fn a_plain_key_is_forwarded() {
    assert_eq!(
        decide("GET", "/pkarr/abc123"),
        Action::Forward { key: "abc123" }
    );
    assert_eq!(
        decide("PUT", "/pkarr/abc123"),
        Action::Forward { key: "abc123" }
    );
}

#[test]
fn a_preflight_is_answered_without_reaching_the_anchor() {
    assert_eq!(decide("OPTIONS", "/pkarr/abc123"), Action::Preflight);
    // Even for a key that would otherwise be rejected: the browser is asking
    // whether it may send, not sending.
    assert_eq!(decide("OPTIONS", "/pkarr/"), Action::Preflight);
}

#[test]
fn an_empty_key_is_not_found() {
    assert_eq!(decide("GET", "/pkarr/"), Action::NotFound);
}

/// A slash makes it not a key. Answering 404 rather than 400 keeps the relay
/// from describing the anchor's namespace to whoever probed it.
#[test]
fn a_key_with_a_slash_is_not_found() {
    assert_eq!(decide("GET", "/pkarr/abc/def"), Action::NotFound);
    assert_eq!(decide("PUT", "/pkarr/a/"), Action::NotFound);
}

/// The key is checked **before** the method: a bad key is not found however
/// it was asked for. Swapping the two turns a 404 into a 405 and tells the
/// caller the path exists.
#[test]
fn a_bad_key_is_not_found_even_with_a_bad_method() {
    assert_eq!(decide("DELETE", "/pkarr/a/b"), Action::NotFound);
    assert_eq!(decide("DELETE", "/pkarr/"), Action::NotFound);
}

#[test]
fn other_methods_are_refused_when_the_key_is_fine() {
    assert_eq!(decide("DELETE", "/pkarr/abc"), Action::MethodNotAllowed);
    assert_eq!(decide("POST", "/pkarr/abc"), Action::MethodNotAllowed);
}

// ── the forwarded URL ─────────────────────────────────────────────────────

#[test]
fn a_trailing_slash_on_the_anchor_url_does_not_double_up() {
    assert_eq!(
        target("https://anchor.test/", "abc"),
        "https://anchor.test/pkarr/abc"
    );
    assert_eq!(
        target("https://anchor.test", "abc"),
        "https://anchor.test/pkarr/abc"
    );
    // More than one, since a config is hand-edited.
    assert_eq!(
        target("https://anchor.test///", "abc"),
        "https://anchor.test/pkarr/abc"
    );
}

/// The key goes through untouched. It is base32 today, but nothing here knows
/// that, and percent-encoding or lower-casing it would break a signature at
/// the far end.
#[test]
fn the_key_is_passed_through_verbatim() {
    for key in ["ABC", "abc", "a-b_c", "1234567890"] {
        assert_eq!(
            target("https://anchor.test", key),
            format!("https://anchor.test/pkarr/{key}")
        );
    }
}
