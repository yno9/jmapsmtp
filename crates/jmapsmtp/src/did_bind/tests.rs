//! The order of the checks is the contract; each test names which one it pins.

use super::*;
use jmapserver::anchor::Verdict;
use pretty_assertions::assert_eq;

fn body(json: &str) -> Vec<u8> {
    json.as_bytes().to_vec()
}

// ── what is refused, and in which order ───────────────────────────────────

#[test]
fn a_body_that_is_not_json_is_did_required_not_a_parse_error() {
    assert_eq!(decide(true, b"not json at all"), Err(Refusal::DidRequired));
}

#[test]
fn an_empty_did_is_refused() {
    assert_eq!(
        decide(true, &body(r#"{"did":"","did_sig":"s"}"#)),
        Err(Refusal::DidRequired)
    );
    assert_eq!(
        decide(true, &body(r#"{"did_sig":"s"}"#)),
        Err(Refusal::DidRequired)
    );
}

/// The anchor check sits **between** `did` and `did_sig`. A request missing
/// both must report the anchor, because on an anchorless relay no signature
/// the caller could send would help.
#[test]
fn an_anchorless_relay_reports_the_anchor_before_the_missing_signature() {
    assert_eq!(
        decide(false, &body(r#"{"did":"did:webvh:abc"}"#)),
        Err(Refusal::NoAnchor),
        "missing did_sig too, but the anchor is the real answer"
    );
}

/// …and the `did` check sits before the anchor check, so an anchorless relay
/// given an empty DID still says `did required`.
#[test]
fn an_anchorless_relay_still_checks_the_did_first() {
    assert_eq!(decide(false, &body("{}")), Err(Refusal::DidRequired));
}

#[test]
fn a_did_without_a_signature_is_refused_when_there_is_an_anchor() {
    assert_eq!(
        decide(true, &body(r#"{"did":"did:webvh:abc"}"#)),
        Err(Refusal::DidSigRequired)
    );
}

#[test]
fn a_complete_request_is_accepted_and_carries_its_fields() {
    assert_eq!(
        decide(
            true,
            &body(r#"{"did":"did:webvh:abc","did_sig":"sig","bind_ts":1785000000}"#)
        ),
        Ok(BindRequest {
            did: "did:webvh:abc".into(),
            bind_ts: 1_785_000_000,
            did_sig: "sig".into(),
        })
    );
}

// ── the size limit ────────────────────────────────────────────────────────

/// Go truncates at 4096 bytes rather than rejecting, so an over-long body
/// fails to parse and answers `did required`. A client sending a big body sees
/// that, not a 413, and this pins the difference.
#[test]
fn an_over_long_body_is_truncated_into_a_parse_failure() {
    let padding = " ".repeat(MAX_BODY);
    let json = format!(r#"{{"did_pad":"{padding}","did":"did:webvh:abc","did_sig":"s"}}"#);
    assert!(json.len() > MAX_BODY);
    assert_eq!(decide(true, json.as_bytes()), Err(Refusal::DidRequired));
}

/// The boundary in the other direction: a body that fits is read whole.
#[test]
fn a_body_just_under_the_limit_is_read_whole() {
    let core = r#"{"pad":"","did":"did:webvh:abc","did_sig":"s"}"#;
    let padding = " ".repeat(MAX_BODY - core.len());
    let json = format!(r#"{{"pad":"{padding}","did":"did:webvh:abc","did_sig":"s"}}"#);
    assert!(json.len() <= MAX_BODY, "fixture must fit: {}", json.len());
    assert!(decide(true, json.as_bytes()).is_ok());
}

// ── translating the anchor's verdict ──────────────────────────────────────

/// Each verdict maps to a different status, and the mapping is the whole point
/// of the enum: a conflict is not a rejection and neither is an outage.
#[test]
fn every_verdict_maps_to_a_distinct_answer() {
    assert_eq!(from_verdict(Verdict::Ok), None);
    assert_eq!(from_verdict(Verdict::Invalid).unwrap().status(), 401);
    assert_eq!(from_verdict(Verdict::Conflict).unwrap().status(), 409);
    assert_eq!(from_verdict(Verdict::Error).unwrap().status(), 503);
}

/// A refusal that answered the same status as another would make the two
/// indistinguishable to a client that only reads the code.
#[test]
fn the_statuses_that_must_differ_do_differ() {
    let anchor_side = [
        Refusal::BindingRejected,
        Refusal::Mismatch,
        Refusal::AnchorUnavailable,
    ];
    let mut seen = std::collections::HashSet::new();
    for r in anchor_side {
        assert!(seen.insert(r.status()), "{r:?} duplicates another status");
    }
}

/// `no identity anchor` is a 400, not a 503. It is a permanent property of
/// this relay, not an outage, and a client that retries on 503 would spin.
#[test]
fn an_absent_anchor_is_not_reported_as_an_outage() {
    assert_eq!(Refusal::NoAnchor.status(), 400);
    assert_ne!(
        Refusal::NoAnchor.status(),
        Refusal::AnchorUnavailable.status()
    );
}
