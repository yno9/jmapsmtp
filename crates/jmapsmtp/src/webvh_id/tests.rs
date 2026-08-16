//! What a relay may read out of a `did:webvh` identifier, and what it must
//! refuse to read out of one.

use super::*;
use pretty_assertions::assert_eq;

const SCID: &str = "QmSCIDPlaceholder1111111111111111111111111111";

fn did(rest: &str) -> String {
    format!("did:webvh:{SCID}:{rest}")
}

#[test]
fn bisets_own_shape_yields_a_domain_and_a_username() {
    assert_eq!(
        parse(&did("biset.md:alice")),
        Ok(WebvhId {
            scid: SCID.into(),
            domain: "biset.md".into(),
            port: None,
            username: "alice".into(),
        })
    );
}

/// The SCID is carried, never judged. Verifying it means hashing the genesis
/// log entry, which needs the log — the anchor's job, not this one's. A relay
/// that rejected an odd-looking SCID would be enforcing a rule it cannot
/// actually check, and would break the moment the method's encoding changed.
#[test]
fn the_scid_is_carried_not_verified() {
    let parsed = parse("did:webvh:not-a-real-scid:biset.md:alice").expect("should parse");
    assert_eq!(parsed.scid, "not-a-real-scid");
    assert_eq!(parsed.domain, "biset.md");
}

/// An empty SCID is still refused: it is a malformed identifier rather than an
/// unverified one, and accepting it would let `did:webvh::biset.md:alice`
/// authorise a name.
#[test]
fn an_empty_scid_is_malformed() {
    assert_eq!(
        parse("did:webvh::biset.md:alice"),
        Err(ParseError::MalformedSegments)
    );
}

// ── the path shape, which is the whole point ──────────────────────────────

/// The legacy `…:{domain}:dids:{username}` form named a log at
/// `/dids/alice/did.jsonl`. Reading `alice` out of it would authorise a name
/// against a document stored somewhere else entirely.
#[test]
fn the_legacy_dids_prefix_is_refused_not_unwrapped() {
    assert_eq!(
        parse(&did("biset.md:dids:alice")),
        Err(ParseError::NotSingleSegmentPath)
    );
}

/// An apex DID's log lives at `.well-known/did.jsonl` and carries no username
/// at all. There is nothing in it to match a localpart against.
#[test]
fn an_apex_did_has_no_username_to_read() {
    assert_eq!(
        parse(&did("biset.md")),
        Err(ParseError::NotSingleSegmentPath)
    );
}

#[test]
fn a_missing_domain_is_malformed() {
    assert_eq!(parse("did:webvh:"), Err(ParseError::MalformedSegments));
    assert_eq!(parse(&did("")), Err(ParseError::MalformedSegments));
}

#[test]
fn a_non_webvh_did_is_not_this_modules_business() {
    assert_eq!(
        parse("did:dht:yiuqe1x3z8b1b1b1b1b1b1b1b1"),
        Err(ParseError::NotWebvh)
    );
    assert_eq!(parse("alice@biset.md"), Err(ParseError::NotWebvh));
    assert_eq!(parse(""), Err(ParseError::NotWebvh));
}

// ── domains ───────────────────────────────────────────────────────────────

/// Domains are compared against a config list, so they are folded once, here.
/// Doing it at the comparison instead would fold in some call sites and not
/// others.
#[test]
fn a_domain_is_lowercased_but_a_username_is_not() {
    let parsed = parse(&did("BISET.MD:Alice")).expect("should parse");
    assert_eq!(parsed.domain, "biset.md");
    assert_eq!(parsed.username, "Alice", "case folding belongs to the caller");
}

/// `%3A` is the method's escape for the separator colon. The port is split off
/// so it can never end up inside a domain compared against the config list —
/// `biset.md%3A8443` must not match, or fail to match, as if it were a
/// different domain name.
#[test]
fn a_port_is_split_off_the_domain() {
    assert_eq!(
        parse(&did("biset.md%3A8443:alice")),
        Ok(WebvhId {
            scid: SCID.into(),
            domain: "biset.md".into(),
            port: Some(8443),
            username: "alice".into(),
        })
    );
    // Lowercase escape too — the method does not pin the hex case.
    assert_eq!(
        parse(&did("biset.md%3a8443:alice")).expect("should parse").port,
        Some(8443)
    );
}

#[test]
fn an_unusable_port_is_refused() {
    assert_eq!(parse(&did("biset.md%3A0:alice")), Err(ParseError::BadPort));
    assert_eq!(parse(&did("biset.md%3A99999:alice")), Err(ParseError::BadPort));
    assert_eq!(parse(&did("biset.md%3A:alice")), Err(ParseError::BadPort));
    assert_eq!(parse(&did("biset.md%3Aweb:alice")), Err(ParseError::BadPort));
}

#[test]
fn a_domain_that_is_only_a_port_is_malformed() {
    assert_eq!(
        parse(&did("%3A8443:alice")),
        Err(ParseError::MalformedSegments)
    );
}

// ── usernames ─────────────────────────────────────────────────────────────

/// The same exclusions the client applies when it turns a DID into a log URL.
/// A name that escapes its own directory addresses a different document than
/// the one it claims to be.
#[test]
fn a_username_that_could_escape_its_directory_is_refused() {
    for bad in ["", ".", "..", "a/b", "a%2Fb", "a%5Cb", "a%00b", " alice", "alice "] {
        assert_eq!(
            parse(&did(&format!("biset.md:{bad}"))),
            Err(ParseError::BadUsername),
            "{bad:?} should not be readable as a username"
        );
    }
}

#[test]
fn a_percent_escaped_username_is_decoded() {
    assert_eq!(
        parse(&did("biset.md:al%2Dice")).expect("should parse").username,
        "al-ice"
    );
}

/// A truncated or non-hex escape is refused rather than passed through
/// literally: `%2` and `%zz` would otherwise become part of the name.
#[test]
fn a_broken_percent_escape_is_refused() {
    for bad in ["al%", "al%2", "al%zz"] {
        assert_eq!(
            parse(&did(&format!("biset.md:{bad}"))),
            Err(ParseError::BadUsername),
            "{bad:?}"
        );
    }
}
