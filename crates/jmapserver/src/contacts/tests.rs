//! The DID-rooted contact cache.
//!
//! The binding a Card records is "this address belonged to this DID when I last
//! checked". An address can move between identities, so a cached address with
//! no DID beside it is worse than no cache — most of these tests are about not
//! losing that pairing.

use super::*;
use pretty_assertions::assert_eq;

fn card(uid: &str, address: &str, did: &str) -> Card {
    Card {
        kind: "Card".into(),
        version: "1.0".into(),
        uid: uid.into(),
        emails: BTreeMap::from([(
            "e1".to_string(),
            EmailAddr {
                address: address.into(),
            },
        )]),
        crypto_keys: BTreeMap::from([("k1".to_string(), CryptoKey { uri: did.into() })]),
        // A service endpoint with a query string, so the card contains the
        // characters Go's encoding/json escapes by default (`&`, `<`, `>`).
        // Without one, `serde_json` and `go_json` produce identical bytes and
        // the escaping requirement is invisible — SPEC.md §4.
        links: BTreeMap::from([(
            "l1".to_string(),
            Link {
                uri: "https://relay.test/jmap?a=1&b=2&t=<now>".into(),
            },
        )]),
        verified_at: 1_785_000_000,
    }
}

const DID: &str = "did:dht:ybndrfg8ejkmcpqxot1uwisza345h769ybndrfg8ejkmcpqxot1uw";
const WEBVH: &str = "did:webvh:QmSCID111111111111111111111111111111111111111:biset.md:dids:bob";

// ── the shape on disk ─────────────────────────────────────────────────────

/// The DID lives in `cryptoKeys` — a DID is a URI by construction, so it fits
/// the native JSContact property with no extension. Only biset's own
/// bookkeeping uses the vendor form the spec requires.
#[test]
fn a_card_serialises_as_jscontact_with_the_did_in_cryptokeys() {
    let json = jmap_types::go_json::to_string(&card("uid-1", "bob@x.test", DID)).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed["@type"], "Card");
    assert_eq!(parsed["version"], "1.0");
    assert_eq!(parsed["cryptoKeys"]["k1"]["uri"], DID);
    assert_eq!(parsed["emails"]["e1"]["address"], "bob@x.test");
    assert_eq!(
        parsed["biset.md:verifiedAt"], 1_785_000_000i64,
        "the vendor-extension form the spec requires"
    );

    // Go's encoding/json HTML-escapes by default, and this file is compared
    // byte for byte across implementations. SPEC.md §4.
    assert!(
        json.contains(r"\u0026") && json.contains(r"\u003c"),
        "`&` and `<` must be escaped as Go escapes them: {json}"
    );
    assert_eq!(
        parsed["links"]["l1"]["uri"], "https://relay.test/jmap?a=1&b=2&t=<now>",
        "and decode back to the original"
    );
}

/// A webvh DID is stored verbatim, colons and path segments and all. Anything
/// that split it on `:` and reassembled would produce a different identifier.
#[test]
fn a_webvh_did_survives_a_round_trip_unchanged() {
    let tmp = tempfile::tempdir().unwrap();
    put_contact(tmp.path(), card("uid-1", "bob@x.test", WEBVH)).unwrap();
    let back = read_contacts(tmp.path());
    assert_eq!(back[0].crypto_keys["k1"].uri, WEBVH);
}

#[test]
fn empty_collections_are_omitted_rather_than_written_as_empty_objects() {
    let json = jmap_types::go_json::to_string(&Card {
        kind: "Card".into(),
        version: "1.0".into(),
        uid: "uid-1".into(),
        ..Default::default()
    })
    .unwrap();
    assert_eq!(
        json, r#"{"@type":"Card","version":"1.0","uid":"uid-1"}"#,
        "declaration order, and nothing empty"
    );
}

// ── upserts ───────────────────────────────────────────────────────────────

#[test]
fn a_new_card_is_appended_and_an_existing_one_replaced() {
    let tmp = tempfile::tempdir().unwrap();
    put_contact(tmp.path(), card("uid-1", "bob@x.test", DID)).unwrap();
    put_contact(tmp.path(), card("uid-2", "carol@y.test", WEBVH)).unwrap();
    assert_eq!(read_contacts(tmp.path()).len(), 2);

    // The same uid replaces rather than duplicating.
    put_contact(tmp.path(), card("uid-1", "bob@moved.test", DID)).unwrap();
    let cards = read_contacts(tmp.path());
    assert_eq!(cards.len(), 2);
    assert_eq!(cards[0].emails["e1"].address, "bob@moved.test");
}

/// Merged, not replaced. A wholesale replace would make every single-card
/// write-through a chance to lose every other contact.
#[test]
fn writing_one_card_does_not_disturb_the_others() {
    let tmp = tempfile::tempdir().unwrap();
    for i in 1..=5 {
        put_contact(
            tmp.path(),
            card(&format!("uid-{i}"), &format!("p{i}@x.test"), DID),
        )
        .unwrap();
    }
    put_contact(tmp.path(), card("uid-3", "p3@moved.test", DID)).unwrap();

    let cards = read_contacts(tmp.path());
    assert_eq!(cards.len(), 5);
    assert_eq!(
        cards.iter().map(|c| c.uid.as_str()).collect::<Vec<_>>(),
        ["uid-1", "uid-2", "uid-3", "uid-4", "uid-5"],
        "the updated card keeps its position, so the file stays diffable"
    );
    assert_eq!(cards[2].emails["e1"].address, "p3@moved.test");
}

/// The whole point of the cache: an address and the DID it belonged to, kept
/// together. A card whose DID were dropped on update would leave an address
/// bound to nothing — worse than no cache, because it looks resolved.
#[test]
fn an_update_keeps_the_address_and_its_did_together() {
    let tmp = tempfile::tempdir().unwrap();
    put_contact(tmp.path(), card("uid-1", "bob@x.test", DID)).unwrap();

    // bob moves to a new address under the same identity.
    put_contact(tmp.path(), card("uid-1", "bob@new.test", DID)).unwrap();
    let cards = read_contacts(tmp.path());
    assert_eq!(cards[0].emails["e1"].address, "bob@new.test");
    assert_eq!(
        cards[0].crypto_keys["k1"].uri, DID,
        "still the same identity"
    );

    // …and the reverse: the address stays, the identity behind it changed.
    // Both must be visible, or the client cannot tell it is talking to
    // somebody else now.
    put_contact(tmp.path(), card("uid-1", "bob@new.test", WEBVH)).unwrap();
    let cards = read_contacts(tmp.path());
    assert_eq!(cards[0].crypto_keys["k1"].uri, WEBVH);
}

// ── reading ───────────────────────────────────────────────────────────────

#[test]
fn an_account_with_no_cache_reads_as_empty() {
    let tmp = tempfile::tempdir().unwrap();
    assert!(read_contacts(tmp.path()).is_empty());
}

/// A malformed file reads as empty rather than failing. The cache is a
/// convenience — losing it costs a re-resolve — and failing the restore because
/// one card is broken would lose the rest too.
#[test]
fn a_malformed_cache_reads_as_empty_rather_than_failing() {
    let tmp = tempfile::tempdir().unwrap();
    for bad in [&b""[..], b"not json", b"{}", br#"[{"uid":]"#] {
        std::fs::write(contacts_path(tmp.path()), bad).unwrap();
        assert!(
            read_contacts(tmp.path()).is_empty(),
            "{:?}",
            String::from_utf8_lossy(bad)
        );
    }
    // …and a write after that starts a fresh list rather than erroring.
    put_contact(tmp.path(), card("uid-1", "bob@x.test", DID)).unwrap();
    assert_eq!(read_contacts(tmp.path()).len(), 1);
}

// ── the upsert contract ───────────────────────────────────────────────────

/// The path `uid` and the body's must agree. Trusting either alone would let a
/// client overwrite one contact's card by addressing another's.
#[test]
fn the_path_uid_and_the_body_uid_have_to_agree() {
    let body = serde_json::to_vec(&card("uid-1", "bob@x.test", DID)).unwrap();
    assert_eq!(
        parse_upsert("uid-1", &body).map(|c| c.uid),
        Ok("uid-1".into())
    );
    assert_eq!(
        parse_upsert("uid-2", &body),
        Err(ContactError::UidMismatch),
        "the path says one contact, the body another"
    );
}

#[test]
fn a_card_with_no_uid_or_no_body_is_refused() {
    assert_eq!(
        parse_upsert("uid-1", b"not json"),
        Err(ContactError::InvalidCard)
    );
    assert_eq!(
        parse_upsert("uid-1", br#"{"@type":"Card","version":"1.0"}"#),
        Err(ContactError::InvalidCard),
        "a card with no uid cannot be addressed"
    );
}

#[test]
fn an_empty_path_uid_is_not_found() {
    let body = serde_json::to_vec(&card("uid-1", "bob@x.test", DID)).unwrap();
    assert_eq!(parse_upsert("", &body), Err(ContactError::NotFound));
}

#[test]
fn each_error_carries_the_status_the_client_expects() {
    for (err, status) in [
        (ContactError::InvalidCard, 400),
        (ContactError::UidMismatch, 400),
        (ContactError::Unauthorized, 401),
        (ContactError::NotFound, 404),
    ] {
        assert_eq!(err.status(), status, "{err:?}");
    }
}
