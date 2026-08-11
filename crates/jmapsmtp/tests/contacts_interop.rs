//! The DID-rooted contact cache, against the oracle.
//!
//! `contacts.json` is written by one implementation and read by whichever
//! starts next, so this checks both directions: the oracle reads what this port
//! wrote, and this port reads what the oracle wrote. A Card whose DID were
//! dropped or reshaped in either direction would leave an address bound to
//! nothing on the other side.

use base64::Engine as _;
use jmapserver::contacts::{Card, CryptoKey, EmailAddr, contacts_path, put_contact, read_contacts};

mod oracle_harness;
use oracle_harness::Oracle;

const AUTH_TOKEN: &[u8] = b"contacts-interop-token-000000000";

fn basic_auth(account: &str) -> String {
    let password = base64::engine::general_purpose::STANDARD.encode(AUTH_TOKEN);
    base64::engine::general_purpose::STANDARD.encode(format!("{account}:{password}"))
}

fn config_json(http_port: u16, smtp_port: u16) -> String {
    format!(
        r#"{{"listen_addr":"127.0.0.1:{http_port}","smtp_port":{smtp_port},
            "base_url":"http://127.0.0.1:{http_port}","hostname":"t.invalid",
            "domain":{{"a.test":{{"account":{{"alice":{{}},"bob":{{}}}}}}}}}}"#
    )
}

fn seed(root: &std::path::Path) {
    for lp in ["alice", "bob"] {
        let acct = root.join("data/a.test").join(lp);
        std::fs::create_dir_all(&acct).unwrap();
        std::fs::write(
            acct.join("auth_token_hash"),
            jmapserver::hash_auth_token(AUTH_TOKEN),
        )
        .unwrap();
    }
}

fn oracle() -> Option<Oracle> {
    Oracle::start_with("CONTACTS_INTEROP", config_json, seed)
}

const DID_DHT: &str = "did:dht:ybndrfg8ejkmcpqxot1uwisza345h769ybndrfg8ejkmcpqxot1uw";
/// A webvh DID with colons and path segments — the shape that breaks anything
/// which splits and reassembles instead of storing verbatim.
const DID_WEBVH: &str =
    "did:webvh:QmSCID111111111111111111111111111111111111111:biset.md:dids:carol";

fn card(uid: &str, address: &str, did: &str) -> Card {
    Card {
        kind: "Card".into(),
        version: "1.0".into(),
        uid: uid.into(),
        emails: std::collections::BTreeMap::from([(
            "e1".to_string(),
            EmailAddr {
                address: address.into(),
            },
        )]),
        crypto_keys: std::collections::BTreeMap::from([(
            "k1".to_string(),
            CryptoKey { uri: did.into() },
        )]),
        // A service endpoint with a query string. Without the `&` and `<`,
        // Go's default HTML escaping never shows up and the byte comparison
        // below passes whether or not this port reproduces it (SPEC.md §4).
        links: std::collections::BTreeMap::from([(
            "l1".to_string(),
            jmapserver::contacts::Link {
                uri: format!("https://relay.test/jmap?who={address}&t=<now>"),
            },
        )]),
        verified_at: 1_785_000_000,
    }
}

fn put_via_oracle(o: &Oracle, account: &str, card: &Card) -> (u16, String) {
    o.put_auth(
        &format!("/contacts/{}", card.uid),
        &serde_json::to_string(card).unwrap(),
        &basic_auth(account),
    )
}

fn get_via_oracle(o: &Oracle, account: &str) -> Vec<Card> {
    let (status, body, _) = o.get_auth("/contacts", &basic_auth(account));
    assert_eq!(status, 200, "{body:?}");
    let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
    serde_json::from_value(parsed["cards"].clone()).expect("cards")
}

// ── both directions ───────────────────────────────────────────────────────

/// The oracle writes, this port reads. That is the migration direction: every
/// contacts.json on disk today was written by Go.
#[test]
fn this_port_reads_the_cards_the_oracle_wrote() {
    let Some(o) = oracle() else { return };

    for c in [
        card("uid-1", "bob@x.test", DID_DHT),
        card("uid-2", "carol@y.test", DID_WEBVH),
    ] {
        let (status, body) = put_via_oracle(&o, "alice@a.test", &c);
        assert_eq!(status, 204, "{body:?}");
    }

    let ours = read_contacts(&o.data_dir().join("a.test/alice"));
    assert_eq!(ours.len(), 2);
    assert_eq!(ours[0].uid, "uid-1");
    assert_eq!(ours[0].crypto_keys["k1"].uri, DID_DHT);
    assert_eq!(
        ours[1].crypto_keys["k1"].uri, DID_WEBVH,
        "a webvh DID survives with its colons and path intact"
    );
    assert_eq!(ours[1].emails["e1"].address, "carol@y.test");
    assert_eq!(ours[1].verified_at, 1_785_000_000);
}

/// This port writes, the oracle reads. That is the rollback direction: a
/// deployment that ran this port and went back must not have lost its cache.
#[test]
fn the_oracle_reads_the_cards_this_port_wrote() {
    let Some(o) = oracle() else { return };
    let acct = o.data_dir().join("a.test/bob");

    put_contact(&acct, card("uid-1", "dave@x.test", DID_DHT)).unwrap();
    put_contact(&acct, card("uid-2", "erin@y.test", DID_WEBVH)).unwrap();

    let go = get_via_oracle(&o, "bob@a.test");
    assert_eq!(go.len(), 2);
    assert_eq!(go[0].crypto_keys["k1"].uri, DID_DHT);
    assert_eq!(go[1].crypto_keys["k1"].uri, DID_WEBVH);
    assert_eq!(go[1].emails["e1"].address, "erin@y.test");
}

/// The file itself, byte for byte. The two implementations take turns writing
/// it, so a difference in field order or omission accumulates as churn.
#[test]
fn the_stored_file_is_byte_identical_between_implementations() {
    let Some(o) = oracle() else { return };

    let cards = [
        card("uid-1", "bob@x.test", DID_DHT),
        card("uid-2", "carol@y.test", DID_WEBVH),
    ];
    for c in &cards {
        put_via_oracle(&o, "alice@a.test", c);
    }
    let go_bytes = std::fs::read(contacts_path(&o.data_dir().join("a.test/alice"))).unwrap();

    let mine = tempfile::tempdir().unwrap();
    for c in &cards {
        put_contact(mine.path(), c.clone()).unwrap();
    }
    let our_bytes = std::fs::read(contacts_path(mine.path())).unwrap();

    assert_eq!(
        String::from_utf8_lossy(&our_bytes),
        String::from_utf8_lossy(&go_bytes)
    );
    assert!(
        String::from_utf8_lossy(&go_bytes).contains(r"\u0026"),
        "the fixture must contain characters Go escapes, or this comparison \
         holds whether or not the escaping is reproduced"
    );
}

// ── upsert semantics ──────────────────────────────────────────────────────

/// Merged, not replaced, on both sides — and an update keeps its position, so
/// the two implementations do not reshuffle each other's file.
#[test]
fn an_upsert_merges_and_keeps_position_on_both_implementations() {
    let Some(o) = oracle() else { return };
    let acct = o.data_dir().join("a.test/alice");

    for i in 1..=3 {
        put_via_oracle(
            &o,
            "alice@a.test",
            &card(&format!("uid-{i}"), &format!("p{i}@x.test"), DID_DHT),
        );
    }
    // This port updates the middle one.
    put_contact(&acct, card("uid-2", "p2@moved.test", DID_WEBVH)).unwrap();

    let go = get_via_oracle(&o, "alice@a.test");
    assert_eq!(
        go.iter().map(|c| c.uid.as_str()).collect::<Vec<_>>(),
        ["uid-1", "uid-2", "uid-3"],
        "the updated card keeps its position"
    );
    assert_eq!(go[1].emails["e1"].address, "p2@moved.test");
    assert_eq!(go[1].crypto_keys["k1"].uri, DID_WEBVH);
}

// ── the contract ──────────────────────────────────────────────────────────

#[test]
fn a_uid_mismatch_and_a_bad_card_are_refused_the_same_way() {
    let Some(o) = oracle() else { return };
    let c = card("uid-1", "bob@x.test", DID_DHT);

    let (status, body) = o.put_auth(
        "/contacts/uid-2",
        &serde_json::to_string(&c).unwrap(),
        &basic_auth("alice@a.test"),
    );
    assert_eq!(status, 400, "{body:?}");
    assert_eq!(
        jmapserver::contacts::parse_upsert("uid-2", &serde_json::to_vec(&c).unwrap()),
        Err(jmapserver::contacts::ContactError::UidMismatch)
    );

    let (status, _) = o.put_auth("/contacts/uid-1", "not json", &basic_auth("alice@a.test"));
    assert_eq!(status, 400);
}

/// The cache is per account, resolved from the credential. One account's
/// contacts are never another's.
#[test]
fn the_cache_is_scoped_to_the_credential() {
    let Some(o) = oracle() else { return };
    put_via_oracle(&o, "alice@a.test", &card("uid-1", "bob@x.test", DID_DHT));

    assert!(
        get_via_oracle(&o, "bob@a.test").is_empty(),
        "alice's contacts must not appear for bob"
    );

    let (status, _, _) = o.get("/contacts");
    assert_eq!(status, 401, "unauthenticated");
}

/// An account with no cache yet answers `[]`, not `null`. The Go comment on
/// `ListDeviceKeys` records what a `null` costs: a client doing `.length` on it
/// blanks the view.
#[test]
fn an_empty_cache_is_an_empty_list_not_null() {
    let Some(o) = oracle() else { return };
    let (status, body, _) = o.get_auth("/contacts", &basic_auth("alice@a.test"));
    assert_eq!(status, 200);
    let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(parsed["cards"], serde_json::json!([]), "not null");
}

// ── the uid in the path is percent-encoded ────────────────────────────────

/// **biset's uids are `urn:uuid:…`, and a browser sends the colons as `%3A`.**
///
/// Every existing test here uses `uid-1` — a uid with nothing in it that needs
/// escaping — so all of them passed against a port that never decoded the
/// path. Go's `r.URL.Path` is decoded by `net/http` before the handler sees
/// it; `Uri::path()` is not. The uid from the path then never equalled the uid
/// in the body, and every contact write from a real client answered **400**.
///
/// Found in a production access log:
/// `PUT /contacts/urn%3Auuid%3A66f701df-… -> 400`, after DIDComm messages
/// stopped appearing — biset caches each peer it resolves as a contact.
#[test]
fn a_uid_that_needs_escaping_round_trips_on_both() {
    let Some(o) = oracle() else { return };
    let account = "alice@a.test";
    // The shape biset generates.
    let uid = "urn:uuid:66f701df-e9dd-51a8-adca-31bd6b2fe288";
    let c = card(uid, "peer@x.test", DID_DHT);

    let (go_status, go_body) = put_via_oracle(&o, account, &c);
    assert_eq!(
        go_status, 204,
        "the oracle accepts an escaped uid: {go_body:?}"
    );

    let ours = jmapserver::contacts::parse_upsert(
        // What the handler must pass in: the **decoded** segment, as Go's
        // `URL.Path` gives. Encoding it and not decoding is the bug.
        uid,
        &serde_json::to_vec(&c).unwrap(),
    );
    assert!(ours.is_ok(), "this port must accept the same card");

    // And the encoded form must NOT be accepted as the uid, or the decode
    // would be pointless.
    let encoded = jmapserver::contacts::parse_upsert(
        "urn%3Auuid%3A66f701df-e9dd-51a8-adca-31bd6b2fe288",
        &serde_json::to_vec(&c).unwrap(),
    );
    assert!(
        encoded.is_err(),
        "an undecoded uid must not match the body's — that mismatch is the \
         400 a real client got"
    );

    // The oracle stored it under the decoded uid.
    let cards = get_via_oracle(&o, account);
    assert!(
        cards.iter().any(|x| x.uid == uid),
        "the oracle should list the card under its decoded uid: {:?}",
        cards.iter().map(|x| &x.uid).collect::<Vec<_>>()
    );
}
