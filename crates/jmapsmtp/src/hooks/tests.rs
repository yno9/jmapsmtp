//! The two hooks. The tests that matter most are the stored-copy ones: they
//! decide whether the relay keeps a readable copy of its users' sent mail.

use super::*;
use jmap_types::email::{BodyPart, Header};
use jmap_types::mail::Address;
use pretty_assertions::assert_eq;

fn cfg(json: &str) -> Config {
    serde_json::from_str(json).expect("config should parse")
}

fn addr(email: &str) -> Address {
    Address {
        email: email.into(),
        ..Default::default()
    }
}

/// A message with one text part carrying `body`.
fn message(body: &str) -> Email {
    let mut msg = Email {
        text_body: vec![BodyPart {
            part_id: "1".into(),
            ..Default::default()
        }],
        ..Default::default()
    };
    msg.body_values.insert("1".into(), BodyValue::new(body));
    msg
}

// ── the storage cap ───────────────────────────────────────────────────────

#[test]
fn no_cap_means_no_check() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("big"), vec![0u8; 4 * 1024 * 1024]).unwrap();
    assert_eq!(
        within_storage_cap(&cfg(r#"{"domain":{"a.test":{}}}"#), tmp.path()),
        Ok(())
    );
}

/// The cap is a floor, not a ceiling: at exactly the limit it refuses. The
/// alternative — allowing one more message at the limit — means the cap can be
/// exceeded by an arbitrary amount, since a message has no size bound.
#[test]
fn the_cap_refuses_at_the_limit_not_past_it() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = cfg(r#"{"domain":{"a.test":{}},"max_account_storage_mb":2}"#);

    std::fs::write(tmp.path().join("a"), vec![0u8; 1024 * 1024]).unwrap();
    assert_eq!(within_storage_cap(&cfg, tmp.path()), Ok(()), "1 of 2");

    std::fs::write(tmp.path().join("b"), vec![0u8; 1024 * 1024]).unwrap();
    assert_eq!(
        within_storage_cap(&cfg, tmp.path()),
        Err("storage limit reached (2MB)".into()),
        "exactly at the cap"
    );
}

// ── draft defaults ────────────────────────────────────────────────────────

#[test]
fn a_draft_with_nothing_set_gets_an_id_and_a_message_id() {
    let d = draft_defaults(&Email::default(), "a.test");
    assert!(d.id.is_some());
    assert!(d.rfc_message_id.unwrap().ends_with("@a.test"));
}

#[test]
fn what_the_client_supplied_is_left_alone() {
    let msg = Email {
        id: jmap_types::Id::from("client-chose-this"),
        message_id: vec!["mine@elsewhere.test".into()],
        ..Default::default()
    };
    assert_eq!(
        draft_defaults(&msg, "a.test"),
        DraftDefaults {
            id: None,
            rfc_message_id: None
        }
    );
}

/// An empty first entry counts as absent. Otherwise a client sending
/// `"messageId": [""]` puts a blank Message-ID on the wire.
#[test]
fn an_empty_message_id_entry_counts_as_absent() {
    let msg = Email {
        message_id: vec![String::new()],
        ..Default::default()
    };
    assert!(draft_defaults(&msg, "a.test").rfc_message_id.is_some());
}

#[test]
fn preparing_a_draft_adds_the_custom_headers_and_the_receive_time() {
    let mut msg = message("hi");
    let create = serde_json::json!({"header:X-Ticket:asText": "ABC-1"});
    let at = jmap_types::JmapTime::from_raw("2026-07-29T00:00:00Z");
    prepare_draft(&mut msg, &create, "a.test", at.clone());

    assert_eq!(
        msg.headers,
        [Header {
            name: "X-Ticket".into(),
            value: "ABC-1".into()
        }]
    );
    assert_eq!(msg.received_at, Some(at));
    assert!(!msg.id.is_empty());
}

// ── reply-only outbound ───────────────────────────────────────────────────

fn envelope_to(rcpts: &[&str]) -> Envelope {
    use jmap_types::emailsubmission::Address as EnvAddress;
    Envelope {
        mail_from: Some(EnvAddress::new("alice@a.test")),
        rcpt_to: rcpts.iter().map(|r| EnvAddress::new(*r)).collect(),
    }
}

fn known(addrs: &[&str]) -> std::collections::BTreeSet<String> {
    addrs.iter().map(|a| a.to_lowercase()).collect()
}

#[test]
fn with_the_policy_off_anything_goes() {
    assert_eq!(
        reply_only_allows(
            &cfg(r#"{"domain":{"a.test":{}}}"#),
            "alice@a.test",
            &envelope_to(&["stranger@x.test"]),
            &known(&[])
        ),
        Ok(())
    );
}

/// The point of the policy: an address handed out publicly cannot be used to
/// send cold mail.
#[test]
fn with_the_policy_on_only_people_who_wrote_first_can_be_written_to() {
    let cfg = cfg(r#"{"domain":{"a.test":{}},"reply_only_outbound":true}"#);
    assert_eq!(
        reply_only_allows(
            &cfg,
            "alice@a.test",
            &envelope_to(&["Bob@Other.test"]),
            &known(&["bob@other.test"])
        ),
        Ok(()),
        "matched case-insensitively"
    );
    assert_eq!(
        reply_only_allows(
            &cfg,
            "alice@a.test",
            &envelope_to(&["stranger@x.test"]),
            &known(&["bob@other.test"])
        ),
        Err("reply_only_outbound: stranger@x.test has not sent you a message".into())
    );
}

/// One unknown recipient refuses the whole submission. Sending to the known
/// ones and dropping the rest would tell the user their message went out when
/// part of it did not.
#[test]
fn one_unknown_recipient_refuses_the_whole_message() {
    assert!(
        reply_only_allows(
            &cfg(r#"{"domain":{"a.test":{}},"reply_only_outbound":true}"#),
            "alice@a.test",
            &envelope_to(&["bob@other.test", "stranger@x.test"]),
            &known(&["bob@other.test"])
        )
        .is_err()
    );
}

#[test]
fn an_exempt_sender_skips_the_check_entirely() {
    assert_eq!(
        reply_only_allows(
            &cfg(r#"{"domain":{"a.test":{}},"reply_only_outbound":true,
                    "reply_only_exempt":["alice@a.test"]}"#),
            "alice@a.test",
            &envelope_to(&["stranger@x.test"]),
            &known(&[])
        ),
        Ok(())
    );
}

// ── the stored copy ───────────────────────────────────────────────────────

/// Re-encrypting a body the client already sealed would only make it
/// unreadable to them — the relay has no business touching it.
#[test]
fn a_body_the_client_encrypted_is_marked_and_left_alone() {
    let body = format!("{PGP_MESSAGE_HEADER}\n\nabc\n-----END PGP MESSAGE-----");
    assert_eq!(stored_body(&body, true), StoredBody::AlreadyEncrypted);
    assert_eq!(
        stored_body(&body, false),
        StoredBody::AlreadyEncrypted,
        "and the account key is irrelevant to that"
    );
}

#[test]
fn a_plaintext_body_is_sealed_to_the_accounts_own_key() {
    assert_eq!(stored_body("hello", true), StoredBody::EncryptToAccountKey);
}

/// The case worth understanding rather than glossing: with no key on file the
/// relay stores plaintext. It has to keep *something* — otherwise the user
/// loses their sent mail — and it has nothing to seal it with. Uploading a
/// public key is what turns this off.
#[test]
fn with_no_account_key_the_stored_copy_is_plaintext() {
    assert_eq!(stored_body("hello", false), StoredBody::Plaintext);
}

/// The HTML alternative has to go **including its body value**. Go drops only
/// the references, leaving the plaintext on disk under a part id nothing points
/// at — see `seal_stored_body`'s header and SPEC.md §11.14.
#[test]
fn sealing_replaces_every_text_part_and_drops_the_html() {
    let mut msg = message("the plaintext");
    msg.text_body.push(BodyPart {
        part_id: "2".into(),
        ..Default::default()
    });
    msg.body_values
        .insert("2".into(), BodyValue::new("more plaintext"));
    msg.html_body = vec![BodyPart {
        part_id: "3".into(),
        ..Default::default()
    }];
    msg.body_values
        .insert("3".into(), BodyValue::new("<p>the plaintext</p>"));

    seal_stored_body(&mut msg, "CIPHERTEXT");

    assert_eq!(msg.body_values["1"].value, "CIPHERTEXT");
    assert_eq!(msg.body_values["2"].value, "CIPHERTEXT");
    assert!(msg.html_body.is_empty(), "the reference is gone");
    assert!(
        !msg.body_values.contains_key("3"),
        "and so is the value — a reference nobody holds still holds plaintext"
    );
    assert!(
        !serde_json::to_string(&msg)
            .unwrap()
            .contains("the plaintext"),
        "no part of the sealed message may still hold it: {msg:?}"
    );
}

/// The copy handed to SMTP keeps its plaintext: the recipient gets the real
/// message, and only what stays on the relay is sealed. Getting this wrong
/// sends ciphertext to someone with no key for it.
#[test]
fn sealing_the_stored_copy_does_not_touch_the_one_being_sent() {
    let outbound = message("the plaintext");
    let mut stored = outbound.clone();
    seal_stored_body(&mut stored, "CIPHERTEXT");

    assert_eq!(outbound.body_values["1"].value, "the plaintext");
    assert_eq!(stored.body_values["1"].value, "CIPHERTEXT");
}

// ── the envelope ──────────────────────────────────────────────────────────

#[test]
fn a_supplied_envelope_is_used_as_given() {
    let supplied = envelope_to(&["bob@other.test"]);
    assert_eq!(resolve_envelope(&Email::default(), &supplied), Ok(supplied));
}

#[test]
fn an_absent_envelope_is_derived_from_the_headers() {
    let msg = Email {
        from: vec![addr("alice@a.test")],
        to: vec![addr("bob@other.test")],
        ..Default::default()
    };
    let derived = resolve_envelope(&msg, &Envelope::default()).unwrap();
    assert_eq!(derived.mail_from.unwrap().email, "alice@a.test");
    assert_eq!(derived.rcpt_to[0].email, "bob@other.test");
}

/// Refused, not dropped. A message the client believes it sent, that nothing
/// was ever attempted for, is the worst available outcome.
#[test]
fn a_submission_with_no_recipients_is_refused() {
    assert_eq!(
        resolve_envelope(&Email::default(), &Envelope::default()),
        Err("no recipients".into())
    );
}

// ── after the send ────────────────────────────────────────────────────────

#[test]
fn the_activity_peer_is_the_joined_recipient_list() {
    assert_eq!(
        activity_peer(&envelope_to(&["a@x.test", "b@y.test"])),
        "a@x.test,b@y.test"
    );
    assert_eq!(activity_peer(&Envelope::default()), "");
}

/// The id the message actually went out with, brackets stripped, so the
/// client's threading matches what the recipient sees.
#[test]
fn the_sent_message_id_loses_its_brackets() {
    assert_eq!(
        sent_message_id("<abc@sender.test>"),
        Some("abc@sender.test".into())
    );
    assert_eq!(
        sent_message_id("abc@sender.test"),
        Some("abc@sender.test".into())
    );
    assert_eq!(sent_message_id(""), None);
    assert_eq!(sent_message_id("<>"), None, "brackets around nothing");
}
