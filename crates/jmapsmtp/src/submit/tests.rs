//! The submission pipeline, driven through the real JMAP surface.
//!
//! Nothing here reaches the network: the recipient domain has no MX and the
//! default resolver answers none, so every send fails. That is deliberate —
//! what is being checked is the **storage** half, which happens before the
//! send and is what the user keeps.

use super::*;
use crate::config::Config;
use pretty_assertions::assert_eq;

const PUBKEY: &str = include_str!("../../../../xtask/fixtures/pgp-public.asc");

/// Seeded rather than generated: an RSA-2048 keygen per test is slow, and
/// what is under test is the pipeline.
const DKIM_KEY: &str = include_str!("../../../../xtask/fixtures/dkim-key.pem");

fn relay(json: &str) -> Arc<RelayState> {
    let tmp = tempfile::tempdir().unwrap().keep();
    let cfg: Config = serde_json::from_str(json).expect("config should parse");
    std::fs::create_dir_all(tmp.join("a.test")).unwrap();
    std::fs::write(tmp.join("a.test/key.pem"), DKIM_KEY).unwrap();
    let state = RelayState::with_tokens(cfg, tmp, "", "");
    state.open_stores().expect("stores should open");
    state
}

fn one_account() -> Arc<RelayState> {
    relay(r#"{"domain":{"a.test":{"account":{"alice":{}}}},"hostname":"mx.a.test"}"#)
}

fn draft(body: &str) -> serde_json::Value {
    serde_json::json!({
        "from": [{"email": "alice@a.test"}],
        "to": [{"email": "bob@nonexistent.invalid"}],
        "subject": "hello",
        "keywords": {"$draft": true},
        "textBody": [{"partId": "1", "type": "text/plain"}],
        "htmlBody": [{"partId": "2", "type": "text/html"}],
        "bodyValues": {
            "1": {"value": body},
            "2": {"value": format!("<p>{body}</p>")},
        },
    })
}

/// Create then submit, through the store's own hooks.
async fn create_and_submit(state: &Arc<RelayState>, create: serde_json::Value) -> Email {
    let account = state.accounts.get("alice@a.test").unwrap();
    let raw = serde_json::value::RawValue::from_string(create.to_string()).unwrap();
    let hooks = account.store.hooks();

    let created = (hooks.create_email.as_ref().unwrap())(&raw).expect("create");
    (hooks.submit_email.as_ref().unwrap())(created.clone(), Default::default()).expect("submit");
    // The send is spawned; let it run and fail, so the activity line is
    // written before anything is asserted about it.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    created
}

// ── the stored copy ───────────────────────────────────────────────────────

/// With a key on file, the relay's own copy is sealed — it cannot read its
/// users' sent mail — and **nothing readable is left anywhere in the message**,
/// including the HTML alternative (SPEC.md §11.14).
#[tokio::test]
async fn a_sent_messages_stored_copy_is_sealed_with_no_readable_remains() {
    let state = one_account();
    let account = state.accounts.get("alice@a.test").unwrap();
    std::fs::write(account.dir.join("pubkey.pgp"), PUBKEY).unwrap();

    create_and_submit(&state, draft("the secret plaintext")).await;

    let stored = account.store.all();
    assert_eq!(stored.len(), 1);
    let json = serde_json::to_string(&stored[0]).unwrap();
    assert!(
        json.contains(crate::hooks::PGP_MESSAGE_HEADER),
        "the stored body is sealed: {json:.200}"
    );
    assert!(
        !json.contains("the secret plaintext"),
        "no part of the stored message may still hold the plaintext: {json}"
    );
    assert!(
        stored[0].html_body.is_empty(),
        "the readable alternative is gone"
    );
    assert!(
        !stored[0].keywords.contains_key(crate::hooks::KEYWORD_DRAFT),
        "a submitted message is not a draft"
    );
}

/// Without a key the copy is plaintext. The relay has to keep something —
/// otherwise the user loses their sent mail — and has nothing to seal it with.
#[tokio::test]
async fn with_no_account_key_the_stored_copy_stays_readable() {
    let state = one_account();
    create_and_submit(&state, draft("readable on the relay")).await;

    let stored = state.accounts.get("alice@a.test").unwrap().store.all();
    assert_eq!(
        stored[0].body_values["1"].value, "readable on the relay",
        "uploading a key is what turns this off"
    );
}

/// A body the client already sealed is marked and left alone — re-encrypting
/// it to the account's key would make it unreadable to the recipient's.
#[tokio::test]
async fn a_client_encrypted_body_is_marked_and_not_re_encrypted() {
    let state = one_account();
    let account = state.accounts.get("alice@a.test").unwrap();
    std::fs::write(account.dir.join("pubkey.pgp"), PUBKEY).unwrap();

    let ciphertext = format!(
        "{}\n\nZm9vYmFy\n-----END PGP MESSAGE-----\n",
        crate::hooks::PGP_MESSAGE_HEADER
    );
    create_and_submit(&state, draft(&ciphertext)).await;

    let stored = account.store.all();
    assert_eq!(
        stored[0].body_values["1"].value, ciphertext,
        "byte-identical"
    );
    assert_eq!(
        stored[0].keywords.get(crate::hooks::KEYWORD_E2E),
        Some(&true)
    );
}

// ── the outbound copy is a different object ───────────────────────────────

/// The recipient gets the plaintext; only what stays here is sealed. Getting
/// this wrong sends ciphertext to someone with no key for it.
///
/// Observed through the **wire bytes**, not the object handed in: asserting on
/// the input says nothing about what the send path received, and an earlier
/// version of this test passed while the sealed copy was being sent.
#[tokio::test]
async fn what_goes_on_the_wire_is_the_plaintext_and_what_is_stored_is_not() {
    let guard = crate::outbound::dump::guard().await;

    let state = relay(
        r#"{"domain":{"a.test":{"account":{"alice":{}}}},"hostname":"mx.a.test",
            "debug_dump_eml":true}"#,
    );
    let account = state.accounts.get("alice@a.test").unwrap();
    std::fs::write(account.dir.join("pubkey.pgp"), PUBKEY).unwrap();

    create_and_submit(&state, draft("the plaintext")).await;

    let sent = std::fs::read_to_string(crate::outbound::dump::PATH)
        .expect("the send path built a message");
    drop(guard);

    assert!(
        sent.contains("the plaintext"),
        "the recipient must get the readable message: {sent:.400}"
    );
    assert!(
        !sent.contains(crate::hooks::PGP_MESSAGE_HEADER),
        "the sealed copy must not be what goes out"
    );

    let stored = account.store.all();
    assert!(
        !serde_json::to_string(&stored[0])
            .unwrap()
            .contains("the plaintext"),
        "and the stored copy is sealed"
    );
}

// ── the create hook ───────────────────────────────────────────────────────

#[tokio::test]
async fn a_created_draft_gets_an_id_a_message_id_and_a_receive_time() {
    let state = one_account();
    let account = state.accounts.get("alice@a.test").unwrap();
    let raw = serde_json::value::RawValue::from_string(draft("hi").to_string()).unwrap();
    let created = (account.store.hooks().create_email.as_ref().unwrap())(&raw).unwrap();

    assert!(created.id.as_str().starts_with("srv-"), "{}", created.id);
    assert!(
        created.message_id[0].ends_with("@a.test"),
        "minted at creation so a client can quote it immediately: {:?}",
        created.message_id
    );
    assert!(created.received_at.is_some());

    // Held in memory only — an unsubmitted draft does not survive a restart.
    assert!(
        account.store.all().is_empty(),
        "a draft is pending, not stored"
    );
}

// ── the policies ──────────────────────────────────────────────────────────

/// An address handed out publicly cannot be used to send cold mail.
#[tokio::test]
async fn reply_only_outbound_refuses_a_stranger() {
    let state = relay(
        r#"{"domain":{"a.test":{"account":{"alice":{}}}},"hostname":"mx.a.test",
            "reply_only_outbound":true}"#,
    );
    let account = state.accounts.get("alice@a.test").unwrap();
    let raw = serde_json::value::RawValue::from_string(draft("hi").to_string()).unwrap();
    let hooks = account.store.hooks();
    let created = (hooks.create_email.as_ref().unwrap())(&raw).unwrap();

    let err = (hooks.submit_email.as_ref().unwrap())(created, Default::default())
        .expect_err("a stranger should be refused");
    assert!(err.contains("reply_only_outbound"), "{err}");
    assert!(
        account.store.all().is_empty(),
        "a refused submission stores nothing"
    );
}

#[tokio::test]
async fn submission_stops_at_the_storage_cap() {
    let state = relay(
        r#"{"domain":{"a.test":{"account":{"alice":{}}}},"hostname":"mx.a.test",
            "max_account_storage_mb":1}"#,
    );
    let account = state.accounts.get("alice@a.test").unwrap();
    std::fs::write(account.dir.join("big"), vec![0u8; 1024 * 1024]).unwrap();

    let raw = serde_json::value::RawValue::from_string(draft("hi").to_string()).unwrap();
    let err = (account.store.hooks().create_email.as_ref().unwrap())(&raw)
        .expect_err("the cap should refuse");
    assert!(err.contains("storage limit"), "{err}");
}

// ── what a failed send records ────────────────────────────────────────────

/// The send happens off the request, so its outcome surfaces in the activity
/// log rather than in the response. That is why the log exists.
///
/// The outcome here is `queued`, not `failed`: there is no MX and no resolver,
/// which is an ambiguous silence rather than a refusal, so the relay holds the
/// message. Neither metric counter moves — the message has no outcome yet, and
/// reporting one either way would be a guess. The retry loop counts it when it
/// knows.
#[tokio::test]
async fn a_deferred_send_is_recorded_and_the_message_is_still_stored() {
    let state = one_account();
    create_and_submit(&state, draft("hi")).await;

    let events =
        jmapserver::activity::read_activity(&state.data_dir, "a.test", "alice", 0).unwrap();
    assert_eq!(events.len(), 1, "one attempt recorded");
    assert_eq!(events[0].dir, "out");
    assert_eq!(events[0].peer, "bob@nonexistent.invalid");
    assert_eq!(
        events[0].result, "queued",
        "an ambiguous silence is held, not reported as a refusal"
    );

    assert_eq!(
        state
            .accounts
            .get("alice@a.test")
            .unwrap()
            .store
            .all()
            .len(),
        1,
        "the message is kept regardless — the user sent it"
    );
    assert_eq!(
        state.smtp_outbound(),
        (0, 0),
        "a held message is neither sent nor failed yet"
    );
    assert_eq!(
        crate::queue::load_all(&state.data_dir).len(),
        1,
        "the message the user sent is being held, not dropped"
    );
}
