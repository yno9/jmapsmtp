//! The build-and-sign pipeline.
//!
//! The order of the steps is the contract: each signs or wraps what the
//! previous produced. These pin that order by observing the finished bytes,
//! because a swap does not error — it silently produces a message that fails
//! verification at the far end.

use super::*;
use crate::config::Config;
use pretty_assertions::assert_eq;

const PUBKEY: &str = include_str!("../../../../xtask/fixtures/pgp-public.asc");

/// The shared throwaway DKIM key. Seeded rather than generated: an RSA-2048
/// keygen per test made this module take half a minute, and what is under test
/// is the pipeline, not the key generator.
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

fn message(body: &str) -> Email {
    serde_json::from_value(serde_json::json!({
        "from": [{"email": "alice@a.test"}],
        "to": [{"email": "bob@x.test"}],
        "subject": "hello",
        "textBody": [{"partId": "1", "type": "text/plain"}],
        "bodyValues": {"1": {"value": body}},
    }))
    .unwrap()
}

fn envelope() -> Envelope {
    Envelope {
        mail_from: Some(jmap_types::emailsubmission::Address::new("alice@a.test")),
        rcpt_to: vec![jmap_types::emailsubmission::Address::new("bob@x.test")],
    }
}

use super::dump::{PATH as DUMP_PATH, guard as dump_guard};

/// Build the wire bytes by running the pipeline with the dump enabled, which
/// is the only seam that exposes them without a listening MX.
async fn built_bytes(state: &Arc<RelayState>, msg: &Email) -> Vec<u8> {
    let guard = dump_guard().await;
    let account = state.accounts.get("alice@a.test").unwrap();
    let _ = send(state, &account, msg, &envelope()).await;
    let bytes = std::fs::read(DUMP_PATH).expect("the dump was enabled");
    drop(guard);
    bytes
}

fn dumping() -> Arc<RelayState> {
    relay(
        r#"{"domain":{"a.test":{"account":{"alice":{}}}},"hostname":"mx.a.test",
            "debug_dump_eml":true}"#,
    )
}

// ── refusals ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_submission_with_no_recipients_is_refused_before_anything_is_built() {
    let state = relay(r#"{"domain":{"a.test":{"account":{"alice":{}}}},"hostname":"mx.a.test"}"#);
    let account = state.accounts.get("alice@a.test").unwrap();
    let err = send(&state, &account, &message("hi"), &Envelope::default())
        .await
        .expect_err("no recipients");
    assert_eq!(err, "no recipients");
}

/// With no resolver installed there are no exchangers, so a direct send fails
/// rather than going somewhere unintended.
#[tokio::test]
async fn a_send_with_no_resolver_fails_rather_than_guessing() {
    let state = relay(r#"{"domain":{"a.test":{"account":{"alice":{}}}},"hostname":"mx.a.test"}"#);
    let account = state.accounts.get("alice@a.test").unwrap();
    assert!(
        send(&state, &account, &message("hi"), &envelope())
            .await
            .is_err()
    );
}

// ── the order of the steps ────────────────────────────────────────────────

/// DKIM signs last. A header added after it invalidates the signature, so the
/// `DKIM-Signature` has to sit above the headers it covers.
#[tokio::test]
async fn the_dkim_signature_is_added_last() {
    let state = dumping();
    let raw = built_bytes(&state, &message("hi")).await;
    let text = String::from_utf8_lossy(&raw);

    assert!(
        text.starts_with("DKIM-Signature:"),
        "prepended to the finished message: {text:.120}"
    );
    // …and it covers the headers the pipeline added before it.
    assert!(text.contains("Chat-Version:"), "{text:.400}");
}

#[tokio::test]
async fn the_chat_version_header_is_added() {
    let state = dumping();
    let raw = built_bytes(&state, &message("hi")).await;
    assert!(String::from_utf8_lossy(&raw).contains("Chat-Version: 1.0"));
}

/// The sender's key is advertised when there is one, and the header is absent
/// when there is not — an Autocrypt header with no key is worse than none.
#[tokio::test]
async fn the_autocrypt_header_appears_only_with_a_key_on_file() {
    let state = dumping();
    let raw = built_bytes(&state, &message("hi")).await;
    assert!(
        !String::from_utf8_lossy(&raw).contains("Autocrypt:"),
        "no key on file, so nothing to advertise"
    );

    let account = state.accounts.get("alice@a.test").unwrap();
    std::fs::write(account.dir.join("pubkey.pgp"), PUBKEY).unwrap();
    let raw = built_bytes(&state, &message("hi")).await;
    let text = String::from_utf8_lossy(&raw);
    assert!(text.contains("Autocrypt:"), "{text:.300}");
    assert!(text.contains("addr=alice@a.test"), "{text:.300}");
}

/// A client-encrypted body travels as structured PGP/MIME rather than as text
/// that happens to look like ciphertext.
#[tokio::test]
async fn a_client_encrypted_body_is_wrapped_as_pgp_mime() {
    let state = dumping();
    let ciphertext = format!(
        "{}\n\nZm9vYmFy\n-----END PGP MESSAGE-----\n",
        crate::hooks::PGP_MESSAGE_HEADER
    );
    let raw = built_bytes(&state, &message(&ciphertext)).await;
    let text = String::from_utf8_lossy(&raw);
    assert!(
        text.contains("multipart/encrypted"),
        "wrapped per RFC 3156: {text:.400}"
    );
    assert!(text.contains("application/pgp-encrypted"), "{text:.400}");
}

/// A body whose markers do not form a complete block is sent as-is. In Go this
/// case panics and takes the process down — SPEC.md §11.11.
#[tokio::test]
async fn a_body_with_reversed_pgp_markers_is_sent_unwrapped() {
    let state = dumping();
    let reversed = format!(
        "-----END PGP MESSAGE-----\nnot a block\n{}\n",
        crate::hooks::PGP_MESSAGE_HEADER
    );
    let raw = built_bytes(&state, &message(&reversed)).await;
    let text = String::from_utf8_lossy(&raw);
    assert!(
        !text.contains("multipart/encrypted"),
        "not wrapped, and not a panic"
    );
}

// ── the debug dump ────────────────────────────────────────────────────────

/// Off unless asked for: the file holds plaintext mail. SPEC.md §11.1.
#[tokio::test]
async fn the_debug_dump_is_off_by_default() {
    let guard = dump_guard().await;

    let state = relay(r#"{"domain":{"a.test":{"account":{"alice":{}}}},"hostname":"mx.a.test"}"#);
    let account = state.accounts.get("alice@a.test").unwrap();
    let _ = send(&state, &account, &message("hi"), &envelope()).await;

    let existed = std::path::Path::new(DUMP_PATH).exists();
    drop(guard);
    assert!(!existed, "no dump without debug_dump_eml");
}

#[tokio::test]
async fn the_debug_dump_is_written_owner_only() {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let guard = dump_guard().await;
        let state = dumping();
        let account = state.accounts.get("alice@a.test").unwrap();
        let _ = send(&state, &account, &message("hi"), &envelope()).await;
        let mode = std::fs::metadata(DUMP_PATH).unwrap().permissions().mode();
        drop(guard);
        assert_eq!(mode & 0o777, 0o600, "it is plaintext mail");
    }
}
