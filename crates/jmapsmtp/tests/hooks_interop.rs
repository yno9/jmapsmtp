//! The two store hooks, driven through the oracle's real JMAP API.
//!
//! `Email/set create` and `EmailSubmission/set create` are where the relay does
//! everything a plain JMAP server would not, and the results land on disk. So
//! rather than compare functions, this drives the endpoint and reads what the
//! oracle stored — which is what a client and the next process see.
//!
//! The test worth reading first is the stored-copy one. When an account has a
//! public key on file, the relay seals its own copy of every message the
//! account sends, so the relay cannot read its users' sent mail. When there is
//! no key it stores plaintext, because losing the mail is worse — and that
//! difference is only visible on disk.

use std::path::Path;

use jmapsmtp::hooks::{PGP_MESSAGE_HEADER, StoredBody, stored_body};

mod oracle_harness;
use oracle_harness::Oracle;

/// The static credential, seeded so both sides agree. `auth_token_hash` on
/// disk is base64(sha256(this)); the Basic password is base64(this).
const AUTH_TOKEN: &[u8] = b"hooks-interop-token-000000000000";

fn basic_auth() -> String {
    use base64::Engine as _;
    let password = base64::engine::general_purpose::STANDARD.encode(AUTH_TOKEN);
    base64::engine::general_purpose::STANDARD.encode(format!("alice@a.test:{password}"))
}

fn config_json(http_port: u16, smtp_port: u16) -> String {
    format!(
        r#"{{"listen_addr":"127.0.0.1:{http_port}","smtp_port":{smtp_port},
            "base_url":"http://127.0.0.1:{http_port}","hostname":"t.invalid",
            "domain":{{"a.test":{{"account":{{"alice":{{}},"nokey":{{}}}}}}}}}}"#
    )
}

/// The account's own OpenPGP public key, from the shared fixtures.
const PUBKEY: &str = include_str!("../../../xtask/fixtures/pgp-public.asc");

fn seed(root: &Path) {
    let acct = root.join("data/a.test/alice");
    std::fs::create_dir_all(&acct).unwrap();
    std::fs::write(
        acct.join("auth_token_hash"),
        jmapserver::hash_auth_token(AUTH_TOKEN),
    )
    .unwrap();
    // Only `alice` gets a key, so one boot covers both stored-copy branches.
    std::fs::write(acct.join("pubkey.pgp"), PUBKEY).unwrap();

    let nokey = root.join("data/a.test/nokey");
    std::fs::create_dir_all(&nokey).unwrap();
    std::fs::write(
        nokey.join("auth_token_hash"),
        jmapserver::hash_auth_token(AUTH_TOKEN),
    )
    .unwrap();
}

fn oracle() -> Option<Oracle> {
    Oracle::start_with("HOOKS_INTEROP", config_json, seed)
}

/// One JMAP request, as the account.
fn jmap(o: &Oracle, calls: serde_json::Value) -> serde_json::Value {
    let body = serde_json::json!({
        "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
        "methodCalls": calls,
    })
    .to_string();
    let (status, response) = o.post_json_auth("/jmap/api/", &body, &basic_auth());
    assert_eq!(status, 200, "JMAP request failed: {response}");
    serde_json::from_str(&response).unwrap_or_else(|e| panic!("{e}: {response}"))
}

fn create_draft(o: &Oracle, account: &str, create: serde_json::Value) -> serde_json::Value {
    let res = jmap(
        o,
        serde_json::json!([[
            "Email/set",
            {"accountId": account, "create": {"draft1": create}},
            "c0"
        ]]),
    );
    res["methodResponses"][0][1]["created"]["draft1"].clone()
}

/// Submit a created draft. The send fails (no MX for the recipient), which is
/// what keeps the stored copy showing what the hooks did rather than what SMTP
/// reported back.
fn submit(o: &Oracle, account: &str, email_id: &str) {
    jmap(
        o,
        serde_json::json!([[
            "EmailSubmission/set",
            {"accountId": account,
             "create": {"sub1": {"emailId": email_id, "identityId": account}}},
            "c0"
        ]]),
    );
}

/// Every stored message file for an account.
fn stored_messages(data_dir: &Path, localpart: &str) -> Vec<serde_json::Value> {
    let dir = data_dir.join("a.test").join(localpart).join("messages");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut out: Vec<(String, serde_json::Value)> = entries
        .flatten()
        .filter(|e| e.path().extension().is_some_and(|x| x == "json"))
        .filter_map(|e| {
            let bytes = std::fs::read(e.path()).ok()?;
            Some((
                e.file_name().to_string_lossy().into_owned(),
                serde_json::from_slice(&bytes).ok()?,
            ))
        })
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out.into_iter().map(|(_, v)| v).collect()
}

fn body_of(msg: &serde_json::Value) -> String {
    let part = msg["textBody"][0]["partId"].as_str().unwrap_or("1");
    msg["bodyValues"][part]["value"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

// ── Email/set create ──────────────────────────────────────────────────────

/// **A created draft is held in memory only.** `PutPending` does not write to
/// disk (`go-jmapserver/store.go`: "stores a draft Email in memory only"), so
/// an unsubmitted draft does not survive a restart.
///
/// Found by writing this suite: the first version read the draft back off disk
/// and found nothing there. Pinned rather than worked around, because it is the
/// reason the create hook can afford to mint a Message-ID eagerly — a draft is
/// the client's state, and the relay only holds it between create and submit.
#[test]
fn a_created_draft_is_not_written_to_disk() {
    let Some(o) = oracle() else { return };

    let created = create_draft(
        &o,
        "alice@a.test",
        serde_json::json!({
            "subject": "hello",
            "textBody": [{"partId": "1", "type": "text/plain"}],
            "bodyValues": {"1": {"value": "hi there"}},
        }),
    );
    assert!(created["id"].as_str().is_some(), "created: {created:?}");
    assert!(
        stored_messages(&o.data_dir(), "alice").is_empty(),
        "a draft is pending, not stored — it is lost on restart"
    );
}

/// What the create hook fills in that the client did not send.
///
/// Observed through a submission, because that is the only place it becomes
/// visible: the draft is memory-only (above) and `Email/set` returns just the
/// id. The submit path only rewrites `messageId` on a *successful* send, and
/// this recipient has no MX, so what lands on disk is what the create hook
/// minted.
#[test]
fn the_create_hook_fills_in_what_the_client_omitted() {
    let Some(o) = oracle() else { return };

    let created = create_draft(
        &o,
        "alice@a.test",
        serde_json::json!({
            "from": [{"email": "alice@a.test"}],
            "to": [{"email": "bob@nonexistent.invalid"}],
            "subject": "hello",
            "keywords": {"$draft": true},
            "textBody": [{"partId": "1", "type": "text/plain"}],
            "bodyValues": {"1": {"value": "hi there"}},
            "header:X-Ticket:asText": "  ABC-1  ",
        }),
    );
    let id = created["id"]
        .as_str()
        .expect("an id was minted")
        .to_string();
    assert!(id.starts_with("srv-"), "{id}");

    submit(&o, "alice@a.test", &id);
    let stored = &stored_messages(&o.data_dir(), "alice")[0];

    // Minted at creation, not at send, so a client can quote it as In-Reply-To
    // on its next message without waiting for delivery.
    let mid = stored["messageId"][0]
        .as_str()
        .unwrap_or_else(|| panic!("a Message-ID: {stored:?}"));
    assert!(mid.ends_with("@a.test"), "{mid}");
    assert!(!mid.starts_with('<'), "stored without brackets: {mid}");

    assert!(
        stored["receivedAt"]
            .as_str()
            .is_some_and(|t| t.contains('T')),
        "receivedAt: {stored:?}"
    );

    // The custom header, trimmed.
    let headers = stored["headers"].as_array().expect("headers");
    assert!(
        headers
            .iter()
            .any(|h| h["name"] == "X-Ticket" && h["value"] == "ABC-1"),
        "{headers:?}"
    );

    // This port agrees on what needed filling in, and on the trimming.
    let defaults = jmapsmtp::hooks::draft_defaults(&Default::default(), "a.test");
    assert!(defaults.id.is_some() && defaults.rfc_message_id.is_some());
    assert_eq!(
        jmapsmtp::handler::extract_text_headers(&serde_json::json!({
            "header:X-Ticket:asText": "  ABC-1  "
        })),
        [("X-Ticket".to_string(), "ABC-1".to_string())]
    );
}

/// What the client did supply is kept, so a draft does not silently change
/// identity on its way through the relay.
#[test]
fn a_client_supplied_message_id_is_kept() {
    let Some(o) = oracle() else { return };
    let created = create_draft(
        &o,
        "alice@a.test",
        serde_json::json!({
            "from": [{"email": "alice@a.test"}],
            "to": [{"email": "bob@nonexistent.invalid"}],
            "keywords": {"$draft": true},
            "messageId": ["mine@elsewhere.test"],
            "textBody": [{"partId": "1", "type": "text/plain"}],
            "bodyValues": {"1": {"value": "hi"}},
        }),
    );
    submit(&o, "alice@a.test", created["id"].as_str().unwrap());

    let stored = &stored_messages(&o.data_dir(), "alice")[0];
    assert_eq!(stored["messageId"][0], "mine@elsewhere.test");

    let supplied = jmap_types::email::Email {
        message_id: vec!["mine@elsewhere.test".into()],
        ..Default::default()
    };
    assert!(
        jmapsmtp::hooks::draft_defaults(&supplied, "a.test")
            .rfc_message_id
            .is_none(),
        "this port leaves it alone too"
    );
}

// ── EmailSubmission/set create: the stored copy ───────────────────────────

/// With a public key on file, the relay's own copy of a sent message is
/// sealed — the relay cannot read its users' sent mail.
///
/// The send itself fails here (there is no MX for the recipient), which is the
/// point: sealing happens on the storage path, before and independently of
/// delivery.
#[test]
fn a_sent_messages_stored_copy_is_encrypted_when_the_account_has_a_key() {
    let Some(o) = oracle() else { return };

    let created = create_draft(
        &o,
        "alice@a.test",
        serde_json::json!({
            "from": [{"email": "alice@a.test"}],
            "to": [{"email": "bob@nonexistent.invalid"}],
            "subject": "sealed",
            "keywords": {"$draft": true},
            // An HTML alternative on purpose. Sealing only the text part would
            // leave a readable copy of the same message beside the encrypted
            // one — worse than not encrypting, because it looks protected.
            "textBody": [{"partId": "1", "type": "text/plain"}],
            "htmlBody": [{"partId": "2", "type": "text/html"}],
            "bodyValues": {
                "1": {"value": "the secret plaintext"},
                "2": {"value": "<p>the secret plaintext</p>"},
            },
        }),
    );
    let email_id = created["id"].as_str().unwrap().to_string();

    submit(&o, "alice@a.test", &email_id);

    let stored = &stored_messages(&o.data_dir(), "alice")[0];
    let body = body_of(stored);

    assert!(
        body.starts_with(PGP_MESSAGE_HEADER),
        "the stored copy should be sealed, got: {body:.120}"
    );
    assert!(
        !body.contains("the secret plaintext"),
        "the plaintext must not survive anywhere in the stored body"
    );
    assert!(
        stored["htmlBody"].as_array().is_none_or(|v| v.is_empty()),
        "the HTML reference must be gone: {stored:?}"
    );

    // $draft is cleared: a submitted message is not a draft.
    assert!(
        stored["keywords"]["$draft"].is_null(),
        "keywords: {:?}",
        stored["keywords"]
    );

    assert_eq!(
        stored_body("the secret plaintext", true),
        StoredBody::EncryptToAccountKey,
        "this port decides the same way"
    );

    // ── the declared divergence, SPEC.md §11.14 ──
    //
    // Go drops the htmlBody *references* and leaves the HTML part's value in
    // bodyValues, so the plaintext is still on disk under a part id nothing
    // points at. Asserted as a difference so the fix cannot be lost: if the Go
    // side is ever fixed, this fails and says the divergence is stale rather
    // than letting a regression pass as a match.
    assert!(
        serde_json::to_string(stored)
            .unwrap()
            .contains("the secret plaintext"),
        "the oracle is expected to still leak the HTML plaintext — if it no \
         longer does, SPEC.md §11.14 is stale: {stored:?}"
    );

    // The same message, sealed by this port, keeps nothing readable.
    let mut ours: jmap_types::email::Email = serde_json::from_value(serde_json::json!({
        "textBody": [{"partId": "1", "type": "text/plain"}],
        "htmlBody": [{"partId": "2", "type": "text/html"}],
        "bodyValues": {
            "1": {"value": "the secret plaintext"},
            "2": {"value": "<p>the secret plaintext</p>"},
        },
    }))
    .unwrap();
    jmapsmtp::hooks::seal_stored_body(&mut ours, "CIPHERTEXT");
    assert!(
        !serde_json::to_string(&ours)
            .unwrap()
            .contains("the secret plaintext"),
        "this port leaves no readable copy: {ours:?}"
    );
}

/// With no key on file the stored copy is plaintext. The relay has to keep
/// something — otherwise the user loses their sent mail — and has nothing to
/// seal it with. Only visible on disk, so only checkable here.
#[test]
fn with_no_account_key_the_stored_copy_stays_plaintext() {
    let Some(o) = oracle() else { return };

    let created = create_draft(
        &o,
        "nokey@a.test",
        serde_json::json!({
            "from": [{"email": "nokey@a.test"}],
            "to": [{"email": "bob@nonexistent.invalid"}],
            "keywords": {"$draft": true},
            "textBody": [{"partId": "1", "type": "text/plain"}],
            "bodyValues": {"1": {"value": "readable on the relay"}},
        }),
    );
    let email_id = created["id"].as_str().unwrap().to_string();

    submit(&o, "nokey@a.test", &email_id);

    let body = body_of(&stored_messages(&o.data_dir(), "nokey")[0]);
    assert_eq!(body, "readable on the relay");
    assert_eq!(
        stored_body("readable on the relay", false),
        StoredBody::Plaintext,
        "this port decides the same way — and this is why uploading a key matters"
    );
}

/// A body the client already sealed is marked and left alone. Re-encrypting it
/// to the account's key would make it unreadable to the recipient's.
#[test]
fn a_body_the_client_encrypted_is_marked_and_not_re_encrypted() {
    let Some(o) = oracle() else { return };

    let ciphertext = format!("{PGP_MESSAGE_HEADER}\n\nZm9vYmFy\n-----END PGP MESSAGE-----\n");
    let created = create_draft(
        &o,
        "alice@a.test",
        serde_json::json!({
            "from": [{"email": "alice@a.test"}],
            "to": [{"email": "bob@nonexistent.invalid"}],
            "keywords": {"$draft": true},
            "textBody": [{"partId": "1", "type": "text/plain"}],
            "bodyValues": {"1": {"value": ciphertext}},
        }),
    );
    let email_id = created["id"].as_str().unwrap().to_string();

    submit(&o, "alice@a.test", &email_id);

    let stored = &stored_messages(&o.data_dir(), "alice")[0];
    assert_eq!(body_of(stored), ciphertext, "byte-identical, not re-sealed");
    assert_eq!(
        stored["keywords"]["$e2e"], true,
        "and marked: {:?}",
        stored["keywords"]
    );
    assert_eq!(
        stored_body(&ciphertext, true),
        StoredBody::AlreadyEncrypted,
        "this port decides the same way"
    );
}
