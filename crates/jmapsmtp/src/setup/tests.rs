//! Onboarding. The token tests are the ones with teeth: a setup token is a
//! one-shot account-creation credential, and what happens to it after use
//! decides whether a leaked one is still worth anything.

use super::*;
use pretty_assertions::assert_eq;

fn cfg(json: &str) -> Config {
    serde_json::from_str(json).expect("config should parse")
}

fn two_accounts() -> Config {
    cfg(r#"{"domain":{"a.test":{"account":{"alice":{},"bob":{}}}}}"#)
}

/// A real envelope. Cheap KDF parameters — these tests are about the file and
/// the flow, not about Argon2.
fn envelope() -> (cryptenv::Envelope, Vec<u8>) {
    let kdf = cryptenv::KdfParams {
        time: 1,
        memory: 8,
        threads: 1,
    };
    let (env, _) = cryptenv::Envelope::new_with_kdf("passphrase", kdf).unwrap();
    let bytes = env.to_bytes().unwrap();
    (env, bytes)
}

// ── GET /auth/envelope ────────────────────────────────────────────────────

#[test]
fn an_envelope_is_served_to_anyone_who_asks_for_it() {
    let tmp = tempfile::tempdir().unwrap();
    let (env, bytes) = envelope();
    crate::auth_env::write_envelope(tmp.path(), "a.test", "alice", &env).unwrap();

    assert_eq!(
        read_envelope_for(
            &two_accounts(),
            &DynamicDomains::default(),
            tmp.path(),
            "alice@a.test"
        ),
        Ok(bytes.clone())
    );
    assert_eq!(
        read_envelope_for(
            &two_accounts(),
            &DynamicDomains::default(),
            tmp.path(),
            "ALICE@A.TEST"
        ),
        Ok(bytes),
        "folded"
    );
}

/// A dynamically provisioned account is not in the static config, but needs its
/// envelope for the client's add-account and login flows just as much.
#[test]
fn a_dynamic_accounts_envelope_is_served_too() {
    let tmp = tempfile::tempdir().unwrap();
    let (env, bytes) = envelope();
    crate::auth_env::write_envelope(tmp.path(), "a.test", "provisioned", &env).unwrap();

    assert_eq!(
        read_envelope_for(
            &cfg(r#"{"domain":{"a.test":{}}}"#),
            &DynamicDomains::default(),
            tmp.path(),
            "provisioned@a.test"
        ),
        Ok(bytes),
        "not in the config, and served anyway"
    );
}

#[test]
fn a_custom_domains_envelope_is_served() {
    let tmp = tempfile::tempdir().unwrap();
    let (env, _) = envelope();
    crate::auth_env::write_envelope(tmp.path(), "byo.test", "carol", &env).unwrap();

    let dynamic = DynamicDomains::default();
    assert_eq!(
        read_envelope_for(
            &cfg(r#"{"domain":{"a.test":{}}}"#),
            &dynamic,
            tmp.path(),
            "carol@byo.test"
        ),
        Err(SetupError::NotFound),
        "an unregistered domain is refused before any file is read"
    );

    dynamic.insert("byo.test".into(), Default::default());
    assert!(
        read_envelope_for(
            &cfg(r#"{"domain":{"a.test":{}}}"#),
            &dynamic,
            tmp.path(),
            "carol@byo.test"
        )
        .is_ok()
    );
}

#[test]
fn a_malformed_or_missing_email_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    for bad in ["", "alice", "  "] {
        assert_eq!(
            read_envelope_for(&two_accounts(), &DynamicDomains::default(), tmp.path(), bad),
            Err(SetupError::EmailRequired),
            "{bad:?}"
        );
    }
}

#[test]
fn an_account_with_no_envelope_is_not_found() {
    let tmp = tempfile::tempdir().unwrap();
    assert_eq!(
        read_envelope_for(
            &two_accounts(),
            &DynamicDomains::default(),
            tmp.path(),
            "alice@a.test"
        ),
        Err(SetupError::NotFound)
    );
}

/// Raw bytes, not a re-serialisation: the client compares what it uploaded, and
/// a reformat would hand back a file that differs from the one it sent.
#[test]
fn the_envelope_is_returned_byte_for_byte() {
    let tmp = tempfile::tempdir().unwrap();
    let (_, bytes) = envelope();
    let dir = crate::auth_env::account_dir(tmp.path(), "a.test", "alice");
    std::fs::create_dir_all(&dir).unwrap();
    // Written with extra whitespace, which a re-serialisation would strip.
    let spaced = format!("  {}  ", String::from_utf8(bytes).unwrap());
    std::fs::write(dir.join("envelope.json"), &spaced).unwrap();

    assert_eq!(
        read_envelope_for(
            &two_accounts(),
            &DynamicDomains::default(),
            tmp.path(),
            "alice@a.test"
        ),
        Ok(spaced.into_bytes())
    );
}

// ── PUT /auth/envelope ────────────────────────────────────────────────────

#[test]
fn a_rewrapped_envelope_replaces_the_stored_one() {
    let tmp = tempfile::tempdir().unwrap();
    let (old, _) = envelope();
    crate::auth_env::write_envelope(tmp.path(), "a.test", "alice", &old).unwrap();

    let (_, new_bytes) = envelope();
    assert_eq!(
        replace_envelope(tmp.path(), "a.test", "alice", &new_bytes),
        Ok(())
    );
    assert_eq!(
        read_envelope_for(
            &two_accounts(),
            &DynamicDomains::default(),
            tmp.path(),
            "alice@a.test"
        ),
        Ok(new_bytes)
    );
}

/// Validated before writing. An envelope that cannot be parsed back locks the
/// account out permanently — there is no other copy of the wrapped secret.
#[test]
fn an_unparseable_envelope_is_refused_and_the_old_one_survives() {
    let tmp = tempfile::tempdir().unwrap();
    let (old, old_bytes) = envelope();
    crate::auth_env::write_envelope(tmp.path(), "a.test", "alice", &old).unwrap();

    for bad in [&b""[..], b"not json", br#"{"v":99}"#] {
        assert_eq!(
            replace_envelope(tmp.path(), "a.test", "alice", bad),
            Err(SetupError::InvalidEnvelope),
            "{:?}",
            String::from_utf8_lossy(bad)
        );
    }
    assert_eq!(
        read_envelope_for(
            &two_accounts(),
            &DynamicDomains::default(),
            tmp.path(),
            "alice@a.test"
        ),
        Ok(old_bytes),
        "the account must not be locked out by a bad upload"
    );
}

// ── setup tokens ──────────────────────────────────────────────────────────

fn issue(cfg: &Config, data_dir: &std::path::Path) -> Vec<crate::startup::SetupInvite> {
    crate::startup::issue_setup_tokens(cfg, data_dir)
}

#[test]
fn a_token_resolves_to_the_account_it_was_issued_for() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = two_accounts();
    let invites = issue(&cfg, tmp.path());

    for invite in &invites {
        assert_eq!(
            account_for_token(&cfg, tmp.path(), &invite.token),
            Ok((invite.domain.clone(), invite.localpart.clone()))
        );
    }
}

#[test]
fn an_unknown_or_absent_token_resolves_to_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = two_accounts();
    issue(&cfg, tmp.path());

    assert_eq!(
        account_for_token(&cfg, tmp.path(), "not-a-token"),
        Err(SetupError::InvalidToken)
    );
    assert_eq!(
        account_for_token(&cfg, tmp.path(), ""),
        Err(SetupError::TokenRequired),
        "an empty token is a malformed request, not a wrong guess"
    );
}

/// An empty token must never match an account whose token file happens to be
/// empty or missing — which is what a plain `==` against a trimmed empty file
/// would do.
#[test]
fn an_empty_token_does_not_match_an_empty_token_file() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = two_accounts();
    let dir = crate::auth_env::account_dir(tmp.path(), "a.test", "alice");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("setup.token"), b"   \n").unwrap();

    assert_eq!(
        account_for_token(&cfg, tmp.path(), ""),
        Err(SetupError::TokenRequired)
    );
    assert_eq!(
        account_for_token(&cfg, tmp.path(), "  "),
        Err(SetupError::InvalidToken),
        "and neither does whitespace"
    );
}

// ── signup ────────────────────────────────────────────────────────────────

#[test]
fn a_signup_installs_the_envelope_and_burns_the_token() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = two_accounts();
    let invites = issue(&cfg, tmp.path());
    let invite = &invites[0];
    let (_, bytes) = envelope();

    assert_eq!(
        signup(&cfg, tmp.path(), &invite.token, &bytes),
        Ok((invite.domain.clone(), invite.localpart.clone()))
    );
    assert!(
        crate::auth_env::read_envelope(tmp.path(), &invite.domain, &invite.localpart).is_some()
    );
    assert!(
        !crate::startup::token_file(tmp.path(), &invite.domain, &invite.localpart).exists(),
        "the token is one-shot"
    );
    assert_eq!(
        account_for_token(&cfg, tmp.path(), &invite.token),
        Err(SetupError::InvalidToken),
        "and cannot be replayed"
    );
}

/// Non-idempotent on purpose: a replayed signup must not install a *different*
/// envelope over a claimed account, which would hand it to whoever replayed.
#[test]
fn a_signup_against_a_claimed_account_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = two_accounts();
    let invites = issue(&cfg, tmp.path());
    let invite = &invites[0];
    let (_, first) = envelope();
    signup(&cfg, tmp.path(), &invite.token, &first).unwrap();

    // Even with the token restored, a second signup is refused.
    std::fs::write(
        crate::startup::token_file(tmp.path(), &invite.domain, &invite.localpart),
        &invite.token,
    )
    .unwrap();
    let (_, second) = envelope();
    assert_eq!(
        signup(&cfg, tmp.path(), &invite.token, &second),
        Err(SetupError::AlreadyInitialized)
    );

    // The original envelope is untouched.
    assert_eq!(
        read_envelope_for(
            &cfg,
            &DynamicDomains::default(),
            tmp.path(),
            &format!("{}@{}", invite.localpart, invite.domain)
        ),
        Ok(first)
    );
}

/// The token is burned only after the envelope is written. The other order
/// leaves an account that can never be claimed if the write fails.
#[test]
fn a_failed_signup_leaves_the_token_usable() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = two_accounts();
    let invites = issue(&cfg, tmp.path());
    let invite = &invites[0];

    assert_eq!(
        signup(&cfg, tmp.path(), &invite.token, b"not an envelope"),
        Err(SetupError::InvalidEnvelope)
    );
    assert_eq!(
        account_for_token(&cfg, tmp.path(), &invite.token),
        Ok((invite.domain.clone(), invite.localpart.clone())),
        "a client that sent a bad body must be able to try again"
    );
}

#[test]
fn a_signup_with_no_token_is_refused_before_anything_is_read() {
    let tmp = tempfile::tempdir().unwrap();
    let (_, bytes) = envelope();
    assert_eq!(
        signup(&two_accounts(), tmp.path(), "", &bytes),
        Err(SetupError::TokenRequired)
    );
}

// ── relay-info ────────────────────────────────────────────────────────────

/// Public, so anything here is public to everyone. Four fields and no more.
#[test]
fn relay_info_carries_a_label_a_colour_and_what_the_relay_is() {
    let info = relay_info(&cfg(
        r##"{"domain":{"a.test":{}},"relay_label":"Biset","relay_color":"#123456"}"##,
    ));
    assert_eq!(
        serde_json::to_value(&info).unwrap(),
        serde_json::json!({"label": "Biset", "color": "#123456", "type": "mail"}),
        "no hostname, no domain list, no account count"
    );
}

/// `domain` is where a new account **actually lands**, which is not
/// necessarily this relay's hostname — so a client previewing
/// `username@<hostname>` before signup was wrong whenever the two differ.
#[test]
fn relay_info_names_the_domain_a_new_account_would_land_on() {
    let info = relay_info(&cfg(
        r#"{"domain":{"closed.test":{},"open.test":{"allow_provision":true}}}"#,
    ));
    assert_eq!(info.domain.as_deref(), Some("open.test"));
    assert_eq!(serde_json::to_value(&info).unwrap()["domain"], "open.test");
}

/// Absent, not empty, when nothing is open: a client showing `username@` with
/// a blank domain is worse than one that knows it cannot preview.
#[test]
fn relay_info_omits_the_domain_when_nothing_is_open() {
    let info = relay_info(&cfg(r#"{"domain":{"a.test":{}}}"#));
    assert_eq!(info.domain, None);
    assert!(
        serde_json::to_value(&info).unwrap().get("domain").is_none(),
        "omitted, not null"
    );
}

#[test]
fn relay_info_falls_back_to_the_defaults() {
    let info = relay_info(&cfg(r#"{"domain":{"a.test":{}}}"#));
    assert_eq!(info.label, "Mail");
    assert_eq!(info.color, "#64748b");
    assert_eq!(info.kind, "mail");
}

// ── statuses ──────────────────────────────────────────────────────────────

#[test]
fn each_error_carries_the_status_the_client_expects() {
    for (err, status) in [
        (SetupError::EmailRequired, 400),
        (SetupError::TokenRequired, 400),
        (SetupError::InvalidEnvelope, 400),
        (SetupError::Unauthorized, 401),
        (SetupError::InvalidToken, 401),
        (SetupError::NotFound, 404),
        (SetupError::AlreadyInitialized, 409),
    ] {
        assert_eq!(err.status(), status, "{err:?}");
    }
}
