//! Onboarding, against the oracle: `/auth/envelope`, `/auth/signup`,
//! `/relay-info`.
//!
//! `GET /auth/envelope` is unauthenticated by design, and `POST /auth/signup`
//! turns a token into an account's first credential — so both are reachable by
//! anyone who can open the port, and their exact answers are the boundary.

use base64::Engine as _;
use jmapsmtp::setup::{SetupError, account_for_token, read_envelope_for, relay_info};

mod oracle_harness;
use oracle_harness::Oracle;

fn config_json(http_port: u16, smtp_port: u16) -> String {
    format!(
        r##"{{"listen_addr":"127.0.0.1:{http_port}","smtp_port":{smtp_port},
            "base_url":"http://127.0.0.1:{http_port}","hostname":"t.invalid",
            "relay_label":"Biset","relay_color":"#123456",
            "domain":{{"a.test":{{"account":{{"alice":{{}},"bob":{{}}}}}}}}}}"##
    )
}

fn rust_config() -> jmapsmtp::config::Config {
    serde_json::from_str(&config_json(1, 1)).unwrap()
}

fn oracle() -> Option<Oracle> {
    Oracle::start_with("SETUP_INTEROP", config_json, |_| {})
}

/// A real envelope, built with cheap KDF parameters.
fn envelope_bytes() -> Vec<u8> {
    let kdf = cryptenv::KdfParams {
        time: 1,
        memory: 8,
        threads: 1,
    };
    let (env, _) = cryptenv::Envelope::new_with_kdf("passphrase", kdf).unwrap();
    env.to_bytes().unwrap()
}

/// The setup token the oracle issued for an account at startup.
fn token_for(o: &Oracle, localpart: &str) -> String {
    std::fs::read_to_string(
        o.data_dir()
            .join("a.test")
            .join(localpart)
            .join("setup.token"),
    )
    .unwrap_or_else(|e| panic!("the oracle should have issued a token for {localpart}: {e}"))
}

// ── relay-info ────────────────────────────────────────────────────────────

/// Shown on a login screen before there is any credential. The property worth
/// keeping is that it carries *nothing else* — no hostname, no domain list, no
/// account count.
#[test]
fn relay_info_is_public_and_carries_only_a_label_and_a_colour() {
    let Some(o) = oracle() else { return };
    let (status, body, _) = o.get("/relay-info");
    assert_eq!(status, 200);

    let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        parsed,
        serde_json::json!({"label": "Biset", "color": "#123456", "type": "mail"}),
        "the oracle exposes a field this port does not"
    );
    assert_eq!(
        serde_json::to_value(relay_info(&rust_config())).unwrap(),
        parsed,
        "this port answers the same"
    );
}

/// `domain` names where a new account lands, and is absent when nothing is
/// open. A separate boot, because it depends on the config rather than the
/// request.
#[test]
fn relay_info_names_the_provisioning_domain_when_there_is_one() {
    fn open_config(http_port: u16, smtp_port: u16) -> String {
        format!(
            r##"{{"listen_addr":"127.0.0.1:{http_port}","smtp_port":{smtp_port},
                "base_url":"http://127.0.0.1:{http_port}","hostname":"t.invalid",
                "relay_label":"Biset","relay_color":"#123456",
                "domain":{{"closed.test":{{}},"open.test":{{"allow_provision":true}}}}}}"##
        )
    }
    let Some(o) = Oracle::start_with("SETUP_INTEROP", open_config, |_| {}) else {
        return;
    };
    let (status, body, _) = o.get("/relay-info");
    assert_eq!(status, 200);
    let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(parsed["domain"], "open.test");

    let cfg: jmapsmtp::config::Config = serde_json::from_str(&open_config(1, 1)).unwrap();
    assert_eq!(
        serde_json::to_value(relay_info(&cfg)).unwrap(),
        parsed,
        "this port answers the same"
    );
}

// ── GET /auth/envelope ────────────────────────────────────────────────────

#[test]
fn a_missing_or_malformed_email_is_refused_the_same_way() {
    let Some(o) = oracle() else { return };
    for target in [
        "/auth/envelope",
        "/auth/envelope?email=",
        "/auth/envelope?email=alice",
    ] {
        let (status, body, _) = o.get(target);
        assert_eq!(status, 400, "{target}: {body:?}");
        assert_eq!(SetupError::EmailRequired.message(), body.trim());
    }
}

#[test]
fn an_unknown_domain_and_an_account_with_no_envelope_are_both_not_found() {
    let Some(o) = oracle() else { return };
    for target in [
        "/auth/envelope?email=alice@nope.test",
        "/auth/envelope?email=alice@a.test",
        "/auth/envelope?email=nobody@a.test",
    ] {
        let (status, _, _) = o.get(target);
        assert_eq!(status, 404, "{target}");
    }
}

// ── signup, and what the token is worth afterwards ────────────────────────

/// The whole onboarding path, and then the two replays that must fail.
#[test]
fn a_signup_claims_the_account_and_the_token_is_then_worthless() {
    let Some(o) = oracle() else { return };
    let token = token_for(&o, "alice");
    assert_eq!(token.len(), 32, "16 random bytes as hex");
    assert_eq!(
        account_for_token(&rust_config(), &o.data_dir(), &token),
        Ok(("a.test".into(), "alice".into())),
        "this port resolves the oracle's token to the same account"
    );

    let envelope = envelope_bytes();
    let (status, body) = o.post_json(
        &format!("/auth/signup?token={token}"),
        &String::from_utf8(envelope.clone()).unwrap(),
    );
    assert_eq!(status, 204, "{body:?}");

    // The envelope is now served, byte for byte, to anyone who asks — which is
    // the point: the client needs it before it has a credential, and it is
    // inert without the password.
    let (status, served, _) = o.get("/auth/envelope?email=alice@a.test");
    assert_eq!(status, 200);
    assert_eq!(served.as_bytes(), &envelope[..], "byte for byte");
    assert_eq!(
        read_envelope_for(
            &rust_config(),
            &jmapsmtp::config::DynamicDomains::default(),
            &o.data_dir(),
            "alice@a.test"
        ),
        Ok(envelope.clone()),
        "this port reads the same bytes"
    );

    // The token is burned.
    assert!(
        !o.data_dir().join("a.test/alice/setup.token").exists(),
        "a setup token is one-shot"
    );
    assert_eq!(
        account_for_token(&rust_config(), &o.data_dir(), &token),
        Err(SetupError::InvalidToken)
    );

    // Replaying it is refused…
    let (status, _) = o.post_json(
        &format!("/auth/signup?token={token}"),
        &String::from_utf8(envelope_bytes()).unwrap(),
    );
    assert_eq!(status, SetupError::InvalidToken.status());

    // …and so is a signup against the claimed account even if the token were
    // somehow restored. A replay must not install a DIFFERENT envelope over a
    // claimed account, which would hand it to whoever replayed.
    std::fs::write(o.data_dir().join("a.test/alice/setup.token"), &token).unwrap();
    let other = envelope_bytes();
    let (status, _) = o.post_json(
        &format!("/auth/signup?token={token}"),
        &String::from_utf8(other).unwrap(),
    );
    assert_eq!(status, SetupError::AlreadyInitialized.status());

    let (_, still, _) = o.get("/auth/envelope?email=alice@a.test");
    assert_eq!(
        still.as_bytes(),
        &envelope[..],
        "the original envelope must survive the replay"
    );
}

/// The same sequence, run by **this port's** `signup` against the oracle's own
/// data directory, on a second account the oracle has not touched.
///
/// The test above drives only the oracle, so it says nothing about whether this
/// port agrees — mutating `signup` left it green. Running both against the same
/// on-disk state, and asserting the same outcomes, is what makes the comparison
/// real.
#[test]
fn this_ports_signup_reaches_the_same_state_the_oracles_did() {
    let Some(o) = oracle() else { return };
    let data = o.data_dir();
    let cfg = rust_config();

    // The oracle claims alice…
    let alice_token = token_for(&o, "alice");
    let alice_env = envelope_bytes();
    let (status, _) = o.post_json(
        &format!("/auth/signup?token={alice_token}"),
        &String::from_utf8(alice_env.clone()).unwrap(),
    );
    assert_eq!(status, 204);

    // …and this port claims bob, the same way.
    let bob_token = token_for(&o, "bob");
    let bob_env = envelope_bytes();
    assert_eq!(
        jmapsmtp::setup::signup(&cfg, &data, &bob_token, &bob_env),
        Ok(("a.test".into(), "bob".into()))
    );

    // Both accounts are now in the same shape, checked through the oracle's own
    // HTTP surface — so this port's write is one the running Go binary reads.
    for (localpart, env) in [("alice", &alice_env), ("bob", &bob_env)] {
        let (status, served, _) = o.get(&format!("/auth/envelope?email={localpart}@a.test"));
        assert_eq!(status, 200, "{localpart}");
        assert_eq!(served.as_bytes(), &env[..], "{localpart}");
        assert!(
            !data
                .join("a.test")
                .join(localpart)
                .join("setup.token")
                .exists(),
            "{localpart}: the token should be burned"
        );
    }

    // And the same refusals, in both directions.
    assert_eq!(
        jmapsmtp::setup::signup(&cfg, &data, &bob_token, &envelope_bytes()),
        Err(SetupError::InvalidToken),
        "this port refuses the replay the oracle refuses"
    );
    std::fs::write(data.join("a.test/bob/setup.token"), &bob_token).unwrap();
    assert_eq!(
        jmapsmtp::setup::signup(&cfg, &data, &bob_token, &envelope_bytes()),
        Err(SetupError::AlreadyInitialized),
        "and refuses a signup over a claimed account, as the oracle does"
    );
    let (status, _) = o.post_json(
        &format!("/auth/signup?token={bob_token}"),
        &String::from_utf8(envelope_bytes()).unwrap(),
    );
    assert_eq!(
        status,
        SetupError::AlreadyInitialized.status(),
        "the oracle agrees on the account this port claimed"
    );

    // A bad body leaves the token usable, on this port as on the oracle.
    std::fs::remove_file(data.join("a.test/bob/envelope.json")).unwrap();
    assert_eq!(
        jmapsmtp::setup::signup(&cfg, &data, &bob_token, b"not an envelope"),
        Err(SetupError::InvalidEnvelope)
    );
    assert_eq!(
        account_for_token(&cfg, &data, &bob_token),
        Ok(("a.test".into(), "bob".into())),
        "a client that sent a bad body must be able to try again"
    );
}

#[test]
fn a_signup_with_a_wrong_or_missing_token_is_refused() {
    let Some(o) = oracle() else { return };
    let body = String::from_utf8(envelope_bytes()).unwrap();

    let (status, b) = o.post_json("/auth/signup", &body);
    assert_eq!(status, SetupError::TokenRequired.status(), "{b:?}");
    assert_eq!(SetupError::TokenRequired.message(), b.trim());

    let (status, b) = o.post_json("/auth/signup?token=not-a-real-token", &body);
    assert_eq!(status, SetupError::InvalidToken.status());
    assert_eq!(SetupError::InvalidToken.message(), b.trim());
}

/// A bad body must leave the token usable — the other order strands an account
/// that can never be claimed.
#[test]
fn a_signup_with_an_unparseable_envelope_leaves_the_token_usable() {
    let Some(o) = oracle() else { return };
    let token = token_for(&o, "bob");

    let (status, _) = o.post_json(&format!("/auth/signup?token={token}"), "not an envelope");
    assert_eq!(status, SetupError::InvalidEnvelope.status());
    assert!(
        o.data_dir().join("a.test/bob/setup.token").exists(),
        "a client that sent a bad body must be able to try again"
    );

    // …and it does work on the retry.
    let (status, _) = o.post_json(
        &format!("/auth/signup?token={token}"),
        &String::from_utf8(envelope_bytes()).unwrap(),
    );
    assert_eq!(status, 204);
}

// ── PUT /auth/envelope ────────────────────────────────────────────────────

/// A password change: the relay never sees the master secret, it only enforces
/// "you held the old credential". The account comes from the authenticated
/// identity, so this can only ever replace the caller's own envelope.
#[test]
fn rotating_an_envelope_needs_the_current_credential() {
    let Some(o) = oracle() else { return };

    // Claim the account, and give it a static credential to authenticate with.
    let token = token_for(&o, "alice");
    let first = envelope_bytes();
    o.post_json(
        &format!("/auth/signup?token={token}"),
        &String::from_utf8(first.clone()).unwrap(),
    );
    const AUTH_TOKEN: &[u8] = b"setup-interop-token-000000000000";
    std::fs::write(
        o.data_dir().join("a.test/alice/auth_token_hash"),
        jmapserver::hash_auth_token(AUTH_TOKEN),
    )
    .unwrap();
    let password = base64::engine::general_purpose::STANDARD.encode(AUTH_TOKEN);
    let auth = base64::engine::general_purpose::STANDARD.encode(format!("alice@a.test:{password}"));

    // Unauthenticated: refused, and nothing changes.
    let second = envelope_bytes();
    let (status, _, _) = o.get("/auth/envelope?email=alice@a.test");
    assert_eq!(status, 200);
    let (status, _) = o.put_auth(
        "/auth/envelope",
        &String::from_utf8(second.clone()).unwrap(),
        "",
    );
    assert_eq!(status, 401);

    // Authenticated: replaced.
    let (status, b) = o.put_auth(
        "/auth/envelope",
        &String::from_utf8(second.clone()).unwrap(),
        &auth,
    );
    assert_eq!(status, 204, "{b:?}");
    let (_, served, _) = o.get("/auth/envelope?email=alice@a.test");
    assert_eq!(served.as_bytes(), &second[..]);
    assert_ne!(served.as_bytes(), &first[..], "the two envelopes differ");

    // An unparseable one is refused, and the account is not locked out — there
    // is no other copy of the wrapped secret.
    let (status, _) = o.put_auth("/auth/envelope", "not an envelope", &auth);
    assert_eq!(status, SetupError::InvalidEnvelope.status());
    let (_, still, _) = o.get("/auth/envelope?email=alice@a.test");
    assert_eq!(still.as_bytes(), &second[..]);
}
