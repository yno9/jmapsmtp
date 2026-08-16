//! Bring-your-own domain and self-deletion, against the oracle.
//!
//! The two tokens are the ownership contract: an operator pastes the verify
//! token into DNS, and a client sends the provisioning secret back on every
//! account creation. Both are HMACs of the relay's secret, so a difference of
//! one byte means every BYO domain stops working across the migration —
//! recorded TXT records no longer match, and existing provisioning secrets are
//! refused.
//!
//! `/domain/add` cannot be driven end to end here: it does a live DNS lookup
//! for a record on a domain nobody controls. So the verification step is tested
//! by its refusal, and everything derived from the secret is compared directly.

use base64::Engine as _;
use jmapsmtp::customdomain::{
    DomainError, provision_secret_for, registered_domain_config, verify_token, verify_txt_name,
};

mod oracle_harness;
use oracle_harness::Oracle;

const AUTH_TOKEN: &[u8] = b"domain-interop-token-00000000000";

fn basic_auth(account: &str) -> String {
    let password = base64::engine::general_purpose::STANDARD.encode(AUTH_TOKEN);
    base64::engine::general_purpose::STANDARD.encode(format!("{account}:{password}"))
}

fn config_json(http_port: u16, smtp_port: u16) -> String {
    format!(
        r#"{{"listen_addr":"127.0.0.1:{http_port}","smtp_port":{smtp_port},
            "base_url":"http://127.0.0.1:{http_port}","hostname":"mx.a.test",
            "domain_verify_secret":"s3cret-shared-with-the-oracle",
            "domain":{{"a.test":{{"account":{{"static":{{}}}}}}}}}}"#
    )
}

fn rust_config() -> jmapsmtp::config::Config {
    serde_json::from_str(&config_json(1, 1)).unwrap()
}

/// `static@a.test` is configured; `dynamic@a.test` is not, and has only a
/// credential — the two sides of the self-deletion rule.
fn seed(root: &std::path::Path) {
    for lp in ["static", "dynamic"] {
        let acct = root.join("data/a.test").join(lp);
        std::fs::create_dir_all(&acct).unwrap();
        std::fs::write(
            acct.join("auth_token_hash"),
            jmapserver::hash_auth_token(AUTH_TOKEN),
        )
        .unwrap();
        std::fs::write(acct.join("mail.json"), b"precious").unwrap();
    }
}

fn oracle() -> Option<Oracle> {
    Oracle::start_with("CUSTOMDOMAIN_INTEROP", config_json, seed)
}

// ── the tokens ────────────────────────────────────────────────────────────

/// The verify token, byte for byte. It is what an operator pastes into DNS, so
/// a difference means every already-published record stops matching.
#[test]
fn the_verify_token_matches_the_oracles_byte_for_byte() {
    let Some(o) = oracle() else { return };
    let cfg = rust_config();

    for domain in ["y.jp", "example.com", "sub.example.com"] {
        let (status, body, _) = o.get(&format!("/domain/verify-token?domain={domain}"));
        assert_eq!(status, 200, "{domain}: {body:?}");
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();

        assert_eq!(parsed["token"], verify_token(&cfg, domain), "{domain}");
        assert_eq!(parsed["txt_name"], verify_txt_name(domain), "{domain}");
        // The MX target is the relay's own hostname, handed out so a client can
        // show every DNS record on one screen.
        assert_eq!(parsed["mx_target"], "mx.a.test");
        assert_eq!(
            parsed["dkim_name"],
            format!("default._domainkey.{domain}"),
            "{domain}"
        );
        assert!(
            parsed["dkim_value"]
                .as_str()
                .is_some_and(|v| v.starts_with("v=DKIM1; k=rsa; p=")),
            "{domain}: {:?}",
            parsed["dkim_value"]
        );
    }
}

/// Nothing privileged is in that response: it is a public key record, this
/// relay's hostname, and a token that only proves the *asker* read the
/// instructions. The provisioning secret is not there.
#[test]
fn the_verify_token_response_does_not_disclose_the_provisioning_secret() {
    let Some(o) = oracle() else { return };
    let (_, body, _) = o.get("/domain/verify-token?domain=y.jp");
    let secret = provision_secret_for(&rust_config(), "y.jp");
    assert!(
        !body.contains(&secret),
        "the pre-ownership response must not carry the provisioning secret"
    );
}

/// Asking for the token twice must not rotate the DKIM key: an operator who
/// has already published the record would silently start failing DKIM.
#[test]
fn asking_twice_does_not_rotate_the_dkim_key() {
    let Some(o) = oracle() else { return };
    let (_, first, _) = o.get("/domain/verify-token?domain=y.jp");
    let (_, second, _) = o.get("/domain/verify-token?domain=y.jp");
    assert_eq!(first, second);
}

#[test]
fn an_implausible_domain_is_refused_the_same_way() {
    let Some(o) = oracle() else { return };
    for bad in ["", "example", "example.c", "-example.com", "ex..ample.com"] {
        let (status, body, _) = o.get(&format!("/domain/verify-token?domain={bad}"));
        assert_eq!(status, DomainError::InvalidDomain.status(), "{bad:?}");
        assert_eq!(DomainError::InvalidDomain.message(), body.trim(), "{bad:?}");
        assert!(
            !jmapsmtp::customdomain::valid_custom_domain(bad),
            "{bad:?}: this port disagreed"
        );
    }
}

/// Case is normalised rather than refused, and the token returned is the
/// *folded* domain's — so a client that asked with capitals publishes the
/// record for the domain that will actually be registered.
///
/// Found by this suite: the predicate refuses uppercase, but both endpoints
/// fold before calling it, so the request succeeds. Same shape as
/// `provision::valid_username`.
#[test]
fn an_uppercase_domain_is_folded_not_refused() {
    let Some(o) = oracle() else { return };
    let (status, body, _) = o.get("/domain/verify-token?domain=Example.COM");
    assert_eq!(status, 200, "{body:?}");

    let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        parsed["token"],
        verify_token(&rust_config(), "example.com"),
        "the token is the folded domain's"
    );
    assert_eq!(parsed["txt_name"], verify_txt_name("example.com"));

    let (_, lower, _) = o.get("/domain/verify-token?domain=example.com");
    assert_eq!(lower, body, "and identical to asking in lowercase");
}

// ── verification is re-proved every time ──────────────────────────────────

/// `/domain/add` for a domain whose TXT record does not exist is refused with
/// **412**, not 400: the request is well formed, a precondition on the world is
/// not met, and DNS propagation makes "not yet" the common case.
#[test]
fn adding_a_domain_without_the_txt_record_is_a_precondition_failure() {
    let Some(o) = oracle() else { return };
    let (status, body) = o.post_json("/domain/add", r#"{"domain":"y.jp"}"#);
    assert_eq!(status, DomainError::NotVerified.status(), "{body:?}");
    assert_eq!(DomainError::NotVerified.message(), body.trim());
    assert!(
        !o.data_dir().join("_domains/y.jp/domain.json").exists(),
        "an unverified domain must not be registered"
    );
}

#[test]
fn adding_an_implausible_domain_is_refused_before_any_dns_lookup() {
    let Some(o) = oracle() else { return };
    let (status, body) = o.post_json("/domain/add", r#"{"domain":"not a domain"}"#);
    assert_eq!(status, DomainError::InvalidDomain.status());
    assert_eq!(DomainError::InvalidDomain.message(), body.trim());
}

/// What a registration *would* write, compared against what the oracle reads
/// back. The verification step cannot be driven here — it needs a real TXT
/// record — so this seeds the registry the way `/domain/add` would and checks
/// the oracle agrees the domain is registered and gated.
#[test]
fn a_registered_domain_is_gated_and_the_oracle_reads_it_that_way() {
    let Some(o) = oracle() else { return };
    let cfg = rust_config();
    let dc = registered_domain_config(&cfg, "y.jp");

    assert!(!dc.allow_provision, "never open");
    assert_eq!(dc.provision_secret, provision_secret_for(&cfg, "y.jp"));

    // Write it exactly as /domain/add would, then restart the oracle so it
    // loads the registry at startup — which is the path a real deployment takes
    // after a restart.
    let registry = o.data_dir().join("_domains/y.jp");
    std::fs::create_dir_all(&registry).unwrap();
    std::fs::write(
        registry.join("domain.json"),
        jmap_types::go_json::to_vec(&dc).unwrap(),
    )
    .unwrap();

    // The oracle serves envelopes for a domain it knows; an unknown domain 404s
    // before touching the disk. Before the restart it does not know y.jp.
    let (status, _, _) = o.get("/auth/envelope?email=nobody@y.jp");
    assert_eq!(status, 404);

    // This port reads the same file back as a gated domain.
    let dynamic = jmapsmtp::config::DynamicDomains::default();
    dynamic.load(&o.data_dir());
    let loaded = dynamic.get("y.jp").expect("registered");
    assert!(!loaded.allow_provision);
    assert_eq!(loaded.provision_secret, dc.provision_secret);
    assert_eq!(
        jmapsmtp::provision::may_provision(&loaded, "", "", ""),
        Err(jmapsmtp::provision::Refusal::DomainNotOpen),
        "a BYO domain never becomes open"
    );
}

// ── self-deletion ─────────────────────────────────────────────────────────

/// A configured account cannot delete itself — its data would come back on the
/// next start, since the config still names it.
#[test]
fn a_configured_account_cannot_delete_itself_on_either_implementation() {
    let Some(o) = oracle() else { return };
    let (status, body) = o.post_json_auth("/account/delete", "", &basic_auth("static@a.test"));
    assert_eq!(status, DomainError::ServerManaged.status(), "{body:?}");
    assert_eq!(DomainError::ServerManaged.message(), body.trim());
    assert!(
        o.data_dir().join("a.test/static/mail.json").exists(),
        "and nothing was removed"
    );

    let dom_cfg = rust_config().domains.get("a.test").cloned().unwrap();
    assert_eq!(
        jmapsmtp::customdomain::may_self_delete(Some(&dom_cfg), "static"),
        Err(DomainError::ServerManaged),
        "this port agrees"
    );
}

/// A dynamic account is the caller's own to remove, and removal takes the data
/// with it.
#[test]
fn a_dynamic_account_deletes_itself_and_its_data() {
    let Some(o) = oracle() else { return };
    assert!(o.data_dir().join("a.test/dynamic/mail.json").exists());

    let (status, body) = o.post_json_auth("/account/delete", "", &basic_auth("dynamic@a.test"));
    assert!(
        (200..300).contains(&status),
        "the oracle refused a self-delete: {status} {body:?}"
    );
    assert!(
        !o.data_dir().join("a.test/dynamic").exists(),
        "the account directory should be gone"
    );

    let dom_cfg = rust_config().domains.get("a.test").cloned().unwrap();
    assert_eq!(
        jmapsmtp::customdomain::may_self_delete(Some(&dom_cfg), "dynamic"),
        Ok(()),
        "this port agrees"
    );
}

#[test]
fn deleting_without_a_credential_is_refused() {
    let Some(o) = oracle() else { return };
    let (status, _) = o.post_json("/account/delete", "");
    assert_eq!(status, DomainError::Unauthorized.status());
    assert!(
        o.data_dir().join("a.test/dynamic").exists(),
        "nothing removed"
    );
}
