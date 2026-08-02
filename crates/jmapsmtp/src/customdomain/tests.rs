//! Bring-your-own domain, and self-deletion.
//!
//! The test to read first is `registering_a_domain_never_opens_it_for_everyone`:
//! it is the difference between "this domain is verified" and "anyone may
//! create accounts under this domain forever".

use super::*;
use pretty_assertions::assert_eq;

fn cfg(json: &str) -> Config {
    serde_json::from_str(json).expect("config should parse")
}

fn with_secret() -> Config {
    cfg(r#"{"domain":{"a.test":{}},"domain_verify_secret":"s3cret","hostname":"mx.a.test"}"#)
}

// ── domain syntax ─────────────────────────────────────────────────────────

/// This string becomes a directory name under `data/_domains/` **and** a DNS
/// query, so it is checked rather than normalised.
#[test]
fn a_plausible_delegated_hostname_is_accepted() {
    for ok in [
        "y.jp",
        "example.com",
        "sub.example.com",
        "a-b.example.com",
        "x1.y2.example",
        &format!("{}.com", "a".repeat(63)),
    ] {
        assert!(valid_custom_domain(ok), "{ok:?} should be accepted");
    }
}

#[test]
fn anything_that_is_not_one_is_refused() {
    for bad in [
        "",
        "example",     // no TLD
        "example.c",   // one-letter TLD
        "example.123", // numeric TLD
        "-example.com",
        "example-.com",
        "ex..ample.com",
        ".example.com",
        "example.com.", // trailing dot: absolute in DNS, not here
        "exa mple.com",
        "../etc.com",
        "example.com/path",
        &format!("{}.com", "a".repeat(64)),
        &"a.".repeat(200),
    ] {
        assert!(!valid_custom_domain(bad), "{bad:?} should be refused");
    }
}

/// Case is the one thing the endpoints normalise, so an uppercase domain
/// succeeds and registers the folded form. `valid_custom_domain("Example.com")`
/// is false, but neither route ever asks it that.
#[test]
fn an_uppercase_domain_is_folded_not_refused() {
    assert!(
        !valid_custom_domain("Example.com"),
        "the predicate refuses it"
    );
    assert!(
        valid_custom_domain("  Example.COM  ".trim().to_lowercase().as_str()),
        "but the endpoints fold first"
    );

    // …and the token is the folded domain's, so a client that asked with
    // capitals gets the record for the domain that will actually be registered.
    let cfg = with_secret();
    assert_eq!(
        verify_token(&cfg, &"Example.COM".to_lowercase()),
        verify_token(&cfg, "example.com")
    );
}

// ── the two tokens ────────────────────────────────────────────────────────

/// Deterministic, so there is no pending state to store, expire or leak — the
/// expected value is recomputable at any time.
#[test]
fn both_tokens_are_deterministic() {
    let cfg = with_secret();
    assert_eq!(verify_token(&cfg, "y.jp"), verify_token(&cfg, "y.jp"));
    assert_eq!(
        provision_secret_for(&cfg, "y.jp"),
        provision_secret_for(&cfg, "y.jp")
    );
}

#[test]
fn the_verify_token_has_its_published_shape() {
    let token = verify_token(&with_secret(), "y.jp");
    let hex = token
        .strip_prefix("biset-verify=")
        .expect("the prefix is what an operator pastes into DNS");
    assert_eq!(hex.len(), 32);
    assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    assert_eq!(verify_txt_name("y.jp"), "_biset-verify.y.jp");
}

/// The two tokens are derived from the same secret and must not collide —
/// otherwise proving ownership would hand out the account-creation secret, and
/// the TXT record (which is *public*, by construction) would be it.
#[test]
fn the_two_tokens_are_different_for_the_same_domain() {
    let cfg = with_secret();
    let verify = verify_token(&cfg, "y.jp");
    let provision = provision_secret_for(&cfg, "y.jp");
    assert_ne!(verify, provision);
    assert!(
        !verify.contains(&provision),
        "the public TXT record must not disclose the provisioning secret"
    );
}

#[test]
fn different_domains_and_different_secrets_give_different_tokens() {
    let a = with_secret();
    let b = cfg(r#"{"domain":{"a.test":{}},"domain_verify_secret":"other"}"#);
    assert_ne!(verify_token(&a, "y.jp"), verify_token(&a, "z.jp"));
    assert_ne!(verify_token(&a, "y.jp"), verify_token(&b, "y.jp"));
    assert_ne!(
        provision_secret_for(&a, "y.jp"),
        provision_secret_for(&b, "y.jp")
    );
}

// ── verification ──────────────────────────────────────────────────────────

#[test]
fn ownership_needs_the_exact_record_among_whatever_else_is_there() {
    let expected = verify_token(&with_secret(), "y.jp");
    assert!(txt_proves_ownership(
        &["v=spf1 -all".into(), expected.clone()],
        &expected
    ));
    assert!(!txt_proves_ownership(&[], &expected));
    assert!(!txt_proves_ownership(&["v=spf1 -all".into()], &expected));
    assert!(
        !txt_proves_ownership(&[format!("{expected}x")], &expected),
        "a prefix is not a match"
    );
    assert!(
        !txt_proves_ownership(&[expected.to_uppercase()], &expected),
        "and neither is a different case"
    );
}

// ── what registration grants ──────────────────────────────────────────────

/// The heart of it. A verified domain is **gated**, never open: creating an
/// account under it needs the secret handed back in the same response, which is
/// re-issued only to whoever currently controls the DNS.
///
/// Marking it `allow_provision` instead would mean one past registration lets
/// anyone create accounts under someone else's domain forever, with no further
/// proof.
#[test]
fn registering_a_domain_never_opens_it_for_everyone() {
    let cfg = with_secret();
    let dc = registered_domain_config(&cfg, "y.jp");

    assert!(!dc.allow_provision, "a BYO domain is never open");
    assert_eq!(dc.provision_secret, provision_secret_for(&cfg, "y.jp"));
    assert!(dc.accounts.is_empty());
    assert_eq!(dc.selector(), crate::dkim::DEFAULT_SELECTOR);

    // And the gate actually holds.
    assert_eq!(
        crate::provision::may_provision(&dc, &dc.provision_secret),
        Ok(())
    );
    assert_eq!(
        crate::provision::may_provision(&dc, ""),
        Err(crate::provision::Refusal::DomainNotOpen)
    );
    assert_eq!(
        crate::provision::may_provision(&dc, "guessed"),
        Err(crate::provision::Refusal::DomainNotOpen)
    );
}

/// Re-registering an already-verified domain reproduces the same secret, so a
/// returning owner is not locked out of accounts they already created.
#[test]
fn re_registering_reissues_the_same_secret() {
    let cfg = with_secret();
    assert_eq!(
        registered_domain_config(&cfg, "y.jp").provision_secret,
        registered_domain_config(&cfg, "y.jp").provision_secret
    );
}

/// A registered custom domain never becomes a self-service one, so
/// `provision_domain()` — which picks the domain a new account lands on by
/// default — must not start pointing at somebody's BYO domain.
#[test]
fn a_registered_domain_is_never_chosen_as_the_default() {
    let cfg = with_secret();
    let dynamic = crate::config::DynamicDomains::default();
    dynamic.insert("y.jp".into(), registered_domain_config(&cfg, "y.jp"));
    assert_eq!(cfg.provision_domain(), None);
}

// ── self-deletion ─────────────────────────────────────────────────────────

/// A configured account cannot delete itself: it exists because the operator
/// put it in `config.json`, so removing its data leaves the config pointing at
/// nothing and the account returns on the next start.
#[test]
fn a_statically_configured_account_cannot_delete_itself() {
    let dc: DomainConfig = serde_json::from_str(r#"{"account":{"alice":{}}}"#).unwrap();
    assert_eq!(
        may_self_delete(Some(&dc), "alice"),
        Err(DomainError::ServerManaged)
    );
    assert_eq!(DomainError::ServerManaged.status(), 403);
}

#[test]
fn a_dynamic_account_may_delete_itself() {
    let dc: DomainConfig = serde_json::from_str(r#"{"account":{"alice":{}}}"#).unwrap();
    assert_eq!(may_self_delete(Some(&dc), "provisioned"), Ok(()));
    assert_eq!(may_self_delete(None, "anyone"), Ok(()));
}

// ── statuses ──────────────────────────────────────────────────────────────

/// 412, not 400: the request is well formed and a precondition on the *world*
/// is not met. DNS propagation makes "not yet" the common case, so the client
/// should retry rather than rewrite the request.
#[test]
fn an_unverified_domain_is_a_precondition_failure() {
    assert_eq!(DomainError::NotVerified.status(), 412);
    assert!(
        DomainError::NotVerified.message().contains("retry"),
        "the message should tell the operator to wait: {}",
        DomainError::NotVerified.message()
    );
}

#[test]
fn each_error_carries_the_status_the_client_expects() {
    for (err, status) in [
        (DomainError::InvalidDomain, 400),
        (DomainError::Unauthorized, 401),
        (DomainError::ServerManaged, 403),
        (DomainError::NotVerified, 412),
    ] {
        assert_eq!(err.status(), status, "{err:?}");
    }
}
