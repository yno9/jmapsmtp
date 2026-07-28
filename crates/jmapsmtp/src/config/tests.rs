//! The config file's defaults and the two checks that reject a bad one.
//!
//! Everything here goes through the JSON rather than a struct literal, because
//! the JSON is the compatibility surface — an existing deployment's file has
//! to keep loading (PLAN.md §5.1).

use super::*;
use pretty_assertions::assert_eq;

fn parse(json: &str) -> Config {
    serde_json::from_str(json).expect("config should parse")
}

// ── parsing ───────────────────────────────────────────────────────────────

#[test]
fn a_minimal_config_parses_and_validates() {
    let cfg = parse(r#"{"domain":{"example.com":{}}}"#);
    assert!(cfg.validate().is_ok());
    assert_eq!(cfg.domains.len(), 1);
}

#[test]
fn an_unknown_field_is_ignored_rather_than_rejected() {
    // Go's encoding/json ignores unknown keys. A config written for a newer
    // build must still start, or a rollback strands the operator.
    let cfg = parse(r#"{"domain":{"a.test":{}},"some_future_option":42}"#);
    assert!(cfg.validate().is_ok());
}

#[test]
fn the_full_domain_shape_round_trips() {
    let cfg = parse(
        r#"{"domain":{"example.com":{
             "dkim_selector":"sel1",
             "allow_provision":true,
             "account":{"alice":{"alias":["postmaster","a@other.test"]}}
           }}}"#,
    );
    let d = &cfg.domains["example.com"];
    assert_eq!(d.selector(), "sel1");
    assert!(d.allow_provision);
    assert_eq!(d.accounts["alice"].alias, ["postmaster", "a@other.test"]);
}

// ── defaults ──────────────────────────────────────────────────────────────

#[test]
fn omitted_fields_take_the_go_defaults() {
    let cfg = parse(r#"{"domain":{"a.test":{}}}"#);
    assert_eq!(cfg.listen_addr(), "0.0.0.0:8765");
    assert_eq!(cfg.smtp_port(), 25);
    assert_eq!(cfg.relay_label(), "Mail");
    assert_eq!(cfg.relay_color(), "#64748b");
    assert_eq!(cfg.domains["a.test"].selector(), "default");
}

#[test]
fn an_explicit_value_wins_over_the_default() {
    let cfg = parse(r#"{"domain":{"a.test":{}},"listen_addr":"127.0.0.1:1","smtp_port":2525}"#);
    assert_eq!(cfg.listen_addr(), "127.0.0.1:1");
    assert_eq!(cfg.smtp_port(), 2525);
}

// ── validation ────────────────────────────────────────────────────────────

#[test]
fn a_config_with_no_domains_is_refused() {
    assert!(matches!(
        parse("{}").validate(),
        Err(ConfigError::NoDomains)
    ));
}

/// An anchor URL without a token would mean unauthenticated writes to a
/// service on the public internet: anyone could claim an unheld name or
/// release someone else's. Startup has to stop, not warn.
#[test]
#[cfg(feature = "anchor")]
fn an_anchor_url_without_a_token_is_refused() {
    let cfg = parse(r#"{"domain":{"a.test":{}},"anchor_url":"https://anchor.test"}"#);
    assert!(matches!(
        cfg.validate(),
        Err(ConfigError::AnchorTokenMissing)
    ));

    let cfg =
        parse(r#"{"domain":{"a.test":{}},"anchor_url":"https://anchor.test","anchor_token":"s"}"#);
    assert!(cfg.validate().is_ok());
}

/// The anchorless build has no anchor client to authenticate to, so the pair
/// is inert rather than dangerous. Refusing here would make a config shared
/// between an anchored and an anchorless relay unusable on the latter.
#[test]
#[cfg(not(feature = "anchor"))]
fn the_anchorless_build_ignores_the_anchor_settings() {
    let cfg = parse(r#"{"domain":{"a.test":{}},"anchor_url":"https://anchor.test"}"#);
    assert!(cfg.validate().is_ok());
}

// ── provisioning ──────────────────────────────────────────────────────────

#[test]
fn the_provision_domain_is_the_one_that_allows_it() {
    let cfg = parse(r#"{"domain":{"closed.test":{},"open.test":{"allow_provision":true}}}"#);
    assert_eq!(cfg.provision_domain(), Some("open.test"));
    assert_eq!(
        parse(r#"{"domain":{"a.test":{}}}"#).provision_domain(),
        None
    );
}

/// Go ranges over a map here, so with two open domains its answer changes
/// between runs. Sorted order at least makes the misconfiguration behave the
/// same way every time. SPEC.md §11.5.
#[test]
fn two_open_domains_resolve_the_same_way_every_time() {
    let cfg = parse(
        r#"{"domain":{"b.test":{"allow_provision":true},"a.test":{"allow_provision":true}}}"#,
    );
    for _ in 0..20 {
        assert_eq!(cfg.provision_domain(), Some("a.test"));
    }
}

// ── reply-only exemptions ─────────────────────────────────────────────────

#[test]
fn exemptions_match_a_whole_address_or_a_bare_domain() {
    let cfg = parse(
        r#"{"domain":{"a.test":{}},"reply_only_exempt":["  Partner.test ","VIP@other.test"]}"#,
    );
    assert!(cfg.reply_only_exempt("anyone@partner.test"), "by domain");
    assert!(cfg.reply_only_exempt("vip@other.test"), "by address");
    assert!(
        !cfg.reply_only_exempt("someone@other.test"),
        "not the whole domain"
    );
    assert!(!cfg.reply_only_exempt("nobody@elsewhere.test"));
    assert!(
        cfg.reply_only_exempt("partner.test"),
        "a bare domain as the sender matches the entry as an address"
    );
}

// ── the dynamic registry ──────────────────────────────────────────────────

#[test]
fn dynamic_domains_are_restored_from_disk() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("_domains").join("byo.test");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("domain.json"),
        br#"{"dkim_selector":"s2","account":{"bob":{}}}"#,
    )
    .unwrap();

    let dyn_domains = DynamicDomains::default();
    dyn_domains.load(tmp.path());
    let got = dyn_domains.get("byo.test").expect("restored");
    assert_eq!(got.selector(), "s2");
    assert!(got.accounts.contains_key("bob"));
}

/// A missing or unreadable `_domains/` is normal — no BYO domain has ever been
/// registered. It must not stop the relay from starting.
#[test]
fn a_missing_domains_directory_is_not_an_error() {
    let tmp = tempfile::tempdir().unwrap();
    let dyn_domains = DynamicDomains::default();
    dyn_domains.load(tmp.path());
    assert!(dyn_domains.names().is_empty());

    std::fs::create_dir_all(tmp.path().join("_domains").join("half.test")).unwrap();
    dyn_domains.load(tmp.path());
    assert!(
        dyn_domains.names().is_empty(),
        "no domain.json, so not a domain"
    );
}

#[test]
fn a_static_domain_wins_over_a_dynamic_one_of_the_same_name() {
    let cfg = parse(r#"{"domain":{"a.test":{"dkim_selector":"static"}}}"#);
    let dyn_domains = DynamicDomains::default();
    dyn_domains.insert(
        "a.test".into(),
        DomainConfig {
            dkim_selector: "dynamic".into(),
            ..Default::default()
        },
    );
    assert_eq!(
        domain_config(&cfg, &dyn_domains, "a.test")
            .unwrap()
            .selector(),
        "static",
        "the operator's file outranks anything registered at runtime"
    );
    assert!(domain_config(&cfg, &dyn_domains, "nope.test").is_none());
}

// ── the shipped example ───────────────────────────────────────────────────

/// `config.example.json` is what an operator copies to start from, so it has
/// to be a config that actually starts.
///
/// The Go repository's copy is not, in two ways, and this test is why ours
/// differs from it (SPEC.md §11.12):
///
/// 1. It sets `anchor_url` with an empty `anchor_token`, which
///    `checkAnchorConfig` refuses — a first run of the anchored build dies on
///    a message about a field the operator never touched.
/// 2. Its account keys are full addresses (`you@example.com`). The key is a
///    localpart: `Accounts()` builds `localpart + "@" + domain`, so those
///    become `you@example.com@example.com`.
#[test]
fn the_shipped_example_config_loads_and_validates() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("config.example.json");
    let cfg = Config::load(&path).expect("config.example.json should load");

    let accounts = &cfg.domains["example.com"].accounts;
    for localpart in accounts.keys() {
        assert!(
            !localpart.contains('@'),
            "account key {localpart:?} is a localpart, not an address"
        );
    }
    assert_eq!(accounts["you"].alias, ["alias@example.com"]);
}
