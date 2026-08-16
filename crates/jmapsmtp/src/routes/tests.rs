//! The route table, including the check `route_registration_test.go` exists
//! for: registering every route together must not conflict.

use super::*;
use crate::gomux::Route;
use pretty_assertions::assert_eq;

fn cfg(json: &str) -> Config {
    serde_json::from_str(json).expect("config should parse")
}

/// `/pkarr/` forwarded a did:dht record to the anchor's DHT node. It went
/// with did:dht, and must not come back by accident — an open route that
/// proxies a client's bytes to another host is not something to reintroduce
/// without meaning to.
#[test]
fn the_pkarr_gateway_is_gone_in_every_configuration() {
    let anchored =
        cfg(r#"{"domain":{"a.test":{}},"anchor_url":"https://anchor.test","anchor_token":"t"}"#);
    for cfg in [&anchored, &plain()] {
        assert!(
            !route_specs(cfg, false)
                .iter()
                .any(|s| s.pattern == "/pkarr/"),
            "the pkarr gateway is registered again"
        );
    }
}

fn plain() -> Config {
    cfg(r#"{"domain":{"a.test":{}}}"#)
}

/// The port of `route_registration_test.go`.
///
/// The Go original guards a real production incident:
/// `registerAnchorRoutes` registered `POST /account/devices` while
/// `registerDeviceRoutes` registered GET/DELETE on the identical pattern, and
/// `ServeMux` panicked on deploy. No other test in that package called both
/// registration functions the way `main()` does, so nothing caught it.
///
/// This test exists so a regression fails here rather than after
/// `systemctl restart`.
#[test]
fn registering_every_route_together_does_not_conflict() {
    // The widest configuration: every optional group mounted at once, which is
    // the only combination that can surface a conflict between two groups.
    let cfg = cfg(r#"{"domain":{"a.test":{}},"domain_verify_secret":"s"}"#);
    let mux = build_mux(&cfg, true);
    assert_eq!(
        mux.patterns().len(),
        route_specs(&cfg, true).len(),
        "every spec made it into the mux"
    );
}

/// `build_mux` is only as good as the panic behind it, and a test that
/// something does *not* panic is worthless if nothing can. This proves the
/// conflict is still detected.
#[test]
#[should_panic(expected = "registered twice")]
fn a_conflicting_route_still_panics() {
    let mut mux = build_mux(&plain(), false);
    mux.handle("/account/devices", r("/account/devices", Guard::Open));
}

#[test]
fn no_pattern_appears_twice_in_any_configuration() {
    for blobs in [false, true] {
        for secret in ["", "s"] {
            let cfg = cfg(&format!(
                r#"{{"domain":{{"a.test":{{}}}},"domain_verify_secret":"{secret}"}}"#
            ));
            let specs = route_specs(&cfg, blobs);
            let mut seen: Vec<&str> = specs.iter().map(|s| s.pattern).collect();
            let before = seen.len();
            seen.sort_unstable();
            seen.dedup();
            assert_eq!(seen.len(), before, "blobs={blobs} secret={secret:?}");
        }
    }
}

// ── what each configuration mounts ────────────────────────────────────────

fn patterns(cfg: &Config, blobs: bool) -> Vec<&'static str> {
    route_specs(cfg, blobs).iter().map(|s| s.pattern).collect()
}

#[test]
fn the_custom_domain_routes_need_a_verify_secret() {
    assert!(!patterns(&plain(), false).contains(&"/domain/add"));
    let with = cfg(r#"{"domain":{"a.test":{}},"domain_verify_secret":"s"}"#);
    assert!(patterns(&with, false).contains(&"/domain/add"));
    assert!(patterns(&with, false).contains(&"/domain/verify-token"));
}

#[test]
fn the_blob_routes_need_a_blob_handler() {
    assert!(!patterns(&plain(), false).contains(&"/jmap/upload/"));
    assert!(patterns(&plain(), true).contains(&"/jmap/upload/"));
    assert!(patterns(&plain(), true).contains(&"/jmap/download/"));
}

/// The anchorless build mounts no DID routes at all — not a stub that refuses,
/// no route. A relay with no anchor has nothing to answer with, and a 404 says
/// so more honestly than a 500.
#[test]
fn the_anchor_routes_follow_the_build() {
    let p = patterns(&plain(), false);
    let has_anchor = cfg!(feature = "anchor");
    assert_eq!(p.contains(&"/account/did"), has_anchor);
    assert_eq!(p.contains(&"/admin/drain-anchor"), has_anchor);
}

// ── the guards ────────────────────────────────────────────────────────────

fn guard(pattern: &str) -> Guard {
    let cfg = cfg(r#"{"domain":{"a.test":{}},"domain_verify_secret":"s"}"#);
    route_specs(&cfg, true)
        .into_iter()
        .find(|s| s.pattern == pattern)
        .unwrap_or_else(|| panic!("no route {pattern}"))
        .guard
}

/// The three deliberately-unauthenticated routes, listed so that adding a
/// fourth is a decision someone makes on purpose.
#[test]
fn only_these_routes_are_open() {
    let cfg = cfg(r#"{"domain":{"a.test":{}},"domain_verify_secret":"s"}"#);
    let mut open: Vec<&str> = route_specs(&cfg, true)
        .iter()
        .filter(|s| s.guard == Guard::Open)
        .map(|s| s.pattern)
        .collect();
    open.sort_unstable();

    let mut expected = vec![
        // WKD is a public directory by definition — the whole point is that a
        // stranger can find a public key before they can send you anything.
        "/.well-known/openpgpkey/hu/",
        "/.well-known/openpgpkey/policy",
        "/pgp/pubkey",
        // A public key, needed by a service worker before it has a credential.
        "/jmap/push/vapid-public-key",
        // Relay name and colour, shown on a login screen.
        "/relay-info",
        // The HTML shell only; every call it makes carries the bearer token.
        "/admin/dashboard",
        // A nonce authorises nothing by itself (session_nonce.rs's own
        // note) — handing one out reveals nothing about any account.
        "/account/session/challenge",
    ];
    expected.sort_unstable();
    assert_eq!(open, expected);
}

#[test]
fn the_private_key_is_not_public_even_though_the_public_one_is() {
    assert_eq!(guard("/pgp/pubkey"), Guard::Open);
    assert_eq!(guard("/pgp/privkey"), Guard::Account);
    assert_eq!(guard("/pgp/peerkey"), Guard::Account);
}

#[test]
fn the_admin_and_metrics_routes_want_a_bearer_token() {
    assert_eq!(guard("/metrics"), Guard::Bearer);
    assert_eq!(guard("/admin/accounts"), Guard::Bearer);
    assert_eq!(guard("/admin/accounts/"), Guard::Bearer);
    if cfg!(feature = "anchor") {
        assert_eq!(guard("/admin/drain-anchor"), Guard::Bearer);
    }
}

// ── routing through the real table ────────────────────────────────────────

#[test]
fn the_jmap_api_subtree_takes_everything_below_it() {
    let mux = build_mux(&plain(), false);
    match mux.route("/jmap/api/Email/get", "") {
        Route::Found { pattern, .. } => assert_eq!(pattern, "/jmap/api/"),
        other => panic!("{other:?}"),
    }
    assert_eq!(
        mux.route("/jmap/api", ""),
        Route::Redirect("/jmap/api/".into())
    );
}

/// `/account/storage` and its three children are separate exact patterns, so
/// the longest-match rule has to pick the right one.
#[test]
fn the_storage_routes_do_not_shadow_each_other() {
    let mux = build_mux(&plain(), false);
    for path in [
        "/account/storage",
        "/account/storage/messages",
        "/account/storage/export",
        "/account/storage/purge-messages",
    ] {
        match mux.route(path, "") {
            Route::Found { pattern, .. } => assert_eq!(pattern, path),
            other => panic!("{path}: {other:?}"),
        }
    }
    assert_eq!(
        mux.route("/account/storage/nope", ""),
        Route::NotFound,
        "there is no /account/ subtree to absorb it"
    );
}

#[test]
fn contacts_has_both_an_exact_and_a_subtree_pattern() {
    let mux = build_mux(&plain(), false);
    match mux.route("/contacts", "") {
        Route::Found { pattern, .. } => assert_eq!(pattern, "/contacts"),
        other => panic!("{other:?}"),
    }
    match mux.route("/contacts/alice@a.test", "") {
        Route::Found { pattern, .. } => assert_eq!(pattern, "/contacts/"),
        other => panic!("{other:?}"),
    }
}
