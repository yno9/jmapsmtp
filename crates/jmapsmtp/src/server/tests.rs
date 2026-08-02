//! The HTTP surface.
//!
//! These exercise routing, CORS and the two wired handlers through the real
//! axum app. `tests/server_interop.rs` compares the same responses against the
//! oracle byte for byte.

use super::*;
use axum::http::Method;
use pretty_assertions::assert_eq;
use tower::ServiceExt as _;

fn state() -> Arc<RelayState> {
    state_with_tokens("", "")
}

fn state_with_tokens(admin: &str, metrics: &str) -> Arc<RelayState> {
    let tmp = tempfile::tempdir().unwrap().keep();
    let cfg: Config = serde_json::from_str(
        r##"{"domain":{"a.test":{"account":{"alice":{}}}},
             "relay_label":"Biset","relay_color":"#123456"}"##,
    )
    .unwrap();
    RelayState::with_tokens(cfg, tmp, admin, metrics)
}

async fn get(state: Arc<RelayState>, target: &str) -> (u16, String, Response<Body>) {
    request(state, Method::GET, target).await
}

async fn request(
    state: Arc<RelayState>,
    method: Method,
    target: &str,
) -> (u16, String, Response<Body>) {
    let req = Request::builder()
        .method(method)
        .uri(target)
        .body(Body::empty())
        .unwrap();
    let res = app(state).oneshot(req).await.unwrap();
    let status = res.status().as_u16();
    let (parts, body) = res.into_parts();
    let bytes = axum::body::to_bytes(body, 1 << 20).await.unwrap();
    let text = String::from_utf8_lossy(&bytes).into_owned();
    (
        status,
        text.clone(),
        Response::from_parts(parts, Body::from(text)),
    )
}

fn header(res: &Response<Body>, name: &str) -> String {
    res.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string()
}

// ── routing ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn an_unrouted_path_gets_the_mux_own_404() {
    let (status, body, _) = get(state(), "/nope").await;
    assert_eq!(status, 404);
    assert_eq!(
        body, "404 page not found\n",
        "the mux's own body, distinguishable from a handler's 404"
    );
}

#[tokio::test]
async fn a_subtree_path_missing_its_slash_redirects() {
    let (status, _, res) = get(state(), "/jmap/api").await;
    assert_eq!(status, REDIRECT_STATUS);
    assert_eq!(header(&res, "location"), "/jmap/api/");
}

#[tokio::test]
async fn a_dirty_path_is_cleaned_before_routing() {
    let (status, _, res) = get(state(), "//relay-info").await;
    assert_eq!(status, REDIRECT_STATUS);
    assert_eq!(header(&res, "location"), "/relay-info");
}

// ── CORS ──────────────────────────────────────────────────────────────────

/// Every response carries CORS headers, including a 404 — Go's wrapper runs
/// before the mux, so an unrouted path is still CORS-visible.
#[tokio::test]
async fn every_response_carries_cors_headers() {
    for target in ["/relay-info", "/nope"] {
        let (_, _, res) = get(state(), target).await;
        assert_eq!(header(&res, "access-control-allow-origin"), "*", "{target}");
        assert_eq!(
            header(&res, "access-control-allow-headers"),
            "Authorization, Content-Type",
            "{target}"
        );
    }
}

/// **A handler's own method list wins over the wrapper's.** Go's wrapper
/// writes its headers before calling the handler, so a handler that sets its
/// own overwrites them — `/relay-info` answers `GET, OPTIONS`, not the
/// wrapper's `GET, POST, PUT, OPTIONS`.
///
/// This test previously asserted the opposite and passed, because the port
/// applied the wrapper *after* dispatch and clobbered every per-route list.
/// Running the two servers side by side is what showed it.
#[tokio::test]
async fn a_handlers_own_cors_methods_override_the_wrappers() {
    let (_, _, res) = get(state(), "/relay-info").await;
    assert_eq!(
        header(&res, "access-control-allow-methods"),
        "GET, OPTIONS",
        "the route's own list"
    );

    let (_, _, res) = get(state(), "/nope").await;
    assert_eq!(
        header(&res, "access-control-allow-methods"),
        "GET, POST, PUT, OPTIONS",
        "and the wrapper's where no handler ran"
    );
}

/// A preflight is answered before routing, so it succeeds even for a path that
/// does not exist.
#[tokio::test]
async fn a_preflight_is_answered_without_routing() {
    for target in ["/relay-info", "/nope", "/jmap/api"] {
        let (status, body, res) = request(state(), Method::OPTIONS, target).await;
        assert_eq!(status, 204, "{target}");
        assert_eq!(body, "", "{target}");
        assert_eq!(header(&res, "access-control-allow-origin"), "*");
    }
}

// ── /relay-info ───────────────────────────────────────────────────────────

#[tokio::test]
async fn relay_info_is_served_without_a_credential() {
    let (status, body, res) = get(state(), "/relay-info").await;
    assert_eq!(status, 200);
    assert_eq!(header(&res, "content-type"), "application/json");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&body).unwrap(),
        serde_json::json!({"label": "Biset", "color": "#123456", "type": "mail"})
    );
}

// ── /setup ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn setup_needs_a_token() {
    let (status, body, _) = get(state(), "/setup").await;
    assert_eq!(status, 400);
    assert_eq!(body, "token required\n");
}

#[tokio::test]
async fn setup_renders_the_page_for_a_valid_token() {
    let state = state();
    let invites = crate::startup::issue_setup_tokens(&state.cfg, &state.data_dir);
    let token = invites[0].token.clone();

    let (status, body, res) = get(state.clone(), &format!("/setup?token={token}")).await;
    assert_eq!(status, 200);
    assert_eq!(header(&res, "content-type"), "text/html; charset=utf-8");
    assert_eq!(body, crate::setup_page::render("alice", "a.test", &token));
}

/// The token is checked before the method, so a wrong method with a bad token
/// reports the token — the order decides whether a wrong-method request can be
/// used to probe tokens.
#[tokio::test]
async fn setup_checks_the_token_before_the_method() {
    let state = state();
    let invites = crate::startup::issue_setup_tokens(&state.cfg, &state.data_dir);
    let token = invites[0].token.clone();

    let (status, _, _) = request(
        state.clone(),
        Method::POST,
        &format!("/setup?token={token}"),
    )
    .await;
    assert_eq!(status, 405, "a good token, a wrong method");

    let (status, _, _) = request(state, Method::POST, "/setup?token=wrong").await;
    assert_eq!(status, 401, "a bad token is refused before the method");
}

// ── the bearer guard ──────────────────────────────────────────────────────

/// Applied at the dispatcher rather than inside each handler, so a new admin
/// route cannot be added without one. SPEC.md §11.13.
#[tokio::test]
async fn the_bearer_routes_are_closed_when_their_token_is_unset() {
    for target in ["/metrics", "/admin/accounts"] {
        let (status, _, res) = get(state(), target).await;
        assert_eq!(status, 401, "{target}");
        assert_eq!(header(&res, "www-authenticate"), "Bearer", "{target}");
    }
}

/// The two tokens are separate: `METRICS_TOKEN` must not open `/admin/*`.
/// Reusing one for both would give a Prometheus scraper the admin surface.
#[tokio::test]
async fn the_metrics_token_does_not_open_the_admin_routes() {
    let state = state_with_tokens("admin-secret", "metrics-secret");

    let with = |token: &str, target: &str| {
        let state = state.clone();
        let req = Request::builder()
            .uri(target)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        async move { app(state).oneshot(req).await.unwrap().status().as_u16() }
    };

    assert_ne!(
        with("metrics-secret", "/metrics").await,
        401,
        "its own route"
    );
    assert_eq!(
        with("metrics-secret", "/admin/accounts").await,
        401,
        "a scraper's token must not reach the admin surface"
    );
    assert_ne!(with("admin-secret", "/admin/accounts").await, 401);
    assert_eq!(with("admin-secret", "/metrics").await, 401);
}

// ── bring-your-own domain ─────────────────────────────────────────────────

/// A registration that succeeds — the half `server_interop` cannot reach,
/// because it needs a live TXT record on a domain nobody controls.
#[tokio::test]
async fn a_verified_domain_is_registered_gated_and_never_open() {
    struct Answers(String, String);
    impl crate::dns::TxtResolver for Answers {
        fn lookup_txt(&self, name: &str) -> Vec<String> {
            if name == self.0 {
                // Alongside unrelated records, as a real domain has.
                vec!["v=spf1 -all".into(), self.1.clone()]
            } else {
                Vec::new()
            }
        }
    }

    let tmp = tempfile::tempdir().unwrap().keep();
    let cfg: Config = serde_json::from_str(
        r#"{"domain":{"a.test":{}},"hostname":"mx.a.test",
            "domain_verify_secret":"s3cret"}"#,
    )
    .unwrap();
    let expected = crate::customdomain::verify_token(&cfg, "y.jp");
    let mut state = RelayState::with_tokens(cfg, tmp, "", "");
    Arc::get_mut(&mut state).unwrap().txt = Arc::new(Answers(
        crate::customdomain::verify_txt_name("y.jp"),
        expected,
    ));

    let post = |state: Arc<RelayState>, body: &'static str| async move {
        let req = Request::builder()
            .method(Method::POST)
            .uri("/domain/add")
            .body(Body::from(body))
            .unwrap();
        let res = app(state).oneshot(req).await.unwrap();
        let status = res.status().as_u16();
        let bytes = axum::body::to_bytes(res.into_body(), 1 << 20)
            .await
            .unwrap();
        (status, String::from_utf8_lossy(&bytes).into_owned())
    };

    let (status, body) = post(state.clone(), r#"{"domain":"y.jp"}"#).await;
    assert_eq!(status, 200, "{body}");
    let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(parsed["domain"], "y.jp");
    assert_eq!(parsed["mx_target"], "mx.a.test");
    assert_eq!(
        parsed["provision_secret"],
        crate::customdomain::provision_secret_for(&state.cfg, "y.jp"),
        "re-issued to whoever currently controls the DNS"
    );

    // Registered, and **gated** — never open.
    let registered = state.dynamic_domains.get("y.jp").expect("registered");
    assert!(
        !registered.allow_provision,
        "one past registration must not open the domain forever"
    );
    assert_eq!(
        crate::provision::may_provision(&registered, ""),
        Err(crate::provision::Refusal::DomainNotOpen)
    );
    assert_eq!(
        crate::provision::may_provision(&registered, &registered.provision_secret),
        Ok(())
    );

    // …and on disk, so a restart restores it.
    let on_disk = state.data_dir.join("_domains/y.jp/domain.json");
    assert!(on_disk.exists());
    let reloaded = crate::config::DynamicDomains::default();
    reloaded.load(&state.data_dir);
    assert_eq!(
        reloaded.get("y.jp").map(|d| d.provision_secret),
        Some(registered.provision_secret.clone()),
        "a restart must not invalidate the secret already handed out"
    );

    // A domain whose record is not there is refused, even after another was
    // registered successfully.
    let (status, _) = post(state.clone(), r#"{"domain":"other.test"}"#).await;
    assert_eq!(status, 412);
    assert!(!state.data_dir.join("_domains/other.test").exists());
}

/// The default resolver answers nothing, so a relay that has not installed one
/// refuses every proof. Failing closed is the only safe default: a relay that
/// resolved nothing and accepted anyway would hand out domains.
#[tokio::test]
async fn a_relay_with_no_resolver_refuses_every_ownership_proof() {
    let tmp = tempfile::tempdir().unwrap().keep();
    let cfg: Config =
        serde_json::from_str(r#"{"domain":{"a.test":{}},"domain_verify_secret":"s3cret"}"#)
            .unwrap();
    let state = RelayState::with_tokens(cfg, tmp, "", "");

    let req = Request::builder()
        .method(Method::POST)
        .uri("/domain/add")
        .body(Body::from(r#"{"domain":"y.jp"}"#))
        .unwrap();
    let res = app(state.clone()).oneshot(req).await.unwrap();
    assert_eq!(res.status().as_u16(), 412);
    assert!(state.dynamic_domains.get("y.jp").is_none());
}

// ── opening the stores ────────────────────────────────────────────────────

/// Every configured account gets a store and the single derived inbox.
///
/// Tested here rather than in `server_interop`: that suite shares the oracle's
/// data directory, so the oracle has already written `mailboxes.json` and
/// removing this port's write changes nothing there. A fresh directory is the
/// only place the write itself is observable.
#[tokio::test]
async fn opening_the_stores_writes_the_derived_inbox() {
    let state = state();
    state.open_stores().expect("stores should open");

    let path = state.data_dir.join("a.test/alice/mailboxes.json");
    let stored: Vec<jmap_types::mailbox::Mailbox> =
        serde_json::from_slice(&std::fs::read(&path).expect("mailboxes.json")).unwrap();
    assert_eq!(stored.len(), 1, "one mailbox per account");
    assert_eq!(
        stored[0].id,
        crate::handler::default_inbox("alice@a.test").id,
        "derived from the address, so a cached id survives a restart"
    );

    // …and the account is resolvable by its address and its aliases.
    assert!(state.accounts.get("alice@a.test").is_some());
    assert!(state.accounts.resolve("alice@a.test").is_some());
}

/// An account with an alias resolves by it. The alias map is built in the same
/// step, so a store without its aliases would take mail nowhere.
#[tokio::test]
async fn opening_the_stores_registers_the_alias_map() {
    let tmp = tempfile::tempdir().unwrap().keep();
    let cfg: Config = serde_json::from_str(
        r#"{"domain":{"a.test":{"account":{"alice":{"alias":["postmaster","a@other.test"]}}}}}"#,
    )
    .unwrap();
    let state = RelayState::with_tokens(cfg, tmp, "", "");
    state.open_stores().unwrap();

    for addr in ["alice@a.test", "postmaster@a.test", "a@other.test"] {
        assert_eq!(
            state.accounts.resolve(addr).map(|a| a.email.clone()),
            Some("alice@a.test".into()),
            "{addr}"
        );
    }
}

// ── /admin/accounts/<address> ─────────────────────────────────────────────

/// The address is split on the **last** `@`, as Go's `LastIndex` does. The
/// bearer guard closes this route in the interop suite, so nothing there
/// reaches the parsing — it is tested here or nowhere.
#[tokio::test]
async fn the_admin_detail_address_splits_on_the_last_at() {
    let state = state_with_tokens("admin-secret", "");
    let acct = state.data_dir.join("a.test").join("odd@name");
    std::fs::create_dir_all(&acct).unwrap();

    let ask = |target: &str| {
        let state = state.clone();
        let req = Request::builder()
            .uri(target.to_string())
            .header(header::AUTHORIZATION, "Bearer admin-secret")
            .body(Body::empty())
            .unwrap();
        async move {
            let res = app(state).oneshot(req).await.unwrap();
            let status = res.status().as_u16();
            let bytes = axum::body::to_bytes(res.into_body(), 1 << 20)
                .await
                .unwrap();
            (status, String::from_utf8_lossy(&bytes).into_owned())
        }
    };

    // Splitting on the first `@` would look for a domain of `name@a.test`.
    let (status, body) = ask("/admin/accounts/odd@name@a.test").await;
    assert_eq!(status, 200, "{body}");
    assert!(body.contains("\"localpart\":\"odd@name\""), "{body}");
    assert!(body.contains("\"domain\":\"a.test\""), "{body}");
}

#[tokio::test]
async fn the_admin_detail_refuses_an_address_that_is_not_one() {
    let state = state_with_tokens("admin-secret", "");
    let ask = |target: &str| {
        let state = state.clone();
        let req = Request::builder()
            .uri(target.to_string())
            .header(header::AUTHORIZATION, "Bearer admin-secret")
            .body(Body::empty())
            .unwrap();
        async move { app(state).oneshot(req).await.unwrap().status().as_u16() }
    };
    for bad in [
        "/admin/accounts/",
        "/admin/accounts/noat",
        "/admin/accounts/@a.test",
        "/admin/accounts/alice@",
    ] {
        assert_eq!(ask(bad).await, 400, "{bad}");
    }
    assert_eq!(
        ask("/admin/accounts/nobody@a.test").await,
        404,
        "a well-formed address with no account"
    );
}

// ── query parsing ─────────────────────────────────────────────────────────

#[test]
fn query_values_are_percent_decoded() {
    let req = |uri: &str| Request::builder().uri(uri).body(()).unwrap();
    assert_eq!(
        query_param(&req("/x?email=a%40b.test"), "email").as_deref(),
        Some("a@b.test")
    );
    assert_eq!(
        query_param(&req("/x?q=one+two"), "q").as_deref(),
        Some("one two"),
        "+ is a space in a query"
    );
    assert_eq!(query_param(&req("/x?a=1&b=2"), "b").as_deref(), Some("2"));
    assert_eq!(query_param(&req("/x?flag"), "flag").as_deref(), Some(""));
    assert_eq!(query_param(&req("/x"), "missing"), None);
    assert_eq!(
        query_param(&req("/x?q=%zz"), "q").as_deref(),
        Some("%zz"),
        "an invalid escape is left as written"
    );
}

// ── what is not wired yet ─────────────────────────────────────────────────

/// The routes without a handler answer 501, not something plausible.
///
/// A 404 or an empty 200 would let `just difftest` pass on a coincidence; 501
/// makes every unwired route show up as a difference until it is wired.
/// An unwired route answers 501 — not 404, and not an empty 200 — so
/// `server_interop` reports it as a difference rather than passing on a
/// coincidence.
///
/// Deliberately does **not** name a route. Three earlier versions of this test
/// hardcoded one and went stale the moment it was wired, each time failing for
/// a reason that had nothing to do with what it was checking. The authoritative
/// list lives in `tests/server_interop.rs`, where it is compared against the
/// oracle; this only pins the shape of the answer.
#[test]
fn the_not_implemented_answer_is_a_501_with_a_plain_body() {
    let res = text_error(501, "not implemented");
    assert_eq!(res.status().as_u16(), 501);
    assert_eq!(
        res.headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("text/plain; charset=utf-8")
    );
    assert_ne!(res.status().as_u16(), 404, "never the mux's own 404");
}
