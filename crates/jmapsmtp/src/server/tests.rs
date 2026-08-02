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
#[tokio::test]
async fn unwired_routes_answer_501_rather_than_something_plausible() {
    // `/account/provision` is still unwired. `tests/server_interop.rs` holds
    // the authoritative list and compares each against the oracle; this only
    // checks the shape of the answer.
    let (status, body, _) = get(state(), "/account/provision").await;
    assert_eq!(status, 501);
    assert_eq!(body, "not implemented\n");
}
