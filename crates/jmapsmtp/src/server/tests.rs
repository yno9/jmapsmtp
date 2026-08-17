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

// ── push and the event stream ─────────────────────────────────────────────

/// An account with a credential, for the routes that need one.
fn state_with_account() -> (Arc<RelayState>, String) {
    use base64::Engine as _;
    const TOKEN: &[u8] = b"server-unit-token-00000000000000";
    let state = state();
    crate::auth_env::write_auth_hash(
        &state.data_dir,
        "a.test",
        "alice",
        &jmapserver::hash_auth_token(TOKEN),
    )
    .unwrap();
    let password = base64::engine::general_purpose::STANDARD.encode(TOKEN);
    let auth = base64::engine::general_purpose::STANDARD.encode(format!("alice@a.test:{password}"));
    (state, auth)
}

/// The stream sends its first frame **immediately**, so a client knows it is
/// live rather than waiting for a change that may be hours away.
#[tokio::test]
async fn the_event_stream_opens_with_a_state_frame() {
    let (state, auth) = state_with_account();
    let req = Request::builder()
        .uri("/jmap/eventsource/")
        .header(header::AUTHORIZATION, format!("Basic {auth}"))
        .body(Body::empty())
        .unwrap();
    let res = app(state.clone()).oneshot(req).await.unwrap();

    assert_eq!(res.status().as_u16(), 200);
    assert_eq!(header(&res, "content-type"), "text/event-stream");
    assert_eq!(header(&res, "cache-control"), "no-cache");
    // Over HTTP/2 a hop-by-hop header is a protocol violation and resets the
    // stream — it surfaced as ERR_HTTP2_PROTOCOL_ERROR after the 200 was
    // already sent.
    assert_eq!(header(&res, "connection"), "", "no keep-alive header");

    let mut body = res.into_body().into_data_stream();
    let first = next_frame(&mut body).await;
    assert_eq!(first, jmapserver::push::STATE_EVENT);

    // A change wakes it again.
    state.hub.notify();
    let second = next_frame(&mut body).await;
    assert_eq!(second, jmapserver::push::STATE_EVENT);
}

async fn next_frame(
    body: &mut (impl futures_util::Stream<Item = Result<axum::body::Bytes, axum::Error>> + Unpin),
) -> String {
    use futures_util::StreamExt as _;
    let chunk = tokio::time::timeout(std::time::Duration::from_secs(5), body.next())
        .await
        .expect("a frame within five seconds")
        .expect("the stream should not end")
        .expect("a readable chunk");
    String::from_utf8_lossy(&chunk).into_owned()
}

/// Subscribe and unsubscribe, through the routes, with persistence — the path
/// a browser actually takes.
#[tokio::test]
async fn a_push_subscription_round_trips_through_the_routes() {
    let (state, auth) = state_with_account();
    state.load_push_subscriptions();

    let post = |state: Arc<RelayState>, target: &'static str, auth: String, body: String| async move {
        let req = Request::builder()
            .method(Method::POST)
            .uri(target)
            .header(header::AUTHORIZATION, format!("Basic {auth}"))
            .body(Body::from(body))
            .unwrap();
        app(state).oneshot(req).await.unwrap().status().as_u16()
    };

    let account = jmap_types::Id::from("alice@a.test");
    assert_eq!(
        post(
            state.clone(),
            "/jmap/push/subscribe",
            auth.clone(),
            r#"{"endpoint":"https://push.test/1","keys":{"p256dh":"k","auth":"a"}}"#.into()
        )
        .await,
        204
    );
    assert_eq!(state.push.read().for_account(&account).len(), 1);

    // Persisted, so a restart does not silently stop notifying.
    assert!(jmapserver::push::PushRegistry::path(&state.data_dir).exists());

    assert_eq!(
        post(
            state.clone(),
            "/jmap/push/unsubscribe",
            auth.clone(),
            r#"{"endpoint":"https://push.test/1"}"#.into()
        )
        .await,
        204
    );
    assert!(state.push.read().for_account(&account).is_empty());

    // A body with no endpoint is a bad request, not a silent no-op.
    assert_eq!(
        post(state.clone(), "/jmap/push/subscribe", auth, r#"{}"#.into()).await,
        400
    );
}

/// One account's credential cannot register a subscription for another: the
/// account comes from the credential, and the body carries no address.
#[tokio::test]
async fn a_push_subscription_is_scoped_to_the_credential() {
    let (state, auth) = state_with_account();
    let req = Request::builder()
        .method(Method::POST)
        .uri("/jmap/push/subscribe")
        .header(header::AUTHORIZATION, format!("Basic {auth}"))
        .body(Body::from(
            r#"{"endpoint":"https://push.test/1","accountId":"bob@a.test"}"#,
        ))
        .unwrap();
    assert_eq!(
        app(state.clone())
            .oneshot(req)
            .await
            .unwrap()
            .status()
            .as_u16(),
        204
    );
    assert_eq!(
        state
            .push
            .read()
            .for_account(&jmap_types::Id::from("alice@a.test"))
            .len(),
        1,
        "registered against the credential"
    );
    assert!(
        state
            .push
            .read()
            .for_account(&jmap_types::Id::from("bob@a.test"))
            .is_empty(),
        "an accountId in the body is ignored"
    );
}

// ── the identity anchor ───────────────────────────────────────────────────

/// A transport that answers from a script and records what it was asked.
#[cfg(feature = "anchor")]
#[derive(Default)]
struct ScriptedAnchor {
    replies: parking_lot::Mutex<Vec<(u16, String)>>,
    seen: parking_lot::Mutex<Vec<String>>,
}

#[cfg(feature = "anchor")]
impl jmapserver::anchor::Transport for ScriptedAnchor {
    fn send(
        &self,
        _method: &str,
        url: &str,
        _token: &str,
        body: Option<&[u8]>,
    ) -> Option<(u16, String)> {
        self.seen.lock().push(format!(
            "{url} {}",
            body.map(|b| String::from_utf8_lossy(b).into_owned())
                .unwrap_or_default()
        ));
        let mut replies = self.replies.lock();
        if replies.is_empty() {
            None
        } else {
            Some(replies.remove(0))
        }
    }
}

#[cfg(feature = "anchor")]
fn anchored_state(replies: Vec<(u16, &str)>) -> (Arc<RelayState>, Arc<ScriptedAnchor>) {
    let tmp = tempfile::tempdir().unwrap().keep();
    let cfg: Config = serde_json::from_str(
        r#"{"domain":{"open.test":{"allow_provision":true}},
            "anchor_url":"https://anchor.test","anchor_token":"relay-secret"}"#,
    )
    .unwrap();
    let mut state = RelayState::with_tokens(cfg, tmp, "", "");
    let transport = Arc::new(ScriptedAnchor {
        replies: parking_lot::Mutex::new(
            replies
                .into_iter()
                .map(|(s, b)| (s, b.to_string()))
                .collect(),
        ),
        seen: Default::default(),
    });
    state.set_anchor(transport.clone());
    (state, transport)
}

#[cfg(feature = "anchor")]
fn webvh_provision() -> String {
    serde_json::json!({
        "username": "carol", "domain": "open.test",
        "did": "did:webvh:QmSCID111111111111111111111111111111111111111:biset.md:carol",
        "did_sig": "c2ln", "bind_ts": 1_785_000_000i64,
        "device_pub_key": "DEVKEY", "device_label": "Laptop",
        "device_vouch_ts": 1_785_000_000i64, "device_vouch_sig": "c2ln",
    })
    .to_string()
}

#[cfg(feature = "anchor")]
async fn provision(state: Arc<RelayState>, body: String) -> (u16, String) {
    let req = Request::builder()
        .method(Method::POST)
        .uri("/account/provision")
        .header(header::HOST, "mail.open.test:8443")
        .body(Body::from(body))
        .unwrap();
    let res = app(state).oneshot(req).await.unwrap();
    let status = res.status().as_u16();
    let bytes = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

/// A did:webvh account is created once the anchor confirms the claim and the
/// vouch. This is the branch that could not be tested before the client
/// existed.
#[cfg(feature = "anchor")]
#[tokio::test]
async fn an_anchored_provision_claims_then_vouches_then_writes_the_device() {
    let (state, anchor) = anchored_state(vec![(201, ""), (200, "")]);
    let (status, body) = provision(state.clone(), webvh_provision()).await;
    assert_eq!(status, 201, "{body}");

    let seen = anchor.seen.lock().clone();
    assert_eq!(seen.len(), 2, "one claim, one vouch");
    assert!(
        seen[0].starts_with("https://anchor.test/_anchor/identity/carol"),
        "{}",
        seen[0]
    );
    assert!(
        seen[1].starts_with("https://anchor.test/_anchor/devices/vouch"),
        "{}",
        seen[1]
    );

    // The claim carries the Host **this relay observed**, not the configured
    // hostname — it is what the client signed against.
    assert!(
        seen[0].contains(r#""host":"mail.open.test:8443""#),
        "{}",
        seen[0]
    );

    // Filed under the DID's SCID, not the human name "carol" — SCID-primary
    // accounts (PLANSCID.md): the account itself is keyed by the permanent
    // SCID segment, and "carol" becomes a delivery alias instead (checked
    // below), so a later username change is never a directory move.
    let acct = crate::auth_env::account_dir(
        &state.data_dir,
        "open.test",
        "qmscid111111111111111111111111111111111111111",
    );
    assert_eq!(
        jmapserver::devicekeys::list_device_keys(&acct).len(),
        1,
        "the device key is written only after the anchor agrees"
    );
    let parsed = serde_json::from_str::<serde_json::Value>(&body).unwrap();
    assert_eq!(parsed["did_bound"], true);
    assert_eq!(
        parsed["email"], "qmscid111111111111111111111111111111111111111@open.test",
        "the client is told its SCID address, not the human name it claimed"
    );
    assert_eq!(
        state
            .accounts
            .resolve("carol@open.test")
            .map(|a| a.email.clone()),
        Some("qmscid111111111111111111111111111111111111111@open.test".to_string()),
        "the human name is registered as an alias to the SCID account"
    );
}

/// The claim happens **before** the vouch. A vouch accepted against a name
/// this DID does not hold would bind a device to somebody else's mailbox.
#[cfg(feature = "anchor")]
#[tokio::test]
async fn a_conflicting_claim_stops_before_the_vouch_is_even_asked() {
    let (state, anchor) = anchored_state(vec![(409, "held by a different key")]);
    let (status, _) = provision(state.clone(), webvh_provision()).await;
    assert_eq!(
        status,
        crate::provision::Refusal::IdentityOwnedByAnother.status()
    );
    assert_eq!(anchor.seen.lock().len(), 1, "the vouch was never asked");
    assert!(
        !crate::auth_env::account_dir(&state.data_dir, "open.test", "carol").exists(),
        "and nothing was written"
    );
}

/// Never "proceed unanchored": an unbound name can be claimed by somebody else
/// later, and the collision surfaces as the original owner losing their
/// address.
#[cfg(feature = "anchor")]
#[tokio::test]
async fn an_unreachable_anchor_refuses_the_provision() {
    let (state, _) = anchored_state(vec![]);
    let (status, _) = provision(state.clone(), webvh_provision()).await;
    assert_eq!(status, 503, "not created unanchored");
    assert!(!crate::auth_env::account_dir(&state.data_dir, "open.test", "carol").exists());
}

/// A rejected proof is 401 and an unreachable anchor is 503. Confusing them
/// sends a user re-deriving a key that was never the problem.
#[cfg(feature = "anchor")]
#[tokio::test]
async fn a_rejected_binding_is_distinguishable_from_an_unreachable_anchor() {
    let (state, _) = anchored_state(vec![(401, "stale timestamp")]);
    assert_eq!(provision(state, webvh_provision()).await.0, 401);

    // And a relay the anchor refuses is 503, not 401 — the proof was never
    // looked at.
    let (state, _) = anchored_state(vec![(403, "unknown relay")]);
    assert_eq!(provision(state, webvh_provision()).await.0, 503);
}

/// The claim can succeed and the vouch still fail; the account is not created.
#[cfg(feature = "anchor")]
#[tokio::test]
async fn a_rejected_vouch_after_a_good_claim_creates_nothing() {
    let (state, anchor) = anchored_state(vec![(201, ""), (401, "bad signature")]);
    let (status, _) = provision(state.clone(), webvh_provision()).await;
    assert_eq!(
        status,
        crate::provision::Refusal::DeviceVouchRejected.status()
    );
    assert_eq!(anchor.seen.lock().len(), 2);
    assert!(!crate::auth_env::account_dir(&state.data_dir, "open.test", "carol").exists());
}

// ── authorized_did_domain: verify-binding instead of claim ─────────────────

#[cfg(feature = "anchor")]
fn authorized_did_domain_state(replies: Vec<(u16, &str)>) -> (Arc<RelayState>, Arc<ScriptedAnchor>) {
    let tmp = tempfile::tempdir().unwrap().keep();
    let cfg: Config = serde_json::from_str(
        r#"{"domain":{"open.test":{"authorized_did_domain":"biset.md"}},
            "anchor_url":"https://anchor.test","anchor_token":"relay-secret"}"#,
    )
    .unwrap();
    let mut state = RelayState::with_tokens(cfg, tmp, "", "");
    let transport = Arc::new(ScriptedAnchor {
        replies: parking_lot::Mutex::new(
            replies
                .into_iter()
                .map(|(s, b)| (s, b.to_string()))
                .collect(),
        ),
        seen: Default::default(),
    });
    state.set_anchor(transport.clone());
    (state, transport)
}

/// The one thing this whole mode exists to prove at the wire level: a domain
/// configured with `authorized_did_domain` hits `/_anchor/verify-binding`,
/// never `/_anchor/identity/*` — the claim registry is not consulted, and
/// nothing is written to it.
#[cfg(feature = "anchor")]
#[tokio::test]
async fn authorized_did_domain_calls_verify_binding_not_claim() {
    let (state, anchor) = authorized_did_domain_state(vec![(200, ""), (200, "")]);
    let (status, body) = provision(state.clone(), webvh_provision()).await;
    assert_eq!(status, 201, "{body}");

    let seen = anchor.seen.lock().clone();
    assert_eq!(seen.len(), 2, "one verify-binding, one vouch");
    assert!(
        seen[0].starts_with("https://anchor.test/_anchor/verify-binding"),
        "expected verify-binding, not the claim registry: {}",
        seen[0]
    );
    assert!(
        !seen[0].contains("/_anchor/identity/"),
        "the claim registry route must never be hit on this path: {}",
        seen[0]
    );
    assert!(
        seen[1].starts_with("https://anchor.test/_anchor/devices/vouch"),
        "{}",
        seen[1]
    );

    // The body carries username explicitly (verify-binding has no
    // localpart-in-path shape the way /_anchor/identity/<localpart> does).
    assert!(seen[0].contains(r#""username":"carol""#), "{}", seen[0]);
    assert!(seen[0].contains(r#""domain":"open.test""#), "{}", seen[0]);
}

/// verify-binding has no 409 — there is no registry entry to conflict with.
/// A rejected binding here is always a 401 (signature/domain/username
/// mismatch), never "owned by a different key".
#[cfg(feature = "anchor")]
#[tokio::test]
async fn a_rejected_verify_binding_is_401_not_a_claim_conflict() {
    let (state, anchor) = authorized_did_domain_state(vec![(401, "DID does not name this username")]);
    let (status, _) = provision(state.clone(), webvh_provision()).await;
    assert_eq!(
        status,
        crate::provision::Refusal::DidBindingRejected.status()
    );
    assert_eq!(anchor.seen.lock().len(), 1, "the vouch was never asked");
    assert!(!crate::auth_env::account_dir(&state.data_dir, "open.test", "carol").exists());
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
        crate::provision::may_provision(&registered, "", "", ""),
        Err(crate::provision::Refusal::DomainNotOpen)
    );
    assert_eq!(
        crate::provision::may_provision(&registered, "", "", &registered.provision_secret),
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

// ── the three credential forms the JMAP routes accept ─────────────────────

/// **biset uses two of these three and never Basic**, which is why this port
/// shipped accepting only Basic and a real client could not log in at all:
/// `Bearer <email>:<token>` on `/jmap/api/`, and `?access_token=` on
/// `/jmap/eventsource/`, because `EventSource` cannot set a header.
///
/// Every interop test here authenticated with Basic, so all of them passed.
/// Found by reading a production access log: `POST /jmap/api/ -> 401` and
/// `GET /jmap/eventsource/?access_token=… -> 401`, against a relay whose data
/// was fine.
#[test]
fn the_jmap_routes_take_a_credential_three_ways() {
    let bearer = req_with_auth("Bearer alice@a.test:secret");
    assert_eq!(
        extract_credentials(&bearer, ""),
        Some(("alice@a.test".into(), "secret".into()))
    );

    let basic = {
        use base64::Engine as _;
        req_with_auth(&format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode("alice@a.test:secret")
        ))
    };
    assert_eq!(
        extract_credentials(&basic, ""),
        Some(("alice@a.test".into(), "secret".into()))
    );

    // Percent-encoded, as a browser sends it: `alice@a.test:secret`.
    let plain = Request::builder().body(()).unwrap();
    assert_eq!(
        extract_credentials(&plain, "access_token=alice%40a.test%3Asecret"),
        Some(("alice@a.test".into(), "secret".into()))
    );
}

/// Go's order: Bearer wins over Basic, and a header wins over the query. A
/// client that sends two must get the same one chosen on either side.
#[test]
fn the_forms_are_tried_in_gos_order() {
    let both = req_with_auth("Bearer from@header:h");
    assert_eq!(
        extract_credentials(&both, "access_token=from%40query:q"),
        Some(("from@header".into(), "h".into())),
        "the header must win"
    );
}

/// A token with no colon is Go's legacy single-password shape: no username.
/// Carried through rather than refused here, because the authenticator owns
/// that decision.
#[test]
fn a_token_without_a_colon_has_no_username() {
    let bearer = req_with_auth("Bearer justatoken");
    assert_eq!(
        extract_credentials(&bearer, ""),
        Some((String::new(), "justatoken".into()))
    );
}

#[test]
fn no_credential_at_all_is_none() {
    let bare = Request::builder().body(()).unwrap();
    assert_eq!(extract_credentials(&bare, ""), None);
    assert_eq!(extract_credentials(&bare, "access_token="), None);
    assert_eq!(extract_credentials(&bare, "other=1"), None);
}

fn req_with_auth(value: &str) -> Request<()> {
    Request::builder()
        .header(header::AUTHORIZATION, value)
        .body(())
        .unwrap()
}

// ── SCID migration (PLANSCID.md) ────────────────────────────────────────────

/// A pre-SCID (human-keyed) dynamic account, set up directly rather than
/// through `/account/provision` — this test only cares about migrating an
/// account that's already in this shape, not about how it got there.
fn state_with_legacy_account() -> (Arc<RelayState>, String) {
    use base64::Engine as _;
    const TOKEN: &[u8] = b"legacy-unit-token-000000000000000";
    let state = state();
    crate::auth_env::write_auth_hash(
        &state.data_dir,
        "a.test",
        "bob",
        &jmapserver::hash_auth_token(TOKEN),
    )
    .unwrap();
    state.register_dyn_account("bob", "a.test");
    let password = base64::engine::general_purpose::STANDARD.encode(TOKEN);
    let auth = base64::engine::general_purpose::STANDARD.encode(format!("bob@a.test:{password}"));
    (state, auth)
}

#[tokio::test]
async fn migrating_to_scid_renames_the_account_and_aliases_the_old_name() {
    let (state, auth) = state_with_legacy_account();
    let did = "did:webvh:QmMigrateTest1111111111111111111111111111111:a.test:bob";

    let req = Request::builder()
        .method(Method::POST)
        .uri("/account/migrate-to-scid")
        .header(header::AUTHORIZATION, format!("Basic {auth}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::json!({ "did": did }).to_string()))
        .unwrap();
    let res = app(state.clone()).oneshot(req).await.unwrap();
    let status = res.status().as_u16();
    let body = String::from_utf8(
        axum::body::to_bytes(res.into_body(), 1 << 20)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert_eq!(status, 200, "{body}");
    let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        parsed["email"], "qmmigratetest1111111111111111111111111111111@a.test",
        "the caller is told its new SCID address"
    );

    // The directory itself moved, not just the in-memory table.
    assert!(
        !state.data_dir.join("a.test/bob").exists(),
        "the old directory should be gone"
    );
    assert!(
        state
            .data_dir
            .join("a.test/qmmigratetest1111111111111111111111111111111")
            .exists(),
        "the account now lives under its SCID"
    );

    // The old name still resolves — a fresh device-session login can still
    // present it, exactly as `left-pane.ts`'s post-migration client flow
    // relies on for anything still pointing at the old address.
    assert_eq!(
        state
            .accounts
            .resolve("bob@a.test")
            .map(|a| a.email.clone()),
        Some("qmmigratetest1111111111111111111111111111111@a.test".to_string())
    );
    assert!(
        state
            .accounts
            .get("qmmigratetest1111111111111111111111111111111@a.test")
            .is_some(),
        "the new primary answers directly too"
    );
}

/// A DID that isn't biset's own webvh shape has no SCID to migrate to — the
/// account keeps working exactly as it was, not silently renamed to
/// something meaningless.
#[tokio::test]
async fn migrating_with_a_non_webvh_did_is_refused_and_changes_nothing() {
    let (state, auth) = state_with_legacy_account();
    let req = Request::builder()
        .method(Method::POST)
        .uri("/account/migrate-to-scid")
        .header(header::AUTHORIZATION, format!("Basic {auth}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::json!({ "did": "did:dht:something" }).to_string(),
        ))
        .unwrap();
    let res = app(state.clone()).oneshot(req).await.unwrap();
    assert_eq!(res.status().as_u16(), 400);
    assert!(state.data_dir.join("a.test/bob").exists(), "untouched");
    assert!(state.accounts.get("bob@a.test").is_some());
}

#[tokio::test]
async fn migrating_without_a_credential_is_unauthorized() {
    let (state, _auth) = state_with_legacy_account();
    let req = Request::builder()
        .method(Method::POST)
        .uri("/account/migrate-to-scid")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::json!({ "did": "did:webvh:QmX:a.test:bob" }).to_string(),
        ))
        .unwrap();
    let res = app(state.clone()).oneshot(req).await.unwrap();
    assert_eq!(res.status().as_u16(), 401);
    assert!(state.data_dir.join("a.test/bob").exists(), "untouched");
}
