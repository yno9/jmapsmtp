//! The HTTP surface: axum carries HTTP/1.1, [`crate::gomux`] does the routing.
//!
//! The split is deliberate. axum's router matches by path segment; Go's
//! `ServeMux` matches by prefix, redirects, and panics on a duplicate pattern —
//! all of which are observable (`gomux.rs`'s header). So axum is used only as a
//! transport, with one catch-all handler that hands the path to the same
//! [`GoMux`] the route table builds.
//!
//! # CORS is applied twice, differently, on purpose
//!
//! Go wraps the whole mux in `WrapCORS` (`GET, POST, PUT, OPTIONS`) *and* sets
//! per-route headers inside individual handlers (`GET, POST, OPTIONS` for the
//! JMAP routes, `PUT, OPTIONS` for key upload, and so on). The inner one wins
//! where both apply, because it is set later.
//!
//! That inconsistency is what the Go implementation actually sends, and the
//! differential harness compares these headers — so it is reproduced rather
//! than tidied up.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{HeaderValue, Request, Response, StatusCode, header};

use crate::auth_env::DynAccounts;
use crate::config::{Config, DynamicDomains};
use crate::gomux::{GoMux, REDIRECT_STATUS, Route};
use crate::handler::Accounts;
use crate::routes::{Guard, RouteSpec, build_mux};

/// Everything the routes need, for the life of the process.
pub struct RelayState {
    pub cfg: Config,
    pub data_dir: std::path::PathBuf,
    pub dynamic_domains: DynamicDomains,
    pub dyn_accounts: DynAccounts,
    pub accounts: Accounts,
    /// The relay-wide OpenPGP key, from `BISET_PGP_KEY`.
    pub global_pgp_key: Option<crate::pgp::PublicKey>,
    /// `ADMIN_TOKEN` and `METRICS_TOKEN`, read **once at startup** — which is
    /// also when Go reads them, at route registration. Holding them here
    /// rather than calling `env::var` per request means the guard's behaviour
    /// is a property of the state a test can construct, not of the process
    /// environment it happens to run in.
    pub admin_token: String,
    pub metrics_token: String,
    /// Broadcasts state changes to event-source subscribers.
    pub hub: Arc<jmapserver::Hub>,
    /// Web Push subscriptions, and the VAPID identity they subscribe under.
    pub push: parking_lot::RwLock<jmapserver::push::PushRegistry>,
    pub vapid: jmapserver::push::Vapid,
    /// Resolves the TXT records that prove control of a custom domain.
    ///
    /// Injected rather than constructed inline so a test can answer without a
    /// network — the alternative is a route whose only test is "does the
    /// internet agree".
    pub txt: Arc<dyn crate::dns::TxtResolver>,
    /// Resolves mail exchangers for outbound delivery.
    pub mx: Arc<dyn crate::smtp_out::MxResolver>,
    /// Talks to the identity anchor. Absent in the anchorless build, where
    /// there is nothing to talk to.
    #[cfg(feature = "anchor")]
    pub anchor: Arc<dyn jmapserver::anchor::Transport>,
    /// Outbound SMTP attempts, by result. Counters, so they only ever rise.
    smtp_sent: std::sync::atomic::AtomicU64,
    smtp_failed: std::sync::atomic::AtomicU64,
    mux: GoMux<RouteSpec>,
}

impl RelayState {
    /// Build the state and the routing table.
    ///
    /// # Panics
    ///
    /// If two routes claim the same pattern — at startup, before the listener
    /// opens, which is the whole point of using [`GoMux`].
    pub fn new(cfg: Config, data_dir: std::path::PathBuf) -> Arc<RelayState> {
        let mux = build_mux(&cfg, false);
        let cfg_vapid = (
            cfg.vapid_public_key.clone(),
            cfg.vapid_private_key.clone(),
            cfg.vapid_subscriber.clone(),
        );
        Arc::new(RelayState {
            cfg,
            data_dir,
            dynamic_domains: DynamicDomains::default(),
            dyn_accounts: DynAccounts::default(),
            accounts: Accounts::default(),
            global_pgp_key: load_global_pgp_key(),
            admin_token: crate::bearer::token_from_env("ADMIN_TOKEN"),
            metrics_token: crate::bearer::token_from_env("METRICS_TOKEN"),
            hub: Arc::new(jmapserver::Hub::new()),
            push: parking_lot::RwLock::new(jmapserver::push::PushRegistry::default()),
            vapid: jmapserver::push::Vapid::new(&cfg_vapid.0, &cfg_vapid.1, &cfg_vapid.2),
            txt: Arc::new(NoDns),
            mx: Arc::new(NoDns),
            #[cfg(feature = "anchor")]
            anchor: crate::anchor::HttpTransport::new(),
            smtp_sent: std::sync::atomic::AtomicU64::new(0),
            smtp_failed: std::sync::atomic::AtomicU64::new(0),
            mux,
        })
    }

    /// Open a [`jmapserver::Store`] for every configured account and register
    /// its aliases — step 11 of SPEC.md §2.
    ///
    /// An account whose store cannot be opened is **fatal**, not skipped:
    /// carrying on would serve a relay that silently drops one account's mail
    /// while looking healthy.
    pub fn open_stores(self: &Arc<Self>) -> Result<(), String> {
        let aliases = crate::startup::build_alias_map(&self.cfg);
        // Hooks are installed after every store exists, because a hook holds
        // an Arc back to this state and the accounts it may consult.
        let mut pending_hooks: Vec<String> = Vec::new();
        for (domain, dom_cfg) in &self.cfg.domains {
            for localpart in dom_cfg.accounts.keys() {
                let localpart = localpart.to_lowercase();
                let primary = format!("{localpart}@{domain}");
                let dir = crate::auth_env::account_dir(&self.data_dir, domain, &localpart);
                let store =
                    jmapserver::Store::open(&dir).map_err(|e| format!("store {primary}: {e}"))?;
                // The single mailbox every account gets. Written on every
                // start, and derived from the address, so a client's cached
                // mailbox id survives a restart.
                let _ = store.put_mailboxes(&[crate::handler::default_inbox(&primary)]);

                let mine: Vec<String> = aliases
                    .iter()
                    .filter(|(_, target)| *target == &primary)
                    .map(|(alias, _)| alias.clone())
                    .collect();
                self.accounts.insert(
                    crate::handler::AccountStore {
                        email: primary.clone(),
                        domain: domain.clone(),
                        localpart,
                        dir,
                        store: Arc::new(store),
                    },
                    &mine,
                );
                pending_hooks.push(primary);
            }
        }
        for primary in pending_hooks {
            if let Some(account) = self.accounts.get(&primary) {
                crate::submit::install_hooks(self, &account);
            }
        }
        Ok(())
    }

    /// The JMAP server view of this relay.
    fn jmap(&self) -> jmapserver::Server {
        jmapserver::Server {
            cfg: self.cfg.server_config(),
            handler: Arc::new(crate::handler::RelayHandler {
                accounts: Arc::new(crate::handler::Accounts::clone_of(&self.accounts)),
                hub: self.hub.clone(),
            }),
            hub: self.hub.clone(),
            // Credentials are resolved at the HTTP edge, before a request
            // reaches here, so the library's own auth is not installed —
            // leaving it unset would fall through to its accept-everything
            // default (server.rs's `authenticate`).
            auth: Some(Arc::new(|_, _| None)),
        }
    }

    /// As [`RelayState::new`], with the bearer tokens supplied rather than
    /// read from the environment.
    pub fn with_tokens(
        cfg: Config,
        data_dir: std::path::PathBuf,
        admin_token: &str,
        metrics_token: &str,
    ) -> Arc<RelayState> {
        let state = RelayState::new(cfg, data_dir);
        let mut state = Arc::try_unwrap(state).ok().expect("freshly created");
        state.admin_token = admin_token.to_string();
        state.metrics_token = metrics_token.to_string();
        Arc::new(state)
    }

    pub fn patterns(&self) -> Vec<&str> {
        self.mux.patterns()
    }

    /// Load persisted push subscriptions and keep writing them there.
    ///
    /// A browser does not re-subscribe unprompted, so subscriptions lost on
    /// restart are lost permanently — the user simply stops being notified.
    pub fn load_push_subscriptions(&self) {
        self.push.write().set_persist_dir(&self.data_dir);
    }

    /// Replace the anchor transport. For tests: the live one talks to a real
    /// anchor, and the branch it guards is otherwise unreachable.
    #[cfg(all(test, feature = "anchor"))]
    pub fn set_anchor(
        self: &mut Arc<RelayState>,
        transport: Arc<dyn jmapserver::anchor::Transport>,
    ) {
        if let Some(state) = Arc::get_mut(self) {
            state.anchor = transport;
        }
    }

    /// Install the live DNS client. Must be called from inside a runtime.
    pub fn with_dns(self: &mut Arc<RelayState>) {
        if let Some(state) = Arc::get_mut(self) {
            let dns = crate::dns::SystemDns::new();
            state.txt = dns.clone();
            state.mx = dns;
        }
    }

    /// Record the outcome of one outbound send.
    pub fn record_smtp_outbound(&self, sent: bool) {
        use std::sync::atomic::Ordering;
        if sent {
            self.smtp_sent.fetch_add(1, Ordering::Relaxed);
        } else {
            self.smtp_failed.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// `(sent, failed)`.
    pub fn smtp_outbound(&self) -> (u64, u64) {
        use std::sync::atomic::Ordering;
        (
            self.smtp_sent.load(Ordering::Relaxed),
            self.smtp_failed.load(Ordering::Relaxed),
        )
    }
}

/// The resolver a relay has before one is installed.
///
/// Answers nothing, which refuses every ownership proof. Failing closed is the
/// only safe default: a relay that resolved nothing but accepted anyway would
/// hand out domains.
struct NoDns;

impl crate::dns::TxtResolver for NoDns {
    fn lookup_txt(&self, _name: &str) -> Vec<String> {
        Vec::new()
    }
}

impl crate::smtp_out::MxResolver for NoDns {
    /// No exchangers, so every direct send fails rather than going somewhere
    /// unintended. A relay host, if configured, bypasses this entirely.
    fn lookup_mx(&self, _domain: &str) -> Vec<String> {
        Vec::new()
    }
}

/// The relay-wide key, read from `BISET_PGP_KEY` as armored text.
///
/// A key that will not parse is treated as absent rather than fatal: it only
/// affects WKD lookups that would otherwise fall through, and refusing to start
/// over it would take mail down for a directory feature.
fn load_global_pgp_key() -> Option<crate::pgp::PublicKey> {
    let armored = std::env::var("BISET_PGP_KEY").ok()?;
    match crate::pgp::parse_public_key(armored.as_bytes()) {
        Ok(key) => Some(key),
        Err(e) => {
            eprintln!("[pgp] BISET_PGP_KEY did not parse, continuing without it: {e}");
            None
        }
    }
}

/// The outer CORS headers.
///
/// **Filled in only where a handler set nothing**, because Go's wrapper writes
/// them *before* calling the handler and a handler's own `Header().Set`
/// overwrites. So `/relay-info` answers `GET, OPTIONS` — its own list — not
/// the wrapper's `GET, POST, PUT, OPTIONS`.
///
/// Applying these unconditionally after dispatch inverts that, and every
/// per-route list disappears. Found by running the two servers side by side.
fn fill_outer_cors(res: &mut Response<Body>) {
    let h = res.headers_mut();
    for (name, value) in [
        (header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"),
        (
            header::ACCESS_CONTROL_ALLOW_HEADERS,
            "Authorization, Content-Type",
        ),
        (
            header::ACCESS_CONTROL_ALLOW_METHODS,
            "GET, POST, PUT, OPTIONS",
        ),
    ] {
        if !h.contains_key(&name) {
            h.insert(name, HeaderValue::from_static(value));
        }
    }
}

/// A handler's own CORS headers, which override the wrapper's.
pub fn set_route_cors(res: &mut Response<Body>, methods: &'static str, headers: &'static str) {
    let h = res.headers_mut();
    h.insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    h.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static(methods),
    );
    if !headers.is_empty() {
        h.insert(
            header::ACCESS_CONTROL_ALLOW_HEADERS,
            HeaderValue::from_static(headers),
        );
    }
}

/// Go's `http.Error`: a plain-text body with a trailing newline, and the
/// nosniff header.
pub fn text_error(status: u16, message: &str) -> Response<Body> {
    let mut res = Response::new(Body::from(format!("{message}\n")));
    *res.status_mut() = StatusCode::from_u16(status).expect("a valid status");
    res.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    res.headers_mut().insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    res
}

/// `http.Redirect` for a GET: a `Location` header **and** an HTML body.
///
/// The body is easy to miss — a redirect is normally read by a client that
/// ignores it — but it is on the wire, and `fmt.Fprintln` over a string that
/// already ends in a newline is why there are two.
pub fn redirect(to: &str) -> Response<Body> {
    let body = format!(
        "<a href=\"{}\">Temporary Redirect</a>.\n\n",
        html_escape(to)
    );
    let mut res = Response::new(Body::from(body));
    *res.status_mut() = StatusCode::from_u16(REDIRECT_STATUS).expect("a valid redirect status");
    if let Ok(v) = HeaderValue::from_str(to) {
        res.headers_mut().insert(header::LOCATION, v);
    }
    res.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    res
}

/// `html.EscapeString`, which is what `http.Redirect` runs the URL through.
fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '\'' => out.push_str("&#39;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&#34;"),
            c => out.push(c),
        }
    }
    out
}

/// `http.NotFound`'s exact body — the mux's own 404, distinct from a handler's.
pub fn mux_not_found() -> Response<Body> {
    text_error(404, "404 page not found")
}

/// A JSON body **with a trailing newline**, as `json.NewEncoder(w).Encode`
/// writes one. Every JSON response in the Go implementation goes through an
/// Encoder, so the newline is on all of them.
pub fn json_response(status: u16, mut body: Vec<u8>) -> Response<Body> {
    if !body.ends_with(b"\n") {
        body.push(b'\n');
    }
    let mut res = Response::new(Body::from(body));
    *res.status_mut() = StatusCode::from_u16(status).expect("a valid status");
    res.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    res
}

pub fn no_content() -> Response<Body> {
    let mut res = Response::new(Body::empty());
    *res.status_mut() = StatusCode::NO_CONTENT;
    res
}

/// A 401 that also tells the client how to authenticate.
///
/// The relay's own routes challenge with `Basic realm="biset"`; the JMAP
/// library's challenge with `Bearer realm="jmap"` — see [`unauthorized_jmap`].
/// Two different strings for the same 401, and both are on the wire.
pub fn unauthorized() -> Response<Body> {
    let mut res = text_error(401, "unauthorized");
    res.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static("Basic realm=\"biset\""),
    );
    res
}

/// The JMAP routes' 401. `jmapserver` writes `Bearer realm="jmap"` where the
/// relay's own handlers write `Basic realm="biset"` — a client that acts on
/// the challenge sees a different one depending on which route it hit.
pub fn unauthorized_jmap() -> Response<Body> {
    let mut res = text_error(401, "unauthorized");
    res.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static("Bearer realm=\"jmap\""),
    );
    res
}

/// Resolve HTTP Basic credentials to an account.
///
/// Returns `(domain, localpart)`. The target of every per-account route comes
/// from here and never from the request body or query — which is what makes
/// those routes incapable of acting on somebody else's account.
pub fn authenticate(state: &RelayState, req: &Request<()>) -> Option<(String, String)> {
    use base64::Engine as _;
    let header = req.headers().get(header::AUTHORIZATION)?.to_str().ok()?;
    let encoded = header.strip_prefix("Basic ")?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    let (username, password) = decoded.split_once(':')?;

    let id = crate::auth_env::authenticate(
        &state.cfg,
        &state.dyn_accounts,
        &state.data_dir,
        username,
        password,
    )?;
    let (localpart, domain) = id.as_str().split_once('@')?;
    Some((domain.to_string(), localpart.to_string()))
}

/// The entry point: route, dispatch, then apply the outer CORS.
pub async fn handle(state: Arc<RelayState>, req: Request<Body>) -> Response<Body> {
    let path = req.uri().path().to_string();
    let query = req.uri().query().unwrap_or("").to_string();

    // OPTIONS is answered by the outer wrapper before routing, so a preflight
    // to an unrouted path still succeeds — which is what Go does.
    if req.method() == axum::http::Method::OPTIONS {
        let mut res = no_content();
        fill_outer_cors(&mut res);
        return res;
    }

    let mut res = match state.mux.route(&path, &query) {
        Route::Redirect(to) => redirect(&to),
        Route::NotFound => mux_not_found(),
        Route::Found { pattern, handler } => {
            let (pattern, guard) = (pattern.to_string(), handler.guard);
            dispatch(state.clone(), &pattern, guard, req).await
        }
    };
    fill_outer_cors(&mut res);
    res
}

/// Route a matched request to its handler.
///
/// Not yet complete: the routes without an arm here answer 501 rather than
/// something plausible, so `just difftest` reports them as differences instead
/// of passing on a coincidence. Each is a named milestone, not an oversight.
async fn dispatch(
    state: Arc<RelayState>,
    pattern: &str,
    guard: Guard,
    req: Request<Body>,
) -> Response<Body> {
    // The bearer routes are checked here rather than in each handler, so a new
    // admin route cannot be added without one.
    if guard == Guard::Bearer {
        let token = match pattern {
            "/metrics" => &state.metrics_token,
            _ => &state.admin_token,
        };
        let presented = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if crate::bearer::check(token, presented) == crate::bearer::Bearer::Deny {
            let mut res = text_error(401, "unauthorized");
            res.headers_mut()
                .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
            return res;
        }
    }

    // Read the body once, here, so every handler below stays synchronous —
    // which is what lets them be unit-tested without a runtime.
    let (parts, body) = req.into_parts();
    let body = axum::body::to_bytes(body, 1 << 24)
        .await
        .unwrap_or_default();
    let req = Request::from_parts(parts, ());

    match pattern {
        "/relay-info" => handlers::relay_info(&state),
        "/setup" => handlers::setup(&state, &req),
        "/.well-known/openpgpkey/policy" => handlers::wkd_policy(),
        "/.well-known/openpgpkey/hu/" => handlers::wkd_lookup(&state, &req),
        "/pgp/pubkey" => handlers::pgp_pubkey(&state, &req, &body),
        "/pgp/privkey" => handlers::pgp_privkey(&state, &req, &body),
        "/pgp/peerkey" => handlers::pgp_peerkey(&state, &req, &body),
        "/auth/envelope" => handlers::auth_envelope(&state, &req, &body),
        "/auth/signup" => handlers::auth_signup(&state, &req, &body),
        "/contacts" => handlers::contacts_list(&state, &req),
        "/contacts/" => handlers::contacts_put(&state, &req, &body),
        "/account/session" => handlers::account_session(&state, &req, &body),
        "/account/devices" => handlers::account_devices(&state, &req, &body),
        "/account/storage" => handlers::storage_summary(&state, &req),
        "/account/storage/messages" => handlers::storage_messages(&state, &req),
        "/account/storage/export" => handlers::storage_export(&state, &req),
        "/admin/accounts" => handlers::admin_accounts(&state, &req),
        "/admin/accounts/" => handlers::admin_account_detail(&state, &req),
        "/.well-known/jmap" => handlers::jmap_session(&state, &req),
        "/jmap/api/" => handlers::jmap_api(&state, &req, &body),
        "/account/provision" => handlers::account_provision(&state, &req, &body),
        // Only in the anchor build, mirroring `routes.rs`: the noanchor build
        // does not mount these patterns at all, so there is nothing for the
        // arms to catch and the handlers would not compile — they reach
        // `state.anchor`, which is itself `cfg(feature = "anchor")`.
        #[cfg(feature = "anchor")]
        "/account/did" => handlers::account_did(&state, &req, &body),
        #[cfg(feature = "anchor")]
        "/pkarr/" => handlers::pkarr(&state, &req, &body),
        #[cfg(feature = "anchor")]
        "/admin/drain-anchor" => handlers::drain_anchor(&state, &req),
        "/account/delete" => handlers::account_delete(&state, &req),
        "/account/storage/purge-messages" => handlers::storage_purge(&state, &req),
        "/admin/dashboard" => handlers::admin_dashboard(),
        "/metrics" => handlers::metrics(&state),
        "/domain/verify-token" => handlers::domain_verify_token(&state, &req),
        "/domain/add" => handlers::domain_add(&state, &req, &body),
        "/jmap/push/vapid-public-key" => handlers::push_vapid_key(&state),
        "/jmap/push/subscribe" => handlers::push_subscribe(&state, &req, &body),
        "/jmap/push/unsubscribe" => handlers::push_unsubscribe(&state, &req, &body),
        "/jmap/eventsource/" => handlers::event_source(&state, &req),
        _ => text_error(501, "not implemented"),
    }
}

mod handlers {
    use super::*;

    pub fn relay_info(state: &RelayState) -> Response<Body> {
        let info = crate::setup::relay_info(&state.cfg);
        match jmap_types::go_json::to_vec(&info) {
            Ok(body) => {
                let mut res = json_response(200, body);
                set_route_cors(&mut res, "GET, OPTIONS", "Authorization, Content-Type");
                res
            }
            Err(_) => text_error(500, "internal error"),
        }
    }

    pub fn setup(state: &RelayState, req: &Request<()>) -> Response<Body> {
        let token = query_param(req, "token").unwrap_or_default();
        if token.is_empty() {
            return text_error(400, crate::setup::SetupError::TokenRequired.message());
        }
        // The token is checked before the method, matching Go: a wrong method
        // with a good token is 405, a wrong method with a bad token is 401.
        let Ok((domain, localpart)) =
            crate::setup::account_for_token(&state.cfg, &state.data_dir, &token)
        else {
            return text_error(401, crate::setup::SetupError::InvalidToken.message());
        };
        if req.method() != axum::http::Method::GET {
            return text_error(405, "method not allowed");
        }
        let mut res = Response::new(Body::from(crate::setup_page::render(
            &localpart, &domain, &token,
        )));
        res.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/html; charset=utf-8"),
        );
        res
    }

    // ── helpers ───────────────────────────────────────────────────────────

    /// Every per-account route resolves its target here and nowhere else. An
    /// address in a query or a body is never consulted, which is what makes
    /// these routes incapable of acting on someone else's account.
    fn account(state: &RelayState, req: &Request<()>) -> Option<(String, String)> {
        authenticate(state, req)
    }

    fn method_not_allowed() -> Response<Body> {
        text_error(405, "method not allowed")
    }

    // ── WKD ───────────────────────────────────────────────────────────────

    /// A marker: an empty 200 *is* the answer, and its absence is how a WKD
    /// client learns a domain does not do WKD.
    pub fn wkd_policy() -> Response<Body> {
        let mut res = Response::new(Body::empty());
        *res.status_mut() = StatusCode::OK;
        res
    }

    /// The public directory. Unauthenticated by design — a stranger has to be
    /// able to find a key before they can encrypt to you.
    pub fn wkd_lookup(state: &RelayState, req: &Request<()>) -> Response<Body> {
        let hash = req
            .uri()
            .path()
            .strip_prefix("/.well-known/openpgpkey/hu/")
            .unwrap_or_default();
        let localpart = query_param(req, "l").unwrap_or_default();

        let data_dir = &state.data_dir;
        let key = match crate::wkd::resolve_wkd(
            &state.cfg,
            hash,
            &localpart,
            state.global_pgp_key.is_some(),
            |d, l| crate::wkd::pubkey_file(data_dir, d, l).exists(),
        ) {
            crate::wkd::WkdLookup::UserKey { domain, localpart } => {
                crate::wkd::serve_pubkey(data_dir, &domain, &localpart)
            }
            crate::wkd::WkdLookup::GlobalKey => state
                .global_pgp_key
                .as_ref()
                .and_then(|k| crate::pgp::serialize_public_key(k).ok()),
            crate::wkd::WkdLookup::NotFound => None,
        };
        match key {
            Some(key) => {
                let mut res = octet_stream(key);
                res.headers_mut().insert(
                    header::ACCESS_CONTROL_ALLOW_ORIGIN,
                    HeaderValue::from_static("*"),
                );
                res
            }
            None => mux_not_found(),
        }
    }

    pub fn pgp_pubkey(state: &RelayState, req: &Request<()>, body: &[u8]) -> Response<Body> {
        let mut res = if req.method() != axum::http::Method::PUT {
            method_not_allowed()
        } else {
            match account(state, req) {
                None => unauthorized(),
                Some((domain, localpart)) => {
                    match crate::wkd::store_pubkey(&state.data_dir, &domain, &localpart, body) {
                        Ok(()) => no_content(),
                        Err(e) => text_error(e.status(), e.message()),
                    }
                }
            }
        };
        set_route_cors(&mut res, "PUT, OPTIONS", "Authorization, Content-Type");
        res
    }

    /// The client-side-encrypted private key blob. Encrypted before it gets
    /// here, but still the private key — it leaves only against the account's
    /// own credential.
    pub fn pgp_privkey(state: &RelayState, req: &Request<()>, body: &[u8]) -> Response<Body> {
        let mut res = match account(state, req) {
            None => unauthorized(),
            Some((domain, localpart)) => match *req.method() {
                axum::http::Method::GET => {
                    match crate::wkd::read_privkey(&state.data_dir, &domain, &localpart) {
                        Some(blob) => json_response_raw(200, blob),
                        None => mux_not_found(),
                    }
                }
                axum::http::Method::PUT => {
                    match crate::wkd::store_privkey(&state.data_dir, &domain, &localpart, body) {
                        Ok(()) => no_content(),
                        Err(_) => text_error(500, "internal error"),
                    }
                }
                _ => method_not_allowed(),
            },
        };
        set_route_cors(&mut res, "GET, PUT, OPTIONS", "Authorization, Content-Type");
        res
    }

    /// Autocrypt peer keys, gathered from incoming mail. Per **domain**, not
    /// per account.
    pub fn pgp_peerkey(state: &RelayState, req: &Request<()>, body: &[u8]) -> Response<Body> {
        let mut res = (|| {
            if !matches!(
                *req.method(),
                axum::http::Method::GET | axum::http::Method::PUT
            ) {
                return method_not_allowed();
            }
            // A plain 401 with no WWW-Authenticate, unlike its neighbours.
            let Some((domain, _)) = authenticate(state, req) else {
                return text_error(401, "unauthorized");
            };
            let Some(addr) = query_param(req, "addr").filter(|a| !a.is_empty()) else {
                return text_error(400, crate::wkd::KeyError::AddrRequired.message());
            };
            let path = crate::wkd::peer_key_path(&state.data_dir, &domain, &addr);
            if *req.method() == axum::http::Method::GET {
                match std::fs::read(&path) {
                    Ok(b) => octet_stream(b),
                    Err(_) => text_error(404, crate::wkd::KeyError::NotFound.message()),
                }
            } else {
                if let Some(parent) = path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                match std::fs::write(&path, body) {
                    Ok(()) => no_content(),
                    Err(_) => text_error(500, "internal error"),
                }
            }
        })();
        set_route_cors(&mut res, "GET, PUT, OPTIONS", "Authorization, Content-Type");
        res
    }

    // ── onboarding ────────────────────────────────────────────────────────

    pub fn auth_envelope(state: &RelayState, req: &Request<()>, body: &[u8]) -> Response<Body> {
        let mut res = match *req.method() {
            axum::http::Method::GET => {
                let email = query_param(req, "email").unwrap_or_default();
                match crate::setup::read_envelope_for(
                    &state.cfg,
                    &state.dynamic_domains,
                    &state.data_dir,
                    &email,
                ) {
                    Ok(bytes) => json_response_raw(200, bytes),
                    Err(crate::setup::SetupError::NotFound) => mux_not_found(),
                    Err(e) => text_error(e.status(), e.message()),
                }
            }
            axum::http::Method::PUT => match account(state, req) {
                None => unauthorized(),
                Some((domain, localpart)) => {
                    match crate::setup::replace_envelope(&state.data_dir, &domain, &localpart, body)
                    {
                        Ok(()) => no_content(),
                        Err(e) => text_error(e.status(), e.message()),
                    }
                }
            },
            _ => method_not_allowed(),
        };
        set_route_cors(&mut res, "GET, PUT, OPTIONS", "Authorization, Content-Type");
        res
    }

    pub fn auth_signup(state: &RelayState, req: &Request<()>, body: &[u8]) -> Response<Body> {
        let mut res = if req.method() != axum::http::Method::POST {
            method_not_allowed()
        } else {
            let token = query_param(req, "token").unwrap_or_default();
            match crate::setup::signup(&state.cfg, &state.data_dir, &token, body) {
                Ok(_) => no_content(),
                Err(e) => text_error(e.status(), e.message()),
            }
        };
        set_route_cors(&mut res, "POST, OPTIONS", "Content-Type");
        res
    }

    // ── contacts ──────────────────────────────────────────────────────────

    pub fn contacts_list(state: &RelayState, req: &Request<()>) -> Response<Body> {
        if req.method() != axum::http::Method::GET {
            return method_not_allowed();
        }
        let Some((domain, localpart)) = authenticate(state, req) else {
            return text_error(401, "unauthorized");
        };
        let dir = crate::auth_env::account_dir(&state.data_dir, &domain, &localpart);
        let cards = jmapserver::contacts::read_contacts(&dir);
        match jmap_types::go_json::to_vec(&std::collections::BTreeMap::from([("cards", cards)])) {
            Ok(body) => json_response(200, body),
            Err(_) => text_error(500, "internal error"),
        }
    }

    pub fn contacts_put(state: &RelayState, req: &Request<()>, body: &[u8]) -> Response<Body> {
        if req.method() != axum::http::Method::PUT {
            return method_not_allowed();
        }
        let uid = req
            .uri()
            .path()
            .strip_prefix("/contacts/")
            .unwrap_or_default()
            .to_string();
        if uid.is_empty() {
            return mux_not_found();
        }
        let Some((domain, localpart)) = authenticate(state, req) else {
            return text_error(401, "unauthorized");
        };
        match jmapserver::contacts::parse_upsert(&uid, body) {
            Err(e) => text_error(e.status(), e.message()),
            Ok(card) => {
                let dir = crate::auth_env::account_dir(&state.data_dir, &domain, &localpart);
                if std::fs::create_dir_all(&dir).is_err() {
                    return text_error(500, "internal error");
                }
                match jmapserver::contacts::put_contact(&dir, card) {
                    Ok(()) => no_content(),
                    Err(_) => text_error(500, "internal error"),
                }
            }
        }
    }
    // ── devices and sessions ──────────────────────────────────────────────

    /// Login. **No Basic Auth**: a device signature over
    /// `session:<did>:<devicePubKey>:<ts>` is the whole credential.
    pub fn account_session(state: &RelayState, req: &Request<()>, body: &[u8]) -> Response<Body> {
        let mut res = if req.method() != axum::http::Method::POST {
            method_not_allowed()
        } else {
            match serde_json::from_slice::<crate::devices::SessionRequest>(body) {
                Err(_) => text_error(400, "invalid JSON"),
                Ok(login) => match crate::devices::login(&state.data_dir, &login, now_unix()) {
                    Err(e) => text_error(e.status(), e.message()),
                    Ok(session) => match jmap_types::go_json::to_vec(&session) {
                        Ok(body) => json_response(200, body),
                        Err(_) => text_error(500, "internal error"),
                    },
                },
            }
        };
        set_route_cors(&mut res, "POST, OPTIONS", "Content-Type");
        res
    }

    /// One pattern, three methods. **POST is not behind `authenticate`** — the
    /// vouch signature is the proof, and that is what makes a cold recovery
    /// (mnemonic only, fresh install, no session) possible at all. GET and
    /// DELETE act on an account that already exists, so they do require a
    /// credential.
    pub fn account_devices(state: &RelayState, req: &Request<()>, body: &[u8]) -> Response<Body> {
        let mut res = (|| {
            if *req.method() == axum::http::Method::POST {
                return vouch_device(state, body);
            }
            let Some((domain, localpart)) = authenticate(state, req) else {
                return unauthorized();
            };
            let acct = crate::auth_env::account_dir(&state.data_dir, &domain, &localpart);
            match *req.method() {
                axum::http::Method::GET => {
                    let keys = jmapserver::devicekeys::list_device_keys(&acct);
                    match jmap_types::go_json::to_vec(&keys) {
                        Ok(body) => json_response(200, body),
                        Err(_) => text_error(500, "internal error"),
                    }
                }
                axum::http::Method::DELETE => {
                    let Some(id) = query_param(req, "id").filter(|i| !i.is_empty()) else {
                        return text_error(400, crate::devices::DeviceError::IdRequired.message());
                    };
                    match jmapserver::devicekeys::remove_device_key(&acct, &id) {
                        Ok(()) => no_content(),
                        Err(_) => text_error(500, "internal error"),
                    }
                }
                _ => method_not_allowed(),
            }
        })();
        set_route_cors(
            &mut res,
            "GET, POST, DELETE, OPTIONS",
            "Authorization, Content-Type",
        );
        res
    }

    fn vouch_device(state: &RelayState, body: &[u8]) -> Response<Body> {
        let Ok(vouch) = serde_json::from_slice::<crate::devices::VouchRequest>(body) else {
            return text_error(400, "invalid JSON");
        };
        let (localpart, domain) = match vouch.account() {
            Ok(v) => v,
            Err(e) => return text_error(e.status(), e.message()),
        };
        if !crate::devices::account_exists(&state.data_dir, &domain, &localpart) {
            let e = crate::devices::DeviceError::NoSuchAccount;
            return text_error(e.status(), e.message());
        }
        match crate::devices::check_vouch(&state.cfg, &vouch, now_unix()) {
            Err(e) => text_error(e.status(), e.message()),
            Ok(crate::provision::VouchPath::Anchor) => {
                #[cfg(feature = "anchor")]
                {
                    let verdict = jmapserver::anchor::vouch_device(
                        state.anchor.as_ref(),
                        &crate::anchor::anchor_ref(&state.cfg),
                        &localpart,
                        &domain,
                        &vouch.did,
                        &jmapserver::anchor::DeviceVouchProof {
                            device_pub_key: vouch.device_pub_key.clone(),
                            label: vouch.label.clone(),
                            sig: vouch.sig.clone(),
                            ts: vouch.bind_ts,
                        },
                    );
                    match crate::anchor::device_error(verdict) {
                        Some(e) => text_error(e.status(), e.message()),
                        None => match crate::devices::write_device(
                            &state.data_dir,
                            &domain,
                            &localpart,
                            &vouch,
                            now_unix(),
                        ) {
                            Ok(()) => no_content(),
                            Err(_) => text_error(500, "internal error"),
                        },
                    }
                }
                #[cfg(not(feature = "anchor"))]
                {
                    let e = crate::devices::DeviceError::AnchorUnavailable;
                    text_error(e.status(), e.message())
                }
            }
            Ok(_) => {
                match crate::devices::write_device(
                    &state.data_dir,
                    &domain,
                    &localpart,
                    &vouch,
                    now_unix(),
                ) {
                    Ok(()) => no_content(),
                    Err(_) => text_error(500, "internal error"),
                }
            }
        }
    }

    // ── storage ───────────────────────────────────────────────────────────

    pub fn storage_summary(state: &RelayState, req: &Request<()>) -> Response<Body> {
        storage_route(state, req, "GET, OPTIONS", |data, domain, localpart| {
            let entries = jmapserver::storage::list_account_storage(data, domain, localpart)
                .unwrap_or_default();
            jmap_types::go_json::to_vec(&jmapserver::storage::storage_summary(entries)).ok()
        })
    }

    pub fn storage_messages(state: &RelayState, req: &Request<()>) -> Response<Body> {
        storage_route(state, req, "GET, OPTIONS", |data, domain, localpart| {
            let files = jmapserver::storage::list_message_files(data, domain, localpart)
                .unwrap_or_default();
            jmap_types::go_json::to_vec(&std::collections::BTreeMap::from([("files", files)])).ok()
        })
    }

    /// Every file exactly as it sits on disk, base64-encoded.
    pub fn storage_export(state: &RelayState, req: &Request<()>) -> Response<Body> {
        storage_route(state, req, "GET, OPTIONS", |data, domain, localpart| {
            use base64::Engine as _;
            let files: std::collections::BTreeMap<String, String> =
                jmapserver::storage::export_account_storage(data, domain, localpart)
                    .into_iter()
                    .map(|(k, v)| (k, base64::engine::general_purpose::STANDARD.encode(v)))
                    .collect();
            let mut out = serde_json::Map::new();
            out.insert(
                "email".into(),
                serde_json::Value::String(format!("{localpart}@{domain}")),
            );
            out.insert("files".into(), serde_json::to_value(files).ok()?);
            jmap_types::go_json::to_vec(&serde_json::Value::Object(out)).ok()
        })
    }

    fn storage_route(
        state: &RelayState,
        req: &Request<()>,
        methods: &'static str,
        render: impl Fn(&std::path::Path, &str, &str) -> Option<Vec<u8>>,
    ) -> Response<Body> {
        let mut res = if req.method() != axum::http::Method::GET {
            method_not_allowed()
        } else {
            match authenticate(state, req) {
                None => unauthorized(),
                Some((domain, localpart)) => match render(&state.data_dir, &domain, &localpart) {
                    Some(body) => json_response(200, body),
                    None => text_error(500, "internal error"),
                },
            }
        };
        set_route_cors(&mut res, methods, "Authorization, Content-Type");
        res
    }

    // ── admin ─────────────────────────────────────────────────────────────

    pub fn admin_accounts(state: &RelayState, req: &Request<()>) -> Response<Body> {
        if req.method() != axum::http::Method::GET {
            return method_not_allowed();
        }
        let accounts: Vec<jmapserver::admin::AccountSummary> =
            jmapserver::admin::list_provisioned(&state.data_dir)
                .into_iter()
                .map(|a| {
                    let last = jmapserver::activity::read_activity(
                        &state.data_dir,
                        &a.domain,
                        &a.localpart,
                        1,
                    )
                    .ok()
                    .and_then(|mut v| v.drain(..).next())
                    .map(|e| e.time);
                    jmapserver::admin::account_summary(
                        &state.data_dir,
                        &a.domain,
                        &a.localpart,
                        last,
                    )
                })
                .collect();

        let mut out = serde_json::Map::new();
        out.insert("relay".into(), state.cfg.relay_label.clone().into());
        out.insert("version".into(), crate::VERSION.into());
        match serde_json::to_value(&accounts) {
            Ok(v) => out.insert("accounts".into(), v),
            Err(_) => return text_error(500, "internal error"),
        };
        match jmap_types::go_json::to_vec(&serde_json::Value::Object(out)) {
            Ok(body) => json_response(200, body),
            Err(_) => text_error(500, "internal error"),
        }
    }

    pub fn admin_account_detail(state: &RelayState, req: &Request<()>) -> Response<Body> {
        if req.method() != axum::http::Method::GET {
            return method_not_allowed();
        }
        let addr = req
            .uri()
            .path()
            .strip_prefix("/admin/accounts/")
            .unwrap_or_default();
        // The **last** `@`, because a localpart may contain one.
        let Some(at) = addr.rfind('@') else {
            return text_error(400, "bad address");
        };
        if at == 0 || at == addr.len() - 1 {
            return text_error(400, "bad address");
        }
        let (localpart, domain) = (&addr[..at], &addr[at + 1..]);
        if !state.data_dir.join(domain).join(localpart).exists() {
            return text_error(404, "not found");
        }
        let limit = query_param(req, "limit")
            .and_then(|q| q.parse::<usize>().ok())
            .filter(|n| *n > 0)
            .unwrap_or(jmapserver::activity::DEFAULT_LIMIT);

        let activity =
            jmapserver::activity::read_activity(&state.data_dir, domain, localpart, limit)
                .unwrap_or_default();
        let summary = jmapserver::admin::account_summary(
            &state.data_dir,
            domain,
            localpart,
            activity.first().map(|e| e.time.clone()),
        );
        let usage: std::collections::BTreeMap<String, u64> =
            jmapserver::admin::usage_breakdown(&state.data_dir, domain, localpart)
                .into_iter()
                .collect();

        // The detail embeds the summary's fields, so it is assembled as one
        // object rather than nested — Go embeds the struct.
        let Ok(serde_json::Value::Object(mut out)) = serde_json::to_value(&summary) else {
            return text_error(500, "internal error");
        };
        match (serde_json::to_value(usage), serde_json::to_value(&activity)) {
            (Ok(u), Ok(a)) => {
                out.insert("usage".into(), u);
                out.insert("activity".into(), a);
            }
            _ => return text_error(500, "internal error"),
        }
        match jmap_types::go_json::to_vec(&serde_json::Value::Object(out)) {
            Ok(body) => json_response(200, body),
            Err(_) => text_error(500, "internal error"),
        }
    }

    // ── the JMAP core ─────────────────────────────────────────────────────

    /// `GET /.well-known/jmap` — the session object, which tells a client
    /// which accounts it has and where to send everything else.
    pub fn jmap_session(state: &RelayState, req: &Request<()>) -> Response<Body> {
        let mut res = match authenticate(state, req) {
            None => unauthorized_jmap(),
            Some((domain, localpart)) => {
                let id = jmap_types::Id::from(format!("{localpart}@{domain}").as_str());
                let session = jmapserver::server::session(&state.jmap(), Some(&id));
                json_response_raw(200, jmapserver::server::encode(&session))
            }
        };
        set_route_cors(
            &mut res,
            "GET, POST, OPTIONS",
            "Authorization, Content-Type",
        );
        res
    }

    /// `POST /jmap/api/` — a batch of method calls.
    pub fn jmap_api(state: &RelayState, req: &Request<()>, body: &[u8]) -> Response<Body> {
        let mut res = (|| {
            if authenticate(state, req).is_none() {
                return unauthorized_jmap();
            }
            if req.method() != axum::http::Method::POST {
                return method_not_allowed();
            }
            let Ok(batch) = serde_json::from_slice::<jmapserver::server::ApiRequest>(body) else {
                // `bad request`, not `invalid request` — the exact string Go
                // sends. Found by the differential harness, which is the only
                // thing that would have.
                return text_error(400, "bad request");
            };
            let response = jmapserver::server::run_batch(&state.jmap(), &batch);
            json_response_raw(200, jmapserver::server::encode(&response))
        })();
        set_route_cors(
            &mut res,
            "GET, POST, OPTIONS",
            "Authorization, Content-Type",
        );
        res
    }

    // ── the account lifecycle ─────────────────────────────────────────────

    /// `POST /account/provision` — where a DID becomes an account
    /// (SPEC.md §10-A).
    ///
    /// The device key **is** the credential: the vouch is verified and written
    /// before the account is registered, so there is no "create now, add a
    /// device later" gap for someone else to walk into.
    /// `POST /admin/drain-anchor` — release every claim this relay holds.
    ///
    /// Absent from the noanchor build, where there is no anchor to drain.
    ///
    /// The bearer guard is applied in `dispatch`, not here.
    ///
    /// **A partial drain is reported as a failure**, 502 with the report as
    /// the body: any name in `failed` may still hold a claim, and a claim left
    /// behind blocks a legitimately different relay from ever taking that
    /// name. An operator reading only the status must not be told "done".
    #[cfg(feature = "anchor")]
    pub fn drain_anchor(state: &RelayState, req: &Request<()>) -> Response<Body> {
        if req.method() != axum::http::Method::POST {
            return method_not_allowed();
        }
        let anchor = crate::anchor::anchor_ref(&state.cfg);
        if !anchor.is_configured() {
            return text_error(400, "relay is not anchored — nothing to drain");
        }
        let names: Vec<jmapserver::anchor::Name> =
            jmapserver::admin::list_provisioned(&state.data_dir)
                .into_iter()
                .map(|r| jmapserver::anchor::Name {
                    localpart: r.localpart,
                    domain: r.domain,
                })
                .collect();
        let report = jmapserver::anchor::drain(state.anchor.as_ref(), &anchor, &names);
        println!(
            "[drain] anchor {}: released {}, failed {}",
            anchor.url,
            report.released.len(),
            report.failed.len()
        );
        let status = if report.failed.is_empty() { 200 } else { 502 };
        match jmap_types::go_json::to_vec(&report) {
            Ok(body) => json_response(status, body),
            Err(_) => text_error(500, "internal error"),
        }
    }

    /// `/pkarr/` — forward a DHT record to the anchor's node.
    ///
    /// Unauthenticated on purpose: a client publishes its own signed record
    /// and the signature is what protects it. The relay's own token is added
    /// on the way out, because the anchor's gateway is for its relays and not
    /// for the world.
    #[cfg(feature = "anchor")]
    pub fn pkarr(state: &RelayState, req: &Request<()>, body: &[u8]) -> Response<Body> {
        use crate::pkarr::Action;
        let mut res = (|| {
            let anchor = crate::anchor::anchor_ref(&state.cfg);
            let key = match crate::pkarr::decide(req.method().as_str(), req.uri().path()) {
                Action::Preflight => return no_content(),
                // Go's `http.NotFound`, which is the same body the mux writes
                // for a route nobody registered — so a probe cannot tell the
                // gateway apart from an unmounted path.
                Action::NotFound => return text_error(404, "404 page not found"),
                Action::MethodNotAllowed => return method_not_allowed(),
                Action::Forward { key } => key.to_string(),
            };

            let url = crate::pkarr::target(&anchor.url, &key);
            // A GET carries no body. Go passes `r.Body` through regardless,
            // which for a GET is empty; sending `Some(&[])` instead would put
            // a zero-length body on the wire and change the request.
            let outgoing = if body.is_empty() { None } else { Some(body) };
            let Some(relayed) =
                state
                    .anchor
                    .forward(req.method().as_str(), &url, &anchor.token, outgoing)
            else {
                return text_error(502, "pkarr gateway unreachable");
            };

            let mut res = Response::new(Body::from(relayed.body));
            *res.status_mut() =
                StatusCode::from_u16(relayed.status).unwrap_or(StatusCode::BAD_GATEWAY);
            if let Some(ct) = relayed.content_type
                && let Ok(v) = HeaderValue::from_str(&ct)
            {
                res.headers_mut().insert(header::CONTENT_TYPE, v);
            }
            res
        })();
        set_route_cors(&mut res, "GET, PUT, OPTIONS", "Content-Type");
        res
    }

    /// `PUT /account/did` — bind a DID to the **authenticated** account.
    ///
    /// The account is taken from the credential and never from the body; see
    /// `did_bind`'s header for why that is the whole security property here.
    #[cfg(feature = "anchor")]
    pub fn account_did(state: &RelayState, req: &Request<()>, body: &[u8]) -> Response<Body> {
        let mut res = (|| {
            if req.method() == axum::http::Method::OPTIONS {
                return no_content();
            }
            if req.method() != axum::http::Method::PUT {
                return method_not_allowed();
            }
            // Before the body is even looked at: an unauthenticated caller
            // must not be able to tell a malformed request from a well-formed
            // one, and Go authenticates first.
            let Some((domain, localpart)) = authenticate(state, req) else {
                return unauthorized();
            };

            let anchor = crate::anchor::anchor_ref(&state.cfg);
            let request = match crate::did_bind::decide(anchor.is_configured(), body) {
                Ok(r) => r,
                Err(refusal) => return text_error(refusal.status(), refusal.message()),
            };

            // Go passes `r.Host` through to the anchor as part of the proof,
            // so the signature covers which relay the binding was presented
            // to. A missing Host would change what is signed, so it travels
            // as the empty string rather than being substituted.
            let host = req
                .headers()
                .get(header::HOST)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();

            let verdict = jmapserver::anchor::claim(
                state.anchor.as_ref(),
                &anchor,
                &localpart,
                &domain,
                &request.did,
                &jmapserver::anchor::BindingProof {
                    sig: request.did_sig,
                    ts: request.bind_ts,
                    host,
                },
            );
            match crate::did_bind::from_verdict(verdict) {
                Some(refusal) => text_error(refusal.status(), refusal.message()),
                None => no_content(),
            }
        })();
        set_route_cors(&mut res, "PUT, OPTIONS", "Authorization, Content-Type");
        res
    }

    pub fn account_provision(state: &RelayState, req: &Request<()>, body: &[u8]) -> Response<Body> {
        let mut res = (|| {
            if req.method() != axum::http::Method::POST {
                return method_not_allowed();
            }
            let Ok(request) = serde_json::from_slice::<crate::provision::ProvisionRequest>(body)
            else {
                return text_error(400, "invalid JSON");
            };
            let refuse = |r: crate::provision::Refusal| text_error(r.status(), r.message());

            if let Err(r) = crate::provision::validate(&state.cfg, &request) {
                return refuse(r);
            }
            let username = request.username.trim().to_lowercase();
            let (domain, dom_cfg) = match crate::provision::resolve_domain(
                &state.cfg,
                &state.dynamic_domains,
                &request.domain,
            ) {
                Ok(v) => v,
                Err(r) => return refuse(r),
            };
            if let Err(r) = crate::provision::may_provision(&dom_cfg, &request.provision_secret) {
                return refuse(r);
            }

            let acct_dir = crate::auth_env::account_dir(&state.data_dir, &domain, &username);
            let already = state.dyn_accounts.contains(&format!("{username}@{domain}"))
                || state
                    .accounts
                    .get(&format!("{username}@{domain}"))
                    .is_some();
            if crate::provision::name_is_taken(
                &acct_dir,
                &state.data_dir,
                &domain,
                &username,
                already,
            ) {
                return refuse(crate::provision::Refusal::UsernameTaken);
            }

            match crate::provision::vouch_path(&state.cfg, &request.did) {
                crate::provision::VouchPath::Impossible => {
                    return refuse(crate::provision::Refusal::DidMethodNeedsAnchor);
                }
                #[cfg(feature = "anchor")]
                crate::provision::VouchPath::Anchor => {
                    // Claim the name first. A vouch accepted against a name
                    // this DID does not hold would bind a device to somebody
                    // else's mailbox.
                    let anchor = crate::anchor::anchor_ref(&state.cfg);
                    let claimed = jmapserver::anchor::claim(
                        state.anchor.as_ref(),
                        &anchor,
                        &username,
                        &domain,
                        &request.did,
                        &jmapserver::anchor::BindingProof {
                            sig: request.did_sig.clone(),
                            ts: request.bind_ts,
                            // Verbatim, as this relay observed it: it is what
                            // the client signed against, and what stops a
                            // signature captured elsewhere being replayed here.
                            host: host_header(req),
                        },
                    );
                    if let Some(refusal) = crate::anchor::provision_refusal(claimed) {
                        return refuse(refusal);
                    }

                    let vouched = jmapserver::anchor::vouch_device(
                        state.anchor.as_ref(),
                        &anchor,
                        &username,
                        &domain,
                        &request.did,
                        &jmapserver::anchor::DeviceVouchProof {
                            device_pub_key: request.device_pub_key.clone(),
                            label: request.device_label.clone(),
                            sig: request.device_vouch_sig.clone(),
                            ts: request.device_vouch_ts,
                        },
                    );
                    if crate::anchor::device_error(vouched).is_some() {
                        return refuse(crate::provision::Refusal::DeviceVouchRejected);
                    }
                    let vouch = crate::devices::VouchRequest {
                        username: username.clone(),
                        domain: domain.clone(),
                        did: request.did.clone(),
                        device_pub_key: request.device_pub_key.clone(),
                        label: request.device_label.clone(),
                        bind_ts: request.device_vouch_ts,
                        sig: request.device_vouch_sig.clone(),
                    };
                    if crate::devices::write_device(
                        &state.data_dir,
                        &domain,
                        &username,
                        &vouch,
                        now_unix(),
                    )
                    .is_err()
                    {
                        return text_error(500, "internal error");
                    }
                }
                #[cfg(not(feature = "anchor"))]
                crate::provision::VouchPath::Anchor => {
                    return refuse(crate::provision::Refusal::AnchorUnavailable);
                }
                crate::provision::VouchPath::Local => {
                    let vouch = crate::devices::VouchRequest {
                        username: username.clone(),
                        domain: domain.clone(),
                        did: request.did.clone(),
                        device_pub_key: request.device_pub_key.clone(),
                        label: request.device_label.clone(),
                        bind_ts: request.device_vouch_ts,
                        sig: request.device_vouch_sig.clone(),
                    };
                    if !jmapserver::diddht::verify_did_dht_vouch_local(
                        &vouch.did,
                        &vouch.device_pub_key,
                        &vouch.label,
                        vouch.bind_ts,
                        &vouch.sig,
                        now_unix(),
                    ) {
                        return refuse(crate::provision::Refusal::DeviceVouchRejected);
                    }
                    if crate::devices::write_device(
                        &state.data_dir,
                        &domain,
                        &username,
                        &vouch,
                        now_unix(),
                    )
                    .is_err()
                    {
                        return text_error(500, "internal error");
                    }
                }
            }

            // Own relays keep the envelope for master-secret recovery;
            // third-party relays are not given one. Optional, and unrelated to
            // login either way.
            if let Some(envelope) = &request.envelope
                && let Ok(bytes) = serde_json::to_vec(envelope)
                && let Ok(env) = cryptenv::Envelope::from_bytes(&bytes)
            {
                let _ = crate::auth_env::write_envelope(&state.data_dir, &domain, &username, &env);
            }

            let email = format!("{username}@{domain}");
            state.dyn_accounts.insert(email.clone());
            if let Ok(store) = jmapserver::Store::open(&acct_dir) {
                let _ = store.put_mailboxes(&[crate::handler::default_inbox(&email)]);
                state.accounts.insert(
                    crate::handler::AccountStore {
                        email: email.clone(),
                        domain: domain.clone(),
                        localpart: username.clone(),
                        dir: acct_dir,
                        store: Arc::new(store),
                    },
                    &[],
                );
            }

            let mut out = serde_json::Map::new();
            out.insert("email".into(), email.into());
            // Present only when the client actually sent a DID.
            //
            // Unreachable as written: `validate` already refuses an empty DID
            // with 400, so this is never false. Kept because the Go handler
            // has the same dead branch and the shape is the contract — a
            // client reading `did_bound` should not start depending on its
            // always being there if the DID requirement is ever relaxed.
            if !request.did.is_empty() {
                out.insert(
                    "did_bound".into(),
                    crate::provision::did_bound(&state.cfg, &request).into(),
                );
            }
            match jmap_types::go_json::to_vec(&serde_json::Value::Object(out)) {
                Ok(body) => json_response(201, body),
                Err(_) => text_error(500, "internal error"),
            }
        })();
        set_route_cors(&mut res, "POST, OPTIONS", "Content-Type");
        res
    }

    /// `POST /account/delete` — remove the caller's **own** account.
    ///
    /// The target comes only from the credential, so this can never touch
    /// anyone else's. A statically configured account is refused: its data
    /// would come back on the next start, since config.json still names it.
    pub fn account_delete(state: &RelayState, req: &Request<()>) -> Response<Body> {
        let mut res = (|| {
            if req.method() != axum::http::Method::POST {
                return method_not_allowed();
            }
            let Some((domain, localpart)) = authenticate(state, req) else {
                return unauthorized();
            };
            let dom_cfg = state
                .cfg
                .domains
                .get(&domain)
                .cloned()
                .or_else(|| state.dynamic_domains.get(&domain));
            if let Err(e) = crate::customdomain::may_self_delete(dom_cfg.as_ref(), &localpart) {
                return text_error(e.status(), e.message());
            }

            let email = format!("{localpart}@{domain}");
            // Drop the routing first. An account whose data is gone but whose
            // aliases still resolve would take delivery into a store nobody
            // can reach.
            state.accounts.remove(&email);
            state.dyn_accounts.remove(&email);

            let dir = crate::auth_env::account_dir(&state.data_dir, &domain, &localpart);
            if std::fs::remove_dir_all(&dir).is_err() && dir.exists() {
                return text_error(500, "failed to delete account data");
            }
            no_content()
        })();
        set_route_cors(&mut res, "POST, OPTIONS", "Authorization, Content-Type");
        res
    }

    /// `POST /account/storage/purge-messages` — clear `messages/` and nothing
    /// else. Every other file either holds a credential with no second copy or
    /// is the account's only mailbox.
    pub fn storage_purge(state: &RelayState, req: &Request<()>) -> Response<Body> {
        let mut res = (|| {
            if req.method() != axum::http::Method::POST {
                return method_not_allowed();
            }
            let Some((domain, localpart)) = authenticate(state, req) else {
                return unauthorized();
            };
            let email = format!("{localpart}@{domain}");
            let purged = match state.accounts.get(&email) {
                Some(account) => {
                    let n = account.store.purge();
                    state.hub.notify();
                    n
                }
                None => 0,
            };
            match jmap_types::go_json::to_vec(&std::collections::BTreeMap::from([(
                "purged", purged,
            )])) {
                Ok(body) => json_response(200, body),
                Err(_) => text_error(500, "internal error"),
            }
        })();
        set_route_cors(&mut res, "POST, OPTIONS", "Authorization, Content-Type");
        res
    }

    // ── the dashboard and metrics ─────────────────────────────────────────

    /// The static shell. No token: every call it makes carries one, so the
    /// page itself holds no account data.
    pub fn admin_dashboard() -> Response<Body> {
        let mut res = Response::new(Body::from(jmapserver::admin::DASHBOARD_HTML));
        res.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/html; charset=utf-8"),
        );
        res
    }

    /// Prometheus exposition.
    ///
    /// Only this relay's own metrics. The Go build also registers the Go
    /// runtime and process collectors, which describe the *Go* process and
    /// have no counterpart here — emitting lookalikes would be inventing
    /// numbers. An operator scraping both sees fewer series after a
    /// migration, not different ones.
    pub fn metrics(state: &RelayState) -> Response<Body> {
        let mut metrics =
            jmapserver::admin::collect(&state.data_dir, &state.cfg.relay_label, crate::VERSION);
        let (sent, failed) = state.smtp_outbound();
        metrics.extend(jmapserver::admin::smtp_outbound_metrics(sent, failed));

        let mut res = Response::new(Body::from(jmapserver::admin::render_prometheus(&metrics)));
        res.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
        );
        res
    }

    // ── bring-your-own domain ─────────────────────────────────────────────

    /// The records an owner has to publish. Nothing here is privileged — a
    /// public key record, this relay's hostname, and a token that only proves
    /// the *asker* read the instructions. The provisioning secret is not in
    /// it, and stays behind actual proof of control.
    pub fn domain_verify_token(state: &RelayState, req: &Request<()>) -> Response<Body> {
        let mut res = (|| {
            let domain = query_param(req, "domain")
                .unwrap_or_default()
                .trim()
                .to_lowercase();
            if !crate::customdomain::valid_custom_domain(&domain) {
                let e = crate::customdomain::DomainError::InvalidDomain;
                return text_error(e.status(), e.message());
            }
            let (dkim_name, dkim_value) = domain_dkim(state, &domain);
            let out = std::collections::BTreeMap::from([
                ("txt_name", crate::customdomain::verify_txt_name(&domain)),
                (
                    "token",
                    crate::customdomain::verify_token(&state.cfg, &domain),
                ),
                ("mx_target", state.cfg.hostname.clone()),
                ("dkim_name", dkim_name),
                ("dkim_value", dkim_value),
            ]);
            match jmap_types::go_json::to_vec(&out) {
                Ok(body) => json_response(200, body),
                Err(_) => text_error(500, "internal error"),
            }
        })();
        set_route_cors(&mut res, "GET, OPTIONS", "");
        res
    }

    /// Verify the TXT record is live, then register the domain.
    ///
    /// **Re-checked every time**, even for a domain already registered: a past
    /// registration must not grant standing access to create accounts under it
    /// forever. The provisioning secret is re-issued in the same response, to
    /// whoever currently controls the DNS.
    pub fn domain_add(state: &RelayState, req: &Request<()>, body: &[u8]) -> Response<Body> {
        let mut res = (|| {
            if req.method() != axum::http::Method::POST {
                return method_not_allowed();
            }
            #[derive(serde::Deserialize)]
            struct AddRequest {
                #[serde(default)]
                domain: String,
            }
            let Ok(request) = serde_json::from_slice::<AddRequest>(body) else {
                return text_error(400, "invalid JSON");
            };
            let domain = request.domain.trim().to_lowercase();
            if !crate::customdomain::valid_custom_domain(&domain) {
                let e = crate::customdomain::DomainError::InvalidDomain;
                return text_error(e.status(), e.message());
            }

            let expected = crate::customdomain::verify_token(&state.cfg, &domain);
            let records = state
                .txt
                .lookup_txt(&crate::customdomain::verify_txt_name(&domain));
            if !crate::customdomain::txt_proves_ownership(&records, &expected) {
                let e = crate::customdomain::DomainError::NotVerified;
                return text_error(e.status(), e.message());
            }

            let dir = state.data_dir.join("_domains").join(&domain);
            if std::fs::create_dir_all(&dir).is_err() {
                return text_error(500, "internal error");
            }
            let dom_cfg = crate::customdomain::registered_domain_config(&state.cfg, &domain);
            let Ok(encoded) = jmap_types::go_json::to_vec(&dom_cfg) else {
                return text_error(500, "internal error");
            };
            if crate::write_private(&dir.join("domain.json"), &encoded).is_err() {
                return text_error(500, "internal error");
            }
            state
                .dynamic_domains
                .insert(domain.clone(), dom_cfg.clone());

            let (dkim_name, dkim_value) = domain_dkim(state, &domain);
            let out = std::collections::BTreeMap::from([
                ("domain", domain.clone()),
                ("mx_target", state.cfg.hostname.clone()),
                ("dkim_name", dkim_name),
                ("dkim_value", dkim_value),
                ("provision_secret", dom_cfg.provision_secret.clone()),
            ]);
            match jmap_types::go_json::to_vec(&out) {
                Ok(body) => json_response(200, body),
                Err(_) => text_error(500, "internal error"),
            }
        })();
        set_route_cors(&mut res, "POST, OPTIONS", "Content-Type");
        res
    }

    /// The DKIM record for a custom domain, generating the key on first ask.
    ///
    /// `load_or_generate_key` **loads** an existing key, so asking twice — or
    /// asking again after registration — never rotates one that is already
    /// published in DNS.
    fn domain_dkim(state: &RelayState, domain: &str) -> (String, String) {
        let dir = state.data_dir.join("_domains").join(domain);
        if std::fs::create_dir_all(&dir).is_err() {
            return (String::new(), String::new());
        }
        match crate::dkim::load_or_generate_key(&dir) {
            Ok(key) => {
                let selector = crate::dkim::DEFAULT_SELECTOR;
                let _ = crate::dkim::write_record_file(&dir, selector, domain, &key);
                (
                    format!("{selector}._domainkey.{domain}"),
                    crate::dkim::public_key_record(&key),
                )
            }
            Err(_) => (String::new(), String::new()),
        }
    }

    // ── push and the event stream ─────────────────────────────────────────

    /// The VAPID public key, served **unauthenticated**: a service worker needs
    /// it before the page has a credential, and it is a public key.
    pub fn push_vapid_key(state: &RelayState) -> Response<Body> {
        let mut res = Response::new(Body::from(state.vapid.public.clone()));
        res.headers_mut()
            .insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));
        set_route_cors(
            &mut res,
            "GET, POST, OPTIONS",
            "Authorization, Content-Type",
        );
        res
    }

    pub fn push_subscribe(state: &RelayState, req: &Request<()>, body: &[u8]) -> Response<Body> {
        #[derive(serde::Deserialize)]
        struct Keys {
            #[serde(default)]
            p256dh: String,
            #[serde(default)]
            auth: String,
        }
        #[derive(serde::Deserialize)]
        struct SubscribeRequest {
            #[serde(default)]
            endpoint: String,
            #[serde(default)]
            keys: Option<Keys>,
        }

        let mut res = (|| {
            let Some((domain, localpart)) = authenticate(state, req) else {
                return unauthorized_jmap();
            };
            if req.method() != axum::http::Method::POST {
                return method_not_allowed();
            }
            let Ok(request) = serde_json::from_slice::<SubscribeRequest>(body) else {
                return text_error(400, "bad request");
            };
            if request.endpoint.is_empty() {
                return text_error(400, "bad request");
            }
            let keys = request.keys.unwrap_or(Keys {
                p256dh: String::new(),
                auth: String::new(),
            });
            state.push.write().add(
                &jmap_types::Id::from(format!("{localpart}@{domain}").as_str()),
                jmapserver::push::PushSubscription {
                    endpoint: request.endpoint,
                    p256dh: keys.p256dh,
                    auth: keys.auth,
                },
            );
            no_content()
        })();
        set_route_cors(
            &mut res,
            "GET, POST, OPTIONS",
            "Authorization, Content-Type",
        );
        res
    }

    pub fn push_unsubscribe(state: &RelayState, req: &Request<()>, body: &[u8]) -> Response<Body> {
        #[derive(serde::Deserialize)]
        struct UnsubscribeRequest {
            #[serde(default)]
            endpoint: String,
        }
        let mut res = (|| {
            let Some((domain, localpart)) = authenticate(state, req) else {
                return unauthorized_jmap();
            };
            if req.method() != axum::http::Method::POST {
                return method_not_allowed();
            }
            let Ok(request) = serde_json::from_slice::<UnsubscribeRequest>(body) else {
                return text_error(400, "bad request");
            };
            if request.endpoint.is_empty() {
                return text_error(400, "bad request");
            }
            state.push.write().remove(
                &jmap_types::Id::from(format!("{localpart}@{domain}").as_str()),
                &request.endpoint,
            );
            no_content()
        })();
        set_route_cors(
            &mut res,
            "GET, POST, OPTIONS",
            "Authorization, Content-Type",
        );
        res
    }

    /// `GET /jmap/eventsource/` — a Server-Sent Events stream that wakes a
    /// client when something changed.
    ///
    /// **No `Connection: keep-alive`.** Over HTTP/2 — which browsers use for
    /// any TLS-served connection — a hop-by-hop header is a protocol violation
    /// (RFC 7540 §8.1.2.2) and the stream is reset. It surfaced as
    /// `ERR_HTTP2_PROTOCOL_ERROR` after the 200 had already gone out. HTTP/1.1
    /// keep-alive needs no header either way.
    pub fn event_source(state: &RelayState, req: &Request<()>) -> Response<Body> {
        let mut res = (|| {
            if authenticate(state, req).is_none() {
                return unauthorized_jmap();
            }
            let mut events = state.hub.subscribe_events();
            let stream = async_stream::stream! {
                // The first frame goes out immediately, so a client knows the
                // stream is live rather than waiting for a change that may be
                // hours away.
                yield Ok::<_, std::io::Error>(axum::body::Bytes::from_static(
                    jmapserver::push::STATE_EVENT.as_bytes(),
                ));
                let mut ping = tokio::time::interval(std::time::Duration::from_secs(
                    jmapserver::push::PING_INTERVAL_SECS,
                ));
                ping.tick().await;
                loop {
                    tokio::select! {
                        received = events.recv() => {
                            if received.is_none() {
                                break;
                            }
                            yield Ok(axum::body::Bytes::from_static(
                                jmapserver::push::STATE_EVENT.as_bytes(),
                            ));
                        }
                        _ = ping.tick() => {
                            yield Ok(axum::body::Bytes::from_static(
                                jmapserver::push::PING_EVENT.as_bytes(),
                            ));
                        }
                    }
                }
            };
            let mut res = Response::new(Body::from_stream(stream));
            res.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/event-stream"),
            );
            res.headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
            res
        })();
        set_route_cors(
            &mut res,
            "GET, POST, OPTIONS",
            "Authorization, Content-Type",
        );
        res
    }

    fn now_unix() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }
}

/// A body served as-is, with a JSON content type and **no added newline** —
/// these are stored bytes echoed back, not an Encoder's output.
pub fn json_response_raw(status: u16, body: Vec<u8>) -> Response<Body> {
    let mut res = Response::new(Body::from(body));
    *res.status_mut() = StatusCode::from_u16(status).expect("a valid status");
    res.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    res
}

pub fn octet_stream(body: Vec<u8>) -> Response<Body> {
    let mut res = Response::new(Body::from(body));
    res.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    res
}

/// The `Host` header as the client sent it.
///
/// Forwarded verbatim to the anchor: it is what the client signed against, and
/// this relay is the only party that saw it first-hand. Normalising it — or
/// substituting the configured hostname — removes the protection against a
/// signature captured on one relay being replayed against another.
pub fn host_header(req: &Request<()>) -> String {
    req.headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string()
}

/// One query parameter, percent-decoded.
pub fn query_param(req: &Request<()>, name: &str) -> Option<String> {
    let query = req.uri().query()?;
    for pair in query.split('&') {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        if k == name {
            return Some(percent_decode(v));
        }
    }
    None
}

/// `%XX` and `+`, as `net/url` decodes a query value.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                match u8::from_str_radix(&s[i + 1..i + 3], 16) {
                    Ok(b) => {
                        out.push(b);
                        i += 3;
                    }
                    // An invalid escape is left as written, which is what
                    // net/url does when it reports an error and the caller
                    // ignores it.
                    Err(_) => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Build the axum app: one catch-all, because the routing is [`GoMux`]'s.
pub fn app(state: Arc<RelayState>) -> axum::Router {
    axum::Router::new().fallback(move |req: Request<Body>| {
        let state = state.clone();
        async move { handle(state, req).await }
    })
}

#[cfg(test)]
mod tests;
