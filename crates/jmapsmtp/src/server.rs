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
        Arc::new(RelayState {
            cfg,
            data_dir,
            dynamic_domains: DynamicDomains::default(),
            dyn_accounts: DynAccounts::default(),
            accounts: Accounts::default(),
            global_pgp_key: load_global_pgp_key(),
            admin_token: crate::bearer::token_from_env("ADMIN_TOKEN"),
            metrics_token: crate::bearer::token_from_env("METRICS_TOKEN"),
            mux,
        })
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
pub fn unauthorized() -> Response<Body> {
    let mut res = text_error(401, "unauthorized");
    res.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static("Basic realm=\"biset\""),
    );
    res
}

/// Resolve HTTP Basic credentials to an account.
///
/// Returns `(domain, localpart)`. The target of every per-account route comes
/// from here and never from the request body or query — which is what makes
/// those routes incapable of acting on somebody else's account.
pub fn authenticate(state: &RelayState, req: &Request<Body>) -> Option<(String, String)> {
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

    match pattern {
        "/relay-info" => handlers::relay_info(&state),
        "/setup" => handlers::setup(&state, &req),
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

    pub fn setup(state: &RelayState, req: &Request<Body>) -> Response<Body> {
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
}

/// One query parameter, percent-decoded.
pub fn query_param(req: &Request<Body>, name: &str) -> Option<String> {
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
