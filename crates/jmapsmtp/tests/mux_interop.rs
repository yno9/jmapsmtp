//! The route table and the routing rules, checked against the oracle.
//!
//! Reading the Go source is not enough here for two reasons this test already
//! caught:
//!
//! - `net/http`'s redirect status **depends on the Go version**. The toolchain
//!   installed on this machine is 1.22, whose `ServeMux` sends 301; the oracle
//!   is built with 1.26.3, which sends 307. Reading would have produced a port
//!   that redirects wrongly on every subtree route.
//! - Three routes are conditional in ways the registration call sites do not
//!   show: `/jmap/{upload,download}/` need a handler that implements
//!   `BlobHandler` (this relay's does not), and `/pkarr/` needs a non-empty
//!   `anchor_url`, not merely the anchor build.
//!
//! Existence is probed through the mux itself rather than through status
//! codes, because a handler can answer 404 too — `/.well-known/openpgpkey/hu/`
//! calls `http.NotFound` for an unknown key, byte-identical to the mux's own.
//! Asking for a subtree pattern *without* its trailing slash is unambiguous:
//! only the mux can answer 307 there.

use jmapsmtp::config::Config;
use jmapsmtp::gomux::{REDIRECT_STATUS, Route};
use jmapsmtp::routes::{Guard, build_mux, route_specs};

mod oracle_harness;
use oracle_harness::Oracle;

fn config_json(http_port: u16, smtp_port: u16) -> String {
    format!(
        r#"{{"listen_addr":"127.0.0.1:{http_port}","smtp_port":{smtp_port},
            "base_url":"http://127.0.0.1:{http_port}","hostname":"t.invalid",
            "domain":{{"a.test":{{"account":{{"alice":{{}}}}}}}}}}"#
    )
}

fn rust_config(http_port: u16) -> Config {
    serde_json::from_str(&config_json(http_port, 1)).unwrap()
}

/// The oracle's 404 handler writes exactly this.
const MUX_NOT_FOUND: &str = "404 page not found\n";

// ── the route table ───────────────────────────────────────────────────────

/// Every pattern this port registers must exist on the oracle, and every
/// subtree pattern the oracle has must be one this port registers.
#[test]
fn the_route_table_matches_the_oracle() {
    let Some(o) = Oracle::start(config_json) else {
        return;
    };
    let cfg = rust_config(o.http_port);
    let specs = route_specs(&cfg, false);

    // Subtree patterns: ask for the pattern minus its trailing slash. Only the
    // mux can answer 307 there, so this is existence and nothing else.
    //
    // Except where the sans-slash form is *itself* a registered pattern —
    // `/contacts` and `/admin/accounts` both are — in which case the request
    // reaches that handler and never sees the redirect. There the weaker probe
    // is all that is available: a path under the subtree must not come back
    // with the mux's own 404.
    let all: Vec<&str> = specs.iter().map(|s| s.pattern).collect();
    for spec in specs.iter().filter(|s| s.pattern.ends_with('/')) {
        let without = spec.pattern.trim_end_matches('/');
        if all.contains(&without) {
            let (status, body, _) = o.get(&format!("{}probe", spec.pattern));
            assert_ne!(
                (status, body.as_str()),
                (404, MUX_NOT_FOUND),
                "{} should be registered as a subtree on the oracle",
                spec.pattern
            );
            continue;
        }
        let (status, _, _) = o.get(without);
        assert_eq!(
            status, REDIRECT_STATUS,
            "{} should be registered as a subtree on the oracle",
            spec.pattern
        );
    }

    // Exact patterns: the oracle must not answer them with the mux's own 404.
    //
    // `/account/session/challenge` is exempt: it is a genuinely NEW route
    // (SPEC.md §11.28's nonce half), not a port of anything the Go side
    // has — the whole reason a table of Go-side additions doesn't exist for
    // it to be missing from.
    for spec in specs
        .iter()
        .filter(|s| !s.pattern.ends_with('/') && s.pattern != "/account/session/challenge")
    {
        let (status, body, _) = o.get(spec.pattern);
        assert_ne!(
            (status, body.as_str()),
            (404, MUX_NOT_FOUND),
            "{} is in this port's table but the oracle does not route it",
            spec.pattern
        );
    }
}

/// The mirror image: routes this port deliberately does *not* register must
/// not exist on the oracle either. Without this, a route dropped by accident
/// looks identical to one dropped on purpose.
///
/// **What this pair cannot catch:** a route the oracle serves that this port
/// never listed at all. Nothing over HTTP enumerates a `ServeMux`, so the
/// table was built from an exhaustive grep for `HandleFunc(` and `mux.Handle(`
/// across both Go repositories, and the count below is asserted so that
/// dropping one shows up in a diff rather than silently.
#[test]
fn the_routes_this_port_omits_are_absent_from_the_oracle() {
    let Some(o) = Oracle::start(config_json) else {
        return;
    };

    let cfg = rust_config(o.http_port);
    assert_eq!(
        route_specs(&cfg, false).len(),
        if cfg!(feature = "anchor") { 32 } else { 30 },
        "the route table changed size — if a route was added or removed on \
         purpose, update this number in the same commit"
    );

    // Conditional on config or handler capability, and this oracle has
    // neither: no domain_verify_secret, no anchor_url, no BlobHandler.
    for pattern in [
        "/jmap/upload/",
        "/jmap/download/",
        "/pkarr/",
        "/domain/add",
        "/domain/verify-token",
    ] {
        let without = pattern.trim_end_matches('/');
        let (status, body, _) = o.get(without);
        assert_ne!(
            status, REDIRECT_STATUS,
            "{pattern} should not be registered on this oracle"
        );
        if !pattern.ends_with('/') {
            assert_eq!((status, body.as_str()), (404, MUX_NOT_FOUND), "{pattern}");
        }
    }
}

// ── routing behaviour ─────────────────────────────────────────────────────

/// The redirects and the 404s, compared decision by decision.
#[test]
fn this_port_routes_every_probe_the_way_the_oracle_does() {
    let Some(o) = Oracle::start(config_json) else {
        return;
    };
    let mux = build_mux(&rust_config(o.http_port), false);

    let probes = [
        // exact matches
        ("/relay-info", ""),
        ("/.well-known/jmap", ""),
        ("/account/storage/export", ""),
        // subtree matches, including well below the pattern
        ("/jmap/api/", ""),
        ("/jmap/api/Email/get", ""),
        ("/contacts/alice@a.test", ""),
        // trailing-slash redirects
        ("/jmap/api", ""),
        ("/jmap/api", "x=1"),
        ("/contacts/", ""),
        ("/jmap/eventsource", ""),
        // path cleaning
        ("//relay-info", ""),
        ("/a/../relay-info", "y=2"),
        ("/./relay-info", ""),
        // both at once: one hop, not two
        ("//jmap/api", ""),
        // an exact pattern does not answer with a trailing slash
        ("/relay-info/", ""),
        ("/relay-info/x", ""),
        // traversal cannot escape the root
        ("/../../relay-info", ""),
        // plain misses
        ("/nope", ""),
        ("/jmap/nope", ""),
        ("/account/storage/nope", ""),
    ];

    for (path, query) in probes {
        let target = if query.is_empty() {
            path.to_string()
        } else {
            format!("{path}?{query}")
        };
        let (status, body, location) = o.get(&target);
        let ours = mux.route(path, query);

        match &ours {
            Route::Redirect(to) => {
                assert_eq!(
                    (status, location.as_str()),
                    (REDIRECT_STATUS, to.as_str()),
                    "{target}: this port redirects to {to}"
                );
            }
            Route::NotFound => {
                assert_eq!(
                    (status, body.as_str()),
                    (404, MUX_NOT_FOUND),
                    "{target}: this port does not route it"
                );
            }
            Route::Found { pattern, .. } => {
                assert_ne!(status, REDIRECT_STATUS, "{target}: the oracle redirects");
                assert_ne!(
                    (status, body.as_str()),
                    (404, MUX_NOT_FOUND),
                    "{target}: this port routes it to {pattern}, the oracle does not route it"
                );
            }
        }
    }
}

// ── the declared divergence ───────────────────────────────────────────────

/// SPEC.md §11.13. The oracle runs with no `ADMIN_TOKEN` or `METRICS_TOKEN`,
/// which in Go means **no check at all**.
///
/// This asserts the two implementations still disagree. If the Go side is ever
/// fixed, this test fails and says so — the divergence would then be stale,
/// not lost.
#[test]
fn the_oracle_serves_its_admin_routes_unauthenticated_and_this_port_does_not() {
    let Some(o) = Oracle::start(config_json) else {
        return;
    };
    assert!(
        std::env::var("ADMIN_TOKEN").is_err() && std::env::var("METRICS_TOKEN").is_err(),
        "this test is about the unset case; the harness must not inherit a token"
    );

    // Go: the account list, to anyone who can reach the port.
    let (status, body, _) = o.get("/admin/accounts");
    assert_eq!(
        status, 200,
        "the oracle serves /admin/accounts unauthenticated"
    );
    assert!(
        body.contains("alice@a.test"),
        "and it is the real account list, not an empty stub: {body}"
    );

    // Go: the metrics, likewise.
    let (status, _, _) = o.get("/metrics");
    assert_eq!(status, 200, "the oracle serves /metrics unauthenticated");

    // This port: closed, for every Bearer route.
    for spec in route_specs(&rust_config(o.http_port), false)
        .iter()
        .filter(|s| s.guard == Guard::Bearer)
    {
        assert_eq!(
            jmapsmtp::bearer::check("", ""),
            jmapsmtp::bearer::Bearer::Deny,
            "{} must not be open when its token is unset",
            spec.pattern
        );
    }
}
