//! The request sequence both sides replay, in order.
//!
//! Steps run against one instance to completion, then against the other, so
//! anything stateful (a created email showing up in a later query) is
//! exercised on both sides identically. Order therefore matters: read steps
//! that assert an empty store come before the writes.
//!
//! Coverage grows with the port. Right now this covers the HTTP surface the
//! Go implementation serves without an anchor, a mock DNS, or an SMTP peer;
//! SMTP delivery arrives in M5 and the anchored routes in M6.

use serde_json::{Value, json};

use super::fixture::{ACCOUNT, SETUP_TOKEN};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Auth {
    None,
    Basic,
}

/// Which part of a response a declared difference is about.
///
/// An enum with one variant today, because `Status` is the only aspect a step
/// currently declares. It is an enum rather than a bool so that adding `Body`
/// — when a scenario step needs one — does not mean revisiting every call
/// site to work out what the old flag meant.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Aspect {
    Status,
}

/// How a response body is reduced before comparison.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum BodyMode {
    /// Normalise and compare in full. The default, and what almost every
    /// step wants.
    Full,
    /// Compare only the set of Prometheus metric names — see
    /// `normalize::metric_names`.
    MetricNames,
}

pub struct Step {
    pub name: &'static str,
    pub method: &'static str,
    pub path: String,
    pub auth: Auth,
    pub body: Option<Value>,
    pub body_mode: BodyMode,
    /// A deliberate difference: **what** must differ, and why.
    ///
    /// The aspect is named rather than left as "something about this step",
    /// because a step can differ for more than one reason. `/metrics` differs
    /// in its body regardless — the Go build exports Go-runtime collectors
    /// this port has no counterpart for — and checking "are they identical"
    /// there let a lost status fix pass unnoticed, which is exactly the
    /// failure this mechanism exists to prevent.
    pub divergence: Option<(Aspect, &'static str)>,
}

fn get(name: &'static str, path: &str, auth: Auth) -> Step {
    Step {
        name,
        method: "GET",
        path: path.to_string(),
        auth,
        body: None,
        body_mode: BodyMode::Full,
        divergence: None,
    }
}

fn req(name: &'static str, method: &'static str, path: &str, auth: Auth, body: Value) -> Step {
    Step {
        name,
        method,
        path: path.to_string(),
        auth,
        body: Some(body),
        body_mode: BodyMode::Full,
        divergence: None,
    }
}

/// A JMAP API call, wrapped in the `using`/`methodCalls` envelope.
fn jmap(name: &'static str, method: &str, args: Value) -> Step {
    req(
        name,
        "POST",
        "/jmap/api/",
        Auth::Basic,
        json!({
            "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail", "urn:ietf:params:jmap:submission"],
            "methodCalls": [[method, args, "c0"]],
        }),
    )
}

pub fn steps() -> Vec<Step> {
    let acct = ACCOUNT;
    let mut s = vec![
        // ── unauthenticated surface ───────────────────────────────────────
        get("relay-info", "/relay-info", Auth::None),
        get("session-unauthenticated", "/.well-known/jmap", Auth::None),
        Step {
            name: "session-preflight",
            method: "OPTIONS",
            path: "/.well-known/jmap".into(),
            auth: Auth::None,
            body: None,
            body_mode: BodyMode::Full,
            divergence: None,
        },
        // A route no handler is registered for. WrapCORS must still put CORS
        // headers on the 404 — go-jmapserver/server.go documents this as the
        // reason WrapCORS exists at all, so it is worth pinning.
        get("unknown-route-404", "/no/such/route", Auth::None),
        get("wkd-policy", "/.well-known/openpgpkey/policy", Auth::None),
        // The route that answered 501 here for the whole port while three
        // other layers of comparison reported nothing. The difftest fixture
        // configures no anchor, so this exercises the anchorless refusal —
        // the anchored answers are compared in `did_bind_interop`, which can
        // stand up a stub anchor and this harness cannot.
        get("account-did-wrong-method", "/account/did", Auth::None),
        req(
            "account-did-anchorless",
            "PUT",
            "/account/did",
            Auth::Basic,
            json!({"did": "did:webvh:abc"}),
        ),
        req(
            "account-did-no-did",
            "PUT",
            "/account/did",
            Auth::Basic,
            json!({"did_sig": "sig"}),
        ),
        get(
            "wkd-lookup-hash-matches",
            // zbase32(sha1("alice")), verified against the Go implementation.
            // The hash MATCHES the ?l= localpart, so this takes the per-user
            // branch, finds no uploaded key, and falls through to the global
            // one — which is also absent (no BISET_PGP_KEY), so 404.
            "/.well-known/openpgpkey/hu/kei1q4tipxxu1yj79k9kfukdhfy631xe?l=alice",
            Auth::None,
        ),
        get(
            "wkd-lookup-hash-mismatch",
            // A hash that does NOT correspond to ?l=, which is a different
            // branch: wkd.go rejects the mismatch outright rather than
            // consulting either key.
            "/.well-known/openpgpkey/hu/8xnqfyeqrbanrhqoq5b6ba6a1kzjxfyy?l=alice",
            Auth::None,
        ),
        get(
            "wkd-lookup-no-localpart",
            // No ?l= at all — skips the per-user branch entirely.
            "/.well-known/openpgpkey/hu/kei1q4tipxxu1yj79k9kfukdhfy631xe",
            Auth::None,
        ),
        get(
            "auth-envelope-missing",
            &format!("/auth/envelope?email={acct}"),
            Auth::None,
        ),
        get(
            "auth-envelope-bad-email",
            "/auth/envelope?email=nope",
            Auth::None,
        ),
        get(
            "auth-envelope-unknown-domain",
            "/auth/envelope?email=bob@elsewhere.test",
            Auth::None,
        ),
        get(
            "setup-page",
            &format!("/setup?token={SETUP_TOKEN}"),
            Auth::None,
        ),
        get("setup-bad-token", "/setup?token=deadbeef", Auth::None),
        get("setup-no-token", "/setup", Auth::None),
        // ── refusal paths that need no anchor, DNS or SMTP peer ───────────
        req(
            "provision-no-open-domain",
            "POST",
            "/account/provision",
            Auth::None,
            json!({"username": "bob", "did": "did:dht:abc", "device_pub_key": "x", "device_vouch_sig": "y"}),
        ),
        req(
            "provision-invalid-username",
            "POST",
            "/account/provision",
            Auth::None,
            json!({"username": "Not Valid!", "did": "did:dht:abc"}),
        ),
        req(
            "session-login-unknown-device",
            "POST",
            "/account/session",
            Auth::None,
            json!({
                "username": "alice", "domain": "example.com", "did": "did:dht:abc",
                "device_pub_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "ts": 1, "sig": "AAAA"
            }),
        ),
        req(
            "session-login-missing-fields",
            "POST",
            "/account/session",
            Auth::None,
            json!({"username": "alice"}),
        ),
        // domain_verify_secret is empty in the fixture config, so
        // registerCustomDomain never runs and these must 404.
        get(
            "domain-verify-token-disabled",
            "/domain/verify-token?domain=y.jp",
            Auth::None,
        ),
        // ── authenticated surface ─────────────────────────────────────────
        get("session", "/.well-known/jmap", Auth::Basic),
        get("devices-empty", "/account/devices", Auth::Basic),
        get("devices-delete-no-id", "/account/devices?", Auth::Basic),
        get("pgp-privkey-missing", "/pgp/privkey", Auth::Basic),
        get("pgp-peerkey-no-addr", "/pgp/peerkey", Auth::Basic),
        // ── JMAP reads against an empty store ─────────────────────────────
        jmap(
            "mailbox-get",
            "Mailbox/get",
            json!({"accountId": acct, "ids": null}),
        ),
        jmap("mailbox-query", "Mailbox/query", json!({"accountId": acct})),
        jmap(
            "mailbox-changes",
            "Mailbox/changes",
            json!({"accountId": acct, "sinceState": "0"}),
        ),
        jmap(
            "email-query-empty",
            "Email/query",
            json!({"accountId": acct}),
        ),
        jmap(
            "email-get-empty",
            "Email/get",
            json!({"accountId": acct, "ids": []}),
        ),
        jmap(
            "email-changes",
            "Email/changes",
            json!({"accountId": acct, "sinceState": "0"}),
        ),
        jmap(
            "thread-get-empty",
            "Thread/get",
            json!({"accountId": acct, "ids": []}),
        ),
        jmap(
            "identity-get",
            "Identity/get",
            json!({"accountId": acct, "ids": null}),
        ),
        jmap(
            "submission-get",
            "EmailSubmission/get",
            json!({"accountId": acct, "ids": null}),
        ),
        jmap(
            "submission-query",
            "EmailSubmission/query",
            json!({"accountId": acct}),
        ),
        jmap(
            "vacation-get",
            "VacationResponse/get",
            json!({"accountId": acct, "ids": null}),
        ),
        jmap(
            "searchsnippet-get",
            "SearchSnippet/get",
            json!({"accountId": acct, "emailIds": []}),
        ),
        // ── error shapes ──────────────────────────────────────────────────
        jmap(
            "unknown-method",
            "Nonexistent/get",
            json!({"accountId": acct}),
        ),
        jmap(
            "wrong-account",
            "Email/get",
            json!({"accountId": "nobody@example.com", "ids": []}),
        ),
        req(
            "malformed-envelope",
            "POST",
            "/jmap/api/",
            Auth::Basic,
            json!({"using": [], "methodCalls": "not-an-array"}),
        ),
        // ── writes, then reads that must observe them ─────────────────────
        jmap(
            "email-set-create-draft",
            "Email/set",
            json!({
                "accountId": acct,
                "create": {
                    "draft1": {
                        "mailboxIds": {"mbx-alice@example.com": true},
                        "keywords": {"$draft": true},
                        "from": [{"email": acct, "name": "Alice"}],
                        "to": [{"email": "bob@elsewhere.test", "name": "Bob"}],
                        "subject": "difftest subject",
                        "bodyValues": {"1": {"value": "difftest body"}},
                        "textBody": [{"partId": "1", "type": "text/plain"}]
                    }
                }
            }),
        ),
        jmap(
            "email-query-after-create",
            "Email/query",
            json!({"accountId": acct}),
        ),
        jmap(
            "email-get-after-create",
            "Email/get",
            json!({"accountId": acct, "ids": null, "properties": [
                "id", "subject", "from", "to", "keywords", "mailboxIds", "receivedAt", "preview", "size"
            ]}),
        ),
        jmap(
            "email-changes-after-create",
            "Email/changes",
            json!({"accountId": acct, "sinceState": "0"}),
        ),
        jmap(
            "thread-get-after-create",
            "Thread/get",
            json!({"accountId": acct, "ids": null}),
        ),
        // Session state must have advanced on both sides by the same amount.
        get("session-after-write", "/.well-known/jmap", Auth::Basic),
        // ── metrics ───────────────────────────────────────────────────────
        Step {
            name: "metrics",
            method: "GET",
            path: "/metrics".into(),
            auth: Auth::None,
            body: None,
            body_mode: BodyMode::MetricNames,
            // The oracle serves /metrics to anyone when METRICS_TOKEN is
            // unset; this port closes it. Asserted as a difference so the fix
            // cannot be lost, and so a Go-side fix reports itself as a stale
            // divergence rather than passing as a match.
            divergence: Some((
                Aspect::Status,
                "§11.13 — an unset bearer token closes the route",
            )),
        },
    ];

    // Every step's name is used to key its recorded output, so duplicates
    // would silently overwrite each other.
    let mut names: Vec<&str> = s.iter().map(|st| st.name).collect();
    names.sort_unstable();
    let before = names.len();
    names.dedup();
    assert_eq!(before, names.len(), "duplicate step name in scenario");

    s.shrink_to_fit();
    s
}
