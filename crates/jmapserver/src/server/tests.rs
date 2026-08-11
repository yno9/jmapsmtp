//! Session, authentication, batching and encoding.

use super::*;
use crate::methods::MethodError;
use pretty_assertions::assert_eq;

struct TestHandler;

impl Handler for TestHandler {
    fn capabilities(&self) -> Vec<Uri> {
        vec![
            Uri::from(jmap_types::CAP_MAIL),
            Uri::from(jmap_types::CAP_SUBMISSION),
        ]
    }
    fn accounts(&self) -> Vec<Account> {
        vec![
            Account {
                id: Id::from("alice@example.com"),
                name: "alice@example.com".into(),
            },
            Account {
                id: Id::from("bob@example.com"),
                name: "bob@example.com".into(),
            },
        ]
    }
    fn handle(&self, method: &str, args: &Value) -> MethodResult {
        match method {
            "Echo/one" => Ok(json!({"ids": ["a", "b"], "got": args})),
            "Echo/two" => Ok(json!({"got": args})),
            "Fail/changes" => Err(MethodError::CannotCalculateChanges),
            "Fail/other" => Err(MethodError::ServerFail("boom".into())),
            other => Err(MethodError::UnknownMethod(other.to_string())),
        }
    }
}

fn server(cfg: Config, auth: Option<AuthFn>) -> Server {
    Server {
        cfg,
        handler: Arc::new(TestHandler),
        hub: Arc::new(Hub::new()),
        auth,
    }
}

fn plain() -> Server {
    server(
        Config {
            base_url: "http://relay.test".into(),
            ..Default::default()
        },
        None,
    )
}

// ── session ───────────────────────────────────────────────────────────────

#[test]
fn session_shows_only_the_authenticated_account() {
    let s = plain();
    let sess = session(&s, Some(&Id::from("alice@example.com")));
    let accounts = sess["accounts"].as_object().unwrap();
    assert_eq!(accounts.len(), 1);
    assert!(accounts.contains_key("alice@example.com"));
    assert_eq!(sess["username"], "alice@example.com");
    assert_eq!(
        sess["primaryAccounts"][jmap_types::CAP_MAIL],
        "alice@example.com"
    );
}

#[test]
fn an_unauthenticated_session_shows_every_account() {
    let sess = session(&plain(), None);
    assert_eq!(sess["accounts"].as_object().unwrap().len(), 2);
    // The first account listed wins the username and primaryAccounts slots.
    assert_eq!(sess["username"], "alice@example.com");
}

#[test]
fn session_urls_come_from_base_url_not_the_listen_address() {
    let sess = session(&plain(), None);
    assert_eq!(sess["apiUrl"], "http://relay.test/jmap/api/");
    assert_eq!(
        sess["uploadUrl"],
        "http://relay.test/jmap/upload/{accountId}/"
    );
    assert_eq!(
        sess["downloadUrl"],
        "http://relay.test/jmap/download/{accountId}/{blobId}/{name}?accept={type}"
    );
    assert_eq!(
        sess["eventSourceUrl"],
        "http://relay.test/jmap/eventsource/"
    );
}

#[test]
fn a_trailing_slash_on_base_url_is_trimmed() {
    let s = server(
        Config {
            base_url: "http://relay.test/".into(),
            ..Default::default()
        },
        None,
    );
    assert_eq!(session(&s, None)["apiUrl"], "http://relay.test/jmap/api/");
}

#[test]
fn without_base_url_the_listen_address_is_used() {
    let s = server(
        Config {
            listen_addr: "127.0.0.1:1234".into(),
            ..Default::default()
        },
        None,
    );
    assert_eq!(
        session(&s, None)["apiUrl"],
        "http://127.0.0.1:1234/jmap/api/"
    );

    // And with neither, the same default the Go original hard-codes.
    let s = server(Config::default(), None);
    assert_eq!(session(&s, None)["apiUrl"], "http://0.0.0.0:8765/jmap/api/");
}

#[test]
fn core_capability_is_added_automatically() {
    let sess = session(&plain(), None);
    let caps = sess["capabilities"].as_object().unwrap();
    assert!(caps.contains_key(jmap_types::CAP_CORE));
    assert!(caps.contains_key(jmap_types::CAP_MAIL));
    assert_eq!(caps[jmap_types::CAP_CORE]["maxCallsInRequest"], 32);
    // The handler's own capabilities are advertised as empty objects.
    assert_eq!(caps[jmap_types::CAP_MAIL], json!({}));
}

// ── authentication ────────────────────────────────────────────────────────

#[test]
fn an_auth_function_decides_and_its_rejection_is_final() {
    let s = server(
        Config {
            // Present but must be ignored while an auth function is installed.
            password: "global".into(),
            ..Default::default()
        },
        Some(Arc::new(|u: &str, p: &str| {
            (p == "right").then(|| Id::from(u))
        })),
    );
    assert_eq!(s.authenticate("alice", "right"), Some(Id::from("alice")));
    assert_eq!(s.authenticate("alice", "wrong"), None);
    assert_eq!(
        s.authenticate("alice", "global"),
        None,
        "the global password must not be a way around the auth function"
    );
}

#[test]
fn a_global_password_is_the_second_choice() {
    let s = server(
        Config {
            password: "global".into(),
            ..Default::default()
        },
        None,
    );
    assert_eq!(s.authenticate("alice", "global"), Some(Id::from("alice")));
    assert_eq!(s.authenticate("alice", "nope"), None);
}

/// Not a safe default — no authentication at all. Pinned so that becoming
/// this by accident is a test failure rather than a silent opening.
#[test]
fn with_neither_configured_everything_is_accepted() {
    let s = plain();
    assert_eq!(s.authenticate("anyone", ""), Some(Id::from("anyone")));
}

// ── batching ──────────────────────────────────────────────────────────────

fn batch(calls: Value) -> Value {
    let req: ApiRequest = serde_json::from_value(json!({"methodCalls": calls})).unwrap();
    run_batch(&plain(), &req)
}

#[test]
fn a_batch_returns_one_response_per_call_in_order() {
    let out = batch(json!([
        ["Echo/one", {"a": 1}, "c0"],
        ["Echo/two", {"b": 2}, "c1"],
    ]));
    assert_eq!(out["sessionState"], "0");
    let responses = out["methodResponses"].as_array().unwrap();
    assert_eq!(responses.len(), 2);
    assert_eq!(responses[0][0], "Echo/one");
    assert_eq!(responses[0][2], "c0");
    assert_eq!(responses[1][2], "c1");
}

#[test]
fn a_result_reference_is_resolved_from_an_earlier_call() {
    let out = batch(json!([
        ["Echo/one", {}, "c0"],
        ["Echo/two", {"#ids": {"resultOf": "c0", "path": "/ids"}}, "c1"],
    ]));
    let responses = out["methodResponses"].as_array().unwrap();
    assert_eq!(responses[1][1]["got"], json!({"ids": ["a", "b"]}));
}

#[test]
fn an_unresolvable_reference_fails_only_its_own_call() {
    let out = batch(json!([
        ["Echo/one", {"#ids": {"resultOf": "nope", "path": "/ids"}}, "c0"],
        ["Echo/two", {}, "c1"],
    ]));
    let responses = out["methodResponses"].as_array().unwrap();
    assert_eq!(responses[0][1]["type"], "serverFail");
    assert_eq!(responses[1][0], "Echo/two", "the batch continues");
}

#[test]
fn cannot_calculate_changes_keeps_its_own_error_type() {
    let out = batch(json!([["Fail/changes", {}, "c0"]]));
    let r = &out["methodResponses"][0];
    assert_eq!(r[1]["type"], "cannotCalculateChanges");
    assert_eq!(r[1]["description"], "cannotCalculateChanges");
}

#[test]
fn every_other_failure_is_a_server_fail() {
    let out = batch(json!([["Fail/other", {}, "c0"]]));
    assert_eq!(out["methodResponses"][0][1]["type"], "serverFail");
    assert_eq!(out["methodResponses"][0][1]["description"], "boom");
}

/// The Go original skips a malformed call outright: no response entry, no
/// error, and the batch carries on.
#[test]
fn a_malformed_call_is_skipped_silently() {
    let out = batch(json!([
        "not an array",
        ["Echo/one"],
        ["Echo/two", {}, "c1"]
    ]));
    let responses = out["methodResponses"].as_array().unwrap();
    assert_eq!(responses.len(), 1);
    assert_eq!(responses[0][2], "c1");
}

#[test]
fn an_empty_batch_is_an_empty_response() {
    let out = batch(json!([]));
    assert_eq!(out["methodResponses"], json!([]));
}

// ── encoding ──────────────────────────────────────────────────────────────

/// Responses go out through Go's encoder, which HTML-escapes and appends a
/// newline. Both matter for byte comparison against the Go implementation.
#[test]
fn responses_are_html_escaped_and_newline_terminated() {
    let out = encode(&json!({"subject": "a & b <c>"}));
    assert_eq!(
        String::from_utf8(out).unwrap(),
        "{\"subject\":\"a \\u0026 b \\u003cc\\u003e\"}\n"
    );
}
