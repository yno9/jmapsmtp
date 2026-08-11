//! Routing, checked against what the oracle actually answered.
//!
//! The expectations here were taken from a running Go binary rather than from
//! the Go source: the installed toolchain is 1.22, whose ServeMux redirects
//! with 301, while the oracle is built with 1.26.3, which sends 307. Reading
//! would have got it wrong. `tests/mux_interop.rs` keeps them honest.

use super::*;
use pretty_assertions::assert_eq;

fn mux(patterns: &[&str]) -> GoMux<&'static str> {
    let mut m = GoMux::new();
    for p in patterns {
        m.handle(p, "h");
    }
    m
}

fn found<'a>(r: &Route<'a, &'static str>) -> Option<&'a str> {
    match r {
        Route::Found { pattern, .. } => Some(pattern),
        _ => None,
    }
}

fn redirect(r: &Route<'_, &'static str>) -> Option<String> {
    match r {
        Route::Redirect(to) => Some(to.clone()),
        _ => None,
    }
}

// ── registration ──────────────────────────────────────────────────────────

/// The production incident this module exists for: two registration functions
/// claiming `/account/devices`, one for POST and one for GET/DELETE. Go
/// panicked at startup on deploy; axum would have accepted it and quietly run
/// one of them.
#[test]
#[should_panic(expected = "registered twice")]
fn registering_a_pattern_twice_panics() {
    mux(&["/account/devices", "/account/devices"]);
}

#[test]
#[should_panic(expected = "does not begin with /")]
fn a_pattern_without_a_leading_slash_panics() {
    mux(&["account/devices"]);
}

#[test]
#[should_panic(expected = "empty pattern")]
fn an_empty_pattern_panics() {
    mux(&[""]);
}

/// An exact and a subtree pattern with the same prefix are different
/// patterns, and both are used — `/contacts` and `/contacts/` are separate
/// handlers in the Go code.
#[test]
fn an_exact_and_a_subtree_pattern_can_coexist() {
    let m = mux(&["/contacts", "/contacts/"]);
    assert_eq!(m.patterns(), ["/contacts", "/contacts/"]);
}

// ── matching ──────────────────────────────────────────────────────────────

#[test]
fn an_exact_pattern_matches_only_itself() {
    let m = mux(&["/relay-info"]);
    assert_eq!(found(&m.route("/relay-info", "")), Some("/relay-info"));
    // The oracle answers 404 here: a trailing slash is not the same path, and
    // there is no subtree pattern to fall back to.
    assert_eq!(m.route("/relay-info/", ""), Route::NotFound);
    assert_eq!(m.route("/relay-info/x", ""), Route::NotFound);
}

#[test]
fn a_subtree_pattern_matches_everything_below_it() {
    let m = mux(&["/jmap/api/"]);
    for path in ["/jmap/api/", "/jmap/api/x", "/jmap/api/x/y/z"] {
        assert_eq!(found(&m.route(path, "")), Some("/jmap/api/"), "{path}");
    }
}

#[test]
fn the_longest_matching_pattern_wins() {
    let m = mux(&["/account/", "/account/storage", "/account/storage/export"]);
    assert_eq!(
        found(&m.route("/account/storage", "")),
        Some("/account/storage")
    );
    assert_eq!(
        found(&m.route("/account/storage/export", "")),
        Some("/account/storage/export")
    );
    assert_eq!(
        found(&m.route("/account/storage/messages", "")),
        Some("/account/"),
        "no exact pattern, so the only subtree that prefixes it"
    );
}

#[test]
fn an_unmatched_path_is_not_found() {
    assert_eq!(mux(&["/relay-info"]).route("/nope", ""), Route::NotFound);
    assert_eq!(mux(&[]).route("/", ""), Route::NotFound);
}

// ── redirects ─────────────────────────────────────────────────────────────

#[test]
fn a_path_missing_its_trailing_slash_redirects_to_the_subtree() {
    let m = mux(&["/jmap/api/"]);
    assert_eq!(
        redirect(&m.route("/jmap/api", "")),
        Some("/jmap/api/".into())
    );
    assert_eq!(
        redirect(&m.route("/jmap/api", "x=1")),
        Some("/jmap/api/?x=1".into()),
        "the query survives the redirect"
    );
}

#[test]
fn an_uncleanable_path_redirects_to_its_cleaned_form() {
    let m = mux(&["/relay-info"]);
    assert_eq!(
        redirect(&m.route("//relay-info", "")),
        Some("/relay-info".into())
    );
    assert_eq!(
        redirect(&m.route("/a/../relay-info", "y=2")),
        Some("/relay-info?y=2".into())
    );
}

/// The ordering inside `findHandler`: the trailing-slash redirect is decided
/// before the cleaned-path one, so a dirty path pointing at a subtree gets a
/// single redirect to the final target rather than two hops.
#[test]
fn a_dirty_path_needing_both_redirects_takes_one_hop() {
    let m = mux(&["/jmap/api/"]);
    assert_eq!(
        redirect(&m.route("//jmap/api", "")),
        Some("/jmap/api/".into()),
        "not /jmap/api"
    );
}

/// A path that is already clean and already matches must not redirect —
/// otherwise every request to a subtree loops.
#[test]
fn a_clean_matching_path_does_not_redirect() {
    let m = mux(&["/jmap/api/", "/relay-info"]);
    assert!(redirect(&m.route("/jmap/api/", "")).is_none());
    assert!(redirect(&m.route("/jmap/api/x", "")).is_none());
    assert!(redirect(&m.route("/relay-info", "")).is_none());
}

/// No redirect when there is nothing to redirect *to* — the answer is 404,
/// not a redirect to another 404.
#[test]
fn an_unregistered_path_does_not_get_a_trailing_slash_redirect() {
    assert_eq!(mux(&["/relay-info"]).route("/nope", ""), Route::NotFound);
}

// ── path cleaning ─────────────────────────────────────────────────────────

#[test]
fn clean_path_matches_gos_rules() {
    assert_eq!(clean_path(""), "/");
    assert_eq!(clean_path("/"), "/");
    assert_eq!(
        clean_path("relay-info"),
        "/relay-info",
        "a leading / is added"
    );
    assert_eq!(clean_path("/a//b"), "/a/b");
    assert_eq!(clean_path("/a/./b"), "/a/b");
    assert_eq!(clean_path("/a/b/.."), "/a");
    assert_eq!(
        clean_path("/a/b/../"),
        "/a/",
        "the trailing slash is put back"
    );
    assert_eq!(
        clean_path("/a/"),
        "/a/",
        "an already-clean subtree path is left alone"
    );
}

/// Traversal cannot escape the root: `..` at the top is dropped, so a handler
/// never sees a path outside the tree no matter how the client spells it.
#[test]
fn traversal_above_the_root_is_dropped() {
    assert_eq!(clean_path("/../../etc/passwd"), "/etc/passwd");
    assert_eq!(clean_path("/.."), "/");
    assert_eq!(clean_path("/a/../.."), "/");
}
