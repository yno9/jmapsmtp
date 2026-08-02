//! The `/setup` page.
//!
//! This HTML is a frozen cryptographic artifact: its embedded JavaScript
//! derives the envelope an account logs in with. The tests are about the
//! substitution being Go's, and about the crypto parameters inside the page
//! still matching `cryptenv`.

use super::*;
use pretty_assertions::assert_eq;

fn page() -> String {
    render("alice", "a.test", "deadbeefdeadbeefdeadbeefdeadbeef")
}

// ── the substitution ──────────────────────────────────────────────────────

#[test]
fn every_placeholder_is_filled_and_none_are_left() {
    let out = page();
    assert!(!out.contains("%s"), "an unfilled placeholder remains");
    assert_eq!(
        TEMPLATE.matches("%s").count(),
        7,
        "seven placeholders: localpart and domain three times each, then the token"
    );
    assert_eq!(
        out.matches("alice").count(),
        3,
        "the localpart lands in the heading, the completion message and the \
         EMAIL constant"
    );
    assert_eq!(out.matches("a.test").count(), 3);
    assert!(out.contains("deadbeefdeadbeefdeadbeefdeadbeef"));
}

/// Go's `fmt` reads `%%` as one literal `%`. The CSS in this page relies on it
/// — `width:100%%` — and two independent string replacements would get `%%s`
/// wrong, which is why the substitution is a single left-to-right pass.
#[test]
fn a_doubled_percent_becomes_one() {
    assert!(
        TEMPLATE.contains("100%%"),
        "the template still has the escape"
    );
    let out = page();
    assert!(out.contains("width:100%;"), "collapsed to one: {out:.400}");
    assert!(!out.contains("100%%"));
}

#[test]
fn the_rendered_page_is_deterministic() {
    assert_eq!(page(), page());
}

#[test]
fn the_placeholders_land_in_the_right_places() {
    let out = render("bob", "b.test", "TOKEN123");
    // The heading, the completion message and the JS constant all name the
    // address; the token appears once, in the signup URL.
    assert!(out.contains("bob@b.test のパスワード設定"), "the heading");
    assert_eq!(
        out.matches("TOKEN123").count(),
        1,
        "the token appears exactly once"
    );
    assert!(
        out.contains("bob@b.test"),
        "the address is assembled, not left split"
    );
}

// ── the frozen crypto ─────────────────────────────────────────────────────

/// The page derives the envelope the account will log in with, so its
/// parameters have to match `cryptenv` exactly. A difference here does not
/// error — it produces an account that cannot log in.
#[test]
fn the_pages_kdf_parameters_match_cryptenv() {
    let out = page();
    // Argon2id, t=3, m=64MiB, p=4 — SPEC.md §4.
    assert!(out.contains("argon2id"), "the KDF");
    assert!(
        out.contains("const KDF = { t: 3, m: 64 * 1024, p: 4 }"),
        "the page's KDF constant changed: {}",
        out.lines()
            .find(|l| l.contains("const KDF"))
            .unwrap_or("(gone)")
    );

    // …and those are the values cryptenv uses, checked rather than assumed.
    assert_eq!(cryptenv::DEFAULT_KDF.time, 3);
    assert_eq!(cryptenv::DEFAULT_KDF.memory, 64 * 1024, "KiB");
    assert_eq!(cryptenv::DEFAULT_KDF.threads, 4);

    // The envelope the page uploads carries these back, so the server can
    // re-derive with them.
    assert!(
        out.contains("kdf: KDF"),
        "the envelope carries the parameters"
    );
}

/// The page derives **only the auth token**, with
/// `biset-jmapsmtp/auth/v1` — the encryption key's `…/enc/v1` is derived later,
/// by the client that actually encrypts, and never here.
///
/// If this string differed from `cryptenv`'s, the token the page registers
/// would not be the one the relay checks, and the account would be
/// unreachable from the moment it was created.
#[test]
fn the_page_derives_the_auth_token_with_the_same_hkdf_info_as_cryptenv() {
    let out = page();
    assert!(
        out.contains("hkdf(masterSecret, 'biset-jmapsmtp/auth/v1', 32)"),
        "the auth derivation changed: {}",
        out.lines()
            .find(|l| l.contains("hkdf("))
            .unwrap_or("(gone)")
    );
    assert!(
        !out.contains("biset-jmapsmtp/enc/v1"),
        "the setup page has no reason to derive the encryption key"
    );
    assert!(
        out.contains("'HKDF', hash: 'SHA-256'") || out.contains("name: 'HKDF', hash: 'SHA-256'"),
        "SHA-256, matching cryptenv"
    );
}

/// The page POSTs to the endpoint that consumes the token, with the token it
/// was rendered for.
#[test]
fn the_page_posts_its_envelope_to_the_signup_endpoint() {
    let out = render("alice", "a.test", "TOK");
    assert!(
        out.contains("/auth/signup?token=") || out.contains("/auth/signup?token=${"),
        "the signup URL: {}",
        out.lines()
            .find(|l| l.contains("auth/signup"))
            .unwrap_or("(no such line)")
    );
}

/// The envelope is built in the browser, so the password never leaves it.
/// Anything that posted the password itself would defeat the whole design.
#[test]
fn the_page_never_sends_the_password_anywhere() {
    let out = page();
    let posting_lines: Vec<&str> = out
        .lines()
        .filter(|l| l.contains("fetch(") || l.contains("body:"))
        .collect();
    for line in &posting_lines {
        assert!(
            !line.contains("password") || line.contains("//"),
            "a request line mentions the password: {line}"
        );
    }
    assert!(!posting_lines.is_empty(), "the page does post something");
}
