//! The `/setup` page. Port of `setupHTMLTemplate` in `go-jmapsmtp/main.go`.
//!
//! The page builds a cryptenv envelope **in the browser** — Argon2id, AES-GCM
//! and HKDF over the password the user types — and POSTs it to
//! `/auth/signup?token=…`. The relay never sees the password or the master
//! secret; it receives an envelope it cannot open.
//!
//! That makes this HTML a **frozen cryptographic artifact**, not a view. Its
//! embedded JavaScript has to derive byte-identical material to
//! [`cryptenv`](../../cryptenv/index.html) — same KDF parameters, same HKDF
//! infos, same envelope layout — or an account set up through this page cannot
//! log in. So the template is carried over **verbatim** from the Go source
//! rather than rewritten, and `setup_interop` compares the served bytes.
//!
//! Changing anything inside it is changing a released client. SPEC.md §4.

/// The template, exactly as the Go source holds it. Seven `%s` placeholders and
/// one `%%`.
const TEMPLATE: &str = include_str!("setup_page.html");

/// Render the page for one account.
///
/// The substitution is Go's `fmt.Sprintf`, not a general template engine: a
/// single left-to-right pass where `%%` consumes both characters and emits one
/// `%`. Doing it as two independent replacements would mishandle `%%s`, which
/// Go reads as a literal `%` followed by a literal `s`.
pub fn render(localpart: &str, domain: &str, token: &str) -> String {
    // localpart, domain (heading), localpart, domain (done message),
    // localpart, domain (the EMAIL constant), then the token.
    let args = [
        localpart, domain, localpart, domain, localpart, domain, token,
    ];
    let mut args = args.iter();

    let mut out = String::with_capacity(TEMPLATE.len() + 64);
    let mut chars = TEMPLATE.chars();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('%') => out.push('%'),
            Some('s') => out.push_str(
                args.next()
                    .expect("the template has exactly seven placeholders"),
            ),
            // Unreachable for this template, and reproducing Go's `%!x(…)`
            // noise would be inventing behaviour for an input that cannot
            // occur. A panic says the template changed.
            Some(other) => panic!("unsupported verb %{other} in the setup template"),
            None => out.push('%'),
        }
    }
    assert!(
        args.next().is_none(),
        "the setup template consumed fewer than seven placeholders"
    );
    out
}

#[cfg(test)]
mod tests;
