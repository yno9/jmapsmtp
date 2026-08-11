//! A port of `net/http.ServeMux`'s routing, because the wire behaviour is
//! observable and axum's is different.
//!
//! Three things make this worth 150 lines rather than a `axum::Router`:
//!
//! 1. **Registering the same pattern twice panics.** That is not a detail —
//!    it is a production incident. `registerAnchorRoutes` used to register
//!    `POST /account/devices` while `registerDeviceRoutes` registered
//!    GET/DELETE on the identical pattern, and `ServeMux` killed the relay on
//!    deploy. axum accepts the duplicate silently, so without this the port
//!    loses the crash *and* keeps the bug (SPEC.md §2).
//! 2. **Subtree patterns.** `/jmap/api/` matches `/jmap/api/anything/at/all`,
//!    and the handlers parse the remainder themselves. axum would 404.
//! 3. **The redirects.** `/jmap/api` → `/jmap/api/`, and `//relay-info` →
//!    `/relay-info`, both 307 with the query string carried over. A client
//!    that relies on either would break.
//!
//! ## The status code depends on the Go version
//!
//! Go 1.22 sends **301** for both redirects; Go 1.26 sends **307**. This port
//! follows the toolchain the oracle is built with (1.26.3, so 307), which was
//! established by asking the running binary — reading the Go source on this
//! machine would have given 301, because the installed `go` is 1.22.
//!
//! If the oracle is ever rebuilt with an older toolchain, `mux_interop` starts
//! failing on the redirect cases. That is the intended outcome: the answer is
//! to decide which status the port should send, not to loosen the test.

use std::collections::BTreeMap;

/// Go's `net/http.StatusTemporaryRedirect`. See the note above.
pub const REDIRECT_STATUS: u16 = 307;

/// What a path resolves to.
#[derive(Debug, PartialEq, Eq)]
pub enum Route<'a, H> {
    /// The pattern that matched, and its handler. Handlers registered on a
    /// subtree pattern get the whole path and split it themselves, exactly as
    /// the Go ones do.
    Found {
        pattern: &'a str,
        handler: &'a H,
    },
    /// A 307 with this `Location`. Relative, as Go writes it.
    Redirect(String),
    NotFound,
}

/// The routing table.
#[derive(Debug, Default)]
pub struct GoMux<H> {
    routes: BTreeMap<String, H>,
}

impl<H> GoMux<H> {
    pub fn new() -> GoMux<H> {
        GoMux {
            routes: BTreeMap::new(),
        }
    }

    /// Register `pattern`.
    ///
    /// # Panics
    ///
    /// If the pattern is empty, does not start with `/`, or is already
    /// registered. All three are what `ServeMux.Handle` panics on, and the
    /// panic is the point: it happens at startup, before the relay serves
    /// anything, rather than after a deploy.
    pub fn handle(&mut self, pattern: &str, handler: H) -> &mut Self {
        assert!(!pattern.is_empty(), "gomux: empty pattern");
        assert!(
            pattern.starts_with('/'),
            "gomux: pattern {pattern:?} does not begin with /"
        );
        assert!(
            !self.routes.contains_key(pattern),
            "gomux: pattern {pattern:?} is registered twice — \
             merge the handlers and dispatch on the method inside"
        );
        self.routes.insert(pattern.to_string(), handler);
        self
    }

    pub fn patterns(&self) -> Vec<&str> {
        self.routes.keys().map(String::as_str).collect()
    }

    /// Resolve a request path and query, in `findHandler`'s order.
    ///
    /// The order matters and is not the obvious one: the trailing-slash
    /// redirect is decided *before* the cleaned-path redirect, so a request
    /// for `//jmap/api` gets one redirect straight to `/jmap/api/` rather than
    /// two hops through `/jmap/api`.
    pub fn route(&self, path: &str, raw_query: &str) -> Route<'_, H> {
        let cleaned = clean_path(path);
        let matched = self.match_path(&cleaned);

        // Trailing-slash redirect: no exact match, the path does not already
        // end in `/`, and adding one would match exactly.
        let exact = matched.is_some_and(|p| p == cleaned);
        if !exact && !cleaned.ends_with('/') && !cleaned.is_empty() {
            let with_slash = format!("{cleaned}/");
            if self.match_path(&with_slash) == Some(with_slash.as_str()) {
                return Route::Redirect(with_query(&with_slash, raw_query));
            }
        }

        if cleaned != path {
            return Route::Redirect(with_query(&cleaned, raw_query));
        }

        match matched {
            Some(pattern) => Route::Found {
                pattern: self.routes.get_key_value(pattern).unwrap().0,
                handler: &self.routes[pattern],
            },
            // Every pattern here is method-less, so Go's Method-Not-Allowed
            // branch is unreachable: `matchingMethods` only ever finds a
            // pattern that differs by method. The 405s this relay sends all
            // come from inside a handler.
            None => Route::NotFound,
        }
    }

    /// The most specific pattern matching `path`, which for literal patterns
    /// means the longest.
    fn match_path(&self, path: &str) -> Option<&str> {
        if let Some((pattern, _)) = self.routes.get_key_value(path) {
            return Some(pattern);
        }
        self.routes
            .keys()
            .filter(|p| p.ends_with('/') && path.starts_with(p.as_str()))
            .max_by_key(|p| p.len())
            .map(String::as_str)
    }
}

fn with_query(path: &str, raw_query: &str) -> String {
    if raw_query.is_empty() {
        path.to_string()
    } else {
        format!("{path}?{raw_query}")
    }
}

/// Go's `net/http.cleanPath`: `path.Clean`, with the trailing slash put back.
pub fn clean_path(p: &str) -> String {
    if p.is_empty() {
        return "/".to_string();
    }
    let owned;
    let p = if p.starts_with('/') {
        p
    } else {
        owned = format!("/{p}");
        &owned
    };
    let np = lexical_clean(p);
    // `Clean` drops a trailing slash; Go puts it back so a subtree pattern
    // still matches.
    if p.ends_with('/') && np != "/" {
        format!("{np}/")
    } else {
        np
    }
}

/// `path.Clean` for a rooted path: collapse `//`, resolve `.` and `..`.
///
/// `..` at the root is dropped rather than escaping it, which is what keeps
/// `/../../etc/passwd` from ever reaching a handler as anything but `/etc/passwd`.
fn lexical_clean(p: &str) -> String {
    let mut out: Vec<&str> = Vec::new();
    for seg in p.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            s => out.push(s),
        }
    }
    if out.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", out.join("/"))
    }
}

#[cfg(test)]
mod tests;
