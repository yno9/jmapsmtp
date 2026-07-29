//! The bearer-token guard on `/metrics`, `/admin/*` and `/admin/drain-anchor`.
//!
//! # This does not match the Go implementation, on purpose
//!
//! `go-jmapserver/metrics.go:bearerAuth` is:
//!
//! ```go
//! if token != "" {
//!     ... check the Authorization header, 401 on mismatch ...
//! }
//! next.ServeHTTP(w, r)
//! ```
//!
//! An **empty token means no check at all**, so a relay started without
//! `ADMIN_TOKEN` in its environment serves every admin route to anyone who can
//! reach the port. Verified against the oracle: with no token set,
//! `GET /admin/accounts` returns the full list of provisioned addresses to an
//! unauthenticated request, and `POST /admin/drain-anchor` — which releases
//! every one of this relay's claims at the anchor — reaches its handler.
//!
//! That is not a plausible reading of "no token configured". An operator who
//! sets no token has not chosen to publish their account list; they have not
//! thought about it. This port treats a missing token as **closed**, and the
//! divergence is asserted by `bearer_interop` so it cannot be lost. SPEC.md
//! §11.13.
//!
//! **This changes behaviour on upgrade** for one realistic deployment: a
//! Prometheus scraping `/metrics` with no `METRICS_TOKEN` set starts getting
//! 401s. That is a visible, immediately diagnosable break — set the variable —
//! and the alternative is leaving `/admin/accounts` open to keep it working.

use subtle::ConstantTimeEq as _;

/// The outcome of the guard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bearer {
    Allow,
    /// 401 with `WWW-Authenticate: Bearer`.
    Deny,
}

/// Check an `Authorization` header against the configured token.
///
/// `token` is the value of `ADMIN_TOKEN` / `METRICS_TOKEN`; `header` is the
/// raw `Authorization` header, or empty when absent.
pub fn check(token: &str, header: &str) -> Bearer {
    // The divergence. See the module header.
    if token.is_empty() {
        return Bearer::Deny;
    }
    let Some(presented) = header.strip_prefix("Bearer ") else {
        return Bearer::Deny;
    };
    // Constant time, as the Go original is: a token compared with an early
    // exit leaks its prefix to anyone who can time the response.
    if presented.as_bytes().ct_eq(token.as_bytes()).into() {
        Bearer::Allow
    } else {
        Bearer::Deny
    }
}

/// Read a token out of the environment, as `main()` does.
pub fn token_from_env(var: &str) -> String {
    std::env::var(var).unwrap_or_default()
}

#[cfg(test)]
mod tests;
