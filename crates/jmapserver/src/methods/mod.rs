//! The RFC 8621 method handlers.
//!
//! Every handler returns a `serde_json::Value` built from `json!`, mirroring
//! the Go originals' `map[string]any`. That is not laziness: Go marshals a map
//! with its keys sorted, and `serde_json::Map` — with `preserve_order` off —
//! does the same, so the two produce identical bytes without either side
//! having to declare a struct per response.
//!
//! **Where Go ranges over a map, this sorts.** Response fields like `created`,
//! `updated` and `destroyed` are built from Go maps, so their order changes
//! from run to run; two Go processes disagree with each other. JMAP treats
//! them as sets (RFC 8620 §5.2), so ordering carries no meaning and sorting
//! loses nothing — while making the output reproducible. See SPEC.md §11.5.

pub mod email;
pub mod identity;
pub mod mailbox;
pub mod searchsnippet;
pub mod submission;
pub mod thread;
pub mod vacation;

use serde_json::{Value, json};

/// The error object shape shared by every `notCreated`/`notUpdated`/
/// `notDestroyed` entry — go-jmapserver's `errObj`.
pub(crate) fn err_obj(typ: &str, desc: &str) -> Value {
    json!({"type": typ, "description": desc})
}

/// A method failure. `CannotCalculateChanges` is the one the server turns
/// into that specific JMAP error type rather than `serverFail`; the Go
/// original signals it by returning an error whose message is exactly
/// "cannotCalculateChanges", which this makes a type instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MethodError {
    CannotCalculateChanges,
    UnknownMethod(String),
    ServerFail(String),
}

impl MethodError {
    /// The `type` field of the JMAP error response.
    pub fn error_type(&self) -> &'static str {
        match self {
            MethodError::CannotCalculateChanges => "cannotCalculateChanges",
            _ => "serverFail",
        }
    }
}

impl std::fmt::Display for MethodError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MethodError::CannotCalculateChanges => f.write_str("cannotCalculateChanges"),
            MethodError::UnknownMethod(m) => write!(f, "unknown method: {m}"),
            MethodError::ServerFail(m) => f.write_str(m),
        }
    }
}

pub type MethodResult = Result<Value, MethodError>;

/// Parse a state string. Anything not a non-negative integer means the client
/// cannot be brought up to date incrementally.
pub(crate) fn parse_since(s: &str) -> Result<i64, MethodError> {
    match s.parse::<i64>() {
        Ok(n) if n >= 0 => Ok(n),
        _ => Err(MethodError::CannotCalculateChanges),
    }
}
