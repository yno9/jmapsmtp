//! JMAP (RFC 8620 / RFC 8621) wire types.
//!
//! Port of the `git.sr.ht/~rockorager/go-jmap` subset this project uses.
//!
//! These types are not merely a convenience: their serialisation is a
//! compatibility contract in two directions at once. They are what biset
//! parses off the wire, and what sits in `data/.../messages/*.json` on every
//! existing deployment. Three Go behaviours therefore have to be reproduced
//! exactly, all verified against the Go implementation:
//!
//! 1. **`omitempty` is total.** Go omits a zero number, a false bool, an
//!    empty string, and a nil *or empty* map/slice alike. An `Email{}`
//!    marshals to `{}`. Every field carries the matching
//!    `skip_serializing_if` — except [`email::BodyValue::is_truncated`],
//!    which has no `omitempty` in Go and so is always present.
//! 2. **Field order is declaration order**, in both languages. The order here
//!    matches the Go structs field for field.
//! 3. **Map keys are sorted.** Go's `encoding/json` sorts them; the
//!    [`BTreeMap`](std::collections::BTreeMap)s used throughout do the same.
//!    A `HashMap` would not, and `serde_json`'s `preserve_order` feature is
//!    deliberately off for the same reason.
//!
//! A fourth, found the hard way: **Go HTML-escapes `<`, `>` and `&`** in
//! strings. See [`go_json`], which every writer must use in place of
//! `serde_json::to_vec`.
//!
//! Unknown fields are ignored rather than rejected, matching Go — a message
//! written by a newer version must still load.

pub mod email;
pub mod emailsubmission;
pub mod go_json;
pub mod identity;
pub mod mail;
pub mod mailbox;
pub mod thread;
pub mod time;

use std::fmt;

use serde::{Deserialize, Serialize};

pub use time::JmapTime;

/// A unique identifier assigned by the server.
///
/// Go declares `type ID string`, so anything that fits in a string fits here.
/// The spec's `^[A-Za-z0-9\-_]+$` restriction is *not* enforced: this relay
/// mints ids containing `@` (`mbx-alice@example.com`) and full URLs, and
/// rejecting them would reject its own data.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Id(pub String);

impl Id {
    pub fn as_str(&self) -> &str {
        &self.0
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Display for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<String> for Id {
    fn from(s: String) -> Self {
        Id(s)
    }
}

impl From<&str> for Id {
    fn from(s: &str) -> Self {
        Id(s.to_string())
    }
}

impl std::ops::Deref for Id {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

/// A capability URI, e.g. `urn:ietf:params:jmap:mail`.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Uri(pub String);

impl fmt::Display for Uri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&str> for Uri {
    fn from(s: &str) -> Self {
        Uri(s.to_string())
    }
}

pub const CAP_CORE: &str = "urn:ietf:params:jmap:core";
pub const CAP_MAIL: &str = "urn:ietf:params:jmap:mail";
pub const CAP_SUBMISSION: &str = "urn:ietf:params:jmap:submission";

/// An account as it appears in the JMAP Session object.
///
/// Go tags `ID` as `json:"-"` — the id is the key in the Session's `accounts`
/// map, never a field of the value.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Account {
    #[serde(skip)]
    pub id: Id,
    pub name: String,
    #[serde(rename = "isPersonal")]
    pub is_personal: bool,
    #[serde(rename = "isReadOnly")]
    pub is_read_only: bool,
}

/// `true` when the value should be omitted under Go's `omitempty`.
pub(crate) fn is_false(b: &bool) -> bool {
    !*b
}

pub(crate) fn is_zero_u64(n: &u64) -> bool {
    *n == 0
}
