//! `git.sr.ht/~rockorager/go-jmap/mail` — the shared address type.

use serde::{Deserialize, Serialize};

/// An RFC 5322 address as JMAP represents it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Address {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub email: String,
}

impl Address {
    pub fn new(email: impl Into<String>) -> Self {
        Address {
            name: String::new(),
            email: email.into(),
        }
    }

    /// `Name <email>`, or just the address when unnamed. Mirrors Go's
    /// `Address.String`.
    pub fn to_rfc5322(&self) -> String {
        if self.name.is_empty() {
            self.email.clone()
        } else {
            format!("{} <{}>", self.name, self.email)
        }
    }
}
