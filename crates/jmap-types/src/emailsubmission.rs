//! `git.sr.ht/~rockorager/go-jmap/mail/emailsubmission`.
//!
//! Only the envelope is needed: submission records themselves are stored as
//! free-form JSON objects (Go keeps them as `map[string]any`).

use serde::{Deserialize, Serialize};

/// The SMTP envelope of a submission.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    /// The return address for the SMTP submission.
    #[serde(rename = "mailFrom", default, skip_serializing_if = "Option::is_none")]
    pub mail_from: Option<Address>,
    #[serde(rename = "rcptTo", default, skip_serializing_if = "Vec::is_empty")]
    pub rcpt_to: Vec<Address>,
}

/// An envelope address. `parameters` carries SMTP extension arguments and is
/// passed through untouched.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Address {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub email: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parameters: Option<serde_json::Value>,
}

impl Address {
    pub fn new(email: impl Into<String>) -> Self {
        Address {
            email: email.into(),
            parameters: None,
        }
    }
}
