//! `git.sr.ht/~rockorager/go-jmap/mail/identity`.

use serde::{Deserialize, Serialize};

use crate::{Id, is_false, mail::Address};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identity {
    #[serde(default, skip_serializing_if = "Id::is_empty")]
    pub id: Id,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub email: String,
    #[serde(rename = "replyTo", default, skip_serializing_if = "Vec::is_empty")]
    pub reply_to: Vec<Address>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bcc: Vec<Address>,
    #[serde(
        rename = "textSignature",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub text_signature: String,
    #[serde(
        rename = "htmlSignature",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub html_signature: String,
    #[serde(rename = "mayDelete", default, skip_serializing_if = "is_false")]
    pub may_delete: bool,
}
