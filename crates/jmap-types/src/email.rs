//! `git.sr.ht/~rockorager/go-jmap/mail/email` — the Email object (RFC 8621 §4).
//!
//! Field order below matches the Go struct exactly, because Go marshals in
//! declaration order and these values are compared byte for byte against
//! files it wrote.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{Id, JmapTime, is_false, is_zero_u64, mail::Address};

/// A representation of an RFC 5322 message.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Email {
    #[serde(default, skip_serializing_if = "Id::is_empty")]
    pub id: Id,
    #[serde(rename = "blobId", default, skip_serializing_if = "Id::is_empty")]
    pub blob_id: Id,
    #[serde(rename = "threadId", default, skip_serializing_if = "Id::is_empty")]
    pub thread_id: Id,
    /// Mailbox membership. A `false` value is retained, not dropped — Go's
    /// `omitempty` applies to the map as a whole, never to its entries.
    #[serde(
        rename = "mailboxIds",
        default,
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub mailbox_ids: BTreeMap<Id, bool>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub keywords: BTreeMap<String, bool>,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub size: u64,
    #[serde(
        rename = "receivedAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub received_at: Option<JmapTime>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub headers: Vec<Header>,
    #[serde(rename = "messageId", default, skip_serializing_if = "Vec::is_empty")]
    pub message_id: Vec<String>,
    #[serde(rename = "inReplyTo", default, skip_serializing_if = "Vec::is_empty")]
    pub in_reply_to: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sender: Vec<Address>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub from: Vec<Address>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub to: Vec<Address>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cc: Vec<Address>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bcc: Vec<Address>,
    #[serde(rename = "replyTo", default, skip_serializing_if = "Vec::is_empty")]
    pub reply_to: Vec<Address>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub subject: String,
    #[serde(rename = "sentAt", default, skip_serializing_if = "Option::is_none")]
    pub sent_at: Option<JmapTime>,
    #[serde(
        rename = "bodyStructure",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub body_structure: Option<Box<BodyPart>>,
    #[serde(
        rename = "bodyValues",
        default,
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub body_values: BTreeMap<String, BodyValue>,
    #[serde(rename = "textBody", default, skip_serializing_if = "Vec::is_empty")]
    pub text_body: Vec<BodyPart>,
    #[serde(rename = "htmlBody", default, skip_serializing_if = "Vec::is_empty")]
    pub html_body: Vec<BodyPart>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attachments: Vec<BodyPart>,
    #[serde(rename = "hasAttachment", default, skip_serializing_if = "is_false")]
    pub has_attachment: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub preview: String,
    #[serde(
        rename = "smimeStatus",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub smime_status: String,
    #[serde(
        rename = "smimeStatusAtDelivery",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub smime_status_at_delivery: String,
    #[serde(rename = "smimeErrors", default, skip_serializing_if = "Vec::is_empty")]
    pub smime_errors: Vec<String>,
    #[serde(
        rename = "smimeVerifiedAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub smime_verified_at: Option<JmapTime>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub value: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BodyPart {
    #[serde(rename = "partId", default, skip_serializing_if = "String::is_empty")]
    pub part_id: String,
    #[serde(rename = "blobId", default, skip_serializing_if = "Id::is_empty")]
    pub blob_id: Id,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub size: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub headers: Vec<Header>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
    #[serde(rename = "type", default, skip_serializing_if = "String::is_empty")]
    pub type_: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub charset: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub disposition: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub cid: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub language: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub location: String,
    #[serde(rename = "subParts", default, skip_serializing_if = "Vec::is_empty")]
    pub sub_parts: Vec<BodyPart>,
}

/// The decoded content of one body part.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BodyValue {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub value: String,
    #[serde(
        rename = "isEncodingProblem",
        default,
        skip_serializing_if = "is_false"
    )]
    pub is_encoding_problem: bool,
    /// **No `skip_serializing_if`, deliberately.** The Go field carries no
    /// `omitempty`, so `"isTruncated":false` is always present — confirmed
    /// against the Go implementation's output.
    #[serde(rename = "isTruncated", default)]
    pub is_truncated: bool,
}

impl BodyValue {
    pub fn new(value: impl Into<String>) -> Self {
        BodyValue {
            value: value.into(),
            is_encoding_problem: false,
            is_truncated: false,
        }
    }
}
