//! `git.sr.ht/~rockorager/go-jmap/mail/mailbox`.

use serde::{Deserialize, Serialize};

use crate::{Id, is_false, is_zero_u64};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mailbox {
    #[serde(default, skip_serializing_if = "Id::is_empty")]
    pub id: Id,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
    #[serde(rename = "parentId", default, skip_serializing_if = "Id::is_empty")]
    pub parent_id: Id,
    #[serde(default, skip_serializing_if = "Role::is_empty")]
    pub role: Role,
    #[serde(rename = "sortOrder", default, skip_serializing_if = "is_zero_u64")]
    pub sort_order: u64,
    #[serde(rename = "totalEmails", default, skip_serializing_if = "is_zero_u64")]
    pub total_emails: u64,
    #[serde(rename = "unreadEmails", default, skip_serializing_if = "is_zero_u64")]
    pub unread_emails: u64,
    #[serde(rename = "totalThreads", default, skip_serializing_if = "is_zero_u64")]
    pub total_threads: u64,
    #[serde(rename = "unreadThreads", default, skip_serializing_if = "is_zero_u64")]
    pub unread_threads: u64,
    /// Serialised as `myRights`, matching the Go tag.
    #[serde(rename = "myRights", default, skip_serializing_if = "Option::is_none")]
    pub rights: Option<Rights>,
    #[serde(rename = "isSubscribed", default, skip_serializing_if = "is_false")]
    pub is_subscribed: bool,
}

/// A mailbox role. Go declares `type Role string`, so an unrecognised value
/// passes through rather than failing to parse.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Role(pub String);

impl Role {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for Role {
    fn from(s: &str) -> Self {
        Role(s.to_string())
    }
}

macro_rules! roles {
    ($($konst:ident => $value:literal),* $(,)?) => {
        impl Role {
            $(pub const $konst: &'static str = $value;)*
        }
    };
}

roles! {
    ALL => "all",
    ARCHIVE => "archive",
    DRAFTS => "drafts",
    FLAGGED => "flagged",
    HAS_CHILDREN => "haschildren",
    HAS_NO_CHILDREN => "hasnochildren",
    IMPORTANT => "important",
    INBOX => "inbox",
    JUNK => "junk",
    MARKED => "marked",
    NO_INFERIORS => "noinferiors",
    NON_EXISTENT => "nonexistent",
    NO_SELECT => "noselect",
    REMOTE => "remote",
    SENT => "sent",
    SUBSCRIBED => "subscribed",
    TRASH => "trash",
    UNMARKED => "unmarked",
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rights {
    #[serde(rename = "mayReadItems", default, skip_serializing_if = "is_false")]
    pub may_read_items: bool,
    #[serde(rename = "mayAddItems", default, skip_serializing_if = "is_false")]
    pub may_add_items: bool,
    #[serde(rename = "mayRemoveItems", default, skip_serializing_if = "is_false")]
    pub may_remove_items: bool,
    #[serde(rename = "maySetSeen", default, skip_serializing_if = "is_false")]
    pub may_set_seen: bool,
    #[serde(rename = "maySetKeywords", default, skip_serializing_if = "is_false")]
    pub may_set_keywords: bool,
    #[serde(rename = "mayCreateChild", default, skip_serializing_if = "is_false")]
    pub may_create_child: bool,
    #[serde(rename = "mayRename", default, skip_serializing_if = "is_false")]
    pub may_rename: bool,
    #[serde(rename = "mayDelete", default, skip_serializing_if = "is_false")]
    pub may_delete: bool,
    #[serde(rename = "maySubmit", default, skip_serializing_if = "is_false")]
    pub may_submit: bool,
}
