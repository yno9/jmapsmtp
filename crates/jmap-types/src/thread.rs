//! `git.sr.ht/~rockorager/go-jmap/mail/thread`.

use serde::{Deserialize, Serialize};

use crate::Id;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Thread {
    #[serde(default, skip_serializing_if = "Id::is_empty")]
    pub id: Id,
    #[serde(rename = "emailIds", default, skip_serializing_if = "Vec::is_empty")]
    pub email_ids: Vec<Id>,
}
