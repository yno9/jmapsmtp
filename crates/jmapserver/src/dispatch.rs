//! Routing a single JMAP method call to its handler.
//!
//! Port of `go-jmapserver/dispatch.go`. Protocol-specific work that has to
//! happen first — draining an inbound buffer before `Email/query`, say — runs
//! in the application's `Handler`, before it calls here.

use jmap_types::Id;
use serde_json::Value;

use crate::methods::{self, MethodError, MethodResult};
use crate::store::Store;

impl Store {
    /// Execute one method call against this store.
    ///
    /// `now` is the timestamp `EmailSubmission/set` stamps onto the records it
    /// writes; it is a parameter rather than a clock read so tests can pin it.
    pub fn dispatch(&self, account_id: &Id, method: &str, args: &Value, now: &str) -> MethodResult {
        match method {
            "Mailbox/get" => methods::mailbox::get(self, account_id, args),
            "Mailbox/changes" => methods::mailbox::changes(self, account_id, args),
            "Mailbox/query" => methods::mailbox::query(self, account_id, args),
            "Mailbox/queryChanges" => methods::mailbox::query_changes(self, account_id, args),
            "Mailbox/set" => methods::mailbox::set(self, account_id, args),

            "Thread/get" => methods::thread::get(self, account_id, args),
            "Thread/changes" => methods::thread::changes(self, account_id, args),

            "Email/get" => methods::email::get(self, account_id, args),
            "Email/changes" => methods::email::changes(self, account_id, args),
            "Email/query" => methods::email::query(self, account_id, args),
            "Email/queryChanges" => methods::email::query_changes(self, account_id, args),
            "Email/set" => methods::email::set(self, account_id, args),
            "Email/copy" => methods::email::copy(self, account_id, args),
            "Email/import" => methods::email::import(self, account_id, args, now),
            "Email/parse" => methods::email::parse(self, account_id, args, now),

            "SearchSnippet/get" => methods::searchsnippet::get(self, account_id, args),

            "Identity/get" => methods::identity::get(self, account_id),
            "Identity/changes" => methods::identity::changes(self, account_id, args),
            "Identity/set" => methods::identity::set(self, account_id, args),

            "EmailSubmission/get" => methods::submission::get(self, account_id, args),
            "EmailSubmission/changes" => methods::submission::changes(self, account_id, args),
            "EmailSubmission/query" => methods::submission::query(self, account_id, args),
            "EmailSubmission/queryChanges" => {
                methods::submission::query_changes(self, account_id, args)
            }
            "EmailSubmission/set" => methods::submission::set(self, account_id, args, now),

            "VacationResponse/get" => methods::vacation::get(self, account_id, args),
            "VacationResponse/set" => methods::vacation::set(self, account_id, args),

            other => Err(MethodError::UnknownMethod(other.to_string())),
        }
    }
}
