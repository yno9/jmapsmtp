//! `Thread/*`. Port of `go-jmapserver/thread.go`.
//!
//! Threads are not persisted; they are derived from the message store on
//! demand by grouping on `threadId`.

use std::collections::{BTreeMap, BTreeSet};

use jmap_types::Id;
use serde::Deserialize;
use serde_json::{Value, json};

use super::{MethodError, MethodResult, parse_since};
use crate::store::Store;

#[derive(Default, Deserialize)]
struct GetArgs {
    #[serde(default)]
    ids: Vec<Id>,
}

pub fn get(store: &Store, account_id: &Id, args: &Value) -> MethodResult {
    let req: GetArgs = serde_json::from_value(args.clone()).unwrap_or_default();

    // Members sorted OLDEST first — the opposite of Store::all, which is
    // newest first. A thread reads top to bottom.
    let mut by_thread: BTreeMap<Id, Vec<(::time::OffsetDateTime, Id)>> = BTreeMap::new();
    for m in store.all() {
        if m.thread_id.is_empty() {
            continue;
        }
        let at = m
            .received_at
            .as_ref()
            .map_or(::time::OffsetDateTime::UNIX_EPOCH, |t| t.sort_key());
        by_thread
            .entry(m.thread_id.clone())
            .or_default()
            .push((at, m.id));
    }
    for entries in by_thread.values_mut() {
        entries.sort();
    }

    let mut list = Vec::new();
    let mut not_found = Vec::new();
    for tid in &req.ids {
        match by_thread.get(tid) {
            None => not_found.push(tid.clone()),
            Some(entries) => {
                let email_ids: Vec<&Id> = entries.iter().map(|(_, id)| id).collect();
                list.push(json!({"id": tid, "emailIds": email_ids}));
            }
        }
    }

    Ok(json!({
        "accountId": account_id,
        "state": store.state(),
        "list": list,
        "notFound": not_found,
    }))
}

#[derive(Default, Deserialize)]
struct ChangesArgs {
    #[serde(default, rename = "sinceState")]
    since_state: String,
}

/// Thread state mirrors email state: a thread counts as changed when any of
/// its messages did.
pub fn changes(store: &Store, account_id: &Id, args: &Value) -> MethodResult {
    let req: ChangesArgs = serde_json::from_value(args.clone()).unwrap_or_default();
    let since = parse_since(&req.since_state)?;
    let cur: i64 = store.state().parse().unwrap_or(0);
    if since > cur {
        return Err(MethodError::CannotCalculateChanges);
    }

    let log = store.changes();
    let mut changed_emails = BTreeSet::new();
    for v in (since + 1)..=cur {
        let rec = log.get(&v).ok_or(MethodError::CannotCalculateChanges)?;
        for id in rec.added.iter().chain(&rec.updated).chain(&rec.removed) {
            changed_emails.insert(id.clone());
        }
    }

    // A destroyed message is no longer in the store, so its thread cannot be
    // resolved and drops out — the Go original behaves the same way.
    let mut changed_threads = BTreeSet::new();
    for id in &changed_emails {
        if let Some(m) = store.get(id)
            && !m.thread_id.is_empty()
        {
            changed_threads.insert(m.thread_id);
        }
    }

    Ok(json!({
        "accountId": account_id,
        "oldState": req.since_state,
        "newState": cur.to_string(),
        "hasMoreChanges": false,
        "created": Vec::<Id>::new(),
        "updated": changed_threads,
        "destroyed": Vec::<Id>::new(),
    }))
}
