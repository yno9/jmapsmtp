//! `EmailSubmission/*`. Port of `go-jmapserver/submission.go`.

use std::collections::BTreeMap;

use jmap_types::Id;
use jmap_types::emailsubmission::Envelope;
use serde::Deserialize;
use serde_json::{Value, json};

use super::{MethodError, MethodResult, err_obj, parse_since};
use crate::store::{JsonObject, Store};

pub fn get(store: &Store, account_id: &Id, _args: &Value) -> MethodResult {
    Ok(json!({
        "accountId": account_id,
        "state": store.submission_state(),
        "list": store.submissions(),
        "notFound": Vec::<Id>::new(),
    }))
}

#[derive(Default, Deserialize)]
struct ChangesArgs {
    #[serde(default, rename = "sinceState")]
    since_state: String,
}

/// Submissions carry no per-version change log, so this reports an empty diff
/// and leaves the client to re-fetch with `EmailSubmission/get`. A state ahead
/// of the server's is still refused.
pub fn changes(store: &Store, account_id: &Id, args: &Value) -> MethodResult {
    let req: ChangesArgs = serde_json::from_value(args.clone()).unwrap_or_default();
    let cur: i64 = store.submission_state().parse().unwrap_or(0);
    if parse_since(&req.since_state)? > cur {
        return Err(MethodError::CannotCalculateChanges);
    }
    Ok(json!({
        "accountId": account_id,
        "oldState": req.since_state,
        "newState": cur.to_string(),
        "hasMoreChanges": false,
        "created": Vec::<Id>::new(),
        "updated": Vec::<Id>::new(),
        "destroyed": Vec::<Id>::new(),
    }))
}

pub fn query(store: &Store, account_id: &Id, _args: &Value) -> MethodResult {
    let ids: Vec<&str> = store
        .submissions()
        .iter()
        .filter_map(|s| s.get("id").and_then(Value::as_str))
        .map(str::to_string)
        .collect::<Vec<String>>()
        .leak()
        .iter()
        .map(String::as_str)
        .collect();
    Ok(json!({
        "accountId": account_id,
        "queryState": store.submission_state(),
        "canCalculateChanges": false,
        "position": 0,
        "total": ids.len(),
        "ids": ids,
    }))
}

#[derive(Default, Deserialize)]
struct QueryChangesArgs {
    #[serde(default, rename = "sinceQueryState")]
    since_query_state: String,
}

pub fn query_changes(store: &Store, account_id: &Id, args: &Value) -> MethodResult {
    let req: QueryChangesArgs = serde_json::from_value(args.clone()).unwrap_or_default();
    let cur: i64 = store.submission_state().parse().unwrap_or(0);
    if parse_since(&req.since_query_state)? > cur {
        return Err(MethodError::CannotCalculateChanges);
    }
    Ok(json!({
        "accountId": account_id,
        "oldQueryState": req.since_query_state,
        "newQueryState": cur.to_string(),
        "removed": Vec::<Id>::new(),
        "added": Vec::<Value>::new(),
    }))
}

#[derive(Default, Deserialize)]
struct SetArgs {
    #[serde(default)]
    create: BTreeMap<Id, CreateSpec>,
}

#[derive(Default, Deserialize)]
struct CreateSpec {
    #[serde(default, rename = "emailId")]
    email_id: Id,
    #[serde(default)]
    envelope: Option<Envelope>,
}

/// `now` is injected so tests can pin the timestamps this writes into the
/// submission record and its id.
pub fn set(store: &Store, account_id: &Id, args: &Value, now: &str) -> MethodResult {
    let req: SetArgs = serde_json::from_value(args.clone()).unwrap_or_default();
    let hooks = store.hooks();

    let mut created = serde_json::Map::new();
    let mut not_created = serde_json::Map::new();

    for (key, spec) in req.create {
        let Some(hook) = &hooks.submit_email else {
            not_created.insert(
                key.0,
                err_obj("serverFail", "EmailSubmission/set not configured"),
            );
            continue;
        };
        // A draft lives in the pending map until it is submitted; falling back
        // to the persisted store covers re-sending something already saved.
        let Some(msg) = store
            .take_pending(&spec.email_id)
            .or_else(|| store.get(&spec.email_id))
        else {
            not_created.insert(
                key.0,
                err_obj(
                    "notFound",
                    &format!("email {:?} not found", spec.email_id.0),
                ),
            );
            continue;
        };
        let env = spec.envelope.unwrap_or_default();
        let (id, thread_id) = (msg.id.clone(), msg.thread_id.clone());
        if let Err(e) = hook(msg, env) {
            not_created.insert(key.0, err_obj("serverFail", &e));
            continue;
        }

        let sub_id = format!("sub-{key}-{now}");
        let mut rec = JsonObject::new();
        rec.insert("id".into(), Value::String(sub_id.clone()));
        rec.insert("identityId".into(), Value::String(String::new()));
        rec.insert("emailId".into(), Value::String(id.0));
        rec.insert("threadId".into(), Value::String(thread_id.0));
        rec.insert("sendAt".into(), Value::String(now.to_string()));
        rec.insert("undoStatus".into(), Value::String("final".into()));
        store.add_submission(rec);

        created.insert(
            key.0,
            json!({"id": sub_id, "sendAt": now, "undoStatus": "final"}),
        );
    }

    // oldState and newState are both read after the writes, so they are always
    // equal — preserved from the Go original (SPEC.md §11.8).
    Ok(json!({
        "accountId": account_id,
        "oldState": store.submission_state(),
        "newState": store.submission_state(),
        "created": created,
        "notCreated": not_created,
        "updated": serde_json::Map::new(),
        "notUpdated": serde_json::Map::new(),
        "destroyed": Vec::<String>::new(),
        "notDestroyed": serde_json::Map::new(),
    }))
}
