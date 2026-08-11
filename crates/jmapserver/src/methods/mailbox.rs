//! `Mailbox/*`. Port of `go-jmapserver/mailbox.go`.

use std::collections::BTreeSet;

use jmap_types::Id;
use jmap_types::mailbox::Mailbox;
use serde::Deserialize;
use serde_json::{Value, json};

use super::{MethodError, MethodResult, err_obj, parse_since};
use crate::store::{MailboxChangeRecord, Store};

pub fn get(store: &Store, account_id: &Id, _args: &Value) -> MethodResult {
    Ok(json!({
        "accountId": account_id,
        "state": store.mailbox_state(),
        "list": store.mailboxes(),
        // A bare [] rather than a list of ids: Mailbox/get looks nothing up
        // by id, so nothing can be missing. Typed as []string in Go.
        "notFound": Vec::<String>::new(),
    }))
}

#[derive(Default, Deserialize)]
struct ChangesArgs {
    #[serde(default, rename = "sinceState")]
    since_state: String,
}

pub fn changes(store: &Store, account_id: &Id, args: &Value) -> MethodResult {
    let req: ChangesArgs = serde_json::from_value(args.clone()).unwrap_or_default();
    let since = parse_since(&req.since_state)?;
    let cur: i64 = store.mailbox_state().parse().unwrap_or(0);
    if since > cur {
        return Err(MethodError::CannotCalculateChanges);
    }

    let log = store.mailbox_changes();
    let (mut created, mut updated, mut destroyed) =
        (BTreeSet::new(), BTreeSet::new(), BTreeSet::new());
    for v in (since + 1)..=cur {
        let rec = log.get(&v).ok_or(MethodError::CannotCalculateChanges)?;
        for id in &rec.created {
            created.insert(id.clone());
            destroyed.remove(id);
        }
        for id in &rec.updated {
            if !created.contains(id) {
                updated.insert(id.clone());
            }
        }
        for id in &rec.destroyed {
            destroyed.insert(id.clone());
            created.remove(id);
            updated.remove(id);
        }
    }

    Ok(json!({
        "accountId": account_id,
        "oldState": req.since_state,
        "newState": cur.to_string(),
        "hasMoreChanges": false,
        "created": created,
        "updated": updated,
        "destroyed": destroyed,
    }))
}

#[derive(Default, Deserialize)]
struct QueryArgs {
    #[serde(default)]
    filter: Option<QueryFilter>,
}

#[derive(Default, Deserialize)]
struct QueryFilter {
    #[serde(default)]
    name: String,
    #[serde(default)]
    role: String,
}

pub fn query(store: &Store, account_id: &Id, args: &Value) -> MethodResult {
    let req: QueryArgs = serde_json::from_value(args.clone()).unwrap_or_default();
    let ids: Vec<Id> = store
        .mailboxes()
        .into_iter()
        .filter(|mb| match &req.filter {
            None => true,
            Some(f) => {
                (f.name.is_empty() || mb.name.to_lowercase().contains(&f.name.to_lowercase()))
                    && (f.role.is_empty() || mb.role.as_str() == f.role)
            }
        })
        .map(|mb| mb.id)
        .collect();

    Ok(json!({
        "accountId": account_id,
        "queryState": store.mailbox_state(),
        "canCalculateChanges": true,
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
    let since = parse_since(&req.since_query_state)?;
    let cur: i64 = store.mailbox_state().parse().unwrap_or(0);
    if since > cur {
        return Err(MethodError::CannotCalculateChanges);
    }

    let log = store.mailbox_changes();
    let (mut added, mut removed) = (BTreeSet::new(), BTreeSet::new());
    for v in (since + 1)..=cur {
        let rec = log.get(&v).ok_or(MethodError::CannotCalculateChanges)?;
        for id in &rec.created {
            added.insert(id.clone());
            removed.remove(id);
        }
        for id in &rec.destroyed {
            removed.insert(id.clone());
            added.remove(id);
        }
    }

    // The index is a running counter over the set, not a position in the
    // query result — that is what the Go original computes, and over a map,
    // so which id gets which index is arbitrary there. Sorted order at least
    // makes it repeatable.
    let added: Vec<Value> = added
        .into_iter()
        .enumerate()
        .map(|(i, id)| json!({"id": id, "index": i}))
        .collect();

    Ok(json!({
        "accountId": account_id,
        "oldQueryState": req.since_query_state,
        "newQueryState": cur.to_string(),
        "removed": removed,
        "added": added,
    }))
}

#[derive(Default, Deserialize)]
struct SetArgs {
    #[serde(default)]
    create: std::collections::BTreeMap<Id, Mailbox>,
    #[serde(default)]
    update: std::collections::BTreeMap<Id, Value>,
    #[serde(default)]
    destroy: Vec<Id>,
}

pub fn set(store: &Store, account_id: &Id, args: &Value) -> MethodResult {
    let req: SetArgs = serde_json::from_value(args.clone()).unwrap_or_default();
    let hooks = store.hooks();

    let old_state = store.mailbox_state();
    let mut mbs = store.mailboxes();

    let mut created = serde_json::Map::new();
    let mut not_created = serde_json::Map::new();
    let mut updated = serde_json::Map::new();
    let mut not_updated = serde_json::Map::new();
    let mut destroyed: Vec<Id> = Vec::new();
    let mut not_destroyed = serde_json::Map::new();

    let mut rec = MailboxChangeRecord::default();
    let mut changed = false;

    for (key, mut mb) in req.create {
        if mb.id.is_empty() {
            mb.id = Id(format!("mbx-{key}"));
        }
        if let Some(hook) = &hooks.set_mailbox
            && let Err(e) = hook("create", &mb.id, Some(&mb))
        {
            not_created.insert(key.0, err_obj("serverFail", &e));
            continue;
        }
        created.insert(key.0, json!({"id": mb.id}));
        rec.created.push(mb.id.clone());
        mbs.push(mb);
        changed = true;
    }

    for (id, patch) in req.update {
        let Some(idx) = mbs.iter().position(|mb| mb.id == id) else {
            not_updated.insert(id.0, err_obj("notFound", "mailbox not found"));
            continue;
        };
        // Only `name` is honoured; every other property is silently ignored,
        // as in the Go original.
        if let Some(name) = patch.get("name").and_then(Value::as_str) {
            mbs[idx].name = name.to_string();
        }
        updated.insert(id.0.clone(), json!({}));
        rec.updated.push(id);
        changed = true;
    }

    let mut destroy_set = BTreeSet::new();
    for id in req.destroy {
        if !mbs.iter().any(|mb| mb.id == id) {
            not_destroyed.insert(id.0, err_obj("notFound", "mailbox not found"));
            continue;
        }
        if let Some(hook) = &hooks.set_mailbox
            && let Err(e) = hook("destroy", &id, None)
        {
            not_destroyed.insert(id.0, err_obj("serverFail", &e));
            continue;
        }
        destroy_set.insert(id.clone());
        destroyed.push(id.clone());
        rec.destroyed.push(id);
        changed = true;
    }

    if changed {
        mbs.retain(|mb| !destroy_set.contains(&mb.id));
        let _ = store.put_mailboxes(&mbs);
        store.bump_mailbox_state(rec);
    }

    Ok(json!({
        "accountId": account_id,
        "oldState": old_state,
        "newState": store.mailbox_state(),
        "created": created,
        "updated": updated,
        "destroyed": destroyed,
        "notCreated": not_created,
        "notUpdated": not_updated,
        "notDestroyed": not_destroyed,
    }))
}
