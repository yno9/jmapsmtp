//! `Email/*`. Port of the handler half of `go-jmapserver/email.go`.
//!
//! The MIME half of that file (`ParseMIMEEmail`, `BuildRFC5322`,
//! `ExtractAttachments`) is M5; `Email/import` and `Email/parse` need it and
//! are stubbed here until then.

use std::collections::{BTreeMap, BTreeSet};

use jmap_types::Id;
use jmap_types::email::Email;
use serde::Deserialize;
use serde_json::{Value, json};

use super::{MethodError, MethodResult, err_obj, parse_since};
use crate::store::{ChangeRecord, JsonObject, Store};

/// Case-insensitive match against subject, any From/To/Cc name or address,
/// and every body value.
fn matches_text(m: &Email, q: &str) -> bool {
    let q = q.to_lowercase();
    if m.subject.to_lowercase().contains(&q) {
        return true;
    }
    for addrs in [&m.from, &m.to, &m.cc] {
        for a in addrs {
            if a.name.to_lowercase().contains(&q) || a.email.to_lowercase().contains(&q) {
                return true;
            }
        }
    }
    m.body_values
        .values()
        .any(|bv| bv.value.to_lowercase().contains(&q))
}

#[derive(Default, Deserialize)]
struct GetArgs {
    #[serde(default)]
    ids: Vec<Id>,
}

pub fn get(store: &Store, account_id: &Id, args: &Value) -> MethodResult {
    let req: GetArgs = serde_json::from_value(args.clone()).unwrap_or_default();
    let mut list = Vec::new();
    let mut not_found = Vec::new();
    for id in &req.ids {
        match store.get(id) {
            Some(m) => list.push(m),
            None => not_found.push(id.clone()),
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
struct QueryArgs {
    #[serde(default)]
    filter: Option<QueryFilter>,
    #[serde(default)]
    position: i64,
    #[serde(default)]
    limit: u64,
}

#[derive(Default, Deserialize)]
struct QueryFilter {
    #[serde(default, rename = "inMailbox")]
    in_mailbox: String,
    #[serde(default)]
    text: String,
}

pub fn query(store: &Store, account_id: &Id, args: &Value) -> MethodResult {
    let req: QueryArgs = serde_json::from_value(args.clone()).unwrap_or_default();

    // Store::all is already newest-first; the filter preserves that order,
    // which is the order clients render.
    let filtered: Vec<Id> = store
        .all()
        .into_iter()
        .filter(|m| match &req.filter {
            None => true,
            Some(f) => {
                (f.in_mailbox.is_empty()
                    || m.mailbox_ids.get(&Id::from(f.in_mailbox.as_str())) == Some(&true))
                    && (f.text.is_empty() || matches_text(m, &f.text))
            }
        })
        .map(|m| m.id)
        .collect();

    let total = filtered.len();
    let start = req.position.max(0) as usize;
    let ids: &[Id] = if start >= total {
        &[]
    } else {
        let end = if req.limit > 0 {
            (start + req.limit as usize).min(total)
        } else {
            total
        };
        &filtered[start..end]
    };

    Ok(json!({
        "accountId": account_id,
        "queryState": store.state(),
        "canCalculateChanges": true,
        "position": start,
        "total": total,
        "ids": ids,
    }))
}

#[derive(Default, Deserialize)]
struct ChangesArgs {
    #[serde(default, rename = "sinceState")]
    since_state: String,
}

/// created, updated, destroyed — the shape every `*/changes` response reports.
type ChangeSets = (BTreeSet<Id>, BTreeSet<Id>, BTreeSet<Id>);

/// Fold the change log from `since` to now into three sets.
fn fold_changes(
    log: &BTreeMap<i64, ChangeRecord>,
    since: i64,
    cur: i64,
) -> Result<ChangeSets, MethodError> {
    let (mut created, mut updated, mut destroyed) =
        (BTreeSet::new(), BTreeSet::new(), BTreeSet::new());
    for v in (since + 1)..=cur {
        let rec = log.get(&v).ok_or(MethodError::CannotCalculateChanges)?;
        for id in &rec.added {
            created.insert(id.clone());
            destroyed.remove(id);
        }
        for id in &rec.updated {
            // An update to something created in the same window is folded
            // into the creation, not reported twice.
            if !created.contains(id) {
                updated.insert(id.clone());
            }
        }
        for id in &rec.removed {
            destroyed.insert(id.clone());
            created.remove(id);
            updated.remove(id);
        }
    }
    Ok((created, updated, destroyed))
}

pub fn changes(store: &Store, account_id: &Id, args: &Value) -> MethodResult {
    let req: ChangesArgs = serde_json::from_value(args.clone()).unwrap_or_default();
    let since = parse_since(&req.since_state)?;
    let cur: i64 = store.state().parse().unwrap_or(0);
    if since > cur {
        return Err(MethodError::CannotCalculateChanges);
    }
    let (created, updated, destroyed) = fold_changes(&store.changes(), since, cur)?;
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
struct QueryChangesArgs {
    #[serde(default, rename = "sinceQueryState")]
    since_query_state: String,
}

pub fn query_changes(store: &Store, account_id: &Id, args: &Value) -> MethodResult {
    let req: QueryChangesArgs = serde_json::from_value(args.clone()).unwrap_or_default();
    let since = parse_since(&req.since_query_state)?;
    let cur: i64 = store.state().parse().unwrap_or(0);
    if since > cur {
        return Err(MethodError::CannotCalculateChanges);
    }

    let log = store.changes();
    let (mut added, mut removed) = (BTreeSet::new(), BTreeSet::new());
    for v in (since + 1)..=cur {
        let rec = log.get(&v).ok_or(MethodError::CannotCalculateChanges)?;
        for id in &rec.added {
            added.insert(id.clone());
            removed.remove(id);
        }
        for id in &rec.removed {
            removed.insert(id.clone());
            added.remove(id);
        }
    }
    // As in Mailbox/queryChanges: the index is a counter over the set, not a
    // position in the query result.
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
    create: BTreeMap<Id, Box<serde_json::value::RawValue>>,
    #[serde(default)]
    update: BTreeMap<Id, Value>,
    #[serde(default)]
    destroy: Vec<Id>,
}

pub fn set(store: &Store, account_id: &Id, args: &Value) -> MethodResult {
    let req: SetArgs = serde_json::from_value(args.clone()).unwrap_or_default();
    let hooks = store.hooks();

    let old_state = store.state();
    let mut created = serde_json::Map::new();
    let mut not_created = serde_json::Map::new();
    let mut updated = serde_json::Map::new();
    let mut not_updated = serde_json::Map::new();
    let mut destroyed: Vec<Id> = Vec::new();
    let mut not_destroyed = serde_json::Map::new();

    for (key, raw) in req.create {
        // Creation is entirely the application's business: the store has no
        // idea how to mint an id, a Message-ID or a receive time.
        let Some(hook) = &hooks.create_email else {
            not_created.insert(
                key.0,
                err_obj("serverFail", "Email/set create not configured"),
            );
            continue;
        };
        match hook(&raw) {
            Ok(m) => {
                created.insert(key.0, json!({"id": m.id}));
            }
            Err(e) => {
                not_created.insert(key.0, err_obj("serverFail", &e));
            }
        }
    }

    for (id, patch) in req.update {
        let Some(patch) = patch.as_object() else {
            not_updated.insert(
                id.0,
                err_obj("invalidProperties", "patch must be an object"),
            );
            continue;
        };
        let patch: JsonObject = patch.clone().into_iter().collect();
        if let Some(hook) = &hooks.update_email
            && let Err(e) = hook(&id, &patch)
        {
            not_updated.insert(id.0, err_obj("serverFail", &e));
            continue;
        }
        match store.patch_email(&id, &patch) {
            Ok(()) => {
                updated.insert(id.0, json!({}));
            }
            Err(e) => {
                not_updated.insert(id.0, err_obj("serverFail", &e.to_string()));
            }
        }
    }

    for id in req.destroy {
        if let Some(hook) = &hooks.destroy_email
            && let Err(e) = hook(&id)
        {
            not_destroyed.insert(id.0, err_obj("serverFail", &e));
            continue;
        }
        store.delete(&id);
        destroyed.push(id);
    }

    Ok(json!({
        "accountId": account_id,
        "oldState": old_state,
        "newState": store.state(),
        "created": created,
        "updated": updated,
        "destroyed": destroyed,
        "notCreated": not_created,
        "notUpdated": not_updated,
        "notDestroyed": not_destroyed,
    }))
}

#[derive(Default, Deserialize)]
struct CopyArgs {
    #[serde(default, rename = "fromAccountId")]
    from_account_id: Id,
    #[serde(default)]
    create: BTreeMap<Id, CopySpec>,
}

#[derive(Default, Deserialize)]
struct CopySpec {
    #[serde(default)]
    id: Id,
    #[serde(default, rename = "mailboxIds")]
    mailbox_ids: BTreeMap<Id, bool>,
}

pub fn copy(store: &Store, account_id: &Id, args: &Value) -> MethodResult {
    let req: CopyArgs = serde_json::from_value(args.clone()).unwrap_or_default();
    let mut created = serde_json::Map::new();
    let mut not_created = serde_json::Map::new();

    for (key, spec) in req.create {
        let Some(mut m) = store.get(&spec.id) else {
            not_created.insert(
                key.0,
                err_obj("notFound", &format!("email {:?} not found", spec.id.0)),
            );
            continue;
        };
        let new_id = Id(format!("{}-cp-{}", spec.id, key));
        m.id = new_id.clone();
        if !spec.mailbox_ids.is_empty() {
            m.mailbox_ids = spec.mailbox_ids;
        }
        match store.put(m) {
            Ok(()) => {
                created.insert(key.0, json!({"id": new_id}));
            }
            Err(e) => {
                not_created.insert(key.0, err_obj("serverFail", &e.to_string()));
            }
        }
    }

    let from_id = if req.from_account_id.is_empty() {
        account_id.clone()
    } else {
        req.from_account_id
    };
    // oldState and newState are both read after the writes, so they are always
    // equal — preserved from the Go original (SPEC.md §11.8).
    Ok(json!({
        "fromAccountId": from_id,
        "accountId": account_id,
        "oldState": store.state(),
        "newState": store.state(),
        "created": created,
        "notCreated": not_created,
    }))
}

/// `Email/import` needs `ParseMIMEEmail`, which arrives in M5.
pub fn import(store: &Store, account_id: &Id, args: &Value) -> MethodResult {
    let _ = (store, args);
    Ok(json!({
        "accountId": account_id,
        "oldState": store.state(),
        "newState": store.state(),
        "created": serde_json::Map::new(),
        "notCreated": serde_json::Map::new(),
    }))
}

/// `Email/parse` needs `ParseMIMEEmail`, which arrives in M5.
pub fn parse(store: &Store, account_id: &Id, args: &Value) -> MethodResult {
    let _ = (store, args);
    Ok(json!({
        "accountId": account_id,
        "parsed": serde_json::Map::new(),
        "notParsable": serde_json::Map::new(),
    }))
}
