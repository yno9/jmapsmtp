//! `Identity/*`. Port of `go-jmapserver/identity.go`.

use std::collections::{BTreeMap, BTreeSet};

use jmap_types::Id;
use serde::Deserialize;
use serde_json::{Value, json};

use super::{MethodResult, err_obj};
use crate::store::{JsonObject, Store};

/// Stored identities, or a synthesised default when the account has none.
pub fn get(store: &Store, account_id: &Id) -> MethodResult {
    let ids = store.identities();
    let list = if ids.is_empty() {
        vec![Store::default_identity(account_id.as_str())]
    } else {
        ids
    };
    Ok(json!({
        "accountId": account_id,
        "state": store.identity_state(),
        "list": list,
        "notFound": Vec::<Id>::new(),
    }))
}

#[derive(Default, Deserialize)]
struct ChangesArgs {
    #[serde(default, rename = "sinceState")]
    since_state: String,
}

/// Always reports no changes: identity changes are not tracked per version.
pub fn changes(store: &Store, account_id: &Id, args: &Value) -> MethodResult {
    let req: ChangesArgs = serde_json::from_value(args.clone()).unwrap_or_default();
    Ok(json!({
        "accountId": account_id,
        "oldState": req.since_state,
        "newState": store.identity_state(),
        "hasMoreChanges": false,
        "created": Vec::<Id>::new(),
        "updated": Vec::<Id>::new(),
        "destroyed": Vec::<Id>::new(),
    }))
}

#[derive(Default, Deserialize)]
struct SetArgs {
    #[serde(default)]
    create: BTreeMap<Id, Value>,
    #[serde(default)]
    update: BTreeMap<Id, Value>,
    #[serde(default)]
    destroy: Vec<Id>,
}

fn as_object(v: &Value) -> Option<JsonObject> {
    v.as_object().map(|m| m.clone().into_iter().collect())
}

pub fn set(store: &Store, account_id: &Id, args: &Value) -> MethodResult {
    let req: SetArgs = serde_json::from_value(args.clone()).unwrap_or_default();
    let hooks = store.hooks();

    let old_state = store.identity_state();
    let mut identities = store.identities();
    let mut bumps: i64 = 0;

    let mut created = serde_json::Map::new();
    let mut not_created = serde_json::Map::new();
    let mut updated = serde_json::Map::new();
    let mut not_updated = serde_json::Map::new();
    let mut destroyed: Vec<Id> = Vec::new();
    let mut not_destroyed = serde_json::Map::new();

    let index_of = |list: &[JsonObject], id: &str| {
        list.iter()
            .position(|o| o.get("id").and_then(Value::as_str) == Some(id))
    };

    for (key, raw) in req.create {
        let Some(mut data) = as_object(&raw) else {
            not_created.insert(
                key.0,
                err_obj("invalidProperties", "identity must be an object"),
            );
            continue;
        };
        let new_id = match data.get("id").and_then(Value::as_str) {
            Some(v) if !v.is_empty() => v.to_string(),
            _ => format!("identity-{key}"),
        };
        data.insert("id".into(), Value::String(new_id.clone()));
        if let Some(hook) = &hooks.set_identity
            && let Err(e) = hook("create", &Id(new_id.clone()), Some(&data))
        {
            not_created.insert(key.0, err_obj("serverFail", &e));
            continue;
        }
        identities.push(data);
        bumps += 1;
        created.insert(key.0, json!({"id": new_id}));
    }

    for (id, raw) in req.update {
        let existing = index_of(&identities, id.as_str());
        // Identity/get synthesises a default whenever the account has none,
        // and never stores it. A client editing "its identity" naturally
        // targets that id, because that is the id Identity/get just handed
        // it. Rejecting it as notFound made every such edit appear to
        // succeed and silently do nothing, with the next Identity/get
        // re-synthesising the untouched original — so this upserts instead.
        let base = match existing {
            Some(i) => identities[i].clone(),
            None if id.as_str() == format!("identity-{account_id}") => {
                Store::default_identity(account_id.as_str())
            }
            None => {
                not_updated.insert(id.0, err_obj("notFound", "identity not found"));
                continue;
            }
        };
        let Some(patch) = as_object(&raw) else {
            not_updated.insert(
                id.0,
                err_obj("invalidProperties", "patch must be an object"),
            );
            continue;
        };
        let mut merged = base;
        merged.extend(patch);

        if let Some(hook) = &hooks.set_identity {
            let op = if existing.is_some() {
                "update"
            } else {
                "create"
            };
            if let Err(e) = hook(op, &id, Some(&merged)) {
                not_updated.insert(id.0, err_obj("serverFail", &e));
                continue;
            }
        }
        match existing {
            Some(i) => identities[i] = merged,
            None => identities.push(merged),
        }
        bumps += 1;
        updated.insert(id.0, json!({}));
    }

    let mut destroy_set = BTreeSet::new();
    for id in req.destroy {
        if index_of(&identities, id.as_str()).is_none() {
            not_destroyed.insert(id.0, err_obj("notFound", "identity not found"));
            continue;
        }
        if let Some(hook) = &hooks.set_identity
            && let Err(e) = hook("destroy", &id, None)
        {
            not_destroyed.insert(id.0, err_obj("serverFail", &e));
            continue;
        }
        destroy_set.insert(id.0.clone());
        destroyed.push(id);
        bumps += 1;
    }
    if !destroy_set.is_empty() {
        identities.retain(|o| {
            o.get("id")
                .and_then(Value::as_str)
                .is_none_or(|v| !destroy_set.contains(v))
        });
    }

    if bumps > 0 {
        store.replace_identities(identities, bumps);
    }

    Ok(json!({
        "accountId": account_id,
        "oldState": old_state,
        "newState": store.identity_state(),
        "created": created,
        "updated": updated,
        "destroyed": destroyed,
        "notCreated": not_created,
        "notUpdated": not_updated,
        "notDestroyed": not_destroyed,
    }))
}
