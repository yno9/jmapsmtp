//! `VacationResponse/*`. Port of `go-jmapserver/vacation.go`.
//!
//! A singleton held in memory only — it does not survive a restart, as in the
//! Go original.

use std::collections::BTreeMap;

use jmap_types::Id;
use serde::Deserialize;
use serde_json::{Value, json};

use super::{MethodResult, err_obj};
use crate::store::{JsonObject, Store};

pub fn get(store: &Store, account_id: &Id, _args: &Value) -> MethodResult {
    let vr = store.vacation().unwrap_or_else(|| {
        let mut m = JsonObject::new();
        m.insert("id".into(), Value::String("singleton".into()));
        m.insert("isEnabled".into(), Value::Bool(false));
        m.insert("subject".into(), Value::Null);
        m.insert("textBody".into(), Value::Null);
        m.insert("htmlBody".into(), Value::Null);
        m
    });
    Ok(json!({
        "accountId": account_id,
        "state": "0",
        "list": [vr],
        "notFound": Vec::<Id>::new(),
    }))
}

#[derive(Default, Deserialize)]
struct SetArgs {
    #[serde(default)]
    update: BTreeMap<String, Value>,
}

pub fn set(store: &Store, account_id: &Id, args: &Value) -> MethodResult {
    let req: SetArgs = serde_json::from_value(args.clone()).unwrap_or_default();
    let mut updated = serde_json::Map::new();
    let mut not_updated = serde_json::Map::new();

    for (id, raw) in req.update {
        let Some(patch) = raw.as_object() else {
            not_updated.insert(id, err_obj("invalidProperties", "patch must be an object"));
            continue;
        };
        let mut vr = store.vacation().unwrap_or_else(|| {
            let mut m = JsonObject::new();
            m.insert("id".into(), Value::String("singleton".into()));
            m.insert("isEnabled".into(), Value::Bool(false));
            m
        });
        for (k, v) in patch {
            vr.insert(k.clone(), v.clone());
        }
        store.set_vacation(Some(vr));
        updated.insert(id, json!({}));
    }

    // The state is a hard-coded "0": there is nothing to version.
    Ok(json!({
        "accountId": account_id,
        "oldState": "0",
        "newState": "0",
        "created": serde_json::Map::new(),
        "updated": updated,
        "destroyed": Vec::<String>::new(),
        "notCreated": serde_json::Map::new(),
        "notUpdated": not_updated,
        "notDestroyed": serde_json::Map::new(),
    }))
}
