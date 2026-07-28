//! `SearchSnippet/get`. Port of the handler in `go-jmapserver/dispatch.go`.

use jmap_types::Id;
use serde::Deserialize;
use serde_json::{Value, json};

use super::MethodResult;
use crate::store::Store;

#[derive(Default, Deserialize)]
struct Args {
    #[serde(default)]
    filter: Option<Filter>,
    #[serde(default, rename = "emailIds")]
    email_ids: Vec<Id>,
}

#[derive(Default, Deserialize)]
struct Filter {
    #[serde(default)]
    text: String,
}

pub fn get(store: &Store, account_id: &Id, args: &Value) -> MethodResult {
    let req: Args = serde_json::from_value(args.clone()).unwrap_or_default();
    let query = req.filter.as_ref().map(|f| f.text.as_str()).unwrap_or("");

    let mut list = Vec::new();
    let mut not_found = Vec::new();
    for id in &req.email_ids {
        let Some(m) = store.get(id) else {
            not_found.push(id.clone());
            continue;
        };
        let (mut subject, mut preview) = (Value::Null, Value::Null);
        if !query.is_empty() {
            let q = query.to_lowercase();
            if let Some(s) = first_match(&m.subject, &q) {
                subject = Value::String(s);
            }
            // Only the first body value is searched — whichever that is. In
            // Go it is whichever the map happens to yield first; here it is
            // the lowest part id, which at least is repeatable.
            let body = m.body_values.values().next().map_or("", |bv| &bv.value);
            if let Some(p) = first_match(body, &q) {
                preview = Value::String(p);
            }
        }
        list.push(json!({"emailId": id, "subject": subject, "preview": preview}));
    }

    Ok(json!({
        "accountId": account_id,
        "list": list,
        "notFound": not_found,
    }))
}

/// A window around the first match: 20 characters before, 80 after, ellipsed
/// at both ends. `None` when the query does not occur.
///
/// The Go original slices bytes, which would split a multi-byte character;
/// this walks to the nearest character boundary instead, so the same input
/// yields the same window without risking invalid UTF-8.
fn first_match(text: &str, query_lower: &str) -> Option<String> {
    let idx = text.to_lowercase().find(query_lower)?;
    // The lowercased index maps back only for text whose case mapping is
    // length-preserving; clamp into range for the rest.
    let idx = idx.min(text.len());
    let start = floor_boundary(text, idx.saturating_sub(20));
    let end = ceil_boundary(text, (idx + query_lower.len() + 80).min(text.len()));
    Some(format!("…{}…", &text[start..end]))
}

fn floor_boundary(s: &str, mut i: usize) -> usize {
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

fn ceil_boundary(s: &str, mut i: usize) -> usize {
    while i < s.len() && !s.is_char_boundary(i) {
        i += 1;
    }
    i.min(s.len())
}
