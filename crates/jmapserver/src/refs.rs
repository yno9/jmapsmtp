//! JMAP result references (RFC 8620 §3.7).
//!
//! An argument whose name starts with `#` is replaced by a value pulled out of
//! an earlier call's result, addressed by a slash-delimited path.

use serde::Deserialize;
use serde_json::{Map, Value};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefError(pub String);

impl std::fmt::Display for RefError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Deserialize)]
struct ResultReference {
    #[serde(rename = "resultOf")]
    result_of: String,
    path: String,
}

/// Substitute every `#`-prefixed argument. Arguments that are not an object,
/// and objects with no references, are returned untouched — including on a
/// parse failure, matching the Go original, which treats a non-object as
/// having nothing to resolve rather than as an error.
pub fn resolve(args: &Value, results: &BTreeMap<String, Value>) -> Result<Value, RefError> {
    let Some(obj) = args.as_object() else {
        return Ok(args.clone());
    };
    if !obj.keys().any(|k| k.starts_with('#')) {
        return Ok(args.clone());
    }

    let mut out = Map::new();
    for (k, v) in obj {
        let Some(name) = k.strip_prefix('#') else {
            out.insert(k.clone(), v.clone());
            continue;
        };
        let reference: ResultReference = serde_json::from_value(v.clone())
            .map_err(|e| RefError(format!("bad result reference {k}: {e}")))?;
        let prev = results
            .get(&reference.result_of)
            .ok_or_else(|| RefError(format!("no result for callId {:?}", reference.result_of)))?;
        let resolved = json_path(prev, &reference.path).map_err(|e| {
            RefError(format!(
                "path {:?} in {:?}: {e}",
                reference.path, reference.result_of
            ))
        })?;
        out.insert(name.to_string(), resolved);
    }
    Ok(Value::Object(out))
}

/// Walk a slash-delimited path, e.g. `/list/0/id`. Empty segments are skipped,
/// so a leading slash and a doubled one are both tolerated.
fn json_path(data: &Value, path: &str) -> Result<Value, String> {
    let mut cur = data;
    for seg in path.trim_start_matches('/').split('/') {
        if seg.is_empty() {
            continue;
        }
        cur = match cur {
            Value::Object(m) => m.get(seg).ok_or_else(|| format!("key {seg:?} not found"))?,
            Value::Array(a) => {
                let idx: usize = seg
                    .parse()
                    .map_err(|_| format!("expected array index at {seg:?}"))?;
                a.get(idx)
                    .ok_or_else(|| format!("index {idx} out of range (len {})", a.len()))?
            }
            _ => return Err(format!("expected object or array at {seg:?}")),
        };
    }
    Ok(cur.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn results() -> BTreeMap<String, Value> {
        let mut m = BTreeMap::new();
        m.insert(
            "c0".to_string(),
            json!({"ids": ["a", "b"], "list": [{"id": "x"}], "state": "3"}),
        );
        m
    }

    #[test]
    fn passes_through_arguments_with_no_references() {
        let args = json!({"accountId": "acct", "ids": ["a"]});
        assert_eq!(resolve(&args, &results()).unwrap(), args);
    }

    #[test]
    fn substitutes_a_reference_and_drops_the_hash() {
        let args = json!({
            "accountId": "acct",
            "#ids": {"resultOf": "c0", "path": "/ids"},
        });
        assert_eq!(
            resolve(&args, &results()).unwrap(),
            json!({"accountId": "acct", "ids": ["a", "b"]})
        );
    }

    #[test]
    fn indexes_into_arrays() {
        let args = json!({"#id": {"resultOf": "c0", "path": "/list/0/id"}});
        assert_eq!(resolve(&args, &results()).unwrap(), json!({"id": "x"}));
    }

    #[test]
    fn reports_the_failures_the_go_original_reports() {
        for (args, expected) in [
            (
                json!({"#ids": {"resultOf": "nope", "path": "/ids"}}),
                "no result for callId",
            ),
            (
                json!({"#ids": {"resultOf": "c0", "path": "/missing"}}),
                "not found",
            ),
            (
                json!({"#ids": {"resultOf": "c0", "path": "/ids/9"}}),
                "out of range",
            ),
            (
                json!({"#ids": {"resultOf": "c0", "path": "/state/0"}}),
                "expected object or array",
            ),
            (
                json!({"#ids": {"resultOf": "c0", "path": "/ids/x"}}),
                "expected array index",
            ),
            (json!({"#ids": "not a reference"}), "bad result reference"),
        ] {
            let err = resolve(&args, &results()).expect_err("must fail");
            assert!(err.0.contains(expected), "{} lacks {expected:?}", err.0);
        }
    }

    #[test]
    fn a_non_object_argument_is_left_alone() {
        assert_eq!(
            resolve(&json!("scalar"), &results()).unwrap(),
            json!("scalar")
        );
    }
}
