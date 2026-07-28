//! The JMAP HTTP surface. Port of `go-jmapserver/server.go`.
//!
//! The application implements [`Handler`]; this module owns everything about
//! HTTP and the JMAP wire format, and the handler never sees either.
//!
//! CORS is written out by hand rather than delegated to a middleware, and the
//! header values deliberately differ between routes: the per-route wrapper
//! advertises `GET, POST, OPTIONS` while the outer one advertises
//! `GET, POST, PUT, OPTIONS`. That inconsistency is what the Go implementation
//! actually sends, and the differential harness compares these headers, so
//! tidying it up would be a behaviour change.

use std::collections::BTreeMap;
use std::sync::Arc;

use jmap_types::{Id, Uri, go_json};
use parking_lot::Mutex;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::methods::MethodResult;
use crate::refs;

/// HTTP server configuration.
///
/// Field names match the JSON in `config.json`, which is shared with the
/// application's own settings — the Go original embeds this struct.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Config {
    #[serde(default, rename = "listen_addr")]
    pub listen_addr: String,
    #[serde(default)]
    pub password: String,
    #[serde(default, rename = "base_url")]
    pub base_url: String,
    #[serde(default, rename = "vapid_public_key")]
    pub vapid_public_key: String,
    #[serde(default, rename = "vapid_private_key")]
    pub vapid_private_key: String,
    #[serde(default, rename = "vapid_subscriber")]
    pub vapid_subscriber: String,
}

/// One account exposed by the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub id: Id,
    pub name: String,
}

/// Implemented by the application. The server calls these; they never touch
/// HTTP or the JMAP envelope.
pub trait Handler: Send + Sync {
    /// The capability URIs this server supports.
    /// `urn:ietf:params:jmap:core` is added automatically.
    fn capabilities(&self) -> Vec<Uri>;

    /// One entry per configured account.
    fn accounts(&self) -> Vec<Account>;

    /// Execute a single method call. Arguments arrive fully resolved, with
    /// result references already substituted.
    fn handle(&self, method: &str, args: &Value) -> MethodResult;

    /// Whether this handler supports blob upload/download. When false, those
    /// two routes are not mounted at all — matching the Go original, which
    /// mounts them only if the handler also implements `BlobHandler`.
    fn supports_blobs(&self) -> bool {
        false
    }

    fn upload_blob(&self, _content_type: &str, _data: &[u8]) -> String {
        String::new()
    }

    fn download_blob(&self, _blob_id: &str) -> Option<Vec<u8>> {
        None
    }
}

/// Broadcasts state-change events to event-source subscribers.
pub struct Hub {
    subs: Mutex<Vec<tokio::sync::mpsc::Sender<()>>>,
}

impl Default for Hub {
    fn default() -> Self {
        Self::new()
    }
}

impl Hub {
    pub fn new() -> Hub {
        Hub {
            subs: Mutex::new(Vec::new()),
        }
    }

    /// Wake every subscriber. A subscriber whose buffer is already full is
    /// skipped rather than waited on: the event carries no payload, so one
    /// pending wake-up is as good as two.
    pub fn notify(&self) {
        let mut subs = self.subs.lock();
        subs.retain(|tx| !tx.is_closed());
        for tx in subs.iter() {
            let _ = tx.try_send(());
        }
    }

    fn subscribe(&self) -> tokio::sync::mpsc::Receiver<()> {
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        self.subs.lock().push(tx);
        rx
    }
}

/// Resolves a username/password to an account, or rejects it.
///
/// A direct port of the Go `Config.AuthFunc` field rather than a method on
/// [`Handler`]: its *presence* is load-bearing. Installing one disables both
/// fallbacks below, and Rust gives no way to ask whether a trait method was
/// overridden, so the distinction has to be a value.
pub type AuthFn = Arc<dyn Fn(&str, &str) -> Option<Id> + Send + Sync>;

/// Everything the routes need.
pub struct Server {
    pub cfg: Config,
    pub handler: Arc<dyn Handler>,
    pub hub: Arc<Hub>,
    pub auth: Option<AuthFn>,
}

impl Server {
    /// Resolve credentials, in the Go original's order of precedence.
    ///
    /// 1. An installed [`AuthFn`] decides, and its rejection is final.
    /// 2. Otherwise a single global password, if configured.
    /// 3. Otherwise **everything is accepted**.
    ///
    /// Step 3 is wide open by design — it is what lets the library be used
    /// with no auth at all — so an application that wants a closed server
    /// must install an `auth` function. Leaving both unset is not a safe
    /// default; it is no authentication.
    pub fn authenticate(&self, username: &str, password: &str) -> Option<Id> {
        if let Some(auth) = &self.auth {
            return auth(username, password);
        }
        if !self.cfg.password.is_empty() {
            return (password == self.cfg.password).then(|| Id::from(username));
        }
        Some(Id::from(username))
    }
}

/// The JMAP Session object (RFC 8620 §2).
pub fn session(srv: &Server, authed: Option<&Id>) -> Value {
    let caps = srv.handler.capabilities();

    let mut raw_caps = serde_json::Map::new();
    raw_caps.insert(
        jmap_types::CAP_CORE.to_string(),
        json!({
            "maxSizeUpload": 50_000_000,
            "maxConcurrentUpload": 4,
            "maxSizeRequest": 10_000_000,
            "maxConcurrentRequests": 4,
            "maxCallsInRequest": 32,
            "maxObjectsInGet": 500,
            "maxObjectsInSet": 500,
            "collationAlgorithms": [],
        }),
    );
    let mut acct_caps = serde_json::Map::new();
    for uri in &caps {
        raw_caps.insert(uri.0.clone(), json!({}));
        acct_caps.insert(uri.0.clone(), json!({}));
    }

    let mut accounts = serde_json::Map::new();
    let mut primary = serde_json::Map::new();
    let mut username = String::new();

    for a in srv.handler.accounts() {
        // An authenticated session shows only its own account.
        if let Some(authed) = authed
            && !authed.is_empty()
            && &a.id != authed
        {
            continue;
        }
        accounts.insert(
            a.id.0.clone(),
            json!({
                "name": a.name,
                "isPersonal": true,
                "isReadOnly": false,
                "accountCapabilities": acct_caps,
            }),
        );
        if username.is_empty() {
            username = a.name.clone();
            for uri in &caps {
                primary.insert(uri.0.clone(), Value::String(a.id.0.clone()));
            }
        }
    }

    let base = base_url(&srv.cfg);
    json!({
        "capabilities": raw_caps,
        "accounts": accounts,
        "primaryAccounts": primary,
        "username": username,
        "apiUrl": format!("{base}/jmap/api/"),
        "downloadUrl": format!("{base}/jmap/download/{{accountId}}/{{blobId}}/{{name}}?accept={{type}}"),
        "uploadUrl": format!("{base}/jmap/upload/{{accountId}}/"),
        "eventSourceUrl": format!("{base}/jmap/eventsource/"),
        "state": "0",
    })
}

fn base_url(cfg: &Config) -> String {
    let base = cfg.base_url.trim_end_matches('/');
    if !base.is_empty() {
        return base.to_string();
    }
    let addr = if cfg.listen_addr.is_empty() {
        "0.0.0.0:8765"
    } else {
        &cfg.listen_addr
    };
    format!("http://{addr}")
}

/// One `/jmap/api/` request.
#[derive(Default, Deserialize)]
pub struct ApiRequest {
    #[serde(default, rename = "methodCalls")]
    pub method_calls: Vec<Value>,
}

/// Run a batch of method calls, resolving result references between them.
///
/// A call that fails to parse as a three-element array is skipped silently and
/// produces no response entry, as in the Go original — the batch is not
/// aborted and no error is reported for it.
pub fn run_batch(srv: &Server, req: &ApiRequest) -> Value {
    let mut results: BTreeMap<String, Value> = BTreeMap::new();
    let mut responses: Vec<Value> = Vec::new();

    for raw in &req.method_calls {
        let Some(call) = raw.as_array() else { continue };
        if call.len() < 3 {
            continue;
        }
        let name = call[0].as_str().unwrap_or("").to_string();
        let call_id = call[2].as_str().unwrap_or("").to_string();

        let args = match refs::resolve(&call[1], &results) {
            Ok(a) => a,
            Err(e) => {
                responses.push(error_response(&name, &call_id, "serverFail", &e.0));
                continue;
            }
        };

        match srv.handler.handle(&name, &args) {
            Ok(result) => {
                results.insert(call_id.clone(), result.clone());
                responses.push(json!([name, result, call_id]));
            }
            Err(e) => {
                responses.push(error_response(
                    &name,
                    &call_id,
                    e.error_type(),
                    &e.to_string(),
                ));
            }
        }
    }

    json!({"sessionState": "0", "methodResponses": responses})
}

fn error_response(name: &str, call_id: &str, err_type: &str, desc: &str) -> Value {
    json!([name, {"type": err_type, "description": desc}, call_id])
}

/// Serialise a response the way Go would — HTML escaping included.
pub fn encode(value: &Value) -> Vec<u8> {
    let mut out = go_json::to_vec(value).unwrap_or_else(|_| b"{}".to_vec());
    // `json.NewEncoder(w).Encode` appends a newline; `json.Marshal` does not.
    // Every JMAP response goes through the encoder, so every one ends in one.
    out.push(b'\n');
    out
}

/// The first event an event-source subscriber receives, and the one sent on
/// every later notification.
pub const SSE_STATE_EVENT: &str =
    "event: state\ndata: {\"changed\":{\"urn:ietf:params:jmap:mail\":null}}\n\n";
pub const SSE_PING: &str = ": ping\n\n";

impl Hub {
    /// Subscribe for use by an event-source route.
    pub fn subscribe_events(&self) -> tokio::sync::mpsc::Receiver<()> {
        self.subscribe()
    }
}

#[cfg(test)]
mod tests;
