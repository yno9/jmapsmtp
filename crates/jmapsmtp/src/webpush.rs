//! Sending Web Push notifications.
//!
//! The subscription registry lives in [`jmapserver::push`]; this is delivery.
//!
//! # What a notification carries
//!
//! **Nothing.** The payload names the changed capability and no more — the
//! same frame the event-source stream sends. A client is told that something
//! changed and fetches over an authenticated connection. Putting a sender or a
//! subject in it would hand message metadata to the push service, which is a
//! third party the relay does not control and the user did not choose.
//!
//! # Encryption and signing are borrowed; sending is not
//!
//! RFC 8291 encryption and the VAPID JWT come from `web-push`, built without a
//! client feature. Its clients pull a second TLS stack, and this relay already
//! has one — so the request is built here and sent with the same HTTP client
//! the anchor uses.

use std::sync::Arc;

use jmapserver::push::{PushSubscription, Vapid};

/// The payload every notification carries.
///
/// Byte-identical to the event-source frame's data, so a client can handle one
/// path for both.
pub const PAYLOAD: &str = r#"{"changed":{"urn:ietf:params:jmap:mail":null}}"#;

/// How long a push service should hold an undelivered message, in seconds.
///
/// Four hours: long enough for a phone that is off overnight to still be woken
/// in the morning, short enough that a client coming back after days is not
/// handed a queue of identical "something changed" frames.
pub const TTL_SECS: u32 = 4 * 60 * 60;

/// What happened to one send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Delivery {
    Sent,
    /// The push service says this subscription is dead. **The caller should
    /// remove it**: a browser that revoked it never tells the relay, so a
    /// registry that never prunes grows forever and every send retries
    /// endpoints that will never accept again.
    Gone,
    /// Anything else — a transient failure, or a service that is down.
    Failed(String),
}

/// One prepared push request: where it goes, what it carries, and the headers
/// the push service needs to route and authorise it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushRequest {
    pub endpoint: String,
    pub headers: Vec<(String, String)>,
    /// The RFC 8291 ciphertext.
    pub body: Vec<u8>,
}

impl PushRequest {
    /// One header, matched case-insensitively as HTTP requires.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Build the encrypted, signed request for one subscription.
///
/// Split from sending so the whole construction — the payload, the TTL, the
/// VAPID subject — is testable without a push service to point at.
pub fn build_request(vapid: &Vapid, sub: &PushSubscription) -> Result<PushRequest, String> {
    let info =
        web_push::SubscriptionInfo::new(sub.endpoint.clone(), sub.p256dh.clone(), sub.auth.clone());

    let mut signature = web_push::VapidSignatureBuilder::from_base64(
        &vapid.private,
        web_push::URL_SAFE_NO_PAD,
        &info,
    )
    .map_err(|e| format!("vapid key: {e}"))?;
    // RFC 8292 §2.1: the JWT's `sub` names a contact for the sender, so a push
    // service with a problem has somebody to reach. Apple rejects a missing or
    // malformed one outright.
    if !vapid.subscriber.is_empty() {
        signature.add_claim("sub", format!("mailto:{}", vapid.subscriber));
    }
    let signature = signature.build().map_err(|e| format!("vapid: {e}"))?;

    let mut builder = web_push::WebPushMessageBuilder::new(&info);
    builder.set_payload(web_push::ContentEncoding::Aes128Gcm, PAYLOAD.as_bytes());
    builder.set_vapid_signature(signature);
    builder.set_ttl(TTL_SECS);
    let message = builder.build().map_err(|e| format!("encrypt: {e}"))?;

    // Assembled here rather than through the crate's `build_request`: that
    // returns an `http` 0.2 request and this workspace is on `http` 1, so
    // borrowing it would mean carrying two versions of the same crate. The
    // fields below are the whole of what it builds.
    let endpoint = message.endpoint.to_string();
    let mut headers = vec![("TTL".to_string(), message.ttl.to_string())];
    let payload = message.payload.ok_or("no payload was encrypted")?;
    headers.push((
        "Content-Encoding".into(),
        payload.content_encoding.to_str().to_string(),
    ));
    headers.push(("Content-Type".into(), "application/octet-stream".into()));
    for (name, value) in payload.crypto_headers {
        headers.push((name.to_string(), value));
    }
    // Content-Length is set by the HTTP client from the body; setting it here
    // as well makes reqwest send it twice.
    Ok(PushRequest {
        endpoint,
        headers,
        body: payload.content,
    })
}

/// Classify a push service's answer.
///
/// 404 and 410 are the service saying the subscription no longer exists. Every
/// other failure is transient as far as this relay can tell, and dropping a
/// subscription over one would silently stop notifying a working client.
pub fn classify(status: u16, body: &str) -> Delivery {
    match status {
        200..=299 => Delivery::Sent,
        404 | 410 => Delivery::Gone,
        other => Delivery::Failed(format!("{other}: {}", body.trim())),
    }
}

/// Notify every subscription an account has, pruning the dead ones.
pub async fn notify(state: &Arc<crate::server::RelayState>, account: &jmap_types::Id) {
    let vapid = state.vapid.clone();
    if vapid.public.is_empty() || vapid.private.is_empty() {
        // Not configured. Silent rather than logged per message: a relay
        // without push is a normal deployment, not a fault.
        return;
    }

    let subs = state.push.read().for_account(account);
    for sub in subs {
        let outcome = send_one(&vapid, &sub).await;
        match outcome {
            Delivery::Sent => {}
            Delivery::Gone => {
                // The browser revoked it and never told us. Pruning here is
                // the only way the registry stays finite.
                state.push.write().remove(account, &sub.endpoint);
            }
            Delivery::Failed(e) => {
                eprintln!("[push] {} failed: {e}", sub.endpoint);
            }
        }
    }
}

async fn send_one(vapid: &Vapid, sub: &PushSubscription) -> Delivery {
    let request = match build_request(vapid, sub) {
        Ok(v) => v,
        Err(e) => return Delivery::Failed(e),
    };

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build();
    let Ok(client) = client else {
        return Delivery::Failed("client".into());
    };
    let mut pending = client.post(&request.endpoint).body(request.body);
    for (name, value) in request.headers {
        pending = pending.header(name, value);
    }
    match pending.send().await {
        Err(e) => Delivery::Failed(e.to_string()),
        Ok(response) => {
            let status = response.status().as_u16();
            let body = response.text().await.unwrap_or_default();
            classify(status, &body)
        }
    }
}

#[cfg(test)]
mod tests;
