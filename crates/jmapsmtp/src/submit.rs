//! Outbound submission: the `Email/set create` and `EmailSubmission/set create`
//! hooks, wired to the SMTP client.
//!
//! This is where a stored message becomes a sent one, and it is the highest-
//! consequence path in the relay — [`crate::hooks`] holds the decisions and
//! this holds the assembly.
//!
//! # The stored copy and the sent copy are different objects
//!
//! The recipient gets the plaintext; what stays on the relay is sealed to the
//! account's own key where there is one. Sending the sealed copy would deliver
//! ciphertext to someone with no key for it, and storing the plaintext would
//! defeat the sealing — so the two are built from one message and diverge
//! before either leaves.
//!
//! # Sending happens after the store write, off the request
//!
//! A submission returns as soon as the message is stored. Delivery can take
//! seconds against a slow MX, and a client blocked on it cannot show the
//! message it already has. The consequence is that a send failure surfaces in
//! the activity log rather than in the response, which is the Go behaviour and
//! the reason the log exists.

use std::sync::Arc;

use jmap_types::email::Email;
use jmap_types::emailsubmission::Envelope;

use crate::handler::AccountStore;
use crate::server::RelayState;

/// Install the create and submit hooks on one account's store.
pub fn install_hooks(state: &Arc<RelayState>, account: &Arc<AccountStore>) {
    let create_state = state.clone();
    let create_account = account.clone();
    let submit_state = state.clone();
    let submit_account = account.clone();

    account.store.set_hooks(jmapserver::store::Hooks {
        create_email: Some(Arc::new(move |raw| {
            on_create_email(&create_state, &create_account, raw)
        })),
        submit_email: Some(Arc::new(move |msg, envelope| {
            on_submit_email(&submit_state, &submit_account, msg, envelope)
        })),
        ..Default::default()
    });
}

/// `Email/set create` — a draft.
///
/// The draft is held **in memory only** (`put_pending`), so an unsubmitted one
/// does not survive a restart. That is what lets the Message-ID be minted here
/// rather than at send: the draft is the client's state, and the relay holds it
/// only between create and submit.
fn on_create_email(
    state: &Arc<RelayState>,
    account: &Arc<AccountStore>,
    raw: &serde_json::value::RawValue,
) -> Result<Email, String> {
    crate::hooks::within_storage_cap(&state.cfg, &account.dir)?;

    let create: serde_json::Value = serde_json::from_str(raw.get()).map_err(|e| e.to_string())?;
    let mut msg: Email = serde_json::from_str(raw.get()).map_err(|e| e.to_string())?;

    crate::hooks::prepare_draft(
        &mut msg,
        &create,
        &account.domain,
        jmap_types::JmapTime::now_utc(),
    );
    account.store.put_pending(msg.clone());
    Ok(msg)
}

/// `EmailSubmission/set create` — send it.
fn on_submit_email(
    state: &Arc<RelayState>,
    account: &Arc<AccountStore>,
    msg: Email,
    envelope: Envelope,
) -> Result<(), String> {
    crate::hooks::within_storage_cap(&state.cfg, &account.dir)?;
    let envelope = crate::hooks::resolve_envelope(&msg, &envelope)?;

    if state.cfg.reply_only_outbound {
        let known = crate::handler::known_correspondents(&account.store.all());
        crate::hooks::reply_only_allows(&state.cfg, &account.email, &envelope, &known)?;
    }

    // The copy that goes out keeps its plaintext; only what stays here is
    // sealed. Cloned before either is touched.
    let outbound = msg.clone();
    let mut stored = msg;
    stored.keywords.remove(crate::hooks::KEYWORD_DRAFT);

    let body = jmapserver::message_body(&stored);
    if !body.is_empty() {
        let account_key = crate::pgp::load_account_key(&account.dir);
        match crate::hooks::stored_body(&body, account_key.is_some()) {
            crate::hooks::StoredBody::AlreadyEncrypted => {
                stored
                    .keywords
                    .insert(crate::hooks::KEYWORD_E2E.to_string(), true);
            }
            crate::hooks::StoredBody::EncryptToAccountKey => {
                if let Some(key) = &account_key
                    && let Ok(sealed) =
                        crate::pgp::encrypt_inline(body.as_bytes(), std::slice::from_ref(key))
                {
                    crate::hooks::seal_stored_body(&mut stored, &String::from_utf8_lossy(&sealed));
                }
                // A failure to encrypt leaves the plaintext stored rather than
                // failing the send. The message is already going out; refusing
                // now would lose it to protect a copy the user can delete.
            }
            crate::hooks::StoredBody::Plaintext => {}
        }
    }

    account
        .store
        .put(stored.clone())
        .map_err(|e| e.to_string())?;
    state.hub.notify();

    spawn_send(
        state.clone(),
        account.clone(),
        outbound,
        stored,
        envelope,
        body,
    );
    Ok(())
}

/// Hand the message to SMTP, then record what happened.
fn spawn_send(
    state: Arc<RelayState>,
    account: Arc<AccountStore>,
    outbound: Email,
    stored: Email,
    envelope: Envelope,
    body: String,
) {
    tokio::spawn(async move {
        let peer = crate::hooks::activity_peer(&envelope);
        let result = crate::outbound::send(&state, &account, &outbound, &envelope).await;

        let _ = jmapserver::activity::append_activity(
            &state.data_dir,
            &account.domain,
            &account.localpart,
            &jmapserver::activity::ActivityEvent {
                dir: "out".into(),
                kind: "email".into(),
                peer,
                bytes: body.len() as i64,
                result: crate::handler::activity_result(result.is_ok()).into(),
                ..Default::default()
            },
        );

        match result {
            Err(e) => {
                state.record_smtp_outbound(false);
                eprintln!("[smtp] send failed: {e}");
            }
            Ok(sent_message_id) => {
                state.record_smtp_outbound(true);
                // The id the message actually went out with can differ from
                // the one minted at creation. Storing the real one keeps the
                // client's threading aligned with what the recipient sees.
                if let Some(id) = sent_message_id
                    .as_deref()
                    .and_then(crate::hooks::sent_message_id)
                {
                    let mut updated = stored;
                    updated.message_id = vec![id];
                    let _ = account.store.put(updated);
                    state.hub.notify();
                }
            }
        }
    });
}

#[cfg(test)]
mod tests;
