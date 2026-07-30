//! The two store hooks: what happens when a client creates a draft, and what
//! happens when it submits one. Port of the `OnCreateEmail` / `OnSubmitEmail`
//! closures in `go-jmapsmtp/main.go:makeStore`.
//!
//! Everything the relay does that a plain JMAP server would not happens here,
//! which makes this the highest-consequence code in the port: it is where the
//! stored copy of a sent message gets encrypted, and where outbound policy is
//! enforced. Both are decision functions with the I/O lifted out, so a test
//! can reach every branch.

use jmap_types::email::{BodyValue, Email};
use jmap_types::emailsubmission::Envelope;

use crate::config::Config;

/// The marker that says a body is already end-to-end encrypted.
pub const PGP_MESSAGE_HEADER: &str = "-----BEGIN PGP MESSAGE-----";

/// The keyword set on a message whose body the client encrypted itself.
pub const KEYWORD_E2E: &str = "$e2e";
/// Cleared on submission: a submitted message is not a draft any more.
pub const KEYWORD_DRAFT: &str = "$draft";

/// Whether the account is under its storage cap.
///
/// Checked on **both** paths — a received message and a sent one — because
/// either can be what fills the disk. `0` means unlimited.
pub fn within_storage_cap(cfg: &Config, acct_dir: &std::path::Path) -> Result<(), String> {
    let cap = cfg.max_account_storage_mb;
    if cap == 0 {
        return Ok(());
    }
    let used = crate::handler::dir_size_mb(acct_dir);
    if used >= cap {
        return Err(format!("storage limit reached ({cap}MB)"));
    }
    Ok(())
}

/// What a newly created draft needs filled in that the client did not supply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DraftDefaults {
    /// Minted when the client sent no id.
    pub id: Option<jmap_types::Id>,
    /// Minted when the client sent no `messageId`, or an empty first entry.
    pub rfc_message_id: Option<String>,
}

/// Decide what to fill in on `Email/set create`.
///
/// The RFC Message-ID is assigned **here, at creation**, not at send. That is
/// what lets a client quote it as `In-Reply-To` on the next message
/// immediately: the reply chain is built locally and stays correct even if the
/// send later fails.
pub fn draft_defaults(msg: &Email, domain: &str) -> DraftDefaults {
    DraftDefaults {
        id: msg.id.is_empty().then(crate::handler::new_id),
        // An empty *first* entry counts as absent, not just an empty list — a
        // client that sends `"messageId": [""]` gets a real one rather than a
        // message with a blank Message-ID on the wire.
        rfc_message_id: msg
            .message_id
            .first()
            .is_none_or(|s| s.is_empty())
            .then(|| crate::handler::new_rfc_message_id(domain)),
    }
}

/// Apply [`draft_defaults`], plus the custom headers and the receive time.
///
/// `received_at` is passed in rather than read from the clock so a test can
/// pin it; the caller uses now-in-UTC.
pub fn prepare_draft(
    msg: &mut Email,
    create: &serde_json::Value,
    domain: &str,
    received_at: jmap_types::JmapTime,
) {
    for (name, value) in crate::handler::extract_text_headers(create) {
        msg.headers.push(jmap_types::email::Header { name, value });
    }
    let defaults = draft_defaults(msg, domain);
    if let Some(id) = defaults.id {
        msg.id = id;
    }
    if let Some(mid) = defaults.rfc_message_id {
        msg.message_id = vec![mid];
    }
    msg.received_at = Some(received_at);
}

/// Whether an outbound message is allowed by `reply_only_outbound`.
///
/// The rule: this account may only write to someone who has written to it.
/// It exists so an address handed out publicly cannot be used to send cold
/// mail, which is what makes a throwaway relay address safe to publish.
///
/// `known` comes from every stored message's `From`, rebuilt per submission
/// rather than cached — an incoming message has to count immediately, or the
/// relay refuses a reply to a message the user is looking at.
pub fn reply_only_allows(
    cfg: &Config,
    sender: &str,
    envelope: &Envelope,
    known: &std::collections::BTreeSet<String>,
) -> Result<(), String> {
    if !cfg.reply_only_outbound || cfg.reply_only_exempt(sender) {
        return Ok(());
    }
    for rcpt in &envelope.rcpt_to {
        if !known.contains(&rcpt.email.to_lowercase()) {
            return Err(format!(
                "reply_only_outbound: {} has not sent you a message",
                rcpt.email
            ));
        }
    }
    Ok(())
}

/// What to do with the copy of a sent message that stays on the relay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoredBody {
    /// The client encrypted it. Mark it and store as-is — re-encrypting
    /// someone else's ciphertext to a different key would only make it
    /// unreadable to them.
    AlreadyEncrypted,
    /// Encrypt to the account's own public key, so the relay keeps a copy it
    /// cannot itself read.
    EncryptToAccountKey,
    /// No account key on file: store the plaintext.
    ///
    /// This is the case worth understanding. The relay has to keep *something*
    /// or the user loses their sent mail, and it has no key to seal it with.
    /// Uploading a public key is what turns this off.
    Plaintext,
}

/// Decide how the stored copy is treated.
pub fn stored_body(body: &str, has_account_key: bool) -> StoredBody {
    if body.contains(PGP_MESSAGE_HEADER) {
        return StoredBody::AlreadyEncrypted;
    }
    if has_account_key {
        StoredBody::EncryptToAccountKey
    } else {
        StoredBody::Plaintext
    }
}

/// Replace every text part's body value with `ciphertext`, and drop the HTML
/// alternative entirely.
///
/// The body values are cloned before mutating so the copy handed to SMTP keeps
/// its plaintext — the recipient gets the real message; only the stored copy is
/// sealed.
///
/// # This drops more than the Go original does, on purpose
///
/// Go sets `msg.HTMLBody = nil`, which removes the *references* to the HTML
/// parts but leaves their entries in `BodyValues`. So the stored copy of a
/// sealed message still contains the plaintext, verbatim, under a part id
/// nothing points at — and any rich-text client sends an HTML alternative.
/// Observed on the oracle: `bodyValues["2"].value` was
/// `"<p>the secret plaintext</p>"` beside the encrypted text part.
///
/// That defeats the point of sealing, which is that the relay cannot read its
/// users' sent mail. This port removes the values along with the references —
/// completing what the Go code started rather than changing its intent, since
/// nothing can reach an unreferenced part anyway. SPEC.md §11.14.
///
/// **Not fixed here:** attachment body values are still stored as they arrive.
/// That is a larger question than this function — an attachment is not an
/// alternative rendering of the sealed text, and deciding what happens to it
/// changes what a client can still open. Recorded in SPEC.md §11.14 rather
/// than quietly widened.
pub fn seal_stored_body(msg: &mut Email, ciphertext: &str) {
    let mut sealed = msg.body_values.clone();
    for part in &msg.html_body {
        sealed.remove(&part.part_id);
    }
    for part in &msg.text_body {
        sealed.insert(
            part.part_id.clone(),
            BodyValue {
                value: ciphertext.to_string(),
                ..Default::default()
            },
        );
    }
    msg.body_values = sealed;
    msg.html_body.clear();
}

/// The envelope to send with, falling back to one derived from the headers.
///
/// A submission with no recipients is refused rather than silently dropped: a
/// message the client believes it sent, that nothing was ever attempted for,
/// is the worst of the available outcomes.
pub fn resolve_envelope(msg: &Email, supplied: &Envelope) -> Result<Envelope, String> {
    if supplied.mail_from.is_some() {
        return Ok(supplied.clone());
    }
    jmapserver::build_envelope(msg).ok_or_else(|| "no recipients".to_string())
}

/// The comma-joined recipient list recorded in the activity log.
pub fn activity_peer(envelope: &Envelope) -> String {
    envelope
        .rcpt_to
        .iter()
        .map(|r| r.email.as_str())
        .collect::<Vec<_>>()
        .join(",")
}

/// The Message-ID to store after a successful send, with the angle brackets
/// stripped.
///
/// The SMTP layer reports the id the message actually went out with, which can
/// differ from the one minted at creation. Storing the real one keeps the
/// client's threading aligned with what the recipient sees.
pub fn sent_message_id(reported: &str) -> Option<String> {
    let trimmed = reported.trim_matches(|c| c == '<' || c == '>');
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

#[cfg(test)]
mod tests;
