//! Turning a stored message into bytes on the wire, and handing them to SMTP.
//!
//! The order of the steps is the contract, not a preference — each one signs
//! or wraps what the previous produced, so swapping two silently invalidates
//! the result:
//!
//! 1. **Build** RFC 5322 from the JMAP object.
//! 2. **Autocrypt**: advertise the sender's key.
//! 3. **Chat-Version**, for clients that key off it.
//! 4. **PGP/MIME wrap**, if the body is already client-encrypted.
//! 5. **DKIM sign** — last, because it signs the finished message. Any header
//!    added after this invalidates the signature.
//! 6. **Send.**

use std::sync::Arc;

use jmap_types::email::Email;
use jmap_types::emailsubmission::Envelope;

use crate::handler::AccountStore;
use crate::server::RelayState;

/// Build, sign and deliver. Returns the Message-ID the message went out with.
/// What became of a submission.
///
/// "Sent" and "queued" are different things and the difference has to reach
/// the activity log and the metrics. Collapsing them into `Ok` would tell an
/// operator that nothing is failing while mail sits on disk waiting for a
/// receiver that may never take it — the same shape as a log that recorded
/// only failures and looked like a list of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Accepted by the far end. Carries the Message-ID it went out with, when
    /// one was generated here.
    Sent(Option<String>),
    /// Held for retry after a temporary failure.
    Queued,
}

impl Outcome {
    /// The word the activity log records.
    pub fn activity_result(&self) -> &'static str {
        match self {
            Outcome::Sent(_) => "ok",
            Outcome::Queued => "queued",
        }
    }
}

pub async fn send(
    state: &Arc<RelayState>,
    account: &Arc<AccountStore>,
    msg: &Email,
    envelope: &Envelope,
) -> Result<Outcome, String> {
    let from = envelope
        .mail_from
        .as_ref()
        .map(|a| a.email.clone())
        .unwrap_or_default();
    let to: Vec<String> = envelope.rcpt_to.iter().map(|r| r.email.clone()).collect();
    if to.is_empty() {
        return Err("no recipients".into());
    }

    let (mut raw, generated_id) = jmapserver::mime::build_rfc5322(
        msg,
        &state.cfg.hostname,
        ::time::OffsetDateTime::now_utc(),
        &random_hex(6),
    );

    // 2-3. Advertise the sender's key, and mark the message for chat clients.
    if let Some(key) = crate::pgp::load_account_key(&account.dir)
        && let Ok(serialized) = crate::pgp::serialize_public_key(&key)
    {
        use base64::Engine as _;
        raw = crate::autocrypt::inject_autocrypt(
            &raw,
            &from,
            &base64::engine::general_purpose::STANDARD.encode(serialized),
        );
    }
    raw = crate::autocrypt::inject_chat_version(&raw);

    // 4. A body the client already encrypted is wrapped as PGP/MIME so it
    //    travels as a structured message rather than text that happens to look
    //    like ciphertext. A body whose markers do not form a complete block is
    //    sent as-is — see `autocrypt`'s note on SPEC.md §11.11.
    if raw
        .windows(crate::hooks::PGP_MESSAGE_HEADER.len())
        .any(|w| w == crate::hooks::PGP_MESSAGE_HEADER.as_bytes())
        && let Some(wrapped) = crate::autocrypt::pgp_mime_wrap_inline(&raw)
    {
        raw = wrapped;
    }

    // 5. DKIM last: it signs the finished message, and a header added after
    //    this invalidates the signature.
    if let Some((_, domain)) = from.rsplit_once('@')
        && let Ok(key) = crate::dkim::load_or_generate_key(&state.data_dir.join(domain))
    {
        let selector = state
            .cfg
            .domains
            .get(domain)
            .map(|d| d.selector().to_string())
            .unwrap_or_else(|| crate::dkim::DEFAULT_SELECTOR.to_string());
        raw = crate::dkim::sign(&raw, &key, domain, &selector);
    }

    // Off unless asked for: this file holds plaintext mail. SPEC.md §11.1.
    if state.cfg.debug_dump_eml {
        let _ = crate::write_private(std::path::Path::new("/tmp/jmapsmtp-last-out.eml"), &raw);
    }

    let sender = crate::smtp_out::Sender {
        hostname: state.cfg.hostname.clone(),
        relay_host: Some(state.cfg.relay_host.clone()).filter(|h| !h.is_empty()),
        // Production trusts the system store and nothing besides.
        extra_roots: Vec::new(),
    };
    // A temporary failure is not the sender's problem to solve. It goes on
    // the queue and the submission succeeds, because the relay has taken
    // responsibility for the message — the SMTP meaning of a 4xx. Go reports
    // the error and drops the mail; SPEC.md §11.25.
    match sender.deliver(state.mx.as_ref(), &from, &to, &raw).await {
        Ok(()) => Ok(Outcome::Sent(Some(generated_id))),
        Err(e) => match crate::queue::policy::classify(&e) {
            crate::queue::policy::Temporality::Permanent => Err(e.to_string()),
            crate::queue::policy::Temporality::Temporary => {
                match crate::queue::enqueue(&state.data_dir, &from, &to, &raw, &e.to_string()) {
                    Ok(entry) => {
                        tracing::info!(
                            "[queue] {} deferred after {e}; retrying, {} attempts left",
                            entry.id,
                            crate::queue::policy::attempts_remaining(entry.attempts)
                        );
                        Ok(Outcome::Queued)
                    }
                    // The queue is the safety net; with nowhere to write it,
                    // the honest answer is the original failure rather than a
                    // success for a message nothing now holds.
                    Err(q) => {
                        tracing::error!("[queue] could not hold a deferred message: {q}");
                        Err(e.to_string())
                    }
                }
            }
        },
    }
}

pub(crate) fn random_hex(n: usize) -> String {
    use rand::TryRngCore as _;
    let mut b = vec![0u8; n];
    rand::rngs::OsRng
        .try_fill_bytes(&mut b)
        .expect("the OS random source failed");
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The fixed path `debug_dump_eml` writes to, and a lock over it.
///
/// The path is the Go implementation's and cannot be parameterised, so every
/// test that reads it shares one file. Exposed here rather than kept in one
/// test module because both `outbound` and `submit` observe the sent bytes
/// through it — two separate locks would not serialise against each other,
/// which is how this first failed.
#[cfg(test)]
pub(crate) mod dump {
    pub const PATH: &str = "/tmp/jmapsmtp-last-out.eml";
    /// An async mutex: the work between taking it and reading the file is a
    /// `send().await`, and a blocking guard held across an await is both a
    /// clippy error and a real way to stall the runtime.
    pub static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// Take the lock and clear the file.
    pub async fn guard() -> tokio::sync::MutexGuard<'static, ()> {
        let guard = LOCK.lock().await;
        let _ = std::fs::remove_file(PATH);
        guard
    }
}

#[cfg(test)]
mod tests;
