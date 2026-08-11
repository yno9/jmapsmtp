//! Messages that could not be delivered yet.
//!
//! Neither implementation had one. `outbound::send` handed a failure straight
//! back to the JMAP client and the message was gone — no retry, no record, no
//! second chance. `smtp_out`'s own header said "the message fails and the
//! queue above retries", and there was no queue above.
//!
//! What that costs is not exotic. **Greylisting** — refusing an unknown
//! sender's first attempt with a 4xx and accepting a retry minutes later — is
//! ordinary practice at a large fraction of mail servers. Every greylisted
//! message this relay ever sent was lost, and the sender was told the address
//! did not work.
//!
//! # On disk, because that is the point
//!
//! An in-memory queue loses everything a restart touches, and a relay is
//! restarted to deploy, to change config, and when it crashes. Each queued
//! message is a directory under `data/_queue/`:
//!
//! ```text
//! data/_queue/<id>/message.eml   the bytes to send, exactly as built
//! data/_queue/<id>/meta.json     envelope, attempt count, when to try next
//! ```
//!
//! The message and its metadata are separate files so the metadata can be
//! rewritten after each attempt without touching the message.
//!
//! # What the sender is told
//!
//! A temporary failure is reported to the client as **success**, because that
//! is what it is: the relay has taken responsibility for the message. This
//! differs from Go, which reports the error and drops the mail — SPEC.md
//! §11.25. When the schedule runs out, the sender gets a delivery-failure
//! message in their own mailbox, because a message that vanishes after fifteen
//! hours of silence is the outcome this whole module exists to prevent.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub mod policy;

/// One message waiting to go out.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Entry {
    pub id: String,
    pub from: String,
    pub to: Vec<String>,
    /// Attempts already made, including the one that put it here.
    pub attempts: u32,
    /// Unix milliseconds. Nothing is tried before this.
    pub next_attempt: i64,
    /// Unix milliseconds, for the give-up message.
    pub first_queued: i64,
    /// What the far end said last, verbatim, for the failure report.
    pub last_error: String,
}

/// The queue directory under the data root.
pub fn dir(data_dir: &Path) -> PathBuf {
    data_dir.join("_queue")
}

fn now_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Take responsibility for a message that could not be sent yet.
///
/// The bytes are written before the metadata: a crash between the two leaves a
/// directory with no `meta.json`, which [`load_all`] skips, rather than an
/// entry pointing at a message that is not there.
pub fn enqueue(
    data_dir: &Path,
    from: &str,
    to: &[String],
    raw: &[u8],
    error: &str,
) -> std::io::Result<Entry> {
    let id = format!("{:x}-{}", now_millis(), crate::outbound::random_hex(8));
    let d = dir(data_dir).join(&id);
    std::fs::create_dir_all(&d)?;
    crate::write_private(&d.join("message.eml"), raw)?;

    let entry = Entry {
        id,
        from: from.to_string(),
        to: to.to_vec(),
        attempts: 1,
        next_attempt: now_millis()
            + policy::backoff(1)
                .map(|w| w.as_millis() as i64)
                .unwrap_or(0),
        first_queued: now_millis(),
        last_error: error.to_string(),
    };
    write_meta(&d, &entry)?;
    Ok(entry)
}

fn write_meta(d: &Path, entry: &Entry) -> std::io::Result<()> {
    // Written whole and renamed: a half-written meta.json is an entry that
    // cannot be parsed, and the message beside it would never be tried again.
    let tmp = d.join("meta.json.tmp");
    let json = serde_json::to_vec_pretty(entry).map_err(std::io::Error::other)?;
    crate::write_private(&tmp, &json)?;
    std::fs::rename(tmp, d.join("meta.json"))
}

/// Every entry currently queued, oldest first.
pub fn load_all(data_dir: &Path) -> Vec<Entry> {
    let mut out = Vec::new();
    let Ok(read) = std::fs::read_dir(dir(data_dir)) else {
        return out;
    };
    for e in read.flatten() {
        let meta = e.path().join("meta.json");
        let Ok(bytes) = std::fs::read(&meta) else {
            continue;
        };
        if let Ok(entry) = serde_json::from_slice::<Entry>(&bytes) {
            out.push(entry);
        }
    }
    out.sort_by_key(|e| e.first_queued);
    out
}

/// The bytes to send for an entry.
pub fn message(data_dir: &Path, id: &str) -> std::io::Result<Vec<u8>> {
    std::fs::read(dir(data_dir).join(id).join("message.eml"))
}

/// Record another failed attempt and schedule the next one.
///
/// `Ok(None)` means the schedule has run out and the entry has been removed —
/// the caller is responsible for telling the sender.
pub fn defer(data_dir: &Path, entry: &Entry, error: &str) -> std::io::Result<Option<Entry>> {
    let attempts = entry.attempts + 1;
    let Some(wait) = policy::backoff(attempts) else {
        remove(data_dir, &entry.id)?;
        return Ok(None);
    };
    let updated = Entry {
        attempts,
        next_attempt: now_millis() + wait.as_millis() as i64,
        last_error: error.to_string(),
        ..entry.clone()
    };
    write_meta(&dir(data_dir).join(&entry.id), &updated)?;
    Ok(Some(updated))
}

/// Delivered, or given up on.
pub fn remove(data_dir: &Path, id: &str) -> std::io::Result<()> {
    match std::fs::remove_dir_all(dir(data_dir).join(id)) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        other => other,
    }
}

/// Entries whose time has come.
pub fn due(data_dir: &Path, now: i64) -> Vec<Entry> {
    load_all(data_dir)
        .into_iter()
        .filter(|e| e.next_attempt <= now)
        .collect()
}

#[cfg(test)]
mod tests;

/// Retry what is due, for ever.
///
/// One pass a minute. The interval is the shortest step in the schedule, so
/// nothing waits appreciably longer than it was told to, and a pass over an
/// empty directory costs one `read_dir`.
///
/// Runs sequentially rather than fanning out: a queue draining after an
/// outage would otherwise open a connection per message to a server that has
/// just come back, which is how a retry storm looks from the other side.
pub async fn spawn_retries(state: std::sync::Arc<crate::server::RelayState>) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            tick.tick().await;
            let now = now_millis();
            for entry in due(&state.data_dir, now) {
                retry_one(&state, &entry).await;
            }
        }
    });
}

async fn retry_one(state: &std::sync::Arc<crate::server::RelayState>, entry: &Entry) {
    let Ok(raw) = message(&state.data_dir, &entry.id) else {
        // The bytes are gone but the metadata is not: nothing can be sent, and
        // leaving it would retry for ever.
        tracing::warn!("[queue] {} has no message; dropping", entry.id);
        let _ = remove(&state.data_dir, &entry.id);
        return;
    };
    let sender = crate::smtp_out::Sender {
        hostname: state.cfg.hostname.clone(),
        relay_host: Some(state.cfg.relay_host.clone()).filter(|h| !h.is_empty()),
        extra_roots: Vec::new(),
    };
    match sender
        .deliver(state.mx.as_ref(), &entry.from, &entry.to, &raw)
        .await
    {
        Ok(()) => {
            tracing::info!(
                "[queue] {} delivered on attempt {}",
                entry.id,
                entry.attempts + 1
            );
            // The outcome is known now, so this is where it is counted —
            // submission counted nothing, because at that point there was
            // nothing to count.
            state.record_smtp_outbound(true);
            let _ = remove(&state.data_dir, &entry.id);
        }
        Err(e) => {
            let permanent = policy::classify(&e) == policy::Temporality::Permanent;
            if permanent {
                tracing::warn!("[queue] {} refused for good: {e}", entry.id);
                state.record_smtp_outbound(false);
                let _ = remove(&state.data_dir, &entry.id);
                report_failure(state, entry, &e.to_string()).await;
                return;
            }
            match defer(&state.data_dir, entry, &e.to_string()) {
                Ok(Some(next)) => tracing::info!(
                    "[queue] {} deferred again after {e}; {} attempts left",
                    entry.id,
                    policy::attempts_remaining(next.attempts)
                ),
                Ok(None) => {
                    tracing::warn!("[queue] {} gave up after {e}", entry.id);
                    state.record_smtp_outbound(false);
                    report_failure(state, entry, &e.to_string()).await;
                }
                Err(io) => tracing::error!("[queue] {} could not be updated: {io}", entry.id),
            }
        }
    }
}

/// Put a delivery-failure notice in the sender's own mailbox.
///
/// Without this the queue only moves the silence later: the message stops
/// being retried and nobody is told. A notice in the mailbox the sender is
/// already looking at is the one place they will see it — the relay cannot
/// bounce to an external `MAIL FROM` it does not control, and the sender here
/// is always one of its own accounts.
async fn report_failure(
    state: &std::sync::Arc<crate::server::RelayState>,
    entry: &Entry,
    error: &str,
) {
    let Some(account) = state.accounts.resolve(&entry.from) else {
        tracing::warn!(
            "[queue] {} failed for {} and there is no local mailbox to tell",
            entry.id,
            entry.from
        );
        return;
    };
    let held = std::time::Duration::from_millis((now_millis() - entry.first_queued).max(0) as u64);
    let body = format!(
        "Delivery to the following recipients failed permanently:\r\n\
         \r\n\
         \t{}\r\n\
         \r\n\
         The relay held this message for {} and made {} attempts.\r\n\
         The last response from the receiving server was:\r\n\
         \r\n\
         \t{}\r\n",
        entry.to.join("\r\n\t"),
        human_duration(held),
        entry.attempts,
        error,
    );
    let notice = format!(
        "From: Mail Delivery System <postmaster@{}>\r\n\
         To: {}\r\n\
         Subject: Undelivered mail: {}\r\n\
         Date: {}\r\n\
         Message-ID: <queue-{}@{}>\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         \r\n\
         {}",
        state.cfg.hostname,
        entry.from,
        entry.to.join(", "),
        jmapserver::format_rfc1123z(::time::OffsetDateTime::now_utc()),
        entry.id,
        state.cfg.hostname,
        body,
    );

    let delivery = crate::delivery::Delivery {
        state: state.clone(),
    };
    delivery.deliver_local(&account, "postmaster", notice.as_bytes());
    state.hub.notify();
}

/// "3 h 20 min", for a sentence a person reads once.
fn human_duration(d: std::time::Duration) -> String {
    let mins = d.as_secs() / 60;
    if mins < 60 {
        return format!("{mins} min");
    }
    let (h, m) = (mins / 60, mins % 60);
    if m == 0 {
        format!("{h} h")
    } else {
        format!("{h} h {m} min")
    }
}
