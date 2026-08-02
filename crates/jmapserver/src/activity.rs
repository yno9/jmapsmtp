//! The per-account activity log. Port of `go-jmapserver/activity.go`.
//!
//! # Metadata only, by construction
//!
//! An event records the peer, kind, size and result of a message — **never a
//! body, and never a subject**. That is what makes the log safe to expose over
//! the admin API at all: the operator can see that mail moved and whether it
//! worked, without being able to read it.
//!
//! [`ActivityEvent::note`] is the one free-text field and is documented as "a
//! short summary only". It is the field a future change would be tempted to put
//! a subject line in, which is why the type says so.
//!
//! # Append-only JSONL, with one generation of rotation
//!
//! `activity.log`, one line per event, newest last. Past 2 MiB it is renamed to
//! `activity.log.1` before the next append — a single generation, so the log is
//! bounded rather than archived. Appending is best-effort: a caller logs and
//! carries on rather than failing a message operation for the sake of an audit
//! line.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// One line of an account's activity log.
///
/// Field order matters: Go marshals in declaration order, and these lines are
/// compared byte for byte across implementations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActivityEvent {
    #[serde(rename = "t")]
    pub time: jmap_types::JmapTime,
    /// `"in"` or `"out"`.
    pub dir: String,
    /// `"email"`, `"note"`, `"follow"`, …
    pub kind: String,
    /// The remote handle or address.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub peer: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub msgid: String,
    /// Payload size.
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub bytes: i64,
    /// `"ok"`, `"failed"`, …
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub result: String,
    /// **A short summary only — never a message body or subject.** The log is
    /// exposed over the admin API, so anything put here becomes readable by the
    /// operator.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub note: String,
}

fn is_zero_i64(n: &i64) -> bool {
    *n == 0
}

impl Default for ActivityEvent {
    /// A fresh event stamped **now, in UTC** — the same thing
    /// `AppendActivity` does for a zero time. `JmapTime` has no meaningful
    /// zero: it holds the string as written, and an empty one would serialise
    /// as `"t":""`.
    fn default() -> Self {
        ActivityEvent {
            time: jmap_types::JmapTime::now_utc(),
            dir: String::new(),
            kind: String::new(),
            peer: String::new(),
            msgid: String::new(),
            bytes: 0,
            result: String::new(),
            note: String::new(),
        }
    }
}

pub const ACTIVITY_LOG_NAME: &str = "activity.log";

/// The size past which the log is rotated before the next append.
///
/// One generation only: `activity.log.1` is overwritten, so the log is
/// **bounded, not archived**. An operator who needs history beyond this has to
/// ship it elsewhere, and the bound is the point — an unbounded audit log on a
/// per-account file is a way to fill a disk from outside.
pub const ACTIVITY_ROTATE_BYTES: u64 = 2 << 20;

/// The default and maximum number of events a read returns.
pub const DEFAULT_LIMIT: usize = 100;

pub fn activity_log_path(data_dir: &Path, domain: &str, localpart: &str) -> PathBuf {
    data_dir
        .join(domain)
        .join(localpart)
        .join(ACTIVITY_LOG_NAME)
}

/// Append one event, rotating first if the log has outgrown its cap.
///
/// Best-effort by contract: the caller logs and continues on error. Failing a
/// delivery because an audit line could not be written would trade the thing
/// being audited for the record of it.
pub fn append_activity(
    data_dir: &Path,
    domain: &str,
    localpart: &str,
    event: &ActivityEvent,
) -> std::io::Result<()> {
    let path = activity_log_path(data_dir, domain, localpart);

    if let Ok(meta) = std::fs::metadata(&path)
        && meta.len() >= ACTIVITY_ROTATE_BYTES
    {
        // A failed rotation is not fatal: the log grows past the cap rather
        // than the event being lost.
        let _ = std::fs::rename(&path, path.with_extension("log.1"));
    }

    let mut line = jmap_types::go_json::to_vec(event)
        .map_err(|e| std::io::Error::other(format!("encoding activity: {e}")))?;
    line.push(b'\n');

    let mut opts = std::fs::OpenOptions::new();
    opts.append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    opts.open(&path)?.write_all(&line)
}

/// Up to `limit` of the most recent events, **newest first**.
///
/// A missing log is an empty list and no error — an account that has simply
/// never had activity is not a failure.
///
/// A line that will not parse is skipped rather than failing the read: the log
/// is append-only from more than one code path, and a torn write must not make
/// the rest unreadable.
pub fn read_activity(
    data_dir: &Path,
    domain: &str,
    localpart: &str,
    limit: usize,
) -> std::io::Result<Vec<ActivityEvent>> {
    let limit = if limit == 0 { DEFAULT_LIMIT } else { limit };
    let bytes = match std::fs::read(activity_log_path(data_dir, domain, localpart)) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };

    // Parse everything, then take the tail. The file is size-bounded by
    // rotation, so a full parse is cheap; scanning backwards would complicate
    // partial and blank lines for no gain at this scale.
    let all: Vec<ActivityEvent> = bytes
        .split(|b| *b == b'\n')
        .map(|line| line.strip_suffix(b"\r").unwrap_or(line))
        .filter(|line| !line.iter().all(u8::is_ascii_whitespace))
        .filter_map(|line| serde_json::from_slice(line).ok())
        .collect();

    Ok(all.into_iter().rev().take(limit).collect())
}

#[cfg(test)]
mod tests;
