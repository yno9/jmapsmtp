//! Disk-backed, in-memory-cached JMAP mail object store.
//!
//! Port of `go-jmapserver/store.go`.
//!
//! Disk layout:
//!
//! ```text
//! <dir>/messages/<id>.json   one file per Email object
//! <dir>/mailboxes.json       Mailbox list
//! <dir>/identities.json      Identity list
//! <dir>/delta.json           state counters + change history
//! ```
//!
//! Pending messages — drafts created by `Email/set` and awaiting
//! `EmailSubmission/set` — are held in memory only and vanish on restart.
//!
//! `state` is a monotonic counter persisted to `delta.json`, so
//! `Email/queryChanges` survives a restart. A missing or corrupt `delta.json`
//! resets it to 0, and clients get `cannotCalculateChanges` on their next
//! call and fall back to a full `Email/query`.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use jmap_types::email::Email;
use jmap_types::mailbox::Mailbox;
use jmap_types::{Id, JmapTime, go_json};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Records message ids added, updated or removed at a single state version.
///
/// The Go struct carries no JSON tags, so the keys are capitalised, and its
/// nil slices marshal as `null` rather than `[]`. Both are reproduced here —
/// verified against the Go implementation's output — because `delta.json` is
/// compared byte for byte with files it wrote.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangeRecord {
    #[serde(rename = "Added", with = "null_if_empty")]
    pub added: Vec<Id>,
    #[serde(rename = "Updated", with = "null_if_empty")]
    pub updated: Vec<Id>,
    #[serde(rename = "Removed", with = "null_if_empty")]
    pub removed: Vec<Id>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MailboxChangeRecord {
    #[serde(rename = "Created", with = "null_if_empty")]
    pub created: Vec<Id>,
    #[serde(rename = "Updated", with = "null_if_empty")]
    pub updated: Vec<Id>,
    #[serde(rename = "Destroyed", with = "null_if_empty")]
    pub destroyed: Vec<Id>,
}

/// A JSON object with sorted keys, as Go's `map[string]any` marshals.
pub type JsonObject = BTreeMap<String, Value>;

/// The contents of `delta.json`.
///
/// No field carries `omitempty`, so all six are always written — a nil map or
/// slice as `null`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct PersistedState {
    state: i64,
    changes: BTreeMap<String, ChangeRecord>,
    #[serde(rename = "mailboxState")]
    mailbox_state: i64,
    #[serde(rename = "mailboxChanges")]
    mailbox_changes: BTreeMap<String, MailboxChangeRecord>,
    /// `null` until the first submission is recorded, matching Go's nil slice.
    #[serde(with = "null_if_empty")]
    submissions: Vec<JsonObject>,
    #[serde(rename = "submissionState")]
    submission_state: i64,
}

#[derive(Default)]
struct Inner {
    /// Persisted messages, keyed by id.
    ///
    /// A `BTreeMap` where Go uses a `map`. Go's iteration order is randomised,
    /// which leaks into two places: the order of ids in a `Purge` change
    /// record, and which entry wins when two stored messages share a
    /// Message-ID during thread resolution. Sorted order makes both
    /// reproducible. Neither is a behavioural change — a change record is a
    /// set, and a duplicate Message-ID has no defined winner — but it does
    /// mean two runs now agree with each other (SPEC.md §11.5).
    msgs: BTreeMap<Id, Email>,
    /// In-memory only; never written to disk.
    pending: BTreeMap<Id, Email>,
    state: i64,
    changes: BTreeMap<i64, ChangeRecord>,
    identities: Vec<JsonObject>,
    mailbox_state: i64,
    mailbox_changes: BTreeMap<i64, MailboxChangeRecord>,
    /// Content-addressed, in-memory only — blobs do not survive a restart in
    /// the Go implementation either.
    blobs: BTreeMap<String, Vec<u8>>,
    submissions: Vec<JsonObject>,
    submission_state: i64,
    /// In-memory VacationResponse.
    vacation: Option<JsonObject>,
}

pub struct Store {
    dir: PathBuf,
    state_file: PathBuf,
    inner: RwLock<Inner>,
}

impl Store {
    /// Open (or create) a store rooted at `dir`.
    ///
    /// Every `*.json` under `messages/` is read; a file that fails to parse,
    /// or parses without an id, is skipped rather than failing the open. One
    /// corrupt message must not take an account offline.
    pub fn open(dir: impl AsRef<Path>) -> io::Result<Store> {
        let dir = dir.as_ref().to_path_buf();
        fs::create_dir_all(dir.join("messages"))?;

        let mut inner = Inner::default();
        if let Ok(entries) = fs::read_dir(dir.join("messages")) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().is_none_or(|e| e != "json") {
                    continue;
                }
                let Ok(bytes) = fs::read(&path) else { continue };
                if let Ok(msg) = serde_json::from_slice::<Email>(&bytes)
                    && !msg.id.is_empty()
                {
                    inner.msgs.insert(msg.id.clone(), msg);
                }
            }
        }

        let store = Store {
            state_file: dir.join("delta.json"),
            dir,
            inner: RwLock::new(inner),
        };
        store.load_state();
        store.load_identities();
        Ok(store)
    }

    // ── state persistence ─────────────────────────────────────────────────

    fn load_state(&self) {
        let Ok(bytes) = fs::read(&self.state_file) else {
            return;
        };
        let Ok(ps) = serde_json::from_slice::<PersistedState>(&bytes) else {
            // A corrupt delta.json resets state to 0 rather than refusing to
            // start; clients recover with a full re-query.
            return;
        };
        let mut inner = self.inner.write();
        inner.state = ps.state;
        for (k, v) in ps.changes {
            if let Ok(n) = k.parse::<i64>() {
                inner.changes.insert(n, v);
            }
        }
        inner.mailbox_state = ps.mailbox_state;
        inner.submission_state = ps.submission_state;
        if !ps.submissions.is_empty() {
            inner.submissions = ps.submissions;
        }
        for (k, v) in ps.mailbox_changes {
            if let Ok(n) = k.parse::<i64>() {
                inner.mailbox_changes.insert(n, v);
            }
        }
    }

    /// Write `delta.json`. Caller holds the write lock.
    ///
    /// A failure is swallowed, as in Go: losing the change log costs clients
    /// an extra full re-query, which is not worth failing the operation that
    /// triggered it.
    fn save_state_locked(&self, inner: &Inner) {
        let ps = PersistedState {
            state: inner.state,
            changes: inner
                .changes
                .iter()
                .map(|(k, v)| (k.to_string(), v.clone()))
                .collect(),
            mailbox_state: inner.mailbox_state,
            mailbox_changes: inner
                .mailbox_changes
                .iter()
                .map(|(k, v)| (k.to_string(), v.clone()))
                .collect(),
            submissions: inner.submissions.clone(),
            submission_state: inner.submission_state,
        };
        if let Ok(bytes) = go_json::to_vec(&ps) {
            let _ = write_file(&self.state_file, &bytes);
        }
    }

    // ── messages ──────────────────────────────────────────────────────────

    /// The current query state, as the string clients see.
    pub fn state(&self) -> String {
        self.inner.read().state.to_string()
    }

    /// Insert or update an Email, on disk and in memory.
    ///
    /// Only a genuinely new message advances the state counter; rewriting an
    /// existing one does not. A message with no thread id gets one resolved
    /// from its reply chain.
    pub fn put(&self, mut msg: Email) -> io::Result<()> {
        if msg.thread_id.is_empty() {
            msg.thread_id = self.resolve_thread_id(&msg);
        }
        let bytes = go_json::to_vec(&msg)?;
        write_file(&self.msg_path(&msg.id), &bytes)?;

        let mut inner = self.inner.write();
        let existed = inner.msgs.insert(msg.id.clone(), msg.clone()).is_some();
        if !existed {
            inner.state += 1;
            let state = inner.state;
            inner.changes.insert(
                state,
                ChangeRecord {
                    added: vec![msg.id],
                    ..Default::default()
                },
            );
            self.save_state_locked(&inner);
        }
        Ok(())
    }

    /// Find the thread a message belongs to.
    ///
    /// A DeltaChat group is a flat chat with no threading concept — there is
    /// no reply-to-a-specific-message UI, just one stream — so a group
    /// message's thread is its group id, full stop, skipping the
    /// In-Reply-To/References walk entirely.
    ///
    /// That shortcut is not merely an optimisation. DeltaChat splits one
    /// logical text+image message into two MIME messages that both reference
    /// a common parent; when that parent is not in the store (it predates the
    /// account joining, or never reached this relay), each half independently
    /// falls through to "no parent found" and mints its own thread id from
    /// its own Message-ID, splitting one message across two threads. Reported
    /// live on 2026-07-14.
    fn resolve_thread_id(&self, msg: &Email) -> Id {
        for h in &msg.headers {
            if h.name.eq_ignore_ascii_case("Chat-Group-Id") && !h.value.is_empty() {
                return Id(format!("thr-group-{}", h.value));
            }
        }

        let inner = self.inner.read();
        // Message-ID → thread id, with angle brackets stripped so `<a@b>` and
        // `a@b` match.
        let mut by_msg_id: BTreeMap<&str, &Id> = BTreeMap::new();
        for stored in inner.msgs.values() {
            for mid in &stored.message_id {
                let k = mid.trim_matches(['<', '>']);
                if !k.is_empty() {
                    by_msg_id.insert(k, &stored.thread_id);
                }
            }
        }
        for reference in msg.in_reply_to.iter().chain(msg.references.iter()) {
            if let Some(tid) = by_msg_id.get(reference.trim_matches(['<', '>']))
                && !tid.is_empty()
            {
                return (*tid).clone();
            }
        }

        // No parent found — start a new thread.
        match msg.message_id.first() {
            Some(mid) if !mid.is_empty() => Id(format!("thr-{mid}")),
            _ => Id(format!("thr-{}", msg.id)),
        }
    }

    /// Look up an Email, persisted or pending.
    pub fn get(&self, id: &Id) -> Option<Email> {
        let inner = self.inner.read();
        inner
            .msgs
            .get(id)
            .or_else(|| inner.pending.get(id))
            .cloned()
    }

    /// Remove a persisted Email.
    ///
    /// The file is removed whether or not the message was in the index, and a
    /// missing message is not an error.
    pub fn delete(&self, id: &Id) {
        {
            let mut inner = self.inner.write();
            if inner.msgs.remove(id).is_some() {
                inner.state += 1;
                let state = inner.state;
                inner.changes.insert(
                    state,
                    ChangeRecord {
                        removed: vec![id.clone()],
                        ..Default::default()
                    },
                );
                self.save_state_locked(&inner);
            }
        }
        let _ = fs::remove_file(self.msg_path(id));
    }

    /// Remove every persisted Email, returning how many there were.
    ///
    /// For admin resets and the "how your data is stored" purge; biset then
    /// re-fetches from relays. The state counter is bumped once so clients on
    /// the event source re-sync.
    pub fn purge(&self) -> usize {
        let removed: Vec<Id> = {
            let mut inner = self.inner.write();
            let removed: Vec<Id> = inner.msgs.keys().cloned().collect();
            inner.msgs.clear();
            if !removed.is_empty() {
                inner.state += 1;
                let state = inner.state;
                inner.changes.insert(
                    state,
                    ChangeRecord {
                        removed: removed.clone(),
                        ..Default::default()
                    },
                );
                self.save_state_locked(&inner);
            }
            removed
        };

        if let Ok(entries) = fs::read_dir(self.dir.join("messages")) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().is_some_and(|e| e == "json") {
                    let _ = fs::remove_file(path);
                }
            }
        }
        removed.len()
    }

    /// Every persisted Email, newest first by `receivedAt`.
    ///
    /// A message with no timestamp sorts as the zero time, matching Go's
    /// `timeVal` over a nil `*time.Time`.
    pub fn all(&self) -> Vec<Email> {
        let mut all: Vec<Email> = self.inner.read().msgs.values().cloned().collect();
        // Descending: newest first. Sorting by the negated key keeps this a
        // sort_by_key rather than a comparator clippy objects to.
        all.sort_by_key(|m| std::cmp::Reverse(sort_key(m)));
        all
    }

    /// Apply a `keywords/*` patch and persist it.
    ///
    /// An unknown id is a no-op, not an error — the Go original returns nil
    /// for a message it does not have.
    pub fn patch_keywords(&self, id: &Id, patch: &JsonObject) -> io::Result<()> {
        self.patch(id, patch, false)
    }

    /// Apply a patch covering both `keywords/*` and `mailboxIds/*`.
    pub fn patch_email(&self, id: &Id, patch: &JsonObject) -> io::Result<()> {
        self.patch(id, patch, true)
    }

    fn patch(&self, id: &Id, patch: &JsonObject, mailboxes_too: bool) -> io::Result<()> {
        let updated = {
            let mut inner = self.inner.write();
            let Some(msg) = inner.msgs.get(id).cloned() else {
                return Ok(());
            };
            let mut cp = msg;
            for (k, v) in patch {
                if let Some(kw) = k.strip_prefix("keywords/") {
                    match v {
                        Value::Bool(b) => {
                            cp.keywords.insert(kw.to_string(), *b);
                        }
                        // Only patch_email honours a null as a removal; the
                        // keywords-only path in Go ignores it.
                        Value::Null if mailboxes_too => {
                            cp.keywords.remove(kw);
                        }
                        _ => {}
                    }
                } else if mailboxes_too && let Some(mb) = k.strip_prefix("mailboxIds/") {
                    match v {
                        Value::Bool(b) => {
                            cp.mailbox_ids.insert(Id::from(mb), *b);
                        }
                        Value::Null => {
                            cp.mailbox_ids.remove(&Id::from(mb));
                        }
                        _ => {}
                    }
                }
            }
            inner.msgs.insert(id.clone(), cp.clone());
            inner.state += 1;
            let state = inner.state;
            inner.changes.insert(
                state,
                ChangeRecord {
                    updated: vec![id.clone()],
                    ..Default::default()
                },
            );
            self.save_state_locked(&inner);
            cp
        };

        let bytes = go_json::to_vec(&updated)?;
        write_file(&self.msg_path(id), &bytes)
    }

    // ── pending ───────────────────────────────────────────────────────────

    /// Hold a draft in memory. Never written to disk.
    pub fn put_pending(&self, msg: Email) {
        self.inner.write().pending.insert(msg.id.clone(), msg);
    }

    /// Remove and return a pending draft, called when it is submitted.
    pub fn take_pending(&self, id: &Id) -> Option<Email> {
        self.inner.write().pending.remove(id)
    }

    // ── mailboxes ─────────────────────────────────────────────────────────

    /// Overwrite the stored Mailbox list.
    ///
    /// Does **not** bump the mailbox state, so clients will not see the change
    /// through `Mailbox/changes`. Prefer [`Store::sync_mailboxes`] for
    /// relay-driven updates.
    pub fn put_mailboxes(&self, mbs: &[Mailbox]) -> io::Result<()> {
        let bytes = go_json::to_vec(mbs)?;
        write_file(&self.dir.join("mailboxes.json"), &bytes)
    }

    /// Reconcile the stored Mailbox list against the authoritative view.
    ///
    /// Idempotent: when the id sets already match, nothing is written and no
    /// state is bumped.
    pub fn sync_mailboxes(&self, mbs: &[Mailbox]) -> io::Result<()> {
        let existing: BTreeSet<Id> = self.mailboxes().into_iter().map(|mb| mb.id).collect();
        let incoming: BTreeSet<Id> = mbs.iter().map(|mb| mb.id.clone()).collect();

        let created: Vec<Id> = incoming.difference(&existing).cloned().collect();
        let destroyed: Vec<Id> = existing.difference(&incoming).cloned().collect();
        if created.is_empty() && destroyed.is_empty() {
            return Ok(());
        }

        self.put_mailboxes(mbs)?;
        self.bump_mailbox_state(MailboxChangeRecord {
            created,
            destroyed,
            ..Default::default()
        });
        Ok(())
    }

    /// The stored Mailbox list. An unreadable or unparseable file yields an
    /// empty list rather than an error, as in Go.
    pub fn mailboxes(&self) -> Vec<Mailbox> {
        fs::read(self.dir.join("mailboxes.json"))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    pub fn mailbox_state(&self) -> String {
        self.inner.read().mailbox_state.to_string()
    }

    pub fn mailbox_changes(&self) -> BTreeMap<i64, MailboxChangeRecord> {
        self.inner.read().mailbox_changes.clone()
    }

    fn bump_mailbox_state(&self, rec: MailboxChangeRecord) {
        let mut inner = self.inner.write();
        inner.mailbox_state += 1;
        let state = inner.mailbox_state;
        inner.mailbox_changes.insert(state, rec);
        self.save_state_locked(&inner);
    }

    /// The change log, for `Email/changes` and `Email/queryChanges`.
    pub fn changes(&self) -> BTreeMap<i64, ChangeRecord> {
        self.inner.read().changes.clone()
    }

    // ── identities ────────────────────────────────────────────────────────

    fn identities_path(&self) -> PathBuf {
        self.dir.join("identities.json")
    }

    fn load_identities(&self) {
        if let Ok(bytes) = fs::read(self.identities_path())
            && let Ok(ids) = serde_json::from_slice::<Vec<JsonObject>>(&bytes)
        {
            self.inner.write().identities = ids;
        }
    }

    pub fn identities(&self) -> Vec<JsonObject> {
        self.inner.read().identities.clone()
    }

    pub fn set_identities(&self, ids: Vec<JsonObject>) {
        let mut inner = self.inner.write();
        inner.identities = ids;
        if let Ok(bytes) = go_json::to_vec(&inner.identities) {
            let _ = write_file(&self.identities_path(), &bytes);
        }
    }

    /// The identity every account gets when it has none of its own.
    pub fn default_identity(account_id: &str) -> JsonObject {
        let name = account_id
            .split_once('@')
            .map_or(account_id, |(local, _)| local);
        let mut m = JsonObject::new();
        m.insert("id".into(), Value::String(format!("identity-{account_id}")));
        m.insert("name".into(), Value::String(name.to_string()));
        m.insert("email".into(), Value::String(account_id.to_string()));
        m.insert("replyTo".into(), Value::Null);
        m.insert("bcc".into(), Value::Null);
        m.insert("textSignature".into(), Value::String(String::new()));
        m.insert("htmlSignature".into(), Value::String(String::new()));
        m.insert("mayDelete".into(), Value::Bool(false));
        m
    }

    // ── vacation ──────────────────────────────────────────────────────────

    pub fn vacation(&self) -> Option<JsonObject> {
        self.inner.read().vacation.clone()
    }

    pub fn set_vacation(&self, v: Option<JsonObject>) {
        self.inner.write().vacation = v;
    }

    // ── blobs ─────────────────────────────────────────────────────────────

    /// Store bytes under a content-addressed id.
    pub fn put_blob(&self, data: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        let id = format!("blob-{}", hex_lower(&Sha256::digest(data)));
        self.inner.write().blobs.insert(id.clone(), data.to_vec());
        id
    }

    pub fn get_blob(&self, id: &str) -> Option<Vec<u8>> {
        self.inner.read().blobs.get(id).cloned()
    }

    // ── submissions ───────────────────────────────────────────────────────

    pub fn add_submission(&self, sub: JsonObject) {
        let mut inner = self.inner.write();
        inner.submissions.push(sub);
        inner.submission_state += 1;
        self.save_state_locked(&inner);
    }

    pub fn submissions(&self) -> Vec<JsonObject> {
        self.inner.read().submissions.clone()
    }

    pub fn submission_state(&self) -> String {
        self.inner.read().submission_state.to_string()
    }

    // ── internal ──────────────────────────────────────────────────────────

    fn msg_path(&self, id: &Id) -> PathBuf {
        self.dir
            .join("messages")
            .join(format!("{}.json", safe_filename(id.as_str())))
    }
}

/// Sort key for `all()`: the receive time, or the epoch when absent.
fn sort_key(m: &Email) -> ::time::OffsetDateTime {
    m.received_at
        .as_ref()
        .map_or(::time::OffsetDateTime::UNIX_EPOCH, JmapTime::sort_key)
}

/// Make an id safe to use as a filename.
///
/// **Lossy on purpose, and kept that way.** Every replaced character maps to
/// the same `-`, and the result is cut at 200 characters, so two distinct ids
/// can collide on one file. The Go implementation has the same hazard; it is
/// preserved rather than fixed because the filename *is* the on-disk format,
/// and a different scheme would leave every existing file stranded under its
/// old name while new writes went elsewhere — the same message readable twice
/// with different content. See SPEC.md §11.6.
fn safe_filename(s: &str) -> String {
    let mut out: String = s
        .chars()
        .map(|c| match c {
            '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => '-',
            other => other,
        })
        .collect();
    // Go slices bytes, not characters. Cutting mid-character would produce
    // invalid UTF-8, so this truncates at the last character boundary at or
    // before byte 200 — the same result for every id the relay actually
    // mints, all of which are ASCII after the replacement above.
    if out.len() > 200 {
        let mut end = 200;
        while !out.is_char_boundary(end) {
            end -= 1;
        }
        out.truncate(end);
    }
    out
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut acc, b| {
        use std::fmt::Write as _;
        let _ = write!(acc, "{b:02x}");
        acc
    })
}

fn write_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    fs::write(path, bytes)
}

/// Serialise an empty `Vec` as `null`, matching a nil Go slice with no
/// `omitempty`; accept either on the way in.
mod null_if_empty {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<T: Serialize, S: Serializer>(v: &[T], s: S) -> Result<S::Ok, S::Error> {
        if v.is_empty() {
            s.serialize_none()
        } else {
            v.serialize(s)
        }
    }

    pub fn deserialize<'de, T, D>(d: D) -> Result<Vec<T>, D::Error>
    where
        T: Deserialize<'de>,
        D: Deserializer<'de>,
    {
        Ok(Option::<Vec<T>>::deserialize(d)?.unwrap_or_default())
    }
}

#[cfg(test)]
mod tests;
