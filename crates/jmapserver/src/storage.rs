//! "How your data is stored". Port of `go-jmapserver/storage.go`.
//!
//! Lets an account holder see the real on-disk shape of their own data, export
//! it whole, and clear just the messages without deleting the account.
//!
//! Every route derives its target **purely from the credential** — no email
//! appears in any request — so none of them can act on another account. That is
//! the same shape as every other per-account endpoint in this family, and it is
//! what makes a purge safe to expose at all.
//!
//! ```text
//! GET  /account/storage                 {"entries":[…],"totalSizeBytes":N}
//! GET  /account/storage/messages        {"files":[…]}
//! GET  /account/storage/export          {"email":…,"files":{path: base64}}
//! POST /account/storage/purge-messages  {"purged":N}
//! ```

use std::path::Path;

use serde::Serialize;

/// One top-level entry in an account's directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StorageEntry {
    pub name: String,
    /// `"file"` or `"dir"`.
    #[serde(rename = "type")]
    pub kind: &'static str,
    /// Files inside. Directories only; omitted otherwise.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub count: u64,
    #[serde(rename = "sizeBytes")]
    pub size_bytes: u64,
}

fn is_zero(n: &u64) -> bool {
    *n == 0
}

/// The account directory, one level deep.
///
/// `messages/` is summarised as a single entry with a count and a total rather
/// than listed file by file: an account can hold thousands, and a per-message
/// tree is not what "how your data is stored" is asking to see. The drill-down
/// is [`list_message_files`], a separate route so the common case does not pay
/// for a directory read that could return thousands of entries.
///
/// Any other subdirectory is skipped defensively — none are expected in the
/// current layout, and listing one would report a size that is not its own.
pub fn list_account_storage(
    data_dir: &Path,
    domain: &str,
    localpart: &str,
) -> std::io::Result<Vec<StorageEntry>> {
    let acct_dir = data_dir.join(domain).join(localpart);
    let mut out = Vec::new();
    // Sorted: Go's ReadDir is sorted, and a listing whose order changed between
    // identical requests would be a visible difference for no reason.
    let mut entries: Vec<_> = std::fs::read_dir(&acct_dir)?.flatten().collect();
    entries.sort_by_key(std::fs::DirEntry::file_name);

    for entry in entries {
        let name = entry.file_name().to_string_lossy().into_owned();
        let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
        if is_dir {
            if name != "messages" {
                continue;
            }
            let (count, size) = summarise_dir(&acct_dir.join("messages"));
            out.push(StorageEntry {
                name,
                kind: "dir",
                count,
                size_bytes: size,
            });
            continue;
        }
        let Ok(meta) = entry.metadata() else { continue };
        out.push(StorageEntry {
            name,
            kind: "file",
            count: 0,
            size_bytes: meta.len(),
        });
    }
    Ok(out)
}

fn summarise_dir(dir: &Path) -> (u64, u64) {
    let (mut count, mut size) = (0, 0);
    let Ok(entries) = std::fs::read_dir(dir) else {
        return (0, 0);
    };
    for entry in entries.flatten() {
        if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        if let Ok(meta) = entry.metadata() {
            count += 1;
            size += meta.len();
        }
    }
    (count, size)
}

/// Every file under `messages/` — the drill-down behind the summarised entry.
pub fn list_message_files(
    data_dir: &Path,
    domain: &str,
    localpart: &str,
) -> std::io::Result<Vec<StorageEntry>> {
    let dir = data_dir.join(domain).join(localpart).join("messages");
    let mut entries: Vec<_> = std::fs::read_dir(&dir)?.flatten().collect();
    entries.sort_by_key(std::fs::DirEntry::file_name);

    Ok(entries
        .into_iter()
        .filter(|e| !e.file_type().map(|t| t.is_dir()).unwrap_or(false))
        .filter_map(|e| {
            Some(StorageEntry {
                name: e.file_name().to_string_lossy().into_owned(),
                kind: "file",
                count: 0,
                size_bytes: e.metadata().ok()?.len(),
            })
        })
        .collect())
}

/// Every file under the account directory, as relative path → raw bytes.
///
/// "How your data is stored", literally: every file exactly as it sits on disk,
/// nothing synthesised and nothing filtered. A file that cannot be read is
/// skipped rather than failing the export — a partial export is worth more than
/// none, and the listing endpoints show what should be there.
pub fn export_account_storage(
    data_dir: &Path,
    domain: &str,
    localpart: &str,
) -> std::collections::BTreeMap<String, Vec<u8>> {
    fn walk(base: &Path, dir: &Path, out: &mut std::collections::BTreeMap<String, Vec<u8>>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                walk(base, &path, out);
                continue;
            }
            let Ok(rel) = path.strip_prefix(base) else {
                continue;
            };
            if let Ok(bytes) = std::fs::read(&path) {
                // Forward slashes regardless of platform: this is a JSON key a
                // client will use as a path.
                out.insert(rel.to_string_lossy().replace('\\', "/"), bytes);
            }
        }
    }
    let acct_dir = data_dir.join(domain).join(localpart);
    let mut out = std::collections::BTreeMap::new();
    walk(&acct_dir, &acct_dir, &mut out);
    out
}

/// Files a purge must never remove.
///
/// `purge-messages` clears **only** `messages/`. Removing any of these would
/// corrupt the account or lock it out entirely — that is what full account
/// deletion is for, and it is a different request with a different name.
///
/// Listed explicitly rather than implied by "only touch messages/", so that a
/// future refactor that widens the purge has to delete a line that says why it
/// should not.
pub const PURGE_MUST_NOT_TOUCH: &[&str] = &[
    "mailboxes.json",
    "identities.json",
    "contacts.json",
    "envelope.json",
    "auth_token_hash",
    "privkey.enc",
    "pubkey.pgp",
    "setup.token",
    "devices",
    "sessions",
];

/// The response body of `GET /account/storage`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StorageSummary {
    pub entries: Vec<StorageEntry>,
    #[serde(rename = "totalSizeBytes")]
    pub total_size_bytes: u64,
}

pub fn storage_summary(entries: Vec<StorageEntry>) -> StorageSummary {
    StorageSummary {
        total_size_bytes: entries.iter().map(|e| e.size_bytes).sum(),
        entries,
    }
}

#[cfg(test)]
mod tests;
