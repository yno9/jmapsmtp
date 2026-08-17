//! The JMAP handler: one [`Store`] per account, and the two hooks that make a
//! stored message an actually-sent one. Port of `go-jmapsmtp/main.go`'s
//! `handler` and `makeStore`.
//!
//! The interesting code is in the hooks. `Email/set create` and
//! `EmailSubmission/set create` arrive as ordinary JMAP method calls, and
//! everything the relay does that a plain JMAP server would not — minting a
//! Message-ID the client can quote immediately, enforcing the storage cap,
//! encrypting the stored copy, handing the message to SMTP — happens inside
//! them.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use jmap_types::mailbox::{Mailbox, Rights, Role};
use jmap_types::{Id, email::Email};

/// Mailbox ids are derived from the address, not minted, so the same account
/// gets the same inbox id on every start and a client's cached id keeps
/// working across restarts.
///
/// `/` is replaced because the id appears in a blob-download path segment.
pub fn make_mailbox_id(addr: &str) -> String {
    format!("mbx-{}", addr.replace('/', "~"))
}

/// The message id for a stored message.
///
/// Derived from the RFC Message-ID when there is one, so re-delivery of the
/// same message — a retry, a duplicate from a second MX — overwrites rather
/// than duplicating. Falls back to address-plus-timestamp otherwise.
///
/// Note the two different replacement characters: `_` here and `~` in
/// [`make_mailbox_id`]. That is not a reason to unify them — both appear in
/// filenames already written to disk.
pub fn make_message_id(message_id: &str, addr: &str, ts_millis: i64) -> String {
    if !message_id.is_empty() {
        return format!("msg-{}", message_id.replace('/', "_"));
    }
    format!("msg-{}-{}", addr.replace('/', "-"), ts_millis)
}

/// The single mailbox every account gets. There is no folder hierarchy: the
/// client is expected to organise by keyword and search.
pub fn default_inbox(addr: &str) -> Mailbox {
    Mailbox {
        id: Id::from(make_mailbox_id(addr).as_str()),
        name: addr.to_string(),
        role: Role::from(Role::INBOX),
        rights: Some(Rights {
            may_read_items: true,
            may_add_items: true,
            may_remove_items: true,
            may_set_seen: true,
            may_set_keywords: true,
            // No child mailboxes, no rename, no delete: there is exactly one
            // mailbox and the account is defined by it.
            may_create_child: false,
            may_rename: false,
            may_delete: false,
            may_submit: true,
        }),
        is_subscribed: true,
        ..Default::default()
    }
}

/// Total size of everything under `dir`, in whole megabytes.
///
/// Truncating division, matching Go: a 1.9 MB account reads as 1, so the cap
/// is crossed only once a full megabyte over. Unreadable entries count as
/// zero rather than failing — a cap check must not be a way to break sending.
pub fn dir_size_mb(dir: &Path) -> u64 {
    fn walk(dir: &Path, total: &mut u64) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            match entry.file_type() {
                Ok(t) if t.is_dir() => walk(&entry.path(), total),
                Ok(t) if t.is_file() => {
                    if let Ok(m) = entry.metadata() {
                        *total += m.len();
                    }
                }
                _ => {}
            }
        }
    }
    let mut total = 0;
    walk(dir, &mut total);
    total / (1024 * 1024)
}

/// A server-minted JMAP id: `srv-<unix millis>-<hex 8 bytes>`.
pub fn new_id() -> Id {
    Id::from(format!("srv-{}-{}", now_millis(), hex(8)).as_str())
}

/// The RFC 5322 Message-ID assigned to a draft the moment it is created:
/// `<unix nanos>.<hex 6 bytes>@<domain>`, without the angle brackets.
///
/// Assigned at creation rather than at send so a client can quote it as
/// `In-Reply-To` on the next message without waiting for delivery — the reply
/// chain is built locally and stays correct even if the send fails.
pub fn new_rfc_message_id(domain: &str) -> String {
    format!("{}.{}@{}", now_nanos(), hex(6), domain)
}

fn now_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn now_nanos() -> i128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i128)
        .unwrap_or(0)
}

fn hex(n: usize) -> String {
    use rand::TryRngCore as _;
    let mut b = vec![0u8; n];
    // These ids are not credentials — they are message and mailbox
    // identifiers — but a predictable one still lets a caller guess another
    // account's ids, so a failure here is not something to paper over.
    rand::rngs::OsRng
        .try_fill_bytes(&mut b)
        .expect("the OS random source failed");
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Pull `header:X-Foo:asText` properties out of an `Email/set create` object.
///
/// JMAP lets a client set an arbitrary header this way. Returned in sorted
/// order by name: Go ranges over a map here, so the order it emits varies
/// between runs, and a message with two custom headers has no stable byte
/// form. SPEC.md §11.5.
///
/// The `sort` below is **defensive, not load-bearing**: `serde_json::Map` is a
/// `BTreeMap` unless the `preserve_order` feature is enabled, so iteration is
/// already ordered and removing the sort changes nothing today. It stays
/// because that is a property of a dependency's feature flags, which any crate
/// in the tree can turn on — and if one does, the sort is the only thing
/// standing between this and Go's nondeterminism. The assumption itself is
/// checked by `serde_json_object_iteration_is_already_ordered`.
///
/// An empty value after trimming is dropped rather than emitted as a bare
/// `X-Foo:` — the client meant to unset it.
pub fn extract_text_headers(create: &serde_json::Value) -> Vec<(String, String)> {
    let Some(obj) = create.as_object() else {
        return Vec::new();
    };
    let mut out: Vec<(String, String)> = obj
        .iter()
        .filter_map(|(key, val)| {
            let name = key
                .strip_prefix("header:")
                .and_then(|k| k.strip_suffix(":asText"))?;
            let value = val.as_str()?.trim();
            if value.is_empty() || name.is_empty() {
                return None;
            }
            Some((name.to_string(), value.to_string()))
        })
        .collect();
    out.sort();
    out
}

/// `"ok"` or `"failed"`, the two values the activity log records.
pub fn activity_result(ok: bool) -> &'static str {
    if ok { "ok" } else { "failed" }
}

/// Addresses that have ever written to this account, lowercased.
///
/// Used by `reply_only_outbound`: an account may only send to someone who has
/// sent to it. The set is rebuilt from every stored message on each submission
/// rather than cached — an incoming message has to count immediately, and a
/// cache that lags would refuse a reply to a message the user is looking at.
pub fn known_correspondents(messages: &[Email]) -> std::collections::BTreeSet<String> {
    messages
        .iter()
        .flat_map(|m| m.from.iter())
        .filter(|a| !a.email.is_empty())
        .map(|a| a.email.to_lowercase())
        .collect()
}

/// One account's runtime state.
pub struct AccountStore {
    pub email: String,
    pub domain: String,
    pub localpart: String,
    pub dir: PathBuf,
    pub store: std::sync::Arc<jmapserver::Store>,
}

/// Every account the relay serves, plus the alias map that routes to them.
#[derive(Default)]
pub struct Accounts {
    inner: parking_lot::RwLock<AccountsInner>,
}

#[derive(Default)]
struct AccountsInner {
    /// Keyed by primary address.
    stores: BTreeMap<String, std::sync::Arc<AccountStore>>,
    /// Every deliverable address → the primary it belongs to.
    aliases: BTreeMap<String, String>,
}

impl Accounts {
    /// A second handle onto the same table.
    ///
    /// The JMAP server takes ownership of its handler, and the handler needs
    /// the same accounts the HTTP layer resolves credentials against — one
    /// copy each would drift the moment an account is provisioned.
    pub fn clone_of(other: &Accounts) -> Accounts {
        Accounts {
            inner: parking_lot::RwLock::new(AccountsInner {
                stores: other.inner.read().stores.clone(),
                aliases: other.inner.read().aliases.clone(),
            }),
        }
    }

    pub fn insert(&self, account: AccountStore, aliases: &[String]) {
        let mut inner = self.inner.write();
        let primary = account.email.clone();
        inner.aliases.insert(primary.clone(), primary.clone());
        for alias in aliases {
            inner.aliases.insert(alias.to_lowercase(), primary.clone());
        }
        inner.stores.insert(primary, std::sync::Arc::new(account));
    }

    /// The account an address delivers to, following the alias map.
    pub fn resolve(&self, address: &str) -> Option<std::sync::Arc<AccountStore>> {
        let inner = self.inner.read();
        let primary = inner.aliases.get(&address.to_lowercase())?;
        inner.stores.get(primary).cloned()
    }

    /// Registers one extra deliverable address for an ALREADY-existing
    /// primary — the SCID-account scheme's whole point (PLANSCID.md): a
    /// human-chosen username becomes an alias pointing at the account's
    /// permanent SCID identity, so renaming it later is this call again with
    /// a different address, never a data move. Fails (returns `false`)
    /// rather than creating a dangling alias when the primary is unknown —
    /// the caller (server.rs's `/account/alias` handler) turns that into a
    /// 404, not a silent no-op.
    pub fn add_alias(&self, alias: &str, primary: &str) -> bool {
        let mut inner = self.inner.write();
        if !inner.stores.contains_key(primary) {
            return false;
        }
        inner.aliases.insert(alias.to_lowercase(), primary.to_string());
        true
    }

    /// Drops one alias. Never removes the primary's own self-alias (the one
    /// `insert` sets up) even if asked — that mapping is what makes the
    /// account reachable at its own address at all, and losing it here would
    /// be indistinguishable from `remove`'s full account deletion while
    /// leaving the account's data behind.
    pub fn remove_alias(&self, alias: &str, primary: &str) -> bool {
        if alias.eq_ignore_ascii_case(primary) {
            return false;
        }
        let mut inner = self.inner.write();
        match inner.aliases.get(alias) {
            Some(p) if p == primary => {
                inner.aliases.remove(alias);
                true
            }
            _ => false,
        }
    }

    /// Every address currently routing to `primary`, aliases only — never
    /// includes `primary` itself. This is what a client displays as "your
    /// address" (PLANSCID.md's display-layer note: queried live rather than
    /// trusted from a possibly-stale DID document).
    pub fn aliases_for(&self, primary: &str) -> Vec<String> {
        self.inner
            .read()
            .aliases
            .iter()
            .filter(|(alias, p)| p.as_str() == primary && alias.as_str() != primary)
            .map(|(alias, _)| alias.clone())
            .collect()
    }

    pub fn get(&self, primary: &str) -> Option<std::sync::Arc<AccountStore>> {
        self.inner
            .read()
            .stores
            .get(&primary.to_lowercase())
            .cloned()
    }

    pub fn remove(&self, primary: &str) -> Option<std::sync::Arc<AccountStore>> {
        let mut inner = self.inner.write();
        let removed = inner.stores.remove(primary);
        // Drop every alias pointing at it, or the address keeps resolving to a
        // store nobody can reach and delivery silently disappears.
        inner.aliases.retain(|_, v| v != primary);
        removed
    }

    pub fn primaries(&self) -> Vec<String> {
        self.inner.read().stores.keys().cloned().collect()
    }

    pub fn aliases(&self) -> BTreeMap<String, String> {
        self.inner.read().aliases.clone()
    }
}

#[cfg(test)]
mod tests;

/// The [`jmapserver::Handler`] this relay installs.
///
/// It owns the per-account [`jmapserver::Store`]s and resolves each method
/// call's `accountId` to one of them. A call naming an account this relay does
/// not serve gets an error rather than another account's data — which is the
/// only isolation there is between accounts at the JMAP layer, since the
/// credential is checked once, at the HTTP edge.
pub struct RelayHandler {
    pub accounts: std::sync::Arc<Accounts>,
    pub hub: std::sync::Arc<jmapserver::Hub>,
}

impl jmapserver::Handler for RelayHandler {
    fn capabilities(&self) -> Vec<jmap_types::Uri> {
        // `urn:ietf:params:jmap:core` is added by the server itself.
        vec![
            jmap_types::Uri::from("urn:ietf:params:jmap:mail"),
            jmap_types::Uri::from("urn:ietf:params:jmap:submission"),
        ]
    }

    fn accounts(&self) -> Vec<jmapserver::Account> {
        self.accounts
            .primaries()
            .into_iter()
            .map(|address| jmapserver::Account {
                id: Id::from(address.as_str()),
                name: address,
            })
            .collect()
    }

    fn handle(&self, method: &str, args: &serde_json::Value) -> jmapserver::MethodResult {
        let account_id = args
            .get("accountId")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let Some(account) = self.accounts.get(account_id) else {
            // Go formats this as `accountNotFound: <id>` and it surfaces as a
            // `serverFail` — the message carries the distinction, not the
            // type. Reproduced verbatim: a client that matches on the string
            // is matching on this one.
            return Err(jmapserver::MethodError::ServerFail(format!(
                "accountNotFound: {account_id}"
            )));
        };
        let now = jmap_types::JmapTime::now_utc();
        account
            .store
            .dispatch(&Id::from(account_id), method, args, now.as_str())
    }
}
