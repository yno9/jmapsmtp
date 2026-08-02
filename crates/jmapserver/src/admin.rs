//! The admin surface and the metrics collector. Port of
//! `go-jmapserver/admin.go` and `metrics.go`.
//!
//! Both are behind a bearer token, and **an unset token closes the route
//! rather than opening it** — see `jmapsmtp::bearer` and SPEC.md §11.13, which
//! is the one deliberate divergence in this area.
//!
//! Everything here is computed from the data directory at request time. There
//! is no cache and no index: the numbers are whatever the disk says, which
//! means they cannot drift, and an account that appears or disappears out of
//! band is reflected immediately.

use std::path::Path;

use serde::Serialize;

/// One provisioned address. The cheap read — callers that only need identities
/// (draining claims from the anchor) should not pay to stat every mailbox.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AccountRef {
    pub domain: String,
    pub localpart: String,
}

impl AccountRef {
    pub fn address(&self) -> String {
        format!("{}@{}", self.localpart, self.domain)
    }
}

/// Directories under `data/` that are not domains.
///
/// `_domains` holds the custom-domain registry. Without it here, its
/// subdirectories are reported as *accounts on a domain called `_domains`* —
/// see `list_provisioned`'s note.
const NOT_DOMAINS: &[&str] = &["_domains"];
/// Directories under a domain that are not accounts.
const NOT_ACCOUNTS: &[&str] = &["peers"];

/// Every provisioned address, from the directory layout alone.
///
/// # This filters more than the Go original
///
/// `ListProvisioned` skips `peers` but not `_domains`, so a relay with any
/// registered custom domain reports each of them as an account —
/// `byo.test@_domains` — in the admin listing and in the account count. Since
/// the same walk backs `Drain`, those phantom rows are also addresses the relay
/// would try to release at the anchor.
///
/// Filtered here. SPEC.md §11.16.
pub fn list_provisioned(data_dir: &Path) -> Vec<AccountRef> {
    let mut out = Vec::new();
    let Ok(domains) = std::fs::read_dir(data_dir) else {
        return out;
    };
    // Sorted, because Go's ReadDir is and the listing is user-visible.
    let mut domains: Vec<String> = domains
        .flatten()
        .filter(|e| e.path().is_dir())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| !NOT_DOMAINS.contains(&n.as_str()))
        .collect();
    domains.sort();

    for domain in domains {
        let Ok(entries) = std::fs::read_dir(data_dir.join(&domain)) else {
            continue;
        };
        let mut localparts: Vec<String> = entries
            .flatten()
            .filter(|e| e.path().is_dir())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| !NOT_ACCOUNTS.contains(&n.as_str()))
            .collect();
        localparts.sort();
        for localpart in localparts {
            out.push(AccountRef {
                domain: domain.clone(),
                localpart,
            });
        }
    }
    out
}

/// One row of `GET /admin/accounts`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AccountSummary {
    pub address: String,
    pub domain: String,
    pub localpart: String,
    pub messages: u64,
    pub bytes: u64,
    #[serde(rename = "lastActivity", skip_serializing_if = "Option::is_none")]
    pub last_activity: Option<jmap_types::JmapTime>,
}

/// The account's persisted message objects and their total bytes.
///
/// Only `*.json` directly under `messages/` counts — the same rule the storage
/// listing uses, so the two never disagree about how many messages an account
/// has.
pub fn message_stats(data_dir: &Path, domain: &str, localpart: &str) -> (u64, u64) {
    let dir = data_dir.join(domain).join(localpart).join("messages");
    let Ok(entries) = std::fs::read_dir(dir) else {
        return (0, 0);
    };
    let (mut count, mut bytes) = (0, 0);
    for entry in entries.flatten() {
        if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        if entry.path().extension().is_none_or(|e| e != "json") {
            continue;
        }
        count += 1;
        if let Ok(meta) = entry.metadata() {
            bytes += meta.len();
        }
    }
    (count, bytes)
}

/// Every regular file under `root`, summed.
pub fn dir_bytes(root: &Path) -> u64 {
    let mut total = 0;
    fn walk(dir: &Path, total: &mut u64) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            match entry.file_type() {
                Ok(t) if t.is_dir() => walk(&entry.path(), total),
                Ok(t) if t.is_file() => {
                    if let Ok(meta) = entry.metadata() {
                        *total += meta.len();
                    }
                }
                _ => {}
            }
        }
    }
    walk(root, &mut total);
    total
}

pub fn account_summary(
    data_dir: &Path,
    domain: &str,
    localpart: &str,
    last_activity: Option<jmap_types::JmapTime>,
) -> AccountSummary {
    let (messages, bytes) = message_stats(data_dir, domain, localpart);
    AccountSummary {
        address: format!("{localpart}@{domain}"),
        domain: domain.to_string(),
        localpart: localpart.to_string(),
        messages,
        bytes,
        last_activity,
    }
}

/// The usage breakdown on `GET /admin/accounts/<address>`.
///
/// `total` minus `messages` is what the avatars, envelopes, keys and activity
/// log come to — which is why both numbers are reported rather than one.
pub fn usage_breakdown(data_dir: &Path, domain: &str, localpart: &str) -> Vec<(String, u64)> {
    let (_, message_bytes) = message_stats(data_dir, domain, localpart);
    vec![
        ("messages".to_string(), message_bytes),
        (
            "total".to_string(),
            dir_bytes(&data_dir.join(domain).join(localpart)),
        ),
    ]
}

// ── metrics ───────────────────────────────────────────────────────────────

/// A metric this relay exports, in Prometheus text form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Metric {
    pub name: &'static str,
    pub help: &'static str,
    pub labels: Vec<(String, String)>,
    pub value: u64,
}

/// The relay's own metrics, computed from the data directory at scrape time.
///
/// Account counts use the same walk as [`list_provisioned`], so the number in
/// `biset_accounts` and the number of rows in `/admin/accounts` agree. In the
/// Go implementation they do not: the collector counts every subdirectory of
/// every top-level directory, including `_domains` and `peers`.
/// SPEC.md §11.16.
pub fn collect(data_dir: &Path, relay_label: &str, version: &str) -> Vec<Metric> {
    let mut out = vec![Metric {
        name: "biset_build_info",
        help: "Build and relay information; the metric value is always 1.",
        labels: vec![
            ("relay".into(), relay_label.to_string()),
            ("version".into(), version.to_string()),
        ],
        value: 1,
    }];

    let mut per_domain: std::collections::BTreeMap<String, u64> = Default::default();
    for account in list_provisioned(data_dir) {
        *per_domain.entry(account.domain).or_default() += 1;
    }
    for (domain, count) in per_domain {
        out.push(Metric {
            name: "biset_accounts",
            help: "Number of provisioned accounts, by domain.",
            labels: vec![("domain".into(), domain)],
            value: count,
        });
    }

    out.push(Metric {
        name: "biset_data_disk_bytes",
        help: "Total size of the data directory tree in bytes.",
        labels: Vec::new(),
        value: dir_bytes(data_dir),
    });
    out
}

#[cfg(test)]
mod tests;
