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

/// A metric this relay exports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Metric {
    pub name: &'static str,
    pub help: &'static str,
    /// `gauge` or `counter`. Part of the exposition, and a client that graphs
    /// a counter as a gauge draws the wrong shape.
    pub kind: &'static str,
    pub labels: Vec<(String, String)>,
    pub value: u64,
}

/// Render metrics in the Prometheus text exposition format.
///
/// One `# HELP` and one `# TYPE` per metric **name**, then every series — a
/// repeated HELP for the same name is a parse error for some scrapers, so
/// series sharing a name have to be emitted together.
///
/// Label values are escaped as the format requires (`\`, `"`, newline). A
/// domain cannot contain any of them today, but a label value is not always a
/// domain and an unescaped quote would corrupt every line after it.
pub fn render_prometheus(metrics: &[Metric]) -> String {
    let mut out = String::new();
    let mut seen: Vec<&str> = Vec::new();
    // Grouped by name, preserving first-appearance order.
    let mut names: Vec<&str> = Vec::new();
    for m in metrics {
        if !names.contains(&m.name) {
            names.push(m.name);
        }
    }
    for name in names {
        for m in metrics.iter().filter(|m| m.name == name) {
            if !seen.contains(&name) {
                out.push_str(&format!("# HELP {} {}\n", m.name, m.help));
                out.push_str(&format!("# TYPE {} {}\n", m.name, m.kind));
                seen.push(name);
            }
            out.push_str(m.name);
            if !m.labels.is_empty() {
                let rendered: Vec<String> = m
                    .labels
                    .iter()
                    .map(|(k, v)| format!("{k}=\"{}\"", escape_label(v)))
                    .collect();
                out.push('{');
                out.push_str(&rendered.join(","));
                out.push('}');
            }
            out.push_str(&format!(" {}\n", m.value));
        }
    }
    out
}

fn escape_label(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }
    out
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
        kind: "gauge",
        labels: vec![
            ("relay".into(), relay_label.to_string()),
            ("version".into(), version.to_string()),
        ],
        value: 1,
    }];

    // Every domain directory gets a series, **including one with no accounts**.
    // Omitting a zero would make "this domain dropped to zero accounts"
    // invisible to a scraper — the series simply disappears, which alerting
    // cannot distinguish from the relay being down.
    let mut per_domain: std::collections::BTreeMap<String, u64> = Default::default();
    if let Ok(entries) = std::fs::read_dir(data_dir) {
        for entry in entries.flatten() {
            if !entry.path().is_dir() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            if NOT_DOMAINS.contains(&name.as_str()) {
                continue;
            }
            per_domain.entry(name).or_default();
        }
    }
    for account in list_provisioned(data_dir) {
        *per_domain.entry(account.domain).or_default() += 1;
    }
    for (domain, count) in per_domain {
        out.push(Metric {
            name: "biset_accounts",
            help: "Number of provisioned accounts, by domain.",
            kind: "gauge",
            labels: vec![("domain".into(), domain)],
            value: count,
        });
    }

    out.push(Metric {
        name: "biset_data_disk_bytes",
        help: "Total size of the data directory tree in bytes.",
        kind: "gauge",
        labels: Vec::new(),
        value: dir_bytes(data_dir),
    });
    out
}

/// The relay's SMTP counters.
///
/// Both label series are emitted **even at zero**, matching
/// `relayCollectors`' pre-initialisation. A counter that only appears after its
/// first event makes `rate()` undefined until then, and an alert on "no sends"
/// cannot fire on a series that does not exist.
pub fn smtp_outbound_metrics(sent: u64, failed: u64) -> Vec<Metric> {
    vec![
        Metric {
            name: "biset_smtp_outbound_total",
            help: "Outbound SMTP send attempts, by result.",
            kind: "counter",
            labels: vec![("result".into(), "failed".into())],
            value: failed,
        },
        Metric {
            name: "biset_smtp_outbound_total",
            help: "Outbound SMTP send attempts, by result.",
            kind: "counter",
            labels: vec![("result".into(), "sent".into())],
            value: sent,
        },
    ]
}

/// The admin dashboard, a single static page.
///
/// Carried over verbatim rather than rewritten: it is a released client, and
/// the JSON it fetches is this module's output. It is served **without a
/// token** — every request the page makes carries one, so the shell itself
/// holds no account data and is safe to serve to anyone who can reach the
/// port. `the_dashboard_shell_is_public_but_carries_no_data` pins that.
pub const DASHBOARD_HTML: &str = include_str!("admin_dashboard.html");

#[cfg(test)]
mod tests;
