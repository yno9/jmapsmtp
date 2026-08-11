//! The startup sequence. Port of the top of `go-jmapsmtp/main.go:main()`.
//!
//! **The order is part of the contract** (SPEC.md §2), and two of the steps
//! are ordered against each other for a reason that is not visible from either
//! one alone. Each such pair is named in the code below; do not reorder them
//! to make the function read better.
//!
//! The steps that need HTTP live in the router; this module is everything
//! before the listener opens, so it can be driven from tests without a socket.

use std::collections::BTreeMap;
use std::path::Path;

use crate::auth_env::{account_dir, read_auth_hash, read_envelope};
use crate::config::{Config, DynamicDomains};

/// Directories under `data/` that are not accounts and must never be swept.
///
/// `peers` holds Autocrypt peer keys for a whole domain; `_domains` holds the
/// custom-domain registry; `_queue` holds mail that has not gone out yet. All
/// sit exactly where an account directory would, and the sweep is a
/// `remove_dir_all`.
///
/// `_queue` is here because it was not, and the sweep deleted it. Mail that
/// had survived a temporary failure would have vanished at the next deploy —
/// the exact loss the queue exists to prevent, arriving by another road. An
/// empty directory being deleted looks like nothing, so only
/// `the_outbound_queue_is_not_swept` shows it.
const RESERVED_DOMAIN_DIRS: &[&str] = &["_domains", "_queue"];
const RESERVED_ACCOUNT_DIRS: &[&str] = &["peers"];

/// The setup token file for an account.
pub fn token_file(data_dir: &Path, domain: &str, localpart: &str) -> std::path::PathBuf {
    account_dir(data_dir, domain, localpart).join("setup.token")
}

/// A fresh setup token: 16 random bytes, hex.
pub fn generate_token() -> String {
    use rand::TryRngCore as _;
    let mut b = [0u8; 16];
    // A token that is not random is not a token. There is no sensible
    // fallback, and continuing with a predictable one would hand out account
    // access, so a failure here is fatal.
    rand::rngs::OsRng
        .try_fill_bytes(&mut b)
        .expect("the OS random source failed");
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Delete account and domain directories that no longer correspond to
/// anything configured.
///
/// **Must run after the dynamic domain registry is loaded.** A custom domain
/// verified in a previous run exists only in `data/_domains/`, so sweeping
/// first deletes the mail of every account on it — the domain looks orphaned
/// purely because nobody has read the file that says otherwise yet.
///
/// An account is kept if it is in the config **or** has an `auth_token_hash`.
/// Note what is *not* consulted: `envelope.json`. A third-party or DID-only
/// account legitimately has no envelope, and keying the sweep off that file
/// deletes every one of them on the next restart.
pub fn cleanup_orphaned_data(
    cfg: &Config,
    dynamic_domains: &DynamicDomains,
    data_dir: &Path,
) -> Vec<String> {
    let mut removed = Vec::new();
    let Ok(domain_dirs) = std::fs::read_dir(data_dir) else {
        return removed;
    };
    // Sorted so the log reads the same way twice, and so a test can assert on
    // it; Go ranges over ReadDir, which is sorted too, but the account loop
    // below is not.
    let mut domains: Vec<String> = domain_dirs
        .flatten()
        .filter(|e| e.path().is_dir())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| !RESERVED_DOMAIN_DIRS.contains(&n.as_str()))
        .collect();
    domains.sort();

    for domain in domains {
        let Some(dom_cfg) = crate::config::domain_config(cfg, dynamic_domains, &domain) else {
            let _ = std::fs::remove_dir_all(data_dir.join(&domain));
            removed.push(format!("data/{domain}"));
            continue;
        };
        let Ok(entries) = std::fs::read_dir(data_dir.join(&domain)) else {
            continue;
        };
        let mut localparts: Vec<String> = entries
            .flatten()
            .filter(|e| e.path().is_dir())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| !RESERVED_ACCOUNT_DIRS.contains(&n.as_str()))
            .collect();
        localparts.sort();

        for localpart in localparts {
            if dom_cfg.accounts.contains_key(&localpart) {
                continue;
            }
            if !read_auth_hash(data_dir, &domain, &localpart).is_empty() {
                continue; // dynamic, but real
            }
            let _ = std::fs::remove_dir_all(account_dir(data_dir, &domain, &localpart));
            removed.push(format!("data/{domain}/{localpart}"));
        }
    }
    removed
}

/// Re-register accounts created in previous runs.
///
/// Same existence rule as the sweep above, and for the same reason: these two
/// have to agree, or a restart deletes what the other would have restored.
pub fn scan_dyn_accounts(
    cfg: &Config,
    dynamic_domains: &DynamicDomains,
    data_dir: &Path,
    register: impl Fn(&str, &str),
) {
    let mut domains: Vec<String> = cfg.domains.keys().cloned().collect();
    domains.extend(dynamic_domains.names());
    domains.sort();
    domains.dedup();

    for domain in domains {
        let Ok(entries) = std::fs::read_dir(data_dir.join(&domain)) else {
            continue;
        };
        let static_accounts = cfg.domains.get(&domain).map(|d| &d.accounts);
        for entry in entries.flatten() {
            if !entry.path().is_dir() {
                continue;
            }
            let localpart = entry.file_name().to_string_lossy().into_owned();
            if RESERVED_ACCOUNT_DIRS.contains(&localpart.as_str()) {
                continue;
            }
            if static_accounts.is_some_and(|a| a.contains_key(&localpart)) {
                continue;
            }
            if !read_auth_hash(data_dir, &domain, &localpart).is_empty() {
                register(&localpart, &domain);
            }
        }
    }
}

/// One line of the `[setup]` log: an account that still needs to be claimed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetupInvite {
    pub localpart: String,
    pub domain: String,
    pub token: String,
}

impl SetupInvite {
    /// The URL printed at startup. This is how the operator hands an account
    /// to its owner, so the format is user-facing.
    pub fn url(&self, base_url: &str) -> String {
        format!("{base_url}/setup?token={}", self.token)
    }
}

/// Issue a setup token to every configured account that has no envelope yet.
///
/// An existing token file is reused rather than replaced. Reissuing on every
/// boot would invalidate the link the operator already sent, so a restart
/// during onboarding would silently break it.
pub fn issue_setup_tokens(cfg: &Config, data_dir: &Path) -> Vec<SetupInvite> {
    let mut invites = Vec::new();
    for (domain, dom_cfg) in &cfg.domains {
        for localpart in dom_cfg.accounts.keys() {
            if read_envelope(data_dir, domain, localpart).is_some() {
                continue; // already claimed
            }
            let path = token_file(data_dir, domain, localpart);
            let existing = std::fs::read_to_string(&path).unwrap_or_default();
            let token = if existing.is_empty() {
                let t = generate_token();
                let _ = std::fs::create_dir_all(account_dir(data_dir, domain, localpart));
                let _ = crate::write_private(&path, t.as_bytes());
                t
            } else {
                existing
            };
            invites.push(SetupInvite {
                localpart: localpart.clone(),
                domain: domain.clone(),
                token,
            });
        }
    }
    invites
}

/// Every address that reaches an account, mapped to that account's primary.
///
/// An alias without an `@` is completed with the domain it is configured
/// under, and everything is folded to lowercase — the lookup side folds too,
/// so an alias written `Postmaster` in the config still matches.
pub fn build_alias_map(cfg: &Config) -> BTreeMap<String, String> {
    let mut aliases = BTreeMap::new();
    for (domain, dom_cfg) in &cfg.domains {
        for (localpart, account) in &dom_cfg.accounts {
            let primary = format!("{}@{}", localpart.to_lowercase(), domain);
            aliases.insert(primary.clone(), primary.clone());
            for alias in &account.alias {
                let alias = alias.to_lowercase();
                let alias = if alias.contains('@') {
                    alias
                } else {
                    format!("{alias}@{domain}")
                };
                aliases.insert(alias, primary.clone());
            }
        }
    }
    aliases
}

#[cfg(test)]
mod tests;
