//! Periodic upkeep. Port of `go-jmapsmtp/maintenance.go`.
//!
//! One task: removing accounts nobody has used. It deletes mail, so the
//! conditions are narrow and every one of them is a separate reason to keep an
//! account rather than one combined rule.
//!
//! **Disabled unless `inactive_purge_days` is set.** A relay that purges by
//! default would delete an operator's data because they did not know about a
//! setting.

use std::path::Path;

use crate::config::Config;

/// How often the sweep runs.
pub const SWEEP_INTERVAL_SECS: u64 = 6 * 60 * 60;

/// The most recent modification time under `dir`, as seconds since the epoch.
///
/// `0` when nothing is there — a directory with no files has no activity, and
/// treating that as "now" would make an empty account immortal.
pub fn last_activity(dir: &Path) -> i64 {
    fn walk(dir: &Path, latest: &mut i64) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            match entry.file_type() {
                Ok(t) if t.is_dir() => walk(&entry.path(), latest),
                Ok(t) if t.is_file() => {
                    if let Ok(modified) = entry.metadata().and_then(|m| m.modified())
                        && let Ok(since) = modified.duration_since(std::time::UNIX_EPOCH)
                    {
                        *latest = (*latest).max(since.as_secs() as i64);
                    }
                }
                _ => {}
            }
        }
    }
    let mut latest = 0;
    walk(dir, &mut latest);
    latest
}

/// Whether an account may be purged, and why not when it may not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Keep {
    /// The domain is not open to self-service registration. An account on a
    /// closed domain was put there deliberately.
    ClosedDomain,
    /// Named in `config.json`. Removing it loses the data and the account
    /// returns on the next start.
    StaticallyConfigured,
    /// Used here since the cutoff.
    Active,
    /// Used on a **sibling relay** since the cutoff.
    ///
    /// The same address is served by more than one relay, and activity on any
    /// of them means the account is in use. Purging on the quiet one deletes
    /// half of a live account's mail.
    ActiveOnAPeer,
}

/// Decide one account's fate.
///
/// Every condition is checked, and each keeps the account on its own — this is
/// deliberately not one combined predicate, because the reasons are unrelated
/// and a future change should have to remove the specific one it means to.
pub fn should_purge(
    cfg: &Config,
    data_dir: &Path,
    domain: &str,
    localpart: &str,
    cutoff: i64,
) -> Result<(), Keep> {
    let Some(dom_cfg) = cfg.domains.get(domain) else {
        return Err(Keep::ClosedDomain);
    };
    if !dom_cfg.allow_provision {
        return Err(Keep::ClosedDomain);
    }
    if dom_cfg.accounts.contains_key(localpart) {
        return Err(Keep::StaticallyConfigured);
    }
    if last_activity(&data_dir.join(domain).join(localpart)) > cutoff {
        return Err(Keep::Active);
    }
    for peer in &cfg.peer_data_dirs {
        if last_activity(&Path::new(peer).join(domain).join(localpart)) > cutoff {
            return Err(Keep::ActiveOnAPeer);
        }
    }
    Ok(())
}

/// Every account the sweep would remove, as `(domain, localpart)`.
///
/// Separated from the removal so the decision can be tested without deleting
/// anything, and so a caller can log what it is about to do before doing it.
pub fn accounts_to_purge(cfg: &Config, data_dir: &Path, now: i64) -> Vec<(String, String)> {
    if cfg.inactive_purge_days == 0 {
        return Vec::new();
    }
    let cutoff = now - (cfg.inactive_purge_days as i64) * 24 * 60 * 60;

    let mut out = Vec::new();
    for (domain, dom_cfg) in &cfg.domains {
        if !dom_cfg.allow_provision {
            continue;
        }
        let Ok(entries) = std::fs::read_dir(data_dir.join(domain)) else {
            continue;
        };
        let mut localparts: Vec<String> = entries
            .flatten()
            .filter(|e| e.path().is_dir())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        localparts.sort();
        for localpart in localparts {
            if should_purge(cfg, data_dir, domain, &localpart, cutoff).is_ok() {
                out.push((domain.clone(), localpart));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests;
