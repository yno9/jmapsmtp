//! The inactive-account sweep.
//!
//! This deletes mail, so every test here is about a reason **not** to. The one
//! that matters most is the peer check: the same address is served by more than
//! one relay, and purging on the quiet one deletes half of a live account.

use super::*;
use pretty_assertions::assert_eq;

const DAY: i64 = 24 * 60 * 60;
const NOW: i64 = 1_785_000_000;

fn cfg(json: &str) -> Config {
    serde_json::from_str(json).expect("config should parse")
}

/// An open domain purging after 30 days.
fn purging() -> Config {
    cfg(r#"{"domain":{"open.test":{"allow_provision":true}},"inactive_purge_days":30}"#)
}

/// Create an account whose files were last touched `age_days` ago.
fn account(data_dir: &Path, domain: &str, localpart: &str, age_days: i64) {
    let dir = data_dir.join(domain).join(localpart);
    std::fs::create_dir_all(dir.join("messages")).unwrap();
    let file = dir.join("messages/m1.json");
    std::fs::write(&file, b"{}").unwrap();
    let when =
        std::time::UNIX_EPOCH + std::time::Duration::from_secs((NOW - age_days * DAY) as u64);
    filetime::set_file_mtime(&file, filetime::FileTime::from_system_time(when)).unwrap();
}

// ── the switch ────────────────────────────────────────────────────────────

/// Off unless asked for. A relay that purged by default would delete an
/// operator's data because they did not know about a setting.
#[test]
fn nothing_is_purged_unless_the_setting_is_present() {
    let tmp = tempfile::tempdir().unwrap();
    account(tmp.path(), "open.test", "ancient", 3650);
    let cfg = cfg(r#"{"domain":{"open.test":{"allow_provision":true}}}"#);
    assert!(accounts_to_purge(&cfg, tmp.path(), NOW).is_empty());
}

// ── the reasons to keep ───────────────────────────────────────────────────

#[test]
fn an_account_used_since_the_cutoff_is_kept() {
    let tmp = tempfile::tempdir().unwrap();
    account(tmp.path(), "open.test", "recent", 5);
    account(tmp.path(), "open.test", "stale", 40);

    assert_eq!(
        accounts_to_purge(&purging(), tmp.path(), NOW),
        [("open.test".to_string(), "stale".to_string())]
    );
}

/// An account on a closed domain was put there deliberately.
#[test]
fn an_account_on_a_closed_domain_is_never_purged() {
    let tmp = tempfile::tempdir().unwrap();
    account(tmp.path(), "closed.test", "ancient", 3650);
    let cfg = cfg(
        r#"{"domain":{"closed.test":{},"open.test":{"allow_provision":true}},
            "inactive_purge_days":30}"#,
    );
    assert!(accounts_to_purge(&cfg, tmp.path(), NOW).is_empty());
    assert_eq!(
        should_purge(&cfg, tmp.path(), "closed.test", "ancient", NOW - 30 * DAY),
        Err(Keep::ClosedDomain)
    );
}

/// Removing it loses the data **and** the account returns on the next start,
/// since config.json still names it.
#[test]
fn a_statically_configured_account_is_never_purged() {
    let tmp = tempfile::tempdir().unwrap();
    account(tmp.path(), "open.test", "listed", 3650);
    let cfg = cfg(
        r#"{"domain":{"open.test":{"allow_provision":true,"account":{"listed":{}}}},
            "inactive_purge_days":30}"#,
    );
    assert!(accounts_to_purge(&cfg, tmp.path(), NOW).is_empty());
    assert_eq!(
        should_purge(&cfg, tmp.path(), "open.test", "listed", NOW - 30 * DAY),
        Err(Keep::StaticallyConfigured)
    );
}

/// The one that matters most. The same address is served by more than one
/// relay; activity on any of them means the account is in use, and purging on
/// the quiet one deletes half of a live account's mail.
#[test]
fn an_account_active_on_a_peer_relay_is_kept() {
    let tmp = tempfile::tempdir().unwrap();
    let peer = tempfile::tempdir().unwrap();
    // Idle here, busy there.
    account(tmp.path(), "open.test", "elsewhere", 3650);
    account(peer.path(), "open.test", "elsewhere", 1);

    let cfg: Config = serde_json::from_str(&format!(
        r#"{{"domain":{{"open.test":{{"allow_provision":true}}}},
            "inactive_purge_days":30,
            "peer_data_dirs":["{}"]}}"#,
        peer.path().display()
    ))
    .unwrap();

    assert!(
        accounts_to_purge(&cfg, tmp.path(), NOW).is_empty(),
        "activity on a peer keeps the account"
    );
    assert_eq!(
        should_purge(&cfg, tmp.path(), "open.test", "elsewhere", NOW - 30 * DAY),
        Err(Keep::ActiveOnAPeer)
    );
}

/// A peer that is *also* idle does not save it — otherwise configuring a peer
/// would disable purging altogether.
#[test]
fn an_account_idle_everywhere_is_purged() {
    let tmp = tempfile::tempdir().unwrap();
    let peer = tempfile::tempdir().unwrap();
    account(tmp.path(), "open.test", "gone", 3650);
    account(peer.path(), "open.test", "gone", 3650);

    let cfg: Config = serde_json::from_str(&format!(
        r#"{{"domain":{{"open.test":{{"allow_provision":true}}}},
            "inactive_purge_days":30,
            "peer_data_dirs":["{}"]}}"#,
        peer.path().display()
    ))
    .unwrap();
    assert_eq!(
        accounts_to_purge(&cfg, tmp.path(), NOW),
        [("open.test".to_string(), "gone".to_string())]
    );
}

/// A peer directory that does not exist reads as no activity, not as an error
/// — an operator who lists a peer that is temporarily unmounted would
/// otherwise have purging silently disabled.
#[test]
fn a_missing_peer_directory_is_not_activity() {
    let tmp = tempfile::tempdir().unwrap();
    account(tmp.path(), "open.test", "gone", 3650);
    let cfg: Config = serde_json::from_str(
        r#"{"domain":{"open.test":{"allow_provision":true}},
            "inactive_purge_days":30,
            "peer_data_dirs":["/nonexistent/nowhere"]}"#,
    )
    .unwrap();
    assert_eq!(accounts_to_purge(&cfg, tmp.path(), NOW).len(), 1);
}

// ── the boundary ──────────────────────────────────────────────────────────

/// Exactly at the cutoff is purged; one second later is kept. Stated because
/// "older than N days" has two readings and this is the one implemented.
#[test]
fn the_cutoff_is_exclusive_on_the_keeping_side() {
    let tmp = tempfile::tempdir().unwrap();
    let cutoff = NOW - 30 * DAY;
    let dir = tmp.path().join("open.test/edge");
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("m.json");
    std::fs::write(&file, b"{}").unwrap();

    let set = |at: i64| {
        filetime::set_file_mtime(
            &file,
            filetime::FileTime::from_system_time(
                std::time::UNIX_EPOCH + std::time::Duration::from_secs(at as u64),
            ),
        )
        .unwrap();
    };

    set(cutoff);
    assert_eq!(
        should_purge(&purging(), tmp.path(), "open.test", "edge", cutoff),
        Ok(())
    );
    set(cutoff + 1);
    assert_eq!(
        should_purge(&purging(), tmp.path(), "open.test", "edge", cutoff),
        Err(Keep::Active)
    );
}

/// A directory with no files has no activity. Reading that as "now" would make
/// an empty account immortal.
#[test]
fn an_empty_account_directory_has_no_activity() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(tmp.path().join("open.test/empty")).unwrap();
    assert_eq!(last_activity(&tmp.path().join("open.test/empty")), 0);
    assert_eq!(
        accounts_to_purge(&purging(), tmp.path(), NOW),
        [("open.test".to_string(), "empty".to_string())]
    );
}

#[test]
fn the_sweep_runs_every_six_hours() {
    assert_eq!(SWEEP_INTERVAL_SECS, 6 * 60 * 60);
}
