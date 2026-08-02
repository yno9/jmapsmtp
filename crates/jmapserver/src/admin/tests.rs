//! The admin listing and the metrics collector.
//!
//! The theme is that these two must agree with each other: an operator watching
//! `biset_accounts` and an operator reading `/admin/accounts` are looking at
//! the same relay, and a number that differs between them is worse than either
//! being wrong, because neither can be checked against the other.

use super::*;
use pretty_assertions::assert_eq;

/// A relay with one real account, a domain-wide `peers/` directory, and a
/// registered custom domain — the three things that sit at the same depth and
/// are not the same kind of thing.
fn relay() -> tempfile::TempDir {
    let tmp = tempfile::tempdir().unwrap();
    let alice = tmp.path().join("a.test/alice/messages");
    std::fs::create_dir_all(&alice).unwrap();
    std::fs::write(alice.join("m1.json"), vec![b'x'; 100]).unwrap();
    std::fs::write(alice.join("m2.json"), vec![b'y'; 200]).unwrap();
    std::fs::write(alice.join("notes.txt"), vec![b'z'; 50]).unwrap();
    std::fs::write(
        tmp.path().join("a.test/alice/envelope.json"),
        vec![b'e'; 40],
    )
    .unwrap();

    // The domain's Autocrypt peer keys. Not an account.
    std::fs::create_dir_all(tmp.path().join("a.test/peers")).unwrap();
    std::fs::write(tmp.path().join("a.test/peers/bob@x.test.pgp"), b"key").unwrap();

    // The custom-domain registry. Not a domain, and its contents are not
    // accounts.
    std::fs::create_dir_all(tmp.path().join("_domains/byo.test")).unwrap();
    std::fs::write(tmp.path().join("_domains/byo.test/domain.json"), b"{}").unwrap();
    tmp
}

// ── who counts as an account ──────────────────────────────────────────────

/// The divergence, SPEC.md §11.16. Go skips `peers` here but not `_domains`, so
/// a relay with any registered custom domain reports `byo.test@_domains` as an
/// account — an address that does not exist.
#[test]
fn neither_peers_nor_the_domain_registry_is_an_account() {
    let tmp = relay();
    assert_eq!(
        list_provisioned(tmp.path()),
        [AccountRef {
            domain: "a.test".into(),
            localpart: "alice".into()
        }],
        "one real account"
    );
}

#[test]
fn the_listing_is_sorted_and_stable() {
    let tmp = relay();
    for lp in ["zed", "bob"] {
        std::fs::create_dir_all(tmp.path().join("a.test").join(lp)).unwrap();
    }
    let first = list_provisioned(tmp.path());
    assert_eq!(
        first
            .iter()
            .map(|a| a.localpart.as_str())
            .collect::<Vec<_>>(),
        ["alice", "bob", "zed"]
    );
    for _ in 0..10 {
        assert_eq!(list_provisioned(tmp.path()), first);
    }
}

#[test]
fn a_missing_data_directory_lists_nothing_rather_than_failing() {
    assert!(list_provisioned(Path::new("/nonexistent/nowhere")).is_empty());
}

// ── the numbers ───────────────────────────────────────────────────────────

/// Only `*.json` directly under `messages/` counts — the same rule the storage
/// listing uses, so the two never disagree about how many messages an account
/// has.
#[test]
fn message_stats_count_only_json_files_directly_under_messages() {
    let tmp = relay();
    assert_eq!(
        message_stats(tmp.path(), "a.test", "alice"),
        (2, 300),
        "notes.txt is not a message"
    );
    assert_eq!(
        message_stats(tmp.path(), "a.test", "nobody"),
        (0, 0),
        "a missing account is zero, not an error"
    );
}

/// `total` minus `messages` is what the envelopes, keys and activity log come
/// to, which is why both are reported rather than one.
#[test]
fn the_usage_breakdown_separates_messages_from_everything_else() {
    let tmp = relay();
    let usage = usage_breakdown(tmp.path(), "a.test", "alice");
    assert_eq!(usage[0], ("messages".into(), 300));
    assert_eq!(
        usage[1],
        ("total".into(), 300 + 50 + 40),
        "messages, notes.txt and envelope.json"
    );
    assert!(usage[1].1 > usage[0].1, "the difference is the point");
}

#[test]
fn a_summary_names_the_address_and_omits_an_absent_activity_time() {
    let tmp = relay();
    let s = account_summary(tmp.path(), "a.test", "alice", None);
    assert_eq!(s.address, "alice@a.test");
    assert_eq!((s.messages, s.bytes), (2, 300));

    let json = serde_json::to_value(&s).unwrap();
    assert!(
        json.get("lastActivity").is_none(),
        "omitted, not null: {json}"
    );
}

// ── metrics ───────────────────────────────────────────────────────────────

/// The property that matters: the metric and the listing count the same thing.
///
/// In the Go implementation they do not. Measured on the oracle with this exact
/// layout: `/admin/accounts` returns one account on `a.test`, while
/// `biset_accounts{domain="a.test"}` reports **2** — the collector counts
/// `peers` — and `biset_accounts{domain="_domains"}` reports 1 besides.
/// SPEC.md §11.16.
#[test]
fn the_account_metric_agrees_with_the_account_listing() {
    let tmp = relay();
    let metrics = collect(tmp.path(), "Biset", "dev");

    let accounts: Vec<&Metric> = metrics
        .iter()
        .filter(|m| m.name == "biset_accounts")
        .collect();
    assert_eq!(accounts.len(), 1, "one domain has accounts: {accounts:?}");
    assert_eq!(
        accounts[0].labels,
        [("domain".to_string(), "a.test".to_string())]
    );
    assert_eq!(accounts[0].value, 1);

    assert_eq!(
        accounts.iter().map(|m| m.value).sum::<u64>(),
        list_provisioned(tmp.path()).len() as u64,
        "the metric and the listing must not disagree"
    );
    assert!(
        !metrics.iter().any(|m| m
            .labels
            .contains(&("domain".to_string(), "_domains".to_string()))),
        "the registry is not a domain"
    );
}

#[test]
fn build_info_is_always_one_and_carries_the_relay_and_version() {
    let m = &collect(&tempfile::tempdir().unwrap().keep(), "Biset", "abc123")[0];
    assert_eq!(m.name, "biset_build_info");
    assert_eq!(m.value, 1);
    assert_eq!(
        m.labels,
        [
            ("relay".to_string(), "Biset".to_string()),
            ("version".to_string(), "abc123".to_string())
        ]
    );
}

/// The disk metric is the whole tree, including the parts that are not
/// accounts — an operator watching disk wants the disk, not the sum of the
/// accounts.
#[test]
fn the_disk_metric_covers_everything_under_the_data_directory() {
    let tmp = relay();
    let disk = collect(tmp.path(), "Biset", "dev")
        .into_iter()
        .find(|m| m.name == "biset_data_disk_bytes")
        .unwrap();
    assert_eq!(
        disk.value,
        dir_bytes(tmp.path()),
        "the whole tree, peers and registry included"
    );
    assert!(
        disk.value > usage_breakdown(tmp.path(), "a.test", "alice")[1].1,
        "strictly more than one account's usage"
    );
    assert!(disk.labels.is_empty());
}

#[test]
fn an_empty_relay_reports_build_info_and_a_zero_disk_size() {
    let tmp = tempfile::tempdir().unwrap();
    let metrics = collect(tmp.path(), "Biset", "dev");
    assert_eq!(metrics.len(), 2, "build_info and disk_bytes: {metrics:?}");
    assert_eq!(
        metrics
            .iter()
            .find(|m| m.name == "biset_data_disk_bytes")
            .unwrap()
            .value,
        0
    );
}
