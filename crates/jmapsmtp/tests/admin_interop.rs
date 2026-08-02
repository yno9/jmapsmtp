//! The admin listing and the metrics collector, against the oracle.
//!
//! Both are read by an operator deciding whether the relay is healthy, so the
//! numbers matter more than the format. The declared divergence here
//! (SPEC.md §11.16) is that the Go implementation's two answers disagree with
//! *each other*: `/admin/accounts` filters `peers` and the metrics collector
//! does not, and neither filters `_domains`.

use jmapsmtp::bearer::{Bearer, check};

mod oracle_harness;
use oracle_harness::Oracle;

fn config_json(http_port: u16, smtp_port: u16) -> String {
    format!(
        r#"{{"listen_addr":"127.0.0.1:{http_port}","smtp_port":{smtp_port},
            "base_url":"http://127.0.0.1:{http_port}","hostname":"t.invalid",
            "domain_verify_secret":"s3cret",
            "domain":{{"a.test":{{"account":{{"alice":{{}}}}}}}}}}"#
    )
}

/// One real account, a domain-wide `peers/`, and a registered custom domain —
/// the three things that sit at the same depth and are not the same kind.
fn seed(root: &std::path::Path) {
    let data = root.join("data");
    let alice = data.join("a.test/alice/messages");
    std::fs::create_dir_all(&alice).unwrap();
    std::fs::write(alice.join("m1.json"), vec![b'x'; 100]).unwrap();
    std::fs::write(alice.join("m2.json"), vec![b'y'; 200]).unwrap();
    std::fs::write(alice.join("notes.txt"), vec![b'z'; 50]).unwrap();

    std::fs::create_dir_all(data.join("a.test/peers")).unwrap();
    std::fs::write(data.join("a.test/peers/bob@x.test.pgp"), b"key").unwrap();

    std::fs::create_dir_all(data.join("_domains/byo.test")).unwrap();
    std::fs::write(data.join("_domains/byo.test/domain.json"), b"{}").unwrap();
}

fn oracle() -> Option<Oracle> {
    Oracle::start_with("ADMIN_INTEROP", config_json, seed)
}

/// `biset_accounts{domain="…"}` as the oracle reports it.
fn go_account_counts(body: &str) -> Vec<(String, u64)> {
    let mut out: Vec<(String, u64)> = body
        .lines()
        .filter(|l| l.starts_with("biset_accounts{"))
        .filter_map(|l| {
            let domain = l.split("domain=\"").nth(1)?.split('"').next()?.to_string();
            let value: f64 = l.rsplit(' ').next()?.parse().ok()?;
            Some((domain, value as u64))
        })
        .collect();
    out.sort();
    out
}

// ── the divergence ────────────────────────────────────────────────────────

/// The oracle's own two answers disagree, and this port's agree.
///
/// Asserted as a difference so the fix cannot be lost: if the Go side is ever
/// corrected, this fails and reports the divergence as stale rather than
/// letting a regression pass as a match.
#[test]
fn the_oracles_metric_and_listing_disagree_and_this_ports_agree() {
    let Some(o) = oracle() else { return };

    let (status, accounts_body, _) = o.get("/admin/accounts");
    assert_eq!(
        status, 200,
        "the oracle serves this unauthenticated (§11.13)"
    );
    let listed: serde_json::Value = serde_json::from_str(&accounts_body).unwrap();
    let listed = listed["accounts"].as_array().unwrap();

    let (status, metrics_body, _) = o.get("/metrics");
    assert_eq!(status, 200);
    let counted = go_account_counts(&metrics_body);

    // What the oracle actually reports, stated outright.
    assert!(
        listed.iter().any(|a| a["address"] == "byo.test@_domains"),
        "the oracle is expected to list the domain registry as an account — \
         if it no longer does, SPEC.md §11.16 is stale: {listed:?}"
    );
    assert_eq!(
        counted,
        [("_domains".to_string(), 1), ("a.test".to_string(), 2)],
        "the oracle's collector counts peers and the registry"
    );

    // …and the two disagree with each other: 2 accounts on a.test by the
    // metric, 1 by the listing.
    let listed_on_a: usize = listed.iter().filter(|a| a["domain"] == "a.test").count();
    assert_eq!(listed_on_a, 1);
    assert_eq!(
        counted.iter().find(|(d, _)| d == "a.test").unwrap().1,
        2,
        "the oracle's own two answers differ for the same domain"
    );

    // This port: one account, one domain, and the two agree.
    let data = o.data_dir();
    let ours = jmapserver::admin::list_provisioned(&data);
    assert_eq!(ours.len(), 1);
    assert_eq!(ours[0].address(), "alice@a.test");

    let our_metrics = jmapserver::admin::collect(&data, "", "dev");
    let our_counts: Vec<(String, u64)> = our_metrics
        .iter()
        .filter(|m| m.name == "biset_accounts")
        .map(|m| (m.labels[0].1.clone(), m.value))
        .collect();
    assert_eq!(our_counts, [("a.test".to_string(), 1)]);
    assert_eq!(
        our_counts.iter().map(|(_, n)| n).sum::<u64>(),
        ours.len() as u64,
        "this port's metric and listing agree"
    );
}

// ── the numbers that are not in dispute ───────────────────────────────────

/// The per-account figures match: only `*.json` directly under `messages/`
/// counts, on both sides.
#[test]
fn the_per_account_message_stats_match() {
    let Some(o) = oracle() else { return };
    let (_, body, _) = o.get("/admin/accounts");
    let listed: serde_json::Value = serde_json::from_str(&body).unwrap();
    let alice = listed["accounts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["address"] == "alice@a.test")
        .expect("alice");

    let (messages, bytes) = jmapserver::admin::message_stats(&o.data_dir(), "a.test", "alice");
    assert_eq!(alice["messages"].as_u64(), Some(messages));
    assert_eq!(alice["bytes"].as_u64(), Some(bytes));
    assert_eq!(
        (messages, bytes),
        (2, 300),
        "notes.txt is not a message on either side"
    );
}

/// Every metric this port emits, compared against the oracle's scrape.
///
/// Read through `collect` rather than by calling the underlying helpers: it is
/// what serves the endpoint, and comparing the helpers instead means a metric
/// wired to the wrong computation passes. (Found by mutation — replacing the
/// disk metric with a sum over accounts left an earlier version of this test
/// green, because it called `dir_bytes` directly.)
#[test]
fn every_metric_this_port_emits_matches_the_oracles() {
    let Some(o) = oracle() else { return };
    let (_, body, _) = o.get("/metrics");

    let go_value = |name: &str| -> Option<u64> {
        body.lines()
            .find(|l| l.starts_with(&format!("{name} ")) || l.starts_with(&format!("{name}{{")))
            .and_then(|l| l.rsplit(' ').next()?.parse::<f64>().ok())
            .map(|v| v as u64)
    };

    // The oracle writes DKIM keys and TLS certs during startup, so the tree is
    // larger than the seed — but both walk it at the same moment, and nothing
    // writes between the two reads.
    let ours = jmapserver::admin::collect(&o.data_dir(), "", "dev");

    let disk = ours
        .iter()
        .find(|m| m.name == "biset_data_disk_bytes")
        .expect("this port emits a disk metric");
    assert_eq!(
        disk.value,
        go_value("biset_data_disk_bytes").expect("the oracle emits one"),
        "biset_data_disk_bytes"
    );

    let build = ours
        .iter()
        .find(|m| m.name == "biset_build_info")
        .expect("this port emits build info");
    assert_eq!(
        build.value,
        go_value("biset_build_info").expect("the oracle emits one"),
        "biset_build_info is always 1"
    );
    assert!(
        body.contains(r#"version="dev""#),
        "and carries the version label: {body:.400}"
    );

    // Every metric name this port emits is one the oracle emits too, so a
    // metric invented here shows up rather than passing unnoticed.
    for metric in &ours {
        assert!(
            body.contains(metric.name),
            "{} is not a metric the oracle exports",
            metric.name
        );
    }
}

// ── the guard ─────────────────────────────────────────────────────────────

/// SPEC.md §11.13. The oracle runs with no ADMIN_TOKEN or METRICS_TOKEN, which
/// in Go means no check at all.
#[test]
fn the_oracle_serves_both_unauthenticated_and_this_port_does_not() {
    let Some(o) = oracle() else { return };
    for route in ["/admin/accounts", "/metrics"] {
        let (status, _, _) = o.get(route);
        assert_eq!(
            status, 200,
            "{route}: the oracle is expected to still serve this with no token \
             — if it no longer does, SPEC.md §11.13 is stale"
        );
    }
    assert_eq!(check("", ""), Bearer::Deny, "this port closes them");
    assert_eq!(check("", "Bearer anything"), Bearer::Deny);
}

/// The dashboard itself is the HTML shell, and needs no token — every call it
/// makes carries one.
#[test]
fn the_dashboard_shell_is_public_but_carries_no_data() {
    let Some(o) = oracle() else { return };
    let (status, body, _) = o.get("/admin/dashboard");
    assert_eq!(status, 200);
    assert!(body.contains("<!doctype html>") || body.contains("<!DOCTYPE html>"));
    assert!(
        !body.contains("alice@a.test"),
        "the shell must not embed account data: it is unauthenticated"
    );
}
