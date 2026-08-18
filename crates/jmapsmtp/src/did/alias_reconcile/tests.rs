//! The pure reconciliation policy — `desired_alias`/`plan` — independent of
//! `RelayState`, the anchor transport, or disk I/O. `reconcile_aliases`
//! itself is a thin loop applying these; it is exercised end-to-end by
//! `tests/` interop coverage instead of here, the same split the codebase
//! uses elsewhere between pure policy (unit-tested) and I/O-touching
//! handlers (interop-tested).

use super::*;
use pretty_assertions::assert_eq;

fn resolved(username: Option<&str>, domain: Option<&str>) -> AliasLookup {
    AliasLookup::Resolved {
        username: username.map(str::to_string),
        domain: domain.map(str::to_string),
    }
}

/// A relay administering two domains — `desired_alias`'s job is membership
/// in this whole set, never just one of them.
fn cfg(json: &str) -> Config {
    serde_json::from_str(json).expect("config should parse")
}
fn administering(domains: &[&str]) -> Config {
    let doms: std::collections::BTreeMap<&str, serde_json::Value> =
        domains.iter().map(|d| (*d, serde_json::json!({}))).collect();
    cfg(&serde_json::json!({ "domain": doms }).to_string())
}

// ── desired_alias ────────────────────────────────────────────────────────

#[test]
fn a_did_currently_on_this_domain_names_its_alias() {
    assert_eq!(
        desired_alias(&administering(&["a.test"]), &resolved(Some("y"), Some("a.test"))),
        Some("y@a.test".to_string())
    );
}

/// User-decided (2026-08-18): a DID whose did:webvh location is on a domain
/// this relay does not administer AT ALL gets no alias here, even though its
/// mail account (the immutable scid@domain primary) is untouched.
#[test]
fn a_did_on_an_unadministered_domain_gets_no_alias_here() {
    assert_eq!(
        desired_alias(&administering(&["a.test"]), &resolved(Some("y"), Some("b.test"))),
        None
    );
}

/// ARC.md §2.9: a relay administering MULTIPLE domains grants the alias on
/// whichever one the DID's current location actually names — even when that
/// is NOT the domain the primary being reconciled happens to sit under. This
/// is the whole reason `desired_alias` takes the full `Config`, not one
/// domain string.
#[test]
fn a_did_on_any_administered_domain_gets_its_alias_there() {
    let cfg = administering(&["a.test", "b.test"]);
    assert_eq!(
        desired_alias(&cfg, &resolved(Some("y"), Some("a.test"))),
        Some("y@a.test".to_string())
    );
    assert_eq!(
        desired_alias(&cfg, &resolved(Some("y"), Some("b.test"))),
        Some("y@b.test".to_string()),
        "b.test is administered too, even if the primary being reconciled sits on a.test"
    );
}

/// Deactivated — `Resolved` with both fields `None` — means the same as
/// "on an unadministered domain": nothing here belongs to it any more.
#[test]
fn a_deactivated_did_wants_no_alias() {
    assert_eq!(desired_alias(&administering(&["a.test"]), &resolved(None, None)), None);
}

// ── plan ────────────────────────────────────────────────────────────────

#[test]
fn a_fresh_claim_is_added_and_nothing_is_removed() {
    let (remove, add) = plan(&[], Some("y@a.test"));
    assert!(remove.is_empty());
    assert_eq!(add, Some("y@a.test".to_string()));
}

#[test]
fn an_already_correct_alias_changes_nothing() {
    let (remove, add) = plan(&["y@a.test".to_string()], Some("y@a.test"));
    assert!(remove.is_empty());
    assert_eq!(add, None, "already present — adding it again would be a no-op write");
}

/// The core case this whole module exists for: a rename left `old@a.test`
/// behind (client-side remove failed, or the client crashed mid-rename), and
/// the DID now names `new@a.test`.
#[test]
fn a_stale_alias_is_replaced_by_the_current_one() {
    let (remove, add) = plan(&["old@a.test".to_string()], Some("new@a.test"));
    assert_eq!(remove, vec!["old@a.test".to_string()]);
    assert_eq!(add, Some("new@a.test".to_string()));
}

/// A `None` desired alias (deactivated, or moved to another domain) clears
/// every alias currently on file, adding nothing back.
#[test]
fn no_desired_alias_removes_everything_and_adds_nothing() {
    let (remove, add) = plan(&["old@a.test".to_string(), "older@a.test".to_string()], None);
    assert_eq!(remove.len(), 2);
    assert_eq!(add, None);
}

/// More than one stale alias can accumulate (two renames, both of whose
/// client-side removals failed) — all of them go, not just the first.
#[test]
fn every_stale_alias_is_removed_not_just_one() {
    let (remove, add) = plan(
        &["a@x.test".to_string(), "b@x.test".to_string(), "c@x.test".to_string()],
        Some("c@x.test"),
    );
    assert_eq!(remove, vec!["a@x.test".to_string(), "b@x.test".to_string()]);
    assert_eq!(add, None, "c@x.test is already present");
}
