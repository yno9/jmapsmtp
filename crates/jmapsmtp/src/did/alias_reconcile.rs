//! Reconciles a SCID-primary account's aliases against its bound DID's
//! CURRENT did:webvh identifier (PLANSCID.md; the reclaim work this pairs
//! with is anchor/webvh-server's same-SCID reclaim rule and webvh-sweep.ts's
//! TTL cleanup — this is that same "does the log still name this location"
//! question, asked on behalf of `/account/alias` instead of a did:webvh
//! host).
//!
//! # Why a sweep, when `/account/alias` already updates eagerly
//!
//! `edit-identity.ts`'s rename flow already calls `/account/alias` itself —
//! add the new address, then remove the old one — the moment a user renames.
//! This sweep is not that path's replacement, it is its backstop: that
//! removal is explicitly best-effort (its own `.catch(() => false)`), so a
//! crashed client, a dropped connection, or a race between two devices can
//! leave a stale alias behind with nothing left to clean it up. Before this
//! existed, that stale alias lived forever — anyone's *next* rename could
//! then legitimately claim it themselves (`add_alias` has never checked
//! whether an address belongs to someone else, jmapsmtp side), and there was
//! no path back.
//!
//! # What "reconciled" means
//!
//! For each SCID-primary account, the desired alias set is exactly ONE
//! address: whatever [`jmapserver::did::anchor::current_alias`] reports as the
//! bound DID's current username, on the condition that DID's current
//! did:webvh location is on THIS relay's own domain (2026-08-18,
//! user-decided — a DID whose location moved elsewhere gets NO alias here,
//! even though its mail account remains; the immutable SCID address is
//! untouched either way). Anything else present is removed; the one desired
//! address is added if missing.
//!
//! # Failure is silence, not deletion
//!
//! [`jmapserver::did::anchor::AliasLookup::Unknown`] (anchor unreachable, or its
//! answer didn't parse) and `NotBound` (no claim — a pre-SCID account, or one
//! that never bound a DID) both leave the account's aliases untouched this
//! cycle. Only a definite `Resolved` answer — even one that resolves to
//! "nothing" (deactivated) — ever removes an alias. An anchor outage must
//! never look like every renamed identity abandoning its address at once.
use std::sync::Arc;

use crate::server::RelayState;
use jmapserver::did::anchor::AliasLookup;

pub fn spawn_alias_reconcile(state: Arc<RelayState>) {
    let anchor = crate::did::anchor::anchor_ref(&state.cfg);
    if !anchor.is_configured() {
        return; // no anchor, no DIDs, nothing for this sweep to do
    }
    tokio::spawn(async move {
        // Same cadence as maintenance's inactive-account sweep
        // (2026-08-18, user-decided): this is not latency-sensitive, since
        // the eager `/account/alias` call already applies a rename
        // immediately — this only cleans up what that path left behind.
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(
            crate::maintenance::SWEEP_INTERVAL_SECS,
        ));
        // Skip the immediate first tick, same reasoning as
        // delivery::spawn_maintenance: a restart loop must not hammer the
        // anchor with a full reconcile pass every time it crashes, and an
        // operator gets one interval to notice a misconfiguration before
        // anything gets removed.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            reconcile_aliases(&state);
        }
    });
}

/// The one alias `localpart@domain` should have, or `None` (deactivated, or
/// its did:webvh location moved off `domain` entirely — either way, no
/// address here belongs to it any more).
///
/// Pure — no I/O, no `RelayState` — so this, the actual policy, is
/// unit-testable directly; [`reconcile_aliases`] is a thin loop applying it.
fn desired_alias(domain: &str, lookup: &AliasLookup) -> Option<String> {
    match lookup {
        AliasLookup::NotBound | AliasLookup::Unknown => {
            unreachable!("callers must skip NotBound/Unknown before asking for a desired alias — see reconcile_aliases")
        }
        AliasLookup::Resolved {
            username: Some(u),
            domain: Some(d),
        } if d == domain => Some(format!("{u}@{d}")),
        AliasLookup::Resolved { .. } => None,
    }
}

/// What to change, computed from the current alias set and the desired one —
/// the other pure half of the policy, so "which aliases get touched" is
/// tested without a live `Accounts` table.
fn plan(current: &[String], desired: Option<&str>) -> (Vec<String>, Option<String>) {
    let remove: Vec<String> = current
        .iter()
        .filter(|a| desired != Some(a.as_str()))
        .cloned()
        .collect();
    let add = desired
        .filter(|d| !current.iter().any(|a| a == d))
        .map(str::to_string);
    (remove, add)
}

/// One reconciliation pass over every account this relay serves. Public so
/// it can be driven directly (tests, or a manual trigger) rather than only
/// on the timer.
pub fn reconcile_aliases(state: &RelayState) {
    let anchor = crate::did::anchor::anchor_ref(&state.cfg);
    if !anchor.is_configured() {
        return;
    }
    for primary in state.accounts.primaries() {
        let Some((localpart, domain)) = primary.split_once('@') else {
            continue;
        };
        let lookup = jmapserver::did::anchor::current_alias(state.anchor.as_ref(), &anchor, localpart, domain);
        if matches!(lookup, AliasLookup::NotBound | AliasLookup::Unknown) {
            continue;
        }
        let desired = desired_alias(domain, &lookup);
        let current = state.accounts.aliases_for(&primary);
        let (remove, add) = plan(&current, desired.as_deref());
        if remove.is_empty() && add.is_none() {
            continue;
        }
        for alias in &remove {
            state.accounts.remove_alias(alias, &primary);
            println!("[alias-reconcile] removed stale alias {alias} for {primary}");
        }
        if let Some(want) = &add {
            state.accounts.add_alias(want, &primary);
            println!("[alias-reconcile] added alias {want} for {primary}");
        }
        // Best-effort persistence, same reasoning as the `/account/alias`
        // handler's own note: the live table (just updated above) is what
        // delivery and GET both read from; this file only feeds a restart's
        // `scan_dyn_accounts` reload, so a write failure here is "won't
        // survive a restart", not "the change didn't apply".
        let updated = state.accounts.aliases_for(&primary);
        if crate::auth_env::write_aliases(&state.data_dir, domain, localpart, &updated).is_err() {
            eprintln!(
                "[alias-reconcile] persisted alias list failed to write for {primary} — will not survive a restart"
            );
        }
    }
}

#[cfg(test)]
mod tests;
