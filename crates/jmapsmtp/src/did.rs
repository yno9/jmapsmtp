//! DID-aware identity — the parts of this relay that exist only because an
//! account might be a `did:webvh` identity rather than a plain password.
//! This relay is a plain JMAP server first (§1 of `ARC.md`); everything
//! under this module is what "and did:webvh-aware" adds on top of that, and
//! nothing outside it depends on any of this.
//!
//! Gathered here (2026-08-18) from across the crate so this exact boundary is
//! one place to look — see `ARC.md` §2 for the design itself (identity
//! model, the credential chain, provisioning, aliasing, the anchor client),
//! this module is just where the code that implements it now lives.
//!
//! Not everything DID-shaped moved here. `jmapserver::did::devicekeys` and
//! `session_nonce` store a device's credential and a login nonce
//! respectively, and neither module's own code knows what a DID is — they
//! are generic mechanism the DID flow happens to be the only caller of
//! today, the same relationship `zbase32.rs`'s own header describes for WKD
//! and the (now-removed) did:dht method sharing one encoding. Filing
//! DID-agnostic code under DID because DID is its only current caller is
//! the mistake that module's history already warns against.

/// Backstop for `/account/alias` against each SCID-primary account's bound
/// DID. Anchor build only — same reasoning as `anchor` below: nothing to
/// reconcile against without one.
#[cfg(feature = "anchor")]
pub mod alias_reconcile;
/// The identity anchor client. Absent in the `--no-default-features` build,
/// which is this port's `go build -tags noanchor` — a relay with no anchor has
/// no client for one rather than a stub that could be reached by mistake.
#[cfg(feature = "anchor")]
pub mod anchor;
/// The DID-binding decision (`PUT /account/did`). Anchor build only — an
/// anchorless relay refuses a DID outright and never reaches this.
#[cfg(feature = "anchor")]
pub mod bind;
/// The DID credential chain at runtime: `/account/session/challenge`,
/// `/account/session` (login), `/account/devices` (vouch/list/revoke).
pub mod devices;
/// Who may create an account, and the DID vouch every creation requires.
pub mod provision;
/// The case-insensitive-safe, reversible SCID<->localpart projection
/// (ARC.md §2.9) — see its own header for why the SCID can't just be
/// lowercased.
pub mod scid_localpart;
/// Reading a `did:webvh` identifier's own segments, for `provision`'s
/// `authorized_did_domain` policy check.
pub mod webvh_id;
