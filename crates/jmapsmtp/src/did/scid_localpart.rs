//! The SCID<->localpart projection (ARC.md §2.9) — a lossless re-encoding of
//! a did:webvh SCID into a JMAP localpart that survives this relay's
//! pervasive `.to_lowercase()` folding (`handler.rs`'s `Accounts` map,
//! `auth_env.rs`'s `authenticate`/`DynAccounts`, and — the one that would
//! otherwise corrupt the identifier outright — `auth_env::account_dir`
//! building a real filesystem path from it, on a filesystem that may itself
//! be case-insensitive by default, macOS/Windows both).
//!
//! # Why not just lowercase the SCID
//!
//! A did:webvh SCID is base58btc (`did/webvh_id.rs`): of its 58 symbols, 46
//! pair up across case (`A`/`a`, `B`/`b`, …), so a 46-character SCID has on
//! the order of 36-37 case-ambiguous positions. Folding case collapses
//! roughly 2^36-37 distinct, independently valid SCIDs onto one lowercase
//! string — a birthday collision becomes reachable at a few hundred thousand
//! registered identities, nowhere near the SHA-256-class collision
//! resistance (`did/webvh_id.rs`'s own SCID discussion, ARC.md §2.1) the
//! identifier is supposed to carry.
//!
//! # Why decode-and-re-encode rather than hash again
//!
//! A SCID already IS `base58(multihash)` — re-encoding the SAME 34 raw bytes
//! (a 2-byte SHA-256 multihash prefix plus the 32-byte digest,
//! `multihash.ts`) in a case-insensitive-safe alphabet loses no entropy and
//! needs no extra hash pass. It is also REVERSIBLE — `from_localpart`
//! recovers the SCID with no registry lookup — which a one-way hash would
//! have given up for nothing: nothing about mail delivery needs the
//! projection to be one-way, and losing reversibility would only have made
//! `localpart@domain` -> "whose identity is this" a round trip to the anchor
//! that this costs nothing to avoid.
//!
//! Reversibility stops at the SCID, not the document: unlike `did:key`, a
//! did:webvh SCID carries no location information on its own, so recovering
//! it from a localpart does not by itself resolve anything — that still
//! needs one registry step (the anchor's `lookupByDid`, `store.ts`).
use jmapserver::{base58, zbase32};

/// did:webvh's SCID: a 2-byte SHA-256 multihash prefix plus the 32-byte
/// digest (`multihash.ts`). Fixed by the method itself (`did:webvh:1.0`
/// permits no other hash), not a detail of this projection.
const SCID_BYTES: usize = 34;

/// The SCID's own base58 form, re-encoded as a case-insensitive-safe JMAP
/// localpart. `None` when `scid` does not decode to exactly [`SCID_BYTES`]
/// bytes — not this relay's job to validate a SCID's shape beyond that
/// (`did/webvh_id.rs`'s own "loose about the SCID" stance); a caller with an
/// unreadable SCID has nothing to provision in the first place.
pub fn to_localpart(scid: &str) -> Option<String> {
    let bytes = base58::decode(scid)?;
    if bytes.len() != SCID_BYTES {
        return None;
    }
    Some(zbase32::encode(&bytes))
}

/// The inverse: recovers a SCID's own base58 form from a localpart this
/// module produced. `None` for anything that isn't exactly one of those —
/// a mistyped or foreign localpart is not a SCID to guess at.
pub fn from_localpart(localpart: &str) -> Option<String> {
    let bytes = zbase32::decode(localpart, SCID_BYTES)?;
    Some(base58::encode(&bytes))
}

#[cfg(test)]
mod tests;
