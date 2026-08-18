//! DID-aware identity — the parts of this crate that exist only because an
//! account might be a `did:webvh` identity rather than a plain password.
//! Nothing else in the crate depends on any of this; a consumer that never
//! touches `did::*` gets a plain JMAP server (store, methods, MIME, push,
//! contacts — see the crate root).
//!
//! Gathered under one module (2026-08-18) so this boundary — generic JMAP
//! server versus what did:webvh adds on top — is one place to look, not four
//! file headers each independently explaining the same split.
pub mod anchor;
pub mod devicebind;
pub mod devicekeys;
pub mod session_nonce;
