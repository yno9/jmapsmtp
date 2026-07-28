//! JMAP server library.
//!
//! Port of `github.com/yno9/go-jmapserver` @ `39a4d0e`. See PLAN.md §3 for the
//! file-by-file mapping and M3/M4/M7 for the porting order.
//!
//! This crate must not reference anything specific to the jmapsmtp binary: the
//! plan is to split it back out into its own repository once the ActivityPub
//! relay (go-jmapap) is ported too (PLAN.md §8-F-2).

pub mod store;

pub use store::{ChangeRecord, JsonObject, MailboxChangeRecord, Store};
