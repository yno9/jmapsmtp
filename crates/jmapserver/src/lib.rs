//! JMAP server library.
//!
//! Port of `github.com/yno9/go-jmapserver` @ `39a4d0e`. See PLAN.md §3 for the
//! file-by-file mapping and M3/M4/M7 for the porting order.
//!
//! This crate must not reference anything specific to the jmapsmtp binary: the
//! plan is to split it back out into its own repository once the ActivityPub
//! relay (go-jmapap) is ported too (PLAN.md §8-F-2).

pub mod activity;
pub mod admin;
pub mod anchor;
pub mod authtoken;
pub mod contacts;
pub mod devicekeys;
pub mod diddht;
pub mod dispatch;
pub mod methods;
pub mod mime;
pub mod push;
pub mod refs;
pub mod server;
pub mod storage;
pub mod store;

pub use authtoken::{decode_auth_token, hash_auth_token, verify_auth_token};
pub use devicekeys::DeviceKey;
pub use methods::{MethodError, MethodResult};
pub use mime::{Attachment, build_envelope, extract_attachments, message_body, parse_mime_email};
pub use server::{Account, AuthFn, Config, Handler, Hub, Server};
pub use store::{ChangeRecord, Hooks, JsonObject, MailboxChangeRecord, Store};
