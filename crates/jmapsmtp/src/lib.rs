//! SMTP <-> JMAP bridge.
//!
//! Port of `github.com/yno9/go-jmapsmtp` @ `1b5cf06`. See PLAN.md.
//!
//! The binary is a thin `main` over this library, so the integration tests can
//! drive the same modules the relay runs.

pub mod autocrypt;
pub mod dkim;
