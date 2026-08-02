//! SMTP <-> JMAP bridge.
//!
//! Port of `github.com/yno9/go-jmapsmtp` @ `1b5cf06`. See PLAN.md.
//!
//! The binary is a thin `main` over this library, so the integration tests can
//! drive the same modules the relay runs.

/// Overridable at build time, as Go's `-ldflags "-X main.version=…"` is.
/// Reported by /admin/accounts and the build-info metric.
pub const VERSION: &str = match option_env!("JMAPSMTP_VERSION") {
    Some(v) => v,
    None => "dev",
};

pub mod auth_env;
pub mod autocrypt;
pub mod bearer;
pub mod config;
pub mod customdomain;
pub mod delivery;
pub mod devices;
pub mod dkim;
pub mod dns;
pub mod gomux;
pub mod handler;
pub mod hooks;
pub mod maintenance;
pub mod pgp;
pub mod provision;
pub mod routes;
pub mod server;
pub mod setup;
pub mod setup_page;
pub mod smtp_in;
pub mod smtp_out;
pub mod startup;
pub mod wkd;

/// Write a file only its owner can read.
///
/// Every file this crate creates holds either a private key, a credential, or
/// plaintext mail, so the mode is applied at creation rather than with a
/// `chmod` afterwards — the gap between the two is a window where the file is
/// world-readable.
pub(crate) fn write_private(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    opts.open(path)?.write_all(bytes)
}
