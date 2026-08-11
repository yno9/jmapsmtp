//! Seeding one relay instance's directory.
//!
//! The guiding rule of this file: **prefer seeding determinism over
//! normalising it away afterwards.** Every file seeded here is one fewer
//! filter in `normalize.rs`, and every filter there is a place a real
//! behavioural difference could hide. The relay generates a random DKIM key,
//! a random self-signed TLS cert and a random setup token on first boot; left
//! alone, all three differ between the two sides and force filters that would
//! also mask a genuine bug in key handling. So they are seeded instead.
//!
//! The same reasoning drives `base_url`: both sides get the identical
//! `base_url` while binding different `listen_addr`, because the JMAP Session
//! response echoes `base_url` into `apiUrl`/`downloadUrl`/`uploadUrl`
//! (go-jmapserver server.go:311). Different ports there would mean filtering
//! URLs — and then a wrong URL would pass unnoticed.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use serde_json::json;

/// The account every scenario step authenticates as.
pub const ACCOUNT: &str = "alice@example.com";
pub const DOMAIN: &str = "example.com";
pub const LOCALPART: &str = "alice";

/// The raw auth token. `auth_token_hash` on disk is base64(sha256(this)), and
/// the Basic Auth password is base64(this) — see go-jmapsmtp/auth_env.go.
pub const AUTH_TOKEN: &[u8] = b"difftest-token-0000000000000000";

/// Seeded rather than generated, so both sides agree. Sizes are irrelevant —
/// these exist only to be identical.
const DKIM_KEY: &str = include_str!("../../fixtures/dkim-key.pem");
const TLS_CERT: &str = include_str!("../../fixtures/smtp-tls-cert.pem");
const TLS_KEY: &str = include_str!("../../fixtures/smtp-tls-key.pem");

/// A fixed setup token. The relay writes a random one at startup for any
/// account with no envelope; seeding it keeps `data/` comparable and lets a
/// scenario step exercise `/setup?token=` with a known value.
pub const SETUP_TOKEN: &str = "0123456789abcdef0123456789abcdef";

/// Everything one side of the comparison needs to run.
pub struct Instance {
    /// The directory the relay binary is copied into. The Go implementation
    /// derives both `config.json` and `data/` from its own argv[0] directory
    /// (main.go's `filepath.Abs(filepath.Dir(os.Args[0]))`), so each side
    /// needs its own copy of the binary rather than a shared one.
    pub dir: std::path::PathBuf,
    pub http_port: u16,
    pub smtp_port: u16,
}

impl Instance {
    pub fn base_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.http_port)
    }
    pub fn data_dir(&self) -> std::path::PathBuf {
        self.dir.join("data")
    }
}

/// A deliberate corruption of one side, used by `difftest --self-test`.
///
/// A harness that cannot fail is worse than no harness: it reports success
/// for work it never checked. Each variant perturbs a different comparison
/// axis, so the self-test proves all of them are live rather than just one.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mutation {
    /// Changes a config value echoed in a response body (`/relay-info`).
    RelayLabel,
    /// Changes a value echoed in the JMAP Session response and nowhere else.
    BaseUrl,
    /// Adds a file to `data/` that the other side will not have.
    ExtraDataFile,
    /// Removes the seeded credential, so every authenticated step 401s.
    BreakCredential,
}

pub const ALL_MUTATIONS: &[Mutation] = &[
    Mutation::RelayLabel,
    Mutation::BaseUrl,
    Mutation::ExtraDataFile,
    Mutation::BreakCredential,
];

/// Write `config.json` and a fully populated `data/` into `inst.dir`.
///
/// `mutation` is `None` for every real run; `Some` only under `--self-test`.
pub fn seed_mutated(inst: &Instance, binary: &Path, mutation: Option<Mutation>) -> Result<()> {
    let dir = &inst.dir;
    if dir.exists() {
        fs::remove_dir_all(dir).with_context(|| format!("clearing {}", dir.display()))?;
    }
    fs::create_dir_all(dir)?;

    // The relay resolves its own directory from argv[0], so the binary has to
    // live here, not be run from elsewhere.
    let dest = dir.join("jmapsmtp");
    fs::copy(binary, &dest).with_context(|| format!("copying {}", binary.display()))?;
    set_executable(&dest)?;

    write_config(inst, mutation)?;
    seed_data(inst, mutation)?;
    Ok(())
}

fn write_config(inst: &Instance, mutation: Option<Mutation>) -> Result<()> {
    // Identical on both sides except the two ports. Notably `base_url` does
    // NOT track http_port — see this module's header.
    let base_url = if mutation == Some(Mutation::BaseUrl) {
        "http://mutated.difftest.invalid"
    } else {
        "http://relay.difftest.invalid"
    };
    let relay_label = if mutation == Some(Mutation::RelayLabel) {
        "Mutated"
    } else {
        "Mail"
    };
    let cfg = json!({
        "listen_addr": format!("127.0.0.1:{}", inst.http_port),
        "base_url": base_url,
        "hostname": "mail.example.com",
        "smtp_port": inst.smtp_port,
        "relay_host": "",
        // Anchorless. An anchored run would need a mock anchor on a third
        // port; that is M6's problem, and the anchorless refusal paths are
        // themselves worth diffing (anchorless_test.go covers the same).
        "anchor_url": "",
        "relay_label": relay_label,
        "relay_color": "#64748b",
        "reply_only_outbound": false,
        "max_account_storage_mb": 0,
        "inactive_purge_days": 0,
        "domain": {
            DOMAIN: {
                "dkim_selector": "default",
                "account": {
                    LOCALPART: { "alias": ["a"] }
                }
            }
        }
    });
    let path = inst.dir.join("config.json");
    fs::write(&path, format!("{}\n", serde_json::to_string_pretty(&cfg)?))
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

fn seed_data(inst: &Instance, mutation: Option<Mutation>) -> Result<()> {
    let data = inst.data_dir();
    let domain_dir = data.join(DOMAIN);
    let acct_dir = domain_dir.join(LOCALPART);
    fs::create_dir_all(&acct_dir)?;

    // Pre-seeded so neither side generates its own (main.go's
    // loadInboundTLS / dkim.go's loadOrGenerateDKIMKey are both
    // load-or-create, so a file that exists is left alone).
    fs::write(data.join("smtp-tls-cert.pem"), TLS_CERT)?;
    fs::write(data.join("smtp-tls-key.pem"), TLS_KEY)?;
    fs::write(domain_dir.join("key.pem"), DKIM_KEY)?;

    // The relay writes this itself at startup for an account with no
    // envelope; seeding it fixes the value instead of leaving it random.
    fs::write(acct_dir.join("setup.token"), SETUP_TOKEN)?;

    // The credential every authenticated scenario step presents.
    if mutation != Some(Mutation::BreakCredential) {
        fs::write(
            acct_dir.join("auth_token_hash"),
            auth_token_hash(AUTH_TOKEN),
        )?;
    }

    if mutation == Some(Mutation::ExtraDataFile) {
        fs::write(acct_dir.join("difftest-extra-file"), "mutation\n")?;
    }

    Ok(())
}

/// base64(sha256(token)) — go-jmapserver/authtoken.go's `HashAuthToken`.
fn auth_token_hash(token: &[u8]) -> String {
    use base64::Engine as _;
    use sha2::{Digest, Sha256};
    let sum = Sha256::digest(token);
    base64::engine::general_purpose::STANDARD.encode(sum)
}

/// base64(token) — what goes in the Basic Auth password field.
pub fn basic_auth_password() -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(AUTH_TOKEN)
}

#[cfg(unix)]
fn set_executable(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(0o755);
    fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(not(unix))]
fn set_executable(_path: &Path) -> Result<()> {
    Ok(())
}
