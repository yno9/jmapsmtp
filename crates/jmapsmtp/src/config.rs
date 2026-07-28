//! `config.json`. Port of the config types in `go-jmapsmtp/main.go` and
//! `customdomain.go`.
//!
//! The schema is unchanged from the Go implementation so an existing
//! deployment's file loads as it stands (PLAN.md §5.1). Unknown fields are
//! ignored rather than rejected, matching Go, so a config written for a newer
//! build still starts.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

/// One account declared in the config file.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountConfig {
    /// Extra addresses delivered to this account. An entry with no `@` is
    /// completed with the domain it sits under.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub alias: Vec<String>,
}

/// One domain, static or dynamically registered.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainConfig {
    #[serde(default, rename = "dkim_selector")]
    pub dkim_selector: String,
    #[serde(default, rename = "account")]
    pub accounts: BTreeMap<String, AccountConfig>,
    /// Open self-service registration.
    #[serde(default, rename = "allow_provision")]
    pub allow_provision: bool,
    /// Gated registration: creation needs this shared secret. One or the
    /// other, never both — a privileged domain is not creatable from the UI.
    #[serde(
        default,
        rename = "provision_secret",
        skip_serializing_if = "String::is_empty"
    )]
    pub provision_secret: String,
}

impl DomainConfig {
    /// The DKIM selector, defaulting to `default` when unset.
    pub fn selector(&self) -> &str {
        if self.dkim_selector.is_empty() {
            crate::dkim::DEFAULT_SELECTOR
        } else {
            &self.dkim_selector
        }
    }
}

/// The whole of `config.json`.
///
/// The JMAP server's own settings are flattened in, as the Go original embeds
/// `jmapserver.Config`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Config {
    #[serde(default, rename = "listen_addr")]
    pub listen_addr: String,
    #[serde(default, rename = "base_url")]
    pub base_url: String,
    /// A single global JMAP password. Superseded by per-account credentials
    /// and kept only because the Go config still carries it.
    #[serde(default)]
    pub password: String,
    #[serde(default, rename = "vapid_public_key")]
    pub vapid_public_key: String,
    #[serde(default, rename = "vapid_private_key")]
    pub vapid_private_key: String,
    #[serde(default, rename = "vapid_subscriber")]
    pub vapid_subscriber: String,

    /// The SMTP EHLO name and the right-hand side of generated Message-IDs.
    #[serde(default)]
    pub hostname: String,
    #[serde(default, rename = "smtp_port")]
    pub smtp_port: u16,
    /// A fixed smarthost. Empty means direct delivery by MX lookup.
    #[serde(default, rename = "relay_host")]
    pub relay_host: String,
    #[serde(default, rename = "smtp_tls_cert")]
    pub tls_cert_file: String,
    #[serde(default, rename = "smtp_tls_key")]
    pub tls_key_file: String,

    #[serde(default, rename = "domain")]
    pub domains: BTreeMap<String, DomainConfig>,

    #[serde(default, rename = "relay_label")]
    pub relay_label: String,
    #[serde(default, rename = "relay_color")]
    pub relay_color: String,

    /// The identity anchor this relay defers every DID question to.
    ///
    /// **This is the whole opt-in.** Set means the relay serves DID
    /// identities; empty means anchorless — and anchorless is the *stricter*
    /// mode, not the laxer one: an account carrying a DID is refused, because
    /// the proof is checked by the anchor and there is nobody to check it.
    /// Plain JMAP accounts behave identically either way.
    #[serde(default, rename = "anchor_url")]
    pub anchor_url: String,
    /// The secret proving this relay may write to the anchor. **Required**
    /// whenever `anchor_url` is set — startup refuses without it. The anchor
    /// sits on the public internet because its mediator must; unauthenticated
    /// writes would let anyone claim a name nobody holds, or take one that
    /// somebody does.
    #[serde(default, rename = "anchor_token")]
    pub anchor_token: String,

    /// Block outbound mail unless every recipient has previously written to
    /// the sender.
    #[serde(default, rename = "reply_only_outbound")]
    pub reply_only_outbound: bool,
    /// Domains or full addresses exempt from the check above.
    #[serde(default, rename = "reply_only_exempt")]
    pub reply_only_exempt: Vec<String>,

    /// Per-account disk cap in megabytes. 0 is unlimited.
    #[serde(default, rename = "max_account_storage_mb")]
    pub max_account_storage_mb: u64,
    /// Remove accounts on open domains idle this many days. 0 disables it.
    #[serde(default, rename = "inactive_purge_days")]
    pub inactive_purge_days: u64,
    /// Sibling relay data directories consulted before purging. An account is
    /// removed only when every peer agrees it is idle.
    #[serde(default, rename = "peer_data_dirs")]
    pub peer_data_dirs: Vec<String>,

    /// Keys the deterministic ownership token for BYO domains. Empty disables
    /// custom-domain onboarding entirely.
    #[serde(default, rename = "domain_verify_secret")]
    pub domain_verify_secret: String,

    /// **Not in the Go config.** Writes every received and sent message to
    /// `/tmp/jmapsmtp-last-{in,out}.eml`. The Go implementation does this
    /// unconditionally; here it is off unless asked for, because those files
    /// hold plaintext mail. SPEC.md §11.1.
    #[serde(default, rename = "debug_dump_eml")]
    pub debug_dump_eml: bool,
}

#[derive(Debug)]
pub enum ConfigError {
    Read(std::io::Error),
    Parse(String),
    NoDomains,
    AnchorTokenMissing,
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Read(e) => write!(f, "config: {e}"),
            ConfigError::Parse(m) => write!(f, "config: {m}"),
            ConfigError::NoDomains => f.write_str("config: no domains defined"),
            ConfigError::AnchorTokenMissing => f.write_str(
                "config: anchor_url is set but anchor_token is empty — the anchor's \
                 writes would be unauthenticated (set it to the anchor's relay_token)",
            ),
        }
    }
}

impl Config {
    /// Read and validate `config.json`.
    pub fn load(path: &Path) -> Result<Config, ConfigError> {
        let bytes = std::fs::read(path).map_err(ConfigError::Read)?;
        let cfg: Config =
            serde_json::from_slice(&bytes).map_err(|e| ConfigError::Parse(e.to_string()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// The two checks the Go implementation makes at startup, in its order.
    ///
    /// The anchor check has deliberately no "warn and carry on": an anchor
    /// whose writes are unauthenticated lets anyone on the internet claim an
    /// unheld name, or release someone else's and take it, DNS record and all.
    /// A silent fallback would be a quiet security degradation.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.domains.is_empty() {
            return Err(ConfigError::NoDomains);
        }
        if cfg!(feature = "anchor") && !self.anchor_url.is_empty() && self.anchor_token.is_empty() {
            return Err(ConfigError::AnchorTokenMissing);
        }
        Ok(())
    }

    /// The JMAP listen address, with the Go default.
    ///
    /// Note this is `8765`, not the `8767` in `config.example.json` — the
    /// example sets it explicitly and the default is never reached in a real
    /// deployment.
    pub fn listen_addr(&self) -> &str {
        if self.listen_addr.is_empty() {
            "0.0.0.0:8765"
        } else {
            &self.listen_addr
        }
    }

    pub fn smtp_port(&self) -> u16 {
        if self.smtp_port == 0 {
            25
        } else {
            self.smtp_port
        }
    }

    pub fn relay_label(&self) -> &str {
        if self.relay_label.is_empty() {
            "Mail"
        } else {
            &self.relay_label
        }
    }

    pub fn relay_color(&self) -> &str {
        if self.relay_color.is_empty() {
            "#64748b"
        } else {
            &self.relay_color
        }
    }

    /// The single domain open to self-service registration, if any.
    ///
    /// Go picks one by ranging over a map, so with more than one
    /// `allow_provision` domain its answer varies between runs. Sorted order
    /// makes the choice reproducible; a config with two open domains was
    /// always a mistake, and now at least it is a consistent one.
    pub fn provision_domain(&self) -> Option<&str> {
        self.domains
            .iter()
            .find(|(_, d)| d.allow_provision)
            .map(|(name, _)| name.as_str())
    }

    /// Whether a sender bypasses `reply_only_outbound`, by full address or by
    /// domain.
    ///
    /// The `!domain.is_empty()` guard has no effect on any reachable input —
    /// the only caller builds `localpart@domain` — but without it a stray
    /// empty entry in the list would match every sender that has no `@`.
    pub fn reply_only_exempt(&self, sender: &str) -> bool {
        let sender = sender.to_lowercase();
        let domain = sender.rsplit_once('@').map(|(_, d)| d).unwrap_or("");
        self.reply_only_exempt
            .iter()
            .map(|e| e.trim().to_lowercase())
            .any(|e| e == sender || (!domain.is_empty() && e == domain))
    }

    /// The JMAP server's own configuration, extracted from this one.
    pub fn server_config(&self) -> jmapserver::Config {
        jmapserver::Config {
            listen_addr: self.listen_addr.clone(),
            password: self.password.clone(),
            base_url: self.base_url.clone(),
            vapid_public_key: self.vapid_public_key.clone(),
            vapid_private_key: self.vapid_private_key.clone(),
            vapid_subscriber: self.vapid_subscriber.clone(),
        }
    }
}

/// Domains registered at runtime through the BYO-domain flow, alongside the
/// static ones.
///
/// Kept separate from [`Config`] because it changes while the relay runs:
/// `POST /domain/add` adds to it without a restart.
#[derive(Default)]
pub struct DynamicDomains(RwLock<BTreeMap<String, DomainConfig>>);

impl DynamicDomains {
    pub fn insert(&self, domain: String, cfg: DomainConfig) {
        self.0.write().insert(domain, cfg);
    }

    pub fn get(&self, domain: &str) -> Option<DomainConfig> {
        self.0.read().get(domain).cloned()
    }

    pub fn names(&self) -> Vec<String> {
        self.0.read().keys().cloned().collect()
    }

    /// Restore the registry from `data/_domains/`, so a restart does not
    /// require re-verification.
    pub fn load(&self, data_dir: &Path) {
        let Ok(entries) = std::fs::read_dir(data_dir.join("_domains")) else {
            return;
        };
        for entry in entries.flatten() {
            if !entry.path().is_dir() {
                continue;
            }
            let domain = entry.file_name().to_string_lossy().into_owned();
            let Ok(bytes) = std::fs::read(entry.path().join("domain.json")) else {
                continue;
            };
            if let Ok(cfg) = serde_json::from_slice::<DomainConfig>(&bytes) {
                self.insert(domain, cfg);
            }
        }
    }
}

/// Resolve a domain against the static config first, then the dynamic
/// registry — the single lookup every domain-gated path should use.
pub fn domain_config(cfg: &Config, dynamic: &DynamicDomains, domain: &str) -> Option<DomainConfig> {
    cfg.domains
        .get(domain)
        .cloned()
        .or_else(|| dynamic.get(domain))
}

/// Everything the relay carries for the life of the process.
pub struct Relay {
    pub cfg: Config,
    pub dir: std::path::PathBuf,
    pub data_dir: std::path::PathBuf,
    pub dynamic_domains: DynamicDomains,
}

impl Relay {
    pub fn new(cfg: Config, dir: std::path::PathBuf) -> Arc<Relay> {
        let data_dir = dir.join("data");
        Arc::new(Relay {
            cfg,
            dir,
            data_dir,
            dynamic_domains: DynamicDomains::default(),
        })
    }

    /// The directory holding one account's data.
    pub fn account_dir(&self, domain: &str, localpart: &str) -> std::path::PathBuf {
        self.data_dir.join(domain).join(localpart)
    }

    pub fn domain_config(&self, domain: &str) -> Option<DomainConfig> {
        domain_config(&self.cfg, &self.dynamic_domains, domain)
    }
}

#[cfg(test)]
mod tests;
