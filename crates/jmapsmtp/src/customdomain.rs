//! Bring-your-own domain, and self-service account deletion. Port of
//! `go-jmapsmtp/customdomain.go` and the `/account/delete` handler.
//!
//! # Ownership is DNS control, re-proved every time
//!
//! A user brings `y.jp` to this relay without running a server themselves. The
//! proof is a TXT record: whoever can write a domain's records already controls
//! it, so the token's only job is to distinguish "an admin who read the
//! instructions and deliberately added this" from coincidence.
//!
//! Both tokens are **deterministic HMACs**, so there is no pending state to
//! store, expire or leak — the expected value is recomputable at any time from
//! the domain and the relay's secret.
//!
//! The re-proof is the part worth keeping: `/domain/add` re-checks the TXT
//! record **every time**, even for an already-registered domain, and a
//! registered domain is never marked `allow_provision`. Otherwise a single past
//! registration would let anyone create accounts under someone else's domain
//! forever, with no further proof.
//!
//! With no `domain_verify_secret` configured there is nothing to key the tokens
//! with, so neither route is mounted at all (see `routes.rs`).

use crate::config::{Config, DomainConfig};

/// A hostname that could plausibly be delegated: labels of 1-63 chars, a TLD of
/// at least two letters.
///
/// This string becomes a directory name under `data/_domains/` **and** a DNS
/// query, so it is checked rather than repaired — with one exception, case.
/// Both endpoints trim and lowercase before calling this, so `Example.com` is
/// accepted and registers `example.com`. The uppercase rejection here is
/// therefore unreachable from either route and exists for any other caller;
/// `an_uppercase_domain_is_folded_not_refused` pins which of the two behaviours
/// the endpoints actually have.
///
/// (Same shape as `provision::valid_username`. Worth noticing as a pattern:
/// a predicate that looks strict, behind a caller that normalises first.)
pub fn valid_custom_domain(domain: &str) -> bool {
    if domain.is_empty() || domain.len() > 253 {
        return false;
    }
    let Some((labels, tld)) = domain.rsplit_once('.') else {
        return false;
    };
    if tld.len() < 2 || !tld.bytes().all(|c| c.is_ascii_lowercase()) {
        return false;
    }
    !labels.is_empty()
        && labels.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
}

fn hmac_hex32(secret: &str, message: &str) -> String {
    use hmac::Mac as _;
    let mut mac = <hmac::Hmac<sha2::Sha256> as hmac::Mac>::new_from_slice(secret.as_bytes())
        .expect("HMAC accepts a key of any length");
    mac.update(message.as_bytes());
    let full: String = mac
        .finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    full[..32].to_string()
}

/// The TXT value proving control of `domain`.
///
/// Deterministic, so nothing is stored between the two steps of the flow.
pub fn verify_token(cfg: &Config, domain: &str) -> String {
    format!(
        "biset-verify={}",
        hmac_hex32(&cfg.domain_verify_secret, domain)
    )
}

/// Where that TXT record has to live.
pub fn verify_txt_name(domain: &str) -> String {
    format!("_biset-verify.{domain}")
}

/// The shared secret that gates account creation under a custom domain.
///
/// Re-issued to whoever currently controls the DNS on **every** completed
/// `/domain/add`, including for a domain already registered. That is what keeps
/// account creation tied to *current* control rather than to a one-time claim.
pub fn provision_secret_for(cfg: &Config, domain: &str) -> String {
    hmac_hex32(&cfg.domain_verify_secret, &format!("provision:{domain}"))
}

/// Whether a live TXT lookup proves ownership.
///
/// Split out from the endpoint so the decision is testable without DNS: the
/// caller supplies the records it found.
pub fn txt_proves_ownership(records: &[String], expected: &str) -> bool {
    records.iter().any(|r| r == expected)
}

/// The configuration a newly verified domain is registered with.
///
/// **Never `allow_provision`.** A verified domain is gated by the secret handed
/// back in the same response, so creating an account under it always needs
/// proof of current DNS control.
///
/// **No `authorized_did_domain` either**, and not because it would be wrong:
/// proving DNS control over `example.org` is a strictly stronger claim than
/// holding a DID rooted there, so the two would agree. It is left absent
/// because setting it would *replace* the secret gate rather than add to it
/// (see [`crate::did::provision::may_provision`]) — a domain verified minutes ago
/// would silently stop needing the proof it was just handed. Admitting
/// identities by home domain is an operator's decision about a domain they
/// configure, not something a verification flow may switch on by itself.
pub fn registered_domain_config(cfg: &Config, domain: &str) -> DomainConfig {
    DomainConfig {
        dkim_selector: crate::dkim::DEFAULT_SELECTOR.to_string(),
        accounts: Default::default(),
        allow_provision: false,
        provision_secret: provision_secret_for(cfg, domain),
        authorized_did_domain: None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainError {
    InvalidDomain,
    /// The TXT record is not (yet) visible.
    NotVerified,
    Unauthorized,
    /// A configured account cannot delete itself.
    ServerManaged,
}

impl DomainError {
    pub fn status(&self) -> u16 {
        match self {
            DomainError::InvalidDomain => 400,
            DomainError::Unauthorized => 401,
            DomainError::ServerManaged => 403,
            // 412, not 400: the request is well formed, a precondition on the
            // world is not met — and DNS propagation means "not yet" is the
            // common case, so the client should retry rather than rewrite it.
            DomainError::NotVerified => 412,
        }
    }

    pub fn message(&self) -> &'static str {
        match self {
            DomainError::InvalidDomain => "invalid domain",
            DomainError::NotVerified => {
                "verification TXT record not found (DNS propagation can take a \
                 few minutes — retry shortly)"
            }
            DomainError::Unauthorized => "unauthorized",
            DomainError::ServerManaged => {
                "this account is server-managed and can't be self-deleted"
            }
        }
    }
}

/// Whether the authenticated account may delete itself.
///
/// A **statically configured** account may not: it exists because the operator
/// put it in `config.json`, so removing its data would leave the config
/// pointing at nothing and the account would come back on the next start.
/// Dynamic accounts are the caller's own to remove.
pub fn may_self_delete(dom_cfg: Option<&DomainConfig>, localpart: &str) -> Result<(), DomainError> {
    match dom_cfg {
        Some(dc) if dc.accounts.contains_key(localpart) => Err(DomainError::ServerManaged),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests;
