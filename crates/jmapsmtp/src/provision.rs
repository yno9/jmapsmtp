//! `POST /account/provision` — where an identity becomes an account.
//! Port of `go-jmapsmtp/provision.go`.
//!
//! # The DID is the identity
//!
//! An account is not created by choosing a password. It is created by a DID
//! proving it controls itself and vouching for one device, and **that device's
//! key is the credential** — there is no `auth_token_hash` in this flow at all.
//! The address is a routing label the DID holds a claim on (SPEC.md §10-A).
//!
//! Two consequences that shape the code below:
//!
//! - **An account can never exist without a working device credential.** The
//!   vouch is verified and written before the account is registered, so there
//!   is no "create now, add a device later" gap for someone else to walk into.
//! - **The relay stores no DID.** Which addresses trace back to which identity
//!   is cross-relay information the anchor derives from the claim. A local copy
//!   is what drifted out of step with the registry before.
//!
//! # `did:dht` and `did:webvh` are not interchangeable
//!
//! A `did:dht` identifier *is* its root public key, so a vouch verifies with
//! no network at all — an anchorless relay can serve those. A `did:webvh`
//! SCID is a hash of the identity's genesis log entry, not a key, so only the
//! anchor can resolve one. An anchorless relay therefore **cannot** create a
//! `did:webvh` account, and says so rather than pretending.
//!
//! This module is the decision logic with no HTTP and no I/O in it, so every
//! branch below is reachable from a test.

use crate::config::{Config, DomainConfig, DynamicDomains};

/// The request body. Field names are the JSON contract with biset's client.
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct ProvisionRequest {
    #[serde(default)]
    pub username: String,
    /// The target domain. Empty means the one open domain, if there is one.
    #[serde(default)]
    pub domain: String,
    #[serde(default)]
    pub did: String,
    #[serde(default, rename = "bind_ts")]
    pub bind_ts: i64,
    #[serde(default, rename = "did_sig")]
    pub did_sig: String,
    #[serde(default, rename = "device_pub_key")]
    pub device_pub_key: String,
    #[serde(default, rename = "device_label")]
    pub device_label: String,
    #[serde(default, rename = "device_vouch_ts")]
    pub device_vouch_ts: i64,
    #[serde(default, rename = "device_vouch_sig")]
    pub device_vouch_sig: String,
    /// Required for a domain gated by a shared secret.
    #[serde(default, rename = "provision_secret")]
    pub provision_secret: String,
    /// The wrapped master secret. **Optional and unrelated to login** — an own
    /// relay keeps it so the user can recover their master secret, a
    /// third-party relay is not given it.
    #[serde(default)]
    pub envelope: Option<serde_json::Value>,
}

/// Why a request was refused. Each carries the status and message the Go
/// handler sends, because a client distinguishes them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    InvalidUsername,
    DeviceCredentialRequired,
    DidRequired,
    DidSigRequired,
    UnknownDomain,
    /// No domain is open to self-service registration.
    NotAvailable,
    /// The domain exists but is gated, and the secret was absent or wrong.
    DomainNotOpen,
    UsernameTaken,
    /// The DID proof was rejected by the anchor.
    DidBindingRejected,
    /// The name belongs to a different identity.
    IdentityOwnedByAnother,
    AnchorUnavailable,
    /// The vouch did not verify.
    DeviceVouchRejected,
    /// The DID's method needs an anchor and this relay has none. Distinct from
    /// [`Refusal::DeviceVouchRejected`] because the client can act on it: the
    /// vouch was fine, the *relay* cannot check it.
    DidMethodNeedsAnchor,
    /// The domain accepts identities from a list of `did:webvh` home domains
    /// and this DID is not rooted at one of them.
    DidDomainNotAuthorized,
    /// The DID is rooted at an authorized domain, but is asking for a
    /// localpart other than its own name. See [`did_domain_gate`].
    DidUsernameMismatch,
    /// The DID could not be read as a `did:webvh` identifier at all, on a
    /// domain that admits identities by their home domain — so there is no
    /// home domain to check. Separate from the two above because it is a
    /// malformed request rather than a refused one.
    DidNotReadable,
}

impl Refusal {
    /// The HTTP status the Go handler answers with.
    pub fn status(&self) -> u16 {
        match self {
            Refusal::InvalidUsername
            | Refusal::DeviceCredentialRequired
            | Refusal::DidRequired
            | Refusal::DidSigRequired
            | Refusal::UnknownDomain => 400,
            Refusal::DidNotReadable => 400,
            Refusal::NotAvailable
            | Refusal::DomainNotOpen
            | Refusal::DidDomainNotAuthorized
            | Refusal::DidUsernameMismatch => 403,
            Refusal::DidBindingRejected
            | Refusal::DeviceVouchRejected
            | Refusal::DidMethodNeedsAnchor => 401,
            Refusal::UsernameTaken | Refusal::IdentityOwnedByAnother => 409,
            Refusal::AnchorUnavailable => 503,
        }
    }

    pub fn message(&self) -> &'static str {
        match self {
            Refusal::InvalidUsername => "invalid username",
            Refusal::DeviceCredentialRequired => "device_pub_key and device_vouch_sig required",
            Refusal::DidRequired => "did required",
            Refusal::DidSigRequired => "did_sig required when did is present",
            Refusal::UnknownDomain => "unknown domain",
            Refusal::NotAvailable => "account creation not available",
            Refusal::DomainNotOpen => "domain not open for provisioning",
            Refusal::DidNotReadable => "did is not a readable did:webvh identifier",
            Refusal::DidDomainNotAuthorized => {
                "this domain does not accept identities from that did's domain"
            }
            Refusal::DidUsernameMismatch => "username must match the did's own name",
            Refusal::UsernameTaken => "username taken",
            Refusal::DidBindingRejected => "did binding rejected",
            Refusal::IdentityOwnedByAnother => "identity owned by a different key",
            Refusal::AnchorUnavailable => "identity anchor unavailable",
            Refusal::DeviceVouchRejected => "device vouch rejected",
            Refusal::DidMethodNeedsAnchor => {
                "this DID method needs an identity anchor, and this relay has none configured"
            }
        }
    }
}

/// A username is a mail localpart *and* a filesystem directory name, so the
/// character set is deliberately narrow: `^[a-z0-9][a-z0-9_-]{0,30}$`.
///
/// Checked rather than sanitised, with one exception: [`validate`] folds the
/// name to lowercase *before* calling this, so `Alice` is accepted and becomes
/// `alice`. Case is the only transformation — anything else that would need
/// mangling to become legal is refused, because a mangled name is a different
/// name than the one the DID signed for.
///
/// The uppercase rejection here is therefore unreachable through `validate`.
/// It stays for any other caller, and
/// `an_uppercase_username_is_folded_not_refused` pins which of the two
/// behaviours the endpoint actually has.
pub fn valid_username(name: &str) -> bool {
    let b = name.as_bytes();
    if b.is_empty() || b.len() > 31 {
        return false;
    }
    let first_ok = b[0].is_ascii_lowercase() || b[0].is_ascii_digit();
    first_ok
        && b[1..]
            .iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_' || *c == b'-')
}

/// Which domain the request lands on, and its configuration.
pub fn resolve_domain(
    cfg: &Config,
    dynamic_domains: &DynamicDomains,
    requested: &str,
) -> Result<(String, DomainConfig), Refusal> {
    let requested = requested.trim().to_lowercase();
    if !requested.is_empty() {
        // A named domain must exist. Falling back to the open one here would
        // put the account somewhere the client did not ask for, under a name
        // the DID signed against a different domain.
        let dom_cfg = crate::config::domain_config(cfg, dynamic_domains, &requested)
            .ok_or(Refusal::UnknownDomain)?;
        return Ok((requested, dom_cfg));
    }
    let domain = cfg.provision_domain().ok_or(Refusal::NotAvailable)?;
    let dom_cfg = cfg.domains[domain].clone();
    Ok((domain.to_string(), dom_cfg))
}

/// The `authorized_did_domain` mode: admit an identity by where it lives, and
/// hold it to its own name.
///
/// # 1:1 is what removes the need for a claim registry
///
/// Because a mail domain names AT MOST ONE did-domain, non-duplication needs
/// no registry at all here: the `did:webvh` log store's own append-only-per-
/// (domain,username) shape already refuses to let a second identity overwrite
/// a name's log, and with only one did-domain in play that IS the whole
/// non-duplication guarantee. A list-of-many would reopen the gap — two
/// did-domains sharing this mail domain could both mint an `alice`, and only
/// a separate first-come registry could say which one actually holds
/// `alice@here` — which is exactly why this field is one value, not a list.
///
/// # The username is not negotiable
///
/// A DID rooted at the authorized domain gets **its own localpart and no
/// other**. `did:webvh:…:example.org:alice` may have `alice@here`, never
/// `bob@here`, and if `alice@here` is already somebody else's it gets nothing —
/// there is no fallback name to offer.
///
/// # Comparison is exact
///
/// `username` arrives already trimmed and lowercased (see [`validate`]), and
/// the DID's own segment is compared as it appears. A DID whose path segment is
/// `Alice` therefore matches nothing this relay will accept, which is correct:
/// its log lives at `/Alice/did.jsonl`, a different document from `/alice/`,
/// and folding the two together here would authorise a name against a log that
/// does not carry it.
pub fn did_domain_gate(dom_cfg: &DomainConfig, did: &str, username: &str) -> Result<(), Refusal> {
    let Some(authorized) = &dom_cfg.authorized_did_domain else {
        return Err(Refusal::DidDomainNotAuthorized);
    };
    let id = crate::webvh_id::parse(did).map_err(|_| Refusal::DidNotReadable)?;
    if !authorized.eq_ignore_ascii_case(&id.domain) {
        return Err(Refusal::DidDomainNotAuthorized);
    }
    if id.username != username {
        return Err(Refusal::DidUsernameMismatch);
    }
    Ok(())
}

/// Whether this request may create an account on this domain.
///
/// Three modes, checked in order of strictness rather than convenience:
///
/// 1. `authorized_did_domain` — admits identities rooted at exactly one named
///    home domain. When set it is the **only** thing consulted: an operator
///    who has named the domain they trust has said something more specific
///    than "open", and letting `allow_provision` also be true would silently
///    discard it.
/// 2. `allow_provision` — open to anyone.
/// 3. `provision_secret` — open to anyone holding the string. An empty secret
///    must never match an empty submitted one.
///
/// A domain with none of the three is not creatable at all, which is how a
/// privileged domain is configured on purpose.
pub fn may_provision(
    dom_cfg: &DomainConfig,
    did: &str,
    username: &str,
    submitted_secret: &str,
) -> Result<(), Refusal> {
    if dom_cfg.authorized_did_domain.is_some() {
        return did_domain_gate(dom_cfg, did, username);
    }
    if dom_cfg.allow_provision {
        return Ok(());
    }
    if dom_cfg.provision_secret.is_empty() || dom_cfg.provision_secret != submitted_secret {
        return Err(Refusal::DomainNotOpen);
    }
    Ok(())
}

/// Whether the name is already in use.
///
/// **Both credential shapes count**, because they mark different generations
/// of account: `auth_token_hash` is the older static credential, and a
/// `devices/` entry is what this flow writes. Checking only one hands an
/// existing account to whoever asks for it.
pub fn name_is_taken(
    acct_dir: &std::path::Path,
    data_dir: &std::path::Path,
    domain: &str,
    localpart: &str,
    already_registered: bool,
) -> bool {
    already_registered
        || !crate::auth_env::read_auth_hash(data_dir, domain, localpart).is_empty()
        || !jmapserver::devicekeys::list_device_keys(acct_dir).is_empty()
}

/// How this relay can check the DID's vouch for the device.
///
/// There used to be a third answer, `Local`: a `did:dht` identifier *is* the
/// identity's raw ed25519 key, so a vouch could be verified from the string
/// with no anchor and no network. That was the only way an anchorless relay
/// could serve a DID account. did:dht is gone, and with it that shortcut — a
/// `did:webvh` root key lives only in a resolved log, never in the identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VouchPath {
    /// Only the anchor can resolve a key for the DID.
    Anchor,
    /// There is no anchor. Nothing can check it.
    Impossible,
}

/// Whether this relay can bind the DID at an anchor at all.
///
/// Both halves are needed: the build has to include the anchor client *and*
/// the operator has to have configured one.
pub fn anchor_configured(cfg: &Config) -> bool {
    cfg!(feature = "anchor") && !cfg.anchor_url.is_empty()
}

/// Pick the vouch path for a DID.
///
/// `did` is no longer inspected: every method this relay serves needs the
/// anchor. Kept as a parameter because the caller has one and a signature
/// that stops mentioning it would hide that the question is about a DID.
pub fn vouch_path(cfg: &Config, _did: &str) -> VouchPath {
    if anchor_configured(cfg) {
        VouchPath::Anchor
    } else {
        VouchPath::Impossible
    }
}

/// The checks that need no anchor and no disk, in the Go handler's order.
///
/// Order matters for what a client is told: a request missing both a username
/// and a DID hears about the username, because that is the field it can fix
/// without re-deriving anything.
pub fn validate(cfg: &Config, req: &ProvisionRequest) -> Result<(), Refusal> {
    if !valid_username(&req.username.trim().to_lowercase()) {
        return Err(Refusal::InvalidUsername);
    }
    if req.device_pub_key.is_empty() || req.device_vouch_sig.is_empty() {
        return Err(Refusal::DeviceCredentialRequired);
    }
    // A DID is not optional. biset derives one for every account — at minimum
    // a did:dht, which costs nothing but local key derivation — and
    // establishing any device credential needs one to vouch.
    if req.did.is_empty() {
        return Err(Refusal::DidRequired);
    }
    // The DID signature is only checked where it can be: it proves control of
    // the DID *to the anchor*, and an anchorless relay has nobody to prove it
    // to. Demanding it anyway would refuse accounts it could serve.
    if anchor_configured(cfg) && req.did_sig.is_empty() {
        return Err(Refusal::DidSigRequired);
    }
    Ok(())
}

/// Whether the created account is bound to its DID at an anchor.
///
/// Reported to the client as `did_bound`, and **only when it sent a DID** — a
/// client that asks for no binding gets the same `{"email":…}` shape it always
/// did.
pub fn did_bound(cfg: &Config, req: &ProvisionRequest) -> bool {
    !req.did.is_empty() && anchor_configured(cfg)
}

#[cfg(test)]
mod tests;
