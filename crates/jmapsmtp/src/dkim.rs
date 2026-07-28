//! DKIM key management and signing. Port of `go-jmapsmtp/dkim.go`.
//!
//! One RSA-2048 key per domain, generated on first use and **never rotated**:
//! the matching public key lives in a DNS TXT record the operator published by
//! hand, so a new key silently breaks every signature until they notice and
//! republish. Load-or-create, with the create exclusive so two starts racing
//! cannot each mint one.

use std::fs;
use std::io;
use std::path::Path;

use base64::Engine as _;
use rsa::RsaPrivateKey;
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};

/// The headers signed. A verifier reconstructs the signed data from the `h=`
/// tag, so which headers are listed is part of what the signature means.
///
/// The *order* in the emitted `h=` is not this order: mail-auth lists the
/// headers in reverse of their appearance in the message — the bottom-up
/// convention RFC 6376 §5.4.2 recommends, so that a header prepended in
/// transit cannot displace a signed one — where go-msgauth lists them as
/// given. Both are valid and each signer is self-consistent with its own
/// `h=`, which is why the Go verifier accepts these signatures. Matching Go
/// exactly would mean not using mail-auth's signer. See SPEC.md §11.10.
pub const SIGNED_HEADERS: &[&str] = &[
    "From",
    "To",
    "Cc",
    "Subject",
    "Date",
    "Message-Id",
    "Content-Type",
];

/// The selector used when a domain's config leaves it empty.
pub const DEFAULT_SELECTOR: &str = "default";

/// Load `<dir>/key.pem`, or generate and persist a fresh RSA-2048 key.
///
/// Written PKCS#8 PEM at mode 0600, created with `O_EXCL` so a concurrent
/// start loses the race rather than overwriting a key that is already
/// published in DNS.
pub fn load_or_generate_key(dir: &Path) -> io::Result<RsaPrivateKey> {
    let path = dir.join("key.pem");
    if let Ok(pem) = fs::read_to_string(&path)
        && let Ok(key) = parse_pkcs8_pem(&pem)
    {
        return Ok(key);
    }

    // rsa 0.9 pins rand_core 0.6, which the workspace's rand 0.9 does not
    // provide; its own re-export is the one that satisfies the bound.
    let key = RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048)
        .map_err(|e| io::Error::other(format!("generating DKIM key: {e}")))?;
    let pem = key
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| io::Error::other(format!("encoding DKIM key: {e}")))?;

    write_new_private_key(&path, pem.as_bytes())?;
    Ok(key)
}

fn parse_pkcs8_pem(pem: &str) -> Result<RsaPrivateKey, rsa::pkcs8::Error> {
    use rsa::pkcs8::DecodePrivateKey as _;
    RsaPrivateKey::from_pkcs8_pem(pem)
}

/// Create the key file exclusively at 0600. An existing file is left alone.
fn write_new_private_key(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write as _;
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    f.write_all(bytes)
}

/// The DNS TXT record value: `v=DKIM1; k=rsa; p=<base64 SPKI DER>`.
pub fn public_key_record(key: &RsaPrivateKey) -> String {
    let spki = match key.to_public_key().to_public_key_der() {
        Ok(der) => der,
        Err(_) => return String::new(),
    };
    let b64 = base64::engine::general_purpose::STANDARD.encode(spki.as_bytes());
    format!("v=DKIM1; k=rsa; p={b64}")
}

/// Write `<dir>/dkim-dns.txt`: the record, with the name to publish it under
/// in a comment above. Purely for the operator; nothing reads it back.
pub fn write_record_file(
    dir: &Path,
    selector: &str,
    domain: &str,
    key: &RsaPrivateKey,
) -> io::Result<()> {
    let record = public_key_record(key);
    if record.is_empty() {
        return Ok(());
    }
    let content =
        format!("# Add this TXT record to DNS:\n# {selector}._domainkey.{domain}\n{record}\n");
    fs::write(dir.join("dkim-dns.txt"), content)
}

/// Sign a raw RFC 5322 message, returning it with a DKIM-Signature header
/// prepended.
///
/// Returns the message unchanged on any failure, as the Go original does: an
/// unsigned message still gets delivered, where a failed send would not.
pub fn sign(raw: &[u8], key: &RsaPrivateKey, domain: &str, selector: &str) -> Vec<u8> {
    match try_sign(raw, key, domain, selector) {
        Ok(signed) => signed,
        Err(e) => {
            tracing::warn!("[dkim] signing failed for {domain}: {e}");
            raw.to_vec()
        }
    }
}

fn try_sign(
    raw: &[u8],
    key: &RsaPrivateKey,
    domain: &str,
    selector: &str,
) -> Result<Vec<u8>, String> {
    use mail_auth::common::crypto::{RsaKey, Sha256};
    use mail_auth::dkim::{Canonicalization, DkimSigner};

    // Handed over as DER rather than PEM: the PEM entry point is deprecated,
    // and this avoids a round trip through text either way.
    let der = key
        .to_pkcs8_der()
        .map_err(|e| format!("re-encoding key: {e}"))?;
    let der = rustls_pki_types::PrivateKeyDer::Pkcs8(der.as_bytes().to_vec().into());
    let signing_key =
        RsaKey::<Sha256>::from_key_der(der).map_err(|e| format!("loading key: {e}"))?;

    let signature = DkimSigner::from_key(signing_key)
        .domain(domain)
        .selector(selector)
        .headers(SIGNED_HEADERS.iter().copied())
        .header_canonicalization(Canonicalization::Relaxed)
        .body_canonicalization(Canonicalization::Relaxed)
        .sign(raw)
        .map_err(|e| format!("signing: {e}"))?;

    // The header goes at the top, ahead of everything it signs.
    use mail_auth::common::headers::HeaderWriter as _;
    let mut out = signature.to_header().into_bytes();
    out.extend_from_slice(raw);
    Ok(out)
}

#[cfg(test)]
mod tests;
