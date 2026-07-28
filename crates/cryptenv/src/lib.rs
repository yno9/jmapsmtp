//! Password-derived key envelope.
//!
//! Port of `go-jmapsmtp/cryptenv/envelope.go`.
//!
//! ```text
//! password ──Argon2id(salt)──> wrap_key
//! wrap_key ──AES-GCM-decrypt──> master_secret (random 32B, generated once)
//! master_secret ──HKDF("auth")──> auth_token  (presented to server)
//! master_secret ──HKDF("enc") ──> KEK         (encrypts PGP keys etc.)
//! ```
//!
//! Password rotation rewraps master_secret only; auth_token and KEK are
//! stable, so existing sessions and `privkey.enc` survive a password change.
//!
//! Every constant here is part of the compatibility contract (SPEC.md §4):
//! changing one locks every existing user out. The browser builds an envelope
//! of exactly this shape in `setupHTMLTemplate`'s inline JavaScript, so the
//! format has two independent implementations that must agree.
//!
//! **The relay itself never performs any of the crypto below.** It only ever
//! parses an envelope ([`Envelope::from_bytes`]) and serialises it back
//! ([`Envelope::to_bytes`]) — the password never reaches the server, so
//! nothing server-side can unseal. Sealing and unsealing exist for clients,
//! for tests, and to keep this implementation honest against the JavaScript
//! one. That is also why [`Envelope::from_bytes`] carries the weight it does:
//! it is the *only* part of this module the relay actually runs.

use std::fmt;

use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use rand::TryRngCore as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq as _;

const MASTER_SECRET_SIZE: usize = 32;
const SALT_SIZE: usize = 16;
const WRAP_KEY_SIZE: usize = 32;
const AES_NONCE_SIZE: usize = 12;
const AES_TAG_SIZE: usize = 16;
const AUTH_TOKEN_SIZE: usize = 32;
const KEK_SIZE: usize = 32;
const AUTH_TOKEN_HASH_SIZE: usize = 32;

const CURRENT_VERSION: u32 = 1;

/// Argon2 will not accept a shorter one, and neither should we.
const MIN_SALT_SIZE: usize = 8;

/// HKDF context strings — changing either is backwards incompatible.
const HKDF_INFO_AUTH: &[u8] = b"biset-jmapsmtp/auth/v1";
const HKDF_INFO_KEK: &[u8] = b"biset-jmapsmtp/enc/v1";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("cryptenv: empty password")]
    EmptyPassword,
    #[error("cryptenv: wrong password")]
    WrongPassword,
    #[error("cryptenv: unsupported version {0}")]
    UnsupportedVersion(u32),
    #[error("cryptenv: {0}")]
    Malformed(&'static str),
    #[error("cryptenv: {0}")]
    Json(String),
    #[error("cryptenv: rng failure")]
    Rng,
}

/// Argon2id cost parameters. Time/Memory/Threads follow OWASP guidance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    /// iterations
    #[serde(rename = "t")]
    pub time: u32,
    /// KiB
    #[serde(rename = "m")]
    pub memory: u32,
    /// lanes
    #[serde(rename = "p")]
    pub threads: u8,
}

/// OWASP-recommended minimum for interactive logins.
pub const DEFAULT_KDF: KdfParams = KdfParams {
    time: 3,
    memory: 64 * 1024,
    threads: 4,
};

/// The per-account password-derived envelope stored server-side.
///
/// Byte slices serialise as standard base64 with padding, matching Go's
/// default `[]byte` encoding and the browser's `btoa` output. Field order is
/// declaration order in both languages, so the serialised JSON is identical.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    #[serde(rename = "v")]
    pub version: u32,
    #[serde(with = "b64")]
    pub salt: Vec<u8>,
    pub kdf: KdfParams,
    /// `nonce(12) || ciphertext || tag(16)`
    #[serde(with = "b64")]
    pub wrapped_secret: Vec<u8>,
    /// `sha256(auth_token)`
    #[serde(with = "b64")]
    pub auth_token_hash: Vec<u8>,
}

/// The secrets an envelope yields once opened. Both are 32 bytes.
pub struct Unsealed {
    pub auth_token: [u8; AUTH_TOKEN_SIZE],
    pub kek: [u8; KEK_SIZE],
}

impl fmt::Debug for Unsealed {
    /// Never print key material, not even in a panic message.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Unsealed { auth_token: <redacted>, kek: <redacted> }")
    }
}

impl Envelope {
    /// Generate a fresh master_secret, seal it with `password`, and return the
    /// envelope alongside the derived auth_token and KEK.
    pub fn new(password: &str) -> Result<(Envelope, Unsealed), Error> {
        Self::new_with_kdf(password, DEFAULT_KDF)
    }

    /// As [`Envelope::new`], with explicit cost parameters. Tests use cheap
    /// ones; nothing else should.
    pub fn new_with_kdf(password: &str, kdf: KdfParams) -> Result<(Envelope, Unsealed), Error> {
        if password.is_empty() {
            return Err(Error::EmptyPassword);
        }
        let mut salt = vec![0u8; SALT_SIZE];
        fill_random(&mut salt)?;
        let mut master_secret = [0u8; MASTER_SECRET_SIZE];
        fill_random(&mut master_secret)?;

        let wrap_key = derive_wrap_key(password, &salt, kdf)?;
        let wrapped_secret = aes_gcm_seal(&wrap_key, &master_secret)?;
        let unsealed = derive_auth_and_kek(&master_secret);

        let env = Envelope {
            version: CURRENT_VERSION,
            salt,
            kdf,
            wrapped_secret,
            auth_token_hash: hash_auth_token(&unsealed.auth_token).to_vec(),
        };
        Ok((env, unsealed))
    }

    /// Recover auth_token and KEK using `password`.
    ///
    /// A wrong password is an AEAD tag mismatch, reported as
    /// [`Error::WrongPassword`] — deliberately indistinguishable from a
    /// corrupt ciphertext, since the caller has no use for the difference.
    pub fn unseal(&self, password: &str) -> Result<Unsealed, Error> {
        self.check()?;
        let wrap_key = derive_wrap_key(password, &self.salt, self.kdf)?;
        let master_secret = aes_gcm_open(&wrap_key, &self.wrapped_secret)?;
        Ok(derive_auth_and_kek(&master_secret))
    }

    /// Change the password without rotating master_secret.
    ///
    /// The auth_token and KEK derived from the returned envelope are
    /// identical to those from this one; persisting it is the caller's job.
    pub fn rewrap(&self, old_pw: &str, new_pw: &str) -> Result<Envelope, Error> {
        if new_pw.is_empty() {
            return Err(Error::EmptyPassword);
        }
        // The Go original checks the version in Unseal but not here, so a
        // future v2 envelope would be silently rewrapped under v1 rules. The
        // check belongs on both paths (SPEC.md §11).
        self.check()?;
        let old_key = derive_wrap_key(old_pw, &self.salt, self.kdf)?;
        let master_secret = aes_gcm_open(&old_key, &self.wrapped_secret)?;

        let mut new_salt = vec![0u8; SALT_SIZE];
        fill_random(&mut new_salt)?;
        let new_key = derive_wrap_key(new_pw, &new_salt, DEFAULT_KDF)?;
        let wrapped_secret = aes_gcm_seal(&new_key, &master_secret)?;
        let unsealed = derive_auth_and_kek(&master_secret);

        Ok(Envelope {
            version: CURRENT_VERSION,
            salt: new_salt,
            kdf: DEFAULT_KDF,
            wrapped_secret,
            auth_token_hash: hash_auth_token(&unsealed.auth_token).to_vec(),
        })
    }

    /// Constant-time check of a presented auth_token against the stored hash.
    ///
    /// master_secret is never reconstructed, so the server can run this
    /// without ever holding the password.
    #[must_use]
    pub fn verify_auth(&self, auth_token: &[u8]) -> bool {
        hash_auth_token(auth_token)
            .ct_eq(self.auth_token_hash.as_slice())
            .into()
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        serde_json::to_vec(self).map_err(|e| Error::Json(e.to_string()))
    }

    /// Parse and validate an envelope.
    ///
    /// **This is the relay's only entry point into this module**, reached from
    /// `POST /auth/signup`, `PUT /auth/envelope` and `POST
    /// /account/provision` — all of them fed by a request body.
    ///
    /// The Go original validates nothing: `{}` and even `null` unmarshal
    /// happily into a zero-valued envelope. Signup then consumes the one-time
    /// setup token, writes that envelope, and answers 204, after which it
    /// refuses to run again ("already initialized"). The account is left
    /// permanently unusable — no password can open a zero-valued envelope,
    /// and the token that would have allowed a retry is gone. An
    /// unauthenticated caller who guesses a setup token can brick an account
    /// with an empty JSON object.
    ///
    /// So this rejects what cannot possibly be a working envelope. The checks
    /// are deliberately narrow: each one marks a value that makes unsealing
    /// impossible or would panic Argon2, never a merely unusual choice. A
    /// client free to pick its own cost parameters stays free to.
    pub fn from_bytes(b: &[u8]) -> Result<Envelope, Error> {
        let env: Envelope = serde_json::from_slice(b).map_err(|e| Error::Json(e.to_string()))?;
        env.check()?;
        Ok(env)
    }

    /// The validation shared by parsing, unsealing and rewrapping.
    fn check(&self) -> Result<(), Error> {
        if self.version != CURRENT_VERSION {
            return Err(Error::UnsupportedVersion(self.version));
        }
        if self.salt.len() < MIN_SALT_SIZE {
            return Err(Error::Malformed("salt too short"));
        }
        // Argon2 panics outright on a zero time or thread count in the Go
        // implementation, and refuses to build Params in this one.
        if self.kdf.time < 1 {
            return Err(Error::Malformed("kdf t must be at least 1"));
        }
        if self.kdf.threads < 1 {
            return Err(Error::Malformed("kdf p must be at least 1"));
        }
        if self.kdf.memory < 8 * u32::from(self.kdf.threads) {
            return Err(Error::Malformed("kdf m must be at least 8*p"));
        }
        // Anything shorter cannot hold a nonce and a tag, let alone a
        // ciphertext.
        if self.wrapped_secret.len() <= AES_NONCE_SIZE + AES_TAG_SIZE {
            return Err(Error::Malformed("wrapped_secret too short"));
        }
        if self.auth_token_hash.len() != AUTH_TOKEN_HASH_SIZE {
            return Err(Error::Malformed("auth_token_hash must be 32 bytes"));
        }
        Ok(())
    }
}

// ── internals ─────────────────────────────────────────────────────────────

fn fill_random(buf: &mut [u8]) -> Result<(), Error> {
    rand::rngs::OsRng
        .try_fill_bytes(buf)
        .map_err(|_| Error::Rng)
}

fn derive_wrap_key(
    password: &str,
    salt: &[u8],
    p: KdfParams,
) -> Result<[u8; WRAP_KEY_SIZE], Error> {
    let params = Params::new(p.memory, p.time, u32::from(p.threads), Some(WRAP_KEY_SIZE))
        .map_err(|_| Error::Malformed("invalid kdf parameters"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; WRAP_KEY_SIZE];
    argon
        .hash_password_into(password.as_bytes(), salt, &mut out)
        .map_err(|_| Error::Malformed("argon2 failed"))?;
    Ok(out)
}

fn derive_auth_and_kek(master_secret: &[u8]) -> Unsealed {
    Unsealed {
        auth_token: hkdf_derive(master_secret, HKDF_INFO_AUTH),
        kek: hkdf_derive(master_secret, HKDF_INFO_KEK),
    }
}

/// HKDF-SHA256 with an absent (all-zero) salt, matching Go's
/// `hkdf.New(sha256.New, secret, nil, info)`.
///
/// Infallible at these sizes: expansion only fails past 255 hash lengths, and
/// N is 32. The Go original panics here for the same reason, which is simply
/// unreachable.
fn hkdf_derive<const N: usize>(secret: &[u8], info: &[u8]) -> [u8; N] {
    let hk = Hkdf::<Sha256>::new(None, secret);
    let mut out = [0u8; N];
    hk.expand(info, &mut out)
        .expect("HKDF expansion of 32 bytes cannot fail");
    out
}

fn hash_auth_token(auth_token: &[u8]) -> [u8; AUTH_TOKEN_HASH_SIZE] {
    Sha256::digest(auth_token).into()
}

fn aes_gcm_seal(key: &[u8; WRAP_KEY_SIZE], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let mut nonce = [0u8; AES_NONCE_SIZE];
    fill_random(&mut nonce)?;
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &[],
            },
        )
        .map_err(|_| Error::Malformed("aes-gcm seal failed"))?;
    let mut out = Vec::with_capacity(nonce.len() + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

fn aes_gcm_open(key: &[u8; WRAP_KEY_SIZE], sealed: &[u8]) -> Result<Vec<u8>, Error> {
    if sealed.len() < AES_NONCE_SIZE {
        return Err(Error::Malformed("sealed too short"));
    }
    let (nonce, ct) = sealed.split_at(AES_NONCE_SIZE);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad: &[] })
        .map_err(|_| Error::WrongPassword)
}

/// Standard base64 with padding — Go's default `[]byte` JSON encoding.
mod b64 {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use serde::{Deserialize as _, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        // Go decodes a JSON null []byte to an empty slice rather than an
        // error; matching that keeps the rejection of such an envelope in one
        // place (Envelope::check) instead of two.
        let s = Option::<String>::deserialize(d)?;
        match s {
            None => Ok(Vec::new()),
            Some(s) => STANDARD.decode(&s).map_err(serde::de::Error::custom),
        }
    }
}

#[cfg(test)]
mod tests;
