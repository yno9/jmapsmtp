//! Password-derived key envelope.
//!
//! Port of `go-jmapsmtp/cryptenv/envelope.go`. See PLAN.md M2.
//!
//! ```text
//! password ──Argon2id(salt)──> wrap_key
//! wrap_key ──AES-GCM-decrypt──> master_secret (random 32B, generated once)
//! master_secret ──HKDF("auth")──> auth_token  (presented to server)
//! master_secret ──HKDF("enc") ──> KEK         (encrypts PGP keys etc.)
//! ```
//!
//! Password rotation rewraps master_secret only; auth_token and KEK are stable.
//!
//! Every constant here is part of the compatibility contract (PLAN.md §5.1):
//! changing one locks every existing user out.
