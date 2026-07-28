//! Go ↔ Rust interoperability.
//!
//! The unit tests prove this implementation is self-consistent, which is not
//! the property that matters: an envelope written by the Go relay has to open
//! here, and one written here has to open there, or a binary swap locks every
//! account out. Only running both implementations can show that.
//!
//! The helper is built by `just interop` and linked against the real Go
//! `cryptenv` package inside the oracle checkout.
//!
//! A missing helper cannot be allowed to look like a pass. Rust has no real
//! skip, so a soft skip reports green — and five green tests that ran nothing
//! is exactly the failure mode `difftest --self-test` exists to prevent.
//! Hence `CRYPTENV_INTEROP=required`: `just test` sets it, so the normal
//! workflow fails loudly if the helper is absent. A bare `cargo test` without
//! it still skips quietly, for the case where the Go toolchain genuinely is
//! not installed.

use std::path::PathBuf;
use std::process::{Command, Stdio};

use cryptenv::{Envelope, KdfParams};

/// Cheap parameters. Real ones make each Argon2 call take ~100ms, and these
/// tests do several round trips per case.
const FAST_KDF: KdfParams = KdfParams {
    time: 1,
    memory: 8 * 1024,
    threads: 1,
};

fn helper() -> Option<PathBuf> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../oracle/cryptenv-interop")
        .canonicalize()
        .ok()?;
    p.exists().then_some(p)
}

/// The helper, or `None` to skip — unless skipping has been forbidden.
fn require_helper() -> Option<PathBuf> {
    if let Some(p) = helper() {
        return Some(p);
    }
    assert!(
        std::env::var_os("CRYPTENV_INTEROP").is_none(),
        "CRYPTENV_INTEROP is set but the Go interop helper is missing — run \
         `just interop`. Refusing to report a pass for a test that ran nothing."
    );
    eprintln!(
        "SKIPPED: Go interop helper not built — run `just interop` (needs the \
         Go toolchain and ~/go-jmapserver). Set CRYPTENV_INTEROP=required to \
         make this an error instead."
    );
    None
}

#[derive(serde::Deserialize)]
struct GoResult {
    #[serde(default)]
    envelope: Option<serde_json::Value>,
    auth: String,
    kek: String,
}

fn go_gen(bin: &PathBuf, password: &str, kdf: KdfParams) -> GoResult {
    let out = Command::new(bin)
        .args([
            "gen",
            password,
            &kdf.time.to_string(),
            &kdf.memory.to_string(),
            &kdf.threads.to_string(),
        ])
        .output()
        .expect("running the Go helper");
    assert!(
        out.status.success(),
        "go gen failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("parsing go gen output")
}

fn go_unseal(bin: &PathBuf, password: &str, envelope: &[u8]) -> Result<GoResult, String> {
    use std::io::Write as _;
    let mut child = Command::new(bin)
        .args(["unseal", password])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawning the Go helper");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(envelope)
        .expect("writing envelope to the Go helper");
    let out = child.wait_with_output().expect("waiting for the Go helper");
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).into_owned());
    }
    Ok(serde_json::from_slice(&out.stdout).expect("parsing go unseal output"))
}

fn b64(b: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(b)
}

/// Go seals, Rust opens. This is the migration direction that matters: an
/// existing deployment's `envelope.json` files were all written by Go.
#[test]
fn rust_opens_a_go_sealed_envelope() {
    let Some(bin) = require_helper() else { return };
    let password = "correct horse battery staple";

    let go = go_gen(&bin, password, FAST_KDF);
    let raw = serde_json::to_vec(&go.envelope.expect("gen returns an envelope")).unwrap();

    let env = Envelope::from_bytes(&raw).expect("Rust must parse a Go-written envelope");
    let opened = env.unseal(password).expect("Rust must unseal it");

    assert_eq!(b64(&opened.auth_token), go.auth, "auth_token differs");
    assert_eq!(b64(&opened.kek), go.kek, "KEK differs");
}

/// Rust seals, Go opens — the rollback direction. If this fails, a deployment
/// that runs the Rust build and then reverts has lost the accounts created in
/// between.
#[test]
fn go_opens_a_rust_sealed_envelope() {
    let Some(bin) = require_helper() else { return };
    let password = "correct horse battery staple";

    let (env, sealed) = Envelope::new_with_kdf(password, FAST_KDF).expect("seal");
    let raw = env.to_bytes().expect("to_bytes");

    let go = go_unseal(&bin, password, &raw).expect("Go must unseal a Rust-written envelope");
    assert_eq!(b64(&sealed.auth_token), go.auth, "auth_token differs");
    assert_eq!(b64(&sealed.kek), go.kek, "KEK differs");
}

/// A wrong password must fail on both sides, not merely on ours.
#[test]
fn go_rejects_the_wrong_password_on_a_rust_sealed_envelope() {
    let Some(bin) = require_helper() else { return };
    let (env, _) = Envelope::new_with_kdf("right", FAST_KDF).expect("seal");
    let raw = env.to_bytes().expect("to_bytes");
    assert!(
        go_unseal(&bin, "wrong", &raw).is_err(),
        "Go accepted a wrong password"
    );
}

/// Rewrapping in one implementation must leave the envelope openable by the
/// other, with the derived keys unchanged — that is the whole point of
/// rewrapping rather than reissuing.
#[test]
fn go_opens_a_rust_rewrapped_envelope_with_unchanged_keys() {
    let Some(bin) = require_helper() else { return };

    let go = go_gen(&bin, "old-pw", FAST_KDF);
    let raw = serde_json::to_vec(&go.envelope.expect("gen returns an envelope")).unwrap();

    let env = Envelope::from_bytes(&raw).expect("parse");
    let rewrapped = env.rewrap("old-pw", "new-pw").expect("rewrap");
    let raw2 = rewrapped.to_bytes().expect("to_bytes");

    let reopened = go_unseal(&bin, "new-pw", &raw2).expect("Go must unseal the rewrapped envelope");
    assert_eq!(
        reopened.auth, go.auth,
        "auth_token changed across a cross-implementation rewrap"
    );
    assert_eq!(reopened.kek, go.kek, "KEK changed across a rewrap");
}

/// The real cost parameters, exercised once. Everything else here runs with
/// cheap ones, which would hide a mismatch that only shows up at p=4 — Argon2
/// with several lanes is a different code path from Argon2 with one.
#[test]
fn interoperates_at_the_real_cost_parameters() {
    let Some(bin) = require_helper() else { return };
    let password = "production-like";

    let go = go_gen(&bin, password, cryptenv::DEFAULT_KDF);
    let raw = serde_json::to_vec(&go.envelope.expect("gen returns an envelope")).unwrap();

    let env = Envelope::from_bytes(&raw).expect("parse");
    assert_eq!(env.kdf, cryptenv::DEFAULT_KDF);
    let opened = env.unseal(password).expect("unseal");
    assert_eq!(b64(&opened.auth_token), go.auth);
    assert_eq!(b64(&opened.kek), go.kek);
}
