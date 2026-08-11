//! `xtask bind-probe` — drive a DID binding the way biset does, end to end.
//!
//! The one path this project rests on and the one no test can cover on its
//! own: the client signs, the relay forwards, and the **anchor** decides. The
//! relay never verifies a binding signature — so a relay-side test proves
//! nothing about whether a real client can bind, and the interop suite's stub
//! anchor answers whatever it is told to.
//!
//! # What is signed
//!
//! From biset's `src/did/binding.ts`:
//!
//! ```text
//! bind:<did>:<username>@<relayHost>:<unixSeconds>
//! ```
//!
//! ed25519 over the UTF-8 bytes with the DID's **root** key, base64 in
//! `did_sig`. The statement is host-bound so a signature captured at one relay
//! cannot be replayed at another.
//!
//! `relayHost` must be what the relay sees in the `Host` header, because that
//! is what it passes on as the proof's `host`. Behind a reverse proxy that is
//! the public name, not `127.0.0.1`.
//!
//! # Why `did:dht`
//!
//! It is **self-certifying**: the identifier *is* the ed25519 public key in
//! z-base-32, so the anchor can check the signature with no network and no
//! prior registration. A `did:webvh` SCID is a hash of a document log, so
//! probing with one would test the anchor's resolver rather than the binding
//! path.
//!
//! The z-base-32 comes from `jmapserver::diddht`, this port's own encoder. If
//! it disagreed with biset's by one character the anchor would read a
//! different public key and reject the signature — so a success here is also
//! a check on that encoding against a third implementation.

use anyhow::{Context, Result, bail};
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};

pub struct Options {
    /// e.g. `https://relay.biset.md`
    pub relay: String,
    /// The account to bind to, e.g. `alice@trial.biset.md`.
    pub account: String,
    /// The account's raw relay token (not base64).
    pub token: String,
    /// Seconds to add to `now`, for probing the anchor's freshness window.
    pub skew: i64,
}

pub fn run(opts: Options) -> Result<()> {
    // `SigningKey::from_bytes` rather than `generate`, because ed25519-dalek
    // carries its own `rand_core` and the workspace's `rand` is a different
    // major — feeding one to the other does not compile, and pinning a second
    // rand into this crate for one call is not worth it. The bytes come from
    // the OS either way.
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).context("reading OS randomness for the DID key")?;
    let signing = SigningKey::from_bytes(&seed);
    let did = format!(
        "did:dht:{}",
        jmapserver::diddht::zbase32_encode(signing.verifying_key().as_bytes())
    );

    let (username, _domain) = opts
        .account
        .split_once('@')
        .context("account must be localpart@domain")?;

    // The host the relay will report, which is the host in the URL — behind
    // caddy that is the public name and it is what the signature covers.
    let host = opts
        .relay
        .split("://")
        .nth(1)
        .unwrap_or(&opts.relay)
        .trim_end_matches('/')
        .to_string();

    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs() as i64
        + opts.skew;

    let statement = format!("bind:{did}:{username}@{host}:{ts}");
    let sig = base64::engine::general_purpose::STANDARD
        .encode(signing.sign(statement.as_bytes()).to_bytes());

    println!("did:       {did}");
    println!("statement: {statement}");
    if opts.skew != 0 {
        println!("skew:      {}s (probing the freshness window)", opts.skew);
    }

    let password = base64::engine::general_purpose::STANDARD.encode(opts.token.as_bytes());
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;
    let res = client
        .put(format!("{}/account/did", opts.relay.trim_end_matches('/')))
        .basic_auth(&opts.account, Some(&password))
        .json(&serde_json::json!({
            "did": did,
            "did_sig": sig,
            "bind_ts": ts,
        }))
        .send()
        .context("PUT /account/did")?;

    let status = res.status().as_u16();
    let body = res.text().unwrap_or_default();
    println!("\n{status} {}", body.trim());

    match status {
        204 => {
            println!(
                "\nbound. The anchor verified a signature this run produced, over the\nstatement biset's binding.ts defines, against the key named by the DID."
            );
            Ok(())
        }
        // Not a failure of the probe: a relay with no anchor cannot bind, and
        // saying so is the correct answer (SPEC.md §11 / did_bind::NoAnchor).
        400 if body.contains("identity anchor") => {
            println!("\nthis relay is anchorless, so there is nothing to bind against");
            Ok(())
        }
        _ => bail!("the binding was not accepted"),
    }
}
