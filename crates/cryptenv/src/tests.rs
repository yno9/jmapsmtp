//! Ports of every test in `go-jmapsmtp/cryptenv/envelope_test.go`, plus the
//! cases covering where this implementation deliberately differs (SPEC.md
//! §11) and the wire-format pins that keep it interoperable.

use super::*;
use pretty_assertions::assert_eq;

/// Cheap Argon2 parameters, matching the Go tests' `fastEnv`. Nothing outside
/// tests may use these.
const FAST_KDF: KdfParams = KdfParams {
    time: 1,
    memory: 8 * 1024,
    threads: 1,
};

fn fast_env(pw: &str) -> (Envelope, Unsealed) {
    Envelope::new_with_kdf(pw, FAST_KDF).expect("new envelope")
}

// ── ports of the Go tests ─────────────────────────────────────────────────

#[test]
fn new_envelope_round_trip() {
    let (env, sealed) = fast_env("correct horse battery staple");
    let got = env.unseal("correct horse battery staple").expect("unseal");
    assert_eq!(sealed.auth_token, got.auth_token);
    assert_eq!(sealed.kek, got.kek);
}

#[test]
fn unseal_wrong_password() {
    let (env, _) = fast_env("correct");
    assert!(matches!(env.unseal("wrong"), Err(Error::WrongPassword)));
}

#[test]
fn rewrap_preserves_derived_keys() {
    let (env, first) = fast_env("old-pw");
    let env2 = env.rewrap("old-pw", "new-pw").expect("rewrap");
    let second = env2.unseal("new-pw").expect("unseal after rewrap");
    assert_eq!(
        first.auth_token, second.auth_token,
        "auth_token changed after rewrap; expected stable"
    );
    assert_eq!(
        first.kek, second.kek,
        "kek changed after rewrap; expected stable"
    );
}

#[test]
fn rewrap_old_password_stops_working() {
    let (env, _) = fast_env("old-pw");
    let env2 = env.rewrap("old-pw", "new-pw").expect("rewrap");
    assert!(
        env2.unseal("old-pw").is_err(),
        "old password should not unseal new envelope"
    );
}

#[test]
fn rewrap_wrong_old_password() {
    let (env, _) = fast_env("old-pw");
    assert!(
        env.rewrap("wrong", "new-pw").is_err(),
        "rewrap should fail with wrong old password"
    );
}

#[test]
fn verify_auth() {
    let (env, sealed) = fast_env("pw");
    assert!(
        env.verify_auth(&sealed.auth_token),
        "should accept the correct token"
    );
    let mut bad = sealed.auth_token;
    bad[0] ^= 0xff;
    assert!(!env.verify_auth(&bad), "should reject a tampered token");
}

#[test]
fn serialization_round_trip() {
    let (env, sealed) = fast_env("pw");
    let bytes = env.to_bytes().expect("to_bytes");
    let got = Envelope::from_bytes(&bytes).expect("from_bytes");
    let reopened = got.unseal("pw").expect("unseal after roundtrip");
    assert_eq!(sealed.auth_token, reopened.auth_token);
    assert_eq!(sealed.kek, reopened.kek);
}

#[test]
fn randomness_across_calls() {
    let (e1, s1) = fast_env("pw");
    let (e2, s2) = fast_env("pw");
    assert_ne!(e1.salt, e2.salt, "salt should be unique per envelope");
    assert_ne!(
        s1.auth_token, s2.auth_token,
        "master_secret (and derived keys) should differ across envelopes"
    );
    assert_ne!(s1.kek, s2.kek);
}

#[test]
fn empty_password() {
    assert!(matches!(Envelope::new(""), Err(Error::EmptyPassword)));
}

// ── wire format ───────────────────────────────────────────────────────────

/// The exact JSON the browser's `setupHTMLTemplate` produces. Parsing this is
/// the whole compatibility requirement; if this test fails, every account
/// created through the setup page is unreadable.
#[test]
fn parses_the_browser_produced_shape() {
    // salt 16B, wrapped_secret 12+32+16=60B, auth_token_hash 32B.
    let json = format!(
        r#"{{"v":1,"salt":"{}","kdf":{{"t":3,"m":65536,"p":4}},"wrapped_secret":"{}","auth_token_hash":"{}"}}"#,
        b64_of(&[0x11; 16]),
        b64_of(&[0x22; 60]),
        b64_of(&[0x33; 32]),
    );
    let env = Envelope::from_bytes(json.as_bytes()).expect("browser shape must parse");
    assert_eq!(env.version, 1);
    assert_eq!(env.kdf, DEFAULT_KDF);
    assert_eq!(env.salt.len(), 16);
    assert_eq!(env.wrapped_secret.len(), 60);
    assert_eq!(env.auth_token_hash.len(), 32);
}

/// Field order and key names must match Go's struct-tag output byte for byte,
/// because an envelope is stored and served verbatim.
#[test]
fn serialises_with_go_field_order_and_names() {
    let env = Envelope {
        version: 1,
        salt: vec![0x11; 16],
        kdf: DEFAULT_KDF,
        wrapped_secret: vec![0x22; 60],
        auth_token_hash: vec![0x33; 32],
    };
    let json = String::from_utf8(env.to_bytes().unwrap()).unwrap();
    let expected = format!(
        r#"{{"v":1,"salt":"{}","kdf":{{"t":3,"m":65536,"p":4}},"wrapped_secret":"{}","auth_token_hash":"{}"}}"#,
        b64_of(&[0x11; 16]),
        b64_of(&[0x22; 60]),
        b64_of(&[0x33; 32]),
    );
    assert_eq!(json, expected);
}

#[test]
fn default_kdf_matches_the_frozen_constants() {
    // SPEC.md §4. Spelled out rather than referenced so a change here has to
    // be deliberate.
    assert_eq!(DEFAULT_KDF.time, 3);
    assert_eq!(DEFAULT_KDF.memory, 65536);
    assert_eq!(DEFAULT_KDF.threads, 4);
}

/// HKDF context strings are the other half of the frozen contract.
#[test]
fn hkdf_info_strings_are_frozen() {
    assert_eq!(HKDF_INFO_AUTH, b"biset-jmapsmtp/auth/v1");
    assert_eq!(HKDF_INFO_KEK, b"biset-jmapsmtp/enc/v1");
}

/// Derivation must be a pure function of master_secret, so an envelope
/// rewrapped anywhere yields the same auth_token. Pinning a known vector
/// catches an accidental change of hash, salt handling or info string that
/// the round-trip tests would not.
///
/// The expected values were produced by the Go implementation itself
/// (`hkdf.New(sha256.New, secret, nil, info)` over a master_secret of 32
/// 0x42 bytes), not by this one.
#[test]
fn hkdf_derivation_matches_the_go_implementation() {
    let master = [0x42u8; 32];
    let out = derive_auth_and_kek(&master);
    assert_eq!(
        b64_of(&out.auth_token),
        "zTfB4OJi8MahMc22X985lq6lEIp14//Nj4at5Aijob8=",
        "auth_token derivation changed — every account's credential just moved"
    );
    assert_eq!(
        b64_of(&out.kek),
        "tLhMh0MBp8mXzd+tpdBxSAV+3irX07mgdiCWi+/sJgY=",
        "KEK derivation changed — every stored privkey.enc just became unreadable"
    );
}

// ── deliberate divergence from the Go implementation (SPEC.md §11) ─────────

/// The Go original accepts all of these and writes them to disk. Signup then
/// consumes the one-time setup token and reports success, leaving an account
/// that no password can ever open and no token can ever retry.
#[test]
fn rejects_envelopes_that_could_never_be_unsealed() {
    let cases: &[(&str, &str)] = &[
        ("{}", "empty object"),
        ("null", "JSON null"),
        (r#"{"v":1}"#, "version only"),
        (
            r#"{"v":99,"salt":"AAAAAAAAAAAAAAAAAAAAAA==","kdf":{"t":3,"m":65536,"p":4},"wrapped_secret":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","auth_token_hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}"#,
            "unsupported version",
        ),
    ];
    for (json, what) in cases {
        assert!(
            Envelope::from_bytes(json.as_bytes()).is_err(),
            "should reject {what}: {json}"
        );
    }
}

/// Argon2 panics on these in Go and refuses to build parameters here, so an
/// envelope carrying them is a latent crash rather than a merely odd choice.
#[test]
fn rejects_kdf_parameters_argon2_cannot_use() {
    for (t, m, p, what) in [
        (0, 65536, 4, "zero iterations"),
        (3, 65536, 0, "zero lanes"),
        (3, 4, 4, "memory below 8*p"),
    ] {
        let json = format!(
            r#"{{"v":1,"salt":"{}","kdf":{{"t":{t},"m":{m},"p":{p}}},"wrapped_secret":"{}","auth_token_hash":"{}"}}"#,
            b64_of(&[0x11; 16]),
            b64_of(&[0x22; 60]),
            b64_of(&[0x33; 32]),
        );
        assert!(
            Envelope::from_bytes(json.as_bytes()).is_err(),
            "should reject {what}"
        );
    }
}

/// Unusual but workable parameters must still be accepted: the validation is
/// there to catch the impossible, not to impose a policy.
#[test]
fn accepts_unusual_but_workable_parameters() {
    let json = format!(
        r#"{{"v":1,"salt":"{}","kdf":{{"t":1,"m":8,"p":1}},"wrapped_secret":"{}","auth_token_hash":"{}"}}"#,
        b64_of(&[0x11; 8]),  // the shortest salt Argon2 accepts
        b64_of(&[0x22; 29]), // nonce + tag + one byte
        b64_of(&[0x33; 32]),
    );
    Envelope::from_bytes(json.as_bytes()).expect("workable parameters must be accepted");
}

/// The Go original checks the version in `Unseal` but not in `Rewrap`.
#[test]
fn rewrap_rejects_an_unsupported_version() {
    let (mut env, _) = fast_env("pw");
    env.version = 2;
    assert!(matches!(
        env.rewrap("pw", "new"),
        Err(Error::UnsupportedVersion(2))
    ));
}

fn b64_of(b: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(b)
}
