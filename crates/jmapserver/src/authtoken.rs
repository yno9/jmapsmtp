//! The per-account relay credential. Port of `go-jmapserver/authtoken.go`.
//!
//! The relay stores only `base64(sha256(token))`, never the token. A stolen
//! `data/` directory yields nothing that can be presented as a credential.

use base64::Engine as _;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq as _;

/// What goes in `auth_token_hash`.
pub fn hash_auth_token(token: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(Sha256::digest(token))
}

/// Compare a presented token against a stored hash, in constant time.
///
/// A malformed stored hash is a rejection, not an error: an account whose
/// credential file is corrupt cannot log in, and saying which of the two went
/// wrong would tell an attacker whether the account exists.
#[must_use]
pub fn verify_auth_token(token: &[u8], stored_hash_b64: &str) -> bool {
    let Ok(stored) = base64::engine::general_purpose::STANDARD.decode(stored_hash_b64) else {
        return false;
    };
    Sha256::digest(token).ct_eq(stored.as_slice()).into()
}

/// Decode a Basic Auth password field.
///
/// Four base64 alphabets are tried in the order the Go original tries them —
/// standard, then raw standard, then URL-safe, then raw URL-safe — because
/// clients differ and a token that fails to decode is indistinguishable from
/// a wrong one.
pub fn decode_auth_token(s: &str) -> Option<Vec<u8>> {
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    STANDARD
        .decode(s)
        .or_else(|_| STANDARD_NO_PAD.decode(s))
        .or_else(|_| URL_SAFE.decode(s))
        .or_else(|_| URL_SAFE_NO_PAD.decode(s))
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    /// The expected value was produced by the Go implementation.
    #[test]
    fn the_hash_matches_the_go_implementation() {
        assert_eq!(
            hash_auth_token(b"difftest-token-0000000000000000"),
            "lKZgMulAhrKKBTMc4n3VROb5xc90tMcBAjqDPZv9DLY="
        );
    }

    #[test]
    fn a_token_verifies_against_its_own_hash() {
        let token = b"some-token";
        assert!(verify_auth_token(token, &hash_auth_token(token)));
        assert!(!verify_auth_token(b"other", &hash_auth_token(token)));
    }

    #[test]
    fn a_corrupt_stored_hash_is_a_rejection_not_a_crash() {
        assert!(!verify_auth_token(b"token", "not base64!!"));
        assert!(!verify_auth_token(b"token", ""));
        // Right encoding, wrong length.
        assert!(!verify_auth_token(b"token", "AAAA"));
    }

    #[test]
    fn every_base64_alphabet_a_client_might_use_decodes() {
        let raw = b"\xfb\xff\xfe binary token";
        for encoded in [
            base64::engine::general_purpose::STANDARD.encode(raw),
            base64::engine::general_purpose::STANDARD_NO_PAD.encode(raw),
            base64::engine::general_purpose::URL_SAFE.encode(raw),
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw),
        ] {
            assert_eq!(
                decode_auth_token(&encoded).as_deref(),
                Some(&raw[..]),
                "{encoded} did not decode"
            );
        }
    }

    #[test]
    fn something_that_is_not_base64_at_all_is_none() {
        assert_eq!(decode_auth_token("not base64 !!!"), None);
    }
}
