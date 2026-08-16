//! Reading a `did:webvh` identifier's own segments — nothing more.
//!
//! # Why the relay parses a DID it refuses to verify
//!
//! [`crate::anchor`] states the division of labour: DID cryptography lives in
//! the anchor, in one place, so a relay never has to be upgraded in lockstep
//! with a DID method. That still holds. This module does not verify anything —
//! no SCID hash, no log, no signature. It reads two strings the identifier
//! carries in plain text, so that [`crate::provision`] can answer a question
//! that is *policy*, not cryptography: **is this identity's home domain one
//! this relay accepts accounts from, and is it asking for its own name?**
//!
//! Those two checks need no network and no keys, which is exactly why they
//! belong here rather than behind an anchor round trip: a request that fails
//! them is refused before the relay spends anything on it.
//!
//! Parsing is therefore deliberately **loose about the SCID and strict about
//! the shape**. The SCID is only checked for being non-empty — its real
//! verification is a hash of the genesis log entry, which only a resolver can
//! do. The path, in contrast, is checked exactly, because it is what carries
//! the username this module exists to read.
//!
//! # One path segment, no `dids/` prefix
//!
//! biset's own shape is `did:webvh:{scid}:{domain}:{username}` (see the
//! client's `did/webvh/identifier.ts`, `buildBisetWebvhDid`). The older
//! `…:{domain}:dids:{username}` form is **not** accepted: it names a different
//! log URL, so treating its second segment as a username would authorise a
//! name against a document that lives somewhere else.
//!
//! A DID at an apex (no path segment at all, log at `.well-known/did.jsonl`)
//! has no username to read and is rejected for the same reason — there is
//! nothing in it to match a localpart against.

/// The parts of a `did:webvh` identifier this relay can act on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebvhId {
    /// Unverified. Carried only so a caller can log or echo the whole DID.
    pub scid: String,
    /// Lowercased, port stripped. The identity's home domain — what
    /// `authorized_did_domain` is matched against.
    pub domain: String,
    /// Present only for a non-default port, which biset never mints but the
    /// method allows. Kept separate so it can never leak into a domain match.
    pub port: Option<u16>,
    /// The single path segment, percent-decoded. biset's username.
    pub username: String,
}

/// Why an identifier could not be read.
///
/// Distinct from a *policy* refusal: this is "that is not a shape I can read
/// a username out of", which the caller turns into its own refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    /// Not a `did:webvh:` identifier at all.
    NotWebvh,
    /// A required segment was empty or absent.
    MalformedSegments,
    /// Zero path segments (an apex DID), or more than one (the legacy
    /// `dids/` form, or somebody else's path convention).
    NotSingleSegmentPath,
    /// The port after `%3A` was not a number in range.
    BadPort,
    /// The username segment decoded to something that cannot be a name — see
    /// [`parse`] for what is excluded and why.
    BadUsername,
}

/// Read a `did:webvh` identifier.
///
/// The username is percent-decoded, then rejected if it contains anything
/// that could make it mean something other than a name: a path separator, a
/// NUL, or the relative segments `.` and `..`. Those are the same exclusions
/// the client's `didToHttpsUrl` applies when it builds the log URL, and for
/// the same reason — a name that escapes its own directory addresses a
/// different document than the one it claims to be.
///
/// Case is **not** folded here. `crate::provision` compares against an
/// already-lowercased username, and folding twice in different places is how
/// the two drift apart.
pub fn parse(did: &str) -> Result<WebvhId, ParseError> {
    let rest = did.strip_prefix("did:webvh:").ok_or(ParseError::NotWebvh)?;
    let mut segments = rest.split(':');

    let scid = segments.next().unwrap_or_default();
    if scid.is_empty() {
        return Err(ParseError::MalformedSegments);
    }
    let domain_and_port = segments.next().unwrap_or_default();
    if domain_and_port.is_empty() {
        return Err(ParseError::MalformedSegments);
    }

    let path: Vec<&str> = segments.collect();
    // Exactly one, always. Zero is an apex DID with no username in it; two or
    // more is the legacy `dids:` form or a foreign convention, and in both
    // cases the last segment is not a name this relay may authorise.
    let [username_raw] = path[..] else {
        return Err(ParseError::NotSingleSegmentPath);
    };

    let (domain, port) = split_port(domain_and_port)?;
    if domain.is_empty() {
        return Err(ParseError::MalformedSegments);
    }

    let username = percent_decode(username_raw).ok_or(ParseError::BadUsername)?;
    if username.is_empty()
        || username == "."
        || username == ".."
        || username.contains(['/', '\\', '\0'])
        || username.trim() != username
    {
        return Err(ParseError::BadUsername);
    }

    Ok(WebvhId {
        scid: scid.to_string(),
        domain,
        port,
        username,
    })
}

/// Split `example.com%3A8443` into its host and port.
///
/// `%3A` is the method's own escape for the colon it uses as a segment
/// separator, so this is not general percent-decoding — a literal `:` here
/// would already have split the identifier one segment earlier.
fn split_port(domain_and_port: &str) -> Result<(String, Option<u16>), ParseError> {
    let lower = domain_and_port.to_ascii_lowercase();
    let Some((host, port)) = lower.split_once("%3a") else {
        return Ok((lower, None));
    };
    let port: u16 = port.parse().map_err(|_| ParseError::BadPort)?;
    if port == 0 {
        return Err(ParseError::BadPort);
    }
    Ok((host.to_string(), Some(port)))
}

/// Percent-decode one path segment, rejecting invalid escapes and any result
/// that is not UTF-8.
fn percent_decode(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = bytes.get(i + 1..i + 3)?;
            let hex = std::str::from_utf8(hex).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

#[cfg(test)]
mod tests;
