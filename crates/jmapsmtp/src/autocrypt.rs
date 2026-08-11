//! Autocrypt headers and PGP/MIME wrapping.
//!
//! Port of the byte-level half of `go-jmapsmtp/autocrypt.go`. Everything here
//! rewrites a raw RFC 5322 message and is deterministic, which is what makes
//! it comparable against the Go implementation byte for byte.
//!
//! The OpenPGP operations themselves — encrypting to a recipient's key,
//! reading a peer's key ring — are not deterministic (a fresh session key
//! every time) and are checked by cross-decryption instead.
//!
//! Every function here returns the message **unchanged** when it cannot do
//! its job. An unsigned or unwrapped message still gets delivered; a failure
//! that stops the send does not.

/// The header/body separator. Every function below works on messages already
/// in CRLF form — the send path builds them that way — so a message with bare
/// LF endings is left alone rather than half-rewritten.
const SEP: &[u8] = b"\r\n\r\n";

/// Add `Chat-Version: 1.0` so DeltaChat and compatible clients treat the
/// message as chat-type and apply Autocrypt to it.
///
/// A message that already carries the header is returned untouched. The check
/// is a substring search for `\nChat-Version:`, which also matches one in the
/// body; that is the Go behaviour, and injecting a duplicate would be worse.
pub fn inject_chat_version(raw: &[u8]) -> Vec<u8> {
    if contains(raw, b"\nChat-Version:") || raw.starts_with(b"Chat-Version:") {
        return raw.to_vec();
    }
    insert_header(raw, "Chat-Version: 1.0\r\n")
}

/// Add an `Autocrypt:` header carrying a serialised public key.
///
/// `key_data` is the base64 of the key's binary OpenPGP serialisation — not
/// armour, which is what the Autocrypt spec asks for.
pub fn inject_autocrypt(raw: &[u8], from: &str, key_data: &str) -> Vec<u8> {
    let header = format!("Autocrypt: addr={from}; prefer-encrypt=mutual; keydata={key_data}\r\n");
    insert_header(raw, &header)
}

/// Insert a header line at the end of the header block.
///
/// Returns the message unchanged when there is no header/body separator: a
/// message that is not a message cannot be given a header.
fn insert_header(raw: &[u8], header: &str) -> Vec<u8> {
    let Some(idx) = find(raw, SEP) else {
        return raw.to_vec();
    };
    // idx+2 is after the CRLF that ends the last header line and before the
    // blank line, so the new header lands as the final one.
    let mut out = Vec::with_capacity(raw.len() + header.len());
    out.extend_from_slice(&raw[..idx + 2]);
    out.extend_from_slice(header.as_bytes());
    out.extend_from_slice(&raw[idx + 2..]);
    out
}

/// Pull `addr` and `keydata` out of an `Autocrypt:` header value.
///
/// Attributes are `;`-separated `key=value` pairs. A pair with no `=` is
/// skipped, and unknown keys are ignored.
pub fn parse_autocrypt_header(header: &str) -> (String, String) {
    let (mut addr, mut keydata) = (String::new(), String::new());
    for part in header.split(';') {
        let Some((k, v)) = part.trim().split_once('=') else {
            continue;
        };
        match k.trim() {
            "addr" => addr = v.trim().to_string(),
            "keydata" => keydata = v.trim().to_string(),
            _ => {}
        }
    }
    (addr, keydata)
}

/// Undo the folding a long `keydata` attribute picked up in transit.
///
/// RFC 5322 lets a header be wrapped across lines; the base64 has to be put
/// back together before it can be decoded.
pub fn unfold_keydata(keydata: &str) -> String {
    keydata
        .chars()
        .filter(|c| !matches!(c, ' ' | '\t' | '\r' | '\n'))
        .collect()
}

/// Rewrap a message whose body is an inline PGP block as RFC 3156
/// `multipart/encrypted`, for SMTP transport and DeltaChat compatibility.
///
/// The client has already encrypted and signed; this only changes the
/// packaging. `None` when there is no header/body separator or no PGP block,
/// in which case the caller sends the message as it stands.
pub fn pgp_mime_wrap_inline(raw: &[u8]) -> Option<Vec<u8>> {
    let header_end = find(raw, SEP)?;
    let (orig_headers, body) = (&raw[..header_end], &raw[header_end + 4..]);

    const START: &[u8] = b"-----BEGIN PGP MESSAGE-----";
    const END: &[u8] = b"-----END PGP MESSAGE-----";
    let start = find(body, START)?;
    // The END marker is searched for **after** the BEGIN marker, which the Go
    // original does not do: it searches the whole body for each independently,
    // checks only that both were found, and then slices `body[start..end+len]`.
    // A body whose END marker precedes its BEGIN marker makes that slice run
    // backwards and panics — and this runs inside an unrecovered goroutine in
    // sendEmail, so the panic takes the entire relay process down, every
    // account on it, on a message body any authenticated sender controls.
    // SPEC.md §11.11.
    let end = find(&body[start..], END)? + start;
    let pgp_block = &body[start..end + END.len()];

    // The boundary is derived from the ciphertext, so it cannot collide with
    // anything inside it — and it makes this function deterministic, which is
    // what lets it be compared against the Go implementation.
    let digest = {
        use sha1::{Digest, Sha1};
        Sha1::digest(pgp_block)
    };
    let boundary = format!("biset-pgp-{}", hex_lower(&digest[..6]));

    let mut out = Vec::with_capacity(raw.len() + 256);
    // Content-Type and Content-Transfer-Encoding describe the old body and are
    // dropped; everything else is kept.
    for line in split_crlf(orig_headers) {
        let name = header_name(line);
        if name.eq_ignore_ascii_case("content-type")
            || name.eq_ignore_ascii_case("content-transfer-encoding")
        {
            continue;
        }
        out.extend_from_slice(line);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(
        format!(
            "Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=\"{boundary}\"\r\n"
        )
        .as_bytes(),
    );
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    out.extend_from_slice(b"Content-Type: application/pgp-encrypted\r\n\r\n");
    out.extend_from_slice(b"Version: 1\r\n");
    out.extend_from_slice(format!("\r\n--{boundary}\r\n").as_bytes());
    out.extend_from_slice(b"Content-Type: application/octet-stream\r\n\r\n");
    // The armour arrives with bare LF; SMTP wants CRLF.
    out.extend_from_slice(&replace_all(pgp_block, b"\n", b"\r\n"));
    out.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    Some(out)
}

/// The name part of a header line, or the whole line when there is no colon.
fn header_name(line: &[u8]) -> &str {
    let end = line.iter().position(|&b| b == b':').unwrap_or(line.len());
    std::str::from_utf8(&line[..end]).unwrap_or("")
}

/// Split on CRLF. Go's `strings.Split(s, "\r\n")` keeps a trailing empty
/// element when the input ends in the separator; this does not, and the
/// caller re-adds the terminator to every line it keeps, so the result
/// matches.
fn split_crlf(data: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut rest = data;
    while let Some(i) = find(rest, b"\r\n") {
        out.push(&rest[..i]);
        rest = &rest[i + 2..];
    }
    if !rest.is_empty() {
        out.push(rest);
    }
    out
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    find(haystack, needle).is_some()
}

fn replace_all(data: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut rest = data;
    while let Some(i) = find(rest, from) {
        out.extend_from_slice(&rest[..i]);
        out.extend_from_slice(to);
        rest = &rest[i + from.len()..];
    }
    out.extend_from_slice(rest);
    out
}

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut acc, b| {
        let _ = write!(acc, "{b:02x}");
        acc
    })
}

#[cfg(test)]
mod tests;
