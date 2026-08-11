//! Zooko Wilcox-O'Hearn's human-oriented base32.
//!
//! **Not** RFC 4648's alphabet. Two unrelated things in this relay need it:
//! WKD hashes a localpart with it (`wkd_hash`, the GnuPG spec), and did:dht
//! encoded its identifiers with it.
//!
//! It lived in `diddht.rs` until did:dht was removed, and moving it out is why
//! that removal did not take WKD with it: an encoding is not a DID method, and
//! filing it under one made a public directory depend on an identity scheme it
//! has nothing to do with.

/// The alphabet, which is the whole difference from RFC 4648.
const ALPHABET: &[u8; 32] = b"ybndrfg8ejkmcpqxot1uwisza345h769";

pub fn encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 8 / 5 + 1);
    let (mut bits, mut value) = (0u32, 0u32);
    for &b in data {
        value = (value << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            out.push(ALPHABET[((value >> (bits - 5)) & 31) as usize] as char);
            bits -= 5;
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((value << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// Decode exactly `byte_len` bytes, discarding the encoder's trailing padding
/// bits. `None` when the input has a character outside the alphabet, or does
/// not yield exactly that many bytes.
pub fn decode(s: &str, byte_len: usize) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(byte_len);
    let (mut bits, mut value) = (0u32, 0u32);
    for c in s.bytes() {
        let idx = ALPHABET.iter().position(|&a| a == c)? as u32;
        value = (value << 5) | idx;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            if out.len() < byte_len {
                out.push(((value >> bits) & 0xff) as u8);
            }
        }
    }
    (out.len() == byte_len).then_some(out)
}

#[cfg(test)]
mod tests;
