//! Bitcoin-style base58 (base58btc, the multibase code `z` uses) — encode and
//! decode, both directions.
//!
//! did:webvh's SCID (DIDWEBVHFEAT.md §3) is the only thing in this crate that
//! currently needs this, but the encoding itself has nothing to do with DIDs
//! — it is a generic way to turn bytes into a string that avoids visually
//! ambiguous characters (`0`/`O`, `I`/`l`, all excluded). Filing it under
//! `did/` because DID is its only caller today would be the exact mistake
//! `zbase32.rs`'s own header already warns against: an encoding is not a DID
//! method, and a future non-DID caller (there is precedent — WKD's own hash
//! uses `zbase32`, a sibling encoding, for a reason unrelated to any
//! identity scheme) should not have to reach into `did/` to find it.
//!
//! Not `bs58` or another crate: ~40 lines of the textbook arbitrary-base
//! conversion algorithm, same size as `zbase32.rs`'s hand-rolled codec, and
//! this crate already prefers that over a dependency for encodings this
//! small (`zbase32.rs`'s own precedent).

const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Encodes bytes to base58. Each leading `0x00` byte becomes a leading `1` —
/// the standard convention (distinct from an ordinary base conversion, which
/// would drop leading zeros entirely) — so `decode` can recover the exact
/// byte length rather than guessing how many zero bytes to prepend.
pub fn encode(bytes: &[u8]) -> String {
    let zeros = bytes.iter().take_while(|&&b| b == 0).count();

    // The accumulator holds the base58 digits of the non-zero-prefix part,
    // least-significant digit first — built by repeatedly folding in one
    // more input byte (multiply the existing bignum by 256, add the byte,
    // carrying in base 58) rather than dividing the whole input by 58
    // repeatedly, which is the same total work with none of the mutable
    // aliasing a division-based approach would need.
    let mut digits: Vec<u8> = Vec::with_capacity(bytes.len() * 138 / 100 + 1);
    for &byte in bytes {
        let mut carry = u32::from(byte);
        for d in digits.iter_mut() {
            let value = u32::from(*d) * 256 + carry;
            *d = (value % 58) as u8;
            carry = value / 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }

    let mut out = String::with_capacity(zeros + digits.len());
    out.extend(std::iter::repeat_n('1', zeros));
    out.extend(digits.iter().rev().map(|&d| ALPHABET[d as usize] as char));
    out
}

/// Decodes base58 back to bytes, or `None` on a character outside the
/// alphabet. The inverse of `encode`: each leading `1` becomes a leading
/// `0x00` byte, so a round trip through `encode` reproduces the original
/// byte length exactly, including leading zero bytes.
pub fn decode(s: &str) -> Option<Vec<u8>> {
    let zeros = s.bytes().take_while(|&b| b == b'1').count();

    let mut bytes: Vec<u8> = Vec::with_capacity(s.len());
    for c in s.bytes().skip(zeros) {
        let mut carry = u32::from(ALPHABET.iter().position(|&a| a == c)? as u8);
        for b in bytes.iter_mut() {
            let value = u32::from(*b) * 58 + carry;
            *b = (value % 256) as u8;
            carry = value / 256;
        }
        while carry > 0 {
            bytes.push((carry % 256) as u8);
            carry /= 256;
        }
    }

    let mut out = vec![0u8; zeros];
    out.extend(bytes.iter().rev());
    Some(out)
}

#[cfg(test)]
mod tests;
