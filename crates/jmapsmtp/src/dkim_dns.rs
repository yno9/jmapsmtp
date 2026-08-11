//! Does DNS publish the key this relay actually signs with?
//!
//! Nothing checked, and the answer was no. `biset.md` signed every outbound
//! message with `data/biset.md/key.pem` while `default._domainkey.biset.md`
//! published a different key — one whose private half exists on neither host.
//! Every signature the relay produced failed verification. Most receivers
//! accept unverified mail and say nothing, so it looked fine for months; the
//! first receiver that insists (Delta Chat's chatmail) answered
//! `554 5.7.1 No valid DKIM signature found` and that is how it surfaced.
//!
//! The same audit found `t.biset.md` — the domain accounts are provisioned
//! into, twenty-one of them — with no record published at all.
//!
//! A relay is the only thing that can notice this: it holds the private key
//! and can read the public one. It cost one lookup per domain at startup.
//!
//! # Not fatal
//!
//! A mismatch does not stop the relay. Mail with a bad signature still gets
//! delivered by most of the internet, and refusing to start would turn a
//! deliverability problem into an outage. DNS being unreachable says nothing
//! at all, and is reported as such rather than as a mismatch — the same
//! fail-open rule the ownership proofs use, for the same reason.

use crate::dns::TxtResolver;

/// What one domain's lookup found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Finding {
    /// DNS publishes exactly what this relay signs with.
    Match,
    /// A record exists and holds a different key. Signatures fail.
    Mismatch,
    /// No `v=DKIM1` record at the name. Signatures fail.
    Missing,
    /// The name answered nothing at all. Could be a lookup failure, so it is
    /// reported separately from `Missing` and not as a mismatch.
    NoAnswer,
}

impl Finding {
    /// Whether an operator needs to do something.
    pub fn is_problem(&self) -> bool {
        matches!(self, Finding::Mismatch | Finding::Missing)
    }
}

/// Compare a published record set against the key this relay holds.
///
/// `expected` is [`crate::dkim::public_key_record`]'s output — the whole
/// `v=DKIM1; k=rsa; p=…` string. Only `p=` is compared: a record may
/// legitimately carry `t=s`, `h=sha256` or a different tag order, and none of
/// that changes which key verifies.
///
/// Split into a function taking the records because the interesting part is
/// this comparison, and a test that has to stand up DNS to reach it is a test
/// nobody writes.
pub fn decide(published: &[String], expected: &str) -> Finding {
    let Some(want) = tag(expected, 'p') else {
        return Finding::NoAnswer;
    };
    if published.is_empty() {
        return Finding::NoAnswer;
    }
    // A long TXT record arrives as several strings to be concatenated
    // (RFC 7208 §3.3); resolvers differ on whether they have already joined
    // them. Try each record whole, and the whole set joined.
    let joined = published.concat();
    let candidates = published
        .iter()
        .map(String::as_str)
        .chain([joined.as_str()]);

    let mut saw_dkim_record = false;
    for record in candidates {
        let record = record.replace([' ', '\t', '\r', '\n'], "");
        if !record.to_ascii_lowercase().contains("v=dkim1") && !record.contains("p=") {
            continue;
        }
        saw_dkim_record = true;
        if let Some(got) = tag(&record, 'p')
            && got == want
        {
            return Finding::Match;
        }
    }
    if saw_dkim_record {
        Finding::Mismatch
    } else {
        Finding::Missing
    }
}

/// The value of a `key=value` tag in a DKIM record, whitespace removed.
///
/// `p=` is base64 and may contain `=` padding, so the value runs to the next
/// `;` rather than to the next `=`.
fn tag(record: &str, name: char) -> Option<String> {
    for part in record.split(';') {
        let part = part.trim();
        let mut it = part.splitn(2, '=');
        let k = it.next()?.trim();
        if k.len() == 1 && k.starts_with(name) {
            let v = it.next()?;
            return Some(v.replace([' ', '\t', '\r', '\n'], ""));
        }
    }
    None
}

/// The name a domain's key is published under.
pub fn record_name(selector: &str, domain: &str) -> String {
    format!("{selector}._domainkey.{domain}")
}

/// Check one domain and log the result.
///
/// Returns the finding so a caller (and a test) can see it; the log line is
/// what an operator sees.
pub fn check_domain(
    resolver: &dyn TxtResolver,
    selector: &str,
    domain: &str,
    expected_record: &str,
) -> Finding {
    let name = record_name(selector, domain);
    let finding = decide(&resolver.lookup_txt(&name), expected_record);
    match finding {
        Finding::Match => tracing::info!("[dkim-dns] {name}: published key matches"),
        Finding::Mismatch => tracing::warn!(
            "[dkim-dns] {name} publishes a DIFFERENT key — every signature this \
             relay makes for {domain} fails verification. Publish the record in \
             data/{domain}/dkim-dns.txt"
        ),
        Finding::Missing => tracing::warn!(
            "[dkim-dns] {name} has no DKIM record — every signature this relay \
             makes for {domain} fails verification. Publish the record in \
             data/{domain}/dkim-dns.txt"
        ),
        Finding::NoAnswer => tracing::info!(
            "[dkim-dns] {name}: no answer — DNS may be unreachable, so this is \
             not a verdict"
        ),
    }
    finding
}

#[cfg(test)]
mod tests;
