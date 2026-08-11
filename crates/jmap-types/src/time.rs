//! JMAP UTCDate values.
//!
//! A stored message is read, possibly modified, and written back whole. If a
//! timestamp were parsed into a datetime and re-serialised, every rewrite
//! would rewrite the representation too — `+09:00` becoming `Z`, `.12`
//! becoming `.120000000` — silently churning files that were meant to be left
//! alone and breaking byte-level comparison against the Go implementation.
//!
//! So a timestamp is kept as **the exact string it arrived as**. Parsing
//! happens only when something needs to order two of them, and formatting
//! only when minting a new one.
//!
//! Go's `time.Time` marshals as RFC 3339 with a variable-precision fraction:
//! nine digits, trailing zeros trimmed, and the decimal point dropped when
//! nothing is left. Verified against the Go implementation:
//!
//! ```text
//! 2026-07-27T23:49:16Z
//! 2026-07-27T23:49:16.123456789Z
//! 2026-07-27T23:49:16.12Z          (not .120000000)
//! 2026-07-27T23:49:16+09:00        (offset preserved, not normalised to Z)
//! ```

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
// `::time` disambiguates the crate from this module, which shadows it.
use ::time::OffsetDateTime;
use ::time::format_description::well_known::Rfc3339;

/// A JMAP UTCDate, preserved verbatim.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct JmapTime(String);

impl JmapTime {
    /// Wrap a string as-is. Whatever it is, it comes back out unchanged.
    pub fn from_raw(s: impl Into<String>) -> Self {
        JmapTime(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The current time in UTC, formatted the way Go would.
    pub fn now_utc() -> Self {
        Self::from_datetime(OffsetDateTime::now_utc())
    }

    /// Format a datetime the way Go's `time.Time` marshals one.
    pub fn from_datetime(t: OffsetDateTime) -> Self {
        JmapTime(format_go_style(t))
    }

    /// Parse for ordering. `None` when the string is not RFC 3339 — which
    /// sorts it to the epoch rather than dropping the message, matching Go,
    /// where an unparseable timestamp leaves a nil `*time.Time` that
    /// `timeVal` turns into the zero time.
    pub fn to_datetime(&self) -> Option<OffsetDateTime> {
        OffsetDateTime::parse(&self.0, &Rfc3339).ok()
    }

    /// The instant this represents, or the epoch when it cannot be parsed.
    /// Mirrors go-jmapserver's `timeVal`.
    pub fn sort_key(&self) -> OffsetDateTime {
        self.to_datetime().unwrap_or(OffsetDateTime::UNIX_EPOCH)
    }
}

impl fmt::Display for JmapTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for JmapTime {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for JmapTime {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(JmapTime(String::deserialize(d)?))
    }
}

/// RFC 3339 with Go's fractional-second rules.
///
/// The `time` crate always emits either no fraction or a fixed-width one, so
/// the trimming is done here rather than through a format description.
fn format_go_style(t: OffsetDateTime) -> String {
    let nanos = t.nanosecond();
    let date = format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        t.year(),
        u8::from(t.month()),
        t.day(),
        t.hour(),
        t.minute(),
        t.second(),
    );

    let mut out = date;
    if nanos != 0 {
        let frac = format!("{nanos:09}");
        let trimmed = frac.trim_end_matches('0');
        if !trimmed.is_empty() {
            out.push('.');
            out.push_str(trimmed);
        }
    }

    let offset = t.offset();
    if offset.is_utc() {
        out.push('Z');
    } else {
        let (h, m, _) = offset.as_hms();
        let sign = if offset.is_negative() { '-' } else { '+' };
        out.push_str(&format!("{sign}{:02}:{:02}", h.abs(), m.abs()));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ::time::macros::datetime;

    /// The four cases captured from the Go implementation, in this module's
    /// header.
    #[test]
    fn formats_like_go() {
        assert_eq!(
            format_go_style(datetime!(2026-07-27 23:49:16 UTC)),
            "2026-07-27T23:49:16Z"
        );
        assert_eq!(
            format_go_style(datetime!(2026-07-27 23:49:16.123456789 UTC)),
            "2026-07-27T23:49:16.123456789Z"
        );
        assert_eq!(
            format_go_style(datetime!(2026-07-27 23:49:16.12 UTC)),
            "2026-07-27T23:49:16.12Z",
            "trailing zeros in the fraction must be trimmed"
        );
        assert_eq!(
            format_go_style(datetime!(2026-07-27 23:49:16 +09:00)),
            "2026-07-27T23:49:16+09:00",
            "a non-UTC offset must be preserved, not normalised to Z"
        );
        assert_eq!(
            format_go_style(datetime!(2026-07-27 23:49:16 -05:30)),
            "2026-07-27T23:49:16-05:30"
        );
    }

    /// The property that makes storing the raw string worth the trouble.
    #[test]
    fn round_trips_verbatim() {
        for s in [
            "2026-07-27T23:49:16Z",
            "2026-07-27T23:49:16.12Z",
            "2026-07-27T23:49:16+09:00",
            "2026-07-27T23:49:16.000000001-05:30",
            "not a timestamp at all",
        ] {
            let t = JmapTime::from_raw(s);
            let json = serde_json::to_string(&t).unwrap();
            let back: JmapTime = serde_json::from_str(&json).unwrap();
            assert_eq!(back.as_str(), s, "{s} did not survive a round trip");
        }
    }

    #[test]
    fn orders_across_offsets() {
        // Same instant, different offsets: neither is before the other.
        let utc = JmapTime::from_raw("2026-07-27T23:49:16Z");
        let jst = JmapTime::from_raw("2026-07-28T08:49:16+09:00");
        assert_eq!(utc.sort_key(), jst.sort_key());

        let later = JmapTime::from_raw("2026-07-27T23:49:17Z");
        assert!(later.sort_key() > utc.sort_key());
    }

    #[test]
    fn unparseable_sorts_to_the_epoch() {
        assert_eq!(
            JmapTime::from_raw("garbage").sort_key(),
            OffsetDateTime::UNIX_EPOCH
        );
    }
}
