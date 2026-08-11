//! JSON serialisation byte-compatible with Go's `encoding/json`.
//!
//! `json.Marshal` HTML-escapes by default: `<`, `>` and `&` come out as
//! `\u003c`, `\u003e` and `\u0026`, and the Unicode line separators U+2028
//! and U+2029 as `\u2028` and `\u2029`. `serde_json` emits all five raw.
//!
//! That difference is invisible until it is not. Angle brackets are
//! everywhere in mail — `inReplyTo` and `references` hold `<id@host>`
//! verbatim — and `&` is ordinary in a subject line. Every affected message
//! file would differ from the Go-written one byte for byte while carrying
//! identical data, so a store rewritten by this implementation would churn
//! every such file and the differential harness would light up with hundreds
//! of false differences that hide the real ones.
//!
//! Found by the store interop test, not by reading either implementation.
//!
//! Use [`to_vec`] and [`to_string`] wherever the output is written to disk or
//! sent to a client. Plain `serde_json::to_vec` is fine only for values that
//! never leave this process.

use std::io;

use serde::Serialize;
use serde_json::ser::{Formatter, Serializer};

/// Serialise to bytes the way Go would.
pub fn to_vec<T: Serialize + ?Sized>(value: &T) -> serde_json::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(128);
    let mut ser = Serializer::with_formatter(&mut out, GoFormatter);
    value.serialize(&mut ser)?;
    Ok(out)
}

/// Serialise to a string the way Go would.
pub fn to_string<T: Serialize + ?Sized>(value: &T) -> serde_json::Result<String> {
    let bytes = to_vec(value)?;
    // Every byte written is valid UTF-8: serde_json only ever emits ASCII
    // structure plus the UTF-8 of the input strings.
    Ok(String::from_utf8(bytes).expect("serde_json emits UTF-8"))
}

/// A [`Formatter`] that adds Go's HTML escaping.
///
/// `serde_json` hands every run of characters that needs no escaping of its
/// own to `write_string_fragment`, so intercepting there is enough: the five
/// characters below are not in its escape table and always arrive raw.
struct GoFormatter;

impl Formatter for GoFormatter {
    fn write_string_fragment<W>(&mut self, writer: &mut W, fragment: &str) -> io::Result<()>
    where
        W: ?Sized + io::Write,
    {
        let mut start = 0;
        for (i, c) in fragment.char_indices() {
            let escaped = match c {
                '<' => r"\u003c",
                '>' => r"\u003e",
                '&' => r"\u0026",
                '\u{2028}' => r"\u2028",
                '\u{2029}' => r"\u2029",
                _ => continue,
            };
            writer.write_all(&fragment.as_bytes()[start..i])?;
            writer.write_all(escaped.as_bytes())?;
            start = i + c.len_utf8();
        }
        writer.write_all(&fragment.as_bytes()[start..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Expected values captured from Go's `json.Marshal`.
    #[test]
    fn escapes_the_five_characters_go_escapes() {
        assert_eq!(
            to_string(&json!({"v": "<a>&b"})).unwrap(),
            r#"{"v":"\u003ca\u003e\u0026b"}"#
        );
        assert_eq!(
            to_string(&json!({"v": "a\u{2028}b\u{2029}c"})).unwrap(),
            r#"{"v":"a\u2028b\u2029c"}"#
        );
    }

    /// The case that actually occurs: a bracketed Message-ID.
    #[test]
    fn escapes_a_bracketed_message_id() {
        assert_eq!(
            to_string(&json!({"inReplyTo": ["<parent@example.com>"]})).unwrap(),
            r#"{"inReplyTo":["\u003cparent@example.com\u003e"]}"#
        );
    }

    /// Everything else must be untouched — including the escapes serde_json
    /// already agrees with Go about.
    #[test]
    fn leaves_ordinary_text_alone() {
        for value in [
            json!({"v": "plain ascii"}),
            json!({"v": "日本語とemoji🙂"}),
            json!({"v": "quote\" backslash\\ newline\n tab\t"}),
            json!({"v": ""}),
            json!({"n": 42, "b": true, "z": null}),
        ] {
            assert_eq!(
                to_string(&value).unwrap(),
                serde_json::to_string(&value).unwrap(),
                "should match plain serde_json when no HTML escaping applies"
            );
        }
    }

    /// Escaping only changes the encoding, never the value.
    #[test]
    fn round_trips_through_a_normal_parser() {
        let original = json!({"a": "<&>", "b": ["x\u{2028}y"], "c": {"d": "&&&"}});
        let encoded = to_string(&original).unwrap();
        let decoded: serde_json::Value = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    /// A fragment made entirely of escaped characters, and one starting or
    /// ending with them — the boundaries of the fragment-splitting loop.
    #[test]
    fn handles_escapes_at_fragment_boundaries() {
        assert_eq!(to_string(&json!("<")).unwrap(), r#""\u003c""#);
        assert_eq!(to_string(&json!("<<<")).unwrap(), r#""\u003c\u003c\u003c""#);
        assert_eq!(to_string(&json!("<a")).unwrap(), r#""\u003ca""#);
        assert_eq!(to_string(&json!("a<")).unwrap(), r#""a\u003c""#);
    }
}
