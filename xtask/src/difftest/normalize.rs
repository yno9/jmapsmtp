//! Stripping non-determinism before comparison.
//!
//! **This list is the specification of what the two implementations are
//! allowed to disagree about.** Everything not listed here must match byte for
//! byte. Adding a filter is therefore never a bookkeeping change: it widens
//! the blind spot, so each one carries the reason it is unavoidable.
//!
//! A filter is only justified when the value is genuinely unpredictable —
//! random bytes, a clock reading, or an ordering the language leaves
//! unspecified. If determinism can instead be arranged by seeding the input,
//! that belongs in `fixture.rs`, not here.

use regex::Regex;
use std::sync::LazyLock;

/// One named substitution. The name appears in `--show-filters` and in
/// mismatch reports, so a reader can see which filters were in play.
pub struct Filter {
    pub name: &'static str,
    pub why: &'static str,
    re: Regex,
    with: &'static str,
}

impl Filter {
    fn new(name: &'static str, why: &'static str, pattern: &str, with: &'static str) -> Self {
        Filter {
            name,
            why,
            re: Regex::new(pattern).expect("filter pattern must compile"),
            with,
        }
    }
}

/// Applied in order. Order matters where one pattern would otherwise eat
/// another's input — the PGP and DKIM block filters run before the generic
/// base64 and digit filters for exactly that reason.
pub static FILTERS: LazyLock<Vec<Filter>> = LazyLock::new(|| {
    vec![
        // ── whole blocks first ────────────────────────────────────────────
        Filter::new(
            "pgp-message",
            "OpenPGP encrypts with a fresh random session key every time, so \
             two encryptions of identical plaintext under identical keys never \
             match. Cross-decryption is tested separately (PLAN.md §8-B).",
            r"(?s)-----BEGIN PGP MESSAGE-----.*?-----END PGP MESSAGE-----",
            "<PGP-MESSAGE>",
        ),
        Filter::new(
            "dkim-signature",
            "The DKIM signature covers a Date header and carries its own t= \
             timestamp, so it differs even with the same seeded key. That the \
             signature VERIFIES is checked separately (PLAN.md M5).",
            r"b=[A-Za-z0-9+/=\r\n\t ]+",
            "b=<DKIM-SIG>",
        ),
        // ── identifiers minted from a clock plus randomness ───────────────
        Filter::new(
            "server-id",
            "main.go's newID(): srv-<unix millis>-<8 random bytes>.",
            r"srv-\d{13}-[0-9a-f]{16}",
            "<SRV-ID>",
        ),
        Filter::new(
            "rfc-message-id",
            "makeStore's pre-assigned Message-ID: <unix nanos>.<6 random \
             bytes>@domain.",
            r"\d{19}\.[0-9a-f]{12}@",
            "<RFC-MSGID>@",
        ),
        Filter::new(
            "mime-boundary-biset",
            "buildEncryptedMultipart's boundary: biset_<16 random bytes>.",
            r"biset_[0-9a-f]{32}",
            "<BOUNDARY>",
        ),
        Filter::new(
            "mime-boundary-pgp",
            "pgpMIMEWrapInline's boundary is sha1 of the PGP block, which is \
             itself random (see pgp-message above).",
            r"biset-pgp-[0-9a-f]{12}",
            "<PGP-BOUNDARY>",
        ),
        Filter::new(
            "session-token",
            "IssueSessionToken mints 32 random bytes; only its hash is stored.",
            r#""token":"[A-Za-z0-9+/]{40,}={0,2}""#,
            r#""token":"<SESSION-TOKEN>""#,
        ),
        Filter::new(
            "setup-token",
            "generateToken(): 16 random bytes as hex. Seeded in fixture.rs, so \
             this only catches a token the relay minted for an account the \
             fixture did not cover.",
            r"\b[0-9a-f]{32}\b",
            "<SETUP-TOKEN>",
        ),
        // ── clock readings ────────────────────────────────────────────────
        Filter::new(
            "rfc3339-time",
            "receivedAt / sentAt and every other JMAP UTCDate.",
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z",
            "<TIME>",
        ),
        Filter::new(
            "rfc5322-date",
            "The Date: header of a built message.",
            r"(?im)^Date: .*$",
            "Date: <DATE>",
        ),
        Filter::new(
            "go-log-timestamp",
            "The Go log package stamps every line with the local time. Only \
             applies to captured logs.",
            r"(?m)^\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} ",
            "",
        ),
        Filter::new(
            "dkim-dns-check",
            "SPEC.md §11.24: this port checks at startup whether DNS publishes \
             the key it signs with, and Go does not. The difference is a log \
             line Go has no counterpart for, so it cannot be compared — only \
             dropped. Narrow to the `[dkim-dns]` prefix on purpose: the \
             signing lines (`[dkim] …`) are still compared, and a future \
             check that started shouting on every request would not be hidden \
             by this.",
            r"(?m)^.*\[dkim-dns\].*$\n?",
            "",
        ),
        Filter::new(
            "tracing-level",
            "This port logs through `tracing`, which prefixes each line with \
             a padded level; Go's `log` package writes none. The level is \
             formatting, not behaviour — what the relay says is the contract, \
             not how the line is decorated. Must run BEFORE binary-name, \
             which anchors at the start of the line: with the level still \
             there, that filter matched only the Go side. It also sorts \
             before `[`, so the set comparison misaligned and reported the \
             difference against an unrelated line.",
            r"(?m)^ *(TRACE|DEBUG|INFO|WARN|ERROR) ",
            "",
        ),
        // **After** go-log-timestamp: until that has run, the Go line still
        // starts with a timestamp and an anchored pattern matches only this
        // port's side — which is exactly what happened first time.
        Filter::new(
            "binary-name",
            "The line announcing the JMAP listener is prefixed with the \
             program's own name. A Rust binary calling itself `go-jmap-smtp` \
             would be worse than the difference.",
            r"(?m)^(go-jmap-smtp|jmapsmtp): ",
            "<binary>: ",
        ),
        // ── the one thing the two sides are configured to differ in ───────
        Filter::new(
            "listen-port",
            "The two instances must bind different ports to run at once — \
             the single intentional difference in their config. base_url is \
             deliberately NOT port-derived (see fixture.rs), so this only \
             ever fires on log lines reporting what was bound.",
            r"(127\.0\.0\.1)?:\d{4,5}\b",
            "$1:<PORT>",
        ),
        Filter::new(
            "epoch-fields",
            "created_at / expires_at / bind_ts / ts: seconds since the epoch \
             in JSON. Targeted at the field name rather than at bare digits, \
             so an unrelated number still has to match.",
            r#""(created_at|expires_at|bind_ts|ts|receivedAt|sentAt)":\s*\d+"#,
            r#""$1":<EPOCH>"#,
        ),
        Filter::new(
            "epoch-millis",
            "Bare 13-digit millisecond timestamps embedded in ids that the \
             more specific id filters above did not already cover.",
            r"\b\d{13}\b",
            "<EPOCH-MS>",
        ),
    ]
});

/// Run every filter, in order.
pub fn normalize(input: &str) -> String {
    let mut out = input.to_string();
    for f in FILTERS.iter() {
        // Multi-line anchors are needed for the header filters; enabling them
        // globally is harmless for the rest since no pattern uses $ otherwise.
        out = f.re.replace_all(&out, f.with).into_owned();
    }
    out
}

/// Response headers worth comparing. Everything else (Date, Content-Length,
/// and any transport-level header) is dropped: Date is a clock reading, and
/// Content-Length is derived from a body that normalisation has already
/// changed the length of.
pub const COMPARED_HEADERS: &[&str] = &[
    "access-control-allow-origin",
    "access-control-allow-methods",
    "access-control-allow-headers",
    "content-type",
    "www-authenticate",
    "location",
];

/// Pretty-print a JSON body so a mismatch report shows a line-level diff
/// instead of one enormous line. Non-JSON passes through untouched.
pub fn pretty_if_json(body: &str) -> String {
    match serde_json::from_str::<serde_json::Value>(body) {
        Ok(v) => serde_json::to_string_pretty(&v).unwrap_or_else(|_| body.to_string()),
        Err(_) => body.to_string(),
    }
}

/// Reduce a Prometheus exposition to its sorted, unique metric names.
///
/// `/metrics` reports process memory, file descriptors and GC counters, none
/// of which can match across two processes. The contract that actually
/// matters — and the one PLAN.md M7 states — is that the metric NAMES and
/// their HELP/TYPE lines agree.
pub fn metric_names(body: &str) -> String {
    let mut names: Vec<&str> = body
        .lines()
        .filter_map(|l| {
            let l = l.trim();
            if let Some(rest) = l.strip_prefix("# TYPE ") {
                return rest.split_whitespace().next();
            }
            if l.starts_with('#') || l.is_empty() {
                return None;
            }
            // `name{labels} value` or `name value`
            let name = l.split(['{', ' ']).next()?;
            (!name.is_empty()).then_some(name)
        })
        .collect();
    names.sort_unstable();
    names.dedup();
    names.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_filter_pattern_compiles() {
        assert!(!FILTERS.is_empty());
    }

    #[test]
    fn strips_server_ids_and_times() {
        let got = normalize(
            r#"{"id":"srv-1753660000000-0011223344556677","receivedAt":"2026-07-27T23:49:16Z"}"#,
        );
        assert_eq!(got, r#"{"id":"<SRV-ID>","receivedAt":"<TIME>"}"#);
    }

    #[test]
    fn leaves_ordinary_values_alone() {
        let s = r#"{"name":"alice@example.com","state":"0","size":42}"#;
        assert_eq!(normalize(s), s);
    }

    #[test]
    fn metric_names_ignores_values() {
        let a = "# TYPE foo counter\nfoo{result=\"sent\"} 1\nbar 7\n";
        let b = "# TYPE foo counter\nfoo{result=\"sent\"} 99\nbar 3\n";
        assert_eq!(metric_names(a), metric_names(b));
        assert_eq!(metric_names(a), "bar\nfoo");
    }
}
