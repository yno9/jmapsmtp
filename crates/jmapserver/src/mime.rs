//! RFC 5322 / MIME parsing and building.
//!
//! Port of the MIME half of `go-jmapserver/email.go`.
//!
//! Hand-rolled rather than delegated to a MIME crate. The Go original leans on
//! `net/mail` and `mime/multipart`, whose particular choices — which header
//! wins when one repeats, when an address list is dropped wholesale, how a
//! part with no Content-Type is treated — are what the stored messages and the
//! outgoing wire format are made of. A general-purpose parser would be better
//! at MIME and worse at *this* MIME; the interop test against the real Go
//! implementation is what decides, and matching it is the whole job.

use std::collections::BTreeMap;

use jmap_types::email::{BodyPart, BodyValue, Email, Header};
use jmap_types::emailsubmission::{Address as EnvAddress, Envelope};
use jmap_types::mail::Address;

/// Headers `ParseMIMEEmail` does not copy into `Email::headers`, because they
/// already have a typed home or are transport noise.
const STANDARD_HEADERS: &[&str] = &[
    "from",
    "to",
    "cc",
    "bcc",
    "subject",
    "date",
    "message-id",
    "in-reply-to",
    "references",
    "content-type",
    "content-transfer-encoding",
    "mime-version",
    "autocrypt",
    "autocrypt-gossip",
    "dkim-signature",
    "received",
    "return-path",
    "chat-version",
];

/// A parsed header block: names in their original case, values unfolded.
#[derive(Debug, Default, Clone)]
pub struct Headers {
    /// Every header in the order it appeared, so a repeated one keeps both.
    entries: Vec<(String, String)>,
}

impl Headers {
    /// The first value for `name`, case-insensitively. Go's
    /// `textproto.MIMEHeader.Get` returns the first of the slice.
    pub fn get(&self, name: &str) -> &str {
        self.entries
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map_or("", |(_, v)| v.as_str())
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.entries.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }
}

/// Split a message into its headers and body.
///
/// Returns `None` when there is no header/body separator, matching
/// `mail.ReadMessage`, which errors out and makes the caller give up.
pub fn split_message(data: &[u8]) -> Option<(Headers, &[u8])> {
    let (head, body) = split_head_body(data)?;
    Some((parse_headers(head), body))
}

/// Find the blank line ending the header block. Both CRLF and bare LF are
/// accepted; real mail arrives with either.
fn split_head_body(data: &[u8]) -> Option<(&[u8], &[u8])> {
    if let Some(i) = find(data, b"\r\n\r\n") {
        return Some((&data[..i + 2], &data[i + 4..]));
    }
    if let Some(i) = find(data, b"\n\n") {
        return Some((&data[..i + 1], &data[i + 2..]));
    }
    // A message that is nothing but headers still parses.
    if !data.is_empty() {
        return Some((data, &[]));
    }
    None
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Parse a header block, unfolding continuation lines (RFC 5322 §2.2.3).
fn parse_headers(head: &[u8]) -> Headers {
    let text = String::from_utf8_lossy(head);
    let mut entries: Vec<(String, String)> = Vec::new();
    for line in text.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.is_empty() {
            continue;
        }
        // A leading space or tab continues the previous header.
        if line.starts_with([' ', '\t']) {
            if let Some((_, v)) = entries.last_mut() {
                v.push(' ');
                v.push_str(line.trim_start());
            }
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            entries.push((name.trim().to_string(), value.trim().to_string()));
        }
    }
    Headers { entries }
}

/// Parse raw RFC 5322 bytes into an Email.
///
/// The caller sets `id`, `mailbox_ids` and `received_at` as appropriate;
/// `received_at` is filled in from the Date header here only as a default.
pub fn parse_mime_email(data: &[u8], now: &str) -> Option<Email> {
    let (headers, body) = split_message(data)?;

    let subject = decode_words(headers.get("Subject"));
    let msg_id = headers.get("Message-Id").trim_matches([' ', '<', '>']);
    let in_reply_to = headers.get("In-Reply-To").trim_matches([' ', '<', '>']);

    // An unparseable or absent Date falls back to now, as in Go.
    let date = parse_date(headers.get("Date")).unwrap_or_else(|| now.to_string());

    // From takes a single address and yields nothing at all if the header does
    // not parse; To and Cc take a list and are likewise all-or-nothing.
    let from = parse_address(headers.get("From"))
        .map(|a| vec![a])
        .unwrap_or_default();
    let to = parse_address_list(headers.get("To")).unwrap_or_default();
    let cc = parse_address_list(headers.get("Cc")).unwrap_or_default();

    let references: Vec<String> = headers
        .get("References")
        .split_whitespace()
        .map(|r| r.trim_matches(['<', '>']).to_string())
        .filter(|r| !r.is_empty())
        .collect();

    // Non-standard headers are preserved so Chat-Group-Id and friends survive.
    //
    // Go builds this by ranging over a map, so both the order and — for a
    // header that appears twice — which value wins are unspecified there.
    // Sorted by name, first occurrence winning, is deterministic and is what
    // the map lookup would have produced for the common case of one
    // occurrence. See SPEC.md §11.5.
    let mut extra: BTreeMap<&str, &str> = BTreeMap::new();
    for (name, value) in headers.iter() {
        if STANDARD_HEADERS
            .iter()
            .any(|s| name.eq_ignore_ascii_case(s))
        {
            continue;
        }
        extra.entry(name).or_insert(value);
    }
    let extra_headers: Vec<Header> = extra
        .into_iter()
        .map(|(name, value)| Header {
            name: name.to_string(),
            value: value.to_string(),
        })
        .collect();

    let body_text = extract_mime_text(
        headers.get("Content-Type"),
        headers.get("Content-Transfer-Encoding"),
        body,
    );

    const PART_ID: &str = "1";
    let mut body_values = BTreeMap::new();
    body_values.insert(PART_ID.to_string(), BodyValue::new(body_text));

    Some(Email {
        subject,
        from,
        to,
        cc,
        received_at: Some(jmap_types::JmapTime::from_raw(date)),
        message_id: if msg_id.is_empty() {
            vec![]
        } else {
            vec![msg_id.to_string()]
        },
        in_reply_to: if in_reply_to.is_empty() {
            vec![]
        } else {
            vec![in_reply_to.to_string()]
        },
        references,
        headers: extra_headers,
        body_values,
        text_body: vec![BodyPart {
            part_id: PART_ID.to_string(),
            type_: "text/plain".to_string(),
            ..Default::default()
        }],
        ..Default::default()
    })
}

/// Extract the text body, following the same rules as the Go original.
///
/// The `multipart/encrypted` branch deliberately skips any `text/plain`
/// fallback part: storing that would put the plaintext of a PGP/MIME message
/// on the server, which is the one thing the encryption was for.
pub fn extract_mime_text(content_type: &str, cte: &str, body: &[u8]) -> String {
    if content_type.is_empty() {
        return normalise_newlines(&String::from_utf8_lossy(body));
    }
    let Some((media, params)) = parse_media_type(content_type) else {
        return normalise_newlines(&String::from_utf8_lossy(body));
    };

    match media.as_str() {
        "text/plain" => normalise_newlines(&decode_transfer(cte, body)),
        "text/html" => html_to_markdown(&decode_transfer(cte, body)),
        "multipart/encrypted" => {
            let Some(boundary) = params.get("boundary") else {
                return String::new();
            };
            for part in split_parts(body, boundary) {
                let part_media = parse_media_type(part.headers.get("Content-Type"))
                    .map(|(m, _)| m)
                    .unwrap_or_default();
                if part_media == "application/octet-stream"
                    || part_media == "application/pgp-encrypted"
                {
                    let text = normalise_newlines(&decode_transfer(
                        part.headers.get("Content-Transfer-Encoding"),
                        part.body,
                    ));
                    if text.contains("-----BEGIN PGP MESSAGE-----") {
                        return text;
                    }
                }
            }
            String::new()
        }
        m if m.starts_with("multipart/") => {
            let Some(boundary) = params.get("boundary") else {
                return String::new();
            };
            let mut html_fallback = String::new();
            for part in split_parts(body, boundary) {
                let part_ct = part.headers.get("Content-Type");
                // A part with no Content-Type is skipped outright — not
                // treated as text/plain, which RFC 2045 would default it to.
                if part_ct.is_empty() {
                    continue;
                }
                let part_media = parse_media_type(part_ct)
                    .map(|(m, _)| m)
                    .unwrap_or_default();
                let part_cte = part.headers.get("Content-Transfer-Encoding");

                if part_media == "text/plain" {
                    return normalise_newlines(&decode_transfer(part_cte, part.body));
                }
                if part_media == "text/html" && html_fallback.is_empty() {
                    html_fallback = html_to_markdown(&decode_transfer(part_cte, part.body));
                }
                if part_media.starts_with("multipart/") {
                    let nested = extract_mime_text(part_ct, part_cte, part.body);
                    if !nested.is_empty() {
                        return nested;
                    }
                }
            }
            html_fallback
        }
        _ => String::new(),
    }
}

/// A decoded MIME attachment part.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attachment {
    pub filename: String,
    pub content_type: String,
    pub bytes: Vec<u8>,
}

/// Every part marked `Content-Disposition: attachment`, transfer-decoded.
/// Inline parts — related images and the like — are ignored.
pub fn extract_attachments(raw: &[u8]) -> Vec<Attachment> {
    let Some((headers, body)) = split_message(raw) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    collect_attachments(
        headers.get("Content-Type"),
        headers.get("Content-Transfer-Encoding"),
        headers.get("Content-Disposition"),
        body,
        &mut out,
    );
    out
}

fn collect_attachments(
    content_type: &str,
    cte: &str,
    disposition: &str,
    body: &[u8],
    out: &mut Vec<Attachment>,
) {
    let parsed = parse_media_type(content_type);
    let media = parsed.as_ref().map(|(m, _)| m.as_str()).unwrap_or("");

    if media.starts_with("multipart/") {
        let Some(boundary) = parsed.as_ref().and_then(|(_, p)| p.get("boundary")) else {
            return;
        };
        for part in split_parts(body, boundary) {
            collect_attachments(
                part.headers.get("Content-Type"),
                part.headers.get("Content-Transfer-Encoding"),
                part.headers.get("Content-Disposition"),
                part.body,
                out,
            );
        }
        return;
    }

    // A leaf part is kept only if explicitly dispositioned as an attachment.
    let Some((disp, dparams)) = parse_media_type(disposition) else {
        return;
    };
    if !disp.eq_ignore_ascii_case("attachment") {
        return;
    }
    let filename = dparams
        .get("filename")
        .or_else(|| parsed.as_ref().and_then(|(_, p)| p.get("name")))
        .cloned()
        .unwrap_or_default();
    out.push(Attachment {
        filename,
        content_type: media.to_string(),
        bytes: decode_transfer_bytes(cte, body),
    });
}

/// The text/plain body of an Email, by way of its first text part.
pub fn message_body(m: &Email) -> String {
    m.text_body
        .first()
        .and_then(|p| m.body_values.get(&p.part_id))
        .map_or(String::new(), |bv| bv.value.clone())
}

/// Serialise an Email into RFC 5322 wire format for SMTP.
///
/// Returns the raw bytes and the Message-ID without angle brackets. `now` and
/// `random_hex` are injected rather than read from the clock and the RNG so a
/// test can pin both; the Go original reaches for them directly.
///
/// The header set and their order are fixed: MIME-Version, From, To, Cc,
/// Subject, Date, Message-Id, In-Reply-To, References, any custom headers,
/// Content-Type. DKIM signs over a subset of these, so reordering them
/// changes what verifiers see.
pub fn build_rfc5322(
    e: &Email,
    default_domain: &str,
    now: ::time::OffsetDateTime,
    random_hex: &str,
) -> (Vec<u8>, String) {
    let from = e.from.first().map(format_addr).unwrap_or_default();
    let to = join_addrs(&e.to);
    let cc = join_addrs(&e.cc);

    let mut domain = default_domain.to_string();
    if domain.is_empty()
        && let Some(a) = e.from.first()
        && let Some((_, d)) = a.email.split_once('@')
    {
        domain = d.to_string();
    }
    if domain.is_empty() {
        domain = "localhost".to_string();
    }

    let msg_id = match e.message_id.first() {
        Some(m) if !m.is_empty() => m.trim_matches(['<', '>']).to_string(),
        _ => format!("{}.{random_hex}@{domain}", now.unix_timestamp_nanos()),
    };

    // sentAt wins over receivedAt; with neither, the caller's clock.
    let date = e
        .sent_at
        .as_ref()
        .or(e.received_at.as_ref())
        .and_then(jmap_types::JmapTime::to_datetime)
        .unwrap_or(now);

    // "Re: " on replies, for MUAs that thread on the subject line.
    let mut subject = e.subject.clone();
    if !e.in_reply_to.is_empty()
        && !subject.is_empty()
        && !subject.to_lowercase().starts_with("re:")
    {
        subject = format!("Re: {subject}");
    }

    let mut b = String::new();
    b.push_str("MIME-Version: 1.0\r\n");
    if !from.is_empty() {
        b.push_str(&format!("From: {from}\r\n"));
    }
    if !to.is_empty() {
        b.push_str(&format!("To: {to}\r\n"));
    }
    if !cc.is_empty() {
        b.push_str(&format!("Cc: {cc}\r\n"));
    }
    b.push_str(&format!("Subject: {subject}\r\n"));
    b.push_str(&format!("Date: {}\r\n", format_rfc1123z(date)));
    b.push_str(&format!("Message-Id: <{msg_id}>\r\n"));
    if !e.in_reply_to.is_empty() {
        b.push_str(&format!(
            "In-Reply-To: {}\r\n",
            bracket_join(&e.in_reply_to)
        ));
    }
    if !e.references.is_empty() {
        b.push_str(&format!("References: {}\r\n", bracket_join(&e.references)));
    }

    const SKIP: &[&str] = &[
        "from",
        "to",
        "cc",
        "subject",
        "date",
        "message-id",
        "in-reply-to",
        "references",
        "content-type",
    ];
    for h in &e.headers {
        if !SKIP.iter().any(|s| h.name.eq_ignore_ascii_case(s)) {
            b.push_str(&format!("{}: {}\r\n", h.name, h.value));
        }
    }
    b.push_str("Content-Type: text/plain; charset=utf-8\r\n");
    b.push_str("\r\n");
    b.push_str(&message_body(e));
    (b.into_bytes(), msg_id)
}

/// `Mon, 02 Jan 2006 15:04:05 -0700` — Go's `time.RFC1123Z`.
pub fn format_rfc1123z(t: ::time::OffsetDateTime) -> String {
    const DAYS: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let (h, m, _) = t.offset().as_hms();
    let sign = if t.offset().is_negative() { '-' } else { '+' };
    format!(
        "{}, {:02} {} {:04} {:02}:{:02}:{:02} {sign}{:02}{:02}",
        DAYS[t.weekday().number_days_from_monday() as usize],
        t.day(),
        MONTHS[u8::from(t.month()) as usize - 1],
        t.year(),
        t.hour(),
        t.minute(),
        t.second(),
        h.abs(),
        m.abs(),
    )
}

/// `Name <addr>`, falling back to the localpart as the display name.
///
/// A bare `<addr>` with no display name confuses some clients' reply-all, so
/// the Go original always supplies one.
fn format_addr(a: &Address) -> String {
    if a.email.is_empty() {
        return String::new();
    }
    let mut name = a.name.clone();
    if name.is_empty()
        && let Some((local, _)) = a.email.split_once('@')
        && !local.is_empty()
    {
        name = local.to_string();
    }
    if name.is_empty() {
        return format!("<{}>", a.email);
    }
    format!("{} <{}>", render_display_name(&name), a.email)
}

/// Render a display name the way Go's `mail.Address.String` does.
///
/// Go quotes an all-printable-ASCII name **unconditionally** — `"Alice"`, not
/// `Alice` — and falls back to an RFC 2047 encoded word the moment a
/// multi-byte or non-printable character appears. Neither is what a reading of
/// RFC 5322 would suggest, and both are what goes on the wire.
fn render_display_name(name: &str) -> String {
    let all_printable = name
        .chars()
        .all(|c| (is_vchar(c) || is_wsp(c)) && c.is_ascii());
    if all_printable {
        quote_string(name)
    } else {
        encode_word(name)
    }
}

fn is_vchar(c: char) -> bool {
    ('\u{21}'..='\u{7e}').contains(&c)
}

fn is_wsp(c: char) -> bool {
    c == ' ' || c == '\t'
}

/// `qtext` and whitespace pass through; other visible characters are
/// backslash-escaped; anything else is dropped. Go's `quoteString`.
fn quote_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        let is_qtext = is_vchar(c) && c != '\\' && c != '"';
        if is_qtext || is_wsp(c) {
            out.push(c);
        } else if is_vchar(c) {
            out.push('\\');
            out.push(c);
        }
    }
    out.push('"');
    out
}

/// RFC 2047 Q-encoding over UTF-8, matching `mime.QEncoding.Encode`.
fn encode_word(s: &str) -> String {
    let mut encoded = String::new();
    for b in s.bytes() {
        match b {
            b' ' => encoded.push('_'),
            b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z' => encoded.push(b as char),
            b'!' | b'*' | b'+' | b'-' | b'/' => encoded.push(b as char),
            _ => encoded.push_str(&format!("={b:02X}")),
        }
    }
    format!("=?utf-8?q?{encoded}?=")
}

fn join_addrs(addrs: &[Address]) -> String {
    addrs
        .iter()
        .map(format_addr)
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(", ")
}

fn bracket_join(ids: &[String]) -> String {
    ids.iter()
        .map(|id| id.trim_matches([' ', '<', '>']))
        .filter(|id| !id.is_empty())
        .map(|id| format!("<{id}>"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Build an SMTP envelope from an Email's From/To/Cc/Bcc.
///
/// `None` when there is no From, or no recipient at all. Duplicate recipients
/// are collapsed, keeping the first occurrence's position.
pub fn build_envelope(e: &Email) -> Option<Envelope> {
    let mail_from = e.from.first().map(|a| a.email.clone())?;
    if mail_from.is_empty() {
        return None;
    }
    let mut seen = std::collections::BTreeSet::new();
    let mut rcpt = Vec::new();
    for addrs in [&e.to, &e.cc, &e.bcc] {
        for a in addrs {
            if !a.email.is_empty() && seen.insert(a.email.clone()) {
                rcpt.push(EnvAddress::new(a.email.clone()));
            }
        }
    }
    if rcpt.is_empty() {
        return None;
    }
    Some(Envelope {
        mail_from: Some(EnvAddress::new(mail_from)),
        rcpt_to: rcpt,
    })
}

// ── helpers ───────────────────────────────────────────────────────────────

fn normalise_newlines(s: &str) -> String {
    s.replace("\r\n", "\n")
}

fn decode_transfer(cte: &str, body: &[u8]) -> String {
    String::from_utf8_lossy(&decode_transfer_bytes(cte, body)).into_owned()
}

fn decode_transfer_bytes(cte: &str, body: &[u8]) -> Vec<u8> {
    match cte.trim().to_ascii_lowercase().as_str() {
        "quoted-printable" => decode_quoted_printable(body),
        "base64" => decode_base64_lenient(body),
        _ => body.to_vec(),
    }
}

/// Decode base64, ignoring whitespace and stopping at the first invalid byte.
/// Go's `base64.NewDecoder` behaves the same way: it returns what it managed
/// to decode rather than failing the whole part.
fn decode_base64_lenient(body: &[u8]) -> Vec<u8> {
    use base64::Engine as _;
    let filtered: Vec<u8> = body
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    let engine = base64::engine::general_purpose::STANDARD;
    engine.decode(&filtered).unwrap_or_else(|_| {
        // Truncate to the longest decodable prefix, as a streaming decoder
        // would produce.
        let mut end = filtered.len();
        while end > 0 {
            if let Ok(v) = engine.decode(&filtered[..end]) {
                return v;
            }
            end -= 1;
        }
        Vec::new()
    })
}

fn decode_quoted_printable(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len());
    let mut i = 0;
    while i < body.len() {
        match body[i] {
            b'=' if i + 2 < body.len() => {
                let hex = &body[i + 1..i + 3];
                if hex == b"\r\n" {
                    i += 3;
                    continue;
                }
                match u8::from_str_radix(&String::from_utf8_lossy(hex), 16) {
                    Ok(b) => {
                        out.push(b);
                        i += 3;
                    }
                    Err(_) => {
                        out.push(body[i]);
                        i += 1;
                    }
                }
            }
            // A soft line break: "=" at end of line.
            b'=' if i + 1 < body.len() && body[i + 1] == b'\n' => i += 2,
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    out
}

/// One part of a multipart body.
struct Part<'a> {
    headers: Headers,
    body: &'a [u8],
}

/// Split a multipart body on its boundary.
///
/// The preamble before the first boundary and the epilogue after the closing
/// one are discarded, as RFC 2046 requires.
fn split_parts<'a>(body: &'a [u8], boundary: &str) -> Vec<Part<'a>> {
    let delim = format!("--{boundary}");
    let mut parts = Vec::new();
    let mut rest = body;

    // Skip the preamble.
    let Some(start) = find(rest, delim.as_bytes()) else {
        return parts;
    };
    rest = &rest[start + delim.len()..];

    loop {
        // A closing delimiter ends the body.
        if rest.starts_with(b"--") {
            break;
        }
        // Skip the CRLF (or LF) that ends the delimiter line.
        rest = rest
            .strip_prefix(b"\r\n")
            .or_else(|| rest.strip_prefix(b"\n"))
            .unwrap_or(rest);

        let Some(next) = find(rest, delim.as_bytes()) else {
            break;
        };
        // The CRLF before the delimiter belongs to the delimiter, not the part.
        let mut end = next;
        if end >= 2 && &rest[end - 2..end] == b"\r\n" {
            end -= 2;
        } else if end >= 1 && rest[end - 1] == b'\n' {
            end -= 1;
        }

        if let Some((headers, part_body)) = split_message(&rest[..end]) {
            parts.push(Part {
                headers,
                body: part_body,
            });
        }
        rest = &rest[next + delim.len()..];
    }
    parts
}

/// Parse a `type/subtype; k=v; k2="v2"` header.
///
/// `None` when there is no media type at all, matching
/// `mime.ParseMediaType`'s error, which every caller treats as "unknown".
pub fn parse_media_type(value: &str) -> Option<(String, BTreeMap<String, String>)> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    let (media, rest) = match value.split_once(';') {
        Some((m, r)) => (m, r),
        None => (value, ""),
    };
    let media = media.trim().to_ascii_lowercase();
    if media.is_empty() {
        return None;
    }

    let mut params = BTreeMap::new();
    for param in split_params(rest) {
        if let Some((k, v)) = param.split_once('=') {
            let v = v.trim();
            let v = v
                .strip_prefix('"')
                .and_then(|s| s.strip_suffix('"'))
                .unwrap_or(v);
            params.insert(k.trim().to_ascii_lowercase(), v.to_string());
        }
    }
    Some((media, params))
}

/// Split on `;`, ignoring separators inside a quoted string.
fn split_params(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let (mut start, mut quoted) = (0, false);
    for (i, c) in s.char_indices() {
        match c {
            '"' => quoted = !quoted,
            ';' if !quoted => {
                out.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    if start < s.len() {
        out.push(&s[start..]);
    }
    out
}

/// Decode RFC 2047 encoded words. A word that fails to decode is left as-is,
/// which is what `mime.WordDecoder` does for an unknown charset.
pub fn decode_words(s: &str) -> String {
    if !s.contains("=?") {
        return s.to_string();
    }
    let mut out = String::new();
    let mut rest = s;
    while let Some(start) = rest.find("=?") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let Some(decoded) = decode_one_word(after) else {
            out.push_str("=?");
            rest = after;
            continue;
        };
        out.push_str(&decoded.0);
        rest = decoded.1;
    }
    out.push_str(rest);
    out
}

/// `charset?encoding?text?=` — returns the decoded text and the remainder.
fn decode_one_word(after: &str) -> Option<(String, &str)> {
    let end = after.find("?=")?;
    let word = &after[..end];
    let rest = &after[end + 2..];
    let mut fields = word.splitn(3, '?');
    let charset = fields.next()?;
    let encoding = fields.next()?;
    let text = fields.next()?;

    let bytes = match encoding.to_ascii_lowercase().as_str() {
        "b" => decode_base64_lenient(text.as_bytes()),
        // In an encoded word, `_` stands for a space.
        "q" => decode_quoted_printable(text.replace('_', " ").as_bytes()),
        _ => return None,
    };
    // Only UTF-8 and the ASCII-compatible latin charsets are handled; anything
    // else is left encoded rather than mangled.
    match charset.to_ascii_lowercase().as_str() {
        "utf-8" | "utf8" | "us-ascii" | "ascii" | "iso-8859-1" | "latin1" => {
            Some((String::from_utf8_lossy(&bytes).into_owned(), rest))
        }
        _ => None,
    }
}

/// Parse a Date header into the RFC 3339 form the store keeps.
fn parse_date(value: &str) -> Option<String> {
    let dt = parse_rfc2822(value)?;
    Some(jmap_types::JmapTime::from_datetime(dt).as_str().to_string())
}

/// Parse an RFC 5322 date-time, e.g. `Mon, 02 Jan 2006 15:04:05 -0700`.
fn parse_rfc2822(value: &str) -> Option<::time::OffsetDateTime> {
    use ::time::format_description::well_known::Rfc2822;
    ::time::OffsetDateTime::parse(value.trim(), &Rfc2822).ok()
}

/// Parse a single address. `None` if it does not parse — Go's
/// `mail.ParseAddress` errors and the caller drops the whole header.
pub fn parse_address(value: &str) -> Option<Address> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    let (name, email) = match (value.rfind('<'), value.rfind('>')) {
        (Some(lt), Some(gt)) if gt > lt => {
            let name = value[..lt].trim().trim_matches('"').trim();
            (decode_words(name), value[lt + 1..gt].trim().to_string())
        }
        _ => (String::new(), value.to_string()),
    };
    // An address with no @ is not an address.
    if !email.contains('@') {
        return None;
    }
    Some(Address { name, email })
}

/// Parse a comma-separated address list. `None` if *any* entry fails, matching
/// `mail.ParseAddressList`, which is all-or-nothing.
pub fn parse_address_list(value: &str) -> Option<Vec<Address>> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    let mut out = Vec::new();
    for entry in split_addresses(value) {
        out.push(parse_address(entry)?);
    }
    (!out.is_empty()).then_some(out)
}

/// Split on `,`, ignoring separators inside a quoted display name.
fn split_addresses(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let (mut start, mut quoted) = (0, false);
    for (i, c) in s.char_indices() {
        match c {
            '"' => quoted = !quoted,
            ',' if !quoted => {
                out.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    if start < s.len() {
        out.push(&s[start..]);
    }
    out
}

/// Placeholder until the HTML converter is wired up (PLAN.md §8-G).
fn html_to_markdown(html: &str) -> String {
    normalise_newlines(html).trim().to_string()
}

#[cfg(test)]
mod tests;
