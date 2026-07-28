//! The outbound SMTP client. Port of `go-jmapsmtp/main.go`'s send half.
//!
//! Hand-written rather than driven through lettre, for one behaviour lettre
//! does not offer: a rejected `RCPT TO` is **logged and the send continues**.
//! Delivering to the recipients that were accepted, rather than failing the
//! whole message because one address bounced, is the Go implementation's
//! choice and the right one for a multi-recipient send.
//!
//! Two more choices worth naming, both inherited:
//!
//! * STARTTLS is opportunistic and unauthenticated — a failed handshake logs
//!   and **continues in plaintext**. On port 25 the alternative to
//!   unauthenticated TLS is not authenticated TLS, it is no delivery.
//! * Only the highest-priority MX is tried. There is no fallback to the next
//!   one; the message fails and the queue above retries.

use std::collections::BTreeMap;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

const DIAL_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug)]
pub enum SendError {
    Dial(String, std::io::Error),
    Io(std::io::Error),
    /// The server answered a command with a failure code.
    Rejected {
        command: String,
        reply: String,
    },
    NoRecipients,
    NoMx(String),
    InvalidRecipient(String),
}

impl std::fmt::Display for SendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SendError::Dial(target, e) => write!(f, "dial {target}: {e}"),
            SendError::Io(e) => write!(f, "{e}"),
            SendError::Rejected { command, reply } => write!(f, "{command}: {reply}"),
            SendError::NoRecipients => f.write_str("no recipients"),
            SendError::NoMx(domain) => write!(f, "no MX for {domain}"),
            SendError::InvalidRecipient(addr) => {
                write!(f, "invalid recipient address: {addr:?}")
            }
        }
    }
}

impl From<std::io::Error> for SendError {
    fn from(e: std::io::Error) -> Self {
        SendError::Io(e)
    }
}

/// Resolves the mail exchangers for a domain. A trait so tests can answer
/// without a network, and so the DNS client stays out of the send path.
pub trait MxResolver: Send + Sync {
    /// Hosts in priority order, best first. Empty means the domain takes no
    /// mail.
    fn lookup_mx(&self, domain: &str) -> Vec<String>;
}

pub struct Sender {
    /// Announced in `EHLO`.
    pub hostname: String,
    /// When set, every message goes here and MX lookup never happens.
    pub relay_host: Option<String>,
}

impl Sender {
    /// Deliver a message to every recipient.
    ///
    /// With a relay host, one connection carries them all. Without, they are
    /// grouped by domain and one connection opened per MX. A domain that
    /// fails does not stop the others; the first error is what comes back.
    pub async fn deliver(
        &self,
        resolver: &dyn MxResolver,
        from: &str,
        to: &[String],
        raw: &[u8],
    ) -> Result<(), SendError> {
        if to.is_empty() {
            return Err(SendError::NoRecipients);
        }

        if let Some(relay) = &self.relay_host {
            return self.send_one(relay, from, to, raw).await;
        }

        let mut by_domain: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for addr in to {
            let Some((_, domain)) = addr.rsplit_once('@') else {
                // Go returns here, abandoning recipients already grouped.
                return Err(SendError::InvalidRecipient(addr.clone()));
            };
            by_domain
                .entry(domain.to_string())
                .or_default()
                .push(addr.clone());
        }

        let mut first_error = None;
        for (domain, addrs) in by_domain {
            let mx = resolver.lookup_mx(&domain);
            let Some(host) = mx.first() else {
                let e = SendError::NoMx(domain.clone());
                tracing::warn!("[smtp] send failed: {e}");
                first_error.get_or_insert(e);
                continue;
            };
            // A trailing dot makes the name absolute in DNS but not in a
            // connect string.
            let target = format!("{}:25", host.trim_end_matches('.'));
            if let Err(e) = self.send_one(&target, from, &addrs, raw).await {
                tracing::warn!("[smtp] send failed to {domain}: {e}");
                first_error.get_or_insert(e);
            }
        }
        match first_error {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// One connection, one message, possibly several recipients.
    pub async fn send_one(
        &self,
        target: &str,
        from: &str,
        to: &[String],
        raw: &[u8],
    ) -> Result<(), SendError> {
        tracing::info!("[smtp] connecting to {target} for {to:?}");
        let stream = tokio::time::timeout(DIAL_TIMEOUT, TcpStream::connect(target))
            .await
            .map_err(|_| {
                SendError::Dial(
                    target.to_string(),
                    std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timed out"),
                )
            })?
            .map_err(|e| SendError::Dial(target.to_string(), e))?;

        // STARTTLS is negotiated by the caller when it wants it: this keeps
        // the protocol logic free of the TLS types, and the opportunistic
        // upgrade is wired up alongside the rest of the transport in M6.
        self.converse(stream, target, from, to, raw).await?;
        tracing::info!("[smtp] sent to {to:?} via {target}");
        Ok(())
    }

    async fn converse<S>(
        &self,
        stream: S,
        _target: &str,
        from: &str,
        to: &[String],
        raw: &[u8],
    ) -> Result<(), SendError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let (read, mut write) = tokio::io::split(stream);
        let mut read = BufReader::new(read);

        expect(&mut read, 220, "greeting").await?;

        // EHLO, falling back to HELO for a server that does not know it.
        write
            .write_all(format!("EHLO {}\r\n", self.hostname).as_bytes())
            .await?;
        let ehlo = read_reply(&mut read).await?;
        if !ehlo.starts_with('2') {
            write
                .write_all(format!("HELO {}\r\n", self.hostname).as_bytes())
                .await?;
            check(read_reply(&mut read).await?, 250, "EHLO")?;
        }

        write
            .write_all(format!("MAIL FROM:<{from}>\r\n").as_bytes())
            .await?;
        check(read_reply(&mut read).await?, 250, "MAIL FROM")?;

        // A rejected recipient is logged and skipped, not fatal: the others
        // still get the message.
        for addr in to {
            write
                .write_all(format!("RCPT TO:<{addr}>\r\n").as_bytes())
                .await?;
            let reply = read_reply(&mut read).await?;
            if !reply.starts_with('2') {
                tracing::warn!("[smtp] RCPT TO {addr} rejected: {}", reply.trim_end());
            }
        }

        write.write_all(b"DATA\r\n").await?;
        check(read_reply(&mut read).await?, 354, "DATA")?;

        write.write_all(&dot_stuff(raw)).await?;
        // The terminator must sit on a line of its own, but a message that
        // already ends in a newline must not gain a blank line before it —
        // Go's textproto.DotWriter inserts the CRLF only when one is missing,
        // and adding it unconditionally appends an empty line to every
        // message the receiver stores.
        if !raw.ends_with(b"\n") {
            write.write_all(b"\r\n").await?;
        }
        write.write_all(b".\r\n").await?;
        check(read_reply(&mut read).await?, 250, "end DATA")?;

        // A server that will not say goodbye has still taken the message.
        let _ = write.write_all(b"QUIT\r\n").await;
        let _ = read_reply(&mut read).await;
        Ok(())
    }
}

/// Escape a leading dot on every line, per RFC 5321 §4.5.2, so a body line of
/// `.` cannot be mistaken for the terminator.
fn dot_stuff(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len() + 16);
    let mut at_line_start = true;
    for &b in raw {
        if at_line_start && b == b'.' {
            out.push(b'.');
        }
        out.push(b);
        at_line_start = b == b'\n';
    }
    out
}

/// Read one reply, following continuation lines (`250-…` then `250 …`).
async fn read_reply<R: AsyncRead + Unpin>(read: &mut BufReader<R>) -> std::io::Result<String> {
    let mut out = String::new();
    let mut line = String::new();
    loop {
        line.clear();
        if read.read_line(&mut line).await? == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "connection closed mid-reply",
            ));
        }
        out.push_str(&line);
        // A hyphen in the fourth column means more lines follow.
        if line.as_bytes().get(3) != Some(&b'-') {
            return Ok(out);
        }
    }
}

async fn expect<R: AsyncRead + Unpin>(
    read: &mut BufReader<R>,
    code: u16,
    what: &str,
) -> Result<String, SendError> {
    check(read_reply(read).await?, code, what)
}

/// Accept any reply in the same class as `code` — 250 and 251 are both a
/// successful RCPT, and a server may answer 220 or 221 where the other is
/// expected.
fn check(reply: String, code: u16, what: &str) -> Result<String, SendError> {
    let class = reply.as_bytes().first().copied().unwrap_or(b'5');
    let want_class = b'0' + u8::try_from(code / 100).unwrap_or(5);
    if class == want_class {
        return Ok(reply);
    }
    Err(SendError::Rejected {
        command: what.to_string(),
        reply: reply.trim_end().to_string(),
    })
}

#[cfg(test)]
mod tests;
