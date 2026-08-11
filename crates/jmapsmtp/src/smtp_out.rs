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
//! * STARTTLS is taken whenever the far end advertises it, with the
//!   certificate verified against the system root store — what Go's
//!   `&tls.Config{ServerName: host}` does. A refused STARTTLS *command*
//!   leaves the socket in the clear and the send continues; a failed
//!   *handshake* ends it, because after the server's `220` there is no
//!   plaintext left to continue in.
//!
//!   This paragraph used to say the upgrade was "opportunistic and
//!   unauthenticated", and no upgrade existed at all — the code said the work
//!   was deferred to M6 and M6 came and went. Every chatmail server (Delta
//!   Chat's) answers `530 5.7.0 Must issue a STARTTLS command first` to
//!   `MAIL FROM`, so mail to those addresses had never once left this relay.
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
    /// Roots trusted for outbound STARTTLS **in addition to** the system
    /// store. Empty in production; a test that stands up its own server has
    /// no other way to be trusted, and the alternative — turning verification
    /// off under `cfg(test)` — would mean the shipped path is the one never
    /// exercised.
    pub extra_roots: Vec<rustls_pki_types::CertificateDer<'static>>,
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

        // The greeting and EHLO happen in the clear, because whether to
        // upgrade is *in* the EHLO reply.
        let mut plain = BufReader::new(stream);
        expect(&mut plain, 220, "greeting").await?;
        let ehlo = self.greet(&mut plain).await?;

        if !advertises(&ehlo, "STARTTLS") {
            self.converse(plain, &ehlo, from, to, raw).await?;
            tracing::info!("[smtp] sent to {to:?} via {target} (plaintext)");
            return Ok(());
        }

        plain.get_mut().write_all(b"STARTTLS\r\n").await?;
        let reply = read_reply(&mut plain).await?;
        if !reply.starts_with('2') {
            // The command was refused, so nothing was upgraded and the socket
            // is still a plain one. Go logs and carries on; so do we.
            tracing::warn!(
                "[smtp] STARTTLS refused by {target}: {} (continuing plaintext)",
                reply.trim_end()
            );
            self.converse(plain, &ehlo, from, to, raw).await?;
            tracing::info!("[smtp] sent to {to:?} via {target} (plaintext)");
            return Ok(());
        }

        // Anything the server sent after its 220 was sent before the
        // handshake and cannot be trusted — carrying buffered plaintext into
        // the TLS session is how a stripping attack smuggles commands in.
        if !plain.buffer().is_empty() {
            return Err(SendError::Rejected {
                command: "STARTTLS".into(),
                reply: format!(
                    "server pipelined {} bytes across the TLS boundary",
                    plain.buffer().len()
                ),
            });
        }

        let host = target.rsplit_once(':').map_or(target, |(h, _)| h);
        let tls = self.upgrade(plain.into_inner(), host).await?;
        let mut tls = BufReader::new(tls);
        // EHLO again on the fresh session: the extension list before the
        // upgrade does not carry over, and a server may offer more once
        // encrypted. `net/smtp`'s StartTLS does the same.
        let ehlo = self.greet(&mut tls).await?;
        self.converse(tls, &ehlo, from, to, raw).await?;
        tracing::info!("[smtp] sent to {to:?} via {target} (STARTTLS)");
        Ok(())
    }

    /// `EHLO`, falling back to `HELO` for a server that does not know it.
    async fn greet<S>(&self, read: &mut BufReader<S>) -> Result<String, SendError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        read.get_mut()
            .write_all(format!("EHLO {}\r\n", self.hostname).as_bytes())
            .await?;
        let ehlo = read_reply(read).await?;
        if !ehlo.starts_with('2') {
            read.get_mut()
                .write_all(format!("HELO {}\r\n", self.hostname).as_bytes())
                .await?;
            check(read_reply(read).await?, 250, "EHLO")?;
        }
        Ok(ehlo)
    }

    /// Wrap the socket in TLS, verifying the certificate against the system
    /// root store — the same thing Go's `&tls.Config{ServerName: host}` does.
    ///
    /// Verification is kept on even though this is opportunistic delivery on
    /// port 25, because the oracle verifies and a relay that quietly accepted
    /// any certificate would be a weaker thing wearing the same name. A
    /// handshake that fails ends the send: once the server has answered `220`
    /// the socket belongs to TLS, and there is no plaintext left to fall back
    /// to. Go writes "continuing plaintext" here and then fails at `MAIL
    /// FROM` on the dead socket; the outcome is the same and the message is
    /// not misleading.
    async fn upgrade(
        &self,
        stream: TcpStream,
        host: &str,
    ) -> Result<tokio_rustls::client::TlsStream<TcpStream>, SendError> {
        // Called here rather than trusted to have happened: the only other
        // caller is the *inbound* TLS loader, so a relay with no certificate
        // of its own would reach this line with no provider installed and
        // rustls panics rather than erroring. Sending must not depend on
        // receiving having been set up. Idempotent.
        crate::inbound_tls::install_crypto_provider();

        let mut roots = rustls::RootCertStore::empty();
        match rustls_native_certs::load_native_certs() {
            certs if certs.errors.is_empty() || !certs.certs.is_empty() => {
                for cert in certs.certs {
                    let _ = roots.add(cert);
                }
            }
            certs => {
                tracing::warn!("[smtp] no system roots loaded: {:?}", certs.errors);
            }
        }
        for cert in &self.extra_roots {
            roots.add(cert.clone()).map_err(|e| SendError::Rejected {
                command: "STARTTLS".into(),
                reply: format!("bad extra root: {e}"),
            })?;
        }

        let config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let server_name =
            rustls_pki_types::ServerName::try_from(host.to_string()).map_err(|e| {
                SendError::Rejected {
                    command: "STARTTLS".into(),
                    reply: format!("not a valid server name: {host}: {e}"),
                }
            })?;
        tokio_rustls::TlsConnector::from(std::sync::Arc::new(config))
            .connect(server_name, stream)
            .await
            .map_err(|e| {
                tracing::warn!("[smtp] STARTTLS handshake with {host} failed: {e}");
                SendError::Io(e)
            })
    }

    /// Everything after the (possibly upgraded) session is greeted.
    async fn converse<S>(
        &self,
        mut read: BufReader<S>,
        ehlo: &str,
        from: &str,
        to: &[String],
        raw: &[u8],
    ) -> Result<(), SendError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        // Writing through `get_mut()` rather than splitting: a split would
        // have to `into_inner()` the reader first, and that throws away
        // whatever it has already buffered — every reply a server pipelined
        // ahead of us, silently.
        read.get_mut()
            .write_all(mail_from(from, ehlo).as_bytes())
            .await?;
        check(read_reply(&mut read).await?, 250, "MAIL FROM")?;

        // A rejected recipient is logged and skipped, not fatal: the others
        // still get the message.
        for addr in to {
            read.get_mut()
                .write_all(format!("RCPT TO:<{addr}>\r\n").as_bytes())
                .await?;
            let reply = read_reply(&mut read).await?;
            if !reply.starts_with('2') {
                tracing::warn!("[smtp] RCPT TO {addr} rejected: {}", reply.trim_end());
            }
        }

        read.get_mut().write_all(b"DATA\r\n").await?;
        check(read_reply(&mut read).await?, 354, "DATA")?;

        read.get_mut().write_all(&dot_stuff(raw)).await?;
        // The terminator must sit on a line of its own, but a message that
        // already ends in a newline must not gain a blank line before it —
        // Go's textproto.DotWriter inserts the CRLF only when one is missing,
        // and adding it unconditionally appends an empty line to every
        // message the receiver stores.
        if !raw.ends_with(b"\n") {
            read.get_mut().write_all(b"\r\n").await?;
        }
        read.get_mut().write_all(b".\r\n").await?;
        check(read_reply(&mut read).await?, 250, "end DATA")?;

        // A server that will not say goodbye has still taken the message.
        let _ = read.get_mut().write_all(b"QUIT\r\n").await;
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

/// `MAIL FROM` with the ESMTP parameters `net/smtp` adds.
///
/// **A bare `MAIL FROM` is not equivalent.** `BODY=8BITMIME` tells the far end
/// the message may carry 8-bit octets; without it a strict server is entitled
/// to assume 7-bit, and a UTF-8 subject or body can be mangled or refused.
/// `SMTPUTF8` is the same promise for internationalised addresses. This port
/// sent neither until the two clients' conversations were compared against
/// each other (`smtp_client_dialogue_interop`), because every earlier check
/// looked at what *arrived* rather than at what was said.
///
/// Only what the far end advertised, and in `net/smtp`'s order —
/// `Client.Mail` appends `BODY=8BITMIME` first and `SMTPUTF8` second, and a
/// server that logs the command sees the difference.
fn mail_from(from: &str, ehlo: &str) -> String {
    let mut cmd = format!("MAIL FROM:<{from}>");
    if advertises(ehlo, "8BITMIME") {
        cmd.push_str(" BODY=8BITMIME");
    }
    if advertises(ehlo, "SMTPUTF8") {
        cmd.push_str(" SMTPUTF8");
    }
    cmd.push_str("\r\n");
    cmd
}

/// Whether an EHLO reply advertised `keyword`.
///
/// Matched per line and on the **keyword alone**, because a line may carry a
/// parameter (`250-SIZE 35882577`) and because a substring test would find
/// `SIZE` inside another keyword.
fn advertises(ehlo: &str, keyword: &str) -> bool {
    ehlo.lines().any(|line| {
        let line = line.trim_end_matches('\r');
        // Past the code and its separator, which is `-` on every line but the
        // last and a space on that one.
        let rest = if line.len() > 4 { &line[4..] } else { "" };
        rest.split_whitespace()
            .next()
            .is_some_and(|k| k.eq_ignore_ascii_case(keyword))
    })
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
