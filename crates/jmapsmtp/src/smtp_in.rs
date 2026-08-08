//! The inbound ESMTP server. Port of `go-jmapsmtp/main.go`'s SMTP half.
//!
//! Hand-written rather than taken from a crate, for the reason PLAN.md §4
//! gives: the relay uses `MAIL`, `RCPT`, `DATA`, `RSET`, `QUIT`, `STARTTLS`
//! and `SMTPUTF8` and nothing else, and the Rust SMTP-server crates are less
//! maintained than the surface is large.
//!
//! Two behaviours here look like bugs and are not. An unknown recipient is
//! accepted with a 250 and then silently dropped, and a `DATA` with no
//! surviving recipient is accepted and discarded. Both are the Go
//! implementation's, and both matter: rejecting at `RCPT` would turn this
//! relay into an address-existence oracle for anyone who can open port 25.

use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

/// What the application does with what arrives.
///
/// Every method is fallible so the session can answer with a real SMTP error,
/// but the Go original never rejects: see the module header.
pub trait Backend: Send + Sync + 'static {
    /// Called for `RCPT TO`. `false` means the address is not served here —
    /// the command is still answered 250 and the address dropped.
    fn accepts(&self, rcpt: &str) -> bool;

    /// Called once per `DATA`, with the recipients that survived `accepts`.
    /// Never called with an empty list.
    fn deliver(&self, from: &str, rcpts: &[String], raw: &[u8]);
}

pub struct Config {
    /// Announced in the greeting and in the `EHLO` response.
    pub hostname: String,
    /// Advertise `STARTTLS`.
    pub starttls: bool,
    /// Whether a certificate is actually loaded. Advertised-but-unavailable is
    /// answered `454`; available is answered `220` and the session ends with
    /// [`Outcome::StartTls`] for the caller to upgrade.
    pub tls_available: bool,
    pub enable_smtputf8: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            hostname: "localhost".into(),
            starttls: true,
            tls_available: false,
            enable_smtputf8: true,
        }
    }
}

/// One connection's state.
#[derive(Default)]
struct Session {
    greeted: bool,
    from: Option<String>,
    rcpts: Vec<String>,
}

impl Session {
    fn reset(&mut self) {
        self.from = None;
        self.rcpts.clear();
    }
}

/// Accept connections until the listener fails.
pub async fn serve(listener: TcpListener, cfg: Arc<Config>, backend: Arc<dyn Backend>) {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::error!("[smtp] accept: {e}");
                return;
            }
        };
        let (cfg, backend) = (cfg.clone(), backend.clone());
        tokio::spawn(async move {
            let mut stream = stream;
            if let Err(e) = handle(&mut stream, &cfg, backend.as_ref()).await {
                // A peer hanging up mid-session is ordinary, not an error
                // worth a full log line at anything above debug.
                tracing::debug!("[smtp] session with {peer} ended: {e}");
            }
        });
    }
}

/// How a session ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The client quit, or the connection closed.
    Done,
    /// The client sent `STARTTLS` and was answered `220`. The caller owns the
    /// handshake and re-enters [`handle`] on the upgraded stream.
    ///
    /// Returned rather than handled here so this module needs no TLS
    /// dependency and stays testable over a plain byte stream.
    StartTls,
}

/// Drive one session to completion.
///
/// Returns [`Outcome::StartTls`] when the client asked to upgrade and
/// [`Config::tls_available`] said it could. **Everything negotiated before the
/// upgrade is discarded**: RFC 3207 §4.2 requires the server to forget the
/// EHLO and any envelope, because what came before was not protected and a
/// man in the middle could have written it.
pub async fn handle<S>(
    stream: &mut S,
    cfg: &Config,
    backend: &dyn Backend,
) -> std::io::Result<Outcome>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    // Borrowed rather than consumed so the caller still owns the socket after
    // a `STARTTLS`, and can hand the same one to the TLS acceptor.
    let (read, mut write) = tokio::io::split(stream);
    let mut read = BufReader::new(read);
    let mut session = Session::default();

    write
        .write_all(format!("220 {} ESMTP Service Ready\r\n", cfg.hostname).as_bytes())
        .await?;

    let mut line = String::new();
    let mut errors = 0u32;
    loop {
        line.clear();
        if read.read_line(&mut line).await? == 0 {
            return Ok(Outcome::Done); // the peer hung up
        }
        let command = line.trim_end_matches(['\r', '\n']);
        let (verb, rest) = match split_command(command) {
            Ok(v) => v,
            Err(BadCommand) => {
                write.write_all(b"501 5.5.2 Bad command\r\n").await?;
                write.flush().await?;
                if protocol_error(&mut errors, &mut write).await? {
                    return Ok(Outcome::Done);
                }
                continue;
            }
        };

        match verb.as_str() {
            "EHLO" => {
                session.greeted = true;
                session.reset();
                write.write_all(ehlo_response(cfg, rest).as_bytes()).await?;
            }
            "HELO" => {
                session.greeted = true;
                session.reset();
                write
                    .write_all(format!("250 2.0.0 Hello {rest}\r\n").as_bytes())
                    .await?;
            }
            "MAIL" => {
                if !session.greeted {
                    write
                        .write_all(b"502 5.5.1 Please introduce yourself first.\r\n")
                        .await?;
                    continue;
                }
                match parse_path(rest, "FROM:") {
                    Some(addr) => {
                        write
                            .write_all(
                                format!("250 2.0.0 Roger, accepting mail from <{addr}>\r\n")
                                    .as_bytes(),
                            )
                            .await?;
                        session.from = Some(addr);
                        session.rcpts.clear();
                    }
                    None => {
                        write
                            .write_all(
                                b"501 5.5.2 Was expecting MAIL arg syntax of FROM:<address>\r\n",
                            )
                            .await?;
                    }
                }
            }
            "RCPT" => {
                if session.from.is_none() {
                    write
                        .write_all(b"502 5.5.1 Missing MAIL FROM command.\r\n")
                        .await?;
                    continue;
                }
                match parse_path(rest, "TO:") {
                    Some(addr) => {
                        // Accepted either way; only a served address is kept.
                        // See the module header on why this is not a rejection.
                        if backend.accepts(&addr.to_lowercase()) {
                            session.rcpts.push(addr.to_lowercase());
                        }
                        write
                            .write_all(
                                format!("250 2.0.0 I'll make sure <{addr}> gets this\r\n")
                                    .as_bytes(),
                            )
                            .await?;
                    }
                    None => {
                        write
                            .write_all(
                                b"501 5.5.2 Was expecting RCPT arg syntax of TO:<address>\r\n",
                            )
                            .await?;
                    }
                }
            }
            "DATA" => {
                if session.from.is_none() {
                    write
                        .write_all(b"502 5.5.1 Missing RCPT TO command.\r\n")
                        .await?;
                    continue;
                }
                write
                    .write_all(b"354 Go ahead. End your data with <CR><LF>.<CR><LF>\r\n")
                    .await?;
                let raw = read_data(&mut read).await?;
                if !session.rcpts.is_empty() {
                    backend.deliver(session.from.as_deref().unwrap_or(""), &session.rcpts, &raw);
                }
                session.reset();
                write.write_all(b"250 2.0.0 OK: queued\r\n").await?;
            }
            "RSET" => {
                session.reset();
                write.write_all(b"250 2.0.0 Session reset\r\n").await?;
            }
            "NOOP" => {
                write
                    .write_all(b"250 2.0.0 I have successfully done nothing\r\n")
                    .await?;
            }
            "QUIT" => {
                write.write_all(b"221 2.0.0 Bye\r\n").await?;
                return Ok(Outcome::Done);
            }
            "AUTH" => {
                // The relay authenticates nobody on the inbound path: this is
                // a public MX. Advertising AUTH at all would invite clients to
                // send credentials that go nowhere.
                write
                    .write_all(b"502 5.5.1 This is a public MX; no authentication is offered.\r\n")
                    .await?;
            }
            "STARTTLS" if cfg.starttls && cfg.tls_available => {
                write.write_all(b"220 2.0.0 Ready to start TLS\r\n").await?;
                write.flush().await?;
                return Ok(Outcome::StartTls);
            }
            "STARTTLS" if cfg.starttls => {
                // Advertised but not available — no certificate loaded.
                // Refusing rather than stalling keeps an opportunistic sender
                // on plaintext, which is a delivered message rather than a
                // timed-out one.
                write
                    .write_all(b"454 4.7.0 TLS not available on this connection\r\n")
                    .await?;
            }
            // Answered before the verb table, as go-smtp does: it accepts
            // `VRFY` and refuses to answer it, rather than not knowing it.
            // The difference is `252` — "send anyway" — against a `500` that
            // tells a probing sender the command does not exist.
            "VRFY" => {
                write
                    .write_all(b"252 2.5.0 Cannot VRFY user, but will accept message\r\n")
                    .await?;
            }
            "" => {
                write.write_all(b"500 5.5.2 Error: bad syntax\r\n").await?;
                write.flush().await?;
                if protocol_error(&mut errors, &mut write).await? {
                    return Ok(Outcome::Done);
                }
                continue;
            }
            _ => {
                // "errors" plural, matching go-smtp's own wording. It reads
                // like a typo because it is one; a sender logging the reply
                // gets the same string from either implementation.
                write
                    .write_all(
                        format!("500 5.5.2 Syntax errors, {verb} command unrecognized\r\n")
                            .as_bytes(),
                    )
                    .await?;
                write.flush().await?;
                if protocol_error(&mut errors, &mut write).await? {
                    return Ok(Outcome::Done);
                }
                continue;
            }
        }
        write.flush().await?;
    }
}

/// The multi-line `EHLO` response.
///
/// The capability list and its order match go-smtp's for the options this
/// relay sets: SMTPUTF8 on, TLS configured, no size or recipient limits, and
/// no authentication.
pub fn ehlo_response(cfg: &Config, domain: &str) -> String {
    let mut caps: Vec<String> = vec![
        "PIPELINING".into(),
        "8BITMIME".into(),
        "ENHANCEDSTATUSCODES".into(),
        "CHUNKING".into(),
    ];
    if cfg.starttls {
        caps.push("STARTTLS".into());
    }
    if cfg.enable_smtputf8 {
        caps.push("SMTPUTF8".into());
    }
    caps.push("SIZE".into());

    // go-smtp echoes the domain the client named, not its own hostname
    // (`conn.go`'s `args := []string{"Hello " + domain}`). Advertising the
    // relay's own name here reads as more informative and is simply a
    // different string on the wire.
    let mut out = format!("250-Hello {domain}\r\n");
    let last = caps.len() - 1;
    for (i, cap) in caps.iter().enumerate() {
        let sep = if i == last { ' ' } else { '-' };
        out.push_str(&format!("250{sep}{cap}\r\n"));
    }
    out
}

/// Split a command line into its verb (upper-cased) and the rest.
/// Split a command line **exactly as go-smtp's `parseCmd` does**.
///
/// Its rule is not "split on the first space": a verb is always **four
/// characters**, and anything else is a parse error rather than an unknown
/// command. `NONSENSE` is refused for its shape, never looked up, and answered
/// `501 Bad command` — not the `500 … unrecognized` an unknown four-letter
/// verb gets. A client can tell the two apart, and this port answered 500 for
/// both until the dialogue was compared against the running oracle.
///
/// `STARTTLS` is the one exception, matched by prefix before the length rules
/// it would otherwise fail.
fn split_command(line: &str) -> Result<(String, &str), BadCommand> {
    let line = line.trim_end_matches(['\r', '\n']);
    if line.len() >= 8 && line[..8].eq_ignore_ascii_case("STARTTLS") {
        return Ok(("STARTTLS".to_string(), ""));
    }
    match line.len() {
        0 => Ok((String::new(), "")),
        // Too short to be a verb.
        l if l < 4 => Err(BadCommand),
        4 => Ok((line.to_uppercase(), "")),
        // Too long to be only a verb, too short to carry an argument.
        5 => Err(BadCommand),
        _ if !line.is_char_boundary(4) || line.as_bytes()[4] != b' ' => Err(BadCommand),
        _ => Ok((line[..4].to_uppercase(), line[5..].trim())),
    }
}

/// A line whose *shape* is wrong, as distinct from a verb nobody implements.
pub struct BadCommand;

/// go-smtp hangs up after **more than three** protocol errors, and says so
/// first. Only three replies count towards it — a bad command shape, an empty
/// command, and an unknown verb. A malformed `MAIL FROM` does not: those are
/// answered and forgiven, because a sender that gets its arguments wrong is
/// still speaking SMTP.
///
/// Returns `true` when the connection should close.
const ERROR_THRESHOLD: u32 = 3;

async fn protocol_error<W: tokio::io::AsyncWrite + Unpin>(
    errors: &mut u32,
    write: &mut W,
) -> std::io::Result<bool> {
    use tokio::io::AsyncWriteExt as _;
    *errors += 1;
    if *errors > ERROR_THRESHOLD {
        // "Quiting", one t, is go-smtp's spelling.
        write
            .write_all(b"500 5.5.1 Too many errors. Quiting now\r\n")
            .await?;
        write.flush().await?;
        return Ok(true);
    }
    Ok(false)
}

/// Pull the address out of `FROM:<a@b>` or `TO:<a@b>`, ignoring any ESMTP
/// parameters that follow.
///
/// The angle brackets are optional, which is not RFC-conformant but is what
/// real senders do often enough that go-smtp accepts it too.
fn parse_path(rest: &str, prefix: &str) -> Option<String> {
    let rest = rest.trim_start();
    if !rest
        .len()
        .checked_sub(prefix.len())
        .is_some_and(|_| rest[..prefix.len()].eq_ignore_ascii_case(prefix))
    {
        return None;
    }
    let arg = rest[prefix.len()..].trim_start();
    if let Some(stripped) = arg.strip_prefix('<') {
        let end = stripped.find('>')?;
        return Some(stripped[..end].to_string());
    }
    // No brackets: the address runs to the first space, and anything after is
    // an ESMTP parameter.
    let end = arg.find(char::is_whitespace).unwrap_or(arg.len());
    let addr = &arg[..end];
    (!addr.is_empty()).then(|| addr.to_string())
}

/// Read a `DATA` payload up to the `.` terminator, undoing dot-stuffing.
///
/// A connection that ends before the terminator yields what arrived, which is
/// what the caller then discards — the 250 is only written on the normal path.
async fn read_data<R: AsyncRead + Unpin>(read: &mut BufReader<R>) -> std::io::Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut line = Vec::new();
    loop {
        line.clear();
        if read.read_until(b'\n', &mut line).await? == 0 {
            return Ok(out);
        }
        let body = line.strip_suffix(b"\n").unwrap_or(&line);
        let body = body.strip_suffix(b"\r").unwrap_or(body);
        if body == b"." {
            return Ok(out);
        }
        // RFC 5321 §4.5.2: a leading dot was added by the sender.
        let body = body.strip_prefix(b".").unwrap_or(body);
        out.extend_from_slice(body);
        out.extend_from_slice(b"\r\n");
    }
}

#[cfg(test)]
mod tests;
