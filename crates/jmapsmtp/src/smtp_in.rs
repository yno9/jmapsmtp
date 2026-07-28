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
    /// Advertise `STARTTLS`. The handshake itself is the caller's to wire up.
    pub starttls: bool,
    pub enable_smtputf8: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            hostname: "localhost".into(),
            starttls: true,
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
            if let Err(e) = handle(stream, &cfg, backend.as_ref()).await {
                // A peer hanging up mid-session is ordinary, not an error
                // worth a full log line at anything above debug.
                tracing::debug!("[smtp] session with {peer} ended: {e}");
            }
        });
    }
}

/// Drive one session to completion.
pub async fn handle<S>(stream: S, cfg: &Config, backend: &dyn Backend) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let (read, mut write) = tokio::io::split(stream);
    let mut read = BufReader::new(read);
    let mut session = Session::default();

    write
        .write_all(format!("220 {} ESMTP Service Ready\r\n", cfg.hostname).as_bytes())
        .await?;

    let mut line = String::new();
    loop {
        line.clear();
        if read.read_line(&mut line).await? == 0 {
            return Ok(()); // the peer hung up
        }
        let command = line.trim_end_matches(['\r', '\n']);
        let (verb, rest) = split_command(command);

        match verb.as_str() {
            "EHLO" => {
                session.greeted = true;
                session.reset();
                write.write_all(ehlo_response(cfg).as_bytes()).await?;
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
                        session.from = Some(addr);
                        session.rcpts.clear();
                        write.write_all(b"250 2.0.0 OK\r\n").await?;
                    }
                    None => {
                        write
                            .write_all(
                                b"501 5.5.4 Was expecting MAIL arg syntax of FROM:<address>\r\n",
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
                        write.write_all(b"250 2.0.0 OK\r\n").await?;
                    }
                    None => {
                        write
                            .write_all(
                                b"501 5.5.4 Was expecting RCPT arg syntax of TO:<address>\r\n",
                            )
                            .await?;
                    }
                }
            }
            "DATA" => {
                if session.from.is_none() {
                    write
                        .write_all(b"502 5.5.1 Missing MAIL FROM command.\r\n")
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
                write.write_all(b"250 2.0.0 OK\r\n").await?;
            }
            "NOOP" => write.write_all(b"250 2.0.0 OK\r\n").await?,
            "QUIT" => {
                write.write_all(b"221 2.0.0 Bye\r\n").await?;
                return Ok(());
            }
            "AUTH" => {
                // The relay authenticates nobody on the inbound path: this is
                // a public MX. Advertising AUTH at all would invite clients to
                // send credentials that go nowhere.
                write
                    .write_all(b"502 5.5.1 This is a public MX; no authentication is offered.\r\n")
                    .await?;
            }
            "STARTTLS" if cfg.starttls => {
                // Upgrading the stream is the caller's job — `handle` is
                // generic over the transport precisely so it can be re-entered
                // on the TLS side. Refusing here rather than pretending keeps
                // an opportunistic sender on plaintext instead of stalling it.
                write
                    .write_all(b"454 4.7.0 TLS not available on this connection\r\n")
                    .await?;
            }
            "" => write.write_all(b"500 5.5.2 Error: bad syntax\r\n").await?,
            _ => {
                write
                    .write_all(
                        format!("500 5.5.2 Syntax error, {verb} command unrecognized\r\n")
                            .as_bytes(),
                    )
                    .await?;
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
pub fn ehlo_response(cfg: &Config) -> String {
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

    let mut out = format!("250-{} greets you\r\n", cfg.hostname);
    let last = caps.len() - 1;
    for (i, cap) in caps.iter().enumerate() {
        let sep = if i == last { ' ' } else { '-' };
        out.push_str(&format!("250{sep}{cap}\r\n"));
    }
    out
}

/// Split a command line into its verb (upper-cased) and the rest.
fn split_command(line: &str) -> (String, &str) {
    let line = line.trim_start();
    let end = line.find(char::is_whitespace).unwrap_or(line.len());
    (line[..end].to_uppercase(), line[end..].trim_start())
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
