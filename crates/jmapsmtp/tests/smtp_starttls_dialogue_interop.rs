//! What both clients say to a server that offers **STARTTLS**, compared.
//!
//! `smtp_client_dialogue_interop` already diffs the two clients' commands,
//! and it could never have seen this: its recorder advertises PIPELINING,
//! SIZE, 8BITMIME, ENHANCEDSTATUSCODES and SMTPUTF8, and no STARTTLS. The Go
//! helper had the same gap from the other side — `doSend` said it was a copy
//! of `smtpSend` and had dropped the STARTTLS block. Neither side upgraded,
//! so both agreed, and the suite was green while this port had **never once
//! delivered mail to a server that requires TLS**.
//!
//! Every chatmail server (Delta Chat's) is such a server. `mailchat.pl`
//! answers `530 5.7.0 Must issue a STARTTLS command first` to `MAIL FROM`,
//! which is exactly what the relay's log had been repeating in production.
//!
//! The seam was between two comparisons, and that is where the previous three
//! shipped bugs lived too (ARC.md §9): each layer assumed the other covered
//! the case.
//!
//! # What is compared
//!
//! The command transcript, and **which commands arrived encrypted**. A client
//! that sends `STARTTLS` and then keeps talking in the clear would pass a
//! plain transcript diff; the far end would see plaintext mail.
//!
//! # The certificate
//!
//! Self-signed, generated per run, and handed to *both* clients as an extra
//! root — Go via `SMTP_INTEROP_CA`, this port via `Sender::extra_roots`.
//! Verification stays on for both. Turning it off for the test would leave
//! the shipped path — the one that verifies — unexercised, and that is the
//! path that decides whether real mail moves.
//!
//! `SMTP_INTEROP=required` — the same helper the sibling suites need.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

use pretty_assertions::assert_eq;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

const HELO_NAME: &str = "mail.example.com";
const FROM: &str = "alice@example.com";
const TO: &str = "bob@example.org";
const MESSAGE: &str = "From: alice@example.com\r\n\
     To: bob@example.org\r\n\
     Subject: starttls dialogue\r\n\
     \r\n\
     body\r\n";

/// The name both clients connect to, and the name on the certificate.
const SERVER_NAME: &str = "localhost";

fn require_helper() -> Option<PathBuf> {
    let bin = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../oracle/smtp-interop")
        .canonicalize()
        .ok()?;
    if bin.exists() {
        return Some(bin);
    }
    assert!(
        std::env::var("SMTP_INTEROP").as_deref() != Ok("required"),
        "the Go SMTP helper is missing — run `just interop`"
    );
    None
}

/// One line the server received, and whether it came in encrypted.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Heard {
    line: String,
    encrypted: bool,
}

impl std::fmt::Display for Heard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {}",
            if self.encrypted { "[tls]" } else { "[   ]" },
            self.line
        )
    }
}

struct Cert {
    /// The root, for whoever has to trust it.
    ca_pem: String,
    ca_der: rustls_pki_types::CertificateDer<'static>,
    /// What the recorder presents: leaf first, then the root that signed it.
    chain: Vec<rustls_pki_types::CertificateDer<'static>>,
    key: rustls_pki_types::PrivateKeyDer<'static>,
}

/// A one-run CA, and a leaf for `localhost` signed by it.
///
/// Two tiers because the two libraries disagree about one:
/// `generate_simple_self_signed` has no basic constraints and Go refuses it as
/// a root ("parent certificate cannot sign this kind of certificate"); adding
/// `CA:TRUE` satisfies Go and then rustls refuses the same cert as the end
/// entity (`CaUsedAsEndEntity`). A proper CA signing a proper leaf is the only
/// shape both accept, and it is also the shape a real MX presents.
fn self_signed() -> Cert {
    // The recorder builds a rustls ServerConfig, which needs a provider just
    // as the client does.
    jmapsmtp::inbound_tls::install_crypto_provider();

    let ca_key = rcgen::KeyPair::generate().expect("CA key");
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("CA params");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
    ];
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "smtp interop test CA");
    let ca_cert = ca_params.self_signed(&ca_key).expect("self-signing the CA");
    let issuer = rcgen::Issuer::new(ca_params, ca_key);

    let leaf_key = rcgen::KeyPair::generate().expect("leaf key");
    let mut leaf_params =
        rcgen::CertificateParams::new(vec![SERVER_NAME.to_string()]).expect("leaf params");
    leaf_params.is_ca = rcgen::IsCa::ExplicitNoCa;
    leaf_params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    leaf_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    leaf_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, SERVER_NAME);
    let leaf_cert = leaf_params
        .signed_by(&leaf_key, &issuer)
        .expect("signing the leaf");

    Cert {
        ca_pem: ca_cert.pem(),
        ca_der: ca_cert.der().clone(),
        chain: vec![leaf_cert.der().clone(), ca_cert.der().clone()],
        key: rustls_pki_types::PrivateKeyDer::try_from(leaf_key.serialize_der())
            .expect("the generated key should parse"),
    }
}

/// Answers enough SMTP to keep a client going, upgrades on `STARTTLS`, and
/// records every line with the fact of encryption attached.
///
/// It never judges: a rule here would make the comparison depend on this
/// file's opinions instead of on the two clients.
async fn start_recorder(cert: &Cert, offer_starttls: bool) -> (u16, Arc<Mutex<Vec<Heard>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().unwrap().port();
    let log: Arc<Mutex<Vec<Heard>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = log.clone();

    let tls = Arc::new(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert.chain.clone(), cert.key.clone_key())
            .expect("server config"),
    );

    tokio::spawn(async move {
        // One connection per client; the test drives them one at a time.
        for _ in 0..2u8 {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            let sink = sink.clone();
            let tls = tls.clone();
            tokio::spawn(async move {
                let mut plain = BufReader::new(stream);
                let _ = plain.get_mut().write_all(b"220 recorder ESMTP\r\n").await;

                // Plaintext half.
                let upgrade = loop {
                    let mut line = String::new();
                    if plain.read_line(&mut line).await.unwrap_or(0) == 0 {
                        return;
                    }
                    let cmd = line.trim_end_matches(['\r', '\n']).to_string();
                    sink.lock().unwrap().push(Heard {
                        line: cmd.clone(),
                        encrypted: false,
                    });
                    let upper = cmd.to_uppercase();
                    if upper.starts_with("STARTTLS") {
                        let _ = plain.get_mut().write_all(b"220 go ahead\r\n").await;
                        break true;
                    }
                    let reply = reply_for(&upper, offer_starttls);
                    let _ = plain.get_mut().write_all(reply.as_bytes()).await;
                    if upper.starts_with("QUIT") {
                        return;
                    }
                    if upper.starts_with("DATA") {
                        swallow_body(&mut plain, &sink, false).await;
                    }
                };

                if !upgrade {
                    return;
                }
                let Ok(stream) = tokio_rustls::TlsAcceptor::from(tls)
                    .accept(plain.into_inner())
                    .await
                else {
                    return;
                };
                let mut enc = BufReader::new(stream);
                loop {
                    let mut line = String::new();
                    if enc.read_line(&mut line).await.unwrap_or(0) == 0 {
                        return;
                    }
                    let cmd = line.trim_end_matches(['\r', '\n']).to_string();
                    sink.lock().unwrap().push(Heard {
                        line: cmd.clone(),
                        encrypted: true,
                    });
                    let upper = cmd.to_uppercase();
                    // STARTTLS is not offered a second time; a client that
                    // asked again would be told so by the reply below.
                    let reply = reply_for(&upper, false);
                    let _ = enc.get_mut().write_all(reply.as_bytes()).await;
                    if upper.starts_with("QUIT") {
                        return;
                    }
                    if upper.starts_with("DATA") {
                        swallow_body(&mut enc, &sink, true).await;
                    }
                }
            });
        }
    });
    (port, log)
}

fn reply_for(upper: &str, offer_starttls: bool) -> String {
    if upper.starts_with("EHLO") || upper.starts_with("HELO") {
        let mut out = String::new();
        out.push_str("250-PIPELINING\r\n250-SIZE 35882577\r\n250-8BITMIME\r\n");
        if offer_starttls {
            out.push_str("250-STARTTLS\r\n");
        }
        out.push_str("250-ENHANCEDSTATUSCODES\r\n250-SMTPUTF8\r\n250 recorder\r\n");
        out
    } else if upper.starts_with("DATA") {
        "354 go ahead\r\n".into()
    } else if upper.starts_with("QUIT") {
        "221 bye\r\n".into()
    } else {
        "250 ok\r\n".into()
    }
}

/// Read to the lone `.` and note it, without drowning the transcript in body.
async fn swallow_body<S>(read: &mut BufReader<S>, sink: &Arc<Mutex<Vec<Heard>>>, encrypted: bool)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    loop {
        let mut l = String::new();
        if read.read_line(&mut l).await.unwrap_or(0) == 0 {
            return;
        }
        if l.trim_end_matches(['\r', '\n']) == "." {
            sink.lock().unwrap().push(Heard {
                line: "<message body>".into(),
                encrypted,
            });
            let _ = read.get_mut().write_all(b"250 queued\r\n").await;
            return;
        }
    }
}

fn transcript(log: &Arc<Mutex<Vec<Heard>>>) -> Vec<Heard> {
    std::mem::take(&mut *log.lock().unwrap())
}

/// Drive `net/smtp` at the recorder, trusting the run's certificate.
fn go_send(bin: &Path, port: u16, ca_path: &Path) -> serde_json::Value {
    let request = serde_json::json!({
        "from": FROM, "rcpts": [TO], "message": MESSAGE, "helo": HELO_NAME,
    })
    .to_string();
    let mut child = Command::new(bin)
        .args(["send", &format!("{SERVER_NAME}:{port}")])
        .env("SMTP_INTEROP_CA", ca_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the helper should start");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(request.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "the helper should answer JSON: {e}\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    })
}

/// Both clients, one recorder, `(go, ours)`.
fn both(bin: &Path, offer_starttls: bool) -> (Vec<Heard>, Vec<Heard>) {
    let cert = self_signed();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let (port, log) = rt.block_on(start_recorder(&cert, offer_starttls));

    // Named after the port, not the process: cargo runs the two tests in this
    // file concurrently, and a per-process name meant the second run's
    // certificate overwrote the first's. Go then verified the served
    // certificate against a *different* one and reported "ECDSA verification
    // failure", which reads exactly like a real trust problem.
    let ca = std::env::temp_dir().join(format!("smtp-interop-ca-{port}.pem"));
    std::fs::write(&ca, cert.ca_pem.as_bytes()).expect("write the CA");

    // Go first, so a broken helper is reported before anything else runs.
    let response = {
        let bin = bin.to_path_buf();
        let ca = ca.clone();
        rt.block_on(
            async move { tokio::task::spawn_blocking(move || go_send(&bin, port, &ca)).await },
        )
        .unwrap()
    };
    assert!(
        response["ok"].as_bool().unwrap_or(false),
        "the Go client failed: {response}"
    );
    let go = transcript(&log);

    let ours = rt.block_on(async {
        let sender = jmapsmtp::smtp_out::Sender {
            hostname: HELO_NAME.into(),
            relay_host: None,
            extra_roots: vec![cert.ca_der.clone()],
        };
        sender
            .send_one(
                &format!("{SERVER_NAME}:{port}"),
                FROM,
                &[TO.to_string()],
                MESSAGE.as_bytes(),
            )
            .await
            .expect("the send should succeed");
        transcript(&log)
    });

    let _ = std::fs::remove_file(&ca);
    (go, ours)
}

#[test]
fn both_clients_upgrade_and_say_the_same_things() {
    let Some(bin) = require_helper() else { return };
    let (go, ours) = both(&bin, true);

    assert_eq!(
        ours, go,
        "the two clients differ against a server that offers STARTTLS — this \
         is the difference that stopped mail reaching every chatmail server"
    );

    // Guards on the recorder, not on the clients: if it had stopped recording,
    // or stopped upgrading, the comparison above would pass on two empty or
    // two plaintext transcripts.
    assert!(
        go.iter().any(|h| h.line.eq_ignore_ascii_case("STARTTLS")),
        "the oracle never sent STARTTLS, so nothing was compared: {go:#?}"
    );
    assert!(
        go.iter()
            .any(|h| h.encrypted && h.line.to_uppercase().starts_with("MAIL FROM")),
        "the message was not sent inside TLS: {go:#?}"
    );
    assert!(
        go.iter()
            .filter(|h| h.line.to_uppercase().starts_with("EHLO"))
            .count()
            == 2,
        "EHLO should be sent again after the upgrade: {go:#?}"
    );
}

/// The same recorder with STARTTLS withheld. Without this, a client that
/// blurted `STARTTLS` unconditionally would pass the test above.
#[test]
fn neither_client_offers_starttls_unprompted() {
    let Some(bin) = require_helper() else { return };
    let (go, ours) = both(&bin, false);

    assert_eq!(ours, go, "the two clients differ on a plain server");
    assert!(
        !ours.iter().any(|h| h.line.eq_ignore_ascii_case("STARTTLS")),
        "STARTTLS was sent to a server that never offered it: {ours:#?}"
    );
    assert!(
        ours.iter().all(|h| !h.encrypted),
        "something was encrypted without an upgrade: {ours:#?}"
    );
    assert!(go.len() >= 5, "captured too little: {go:#?}");
}
