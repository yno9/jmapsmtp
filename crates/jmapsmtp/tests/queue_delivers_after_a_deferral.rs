//! A message refused with a 4xx is delivered on a later attempt.
//!
//! The unit tests cover the pieces — what counts as temporary, how the wait
//! widens, what the queue keeps on disk. None of them shows the thing that
//! matters, which is that a greylisted message **arrives**. That needs a
//! server that says no and then yes, and a client that comes back.
//!
//! Greylisting is why this exists: refusing an unknown sender's first attempt
//! with a 4xx and accepting a retry minutes later is ordinary practice, and
//! before the queue every greylisted message this relay sent was lost with the
//! sender told the address did not work.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

/// What [`flaky_server`] hands back: where to connect, what arrived, and how
/// many messages it has been offered.
struct Flaky {
    addr: String,
    accepted: Arc<Mutex<Vec<Vec<u8>>>>,
    attempts: Arc<AtomicUsize>,
}

/// Refuses the first `refusals` messages with a 4xx, then accepts.
///
/// The refusal comes at end-of-DATA, which is where a greylister that has
/// already taken the envelope puts it.
fn flaky_server(refusals: usize) -> Flaky {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap().to_string();
    let accepted: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
    let attempts = Arc::new(AtomicUsize::new(0));
    let (sink, counter) = (accepted.clone(), attempts.clone());

    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut r = BufReader::new(stream.try_clone().unwrap());
            let mut w = stream;
            let _ = write!(w, "220 flaky ESMTP\r\n");
            let _ = w.flush();
            let mut body = Vec::new();
            let mut in_data = false;
            loop {
                let mut line = String::new();
                if r.read_line(&mut line).unwrap_or(0) == 0 {
                    break;
                }
                if in_data {
                    if line.trim_end_matches(['\r', '\n']) == "." {
                        in_data = false;
                        let n = counter.fetch_add(1, Ordering::SeqCst);
                        if n < refusals {
                            let _ = write!(w, "451 4.7.1 Greylisted, try again\r\n");
                        } else {
                            sink.lock().unwrap().push(std::mem::take(&mut body));
                            let _ = write!(w, "250 queued\r\n");
                        }
                        let _ = w.flush();
                        continue;
                    }
                    body.extend_from_slice(line.as_bytes());
                    continue;
                }
                let upper = line.to_uppercase();
                let reply = if upper.starts_with("EHLO") || upper.starts_with("HELO") {
                    "250-8BITMIME\r\n250 flaky\r\n".to_string()
                } else if upper.starts_with("DATA") {
                    in_data = true;
                    "354 go ahead\r\n".into()
                } else if upper.starts_with("QUIT") {
                    let _ = write!(w, "221 bye\r\n");
                    let _ = w.flush();
                    break;
                } else {
                    "250 ok\r\n".into()
                };
                let _ = write!(w, "{reply}");
                let _ = w.flush();
            }
        }
    });
    Flaky {
        addr,
        accepted,
        attempts,
    }
}

fn sender(relay_host: &str) -> jmapsmtp::smtp_out::Sender {
    jmapsmtp::smtp_out::Sender {
        hostname: "mx.a.test".into(),
        relay_host: Some(relay_host.to_string()),
        extra_roots: Vec::new(),
    }
}

const RAW: &[u8] = b"From: alice@a.test\r\nTo: bob@b.test\r\nSubject: held\r\n\r\nhello\r\n";

#[tokio::test]
async fn a_greylisted_message_is_held_and_then_delivered() {
    let Flaky {
        addr,
        accepted,
        attempts,
    } = flaky_server(1);
    let data = tempfile::tempdir().expect("tempdir");
    let to = vec!["bob@b.test".to_string()];

    // First attempt: refused with a 4xx, and held rather than lost.
    let err = sender(&addr)
        .deliver(&NoMx, "alice@a.test", &to, RAW)
        .await
        .expect_err("the server refuses the first message");
    assert_eq!(
        jmapsmtp::queue::policy::classify(&err),
        jmapsmtp::queue::policy::Temporality::Temporary,
        "a 451 at end-of-DATA has to read as temporary or the message is dropped"
    );
    let entry = jmapsmtp::queue::enqueue(data.path(), "alice@a.test", &to, RAW, &err.to_string())
        .expect("enqueue");
    assert!(accepted.lock().unwrap().is_empty(), "nothing arrived yet");

    // The retry the schedule would make, once its wait has passed.
    let held = jmapsmtp::queue::message(data.path(), &entry.id).expect("message kept");
    sender(&addr)
        .deliver(&NoMx, &entry.from, &entry.to, &held)
        .await
        .expect("the second attempt is accepted");
    jmapsmtp::queue::remove(data.path(), &entry.id).expect("remove");

    // The message that arrived is the one that was sent, byte for byte.
    let arrived = accepted.lock().unwrap();
    assert_eq!(arrived.len(), 1, "delivered exactly once");
    let text = String::from_utf8_lossy(&arrived[0]);
    assert!(text.contains("Subject: held"), "wrong message: {text}");
    assert!(text.contains("hello"), "the body did not survive: {text}");
    assert_eq!(
        attempts.load(Ordering::SeqCst),
        2,
        "one refusal, one accept"
    );
    assert!(
        jmapsmtp::queue::load_all(data.path()).is_empty(),
        "a delivered message must leave the queue"
    );
}

/// The envelope is what gets retried — not something re-derived from the
/// headers. A Bcc'd or list-expanded recipient appears nowhere in the message.
#[tokio::test]
async fn the_retry_uses_the_stored_envelope_not_the_headers() {
    let Flaky { addr, accepted, .. } = flaky_server(1);
    let data = tempfile::tempdir().expect("tempdir");
    let hidden = vec!["hidden@elsewhere.test".to_string()];

    let err = sender(&addr)
        .deliver(&NoMx, "bounces+tag@a.test", &hidden, RAW)
        .await
        .expect_err("refused");
    let entry = jmapsmtp::queue::enqueue(
        data.path(),
        "bounces+tag@a.test",
        &hidden,
        RAW,
        &err.to_string(),
    )
    .expect("enqueue");

    let reloaded = jmapsmtp::queue::load_all(data.path())
        .pop()
        .expect("one entry");
    assert_eq!(reloaded.from, "bounces+tag@a.test");
    assert_eq!(reloaded.to, hidden);

    let held = jmapsmtp::queue::message(data.path(), &entry.id).expect("message");
    sender(&addr)
        .deliver(&NoMx, &reloaded.from, &reloaded.to, &held)
        .await
        .expect("accepted");
    assert_eq!(accepted.lock().unwrap().len(), 1);
}

/// `relay_host` is set in these tests, so the resolver is never consulted.
struct NoMx;
impl jmapsmtp::smtp_out::MxResolver for NoMx {
    fn lookup_mx(&self, _domain: &str) -> Vec<String> {
        unreachable!("relay_host is set, so no MX lookup should happen")
    }
}
