//! The binary must actually emit its `tracing` output.
//!
//! It did not. `tracing-subscriber` was a dependency with `env-filter`
//! enabled, nothing installed a subscriber, and all fourteen `tracing::` calls
//! in the crate went nowhere — including every line describing an outbound
//! delivery: the host dialled, a refused STARTTLS, a rejected recipient, the
//! successful send. What reached the journal was the handful of `eprintln!`s,
//! all of them failures, so the log read as a list of errors with no context
//! and no successes.
//!
//! That shape is worse than no log. Chasing a delivery problem in production,
//! I read "no successful send today" out of a log that could not have
//! contained one, and told the user their mail had not gone out. It had.
//!
//! # Why this drives the binary
//!
//! The defect was not in `init_logging` — there was no `init_logging`. It was
//! that nothing called one. A unit test on the function would have passed
//! against the broken build, because the function it tests would have been
//! written to make it pass. Only running the program shows whether anything
//! wires it up.
//!
//! So: start the real binary, and require a known `tracing::info!` line on its
//! output. The line chosen is one the relay must print to be useful at all.

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Where `cargo test` leaves the binary this workspace builds.
fn binary() -> std::path::PathBuf {
    // `current_exe` is target/<profile>/deps/<test>; the binary is two up.
    let mut p = std::env::current_exe().expect("current exe");
    p.pop();
    p.pop();
    p.push("jmapsmtp");
    p
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind")
        .local_addr()
        .unwrap()
        .port()
}

/// Run the relay in a scratch directory until it says something, or time out.
///
/// Returns every line it produced.
fn boot_and_collect(wait_for: &str, timeout: Duration) -> (bool, Vec<String>) {
    let bin = binary();
    assert!(
        bin.exists(),
        "the relay binary is missing at {} — `cargo build` first",
        bin.display()
    );

    // Unique per call, not per process: cargo runs this file's tests
    // concurrently, and a shared directory meant one test exec'd the binary
    // while the other was still copying over it — "Text file busy".
    static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let seq = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("jmapsmtp-log-test-{}-{seq}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    // The relay resolves its config from argv[0]'s directory, so the binary
    // has to sit beside the config.
    let bin_copy = dir.join("jmapsmtp");
    std::fs::copy(&bin, &bin_copy).expect("copy the binary");

    let http = free_port();
    let smtp = free_port();
    std::fs::write(
        dir.join("config.json"),
        format!(
            r#"{{"listen_addr":"127.0.0.1:{http}","smtp_port":{smtp},
                "base_url":"http://127.0.0.1:{http}","hostname":"log.test",
                "domain":{{"a.test":{{"account":{{"alice":{{}}}}}}}}}}"#
        ),
    )
    .expect("config");

    let mut child = Command::new(&bin_copy)
        .current_dir(&dir)
        // Left unset on purpose: the default has to be the useful one. A test
        // that sets RUST_LOG=info would pass against a build whose default
        // filter discarded everything.
        .env_remove("RUST_LOG")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the relay should start");

    // `tracing_subscriber::fmt` writes to **stdout**, not stderr — worth
    // stating because the first version of this test read stderr, saw nothing,
    // and reported that the relay emits no log output at all. Both streams are
    // read here so a failure to start (which goes to stderr) shows up in the
    // message rather than as silence.
    let (tx, rx) = std::sync::mpsc::channel();
    for stream in [
        Box::new(child.stdout.take().expect("stdout")) as Box<dyn std::io::Read + Send>,
        Box::new(child.stderr.take().expect("stderr")),
    ] {
        let tx = tx.clone();
        std::thread::spawn(move || {
            for line in BufReader::new(stream).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    return;
                }
            }
        });
    }
    drop(tx);

    let deadline = Instant::now() + timeout;
    let mut lines = Vec::new();
    let mut found = false;
    while Instant::now() < deadline {
        match rx.recv_timeout(Duration::from_millis(200)) {
            Ok(line) => {
                found = line.contains(wait_for);
                lines.push(line);
                if found {
                    break;
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }

    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&dir);
    (found, lines)
}

#[test]
fn the_relay_emits_its_tracing_output() {
    let (found, lines) = boot_and_collect("jmap listening on", Duration::from_secs(30));
    assert!(
        found,
        "the relay produced no tracing output — every tracing::info!/warn! in \
         the crate is being discarded.\nWhat it did say:\n{}",
        lines.join("\n")
    );
}

/// The default filter has to pass `info`, which is the level the delivery
/// lines are written at. A build that installed a subscriber but left the
/// filter at `warn` would satisfy the test above only by accident of which
/// line it waits for, so the level is asserted where it is used.
#[test]
fn info_is_the_default_level() {
    let (found, lines) = boot_and_collect("[smtp] listening on", Duration::from_secs(30));
    assert!(
        found,
        "the SMTP listener's info line did not appear, so info is filtered \
         out and `[smtp] connecting to` / `sent to` are invisible in \
         production.\nWhat it did say:\n{}",
        lines.join("\n")
    );
}
