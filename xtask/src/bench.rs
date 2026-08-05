//! Latency comparison against the Go implementation (PLAN.md M8b).
//!
//! Same discipline as the differential harness: the number that means
//! something is the one the **Go binary produced on this machine, in this
//! run**, not a figure from a blog post about Go and Rust. So both binaries
//! are booted from the identical difftest fixture, driven over the same
//! connection type, and reported side by side. Absolute milliseconds here are
//! worth little; the ratio between two columns measured minutes apart is
//! worth something.
//!
//! Four things this deliberately does **not** do:
//!
//! - **No concurrency.** One connection, requests in sequence. That measures
//!   per-request work, which is what a port can get wrong. Throughput under
//!   load is a property of the runtime and the machine, and measuring it here
//!   would mostly report how many cores the CI box has.
//! - **No mean.** Medians and p95. Request latency is right-skewed — one GC
//!   pause or one page fault moves a mean and tells you nothing about the
//!   typical request.
//! - **No debug binaries.** An unoptimised Rust build against an optimised Go
//!   build is not a comparison, it is a category error. This refuses to run
//!   against `target/debug`.
//! - **No claim about the SMTP path.** Everything here is HTTP. Delivery
//!   latency is dominated by the network and by the far end.

use std::net::TcpStream;
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use serde_json::{Value, json};

use crate::difftest::fixture::{self, Instance};
use crate::difftest::instance::{Running, free_port};

/// Set on both sides. `/metrics` is the one case where an unset token makes
/// the two implementations do different work — Go serves the page, this port
/// 401s (SPEC.md §11.13) — so timing it unset would compare a full walk of
/// `data/` against a rejection. The first run of this bench did exactly that
/// and the status guard caught it.
const TOKEN: &str = "bench-token";

pub struct Options {
    /// Timed requests per case, per side.
    pub iterations: usize,
    /// Messages delivered into the mailbox before timing anything.
    ///
    /// PLAN.md's M8 criteria name 1,000. Without them `email-query` sorts an
    /// empty list and measures the same thing `relay-info` does — the first
    /// version of this bench did exactly that and claimed to be timing "the
    /// store's sort and filter path".
    pub messages: usize,
}

/// One request shape, chosen because it isolates a different kind of work.
struct Case {
    name: &'static str,
    what: &'static str,
    method: &'static str,
    path: &'static str,
    auth: bool,
    bearer: bool,
    body: Option<Value>,
}

fn cases() -> Vec<Case> {
    vec![
        Case {
            name: "relay-info",
            what: "routing + a small JSON encode; the per-request floor",
            method: "GET",
            path: "/relay-info",
            auth: false,
            bearer: false,
            body: None,
        },
        Case {
            name: "session",
            what: "credential check (sha256) + the Session document",
            method: "GET",
            path: "/.well-known/jmap",
            auth: true,
            bearer: false,
            body: None,
        },
        Case {
            name: "mailbox-get",
            what: "store read + Go-compatible JSON encode",
            method: "POST",
            path: "/jmap/api/",
            auth: true,
            bearer: false,
            body: Some(jmap_call(
                "Mailbox/get",
                json!({"accountId": fixture::ACCOUNT}),
            )),
        },
        Case {
            name: "email-query",
            what: "the store's sort and filter path",
            method: "POST",
            path: "/jmap/api/",
            auth: true,
            bearer: false,
            body: Some(jmap_call(
                "Email/query",
                json!({
                    "accountId": fixture::ACCOUNT,
                    "sort": [{"property": "receivedAt", "isAscending": false}],
                }),
            )),
        },
        Case {
            name: "metrics",
            // NOT a like-for-like comparison, and the gap it shows is
            // mostly not speed: the Go build renders ~40 extra series from
            // the Go-runtime and process collectors, and counts `peers` and
            // the domain registry in the account walk where this port does
            // not (SPEC.md §11.16). Kept because a regression in the walk
            // would still show up as this column moving.
            what: "a walk of data/ — see the note below, the sides differ here",
            method: "GET",
            path: "/metrics",
            auth: false,
            bearer: true,
            body: None,
        },
    ]
}

/// go ÷ rust, so above 1.00× means this port used less of whatever it is.
fn ratio(go: f64, rust: f64) -> String {
    if rust > 0.0 {
        format!("{:.2}×", go / rust)
    } else {
        "—".to_string()
    }
}

fn jmap_call(method: &str, args: Value) -> Value {
    json!({
        "using": [
            "urn:ietf:params:jmap:core",
            "urn:ietf:params:jmap:mail",
            "urn:ietf:params:jmap:submission",
        ],
        "methodCalls": [[method, args, "c0"]],
    })
}

/// Everything measured on one side.
struct SideResult {
    cases: Vec<Sample>,
    /// Spawn to first answered request, coarse (see `POLL_INTERVAL`).
    startup: Duration,
    /// VmRSS after the run, in KiB. `None` off Linux.
    rss_kib: Option<u64>,
}

/// Timings for one case on one side, already sorted.
struct Sample {
    micros: Vec<u128>,
}

impl Sample {
    fn quantile(&self, q: f64) -> f64 {
        if self.micros.is_empty() {
            return f64::NAN;
        }
        // Nearest-rank. With a few hundred samples the choice of quantile
        // definition is far below the run-to-run noise.
        let idx = ((self.micros.len() as f64 - 1.0) * q).round() as usize;
        self.micros[idx] as f64 / 1000.0
    }
    fn median(&self) -> f64 {
        self.quantile(0.5)
    }
    fn p95(&self) -> f64 {
        self.quantile(0.95)
    }
}

pub fn run(opts: Options) -> Result<()> {
    let root = crate::difftest::workspace_root()?;

    let oracle = root.join("oracle/jmapsmtp-oracle");
    if !oracle.exists() {
        bail!(
            "oracle binary not found at {} — run `just oracle` first",
            oracle.display()
        );
    }
    let port = root.join("target/release/jmapsmtp");
    if !port.exists() {
        bail!(
            "release binary not found at {} — run `cargo build --release` first.\n\
             This refuses to bench target/debug: an unoptimised build against an \
             optimised Go build is not a comparison.",
            port.display()
        );
    }

    let work = root.join("target/bench");
    std::fs::create_dir_all(&work)?;

    println!(
        "bench: {} messages delivered, then {} timed requests per case, per side,\n\
         sequential on one connection\n",
        opts.messages, opts.iterations
    );

    let cases = cases();
    let go = measure("oracle", &work.join("go"), &oracle, &cases, &opts)?;
    let rs = measure("rust", &work.join("rs"), &port, &cases, &opts)?;

    report(&cases, &go, &rs, &opts);

    let _ = std::fs::remove_dir_all(&work);
    Ok(())
}

/// Boot one binary from the difftest fixture and time every case against it.
fn measure(
    label: &str,
    dir: &Path,
    binary: &Path,
    cases: &[Case],
    opts: &Options,
) -> Result<SideResult> {
    let inst = Instance {
        dir: dir.to_path_buf(),
        http_port: free_port()?,
        smtp_port: free_port()?,
    };
    fixture::seed_mutated(&inst, binary, None).context("seeding instance")?;
    let running = Running::start_with_tokens(inst, Some(TOKEN)).context("starting instance")?;

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        // Keep-alive on purpose: reconnecting every request would measure the
        // kernel's TCP handshake on both sides equally and drown the part
        // that differs.
        .pool_max_idle_per_host(1)
        .build()?;
    let base = running.inst.base_url();
    let password = fixture::basic_auth_password();

    // Delivered over SMTP rather than written into data/ directly: each side
    // then builds its own store through its own ingestion path, which is the
    // only way to be sure both mailboxes hold the same thing without this
    // harness having to know the on-disk format.
    //
    // In batches, with a JMAP request between them, because Go buffers
    // inbound mail in a 256-slot channel and drops the overflow (SPEC.md
    // §11.17). Delivering 1,000 in one go left the oracle holding 256 and
    // this port holding 1,000 — two different benchmarks wearing one name.
    // The batching is what a real client's polling does anyway.
    let mut sent = 0;
    while sent < opts.messages {
        let n = BATCH.min(opts.messages - sent);
        deliver(label, running.inst.smtp_port, sent, n)
            .with_context(|| format!("{label}: seeding messages {sent}..{}", sent + n))?;
        sent += n;
        // Drains Go's channel, making room for the next batch. A no-op here.
        query_ids(&client, &base, &password)?;
    }
    confirm_stored(label, &client, &base, &password, opts.messages, &running)?;

    let mut out = Vec::new();
    for case in cases {
        // Warm-up, discarded. Both implementations load parts of the store
        // lazily, and the first request also pays for the connection.
        for _ in 0..WARMUP {
            one(&client, &base, &password, case)?;
        }
        let mut micros = Vec::with_capacity(opts.iterations);
        for _ in 0..opts.iterations {
            let t = Instant::now();
            let status = one(&client, &base, &password, case)?;
            micros.push(t.elapsed().as_micros());
            // A case that 4xx/5xx's is not measuring the work it names — a
            // 401 against `session` would time the auth rejection and look
            // impressively fast.
            if status >= 400 {
                bail!(
                    "{label}: case `{}` returned {status}; it is not exercising \
                     what it claims to:\n{}",
                    case.name,
                    running.log()
                );
            }
        }
        micros.sort_unstable();
        out.push(Sample { micros });
    }

    let startup = running.started_in;
    let rss_kib = rss_kib(running.pid());
    drop(running);
    Ok(SideResult {
        cases: out,
        startup,
        rss_kib,
    })
}

/// Ask the relay how many messages it actually has.
///
/// Without this the `email-query` row is a claim rather than a measurement:
/// if delivery silently dropped everything, the query would sort an empty
/// list and report a number indistinguishable from a fast one. The first
/// version of this bench had no messages at all and said it was timing "the
/// store's sort and filter path".
fn confirm_stored(
    label: &str,
    client: &reqwest::blocking::Client,
    base: &str,
    password: &str,
    want: usize,
    running: &Running,
) -> Result<()> {
    let (status, body) = query_ids(client, base, password)?;
    if status >= 400 {
        bail!("{label}: Email/query returned {status}:\n{}", running.log());
    }
    let v: Value = serde_json::from_str(&body)
        .with_context(|| format!("{label}: Email/query response was not JSON: {body}"))?;
    let got = v["methodResponses"][0][1]["ids"]
        .as_array()
        .map(|a| a.len())
        .unwrap_or(0);
    if got != want {
        bail!(
            "{label}: delivered {want} messages but the store holds {got}. \
             The email-query row would be measuring the wrong thing.\n{body}"
        );
    }
    Ok(())
}

/// `Email/query` with no limit worth speaking of. Doubles as the request that
/// drains Go's inbound channel.
fn query_ids(
    client: &reqwest::blocking::Client,
    base: &str,
    password: &str,
) -> Result<(u16, String)> {
    let case = Case {
        name: "confirm",
        what: "",
        method: "POST",
        path: "/jmap/api/",
        auth: true,
        bearer: false,
        body: Some(jmap_call(
            "Email/query",
            json!({"accountId": fixture::ACCOUNT, "limit": 1_000_000}),
        )),
    };
    one_with_body(client, base, password, &case)
}

/// Resident set size from `/proc/<pid>/status`, read while the process is
/// still alive. A peak would be more useful, but VmHWM includes the startup
/// transient and this is meant to answer "does it sit on a lot of memory".
fn rss_kib(pid: u32) -> Option<u64> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    status
        .lines()
        .find_map(|l| l.strip_prefix("VmRSS:"))
        .and_then(|v| v.split_whitespace().next()?.parse().ok())
}

/// Half of Go's 256-slot channel, so a batch cannot fill it even if a
/// message is still in flight when the drain request lands.
const BATCH: usize = 128;

/// Deliver `n` messages to the fixture account over plain SMTP, numbered from
/// `first`.
///
/// `first` is a parameter because the store is keyed by Message-ID: a second
/// batch reusing `bench-0..` overwrites the first, and the mailbox never
/// grows past one batch.
fn deliver(label: &str, port: u16, first: usize, n: usize) -> Result<()> {
    use std::io::{BufRead, BufReader, Write};

    if n == 0 {
        return Ok(());
    }
    let stream = TcpStream::connect(("127.0.0.1", port))
        .with_context(|| format!("connecting to the {label} SMTP listener on {port}"))?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    let mut r = BufReader::new(stream.try_clone()?);
    let mut w = stream;

    let expect = |r: &mut BufReader<TcpStream>, want: u8| -> Result<()> {
        loop {
            let mut line = String::new();
            if r.read_line(&mut line)? == 0 {
                bail!("{label}: SMTP connection closed early");
            }
            let code = line.as_bytes().first().copied().unwrap_or(b'?');
            // Multi-line replies keep going while the 4th byte is '-'.
            if line.as_bytes().get(3) == Some(&b'-') {
                continue;
            }
            if code != want {
                bail!(
                    "{label}: SMTP expected {}xx, got: {}",
                    want - b'0',
                    line.trim()
                );
            }
            return Ok(());
        }
    };

    expect(&mut r, b'2')?; // greeting
    writeln!(w, "EHLO bench.invalid\r")?;
    expect(&mut r, b'2')?;

    for i in first..first + n {
        writeln!(w, "MAIL FROM:<sender@bench.invalid>\r")?;
        expect(&mut r, b'2')?;
        writeln!(w, "RCPT TO:<{}>\r", fixture::ACCOUNT)?;
        expect(&mut r, b'2')?;
        writeln!(w, "DATA\r")?;
        expect(&mut r, b'3')?;
        // Each message gets a distinct Date and Subject so the sort has
        // something to order and the dedupe (if any) cannot collapse them.
        write!(
            w,
            "From: sender@bench.invalid\r\n\
             To: {}\r\n\
             Subject: bench message {i}\r\n\
             Message-ID: <bench-{i}@bench.invalid>\r\n\
             Date: Tue, 05 Aug 2026 {:02}:{:02}:{:02} +0000\r\n\
             \r\n\
             Body of bench message {i}.\r\n\
             .\r\n",
            fixture::ACCOUNT,
            i / 3600 % 24,
            i / 60 % 60,
            i % 60,
        )?;
        w.flush()?;
        expect(&mut r, b'2')?;
    }
    writeln!(w, "QUIT\r")?;
    Ok(())
}

const WARMUP: usize = 20;

fn one(client: &reqwest::blocking::Client, base: &str, password: &str, case: &Case) -> Result<u16> {
    one_with_body(client, base, password, case).map(|(status, _)| status)
}

fn one_with_body(
    client: &reqwest::blocking::Client,
    base: &str,
    password: &str,
    case: &Case,
) -> Result<(u16, String)> {
    let method = reqwest::Method::from_bytes(case.method.as_bytes())?;
    let mut req = client.request(method, format!("{base}{}", case.path));
    if case.auth {
        req = req.basic_auth(fixture::ACCOUNT, Some(password));
    }
    if case.bearer {
        req = req.bearer_auth(TOKEN);
    }
    if let Some(body) = &case.body {
        req = req.header("Content-Type", "application/json").json(body);
    }
    let resp = req
        .send()
        .with_context(|| format!("case {}: {} {}", case.name, case.method, case.path))?;
    let status = resp.status().as_u16();
    // Read the body: leaving it unread would stop the clock before the server
    // has finished writing it, and the encode is exactly what is being timed.
    let body = resp.text()?;
    Ok((status, body))
}

fn report(cases: &[Case], go: &SideResult, rs: &SideResult, opts: &Options) {
    println!(
        "{:<14} {:>10} {:>10} {:>10} {:>10} {:>8}",
        "case", "go p50", "rust p50", "go p95", "rust p95", "p50"
    );
    println!("{}", "─".repeat(66));
    for (i, case) in cases.iter().enumerate() {
        let (g, r) = (&go.cases[i], &rs.cases[i]);
        let ratio = ratio(g.median(), r.median());
        println!(
            "{:<14} {:>9.3}ms {:>9.3}ms {:>9.3}ms {:>9.3}ms {:>8}",
            case.name,
            g.median(),
            r.median(),
            g.p95(),
            r.p95(),
            ratio
        );
    }
    println!(
        "\n{:<14} {:>9.0}ms {:>9.0}ms {:>10} {:>10} {:>8}",
        "startup",
        go.startup.as_secs_f64() * 1000.0,
        rs.startup.as_secs_f64() * 1000.0,
        "—",
        "—",
        ratio(
            go.startup.as_secs_f64() * 1000.0,
            rs.startup.as_secs_f64() * 1000.0
        ),
    );
    if let (Some(g), Some(r)) = (go.rss_kib, rs.rss_kib) {
        println!(
            "{:<14} {:>9.1}MB {:>9.1}MB {:>10} {:>10} {:>8}",
            "resident",
            g as f64 / 1024.0,
            r as f64 / 1024.0,
            "—",
            "—",
            ratio(g as f64, r as f64),
        );
    }

    println!("\ncases (mailbox holds {} messages):", opts.messages);
    for case in cases {
        println!("  {:<14} {}", case.name, case.what);
    }
    println!(
        "\nThe last column is go ÷ rust: above 1.00× this port used less.\n\
         One machine, one run, no concurrency — treat it as a smoke test for a\n\
         gross regression, not as a benchmark result anyone should quote.\n\
         \n\
         `metrics` is the one row that is not like-for-like: the Go build\n\
         renders the go_*/process_* collectors this port has no counterpart\n\
         for, so most of that column is output size, not speed."
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(v: &[u128]) -> Sample {
        let mut micros = v.to_vec();
        micros.sort_unstable();
        Sample { micros }
    }

    /// A quantile that is off by one silently reports the wrong number
    /// forever — nothing downstream would notice, because there is nothing
    /// downstream. These pin both ends and the middle.
    #[test]
    fn quantile_picks_the_nearest_rank() {
        let s = sample(&[1000, 2000, 3000, 4000, 5000]);
        assert_eq!(s.quantile(0.0), 1.0, "p0 is the fastest request");
        assert_eq!(s.median(), 3.0);
        assert_eq!(s.quantile(1.0), 5.0, "p100 is the slowest request");
        // 0.95 of (5-1) = 3.8, rounds to index 4.
        assert_eq!(s.p95(), 5.0);
    }

    #[test]
    fn quantile_reports_microseconds_as_milliseconds() {
        assert_eq!(sample(&[1500]).median(), 1.5);
    }

    #[test]
    fn an_empty_sample_does_not_panic() {
        assert!(sample(&[]).median().is_nan());
    }

    /// Every case must name work the relay actually does, and no two may
    /// measure the same shape — a duplicate would look like corroboration.
    #[test]
    fn cases_are_distinct_and_described() {
        let cases = cases();
        let mut seen = std::collections::HashSet::new();
        for c in &cases {
            assert!(!c.what.is_empty(), "{} has no description", c.name);
            assert!(
                seen.insert((c.method, c.path, c.body.clone())),
                "{} duplicates another case",
                c.name
            );
        }
    }

    /// `/metrics` is the one case whose route is closed without a token on
    /// this side (SPEC.md §11.13). If the bearer were dropped, the Rust
    /// column would time a 401 against Go's full page render.
    #[test]
    fn the_metrics_case_carries_a_bearer_token() {
        let metrics = cases().into_iter().find(|c| c.name == "metrics").unwrap();
        assert!(metrics.bearer);
    }
}
