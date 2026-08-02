//! Starting the real Go binary and talking to it.
//!
//! Shared by the interop tests that need the oracle *running* rather than a
//! Go helper program. That distinction matters: where the behaviour under test
//! is the binary's own — its startup, its routing table — a helper would put a
//! reimplementation between the test and the thing being checked.

#![allow(dead_code)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};

/// A running oracle, killed when dropped.
pub struct Oracle {
    pub root: tempfile::TempDir,
    pub http_port: u16,
    child: Child,
}

/// The oracle built the same way this crate was.
///
/// `cargo test --no-default-features` is the port's `go build -tags noanchor`,
/// and comparing it against the anchored oracle would be comparing two
/// different programs — the route table alone differs by three entries. Both
/// binaries come out of `just oracle`.
pub const ORACLE_BIN: &str = if cfg!(feature = "anchor") {
    "jmapsmtp-oracle"
} else {
    "jmapsmtp-oracle-noanchor"
};

/// The oracle binary, or `None` with a printed skip.
///
/// `just test` sets `<NAME>_INTEROP=required`, which turns a missing binary
/// into a failure rather than a quiet pass — a suite that silently skips is
/// worse than no suite.
pub fn oracle_binary(required_var: &str) -> Option<PathBuf> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../oracle")
        .join(ORACLE_BIN)
        .canonicalize()
        .ok()
        .filter(|p| p.exists());
    if path.is_none() {
        assert!(
            std::env::var(required_var).as_deref() != Ok("required"),
            "{required_var}=required but oracle/{ORACLE_BIN} is missing — run `just oracle`"
        );
        eprintln!("skipping: oracle/{ORACLE_BIN} not built (run `just oracle`)");
    }
    path
}

/// A free TCP port. The oracle binds both an HTTP and an SMTP listener and
/// `log.Fatal`s if either fails, so neither can be left to a default.
///
/// # Why this is not `bind("127.0.0.1:0")`
///
/// Asking the OS for an ephemeral port means binding, reading the port, and
/// dropping the listener before the oracle can bind it. Under `cargo test`'s
/// parallelism two tests hit that window at once and the OS hands them the
/// **same** port — so one oracle wins and the other test silently talks to it,
/// asking a relay that never saw its seed for a token it does not have.
///
/// That is exactly what happened: the whole file passed with
/// `--test-threads=1` and failed one test in parallel, with a 401 that looked
/// like a token bug.
///
/// Ports are handed out from a counter instead. The counter makes two threads
/// in this process never pick the same one, and seeding it from the process id
/// keeps two test binaries running concurrently in different ranges.
pub fn free_port() -> u16 {
    use std::sync::atomic::{AtomicU16, Ordering};
    static NEXT: AtomicU16 = AtomicU16::new(0);

    // 20000..60000, offset per process so concurrent binaries do not overlap.
    const BASE: u32 = 20_000;
    const SPAN: u32 = 40_000;
    let pid_offset = (std::process::id() as u32).wrapping_mul(97) % SPAN;

    for _ in 0..SPAN {
        let n = NEXT.fetch_add(1, Ordering::Relaxed) as u32;
        let port = (BASE + (pid_offset + n * 7) % SPAN) as u16;
        // Still confirm it is actually free — another process on this machine
        // may hold it — but never reuse one this process already handed out.
        if std::net::TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
    panic!("no free port found");
}

impl Oracle {
    /// Start the oracle with a config built by `config_json(http_port,
    /// smtp_port)`, and wait for its HTTP listener — which is the last step of
    /// startup, so a successful connect means the whole sequence ran.
    pub fn start(config_json: fn(u16, u16) -> String) -> Option<Oracle> {
        Oracle::start_with("MUX_INTEROP", config_json, |_| {})
    }

    pub fn start_with(
        required_var: &str,
        config_json: fn(u16, u16) -> String,
        seed: impl FnOnce(&Path),
    ) -> Option<Oracle> {
        Oracle::start_with_env(required_var, config_json, seed, &[])
    }

    /// As [`Oracle::start_with`], with extra environment variables.
    ///
    /// `BISET_PGP_KEY` is the relay-wide OpenPGP key, and it is read from the
    /// environment rather than the config — so a test that needs the
    /// global-key branch of WKD has to set it here.
    pub fn start_with_env(
        required_var: &str,
        config_json: fn(u16, u16) -> String,
        seed: impl FnOnce(&Path),
        env: &[(&str, &str)],
    ) -> Option<Oracle> {
        let oracle = oracle_binary(required_var)?;
        let root = tempfile::tempdir().unwrap();

        // The oracle resolves its own directory from argv[0], not the working
        // directory, and reads config.json from there. A symlink is enough:
        // filepath.Abs does not resolve one.
        std::os::unix::fs::symlink(&oracle, root.path().join(ORACLE_BIN)).unwrap();

        let http_port = free_port();
        std::fs::write(
            root.path().join("config.json"),
            config_json(http_port, free_port()),
        )
        .unwrap();
        seed(root.path());

        let mut child = Command::new(root.path().join(ORACLE_BIN))
            .current_dir("/")
            // The admin routes' behaviour depends on these being unset, and
            // inheriting one from the developer's shell would silently change
            // what the tests observe.
            .env_remove("ADMIN_TOKEN")
            .env_remove("METRICS_TOKEN")
            .envs(env.iter().copied())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("the oracle should start");

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        let addr = format!("127.0.0.1:{http_port}");
        loop {
            if TcpStream::connect(&addr).is_ok() {
                break;
            }
            if let Ok(Some(status)) = child.try_wait() {
                let mut err = String::new();
                let _ = child.stderr.take().unwrap().read_to_string(&mut err);
                panic!("the oracle exited during startup ({status}):\n{err}");
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the oracle never opened {addr}"
            );
            std::thread::sleep(std::time::Duration::from_millis(50));
        }

        Some(Oracle {
            root,
            http_port,
            child,
        })
    }

    pub fn data_dir(&self) -> PathBuf {
        self.root.path().join("data")
    }

    /// `POST target` with a JSON body, returning `(status, body)`.
    pub fn post_json(&self, target: &str, body: &str) -> (u16, String) {
        let (status, body, _) = self.request("POST", target, Some(body), None);
        (status, body)
    }

    /// `POST target` with a JSON body and HTTP Basic credentials.
    pub fn post_json_auth(&self, target: &str, body: &str, auth: &str) -> (u16, String) {
        let (status, body, _) = self.request("POST", target, Some(body), Some(auth));
        (status, body)
    }

    /// `PUT target` with a body and Basic credentials.
    pub fn put_auth(&self, target: &str, body: &str, auth: &str) -> (u16, String) {
        let (status, body, _) = self.request("PUT", target, Some(body), Some(auth));
        (status, body)
    }

    /// `GET target` with Basic credentials.
    pub fn get_auth(&self, target: &str, auth: &str) -> (u16, String, String) {
        self.request("GET", target, None, Some(auth))
    }

    /// `GET target`, returning `(status, body, location)`.
    ///
    /// Hand-rolled rather than via an HTTP client because the paths under test
    /// are deliberately malformed — `//relay-info`, `/a/../relay-info` — and
    /// every client normalises those before they reach the wire, which is
    /// exactly the behaviour being measured.
    pub fn get(&self, target: &str) -> (u16, String, String) {
        self.request("GET", target, None, None)
    }

    fn request(
        &self,
        method: &str,
        target: &str,
        body: Option<&str>,
        basic_auth: Option<&str>,
    ) -> (u16, String, String) {
        let mut s = TcpStream::connect(format!("127.0.0.1:{}", self.http_port)).unwrap();
        s.set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        write!(
            s,
            "{method} {target} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n"
        )
        .unwrap();
        if let Some(auth) = basic_auth {
            write!(s, "Authorization: Basic {auth}\r\n").unwrap();
        }
        match body {
            Some(b) => write!(
                s,
                "Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{b}",
                b.len()
            )
            .unwrap(),
            None => write!(s, "\r\n").unwrap(),
        }
        s.flush().unwrap();

        let mut r = BufReader::new(s);
        let mut line = String::new();
        r.read_line(&mut line).unwrap();
        let status: u16 = line
            .split_whitespace()
            .nth(1)
            .and_then(|c| c.parse().ok())
            .unwrap_or_else(|| panic!("unparseable status line {line:?}"));

        let mut location = String::new();
        let mut chunked = false;
        loop {
            let mut h = String::new();
            r.read_line(&mut h).unwrap();
            let h = h.trim_end();
            if h.is_empty() {
                break;
            }
            if let Some(v) = h.strip_prefix("Location: ") {
                location = v.to_string();
            }
            if h.eq_ignore_ascii_case("transfer-encoding: chunked") {
                chunked = true;
            }
        }

        // Go switches to chunked once a response outgrows its write buffer, so
        // whether a body arrives framed depends on its size — small ones did
        // not, which is why this went unnoticed until the /setup page. Decoding
        // here means a large body is compared as its content rather than as
        // `ea7\r\n<content>\r\n0\r\n\r\n`.
        let body = if chunked {
            read_chunked(&mut r)
        } else {
            let mut body = Vec::new();
            let _ = r.read_to_end(&mut body);
            body
        };
        (
            status,
            String::from_utf8_lossy(&body).into_owned(),
            location,
        )
    }
}

/// RFC 9112 chunked bodies: `<hex size>\r\n<bytes>\r\n` until a zero-sized
/// chunk. Trailers, if any, are discarded — nothing here sends them.
fn read_chunked(r: &mut BufReader<TcpStream>) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut size_line = String::new();
        if r.read_line(&mut size_line).is_err() {
            break;
        }
        // A chunk extension after `;` is legal and ignored.
        let size_hex = size_line.trim().split(';').next().unwrap_or("").to_string();
        let Ok(size) = usize::from_str_radix(&size_hex, 16) else {
            break;
        };
        if size == 0 {
            break;
        }
        let mut chunk = vec![0u8; size];
        if r.read_exact(&mut chunk).is_err() {
            break;
        }
        out.extend_from_slice(&chunk);
        // The CRLF that terminates the chunk.
        let mut crlf = [0u8; 2];
        let _ = r.read_exact(&mut crlf);
    }
    out
}

impl Drop for Oracle {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
