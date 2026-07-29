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
pub fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
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

    /// `GET target`, returning `(status, body, location)`.
    ///
    /// Hand-rolled rather than via an HTTP client because the paths under test
    /// are deliberately malformed — `//relay-info`, `/a/../relay-info` — and
    /// every client normalises those before they reach the wire, which is
    /// exactly the behaviour being measured.
    pub fn get(&self, target: &str) -> (u16, String, String) {
        let mut s = TcpStream::connect(format!("127.0.0.1:{}", self.http_port)).unwrap();
        s.set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        write!(
            s,
            "GET {target} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
        )
        .unwrap();
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
        }
        let mut body = Vec::new();
        let _ = r.read_to_end(&mut body);
        (
            status,
            String::from_utf8_lossy(&body).into_owned(),
            location,
        )
    }
}

impl Drop for Oracle {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
