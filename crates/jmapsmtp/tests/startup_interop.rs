//! The orphan sweep, checked against the Go binary that actually runs it.
//!
//! This path is a `remove_dir_all` over user mail, so reading the Go source
//! and believing it is not enough. The oracle runs `cleanupOrphanedData` as
//! step 6 of its startup, so seeding a `data/` directory, starting the oracle,
//! and looking at what survived is a direct observation of the real rule —
//! including the parts that are easy to get wrong by reading (`peers`,
//! `_domains`, and the envelope-vs-hash distinction).
//!
//! There is no Go helper program here, unlike the other interop tests: the
//! behaviour under test *is* the binary's startup, and wrapping it would put a
//! reimplementation between the test and the thing it checks.

use std::path::{Path, PathBuf};
use std::process::Command;

use jmapsmtp::config::{Config, DynamicDomains};
use jmapsmtp::startup::cleanup_orphaned_data;

/// The oracle, or a skip. `just test` sets `STARTUP_INTEROP=required` so a
/// missing binary is a failure there rather than a quiet pass.
fn oracle() -> Option<PathBuf> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../oracle/jmapsmtp-oracle")
        .canonicalize()
        .ok()
        .filter(|p| p.exists());
    if path.is_none() {
        assert!(
            std::env::var("STARTUP_INTEROP").as_deref() != Ok("required"),
            "STARTUP_INTEROP=required but oracle/jmapsmtp-oracle is missing — run `just oracle`"
        );
        eprintln!("skipping: oracle/jmapsmtp-oracle not built (run `just oracle`)");
    }
    path
}

/// A free TCP port. The oracle binds both an HTTP and an SMTP listener and
/// `log.Fatal`s if either fails, so neither can be left to a default.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Seed one `data/` tree. Returns the temp dir holding `data/`.
fn seed(root: &Path) {
    let data = root.join("data");

    // configured@a.test — in the config, no credential. Kept because configured.
    mkfile(&data.join("a.test/configured/mail.json"), b"m");
    // dynamic@a.test — not configured, but has a credential and no envelope.
    // This is the third-party/DID-only shape: an envelope-keyed sweep eats it.
    mkfile(&data.join("a.test/dynamic/mail.json"), b"m");
    mkfile(&data.join("a.test/dynamic/auth_token_hash"), b"aGFzaA==");
    // enveloped@a.test — an envelope but no credential. The mirror image: if
    // the sweep looked at envelopes it would keep this and drop `dynamic`.
    mkfile(&data.join("a.test/enveloped/mail.json"), b"m");
    mkfile(&data.join("a.test/enveloped/envelope.json"), b"{}");
    // leftover@a.test — neither. Goes.
    mkfile(&data.join("a.test/leftover/mail.json"), b"m");
    // the domain's Autocrypt peer keys, sitting where an account would.
    mkfile(&data.join("a.test/peers/bob@x.test.asc"), b"k");
    // a whole domain nobody configured. Goes, credential or not.
    mkfile(&data.join("gone.test/someone/auth_token_hash"), b"aGFzaA==");
    mkfile(&data.join("gone.test/someone/mail.json"), b"m");
    // the custom-domain registry, and an account on a domain only it knows.
    mkfile(
        &data.join("_domains/byo.test/domain.json"),
        br#"{"dkim_selector":"s"}"#,
    );
    mkfile(&data.join("byo.test/carol/auth_token_hash"), b"aGFzaA==");
    mkfile(&data.join("byo.test/carol/mail.json"), b"m");
}

fn mkfile(path: &Path, contents: &[u8]) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, contents).unwrap();
}

const CONFIG: &str = r#"{
  "listen_addr": "127.0.0.1:%HTTP%",
  "smtp_port": %SMTP%,
  "base_url": "http://127.0.0.1",
  "hostname": "test.invalid",
  "domain": {"a.test": {"account": {"configured": {}}}}
}"#;

/// Every surviving directory under `data/`, relative and sorted.
fn surviving_dirs(data: &Path) -> Vec<String> {
    fn walk(base: &Path, dir: &Path, out: &mut Vec<String>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for e in entries.flatten() {
            if e.path().is_dir() {
                out.push(
                    e.path()
                        .strip_prefix(base)
                        .unwrap()
                        .to_string_lossy()
                        .into_owned(),
                );
                walk(base, &e.path(), out);
            }
        }
    }
    let mut out = Vec::new();
    walk(data, data, &mut out);
    out.sort();
    out
}

/// Run the oracle to the point where its startup sweep has happened, then stop
/// it. Its HTTP listener opening is the signal: that is step 15, the last one.
fn run_oracle_startup(oracle: &Path) -> tempfile::TempDir {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();

    // The oracle resolves its own directory from argv[0], not the working
    // directory, and reads config.json from there. A symlink is enough:
    // filepath.Abs does not resolve one.
    std::os::unix::fs::symlink(oracle, root.join("jmapsmtp-oracle")).unwrap();

    let http_port = free_port();
    let config = CONFIG
        .replace("%HTTP%", &http_port.to_string())
        .replace("%SMTP%", &free_port().to_string());
    std::fs::write(root.join("config.json"), &config).unwrap();
    seed(root);

    let mut child = Command::new(root.join("jmapsmtp-oracle"))
        .current_dir("/")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("the oracle should start");

    // Wait for the HTTP listener, which is the last step of startup.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    let addr = format!("127.0.0.1:{http_port}");
    let mut up = false;
    while std::time::Instant::now() < deadline {
        if std::net::TcpStream::connect(&addr).is_ok() {
            up = true;
            break;
        }
        if let Ok(Some(status)) = child.try_wait() {
            let mut err = String::new();
            use std::io::Read as _;
            let _ = child.stderr.take().unwrap().read_to_string(&mut err);
            panic!("the oracle exited during startup ({status}):\n{err}");
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let _ = child.kill();
    let _ = child.wait();
    assert!(up, "the oracle never opened {addr}");
    tmp
}

#[test]
fn the_orphan_sweep_keeps_exactly_what_the_oracle_keeps() {
    let Some(oracle) = oracle() else { return };

    let go_root = run_oracle_startup(&oracle);
    let go_survivors = surviving_dirs(&go_root.path().join("data"));

    // The same seed, swept by this port. `load` first: the ordering is the
    // contract (SPEC.md §2 steps 5 and 6), and the oracle runs it that way.
    let rust_root = tempfile::tempdir().unwrap();
    seed(rust_root.path());
    let data = rust_root.path().join("data");
    let cfg: Config =
        serde_json::from_str(&CONFIG.replace("%HTTP%", "1").replace("%SMTP%", "1")).unwrap();
    let dynamic_domains = DynamicDomains::default();
    dynamic_domains.load(&data);
    cleanup_orphaned_data(&cfg, &dynamic_domains, &data);
    let rust_survivors = surviving_dirs(&data);

    // The oracle creates directories of its own during startup (DKIM keys,
    // stores, the hub's persist dir). Compare only what the seed put there.
    let seeded: Vec<String> = {
        let fresh = tempfile::tempdir().unwrap();
        seed(fresh.path());
        surviving_dirs(&fresh.path().join("data"))
    };
    let keep =
        |v: Vec<String>| -> Vec<String> { v.into_iter().filter(|d| seeded.contains(d)).collect() };

    let go_survivors = keep(go_survivors);
    assert_eq!(rust_survivors, go_survivors);

    // …and say out loud what that set is, so a change to *both* sides is still
    // visible in the diff.
    assert_eq!(
        go_survivors,
        [
            "_domains",
            "_domains/byo.test",
            "a.test",
            "a.test/configured",
            "a.test/dynamic",
            "a.test/peers",
            "byo.test",
            "byo.test/carol",
        ],
        "enveloped/ and leftover/ swept; gone.test swept whole; \
         byo.test survives only because _domains was loaded first"
    );
}
