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

use std::path::Path;

use jmapsmtp::config::{Config, DynamicDomains};
use jmapsmtp::startup::cleanup_orphaned_data;

mod oracle_harness;
use oracle_harness::Oracle;

fn config_json(http_port: u16, smtp_port: u16) -> String {
    format!(
        r#"{{"listen_addr":"127.0.0.1:{http_port}","smtp_port":{smtp_port},
            "base_url":"http://127.0.0.1","hostname":"test.invalid",
            "domain":{{"a.test":{{"account":{{"configured":{{}}}}}}}}}}"#
    )
}

/// Seed one `data/` tree. Every entry is a case the sweep has to decide.
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

#[test]
fn the_orphan_sweep_keeps_exactly_what_the_oracle_keeps() {
    // Starting the oracle runs its startup, and step 6 of that is the sweep.
    let Some(o) = Oracle::start_with("STARTUP_INTEROP", config_json, seed) else {
        return;
    };
    let go_survivors = surviving_dirs(&o.data_dir());

    // The same seed, swept by this port. `load` first: the ordering is the
    // contract (SPEC.md §2 steps 5 and 6), and the oracle runs it that way.
    let rust_root = tempfile::tempdir().unwrap();
    seed(rust_root.path());
    let data = rust_root.path().join("data");
    let cfg: Config = serde_json::from_str(&config_json(1, 1)).unwrap();
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
