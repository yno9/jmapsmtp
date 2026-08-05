//! The differential harness (PLAN.md M1).
//!
//! Runs the same request sequence against two relay instances, normalises out
//! the values that cannot match, and reports every remaining difference —
//! both in the HTTP responses and in the `data/` tree each instance leaves
//! behind.
//!
//! The mode that matters first is `--both-oracle`, which puts the SAME Go
//! binary on both sides. That run must be green before a run against the Rust
//! port means anything: it is what proves the normalisation filters strip
//! only genuine non-determinism. A filter that is too broad makes the port
//! look correct when it is not, and self-check is the only thing standing
//! between us and that.

pub mod compare;
pub mod fixture;
pub mod instance;
pub mod normalize;
pub mod scenario;

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};

use compare::{Capture, Side};
use fixture::Instance;
use instance::{Running, free_port};
use scenario::{Auth, BodyMode, Step};

pub struct Options {
    /// Run the Go oracle on both sides — the self-check described above.
    pub both_oracle: bool,
    /// Print the normalisation filters and exit.
    pub show_filters: bool,
    /// Keep the working directories after the run for inspection.
    pub keep: bool,
    /// Prove the harness can fail — see `self_test`.
    pub self_test: bool,
}

pub fn run(opts: Options) -> Result<()> {
    if opts.show_filters {
        print_filters();
        return Ok(());
    }
    if opts.self_test {
        return self_test();
    }

    let root = workspace_root()?;
    let oracle = root.join("oracle/jmapsmtp-oracle");
    if !oracle.exists() {
        bail!(
            "oracle binary not found at {} — run `just oracle` first",
            oracle.display()
        );
    }

    let (left_bin, right_bin, right_label) = if opts.both_oracle {
        (oracle.clone(), oracle.clone(), "oracle(B)")
    } else {
        let port = root.join("target/debug/jmapsmtp");
        if !port.exists() {
            bail!(
                "port binary not found at {} — run `cargo build` first",
                port.display()
            );
        }
        (oracle.clone(), port, "rust")
    };

    let work = root.join("target/difftest");
    std::fs::create_dir_all(&work)?;

    println!("difftest: oracle(A) vs {right_label}");
    let left = capture_side("oracle(A)", &work.join("a"), &left_bin, None)?;
    let right = capture_side(right_label, &work.join("b"), &right_bin, None)?;

    // A declared difference is only expected when the two sides are different
    // implementations. `--both-oracle` runs the oracle against itself.
    let report = if opts.both_oracle {
        compare::compare_same_implementation(&left, &right)
    } else {
        compare::compare(&left, &right)
    };
    report.print();

    if !opts.keep {
        // Left in place on failure regardless — the directories are the only
        // way to inspect what actually happened.
        if report.is_clean() {
            let _ = std::fs::remove_dir_all(work.join("a"));
            let _ = std::fs::remove_dir_all(work.join("b"));
        } else {
            println!(
                "\nworking directories kept for inspection:\n  {}",
                work.display()
            );
        }
    }

    if report.is_clean() {
        println!(
            "\ndifftest: OK — {} steps, no differences",
            left.steps.len()
        );
        Ok(())
    } else {
        bail!("difftest: {} difference(s)", report.count())
    }
}

/// Prove the harness can fail.
///
/// A green difftest only means something if a red one is reachable. This runs
/// the oracle against itself once per mutation, each perturbing a different
/// comparison axis (a response body, the Session response, the `data/` tree,
/// the auth path), and insists every one is caught. It fails loudly if any
/// mutation slips through — that would mean a filter is masking real
/// behaviour, or a comparison is not wired up at all.
fn self_test() -> Result<()> {
    let root = workspace_root()?;
    let oracle = root.join("oracle/jmapsmtp-oracle");
    if !oracle.exists() {
        bail!(
            "oracle binary not found at {} — run `just oracle` first",
            oracle.display()
        );
    }
    let work = root.join("target/difftest-selftest");
    std::fs::create_dir_all(&work)?;

    println!("difftest --self-test: each mutation must be detected\n");
    let baseline = capture_side("oracle(A)", &work.join("a"), &oracle, None)?;

    let mut undetected = Vec::new();
    for &m in fixture::ALL_MUTATIONS {
        let mutated = capture_side(
            &format!("mutated({m:?})"),
            &work.join("b"),
            &oracle,
            Some(m),
        )?;
        // The self-test mutates the oracle and compares it with itself.
        let report = compare::compare_same_implementation(&baseline, &mutated);
        if report.is_clean() {
            println!("  {m:?}: NOT DETECTED");
            undetected.push(m);
        } else {
            println!("  {m:?}: detected ({} difference(s))", report.count());
        }
    }

    let _ = std::fs::remove_dir_all(&work);
    if undetected.is_empty() {
        println!("\ndifftest --self-test: OK — every mutation was caught");
        Ok(())
    } else {
        bail!(
            "difftest --self-test: {} mutation(s) went undetected: {undetected:?} — \
             the harness is not comparing what it claims to",
            undetected.len()
        )
    }
}

/// Seed, start, replay, snapshot, stop.
fn capture_side(
    label: &str,
    dir: &Path,
    binary: &Path,
    mutation: Option<fixture::Mutation>,
) -> Result<Side> {
    let inst = Instance {
        dir: dir.to_path_buf(),
        http_port: free_port()?,
        smtp_port: free_port()?,
    };
    fixture::seed_mutated(&inst, binary, mutation).context("seeding instance")?;

    let running = Running::start(inst).context("starting instance")?;
    let steps = replay(&running).context("replaying scenario")?;
    let data = compare::snapshot_data(&running.inst.data_dir()).context("snapshotting data/")?;
    let log = normalize::normalize(&running.log());
    let dir = running.inst.dir.clone();
    drop(running);

    let side = Side {
        label: label.to_string(),
        steps,
        data,
        log,
    };
    side.write_transcript(&dir.join("transcript.txt"))?;
    Ok(side)
}

fn replay(running: &Running) -> Result<Vec<Capture>> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        // The relay answers 3xx nowhere today; following one would hide it.
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let base = running.inst.base_url();
    let password = fixture::basic_auth_password();

    let mut out = Vec::new();
    for step in scenario::steps() {
        out.push(execute(&client, &base, &password, &step)?);
    }
    Ok(out)
}

fn execute(
    client: &reqwest::blocking::Client,
    base: &str,
    password: &str,
    step: &Step,
) -> Result<Capture> {
    let url = format!("{base}{}", step.path);
    let method = reqwest::Method::from_bytes(step.method.as_bytes())?;
    let mut req = client.request(method, &url);
    if step.auth == Auth::Basic {
        req = req.basic_auth(fixture::ACCOUNT, Some(password));
    }
    if let Some(body) = &step.body {
        req = req.header("Content-Type", "application/json").json(body);
    }

    let resp = req
        .send()
        .with_context(|| format!("step {}: {} {}", step.name, step.method, step.path))?;

    let status = resp.status().as_u16();
    let mut headers: Vec<(String, String)> = normalize::COMPARED_HEADERS
        .iter()
        .filter_map(|name| {
            resp.headers()
                .get(*name)
                .and_then(|v| v.to_str().ok())
                .map(|v| ((*name).to_string(), v.to_string()))
        })
        .collect();
    headers.sort();

    let raw = resp.text()?;
    let body = match step.body_mode {
        BodyMode::Full => normalize::pretty_if_json(&normalize::normalize(&raw)),
        BodyMode::MetricNames => normalize::metric_names(&raw),
    };

    Ok(Capture {
        divergence: step.divergence,
        name: step.name.to_string(),
        request: format!("{} {}", step.method, step.path),
        status,
        headers,
        body,
    })
}

fn print_filters() {
    println!(
        "Normalisation filters — the complete list of what the two \
         implementations\nare allowed to disagree about. Everything else must \
         match byte for byte.\n"
    );
    for f in normalize::FILTERS.iter() {
        println!("  {}", f.name);
        for line in textwrap(f.why, 72) {
            println!("      {line}");
        }
        println!();
    }
    println!("Compared response headers (all others dropped):");
    for h in normalize::COMPARED_HEADERS {
        println!("  {h}");
    }
}

fn textwrap(s: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut cur = String::new();
    for word in s.split_whitespace() {
        if !cur.is_empty() && cur.len() + 1 + word.len() > width {
            lines.push(std::mem::take(&mut cur));
        }
        if !cur.is_empty() {
            cur.push(' ');
        }
        cur.push_str(word);
    }
    if !cur.is_empty() {
        lines.push(cur);
    }
    lines
}

/// The workspace root, found by walking up from this crate's manifest.
fn workspace_root() -> Result<PathBuf> {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .map(Path::to_path_buf)
        .context("xtask has no parent directory")
}
