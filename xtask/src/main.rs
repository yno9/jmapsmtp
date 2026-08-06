//! Development tasks.
//!
//! The important one is the differential harness (PLAN.md M1): boot two relay
//! instances against identical config and data, replay the same request
//! sequence into both, then compare status, headers, body and the resulting
//! `data/` tree after normalising away the values that cannot match.
//!
//! `difftest --both-oracle` puts the Go binary on both sides. That run has to
//! be green before a run against the Rust port proves anything — it is what
//! establishes that the filters strip only genuine non-determinism.

mod bench;
mod bindprobe;
mod difftest;

use anyhow::{Result, bail};

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (task, flags) = match args.split_first() {
        Some((t, rest)) => (t.as_str(), rest),
        None => ("help", &[] as &[String]),
    };

    match task {
        "difftest" => difftest::run(difftest::Options {
            both_oracle: has(flags, "--both-oracle"),
            show_filters: has(flags, "--show-filters"),
            keep: has(flags, "--keep"),
            self_test: has(flags, "--self-test"),
        }),
        "bench" => bench::run(bench::Options {
            iterations: value(flags, "--iterations").unwrap_or(200),
            messages: value(flags, "--messages").unwrap_or(1000),
        }),
        "bind-probe" => bindprobe::run(bindprobe::Options {
            relay: text(flags, "--relay").unwrap_or_else(|| "http://127.0.0.1:8767".into()),
            account: text(flags, "--account").unwrap_or_default(),
            token: text(flags, "--token").unwrap_or_default(),
            skew: text(flags, "--skew")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0),
        }),
        "help" | "--help" | "-h" => {
            help();
            Ok(())
        }
        other => {
            help();
            bail!("unknown task: {other}")
        }
    }
}

fn has(flags: &[String], name: &str) -> bool {
    flags.iter().any(|f| f == name)
}

/// `--name=value` or `--name value`, as a string.
fn text(flags: &[String], name: &str) -> Option<String> {
    let prefix = format!("{name}=");
    for (i, f) in flags.iter().enumerate() {
        if let Some(v) = f.strip_prefix(&prefix) {
            return Some(v.to_string());
        }
        if f == name {
            return flags.get(i + 1).cloned();
        }
    }
    None
}

/// `--name=value` or `--name value`.
fn value(flags: &[String], name: &str) -> Option<usize> {
    let prefix = format!("{name}=");
    for (i, f) in flags.iter().enumerate() {
        if let Some(v) = f.strip_prefix(&prefix) {
            return v.parse().ok();
        }
        if f == name {
            return flags.get(i + 1).and_then(|v| v.parse().ok());
        }
    }
    None
}

fn help() {
    eprintln!(
        "\
xtask — development tasks

  difftest [--both-oracle] [--self-test] [--show-filters] [--keep]

      Replay one request sequence against two relay instances and report
      every difference.

      --both-oracle    Run the Go oracle on BOTH sides. Must pass before a
                       run against the Rust port means anything.
      --self-test      Prove the harness can fail: run the oracle against a
                       deliberately mutated copy of itself and require every
                       mutation to be caught.
      --show-filters   Print the normalisation filters and exit.
      --keep           Keep the working directories even on success.

  bench [--iterations N] [--messages N]

  bind-probe --relay URL --account a@b --token TOKEN [--skew SECONDS]

      Sign a DID binding the way biset does and present it to a running
      relay. Proves the identity path end to end: client, relay and anchor.

      Time the Go oracle and this port over the same requests and report
      both. Needs `cargo build --release`; refuses to bench a debug build.
"
    );
}
