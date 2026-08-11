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
            noanchor: has(flags, "--noanchor"),
        }),
        "bench" => bench::run(bench::Options {
            iterations: value(flags, "--iterations").unwrap_or(200),
            messages: value(flags, "--messages").unwrap_or(1000),
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
      --noanchor       Compare the noanchor builds: `go build -tags noanchor`
                       against `cargo build --no-default-features`.
      --self-test      Prove the harness can fail: run the oracle against a
                       deliberately mutated copy of itself and require every
                       mutation to be caught.
      --show-filters   Print the normalisation filters and exit.
      --keep           Keep the working directories even on success.

  bench [--iterations N] [--messages N]

      Time the Go oracle and this port over the same requests and report
      both. Needs `cargo build --release`; refuses to bench a debug build.
"
    );
}
