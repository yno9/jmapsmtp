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
"
    );
}
