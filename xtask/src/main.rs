//! Development tasks.
//!
//! The important one is the differential harness (PLAN.md M1): boot the Go
//! oracle and this port against identical config and data, replay the same
//! request sequence into both, then compare status, headers, body and the
//! resulting `data/` tree after passing everything through the normalisation
//! filters that strip non-determinism (random ids, timestamps, PGP session
//! keys, Go map iteration order).
//!
//! The harness must go green with the ORACLE ON BOTH SIDES before it is worth
//! pointing at Rust — that is what proves the filters strip only genuine
//! non-determinism and nothing else.

fn main() {
    eprintln!("xtask: no tasks implemented yet (see PLAN.md M1)");
}
