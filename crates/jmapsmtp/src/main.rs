//! Entry point. Everything of substance lives in the library.
//!
//! The order below is the contract, not a preference — SPEC.md §2 names the
//! pairs that must not be swapped and why. Each is repeated at the call site.

use std::process::ExitCode;

use jmapsmtp::config::Config;
use jmapsmtp::server::RelayState;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

#[tokio::main]
async fn run() -> Result<(), String> {
    // 1. The directory is resolved from argv[0], **not** the working
    //    directory: the relay is started by a service manager whose cwd is
    //    unrelated, and config.json lives beside the binary.
    let dir = std::env::current_exe()
        .map_err(|e| format!("dir: {e}"))?
        .parent()
        .ok_or("dir: the executable has no parent")?
        .to_path_buf();
    let data_dir = dir.join("data");

    // 2-3. Parse and validate. `validate` refuses a config with no domains,
    //      and an anchor_url with no anchor_token — the latter fatally,
    //      because an unauthenticated anchor write lets anyone take a name.
    let cfg = Config::load(&dir.join("config.json")).map_err(|e| e.to_string())?;

    // 4. The relay-wide PGP key, from the environment.
    let state = RelayState::new(cfg, data_dir.clone());

    // The live DNS client, for MX routing and custom-domain proofs.
    let mut state = state;
    state.with_dns();

    // 5. The dynamic domain registry — **before** the sweep below. A custom
    //    domain verified in an earlier run exists only in data/_domains/, so
    //    sweeping first deletes the mail of every account on it.
    state.dynamic_domains.load(&data_dir);

    // 6. Remove data that no longer corresponds to anything configured.
    for removed in
        jmapsmtp::startup::cleanup_orphaned_data(&state.cfg, &state.dynamic_domains, &data_dir)
    {
        println!("cleanup: removed {removed}");
    }

    // 7. DKIM keys: load-or-create per domain, and never rotate an existing
    //    one — it is already published in DNS.
    for domain in state.cfg.domains.keys() {
        let domain_dir = data_dir.join(domain);
        if let Err(e) = std::fs::create_dir_all(&domain_dir) {
            return Err(format!("dkim {domain}: {e}"));
        }
        match jmapsmtp::dkim::load_or_generate_key(&domain_dir) {
            Ok(key) => {
                let selector = state.cfg.domains[domain].selector();
                let _ = jmapsmtp::dkim::write_record_file(&domain_dir, selector, domain, &key);
            }
            Err(e) => return Err(format!("dkim {domain}: {e}")),
        }
    }

    // 10. A setup token for every configured account that has no envelope. An
    //     existing token is reused, so a restart mid-onboarding does not
    //     invalidate the link the operator already sent.
    for invite in jmapsmtp::startup::issue_setup_tokens(&state.cfg, &data_dir) {
        println!(
            "[setup] {}@{}: {}",
            invite.localpart,
            invite.domain,
            invite.url(&state.cfg.base_url)
        );
    }

    // 11. A Store per configured account, plus the alias map. Fatal on
    //     failure: a relay that starts while silently dropping one account's
    //     mail looks healthy and is not.
    state.open_stores()?;

    // 12. Recover accounts created in previous runs. Same existence rule as
    //     the sweep: an auth_token_hash, never an envelope.
    jmapsmtp::startup::scan_dyn_accounts(
        &state.cfg,
        &state.dynamic_domains,
        &state.dyn_accounts,
        &data_dir,
    );

    // 15. Serve. The route table is built in `RelayState::new` and panics on a
    //     duplicate pattern, so a conflict stops the process here rather than
    //     after a deploy.
    let addr = state.cfg.listen_addr().to_string();
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .map_err(|e| format!("listen {addr}: {e}"))?;
    println!("jmapsmtp: jmap listening on {addr}");

    axum::serve(listener, jmapsmtp::server::app(state))
        .await
        .map_err(|e| format!("serve: {e}"))
}

/// Steps 8, 9, 11, 13 and 14 of SPEC.md §2 — the handler, the auth function,
/// the per-account stores and alias map, periodic maintenance and the SMTP
/// listener — are not wired yet. Their modules exist and are tested; what is
/// missing is the assembly.
///
/// Named here rather than left as an absence so the gap is visible from the
/// entry point.
#[allow(dead_code)]
const NOT_YET_WIRED: &[&str] = &[
    "the JMAP handler and per-account stores (step 8, 11)",
    "periodic maintenance (step 13)",
    "the SMTP listener (step 14)",
];
