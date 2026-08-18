//! Entry point. Everything of substance lives in the library.
//!
//! The order below is the contract, not a preference — SPEC.md §2 names the
//! pairs that must not be swapped and why. Each is repeated at the call site.

use std::process::ExitCode;

use jmapsmtp::config::Config;
use jmapsmtp::server::RelayState;

/// Send `tracing` output somewhere.
///
/// Without this every `tracing::info!`/`warn!`/`error!` in the crate is
/// dropped on the floor, and there were fourteen of them — including the whole
/// outbound SMTP story: which host was dialled, whether STARTTLS was refused,
/// which recipient the far end rejected, whether the message was finally sent.
/// The only lines that reached the journal were the handful written with
/// `eprintln!`, which is why the log looked like it recorded failures and
/// nothing else. Diagnosing a delivery problem meant reading the parts of the
/// story that happened to be shouted.
///
/// `tracing-subscriber` was already a dependency, with `env-filter` enabled.
/// The intent was recorded and the four lines were never written.
///
/// `RUST_LOG` overrides; the default is `info`, which is where the delivery
/// lines live. Not `debug`: that turns on rustls and hyper internals and
/// buries them.
fn init_logging() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        // Colour only for a terminal. Under a service manager the escapes are
        // written literally into the journal, so `journalctl` shows
        // "\x1b[32m INFO\x1b[0m" on every line.
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stdout()))
        // The service manager stamps its own timestamps; a second one in the
        // message is noise in `journalctl`.
        .without_time()
        .with_target(false)
        .init();
}

fn main() -> ExitCode {
    init_logging();
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

    // 8. Push subscriptions persist alongside the account data, so a restart
    //    does not silently stop notifying every client.
    state.load_push_subscriptions();

    // 11. A Store per configured account, plus the alias map. Fatal on
    //     failure: a relay that starts while silently dropping one account's
    //     mail looks healthy and is not.
    state.open_stores()?;

    // 12. Recover accounts created in previous runs. Same existence rule as
    //     the sweep: an auth_token_hash, never an envelope.
    jmapsmtp::startup::scan_dyn_accounts(
        &state.cfg,
        &state.dynamic_domains,
        &data_dir,
        |localpart, domain| state.register_dyn_account(localpart, domain),
    );

    // 13. Periodic upkeep. Returns without starting a timer when
    //     `inactive_purge_days` is unset, so a relay without the setting has
    //     no sweep at all rather than one that wakes to do nothing.
    jmapsmtp::delivery::spawn_maintenance(state.clone());

    // 13b. Alias reconciliation against each SCID-primary account's bound
    //      DID (PLANSCID.md's backstop for edit-identity.ts's eager
    //      add/remove-on-rename). Returns without starting a timer when no
    //      anchor is configured, same "no setting, no timer" shape as
    //      maintenance above. Anchor build only — same gate as the module
    //      itself, nothing to reconcile against without one.
    #[cfg(feature = "anchor")]
    jmapsmtp::did::alias_reconcile::spawn_alias_reconcile(state.clone());

    // 14. SMTP, before the HTTP listener: a relay that accepts JMAP but not
    //     mail is worse than one that is not up yet, because monitoring reads
    //     it as healthy.
    let smtp_port = state.cfg.smtp_port();
    let smtp = tokio::net::TcpListener::bind(("0.0.0.0", smtp_port))
        .await
        .map_err(|e| format!("smtp listen :{smtp_port}: {e}"))?;
    {
        let state = state.clone();
        tokio::spawn(async move {
            // The STARTTLS line comes first, then the bound address — the
            // order an operator reads them in, and the Go original's. Both are
            // logged by `serve_smtp`, which is the only place that knows the
            // first of them.
            if let Err(e) = jmapsmtp::delivery::serve_smtp(smtp, state).await {
                // Fatal for the relay: it is no longer receiving mail, and
                // looking healthy would be worse than exiting.
                eprintln!("smtp: {e}");
                std::process::exit(1);
            }
        });
    }

    // 13b. The outbound queue. Whatever was waiting when the process stopped
    //      is on disk and gets picked up here — that is the whole reason the
    //      queue is a directory rather than a `Vec`.
    {
        let waiting = jmapsmtp::queue::load_all(&data_dir).len();
        if waiting > 0 {
            tracing::info!("[queue] {waiting} message(s) waiting from a previous run");
        }
        jmapsmtp::queue::spawn_retries(state.clone()).await;
    }

    // 14b. Does DNS publish the keys we sign with? A lookup per domain, in the
    //      background: it needs the network, and step 14's ordering contract
    //      is about binding, not about diagnostics. Never fatal — a bad
    //      signature is a deliverability problem, and refusing to start would
    //      make it an outage.
    {
        let state = state.clone();
        tokio::spawn(async move {
            let domains: Vec<String> = state.cfg.domains.keys().cloned().collect();
            for domain in domains {
                let dir = state.data_dir.join(&domain);
                let Ok(key) = jmapsmtp::dkim::load_or_generate_key(&dir) else {
                    continue;
                };
                let selector = state.cfg.domains[&domain].selector().to_string();
                let expected = jmapsmtp::dkim::public_key_record(&key);
                let txt = state.txt.clone();
                // The resolver drives its lookups on a runtime handle from
                // synchronous code, so it must not run on this thread.
                let _ = tokio::task::spawn_blocking(move || {
                    jmapsmtp::dkim_dns::check_domain(txt.as_ref(), &selector, &domain, &expected)
                })
                .await;
            }
        });
    }

    // 15. Serve. The route table is built in `RelayState::new` and panics on a
    //     duplicate pattern, so a conflict stops the process here rather than
    //     after a deploy.
    let addr = state.cfg.listen_addr().to_string();
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .map_err(|e| format!("listen {addr}: {e}"))?;
    tracing::info!("jmapsmtp: jmap listening on {addr}");

    axum::serve(listener, jmapsmtp::server::app(state))
        .await
        .map_err(|e| format!("serve: {e}"))
}

/// Sending Web Push needs the subscription registry loaded, which step 8 does.
/// Nothing else in SPEC.md §2 is missing.
///
/// What remains is M8: end-to-end verification against a live deployment, the
/// documentation, and benchmarks.
const _: () = ();
