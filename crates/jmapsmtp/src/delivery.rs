//! Inbound delivery: the SMTP backend that turns a received message into a
//! stored one, and the listener that feeds it.
//!
//! # Unknown recipients are accepted and dropped
//!
//! `accepts` decides whether an address is served here, and a `false` still
//! answers `250`. Rejecting at `RCPT` would turn port 25 into an oracle
//! telling anyone who can reach it which addresses exist — see `smtp_in`'s
//! header. The message is taken and discarded instead.

use std::sync::Arc;

use crate::server::RelayState;

/// The relay's SMTP backend.
pub struct Delivery {
    pub state: Arc<RelayState>,
}

impl crate::smtp_in::Backend for Delivery {
    fn accepts(&self, rcpt: &str) -> bool {
        self.state.accounts.resolve(rcpt).is_some()
    }

    fn deliver(&self, from: &str, rcpts: &[String], raw: &[u8]) {
        for rcpt in rcpts {
            let Some(account) = self.state.accounts.resolve(rcpt) else {
                // Survived `accepts` and then vanished — the account was
                // deleted between the two. Dropping is the only option left;
                // the sender was already told 250.
                continue;
            };
            match self.store_message(&account, from, raw) {
                Ok(()) => self.log_activity(&account, from, raw.len(), true),
                Err(e) => {
                    eprintln!("[smtp] delivery to {} failed: {e}", account.email);
                    self.log_activity(&account, from, raw.len(), false);
                }
            }
        }
        // One wake-up for the batch: the event carries no payload, so a
        // client woken once fetches everything that arrived.
        self.state.hub.notify();

        // …and one push per account that received something, for clients that
        // are not holding an event-source stream open. Spawned because the
        // push services are remote and a slow one must not hold the SMTP
        // session open — the sender is waiting on that.
        let mut pushed: Vec<String> = Vec::new();
        for rcpt in rcpts {
            if let Some(account) = self.state.accounts.resolve(rcpt)
                && !pushed.contains(&account.email)
            {
                pushed.push(account.email.clone());
                let state = self.state.clone();
                let id = jmap_types::Id::from(account.email.as_str());
                tokio::spawn(async move {
                    crate::webpush::notify(&state, &id).await;
                });
            }
        }
    }
}

impl Delivery {
    fn store_message(
        &self,
        account: &crate::handler::AccountStore,
        from: &str,
        raw: &[u8],
    ) -> std::io::Result<()> {
        // The storage cap is checked on the way in as well as on the way out:
        // either direction can be what fills the disk.
        if let Err(e) = crate::hooks::within_storage_cap(&self.state.cfg, &account.dir) {
            return Err(std::io::Error::other(e));
        }

        let received_at = jmap_types::JmapTime::now_utc();
        // A message that will not parse is dropped rather than stored empty:
        // an entry with no headers and no body is worse than an absence,
        // because it looks like mail arrived.
        let Some(mut message) = jmapserver::parse_mime_email(raw, received_at.as_str()) else {
            return Err(std::io::Error::other("unparseable message"));
        };
        // The id is derived from the RFC Message-ID where there is one, so a
        // redelivery — a retry, or a second MX — overwrites rather than
        // duplicating.
        let rfc_id = message.message_id.first().cloned().unwrap_or_default();
        message.id = jmap_types::Id::from(
            crate::handler::make_message_id(&rfc_id, &account.email, now_millis()).as_str(),
        );
        message.received_at = Some(received_at);
        let _ = from;

        account.store.put(message)
    }

    fn log_activity(
        &self,
        account: &crate::handler::AccountStore,
        from: &str,
        bytes: usize,
        ok: bool,
    ) {
        // Best-effort: an audit line that cannot be written must not undo a
        // delivery that already happened.
        let _ = jmapserver::activity::append_activity(
            &self.state.data_dir,
            &account.domain,
            &account.localpart,
            &jmapserver::activity::ActivityEvent {
                dir: "in".into(),
                kind: "email".into(),
                peer: from.to_string(),
                bytes: bytes as i64,
                result: crate::handler::activity_result(ok).into(),
                ..Default::default()
            },
        );
    }
}

fn now_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Accept SMTP connections until the listener fails.
///
/// A failed session is logged and the connection dropped; one bad peer does
/// not stop the listener. A failure to *accept*, though, is fatal — the relay
/// is no longer receiving mail and looking healthy would be worse than exiting.
pub async fn serve_smtp(
    listener: tokio::net::TcpListener,
    state: Arc<RelayState>,
) -> std::io::Result<()> {
    // Built once: the certificate is re-read per handshake by the reloader
    // inside it, but the TLS configuration itself does not change.
    let tls = crate::inbound_tls::server_config(&state.cfg, &state.data_dir);
    match &tls {
        Some(_) => println!("[smtp] STARTTLS enabled"),
        None => println!("[smtp] STARTTLS disabled (no certificate)"),
    }

    loop {
        let (stream, peer) = listener.accept().await?;
        let state = state.clone();
        let tls = tls.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_session(stream, state, tls).await {
                eprintln!("[smtp] session from {peer} ended: {e}");
            }
        });
    }
}

/// One session, upgrading to TLS if the client asks and a certificate exists.
async fn serve_session(
    mut stream: tokio::net::TcpStream,
    state: Arc<RelayState>,
    tls: Option<Arc<rustls::ServerConfig>>,
) -> std::io::Result<()> {
    let cfg = crate::smtp_in::Config {
        hostname: state.cfg.hostname.clone(),
        starttls: true,
        tls_available: tls.is_some(),
        enable_smtputf8: true,
    };
    let backend = Delivery { state };

    if crate::smtp_in::handle(&mut stream, &cfg, &backend).await?
        != crate::smtp_in::Outcome::StartTls
    {
        return Ok(());
    }
    let Some(tls) = tls else {
        return Ok(());
    };

    let mut upgraded = tokio_rustls::TlsAcceptor::from(tls).accept(stream).await?;
    // STARTTLS is **not** advertised again: RFC 3207 §4.2 forbids it, and a
    // client that saw it a second time would have no way to tell whether the
    // first upgrade took.
    let cfg = crate::smtp_in::Config {
        starttls: false,
        tls_available: false,
        ..cfg
    };
    crate::smtp_in::handle(&mut upgraded, &cfg, &backend).await?;
    Ok(())
}

/// Run the inactive-account sweep on its schedule.
///
/// Returns immediately when purging is disabled, so a relay without the
/// setting has no timer at all rather than one that wakes to do nothing.
pub fn spawn_maintenance(state: Arc<RelayState>) {
    if state.cfg.inactive_purge_days == 0 {
        return;
    }
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(
            crate::maintenance::SWEEP_INTERVAL_SECS,
        ));
        // The first tick is immediate; skip it so a restart loop cannot purge
        // repeatedly, and so an operator gets one interval to notice a
        // misconfiguration.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            purge_inactive(&state);
        }
    });
}

/// One sweep. Public so it can be driven directly rather than only on a timer.
pub fn purge_inactive(state: &RelayState) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    for (domain, localpart) in
        crate::maintenance::accounts_to_purge(&state.cfg, &state.data_dir, now)
    {
        let email = format!("{localpart}@{domain}");
        println!("[maintenance] purging inactive account {email}");
        // Routing first: an account whose data is gone but whose aliases still
        // resolve would take delivery into a store nobody can reach.
        state.accounts.remove(&email);
        state.dyn_accounts.remove(&email);
        if let Err(e) = std::fs::remove_dir_all(state.data_dir.join(&domain).join(&localpart)) {
            eprintln!("[maintenance] failed to remove {email}: {e}");
        }
    }
}

#[cfg(test)]
mod tests;
