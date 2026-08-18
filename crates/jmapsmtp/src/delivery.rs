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
        // …and so is one that *parses* into nothing, which is the case the
        // sentence above described and the code did not check. See
        // `carries_nothing`.
        if carries_nothing(&message) {
            return Err(std::io::Error::other("message carries nothing"));
        }
        // The id is derived from the RFC Message-ID where there is one, so a
        // redelivery — a retry, or a second MX — overwrites rather than
        // duplicating.
        let rfc_id = message.message_id.first().cloned().unwrap_or_default();
        message.id = jmap_types::Id::from(
            crate::handler::make_message_id(&rfc_id, &account.email, now_millis()).as_str(),
        );
        message.received_at = Some(received_at);
        // **Filed into the account's inbox.** A message with no `mailboxIds`
        // is in no mailbox, and a client that lists a mailbox never sees it:
        // it is stored, `Email/get` returns it by id, and the inbox is empty.
        // Go sets this at the same point it sets the id and the receive time
        // (`main.go`'s `e.MailboxIDs = {makeMailboxID(primary): true}`); this
        // port set the other two and not this one, so every delivered message
        // was invisible to biset.
        //
        // The ACTUAL current Inbox mailbox's own id, not a fresh
        // `make_mailbox_id(&account.email)` — those only agree the moment an
        // account is provisioned. A SCID migration (PLANSCID.md) renames the
        // account's own login address but never rewrites the Inbox mailbox
        // record already sitting in mailboxes.json (its id/name were derived
        // from the OLD address at creation time and never revisited) — so
        // mail delivered before a migration and mail delivered after it were
        // landing in two DIFFERENT mailbox ids, invisible to each other from
        // the client's own per-mailbox grouping (found live, 2026-08-18: one
        // DeltaChat contact's conversation split into two separate inbox
        // rows the moment their identity migrated). Falling back to the
        // freshly-derived id only when no Inbox is on record at all yet — a
        // genuinely fresh account, where the two still agree.
        let inbox_id = account
            .store
            .mailboxes()
            .into_iter()
            .find(|m| m.role.as_str() == jmap_types::mailbox::Role::INBOX)
            .map(|m| m.id)
            .unwrap_or_else(|| jmap_types::Id::from(crate::handler::make_mailbox_id(&account.email).as_str()));
        message.mailbox_ids = std::collections::BTreeMap::from([(inbox_id, true)]);
        let _ = from;

        seal_inbound(&mut message, &account.email, &account.dir, raw);

        account.store.put(message)
    }

    /// Store a message the relay itself produced — a delivery-failure notice —
    /// into a local mailbox.
    ///
    /// The same path an arriving message takes, so the notice is filed,
    /// sealed and logged like any other. `from` is a label for the activity
    /// log, not an envelope: nothing is being sent.
    pub fn deliver_local(&self, account: &crate::handler::AccountStore, from: &str, raw: &[u8]) {
        match self.store_message(account, from, raw) {
            Ok(()) => self.log_activity(account, from, raw.len(), true),
            Err(e) => {
                tracing::warn!(
                    "[queue] could not file a failure notice for {}: {e}",
                    account.email
                );
                self.log_activity(account, from, raw.len(), false);
            }
        }
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

/// Whether a parsed message carries nothing a person could read or reply to.
///
/// `parse_mime_email` answers `Some` for input that is not a message at all:
/// six bytes with no headers parse into an `Email` with no addresses, no
/// subject, no Message-ID, and a body part whose value is absent. Filing that
/// puts a row in the inbox that renders as nothing, cannot be opened, and
/// therefore **can never be marked read** — the account's unread count stops
/// at that number for ever.
///
/// Found that way: four probes I sent into port 25 while debugging delivery on
/// 2026-08-10 (six and twelve bytes) left four such rows, and the user's unread
/// counter sat at 4 with nothing to click. `store_message`'s own comment
/// already said an entry with no headers and no body is worse than an absence;
/// only the `None` half of it was implemented.
///
/// Deliberately conservative — every clause must hold. A message from a broken
/// sender with no `From` still has a body, and one with an empty body still
/// has headers; either is real mail and is kept. Only something with no trace
/// of a sender, a recipient, a subject, an id *and* no body text is refused.
pub fn carries_nothing(m: &jmap_types::email::Email) -> bool {
    let no_correspondent =
        m.from.is_empty() && m.sender.is_empty() && m.to.is_empty() && m.cc.is_empty();
    let no_body = m.body_values.values().all(|v| v.value.trim().is_empty());
    no_correspondent && m.subject.trim().is_empty() && m.message_id.is_empty() && no_body
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
        Some(_) => tracing::info!("[smtp] STARTTLS enabled"),
        None => tracing::info!("[smtp] STARTTLS disabled (no certificate)"),
    }
    // After the STARTTLS line, and from this task rather than the one that
    // spawned it — Go prints the pair in this order from inside its SMTP
    // goroutine, and `difftest` compares the startup log line for line.
    // Printing it before the spawn put the two lines the other way round.
    match listener.local_addr() {
        Ok(addr) => tracing::info!("[smtp] listening on :{}", addr.port()),
        Err(e) => tracing::warn!("[smtp] listening, but the address is unknown: {e}"),
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
    // No second banner — see `smtp_in::Greeting`.
    crate::smtp_in::handle_upgraded(&mut upgraded, &cfg, &backend).await?;
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

/// Encrypt a delivered message's body to the recipient's own key.
///
/// Port of the block in Go's inbound path (`main.go`, right after the id,
/// mailbox and receive time are set). **This port had no such path at all**:
/// `seal_stored_body` existed and was reachable only from `submit.rs`, so mail
/// this relay *sent* was sealed and mail it *received* sat on disk in the
/// clear. That is a confidentiality difference, not a display one, and it was
/// recorded in SPEC.md §11.23 rather than fixed for longer than it should have
/// been.
///
/// The order is Go's and it matters:
///
/// 1. A body that is **already PGP** is left exactly as it is and marked
///    `$e2e`. Re-encrypting it would wrap ciphertext the recipient can already
///    read in a second layer, and the keyword is how the client knows not to
///    offer to decrypt it twice.
/// 2. Otherwise, if the account has a public key on file, the body is sealed
///    to it. Attachments are folded into a `multipart/mixed` first, because
///    `parse_mime_email` has already reduced the message to its text body and
///    sealing that alone would drop every attachment.
/// 3. With no key on file, the message is stored in the clear. Refusing to
///    deliver would be worse, and uploading a key is what turns this on.
///
/// The relay cannot undo any of this: it holds the public key only.
pub fn seal_inbound(
    message: &mut jmap_types::email::Email,
    email: &str,
    dir: &std::path::Path,
    raw: &[u8],
) {
    let body = jmapserver::message_body(message);
    if body.is_empty() {
        return;
    }

    if body.contains("-----BEGIN PGP MESSAGE-----") {
        // The sender already encrypted it end to end. Say so and stop.
        message.keywords.insert("$e2e".to_string(), true);
        return;
    }

    let Some(key) = crate::pgp::load_account_key(dir) else {
        return;
    };

    // Attachments survive only if they are inside the plaintext: the parsed
    // message no longer carries them, and the sealed body replaces the text.
    let attachments = jmapserver::extract_attachments(raw);
    let plaintext = if attachments.is_empty() {
        body
    } else {
        crate::pgp::build_encrypted_multipart(
            &body,
            &attachments,
            &crate::pgp::multipart_boundary(),
        )
    };

    match crate::pgp::encrypt_inline(plaintext.as_bytes(), std::slice::from_ref(&key)) {
        Ok(ciphertext) => {
            crate::hooks::seal_stored_body(message, &String::from_utf8_lossy(&ciphertext));
        }
        // Storing the plaintext is what Go does when encryption fails, and the
        // alternative — dropping the mail — loses it outright. Logged, because
        // an account that believes its mail is sealed should not find out
        // silently that it is not.
        Err(e) => tracing::warn!("[pgp] could not seal inbound mail for {email}: {e}"),
    }
}
