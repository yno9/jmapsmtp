//! When to try again, and when to stop.
//!
//! Kept apart from the storage and the loop because these two decisions are
//! the whole behaviour: everything else is files and a timer. A schedule that
//! is wrong loses mail or hammers a stranger's server, and neither shows up in
//! a test that needs a disk and a clock.

use std::time::Duration;

use crate::smtp_out::SendError;

/// Whether a failure is worth trying again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Temporality {
    /// The far end may succeed later: a 4xx, a refused connection, DNS that
    /// did not answer.
    Temporary,
    /// The far end has decided: a 5xx. Trying again produces the same answer
    /// and delays telling the sender.
    Permanent,
}

/// Read the SMTP reply code at the start of a reply line.
fn reply_code(reply: &str) -> Option<u16> {
    reply.trim_start().get(..3)?.parse().ok()
}

/// Classify a failed send.
///
/// The rule is SMTP's own: 4xx means "not now", 5xx means "no". Anything that
/// never got an answer — a dial that failed, a socket that died, a TLS
/// handshake that broke — is temporary, because a network that was down is the
/// commonest reason to be here and it is usually back later.
///
/// **Greylisting is the case that matters.** A greylisting receiver refuses
/// the first attempt from an unknown sender with a 4xx and accepts a retry
/// minutes later. It is standard practice at a large fraction of mail
/// servers. Without a queue, every greylisted message is simply lost, and the
/// sender is told the address does not work.
pub fn classify(e: &SendError) -> Temporality {
    match e {
        // No answer at all.
        SendError::Dial(..) | SendError::Io(_) | SendError::NoMx(_) => Temporality::Temporary,
        // The message could never be sent as written; a retry changes nothing.
        SendError::NoRecipients | SendError::InvalidRecipient(_) => Temporality::Permanent,
        SendError::Rejected { reply, .. } => match reply_code(reply) {
            Some(c) if (400..500).contains(&c) => Temporality::Temporary,
            Some(c) if (500..600).contains(&c) => Temporality::Permanent,
            // A reply we cannot read a code from is not a refusal we can
            // stand behind. Treat it as temporary: the cost of one more
            // attempt is small, and the cost of discarding a message on a
            // misparse is the message.
            _ => Temporality::Temporary,
        },
    }
}

/// How long to wait before attempt number `attempts_so_far + 1`.
///
/// `None` means stop. The schedule is short at first, because greylisting
/// clears in minutes, and then widens so a receiver that is genuinely down is
/// not hammered for a day:
///
/// ```text
/// 1  →   1 min      5  →  2 h
/// 2  →   5 min      6  →  4 h
/// 3  →  15 min      7  →  8 h
/// 4  →   1 h        8  →  stop  (≈ 15½ h in total)
/// ```
///
/// Postfix's default is five days. This is much shorter on purpose: the relay
/// carries chat-shaped mail, where a message delivered a day late is usually
/// worse than one reported undeliverable, and the sender is a person sitting
/// in front of a client who can act on being told.
pub fn backoff(attempts_so_far: u32) -> Option<Duration> {
    const SCHEDULE_SECS: [u64; 7] = [60, 300, 900, 3_600, 7_200, 14_400, 28_800];
    // `attempts_so_far` counts attempts *made*, so the wait after the first
    // one is the first entry. Indexing directly by it shifted the whole
    // schedule: the first retry waited five minutes instead of one, and the
    // window stretched past the documented fifteen hours.
    //
    // Every unit test still passed, because they all called this function and
    // agreed with it. Only running the relay against a server that says 451
    // showed the first retry arriving four minutes late.
    let index = attempts_so_far.checked_sub(1)?;
    SCHEDULE_SECS
        .get(index as usize)
        .copied()
        .map(Duration::from_secs)
}

/// How many tries are left after `attempts_so_far`, for a log line that says
/// something an operator can act on.
pub fn attempts_remaining(attempts_so_far: u32) -> u32 {
    let mut n = attempts_so_far + 1;
    let mut left = 0;
    while backoff(n).is_some() {
        left += 1;
        n += 1;
    }
    left
}

/// The whole schedule, for the message an operator reads.
pub fn total_window() -> Duration {
    let mut total = Duration::ZERO;
    let mut n = 1;
    while let Some(d) = backoff(n) {
        total += d;
        n += 1;
    }
    total
}

#[cfg(test)]
mod tests;
