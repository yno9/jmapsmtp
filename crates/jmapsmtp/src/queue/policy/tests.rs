//! The two decisions, against the replies real servers send.

use super::*;

fn rejected(reply: &str) -> SendError {
    SendError::Rejected {
        command: "MAIL FROM".into(),
        reply: reply.into(),
    }
}

/// The case the queue exists for. A greylisting receiver refuses the first
/// attempt and accepts a retry; without a queue that message is lost.
#[test]
fn greylisting_is_temporary() {
    assert_eq!(
        classify(&rejected(
            "450 4.2.0 Recipient address rejected: Greylisted"
        )),
        Temporality::Temporary
    );
    assert_eq!(
        classify(&rejected("451 4.7.1 Please try again later")),
        Temporality::Temporary
    );
}

/// A refusal the far end means. Retrying delays telling the sender and
/// hardens the relay's reputation for nothing.
#[test]
fn a_five_hundred_is_permanent() {
    assert_eq!(
        classify(&rejected("550 5.1.1 User unknown")),
        Temporality::Permanent
    );
    assert_eq!(
        classify(&rejected("554 5.7.1 No valid DKIM signature found")),
        Temporality::Permanent
    );
}

/// Nothing answered. The network is the commonest reason to be here.
#[test]
fn no_answer_at_all_is_temporary() {
    assert_eq!(
        classify(&SendError::Dial(
            "mx.example:25".into(),
            std::io::Error::new(std::io::ErrorKind::TimedOut, "timed out")
        )),
        Temporality::Temporary
    );
    assert_eq!(
        classify(&SendError::Io(std::io::Error::new(
            std::io::ErrorKind::ConnectionReset,
            "reset"
        ))),
        Temporality::Temporary
    );
    assert_eq!(
        classify(&SendError::NoMx("example.test".into())),
        Temporality::Temporary
    );
}

/// A message that could never be sent as written. A retry re-runs the same
/// mistake.
#[test]
fn an_unsendable_message_is_permanent() {
    assert_eq!(classify(&SendError::NoRecipients), Temporality::Permanent);
    assert_eq!(
        classify(&SendError::InvalidRecipient("not-an-address".into())),
        Temporality::Permanent
    );
}

/// A reply we cannot read a code from is not a refusal worth standing behind.
/// One more attempt costs little; discarding on a misparse costs the message.
#[test]
fn an_unreadable_reply_is_treated_as_temporary() {
    assert_eq!(classify(&rejected("")), Temporality::Temporary);
    assert_eq!(classify(&rejected("gibberish")), Temporality::Temporary);
    assert_eq!(
        classify(&rejected("2.5.0 something with no code")),
        Temporality::Temporary
    );
}

/// The reply arrives with the code first; a code appearing later in the text
/// is not the reply's code.
#[test]
fn only_the_leading_code_counts() {
    assert_eq!(
        classify(&rejected("451 4.7.1 try again, not a 550")),
        Temporality::Temporary,
        "the 550 in the human-readable part is not the reply code"
    );
}

/// The wait is indexed by attempts *made*: after one attempt, the first
/// retry is a minute away. Getting this off by one shifted every step and was
/// invisible to the unit tests, which all agreed with the function.
#[test]
fn the_first_retry_is_soon_and_the_schedule_widens() {
    assert_eq!(
        backoff(1),
        Some(Duration::from_secs(60)),
        "the first retry, after one failed attempt, waits one minute"
    );
    assert_eq!(backoff(2), Some(Duration::from_secs(300)));
    assert_eq!(backoff(0), None, "no attempt has been made yet");
    let mut previous = Duration::ZERO;
    let mut n = 1;
    while let Some(d) = backoff(n) {
        assert!(
            d >= previous,
            "attempt {n} waits less than the one before it"
        );
        previous = d;
        n += 1;
    }
    assert!(n >= 5, "too few attempts to survive a short outage: {n}");
}

/// It has to stop. A queue that never gives up is a queue that never tells
/// anybody, and it grows without bound.
#[test]
fn the_schedule_ends() {
    assert_eq!(backoff(8), None, "seven retries and then stop");
    assert_eq!(backoff(1000), None);
}

/// Long enough for a receiver to come back from a short outage, short enough
/// that a person still cares about being told.
#[test]
fn the_window_is_hours_not_days() {
    let total = total_window();
    assert!(
        total >= Duration::from_secs(8 * 3600),
        "gives up too fast: {total:?}"
    );
    assert!(
        total <= Duration::from_secs(24 * 3600),
        "holds the message too long before reporting: {total:?}"
    );
}
