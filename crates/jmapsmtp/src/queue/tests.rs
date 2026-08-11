//! The queue as it exists on disk, because surviving a restart is the point.

use super::*;

fn tmp() -> tempfile::TempDir {
    tempfile::tempdir().expect("tempdir")
}

const RAW: &[u8] = b"From: a@x.test\r\nTo: b@y.test\r\n\r\nhold on\r\n";

#[test]
fn a_queued_message_survives_being_forgotten_in_memory() {
    let d = tmp();
    let entry = enqueue(
        d.path(),
        "a@x.test",
        &["b@y.test".to_string()],
        RAW,
        "450 greylisted",
    )
    .expect("enqueue");

    // Nothing of the first call is carried over: this is what a restart sees.
    let loaded = load_all(d.path());
    assert_eq!(loaded, vec![entry.clone()]);
    assert_eq!(message(d.path(), &entry.id).expect("message"), RAW);
}

#[test]
fn the_envelope_is_kept_not_re_derived_from_the_headers() {
    let d = tmp();
    // A bounce address and an envelope recipient that appear nowhere in the
    // message — as with a mailing list, or a Bcc.
    let entry = enqueue(
        d.path(),
        "bounces+tag@x.test",
        &["hidden@y.test".to_string(), "other@z.test".to_string()],
        RAW,
        "451 later",
    )
    .expect("enqueue");
    let loaded = load_all(d.path()).pop().expect("one entry");
    assert_eq!(loaded.from, "bounces+tag@x.test");
    assert_eq!(loaded.to, ["hidden@y.test", "other@z.test"]);
    assert_eq!(loaded.id, entry.id);
}

#[test]
fn nothing_is_due_before_its_time() {
    let d = tmp();
    let entry = enqueue(d.path(), "a@x.test", &["b@y.test".into()], RAW, "450").expect("enqueue");
    assert!(
        due(d.path(), entry.first_queued).is_empty(),
        "an entry queued a moment ago must not be retried immediately"
    );
    assert_eq!(due(d.path(), entry.next_attempt).len(), 1);
}

#[test]
fn deferring_widens_the_wait_and_keeps_the_message() {
    let d = tmp();
    let entry = enqueue(d.path(), "a@x.test", &["b@y.test".into()], RAW, "450").expect("enqueue");

    let second = defer(d.path(), &entry, "450 again")
        .expect("defer")
        .expect("still queued");
    assert_eq!(second.attempts, 2);
    assert!(second.next_attempt > entry.next_attempt);
    assert_eq!(second.last_error, "450 again");
    assert_eq!(
        message(d.path(), &entry.id).expect("message"),
        RAW,
        "the message must not be rewritten by a deferral"
    );
}

/// The schedule has to end, and ending has to clean up — otherwise the queue
/// grows for ever and nobody is told.
#[test]
fn the_queue_gives_up_and_removes_the_entry() {
    let d = tmp();
    let mut entry =
        enqueue(d.path(), "a@x.test", &["b@y.test".into()], RAW, "450").expect("enqueue");
    let mut rounds = 0;
    while let Some(next) = defer(d.path(), &entry, "450").expect("defer") {
        entry = next;
        rounds += 1;
        assert!(rounds < 50, "the schedule never ended");
    }
    assert!(
        load_all(d.path()).is_empty(),
        "giving up must leave nothing behind"
    );
    assert!(message(d.path(), &entry.id).is_err());
}

#[test]
fn a_delivered_message_is_removed() {
    let d = tmp();
    let entry = enqueue(d.path(), "a@x.test", &["b@y.test".into()], RAW, "450").expect("enqueue");
    remove(d.path(), &entry.id).expect("remove");
    assert!(load_all(d.path()).is_empty());
    // Removing twice is what a retry racing a delivery does.
    remove(d.path(), &entry.id).expect("removing twice is not an error");
}

/// A crash between writing the message and writing the metadata leaves a
/// directory with no `meta.json`. It must be skipped, not crash the loader.
#[test]
fn a_half_written_entry_is_ignored() {
    let d = tmp();
    enqueue(d.path(), "a@x.test", &["b@y.test".into()], RAW, "450").expect("enqueue");
    std::fs::create_dir_all(dir(d.path()).join("torn")).expect("mkdir");
    std::fs::write(dir(d.path()).join("torn").join("message.eml"), RAW).expect("write");
    assert_eq!(load_all(d.path()).len(), 1);

    // And unparseable metadata, which is the same failure one step later.
    std::fs::write(dir(d.path()).join("torn").join("meta.json"), b"{not json").expect("write");
    assert_eq!(load_all(d.path()).len(), 1);
}

#[test]
fn entries_come_back_oldest_first() {
    let d = tmp();
    let a = enqueue(d.path(), "a@x.test", &["b@y.test".into()], RAW, "450").expect("a");
    std::thread::sleep(std::time::Duration::from_millis(5));
    let b = enqueue(d.path(), "c@x.test", &["d@y.test".into()], RAW, "450").expect("b");
    let ids: Vec<String> = load_all(d.path()).into_iter().map(|e| e.id).collect();
    assert_eq!(ids, vec![a.id, b.id], "a queue is drained in arrival order");
}

/// The queue holds other people's mail, so it is not world-readable.
#[cfg(unix)]
#[test]
fn queued_mail_is_not_readable_by_everyone() {
    use std::os::unix::fs::PermissionsExt as _;
    let d = tmp();
    let entry = enqueue(d.path(), "a@x.test", &["b@y.test".into()], RAW, "450").expect("enqueue");
    let path = dir(d.path()).join(&entry.id).join("message.eml");
    let mode = std::fs::metadata(&path).expect("stat").permissions().mode();
    assert_eq!(
        mode & 0o077,
        0,
        "queued mail is group/other readable: {mode:o}"
    );
}
