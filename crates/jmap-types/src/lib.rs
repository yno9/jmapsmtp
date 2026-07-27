//! JMAP (RFC 8620 / RFC 8621) wire types.
//!
//! Port of the `git.sr.ht/~rockorager/go-jmap` subset this project uses:
//! `mail/email`, `mail/mailbox`, `mail/emailsubmission`, `mail/identity`,
//! `mail/thread`, `mail/vacationresponse`, `core`. See PLAN.md M3.
//!
//! Field names and omitempty behaviour must match the Go struct tags exactly —
//! these types are what biset parses off the wire.
