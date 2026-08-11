//! The comparison, against the shapes DNS actually returns.
//!
//! The cases here are the ones the production audit turned up — a mismatched
//! key, an absent record — plus the encodings a resolver may hand back for the
//! same record, because getting those wrong turns a healthy domain into a
//! false alarm and an operator who learns to ignore the warning.

use super::*;

const KEY_A: &str = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxnd5wl8bhS5fe1hNfmo4";
const KEY_B: &str = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuXnkNaFpcY4A1jwc94ce";

fn expected(key: &str) -> String {
    format!("v=DKIM1; k=rsa; p={key}")
}

#[test]
fn the_published_key_matching_is_a_match() {
    assert_eq!(decide(&[expected(KEY_A)], &expected(KEY_A)), Finding::Match);
}

/// biset.md, as found: a record exists and holds someone else's key.
#[test]
fn a_different_key_is_a_mismatch_not_a_missing_record() {
    assert_eq!(
        decide(&[expected(KEY_B)], &expected(KEY_A)),
        Finding::Mismatch
    );
}

/// t.biset.md, as found: nothing published, twenty-one accounts signing.
#[test]
fn no_records_at_all_is_no_answer() {
    assert_eq!(decide(&[], &expected(KEY_A)), Finding::NoAnswer);
}

/// A name that answers with something that is not a DKIM record — an SPF
/// record on the wrong name, a verification token — is missing, not
/// mismatched. The two need different actions.
#[test]
fn a_non_dkim_record_is_missing() {
    assert_eq!(
        decide(&["some-verification=abc123".into()], &expected(KEY_A)),
        Finding::Missing
    );
}

/// Long TXT records arrive split. Whether the resolver joins them is not
/// something to have an opinion about.
#[test]
fn a_split_record_is_reassembled() {
    let full = expected(KEY_A);
    let (a, b) = full.split_at(30);
    assert_eq!(
        decide(&[a.to_string(), b.to_string()], &full),
        Finding::Match,
        "a record handed back in two strings must not read as a mismatch"
    );
}

/// Extra tags and a different order change nothing about which key verifies.
#[test]
fn other_tags_and_ordering_do_not_matter() {
    let published = format!("k=rsa; t=s; p={KEY_A}; v=DKIM1; h=sha256");
    assert_eq!(decide(&[published], &expected(KEY_A)), Finding::Match);
}

/// Whitespace inside base64 is common when a record is pasted through a UI.
#[test]
fn whitespace_inside_the_key_is_ignored() {
    let published = format!("v=DKIM1; k=rsa; p={} {}", &KEY_A[..20], &KEY_A[20..]);
    assert_eq!(decide(&[published], &expected(KEY_A)), Finding::Match);
}

/// One of several records being right is right — a domain mid-rotation may
/// publish two.
#[test]
fn any_matching_record_is_enough() {
    assert_eq!(
        decide(&[expected(KEY_B), expected(KEY_A)], &expected(KEY_A)),
        Finding::Match
    );
}

/// A relay with no usable key of its own has nothing to compare and must not
/// accuse DNS of being wrong.
#[test]
fn an_empty_expectation_is_not_a_verdict() {
    assert_eq!(decide(&[expected(KEY_A)], ""), Finding::NoAnswer);
}

#[test]
fn only_mismatch_and_missing_ask_for_action() {
    assert!(Finding::Mismatch.is_problem());
    assert!(Finding::Missing.is_problem());
    assert!(!Finding::Match.is_problem());
    assert!(
        !Finding::NoAnswer.is_problem(),
        "an unreachable resolver must not read as a misconfiguration"
    );
}

#[test]
fn the_record_name_is_the_one_dkim_defines() {
    assert_eq!(
        record_name("default", "biset.md"),
        "default._domainkey.biset.md"
    );
}

/// End to end through the resolver trait, so the wiring is exercised too.
#[test]
fn check_domain_uses_the_resolver_and_the_selector() {
    struct Fake(String);
    impl TxtResolver for Fake {
        fn lookup_txt(&self, name: &str) -> Vec<String> {
            assert_eq!(name, "sel._domainkey.example.test", "wrong name queried");
            vec![self.0.clone()]
        }
    }
    assert_eq!(
        check_domain(
            &Fake(expected(KEY_B)),
            "sel",
            "example.test",
            &expected(KEY_A)
        ),
        Finding::Mismatch
    );
}
