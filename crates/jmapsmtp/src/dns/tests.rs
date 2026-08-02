//! What can be checked about DNS without a network.
//!
//! The live resolver is not exercised here — a test that queried real DNS
//! would be a test of the internet. What is pinned is the contract the rest of
//! the relay relies on, through the traits.

use super::*;
use pretty_assertions::assert_eq;

/// A resolver that answers from a table.
struct Fixed(Vec<(String, Vec<String>)>);

impl TxtResolver for Fixed {
    fn lookup_txt(&self, name: &str) -> Vec<String> {
        self.0
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.clone())
            .unwrap_or_default()
    }
}

/// A lookup that fails and a name with no records are the same answer, and
/// both refuse. Treating a failed lookup as anything other than "no proof"
/// would let a resolver outage hand out a domain.
#[test]
fn a_failed_lookup_and_an_empty_one_both_refuse() {
    let cfg: crate::config::Config =
        serde_json::from_str(r#"{"domain":{"a.test":{}},"domain_verify_secret":"s"}"#).unwrap();
    let expected = crate::customdomain::verify_token(&cfg, "y.jp");

    let resolver = Fixed(vec![]);
    assert!(!crate::customdomain::txt_proves_ownership(
        &resolver.lookup_txt(&crate::customdomain::verify_txt_name("y.jp")),
        &expected
    ));

    let resolver = Fixed(vec![(
        crate::customdomain::verify_txt_name("y.jp"),
        vec![String::new()],
    )]);
    assert!(!crate::customdomain::txt_proves_ownership(
        &resolver.lookup_txt(&crate::customdomain::verify_txt_name("y.jp")),
        &expected
    ));
}

#[test]
fn the_record_is_looked_up_under_the_published_name() {
    let cfg: crate::config::Config =
        serde_json::from_str(r#"{"domain":{"a.test":{}},"domain_verify_secret":"s"}"#).unwrap();
    let expected = crate::customdomain::verify_token(&cfg, "y.jp");
    let name = crate::customdomain::verify_txt_name("y.jp");
    assert_eq!(name, "_biset-verify.y.jp");

    // The right record under the right name proves it…
    let resolver = Fixed(vec![(name.clone(), vec![expected.clone()])]);
    assert!(crate::customdomain::txt_proves_ownership(
        &resolver.lookup_txt(&name),
        &expected
    ));

    // …and the same record under a different name does not.
    let resolver = Fixed(vec![("y.jp".into(), vec![expected.clone()])]);
    assert!(!crate::customdomain::txt_proves_ownership(
        &resolver.lookup_txt(&name),
        &expected
    ));
}

/// A domain's TXT records usually include several unrelated ones (SPF, site
/// verification). The proof has to be found among them, not required to be
/// alone.
#[test]
fn the_proof_is_found_among_unrelated_records() {
    let cfg: crate::config::Config =
        serde_json::from_str(r#"{"domain":{"a.test":{}},"domain_verify_secret":"s"}"#).unwrap();
    let expected = crate::customdomain::verify_token(&cfg, "y.jp");
    let name = crate::customdomain::verify_txt_name("y.jp");
    let resolver = Fixed(vec![(
        name.clone(),
        vec![
            "v=spf1 -all".into(),
            "google-site-verification=abc".into(),
            expected.clone(),
        ],
    )]);
    assert!(crate::customdomain::txt_proves_ownership(
        &resolver.lookup_txt(&name),
        &expected
    ));
}
