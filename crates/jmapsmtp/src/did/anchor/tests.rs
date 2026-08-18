//! How anchor verdicts become refusals.
//!
//! The mapping is the whole of this module's judgement, and two of the four
//! cases are the ones that matter: a conflict must not read as a broken proof,
//! and an unreachable anchor must never read as success.

use super::*;
use pretty_assertions::assert_eq;

#[test]
fn a_successful_claim_refuses_nothing() {
    assert_eq!(provision_refusal(Verdict::Ok), None);
    assert_eq!(device_error(Verdict::Ok), None);
}

/// The name is held by a different DID. That is not a broken proof and must
/// not be reported as one — the client's next step is to pick another name,
/// not to re-sign.
#[test]
fn a_conflict_is_reported_as_a_name_collision_not_a_bad_proof() {
    assert_eq!(
        provision_refusal(Verdict::Conflict),
        Some(crate::did::provision::Refusal::IdentityOwnedByAnother)
    );
    assert_ne!(
        provision_refusal(Verdict::Conflict),
        provision_refusal(Verdict::Invalid)
    );
}

#[test]
fn a_rejected_proof_is_reported_as_one() {
    assert_eq!(
        provision_refusal(Verdict::Invalid),
        Some(crate::did::provision::Refusal::DidBindingRejected)
    );
    assert_eq!(
        device_error(Verdict::Invalid),
        Some(crate::did::devices::DeviceError::VouchRejected)
    );
}

/// **Never "proceed unanchored".** An unbound name can be claimed by somebody
/// else later, and the collision surfaces as the original owner losing their
/// address — long after the request that caused it.
#[test]
fn an_unreachable_anchor_refuses_rather_than_proceeding() {
    assert_eq!(
        provision_refusal(Verdict::Error),
        Some(crate::did::provision::Refusal::AnchorUnavailable)
    );
    assert_eq!(
        device_error(Verdict::Error),
        Some(crate::did::devices::DeviceError::AnchorUnavailable)
    );
    assert_ne!(provision_refusal(Verdict::Error), None);
}

/// A 503 says "try again"; a 401 says "your proof was wrong". Confusing them
/// sends a user re-deriving a key that was never the problem.
#[test]
fn an_unreachable_anchor_and_a_rejected_proof_get_different_statuses() {
    assert_eq!(provision_refusal(Verdict::Error).unwrap().status(), 503);
    assert_eq!(provision_refusal(Verdict::Invalid).unwrap().status(), 401);
    assert_eq!(device_error(Verdict::Error).unwrap().status(), 503);
    assert_eq!(device_error(Verdict::Invalid).unwrap().status(), 401);
}

#[test]
fn the_anchor_ref_comes_from_the_configuration() {
    let cfg: crate::config::Config = serde_json::from_str(
        r#"{"domain":{"a.test":{}},"anchor_url":"https://anchor.test","anchor_token":"t"}"#,
    )
    .unwrap();
    let anchor = anchor_ref(&cfg);
    assert_eq!(anchor.url, "https://anchor.test");
    assert_eq!(anchor.token, "t");
    assert!(anchor.is_configured());

    let none: crate::config::Config = serde_json::from_str(r#"{"domain":{"a.test":{}}}"#).unwrap();
    assert!(!anchor_ref(&none).is_configured());
}
