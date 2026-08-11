use super::*;
use pretty_assertions::assert_eq;

#[test]
fn a_matching_token_is_allowed() {
    assert_eq!(check("s3cret", "Bearer s3cret"), Bearer::Allow);
}

#[test]
fn anything_else_is_denied() {
    assert_eq!(check("s3cret", "Bearer wrong"), Bearer::Deny);
    assert_eq!(check("s3cret", ""), Bearer::Deny, "no header");
    assert_eq!(check("s3cret", "s3cret"), Bearer::Deny, "no scheme");
    assert_eq!(check("s3cret", "Basic s3cret"), Bearer::Deny);
    assert_eq!(
        check("s3cret", "bearer s3cret"),
        Bearer::Deny,
        "Go's prefix is case-sensitive"
    );
    assert_eq!(
        check("s3cret", "Bearer s3cret "),
        Bearer::Deny,
        "not trimmed"
    );
    assert_eq!(
        check("s3cret", "Bearer s3cretx"),
        Bearer::Deny,
        "a prefix is not a match"
    );
}

/// The divergence from Go, stated as its own test so that "re-porting it
/// faithfully" fails here rather than quietly reopening the route.
///
/// Go's `bearerAuth` skips the check entirely when the token is empty. See
/// bearer.rs's header and SPEC.md §11.13.
#[test]
fn an_unconfigured_token_closes_the_route_rather_than_opening_it() {
    assert_eq!(check("", ""), Bearer::Deny);
    assert_eq!(check("", "Bearer anything"), Bearer::Deny);
    assert_eq!(
        check("", "Bearer "),
        Bearer::Deny,
        "an empty presented token does not match an empty configured one either"
    );
}
