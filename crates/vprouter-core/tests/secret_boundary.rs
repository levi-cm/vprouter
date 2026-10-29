//! Keep this single ingress case in its own test executable: the permanent
//! process-wide fence needs a fresh process, and spawning from the parallel
//! allocation unit suite can transiently inherit its locked OFDs before exec.
use vprouter_core::{profile::Profile, secret_boundary};

#[test]
fn invalid_profile_ingress_is_permanent_even_after_errors_and_drops() {
    assert!(secret_boundary::pristine());
    assert!(Profile::parse(b"invalid", "de-fra-wg-001", None).is_err());
    assert!(!secret_boundary::pristine());
    secret_boundary::mark_ingress();
    assert!(!secret_boundary::pristine());
}
