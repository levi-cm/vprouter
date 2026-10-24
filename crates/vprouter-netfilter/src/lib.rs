//! Scoped native nftables actuator. This is not a router or namespace manager.
#![forbid(unsafe_code)]
mod actuator;
mod codec;
mod policy;
mod socket;

pub use actuator::{Actuator, Reconciliation};
pub use policy::{Endpoint, Policy, Scope};
use serde::Serialize;

/// Authored reason codes only: no kernel error text or offending packet escapes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Error {
    InvalidAllocation,
    InvalidInput,
    DirectUnsupported,
    SocketUnavailable,
    Io,
    Deadline,
    Oversized,
    Malformed,
    SequenceMismatch,
    SenderMismatch,
    Interrupted,
    KernelRejected,
    GenerationChanged,
    Foreign,
    Drifted,
    QuarantineRequired,
    LabRequired,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod lab;
#[cfg(test)]
mod isolated_kernel_integration {
    #[test]
    #[ignore = "requires disposable netns inside isolated root-owned lab; never run on host"]
    fn native_acceptance() {
        assert_eq!(crate::lab::run(), Ok(()));
    }
    #[test]
    fn admission_fails_in_ordinary_test_environment() {
        // Do not infer ordinary environment from uid: a test runner could itself
        // be inside the real lab. This test only proves missing namespace/marker
        // conditions fail in the normal current environment; it never mutates.
        if std::fs::metadata("/var/lib/vprouter-v2-lab/isolated-acceptance").is_err() {
            assert_eq!(crate::lab::admit(), Err(crate::Error::LabRequired));
        }
    }
}
