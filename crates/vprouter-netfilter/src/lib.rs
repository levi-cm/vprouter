//! Scoped native nftables actuator. This is not a router or namespace manager.
#![forbid(unsafe_code)]
mod actuator;
mod codec;
mod cooperation;
mod enforcement;
mod fixed_bootstrap;
pub use fixed_bootstrap::{PendingBootstrap, VerifiedBootstrap};
mod fixed_producer;
pub use fixed_producer::{
    PendingProducerObservation, ProducerObservationContinuation, VerifiedProducerObservation,
};
mod fixed_quarantine;
mod fixed_sockets;
pub use fixed_quarantine::{PendingInitialQuarantine, VerifiedInitialQuarantine};
mod policy;
mod producer;
mod socket;
mod terminal;

pub use actuator::{Actuator, Reconciliation};
pub use enforcement::Enforcement;
pub use fixed_sockets::{PendingNetfilterSockets, VerifiedNetfilterSockets};
pub use policy::{Endpoint, Policy, Scope, Stage};
pub use producer::SocketProducer;
use serde::Serialize;
pub use terminal::{BootDeadline, TerminalQuarantine};

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
/// Drain original constructors retained after caller failure/Drop. This never
/// releases canonical reservations or establishes quarantine.
pub fn poll_retained_native() {
    fixed_sockets::poll_retained();
    fixed_quarantine::poll_retained();
    fixed_producer::poll_retained();
    fixed_bootstrap::poll_retained();
}
pub fn retained_native_children_reaped() -> bool {
    fixed_sockets::children_reaped()
        && fixed_quarantine::children_reaped()
        && fixed_producer::children_reaped()
        && fixed_bootstrap::children_reaped()
}

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
