//! Allocation-bound native observations and DOWN-only resource provisioning.
//! No activation, namespace entry, readiness, or quarantine removal API exists.
#![forbid(unsafe_code)]

mod audit;
mod native;
mod plan;
mod project;
mod socket;

pub use audit::{Audit, Snapshot};
pub use native::{DownLink, NamespaceTarget, NativeNetwork, VethPair};
pub use plan::Plan;
pub use project::{Address, Link, Peer, Route, Rule, Wireguard};

/// Fixed errors intentionally carry no external errors, payloads, or keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidInput,
    DirectUnsupported,
    Foreign,
    Drifted,
    Absent,
    Unsupported,
    Malformed,
    Oversized,
    Deadline,
    SocketUnavailable,
    Io,
    KernelRejected,
    SequenceMismatch,
    SenderMismatch,
    Interrupted,
    NamespaceUnverified,
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
mod tests;
