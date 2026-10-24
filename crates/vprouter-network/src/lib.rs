//! Allocation-bound native observations, DOWN provisioning and quarantined activation.
//! Guarded activation requires retained netfilter quarantine authority.
//! Namespace entry, readiness and quarantine removal are not provided here.
#![forbid(unsafe_code)]

mod audit;
mod guarded;
mod native;
mod plan;
mod project;
mod socket;

pub use audit::{Audit, Snapshot};
pub use guarded::ActiveLinks;
pub use native::{DownLink, MetadataSnapshot, NamespaceTarget, NativeNetwork, VethPair};
pub use plan::{MonitoringPlan, Plan};
pub use project::{Address, Link, Peer, Route, Rule, Wireguard};

/// Fixed errors intentionally carry no external errors, payloads, or keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidInput,
    DirectUnsupported,
    Foreign,
    Drifted,
    HostDrift,
    TransportDrift,
    DataDrift,
    Absent,
    Unsupported,
    UnsupportedLinkAttribute(u16),
    UnsupportedLinkInfo(u16),
    UnsupportedAddressAttribute(u16),
    UnsupportedRouteAttribute(u16),
    Malformed,
    Oversized,
    Deadline,
    SocketUnavailable,
    Io,
    KernelRejected,
    KernelErrno(i32),
    ActivationKernel { step: &'static str, errno: i32 },
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
