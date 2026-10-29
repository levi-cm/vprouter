//! Allocation-bound native observations, DOWN provisioning and quarantined activation.
//! Guarded activation requires retained netfilter quarantine authority.
//! Namespace entry, readiness and quarantine removal are not provided here.
#![forbid(unsafe_code)]

mod audit;
mod guarded;
mod host_observation;
mod native;
mod plan;
mod project;
mod secret_role;
mod socket;

pub use audit::{Audit, Snapshot};
pub use guarded::{
    ActiveLinks, DaemonDeclaration, DaemonLinks, DaemonPeer, HostAdditionPlan, HostAuditTicket,
    HostAuthority, HostRemovalPlan, NativeRemovalPlan, PendingHostAdmission,
    planned_host_link_index,
};
pub use host_observation::{HOST_OBSERVATION_BYTES, HostObservation};
#[cfg(feature = "lab")]
pub use native::LabRouteRead;
pub use native::{
    DeclaredWanRead, DownLink, HostRead, MetadataSnapshot, NamespaceTarget, NativeNetwork,
    RouteObserver, VethPair,
};
pub use plan::{MonitoringPlan, Plan};
pub use project::{Address, Link, Peer, Route, Rule, Wireguard};
pub use secret_role::{
    PendingSocketPreparation, PendingVethCreation, PendingVethHostMove, PendingWireguardMove,
    PendingWireguardProvision, PendingWireguardQuery, VerifiedSocketPreparation,
    VerifiedVethCreation, VerifiedVethHostMove, VerifiedWireguardMove, VerifiedWireguardProvision,
    VerifiedWireguardQuery,
};

/// Poll original fixed secret-query children retained after caller Drop. This
/// gives no journal, cleanup, resource reuse or publication authority.
pub fn poll_retained_secret_roles() {
    secret_role::poll_retained();
}
pub fn retained_secret_children_reaped() -> bool {
    secret_role::children_reaped()
}

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
