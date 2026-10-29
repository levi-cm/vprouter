//! Linux mechanics for the fixed WireGuard secret role.
//!
//! This crate cannot authorize resource creation, publication, journal mutation,
//! or cleanup. The network crate owns the original operation and the launch
//! owner retains its durable intent, capacity, registrations and unique service.
//! No callback, deserializable completion, or externally supplied report can
//! construct an original-child receipt. Secret ingress happens only after the
//! child-only installed-role capability has been returned.
#![deny(unsafe_op_in_unsafe_fn)]

mod filter;
mod gate;
mod linux;
mod veth;
pub use veth::{
    ConfinedVeth, PreparedVeth, VethChild, VethCompleted, VethDescriptors, VethFork, VethMoveTarget,
};
mod netfilter;
mod sockets;
pub use netfilter::{
    ConfinedNetfilter, NetfilterChild, NetfilterCompleted, NetfilterDescriptors, NetfilterFork,
    PreparedNetfilter,
};
mod producer_bootstrap;
pub use producer_bootstrap::{
    ConfinedProducerBootstrap, ConfinedProducerGroup, PreparedProducerBootstrap,
    ProducerAncestryDescriptors, ProducerBootstrapChild, ProducerBootstrapCompleted,
    ProducerBootstrapDescriptors, ProducerBootstrapFork,
};
mod producer_netfilter;
pub use producer_netfilter::{
    ConfinedProducerNetfilter, PreparedProducerNetfilter, ProducerNetfilterChild,
    ProducerNetfilterCompleted, ProducerNetfilterDescriptors, ProducerNetfilterFork,
};
pub use wireguard::ProducerDescriptors;
mod wireguard;
pub use sockets::{PreparedSockets, SocketChild, SocketCompletion};

pub use gate::{WireguardChildGate, WireguardReleaseGate, prepare_wireguard_gate};
pub use wireguard::{
    Birth, Completed, ConfinedWireguard, ForkOutcome, PreparedWireguard, ReapWitness,
    WireguardChild, WireguardDescriptors, WireguardMoveTarget,
};

#[cfg(feature = "lab")]
pub use wireguard::LabFailure;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Creator,
    Confinement,
    Deadline,
    Descriptor,
    Native,
    Protocol,
    Capacity,
    Interrupted,
}
pub type Result<T> = std::result::Result<T, Error>;

/// Collect only original children previously transferred by this crate. An
/// uncertain waitpid result keeps the complete native owner retained.
pub fn poll_retained() {
    wireguard::poll_retained();
    sockets::poll_retained();
}
pub fn retained_children_reaped() -> bool {
    wireguard::retained_children_reaped() && sockets::retained_children_reaped()
}
/// Creator-local monotonic diagnostic count, never permission or reap proof.
pub fn native_birth_count() -> u64 {
    linux::native_birth_count()
}

/// Test-only exact production programs, not a constructor/admission capability.
#[cfg(feature = "lab")]
pub fn lab_fixed_filter(
    socket_creator: bool,
    namespace: i32,
    result: i32,
    gate: i32,
) -> Vec<libc::sock_filter> {
    if socket_creator {
        filter::socket_creator(namespace, result, gate)
    } else {
        filter::wireguard(&[], &[3, 4], &[namespace], result, gate)
    }
}

/// Exact fixed Veth policy: GENERIC custody is retained, transactions denied.
#[cfg(feature = "lab")]
pub fn lab_veth_filter(namespace: i32, result: i32, gate: i32) -> Vec<libc::sock_filter> {
    filter::wireguard(&[], &[3], &[4, namespace], result, gate)
}

/// Exact Veth movement mechanics: both ROUTE sockets transact; both GENERIC
/// sockets and both namespace pins remain metadata-only.
#[cfg(feature = "lab")]
pub fn lab_veth_move_filter(
    namespace: i32,
    target: i32,
    result: i32,
    gate: i32,
) -> Vec<libc::sock_filter> {
    filter::wireguard(&[], &[3, 5], &[4, 6, namespace, target], result, gate)
}

/// Exact four-socket movement policy, test only; no movement authority.
#[cfg(feature = "lab")]
pub fn lab_movement_filter(
    namespace: i32,
    target: i32,
    result: i32,
    gate: i32,
) -> Vec<libc::sock_filter> {
    filter::wireguard(&[], &[3, 4, 5, 6], &[namespace, target], result, gate)
}

/// Exact fixed NETLINK_NETFILTER policies; test-only mechanical access.
#[cfg(feature = "lab")]
pub fn lab_netfilter_filter(
    socket_creator: bool,
    namespace: i32,
    result: i32,
    gate: i32,
) -> Vec<libc::sock_filter> {
    if socket_creator {
        filter::netfilter_socket_creator(namespace, result, gate)
    } else {
        filter::wireguard(&[], &[3, 4], &[namespace], result, gate)
    }
}

/// Exact closed producer observation read/pin sets, mechanical tests only.
#[cfg(feature = "lab")]
pub fn lab_producer_netfilter_filter(
    namespace: i32,
    result: i32,
    gate: i32,
) -> Vec<libc::sock_filter> {
    filter::wireguard(
        &[7, 8, 9, 10],
        &[3, 4],
        &[namespace, 5, 6, 7, 8, 9, 10],
        result,
        gate,
    )
}

/// Exact Bootstrap read-only ancestry extension. Only the test process supplies
/// the fixed name pointer; this function mints no installed-role capability.
#[cfg(feature = "lab")]
pub fn lab_producer_bootstrap_filter(
    namespace: i32,
    result: i32,
    gate: i32,
    name: &std::ffi::CStr,
) -> Vec<libc::sock_filter> {
    filter::producer_bootstrap(
        &[7, 8, 9, 10],
        &[3, 4],
        &[namespace, 5, 6, 7, 8, 9, 10, 11, 12],
        result,
        gate,
        &[(11, name.as_ptr() as u64)],
    )
}

/// Creator-bound diagnostic count only; never native completion or admission.
#[cfg(feature = "lab")]
pub fn lab_live_child_capacity() -> usize {
    wireguard::live_count()
}

/// Isolated test-process entry only. It intentionally retains a failed original
/// constructor; callers must not use this as a production owner operation.
#[cfg(feature = "lab")]
mod capacity_lab;
#[cfg(feature = "lab")]
pub use capacity_lab::{
    Evidence as LabCapacityRefusalEvidence, failed_refusal as lab_capacity_refusal_selftest,
};
