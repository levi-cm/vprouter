//! Separately typed fixed ROUTE-only veth executor. Canonical intent/birth remains
//! launch-owned; these types establish only original native mechanics.
use crate::wireguard::{
    Completed, ConfinedWireguard, ForkOutcome, PreparedWireguard, WireguardChild,
    WireguardDescriptors, WireguardMoveTarget,
};
use crate::{Birth, Error, ReapWitness, Result, WireguardChildGate};
use std::{
    os::fd::{BorrowedFd, OwnedFd},
    sync::Arc,
};
pub struct VethDescriptors<'a> {
    pub route: BorrowedFd<'a>,
    pub generic: BorrowedFd<'a>,
    pub namespace: BorrowedFd<'a>,
}
pub struct VethMoveTarget<'a> {
    pub route: BorrowedFd<'a>,
    pub generic: BorrowedFd<'a>,
    pub namespace: BorrowedFd<'a>,
}
pub struct PreparedVeth {
    inner: PreparedWireguard,
}
pub enum VethFork {
    Parent(VethChild, ReapWitness),
    Child(ConfinedVeth),
}
pub struct ConfinedVeth {
    inner: ConfinedWireguard,
}
pub struct VethChild {
    inner: WireguardChild,
}
pub struct VethCompleted {
    inner: Completed,
}
impl PreparedVeth {
    pub fn new(
        fds: VethDescriptors<'_>,
        digest: [u8; 32],
        end: f64,
        gate: WireguardChildGate,
    ) -> Result<Self> {
        Ok(Self {
            inner: PreparedWireguard::for_veth(
                WireguardDescriptors {
                    profiles: &[],
                    route: fds.route,
                    generic: fds.generic,
                    namespace: fds.namespace,
                },
                digest,
                end,
                gate,
            )?,
        })
    }
    pub fn for_down_move(
        fds: VethDescriptors<'_>,
        target: VethMoveTarget<'_>,
        digest: [u8; 32],
        end: f64,
        gate: WireguardChildGate,
    ) -> Result<Self> {
        Ok(Self {
            inner: PreparedWireguard::for_veth_move(
                WireguardDescriptors {
                    profiles: &[],
                    route: fds.route,
                    generic: fds.generic,
                    namespace: fds.namespace,
                },
                WireguardMoveTarget {
                    route: target.route,
                    generic: target.generic,
                    namespace: target.namespace,
                },
                digest,
                end,
                gate,
            )?,
        })
    }
    pub fn descriptors(&self) -> Result<Vec<BorrowedFd<'_>>> {
        self.inner.descriptors()
    }
    pub fn child_endpoints(&self) -> Result<[BorrowedFd<'_>; 2]> {
        Ok([self.inner.child_channel()?, self.inner.child_gate()?])
    }
    pub fn timer_owner(&self) -> Result<Arc<OwnedFd>> {
        self.inner.timer_owner()
    }
    pub fn birth(self) -> Result<VethFork> {
        Ok(match self.inner.birth()? {
            ForkOutcome::Parent(inner, original) => VethFork::Parent(VethChild { inner }, original),
            ForkOutcome::Child(inner) => VethFork::Child(ConfinedVeth { inner }),
        })
    }
}
impl ConfinedVeth {
    pub fn require(&self) -> Result<()> {
        if !self.inner.is_veth() {
            return Err(Error::Protocol);
        }
        self.inner.require()
    }
    pub fn namespace_identity(&self) -> Result<(u64, u64)> {
        self.require()?;
        self.inner.selected_namespace()
    }
    pub fn deadline(&self) -> f64 {
        self.inner.deadline()
    }
    pub fn socket_descriptors(&self) -> Result<[BorrowedFd<'_>; 2]> {
        self.require()?;
        self.inner.socket_descriptors()
    }
    pub fn socket_owners(&self) -> Result<[Arc<OwnedFd>; 2]> {
        self.require()?;
        self.inner.socket_owners()
    }
    pub fn move_target_descriptors(&self) -> Result<[BorrowedFd<'_>; 2]> {
        self.require()?;
        self.inner.move_target_descriptors()
    }
    pub fn move_target_sockets(&self) -> Result<[Arc<OwnedFd>; 2]> {
        self.require()?;
        self.inner.move_target_sockets()
    }
    pub fn move_target_namespace(&self) -> Result<(BorrowedFd<'_>, (u64, u64))> {
        self.require()?;
        self.inner.move_target_namespace()
    }
    pub fn timer_owner(&self) -> Result<Arc<OwnedFd>> {
        self.require()?;
        self.inner.timer_owner()
    }
    pub fn finish(self, bytes: &[u8]) -> ! {
        self.inner.finish(bytes)
    }
    pub fn fail(self) -> ! {
        self.inner.fail()
    }
}
impl VethChild {
    pub fn descriptors(&self) -> Result<Vec<BorrowedFd<'_>>> {
        self.inner.descriptors()
    }
    pub fn pidfd(&self) -> Result<BorrowedFd<'_>> {
        self.inner.pidfd()
    }
    pub fn identify(&mut self) -> Result<Birth> {
        self.inner.identify()
    }
    pub fn original_child(&self) -> Result<ReapWitness> {
        self.inner.reap_witness()
    }
    pub fn collect(&mut self) -> Result<Option<i32>> {
        self.inner.collect()
    }
    pub fn cancel(&mut self, e: Error) {
        self.inner.cancel(e)
    }
    pub fn poll(&mut self) -> Result<Option<VethCompleted>> {
        match self.inner.poll()? {
            None => Ok(None),
            Some(inner) => {
                if !inner.is_veth() {
                    return Err(Error::Protocol);
                }
                Ok(Some(VethCompleted { inner }))
            }
        }
    }
}
impl VethCompleted {
    pub fn descriptors(&self) -> Result<Vec<BorrowedFd<'_>>> {
        self.require_retained()?;
        self.inner.descriptors()
    }
    pub fn require_current(&self) -> Result<()> {
        if !self.inner.is_veth() {
            return Err(Error::Protocol);
        }
        self.inner.require_current()
    }
    pub fn public_report(&self) -> Result<&[u8]> {
        self.require_current()?;
        self.inner.public_report()
    }
    pub fn timer_owner(&self) -> Result<Arc<OwnedFd>> {
        self.require_current()?;
        self.inner.timer_owner()
    }
    pub fn original_child(&self) -> Result<ReapWitness> {
        self.inner.reap_witness()
    }
    pub fn accepted_at(&self) -> Result<f64> {
        self.inner.accepted_at()
    }
    pub fn child_reported_at(&self) -> Result<f64> {
        self.inner.child_reported_at()
    }
    pub fn birth(&self) -> Result<Birth> {
        self.inner.birth()
    }
    /// Original timer custody only. A new operation must install a distinct
    /// timer without changing the original completion or its observation time.
    pub fn retained_timer_owner(&self) -> Result<Arc<OwnedFd>> {
        self.require_retained()?;
        self.inner.retained_timer_owner()
    }
    /// Historical original completion custody, not renewed link validity.
    pub fn require_retained(&self) -> Result<()> {
        if !self.inner.is_veth() {
            return Err(Error::Protocol);
        }
        self.inner.retained_timer_owner()?;
        Ok(())
    }
}
