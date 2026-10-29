//! Fixed producer/quarantine observation mechanics. No producer placement,
//! permit, activation, or original cgroup creation authority is returned.
use crate::wireguard::{
    Completed, ConfinedWireguard, ForkOutcome, PreparedWireguard, WireguardChild,
    WireguardDescriptors,
};
use crate::{Birth, Error, ReapWitness, Result, WireguardChildGate};
use std::{
    os::fd::{BorrowedFd, OwnedFd},
    sync::Arc,
};
pub struct ProducerNetfilterDescriptors<'a> {
    pub main: BorrowedFd<'a>,
    pub emergency: BorrowedFd<'a>,
    pub namespace: BorrowedFd<'a>,
    pub producer: crate::wireguard::ProducerDescriptors<'a>,
}
pub struct PreparedProducerNetfilter {
    inner: PreparedWireguard,
}
pub enum ProducerNetfilterFork {
    Parent(ProducerNetfilterChild, ReapWitness),
    Child(ConfinedProducerNetfilter),
}
pub struct ConfinedProducerNetfilter {
    inner: ConfinedWireguard,
}
pub struct ProducerNetfilterChild {
    inner: WireguardChild,
}
pub struct ProducerNetfilterCompleted {
    inner: Completed,
}
impl PreparedProducerNetfilter {
    pub fn new(
        fds: ProducerNetfilterDescriptors<'_>,
        digest: [u8; 32],
        end: f64,
        gate: WireguardChildGate,
    ) -> Result<Self> {
        Ok(Self {
            inner: PreparedWireguard::for_producer_netfilter(
                WireguardDescriptors {
                    profiles: &[],
                    route: fds.main,
                    generic: fds.emergency,
                    namespace: fds.namespace,
                },
                fds.producer,
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
    pub fn birth(self) -> Result<ProducerNetfilterFork> {
        Ok(match self.inner.birth()? {
            ForkOutcome::Parent(inner, original) => {
                ProducerNetfilterFork::Parent(ProducerNetfilterChild { inner }, original)
            }
            ForkOutcome::Child(inner) => {
                ProducerNetfilterFork::Child(ConfinedProducerNetfilter { inner })
            }
        })
    }
}
impl ConfinedProducerNetfilter {
    pub fn require(&self) -> Result<()> {
        if !self.inner.is_producer_netfilter() {
            return Err(Error::Protocol);
        }
        self.inner.require()
    }
    pub fn namespace_identity(&self) -> Result<(u64, u64)> {
        self.require()?;
        self.inner.selected_namespace()
    }
    pub fn producer_owners(&self) -> Result<[Arc<OwnedFd>; 6]> {
        self.require()?;
        self.inner.producer_owners()
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
impl ProducerNetfilterChild {
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
    pub fn poll(&mut self) -> Result<Option<ProducerNetfilterCompleted>> {
        match self.inner.poll()? {
            None => Ok(None),
            Some(inner) => {
                if !inner.is_producer_netfilter() {
                    return Err(Error::Protocol);
                }
                Ok(Some(ProducerNetfilterCompleted { inner }))
            }
        }
    }
}
impl ProducerNetfilterCompleted {
    pub fn descriptors(&self) -> Result<Vec<BorrowedFd<'_>>> {
        self.require_retained()?;
        self.inner.descriptors()
    }
    pub fn require_current(&self) -> Result<()> {
        if !self.inner.is_producer_netfilter() {
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
    pub fn retained_timer_owner(&self) -> Result<Arc<OwnedFd>> {
        self.require_retained()?;
        self.inner.retained_timer_owner()
    }
    /// Historical original completion custody, not renewed table validity.
    pub fn require_retained(&self) -> Result<()> {
        if !self.inner.is_producer_netfilter() {
            return Err(Error::Protocol);
        }
        self.inner.retained_timer_owner()?;
        Ok(())
    }
}
