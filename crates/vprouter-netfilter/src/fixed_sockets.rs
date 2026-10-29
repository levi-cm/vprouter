//! Private completion construction from this pending operation's own fixed
//! socket creator. There is deliberately no arbitrary FD/report constructor.
fn end_instant(end: f64) -> crate::Result<()> {
    crate::BootDeadline::at(end)?.check()
}
fn mapped(e: vprouter_native_role::Error) -> crate::Error {
    if e == vprouter_native_role::Error::Deadline {
        crate::Error::Deadline
    } else {
        crate::Error::Interrupted
    }
}
use crate::{Actuator, Error, Policy, Result};
use std::{
    cell::RefCell,
    os::fd::{AsFd, BorrowedFd, OwnedFd},
};
use vprouter_native_role::{
    Birth, PreparedSockets, ReapWitness, SocketChild, SocketCompletion, WireguardChildGate,
};
struct Native {
    creator: u32,
    policy: Policy,
    namespace: OwnedFd,
    identity: (u64, u64),
    end: f64,
    prepared: Option<PreparedSockets>,
    child: Option<SocketChild>,
    completed: Option<SocketCompletion>,
    network: Option<Actuator>,
    failed: Option<Error>,
}
impl Native {
    fn verify(&self) -> Result<()> {
        if self.creator != std::process::id() || !vprouter_core::secret_boundary::pristine() {
            return Err(Error::Foreign);
        }
        let s = rustix::fs::fstat(&self.namespace).map_err(|_| Error::Foreign)?;
        if (s.st_dev, s.st_ino) != self.identity
            || rustix::fs::fstatfs(&self.namespace)
                .map_err(|_| Error::Foreign)?
                .f_type as u64
                != 0x6e736673
        {
            return Err(Error::Foreign);
        }
        Ok(())
    }
    fn fail(&mut self, e: Error) {
        if self.creator != std::process::id() {
            return;
        }
        self.failed.get_or_insert(e);
        if let Some(c) = &mut self.child {
            c.cancel(vprouter_native_role::Error::Interrupted);
        }
    }
    fn collect(&mut self) {
        if self.creator == std::process::id()
            && let Some(c) = &mut self.child
        {
            let _ = c.collect();
        }
    }
    fn reaped(&self) -> bool {
        self.completed.is_some()
            || self.child.as_ref().is_none_or(|c| {
                c.original_child()
                    .and_then(|r| r.actual_status())
                    .is_ok_and(|s| s.is_some())
            })
    }
}
thread_local! {static RETAINED:RefCell<Vec<Native>>=const{RefCell::new(Vec::new())};}
fn retain(mut n: Native) {
    if n.creator != std::process::id() {
        std::mem::forget(n);
        return;
    }
    n.fail(Error::Interrupted);
    RETAINED.with(|r| r.borrow_mut().push(n));
}
pub struct PendingNetfilterSockets {
    inner: Option<Native>,
}
pub struct VerifiedNetfilterSockets {
    inner: Option<Native>,
}
impl Drop for PendingNetfilterSockets {
    fn drop(&mut self) {
        if let Some(n) = self.inner.take() {
            retain(n);
        }
    }
}
impl Drop for VerifiedNetfilterSockets {
    fn drop(&mut self) {
        if let Some(n) = self.inner.take() {
            retain(n);
        }
    }
}
impl PendingNetfilterSockets {
    pub fn prepare(
        policy: Policy,
        namespace: BorrowedFd<'_>,
        digest: [u8; 32],
        end: f64,
        gate: WireguardChildGate,
    ) -> Result<Self> {
        if RETAINED.with(|r| {
            r.borrow()
                .iter()
                .filter(|n| n.creator == std::process::id())
                .count()
        }) >= 64
        {
            return Err(Error::Oversized);
        }
        end_instant(end)?;
        let namespace =
            rustix::io::fcntl_dupfd_cloexec(namespace, 3).map_err(|_| Error::Foreign)?;
        let stat = rustix::fs::fstat(&namespace).map_err(|_| Error::Foreign)?;
        let prepared =
            PreparedSockets::new_netfilter(namespace.as_fd(), digest, end, gate).map_err(mapped)?;
        let n = Native {
            creator: std::process::id(),
            policy,
            namespace,
            identity: (stat.st_dev, stat.st_ino),
            end,
            prepared: Some(prepared),
            child: None,
            completed: None,
            network: None,
            failed: None,
        };
        n.verify()?;
        Ok(Self { inner: Some(n) })
    }
    fn get(&self) -> Result<&Native> {
        let n = self.inner.as_ref().ok_or(Error::Interrupted)?;
        n.verify()?;
        Ok(n)
    }
    pub fn descriptors(&self) -> Result<Vec<BorrowedFd<'_>>> {
        let n = self.get()?;
        let mut fds = vec![n.namespace.as_fd()];
        if let Some(p) = &n.prepared {
            fds.extend(p.descriptors().map_err(mapped)?);
        }
        if let Some(c) = &n.child {
            fds.extend(c.descriptors().map_err(mapped)?);
        }
        Ok(fds)
    }
    pub fn child_endpoints_before_birth(&self) -> Result<[BorrowedFd<'_>; 2]> {
        self.get()?
            .prepared
            .as_ref()
            .ok_or(Error::Interrupted)?
            .child_endpoints()
            .map_err(mapped)
    }
    pub fn birth(&mut self) -> Result<ReapWitness> {
        let n = self.inner.as_mut().ok_or(Error::Interrupted)?;
        n.verify()?;
        end_instant(n.end)?;
        if n.failed.is_some() || n.child.is_some() {
            return Err(Error::Interrupted);
        }
        let p = n.prepared.take().ok_or(Error::Interrupted)?;
        match p.birth().map_err(mapped) {
            Ok((child, receipt)) => {
                n.child = Some(child);
                Ok(receipt)
            }
            Err(e) => {
                n.fail(e);
                Err(e)
            }
        }
    }
    pub fn pidfd(&self) -> Result<BorrowedFd<'_>> {
        self.get()?
            .child
            .as_ref()
            .ok_or(Error::Interrupted)?
            .pidfd()
            .map_err(mapped)
    }
    pub fn original_child(&self) -> Result<ReapWitness> {
        self.get()?
            .child
            .as_ref()
            .ok_or(Error::Interrupted)?
            .original_child()
            .map_err(mapped)
    }
    pub fn identify(&mut self) -> Result<Birth> {
        self.inner
            .as_mut()
            .ok_or(Error::Interrupted)?
            .child
            .as_mut()
            .ok_or(Error::Interrupted)?
            .identify()
            .map_err(mapped)
    }
    /// Trusted launch adapter receives, registers all current originals even on
    /// eventual refusal, then calls poll. No native read occurs inside poll.
    pub fn receive_native(&mut self) -> Result<()> {
        let n = self.inner.as_mut().ok_or(Error::Interrupted)?;
        n.verify()?;
        n.child
            .as_mut()
            .ok_or(Error::Interrupted)?
            .receive_native()
            .map_err(mapped)
    }
    pub fn poll(&mut self) -> Result<Option<VerifiedNetfilterSockets>> {
        let n = self.inner.as_mut().ok_or(Error::Interrupted)?;
        n.verify()?;
        let result = (|| {
            end_instant(n.end)?;
            if let Some(e) = n.failed {
                return Err(e);
            }
            let Some(c) = n
                .child
                .as_mut()
                .ok_or(Error::Interrupted)?
                .poll()
                .map_err(mapped)?
            else {
                return Ok(false);
            };
            n.completed = Some(c);
            let c = n.completed.as_ref().ok_or(Error::Interrupted)?;
            if c.namespace_identity().map_err(mapped)? != n.identity {
                return Err(Error::Foreign);
            }
            n.network = Some(Actuator::from_fixed_creator(n.policy.clone(), c)?);
            end_instant(n.end)?;
            Ok(true)
        })();
        match result {
            Ok(false) => Ok(None),
            Ok(true) => Ok(Some(VerifiedNetfilterSockets {
                inner: self.inner.take(),
            })),
            Err(e) => {
                n.fail(e);
                Err(e)
            }
        }
    }
    pub fn cancel(&mut self) {
        if let Some(n) = &mut self.inner {
            n.fail(Error::Interrupted);
        }
    }
    pub fn collect(&mut self) {
        if let Some(n) = &mut self.inner {
            n.collect();
        }
    }
}
impl VerifiedNetfilterSockets {
    pub(super) fn original_actuator(&self) -> Result<&Actuator> {
        let n = self.inner.as_ref().ok_or(Error::Interrupted)?;
        n.verify()?;
        if n.failed.is_some() {
            return Err(Error::Interrupted);
        }
        let pair = n
            .completed
            .as_ref()
            .ok_or(Error::Interrupted)?
            .retained_netfilter_sockets()
            .map_err(mapped)?;
        let actuator = n.network.as_ref().ok_or(Error::Interrupted)?;
        if !actuator.matches_original_pair(&pair) {
            return Err(Error::Foreign);
        }
        Ok(actuator)
    }
    pub(super) fn original_namespace(&self) -> Result<BorrowedFd<'_>> {
        self.original_actuator()?;
        Ok(self
            .inner
            .as_ref()
            .ok_or(Error::Interrupted)?
            .namespace
            .as_fd())
    }
    pub(crate) fn retained_namespace_for(&self, actuator: &Actuator) -> Result<BorrowedFd<'_>> {
        let n = self.inner.as_ref().ok_or(Error::Interrupted)?;
        n.verify()?;
        if n.failed.is_some() || n.network.is_some() {
            return Err(Error::Foreign);
        }
        let pair = n
            .completed
            .as_ref()
            .ok_or(Error::Interrupted)?
            .retained_netfilter_sockets()
            .map_err(mapped)?;
        if !actuator.matches_original_pair(&pair) {
            return Err(Error::Foreign);
        }
        Ok(n.namespace.as_fd())
    }
    pub(super) fn take_actuator(&mut self) -> Actuator {
        self.inner
            .as_mut()
            .expect("prevalidated original")
            .network
            .take()
            .expect("prevalidated actuator")
    }

    pub(super) fn require_current(&self) -> Result<()> {
        let n = self.inner.as_ref().ok_or(Error::Interrupted)?;
        n.verify()?;
        end_instant(n.end)?;
        n.completed
            .as_ref()
            .ok_or(Error::Interrupted)?
            .netfilter_sockets()
            .map_err(mapped)?;
        Ok(())
    }
    pub fn original_child(&self) -> Result<ReapWitness> {
        let n = self.inner.as_ref().ok_or(Error::Interrupted)?;
        n.verify()?;
        n.completed
            .as_ref()
            .ok_or(Error::Interrupted)?
            .original_child()
            .map_err(mapped)
    }
    pub fn accepted_at(&self) -> Result<f64> {
        self.require_current()?;
        self.inner
            .as_ref()
            .ok_or(Error::Interrupted)?
            .completed
            .as_ref()
            .ok_or(Error::Interrupted)?
            .accepted_at()
            .map_err(mapped)
    }
    /// Only original accepted native custody; launch must independently match
    /// its canonical Result ACK before any subsequent operation is admitted.
    pub fn historical_receipt(&self) -> Result<(ReapWitness, f64)> {
        let n = self.inner.as_ref().ok_or(Error::Interrupted)?;
        n.verify()?;
        if n.failed.is_some() {
            return Err(Error::Interrupted);
        }
        let c = n.completed.as_ref().ok_or(Error::Interrupted)?;
        c.retained_netfilter_sockets().map_err(mapped)?;
        c.retained_receipt().map_err(mapped)
    }
    pub fn namespace_identity(&self) -> Result<(u64, u64)> {
        let n = self.inner.as_ref().ok_or(Error::Interrupted)?;
        n.verify()?;
        Ok(n.identity)
    }
}
pub(super) fn poll_retained() {
    RETAINED.with(|r| {
        for n in r.borrow_mut().iter_mut() {
            n.collect();
        }
    });
}
pub(super) fn children_reaped() -> bool {
    RETAINED.with(|r| {
        r.borrow()
            .iter()
            .all(|n| n.creator != std::process::id() || n.reaped())
    })
}
