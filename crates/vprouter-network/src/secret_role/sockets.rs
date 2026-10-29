//! Private completion construction from this pending operation's own fixed
//! socket creator. There is deliberately no arbitrary FD/report constructor.
use super::{end_instant, mapped};
use crate::{Error, NativeNetwork, Plan, Result};
use std::{
    cell::RefCell,
    os::fd::{AsFd, BorrowedFd, OwnedFd},
};
use vprouter_native_role::{
    Birth, PreparedSockets, ReapWitness, SocketChild, SocketCompletion, WireguardChildGate,
};
struct Native {
    creator: u32,
    plan: Plan,
    namespace: OwnedFd,
    identity: (u64, u64),
    end: f64,
    prepared: Option<PreparedSockets>,
    child: Option<SocketChild>,
    completed: Option<SocketCompletion>,
    network: Option<NativeNetwork>,
    failed: Option<Error>,
}
impl Native {
    fn verify(&self) -> Result<()> {
        if self.creator != std::process::id() || !vprouter_core::secret_boundary::pristine() {
            return Err(Error::NamespaceUnverified);
        }
        let s = rustix::fs::fstat(&self.namespace).map_err(|_| Error::NamespaceUnverified)?;
        if (s.st_dev, s.st_ino) != self.identity
            || rustix::fs::fstatfs(&self.namespace)
                .map_err(|_| Error::NamespaceUnverified)?
                .f_type as u64
                != 0x6e736673
        {
            return Err(Error::NamespaceUnverified);
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
pub struct PendingSocketPreparation {
    inner: Option<Native>,
}
pub struct VerifiedSocketPreparation {
    inner: Option<Native>,
}
impl Drop for PendingSocketPreparation {
    fn drop(&mut self) {
        if let Some(n) = self.inner.take() {
            retain(n);
        }
    }
}
impl Drop for VerifiedSocketPreparation {
    fn drop(&mut self) {
        if let Some(n) = self.inner.take() {
            retain(n);
        }
    }
}
impl PendingSocketPreparation {
    pub fn prepare(
        plan: Plan,
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
        let namespace = rustix::io::fcntl_dupfd_cloexec(namespace, 3)
            .map_err(|_| Error::NamespaceUnverified)?;
        let stat = rustix::fs::fstat(&namespace).map_err(|_| Error::NamespaceUnverified)?;
        let prepared =
            PreparedSockets::new(namespace.as_fd(), digest, end, gate).map_err(mapped)?;
        let n = Native {
            creator: std::process::id(),
            plan,
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
    pub fn poll(&mut self) -> Result<Option<VerifiedSocketPreparation>> {
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
                return Err(Error::NamespaceUnverified);
            }
            n.network = Some(NativeNetwork::from_socket_creator(n.plan.clone(), c)?);
            end_instant(n.end)?;
            Ok(true)
        })();
        match result {
            Ok(false) => Ok(None),
            Ok(true) => Ok(Some(VerifiedSocketPreparation {
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
impl VerifiedSocketPreparation {
    // Only the fixed sibling move constructor calls this immediately after
    // retained_network_slot validation and all fallible preparation succeeds.
    pub(super) fn inner_network_take(&mut self) -> NativeNetwork {
        self.inner
            .as_mut()
            .expect("validated original socket receipt")
            .network
            .take()
            .expect("validated original socket network")
    }
    pub(super) fn retained_network_slot(&mut self) -> Result<&mut Option<NativeNetwork>> {
        let n = self.inner.as_mut().ok_or(Error::Interrupted)?;
        n.verify()?;
        if n.failed.is_some() {
            return Err(Error::Interrupted);
        }
        let sockets = n
            .completed
            .as_ref()
            .ok_or(Error::Interrupted)?
            .retained_sockets()
            .map_err(mapped)?;
        if !n
            .network
            .as_ref()
            .is_some_and(|network| network.matches_socket_owners(&sockets))
        {
            return Err(Error::Foreign);
        }
        Ok(&mut n.network)
    }
    pub(super) fn require_current(&self) -> Result<()> {
        let n = self.inner.as_ref().ok_or(Error::Interrupted)?;
        n.verify()?;
        end_instant(n.end)?;
        n.completed
            .as_ref()
            .ok_or(Error::Interrupted)?
            .sockets()
            .map_err(mapped)?;
        Ok(())
    }

    pub(super) fn network_slot(&mut self) -> Result<&mut Option<NativeNetwork>> {
        let n = self.inner.as_mut().ok_or(Error::Interrupted)?;
        n.verify()?;
        end_instant(n.end)?;
        n.completed
            .as_ref()
            .ok_or(Error::Interrupted)?
            .sockets()
            .map_err(mapped)?;
        Ok(&mut n.network)
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
        self.inner
            .as_ref()
            .ok_or(Error::Interrupted)?
            .completed
            .as_ref()
            .ok_or(Error::Interrupted)?
            .accepted_at()
            .map_err(mapped)
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
