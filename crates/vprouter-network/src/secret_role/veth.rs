//! One fixed exclusive, unaddressed DOWN pair birth in original TRANSPORT.
//! The parent owns no release endpoint and never adopts a caller's pair report.
mod movement;
use super::{VerifiedSocketPreparation, end_instant, mapped};
use crate::{DownLink, Error, Link, NativeNetwork, Result, VethPair};
pub use movement::{PendingVethHostMove, VerifiedVethHostMove};
use std::{cell::RefCell, os::fd::BorrowedFd, rc::Rc};
use vprouter_native_role::{
    Birth, ConfinedVeth, PreparedVeth, ReapWitness, VethChild, VethCompleted, VethDescriptors,
    VethFork, WireguardChildGate,
};

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Report {
    sequences: [u32; 2],
    host: Link,
    peer: Link,
}
struct Native {
    creator: u32,
    _socket_origin: VerifiedSocketPreparation,
    network: NativeNetwork,
    origin: Rc<()>,
    prepared: Option<PreparedVeth>,
    child: Option<VethChild>,
    completed: Option<VethCompleted>,
    report: Option<Report>,
    pair: Option<VethPair>,
    host: Option<DownLink>,
    peer: Option<DownLink>,
    readback: Option<crate::native::Readback>,
    phase: u8,
    bound: bool,
    prepared_valid: bool,
    accepted_at: Option<f64>,
    accepted_sequences: Option<[u32; 2]>,
    end: f64,
    failure: Option<Error>,
}
impl Native {
    fn creator(&self) -> Result<()> {
        if self.creator != std::process::id() || !vprouter_core::secret_boundary::pristine() {
            return Err(Error::NamespaceUnverified);
        }
        Ok(())
    }
    fn fail(&mut self, error: Error) {
        if self.creator == std::process::id() {
            self.failure.get_or_insert(error);
            if let Some(c) = &mut self.child {
                c.cancel(vprouter_native_role::Error::Interrupted);
            }
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
pub struct PendingVethCreation {
    inner: Option<Native>,
}
pub struct VerifiedVethCreation {
    inner: Option<Native>,
}
fn retain(mut n: Native) {
    if n.creator != std::process::id() {
        std::mem::forget(n);
        return;
    }
    n.fail(Error::Interrupted);
    RETAINED.with(|r| r.borrow_mut().push(n));
}
impl Drop for PendingVethCreation {
    fn drop(&mut self) {
        if let Some(n) = self.inner.take() {
            retain(n);
        }
    }
}
impl Drop for VerifiedVethCreation {
    fn drop(&mut self) {
        if let Some(n) = self.inner.take() {
            retain(n);
        }
    }
}
impl PendingVethCreation {
    pub fn prepare(
        sockets: &mut Option<VerifiedSocketPreparation>,
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
        let original = sockets.as_mut().ok_or(Error::Interrupted)?;
        let network = original
            .retained_network_slot()?
            .as_ref()
            .ok_or(Error::Interrupted)?;
        let ns = rustix::fs::fstat(namespace).map_err(|_| Error::NamespaceUnverified)?;
        if (ns.st_dev, ns.st_ino) != network.namespace {
            return Err(Error::NamespaceUnverified);
        }
        let [route, generic] = network.descriptors();
        let prepared = PreparedVeth::new(
            VethDescriptors {
                route,
                generic,
                namespace,
            },
            digest,
            end,
            gate,
        )
        .map_err(mapped)?;
        // No subsequent fallible native validation until launch stores and
        // registers this entire owner, including the original socket receipt.
        let network = original.inner_network_take();
        Ok(Self {
            inner: Some(Native {
                creator: std::process::id(),
                _socket_origin: sockets
                    .take()
                    .expect("original socket owner validated before transfer"),
                network,
                origin: Rc::new(()),
                prepared: Some(prepared),
                child: None,
                completed: None,
                report: None,
                pair: None,
                host: None,
                peer: None,
                readback: None,
                phase: 0,
                bound: false,
                prepared_valid: false,
                accepted_at: None,
                accepted_sequences: None,
                end,
                failure: None,
            }),
        })
    }
    fn get(&self) -> Result<&Native> {
        let n = self.inner.as_ref().ok_or(Error::Interrupted)?;
        n.creator()?;
        Ok(n)
    }
    #[cfg(feature = "lab")]
    pub fn lab_parent_readback_pending(&self) -> Result<bool> {
        Ok(self.get()?.completed.is_some())
    }
    pub fn descriptors(&self) -> Result<Vec<BorrowedFd<'_>>> {
        let n = self.get()?;
        let mut fds = n.network.descriptors().to_vec();
        if let Some(p) = &n.prepared {
            fds.extend(p.descriptors().map_err(mapped)?);
        }
        if let Some(c) = &n.completed {
            fds.extend(c.descriptors().map_err(mapped)?);
        } else if let Some(c) = &n.child {
            fds.extend(c.descriptors().map_err(mapped)?);
        }
        Ok(fds)
    }
    pub fn child_endpoints_before_birth(&self) -> Result<[BorrowedFd<'_>; 2]> {
        let p = self.get()?.prepared.as_ref().ok_or(Error::Interrupted)?;
        p.child_endpoints().map_err(mapped)
    }
    pub fn validate_prepared(&mut self) -> Result<bool> {
        let n = self.inner.as_mut().ok_or(Error::Interrupted)?;
        n.creator()?;
        let result = (|| {
            if n.prepared_valid || n.failure.is_some() {
                return Err(Error::Interrupted);
            }
            if !n.bound {
                n.network.bind_cleanup_deadline(
                    vprouter_netfilter::BootDeadline::at(n.end).map_err(|_| Error::Deadline)?,
                    n.prepared
                        .as_ref()
                        .ok_or(Error::Interrupted)?
                        .timer_owner()
                        .map_err(mapped)?,
                )?;
                n.bound = true;
                n.readback = Some(
                    n.network
                        .start_absent_readback(n.network.plan.host_name(), n.end)?,
                );
            }
            let Some(crate::native::ReadbackResult::Absent) = n
                .network
                .poll_readback(n.readback.as_mut().ok_or(Error::Interrupted)?)?
            else {
                return Ok(false);
            };
            n.readback.take();
            if n.phase == 0 {
                n.phase = 1;
                n.readback = Some(
                    n.network
                        .start_absent_readback(n.network.plan.transport_name(), n.end)?,
                );
                return Ok(false);
            }
            end_instant(n.end)?;
            n.phase = 0;
            n.prepared_valid = true;
            Ok(true)
        })();
        if let Err(e) = result {
            n.fail(e);
        }
        result
    }
    pub fn birth(&mut self) -> Result<ReapWitness> {
        let n = self.inner.as_mut().ok_or(Error::Interrupted)?;
        n.creator()?;
        if !n.prepared_valid || n.failure.is_some() || n.child.is_some() {
            return Err(Error::Interrupted);
        }
        match n
            .prepared
            .take()
            .ok_or(Error::Interrupted)?
            .birth()
            .map_err(mapped)
        {
            Ok(VethFork::Child(role)) => run(n, role),
            Ok(VethFork::Parent(child, original)) => {
                n.child = Some(child);
                Ok(original)
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
        let n = self.get()?;
        if let Some(c) = &n.completed {
            c.original_child().map_err(mapped)
        } else {
            n.child
                .as_ref()
                .ok_or(Error::Interrupted)?
                .original_child()
                .map_err(mapped)
        }
    }
    pub fn identify(&mut self) -> Result<Birth> {
        let n = self.inner.as_mut().ok_or(Error::Interrupted)?;
        n.creator()?;
        let result = n
            .child
            .as_mut()
            .ok_or(Error::Interrupted)?
            .identify()
            .map_err(mapped);
        if let Err(e) = result {
            n.fail(e);
        }
        result
    }
    pub fn cancel(&mut self, error: Error) {
        if let Some(n) = &mut self.inner {
            n.fail(error);
        }
    }
    pub fn collect(&mut self) {
        if let Some(n) = &mut self.inner {
            n.collect();
        }
    }
    pub fn poll(&mut self) -> Result<Option<VerifiedVethCreation>> {
        let n = self.inner.as_mut().ok_or(Error::Interrupted)?;
        n.creator()?;
        if let Some(e) = n.failure {
            n.collect();
            return Err(e);
        }
        let result =
            (|| {
                if n.completed.is_none() {
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
                }
                let c = n.completed.as_ref().ok_or(Error::Interrupted)?;
                c.require_current().map_err(mapped)?;
                if n.report.is_none() {
                    let report: Report = serde_json::from_slice(c.public_report().map_err(mapped)?)
                        .map_err(|_| Error::Malformed)?;
                    n.network.accept_veth_sequences(c, report.sequences)?;
                    n.report = Some(report);
                    n.readback = Some(n.network.start_token_readback(
                        n.network.plan.host_name(),
                        "veth",
                        n.end,
                    )?);
                }
                let Some(observation) = n
                    .network
                    .poll_readback(n.readback.as_mut().ok_or(Error::Interrupted)?)?
                else {
                    return Ok(false);
                };
                n.readback.take();
                match (n.phase, observation) {
                    (0, crate::native::ReadbackResult::Token(host)) => {
                        n.host = Some(host);
                        n.phase = 1;
                        n.readback = Some(n.network.start_down_readback(
                            n.host.as_ref().ok_or(Error::Interrupted)?,
                            n.end,
                        )?);
                        return Ok(false);
                    }
                    (1, crate::native::ReadbackResult::Down(_)) => {
                        n.phase = 2;
                        n.readback = Some(n.network.start_token_readback(
                            n.network.plan.transport_name(),
                            "veth",
                            n.end,
                        )?);
                        return Ok(false);
                    }
                    (2, crate::native::ReadbackResult::Token(peer)) => {
                        n.peer = Some(peer);
                        n.phase = 3;
                        n.readback = Some(n.network.start_down_readback(
                            n.peer.as_ref().ok_or(Error::Interrupted)?,
                            n.end,
                        )?);
                        return Ok(false);
                    }
                    (3, crate::native::ReadbackResult::Down(_)) => (),
                    _ => return Err(Error::Malformed),
                }
                let host = n.host.as_ref().ok_or(Error::Interrupted)?;
                let peer = n.peer.as_ref().ok_or(Error::Interrupted)?;
                let report = n.report.as_ref().ok_or(Error::Interrupted)?;
                if host.link != report.host
                    || peer.link != report.peer
                    || host.index() == peer.index()
                    || host.link.peer_index != Some(peer.index())
                    || peer.link.peer_index != Some(host.index())
                {
                    return Err(Error::Drifted);
                }
                c.require_current().map_err(mapped)?;
                end_instant(n.end)?;
                n.accepted_sequences = Some(n.network.sequences()?);
                n.pair = Some(VethPair {
                    host: n.host.take().ok_or(Error::Interrupted)?,
                    transport: n.peer.take().ok_or(Error::Interrupted)?,
                });
                n.accepted_at = Some(vprouter_core::health::boot_seconds());
                end_instant(n.end)?;
                Ok(true)
            })();
        match result {
            Ok(false) => Ok(None),
            Ok(true) => Ok(Some(VerifiedVethCreation {
                inner: self.inner.take(),
            })),
            Err(e) => {
                n.fail(e);
                Err(e)
            }
        }
    }
}
impl VerifiedVethCreation {
    fn retained(&self) -> Result<&Native> {
        let n = self.inner.as_ref().ok_or(Error::Interrupted)?;
        n.creator()?;
        let c = n.completed.as_ref().ok_or(Error::Interrupted)?;
        c.retained_timer_owner().map_err(mapped)?;
        if n.failure.is_some()
            || n.pair.is_none()
            || n.accepted_sequences.is_none()
            || n.accepted_at
                .is_none_or(|at| !at.is_finite() || at >= n.end || at < n.end - 2.)
        {
            return Err(Error::Foreign);
        }
        Ok(n)
    }
    pub fn observation(&self) -> Result<(&Link, &Link)> {
        let p = self.retained()?.pair.as_ref().ok_or(Error::Interrupted)?;
        Ok((&p.host.link, &p.transport.link))
    }
    pub fn accepted_at(&self) -> Result<f64> {
        self.retained()?.accepted_at.ok_or(Error::Interrupted)
    }
    pub fn original_child(&self) -> Result<ReapWitness> {
        self.retained()?
            .completed
            .as_ref()
            .ok_or(Error::Interrupted)?
            .original_child()
            .map_err(mapped)
    }
    pub(crate) fn original_pair(&self) -> Result<(&VethPair, &Rc<()>)> {
        let n = self.retained()?;
        Ok((n.pair.as_ref().ok_or(Error::Interrupted)?, &n.origin))
    }
}
fn run(n: &Native, role: ConfinedVeth) -> ! {
    let result = (|| {
        let mut network = n.network.confined_veth(&role)?;
        let pair = network.create_isolated_veth_pair_fixed(end_instant(role.deadline())?)?;
        role.require().map_err(mapped)?;
        serde_json::to_vec(&Report {
            sequences: network.sequences()?,
            host: pair.host.link,
            peer: pair.transport.link,
        })
        .map_err(|_| Error::Malformed)
    })();
    match result {
        Ok(bytes) => role.finish(&bytes),
        Err(_) => role.fail(),
    }
}
pub(super) fn poll_retained() {
    movement::poll_retained();
    RETAINED.with(|r| {
        for n in r.borrow_mut().iter_mut() {
            n.collect();
        }
    });
}
pub(super) fn children_reaped() -> bool {
    if !movement::children_reaped() {
        return false;
    }
    RETAINED.with(|r| {
        r.borrow()
            .iter()
            .all(|n| n.creator != std::process::id() || n.reaped())
    })
}
