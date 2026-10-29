//! One fixed original TRANSPORT pair endpoint -> declared HOST DOWN move. The parent owns
//! no release endpoint; only launch's exact durable movement Birth releases it.
use super::{VerifiedSocketPreparation, VerifiedVethCreation, end_instant, mapped};
use crate::{
    DownLink, Error, HostAdditionPlan, HostObservation, HostRead, Link, NativeNetwork, Result,
};
use std::{cell::RefCell, os::fd::BorrowedFd};
use vprouter_native_role::{
    Birth, ConfinedVeth, PreparedVeth, ReapWitness, VethChild, VethCompleted, VethDescriptors,
    VethFork, VethMoveTarget, WireguardChildGate,
};

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Report {
    source_sequences: [u32; 2],
    target_sequences: [u32; 2],
    link: Link,
    peer: Link,
}
struct Native {
    creator: u32,
    source: VerifiedVethCreation,
    _target_origin: VerifiedSocketPreparation,
    target: NativeNetwork,
    plan: HostAdditionPlan,
    before: HostObservation,
    after: HostObservation,
    host_read: Option<HostRead>,
    final_observed: Option<HostObservation>,
    peer: Option<DownLink>,
    accepted_sequences: Option<([u32; 2], [u32; 2])>,
    prepared: Option<PreparedVeth>,
    child: Option<VethChild>,
    completed: Option<VethCompleted>,
    moved: Option<DownLink>,
    report: Option<Report>,
    accepted_at: Option<f64>,
    end: f64,
    failed: Option<Error>,
    validated: bool,
    preparation_bound: bool,
    readback: Option<crate::native::Readback>,
    read_phase: u8,
}
impl Native {
    fn creator(&self) -> Result<()> {
        if self.creator != std::process::id() || !vprouter_core::secret_boundary::pristine() {
            return Err(Error::NamespaceUnverified);
        }
        Ok(())
    }
    fn fail(&mut self, error: Error) {
        if self.creator != std::process::id() {
            return;
        }
        self.failed.get_or_insert(error);
        if let Some(child) = &mut self.child {
            child.cancel(vprouter_native_role::Error::Interrupted);
        }
    }
    fn collect(&mut self) {
        if self.creator == std::process::id()
            && let Some(child) = &mut self.child
        {
            let _ = child.collect();
        }
    }
    fn reaped(&self) -> bool {
        if let Some(c) = &self.completed {
            return c.original_child().and_then(|r| r.actual_status()) == Ok(Some(0));
        }
        self.child.as_ref().is_none_or(|c| {
            c.original_child()
                .and_then(|r| r.actual_status())
                .is_ok_and(|s| s.is_some())
        })
    }
}
thread_local! { static RETAINED: RefCell<Vec<Native>> = const { RefCell::new(Vec::new()) }; }
fn retain(mut n: Native) {
    if n.creator != std::process::id() {
        std::mem::forget(n);
        return;
    }
    n.fail(Error::Interrupted);
    RETAINED.with(|r| r.borrow_mut().push(n));
}
pub struct PendingVethHostMove {
    inner: Option<Native>,
}
pub struct VerifiedVethHostMove {
    inner: Option<Native>,
}
impl Drop for PendingVethHostMove {
    fn drop(&mut self) {
        if let Some(n) = self.inner.take() {
            retain(n);
        }
    }
}
impl Drop for VerifiedVethHostMove {
    fn drop(&mut self) {
        if let Some(n) = self.inner.take() {
            retain(n);
        }
    }
}
impl PendingVethHostMove {
    #[allow(clippy::too_many_arguments)]
    pub fn prepare(
        source_slot: &mut Option<VerifiedVethCreation>,
        target_slot: &mut Option<VerifiedSocketPreparation>,
        plan_slot: &mut Option<HostAdditionPlan>,
        source_namespace: BorrowedFd<'_>,
        target_namespace: BorrowedFd<'_>,
        digest: [u8; 32],
        end: f64,
        child_gate: WireguardChildGate,
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
        let source = source_slot.as_ref().ok_or(Error::Interrupted)?;
        let q = source.retained()?;
        let plan = plan_slot.as_ref().ok_or(Error::Interrupted)?;
        let (before, after) = plan.fixed_observations(source)?;
        let target = target_slot
            .as_mut()
            .ok_or(Error::Interrupted)?
            .retained_network_slot()?
            .as_ref()
            .ok_or(Error::Interrupted)?;
        if q.network.plan != target.plan
            || q.network.namespace == target.namespace
            || target.namespace != before.namespace
        {
            return Err(Error::Foreign);
        }
        for (fd, identity) in [
            (source_namespace, q.network.namespace),
            (target_namespace, target.namespace),
        ] {
            let s = rustix::fs::fstat(fd).map_err(|_| Error::NamespaceUnverified)?;
            if (s.st_dev, s.st_ino) != identity {
                return Err(Error::NamespaceUnverified);
            }
        }
        let [route, generic] = q.network.descriptors();
        let [target_route, target_generic] = target.descriptors();
        let prepared = PreparedVeth::for_down_move(
            VethDescriptors {
                route,
                generic,
                namespace: source_namespace,
            },
            VethMoveTarget {
                route: target_route,
                generic: target_generic,
                namespace: target_namespace,
            },
            digest,
            end,
            child_gate,
        )
        .map_err(mapped)?;
        // No timer attachment, native readback or fallible validation after
        // consumption until launch stores and registers this complete bundle.
        let target = target_slot
            .as_mut()
            .expect("validated original target")
            .inner_network_take();
        Ok(Self {
            inner: Some(Native {
                creator: std::process::id(),
                source: source_slot.take().expect("validated source"),
                _target_origin: target_slot.take().expect("validated target"),
                target,
                plan: plan_slot.take().expect("validated original addition plan"),
                before,
                after,
                host_read: None,
                final_observed: None,
                peer: None,
                accepted_sequences: None,
                prepared: Some(prepared),
                child: None,
                completed: None,
                moved: None,
                report: None,
                accepted_at: None,
                end,
                failed: None,
                validated: false,
                preparation_bound: false,
                readback: None,
                read_phase: 0,
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
        let q = n.source.inner.as_ref().ok_or(Error::Interrupted)?;
        let mut out = q.network.descriptors().to_vec();
        out.extend(n.target.descriptors());
        if let Some(p) = &n.prepared {
            out.extend(p.descriptors().map_err(mapped)?);
        }
        if let Some(completed) = &n.completed {
            out.extend(completed.descriptors().map_err(mapped)?);
        } else if let Some(c) = &n.child {
            out.extend(c.descriptors().map_err(mapped)?);
        }
        Ok(out)
    }
    pub fn child_endpoints_before_birth(&self) -> Result<[BorrowedFd<'_>; 2]> {
        self.get()?
            .prepared
            .as_ref()
            .ok_or(Error::Interrupted)?
            .child_endpoints()
            .map_err(mapped)
    }
    pub fn validate_prepared(&mut self) -> Result<bool> {
        let n = self.inner.as_mut().ok_or(Error::Interrupted)?;
        n.creator()?;
        let result = (|| {
            if n.validated || n.failed.is_some() {
                return Err(Error::Interrupted);
            }
            n.plan.target_index()?;
            let q = n.source.inner.as_mut().ok_or(Error::Interrupted)?;
            let pair = q.pair.as_ref().ok_or(Error::Interrupted)?;
            if !n.preparation_bound {
                let timer = n
                    .prepared
                    .as_ref()
                    .ok_or(Error::Interrupted)?
                    .timer_owner()
                    .map_err(mapped)?;
                let end =
                    vprouter_netfilter::BootDeadline::at(n.end).map_err(|_| Error::Deadline)?;
                q.network.rebind_veth_operation(
                    q.completed.as_ref().ok_or(Error::Interrupted)?,
                    q.accepted_sequences.ok_or(Error::Interrupted)?,
                    end,
                    timer.clone(),
                )?;
                n.target.bind_cleanup_deadline(end, timer)?;
                n.preparation_bound = true;
                n.readback = Some(q.network.start_down_readback(&pair.host, n.end)?);
            }
            if n.read_phase < 2 {
                let Some(crate::native::ReadbackResult::Down(_)) = q
                    .network
                    .poll_readback(n.readback.as_mut().ok_or(Error::Interrupted)?)?
                else {
                    return Ok(false);
                };
                n.readback.take();
                n.read_phase += 1;
                if n.read_phase == 1 {
                    n.readback = Some(q.network.start_down_readback(&pair.transport, n.end)?);
                } else {
                    n.host_read = Some(n.target.start_host_read(n.end)?);
                }
                return Ok(false);
            }
            let Some(observed) = n
                .target
                .poll_host_read(n.host_read.as_mut().ok_or(Error::Interrupted)?)?
            else {
                return Ok(false);
            };
            crate::guarded::exact(&observed.snapshot(), &n.before.snapshot())?;
            n.host_read.take();
            n.read_phase = 0;
            end_instant(n.end)?;
            n.validated = true;
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
        if !n.validated || n.failed.is_some() || n.child.is_some() {
            return Err(Error::Interrupted);
        }
        let p = n.prepared.take().ok_or(Error::Interrupted)?;
        match p.birth().map_err(mapped) {
            Err(e) => {
                n.fail(e);
                Err(e)
            }
            Ok(VethFork::Child(role)) => run(n, role),
            Ok(VethFork::Parent(child, receipt)) => {
                n.child = Some(child);
                Ok(receipt)
            }
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
    pub fn poll(&mut self) -> Result<Option<VerifiedVethHostMove>> {
        let n = self.inner.as_mut().ok_or(Error::Interrupted)?;
        n.creator()?;
        if let Some(e) = n.failed {
            n.collect();
            return Err(e);
        }
        let result = (|| {
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
            n.plan.target_index()?;
            let q = n.source.inner.as_mut().ok_or(Error::Interrupted)?;
            let pair = q.pair.as_ref().ok_or(Error::Interrupted)?;
            let index = n.plan.target_index()?;
            let mut expected_host = pair.host.link.clone();
            expected_host.index = index;
            let mut expected_peer = pair.transport.link.clone();
            expected_peer.peer_index = Some(index);
            if n.report.is_none() {
                let report: Report = serde_json::from_slice(c.public_report().map_err(mapped)?)
                    .map_err(|_| Error::Malformed)?;
                if report.link != expected_host
                    || report.peer != expected_peer
                    || report.source_sequences[1] != q.network.sequences()?[1]
                    || report.target_sequences[1] != n.target.sequences()?[1]
                {
                    return Err(Error::Drifted);
                }
                q.network
                    .accept_veth_sequences(c, report.source_sequences)?;
                n.target.accept_veth_sequences(c, report.target_sequences)?;
                n.report = Some(report);
                n.readback = Some(q.network.start_absent_readback(pair.host.name(), n.end)?);
            }
            match n.read_phase {
                0 => {
                    let Some(crate::native::ReadbackResult::Absent) = q
                        .network
                        .poll_readback(n.readback.as_mut().ok_or(Error::Interrupted)?)?
                    else {
                        return Ok(false);
                    };
                    n.readback = Some(q.network.start_token_readback(
                        pair.transport.name(),
                        "veth",
                        n.end,
                    )?);
                    n.read_phase = 1;
                    return Ok(false);
                }
                1 => {
                    let Some(crate::native::ReadbackResult::Token(peer)) = q
                        .network
                        .poll_readback(n.readback.as_mut().ok_or(Error::Interrupted)?)?
                    else {
                        return Ok(false);
                    };
                    if peer.link != expected_peer {
                        return Err(Error::Drifted);
                    }
                    n.readback = Some(q.network.start_down_readback(&peer, n.end)?);
                    n.peer = Some(peer);
                    n.read_phase = 2;
                    return Ok(false);
                }
                2 => {
                    let Some(crate::native::ReadbackResult::Down(peer)) = q
                        .network
                        .poll_readback(n.readback.as_mut().ok_or(Error::Interrupted)?)?
                    else {
                        return Ok(false);
                    };
                    if peer != expected_peer {
                        return Err(Error::Drifted);
                    }
                    n.readback = Some(n.target.start_token_readback(
                        pair.host.name(),
                        "veth",
                        n.end,
                    )?);
                    n.read_phase = 3;
                    return Ok(false);
                }
                3 => {
                    let Some(crate::native::ReadbackResult::Token(moved)) = n
                        .target
                        .poll_readback(n.readback.as_mut().ok_or(Error::Interrupted)?)?
                    else {
                        return Ok(false);
                    };
                    if moved.link != expected_host {
                        return Err(Error::Drifted);
                    }
                    n.readback = Some(n.target.start_down_readback(&moved, n.end)?);
                    n.moved = Some(moved);
                    n.read_phase = 4;
                    return Ok(false);
                }
                4 => {
                    let Some(crate::native::ReadbackResult::Down(moved)) = n
                        .target
                        .poll_readback(n.readback.as_mut().ok_or(Error::Interrupted)?)?
                    else {
                        return Ok(false);
                    };
                    if moved != expected_host {
                        return Err(Error::Drifted);
                    }
                    n.readback.take();
                    n.host_read = Some(n.target.start_host_read(n.end)?);
                    n.read_phase = 5;
                    return Ok(false);
                }
                5 => (),
                _ => return Err(Error::Interrupted),
            }
            let Some(observed) = n
                .target
                .poll_host_read(n.host_read.as_mut().ok_or(Error::Interrupted)?)?
            else {
                return Ok(false);
            };
            crate::guarded::exact(&observed.snapshot(), &n.after.snapshot())?;
            n.host_read.take();
            c.require_current().map_err(mapped)?;
            end_instant(n.end)?;
            n.accepted_sequences = Some((q.network.sequences()?, n.target.sequences()?));
            n.plan.finish_original(&q.origin, &observed)?;
            n.final_observed = Some(observed);
            n.accepted_at = Some(vprouter_core::health::boot_seconds());
            end_instant(n.end)?;
            Ok(true)
        })();
        match result {
            Ok(false) => Ok(None),
            Ok(true) => Ok(Some(VerifiedVethHostMove {
                inner: self.inner.take(),
            })),
            Err(e) => {
                n.fail(e);
                Err(e)
            }
        }
    }
}
impl VerifiedVethHostMove {
    /// Historical whole-HOST read from this operation's actual original parent
    /// readback. It is public evidence, not a renewed admission or mutation grant.
    pub fn host_observation(&self) -> Result<&HostObservation> {
        let n = self.inner.as_ref().ok_or(Error::Interrupted)?;
        n.creator()?;
        n.completed
            .as_ref()
            .ok_or(Error::Interrupted)?
            .require_retained()
            .map_err(mapped)?;
        let at = n.accepted_at.ok_or(Error::Interrupted)?;
        if !at.is_finite() || at >= n.end || n.failed.is_some() {
            return Err(Error::Interrupted);
        }
        n.final_observed.as_ref().ok_or(Error::Interrupted)
    }
    pub fn observation(&self) -> Result<(&Link, &Link)> {
        let n = self.inner.as_ref().ok_or(Error::Interrupted)?;
        n.creator()?;
        n.completed
            .as_ref()
            .ok_or(Error::Interrupted)?
            .require_current()
            .map_err(mapped)?;
        let r = n.report.as_ref().ok_or(Error::Interrupted)?;
        Ok((&r.link, &r.peer))
    }
    pub fn accepted_at(&self) -> Result<f64> {
        let n = self.inner.as_ref().ok_or(Error::Interrupted)?;
        n.creator()?;
        n.accepted_at.ok_or(Error::Interrupted)
    }
    pub fn original_child(&self) -> Result<ReapWitness> {
        let n = self.inner.as_ref().ok_or(Error::Interrupted)?;
        n.creator()?;
        n.completed
            .as_ref()
            .ok_or(Error::Interrupted)?
            .original_child()
            .map_err(mapped)
    }
}
fn run(n: &Native, role: ConfinedVeth) -> ! {
    let result = (|| {
        let q = n.source.inner.as_ref().ok_or(Error::Interrupted)?;
        let mut source = q.network.confined_veth(&role)?;
        let mut target = n.target.confined_veth_target(&role)?;
        let (target_fd, target_identity) = role.move_target_namespace().map_err(mapped)?;
        // The fixed index/shape is captured before fork; no copied parent Rc
        // method is called in the foreign child to acquire authority.
        let index = n
            .after
            .snapshot()
            .links
            .iter()
            .find(|l| l.name == q.network.plan.host_name())
            .ok_or(Error::Foreign)?
            .index;
        let pair = source.move_veth_host_fixed(
            &mut target,
            target_fd,
            target_identity,
            q.pair.as_ref().ok_or(Error::Interrupted)?,
            index,
            &n.before,
            &n.after,
            end_instant(role.deadline())?,
        )?;
        role.require().map_err(mapped)?;
        serde_json::to_vec(&Report {
            source_sequences: source.sequences()?,
            target_sequences: target.sequences()?,
            link: pair.host.link,
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
