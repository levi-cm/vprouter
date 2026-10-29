//! One fixed original TRANSPORT -> admitted DATA DOWN move. The parent owns
//! no release endpoint; only launch's exact durable movement Birth releases it.
use super::{VerifiedSocketPreparation, VerifiedWireguardQuery, end_instant, mapped};
use crate::{DownLink, Error, Link, NativeNetwork, Result, Wireguard};
use std::{cell::RefCell, os::fd::BorrowedFd};
use vprouter_native_role::{
    Birth, Completed, ConfinedWireguard, ForkOutcome, PreparedWireguard, ReapWitness,
    WireguardChild, WireguardChildGate, WireguardDescriptors, WireguardMoveTarget,
};

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Report {
    source_sequences: [u32; 2],
    target_sequences: [u32; 2],
    link: Link,
    wireguard: Wireguard,
}
struct Native {
    creator: u32,
    source: VerifiedWireguardQuery,
    _target_origin: VerifiedSocketPreparation,
    target: NativeNetwork,
    prepared: Option<PreparedWireguard>,
    child: Option<WireguardChild>,
    completed: Option<Completed>,
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
            return c.reap_witness().and_then(|r| r.actual_status()) == Ok(Some(0));
        }
        self.child.as_ref().is_none_or(|c| {
            c.reap_witness()
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
pub struct PendingWireguardMove {
    inner: Option<Native>,
}
pub struct VerifiedWireguardMove {
    inner: Option<Native>,
}
impl Drop for PendingWireguardMove {
    fn drop(&mut self) {
        if let Some(n) = self.inner.take() {
            retain(n);
        }
    }
}
impl Drop for VerifiedWireguardMove {
    fn drop(&mut self) {
        if let Some(n) = self.inner.take() {
            retain(n);
        }
    }
}
impl PendingWireguardMove {
    #[allow(clippy::too_many_arguments)]
    pub fn prepare(
        source_slot: &mut Option<VerifiedWireguardQuery>,
        target_slot: &mut Option<VerifiedSocketPreparation>,
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
        let q = source.inner.as_ref().ok_or(Error::Interrupted)?;
        q.creator()?;
        let prior = q.completed.as_ref().ok_or(Error::Interrupted)?;
        prior.retained_timer_owner().map_err(mapped)?;
        if q.failure.is_some()
            || q.report.is_none()
            || q.accepted_at
                .is_none_or(|at| !at.is_finite() || at >= q.end)
        {
            return Err(Error::Interrupted);
        }
        let target = target_slot
            .as_mut()
            .ok_or(Error::Interrupted)?
            .retained_network_slot()?
            .as_ref()
            .ok_or(Error::Interrupted)?;
        if q.network.plan != target.plan || q.network.namespace == target.namespace {
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
        let prepared = PreparedWireguard::for_down_move(
            WireguardDescriptors {
                profiles: &[],
                route,
                generic,
                namespace: source_namespace,
            },
            WireguardMoveTarget {
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
    pub fn child_channel_before_birth(&self) -> Result<BorrowedFd<'_>> {
        self.get()?
            .prepared
            .as_ref()
            .ok_or(Error::Interrupted)?
            .child_channel()
            .map_err(mapped)
    }
    pub fn child_gate_before_birth(&self) -> Result<BorrowedFd<'_>> {
        self.get()?
            .prepared
            .as_ref()
            .ok_or(Error::Interrupted)?
            .child_gate()
            .map_err(mapped)
    }
    pub fn validate_prepared(&mut self) -> Result<bool> {
        let n = self.inner.as_mut().ok_or(Error::Interrupted)?;
        n.creator()?;
        let result = (|| {
            if n.validated || n.failed.is_some() {
                return Err(Error::Interrupted);
            }
            let q = n.source.inner.as_mut().ok_or(Error::Interrupted)?;
            if !n.preparation_bound {
                let timer = n
                    .prepared
                    .as_ref()
                    .ok_or(Error::Interrupted)?
                    .timer_owner()
                    .map_err(mapped)?;
                let end =
                    vprouter_netfilter::BootDeadline::at(n.end).map_err(|_| Error::Deadline)?;
                q.network.rebind_accepted_operation(
                    q.completed.as_ref().ok_or(Error::Interrupted)?,
                    q.accepted_sequences.ok_or(Error::Interrupted)?,
                    end,
                    timer.clone(),
                )?;
                n.target.bind_cleanup_deadline(end, timer)?;
                n.preparation_bound = true;
                n.readback = Some(q.network.start_down_readback(&q.original, n.end)?);
            }
            if n.read_phase == 0 {
                let Some(crate::native::ReadbackResult::Down(_)) = q
                    .network
                    .poll_readback(n.readback.as_mut().ok_or(Error::Interrupted)?)?
                else {
                    return Ok(false);
                };
                n.readback.take();
                n.read_phase = 1;
                n.readback = Some(n.target.start_absent_readback(q.original.name(), n.end)?);
                return Ok(false);
            }
            let Some(crate::native::ReadbackResult::Absent) = n
                .target
                .poll_readback(n.readback.as_mut().ok_or(Error::Interrupted)?)?
            else {
                return Ok(false);
            };
            n.readback.take();
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
            Ok(ForkOutcome::Child(role)) => run(n, role),
            Ok(ForkOutcome::Parent(child, receipt)) => {
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
        self.get()?
            .child
            .as_ref()
            .ok_or(Error::Interrupted)?
            .reap_witness()
            .map_err(mapped)
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
    pub fn poll(&mut self) -> Result<Option<VerifiedWireguardMove>> {
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
            let q = n.source.inner.as_mut().ok_or(Error::Interrupted)?;
            if n.report.is_none() {
                let report: Report = serde_json::from_slice(c.public_report().map_err(mapped)?)
                    .map_err(|_| Error::Malformed)?;
                q.network.accept_sequences(c, report.source_sequences)?;
                n.target.accept_sequences(c, report.target_sequences)?;
                n.report = Some(report);
                n.readback = Some(q.network.start_absent_readback(q.original.name(), n.end)?);
            }
            if n.read_phase == 0 {
                let Some(crate::native::ReadbackResult::Absent) = q
                    .network
                    .poll_readback(n.readback.as_mut().ok_or(Error::Interrupted)?)?
                else {
                    return Ok(false);
                };
                n.readback.take();
                n.read_phase = 1;
                n.readback = Some(n.target.start_token_readback(
                    q.original.name(),
                    "wireguard",
                    n.end,
                )?);
                return Ok(false);
            }
            if n.read_phase == 1 {
                let Some(crate::native::ReadbackResult::Token(moved)) = n
                    .target
                    .poll_readback(n.readback.as_mut().ok_or(Error::Interrupted)?)?
                else {
                    return Ok(false);
                };
                n.readback.take();
                n.moved = Some(moved);
                n.read_phase = 2;
                n.readback = Some(
                    n.target
                        .start_down_readback(n.moved.as_ref().ok_or(Error::Interrupted)?, n.end)?,
                );
                return Ok(false);
            }
            let Some(crate::native::ReadbackResult::Down(observed)) = n
                .target
                .poll_readback(n.readback.as_mut().ok_or(Error::Interrupted)?)?
            else {
                return Ok(false);
            };
            n.readback.take();
            let moved = n.moved.as_ref().ok_or(Error::Interrupted)?;
            let report = n.report.as_ref().ok_or(Error::Interrupted)?;
            if observed != report.link {
                return Err(Error::Drifted);
            }
            n.target
                .check_public_wireguard(&report.wireguard, moved.index())?;
            c.require_current().map_err(mapped)?;
            end_instant(n.end)?;
            n.accepted_at = Some(vprouter_core::health::boot_seconds());
            end_instant(n.end)?;
            Ok(true)
        })();
        match result {
            Ok(false) => Ok(None),
            Ok(true) => Ok(Some(VerifiedWireguardMove {
                inner: self.inner.take(),
            })),
            Err(e) => {
                n.fail(e);
                Err(e)
            }
        }
    }
}
impl VerifiedWireguardMove {
    pub fn observation(&self) -> Result<(&Link, &Wireguard)> {
        let n = self.inner.as_ref().ok_or(Error::Interrupted)?;
        n.creator()?;
        n.completed
            .as_ref()
            .ok_or(Error::Interrupted)?
            .require_current()
            .map_err(mapped)?;
        let r = n.report.as_ref().ok_or(Error::Interrupted)?;
        Ok((&r.link, &r.wireguard))
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
            .reap_witness()
            .map_err(mapped)
    }
}
fn run(n: &Native, role: ConfinedWireguard) -> ! {
    let result = (|| {
        let q = n.source.inner.as_ref().ok_or(Error::Interrupted)?;
        let mut source = q.network.confined(&role)?;
        let mut target = n.target.confined_move_target(&role)?;
        let (target_fd, target_identity) = role.move_target_namespace().map_err(mapped)?;
        let end = end_instant(role.deadline())?;
        let moved = source.move_wireguard_down_fixed(
            &mut target,
            target_fd,
            target_identity,
            &q.original,
            end,
        )?;
        let wireguard = target.checked_wireguard(moved.index(), end)?;
        let link = target.owned_down(&moved, end)?;
        source.absent(q.original.name(), end)?;
        role.require().map_err(mapped)?;
        serde_json::to_vec(&Report {
            source_sequences: source.sequences()?,
            target_sequences: target.sequences()?,
            link,
            wireguard,
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

#[cfg(feature = "lab")]
impl Native {
    fn lab_cached_progress(&self) -> Option<serde_json::Value> {
        if self.creator != std::process::id() {
            return None;
        }
        Some(
            serde_json::json!({"read_phase":self.read_phase,"readback_present":self.readback.is_some(),
            "completed_present":self.completed.is_some(),"report_present":self.report.is_some(),
            "validated":self.validated,"preparation_bound":self.preparation_bound,"accepted_at":self.accepted_at}),
        )
    }
}
#[cfg(feature = "lab")]
impl PendingWireguardMove {
    pub fn lab_cached_progress(&self) -> Option<serde_json::Value> {
        self.inner.as_ref()?.lab_cached_progress()
    }
}
#[cfg(feature = "lab")]
impl VerifiedWireguardMove {
    pub fn lab_cached_progress(&self) -> Option<serde_json::Value> {
        self.inner.as_ref()?.lab_cached_progress()
    }
}
