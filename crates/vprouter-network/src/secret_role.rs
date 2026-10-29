//! Fixed secret-bearing WireGuard query. Only this private entry can bind the
//! lower native receipt to the original network object and DOWN token. The
//! ordinary parent never receives raw GetDevice frames or secret attributes.
mod movement;
mod profiles;
mod provision;
mod sockets;
mod veth;
use crate::{DownLink, Error, Link, NativeNetwork, Result, Wireguard};
pub use movement::{PendingWireguardMove, VerifiedWireguardMove};
pub use provision::{PendingWireguardProvision, VerifiedWireguardProvision};
pub use sockets::{PendingSocketPreparation, VerifiedSocketPreparation};
use std::{cell::RefCell, os::fd::BorrowedFd, time::Instant};
pub use veth::{
    PendingVethCreation, PendingVethHostMove, VerifiedVethCreation, VerifiedVethHostMove,
};
use vprouter_native_role::{
    Birth, Completed, ConfinedWireguard, ForkOutcome, PreparedWireguard, ReapWitness,
    WireguardChild, WireguardDescriptors,
};

pub(crate) fn mapped(error: vprouter_native_role::Error) -> Error {
    match error {
        vprouter_native_role::Error::Deadline => Error::Deadline,
        vprouter_native_role::Error::Creator | vprouter_native_role::Error::Confinement => {
            Error::NamespaceUnverified
        }
        vprouter_native_role::Error::Protocol => Error::Malformed,
        vprouter_native_role::Error::Capacity => Error::Oversized,
        _ => Error::Interrupted,
    }
}
pub(crate) fn end_instant(end: f64) -> Result<Instant> {
    let now = vprouter_core::health::boot_seconds();
    if !end.is_finite() || !now.is_finite() || now >= end || end - now > 2. {
        return Err(Error::Deadline);
    }
    // This only schedules waits. Every socket also checks the original absolute
    // BOOTTIME end before/after all native sends, receives and waits.
    Ok(Instant::now()
        + std::time::Duration::try_from_secs_f64(end - now).map_err(|_| Error::Deadline)?)
}
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct QueryReport {
    sequences: [u32; 2],
    link: Link,
    wireguard: Wireguard,
}
struct Query {
    _provision_origin: Option<VerifiedWireguardProvision>,
    creator: u32,
    network: NativeNetwork,
    original: DownLink,
    prepared: Option<PreparedWireguard>,
    child: Option<WireguardChild>,
    completed: Option<Completed>,
    report: Option<QueryReport>,
    accepted_at: Option<f64>,
    accepted_sequences: Option<[u32; 2]>,
    end: f64,
    failure: Option<Error>,
    validated_preparation: bool,
    preparation_bound: bool,
    readback: Option<crate::native::Readback>,
}
impl Query {
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
        self.failure.get_or_insert(error);
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
        if self.creator != std::process::id() {
            return false;
        }
        if let Some(completed) = &self.completed {
            return completed.reap_witness().and_then(|w| w.actual_status()) == Ok(Some(0));
        }
        self.child.as_ref().is_none_or(|child| {
            child
                .reap_witness()
                .and_then(|w| w.actual_status())
                .ok()
                .flatten()
                .is_some()
        })
    }
}
thread_local! {static RETAINED:RefCell<Vec<Query>>=const{RefCell::new(Vec::new())};}

/// Consumes the exact original DOWN token and its dedicated network sockets.
/// Canonical launch ownership and the unique service remain in the caller's
/// retained driver. Prepare does not read a profile or a raw WireGuard reply.
pub struct PendingWireguardQuery {
    inner: Option<Query>,
}
impl PendingWireguardQuery {
    pub fn prepare_from_original_provision(
        provision: &mut Option<VerifiedWireguardProvision>,
        namespace: BorrowedFd<'_>,
        request_digest: [u8; 32],
        original_end: f64,
        child_gate: vprouter_native_role::WireguardChildGate,
    ) -> Result<Self> {
        let original = provision.as_mut().ok_or(Error::Interrupted)?;
        original.down()?;
        let p = original.inner.as_mut().ok_or(Error::Interrupted)?;
        p.creator()?;
        let completed = p.completed.as_ref().ok_or(Error::Interrupted)?;
        completed.require_current().map_err(mapped)?;
        let mut query = Self::prepare(
            &mut p.network,
            &mut p.down,
            namespace,
            request_digest,
            original_end,
            child_gate,
        )?;
        // Final old-current/native checks wait until launch owns this bundle.
        query
            .inner
            .as_mut()
            .ok_or(Error::Interrupted)?
            ._provision_origin = provision.take();
        Ok(query)
    }
    pub fn prepare(
        network_slot: &mut Option<NativeNetwork>,
        original_slot: &mut Option<DownLink>,
        namespace: BorrowedFd<'_>,
        request_digest: [u8; 32],
        original_end: f64,
        child_gate: vprouter_native_role::WireguardChildGate,
    ) -> Result<Self> {
        if RETAINED.with(|r| {
            r.borrow()
                .iter()
                .filter(|q| q.creator == std::process::id())
                .count()
        }) >= 64
        {
            return Err(Error::Oversized);
        }
        let network = network_slot.as_mut().ok_or(Error::Interrupted)?;
        let original = original_slot.as_ref().ok_or(Error::Interrupted)?;
        if !vprouter_core::secret_boundary::pristine()
            || original.namespace != network.namespace
            || original.link.alias != network.plan.alias
            || original.link.name != network.plan.wireguard_name()
            || original.link.kind != "wireguard"
            || original.link.up
        {
            return Err(Error::Foreign);
        }
        let stat = rustix::fs::fstat(namespace).map_err(|_| Error::NamespaceUnverified)?;
        if (stat.st_dev, stat.st_ino) != network.namespace {
            return Err(Error::NamespaceUnverified);
        }
        let [route, generic] = network.descriptors();
        let prepared = PreparedWireguard::new(
            WireguardDescriptors {
                profiles: &[],
                route,
                generic,
                namespace,
            },
            request_digest,
            original_end,
            child_gate,
        )
        .map_err(mapped)?;
        let network = network_slot.take().ok_or(Error::Interrupted)?;
        let original = original_slot.take().ok_or(Error::Interrupted)?;
        Ok(Self {
            inner: Some(Query {
                _provision_origin: None,
                creator: std::process::id(),
                network,
                original,
                prepared: Some(prepared),
                child: None,
                completed: None,
                report: None,
                accepted_at: None,
                accepted_sequences: None,
                end: original_end,
                failure: None,
                validated_preparation: false,
                preparation_bound: false,
                readback: None,
            }),
        })
    }
    pub fn validate_prepared(&mut self) -> Result<bool> {
        let q = self.inner.as_mut().ok_or(Error::Interrupted)?;
        q.creator()?;
        let result = (|| {
            if q.validated_preparation || q.failure.is_some() {
                return Err(Error::Interrupted);
            }
            if !q.preparation_bound {
                if let Some(p) = &q._provision_origin {
                    q.network.finish_operation(
                        p.inner
                            .as_ref()
                            .and_then(|p| p.completed.as_ref())
                            .ok_or(Error::Interrupted)?,
                    )?;
                }
                q.network.bind_cleanup_deadline(
                    vprouter_netfilter::BootDeadline::at(q.end).map_err(|_| Error::Deadline)?,
                    q.prepared
                        .as_ref()
                        .ok_or(Error::Interrupted)?
                        .timer_owner()
                        .map_err(mapped)?,
                )?;
                q.preparation_bound = true;
                q.readback = Some(q.network.start_down_readback(&q.original, q.end)?);
            }
            let Some(crate::native::ReadbackResult::Down(_)) = q
                .network
                .poll_readback(q.readback.as_mut().ok_or(Error::Interrupted)?)?
            else {
                return Ok(false);
            };
            q.readback.take();
            if let Some(p) = &q._provision_origin {
                p.inner
                    .as_ref()
                    .and_then(|p| p.completed.as_ref())
                    .ok_or(Error::Interrupted)?
                    .require_current()
                    .map_err(mapped)?;
            }
            end_instant(q.end)?;
            q.validated_preparation = true;
            Ok(true)
        })();
        if let Err(e) = result {
            q.fail(e);
        }
        result
    }
    fn get(&self) -> Result<&Query> {
        let q = self.inner.as_ref().ok_or(Error::Interrupted)?;
        q.creator()?;
        Ok(q)
    }
    /// Register these original selected pins and endpoints before birth. The
    /// caller retains those registrations alongside this entire pending owner.
    #[cfg(feature = "lab")]
    pub fn lab_parent_readback_pending(&self) -> Result<bool> {
        Ok(self.get()?.completed.is_some())
    }
    pub fn descriptors(&self) -> Result<Vec<BorrowedFd<'_>>> {
        let q = self.get()?;
        let mut fds = q.network.descriptors().to_vec();
        if let Some(prepared) = &q.prepared {
            fds.extend(prepared.descriptors().map_err(mapped)?);
        }
        if let Some(completed) = &q.completed {
            fds.extend(completed.descriptors().map_err(mapped)?);
        } else if let Some(child) = &q.child {
            fds.extend(child.descriptors().map_err(mapped)?);
        }
        Ok(fds)
    }
    pub fn child_endpoints_before_birth(&self) -> Result<[BorrowedFd<'_>; 2]> {
        Ok([
            self.child_channel_before_birth()?,
            self.child_gate_before_birth()?,
        ])
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
    pub fn birth(&mut self) -> Result<ReapWitness> {
        let q = self.inner.as_mut().ok_or(Error::Interrupted)?;
        q.creator()?;
        if !q.validated_preparation || q.failure.is_some() || q.child.is_some() {
            return Err(Error::Interrupted);
        }
        let prepared = q.prepared.take().ok_or(Error::Interrupted)?;
        match prepared.birth().map_err(mapped) {
            Err(error) => {
                q.fail(error);
                Err(error)
            }
            Ok(ForkOutcome::Child(role)) => run_query(q, role),
            Ok(ForkOutcome::Parent(child, receipt)) => {
                q.child = Some(child); // Before any fallible PID/start/registration work.
                Ok(receipt)
            }
        }
    }
    /// Called only after the owner has registered the freshly returned original
    /// pidfd. Failure leaves the complete born child in this pending object.
    pub fn identify(&mut self) -> Result<Birth> {
        let q = self.inner.as_mut().ok_or(Error::Interrupted)?;
        q.creator()?;
        let result = q
            .child
            .as_mut()
            .ok_or(Error::Interrupted)?
            .identify()
            .map_err(mapped);
        if let Err(error) = result {
            q.fail(error);
        }
        result
    }
    pub fn original_child(&self) -> Result<ReapWitness> {
        self.get()?
            .child
            .as_ref()
            .ok_or(Error::Interrupted)?
            .reap_witness()
            .map_err(mapped)
    }
    pub fn pidfd(&self) -> Result<BorrowedFd<'_>> {
        self.get()?
            .child
            .as_ref()
            .ok_or(Error::Interrupted)?
            .pidfd()
            .map_err(mapped)
    }
    pub fn cancel(&mut self, error: Error) {
        if let Some(q) = self.inner.as_mut() {
            q.fail(error);
        }
    }
    pub fn collect(&mut self) {
        if let Some(q) = self.inner.as_mut() {
            q.collect();
        }
    }
    pub fn poll(&mut self) -> Result<Option<VerifiedWireguardQuery>> {
        let q = self.inner.as_mut().ok_or(Error::Interrupted)?;
        q.creator()?;
        if let Some(error) = q.failure {
            q.collect();
            return Err(error);
        }
        let result = (|| {
            if q.completed.is_none() {
                let Some(completed) = q
                    .child
                    .as_mut()
                    .ok_or(Error::Interrupted)?
                    .poll()
                    .map_err(mapped)?
                else {
                    return Ok(false);
                };
                q.completed = Some(completed);
            }
            let completed = q.completed.as_ref().ok_or(Error::Interrupted)?;
            completed.require_current().map_err(mapped)?;
            if q.report.is_none() {
                let report: QueryReport =
                    serde_json::from_slice(completed.public_report().map_err(mapped)?)
                        .map_err(|_| Error::Malformed)?;
                q.network.accept_sequences(completed, report.sequences)?;
                q.report = Some(report);
                q.readback = Some(q.network.start_down_readback(&q.original, q.end)?);
            }
            let Some(crate::native::ReadbackResult::Down(current)) = q
                .network
                .poll_readback(q.readback.as_mut().ok_or(Error::Interrupted)?)?
            else {
                return Ok(false);
            };
            q.readback.take();
            let report = q.report.as_ref().ok_or(Error::Interrupted)?;
            if report.link != current || report.link != q.original.link {
                return Err(Error::Drifted);
            }
            q.network
                .check_public_wireguard(&report.wireguard, q.original.index())?;
            completed.require_current().map_err(mapped)?;
            end_instant(q.end)?;
            q.accepted_sequences = Some(q.network.sequences()?);
            q.accepted_at = Some(vprouter_core::health::boot_seconds());
            end_instant(q.end)?;
            Ok(true)
        })();
        match result {
            Ok(false) => Ok(None),
            Ok(true) => Ok(Some(VerifiedWireguardQuery {
                inner: self.inner.take(),
            })),
            Err(error) => {
                q.fail(error);
                Err(error)
            }
        }
    }
}
impl Drop for PendingWireguardQuery {
    fn drop(&mut self) {
        if let Some(mut q) = self.inner.take() {
            if q.creator != std::process::id() {
                std::mem::forget(q);
                return;
            }
            q.fail(Error::Interrupted);
            RETAINED.with(|r| r.borrow_mut().push(q));
        }
    }
}
/// Sealed actual-query receipt and original DOWN custody. This does not expose
/// a method accepting arbitrary public bytes or a foreign lower Completed.
pub struct VerifiedWireguardQuery {
    inner: Option<Query>,
}
impl VerifiedWireguardQuery {
    #[cfg(feature = "lab")]
    pub fn lab_query_sequences(&self) -> Result<[[u32; 2]; 2]> {
        let q = self.inner.as_ref().ok_or(Error::Interrupted)?;
        q.creator()?;
        if q.failure.is_some() || q.accepted_at.is_none() {
            return Err(Error::Interrupted);
        }
        Ok([
            q.report.as_ref().ok_or(Error::Interrupted)?.sequences,
            q.accepted_sequences.ok_or(Error::Interrupted)?,
        ])
    }
    pub fn link_observation(&self) -> Result<&Link> {
        self.observation()?;
        Ok(&self
            .inner
            .as_ref()
            .ok_or(Error::Interrupted)?
            .report
            .as_ref()
            .ok_or(Error::Interrupted)?
            .link)
    }
    pub fn observation(&self) -> Result<&Wireguard> {
        let q = self.inner.as_ref().ok_or(Error::Interrupted)?;
        q.creator()?;
        q.completed
            .as_ref()
            .ok_or(Error::Interrupted)?
            .require_current()
            .map_err(mapped)?;
        Ok(&q.report.as_ref().ok_or(Error::Interrupted)?.wireguard)
    }
    pub fn accepted_at(&self) -> Result<f64> {
        let q = self.inner.as_ref().ok_or(Error::Interrupted)?;
        q.creator()?;
        q.accepted_at.ok_or(Error::Interrupted)
    }
    pub fn original_child(&self) -> Result<ReapWitness> {
        let q = self.inner.as_ref().ok_or(Error::Interrupted)?;
        q.creator()?;
        q.completed
            .as_ref()
            .ok_or(Error::Interrupted)?
            .reap_witness()
            .map_err(mapped)
    }
}
impl Drop for VerifiedWireguardQuery {
    fn drop(&mut self) {
        if let Some(q) = self.inner.take() {
            if q.creator != std::process::id() {
                std::mem::forget(q);
                return;
            }
            RETAINED.with(|r| r.borrow_mut().push(q));
        }
    }
}
fn run_query(original: &Query, role: ConfinedWireguard) -> ! {
    let result = (|| {
        let mut network = original.network.confined(&role)?;
        let end = end_instant(role.deadline())?;
        let before = network.owned_down(&original.original, end)?;
        let wireguard = network.checked_wireguard(original.original.index(), end)?;
        let after = network.owned_down(&original.original, end)?;
        if before != after {
            return Err(Error::Drifted);
        }
        role.require().map_err(mapped)?;
        serde_json::to_vec(&QueryReport {
            sequences: network.sequences()?,
            link: after,
            wireguard,
        })
        .map_err(|_| Error::Malformed)
    })();
    // Raw Zeroizing receive/typed secret parser buffers have left scope before
    // sending a bounded public projection. No ordinary parent destructor runs.
    match result {
        Ok(bytes) => role.finish(&bytes),
        Err(_) => role.fail(),
    }
}
pub(crate) fn poll_retained() {
    veth::poll_retained();
    movement::poll_retained();
    sockets::poll_retained();
    provision::poll_retained();
    RETAINED.with(|r| {
        for q in r.borrow_mut().iter_mut() {
            q.collect();
        }
    });
    vprouter_native_role::poll_retained();
}
pub(crate) fn children_reaped() -> bool {
    if !veth::children_reaped() {
        return false;
    }
    sockets::children_reaped()
        && movement::children_reaped()
        && provision::children_reaped()
        && vprouter_native_role::retained_children_reaped()
        && RETAINED.with(|r| {
            r.borrow()
                .iter()
                .all(|q| q.creator != std::process::id() || q.reaped())
        })
}
