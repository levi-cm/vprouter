//! One fixed native creation, private-profile reload, SetDevice and readback.
//! The launch kernel retains the DISTINCT release gate and canonical intent.
use super::{QueryReport, end_instant, mapped, profiles::Profiles};
use crate::{DownLink, Error, NativeNetwork, Result, Wireguard};
use std::{cell::RefCell, os::fd::BorrowedFd};
use vprouter_core::config::PublicConfiguration;
use vprouter_native_role::{
    Birth, Completed, ConfinedWireguard, ForkOutcome, PreparedWireguard, ReapWitness,
    WireguardChild, WireguardChildGate, WireguardDescriptors,
};

pub(super) struct Provision {
    _socket_origin: Option<super::VerifiedSocketPreparation>,
    creator: u32,
    pub(super) network: Option<NativeNetwork>,
    profiles: Profiles,
    prepared: Option<PreparedWireguard>,
    child: Option<WireguardChild>,
    pub(super) completed: Option<Completed>,
    pub(super) down: Option<DownLink>,
    report: Option<QueryReport>,
    accepted_at: Option<f64>,
    end: f64,
    failure: Option<Error>,
    validated_preparation: bool,
    preparation_bound: bool,
    readback: Option<crate::native::Readback>,
    read_phase: u8,
    #[cfg(feature = "lab")]
    parent_stage: u8,
}
impl Provision {
    pub(super) fn creator(&self) -> Result<()> {
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
        if let Some(completed) = &self.completed {
            return completed.reap_witness().and_then(|r| r.actual_status()) == Ok(Some(0));
        }
        self.child.as_ref().is_none_or(|child| {
            child
                .reap_witness()
                .and_then(|r| r.actual_status())
                .ok()
                .flatten()
                .is_some()
        })
    }
}
thread_local! {static RETAINED:RefCell<Vec<Provision>>=const{RefCell::new(Vec::new())};}

pub struct PendingWireguardProvision {
    inner: Option<Provision>,
}
impl PendingWireguardProvision {
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_from_original_sockets(
        sockets: &mut Option<super::VerifiedSocketPreparation>,
        namespace: BorrowedFd<'_>,
        public: &PublicConfiguration,
        member: &str,
        inputs: &[(String, BorrowedFd<'_>)],
        request_digest: [u8; 32],
        original_end: f64,
        child_gate: WireguardChildGate,
    ) -> Result<Self> {
        let original = sockets.as_mut().ok_or(Error::Interrupted)?;
        let mut pending = Self::prepare(
            original.network_slot()?,
            namespace,
            public,
            member,
            inputs,
            request_digest,
            original_end,
            child_gate,
        )?;
        // Remaining checks run only after launch owns/registers this Pending.
        pending
            .inner
            .as_mut()
            .ok_or(Error::Interrupted)?
            ._socket_origin = sockets.take();
        Ok(pending)
    }
    /// Prepare without reading any profile. A prior durable creation intent is
    /// launch-owned. All original inputs remain in caller slots on rejection.
    /// The caller's separate parent gate never enters this object or inventory.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare(
        network_slot: &mut Option<NativeNetwork>,
        namespace: BorrowedFd<'_>,
        public: &PublicConfiguration,
        member: &str,
        inputs: &[(String, BorrowedFd<'_>)],
        request_digest: [u8; 32],
        original_end: f64,
        child_gate: WireguardChildGate,
    ) -> Result<Self> {
        if RETAINED.with(|r| {
            r.borrow()
                .iter()
                .filter(|p| p.creator == std::process::id())
                .count()
        }) >= 64
        {
            return Err(Error::Oversized);
        }
        let network = network_slot.as_mut().ok_or(Error::Interrupted)?;
        if !vprouter_core::secret_boundary::pristine() || network.plan.allocation.exit_id != member
        {
            return Err(Error::Foreign);
        }
        let profile = public
            .exits()
            .iter()
            .find(|e| e.exit().id == member)
            .and_then(|e| e.profile())
            .ok_or(Error::InvalidInput)?;
        if profile.device_public_key() != network.plan.public_key
            || profile.peer_public_key() != &network.plan.peer
            || profile.endpoint() != network.plan.endpoint
            || profile.address() != network.plan.address
        {
            return Err(Error::Foreign);
        }
        let ns = rustix::fs::fstat(namespace).map_err(|_| Error::NamespaceUnverified)?;
        if (ns.st_dev, ns.st_ino) != network.namespace {
            return Err(Error::NamespaceUnverified);
        }
        let profiles = Profiles::pin(public, member, inputs)?;
        let selected = profiles.descriptors()?;
        let [route, generic] = network.descriptors();
        let prepared = PreparedWireguard::new(
            WireguardDescriptors {
                profiles: &selected,
                route,
                generic,
                namespace,
            },
            request_digest,
            original_end,
            child_gate,
        )
        .map_err(mapped)?;
        Ok(Self {
            inner: Some(Provision {
                _socket_origin: None,
                creator: std::process::id(),
                network: Some(network_slot.take().ok_or(Error::Interrupted)?),
                profiles,
                prepared: Some(prepared),
                child: None,
                completed: None,
                down: None,
                report: None,
                accepted_at: None,
                end: original_end,
                failure: None,
                validated_preparation: false,
                preparation_bound: false,
                readback: None,
                read_phase: 0,
                #[cfg(feature = "lab")]
                parent_stage: 0,
            }),
        })
    }
    /// Launch has stored and registered the whole prepared bundle before this
    /// may attach a timer or perform native readback. Every error stays owned.
    pub fn validate_prepared(&mut self) -> Result<bool> {
        let p = self.inner.as_mut().ok_or(Error::Interrupted)?;
        p.creator()?;
        let result = (|| {
            if p.validated_preparation || p.failure.is_some() {
                return Err(Error::Interrupted);
            }
            let network = p.network.as_mut().ok_or(Error::Interrupted)?;
            if !p.preparation_bound {
                network.bind_cleanup_deadline(
                    vprouter_netfilter::BootDeadline::at(p.end).map_err(|_| Error::Deadline)?,
                    p.prepared
                        .as_ref()
                        .ok_or(Error::Interrupted)?
                        .timer_owner()
                        .map_err(mapped)?,
                )?;
                p.preparation_bound = true;
                p.readback =
                    Some(network.start_absent_readback(network.plan.wireguard_name(), p.end)?);
            }
            let Some(crate::native::ReadbackResult::Absent) =
                network.poll_readback(p.readback.as_mut().ok_or(Error::Interrupted)?)?
            else {
                return Ok(false);
            };
            p.readback.take();
            p.profiles.verify_parent()?;
            end_instant(p.end)?;
            if let Some(origin) = &p._socket_origin {
                origin.require_current()?;
            }
            p.validated_preparation = true;
            Ok(true)
        })();
        if let Err(e) = result {
            p.fail(e);
        }
        result
    }
    fn get(&self) -> Result<&Provision> {
        let p = self.inner.as_ref().ok_or(Error::Interrupted)?;
        p.creator()?;
        Ok(p)
    }
    #[cfg(feature = "lab")]
    pub fn lab_parent_readback_pending(&self) -> Result<bool> {
        Ok(self.get()?.completed.is_some())
    }
    pub fn descriptors(&self) -> Result<Vec<BorrowedFd<'_>>> {
        let p = self.get()?;
        let mut fds = p
            .network
            .as_ref()
            .ok_or(Error::Interrupted)?
            .descriptors()
            .to_vec();
        fds.extend(p.profiles.descriptors()?);
        if let Some(prepared) = &p.prepared {
            fds.extend(prepared.descriptors().map_err(mapped)?);
        }
        if let Some(completed) = &p.completed {
            fds.extend(completed.descriptors().map_err(mapped)?);
        } else if let Some(child) = &p.child {
            fds.extend(child.descriptors().map_err(mapped)?);
        }
        Ok(fds)
    }
    pub fn child_endpoints_before_birth(&self) -> Result<[BorrowedFd<'_>; 2]> {
        let p = self.get()?.prepared.as_ref().ok_or(Error::Interrupted)?;
        Ok([
            p.child_channel().map_err(mapped)?,
            p.child_gate().map_err(mapped)?,
        ])
    }
    /// Launch registers the entire prepared set before this call. The original
    /// parent outcome is stored BEFORE any fallible PID/start or result work.
    pub fn birth(&mut self) -> Result<ReapWitness> {
        let p = self.inner.as_mut().ok_or(Error::Interrupted)?;
        p.creator()?;
        p.profiles.verify_parent()?;
        if !p.validated_preparation || p.failure.is_some() || p.child.is_some() {
            return Err(Error::Interrupted);
        }
        let prepared = p.prepared.take().ok_or(Error::Interrupted)?;
        match prepared.birth().map_err(mapped) {
            Err(error) => {
                p.fail(error);
                Err(error)
            }
            Ok(ForkOutcome::Child(role)) => run(p, role),
            Ok(ForkOutcome::Parent(child, receipt)) => {
                p.child = Some(child);
                Ok(receipt)
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
            .reap_witness()
            .map_err(mapped)
    }
    pub fn identify(&mut self) -> Result<Birth> {
        let p = self.inner.as_mut().ok_or(Error::Interrupted)?;
        p.creator()?;
        let result = p
            .child
            .as_mut()
            .ok_or(Error::Interrupted)?
            .identify()
            .map_err(mapped);
        if let Err(error) = result {
            p.fail(error);
        }
        result
    }
    pub fn cancel(&mut self, error: Error) {
        if let Some(p) = self.inner.as_mut() {
            p.fail(error);
        }
    }
    pub fn collect(&mut self) {
        if let Some(p) = self.inner.as_mut() {
            p.collect();
        }
    }
    #[cfg(feature = "lab")]
    pub fn lab_failure(
        &self,
    ) -> Result<(u8, Option<Error>, Option<vprouter_native_role::LabFailure>)> {
        let p = self.inner.as_ref().ok_or(Error::Interrupted)?;
        p.creator()?;
        Ok((
            p.parent_stage,
            p.failure,
            p.child
                .as_ref()
                // Completed owns the original child after success; an empty
                // child wrapper must not hide a later parent acceptance phase.
                .and_then(|c| c.lab_failure().ok())
                .flatten(),
        ))
    }
    pub fn poll(&mut self) -> Result<Option<VerifiedWireguardProvision>> {
        let p = self.inner.as_mut().ok_or(Error::Interrupted)?;
        p.creator()?;
        if let Some(error) = p.failure {
            p.collect();
            return Err(error);
        }
        let result = (|| {
            if p.completed.is_none() {
                #[cfg(feature = "lab")]
                {
                    p.parent_stage = 1;
                }
                let Some(c) = p
                    .child
                    .as_mut()
                    .ok_or(Error::Interrupted)?
                    .poll()
                    .map_err(mapped)?
                else {
                    return Ok(false);
                };
                p.completed = Some(c);
            }
            let completed = p.completed.as_ref().ok_or(Error::Interrupted)?;
            #[cfg(feature = "lab")]
            {
                p.parent_stage = 2;
            }
            completed.require_current().map_err(mapped)?;
            p.profiles.verify_parent()?;
            let network = p.network.as_mut().ok_or(Error::Interrupted)?;
            if p.report.is_none() {
                #[cfg(feature = "lab")]
                {
                    p.parent_stage = 4;
                }
                let report: QueryReport =
                    serde_json::from_slice(completed.public_report().map_err(mapped)?)
                        .map_err(|_| Error::Malformed)?;
                network.accept_sequences(completed, report.sequences)?;
                p.report = Some(report);
                p.readback = Some(network.start_token_readback(
                    network.plan.wireguard_name(),
                    "wireguard",
                    p.end,
                )?);
            }
            if p.read_phase == 0 {
                #[cfg(feature = "lab")]
                {
                    p.parent_stage = 6;
                }
                let Some(crate::native::ReadbackResult::Token(down)) =
                    network.poll_readback(p.readback.as_mut().ok_or(Error::Interrupted)?)?
                else {
                    return Ok(false);
                };
                p.readback.take();
                p.down = Some(down);
                p.read_phase = 1;
                p.readback = Some(
                    network
                        .start_down_readback(p.down.as_ref().ok_or(Error::Interrupted)?, p.end)?,
                );
                return Ok(false);
            }
            #[cfg(feature = "lab")]
            {
                p.parent_stage = 7;
            }
            let Some(crate::native::ReadbackResult::Down(_)) =
                network.poll_readback(p.readback.as_mut().ok_or(Error::Interrupted)?)?
            else {
                return Ok(false);
            };
            p.readback.take();
            let down = p.down.as_ref().ok_or(Error::Interrupted)?;
            let report = p.report.as_ref().ok_or(Error::Interrupted)?;
            if report.link != down.link {
                return Err(Error::Drifted);
            }
            #[cfg(feature = "lab")]
            {
                p.parent_stage = 9;
            }
            network.check_public_wireguard(&report.wireguard, down.index())?;
            completed.require_current().map_err(mapped)?;
            #[cfg(feature = "lab")]
            {
                p.parent_stage = 10;
            }
            p.accepted_at = Some(vprouter_core::health::boot_seconds());
            end_instant(p.end)?;
            Ok(true)
        })();
        match result {
            Ok(false) => Ok(None),
            Ok(true) => Ok(Some(VerifiedWireguardProvision {
                inner: self.inner.take(),
            })),
            Err(error) => {
                p.fail(error);
                Err(error)
            }
        }
    }
}
impl Drop for PendingWireguardProvision {
    fn drop(&mut self) {
        if let Some(mut p) = self.inner.take() {
            if p.creator != std::process::id() {
                std::mem::forget(p);
                return;
            }
            p.fail(Error::Interrupted);
            RETAINED.with(|r| r.borrow_mut().push(p));
        }
    }
}
/// Exact native provision completion; still no canonical Result persistence,
/// movement, UP permission, namespace cleanup or ordinary resource reuse.
pub struct VerifiedWireguardProvision {
    pub(super) inner: Option<Provision>,
}
impl VerifiedWireguardProvision {
    pub fn link_observation(&self) -> Result<&crate::Link> {
        self.down()?;
        self.inner
            .as_ref()
            .and_then(|p| p.report.as_ref())
            .map(|r| &r.link)
            .ok_or(Error::Interrupted)
    }
    pub fn down(&self) -> Result<&DownLink> {
        let p = self.inner.as_ref().ok_or(Error::Interrupted)?;
        p.creator()?;
        p.completed
            .as_ref()
            .ok_or(Error::Interrupted)?
            .require_current()
            .map_err(mapped)?;
        p.down.as_ref().ok_or(Error::Interrupted)
    }
    pub fn observation(&self) -> Result<&Wireguard> {
        let p = self.inner.as_ref().ok_or(Error::Interrupted)?;
        p.creator()?;
        p.completed
            .as_ref()
            .ok_or(Error::Interrupted)?
            .require_current()
            .map_err(mapped)?;
        Ok(&p.report.as_ref().ok_or(Error::Interrupted)?.wireguard)
    }
    pub fn accepted_at(&self) -> Result<f64> {
        let p = self.inner.as_ref().ok_or(Error::Interrupted)?;
        p.creator()?;
        p.accepted_at.ok_or(Error::Interrupted)
    }
    pub fn original_child(&self) -> Result<ReapWitness> {
        let p = self.inner.as_ref().ok_or(Error::Interrupted)?;
        p.creator()?;
        p.completed
            .as_ref()
            .ok_or(Error::Interrupted)?
            .reap_witness()
            .map_err(mapped)
    }
}
impl Drop for VerifiedWireguardProvision {
    fn drop(&mut self) {
        if let Some(p) = self.inner.take() {
            if p.creator != std::process::id() {
                std::mem::forget(p);
                return;
            }
            RETAINED.with(|r| r.borrow_mut().push(p));
        }
    }
}
fn run(original: &Provision, role: ConfinedWireguard) -> ! {
    let result = (|| {
        #[cfg(feature = "lab")]
        role.lab_stage(1);
        let validated = original.profiles.load(&role)?;
        #[cfg(feature = "lab")]
        role.lab_stage(2);
        let profile = validated
            .exits()
            .iter()
            .find(|e| e.exit().id == original.profiles.member())
            .and_then(|e| e.profile())
            .ok_or(Error::InvalidInput)?;
        #[cfg(feature = "lab")]
        role.lab_stage(3);
        let mut network = original
            .network
            .as_ref()
            .ok_or(Error::Interrupted)?
            .confined(&role)?;
        #[cfg(feature = "lab")]
        let down = network.create_wireguard_down_profiled(
            profile,
            end_instant(role.deadline())?,
            |stage| role.lab_stage(stage),
        )?;
        #[cfg(not(feature = "lab"))]
        let down = network.create_wireguard_down_until(profile, end_instant(role.deadline())?)?;
        #[cfg(feature = "lab")]
        role.lab_stage(21);
        let wireguard = network.checked_wireguard(down.index(), end_instant(role.deadline())?)?;
        #[cfg(feature = "lab")]
        role.lab_stage(22);
        let link = network.owned_down(&down, end_instant(role.deadline())?)?;
        #[cfg(feature = "lab")]
        role.lab_stage(23);
        role.require().map_err(mapped)?;
        // Drop all key-bearing profiles before even encoding the public receipt.
        drop(validated);
        #[cfg(feature = "lab")]
        role.lab_stage(24);
        serde_json::to_vec(&QueryReport {
            sequences: network.sequences()?,
            link,
            wireguard,
        })
        .map_err(|_| Error::Malformed)
    })();
    match result {
        Ok(bytes) => role.finish(&bytes),
        Err(error) => {
            #[cfg(feature = "lab")]
            {
                let (code, errno) = match error {
                    Error::InvalidInput => (1, 0),
                    Error::Foreign => (2, 0),
                    Error::Drifted => (3, 0),
                    Error::Absent => (4, 0),
                    Error::Unsupported => (5, 0),
                    Error::Malformed => (6, 0),
                    Error::Oversized => (7, 0),
                    Error::Deadline => (8, 0),
                    Error::SocketUnavailable => (9, 0),
                    Error::Io => (10, 0),
                    Error::KernelRejected => (11, 0),
                    Error::KernelErrno(e) => (12, e),
                    Error::SequenceMismatch => (13, 0),
                    Error::SenderMismatch => (14, 0),
                    Error::Interrupted => (15, 0),
                    Error::NamespaceUnverified => (16, 0),
                    _ => (31, 0),
                };
                role.lab_fail(code, errno)
            }
            #[cfg(not(feature = "lab"))]
            {
                let _ = error;
                role.fail()
            }
        }
    }
}
pub(super) fn poll_retained() {
    RETAINED.with(|r| {
        for p in r.borrow_mut().iter_mut() {
            p.collect();
        }
    });
}
pub(super) fn children_reaped() -> bool {
    RETAINED.with(|r| {
        r.borrow()
            .iter()
            .all(|p| p.creator != std::process::id() || p.reaped())
    })
}
