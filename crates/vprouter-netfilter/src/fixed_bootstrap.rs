//! Fixed Bootstrap transition of the SAME retained exclusive quarantine.
//! Original Source and canonical permission remain in launch. This returns only
//! own-child operation evidence, never SocketProducer/Enforcement/UP/READY.
use crate::{BootDeadline, Error, Result, VerifiedInitialQuarantine, VerifiedProducerObservation};
use std::{cell::RefCell, os::fd::BorrowedFd};
use vprouter_native_role::{
    Birth, ConfinedProducerBootstrap, PreparedProducerBootstrap, ProducerBootstrapChild,
    ProducerBootstrapCompleted, ProducerBootstrapDescriptors, ProducerBootstrapFork,
    ProducerDescriptors, ReapWitness, WireguardChildGate,
};
fn mapped(e: vprouter_native_role::Error) -> Error {
    if e == vprouter_native_role::Error::Deadline {
        Error::Deadline
    } else {
        Error::Interrupted
    }
}
type Pins = [(u64, u64, u32); 6];
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Report {
    namespace: (u64, u64),
    policy: [u8; 32],
    pins: Pins,
    sequences: [u32; 2],
    observed_at: f64,
}

enum Origin {
    Initial(Box<VerifiedInitialQuarantine>),
    Observed(Box<VerifiedProducerObservation>),
}
impl Origin {
    fn binding_actuator(&self) -> Result<&crate::Actuator> {
        match self {
            Self::Initial(v) => v.binding_actuator(),
            Self::Observed(v) => v.bootstrap_actuator(),
        }
    }
    fn binding_namespace(&self) -> Result<BorrowedFd<'_>> {
        match self {
            Self::Initial(v) => v.binding_namespace(),
            Self::Observed(v) => v.bootstrap_namespace(),
        }
    }
    fn namespace_identity(&self) -> Result<(u64, u64)> {
        Ok(self.binding_actuator()?.namespace())
    }
    fn begin_bootstrap(
        &mut self,
        end: BootDeadline,
        timer: std::sync::Arc<std::os::fd::OwnedFd>,
    ) -> Result<()> {
        match self {
            Self::Initial(v) => v.begin_bootstrap(end, timer),
            Self::Observed(v) => v.begin_bootstrap(end, timer),
        }
    }
    fn accept_bootstrap(&mut self, c: &ProducerBootstrapCompleted, seq: [u32; 2]) -> Result<()> {
        match self {
            Self::Initial(v) => v.accept_bootstrap(c, seq),
            Self::Observed(v) => v.accept_bootstrap(c, seq),
        }
    }
    fn confined_bootstrap(&self, role: &ConfinedProducerBootstrap) -> Result<crate::Actuator> {
        match self {
            Self::Initial(v) => v.confined_bootstrap(role),
            Self::Observed(v) => v.confined_bootstrap(role),
        }
    }
}

struct Native {
    creator: u32,
    origin: Origin,
    policy: [u8; 32],
    pins: Pins,
    end: f64,
    prepared: Option<PreparedProducerBootstrap>,
    child: Option<ProducerBootstrapChild>,
    completed: Option<ProducerBootstrapCompleted>,
    validated: bool,
    failure: Option<Error>,
    accepted_at: Option<f64>,
    observed_at: Option<f64>,
    sequences: Option<[u32; 2]>,
}
impl Native {
    fn creator(&self) -> Result<()> {
        if self.creator != std::process::id() || !vprouter_core::secret_boundary::pristine() {
            Err(Error::Foreign)
        } else {
            Ok(())
        }
    }
    fn fail(&mut self, e: Error) {
        if self.creator == std::process::id() {
            self.failure.get_or_insert(e);
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
                    .and_then(|w| w.actual_status())
                    .is_ok_and(|s| s.is_some())
            })
    }
}
thread_local! {#[allow(clippy::vec_box)] static RETAINED:RefCell<Vec<Box<Native>>>=const{RefCell::new(Vec::new())};}
fn retain(mut n: Box<Native>) {
    if n.creator != std::process::id() {
        std::mem::forget(n);
        return;
    }
    n.fail(Error::Interrupted);
    RETAINED.with(|r| r.borrow_mut().push(n));
}
pub struct PendingBootstrap {
    inner: Option<Box<Native>>,
}
pub struct VerifiedBootstrap {
    inner: Option<Box<Native>>,
}
impl Drop for PendingBootstrap {
    fn drop(&mut self) {
        if let Some(n) = self.inner.take() {
            retain(n);
        }
    }
}
impl Drop for VerifiedBootstrap {
    fn drop(&mut self) {
        if let Some(n) = self.inner.take() {
            retain(n);
        }
    }
}
impl PendingBootstrap {
    /// Trusted launch retains original Source, canonical gates and registrations.
    /// This constructor consumes only its own original exclusive initial owner.
    pub fn prepare_initial(
        slot: &mut Option<VerifiedInitialQuarantine>,
        producer: ProducerDescriptors<'_>,
        ancestry: vprouter_native_role::ProducerAncestryDescriptors<'_>,
        digest: [u8; 32],
        end: f64,
        gate: WireguardChildGate,
    ) -> Result<Self> {
        let origin = slot.as_ref().ok_or(Error::Interrupted)?;
        if origin.binding_actuator()?.policy().scope() == crate::Scope::Data {
            return Err(Error::Foreign);
        }
        Self::prepare(
            Origin::Initial(Box::new(slot.take().ok_or(Error::Interrupted)?)),
            producer,
            ancestry,
            digest,
            end,
            gate,
        )
    }
    pub fn prepare_observed(
        slot: &mut Option<VerifiedProducerObservation>,
        producer: ProducerDescriptors<'_>,
        ancestry: vprouter_native_role::ProducerAncestryDescriptors<'_>,
        digest: [u8; 32],
        end: f64,
        gate: WireguardChildGate,
    ) -> Result<(Self, crate::ProducerObservationContinuation)> {
        let origin = slot.as_ref().ok_or(Error::Interrupted)?;
        if origin.bootstrap_actuator()?.policy().scope() != crate::Scope::Data {
            return Err(Error::Foreign);
        }
        let continuity = origin.bootstrap_continuation()?;
        let pending = Self::prepare(
            Origin::Observed(Box::new(slot.take().ok_or(Error::Interrupted)?)),
            producer,
            ancestry,
            digest,
            end,
            gate,
        )?;
        Ok((pending, continuity))
    }
    fn prepare(
        origin: Origin,
        producer: ProducerDescriptors<'_>,
        ancestry: vprouter_native_role::ProducerAncestryDescriptors<'_>,
        digest: [u8; 32],
        end: f64,
        gate: WireguardChildGate,
    ) -> Result<Self> {
        // Own the complete original before any native check or new preparation.
        let mut value = Self {
            inner: Some(Box::new(Native {
                creator: std::process::id(),
                origin,
                policy: [0; 32],
                pins: [(0, 0, 0); 6],
                end,
                prepared: None,
                child: None,
                completed: None,
                validated: false,
                failure: None,
                accepted_at: None,
                observed_at: None,
                sequences: None,
            })),
        };
        let n = value.inner.as_mut().ok_or(Error::Interrupted)?;
        BootDeadline::at(end)?.check()?;
        if RETAINED.with(|r| {
            r.borrow()
                .iter()
                .filter(|n| n.creator == std::process::id())
                .count()
        }) >= 64
        {
            return Err(Error::Oversized);
        }
        n.policy = n.origin.binding_actuator()?.policy().initial_digest()?;
        let fds = [
            producer.parent,
            producer.group,
            producer.procs,
            producer.events,
            producer.kind,
            producer.subtree,
        ];
        for (fd, pin) in fds.into_iter().zip(&mut n.pins) {
            let s = rustix::fs::fstat(fd).map_err(|_| Error::Foreign)?;
            *pin = (s.st_dev, s.st_ino, s.st_mode);
        }
        if n.pins[0].0 != n.pins[1].0 || n.pins[0].1 == n.pins[1].1 {
            return Err(Error::Foreign);
        }
        let [main, emergency] = n.origin.binding_actuator()?.descriptors();
        n.prepared = Some(
            PreparedProducerBootstrap::new(
                ProducerBootstrapDescriptors {
                    main,
                    emergency,
                    namespace: n.origin.binding_namespace()?,
                    producer,
                    ancestry,
                },
                digest,
                end,
                gate,
            )
            .map_err(mapped)?,
        );
        // The complete prepared owner must reach launch registration before
        // further fallible validation; validate_prepared checks this same end.
        Ok(value)
    }
    fn get(&self) -> Result<&Native> {
        let n = self.inner.as_ref().ok_or(Error::Interrupted)?;
        n.creator()?;
        Ok(n)
    }
    pub fn descriptors(&self) -> Result<Vec<BorrowedFd<'_>>> {
        let n = self.get()?;
        let mut fds = n.origin.binding_actuator()?.descriptors().to_vec();
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
        self.get()?
            .prepared
            .as_ref()
            .ok_or(Error::Interrupted)?
            .child_endpoints()
            .map_err(mapped)
    }
    /// Whole original owner and every registration must be stored by launch
    /// before this first mutation of the original sockets' operation timers.
    pub fn validate_prepared(&mut self) -> Result<()> {
        let n = self.inner.as_mut().ok_or(Error::Interrupted)?;
        n.creator()?;
        let answer = (|| {
            if n.validated || n.failure.is_some() {
                return Err(Error::Interrupted);
            }
            let p = n.prepared.as_ref().ok_or(Error::Interrupted)?;
            n.origin
                .begin_bootstrap(BootDeadline::at(n.end)?, p.timer_owner().map_err(mapped)?)?;
            BootDeadline::at(n.end)?.check()?;
            n.validated = true;
            Ok(())
        })();
        if let Err(e) = answer {
            n.fail(e);
        }
        answer
    }
    pub fn birth(&mut self) -> Result<ReapWitness> {
        let n = self.inner.as_mut().ok_or(Error::Interrupted)?;
        n.creator()?;
        if !n.validated || n.failure.is_some() || n.child.is_some() {
            return Err(Error::Interrupted);
        }
        match n
            .prepared
            .take()
            .ok_or(Error::Interrupted)?
            .birth()
            .map_err(mapped)
        {
            Ok(ProducerBootstrapFork::Parent(child, original)) => {
                n.child = Some(child);
                Ok(original)
            }
            Ok(ProducerBootstrapFork::Child(role)) => run(n, role),
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
    pub fn identify(&mut self) -> Result<Birth> {
        let n = self.inner.as_mut().ok_or(Error::Interrupted)?;
        n.creator()?;
        n.child
            .as_mut()
            .ok_or(Error::Interrupted)?
            .identify()
            .map_err(mapped)
    }
    pub fn cancel(&mut self, e: Error) {
        if let Some(n) = &mut self.inner {
            n.fail(e);
        }
    }
    pub fn collect(&mut self) {
        if let Some(n) = &mut self.inner {
            n.collect();
        }
    }
    pub fn poll(&mut self) -> Result<Option<VerifiedBootstrap>> {
        let n = self.inner.as_mut().ok_or(Error::Interrupted)?;
        n.creator()?;
        if let Some(e) = n.failure {
            n.collect();
            return Err(e);
        }
        let answer = (|| {
            BootDeadline::at(n.end)?.check()?;
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
            let report: Report = serde_json::from_slice(c.public_report().map_err(mapped)?)
                .map_err(|_| Error::Malformed)?;
            let birth = c.birth().map_err(mapped)?;
            if report.namespace != n.origin.namespace_identity()?
                || report.policy != n.policy
                || report.pins != n.pins
                || !report.observed_at.is_finite()
                || report.observed_at < birth.born_at
                || report.observed_at > c.child_reported_at().map_err(mapped)?
                || report.observed_at >= n.end
            {
                return Err(Error::Foreign);
            }
            n.origin.accept_bootstrap(c, report.sequences)?;
            c.require_current().map_err(mapped)?;
            n.sequences = Some(n.origin.binding_actuator()?.initial_sequences()?);
            n.observed_at = Some(report.observed_at);
            n.accepted_at = Some(vprouter_core::health::boot_seconds());
            BootDeadline::at(n.end)?.check()?;
            Ok(true)
        })();
        match answer {
            Ok(false) => Ok(None),
            Ok(true) => Ok(Some(VerifiedBootstrap {
                inner: self.inner.take(),
            })),
            Err(e) => {
                n.fail(e);
                Err(e)
            }
        }
    }
}
fn observe_group(role: &ConfinedProducerBootstrap, expected: &Pins) -> Result<()> {
    role.require().map_err(mapped)?;
    let fds = role.producer_owners().map_err(mapped)?;
    for (i, (fd, expected)) in fds.iter().zip(expected).enumerate() {
        let s = rustix::fs::fstat(fd).map_err(|_| Error::Foreign)?;
        if (s.st_dev, s.st_ino, s.st_mode) != *expected
            || s.st_uid != 0
            || s.st_gid != 0
            || rustix::fs::fstatfs(fd).map_err(|_| Error::Foreign)?.f_type as u64 != 0x63677270
            || (i == 1 && s.st_mode & 0o7777 != 0o700)
        {
            return Err(Error::Foreign);
        }
    }
    for (index, fd) in fds[2..].iter().enumerate() {
        let mut bytes = [0u8; 4097];
        let count = rustix::io::pread(fd, &mut bytes, 0).map_err(|_| Error::Io)?;
        if count > 4096 {
            return Err(Error::Oversized);
        }
        let text = std::str::from_utf8(&bytes[..count]).map_err(|_| Error::Malformed)?;
        let valid = match index {
            0 | 3 => text.trim().is_empty(),
            1 => text.lines().eq(["populated 0", "frozen 0"]),
            2 => text.trim() == "domain",
            _ => false,
        };
        if !valid {
            return Err(Error::Drifted);
        }
        role.require().map_err(mapped)?;
    }
    Ok(())
}
fn run(n: &Native, role: ConfinedProducerBootstrap) -> ! {
    let answer = (|| {
        observe_group(&role, &n.pins)?;
        let mut a = n.origin.confined_bootstrap(&role)?;
        a.verify_initial_quarantine()?;
        observe_group(&role, &n.pins)?;
        a.install_original_bootstrap_permit()?;
        a.install_bootstrap()?;
        a.verify_bootstrap_observation()?;
        observe_group(&role, &n.pins)?;
        a.verify_bootstrap_observation()?;
        let observed_at = vprouter_core::health::boot_seconds();
        role.require().map_err(mapped)?;
        serde_json::to_vec(&Report {
            namespace: a.namespace(),
            policy: n.policy,
            pins: n.pins,
            sequences: a.initial_sequences()?,
            observed_at,
        })
        .map_err(|_| Error::Malformed)
    })();
    match answer {
        Ok(bytes) => role.finish(&bytes),
        Err(_) => role.fail(),
    }
}
impl VerifiedBootstrap {
    fn get(&self) -> Result<&Native> {
        let n = self.inner.as_ref().ok_or(Error::Interrupted)?;
        n.creator()?;
        n.completed
            .as_ref()
            .ok_or(Error::Interrupted)?
            .require_retained()
            .map_err(mapped)?;
        if n.failure.is_some() {
            return Err(Error::Interrupted);
        }
        Ok(n)
    }
    pub fn original_child(&self) -> Result<ReapWitness> {
        self.get()?
            .completed
            .as_ref()
            .ok_or(Error::Interrupted)?
            .original_child()
            .map_err(mapped)
    }
    pub fn accepted_at(&self) -> Result<f64> {
        self.get()?.accepted_at.ok_or(Error::Interrupted)
    }
    pub fn observed_at(&self) -> Result<f64> {
        self.get()?.observed_at.ok_or(Error::Interrupted)
    }
    pub fn identities(&self) -> Result<[(u64, u64); 6]> {
        Ok(self.get()?.pins.map(|p| (p.0, p.1)))
    }
    pub fn namespace_identity(&self) -> Result<(u64, u64)> {
        self.get()?.origin.namespace_identity()
    }
    pub fn policy_digest(&self) -> Result<[u8; 32]> {
        Ok(self.get()?.policy)
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
