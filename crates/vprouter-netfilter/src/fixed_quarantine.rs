//! Initial exclusive quarantine only, from this owner's original two sockets.
//! No permit, bootstrap, release, cleanup, or external completion constructor.
use crate::{Actuator, BootDeadline, Error, Result, VerifiedNetfilterSockets};
use std::{cell::RefCell, os::fd::BorrowedFd};
use vprouter_native_role::{
    Birth, ConfinedNetfilter, NetfilterChild, NetfilterCompleted, NetfilterDescriptors,
    NetfilterFork, PreparedNetfilter, ReapWitness, WireguardChildGate,
};
fn mapped(e: vprouter_native_role::Error) -> Error {
    if e == vprouter_native_role::Error::Deadline {
        Error::Deadline
    } else {
        Error::Interrupted
    }
}
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Report {
    namespace: (u64, u64),
    policy: [u8; 32],
    sequences: [u32; 2],
    observed_at: f64,
}
struct Native {
    creator: u32,
    _origin: VerifiedNetfilterSockets,
    actuator: Actuator,
    policy: [u8; 32],
    end: f64,
    prepared: Option<PreparedNetfilter>,
    child: Option<NetfilterChild>,
    completed: Option<NetfilterCompleted>,
    failure: Option<Error>,
    validated: bool,
    accepted_at: Option<f64>,
    observed_at: Option<f64>,
    accepted_sequences: Option<[u32; 2]>,
    binding_started: bool,
    bootstrap_started: bool,
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
thread_local! {static RETAINED:RefCell<Vec<Native>>=const{RefCell::new(Vec::new())};}
fn retain(mut n: Native) {
    if n.creator != std::process::id() {
        std::mem::forget(n);
        return;
    }
    n.fail(Error::Interrupted);
    RETAINED.with(|r| r.borrow_mut().push(n));
}
pub struct PendingInitialQuarantine {
    inner: Option<Native>,
}
pub struct VerifiedInitialQuarantine {
    inner: Option<Native>,
}
impl Drop for PendingInitialQuarantine {
    fn drop(&mut self) {
        if let Some(n) = self.inner.take() {
            retain(n);
        }
    }
}
impl Drop for VerifiedInitialQuarantine {
    fn drop(&mut self) {
        if let Some(n) = self.inner.take() {
            retain(n);
        }
    }
}
impl PendingInitialQuarantine {
    pub fn prepare(
        slot: &mut Option<VerifiedNetfilterSockets>,
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
        BootDeadline::at(end)?.check()?;
        let original = slot.as_ref().ok_or(Error::Interrupted)?;
        let a = original.original_actuator()?;
        let policy = a.policy().initial_digest()?;
        let [main, emergency] = a.descriptors();
        let p = PreparedNetfilter::new(
            NetfilterDescriptors {
                main,
                emergency,
                namespace: original.original_namespace()?,
            },
            digest,
            end,
            gate,
        )
        .map_err(mapped)?;
        // Every fallible preparation precedes consuming original custody.
        let mut origin = slot.take().expect("validated original socket owner");
        let actuator = origin.take_actuator();
        Ok(Self {
            inner: Some(Native {
                creator: std::process::id(),
                _origin: origin,
                actuator,
                policy,
                end,
                prepared: Some(p),
                child: None,
                completed: None,
                failure: None,
                validated: false,
                accepted_at: None,
                observed_at: None,
                accepted_sequences: None,
                binding_started: false,
                bootstrap_started: false,
            }),
        })
    }
    fn get(&self) -> Result<&Native> {
        let n = self.inner.as_ref().ok_or(Error::Interrupted)?;
        n.creator()?;
        Ok(n)
    }
    pub fn descriptors(&self) -> Result<Vec<BorrowedFd<'_>>> {
        let n = self.get()?;
        let mut f = n.actuator.descriptors().to_vec();
        if let Some(p) = &n.prepared {
            f.extend(p.descriptors().map_err(mapped)?);
        }
        if let Some(c) = &n.child {
            f.extend(c.descriptors().map_err(mapped)?);
        }
        Ok(f)
    }
    pub fn child_endpoints_before_birth(&self) -> Result<[BorrowedFd<'_>; 2]> {
        self.get()?
            .prepared
            .as_ref()
            .ok_or(Error::Interrupted)?
            .child_endpoints()
            .map_err(mapped)
    }
    /// Called only after launch retains/registers the whole preparatory owner.
    pub fn validate_prepared(&mut self) -> Result<()> {
        let n = self.inner.as_mut().ok_or(Error::Interrupted)?;
        n.creator()?;
        let result = (|| {
            if n.validated || n.failure.is_some() {
                return Err(Error::Interrupted);
            }
            let p = n.prepared.as_ref().ok_or(Error::Interrupted)?;
            n.actuator.bind_cleanup_deadline(
                BootDeadline::at(n.end)?,
                p.timer_owner().map_err(mapped)?,
            )?;
            if n.actuator.policy().initial_digest()? != n.policy {
                return Err(Error::Foreign);
            }
            BootDeadline::at(n.end)?.check()?;
            n.validated = true;
            Ok(())
        })();
        if let Err(e) = result {
            n.fail(e);
        }
        result
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
            Ok(NetfilterFork::Parent(child, original)) => {
                n.child = Some(child);
                Ok(original)
            }
            Ok(NetfilterFork::Child(role)) => run(n, role),
            Err(e) => {
                n.fail(e);
                Err(e)
            }
        }
    }
    pub fn original_child(&self) -> Result<ReapWitness> {
        self.get()?
            .child
            .as_ref()
            .ok_or(Error::Interrupted)?
            .original_child()
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
    pub fn poll(&mut self) -> Result<Option<VerifiedInitialQuarantine>> {
        let n = self.inner.as_mut().ok_or(Error::Interrupted)?;
        n.creator()?;
        if let Some(e) = n.failure {
            n.collect();
            return Err(e);
        }
        let result = (|| {
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
            if report.namespace != n.actuator.namespace() || report.policy != n.policy {
                return Err(Error::Foreign);
            }
            n.actuator.accept_initial_sequences(c, report.sequences)?;
            let birth = c.birth().map_err(mapped)?;
            if !report.observed_at.is_finite()
                || report.observed_at < birth.born_at
                || report.observed_at > c.child_reported_at().map_err(mapped)?
                || report.observed_at >= n.end
            {
                return Err(Error::Malformed);
            }
            n.observed_at = Some(report.observed_at);
            c.require_current().map_err(mapped)?;
            BootDeadline::at(n.end)?.check()?;
            n.accepted_sequences = Some(n.actuator.initial_sequences()?);
            n.accepted_at = Some(vprouter_core::health::boot_seconds());
            BootDeadline::at(n.end)?.check()?;
            Ok(true)
        })();
        match result {
            Ok(false) => Ok(None),
            Ok(true) => Ok(Some(VerifiedInitialQuarantine {
                inner: self.inner.take(),
            })),
            Err(e) => {
                n.fail(e);
                Err(e)
            }
        }
    }
}
impl VerifiedInitialQuarantine {
    fn binding_native(&self) -> Result<&Native> {
        let n = self.inner.as_ref().ok_or(Error::Interrupted)?;
        n.creator()?;
        let completed = n.completed.as_ref().ok_or(Error::Interrupted)?;
        completed.require_retained().map_err(mapped)?;
        let birth = completed.birth().map_err(mapped)?;
        if n.failure.is_some()
            || n.accepted_at
                .is_none_or(|at| !at.is_finite() || at < birth.born_at || at >= n.end)
            || n.observed_at.is_none()
            || n.accepted_sequences.is_none()
        {
            return Err(Error::Foreign);
        }
        Ok(n)
    }
    pub(crate) fn binding_actuator(&self) -> Result<&Actuator> {
        Ok(&self.binding_native()?.actuator)
    }
    pub(crate) fn binding_namespace(&self) -> Result<BorrowedFd<'_>> {
        let n = self.binding_native()?;
        n._origin.retained_namespace_for(&n.actuator)
    }
    pub(crate) fn binding_descriptors(&self) -> Result<Vec<BorrowedFd<'_>>> {
        Ok(self.binding_native()?.actuator.descriptors().to_vec())
    }
    /// Only the installed fixed child uses cached parent identity/shape here.
    /// Parent-owned descriptors were closed; verify selected duplicates through
    /// the unforgeable role instead of invoking creator-bound parent getters.
    pub(crate) fn confined_binding(
        &self,
        role: &vprouter_native_role::ConfinedProducerNetfilter,
    ) -> Result<Actuator> {
        let n = self.inner.as_ref().ok_or(Error::Interrupted)?;
        if n.creator == std::process::id()
            || !n.binding_started
            || n.failure.is_some()
            || n.completed.is_none()
            || n.accepted_at.is_none()
        {
            return Err(Error::Foreign);
        }
        n.actuator.confined_producer_observation(role)
    }
    pub(crate) fn begin_binding(
        &mut self,
        end: BootDeadline,
        timer: std::sync::Arc<std::os::fd::OwnedFd>,
    ) -> Result<()> {
        self.binding_native()?;
        let n = self.inner.as_mut().ok_or(Error::Interrupted)?;
        if n.binding_started || n.bootstrap_started {
            return Err(Error::Foreign);
        }
        n.binding_started = true;
        let result = n.actuator.rebind_initial_observation(
            n.completed.as_ref().ok_or(Error::Interrupted)?,
            n.accepted_sequences.ok_or(Error::Interrupted)?,
            end,
            timer,
        );
        if let Err(e) = result {
            n.fail(e);
        }
        result
    }
    pub(crate) fn accept_binding(
        &mut self,
        completed: &vprouter_native_role::ProducerNetfilterCompleted,
        seq: [u32; 2],
    ) -> Result<()> {
        self.binding_native()?;
        let n = self.inner.as_mut().ok_or(Error::Interrupted)?;
        if !n.binding_started {
            return Err(Error::Foreign);
        }
        n.actuator.accept_producer_observation(completed, seq)
    }
    pub(crate) fn begin_bootstrap(
        &mut self,
        end: BootDeadline,
        timer: std::sync::Arc<std::os::fd::OwnedFd>,
    ) -> Result<()> {
        self.binding_native()?;
        let n = self.inner.as_mut().ok_or(Error::Interrupted)?;
        if n.bootstrap_started || n.binding_started {
            return Err(Error::Foreign);
        }
        n.bootstrap_started = true;
        let result = n.actuator.rebind_initial_bootstrap(
            n.completed.as_ref().ok_or(Error::Interrupted)?,
            n.accepted_sequences.ok_or(Error::Interrupted)?,
            end,
            timer,
        );
        if let Err(e) = result {
            n.fail(e);
        }
        result
    }
    pub(crate) fn begin_observed_bootstrap(
        &mut self,
        original: &vprouter_native_role::ProducerNetfilterCompleted,
        seq: [u32; 2],
        end: BootDeadline,
        timer: std::sync::Arc<std::os::fd::OwnedFd>,
    ) -> Result<()> {
        self.binding_native()?;
        let n = self.inner.as_mut().ok_or(Error::Interrupted)?;
        if n.bootstrap_started || !n.binding_started {
            return Err(Error::Foreign);
        }
        n.bootstrap_started = true;
        let result = n
            .actuator
            .rebind_observed_bootstrap(original, seq, end, timer);
        if let Err(e) = result {
            n.fail(e);
        }
        result
    }
    pub(crate) fn confined_bootstrap(
        &self,
        role: &vprouter_native_role::ConfinedProducerBootstrap,
    ) -> Result<Actuator> {
        let n = self.inner.as_ref().ok_or(Error::Interrupted)?;
        if n.creator == std::process::id()
            || !n.bootstrap_started
            || n.failure.is_some()
            || n.completed.is_none()
            || n.accepted_at.is_none()
        {
            return Err(Error::Foreign);
        }
        n.actuator.confined_bootstrap(role)
    }
    pub(crate) fn accept_bootstrap(
        &mut self,
        original: &vprouter_native_role::ProducerBootstrapCompleted,
        seq: [u32; 2],
    ) -> Result<()> {
        self.binding_native()?;
        let n = self.inner.as_mut().ok_or(Error::Interrupted)?;
        if !n.bootstrap_started {
            return Err(Error::Foreign);
        }
        n.actuator.accept_bootstrap_sequences(original, seq)
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
    pub fn accepted_at(&self) -> Result<f64> {
        let n = self.inner.as_ref().ok_or(Error::Interrupted)?;
        n.creator()?;
        n.accepted_at.ok_or(Error::Interrupted)
    }
    /// Original final child observation, distinct from parent acceptance.
    /// Neither timestamp means tables remained unchanged afterward.
    pub fn observed_at(&self) -> Result<f64> {
        let n = self.inner.as_ref().ok_or(Error::Interrupted)?;
        n.creator()?;
        n.completed
            .as_ref()
            .ok_or(Error::Interrupted)?
            .require_retained()
            .map_err(mapped)?;
        n.observed_at.ok_or(Error::Interrupted)
    }
    pub fn namespace_identity(&self) -> Result<(u64, u64)> {
        let n = self.inner.as_ref().ok_or(Error::Interrupted)?;
        n.creator()?;
        Ok(n.actuator.namespace())
    }
    pub fn policy_digest(&self) -> Result<[u8; 32]> {
        let n = self.inner.as_ref().ok_or(Error::Interrupted)?;
        n.creator()?;
        Ok(n.policy)
    }
}
fn run(n: &Native, role: ConfinedNetfilter) -> ! {
    let result = (|| {
        let mut a = n.actuator.confined_initial(&role)?;
        a.install_initial_quarantine()?;
        // Preserve the second exact generation-bracketed verification inside
        // this fixed role. Parent receipt/ACK does not claim post-reap freshness.
        a.verify_initial_quarantine()?;
        let observed_at = vprouter_core::health::boot_seconds();
        role.require().map_err(mapped)?;
        serde_json::to_vec(&Report {
            namespace: a.namespace(),
            policy: n.policy,
            sequences: a.initial_sequences()?,
            observed_at,
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
