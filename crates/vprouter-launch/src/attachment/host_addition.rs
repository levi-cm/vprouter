//! Consuming host preparation. Retains the original producer-bound assembly and
//! protected generation declaration throughout both native baseline reads.
//! Observation is not a pair birth, host addition, operational permit or UP.
mod operation;
use super::super::{inventory, kernel, owned::preparation::quarantine::Binding};
use super::{
    Error, Result, host_baseline::PinnedBaseline, producer_binding::ProducerBoundAssembly,
};
pub(crate) use operation::{Kind, Request};
use std::{cell::RefCell, path::Path, rc::Rc};

/// One original generation admission. Member continuations retain this SAME
/// object; they never re-admit a baseline after an owned endpoint appears.
/// The observer, its registration, both-read receipt and declaration pin live
/// alongside the shared model through every member/addition failure.
struct Generation {
    creator: u32,
    declaration: Rc<PinnedBaseline>,
    admission: vprouter_network::PendingHostAdmission,
    observer_token: inventory::Registration,
    authority: vprouter_network::HostAuthority,
    allocation: vprouter_core::allocation::AllocationRecord,
    host: super::Identity,
    requested_at: f64,
    accepted_at: f64,
}
impl Generation {
    fn verify(&self, binding: &Binding) -> Result<()> {
        let spec = binding.data().request().spec();
        if self.creator != std::process::id()
            || serde_json::to_vec(&self.allocation).map_err(|_| Error::OwnershipMismatch)?
                != serde_json::to_vec(&spec.allocation).map_err(|_| Error::OwnershipMismatch)?
            || self.host != binding.host()
            || !self.accepted_at.is_finite()
            || self.accepted_at < self.requested_at
            || self.accepted_at >= self.requested_at + 2.
            || self
                .admission
                .accepted_at()
                .map_err(|_| Error::OwnershipMismatch)?
                != self.accepted_at
            || !self.observer_token.contains(
                self.admission
                    .descriptor()
                    .map_err(|_| Error::DescriptorInventory)?,
            )
        {
            return Err(Error::OwnershipMismatch);
        }
        self.declaration.verify(&self.allocation, self.host)
    }
}
struct Native {
    #[cfg(test)]
    anchor: Rc<()>,
    creator: u32,
    input: ProducerBoundAssembly,
    binding: Rc<Binding>,
    plan: vprouter_network::Plan,
    generation: Option<Rc<Generation>>,
    declaration: Option<Rc<PinnedBaseline>>,
    observer: Option<vprouter_network::RouteObserver>,
    observer_token: Option<inventory::Registration>,
    admission: Option<vprouter_network::PendingHostAdmission>,
    authority: Option<vprouter_network::HostAuthority>,
    requested_at: f64,
    accepted_at: Option<f64>,
    failure: Option<Error>,
}
pub(super) struct PendingHostBaseline {
    native: Option<Box<Native>>,
}
/// Original privately observed declaration and complete resource owner. The
/// forthcoming pair Intent must durably bind this SAME owner before any birth.
pub(super) struct ObservedHostAssembly {
    native: Option<Box<Native>>,
}
// Keep the same heap-owned bundle on retention; never move its pointee onto the stack.
thread_local! { #[allow(clippy::vec_box)] static RETAINED: RefCell<Vec<Box<Native>>> = const { RefCell::new(Vec::new()) }; }
impl Native {
    fn check_custody(&self) -> Result<()> {
        if self.creator != std::process::id() || self.failure.is_some() {
            return Err(Error::OwnershipMismatch);
        }
        let (original, _) = self.input.host_custody()?;
        if !Rc::ptr_eq(original, &self.binding) {
            return Err(Error::OwnershipMismatch);
        }
        if let Some(generation) = &self.generation {
            generation.verify(&self.binding)?;
            return kernel::owner_admission_permitted();
        }
        let spec = self.binding.data().request().spec();
        self.declaration
            .as_ref()
            .ok_or(Error::Interrupted)?
            .verify(&spec.allocation, self.binding.host())?;
        let fd = if let Some(read) = &self.admission {
            read.descriptor().map_err(|_| Error::DescriptorInventory)?
        } else {
            self.observer
                .as_ref()
                .ok_or(Error::Interrupted)?
                .descriptor()
        };
        if !self
            .observer_token
            .as_ref()
            .ok_or(Error::DescriptorInventory)?
            .contains(fd)
        {
            return Err(Error::DescriptorInventory);
        }
        kernel::owner_admission_permitted()
    }
    fn check_current(&self) -> Result<()> {
        self.check_custody()?;
        self.binding.verify(self.input.host_service()?)?;
        let now = vprouter_core::health::boot_seconds();
        if !now.is_finite() || now < self.requested_at || now >= self.requested_at + 2. {
            return Err(Error::Deadline);
        }
        Ok(())
    }
    fn fail(&mut self, error: Error) {
        if self.creator == std::process::id() {
            self.failure.get_or_insert(error);
            self.input.fail(error);
        }
    }
    fn collect(&mut self) {
        if self.creator == std::process::id() {
            self.input.collect();
        }
    }
}
impl PendingHostBaseline {
    pub(super) fn new(
        slot: &mut Option<ProducerBoundAssembly>,
        declaration: &Path,
    ) -> Result<Self> {
        kernel::secret::seal_parent()?;
        let binding = slot.as_ref().ok_or(Error::Interrupted)?.host_context()?;
        let spec = binding.data().request().spec();
        let profile = binding
            .configuration()
            .exits()
            .iter()
            .find(|e| e.exit().id == spec.exit.exit_id)
            .and_then(|e| e.profile())
            .ok_or(Error::InvalidSpec)?;
        let plan = vprouter_network::Plan::from_public(
            &spec.allocation,
            &spec.allocation.deployment_id,
            &spec.exit,
            profile,
        )
        .map_err(|_| Error::OwnershipMismatch)?;
        let requested_at = vprouter_core::health::boot_seconds();
        if !requested_at.is_finite() || requested_at <= 0. {
            return Err(Error::Deadline);
        }
        // The entire original owner is stored before opening any new input or
        // socket, registration, or other fallible preparation.
        let mut value = Self {
            native: Some(Box::new(Native {
                #[cfg(test)]
                anchor: Rc::new(()),
                creator: std::process::id(),
                input: slot.take().ok_or(Error::Interrupted)?,
                binding,
                plan,
                generation: None,
                declaration: None,
                observer: None,
                observer_token: None,
                admission: None,
                authority: None,
                requested_at,
                accepted_at: None,
                failure: None,
            })),
        };
        let n = value.native.as_mut().ok_or(Error::Interrupted)?;
        let spec = n.binding.data().request().spec();
        n.declaration = Some(PinnedBaseline::load(
            declaration,
            &spec.allocation,
            n.binding.host(),
        )?);
        n.observer =
            Some(vprouter_network::RouteObserver::open().map_err(|_| Error::NetworkOperation)?);
        let observer = n.observer.as_ref().ok_or(Error::Interrupted)?;
        n.observer_token = Some(inventory::Registration::owned(&[observer.descriptor()])?);
        let host = n.binding.host();
        if observer.namespace_identity() != (host.dev, host.ino) {
            return Err(Error::NamespaceMismatch);
        }
        n.check_current()?;
        let declared = n
            .declaration
            .as_ref()
            .ok_or(Error::Interrupted)?
            .observation(&spec.allocation, host)?;
        n.admission = Some(
            vprouter_network::HostAuthority::begin_declared(
                &mut n.observer,
                &spec.allocation,
                &n.plan,
                declared,
                n.requested_at + 2.,
            )
            .map_err(|_| Error::NetworkOperation)?,
        );
        n.check_current()?;
        Ok(value)
    }
    pub(super) fn poll(&mut self) -> Result<Option<ObservedHostAssembly>> {
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        if n.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        if let Some(error) = n.failure {
            n.collect();
            return Err(error);
        }
        let result = (|| {
            n.check_current()?;
            if let Some(authority) = n
                .admission
                .as_mut()
                .ok_or(Error::Interrupted)?
                .poll()
                .map_err(|_| Error::NetworkOperation)?
            {
                n.authority = Some(authority);
                n.accepted_at = Some(
                    n.admission
                        .as_ref()
                        .ok_or(Error::Interrupted)?
                        .accepted_at()
                        .map_err(|_| Error::NetworkOperation)?,
                );
            }
            n.check_current()?;
            Ok(n.authority.is_some())
        })();
        match result {
            Ok(true) => {
                // All fields were validated together above. No fallible work
                // splits custody while moving them into the one shared owner.
                n.generation = Some(Rc::new(Generation {
                    creator: n.creator,
                    declaration: n.declaration.take().expect("validated declaration"),
                    admission: n.admission.take().expect("completed two-read admission"),
                    observer_token: n
                        .observer_token
                        .take()
                        .expect("original observer registration"),
                    authority: n.authority.take().expect("original admitted model"),
                    allocation: n.binding.data().request().spec().allocation.clone(),
                    host: n.binding.host(),
                    requested_at: n.requested_at,
                    accepted_at: n.accepted_at.expect("original accepted time"),
                }));
                Ok(Some(ObservedHostAssembly {
                    native: self.native.take(),
                }))
            }
            Ok(false) => Ok(None),
            Err(error) => {
                n.fail(error);
                n.collect();
                Err(error)
            }
        }
    }
}
fn retain(mut n: Box<Native>) {
    if n.creator != std::process::id() {
        std::mem::forget(n);
        return;
    }
    n.fail(Error::Interrupted);
    RETAINED.with(|r| r.borrow_mut().push(n));
}
impl Drop for PendingHostBaseline {
    fn drop(&mut self) {
        if let Some(n) = self.native.take() {
            retain(n);
        }
    }
}
impl Drop for ObservedHostAssembly {
    fn drop(&mut self) {
        if let Some(n) = self.native.take() {
            retain(n);
        }
    }
}
pub(super) fn poll_retained() {
    operation::poll_retained();
    RETAINED.with(|r| {
        for n in r.borrow_mut().iter_mut() {
            n.collect();
        }
    });
}
pub(super) fn children_reaped() -> bool {
    if !operation::children_reaped() {
        return false;
    }
    RETAINED.with(|r| {
        r.borrow()
            .iter()
            .all(|n| n.creator != std::process::id() || n.input.children_reaped())
    })
}

/// Connected continuation; no pair preparation begins before the one original
/// protected generation admission has completed both native reads.
pub(super) struct PendingHostAddition {
    baseline: Option<PendingHostBaseline>,
    observed: Option<ObservedHostAssembly>,
    links: Option<operation::PendingHostLinks>,
    failure: Option<Error>,
    complete: bool,
}
pub(super) struct HostAddedPrimary {
    original: operation::HostLinkedAssembly,
}
impl HostAddedPrimary {
    pub(super) fn bootstrap_previous(
        &mut self,
        scope: super::quarantine::Scope,
    ) -> Result<kernel::bootstrap::Previous<'_>> {
        self.original.bootstrap_previous(scope)
    }
    pub(super) fn require_operational_custody(&self) -> Result<()> {
        self.original.require_operational_custody()
    }
    pub(super) fn operational_context(&self) -> Result<super::operational::Context<'_>> {
        self.original.operational_context()
    }
    pub(super) fn operational_custody(&self) -> Result<super::operational::Custody<'_>> {
        self.original.operational_custody()
    }
    pub(super) fn operational_custody_service_mut(
        &mut self,
    ) -> Result<&mut super::super::owned::preparation::Server> {
        self.original.operational_custody_service_mut()
    }
    pub(super) fn operational_service_mut(
        &mut self,
    ) -> Result<&mut super::super::owned::preparation::Server> {
        self.original.operational_service_mut()
    }
    pub(super) fn operational_plan(&self) -> Result<Vec<kernel::ResourceTransfer>> {
        self.original.operational_plan()
    }
    pub(super) fn reserve_operational_extension(
        &self,
        plan: &[kernel::ResourceTransfer],
    ) -> Result<super::super::owned::preparation::assembly::OperationalReservation> {
        self.original.reserve_operational_extension(plan)
    }
    pub(super) fn fail(&mut self, error: Error) {
        self.original.fail(error);
    }
    pub(super) fn collect(&mut self) {
        self.original.collect();
    }
    pub(super) fn children_reaped(&self) -> bool {
        self.original.reaped()
    }
}
impl PendingHostAddition {
    pub(super) fn new(
        input: &mut Option<ProducerBoundAssembly>,
        declaration: &Path,
    ) -> Result<Self> {
        Ok(Self {
            baseline: Some(PendingHostBaseline::new(input, declaration)?),
            observed: None,
            links: None,
            failure: None,
            complete: false,
        })
    }
    pub(super) fn poll(&mut self) -> Result<Option<HostAddedPrimary>> {
        if let Some(e) = self.failure {
            // Keep servicing only the original failed owners while the caller
            // retains this wrapper. No new operation or acceptance is possible.
            if let Some(n) = self.baseline.as_mut().and_then(|p| p.native.as_mut()) {
                n.collect();
            }
            if let Some(n) = self.observed.as_mut().and_then(|p| p.native.as_mut()) {
                n.collect();
            }
            if let Some(p) = &mut self.links {
                p.collect();
            }
            return Err(e);
        }
        if self.complete {
            return Err(Error::OwnershipMismatch);
        }
        let result = (|| {
            if let Some(baseline) = &mut self.baseline {
                let Some(observed) = baseline.poll()? else {
                    return Ok(None);
                };
                self.observed = Some(observed);
                self.baseline.take();
                self.links = Some(operation::PendingHostLinks::new(&mut self.observed)?);
                return Ok(None);
            }
            let Some(original) = self.links.as_mut().ok_or(Error::Interrupted)?.poll()? else {
                return Ok(None);
            };
            self.links.take();
            self.complete = true;
            Ok(Some(HostAddedPrimary { original }))
        })();
        if let Err(e) = result {
            self.failure = Some(e);
        }
        result
    }
}

#[cfg(test)]
pub(crate) fn lab_run(fault: u8) -> Result<()> {
    operation::lab_run(fault)
}
#[cfg(test)]
const LAB_MARKER: &str = "LAB_SECRET_HOST_ADDITION";
#[cfg(test)]
const LAB_LABELS: [&str; 4] = [
    "actual_original_down_pair_added_to_declared_host",
    "actual_host_addition_postbirth_failure_retains_isolated_pair",
    "actual_host_addition_result_failure_retains_unacknowledged_host_endpoint",
    "actual_host_addition_registration_failure_retains_original_generation",
];

#[cfg(test)]
pub(super) fn lab_added() -> Result<(HostAddedPrimary, serde_json::Value)> {
    operation::lab_added()
}
#[cfg(test)]
pub(crate) struct LabAnchors(operation::LabAnchors);
#[cfg(test)]
impl LabAnchors {
    pub(crate) fn require_retained(&self) -> Result<()> {
        self.0.require_retained()
    }
}
#[cfg(test)]
impl HostAddedPrimary {
    pub(super) fn lab_preparation(&mut self) -> Result<serde_json::Value> {
        self.original.lab_preparation()
    }
    pub(super) fn lab_bootstrap_result_charge(
        &mut self,
        failed: bool,
    ) -> Result<(kernel::LabJournalCharge, serde_json::Value)> {
        self.original.lab_bootstrap_result_charge(failed)
    }
    pub(crate) fn lab_anchors(&self) -> Result<LabAnchors> {
        self.original.lab_anchors().map(LabAnchors)
    }
}
