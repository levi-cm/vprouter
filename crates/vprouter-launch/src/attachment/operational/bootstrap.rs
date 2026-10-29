//! Original, scope-specific Bootstrap request. Its Source and exact20 owner are
//! native custody; public histories alone cannot construct this request.
use super::super::super::{
    kernel,
    owned::{
        Identity,
        preparation::{Server, quarantine::Binding},
    },
};
use super::super::{Error, Result, quarantine::Scope};
use super::{OperationalOwner, producer::Pins};
use std::rc::Rc;
pub(crate) struct Request {
    creator: u32,
    binding: Rc<Binding>,
    source: Rc<kernel::producer_creation::Source>,
    query: Rc<kernel::docker_query::Accepted>,
    pins: Pins,
    identities: [(u64, u64, u32); 8],
    group: Identity,
    namespace: Identity,
    scope: Scope,
    policy: [u8; 32],
    digest: [u8; 32],
}
impl Request {
    #[cfg(test)]
    pub(crate) fn lab_registered_slots(&self) -> Result<usize> {
        self.pins.lab_registered_slots()
    }

    pub(super) fn new(
        input: &OperationalOwner,
        query: Rc<kernel::docker_query::Accepted>,
    ) -> Result<Rc<Self>> {
        input.require_complete()?;
        let context = input.context()?;
        query.verify_bootstrap_service(context.service)?;
        let index = query
            .request()
            .kind()
            .bootstrap_index()
            .ok_or(Error::OwnershipMismatch)?;
        if query
            .request()
            .quarantine
            .as_ref()
            .is_none_or(|b| !Rc::ptr_eq(b, &context.binding))
            || !Rc::ptr_eq(context.source.request().binding(), &context.binding)
        {
            return Err(Error::OwnershipMismatch);
        }
        query.request().revalidate_quarantine_process_pins()?;
        let scope = *[Scope::Host, Scope::Transport, Scope::Data]
            .get(index)
            .ok_or(Error::OwnershipMismatch)?;
        let namespace = match scope {
            Scope::Host => context.binding.host(),
            Scope::Transport => context.binding.transport().request().source_identity(),
            Scope::Data => context.binding.data().request().source_identity(),
        };
        let pins = Pins::new(context.source.clone(), query.request().requested_at())?;
        let identities = pins.identities()?;
        let group = context.source.identity()?;
        let policy = context.service.bootstrap_policy(&context.source, scope)?;
        use sha2::Digest;
        let digest = sha2::Sha256::digest(
            serde_json::to_vec(&(
                "original_producer_scope_bootstrap_v1",
                context.binding.configuration_digest(),
                context.binding.public_result(),
                context.source.request().digest(),
                context.source.birth()?,
                context.source.verified_at(),
                context.source.request().parent_identity(),
                context.source.request().name(),
                group,
                scope,
                namespace,
                policy,
                identities,
                query.request().digest(),
                query.request().requested_at(),
            ))
            .map_err(|_| Error::InvalidSpec)?,
        )
        .into();
        let value = Rc::new(Self {
            creator: std::process::id(),
            binding: context.binding,
            source: context.source,
            query,
            pins,
            identities,
            group,
            namespace,
            scope,
            policy,
            digest,
        });
        value.verify()?;
        Ok(value)
    }
    pub(crate) fn require_query_origin(
        &self,
        query: &Rc<kernel::docker_query::Accepted>,
    ) -> Result<()> {
        self.verify_retained()?;
        if !Rc::ptr_eq(query, &self.query) {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
    pub(crate) fn check(&self) -> Result<()> {
        if self.creator != std::process::id()
            || self.query.request().kind().bootstrap_index() != Some(self.index())
            || self
                .query
                .request()
                .quarantine
                .as_ref()
                .is_none_or(|b| !Rc::ptr_eq(b, &self.binding))
        {
            return Err(Error::OwnershipMismatch);
        }
        kernel::owner_admission_permitted()?;
        self.query.require()
    }
    pub(crate) fn verify_retained(&self) -> Result<()> {
        if self.creator != std::process::id()
            || !Rc::ptr_eq(self.source.request().binding(), &self.binding)
            || !self.pins.matches_source(&self.source)
        {
            return Err(Error::OwnershipMismatch);
        }
        self.source.verify_acknowledged_history()?;
        self.pins.verify_retained()?;
        if self.source.identity()? != self.group {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
    pub(crate) fn verify(&self) -> Result<()> {
        self.check()?;
        self.verify_retained()?;
        self.check()
    }
    pub(crate) fn verify_service(&self, s: &Server) -> Result<()> {
        self.verify()?;
        self.source.bind_service(s)?;
        self.binding.verify(s)?;
        self.query.verify_bootstrap_service(s)
    }
    pub(crate) fn index(&self) -> usize {
        match self.scope {
            Scope::Host => 0,
            Scope::Transport => 1,
            Scope::Data => 2,
        }
    }
    pub(crate) fn scope(&self) -> Scope {
        self.scope
    }
    pub(crate) fn namespace(&self) -> Identity {
        self.namespace
    }
    pub(crate) fn binding(&self) -> &Rc<Binding> {
        &self.binding
    }
    pub(crate) fn source(&self) -> &Rc<kernel::producer_creation::Source> {
        &self.source
    }
    pub(crate) fn digest(&self) -> [u8; 32] {
        self.digest
    }
    pub(crate) fn query_digest(&self) -> [u8; 32] {
        self.query.request().digest()
    }
    pub(crate) fn policy_digest(&self) -> [u8; 32] {
        self.policy
    }
    pub(crate) fn identities(&self) -> [(u64, u64, u32); 8] {
        self.identities
    }
    pub(crate) fn group(&self) -> Identity {
        self.group
    }
    pub(crate) fn requested_at(&self) -> f64 {
        self.query.request().requested_at()
    }
    pub(crate) fn deadline(&self) -> f64 {
        self.query.request().deadline()
    }
    pub(crate) fn descriptors(&self) -> Result<vprouter_native_role::ProducerDescriptors<'_>> {
        self.pins.selected()
    }
    pub(crate) fn ancestry(&self) -> Result<vprouter_native_role::ProducerAncestryDescriptors<'_>> {
        self.pins.ancestry()
    }
}

use super::super::super::owned::preparation::{
    bootstrap::Progress, inspection::QuarantineProgress, quarantine::Progress as QueryProgress,
};
use super::super::{InspectionRequest, QueryKind};
use std::cell::RefCell;
#[derive(Clone, Copy)]
enum Step {
    QueryIntent,
    QueryBirth,
    QueryReading,
    QueryResult,
    Intent,
    Birth,
    Reading,
    Result,
    Next,
    Complete,
}
struct Native {
    creator: u32,
    input: OperationalOwner,
    binding: Rc<Binding>,
    query: Rc<InspectionRequest>,
    completed: Vec<(
        Rc<kernel::docker_query::Accepted>,
        kernel::bootstrap::Verified,
    )>,
    query_child: Option<kernel::docker_query::Child>,
    query_verified: Option<kernel::docker_query::Verified>,
    query_accepted: Option<Rc<kernel::docker_query::Accepted>>,
    request: Option<Rc<Request>>,
    child: Option<kernel::bootstrap::Child>,
    verified: Option<kernel::bootstrap::Verified>,
    step: Step,
    failure: Option<Error>,
    #[cfg(test)]
    anchor: Rc<()>,
    #[cfg(test)]
    final_verified_at: Option<f64>,
    #[cfg(test)]
    process_verified_at: Vec<f64>,
}
pub(crate) struct PendingBootstrap {
    native: Option<Box<Native>>,
}
pub(crate) struct BootstrappedOwner {
    native: Option<Box<Native>>,
}
// Keep the same heap-owned bundle on retention; never move its pointee onto the stack.
thread_local! {#[allow(clippy::vec_box)] static RETAINED:RefCell<Vec<Box<Native>>>=const{RefCell::new(Vec::new())};}
impl Native {
    fn fail(&mut self, e: Error) {
        if self.creator != std::process::id() {
            return;
        }
        self.failure.get_or_insert(e);
        self.input.fail(e);
        if let Some(c) = &mut self.query_child {
            c.cancel(e);
        }
        if let Some(c) = &mut self.child {
            c.cancel(e);
        }
    }
    fn collect(&mut self) {
        if self.creator != std::process::id() {
            return;
        }
        self.input.collect();
        if let Some(c) = &mut self.query_child {
            c.collect();
        }
        if let Some(c) = &mut self.child {
            c.collect();
        }
    }
    fn reaped(&self) -> bool {
        self.input.reaped()
            && self
                .query_child
                .as_ref()
                .is_none_or(kernel::docker_query::Child::reaped)
            && self
                .child
                .as_ref()
                .is_none_or(kernel::bootstrap::Child::reaped)
    }
    fn advance(&mut self) -> Result<()> {
        if matches!(self.step, Step::Next) {
            if self.completed.len() == 3 {
                self.input.require_complete()?;
                self.input
                    .context()?
                    .service
                    .verify_bootstrap_chain(&self.completed)?;
                self.step = Step::Complete;
                return Ok(());
            }
            let kind = *[
                QueryKind::BootstrapHostRecheck,
                QueryKind::BootstrapTransportRecheck,
                QueryKind::BootstrapDataRecheck,
            ]
            .get(self.completed.len())
            .ok_or(Error::OwnershipMismatch)?;
            self.query = InspectionRequest::for_bootstrap(&self.input, kind)?;
            #[cfg(test)]
            {
                self.final_verified_at = None;
            }
            self.query_child = None;
            self.query_verified = None;
            self.request = None;
            self.child = None;
            self.input.service_mut()?.start_inspection(&self.query)?;
            self.step = Step::QueryIntent;
        }
        self.query.check_deadline()?;
        let service = self.input.context()?.service;
        match self.step {
            Step::QueryIntent => self.binding.verify_progress(
                service,
                QueryProgress::Query(&self.query, QuarantineProgress::Intent),
            )?,
            Step::QueryBirth => self.binding.verify_progress(
                service,
                QueryProgress::Query(
                    &self.query,
                    QuarantineProgress::Birth(self.query_child.as_ref().ok_or(Error::Interrupted)?),
                ),
            )?,
            Step::QueryResult => self.binding.verify_progress(
                service,
                QueryProgress::Query(
                    &self.query,
                    QuarantineProgress::Result(
                        self.query_verified.as_ref().ok_or(Error::Interrupted)?,
                    ),
                ),
            )?,
            Step::Intent => self.binding.verify_bootstrap_progress(
                service,
                self.request.as_ref().ok_or(Error::Interrupted)?,
                Progress::Intent,
            )?,
            Step::Birth => self.binding.verify_bootstrap_progress(
                service,
                self.request.as_ref().ok_or(Error::Interrupted)?,
                Progress::Birth(self.child.as_ref().ok_or(Error::Interrupted)?),
            )?,
            Step::Result => self.binding.verify_bootstrap_progress(
                service,
                self.request.as_ref().ok_or(Error::Interrupted)?,
                Progress::Result(self.verified.as_ref().ok_or(Error::Interrupted)?),
            )?,
            _ => self.binding.verify(service)?,
        }
        match self.step {
            Step::QueryIntent => {
                if let Some(i) = self
                    .input
                    .service_mut()?
                    .poll_inspection_intent(&self.query)?
                {
                    self.query_child = Some(kernel::docker_query::spawn(self.query.clone(), i)?);
                    self.input.service_mut()?.start_inspection_birth(
                        self.query_child.as_ref().ok_or(Error::Interrupted)?,
                    )?;
                    self.step = Step::QueryBirth;
                }
            }
            Step::QueryBirth => {
                let c = self.query_child.as_mut().ok_or(Error::Interrupted)?;
                if let Some(g) = self.input.service_mut()?.poll_inspection_birth(c)? {
                    c.release(g)?;
                    self.step = Step::QueryReading;
                }
            }
            Step::QueryReading => {
                if let Some(v) = self
                    .query_child
                    .as_mut()
                    .ok_or(Error::Interrupted)?
                    .poll()?
                {
                    self.query_verified = Some(v);
                    self.input.service_mut()?.start_inspection_result(
                        self.query_verified.as_ref().ok_or(Error::Interrupted)?,
                    )?;
                    self.step = Step::QueryResult;
                }
            }
            Step::QueryResult => {
                if let Some(r) = self.input.service_mut()?.poll_inspection_result(
                    self.query_verified.as_ref().ok_or(Error::Interrupted)?,
                )? {
                    self.query_accepted = Some(Rc::new(kernel::docker_query::Verified::accept(
                        &mut self.query_verified,
                        r,
                    )?));
                    self.request = Some(Request::new(
                        &self.input,
                        self.query_accepted
                            .as_ref()
                            .ok_or(Error::Interrupted)?
                            .clone(),
                    )?);
                    self.input
                        .service_mut()?
                        .start_bootstrap(self.request.as_ref().ok_or(Error::Interrupted)?)?;
                    self.step = Step::Intent;
                }
            }
            Step::Intent => {
                let r = self.request.as_ref().ok_or(Error::Interrupted)?;
                if let Some(i) = self.input.service_mut()?.poll_bootstrap_intent(r)? {
                    self.child = Some(kernel::bootstrap::spawn(
                        r.clone(),
                        i,
                        self.input.bootstrap_previous(r.scope())?,
                    )?);
                    self.input
                        .service_mut()?
                        .start_bootstrap_birth(self.child.as_ref().ok_or(Error::Interrupted)?)?;
                    self.step = Step::Birth;
                }
            }
            Step::Birth => {
                let c = self.child.as_mut().ok_or(Error::Interrupted)?;
                if let Some(g) = self.input.service_mut()?.poll_bootstrap_birth(c)? {
                    c.release(g)?;
                    self.step = Step::Reading;
                }
            }
            Step::Reading => {
                if let Some(v) = self.child.as_mut().ok_or(Error::Interrupted)?.poll()? {
                    self.verified = Some(v);
                    self.input.service_mut()?.start_bootstrap_source(
                        self.verified.as_ref().ok_or(Error::Interrupted)?,
                    )?;
                    self.step = Step::Result;
                }
            }
            Step::Result => {
                let v = self.verified.as_mut().ok_or(Error::Interrupted)?;
                if let Some(r) = self.input.service_mut()?.poll_bootstrap_source(v)? {
                    v.accept(r)?;
                    self.request.as_ref().ok_or(Error::Interrupted)?.verify()?;
                    self.query.revalidate_quarantine_process_pins()?;
                    self.query.check_deadline()?;
                    #[cfg(test)]
                    {
                        let at = vprouter_core::health::boot_seconds();
                        self.final_verified_at = Some(at);
                        self.process_verified_at.push(at);
                    }
                    self.completed.push((
                        self.query_accepted.take().ok_or(Error::Interrupted)?,
                        self.verified.take().ok_or(Error::Interrupted)?,
                    ));
                    self.step = Step::Next;
                }
            }
            Step::Next | Step::Complete => (),
        }
        self.query.check_deadline()
    }
}
impl PendingBootstrap {
    pub(crate) fn new(slot: &mut Option<OperationalOwner>) -> Result<Self> {
        let input = slot.as_ref().ok_or(Error::Interrupted)?;
        input.require_complete()?;
        let binding = input.context()?.binding;
        let query = InspectionRequest::for_bootstrap(input, QueryKind::BootstrapHostRecheck)?;
        let mut value = Self {
            native: Some(Box::new(Native {
                creator: std::process::id(),
                input: slot.take().ok_or(Error::Interrupted)?,
                binding,
                query,
                completed: Vec::with_capacity(3),
                query_child: None,
                query_verified: None,
                query_accepted: None,
                request: None,
                child: None,
                verified: None,
                step: Step::QueryIntent,
                failure: None,
                #[cfg(test)]
                anchor: Rc::new(()),
                #[cfg(test)]
                final_verified_at: None,
                #[cfg(test)]
                process_verified_at: Vec::with_capacity(3),
            })),
        };
        let n = value.native.as_mut().ok_or(Error::Interrupted)?;
        if let Err(e) = n.input.service_mut()?.start_inspection(&n.query) {
            n.fail(e);
            return Err(e);
        }
        Ok(value)
    }
    pub(crate) fn poll(&mut self) -> Result<Option<BootstrappedOwner>> {
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        if n.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        if let Some(e) = n.failure {
            n.collect();
            return Err(e);
        }
        match n.advance() {
            Ok(()) if matches!(n.step, Step::Complete) => Ok(Some(BootstrappedOwner {
                native: self.native.take(),
            })),
            Ok(()) => Ok(None),
            Err(e) => {
                n.fail(e);
                n.collect();
                Err(e)
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
impl Drop for PendingBootstrap {
    fn drop(&mut self) {
        if let Some(n) = self.native.take() {
            retain(n);
        }
    }
}
impl Drop for BootstrappedOwner {
    fn drop(&mut self) {
        if let Some(n) = self.native.take() {
            retain(n);
        }
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

#[cfg(test)]
const LAB_LABELS: [&str; 7] = [
    "actual_original_three_scope_bootstrap_after_exact_twenty_handoff",
    "actual_bootstrap_postbirth_failure_retains_original_twenty_owners",
    "actual_bootstrap_result_failure_retains_unacknowledged_data_policy",
    "actual_bootstrap_registration_failure_retains_original_data_policy",
    "actual_twenty_handoff_fence_refuses_all_suffix_retirements",
    "actual_twenty_handoff_partial_fence_retains_original_suffix",
    "actual_twenty_duplicate_reservation_refused_before_bootstrap",
];
#[cfg(test)]
pub(crate) fn lab_run(fault: u8) -> Result<()> {
    use std::time::Duration;
    let label = *LAB_LABELS.get(fault as usize).ok_or(Error::InvalidSpec)?;
    let mut handoff = super::lab_handoff(fault)?;
    let mut pending = None;
    let mut complete = None;
    let mut bootstrap_anchor = None;
    let mut armed = false;
    let mut result_held = false;
    let mut original_charge: Option<kernel::LabJournalCharge> = None;
    let mut retained_result_writer = None;
    let mut failed_constructor = None;
    let mut retry = None;
    let mut own_intent = None;
    let mut own_queued = false;
    let mut own_held = 0usize;
    let mut own_negatives = 0usize;
    let mut own_released = false;
    if !matches!(fault, 4 | 5) {
        pending = Some(PendingBootstrap::new(&mut handoff.owner)?);
        bootstrap_anchor = Some(Rc::downgrade(
            &pending
                .as_ref()
                .ok_or(Error::Interrupted)?
                .native
                .as_ref()
                .ok_or(Error::Interrupted)?
                .anchor,
        ));
        let outcome = loop {
            let n = pending
                .as_mut()
                .ok_or(Error::Interrupted)?
                .native
                .as_mut()
                .ok_or(Error::Interrupted)?;
            if n.completed.is_empty() && matches!(n.step, Step::Intent) && !own_released {
                let r = n.request.as_ref().ok_or(Error::Interrupted)?.clone();
                if !own_queued {
                    n.input.service_mut()?.lab_hold_bootstrap_intent()?;
                    own_negatives += n
                        .binding
                        .lab_bootstrap_intent_negatives(n.input.context()?.service, &r)?;
                    own_queued = true;
                }
                if n.input.service_mut()?.lab_checkpoint()? {
                    if own_held == 0 {
                        own_negatives += n
                            .binding
                            .lab_bootstrap_intent_negatives(n.input.context()?.service, &r)?;
                    }
                    let writer = n
                        .input
                        .context()?
                        .service
                        .lab_pending_writer_identity()?
                        .ok_or(Error::OwnershipMismatch)?;
                    if own_held >= 2 {
                        n.input.service_mut()?.lab_release_bootstrap_intent()?;
                        own_released = true;
                        own_intent = Some(
                            serde_json::json!({"index":writer.0,"pid":writer.1,"start":writer.2,"queued_polls":1,"held_pending_polls":own_held,"negative_checks":own_negatives,"released":true}),
                        );
                    } else {
                        own_held += 1;
                    }
                }
            }
            if n.completed.len() == 2 && matches!(n.step, Step::Intent) && !armed {
                let r = n.request.as_ref().ok_or(Error::Interrupted)?;
                match fault {
                    1 | 3 => kernel::bootstrap::lab_arm(r, fault),
                    2 => n.input.service_mut()?.lab_hold_bootstrap_result()?,
                    _ => (),
                }
                armed = true;
            }
            if fault == 2
                && n.completed.len() == 2
                && matches!(n.step, Step::Result)
                && n.input.service_mut()?.lab_checkpoint()?
            {
                original_charge =
                    Some(n.input.service_mut()?.lab_bootstrap_result_charge(false)?.0);
                result_held = true;
                n.fail(Error::ChildFailed);
            }
            match pending.as_mut().ok_or(Error::Interrupted)?.poll() {
                Ok(Some(value)) => break Ok(value),
                Ok(None) => std::thread::sleep(Duration::from_millis(1)),
                Err(error) => break Err(error),
            }
        };
        match outcome {
            Ok(value) => {
                if !matches!(fault, 0 | 6) {
                    return Err(Error::OwnershipMismatch);
                }
                complete = Some(value);
            }
            Err(error) => {
                let n = pending
                    .as_mut()
                    .ok_or(Error::Interrupted)?
                    .native
                    .as_mut()
                    .ok_or(Error::Interrupted)?;
                let request = n.request.as_ref().ok_or(Error::Interrupted)?.clone();
                eprintln!(
                    "LAB_SECRET_BOOTSTRAP_FAILURE scope={:?} reason={error:?} requested_at={} deadline={} now={}",
                    request.scope(),
                    request.requested_at(),
                    request.deadline(),
                    vprouter_core::health::boot_seconds()
                );
                if !armed
                    || !(matches!(fault, 1 | 3) && error == Error::DescriptorInventory
                        || fault == 2 && result_held && error == Error::ChildFailed)
                {
                    return Err(error);
                }
                let collect_end = vprouter_core::health::boot_seconds() + 2.;
                loop {
                    n.collect();
                    if matches!(fault, 1 | 3) {
                        failed_constructor = kernel::bootstrap::lab_failed_context(&request)?;
                    }
                    if n.reaped() && (fault == 2 || failed_constructor.is_some()) {
                        break;
                    }
                    if vprouter_core::health::boot_seconds() >= collect_end {
                        return Err(Error::Deadline);
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
                if fault == 2 {
                    let (charge, mut evidence) = n.input.lab_bootstrap_result_charge(true)?;
                    original_charge
                        .as_ref()
                        .ok_or(Error::Interrupted)?
                        .same_original(&charge)?;
                    evidence["charge_retained_before_cancel"] = serde_json::json!(true);
                    evidence["charge_retained_after_collection"] = serde_json::json!(true);
                    evidence["charge_retained_after_retries"] = serde_json::json!(false);
                    evidence["charge_retained_after_drop"] = serde_json::json!(false);
                    retained_result_writer = Some(evidence);
                }
                let step = std::mem::discriminant(&n.step);
                let before = super::lab_charges();
                let births = kernel::lab_native_births();
                for _ in 0..2 {
                    if !matches!(pending.as_mut().ok_or(Error::Interrupted)?.poll(), Err(e) if e == error)
                    {
                        return Err(Error::OwnershipMismatch);
                    }
                    let n = pending
                        .as_mut()
                        .ok_or(Error::Interrupted)?
                        .native
                        .as_mut()
                        .ok_or(Error::Interrupted)?;
                    if n.failure != Some(error)
                        || std::mem::discriminant(&n.step) != step
                        || !Rc::ptr_eq(n.request.as_ref().ok_or(Error::Interrupted)?, &request)
                        || n.input.context().is_ok()
                        || n.input.require_complete().is_ok()
                    {
                        return Err(Error::OwnershipMismatch);
                    }
                }
                if before != super::lab_charges() || births != kernel::lab_native_births() {
                    return Err(Error::OwnershipMismatch);
                }
                if fault == 2 {
                    let n = pending
                        .as_mut()
                        .ok_or(Error::Interrupted)?
                        .native
                        .as_mut()
                        .ok_or(Error::Interrupted)?;
                    original_charge
                        .as_ref()
                        .ok_or(Error::Interrupted)?
                        .same_original(&n.input.lab_bootstrap_result_charge(true)?.0)?;
                    retained_result_writer.as_mut().ok_or(Error::Interrupted)?["charge_retained_after_retries"] =
                        serde_json::json!(true);
                }
                retry = Some(
                    serde_json::json!({"polls":2,"native_births_before":births,"native_births_after":kernel::lab_native_births(),"charges_before":before,"charges_after":super::lab_charges(),"same_original_request":true,"same_step":true,"original_error_retained":true,"operational_owner_reuse_refused":true}),
                );
            }
        }
    }
    let mut operations = Vec::new();
    let mut queries = Vec::new();
    let mut final_process_at = None;
    let mut process_verified_at = Vec::new();
    let preparation = if let Some(owner) = handoff.owner.as_mut() {
        owner.lab_preparation()?
    } else {
        let n = if let Some(v) = &mut complete {
            v.native.as_mut()
        } else {
            pending.as_mut().and_then(|p| p.native.as_mut())
        }
        .ok_or(Error::Interrupted)?;
        for (q, v) in &mut n.completed {
            queries.push(q.lab_evidence()?);
            operations.push(v.lab_evidence()?);
        }
        if let Some(q) = &n.query_accepted {
            queries.push(q.lab_evidence()?);
        }
        if let Some(v) = &mut n.verified {
            operations.push(v.lab_evidence()?);
        }
        final_process_at = n.final_verified_at;
        process_verified_at = n.process_verified_at.clone();
        n.input.lab_preparation()?
    };
    let writer_count = if matches!(fault, 4 | 5) {
        87
    } else if matches!(fault, 1 | 3) {
        103
    } else {
        105
    };
    let writers = preparation["writers"]
        .as_array()
        .ok_or(Error::OwnershipMismatch)?;
    let prefix = handoff.host["preparation"]["writers"]
        .as_array()
        .ok_or(Error::OwnershipMismatch)?;
    if writers.len() != writer_count
        || writers.get(..87) != Some(prefix.as_slice())
        || preparation["native_children_reaped"] != true
        || preparation["member_native_jobs_collected"] != false
        || preparation["service_reserved"] != true
        || preparation["canonical_pending"] != (fault == 2)
        || preparation["mutation_fenced"] != matches!(fault, 2 | 4 | 5)
        || preparation["entry_phase"] != "creating"
        || preparation["entry_links_absent"] != true
        || preparation["entry_attempt_absent"] != true
        || preparation["entry_terminal_absent"] != true
        || preparation["entry_producer"] != handoff.host["preparation"]["entry_producer"]
    {
        return Err(Error::OwnershipMismatch);
    }
    for key in [
        "wireguard",
        "netfilter",
        "producer_creation",
        "producer_binding",
        "producer_binding_query",
        "producer_query",
        "quarantine_query",
        "movement_query",
        "inspection",
        "attachment",
        "fresh_transport",
        "host_link",
        "base_network",
        "data_network",
        "transport_network",
        "canonical_owner_epoch",
    ] {
        if preparation[key] != handoff.host["preparation"][key] {
            return Err(Error::OwnershipMismatch);
        }
    }
    if !matches!(fault, 4 | 5) {
        let own = own_intent.as_ref().ok_or(Error::OwnershipMismatch)?;
        if own["index"] != 90
            || writers[90]["pid"] != own["pid"]
            || writers[90]["start"] != own["start"]
            || writers[90]["actual_wait_status"] != 0
            || writers[90]["verified_at"].is_null()
        {
            return Err(Error::OwnershipMismatch);
        }
        let names = ["host", "transport", "data"];
        for (i, writer) in writers.iter().enumerate().skip(87) {
            let scope = (i - 87) / 6;
            let stage = (i - 87) % 6;
            let phase = format!(
                "bootstrap_{}_{}{}",
                names[scope],
                if stage < 3 { "query_" } else { "" },
                ["intent", "birth", "result"][stage % 3]
            );
            let end = queries[scope]["deadline"]
                .as_f64()
                .ok_or(Error::OwnershipMismatch)?;
            let queued = writer["queued_at"]
                .as_f64()
                .ok_or(Error::OwnershipMismatch)?;
            let failed = fault == 2 && i == 104;
            if writer["phase"] != phase
                || !queued.is_finite()
                || queued < end - 2.
                || queued >= end
                || writer["io_deadline"] != end
                || writer["parent_deadline"] != end
                || writer["actual_wait_status"] != if failed { 9 } else { 0 }
                || if failed {
                    !writer["verified_at"].is_null()
                } else {
                    writer["verified_at"]
                        .as_f64()
                        .is_none_or(|at| !at.is_finite() || at < queued || at >= end)
                }
            {
                return Err(Error::OwnershipMismatch);
            }
        }
    }
    if !matches!(fault, 4 | 5) {
        if queries.len() != 3 || operations.len() != if matches!(fault, 1 | 3) { 2 } else { 3 } {
            return Err(Error::OwnershipMismatch);
        }
        for (index, query) in queries.iter().enumerate() {
            let history = &preparation["bootstrap_queries"][index];
            if query["actual_wait_status"] != 0
                || query["birth"] != history["birth"]
                || query["facts"] != history["facts"]
                || query["verified_at"] != history["verified_at"]
            {
                return Err(Error::OwnershipMismatch);
            }
        }
        for (index, op) in operations.iter().enumerate() {
            let history = &preparation["bootstrap"][index];
            if op["actual_wait_status"] != 0
                || op["eof"] != true
                || op["request"] != history["request"]
                || op["birth"] != history["birth"]
                || op["query"] != history["query"]
                || op["requested_at"] != queries[index]["requested_at"]
                || op["deadline"] != queries[index]["deadline"]
                || op["acknowledged"] != !(fault == 2 && index == 2)
            {
                return Err(Error::OwnershipMismatch);
            }
            if fault == 2 && index == 2 {
                if !history["result"].is_null() || !history["verified_at"].is_null() {
                    return Err(Error::OwnershipMismatch);
                }
                let proposal = &preparation["pending_bootstrap"][index];
                if proposal["request"] != history["request"]
                    || proposal["birth"] != history["birth"]
                    || proposal["result"] != op["result"]
                    || proposal["verified_at"] != op["accepted_at"]
                {
                    return Err(Error::OwnershipMismatch);
                }
            } else if op["result"] != history["result"]
                || op["accepted_at"] != history["verified_at"]
            {
                return Err(Error::OwnershipMismatch);
            }
        }
    }
    let completed_scopes = if matches!(fault, 4 | 5) {
        0
    } else if matches!(fault, 0 | 6) {
        3
    } else {
        2
    };
    if process_verified_at.len() != completed_scopes {
        return Err(Error::OwnershipMismatch);
    }
    for (index, at) in process_verified_at.iter().enumerate() {
        let end = queries[index]["deadline"]
            .as_f64()
            .ok_or(Error::OwnershipMismatch)?;
        let ack = writers[87 + index * 6 + 5]["verified_at"]
            .as_f64()
            .ok_or(Error::OwnershipMismatch)?;
        if !at.is_finite() || *at < ack || *at >= end {
            return Err(Error::OwnershipMismatch);
        }
    }
    if matches!(fault, 1..=5) && final_process_at.is_some() {
        return Err(Error::OwnershipMismatch);
    }
    if let Some(c) = &failed_constructor
        && (c["native_born"] != (fault == 1)
            || c["durable_birth_released"] != false
            || c["borrowed_registration_count"] != 2
            || !c["original_start"].is_null()
            || !c["birth"].is_null()
            || c["complete_native_registration"] != false
            || !c["result"].is_null()
            || c["actual_wait_status"]
                != if fault == 1 {
                    serde_json::json!(9)
                } else {
                    serde_json::Value::Null
                })
    {
        return Err(Error::OwnershipMismatch);
    }
    let before_drop = super::lab_charges();
    let expected = match fault {
        2 => [4, 3],
        3 => [2, 2],
        4 => [5, 5],
        5 => [4, 4],
        _ => [3, 3],
    };
    if before_drop != expected {
        return Err(Error::OwnershipMismatch);
    }
    let canonical_negative_checks = if matches!(fault, 0 | 6) {
        complete
            .as_ref()
            .ok_or(Error::Interrupted)?
            .native
            .as_ref()
            .ok_or(Error::Interrupted)?
            .input
            .context()?
            .service
            .lab_bootstrap_schema_checks()?
    } else {
        0
    };
    if !matches!(fault, 4 | 5) && (!own_released || own_held != 2 || own_negatives != 8) {
        return Err(Error::OwnershipMismatch);
    }
    let mut witness = serde_json::json!({"schema":1,"fault":fault,"own_intent_polling":own_intent,"canonical_negative_checks":canonical_negative_checks,"host_addition":handoff.host,"handoff":handoff.evidence,"preparation":preparation,
        "operations":operations,"queries":queries,"failed_constructor":failed_constructor,"failure_retry":retry,"retained_result_writer":retained_result_writer,
        "charges_before_drop":before_drop,"charges_after_drop":serde_json::Value::Null,"final_process_verified_at":final_process_at,"scope_process_verified_at":process_verified_at,
        "result_writer_held":result_held,"whole_chain_retained_after_drop":false,"original_nine_contexts_retained_after_drop":false,
        "operational_context_retained_after_drop":false,"bootstrap_context_retained_after_drop":false,
        "bootstrap_context_created":bootstrap_anchor.is_some(),"bootstrap_all_scopes_acknowledged":matches!(fault,0|6),
        "parent_pristine":vprouter_core::secret_boundary::pristine(),"placement_authorized":false,"up_authorized":false,"health_ready_authorized":false,
        "resource_cleanup_authorized":false,"multi_exit_runtime_proven":false,"requirement8_complete":false});
    drop(complete);
    drop(pending);
    drop(handoff.owner);
    handoff.original_anchors.require_retained()?;
    if handoff.anchor.upgrade().is_none()
        || bootstrap_anchor
            .as_ref()
            .is_some_and(|w| w.upgrade().is_none())
        || super::lab_charges() != before_drop
    {
        return Err(Error::OwnershipMismatch);
    }
    if let Some(charge) = &original_charge {
        let (pid, start, status) = charge.facts()?;
        if witness["retained_result_writer"]["pid"] != pid
            || witness["retained_result_writer"]["start"] != start
            || status != Some(9)
        {
            return Err(Error::OwnershipMismatch);
        }
        witness["retained_result_writer"]["charge_retained_after_drop"] = serde_json::json!(true);
    }
    for key in [
        "whole_chain_retained_after_drop",
        "original_nine_contexts_retained_after_drop",
        "operational_context_retained_after_drop",
    ] {
        witness[key] = serde_json::json!(true);
    }
    witness["bootstrap_context_retained_after_drop"] =
        serde_json::json!(bootstrap_anchor.is_some());
    witness["charges_after_drop"] = serde_json::json!(super::lab_charges());
    println!("{}", serde_json::json!({"case":label,"result":"PASS"}));
    println!("LAB_SECRET_BOOTSTRAP {witness}");
    Ok(())
}
