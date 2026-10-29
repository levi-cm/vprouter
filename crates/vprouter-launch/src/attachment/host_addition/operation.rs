//! Closed canonical operations over the original generation admission.
use super::super::super::owned::preparation::Server;
#[cfg(test)]
use super::super::operational::lab_phase;
use super::*;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::os::fd::BorrowedFd;
fn hash(bytes: &[u8]) -> [u8; 32] {
    sha2::Sha256::digest(bytes).into()
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Kind {
    TransportSockets,
    Pair,
    HostSockets,
    Move,
}
impl Kind {
    pub(crate) fn index(self) -> usize {
        match self {
            Self::TransportSockets => 0,
            Self::Pair => 1,
            Self::HostSockets => 2,
            Self::Move => 3,
        }
    }
}
#[cfg_attr(test, derive(Clone))]
pub(crate) struct Request {
    creator: u32,
    binding: Rc<Binding>,
    generation: Rc<Generation>,
    plan: vprouter_network::Plan,
    kind: Kind,
    requested_at: f64,
    digest: [u8; 32],
    addition: Option<([u8; 32], u32)>,
}
impl Request {
    pub(super) fn new(
        owner: &ObservedHostAssembly,
        kind: Kind,
        addition: Option<&vprouter_network::HostAdditionPlan>,
    ) -> Result<Rc<Self>> {
        kernel::secret::seal_parent()?;
        let n = owner.native.as_ref().ok_or(Error::Interrupted)?;
        n.check_custody()?;
        n.binding.verify(n.input.host_service()?)?;
        let generation = n
            .generation
            .as_ref()
            .ok_or(Error::OwnershipMismatch)?
            .clone();
        generation.verify(&n.binding)?;
        let addition = addition
            .map(|p| {
                Ok((
                    hash(p.intent_bytes().map_err(|_| Error::NetworkOperation)?),
                    p.planned_index().map_err(|_| Error::NetworkOperation)?,
                ))
            })
            .transpose()?;
        if (kind == Kind::Move) != addition.is_some() {
            return Err(Error::OwnershipMismatch);
        }
        let requested_at = vprouter_core::health::boot_seconds();
        let mut request = Self {
            creator: std::process::id(),
            binding: n.binding.clone(),
            generation,
            plan: n.plan.clone(),
            kind,
            requested_at,
            digest: [0; 32],
            addition,
        };
        request.digest = hash(
            &serde_json::to_vec(&(
                "original_host_link_v1",
                kind,
                request.binding.public_result(),
                request.binding.configuration_digest(),
                request.binding.data().request().spec().exit.exit_id.clone(),
                request.declaration_digest(),
                request.admission_window(),
                request.namespace(),
                request.binding.host(),
                request.addition,
                requested_at,
            ))
            .map_err(|_| Error::InvalidSpec)?,
        );
        request.verify()?;
        Ok(Rc::new(request))
    }
    pub(crate) fn verify(&self) -> Result<()> {
        if self.creator != std::process::id() || self.digest == [0; 32] {
            return Err(Error::OwnershipMismatch);
        }
        self.verify_retained()?;
        self.check()
    }
    pub(crate) fn verify_retained(&self) -> Result<()> {
        if self.creator != std::process::id() || self.digest == [0; 32] {
            return Err(Error::OwnershipMismatch);
        }
        self.binding.verify_retained()?;
        self.generation.verify(&self.binding)
    }
    pub(crate) fn check(&self) -> Result<()> {
        kernel::owner_admission_permitted()?;
        let now = vprouter_core::health::boot_seconds();
        if !now.is_finite()
            || !self.requested_at.is_finite()
            || now < self.requested_at
            || now >= self.deadline()
        {
            return Err(Error::Deadline);
        }
        Ok(())
    }
    pub(crate) fn verify_service(&self, service: &Server) -> Result<()> {
        self.verify()?;
        self.binding.verify(service)
    }
    pub(crate) fn binding(&self) -> &Rc<Binding> {
        &self.binding
    }
    pub(crate) fn kind(&self) -> Kind {
        self.kind
    }
    pub(crate) fn index(&self) -> usize {
        self.kind.index()
    }
    pub(crate) fn digest(&self) -> [u8; 32] {
        self.digest
    }
    pub(crate) fn declaration_digest(&self) -> [u8; 32] {
        self.generation.declaration.digest()
    }
    pub(crate) fn admission_window(&self) -> [f64; 3] {
        [
            self.generation.requested_at,
            self.generation.requested_at + 2.,
            self.generation.accepted_at,
        ]
    }
    pub(crate) fn requested_at(&self) -> f64 {
        self.requested_at
    }
    pub(crate) fn deadline(&self) -> f64 {
        self.requested_at + 2.
    }
    pub(crate) fn plan(&self) -> &vprouter_network::Plan {
        &self.plan
    }
    pub(crate) fn addition(&self) -> Option<([u8; 32], u32)> {
        self.addition
    }
    pub(crate) fn namespace(&self) -> super::super::Identity {
        if self.kind == Kind::HostSockets {
            self.binding.host()
        } else {
            self.binding.transport().request().source_identity()
        }
    }
    pub(crate) fn source(&self) -> BorrowedFd<'_> {
        if self.kind == Kind::HostSockets {
            self.binding.host_pin()
        } else {
            self.binding.transport().request().source()
        }
    }
    pub(crate) fn target(&self) -> BorrowedFd<'_> {
        self.binding.host_pin()
    }
}

#[derive(Clone, Copy, Debug)]
enum Step {
    Prepare,
    Intent,
    Preparing,
    Birth,
    Executing,
    Result,
    Complete,
}
struct Owner {
    #[cfg(test)]
    anchor: Rc<()>,
    creator: u32,
    input: ObservedHostAssembly,
    previous: Vec<kernel::host_link::Verified>,
    addition: Option<vprouter_network::HostAdditionPlan>,
    request: Option<Rc<Request>>,
    child: Option<kernel::host_link::Child>,
    verified: Option<kernel::host_link::Verified>,
    index: usize,
    step: Step,
    failure: Option<Error>,
}
pub(super) struct PendingHostLinks {
    native: Option<Box<Owner>>,
}
pub(super) struct HostLinkedAssembly {
    native: Option<Box<Owner>>,
}
impl HostLinkedAssembly {
    pub(super) fn bootstrap_previous(
        &mut self,
        scope: super::super::quarantine::Scope,
    ) -> Result<kernel::bootstrap::Previous<'_>> {
        self.operational_context()?;
        self.native
            .as_mut()
            .ok_or(Error::Interrupted)?
            .input
            .native
            .as_mut()
            .ok_or(Error::Interrupted)?
            .input
            .bootstrap_previous(scope)
    }
    fn retained(&self) -> Result<&Owner> {
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        if n.creator != std::process::id()
            || n.failure.is_some()
            || !matches!(n.step, Step::Complete)
            || n.index != 4
            || n.child.is_some()
            || n.verified.is_some()
        {
            return Err(Error::OwnershipMismatch);
        }
        let input = n.input()?;
        input.check_custody()?;
        let generation = input.generation.as_ref().ok_or(Error::OwnershipMismatch)?;
        generation.verify(&input.binding)?;
        if n.previous.iter().any(|v| {
            !Rc::ptr_eq(&v.request().generation, generation)
                || !Rc::ptr_eq(v.request().binding(), &input.binding)
        }) {
            return Err(Error::OwnershipMismatch);
        }
        Ok(n)
    }
    pub(super) fn require_operational_custody(&self) -> Result<()> {
        let n = self.retained()?;
        n.input()?
            .input
            .host_custody()?
            .1
            .verify_completed_host_links(&n.previous)
    }
    pub(super) fn operational_context(&self) -> Result<super::super::operational::Context<'_>> {
        let n = self.retained()?;
        let input = &n.input()?.input;
        let (binding, service) = input.host_custody()?;
        service.verify_completed_host_custody(&n.previous)?;
        Ok(super::super::operational::Context {
            binding: binding.clone(),
            source: input.operational_source()?,
            service,
        })
    }
    pub(super) fn operational_service_mut(&mut self) -> Result<&mut Server> {
        self.operational_context()?;
        self.native.as_mut().ok_or(Error::Interrupted)?.service()
    }
    pub(super) fn operational_plan(&self) -> Result<Vec<kernel::ResourceTransfer>> {
        self.require_operational_custody()?;
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        let mut plan = Vec::with_capacity(5);
        plan.push(n.input()?.input.operational_resource()?);
        for receipt in &n.previous {
            plan.push(receipt.resource_transfer()?);
        }
        Ok(plan)
    }
    pub(super) fn reserve_operational_extension(
        &self,
        plan: &[kernel::ResourceTransfer],
    ) -> Result<super::super::super::owned::preparation::assembly::OperationalReservation> {
        self.require_operational_custody()?;
        self.native
            .as_ref()
            .ok_or(Error::Interrupted)?
            .input()?
            .input
            .reserve_operational_extension(plan)
    }
    pub(super) fn fail(&mut self, error: Error) {
        if let Some(n) = &mut self.native {
            n.fail(error);
        }
    }
    pub(super) fn collect(&mut self) {
        if let Some(n) = &mut self.native {
            n.collect();
        }
    }
    pub(super) fn reaped(&self) -> bool {
        self.native
            .as_ref()
            .is_none_or(|n| n.creator == std::process::id() && n.reaped())
    }
}
// Keep the same heap-owned bundle on retention; never move its pointee onto the stack.
thread_local! {#[allow(clippy::vec_box)] static RETAINED_LINKS:RefCell<Vec<Box<Owner>>>=const{RefCell::new(Vec::new())};}
impl Owner {
    fn input(&self) -> Result<&super::Native> {
        self.input.native.as_deref().ok_or(Error::Interrupted)
    }
    fn service(&mut self) -> Result<&mut Server> {
        self.input
            .native
            .as_mut()
            .ok_or(Error::Interrupted)?
            .input
            .host_custody_mut()
    }
    fn fail(&mut self, e: Error) {
        if self.creator == std::process::id() {
            self.failure.get_or_insert(e);
            if let Some(c) = &mut self.child {
                c.cancel(e);
            }
            if let Some(n) = &mut self.input.native {
                n.fail(e);
            }
        }
    }
    fn collect(&mut self) {
        if self.creator == std::process::id() {
            if let Some(c) = &mut self.child {
                c.collect();
            }
            if let Some(n) = &mut self.input.native {
                n.collect();
            }
        }
    }
    fn reaped(&self) -> bool {
        self.child.as_ref().is_none_or(|c| c.reaped())
            && self
                .input
                .native
                .as_ref()
                .is_none_or(|n| n.input.children_reaped())
    }
    fn check(&self) -> Result<()> {
        if self.creator != std::process::id() || self.failure.is_some() {
            return Err(Error::OwnershipMismatch);
        }
        let input = self.input()?;
        input.check_custody()?;
        let (_, service) = input.input.host_custody()?;
        use super::super::super::owned::preparation::host_link::Progress;
        match self.step {
            Step::Intent => input.binding.verify_host_link_progress(
                service,
                self.request.as_ref().ok_or(Error::Interrupted)?,
                Progress::Intent,
            ),
            Step::Birth => input.binding.verify_host_link_progress(
                service,
                self.request.as_ref().ok_or(Error::Interrupted)?,
                Progress::Birth(self.child.as_ref().ok_or(Error::Interrupted)?),
            ),
            Step::Result => input.binding.verify_host_link_progress(
                service,
                self.request.as_ref().ok_or(Error::Interrupted)?,
                Progress::Result(self.verified.as_ref().ok_or(Error::Interrupted)?),
            ),
            _ => input.binding.verify(service),
        }
    }
    fn advance(&mut self) -> Result<bool> {
        self.check()?;
        match self.step {
            Step::Prepare => {
                let kind = *[
                    Kind::TransportSockets,
                    Kind::Pair,
                    Kind::HostSockets,
                    Kind::Move,
                ]
                .get(self.index)
                .ok_or(Error::OwnershipMismatch)?;
                if kind == Kind::Move {
                    let generation = self
                        .input()?
                        .generation
                        .as_ref()
                        .ok_or(Error::OwnershipMismatch)?;
                    self.addition = Some(
                        self.previous
                            .get(1)
                            .ok_or(Error::OwnershipMismatch)?
                            .prepare_addition(&generation.authority)?,
                    );
                }
                self.request = Some(Request::new(&self.input, kind, self.addition.as_ref())?);
                let request = self.request.as_ref().ok_or(Error::Interrupted)?.clone();
                let input = self.input.native.as_mut().ok_or(Error::Interrupted)?;
                input
                    .input
                    .host_custody_mut()?
                    .start_host_link(&request, &self.previous)?;
                self.step = Step::Intent;
            }
            Step::Intent => {
                let request = self.request.as_ref().ok_or(Error::Interrupted)?.clone();
                let Some(intent) = self.service()?.poll_host_link_intent(&request)? else {
                    return Ok(false);
                };
                if request.kind() == Kind::Move {
                    self.addition
                        .as_mut()
                        .ok_or(Error::OwnershipMismatch)?
                        .activate()
                        .map_err(|_| Error::NetworkOperation)?;
                }
                self.child = Some(kernel::host_link::Child::spawn(
                    request,
                    intent,
                    &mut self.previous,
                    &mut self.addition,
                )?);
                self.step = Step::Preparing;
            }
            Step::Preparing => {
                let child = self.child.as_mut().ok_or(Error::Interrupted)?;
                if !child.poll_prepared()? {
                    return Ok(false);
                }
                self.input
                    .native
                    .as_mut()
                    .ok_or(Error::Interrupted)?
                    .input
                    .host_custody_mut()?
                    .start_host_link_birth(child)?;
                self.step = Step::Birth;
            }
            Step::Birth => {
                let child = self.child.as_mut().ok_or(Error::Interrupted)?;
                let Some(gate) = self
                    .input
                    .native
                    .as_mut()
                    .ok_or(Error::Interrupted)?
                    .input
                    .host_custody_mut()?
                    .poll_host_link_birth(child)?
                else {
                    return Ok(false);
                };
                child.release(gate)?;
                self.step = Step::Executing;
            }
            Step::Executing => {
                let Some(verified) = self.child.as_mut().ok_or(Error::Interrupted)?.poll()? else {
                    return Ok(false);
                };
                self.verified = Some(verified);
                self.child.take();
                self.input
                    .native
                    .as_mut()
                    .ok_or(Error::Interrupted)?
                    .input
                    .host_custody_mut()?
                    .start_host_link_result(self.verified.as_ref().ok_or(Error::Interrupted)?)?;
                self.step = Step::Result;
            }
            Step::Result => {
                let verified = self.verified.as_mut().ok_or(Error::Interrupted)?;
                let Some(receipt) = self
                    .input
                    .native
                    .as_mut()
                    .ok_or(Error::Interrupted)?
                    .input
                    .host_custody_mut()?
                    .poll_host_link_result(verified)?
                else {
                    return Ok(false);
                };
                verified.accept(receipt)?;
                self.previous
                    .push(self.verified.take().ok_or(Error::Interrupted)?);
                self.index += 1;
                self.step = if self.index == 4 {
                    Step::Complete
                } else {
                    Step::Prepare
                };
            }
            Step::Complete => return Err(Error::OwnershipMismatch),
        }
        if let Some(r) = &self.request {
            r.check()?;
        }
        Ok(matches!(self.step, Step::Complete))
    }
}
impl PendingHostLinks {
    pub(super) fn collect(&mut self) {
        if let Some(n) = &mut self.native {
            n.collect();
        }
    }
    pub(super) fn new(slot: &mut Option<ObservedHostAssembly>) -> Result<Self> {
        let input = slot
            .as_ref()
            .ok_or(Error::Interrupted)?
            .native
            .as_ref()
            .ok_or(Error::Interrupted)?;
        input.check_custody()?;
        input.binding.verify(input.input.host_service()?)?;
        input
            .generation
            .as_ref()
            .ok_or(Error::OwnershipMismatch)?
            .verify(&input.binding)?;
        Ok(Self {
            native: Some(Box::new(Owner {
                #[cfg(test)]
                anchor: Rc::new(()),
                creator: std::process::id(),
                input: slot.take().expect("validated original host owner"),
                previous: Vec::with_capacity(4),
                addition: None,
                request: None,
                child: None,
                verified: None,
                index: 0,
                step: Step::Prepare,
                failure: None,
            })),
        })
    }
    pub(super) fn poll(&mut self) -> Result<Option<HostLinkedAssembly>> {
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        if n.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        if let Some(e) = n.failure {
            n.collect();
            return Err(e);
        }
        match n.advance() {
            Ok(false) => Ok(None),
            Ok(true) => Ok(Some(HostLinkedAssembly {
                native: self.native.take(),
            })),
            Err(e) => {
                n.fail(e);
                n.collect();
                Err(e)
            }
        }
    }
}
fn retain(mut n: Box<Owner>) {
    if n.creator != std::process::id() {
        std::mem::forget(n);
        return;
    }
    n.fail(Error::Interrupted);
    RETAINED_LINKS.with(|r| r.borrow_mut().push(n));
}
impl Drop for PendingHostLinks {
    fn drop(&mut self) {
        if let Some(n) = self.native.take() {
            retain(n);
        }
    }
}
impl Drop for HostLinkedAssembly {
    fn drop(&mut self) {
        if let Some(n) = self.native.take() {
            retain(n);
        }
    }
}
pub(super) fn poll_retained() {
    RETAINED_LINKS.with(|r| {
        for n in r.borrow_mut().iter_mut() {
            n.collect();
        }
    });
}
pub(super) fn children_reaped() -> bool {
    RETAINED_LINKS.with(|r| {
        r.borrow()
            .iter()
            .all(|n| n.creator != std::process::id() || n.reaped())
    })
}

#[cfg(test)]
impl Request {
    pub(crate) fn lab_changed_index(&self) -> Rc<Self> {
        let mut other = self.clone();
        other.kind = Kind::Pair;
        Rc::new(other)
    }
}

#[cfg(test)]
fn lab_charges() -> [usize; 2] {
    [
        kernel::lab_live_child_capacity(),
        vprouter_native_role::lab_live_child_capacity(),
    ]
}
#[cfg(test)]
fn lab_owner(pending: &mut PendingHostAddition) -> Result<&mut Owner> {
    pending
        .links
        .as_mut()
        .and_then(|p| p.native.as_deref_mut())
        .ok_or(Error::Interrupted)
}
#[cfg(test)]
pub(super) fn lab_run(fault: u8) -> Result<()> {
    lab_build(fault, false).map(|_| ())
}
#[cfg(test)]
pub(super) fn lab_added() -> Result<(HostAddedPrimary, serde_json::Value)> {
    let (value, witness) = lab_build(0, true)?;
    Ok((value.ok_or(Error::OwnershipMismatch)?, witness))
}
#[cfg(test)]
fn lab_build(
    fault: u8,
    continuation: bool,
) -> Result<(Option<HostAddedPrimary>, serde_json::Value)> {
    if continuation && fault != 0 {
        return Err(Error::OwnershipMismatch);
    }
    use std::time::Duration;
    let label = *super::LAB_LABELS
        .get(fault as usize)
        .ok_or(Error::InvalidSpec)?;
    let (original, prefix) = super::super::producer_binding::lab_bound()?;
    let old_anchors = original.lab_anchors()?;
    let before = lab_charges();
    if before != [1, 1]
        || prefix["continued_original_context"] != true
        || !prefix["charges_after_drop"].is_null()
    {
        return Err(Error::OwnershipMismatch);
    }
    let mut slot = Some(original);
    let mut pending = PendingHostAddition::new(
        &mut slot,
        Path::new("/var/lib/vprouter-v2-lab/secret-host-baseline.json"),
    )?;
    let baseline_anchor = Rc::downgrade(
        &pending
            .baseline
            .as_ref()
            .and_then(|v| v.native.as_ref())
            .ok_or(Error::Interrupted)?
            .anchor,
    );
    let mut admission_polls = 0u32;
    while pending.links.is_none() {
        admission_polls = admission_polls.checked_add(1).ok_or(Error::TooLarge)?;
        if pending.poll()?.is_some() {
            return Err(Error::OwnershipMismatch);
        }
        if pending.links.is_none() {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    let n = lab_owner(&mut pending)?;
    let link_anchor = Rc::downgrade(&n.anchor);
    let generation = n.input()?.generation.as_ref().ok_or(Error::Interrupted)?;
    let generation_anchor = Rc::downgrade(generation);
    let declaration = serde_json::to_value(
        generation
            .declaration
            .observation(&generation.allocation, generation.host)?,
    )
    .map_err(|_| Error::InvalidSpec)?;
    let admission = serde_json::json!({"declaration":generation.declaration.digest(),"namespace":generation.host,
        "requested_at":generation.requested_at,"deadline":generation.requested_at+2.,"accepted_at":generation.accepted_at,
        "polls":admission_polls,"two_original_reads_verified":true,"same_generation_owner_retained":true,"declared_baseline":declaration});
    let planned_index = vprouter_network::planned_host_link_index(
        &generation.allocation,
        &n.input()?.binding.data().request().spec().exit.exit_id,
    )
    .map_err(|_| Error::InvalidSpec)?;
    n.service()?.lab_hold_host_writer(true)?;
    let mut queued_polls = 0u32;
    let mut held_polls = 0u32;
    let mut negative_checks = 0usize;
    let mut intent_released = false;
    let mut first_writer = None;
    let mut armed = false;
    let mut result_held = false;
    let mut original_charge = None;
    let outcome = loop {
        let n = lab_owner(&mut pending)?;
        if n.index == 0 && matches!(n.step, Step::Intent) && !intent_released {
            let request = n.request.as_ref().ok_or(Error::Interrupted)?.clone();
            if queued_polls == 0 {
                let input = n.input()?;
                negative_checks += input
                    .binding
                    .lab_host_intent_negatives(input.input.host_custody()?.1, &request)?;
                queued_polls = 1;
            }
            if n.service()?.lab_checkpoint()? {
                if held_polls == 0 {
                    let input = n.input()?;
                    negative_checks += input
                        .binding
                        .lab_host_intent_negatives(input.input.host_custody()?.1, &request)?;
                    first_writer = n.service()?.lab_pending_writer_identity()?;
                }
                held_polls += 1;
                if held_polls == 3 {
                    n.service()?.lab_release_host_intent()?;
                    intent_released = true;
                }
            }
        }
        if n.index == 3 && !armed {
            if matches!(fault, 1 | 3) && matches!(n.step, Step::Intent) {
                kernel::host_link::lab_arm(n.request.as_ref().ok_or(Error::Interrupted)?, fault)?;
                armed = true;
            } else if fault == 2 && matches!(n.step, Step::Executing) {
                n.service()?.lab_hold_host_writer(false)?;
                armed = true;
            }
        }
        if fault == 2
            && armed
            && n.index == 3
            && matches!(n.step, Step::Result)
            && n.service()?.lab_checkpoint()?
        {
            result_held = true;
            original_charge = Some(
                n.input
                    .native
                    .as_mut()
                    .ok_or(Error::Interrupted)?
                    .input
                    .lab_host_result_charge(false)?
                    .0,
            );
            n.fail(Error::ChildFailed);
        }
        match pending.poll() {
            Ok(Some(v)) => break Ok(v),
            Ok(None) => std::thread::sleep(Duration::from_millis(1)),
            Err(e) => break Err(e),
        }
    };
    let mut complete = None;
    let mut failed_constructor = None;
    let mut failure_retry = None;
    let mut retained_result_writer = None;
    match outcome {
        Ok(v) if fault == 0 => complete = Some(v),
        Ok(_) => return Err(Error::OwnershipMismatch),
        Err(error) => {
            let n = lab_owner(&mut pending)?;
            let r = n.request.as_ref().ok_or(Error::Interrupted)?.clone();
            eprintln!(
                "LAB_SECRET_HOST_ADDITION_FAILURE kind={:?} step={:?} reason={error:?} requested_at={} deadline={} now={}",
                r.kind(),
                n.step,
                r.requested_at(),
                r.deadline(),
                vprouter_core::health::boot_seconds()
            );
            if !armed
                || !(fault == 2 && result_held && error == Error::ChildFailed
                    || matches!(fault, 1 | 3) && error == Error::DescriptorInventory)
            {
                return Err(error);
            }
            // Collection bound only: it cannot accept or renew the failed operation.
            let collect_end = vprouter_core::health::boot_seconds() + 2.;
            loop {
                n.collect();
                if matches!(fault, 1 | 3) {
                    failed_constructor = if let Some(c) = n.child.as_mut() {
                        if c.reaped() {
                            Some(c.lab_evidence()?)
                        } else {
                            None
                        }
                    } else {
                        kernel::host_link::lab_failed_context(&r)?
                    };
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
                let (charge, mut evidence) = n
                    .input
                    .native
                    .as_mut()
                    .ok_or(Error::Interrupted)?
                    .input
                    .lab_host_result_charge(true)?;
                original_charge
                    .as_ref()
                    .ok_or(Error::OwnershipMismatch)?
                    .same_original(&charge)?;
                evidence["charge_retained_before_cancel"] = serde_json::json!(true);
                evidence["charge_retained_after_collection"] = serde_json::json!(true);
                evidence["charge_retained_after_retries"] = serde_json::json!(false);
                evidence["charge_retained_after_drop"] = serde_json::json!(false);
                retained_result_writer = Some(evidence);
            }
            let old_step = std::mem::discriminant(&n.step);
            let births = kernel::lab_native_births();
            let charges = lab_charges();
            for _ in 0..2 {
                if !matches!(pending.poll(),Err(e) if e==error) {
                    return Err(Error::OwnershipMismatch);
                }
                let n = lab_owner(&mut pending)?;
                if n.failure != Some(error)
                    || std::mem::discriminant(&n.step) != old_step
                    || !Rc::ptr_eq(n.request.as_ref().ok_or(Error::Interrupted)?, &r)
                    || !matches!(
                        n.input()?.input.host_custody(),
                        Err(Error::OwnershipMismatch)
                    )
                {
                    return Err(Error::OwnershipMismatch);
                }
            }
            if kernel::lab_native_births() != births || lab_charges() != charges {
                return Err(Error::OwnershipMismatch);
            }
            if fault == 2 {
                let (charge, _) = lab_owner(&mut pending)?
                    .input
                    .native
                    .as_mut()
                    .ok_or(Error::Interrupted)?
                    .input
                    .lab_host_result_charge(true)?;
                original_charge
                    .as_ref()
                    .ok_or(Error::OwnershipMismatch)?
                    .same_original(&charge)?;
                retained_result_writer.as_mut().ok_or(Error::Interrupted)?["charge_retained_after_retries"] =
                    serde_json::json!(true);
            }
            failure_retry = Some(
                serde_json::json!({"polls":2,"native_births_before":births,"native_births_after":kernel::lab_native_births(),
                "charges_before":charges,"charges_after":lab_charges(),"same_original_request":true,"same_step":true,"original_error_retained":true,"generation_reuse_refused":true}),
            );
        }
    }
    lab_phase("host.writer_summary", false);
    let n = if let Some(c) = complete.as_mut() {
        c.original.native.as_mut().ok_or(Error::Interrupted)?
    } else {
        lab_owner(&mut pending)?
    };
    let mut operations = n
        .previous
        .iter_mut()
        .map(kernel::host_link::Verified::lab_evidence)
        .collect::<Result<Vec<_>>>()?;
    if let Some(v) = n.verified.as_mut() {
        operations.push(v.lab_evidence()?);
    }
    let preparation = n
        .input
        .native
        .as_mut()
        .ok_or(Error::Interrupted)?
        .input
        .lab_preparation()?;
    let writers = preparation["writers"]
        .as_array()
        .ok_or(Error::OwnershipMismatch)?;
    let old_writers = prefix["preparation"]["writers"]
        .as_array()
        .ok_or(Error::OwnershipMismatch)?;
    let expected_writers = if matches!(fault, 1 | 3) { 85 } else { 87 };
    if writers.len() != expected_writers
        || old_writers.len() != 75
        || writers[..75] != old_writers[..]
        || preparation["mutation_fenced"] != (fault == 2)
        || preparation["canonical_pending"] != (fault == 2)
        || preparation["native_children_reaped"] != true
        || preparation["service_reserved"] != true
        || preparation["member_native_jobs_collected"] != false
        || preparation["entry_phase"] != "creating"
        || preparation["entry_links_absent"] != true
        || preparation["entry_attempt_absent"] != true
        || preparation["entry_terminal_absent"] != true
        || preparation["entry_producer_absent"] != false
    {
        return Err(Error::OwnershipMismatch);
    }
    lab_phase("host.writer_summary", true);
    lab_phase("host.prefix_histories", false);
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
    ] {
        if preparation[key] != prefix["preparation"][key] {
            return Err(Error::OwnershipMismatch);
        }
    }
    lab_phase("host.prefix_histories", true);
    lab_phase("host.intent_oracle", false);
    if queued_polls != 1 || held_polls != 3 || negative_checks != 12 || !intent_released {
        return Err(Error::OwnershipMismatch);
    }
    lab_phase("host.intent_oracle", true);
    lab_phase("host.first_writer", false);
    let (wi, pid, start) = first_writer.ok_or(Error::OwnershipMismatch)?;
    if wi != 75
        || writers[wi]["pid"] != pid
        || writers[wi]["start"] != start
        || writers[wi]["actual_wait_status"] != 0
        || writers[wi]["verified_at"].is_null()
    {
        return Err(Error::OwnershipMismatch);
    }
    lab_phase("host.first_writer", true);
    lab_phase("host.operation_summary", false);
    let history = preparation["host_link"]
        .as_array()
        .ok_or(Error::OwnershipMismatch)?;
    if history.len() != 4 || operations.len() != if matches!(fault, 1 | 3) { 3 } else { 4 } {
        return Err(Error::OwnershipMismatch);
    }
    lab_phase("host.operation_summary", true);
    lab_phase("host.operation_receipts", false);
    for (index, op) in operations.iter().enumerate() {
        let h = &history[index];
        if op["request"] != h["request"]
            || op["birth"] != h["birth"]
            || op["actual_wait_status"] != 0
            || op["eof"] != true
            || op["original_registration_slots_verified"] != true
            || op["durable_birth_released"] != true
            || op["borrowed_registration_count"] != [0, 2, 0, 4][index]
        {
            return Err(Error::OwnershipMismatch);
        }
        if (index == 1 || index == 3)
            && (op["postcompletion_inventory_preserved"] != true
                || op["postcompletion_inventory_polls"]
                    .as_u64()
                    .is_none_or(|v| v < 2))
        {
            return Err(Error::OwnershipMismatch);
        }
        if index == 3 && fault == 2 {
            if !h["result"].is_null()
                || !h["verified_at"].is_null()
                || op["acknowledged"] != false
                || op["result"] != preparation["pending_host_link"][3]["result"]
                || op["accepted_at"] != preparation["pending_host_link"][3]["verified_at"]
            {
                return Err(Error::OwnershipMismatch);
            }
        } else if op["result"] != h["result"]
            || op["accepted_at"] != h["verified_at"]
            || op["acknowledged"] != true
        {
            return Err(Error::OwnershipMismatch);
        }
    }
    if let Some(c) = failed_constructor.as_ref() {
        if c["kind"] != "move"
            || c["request"] != history[3]["request"]
            || c["borrowed_registration_count"] != 4
            || c["durable_birth_released"] != false
            || c["complete_native_registration"] != false
            || c["original_registration_slots_verified"] != true
            || !c["birth"].is_null()
            || !c["result"].is_null()
            || !history[3]["birth"].is_null()
            || !history[3]["result"].is_null()
        {
            return Err(Error::OwnershipMismatch);
        }
        if fault == 1 {
            if c["native_born"] != true
                || !c["original_start"].is_null()
                || c["actual_wait_status"] != 9
                || c["native_job_state"] != "born"
            {
                return Err(Error::OwnershipMismatch);
            }
        } else if c["native_born"] != false
            || !c["original_pid"].is_null()
            || !c["actual_wait_status"].is_null()
            || c["native_job_state"] != "prepared"
        {
            return Err(Error::OwnershipMismatch);
        }
    }
    lab_phase("host.operation_receipts", true);
    lab_phase("host.writer_receipts", false);
    for (index, w) in writers.iter().enumerate().skip(75) {
        let op = &history[(index - 75) / 3];
        let phase = ["host_link_intent", "host_link_birth", "host_link_result"][(index - 75) % 3];
        if w["phase"] != phase
            || w["io_deadline"] != op["deadline"]
            || w["parent_deadline"] != op["deadline"]
        {
            return Err(Error::OwnershipMismatch);
        }
        if fault == 2 && index == 86 {
            if w["actual_wait_status"] != 9 || !w["verified_at"].is_null() {
                return Err(Error::OwnershipMismatch);
            }
        } else if w["actual_wait_status"] != 0 || w["verified_at"].is_null() {
            return Err(Error::OwnershipMismatch);
        }
    }
    lab_phase("host.writer_receipts", true);
    lab_phase("host.inventory", false);
    if matches!(fault, 0 | 2) {
        let op = &operations[3];
        let actual = &op["host_observation"];
        for key in ["namespace", "addresses", "routes", "rules"] {
            if actual[key] != declaration[key] {
                return Err(Error::OwnershipMismatch);
            }
        }
        let links = actual["links"].as_array().ok_or(Error::OwnershipMismatch)?;
        let prior = declaration["links"]
            .as_array()
            .ok_or(Error::OwnershipMismatch)?;
        let added = &op["result"]["host"];
        if links.len() != prior.len() + 1
            || !links.contains(added)
            || prior.iter().any(|v| !links.contains(v))
            || added["index"] != planned_index
            || added["up"] != false
        {
            return Err(Error::OwnershipMismatch);
        }
    }
    lab_phase("host.inventory", true);
    lab_phase("host.schema_oracle", false);
    let canonical_negative_checks = if fault == 0 {
        n.service()?.lab_host_schema_checks()?
    } else {
        0
    };
    lab_phase("host.schema_oracle", true);
    lab_phase("host.charges", false);
    let before_drop = lab_charges();
    let expected = match fault {
        2 => [6, 5],
        3 => [4, 4],
        _ => [5, 5],
    };
    if before_drop != expected {
        return Err(Error::OwnershipMismatch);
    }
    lab_phase("host.charges", true);
    let mut witness = serde_json::json!({"schema":1,"fault":fault,"producer_binding":prefix,"preparation":preparation,"admission":admission,
        "operations":operations,"failed_constructor":failed_constructor,"planned_host_link_index":planned_index,"canonical_negative_checks":canonical_negative_checks,
        "own_intent_polling":{"index":wi,"pid":pid,"start":start,"queued_polls":queued_polls,"held_pending_polls":held_polls-1,"negative_checks":negative_checks,"released":intent_released},
        "charges_before":before,"charges_before_drop":before_drop,"failure_retry":failure_retry,"retained_result_writer":retained_result_writer,
        "result_writer_held":result_held,"isolated_pair_creation_observed":true,"single_down_host_addition_observed":matches!(fault,0|2),
        "canonical_host_addition_acknowledged":fault==0,"unacknowledged_host_addition_retained":fault==2,
        "host_addresses_routes_rules_preserved":matches!(fault,0|2),"host_neighbor_mutation_authorized":false,
        "whole_chain_retained_after_drop":false,"original_six_contexts_retained_after_drop":false,"baseline_context_retained_after_drop":false,
        "generation_context_retained_after_drop":false,"host_link_context_retained_after_drop":false,
        "parent_pristine":vprouter_core::secret_boundary::pristine(),"placement_authorized":false,"up_authorized":false,"health_ready_authorized":false,
        "resource_cleanup_authorized":false,"multi_exit_runtime_proven":false,"requirement8_complete":false});
    witness["continued_original_context"] = serde_json::json!(continuation);
    witness["charges_after_drop"] = serde_json::Value::Null;
    if continuation {
        lab_phase("host.return", false);
        let complete = complete.take().ok_or(Error::OwnershipMismatch)?;
        lab_phase("host.return", true);
        return Ok((Some(complete), witness));
    }
    drop(complete);
    drop(pending);
    drop(slot);
    if old_anchors.len() != 6
        || old_anchors.iter().any(|w| w.upgrade().is_none())
        || baseline_anchor.upgrade().is_none()
        || link_anchor.upgrade().is_none()
        || generation_anchor.upgrade().is_none()
        || lab_charges() != before_drop
    {
        return Err(Error::OwnershipMismatch);
    }
    if fault == 2 {
        let (pid, start, status) = original_charge
            .as_ref()
            .ok_or(Error::OwnershipMismatch)?
            .facts()?;
        let r = &witness["retained_result_writer"];
        if r["pid"] != pid || r["start"] != start || status != Some(9) {
            return Err(Error::OwnershipMismatch);
        }
        witness["retained_result_writer"]["charge_retained_after_drop"] = serde_json::json!(true);
    }
    for key in [
        "whole_chain_retained_after_drop",
        "original_six_contexts_retained_after_drop",
        "baseline_context_retained_after_drop",
        "generation_context_retained_after_drop",
        "host_link_context_retained_after_drop",
    ] {
        witness[key] = serde_json::json!(true);
    }
    witness["charges_after_drop"] = serde_json::json!(lab_charges());
    println!("{}", serde_json::json!({"case":label,"result":"PASS"}));
    println!("{} {witness}", super::LAB_MARKER);
    Ok((None, witness))
}

#[cfg(test)]
pub(super) struct LabAnchors {
    original: Vec<std::rc::Weak<()>>,
    baseline: std::rc::Weak<()>,
    link: std::rc::Weak<()>,
    generation: std::rc::Weak<Generation>,
}
#[cfg(test)]
impl LabAnchors {
    pub(super) fn require_retained(&self) -> Result<()> {
        if self.original.len() != 6
            || self.original.iter().any(|w| w.upgrade().is_none())
            || self.baseline.upgrade().is_none()
            || self.link.upgrade().is_none()
            || self.generation.upgrade().is_none()
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
}
#[cfg(test)]
impl HostLinkedAssembly {
    pub(super) fn lab_preparation(&mut self) -> Result<serde_json::Value> {
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        if n.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        n.input
            .native
            .as_mut()
            .ok_or(Error::Interrupted)?
            .input
            .lab_preparation()
    }
    pub(super) fn lab_bootstrap_result_charge(
        &mut self,
        failed: bool,
    ) -> Result<(kernel::LabJournalCharge, serde_json::Value)> {
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        if n.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        n.input
            .native
            .as_mut()
            .ok_or(Error::Interrupted)?
            .input
            .lab_bootstrap_result_charge(failed)
    }
    pub(super) fn lab_anchors(&self) -> Result<LabAnchors> {
        let n = self.retained()?;
        let input = n.input()?;
        Ok(LabAnchors {
            original: input.input.lab_anchors()?,
            baseline: Rc::downgrade(&input.anchor),
            link: Rc::downgrade(&n.anchor),
            generation: Rc::downgrade(input.generation.as_ref().ok_or(Error::OwnershipMismatch)?),
        })
    }
}
