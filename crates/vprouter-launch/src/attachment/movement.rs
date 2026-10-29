//! A fresh ExistingAdmitted policy query for the original DATA target.
//! Its single original end will also bind the subsequent fixed DOWN move.
//! Historical namespace custody alone never renews Docker policy admission.
#[cfg(test)]
pub(crate) mod trace;

use super::super::{kernel, owned::preparation::Server};
use super::{
    Error, InspectionRequest, QueryKind, Result,
    provision::{PendingProvision, ProvisionedTransport},
};
use std::{cell::RefCell, rc::Rc};

impl InspectionRequest {
    fn for_movement(input: &ProvisionedTransport) -> Result<Rc<Self>> {
        let requested_at = Self::start_clock()?;
        let movement = input.movement_binding()?;
        movement.verify(input.service_ref()?)?;
        let original = movement.data().request();
        original.revalidate_retained_process()?;
        let staging = serde_json::from_slice(
            &serde_json::to_vec(original.staging()).map_err(|_| Error::InvalidSpec)?,
        )
        .map_err(|_| Error::InvalidSpec)?;
        use sha2::Digest;
        let digest = sha2::Sha256::digest(
            serde_json::to_vec(&(
                "existing_admitted_data_movement_v1",
                original.spec(),
                &staging,
                movement.public_result(),
                original.digest(),
                movement.data().birth()?,
                movement.transport().request().digest(),
                movement.transport().birth()?,
                QueryKind::MovementRecheck,
                requested_at,
            ))
            .map_err(|_| Error::InvalidSpec)?,
        )
        .into();
        let request = Rc::new(Self {
            creator: std::process::id(),
            spec: original.spec().clone(),
            staging,
            binding: movement.query_public_binding(),
            requested_at,
            digest,
            kind: QueryKind::MovementRecheck,
            mounted: None,
            movement: Some(movement),
            quarantine: None,
        });
        request.verify_service(input.service_ref()?)?;
        request.check_deadline()?;
        Ok(request)
    }
    fn revalidate_movement_process(&self, service: &Server) -> Result<()> {
        self.verify_service(service)?;
        self.revalidate_movement_process_pins()
    }
    pub(crate) fn revalidate_movement_process_pins(&self) -> Result<()> {
        if self.kind != QueryKind::MovementRecheck {
            return Err(Error::OwnershipMismatch);
        }
        self.check_deadline()?;
        self.movement
            .as_ref()
            .ok_or(Error::OwnershipMismatch)?
            .data()
            .request()
            .revalidate_retained_process()?;
        self.check_deadline()
    }
}

pub(super) struct PendingMovement {
    native: Option<Box<Native>>,
}
/// A current fixed query bound to the SAME movement clock. It is not a general
/// replacement Admission and cannot authorize a different namespace or UP.
pub(super) struct MovedPrimary {
    native: Option<Box<Native>>,
}
impl MovedPrimary {
    pub(super) fn assembly_operations(&self) -> Result<&[kernel::wireguard_role::Verified]> {
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        if n.creator != std::process::id()
            || n.failure.is_some()
            || !matches!(n.step, Step::Complete)
            || n.input.is_some()
            || n.moving.is_some()
            || n.verified.is_some()
            || n.accepted.is_none()
        {
            return Err(Error::OwnershipMismatch);
        }
        n.moved
            .as_ref()
            .ok_or(Error::Interrupted)?
            .assembly_operations()
    }

    pub(super) fn verify_netfilter_prefix(
        &self,
        binding: &Rc<super::super::owned::preparation::quarantine::Binding>,
        previous: &[kernel::netfilter_role::Verified],
    ) -> Result<()> {
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        if n.creator != std::process::id()
            || n.failure.is_some()
            || !matches!(n.step, Step::Complete)
        {
            return Err(Error::OwnershipMismatch);
        }
        n.moved
            .as_ref()
            .ok_or(Error::Interrupted)?
            .verify_netfilter_prefix(binding, previous)
    }
    pub(super) fn start_netfilter(
        &mut self,
        request: &Rc<super::quarantine::Request>,
        previous: &[kernel::netfilter_role::Verified],
    ) -> Result<()> {
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        if n.creator != std::process::id()
            || n.failure.is_some()
            || !matches!(n.step, Step::Complete)
        {
            return Err(Error::OwnershipMismatch);
        }
        n.moved
            .as_mut()
            .ok_or(Error::Interrupted)?
            .start_netfilter(request, previous)
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
    pub(super) fn quarantine_binding(
        &self,
    ) -> Result<Rc<super::super::owned::preparation::quarantine::Binding>> {
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        if n.creator != std::process::id()
            || n.failure.is_some()
            || !matches!(n.step, Step::Complete)
            || n.accepted.is_none()
            || n.input.is_some()
            || n.moving.is_some()
        {
            return Err(Error::OwnershipMismatch);
        }
        n.moved
            .as_ref()
            .ok_or(Error::Interrupted)?
            .quarantine_binding()
    }
    pub(super) fn service(&mut self) -> Result<&mut Server> {
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        if n.creator != std::process::id()
            || n.failure.is_some()
            || !matches!(n.step, Step::Complete)
        {
            return Err(Error::OwnershipMismatch);
        }
        n.moved.as_mut().ok_or(Error::Interrupted)?.service()
    }
    pub(super) fn service_ref(&self) -> Result<&Server> {
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        if n.creator != std::process::id()
            || n.failure.is_some()
            || !matches!(n.step, Step::Complete)
        {
            return Err(Error::OwnershipMismatch);
        }
        n.moved.as_ref().ok_or(Error::Interrupted)?.service_ref()
    }
}
struct Native {
    creator: u32,
    input: Option<ProvisionedTransport>,
    moving: Option<PendingProvision>,
    moved: Option<ProvisionedTransport>,
    request: Rc<InspectionRequest>,
    child: Option<kernel::docker_query::Child>,
    verified: Option<kernel::docker_query::Verified>,
    accepted: Option<Rc<kernel::docker_query::Accepted>>,
    step: Step,
    failure: Option<Error>,
    #[cfg(test)]
    final_process_verified_at: Option<f64>,
    #[cfg(test)]
    lab_anchor: Rc<()>,
}
#[derive(Clone, Copy)]
enum Step {
    Intent,
    Birth,
    Reading,
    Result,
    MovePreparation,
    Moving,
    Complete,
}
// Keep the same heap-owned bundle on retention; never move its pointee onto the stack.
thread_local! { #[allow(clippy::vec_box)] static RETAINED: RefCell<Vec<Box<Native>>> = const { RefCell::new(Vec::new()) }; }
impl Native {
    fn input(&self) -> Result<&ProvisionedTransport> {
        self.input.as_ref().ok_or(Error::Interrupted)
    }
    fn input_mut(&mut self) -> Result<&mut ProvisionedTransport> {
        self.input.as_mut().ok_or(Error::Interrupted)
    }

    fn fail(&mut self, error: Error) {
        if self.creator != std::process::id() {
            return;
        }
        self.failure.get_or_insert(error);
        if let Some(input) = &mut self.input
            && let Ok(service) = input.service()
        {
            service.fail(error);
        }
        if let Some(child) = &mut self.child {
            child.cancel(error);
        }
        if let Some(moving) = &mut self.moving {
            moving.fail(error);
        }
        if let Some(moved) = &mut self.moved
            && let Ok(service) = moved.service()
        {
            service.fail(error);
        }
    }
    fn collect(&mut self) {
        if self.creator != std::process::id() {
            return;
        }
        if let Some(input) = &mut self.input
            && let Ok(service) = input.service()
        {
            service.collect();
        }
        if let Some(child) = &mut self.child {
            child.collect();
        }
        if let Some(moving) = &mut self.moving {
            moving.collect();
        }
        if let Some(moved) = &mut self.moved
            && let Ok(service) = moved.service()
        {
            service.collect();
        }
    }
    fn reaped(&self) -> bool {
        self.input
            .as_ref()
            .is_none_or(|input| input.service_ref().is_ok_and(Server::children_reaped))
            && self.moving.as_ref().is_none_or(PendingProvision::reaped)
            && self
                .moved
                .as_ref()
                .is_none_or(|input| input.service_ref().is_ok_and(Server::children_reaped))
            && self
                .child
                .as_ref()
                .is_none_or(kernel::docker_query::Child::reaped)
    }
    fn advance(&mut self) -> Result<()> {
        #[cfg(test)]
        let span = trace::Span::new("outer", "entry_deadline");
        self.request.check_deadline()?;
        #[cfg(test)]
        span.finish();
        match self.step {
            Step::Intent => {
                if let Some(intent) = self
                    .input
                    .as_mut()
                    .ok_or(Error::Interrupted)?
                    .service()?
                    .poll_inspection_intent(&self.request)?
                {
                    self.child = Some(kernel::docker_query::spawn(self.request.clone(), intent)?);
                    self.input
                        .as_mut()
                        .ok_or(Error::Interrupted)?
                        .service()?
                        .start_inspection_birth(self.child.as_ref().ok_or(Error::Interrupted)?)?;
                    self.step = Step::Birth;
                }
            }
            Step::Birth => {
                let child = self.child.as_mut().ok_or(Error::Interrupted)?;
                if let Some(gate) = self
                    .input
                    .as_mut()
                    .ok_or(Error::Interrupted)?
                    .service()?
                    .poll_inspection_birth(child)?
                {
                    child.release(gate)?;
                    self.step = Step::Reading;
                }
            }
            Step::Reading => {
                if let Some(verified) = self.child.as_mut().ok_or(Error::Interrupted)?.poll()? {
                    self.verified = Some(verified);
                    self.input
                        .as_mut()
                        .ok_or(Error::Interrupted)?
                        .service()?
                        .start_inspection_result(
                            self.verified.as_ref().ok_or(Error::Interrupted)?,
                        )?;
                    self.step = Step::Result;
                }
            }
            Step::Result => {
                if let Some(receipt) = self
                    .input
                    .as_mut()
                    .ok_or(Error::Interrupted)?
                    .service()?
                    .poll_inspection_result(self.verified.as_ref().ok_or(Error::Interrupted)?)?
                {
                    self.accepted = Some(Rc::new(kernel::docker_query::Verified::accept(
                        &mut self.verified,
                        receipt,
                    )?));
                    self.accepted
                        .as_ref()
                        .ok_or(Error::Interrupted)?
                        .require()?;
                    self.request
                        .revalidate_movement_process(self.input()?.service_ref()?)?;
                    self.step = Step::MovePreparation;
                }
            }
            Step::MovePreparation => {
                let accepted = self.accepted.as_ref().ok_or(Error::Interrupted)?.clone();
                self.moving = Some(ProvisionedTransport::move_down(&mut self.input, accepted)?);
                self.step = Step::Moving;
            }
            Step::Moving => {
                #[cfg(test)]
                let span = trace::Span::new("outer", "inner_poll");
                let moved = self.moving.as_mut().ok_or(Error::Interrupted)?.poll()?;
                #[cfg(test)]
                span.finish();
                if let Some(moved) = moved {
                    self.moved = Some(moved);
                    self.moving.take();
                    #[cfg(test)]
                    let span = trace::Span::new("outer", "final_process");
                    self.request.revalidate_movement_process_pins()?;
                    #[cfg(test)]
                    span.finish();
                    #[cfg(test)]
                    {
                        let at = vprouter_core::health::boot_seconds();
                        if !at.is_finite() || at >= self.request.deadline() {
                            return Err(Error::Deadline);
                        }
                        self.final_process_verified_at = Some(at);
                    }
                    self.step = Step::Complete;
                }
            }
            Step::Complete => (),
        }
        #[cfg(test)]
        let span = trace::Span::new("outer", "final_deadline");
        self.request.check_deadline()?;
        #[cfg(test)]
        span.finish();
        Ok(())
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
impl Drop for PendingMovement {
    fn drop(&mut self) {
        if let Some(n) = self.native.take() {
            retain(n);
        }
    }
}
impl Drop for MovedPrimary {
    fn drop(&mut self) {
        if let Some(n) = self.native.take() {
            retain(n);
        }
    }
}
impl PendingMovement {
    pub(super) fn new(slot: &mut Option<ProvisionedTransport>) -> Result<Self> {
        if RETAINED.with(|r| {
            r.borrow()
                .iter()
                .filter(|n| n.creator == std::process::id())
                .count()
        }) >= 64
        {
            return Err(Error::OwnershipMismatch);
        }
        let request = InspectionRequest::for_movement(slot.as_ref().ok_or(Error::Interrupted)?)?;
        let mut value = Self {
            native: Some(Box::new(Native {
                creator: std::process::id(),
                input: Some(slot.take().ok_or(Error::Interrupted)?),
                moving: None,
                moved: None,
                request,
                child: None,
                verified: None,
                accepted: None,
                step: Step::Intent,
                failure: None,
                #[cfg(test)]
                final_process_verified_at: None,
                #[cfg(test)]
                lab_anchor: Rc::new(()),
            })),
        };
        let n = value.native.as_mut().ok_or(Error::Interrupted)?;
        n.input
            .as_mut()
            .ok_or(Error::Interrupted)?
            .service()?
            .start_inspection(&n.request)?;
        Ok(value)
    }
    pub(super) fn poll(&mut self) -> Result<Option<MovedPrimary>> {
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        if n.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        if let Some(error) = n.failure {
            n.collect();
            return Err(error);
        }
        if let Err(error) = n.advance() {
            #[cfg(test)]
            if trace::active() {
                eprintln!("LAB_MOVEMENT_PRIMARY_FAILURE scope=outer reason={error:?}");
                trace::emit(
                    "outer",
                    error,
                    serde_json::json!({
                        "outer_step": match n.step {Step::Intent=>"query_intent",Step::Birth=>"query_birth",Step::Reading=>"query_reading",Step::Result=>"query_result",Step::MovePreparation=>"move_prepare",Step::Moving=>"moving",Step::Complete=>"complete"},
                        "inner":n.moving.as_ref().and_then(PendingProvision::lab_cached_progress),
                        "completed_owner":n.moved.as_ref().and_then(ProvisionedTransport::lab_cached_progress),"final_process_verified_at":n.final_process_verified_at,
                    }),
                );
            }
            n.fail(error);
            n.collect();
            return Err(error);
        }
        if matches!(n.step, Step::Complete) {
            Ok(Some(MovedPrimary {
                native: self.native.take(),
            }))
        } else {
            Ok(None)
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
pub(crate) fn lab_run(fault: u8) -> Result<()> {
    if lab_build(fault, false)?.is_some() {
        return Err(Error::OwnershipMismatch);
    }
    Ok(())
}
#[cfg(test)]
pub(super) fn lab_moved() -> Result<(MovedPrimary, serde_json::Value)> {
    lab_build(0, true)?.ok_or(Error::OwnershipMismatch)
}
#[cfg(test)]
impl MovedPrimary {
    pub(super) fn lab_service(&mut self) -> Result<&mut Server> {
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        if n.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        n.moved.as_mut().ok_or(Error::Interrupted)?.service()
    }
    pub(super) fn lab_anchors(&self) -> Result<(std::rc::Weak<()>, std::rc::Weak<()>)> {
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        if n.creator != std::process::id()
            || n.failure.is_some()
            || !matches!(n.step, Step::Complete)
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok((
            Rc::downgrade(&n.lab_anchor),
            n.moved.as_ref().ok_or(Error::Interrupted)?.lab_weak()?,
        ))
    }
}
#[cfg(test)]
fn lab_build(fault: u8, continuation: bool) -> Result<Option<(MovedPrimary, serde_json::Value)>> {
    if continuation && fault != 0 {
        return Err(Error::InvalidSpec);
    }
    use std::time::Duration;
    let label = match fault {
        0 => "actual_secret_free_parent_original_down_wireguard_move_to_data",
        1 => "actual_wireguard_move_postbirth_failure_retains_both_namespaces",
        2 => "actual_wireguard_move_result_writer_failure_retains_original_networks",
        3 => "actual_wireguard_move_registration_failure_retains_prepared_context",
        _ => return Err(Error::InvalidSpec),
    };
    let (original, provision) = super::provision::lab_provisioned()?;
    let weak = original.lab_weak()?;
    let mut original = Some(original);
    let mut sockets = ProvisionedTransport::data_sockets(&mut original)?;
    let with_sockets = loop {
        match sockets.poll() {
            Ok(Some(value)) => break value,
            Ok(None) => std::thread::sleep(Duration::from_millis(1)),
            Err(error) => {
                eprintln!("LAB_SECRET_MOVEMENT_FAILURE phase=data_sockets reason={error:?}");
                return Err(error);
            }
        }
    };
    let mut with_sockets = Some(with_sockets);
    let mut pending = PendingMovement::new(&mut with_sockets)?;
    let original_request = &pending.native.as_ref().ok_or(Error::Interrupted)?.request;
    trace::arm(
        original_request.digest(),
        original_request.requested_at(),
        original_request.deadline(),
    );
    let movement_weak = Rc::downgrade(
        &pending
            .native
            .as_ref()
            .ok_or(Error::Interrupted)?
            .lab_anchor,
    );
    let mut armed = false;
    let mut held = false;
    let result = loop {
        let n = pending.native.as_mut().ok_or(Error::Interrupted)?;
        if let Some(moving) = &mut n.moving {
            held |= moving.lab_move_injection(fault, &mut armed)?;
        }
        match pending.poll() {
            Ok(Some(value)) => break Ok(value),
            Ok(None) => std::thread::sleep(Duration::from_millis(1)),
            Err(error) => break Err(error),
        }
    };
    let mut complete = None;
    let mut failed_constructor = None;
    match result {
        Ok(value) if fault == 0 => complete = Some(value),
        Ok(_) => return Err(Error::OwnershipMismatch),
        Err(error) => {
            let n = pending.native.as_mut().ok_or(Error::Interrupted)?;
            eprintln!(
                "LAB_SECRET_MOVEMENT_FAILURE phase={} reason={error:?} requested_at={} deadline={} now={}",
                match n.step {
                    Step::Intent => "query_intent",
                    Step::Birth => "query_birth",
                    Step::Reading => "query_reading",
                    Step::Result => "query_result",
                    Step::MovePreparation => "move_prepare",
                    Step::Moving => "moving",
                    Step::Complete => "complete",
                },
                n.request.requested_at(),
                n.request.deadline(),
                vprouter_core::health::boot_seconds()
            );
            if !armed
                || !(fault == 2 && held && error == Error::ChildFailed
                    || matches!(fault, 1 | 3) && error == Error::DescriptorInventory)
            {
                return Err(error);
            }
            // Collection only; this does not extend any query/mutation end.
            let collect_end = vprouter_core::health::boot_seconds() + 2.;
            loop {
                n.collect();
                if matches!(fault, 1 | 3) {
                    failed_constructor = n
                        .moving
                        .as_mut()
                        .ok_or(Error::Interrupted)?
                        .lab_failed_move()?;
                }
                if n.reaped() && (fault == 2 || failed_constructor.is_some()) {
                    break;
                }
                if vprouter_core::health::boot_seconds() >= collect_end {
                    return Err(Error::Deadline);
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    }
    let n = if let Some(v) = &mut complete {
        v.native.as_mut()
    } else {
        pending.native.as_mut()
    }
    .ok_or(Error::Interrupted)?;
    let evidence = if let Some(value) = &mut n.moved {
        value.lab_movement_evidence()?
    } else {
        n.moving
            .as_mut()
            .ok_or(Error::Interrupted)?
            .lab_movement_evidence()?
    };
    let query = n
        .accepted
        .as_ref()
        .ok_or(Error::Interrupted)?
        .lab_evidence()?;
    let preparation = &evidence["preparation"];
    let writers = preparation["writers"]
        .as_array()
        .ok_or(Error::OwnershipMismatch)?;
    let old_writers = provision["preparation"]["writers"]
        .as_array()
        .ok_or(Error::OwnershipMismatch)?;
    let histories = preparation["wireguard"]
        .as_array()
        .ok_or(Error::OwnershipMismatch)?;
    let operations = evidence["operations"]
        .as_array()
        .ok_or(Error::OwnershipMismatch)?;
    if writers.len() != if matches!(fault, 1 | 3) { 40 } else { 42 }
        || writers.get(..33) != Some(old_writers.as_slice())
        || histories.len() != 5
        || histories.get(..3)
            != provision["preparation"]["wireguard"]
                .as_array()
                .map(Vec::as_slice)
        || operations.len() != if matches!(fault, 1 | 3) { 4 } else { 5 }
        || operations.get(..3) != provision["operations"].as_array().map(Vec::as_slice)
        || provision["continued_original_context"] != true
        || provision["whole_context_retained_after_drop"] != false
        || preparation["canonical_owner_epoch"] != provision["preparation"]["canonical_owner_epoch"]
        || preparation["inspection"] != provision["preparation"]["inspection"]
        || preparation["attachment"] != provision["preparation"]["attachment"]
        || preparation["fresh_transport"] != provision["preparation"]["fresh_transport"]
        || preparation["base_network"] != provision["preparation"]["base_network"]
        || preparation["data_network"] != provision["preparation"]["data_network"]
        || preparation["transport_network"] != provision["preparation"]["transport_network"]
        || preparation["canonical_pending"] != (fault == 2)
        || preparation["mutation_fenced"] != (fault == 2)
        || preparation["native_children_reaped"] != true
        || preparation["member_native_jobs_collected"] != false
        || preparation["service_reserved"] != true
        || !vprouter_core::secret_boundary::pristine()
        || query["kind"] != "MovementRecheck"
        || query["actual_wait_status"] != 0
        || query["birth"] != preparation["movement_query"]["birth"]
        || query["verified_at"] != preparation["movement_query"]["verified_at"]
        || query["facts"] != preparation["movement_query"]["facts"]
        || query["requested_at"] != histories[4]["requested_at"]
        || query["deadline"] != histories[4]["deadline"]
        || histories[3]["kind"] != "data_sockets"
        || histories[4]["kind"] != "move"
        || histories[3]["namespace"] != preparation["data_network"]
        || histories[4]["namespace"] != preparation["transport_network"]
        || histories[4]["destination"] != preparation["data_network"]
        || histories[4]["movement_query"] != preparation["movement_query"]["request"]
    {
        return Err(Error::OwnershipMismatch);
    }
    // The actual original Query parent readback must advance route sequence;
    // its cached accepted state, not the earlier child report, authorizes only
    // custody transfer of that exact pair to the new operation.
    let sequences = &operations[2]["query_sequences"];
    let child_route = sequences[0][0].as_u64().ok_or(Error::OwnershipMismatch)?;
    let parent_route = sequences[1][0].as_u64().ok_or(Error::OwnershipMismatch)?;
    if parent_route <= child_route || sequences[0][1] != sequences[1][1] {
        return Err(Error::OwnershipMismatch);
    }
    let phases = [
        "wireguard_intent",
        "wireguard_birth",
        "wireguard_result",
        "movement_query_intent",
        "movement_query_birth",
        "movement_query_result",
        "wireguard_intent",
        "wireguard_birth",
        "wireguard_result",
    ];
    for (index, writer) in writers.iter().enumerate().skip(33) {
        let end = if index < 36 {
            histories[3]["deadline"].as_f64()
        } else {
            query["deadline"].as_f64()
        }
        .ok_or(Error::OwnershipMismatch)?;
        let queued = writer["queued_at"]
            .as_f64()
            .ok_or(Error::OwnershipMismatch)?;
        let failed = fault == 2 && index == 41;
        if writer["phase"] != phases[index - 33]
            || !end.is_finite()
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
    for (i, operation) in operations.iter().enumerate().skip(3) {
        let h = &histories[i];
        let result_history = if fault == 2 && i == 4 {
            if !h["result"].is_null() || !h["verified_at"].is_null() {
                return Err(Error::OwnershipMismatch);
            }
            let proposal = preparation["pending_wireguard"]
                .as_array()
                .and_then(|v| v.get(i))
                .ok_or(Error::OwnershipMismatch)?;
            if proposal["request"] != h["request"]
                || proposal["birth"] != h["birth"]
                || proposal["requested_at"] != h["requested_at"]
                || proposal["deadline"] != h["deadline"]
            {
                return Err(Error::OwnershipMismatch);
            }
            proposal
        } else {
            h
        };
        if operation["actual_wait_status"] != 0
            || operation["native_born"] != true
            || operation["native_job_state"] != "born"
            || operation["full_descriptor_registration"] != true
            || operation["context_retained"] != true
            || operation["birth"] != h["birth"]
            || operation["request"] != h["request"]
            || operation["requested_at"] != h["requested_at"]
            || operation["deadline"] != h["deadline"]
            || operation["result"] != result_history["result"]
            || operation["accepted_at"] != result_history["verified_at"]
            || operation["acknowledged"] != !(fault == 2 && i == 4)
            || operation["borrowed_registration_count"] != if i == 3 { 0 } else { 4 }
        {
            return Err(Error::OwnershipMismatch);
        }
    }
    if let Some(f) = &failed_constructor {
        if f["kind"] != "move"
            || f["request"] != histories[4]["request"]
            || f["full_descriptor_registration"] != true
            || f["borrowed_registration_count"] != 4
            || f["native_born"] != (fault == 1)
            || f["native_job_state"] != if fault == 1 { "born" } else { "prepared" }
            || !f["birth"].is_null()
            || !f["original_start"].is_null()
            || !histories[4]["birth"].is_null()
            || !histories[4]["result"].is_null()
            || if fault == 1 {
                f["actual_wait_status"] != 9 || f["original_pid"].as_u64().is_none_or(|p| p <= 1)
            } else {
                !f["actual_wait_status"].is_null() || !f["original_pid"].is_null()
            }
        {
            return Err(Error::OwnershipMismatch);
        }
    } else {
        let moved = &operations[4]["result"];
        let original = &provision["operations"][2]["result"];
        if evidence["move_borrows_both_original_pairs"] != true
            || moved["namespace"] != preparation["data_network"]
            || moved["link"]["up"] != false
            || moved["link"]["kind"] != "wireguard"
            || moved["link"]["name"] != original["link"]["name"]
            || moved["link"]["alias"] != original["link"]["alias"]
            || moved["wireguard"]["public_key"] != original["wireguard"]["public_key"]
            || moved["wireguard"]["peers"] != original["wireguard"]["peers"]
        {
            return Err(Error::OwnershipMismatch);
        }
    }
    let final_process_verified_at = n.final_process_verified_at;
    if fault == 0 {
        let at = final_process_verified_at.ok_or(Error::OwnershipMismatch)?;
        let ack = writers[41]["verified_at"]
            .as_f64()
            .ok_or(Error::OwnershipMismatch)?;
        if !at.is_finite() || at < ack || at >= n.request.deadline() {
            return Err(Error::OwnershipMismatch);
        }
    } else if final_process_verified_at.is_some() {
        return Err(Error::OwnershipMismatch);
    }
    let witness = serde_json::json!({"schema":1,"fault":fault,"provision":provision,
        "preparation":preparation,"operations":operations,"movement_query":query,
        "final_process_verified_at":final_process_verified_at,"original_query_parent_readback_advanced":true,
        "failed_constructor":failed_constructor,"held_real_result_writer":held,
        "unacknowledged_native_result_retained":fault==2,"move_borrows_both_original_pairs":evidence["move_borrows_both_original_pairs"],
        "parent_pristine":true,"same_service_retained":true,"whole_chain_retained_after_drop":!continuation,"movement_context_retained_after_drop":!continuation,"original_provision_context_retained_after_drop":!continuation,"continued_original_context":continuation,
        "data_move_completed":matches!(fault,0|2),"wireguard_down_only":true,"host_resources_created":false,
        "operational_reuse_authorized":false,"requirement8_complete":false});
    if continuation {
        let moved = complete.take().ok_or(Error::OwnershipMismatch)?;
        return Ok(Some((moved, witness)));
    }
    drop(complete);
    drop(pending);
    drop(sockets);
    if weak.upgrade().is_none() || movement_weak.upgrade().is_none() {
        return Err(Error::OwnershipMismatch);
    }
    println!("{}", serde_json::json!({"case":label,"result":"PASS"}));
    println!("LAB_SECRET_MOVEMENT {witness}");
    Ok(None)
}
