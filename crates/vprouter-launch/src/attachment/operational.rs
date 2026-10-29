//! Consuming owner for the next operational transition. This handoff retires
//! only original completed child charges: it grants no UP, placement, policy
//! permit or READY, and every resource remains nonquiet and originally owned.
pub(crate) mod bootstrap;
mod producer;
use super::super::{
    kernel::ResourceTransfer, owned::preparation::assembly::OperationalReservation,
};
use super::{Error, Result, host_addition::HostAddedPrimary};
use std::cell::RefCell;

pub(super) struct Context<'a> {
    pub(super) binding: std::rc::Rc<super::super::owned::preparation::quarantine::Binding>,
    pub(super) source: std::rc::Rc<super::super::kernel::producer_creation::Source>,
    pub(super) service: &'a super::super::owned::preparation::Server,
}
struct Native {
    creator: u32,
    original: HostAddedPrimary,
    plan: Vec<ResourceTransfer>,
    reservation: Option<OperationalReservation>,
    retired: usize,
    complete: bool,
    failure: Option<Error>,
    #[cfg(test)]
    anchor: std::rc::Rc<()>,
}
pub(crate) struct OperationalOwner {
    native: Option<Box<Native>>,
}
// Retention moves only the unique heap owner, never the complete pointee.
thread_local! {
    #[allow(clippy::vec_box)]
    static RETAINED: RefCell<Vec<Box<Native>>> = const { RefCell::new(Vec::new()) };
}
impl Native {
    fn fail(&mut self, error: Error) {
        if self.creator == std::process::id() {
            self.failure.get_or_insert(error);
            if let Some(reservation) = &self.reservation {
                reservation.latch_failure();
            }
            self.original.fail(error);
        }
    }
}
impl OperationalOwner {
    pub(super) fn bootstrap_previous(
        &mut self,
        scope: super::quarantine::Scope,
    ) -> Result<super::super::kernel::bootstrap::Previous<'_>> {
        self.require_complete()?;
        self.native
            .as_mut()
            .ok_or(Error::Interrupted)?
            .original
            .bootstrap_previous(scope)
    }
    pub(super) fn fail(&mut self, error: Error) {
        if let Some(n) = &mut self.native {
            n.fail(error);
        }
    }
    pub(super) fn collect(&mut self) {
        if let Some(n) = &mut self.native
            && n.creator == std::process::id()
        {
            n.original.collect();
        }
    }
    pub(super) fn reaped(&self) -> bool {
        self.native
            .as_ref()
            .is_none_or(|n| n.creator == std::process::id() && n.original.children_reaped())
    }
    pub(super) fn new(slot: &mut Option<HostAddedPrimary>) -> Result<Self> {
        // Store the whole original Generation, producer, tables, sockets and
        // canonical owner before even deriving the retained ticket plan.
        let mut value = Self {
            native: Some(Box::new(Native {
                creator: std::process::id(),
                original: slot.take().ok_or(Error::Interrupted)?,
                plan: Vec::new(),
                reservation: None,
                retired: 0,
                complete: false,
                failure: None,
                #[cfg(test)]
                anchor: std::rc::Rc::new(()),
            })),
        };
        let n = value.native.as_mut().ok_or(Error::Interrupted)?;
        #[cfg(test)]
        lab_phase("handoff.plan", false);
        n.plan = n.original.operational_plan()?;
        #[cfg(test)]
        lab_phase("handoff.plan", true);
        #[cfg(test)]
        lab_phase("handoff.reserve", false);
        n.reservation = Some(n.original.reserve_operational_extension(&n.plan)?);
        #[cfg(test)]
        lab_phase("handoff.reserve", true);
        Ok(value)
    }
    pub(super) fn poll(&mut self) -> Result<bool> {
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        if n.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        if let Some(error) = n.failure {
            n.original.collect();
            return Err(error);
        }
        if n.complete {
            self.require_complete()?;
            return Ok(true);
        }
        let result = (|| {
            let reservation = n.reservation.as_ref().ok_or(Error::OwnershipMismatch)?;
            reservation.require_pending()?;
            if n.retired < n.plan.len() {
                n.plan[n.retired].retire_capacity()?;
                n.retired += 1;
            }
            if n.retired == n.plan.len() {
                reservation.finish(&n.plan)?;
                n.complete = true;
            }
            Ok(n.complete)
        })();
        if let Err(error) = result {
            n.fail(error);
            n.original.collect();
        }
        result
    }
    // Custody only while its exact typed query/operation writer is pending.
    // The caller must additionally prove its own continuation before polling it.
    pub(super) fn context(&self) -> Result<Context<'_>> {
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        if n.creator != std::process::id() || n.failure.is_some() || !n.complete || n.retired != 5 {
            return Err(Error::OwnershipMismatch);
        }
        n.reservation
            .as_ref()
            .ok_or(Error::OwnershipMismatch)?
            .require_resources(&n.plan)?;
        n.original.operational_context()
    }
    pub(super) fn service_mut(&mut self) -> Result<&mut super::super::owned::preparation::Server> {
        self.context()?;
        self.native
            .as_mut()
            .ok_or(Error::Interrupted)?
            .original
            .operational_service_mut()
    }
    pub(super) fn require_complete(&self) -> Result<()> {
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        if n.creator != std::process::id() || n.failure.is_some() || !n.complete || n.retired != 5 {
            return Err(Error::OwnershipMismatch);
        }
        n.reservation
            .as_ref()
            .ok_or(Error::OwnershipMismatch)?
            .require_complete(&n.plan)?;
        n.original.require_operational_custody()
    }
}
impl Drop for OperationalOwner {
    fn drop(&mut self) {
        let Some(mut n) = self.native.take() else {
            return;
        };
        if n.creator != std::process::id() {
            std::mem::forget(n);
            return;
        }
        n.fail(Error::Interrupted);
        RETAINED.with(|r| r.borrow_mut().push(n));
    }
}
pub(super) fn poll_retained() {
    bootstrap::poll_retained();
    RETAINED.with(|r| {
        for n in r.borrow_mut().iter_mut() {
            if n.creator == std::process::id() {
                n.original.collect();
            }
        }
    });
}
pub(super) fn children_reaped() -> bool {
    bootstrap::children_reaped()
        && RETAINED.with(|r| {
            r.borrow()
                .iter()
                .all(|n| n.creator != std::process::id() || n.original.children_reaped())
        })
}

#[cfg(test)]
impl OperationalOwner {
    pub(super) fn lab_preparation(&mut self) -> Result<serde_json::Value> {
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        if n.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        n.original.lab_preparation()
    }
    pub(super) fn lab_bootstrap_result_charge(
        &mut self,
        failed: bool,
    ) -> Result<(super::super::kernel::LabJournalCharge, serde_json::Value)> {
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        if n.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        n.original.lab_bootstrap_result_charge(failed)
    }
}

#[cfg(test)]
fn lab_charges() -> [usize; 2] {
    [
        super::super::kernel::lab_live_child_capacity(),
        vprouter_native_role::lab_live_child_capacity(),
    ]
}
#[cfg(test)]
pub(super) fn lab_phase(stage: &'static str, complete: bool) {
    let event = if complete { "ok" } else { "begin" };
    eprintln!("LAB_SECRET_BOOTSTRAP_PHASE stage={stage} event={event}");
}
#[cfg(test)]
fn lab_retirement_phase(complete: bool, retired: usize) {
    let event = if complete { "ok" } else { "begin" };
    let retired = retired.min(5);
    eprintln!("LAB_SECRET_BOOTSTRAP_PHASE stage=handoff.retire event={event} retired={retired}");
}
#[cfg(test)]
pub(super) struct LabHandoff {
    pub(super) owner: Option<OperationalOwner>,
    pub(super) host: serde_json::Value,
    pub(super) evidence: serde_json::Value,
    pub(super) original_anchors: super::host_addition::LabAnchors,
    pub(super) anchor: std::rc::Weak<()>,
}
#[cfg(test)]
pub(super) fn lab_handoff(fault: u8) -> Result<LabHandoff> {
    lab_phase("handoff.host", false);
    let (input, host) = super::host_addition::lab_added()?;
    lab_phase("handoff.host", true);
    lab_phase("handoff.anchors", false);
    let original_anchors = input.lab_anchors()?;
    lab_phase("handoff.anchors", true);
    lab_phase("handoff.host_witness", false);
    if host["fault"] != 0
        || host["continued_original_context"] != true
        || !host["charges_after_drop"].is_null()
        || lab_charges() != [5, 5]
    {
        return Err(Error::OwnershipMismatch);
    }
    lab_phase("handoff.host_witness", true);
    let mut slot = Some(input);
    lab_phase("handoff.construct", false);
    let mut owner = OperationalOwner::new(&mut slot)?;
    lab_phase("handoff.construct", true);
    let anchor = std::rc::Rc::downgrade(&owner.native.as_ref().ok_or(Error::Interrupted)?.anchor);
    let before = lab_charges();
    let mut duplicate = None;
    if fault == 6 {
        let n = owner.native.as_ref().ok_or(Error::Interrupted)?;
        let first = lab_charges();
        if n.original.reserve_operational_extension(&n.plan).is_ok() || first != lab_charges() {
            return Err(Error::OwnershipMismatch);
        }
        duplicate = Some(serde_json::json!({"before":first,"after":lab_charges(),"refused":true}));
    }
    let mut repeats = 0usize;
    let mut fence_counts = None;
    loop {
        let n = owner.native.as_ref().ok_or(Error::Interrupted)?;
        if matches!(fault, 4 | 5) && n.retired == usize::from(fault == 5) {
            n.reservation
                .as_ref()
                .ok_or(Error::OwnershipMismatch)?
                .lab_fence()?;
            let counts = lab_charges();
            for _ in 0..2 {
                if owner.poll() != Err(Error::OwnershipMismatch)
                    || lab_charges() != counts
                    || owner.require_complete().is_ok()
                    || owner.context().is_ok()
                {
                    return Err(Error::OwnershipMismatch);
                }
            }
            fence_counts =
                Some(serde_json::json!({"before":counts,"after":lab_charges(),"refused_polls":2}));
            break;
        }
        let retired = owner.native.as_ref().ok_or(Error::Interrupted)?.retired;
        lab_retirement_phase(false, retired);
        let complete = owner.poll()?;
        let n = owner.native.as_mut().ok_or(Error::Interrupted)?;
        if n.retired != retired + 1 {
            return Err(Error::OwnershipMismatch);
        }
        let counts = lab_charges();
        if n.plan[retired].retire_capacity().is_ok() || lab_charges() != counts {
            return Err(Error::OwnershipMismatch);
        }
        lab_retirement_phase(true, n.retired);
        repeats += 1;
        if complete {
            break;
        }
    }
    lab_phase("handoff.final_counts", false);
    let after = lab_charges();
    let n = owner.native.as_ref().ok_or(Error::Interrupted)?;
    let expected = match fault {
        4 => 0,
        5 => 1,
        _ => 5,
    };
    if n.retired != expected
        || after != [5 - expected, 5 - expected]
        || n.complete != (expected == 5)
        || n.failure.is_some() != matches!(fault, 4 | 5)
        || !n.original.children_reaped()
    {
        return Err(Error::OwnershipMismatch);
    }
    lab_phase("handoff.final_counts", true);
    lab_phase("handoff.resource_evidence", false);
    let resources = n
        .plan
        .iter()
        .map(ResourceTransfer::lab_evidence)
        .collect::<Result<Vec<_>>>()?;
    lab_phase("handoff.resource_evidence", true);
    lab_phase("handoff.reservation_evidence", false);
    let reservation = n
        .reservation
        .as_ref()
        .ok_or(Error::OwnershipMismatch)?
        .lab_evidence()?;
    lab_phase("handoff.reservation_evidence", true);
    lab_phase("handoff.preparation_read", false);
    let preparation = owner.lab_preparation()?;
    lab_phase("handoff.preparation_read", true);
    lab_phase("handoff.preparation_equal", false);
    let mut prior = host["preparation"].clone();
    prior["mutation_fenced"] = serde_json::json!(matches!(fault, 4 | 5));
    if preparation != prior {
        return Err(Error::OwnershipMismatch);
    }
    lab_phase("handoff.preparation_equal", true);
    let evidence = serde_json::json!({"resources":resources,"reservation":reservation,
        "charges_before":before,"charges_after":after,"retired_suffix_jobs":expected,"repeat_retirement_refusals":repeats,
        "duplicate_reservation":duplicate,"fence_counts":fence_counts,"preparation":preparation,
        "historical_original_jobs":15,"complete_original_job_set":20,"complete":expected==5,
        "resources_collected":false,"global_child_capacity_limit":64});
    lab_phase("handoff.return", true);
    Ok(LabHandoff {
        owner: Some(owner),
        host,
        evidence,
        original_anchors,
        anchor,
    })
}
