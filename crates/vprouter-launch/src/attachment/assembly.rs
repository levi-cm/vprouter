//! Consuming custody-only assembly. The original complete resource owners stay
//! together before reservation and through partial capacity retirement. This is
//! not operational publication, fresh policy, resource collection, or cleanup.
use super::super::{kernel::ResourceTransfer, owned::preparation::assembly::Reservation};
use super::{Error, Result, quarantine::producer::PreparedProducer};
use std::cell::RefCell;
use std::rc::Rc;
struct Native {
    creator: u32,
    input: PreparedProducer,
    plan: Vec<ResourceTransfer>,
    reservation: Option<Reservation>,
    retired: usize,
    complete: bool,
    failure: Option<Error>,
    #[cfg(test)]
    anchor: Rc<()>,
}
pub(crate) struct Assembly {
    native: Option<Box<Native>>,
}
// Keep the same heap-owned bundle on retention; never move its pointee onto the stack.
thread_local! {#[allow(clippy::vec_box)] static RETAINED:RefCell<Vec<Box<Native>>>=const{RefCell::new(Vec::new())};}
impl Native {
    fn fail(&mut self, error: Error) {
        if self.creator != std::process::id() {
            return;
        }
        self.failure.get_or_insert(error);
        self.input.fail(error);
    }
}
impl Assembly {
    pub(crate) fn bootstrap_initial(
        &mut self,
        scope: super::quarantine::Scope,
    ) -> Result<&mut super::super::kernel::netfilter_role::Verified> {
        self.require_complete()?;
        self.native
            .as_mut()
            .ok_or(Error::Interrupted)?
            .input
            .bootstrap_initial(scope)
    }
    pub(crate) fn reserve_operational_extension(
        &self,
        plan: &[ResourceTransfer],
    ) -> Result<super::super::owned::preparation::assembly::OperationalReservation> {
        let n = self.require_complete()?;
        n.input.service_ref()?.reserve_operational_extension(
            n.reservation.as_ref().ok_or(Error::OwnershipMismatch)?,
            &n.plan,
            plan,
        )
    }

    fn require_complete(&self) -> Result<&Native> {
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        if n.creator != std::process::id() || !n.complete || n.failure.is_some() || n.retired != 15
        {
            return Err(Error::OwnershipMismatch);
        }
        n.reservation
            .as_ref()
            .ok_or(Error::OwnershipMismatch)?
            .require_complete(&n.plan)?;
        Ok(n)
    }
    pub(crate) fn binding_source(
        &self,
    ) -> Result<Rc<super::super::kernel::producer_creation::Source>> {
        self.require_complete()?.input.binding_source()
    }
    pub(crate) fn binding_context(
        &self,
    ) -> Result<Rc<super::super::owned::preparation::quarantine::Binding>> {
        self.require_complete()?.input.binding_context()
    }
    pub(crate) fn service_ref(&self) -> Result<&super::super::owned::preparation::Server> {
        self.require_complete()?.input.service_ref()
    }
    pub(crate) fn service(&mut self) -> Result<&mut super::super::owned::preparation::Server> {
        self.require_complete()?;
        self.native
            .as_mut()
            .ok_or(Error::Interrupted)?
            .input
            .service()
    }
    pub(crate) fn binding_initial(
        &mut self,
    ) -> Result<&mut super::super::kernel::netfilter_role::Verified> {
        self.require_complete()?;
        self.native
            .as_mut()
            .ok_or(Error::Interrupted)?
            .input
            .binding_initial()
    }
    pub(crate) fn fail(&mut self, error: Error) {
        if let Some(n) = &mut self.native {
            n.fail(error);
        }
    }
    pub(crate) fn collect(&mut self) {
        if let Some(n) = &mut self.native {
            n.input.collect();
        }
    }
    pub(crate) fn children_reaped(&self) -> bool {
        self.native
            .as_ref()
            .is_none_or(|n| n.creator == std::process::id() && n.input.children_reaped())
    }
    pub(crate) fn new(slot: &mut Option<PreparedProducer>) -> Result<Self> {
        // Store the SAME full owner before any transfer plan validation or
        // global reservation. Err drops this wrapper into permanent retention.
        let mut value = Self {
            native: Some(Box::new(Native {
                creator: std::process::id(),
                input: slot.take().ok_or(Error::Interrupted)?,
                plan: Vec::new(),
                reservation: None,
                retired: 0,
                complete: false,
                failure: None,
                #[cfg(test)]
                anchor: Rc::new(()),
            })),
        };
        let n = value.native.as_mut().ok_or(Error::Interrupted)?;
        n.plan = n.input.assembly_plan()?;
        n.reservation = Some(n.input.service_ref()?.reserve_assembly(&n.plan)?);
        Ok(value)
    }
    pub(crate) fn poll(&mut self) -> Result<bool> {
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        if n.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        if let Some(error) = n.failure {
            return Err(error);
        }
        if n.complete {
            return Ok(true);
        }
        let result = (|| {
            n.reservation
                .as_ref()
                .ok_or(Error::OwnershipMismatch)?
                .require_pending()?;
            if n.retired < n.plan.len() {
                n.plan[n.retired].retire_capacity()?;
                n.retired += 1;
            }
            if n.retired == n.plan.len() {
                n.reservation
                    .as_ref()
                    .ok_or(Error::OwnershipMismatch)?
                    .finish(&n.plan)?;
                n.complete = true;
            }
            Ok(n.complete)
        })();
        if let Err(error) = result {
            n.fail(error);
        }
        result
    }
}
impl Drop for Assembly {
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
    RETAINED.with(|r| {
        for n in r.borrow_mut().iter_mut() {
            if n.creator == std::process::id() {
                n.input.collect();
            }
        }
    });
}

pub(super) fn children_reaped() -> bool {
    RETAINED.with(|r| {
        r.borrow()
            .iter()
            .all(|n| n.creator != std::process::id() || n.input.children_reaped())
    })
}

#[cfg(test)]
fn charges() -> [usize; 2] {
    [
        super::super::kernel::lab_live_child_capacity(),
        vprouter_native_role::lab_live_child_capacity(),
    ]
}
#[cfg(test)]
pub(crate) fn lab_run(fault: u8) -> Result<()> {
    lab_build(fault, false).map(|_| ())
}
#[cfg(test)]
pub(crate) fn lab_assembled() -> Result<(Assembly, serde_json::Value)> {
    let (owner, witness) = lab_build(0, true)?;
    Ok((owner.ok_or(Error::Interrupted)?, witness))
}
#[cfg(test)]
fn lab_build(fault: u8, continuation: bool) -> Result<(Option<Assembly>, serde_json::Value)> {
    if continuation && fault != 0 {
        return Err(Error::InvalidSpec);
    }
    let label = match fault {
        0 => "actual_secret_free_parent_original_resource_assembly",
        1 => "actual_assembly_pretransfer_failure_retains_all_resources",
        2 => "actual_assembly_partial_transfer_failure_retains_all_resources",
        3 => "actual_assembly_duplicate_reservation_refused",
        _ => return Err(Error::InvalidSpec),
    };
    let (input, quarantine) = super::quarantine::producer::lab_prepared()?;
    let old = input.lab_anchors()?;
    let before = charges();
    if before != [15, 11] {
        return Err(Error::OwnershipMismatch);
    }
    let mut slot = Some(input);
    let mut assembly = Assembly::new(&mut slot)?;
    let weak = Rc::downgrade(&assembly.native.as_ref().ok_or(Error::Interrupted)?.anchor);
    let foreign_eligibility = assembly.native.as_ref().ok_or(Error::Interrupted)?.plan[3]
        .lab_eligible_foreign_refusal()?;
    let mut duplicate = false;
    let mut duplicate_counts = None;
    if fault == 3 {
        let n = assembly.native.as_ref().ok_or(Error::Interrupted)?;
        let prior = charges();
        if !matches!(
            n.input.service_ref()?.reserve_assembly(&n.plan),
            Err(Error::LockBusy)
        ) || charges() != prior
        {
            return Err(Error::OwnershipMismatch);
        }
        duplicate = true;
        duplicate_counts = Some([prior, charges()]);
    }
    let mut repeat = false;
    let mut lower_repeat = false;
    let mut fenced_counts = None;
    if fault != 1 {
        if assembly.poll()? {
            return Err(Error::OwnershipMismatch);
        }
        let n = assembly.native.as_mut().ok_or(Error::Interrupted)?;
        let prior = charges();
        if n.retired != 1
            || !matches!(n.plan[0].retire_capacity(), Err(Error::OwnershipMismatch))
            || charges() != prior
        {
            return Err(Error::OwnershipMismatch);
        }
        repeat = true;
    }
    if matches!(fault, 1 | 2) {
        let n = assembly.native.as_ref().ok_or(Error::Interrupted)?;
        n.reservation
            .as_ref()
            .ok_or(Error::Interrupted)?
            .lab_fence()?;
        let prior = charges();
        if !matches!(assembly.poll(), Err(Error::OwnershipMismatch)) || charges() != prior {
            return Err(Error::OwnershipMismatch);
        }
        fenced_counts = Some([prior, charges()]);
    } else {
        while !assembly.poll()? {
            let n = assembly.native.as_ref().ok_or(Error::Interrupted)?;
            if n.retired == 4 {
                let prior = charges();
                n.plan[3].lab_refuse_repeated_lower_retirement()?;
                if charges() != prior {
                    return Err(Error::OwnershipMismatch);
                }
                lower_repeat = true;
            }
        }
    }
    let after = charges();
    let n = assembly.native.as_mut().ok_or(Error::Interrupted)?;
    let expected = match fault {
        1 => 0,
        2 => 1,
        _ => 15,
    };
    if n.retired != expected
        || after != [15 - expected, if expected == 15 { 0 } else { 11 }]
        || n.complete != matches!(fault, 0 | 3)
        || n.failure.is_some() != matches!(fault, 1 | 2)
        || !n.input.children_reaped()
    {
        return Err(Error::OwnershipMismatch);
    }
    let resources = n
        .plan
        .iter()
        .map(ResourceTransfer::lab_evidence)
        .collect::<Result<Vec<_>>>()?;
    if resources.len() != 15
        || resources
            .iter()
            .filter(|r| r["fully_retired"] == true)
            .count()
            != expected
    {
        return Err(Error::OwnershipMismatch);
    }
    let reservation = n
        .reservation
        .as_ref()
        .ok_or(Error::Interrupted)?
        .lab_evidence()?;
    let preparation = n.input.lab_preparation()?;
    let mut expected_preparation = quarantine["preparation"].clone();
    expected_preparation["mutation_fenced"] = serde_json::Value::Bool(matches!(fault, 1 | 2));
    if preparation != expected_preparation
        || preparation["writers"]
            .as_array()
            .is_none_or(|v| v.len() != 69)
        || preparation["native_children_reaped"] != true
        || preparation["member_native_jobs_collected"] != false
        || preparation["service_reserved"] != true
        || preparation["canonical_pending"] != false
    {
        return Err(Error::OwnershipMismatch);
    }
    let complete = n.complete;
    let mut witness = serde_json::json!({"schema":1,"fault":fault,"foreign_eligibility":foreign_eligibility,"quarantine":quarantine,"preparation":preparation,
        "resources":resources,"reservation":reservation,"charges_before":before,"charges_after":after,"charges_after_drop":serde_json::Value::Null,
        "retired_original_jobs":expected,"handoff_complete":complete,"duplicate_reservation_refused":duplicate,
        "duplicate_reservation_counts":duplicate_counts,"repeat_retirement_refused":repeat,"lower_repeat_retirement_refused":lower_repeat,"fence_blocked_next_transfer":matches!(fault,1|2),
        "fence_counts":fenced_counts,"whole_chain_retained_after_drop":!continuation,"assembly_context_retained_after_drop":!continuation,
        "producer_context_retained_after_drop":!continuation,"quarantine_context_retained_after_drop":!continuation,"movement_context_retained_after_drop":!continuation,
        "original_provision_context_retained_after_drop":!continuation,"parent_pristine":vprouter_core::secret_boundary::pristine(),
        "resource_cleanup_authorized":false,"producer_operational_publication":false,"up_authorized":false,"operational_reuse_authorized":false,
        "continued_original_context":continuation,"global_child_capacity_limit":64,"multi_exit_runtime_proven":false,"requirement8_complete":false});
    if continuation {
        return Ok((Some(assembly), witness));
    }
    drop(assembly);
    drop(slot);
    if weak.upgrade().is_none() || old.iter().any(|w| w.upgrade().is_none()) || charges() != after {
        return Err(Error::OwnershipMismatch);
    }
    witness["charges_after_drop"] = serde_json::json!(charges());
    println!("{}", serde_json::json!({"case":label,"result":"PASS"}));
    println!("LAB_SECRET_ASSEMBLY {witness}");
    Ok((None, witness))
}

#[cfg(test)]
impl Assembly {
    pub(crate) fn lab_anchors(&self) -> Result<[std::rc::Weak<()>; 5]> {
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        if n.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        let old = n.input.lab_anchors()?;
        Ok([
            Rc::downgrade(&n.anchor),
            old[0].clone(),
            old[1].clone(),
            old[2].clone(),
            old[3].clone(),
        ])
    }
    pub(crate) fn lab_bootstrap_result_charge(
        &mut self,
        failed: bool,
    ) -> Result<(super::super::kernel::LabJournalCharge, serde_json::Value)> {
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        if n.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        n.input.lab_bootstrap_result_charge(failed)
    }
    pub(crate) fn lab_preparation(&mut self) -> Result<serde_json::Value> {
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        if n.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        n.input.lab_preparation()
    }
    pub(crate) fn lab_binding_result_charge(
        &mut self,
        failed: bool,
    ) -> Result<(super::super::kernel::LabJournalCharge, serde_json::Value)> {
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        if n.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        n.input.lab_binding_result_charge(failed)
    }
    pub(crate) fn lab_host_result_charge(
        &mut self,
        failed: bool,
    ) -> Result<(super::super::kernel::LabJournalCharge, serde_json::Value)> {
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        if n.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        n.input.lab_host_result_charge(failed)
    }
}
