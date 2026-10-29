//! Canonical custody-only assembly admission. No resource/producer/network
//! publication occurs here; transferred child capacity is distinct from quiet.
use super::*;
use kernel::ResourceTransfer;
use std::{
    cell::{Cell, RefCell},
    rc::Rc,
};
const JOBS: usize = 15;
const OPERATIONAL_JOBS: usize = 5;
const OWNERS: usize = vprouter_core::config::MAX_EXITS;
struct Registry {
    creator: u32,
    owners: Vec<Rc<ReservationState>>,
}
thread_local! {static REGISTRY:RefCell<Registry>=const{RefCell::new(Registry{creator:0,owners:Vec::new()})};}
struct ReservationState {
    creator: u32,
    shared: Rc<SharedJournal>,
    member: String,
    epoch: OwnerDomainRecord,
    jobs: Vec<kernel::NativeJobDrain>,
    complete: Cell<bool>,
    operational: RefCell<Option<Rc<OperationalState>>>,
}
/// Non-Clone original reservation; the global registry retains even abandoned
/// reservations and bounds their total storage independently of child64.
pub(crate) struct Reservation {
    state: Rc<ReservationState>,
}
impl Reservation {
    pub(crate) fn require_complete(&self, plan: &[ResourceTransfer]) -> Result<()> {
        let s = &self.state;
        if s.creator != std::process::id()
            || !s.complete.get()
            || s.shared.fenced.get()
            || s.shared.journal.borrow().record.owner_epoch.as_ref() != Some(&s.epoch)
            || s.shared
                .native_jobs
                .borrow()
                .transferring
                .contains(&s.member)
            || !s.shared.services.borrow().contains(&s.member)
            || s.operational
                .borrow()
                .as_ref()
                .is_some_and(|v| !v.complete.get() || v.failed.get())
            || plan.len() != JOBS
            || !plan
                .iter()
                .zip(&s.jobs)
                .all(|(p, j)| p.matches(j) && p.fully_retired())
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
    pub(crate) fn require_pending(&self) -> Result<()> {
        let s = &self.state;
        if s.creator != std::process::id()
            || s.complete.get()
            || s.shared.fenced.get()
            || s.shared.pending.borrow().is_some()
            || s.shared.journal.borrow().record.owner_epoch.as_ref() != Some(&s.epoch)
            || !s
                .shared
                .native_jobs
                .borrow()
                .transferring
                .contains(&s.member)
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
    #[cfg(test)]
    pub(crate) fn lab_fence(&self) -> Result<()> {
        self.require_pending()?;
        self.state.shared.fenced.set(true);
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn lab_evidence(&self) -> Result<serde_json::Value> {
        let s = &self.state;
        if s.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        let registry = REGISTRY.with(|r| r.borrow().owners.len());
        Ok(
            serde_json::json!({"member":s.member,"owner_epoch":s.epoch,"original_jobs":s.jobs.len(),"complete":s.complete.get(),
            "global_assemblies_reserved":registry,"global_assembly_limit":OWNERS,"global_transferred_ticket_limit":OWNERS*(JOBS+OPERATIONAL_JOBS),
            "member_transfer_pending":s.shared.native_jobs.borrow().transferring.contains(&s.member)}),
        )
    }

    pub(crate) fn finish(&self, plan: &[ResourceTransfer]) -> Result<()> {
        self.require_pending()?;
        let s = &self.state;
        if s.creator != std::process::id()
            || s.complete.get()
            || plan.len() != JOBS
            || s.shared.fenced.get()
            || s.shared.pending.borrow().is_some()
            || s.shared.journal.borrow().record.owner_epoch.as_ref() != Some(&s.epoch)
            || !plan
                .iter()
                .zip(&s.jobs)
                .all(|(p, j)| p.matches(j) && p.fully_retired())
        {
            return Err(Error::OwnershipMismatch);
        }
        let mut jobs = s
            .shared
            .native_jobs
            .try_borrow_mut()
            .map_err(|_| Error::LockBusy)?;
        if !jobs.transferring.remove(&s.member) {
            return Err(Error::OwnershipMismatch);
        }
        s.complete.set(true);
        Ok(())
    }
}
impl Server {
    pub(crate) fn assembly_plan(
        &self,
        binding: &Rc<quarantine::Binding>,
        original: &[kernel::wireguard_role::Verified],
        netfilter: &[kernel::netfilter_role::Verified],
        producer: &kernel::producer_creation::Source,
    ) -> Result<Vec<ResourceTransfer>> {
        binding.verify(self)?;
        if original.len() != 5
            || netfilter.len() != 6
            || !Rc::ptr_eq(producer.request().binding(), binding)
        {
            return Err(Error::OwnershipMismatch);
        }
        producer.bind_service(self)?;
        producer.verify_acknowledged_history()?;
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        let shared = &n.transaction.shared;
        let j = shared.journal.borrow();
        let entry = j
            .record
            .entries
            .iter()
            .find(|e| e.exit_id == n.history.member)
            .ok_or(Error::OwnershipMismatch)?;
        let p = entry.preparation.as_ref().ok_or(Error::OwnershipMismatch)?;
        p.validate(&j.record, entry)?;
        if p.wireguard.len() != 5 || p.netfilter.len() != 6 || entry.producer.is_some() {
            return Err(Error::OwnershipMismatch);
        }
        for (h, v) in p.wireguard.iter().zip(original) {
            v.bind_service(self)?;
            h.matches_assembly_receipt(v)?;
        }
        for (h, v) in p.netfilter.iter().zip(netfilter) {
            v.bind_service(self)?;
            h.matches_assembly_receipt(v)?;
        }
        drop(j);
        let mut plan = Vec::with_capacity(JOBS);
        plan.push(binding.data().resource_transfer()?);
        plan.push(
            binding
                .transport()
                .request()
                .original()
                .resource_transfer()?,
        );
        plan.push(binding.transport().resource_transfer()?);
        for v in original {
            plan.push(v.resource_transfer()?);
        }
        for v in netfilter {
            plan.push(v.resource_transfer()?);
        }
        plan.push(producer.resource_transfer()?);
        Ok(plan)
    }
    pub(crate) fn reserve_assembly(&self, plan: &[ResourceTransfer]) -> Result<Reservation> {
        self.verify_preparation_idle()?;
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        n.require_creator()?;
        let shared = &n.transaction.shared;
        if shared.fenced.get() || plan.len() != JOBS {
            return Err(Error::OwnershipMismatch);
        }
        let epoch = n.owner.record(&n.domains)?;
        if shared.journal.borrow().record.owner_epoch.as_ref() != Some(&epoch) {
            return Err(Error::OwnershipMismatch);
        }
        let kinds = [
            kernel::NativeJobKind::NamespaceAttachment,
            kernel::NativeJobKind::FreshTransport,
            kernel::NativeJobKind::FreshTransportMount,
        ];
        for (i, p) in plan.iter().enumerate() {
            p.verify()?;
            let expected = if i < 3 {
                kinds[i]
            } else if i < 8 {
                kernel::NativeJobKind::WireguardSecret
            } else if i < 14 {
                kernel::NativeJobKind::FixedNetfilter
            } else {
                kernel::NativeJobKind::ProducerCreation
            };
            if p.kind() != expected || plan[..i].iter().any(|old| p.same_charge(old)) {
                return Err(Error::OwnershipMismatch);
            }
        }
        let mut jobs = shared
            .native_jobs
            .try_borrow_mut()
            .map_err(|_| Error::LockBusy)?;
        jobs.prune()?;
        if jobs.transferring.contains(&n.history.member) {
            return Err(Error::LockBusy);
        }
        let originals: Vec<_> = jobs
            .pending
            .values()
            .filter(|(member, _)| member == &n.history.member)
            .map(|(_, r)| r)
            .collect();
        if originals.len() != JOBS
            || originals
                .iter()
                .any(|r| plan.iter().filter(|p| p.matches(r)).count() != 1)
        {
            return Err(Error::OwnershipMismatch);
        }
        let exact: Vec<_> = plan
            .iter()
            .map(|p| {
                originals
                    .iter()
                    .find(|r| p.matches(r))
                    .map(|r| (**r).clone())
                    .ok_or(Error::OwnershipMismatch)
            })
            .collect::<Result<_>>()?;
        REGISTRY.with(|registry| {
            let mut registry = registry.try_borrow_mut().map_err(|_| Error::LockBusy)?;
            if registry.creator != n.creator {
                let foreign = std::mem::replace(
                    &mut *registry,
                    Registry {
                        creator: n.creator,
                        owners: Vec::new(),
                    },
                );
                std::mem::forget(foreign);
            }
            if registry.owners.len() >= OWNERS
                || registry.owners.iter().any(|r| {
                    r.member == n.history.member
                        && (Rc::ptr_eq(&r.shared, shared) || r.epoch == epoch)
                })
            {
                return Err(Error::LockBusy);
            }
            let state = Rc::new(ReservationState {
                creator: n.creator,
                shared: shared.clone(),
                member: n.history.member.clone(),
                epoch,
                jobs: exact,
                complete: Cell::new(false),
                operational: RefCell::new(None),
            });
            jobs.transferring.insert(n.history.member.clone());
            registry.owners.push(state.clone());
            Ok(Reservation { state })
        })
    }
}

/// One exact suffix of the original member reservation. The registry retains
/// this state even if the consuming owner fails or is abandoned. The weak back
/// pointer avoids a cycle; the original global registry owns the parent.
struct OperationalState {
    parent: std::rc::Weak<ReservationState>,
    jobs: Vec<kernel::NativeJobDrain>,
    complete: Cell<bool>,
    failed: Cell<bool>,
}
pub(crate) struct OperationalReservation {
    state: Rc<OperationalState>,
}
impl OperationalReservation {
    #[cfg(test)]
    pub(crate) fn lab_fence(&self) -> Result<()> {
        self.require_pending()?;
        self.parent()?.shared.fenced.set(true);
        Ok(())
    }
    #[cfg(test)]
    pub(crate) fn lab_evidence(&self) -> Result<serde_json::Value> {
        let p = self
            .state
            .parent
            .upgrade()
            .ok_or(Error::OwnershipMismatch)?;
        if p.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        Ok(
            serde_json::json!({"member":p.member,"owner_epoch":p.epoch,"original_jobs":p.jobs.len(),"suffix_jobs":self.state.jobs.len(),"suffix_complete":self.state.complete.get(),"suffix_failed":self.state.failed.get(),"member_transfer_pending":p.shared.native_jobs.borrow().transferring.contains(&p.member),"global_transferred_ticket_limit":OWNERS*(JOBS+OPERATIONAL_JOBS)}),
        )
    }

    fn parent(&self) -> Result<Rc<ReservationState>> {
        let p = self
            .state
            .parent
            .upgrade()
            .ok_or(Error::OwnershipMismatch)?;
        if p.creator != std::process::id()
            || self.state.failed.get()
            || !p.complete.get()
            || p.jobs.len() != JOBS
            || p.jobs.iter().any(|j| j.resources_transferred() != Ok(true))
            || p.shared.fenced.get()
            || p.shared.journal.borrow().record.owner_epoch.as_ref() != Some(&p.epoch)
            || !p.shared.services.borrow().contains(&p.member)
            || p.operational
                .borrow()
                .as_ref()
                .is_none_or(|v| !Rc::ptr_eq(v, &self.state))
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(p)
    }
    pub(crate) fn require_pending(&self) -> Result<()> {
        let p = self.parent()?;
        if self.state.complete.get()
            || p.shared.pending.borrow().is_some()
            || !p
                .shared
                .native_jobs
                .borrow()
                .transferring
                .contains(&p.member)
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
    pub(crate) fn latch_failure(&self) {
        if let Some(p) = self.state.parent.upgrade()
            && p.creator == std::process::id()
        {
            self.state.failed.set(true);
        }
    }
    pub(crate) fn require_complete(&self, plan: &[ResourceTransfer]) -> Result<()> {
        self.require_resources(plan)?;
        if self.parent()?.shared.pending.borrow().is_some() {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
    /// Historical handoff plus current retained reservation custody only. An
    /// ongoing writer must separately prove its exact typed request/proposal.
    pub(crate) fn require_resources(&self, plan: &[ResourceTransfer]) -> Result<()> {
        let p = self.parent()?;
        if !self.state.complete.get()
            || p.shared
                .native_jobs
                .borrow()
                .transferring
                .contains(&p.member)
            || plan.len() != OPERATIONAL_JOBS
            || !plan
                .iter()
                .zip(&self.state.jobs)
                .all(|(v, j)| v.matches(j) && v.fully_retired())
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
    pub(crate) fn finish(&self, plan: &[ResourceTransfer]) -> Result<()> {
        self.require_pending()?;
        if plan.len() != OPERATIONAL_JOBS
            || !plan
                .iter()
                .zip(&self.state.jobs)
                .all(|(v, j)| v.matches(j) && v.fully_retired())
        {
            return Err(Error::OwnershipMismatch);
        }
        let p = self.parent()?;
        let mut jobs = p
            .shared
            .native_jobs
            .try_borrow_mut()
            .map_err(|_| Error::LockBusy)?;
        if !jobs.transferring.remove(&p.member) {
            return Err(Error::OwnershipMismatch);
        }
        self.state.complete.set(true);
        Ok(())
    }
}
impl Server {
    /// The initial reservation is the only source of this one-time extension.
    /// Neither a parsed record nor a number of completed jobs can create it.
    pub(crate) fn reserve_operational_extension(
        &self,
        original: &Reservation,
        original_plan: &[ResourceTransfer],
        plan: &[ResourceTransfer],
    ) -> Result<OperationalReservation> {
        original.require_complete(original_plan)?;
        self.verify_preparation_idle()?;
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        n.require_creator()?;
        let p = &original.state;
        let shared = &n.transaction.shared;
        if !Rc::ptr_eq(&p.shared, shared)
            || p.member != n.history.member
            || p.epoch != n.owner.record(&n.domains)?
            || p.operational.borrow().is_some()
            || plan.len() != OPERATIONAL_JOBS
        {
            return Err(Error::OwnershipMismatch);
        }
        for (index, v) in plan.iter().enumerate() {
            v.verify()?;
            let expected = if index == 0 {
                kernel::NativeJobKind::FixedNetfilter
            } else {
                kernel::NativeJobKind::FixedVeth
            };
            if v.kind() != expected
                || plan[..index].iter().any(|old| v.same_charge(old))
                || original_plan.iter().any(|old| v.same_charge(old))
            {
                return Err(Error::OwnershipMismatch);
            }
        }
        let mut jobs = shared
            .native_jobs
            .try_borrow_mut()
            .map_err(|_| Error::LockBusy)?;
        jobs.prune()?;
        if jobs.transferring.contains(&p.member) {
            return Err(Error::LockBusy);
        }
        let all: Vec<_> = jobs
            .pending
            .values()
            .filter(|(member, _)| member == &p.member)
            .map(|(_, j)| j)
            .collect();
        if all.len() != JOBS + OPERATIONAL_JOBS
            || all.iter().any(|j| {
                original_plan
                    .iter()
                    .chain(plan)
                    .filter(|v| v.matches(j))
                    .count()
                    != 1
            })
        {
            return Err(Error::OwnershipMismatch);
        }
        let exact = plan
            .iter()
            .map(|v| {
                all.iter()
                    .find(|j| v.matches(j))
                    .map(|j| (**j).clone())
                    .ok_or(Error::OwnershipMismatch)
            })
            .collect::<Result<Vec<_>>>()?;
        let mut slot = p
            .operational
            .try_borrow_mut()
            .map_err(|_| Error::LockBusy)?;
        if slot.is_some() {
            return Err(Error::OwnershipMismatch);
        }
        let state = Rc::new(OperationalState {
            parent: Rc::downgrade(p),
            jobs: exact,
            complete: Cell::new(false),
            failed: Cell::new(false),
        });
        // All binding/set validation precedes reserving this permanent suffix,
        // and the consuming owner still retains every original resource.
        *slot = Some(state.clone());
        jobs.transferring.insert(p.member.clone());
        Ok(OperationalReservation { state })
    }
}
