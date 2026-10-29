//! Historical custody after the original DOWN move. This binding grants no
//! nft mutation: separately durable operation intent/birth and current fixed
//! native completion are required. Existing DATA policy needs its own recheck.
use super::*;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

pub(crate) struct Binding {
    public: PublicBinding,
    transport: Rc<kernel::fresh_transport_mount::Mounted>,
    operations: Vec<wireguard::History>,
    movement_query: [u8; 32],
    host: Identity,
    host_pin: OwnedFd,
    host_registration: super::super::super::inventory::Registration,
    configuration: vprouter_core::config::PublicConfiguration,
    configuration_digest: [u8; 32],
    owner: Rc<OwnerDomain>,
    domains: Domains,
}
impl Binding {
    pub(super) fn verify_owner_origin(
        &self,
        shared: &Rc<SharedJournal>,
        owner: &Rc<OwnerDomain>,
        member: &str,
    ) -> Result<()> {
        if self.public.creator != std::process::id()
            || !Rc::ptr_eq(shared, &self.public.shared)
            || !Rc::ptr_eq(owner, &self.owner)
            || member != self.public.member
        {
            return Err(Error::OwnershipMismatch);
        }
        self.verify_retained()
    }

    pub(crate) fn verify(&self, server: &Server) -> Result<()> {
        server.verify_preparation_idle()?;
        self.verify_service_custody(server)
    }
    pub(super) fn verify_service_custody(&self, server: &Server) -> Result<()> {
        #[cfg(test)]
        let _cost = super::lab_cost::Timer::new(super::lab_cost::Key::BindingServiceCustody);
        server.verify_transport_custody(&self.transport)?;
        let n = server.native.as_ref().ok_or(Error::Interrupted)?;
        n.require_creator()?;
        if self.public.creator != n.creator
            || !Rc::ptr_eq(&self.public.shared, &n.transaction.shared)
            || self.public.member != n.history.member
            || !Rc::ptr_eq(&self.owner, &n.owner)
        {
            return Err(Error::OwnershipMismatch);
        }
        self.verify_retained()
    }
    pub(crate) fn verify_retained(&self) -> Result<()> {
        #[cfg(test)]
        let _cost = super::lab_cost::Timer::new(super::lab_cost::Key::BindingRetained);
        if self.public.creator != std::process::id() || !vprouter_core::secret_boundary::pristine()
        {
            return Err(Error::OwnershipMismatch);
        }
        {
            #[cfg(test)]
            let _retained_cost = super::lab_cost::RetainedTimer::new(
                super::lab_cost::RetainedKey::RetainedTransport,
            );
            self.transport.verify_retained()?;
        }
        {
            #[cfg(test)]
            let _retained_cost =
                super::lab_cost::RetainedTimer::new(super::lab_cost::RetainedKey::RetainedData);
            self.data().verify_retained()?;
        }
        let shared = &self.public.shared;
        let j = shared.journal.borrow();
        let spec = self.data().request().spec();
        if self.public.member != spec.exit.exit_id
            || !same_allocation(&j.record.allocation, &spec.allocation)?
            || j.record.primary_exit_id != self.public.member
            || j.record.entries.len() != 1
            || shared.services.borrow().len() != 1
            || {
                #[cfg(test)]
                let _retained_cost = super::lab_cost::RetainedTimer::new(
                    super::lab_cost::RetainedKey::RetainedOwnerRecord,
                );
                self.owner.record(&self.domains)?
            } != self.public.owner
        {
            return Err(Error::OwnershipMismatch);
        }
        if j.record.owner_network != Some(self.host)
            || !self.host_registration.contains(self.host_pin.as_fd())
            || Identity::network(&self.host_pin)? != self.host
        {
            return Err(Error::OwnershipMismatch);
        }
        let e = &j.record.entries[0];
        let p = e.preparation.as_ref().ok_or(Error::OwnershipMismatch)?;
        {
            #[cfg(test)]
            let _retained_cost =
                super::lab_cost::RetainedTimer::new(super::lab_cost::RetainedKey::RetainedHistory);
            p.validate(&j.record, e)?;
        }
        if e.phase != Phase::Creating
            || e.terminal.is_some()
            || p.result.as_ref() != Some(&self.public.result)
            || p.wireguard.as_slice() != self.operations.as_slice()
            || self.operations.len() != 5
            || p.configuration != self.configuration_digest
            || p.movement_query
                .as_ref()
                .ok_or(Error::OwnershipMismatch)?
                .completed_movement()?
                .0
                != self.movement_query
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
    pub(crate) fn host(&self) -> Identity {
        self.host
    }
    pub(crate) fn host_pin(&self) -> BorrowedFd<'_> {
        self.host_pin.as_fd()
    }
    pub(crate) fn configuration(&self) -> &vprouter_core::config::PublicConfiguration {
        &self.configuration
    }
    pub(crate) fn configuration_digest(&self) -> [u8; 32] {
        self.configuration_digest
    }
    pub(crate) fn data(&self) -> &Rc<kernel::namespace_attachment::Mounted> {
        self.transport.request().original().request().data()
    }
    pub(crate) fn public_result(&self) -> [u8; 32] {
        self.public.public_result()
    }
    pub(crate) fn public(&self) -> &PublicBinding {
        &self.public
    }
    pub(crate) fn query_public_binding(&self) -> PublicBinding {
        PublicBinding {
            creator: self.public.creator,
            shared: self.public.shared.clone(),
            member: self.public.member.clone(),
            result: self.public.result.clone(),
            owner: self.public.owner.clone(),
        }
    }
    pub(crate) fn transport(&self) -> &Rc<kernel::fresh_transport_mount::Mounted> {
        &self.transport
    }
}

impl Server {
    pub(crate) fn bind_quarantine(
        &self,
        transport: Rc<kernel::fresh_transport_mount::Mounted>,
        previous: &[kernel::wireguard_role::Verified],
    ) -> Result<Rc<Binding>> {
        self.verify_transport_mounted(&transport)?;
        if previous.len() != 5 {
            return Err(Error::OwnershipMismatch);
        }
        for v in previous {
            v.bind_service(self)?;
            v.require_acknowledged()?;
        }
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        let shared = &n.transaction.shared;
        let j = shared.journal.borrow();
        let p = j
            .record
            .entries
            .iter()
            .find(|e| e.exit_id == n.history.member)
            .and_then(|e| e.preparation.as_ref())
            .ok_or(Error::OwnershipMismatch)?;
        if p.wireguard.len() != previous.len() || p.movement_query.is_none() {
            return Err(Error::OwnershipMismatch);
        }
        for (h, v) in p.wireguard.iter().zip(previous) {
            h.matches_receipt(v)?;
        }
        let host = j.record.owner_network.ok_or(Error::OwnershipMismatch)?;
        // Current owner validation above binds this native opening to the
        // original owner-host anchor; a caller namespace tuple cannot mint it.
        n.owner.record(&n.domains)?;
        let host_pin = rustix::fs::open(
            "/proc/self/ns/net",
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|_| Error::NamespaceMismatch)?;
        let host_registration =
            super::super::super::inventory::Registration::owned(&[host_pin.as_fd()])?;
        if Identity::network(&host_pin)? != host {
            return Err(Error::NamespaceMismatch);
        }
        let value = Rc::new(Binding {
            public: PublicBinding {
                creator: n.creator,
                shared: shared.clone(),
                member: n.history.member.clone(),
                result: p.result.clone().ok_or(Error::OwnershipMismatch)?,
                owner: p.owner.clone(),
            },
            transport,
            operations: p.wireguard.clone(),
            host,
            host_pin,
            host_registration,
            configuration: previous[4].request().configuration().clone(),
            configuration_digest: p.configuration,
            owner: n.owner.clone(),
            domains: n.domains.clone(),
            movement_query: p
                .movement_query
                .as_ref()
                .ok_or(Error::OwnershipMismatch)?
                .completed_movement()?
                .0,
        });
        drop(j);
        let mut jobs = shared.native_jobs.borrow_mut();
        jobs.prune()?;
        let mut count = 0;
        for (member, receipt) in jobs.pending.values() {
            if member == &n.history.member {
                let mut known = value.data().matches_job(receipt)?
                    || value.transport.matches_job(receipt)?
                    || value.transport.request().original().matches_job(receipt)?;
                for v in previous {
                    known |= v.matches_job(receipt)?;
                }
                if !known {
                    return Err(Error::OwnershipMismatch);
                }
                count += 1;
            }
        }
        if count != 8 {
            return Err(Error::OwnershipMismatch);
        }
        drop(jobs);
        value.verify(self)?;
        Ok(value)
    }
}

use super::super::super::attachment::quarantine::{Kind, Scope};
/// Durable public evidence only; parsing this never constructs a native gate.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Operation {
    kind: Kind,
    scope: Scope,
    request: [u8; 32],
    namespace: Identity,
    configuration: [u8; 32],
    host_declaration: [u8; 32],
    policy: [u8; 32],
    query: Option<[u8; 32]>,
    requested_at: f64,
    deadline: f64,
    birth: Option<ValidationBirth>,
    result: Option<PublicResult>,
    verified_at: Option<f64>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PublicResult {
    pub(crate) namespace: Identity,
    pub(crate) policy: [u8; 32],
    /// Final original child observation, never a post-reap/current-table claim.
    pub(crate) observed_at: Option<f64>,
}
impl Operation {
    pub(super) fn matches_assembly_receipt(&self, v: &Verified) -> Result<()> {
        v.require_acknowledged()?;
        if self.request != v.request().digest()
            || self.birth.as_ref() != Some(&v.birth()?)
            || self.result.as_ref() != Some(v.historical_result()?)
            || self.verified_at != Some(v.historical_accepted_at()?)
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }

    pub(super) fn bootstrap_policy(&self, scope: Scope) -> Result<[u8; 32]> {
        self.completed_at()?;
        if self.kind != Kind::InitialQuarantine || self.scope != scope {
            return Err(Error::OwnershipMismatch);
        }
        Ok(self.policy)
    }
    pub(super) fn binding_policy(&self) -> Result<[u8; 32]> {
        self.completed_at()?;
        if self.kind != Kind::InitialQuarantine || self.scope != Scope::Data {
            return Err(Error::OwnershipMismatch);
        }
        Ok(self.policy)
    }
    pub(super) fn completed_at(&self) -> Result<f64> {
        if self.result.is_none() || self.birth.is_none() {
            return Err(Error::OwnershipMismatch);
        }
        self.verified_at.ok_or(Error::OwnershipMismatch)
    }

    pub(super) fn completed_data_sockets_at(&self) -> Result<f64> {
        if self.scope != Scope::Data
            || self.kind != Kind::Sockets
            || self.result.is_none()
            || self.birth.is_none()
        {
            return Err(Error::OwnershipMismatch);
        }
        self.verified_at.ok_or(Error::OwnershipMismatch)
    }

    pub(super) fn validate(
        &self,
        record: &Record,
        entry: &Entry,
        p: &super::History,
        index: usize,
    ) -> Result<()> {
        let expected = [
            (Scope::Host, Kind::Sockets),
            (Scope::Host, Kind::InitialQuarantine),
            (Scope::Transport, Kind::Sockets),
            (Scope::Transport, Kind::InitialQuarantine),
            (Scope::Data, Kind::Sockets),
            (Scope::Data, Kind::InitialQuarantine),
        ];
        if expected.get(index) != Some(&(self.scope, self.kind))
            || self.request == [0; 32]
            || self.policy == [0; 32]
            || self.host_declaration == [0; 32]
            || self.configuration != p.configuration
            || self.namespace.ino == 0
            || Some(self.namespace)
                != match self.scope {
                    Scope::Host => record.owner_network,
                    Scope::Transport => entry.transport,
                    Scope::Data => entry.data,
                }
            || !self.requested_at.is_finite()
            || self.requested_at <= 0.
            || self.deadline != self.requested_at + 2.
            || p.wireguard.len() != 5
            || p.wireguard
                .last()
                .ok_or(Error::OwnershipMismatch)?
                .completed_move_at()?
                > self.requested_at
        {
            return Err(Error::OwnershipMismatch);
        }
        if (self.scope, self.kind) == (Scope::Data, Kind::InitialQuarantine) {
            let (query, start, at) = p
                .quarantine_query
                .as_ref()
                .ok_or(Error::OwnershipMismatch)?
                .completed_quarantine()?;
            if self.query != Some(query)
                || start != self.requested_at
                || self.birth.as_ref().is_some_and(|b| b.born_at < at)
            {
                return Err(Error::OwnershipMismatch);
            }
        } else if self.query.is_some() {
            return Err(Error::OwnershipMismatch);
        }
        if index > 0 {
            let previous = p.netfilter.get(index - 1).ok_or(Error::OwnershipMismatch)?;
            if previous.result.is_none()
                || previous.verified_at.is_none_or(|at| at > self.requested_at)
                || previous.host_declaration != self.host_declaration
                || (self.kind == Kind::InitialQuarantine && previous.policy != self.policy)
            {
                return Err(Error::OwnershipMismatch);
            }
        }
        if let Some(b) = &self.birth
            && (b.pid <= 1
                || b.start == 0
                || !b.born_at.is_finite()
                || b.born_at < self.requested_at
                || b.born_at >= self.deadline
                || b.deadline != self.deadline)
        {
            return Err(Error::OwnershipMismatch);
        }
        match (&self.result, self.verified_at) {
            (None, None) => Ok(()),
            (Some(r), Some(at)) => {
                let b = self.birth.as_ref().ok_or(Error::OwnershipMismatch)?;
                if r.namespace != self.namespace
                    || r.policy != self.policy
                    || !at.is_finite()
                    || at < b.born_at
                    || at >= self.deadline
                {
                    return Err(Error::OwnershipMismatch);
                }
                match (self.kind, r.observed_at) {
                    (Kind::Sockets, None) => Ok(()),
                    (Kind::InitialQuarantine, Some(observed))
                        if observed.is_finite() && observed >= b.born_at && observed <= at =>
                    {
                        Ok(())
                    }
                    _ => Err(Error::OwnershipMismatch),
                }
            }
            _ => Err(Error::OwnershipMismatch),
        }
    }
}

use super::super::super::attachment::quarantine::Request;
use kernel::netfilter_role::{Child, Verified};
pub(crate) struct Intent {
    creator: u32,
    shared: Rc<SharedJournal>,
    member: String,
    history: Operation,
    index: usize,
    owner: Rc<OwnerDomain>,
    domains: Domains,
    lease: MutatorLease,
}
impl Intent {
    pub(super) fn verify_shared_origin(
        &self,
        shared: &Rc<SharedJournal>,
        member: &str,
    ) -> Result<()> {
        if self.creator != std::process::id()
            || !Rc::ptr_eq(&self.shared, shared)
            || self.member != member
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }

    pub(crate) fn transfer_ticket(&self) -> Result<&kernel::NativeJobTicket> {
        if self.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        self.lease.transfer_ticket()
    }

    pub(crate) fn same_service(&self, s: &Server) -> Result<()> {
        let n = s.native.as_ref().ok_or(Error::Interrupted)?;
        n.require_creator()?;
        if self.creator != n.creator
            || !Rc::ptr_eq(&self.shared, &n.transaction.shared)
            || self.member != n.history.member
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
    pub(crate) fn verify_previous(&self, previous: &Self) -> Result<()> {
        if self.creator != std::process::id()
            || previous.creator != self.creator
            || !Rc::ptr_eq(&self.shared, &previous.shared)
            || !Rc::ptr_eq(&self.owner, &previous.owner)
            || self.member != previous.member
            || previous.index.checked_add(1) != Some(self.index)
            || self.history.kind != Kind::InitialQuarantine
            || previous.history.kind != Kind::Sockets
            || self.history.scope != previous.history.scope
            || self.history.namespace != previous.history.namespace
            || self.history.configuration != previous.history.configuration
            || self.history.policy != previous.history.policy
            || self.history.host_declaration != previous.history.host_declaration
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
    pub(crate) fn verify_binding(&self, r: &Request) -> Result<()> {
        let b = r.binding();
        if self.creator != std::process::id()
            || b.public.creator != self.creator
            || !Rc::ptr_eq(&self.shared, &b.public.shared)
            || !Rc::ptr_eq(&self.owner, &b.owner)
            || self.member != b.public.member
        {
            return Err(Error::OwnershipMismatch);
        }
        b.verify_retained()
    }
    pub(crate) fn verify_birth_slot(&self, index: usize, h: &Operation) -> Result<()> {
        if self.creator != std::process::id() || self.index != index || &self.history != h {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
    pub(crate) fn verify(&self, r: &Request) -> Result<()> {
        self.verify_binding(r)?;
        r.verify()?;
        if self.creator != std::process::id()
            || self.member != r.member()
            || self.history.request != r.digest()
            || self.history.kind != r.kind()
            || self.history.namespace != r.namespace()
            || self.history.configuration != r.configuration_digest()
            || self.history.scope != r.scope()
            || self.history.query != r.query_digest()
            || self.history.policy != r.policy_digest()
            || self.history.host_declaration != r.declaration_digest()
            || self.history.requested_at != r.requested_at()
            || self.history.birth.is_some()
            || self.shared.fenced.get()
            || self.shared.pending.borrow().is_some()
            || !self.shared.services.borrow().contains(&self.member)
        {
            return Err(Error::OwnershipMismatch);
        }
        let j = self.shared.journal.borrow();
        let e = j
            .record
            .entries
            .iter()
            .find(|e| e.exit_id == self.member)
            .ok_or(Error::OwnershipMismatch)?;
        let p = e.preparation.as_ref().ok_or(Error::OwnershipMismatch)?;
        if p.netfilter.get(self.index) != Some(&self.history)
            || j.record.owner_epoch.as_ref() != Some(&self.owner.record(&self.domains)?)
        {
            return Err(Error::OwnershipMismatch);
        }
        self.history.validate(&j.record, e, p, self.index)
    }
    pub(crate) fn prepare(&mut self, r: &Request) -> Result<()> {
        self.verify(r)?;
        self.lease
            .prepare_native_job(kernel::NativeJobKind::FixedNetfilter)
    }
    pub(crate) fn lease(&mut self) -> &mut MutatorLease {
        &mut self.lease
    }
    pub(crate) fn matches_job(&self, receipt: &kernel::NativeJobDrain) -> Result<bool> {
        if self.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        receipt.matches_reaped(
            self.lease
                .native_job
                .as_ref()
                .ok_or(Error::OwnershipMismatch)?,
        )
    }
}
pub(crate) struct Gate {
    creator: u32,
    shared: Rc<SharedJournal>,
    member: String,
    history: Operation,
    index: usize,
}
impl Gate {
    pub(crate) fn verify(&self, i: &Intent, b: &ValidationBirth) -> Result<()> {
        if self.creator != std::process::id()
            || self.creator != i.creator
            || !Rc::ptr_eq(&self.shared, &i.shared)
            || self.member != i.member
            || self.index != i.index
            || self.history.request != i.history.request
            || self.history.birth.as_ref() != Some(b)
            || self.history.result.is_some()
            || self.shared.fenced.get()
            || self.shared.pending.borrow().is_some()
        {
            return Err(Error::OwnershipMismatch);
        }
        let j = self.shared.journal.borrow();
        let e = j
            .record
            .entries
            .iter()
            .find(|e| e.exit_id == self.member)
            .ok_or(Error::OwnershipMismatch)?;
        let p = e.preparation.as_ref().ok_or(Error::OwnershipMismatch)?;
        if p.netfilter.get(self.index) != Some(&self.history)
            || j.record.owner_epoch.as_ref() != Some(&i.owner.record(&i.domains)?)
        {
            return Err(Error::OwnershipMismatch);
        }
        self.history.validate(&j.record, e, p, self.index)?;
        original_frame(
            self.history.requested_at,
            vprouter_core::health::boot_seconds(),
        )?;
        kernel::owner_admission_permitted()
    }
}
pub(crate) struct Receipt {
    creator: u32,
    shared: Rc<SharedJournal>,
    member: String,
    history: Operation,
    index: usize,
}
impl Receipt {
    pub(crate) fn verify(&self, v: &Verified) -> Result<()> {
        v.verify()?;
        let i = v.intent()?;
        if self.creator != std::process::id()
            || self.creator != i.creator
            || !Rc::ptr_eq(&self.shared, &i.shared)
            || self.member != i.member
            || self.index != i.index
            || self.history.request != v.request().digest()
            || self.history.birth.as_ref() != Some(&v.birth()?)
            || self.history.result.as_ref() != Some(v.result()?)
            || self.history.verified_at != Some(v.accepted_at()?)
            || self.shared.fenced.get()
            || self.shared.pending.borrow().is_some()
        {
            return Err(Error::OwnershipMismatch);
        }
        let j = self.shared.journal.borrow();
        let e = j
            .record
            .entries
            .iter()
            .find(|e| e.exit_id == self.member)
            .ok_or(Error::OwnershipMismatch)?;
        let p = e.preparation.as_ref().ok_or(Error::OwnershipMismatch)?;
        if p.netfilter.get(self.index) != Some(&self.history) {
            return Err(Error::OwnershipMismatch);
        }
        self.history.validate(&j.record, e, p, self.index)
    }
}
impl Native {
    fn netfilter_history(&self) -> Result<(usize, Operation)> {
        self.require_creator()?;
        let j = self.transaction.shared.journal.borrow();
        let list = &j
            .record
            .entries
            .iter()
            .find(|e| e.exit_id == self.history.member)
            .and_then(|e| e.preparation.as_ref())
            .ok_or(Error::OwnershipMismatch)?
            .netfilter;
        let index = list.len().checked_sub(1).ok_or(Error::OwnershipMismatch)?;
        Ok((index, list[index].clone()))
    }
    fn queue_netfilter(
        &mut self,
        h: Operation,
        index: usize,
        phase: &'static str,
        append: bool,
        request: Rc<Request>,
    ) -> Result<()> {
        #[cfg(test)]
        super::super::super::attachment::quarantine::lab_stage("queue_creator");
        self.require_creator()?;
        kernel::owner_admission_permitted()?;
        original_frame(h.requested_at, vprouter_core::health::boot_seconds())?;
        #[cfg(test)]
        super::super::super::attachment::quarantine::lab_stage("queue_idle");
        #[cfg(test)]
        super::super::super::attachment::quarantine::lab_queue([
            self.failure.is_some(),
            self.pending.is_some(),
            self.queued_at.is_some(),
            self.continuation.is_some(),
            self.result_issued,
        ]);
        if self.failure.is_some()
            || self.pending.is_some()
            || self.queued_at.is_some()
            || self.continuation.is_some()
            || !self.result_issued
        {
            return Err(Error::OwnershipMismatch);
        }
        let shared = &self.transaction.shared;
        #[cfg(test)]
        super::super::super::attachment::quarantine::lab_stage("queue_mutation_slot");
        if !mutation_slot_available(shared.pending.borrow().is_some(), shared.fenced.get())? {
            return Err(Error::LockBusy);
        }
        let mut proposed = shared.journal.borrow().record.clone();
        #[cfg(test)]
        super::super::super::attachment::quarantine::lab_stage("queue_encode_before");
        let before = record_digest(&encode_record(&proposed)?);
        let list = &mut proposed
            .entries
            .iter_mut()
            .find(|e| e.exit_id == self.history.member)
            .and_then(|e| e.preparation.as_mut())
            .ok_or(Error::OwnershipMismatch)?
            .netfilter;
        let started_at = h.requested_at;
        #[cfg(test)]
        super::super::super::attachment::quarantine::lab_stage("queue_append");
        if append {
            if list.len() != index || index >= 6 {
                return Err(Error::OwnershipMismatch);
            }
            list.push(h);
        } else {
            if list.len() != index + 1 {
                return Err(Error::OwnershipMismatch);
            }
            list[index] = h;
        }
        #[cfg(test)]
        super::super::super::attachment::quarantine::lab_stage("queue_bind_anchor");
        proposed.bind_anchor(
            &proposed.allocation,
            &proposed.primary_exit_id,
            proposed.base_network,
            proposed.owner_network,
        )?;
        #[cfg(test)]
        super::super::super::attachment::quarantine::lab_stage("queue_member");
        shared.queue.borrow_mut().push(&self.history.member)?;
        self.continuation = Some(Continuation {
            quarantine_origin: Some(ProgressOrigin::Netfilter(request, index)),
            before,
            proposed,
            started_at,
            phase,
            publication: None,
            transport_publication: None,
        });
        self.queued_at = Some(vprouter_core::health::boot_seconds());
        Ok(())
    }
}
impl Server {
    pub(crate) fn verify_netfilter_prefix(
        &self,
        binding: &Rc<Binding>,
        original: &[kernel::wireguard_role::Verified],
        previous: &[Verified],
    ) -> Result<()> {
        #[cfg(test)]
        super::super::super::attachment::quarantine::lab_stage("prefix_binding");
        binding.verify(self)?;
        if original.len() != 5 {
            return Err(Error::OwnershipMismatch);
        }
        #[cfg(test)]
        super::super::super::attachment::quarantine::lab_stage("prefix_original_ack");
        for v in original {
            v.bind_service(self)?;
            v.require_acknowledged()?;
        }
        #[cfg(test)]
        super::super::super::attachment::quarantine::lab_stage("prefix_netfilter_ack");
        for v in previous {
            v.bind_service(self)?;
            v.require_acknowledged()?;
        }
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        let shared = &n.transaction.shared;
        let j = shared.journal.borrow();
        let e = j
            .record
            .entries
            .iter()
            .find(|e| e.exit_id == n.history.member)
            .ok_or(Error::OwnershipMismatch)?;
        #[cfg(test)]
        super::super::super::attachment::quarantine::lab_stage("prefix_canonical");
        let p = e.preparation.as_ref().ok_or(Error::OwnershipMismatch)?;
        let index = p.netfilter.len();
        if binding.data().request().spec().exit.exit_id.as_str() != n.history.member
            || p.configuration != binding.configuration_digest()
            || previous.len() != index
            || p.wireguard.len() != original.len()
        {
            return Err(Error::OwnershipMismatch);
        }
        #[cfg(test)]
        super::super::super::attachment::quarantine::lab_stage("prefix_original_history");
        for (h, v) in p.wireguard.iter().zip(original) {
            h.matches_receipt(v)?;
        }
        #[cfg(test)]
        super::super::super::attachment::quarantine::lab_stage("prefix_netfilter_history");
        for (h, v) in p.netfilter.iter().zip(previous) {
            if h.request != v.request().digest()
                || h.birth.as_ref() != Some(&v.birth()?)
                || h.result.as_ref() != Some(v.historical_result()?)
            {
                return Err(Error::OwnershipMismatch);
            }
        }
        drop(j);
        #[cfg(test)]
        super::super::super::attachment::quarantine::lab_stage("prefix_original_jobs");
        let mut jobs = shared.native_jobs.borrow_mut();
        jobs.prune()?;
        let mut count = 0;
        #[cfg(test)]
        super::super::super::attachment::quarantine::lab_jobs(jobs.pending.len(), 0);
        for (member, receipt) in jobs.pending.values() {
            if member == binding.data().request().spec().exit.exit_id.as_str() {
                let b = binding;
                let mut known = b.transport().matches_job(receipt)?
                    || b.transport().request().original().matches_job(receipt)?
                    || b.data().matches_job(receipt)?;
                for v in original {
                    known |= v.matches_job(receipt)?;
                }
                for v in previous {
                    known |= v.matches_job(receipt)?;
                }
                if !known {
                    return Err(Error::OwnershipMismatch);
                }
                count += 1;
                #[cfg(test)]
                super::super::super::attachment::quarantine::lab_jobs(jobs.pending.len(), count);
            }
        }
        if count != 8 + index {
            return Err(Error::OwnershipMismatch);
        }
        drop(jobs);
        Ok(())
    }
    pub(crate) fn start_netfilter(
        &mut self,
        r: &Rc<Request>,
        original: &[kernel::wireguard_role::Verified],
        previous: &[Verified],
    ) -> Result<()> {
        #[cfg(test)]
        super::super::super::attachment::quarantine::lab_stage("start_service");
        r.verify_service(self)?;
        self.verify_netfilter_prefix(r.binding(), original, previous)?;
        let index = previous.len();
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        n.queue_netfilter(
            Operation {
                kind: r.kind(),
                scope: r.scope(),
                request: r.digest(),
                namespace: r.namespace(),
                configuration: r.configuration_digest(),
                host_declaration: r.declaration_digest(),
                policy: r.policy_digest(),
                query: r.query_digest(),
                requested_at: r.requested_at(),
                deadline: r.deadline(),
                birth: None,
                result: None,
                verified_at: None,
            },
            index,
            "netfilter_intent",
            true,
            r.clone(),
        )
    }
    pub(crate) fn poll_netfilter_intent(&mut self, r: &Request) -> Result<Option<Intent>> {
        r.verify()?;
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        if !n.poll_inspection("netfilter_intent")? {
            return Ok(None);
        }
        let (index, history) = n.netfilter_history()?;
        let i = Intent {
            creator: n.creator,
            shared: n.transaction.shared.clone(),
            member: n.history.member.clone(),
            history,
            index,
            owner: n.owner.clone(),
            domains: n.domains.clone(),
            lease: n.transaction.retain_allocation_lease()?,
        };
        i.verify(r)?;
        Ok(Some(i))
    }
    pub(crate) fn start_netfilter_birth(&mut self, c: &Child) -> Result<()> {
        c.bind_service(self)?;
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        let (index, mut h) = n.netfilter_history()?;
        c.verify_birth_slot(index, &h)?;
        if h.birth.is_some() {
            return Err(Error::OwnershipMismatch);
        }
        h.birth = Some(c.birth()?);
        n.queue_netfilter(
            h,
            index,
            "netfilter_birth",
            false,
            c.original_request()?.clone(),
        )
    }
    pub(crate) fn poll_netfilter_birth(&mut self, c: &Child) -> Result<Option<Gate>> {
        c.bind_service(self)?;
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        if !n.poll_inspection("netfilter_birth")? {
            return Ok(None);
        }
        let (index, history) = n.netfilter_history()?;
        let g = Gate {
            creator: n.creator,
            shared: n.transaction.shared.clone(),
            member: n.history.member.clone(),
            history,
            index,
        };
        c.verify_gate(&g)?;
        Ok(Some(g))
    }
    pub(crate) fn start_netfilter_result(&mut self, v: &Verified) -> Result<()> {
        v.bind_service(self)?;
        v.verify()?;
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        let (index, mut h) = n.netfilter_history()?;
        if h.request != v.request().digest()
            || h.birth.as_ref() != Some(&v.birth()?)
            || h.result.is_some()
        {
            return Err(Error::OwnershipMismatch);
        }
        h.result = Some(v.result()?.clone());
        h.verified_at = Some(v.accepted_at()?);
        n.queue_netfilter(h, index, "netfilter_result", false, v.request().clone())
    }
    pub(crate) fn poll_netfilter_result(&mut self, v: &Verified) -> Result<Option<Receipt>> {
        v.bind_service(self)?;
        v.verify()?;
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        if !n.poll_inspection("netfilter_result")? {
            return Ok(None);
        }
        let (index, history) = n.netfilter_history()?;
        let r = Receipt {
            creator: n.creator,
            shared: n.transaction.shared.clone(),
            member: n.history.member.clone(),
            history,
            index,
        };
        r.verify(v)?;
        Ok(Some(r))
    }
}

pub(super) enum ProgressOrigin {
    Bootstrap(Rc<super::super::super::attachment::operational::bootstrap::Request>),
    HostLink(Rc<super::super::super::attachment::host_addition::Request>),
    ProducerBinding(Rc<super::super::super::attachment::producer_binding::Request>),
    Netfilter(Rc<Request>, usize),
    Query(Rc<super::super::super::attachment::InspectionRequest>),
}
// Ongoing polling is deliberately separate from idle admission. These variants
// carry the original private operation objects, never deserialized history.
pub(crate) enum Progress<'a> {
    Netfilter(&'a Rc<Request>, usize, NetfilterProgress<'a>),
    Query(
        &'a Rc<super::super::super::attachment::InspectionRequest>,
        inspection::QuarantineProgress<'a>,
    ),
}
pub(crate) enum NetfilterProgress<'a> {
    Intent,
    Birth(&'a Child),
    Result(&'a Verified),
}
impl Binding {
    pub(crate) fn verify_progress(
        self: &Rc<Self>,
        server: &Server,
        progress: Progress<'_>,
    ) -> Result<()> {
        self.verify_service_custody(server)?;
        let n = server.native.as_ref().ok_or(Error::Interrupted)?;
        let shared = &n.transaction.shared;
        let mut expected = shared.journal.borrow().record.clone();
        let p = expected
            .entries
            .iter_mut()
            .find(|e| e.exit_id == n.history.member)
            .and_then(|e| e.preparation.as_mut())
            .ok_or(Error::OwnershipMismatch)?;
        let (phase, started) = match progress {
            Progress::Netfilter(r, index, stage) => {
                if !Rc::ptr_eq(self, r.binding())
                    || !matches!(n.continuation.as_ref().and_then(|c| c.quarantine_origin.as_ref()),
                        Some(ProgressOrigin::Netfilter(original, original_index)) if Rc::ptr_eq(original, r) && *original_index == index)
                {
                    return Err(Error::OwnershipMismatch);
                }
                r.verify()?;
                let initial = Operation {
                    kind: r.kind(),
                    scope: r.scope(),
                    request: r.digest(),
                    namespace: r.namespace(),
                    configuration: r.configuration_digest(),
                    host_declaration: r.declaration_digest(),
                    policy: r.policy_digest(),
                    query: r.query_digest(),
                    requested_at: r.requested_at(),
                    deadline: r.deadline(),
                    birth: None,
                    result: None,
                    verified_at: None,
                };
                let phase = match stage {
                    NetfilterProgress::Intent => {
                        if p.netfilter.len() != index || index >= 6 {
                            return Err(Error::OwnershipMismatch);
                        }
                        p.netfilter.push(initial);
                        "netfilter_intent"
                    }
                    NetfilterProgress::Birth(child) => {
                        child.require_request(r)?;
                        child.bind_service(server)?;
                        if p.netfilter.len() != index + 1 || p.netfilter[index] != initial {
                            return Err(Error::OwnershipMismatch);
                        }
                        child.verify_birth_slot(index, &p.netfilter[index])?;
                        p.netfilter[index].birth = Some(child.birth()?);
                        "netfilter_birth"
                    }
                    NetfilterProgress::Result(verified) => {
                        if !Rc::ptr_eq(r, verified.request()) {
                            return Err(Error::OwnershipMismatch);
                        }
                        verified.bind_service(server)?;
                        let mut born = initial;
                        born.birth = Some(verified.birth()?);
                        if p.netfilter.len() != index + 1 || p.netfilter[index] != born {
                            return Err(Error::OwnershipMismatch);
                        }
                        p.netfilter[index].result = Some(verified.result()?.clone());
                        p.netfilter[index].verified_at = Some(verified.accepted_at()?);
                        "netfilter_result"
                    }
                };
                (phase, r.requested_at())
            }
            Progress::Query(r, stage) => {
                r.require_quarantine_origin(self)?;
                if !matches!(n.continuation.as_ref().and_then(|c| c.quarantine_origin.as_ref()),
                    Some(ProgressOrigin::Query(original)) if Rc::ptr_eq(original, r))
                {
                    return Err(Error::OwnershipMismatch);
                }
                (
                    inspection::apply_quarantine_progress(p, r, stage, server)?,
                    r.requested_at(),
                )
            }
        };
        // Only the typed selected-history change above may differ. All other
        // members, resource identities and original histories remain exact.
        n.verify_owned_progress(&expected, phase, started)?;
        self.verify_retained()?;
        original_frame(started, vprouter_core::health::boot_seconds())
    }
}
impl Native {
    pub(super) fn verify_owned_progress(
        &self,
        expected: &Record,
        phase: &'static str,
        started: f64,
    ) -> Result<()> {
        #[cfg(test)]
        let _cost = super::lab_cost::Timer::new(super::lab_cost::Key::OwnedProgress);
        self.require_creator()?;
        original_frame(started, vprouter_core::health::boot_seconds())?;
        let shared = &self.transaction.shared;
        let c = self.continuation.as_ref().ok_or(Error::OwnershipMismatch)?;
        #[cfg(test)]
        let expected_cost = super::lab_cost::Timer::new(super::lab_cost::Key::ExpectedRecordEncode);
        let expected_bytes = encode_record(expected)?;
        #[cfg(test)]
        drop(expected_cost);
        if self.failure.is_some()
            || !self.result_issued
            || shared.fenced.get()
            || !shared.services.borrow().contains(&self.history.member)
            || c.phase != phase
            || c.started_at != started
            || c.publication.is_some()
            || c.transport_publication.is_some()
            || encode_record(&c.proposed)? != expected_bytes
        {
            return Err(Error::OwnershipMismatch);
        }
        let before = record_digest(&encode_record(&shared.journal.borrow().record)?);
        if c.before != before {
            return Err(Error::OwnershipMismatch);
        }
        match (&self.pending, self.queued_at) {
            (None, Some(queued)) => {
                if !queued.is_finite()
                    || queued < started
                    || queued >= started + 2.
                    || shared.pending.borrow().is_some()
                    || shared.queue.borrow().0.len() != 1
                    || !shared.queue.borrow().first(&self.history.member)
                {
                    return Err(Error::OwnershipMismatch);
                }
            }
            (Some(job), None) => {
                PendingWriter {
                    child: &job.child,
                    jobs: &shared.native_jobs,
                    member: &self.history.member,
                    phase: c.phase,
                    started: c.started_at,
                    deadline: job.deadline,
                    mutation: job.mutation,
                    failed: job.failed,
                    fenced: shared.fenced.get(),
                }
                .verify(phase, started, before, record_digest(&expected_bytes))?;
                if encode_record(
                    shared
                        .pending
                        .borrow()
                        .as_ref()
                        .ok_or(Error::OwnershipMismatch)?,
                )? != expected_bytes
                    || !shared.queue.borrow().0.is_empty()
                {
                    return Err(Error::OwnershipMismatch);
                }
            }
            _ => return Err(Error::OwnershipMismatch),
        }
        Ok(())
    }
}

#[cfg(test)]
impl Binding {
    // Negative checks against the actual queued/held writer without modifying
    // its canonical state, original channels, registration or native receipt.
    pub(crate) fn lab_own_intent_negatives(
        self: &Rc<Self>,
        server: &Server,
        r: &Rc<Request>,
    ) -> Result<usize> {
        self.verify_progress(server, Progress::Netfilter(r, 0, NetfilterProgress::Intent))?;
        let different_request = Rc::new((**r).clone());
        let refused = |value: Result<()>| matches!(value, Err(Error::OwnershipMismatch));
        if !refused(self.verify(server))
            || !refused(self.verify_progress(
                server,
                Progress::Netfilter(&different_request, 0, NetfilterProgress::Intent),
            ))
            || !refused(
                self.verify_progress(server, Progress::Netfilter(r, 1, NetfilterProgress::Intent)),
            )
        {
            return Err(Error::OwnershipMismatch);
        }
        let n = server.native.as_ref().ok_or(Error::Interrupted)?;
        let c = n.continuation.as_ref().ok_or(Error::Interrupted)?;
        let mut other_member = c.proposed.clone();
        other_member.entries[0].exit_id.push_str("-foreign");
        if !refused(n.verify_owned_progress(&c.proposed, "netfilter_birth", c.started_at))
            || !refused(n.verify_owned_progress(&c.proposed, c.phase, c.started_at - 0.001))
            || !refused(n.verify_owned_progress(&other_member, c.phase, c.started_at))
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(6)
    }
}
