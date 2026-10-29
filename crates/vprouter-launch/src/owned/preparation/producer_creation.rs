//! Durable exclusive producer creation evidence, never placement or exception authority.
use super::super::super::attachment::quarantine::producer::Request;
use super::*;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct History {
    request: [u8; 32],
    parent: Identity,
    name: String,
    data: Identity,
    query: [u8; 32],
    requested_at: f64,
    deadline: f64,
    birth: Option<ValidationBirth>,
    group: Option<Identity>,
    verified_at: Option<f64>,
}
impl History {
    pub(super) fn completed_binding(&self) -> Result<(Identity, Identity, &str, Identity)> {
        self.completed_at()?;
        Ok((
            self.parent,
            self.group.ok_or(Error::OwnershipMismatch)?,
            &self.name,
            self.data,
        ))
    }

    pub(super) fn completed_at(&self) -> Result<f64> {
        if self.birth.is_none() || self.group.is_none() {
            return Err(Error::OwnershipMismatch);
        }
        self.verified_at.ok_or(Error::OwnershipMismatch)
    }
    pub(super) fn validate(
        &self,
        record: &Record,
        entry: &Entry,
        preparation: &super::History,
    ) -> Result<()> {
        let (query, start, at) = preparation
            .producer_query
            .as_ref()
            .ok_or(Error::OwnershipMismatch)?
            .completed_producer()?;
        let allocation = record
            .allocation
            .exits
            .iter()
            .find(|a| a.exit_id == entry.exit_id)
            .ok_or(Error::OwnershipMismatch)?;
        if self.request == [0; 32]
            || self.parent.ino == 0
            || self.query != query
            || self.requested_at != start
            || self.deadline != start + 2.
            || Some(self.data) != entry.data
            || self.name
                != vprouter_netfilter::SocketProducer::group_name(&record.allocation, allocation)
            || (entry.producer.is_some()
                && !preparation
                    .producer_binding
                    .as_ref()
                    .is_some_and(|b| b.matches_publication(entry)))
            || preparation.netfilter.len() != 6
        {
            return Err(Error::OwnershipMismatch);
        }
        if let Some(b) = &self.birth
            && (b.pid <= 1
                || b.start == 0
                || !b.born_at.is_finite()
                || b.born_at < at
                || b.born_at >= self.deadline
                || b.deadline != self.deadline)
        {
            return Err(Error::OwnershipMismatch);
        }
        match (self.group, self.verified_at) {
            (None, None) => Ok(()),
            (Some(group), Some(at))
                if group.ino > 0
                    && group.dev == self.parent.dev
                    && group != self.parent
                    && self.birth.as_ref().is_some_and(|b| {
                        at.is_finite() && at >= b.born_at && at < self.deadline
                    }) =>
            {
                Ok(())
            }
            _ => Err(Error::OwnershipMismatch),
        }
    }
}
pub(crate) struct Intent {
    creator: u32,
    shared: Rc<SharedJournal>,
    member: String,
    history: History,
    owner: Rc<OwnerDomain>,
    domains: Domains,
    lease: MutatorLease,
}
impl Intent {
    pub(crate) fn transfer_ticket(&self) -> Result<&kernel::NativeJobTicket> {
        if self.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        self.lease.transfer_ticket()
    }

    fn verify_owner_origin(&self, shared: &Rc<SharedJournal>, member: &str) -> Result<()> {
        if self.creator != std::process::id()
            || !Rc::ptr_eq(&self.shared, shared)
            || self.member != member
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }

    pub(crate) fn matches_job(&self, ticket: &kernel::NativeJobDrain) -> Result<bool> {
        if self.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        ticket.matches_reaped(
            self.lease
                .native_job
                .as_ref()
                .ok_or(Error::OwnershipMismatch)?,
        )
    }
    pub(crate) fn same_service(&self, server: &Server) -> Result<()> {
        let n = server.native.as_ref().ok_or(Error::Interrupted)?;
        n.require_creator()?;
        if self.creator != n.creator
            || !Rc::ptr_eq(&self.shared, &n.transaction.shared)
            || self.member != n.history.member
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
    pub(crate) fn verify(&self, request: &Request) -> Result<()> {
        request.verify()?;
        request
            .binding()
            .verify_owner_origin(&self.shared, &self.owner, &self.member)?;
        if self.creator != std::process::id()
            || self.history.request != request.digest()
            || self.history.parent != request.parent_identity()
            || self.history.name != request.name()
            || self.history.query != request.query_digest()
            || self.history.data != request.data()
            || self.history.requested_at != request.requested_at()
            || self.history.birth.is_some()
            || self.shared.fenced.get()
            || self.shared.pending.borrow().is_some()
            || !self.shared.services.borrow().contains(&self.member)
        {
            return Err(Error::OwnershipMismatch);
        }
        let journal = self.shared.journal.borrow();
        let entry = journal
            .record
            .entries
            .iter()
            .find(|e| e.exit_id == self.member)
            .ok_or(Error::OwnershipMismatch)?;
        let p = entry.preparation.as_ref().ok_or(Error::OwnershipMismatch)?;
        if p.producer_creation.as_ref() != Some(&self.history)
            || journal.record.owner_epoch.as_ref() != Some(&self.owner.record(&self.domains)?)
        {
            return Err(Error::OwnershipMismatch);
        }
        self.history.validate(&journal.record, entry, p)
    }
    pub(crate) fn prepare(&mut self, request: &Request) -> Result<()> {
        self.verify(request)?;
        self.lease
            .prepare_native_job(kernel::NativeJobKind::ProducerCreation)
    }
    pub(crate) fn lease(&mut self) -> &mut MutatorLease {
        &mut self.lease
    }
}
pub(crate) struct Gate {
    creator: u32,
    shared: Rc<SharedJournal>,
    member: String,
    history: History,
}
impl Gate {
    pub(crate) fn verify(&self, intent: &Intent, birth: &ValidationBirth) -> Result<()> {
        if self.creator != std::process::id()
            || self.creator != intent.creator
            || !Rc::ptr_eq(&self.shared, &intent.shared)
            || self.member != intent.member
            || self.history.request != intent.history.request
            || self.history.birth.as_ref() != Some(birth)
            || self.history.group.is_some()
            || self.shared.fenced.get()
            || self.shared.pending.borrow().is_some()
        {
            return Err(Error::OwnershipMismatch);
        }
        let journal = self.shared.journal.borrow();
        let e = journal
            .record
            .entries
            .iter()
            .find(|e| e.exit_id == self.member)
            .ok_or(Error::OwnershipMismatch)?;
        let p = e.preparation.as_ref().ok_or(Error::OwnershipMismatch)?;
        if p.producer_creation.as_ref() != Some(&self.history)
            || journal.record.owner_epoch.as_ref() != Some(&intent.owner.record(&intent.domains)?)
        {
            return Err(Error::OwnershipMismatch);
        }
        self.history.validate(&journal.record, e, p)?;
        original_frame(
            self.history.requested_at,
            vprouter_core::health::boot_seconds(),
        )?;
        kernel::owner_admission_permitted()
    }
}
impl Native {
    pub(super) fn producer_creation_history(&self) -> Result<History> {
        self.require_creator()?;
        self.transaction
            .shared
            .journal
            .borrow()
            .record
            .entries
            .iter()
            .find(|e| e.exit_id == self.history.member)
            .and_then(|e| e.preparation.as_ref())
            .and_then(|p| p.producer_creation.clone())
            .ok_or(Error::OwnershipMismatch)
    }
    fn queue_producer_creation(&mut self, history: History, phase: &'static str) -> Result<()> {
        self.require_creator()?;
        kernel::owner_admission_permitted()?;
        original_frame(history.requested_at, vprouter_core::health::boot_seconds())?;
        if self.failure.is_some()
            || self.pending.is_some()
            || self.queued_at.is_some()
            || self.continuation.is_some()
            || !self.result_issued
        {
            return Err(Error::OwnershipMismatch);
        }
        let shared = &self.transaction.shared;
        if !mutation_slot_available(shared.pending.borrow().is_some(), shared.fenced.get())? {
            return Err(Error::LockBusy);
        }
        let mut proposed = shared.journal.borrow().record.clone();
        let before = record_digest(&encode_record(&proposed)?);
        let entry = proposed
            .entries
            .iter_mut()
            .find(|e| e.exit_id == self.history.member)
            .ok_or(Error::OwnershipMismatch)?;
        let started_at = history.requested_at;
        entry
            .preparation
            .as_mut()
            .ok_or(Error::OwnershipMismatch)?
            .producer_creation = Some(history);
        proposed.bind_anchor(
            &proposed.allocation,
            &proposed.primary_exit_id,
            proposed.base_network,
            proposed.owner_network,
        )?;
        shared.queue.borrow_mut().push(&self.history.member)?;
        self.continuation = Some(Continuation {
            quarantine_origin: None,
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
    pub(crate) fn start_producer_creation(&mut self, request: &Request) -> Result<()> {
        request.verify_service(self)?;
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        let j = n.transaction.shared.journal.borrow();
        let p = j
            .record
            .entries
            .iter()
            .find(|e| e.exit_id == n.history.member)
            .and_then(|e| e.preparation.as_ref())
            .ok_or(Error::OwnershipMismatch)?;
        if p.producer_creation.is_some() || p.netfilter.len() != 6 {
            return Err(Error::OwnershipMismatch);
        }
        drop(j);
        n.queue_producer_creation(
            History {
                request: request.digest(),
                parent: request.parent_identity(),
                name: request.name().into(),
                data: request.data(),
                query: request.query_digest(),
                requested_at: request.requested_at(),
                deadline: request.deadline(),
                birth: None,
                group: None,
                verified_at: None,
            },
            "producer_intent",
        )
    }
    pub(crate) fn poll_producer_creation_intent(
        &mut self,
        request: &Request,
    ) -> Result<Option<Intent>> {
        request.verify()?;
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        if !n.poll_inspection("producer_intent")? {
            return Ok(None);
        }
        let intent = Intent {
            creator: n.creator,
            shared: n.transaction.shared.clone(),
            member: n.history.member.clone(),
            history: n.producer_creation_history()?,
            owner: n.owner.clone(),
            domains: n.domains.clone(),
            lease: n.transaction.retain_allocation_lease()?,
        };
        intent.verify(request)?;
        Ok(Some(intent))
    }
    pub(crate) fn start_producer_creation_birth(
        &mut self,
        child: &kernel::producer_creation::Child,
    ) -> Result<()> {
        child.bind_service(self)?;
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        let mut h = n.producer_creation_history()?;
        if h.birth.is_some() || h.request != child.request_digest()? {
            return Err(Error::OwnershipMismatch);
        }
        h.birth = Some(child.birth()?);
        n.queue_producer_creation(h, "producer_birth")
    }
    pub(crate) fn poll_producer_creation_birth(
        &mut self,
        child: &kernel::producer_creation::Child,
    ) -> Result<Option<Gate>> {
        child.bind_service(self)?;
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        if !n.poll_inspection("producer_birth")? {
            return Ok(None);
        }
        let gate = Gate {
            creator: n.creator,
            shared: n.transaction.shared.clone(),
            member: n.history.member.clone(),
            history: n.producer_creation_history()?,
        };
        child.verify_gate(&gate)?;
        Ok(Some(gate))
    }
    pub(crate) fn start_producer_creation_source(
        &mut self,
        source: &kernel::producer_creation::Source,
    ) -> Result<()> {
        source.bind_service(self)?;
        source.verify()?;
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        let mut h = n.producer_creation_history()?;
        if h.birth.as_ref() != Some(&source.birth()?) || h.group.is_some() {
            return Err(Error::OwnershipMismatch);
        }
        h.group = Some(source.identity()?);
        h.verified_at = Some(source.verified_at());
        n.queue_producer_creation(h, "producer_result")
    }
    pub(crate) fn poll_producer_creation_source(
        &mut self,
        source: &kernel::producer_creation::Source,
    ) -> Result<Option<Receipt>> {
        source.bind_service(self)?;
        source.verify()?;
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        if !n.poll_inspection("producer_result")? {
            return Ok(None);
        }
        let h = n.producer_creation_history()?;
        if h.birth.as_ref() != Some(&source.birth()?)
            || h.group != Some(source.identity()?)
            || h.verified_at != Some(source.verified_at())
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(Some(Receipt {
            creator: n.creator,
            shared: n.transaction.shared.clone(),
            member: n.history.member.clone(),
            history: h,
        }))
    }
}

pub(crate) struct Receipt {
    creator: u32,
    shared: Rc<SharedJournal>,
    member: String,
    history: History,
}
impl Receipt {
    pub(crate) fn verify_write(
        &self,
        source: &kernel::producer_creation::Source,
        proof: &OriginalWrite<'_>,
    ) -> Result<()> {
        proof.verify_origin(&self.shared, &self.member)?;
        source.verify_retained()?;
        source
            .intent()?
            .verify_owner_origin(&self.shared, &self.member)?;
        if self.creator != std::process::id()
            || self.history.request != source.request().digest()
            || self.history.birth.as_ref() != Some(&source.birth()?)
            || self.history.group != Some(source.identity()?)
            || self.history.verified_at != Some(source.verified_at())
            || self.shared.fenced.get()
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
        if p.producer_creation.as_ref() != Some(&self.history) {
            return Err(Error::OwnershipMismatch);
        }
        self.history.validate(&j.record, e, p)
    }
    pub(crate) fn verify(&self, source: &kernel::producer_creation::Source) -> Result<()> {
        source.verify()?;
        self.verify_history(source)
    }
    pub(crate) fn verify_history(&self, source: &kernel::producer_creation::Source) -> Result<()> {
        source.verify_retained()?;
        source
            .intent()?
            .verify_owner_origin(&self.shared, &self.member)?;
        if self.creator != std::process::id()
            || self.history.request != source.request().digest()
            || self.history.birth.as_ref() != Some(&source.birth()?)
            || self.history.group != Some(source.identity()?)
            || self.history.verified_at != Some(source.verified_at())
            || self.shared.pending.borrow().is_some()
            || self.shared.fenced.get()
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
        if p.producer_creation.as_ref() != Some(&self.history) {
            return Err(Error::OwnershipMismatch);
        }
        self.history.validate(&j.record, e, p)
    }
}
