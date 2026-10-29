//! Canonical one-way preparation binding. Parsing cannot create an original
//! producer, quarantine owner, placement or activation capability.
use super::super::super::attachment::producer_binding::Request;
use super::*;
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PublicResult {
    pub(crate) namespace: Identity,
    pub(crate) group: Identity,
    pub(crate) policy: [u8; 32],
    pub(crate) pins: [(u64, u64, u32); 6],
    pub(crate) observed_at: f64,
}
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
    group: Identity,
    creation: producer_creation::History,
    policy: [u8; 32],
    pins: [(u64, u64, u32); 6],
    result: Option<PublicResult>,
    verified_at: Option<f64>,
}
impl History {
    pub(super) fn matches_bootstrap_receipt(
        &self,
        v: &kernel::producer_binding::Verified,
    ) -> Result<()> {
        v.require_acknowledged_history()?;
        if self.request != v.request().digest()
            || self.birth.as_ref() != Some(&v.birth()?)
            || self.result.as_ref() != Some(v.historical_result()?)
            || self.verified_at != Some(v.historical_accepted_at()?)
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
    pub(super) fn host_bound_at(&self) -> Result<f64> {
        if self.result.is_none() {
            return Err(Error::OwnershipMismatch);
        }
        self.verified_at.ok_or(Error::OwnershipMismatch)
    }
    pub(super) fn matches_publication(&self, entry: &Entry) -> bool {
        entry.phase == Phase::Creating
            && entry.links.is_none()
            && entry.attempt.is_none()
            && entry.terminal.is_none()
            && self.result.is_some()
            && self.verified_at.is_some()
            && entry.producer.as_ref().is_some_and(|p| {
                p.binding == Some(self.request) && p.parent == self.parent && p.group == self.group
            })
    }
    pub(super) fn validate(
        &self,
        record: &Record,
        entry: &Entry,
        preparation: &super::History,
    ) -> Result<()> {
        let (query, start, query_at) = preparation
            .producer_binding_query
            .as_ref()
            .ok_or(Error::OwnershipMismatch)?
            .completed_producer_binding()?;
        let original = preparation
            .producer_creation
            .as_ref()
            .ok_or(Error::OwnershipMismatch)?;
        let (parent, group, name, data) = original.completed_binding()?;
        if self.request == [0; 32]
            || self.creation != *original
            || self.parent != parent
            || self.group != group
            || self.name != name
            || self.data != data
            || Some(data) != entry.data
            || self.query != query
            || self.requested_at != start
            || self.deadline != start + 2.
            || original.completed_at()? > start
            || preparation.netfilter.len() != 6
            || preparation.netfilter[5].binding_policy()? != self.policy
            || self.pins[0].0 != parent.dev
            || self.pins[0].1 != parent.ino
            || self.pins[1].0 != group.dev
            || self.pins[1].1 != group.ino
            || self.pins.iter().any(|p| p.1 == 0 || p.0 != parent.dev)
            || record.primary_exit_id != entry.exit_id
        {
            return Err(Error::OwnershipMismatch);
        }
        if let Some(b) = &self.birth
            && (b.pid <= 1
                || b.start == 0
                || !b.born_at.is_finite()
                || b.born_at < query_at
                || b.born_at >= self.deadline
                || b.deadline != self.deadline)
        {
            return Err(Error::OwnershipMismatch);
        }
        match (&self.result, self.verified_at) {
            (None, None) if entry.producer.is_none() => Ok(()),
            (Some(r), Some(at))
                if self.matches_publication(entry)
                    && r.namespace == data
                    && r.group == group
                    && r.policy == self.policy
                    && r.pins == self.pins
                    && r.observed_at.is_finite()
                    && at.is_finite()
                    && r.observed_at <= at
                    && at < self.deadline
                    && self
                        .birth
                        .as_ref()
                        .is_some_and(|b| r.observed_at >= b.born_at) =>
            {
                Ok(())
            }
            _ => Err(Error::OwnershipMismatch),
        }
    }
}
impl Server {
    pub(crate) fn require_producer_bound_history(
        &self,
        original: &kernel::producer_binding::Verified,
    ) -> Result<()> {
        self.verify_preparation_idle()?;
        self.require_producer_bound_custody(original)
    }
    // Custody only; an ongoing caller must separately verify its exact original
    // typed continuation/proposal/phase before advancing a canonical writer.
    pub(crate) fn require_producer_bound_custody(
        &self,
        original: &kernel::producer_binding::Verified,
    ) -> Result<()> {
        original.require_acknowledged_history()?;
        original.bind_service(self)?;
        original.request().binding().verify_service_custody(self)?;
        let native = self.native.as_ref().ok_or(Error::Interrupted)?;
        native.require_creator()?;
        let journal = native.transaction.shared.journal.borrow();
        let entry = journal
            .record
            .entries
            .iter()
            .find(|e| e.exit_id == native.history.member)
            .ok_or(Error::OwnershipMismatch)?;
        let preparation = entry.preparation.as_ref().ok_or(Error::OwnershipMismatch)?;
        let history = preparation
            .producer_binding
            .as_ref()
            .ok_or(Error::OwnershipMismatch)?;
        let mut expected = original.intent()?.history.clone();
        expected.birth = Some(original.birth()?);
        expected.result = Some(original.historical_result()?.clone());
        expected.verified_at = Some(original.historical_accepted_at()?);
        if history != &expected || !history.matches_publication(entry) {
            return Err(Error::OwnershipMismatch);
        }
        history.validate(&journal.record, entry, preparation)
    }
    pub(crate) fn producer_binding_policy(
        &self,
        source: &kernel::producer_creation::Source,
    ) -> Result<[u8; 32]> {
        source.bind_service(self)?;
        source.verify_acknowledged_history()?;
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        n.require_creator()?;
        let j = n.transaction.shared.journal.borrow();
        let e = j
            .record
            .entries
            .iter()
            .find(|e| e.exit_id == n.history.member)
            .ok_or(Error::OwnershipMismatch)?;
        if e.producer.is_some() {
            return Err(Error::OwnershipMismatch);
        }
        let p = e.preparation.as_ref().ok_or(Error::OwnershipMismatch)?;
        if p.netfilter.len() != 6 {
            return Err(Error::OwnershipMismatch);
        }
        p.netfilter[5].binding_policy()
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
    pub(crate) fn verify_previous(
        &self,
        previous: &kernel::netfilter_role::Verified,
    ) -> Result<()> {
        previous.require_acknowledged()?;
        previous
            .intent()?
            .verify_shared_origin(&self.shared, &self.member)?;
        let j = self.shared.journal.borrow();
        let p = j
            .record
            .entries
            .iter()
            .find(|e| e.exit_id == self.member)
            .and_then(|e| e.preparation.as_ref())
            .ok_or(Error::OwnershipMismatch)?;
        if p.netfilter.len() != 6 || previous.request().policy_digest() != self.history.policy {
            return Err(Error::OwnershipMismatch);
        }
        p.netfilter[5].matches_assembly_receipt(previous)
    }
    pub(crate) fn transfer_ticket(&self) -> Result<&kernel::NativeJobTicket> {
        if self.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        self.lease.transfer_ticket()
    }

    pub(super) fn verify_owner_origin(
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
            || self.history.parent != request.parent()
            || self.history.group != request.group()
            || self.history.pins != request.pins()
            || self.history.policy != request.policy_digest()
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
        if p.producer_binding.as_ref() != Some(&self.history)
            || journal.record.owner_epoch.as_ref() != Some(&self.owner.record(&self.domains)?)
        {
            return Err(Error::OwnershipMismatch);
        }
        self.history.validate(&journal.record, entry, p)
    }
    pub(crate) fn prepare(&mut self, request: &Request) -> Result<()> {
        self.verify(request)?;
        self.lease
            .prepare_native_job(kernel::NativeJobKind::FixedNetfilter)
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
            || self.history.result.is_some()
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
        if p.producer_binding.as_ref() != Some(&self.history)
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
    pub(super) fn producer_binding_history(&self) -> Result<History> {
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
            .and_then(|p| p.producer_binding.clone())
            .ok_or(Error::OwnershipMismatch)
    }
    fn queue_producer_binding(
        &mut self,
        history: History,
        phase: &'static str,
        request: Rc<Request>,
    ) -> Result<()> {
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
        if history.result.is_some() {
            if entry.producer.is_some() {
                return Err(Error::OwnershipMismatch);
            }
            entry.producer = Some(ProducerOwnership {
                parent: history.parent,
                group: history.group,
                binding: Some(history.request),
            });
        }
        entry
            .preparation
            .as_mut()
            .ok_or(Error::OwnershipMismatch)?
            .producer_binding = Some(history);
        proposed.bind_anchor(
            &proposed.allocation,
            &proposed.primary_exit_id,
            proposed.base_network,
            proposed.owner_network,
        )?;
        shared.queue.borrow_mut().push(&self.history.member)?;
        self.continuation = Some(Continuation {
            quarantine_origin: Some(quarantine::ProgressOrigin::ProducerBinding(request)),
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
    pub(crate) fn start_producer_binding(&mut self, request: &Rc<Request>) -> Result<()> {
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
        if p.producer_binding.is_some() || p.netfilter.len() != 6 || p.producer_creation.is_none() {
            return Err(Error::OwnershipMismatch);
        }
        let creation = p
            .producer_creation
            .clone()
            .ok_or(Error::OwnershipMismatch)?;
        drop(j);
        n.queue_producer_binding(
            History {
                request: request.digest(),
                parent: request.parent(),
                name: request.name().into(),
                data: request.data(),
                query: request.query_digest(),
                requested_at: request.requested_at(),
                deadline: request.deadline(),
                birth: None,
                group: request.group(),
                pins: request.pins(),
                policy: request.policy_digest(),
                creation,
                result: None,
                verified_at: None,
            },
            "producer_binding_intent",
            request.clone(),
        )
    }
    pub(crate) fn poll_producer_binding_intent(
        &mut self,
        request: &Request,
    ) -> Result<Option<Intent>> {
        request.verify()?;
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        if !n.poll_inspection("producer_binding_intent")? {
            return Ok(None);
        }
        let intent = Intent {
            creator: n.creator,
            shared: n.transaction.shared.clone(),
            member: n.history.member.clone(),
            history: n.producer_binding_history()?,
            owner: n.owner.clone(),
            domains: n.domains.clone(),
            lease: n.transaction.retain_allocation_lease()?,
        };
        intent.verify(request)?;
        Ok(Some(intent))
    }
    pub(crate) fn start_producer_binding_birth(
        &mut self,
        child: &kernel::producer_binding::Child,
    ) -> Result<()> {
        child.bind_service(self)?;
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        let mut h = n.producer_binding_history()?;
        if h.birth.is_some() || h.request != child.request_digest()? {
            return Err(Error::OwnershipMismatch);
        }
        h.birth = Some(child.birth()?);
        n.queue_producer_binding(h, "producer_binding_birth", child.request().clone())
    }
    pub(crate) fn poll_producer_binding_birth(
        &mut self,
        child: &kernel::producer_binding::Child,
    ) -> Result<Option<Gate>> {
        child.bind_service(self)?;
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        if !n.poll_inspection("producer_binding_birth")? {
            return Ok(None);
        }
        let gate = Gate {
            creator: n.creator,
            shared: n.transaction.shared.clone(),
            member: n.history.member.clone(),
            history: n.producer_binding_history()?,
        };
        child.verify_gate(&gate)?;
        Ok(Some(gate))
    }
    pub(crate) fn start_producer_binding_source(
        &mut self,
        source: &kernel::producer_binding::Verified,
    ) -> Result<()> {
        source.bind_service(self)?;
        source.verify()?;
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        let mut h = n.producer_binding_history()?;
        if h.birth.as_ref() != Some(&source.birth()?) || h.result.is_some() {
            return Err(Error::OwnershipMismatch);
        }
        h.result = Some(source.result()?.clone());
        h.verified_at = Some(source.accepted_at()?);
        n.queue_producer_binding(h, "producer_binding_result", source.request().clone())
    }
    pub(crate) fn poll_producer_binding_source(
        &mut self,
        source: &kernel::producer_binding::Verified,
    ) -> Result<Option<Receipt>> {
        source.bind_service(self)?;
        source.verify()?;
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        if !n.poll_inspection("producer_binding_result")? {
            return Ok(None);
        }
        let h = n.producer_binding_history()?;
        if h.birth.as_ref() != Some(&source.birth()?)
            || h.result.as_ref() != Some(source.result()?)
            || h.verified_at != Some(source.accepted_at()?)
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
    pub(crate) fn verify(&self, source: &kernel::producer_binding::Verified) -> Result<()> {
        source.verify()?;
        self.verify_history(source)
    }
    pub(crate) fn verify_history(&self, source: &kernel::producer_binding::Verified) -> Result<()> {
        source.verify_retained()?;
        source
            .intent()?
            .verify_owner_origin(&self.shared, &self.member)?;
        if self.creator != std::process::id()
            || self.history.request != source.request().digest()
            || self.history.birth.as_ref() != Some(&source.birth()?)
            || self.history.result.as_ref() != Some(source.result()?)
            || self.history.verified_at != Some(source.accepted_at()?)
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
        if p.producer_binding.as_ref() != Some(&self.history) {
            return Err(Error::OwnershipMismatch);
        }
        self.history.validate(&j.record, e, p)
    }
}

pub(crate) enum Progress<'a> {
    Intent,
    Birth(&'a kernel::producer_binding::Child),
    Result(&'a kernel::producer_binding::Verified),
}
impl quarantine::Binding {
    pub(crate) fn verify_producer_binding_progress(
        self: &Rc<Self>,
        server: &Server,
        request: &Rc<Request>,
        stage: Progress<'_>,
    ) -> Result<()> {
        self.verify_service_custody(server)?;
        request.verify()?;
        if !Rc::ptr_eq(self, request.binding()) {
            return Err(Error::OwnershipMismatch);
        }
        let n = server.native.as_ref().ok_or(Error::Interrupted)?;
        if !matches!(n.continuation.as_ref().and_then(|c|c.quarantine_origin.as_ref()),Some(quarantine::ProgressOrigin::ProducerBinding(r)) if Rc::ptr_eq(r,request))
        {
            return Err(Error::OwnershipMismatch);
        }
        let mut expected = n.transaction.shared.journal.borrow().record.clone();
        let e = expected
            .entries
            .iter_mut()
            .find(|e| e.exit_id == n.history.member)
            .ok_or(Error::OwnershipMismatch)?;
        let p = e.preparation.as_mut().ok_or(Error::OwnershipMismatch)?;
        let mut h = History {
            request: request.digest(),
            parent: request.parent(),
            name: request.name().into(),
            data: request.data(),
            query: request.query_digest(),
            requested_at: request.requested_at(),
            deadline: request.deadline(),
            birth: None,
            group: request.group(),
            creation: p
                .producer_creation
                .clone()
                .ok_or(Error::OwnershipMismatch)?,
            policy: request.policy_digest(),
            pins: request.pins(),
            result: None,
            verified_at: None,
        };
        let phase = match stage {
            Progress::Intent => {
                if p.producer_binding.is_some() || e.producer.is_some() {
                    return Err(Error::OwnershipMismatch);
                }
                "producer_binding_intent"
            }
            Progress::Birth(c) => {
                if !Rc::ptr_eq(c.request(), request)
                    || p.producer_binding.as_ref() != Some(&h)
                    || e.producer.is_some()
                {
                    return Err(Error::OwnershipMismatch);
                }
                c.bind_service(server)?;
                h.birth = Some(c.birth()?);
                "producer_binding_birth"
            }
            Progress::Result(v) => {
                if !Rc::ptr_eq(v.request(), request) || e.producer.is_some() {
                    return Err(Error::OwnershipMismatch);
                }
                v.bind_service(server)?;
                h.birth = Some(v.birth()?);
                if p.producer_binding.as_ref() != Some(&h) {
                    return Err(Error::OwnershipMismatch);
                }
                h.result = Some(v.result()?.clone());
                h.verified_at = Some(v.accepted_at()?);
                e.producer = Some(ProducerOwnership {
                    parent: h.parent,
                    group: h.group,
                    binding: Some(h.request),
                });
                "producer_binding_result"
            }
        };
        p.producer_binding = Some(h);
        n.verify_owned_progress(&expected, phase, request.requested_at())?;
        self.verify_retained()?;
        request.check()
    }
}

#[cfg(test)]
impl Server {
    /// Exercises only public-record validation and already-refused legacy
    /// entry points. No ownership is reconstructed from these parsed copies.
    pub(crate) fn lab_producer_binding_schema_checks(&self, r: &Request) -> Result<usize> {
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        n.require_creator()?;
        let shared = &n.transaction.shared;
        let journal = shared.journal.borrow();
        let record = &journal.record;
        let validate = |record: &Record| {
            record.bind_anchor(
                &record.allocation,
                &record.primary_exit_id,
                record.base_network,
                record.owner_network,
            )
        };
        validate(record)?;
        let encoded = encode_record(record)?;
        let parsed: Record =
            serde_json::from_slice(&encoded).map_err(|_| Error::OwnershipMismatch)?;
        validate(&parsed)?;
        if encode_record(&parsed)? != encoded {
            return Err(Error::OwnershipMismatch);
        }
        let selected = record
            .entries
            .iter()
            .position(|e| e.exit_id == n.history.member)
            .ok_or(Error::OwnershipMismatch)?;
        let base = serde_json::to_value(record).map_err(|_| Error::OwnershipMismatch)?;
        let mut negatives = 0;
        let mut refuse = |value: serde_json::Value| -> Result<()> {
            if serde_json::from_value::<Record>(value).is_ok_and(|v| validate(&v).is_ok()) {
                return Err(Error::OwnershipMismatch);
            }
            negatives += 1;
            Ok(())
        };
        for path in [
            "/producer/binding",
            "/preparation/producer_binding",
            "/preparation/producer_binding_query",
            "/preparation/producer_creation",
        ] {
            let mut changed = base.clone();
            let pointer = format!("/entries/{selected}{path}");
            *changed
                .pointer_mut(&pointer)
                .ok_or(Error::OwnershipMismatch)? = serde_json::Value::Null;
            refuse(changed)?;
        }
        for path in [
            "/producer/binding/0",
            "/producer/group/ino",
            "/producer/parent/ino",
            "/preparation/producer_binding/query/0",
            "/preparation/producer_binding/policy/0",
            "/preparation/producer_binding/result/group/ino",
            "/preparation/producer_binding/result/policy/0",
            "/preparation/producer_binding/creation/parent/ino",
            "/preparation/producer_creation/group/ino",
            "/preparation/producer_binding_query/request/0",
        ] {
            let mut changed = base.clone();
            let pointer = format!("/entries/{selected}{path}");
            let old = changed
                .pointer(&pointer)
                .and_then(serde_json::Value::as_u64)
                .ok_or(Error::OwnershipMismatch)?;
            *changed
                .pointer_mut(&pointer)
                .ok_or(Error::OwnershipMismatch)? = serde_json::json!(old ^ 1);
            refuse(changed)?;
        }
        for phase in ["activating", "bootstrap"] {
            let mut changed = base.clone();
            changed["entries"][selected]["phase"] = serde_json::json!(phase);
            refuse(changed)?;
        }
        // Legacy verification reaches its discriminator refusal before staging
        // or native acquisition. This is not a fresh native operation window.
        let spec = r.binding().data().request().spec();
        if !matches!(journal.revalidate(spec), Err(Error::OwnershipMismatch))
            || !matches!(
                journal.verify_producer(spec, r.parent(), r.group()),
                Err(Error::OwnershipMismatch)
            )
        {
            return Err(Error::OwnershipMismatch);
        }
        negatives += 2;
        let mut attempt_copy = record.clone();
        let lifecycle = "a".repeat(64);
        let domains = super::super::super::supervision::Domains::new(spec, &lifecycle)?;
        let attempt = AttemptOwnership {
            exit_id: n.history.member.clone(),
            lifecycle,
            allocation: domains.allocation().into(),
            launch: "a".repeat(64),
            resources: attempt_resources(&record.entries[selected])?,
            owner: n.owner.record(&n.domains)?,
            scopes: attempt_scopes(&domains),
            planned_at: vprouter_core::health::boot_seconds(),
            stage: AttemptStage::Planned,
            birth: None,
            guard_group: None,
            retirement: None,
        };
        if !matches!(
            attempt_copy.plan_attempt(&n.history.member, attempt),
            Err(Error::Interrupted)
        ) || encode_record(&attempt_copy)? != encoded
        {
            return Err(Error::OwnershipMismatch);
        }
        negatives += 1;
        drop(journal);
        if !matches!(
            n.transaction.pending_binding(spec),
            Err(Error::OwnershipMismatch)
        ) {
            return Err(Error::OwnershipMismatch);
        }
        negatives += 1;
        // Correct native namespace descriptors are retained solely to ensure
        // these legacy refusals precede their namespace checks; no group or
        // enforcement capability is constructed by the negative test.
        let data = r
            .binding()
            .data()
            .request()
            .source()
            .try_clone_to_owned()
            .map_err(|_| Error::DescriptorDuplicate)?;
        let transport = r
            .binding()
            .transport()
            .request()
            .source()
            .try_clone_to_owned()
            .map_err(|_| Error::DescriptorDuplicate)?;
        let namespaces = OwnedNamespaces::new(spec, data, transport)?;
        let mut journal = shared.journal.borrow_mut();
        if !matches!(
            journal.acquire(spec, r.binding().data().request().source()),
            Err(Error::OwnershipMismatch)
        ) || !matches!(
            journal.begin_transport(spec, &namespaces),
            Err(Error::OwnershipMismatch)
        ) || !matches!(
            journal.bind_links(spec, &namespaces, r.binding().host(), (2, 3, 4)),
            Err(Error::OwnershipMismatch)
        ) || !matches!(
            journal.bootstrap(spec, &namespaces, r.binding().host(), (2, 3, 4)),
            Err(Error::OwnershipMismatch)
        ) || !matches!(
            journal.transport_cleaned(spec),
            Err(Error::OwnershipMismatch)
        ) || encode_record(&journal.record)? != encoded
        {
            return Err(Error::OwnershipMismatch);
        }
        negatives += 5;
        Ok(negatives)
    }
}
