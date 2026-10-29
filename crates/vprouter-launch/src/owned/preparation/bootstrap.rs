//! Evidence for ordered original Bootstrap operations. Parsing this metadata
//! never constructs an original producer, table owner or permission to mutate.
use super::super::super::attachment::operational::bootstrap::Request;
use super::super::super::attachment::quarantine::Scope;
use super::*;
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PublicResult {
    pub(crate) namespace: Identity,
    pub(crate) group: Identity,
    pub(crate) policy: [u8; 32],
    pub(crate) pins: [(u64, u64, u32); 8],
    pub(crate) observed_at: f64,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct History {
    request: [u8; 32],
    scope: Scope,
    namespace: Identity,
    creation: producer_creation::History,
    group: Identity,
    query: [u8; 32],
    requested_at: f64,
    deadline: f64,
    policy: [u8; 32],
    pins: [(u64, u64, u32); 8],
    birth: Option<ValidationBirth>,
    result: Option<PublicResult>,
    verified_at: Option<f64>,
}
impl History {
    pub(super) fn completed_at(&self) -> Result<f64> {
        if self.birth.is_none() || self.result.is_none() {
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
        let scope = *[Scope::Host, Scope::Transport, Scope::Data]
            .get(index)
            .ok_or(Error::OwnershipMismatch)?;
        let (query, start, query_at) = p
            .bootstrap_queries
            .get(index)
            .and_then(Option::as_ref)
            .ok_or(Error::OwnershipMismatch)?
            .completed_bootstrap(index)?;
        let creation = p
            .producer_creation
            .as_ref()
            .ok_or(Error::OwnershipMismatch)?;
        let (parent, group, _, data) = creation.completed_binding()?;
        let namespace = match scope {
            Scope::Host => record.owner_network,
            Scope::Transport => entry.transport,
            Scope::Data => entry.data,
        }
        .ok_or(Error::OwnershipMismatch)?;
        let prior = if index == 0 {
            p.host_link
                .get(3)
                .ok_or(Error::OwnershipMismatch)?
                .completed_host_addition_at()?
        } else {
            p.bootstrap
                .get(index - 1)
                .ok_or(Error::OwnershipMismatch)?
                .completed_at()?
        };
        if self.scope != scope
            || self.request == [0; 32]
            || self.namespace != namespace
            || self.creation != *creation
            || self.group != group
            || Some(data) != entry.data
            || self.query != query
            || self.requested_at != start
            || self.deadline != start + 2.
            || prior > start
            || p.host_link.len() != 4
            || p.netfilter.len() != 6
            || p.producer_binding
                .as_ref()
                .is_none_or(|b| !b.matches_publication(entry))
            || self.policy != p.netfilter[index * 2 + 1].bootstrap_policy(scope)?
            || (self.pins[0].0, self.pins[0].1) != (parent.dev, parent.ino)
            || (self.pins[1].0, self.pins[1].1) != (group.dev, group.ino)
            || self
                .pins
                .iter()
                .any(|pin| pin.0 != parent.dev || pin.1 == 0)
            || self.pins.iter().enumerate().any(|(i, pin)| {
                self.pins[..i]
                    .iter()
                    .any(|old| (old.0, old.1) == (pin.0, pin.1))
            })
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
            (None, None) => Ok(()),
            (Some(r), Some(at))
                if r.namespace == namespace
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
    pub(crate) fn bootstrap_policy(
        &self,
        source: &kernel::producer_creation::Source,
        scope: Scope,
    ) -> Result<[u8; 32]> {
        self.verify_preparation_idle()?;
        source.bind_service(self)?;
        source.verify_acknowledged_history()?;
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        let j = n.transaction.shared.journal.borrow();
        let e = j
            .record
            .entries
            .iter()
            .find(|e| e.exit_id == n.history.member)
            .ok_or(Error::OwnershipMismatch)?;
        let p = e.preparation.as_ref().ok_or(Error::OwnershipMismatch)?;
        p.validate(&j.record, e)?;
        let (_, group, _, _) = p
            .producer_creation
            .as_ref()
            .ok_or(Error::OwnershipMismatch)?
            .completed_binding()?;
        if source.identity()? != group
            || p.host_link.len() != 4
            || p.netfilter.len() != 6
            || p.producer_binding
                .as_ref()
                .is_none_or(|b| !b.matches_publication(e))
        {
            return Err(Error::OwnershipMismatch);
        }
        let index = match scope {
            Scope::Host => 1,
            Scope::Transport => 3,
            Scope::Data => 5,
        };
        p.netfilter[index].bootstrap_policy(scope)
    }
}

#[derive(Clone, Copy)]
enum Stage {
    Intent,
    Birth,
    Result,
}
fn phase(index: usize, stage: Stage) -> &'static str {
    match (index, stage) {
        (0, Stage::Intent) => "bootstrap_host_intent",
        (0, Stage::Birth) => "bootstrap_host_birth",
        (0, Stage::Result) => "bootstrap_host_result",
        (1, Stage::Intent) => "bootstrap_transport_intent",
        (1, Stage::Birth) => "bootstrap_transport_birth",
        (1, Stage::Result) => "bootstrap_transport_result",
        (2, Stage::Intent) => "bootstrap_data_intent",
        (2, Stage::Birth) => "bootstrap_data_birth",
        (2, Stage::Result) => "bootstrap_data_result",
        _ => "invalid_bootstrap_scope",
    }
}
pub(crate) struct Intent {
    creator: u32,
    shared: Rc<SharedJournal>,
    member: String,
    history: History,
    index: usize,
    owner: Rc<OwnerDomain>,
    domains: Domains,
    lease: MutatorLease,
}
impl Intent {
    pub(crate) fn verify_previous(&self, previous: &kernel::bootstrap::Previous<'_>) -> Result<()> {
        if self.creator != std::process::id() {
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
        match previous {
            kernel::bootstrap::Previous::Initial(v) => {
                if self.index >= 2 {
                    return Err(Error::OwnershipMismatch);
                }
                v.intent()?
                    .verify_shared_origin(&self.shared, &self.member)?;
                p.netfilter
                    .get(self.index * 2 + 1)
                    .ok_or(Error::OwnershipMismatch)?
                    .matches_assembly_receipt(v)?;
            }
            kernel::bootstrap::Previous::Observed(v) => {
                if self.index != 2 {
                    return Err(Error::OwnershipMismatch);
                }
                v.intent()?
                    .verify_owner_origin(&self.shared, &self.member)?;
                p.producer_binding
                    .as_ref()
                    .ok_or(Error::OwnershipMismatch)?
                    .matches_bootstrap_receipt(v)?;
            }
        }
        self.history.validate(&journal.record, entry, p, self.index)
    }
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
            || self.index != request.index()
            || self.history.scope != request.scope()
            || self.history.request != request.digest()
            || self.history.group != request.group()
            || self.history.pins != request.identities()
            || self.history.policy != request.policy_digest()
            || self.history.query != request.query_digest()
            || self.history.namespace != request.namespace()
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
        if p.bootstrap.get(self.index) != Some(&self.history)
            || journal.record.owner_epoch.as_ref() != Some(&self.owner.record(&self.domains)?)
        {
            return Err(Error::OwnershipMismatch);
        }
        self.history.validate(&journal.record, entry, p, self.index)
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
    index: usize,
}
impl Gate {
    pub(crate) fn verify(&self, intent: &Intent, birth: &ValidationBirth) -> Result<()> {
        if self.creator != std::process::id()
            || self.creator != intent.creator
            || !Rc::ptr_eq(&self.shared, &intent.shared)
            || self.member != intent.member
            || self.index != intent.index
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
        if p.bootstrap.get(self.index) != Some(&self.history)
            || journal.record.owner_epoch.as_ref() != Some(&intent.owner.record(&intent.domains)?)
        {
            return Err(Error::OwnershipMismatch);
        }
        self.history.validate(&journal.record, e, p, self.index)?;
        original_frame(
            self.history.requested_at,
            vprouter_core::health::boot_seconds(),
        )?;
        kernel::owner_admission_permitted()
    }
}
impl Native {
    pub(super) fn bootstrap_history(&self, index: usize) -> Result<History> {
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
            .and_then(|p| p.bootstrap.get(index).cloned())
            .ok_or(Error::OwnershipMismatch)
    }
    fn queue_bootstrap(
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
        let operations = &mut entry
            .preparation
            .as_mut()
            .ok_or(Error::OwnershipMismatch)?
            .bootstrap;
        let index = request.index();
        if index == operations.len() {
            operations.push(history);
        } else if index.checked_add(1) == Some(operations.len()) {
            operations[index] = history;
        } else {
            return Err(Error::OwnershipMismatch);
        }
        proposed.bind_anchor(
            &proposed.allocation,
            &proposed.primary_exit_id,
            proposed.base_network,
            proposed.owner_network,
        )?;
        shared.queue.borrow_mut().push(&self.history.member)?;
        self.continuation = Some(Continuation {
            quarantine_origin: Some(quarantine::ProgressOrigin::Bootstrap(request)),
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
    pub(crate) fn start_bootstrap(&mut self, request: &Rc<Request>) -> Result<()> {
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
        if p.bootstrap.len() != request.index()
            || p.netfilter.len() != 6
            || p.producer_creation.is_none()
        {
            return Err(Error::OwnershipMismatch);
        }
        let creation = p
            .producer_creation
            .clone()
            .ok_or(Error::OwnershipMismatch)?;
        drop(j);
        n.queue_bootstrap(
            History {
                request: request.digest(),
                scope: request.scope(),
                namespace: request.namespace(),
                query: request.query_digest(),
                requested_at: request.requested_at(),
                deadline: request.deadline(),
                birth: None,
                group: request.group(),
                pins: request.identities(),
                policy: request.policy_digest(),
                creation,
                result: None,
                verified_at: None,
            },
            phase(request.index(), Stage::Intent),
            request.clone(),
        )
    }
    pub(crate) fn poll_bootstrap_intent(&mut self, request: &Request) -> Result<Option<Intent>> {
        request.verify()?;
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        if !n.poll_inspection(phase(request.index(), Stage::Intent))? {
            return Ok(None);
        }
        let intent = Intent {
            creator: n.creator,
            shared: n.transaction.shared.clone(),
            member: n.history.member.clone(),
            history: n.bootstrap_history(request.index())?,
            index: request.index(),
            owner: n.owner.clone(),
            domains: n.domains.clone(),
            lease: n.transaction.retain_allocation_lease()?,
        };
        intent.verify(request)?;
        Ok(Some(intent))
    }
    pub(crate) fn start_bootstrap_birth(&mut self, child: &kernel::bootstrap::Child) -> Result<()> {
        child.bind_service(self)?;
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        let mut h = n.bootstrap_history(child.request().index())?;
        if h.birth.is_some() || h.request != child.request_digest()? {
            return Err(Error::OwnershipMismatch);
        }
        h.birth = Some(child.birth()?);
        n.queue_bootstrap(
            h,
            phase(child.request().index(), Stage::Birth),
            child.request().clone(),
        )
    }
    pub(crate) fn poll_bootstrap_birth(
        &mut self,
        child: &kernel::bootstrap::Child,
    ) -> Result<Option<Gate>> {
        child.bind_service(self)?;
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        if !n.poll_inspection(phase(child.request().index(), Stage::Birth))? {
            return Ok(None);
        }
        let gate = Gate {
            creator: n.creator,
            shared: n.transaction.shared.clone(),
            member: n.history.member.clone(),
            history: n.bootstrap_history(child.request().index())?,
            index: child.request().index(),
        };
        child.verify_gate(&gate)?;
        Ok(Some(gate))
    }
    pub(crate) fn start_bootstrap_source(
        &mut self,
        source: &kernel::bootstrap::Verified,
    ) -> Result<()> {
        source.bind_service(self)?;
        source.verify()?;
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        let mut h = n.bootstrap_history(source.request().index())?;
        if h.birth.as_ref() != Some(&source.birth()?) || h.result.is_some() {
            return Err(Error::OwnershipMismatch);
        }
        h.result = Some(source.result()?.clone());
        h.verified_at = Some(source.accepted_at()?);
        n.queue_bootstrap(
            h,
            phase(source.request().index(), Stage::Result),
            source.request().clone(),
        )
    }
    pub(crate) fn poll_bootstrap_source(
        &mut self,
        source: &kernel::bootstrap::Verified,
    ) -> Result<Option<Receipt>> {
        source.bind_service(self)?;
        source.verify()?;
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        if !n.poll_inspection(phase(source.request().index(), Stage::Result))? {
            return Ok(None);
        }
        let h = n.bootstrap_history(source.request().index())?;
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
            index: source.request().index(),
        }))
    }
}

pub(crate) struct Receipt {
    creator: u32,
    shared: Rc<SharedJournal>,
    member: String,
    history: History,
    index: usize,
}
impl Receipt {
    pub(crate) fn verify(&self, source: &kernel::bootstrap::Verified) -> Result<()> {
        source.verify()?;
        self.verify_history(source)
    }
    pub(crate) fn verify_history(&self, source: &kernel::bootstrap::Verified) -> Result<()> {
        source.verify_retained()?;
        source
            .intent()?
            .verify_owner_origin(&self.shared, &self.member)?;
        if self.creator != std::process::id()
            || self.history.request != source.request().digest()
            || self.history.birth.as_ref() != Some(&source.birth()?)
            || self.history.result.as_ref() != Some(source.historical_result()?)
            || self.history.verified_at != Some(source.historical_accepted_at()?)
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
        if p.bootstrap.get(self.index) != Some(&self.history) {
            return Err(Error::OwnershipMismatch);
        }
        self.history.validate(&j.record, e, p, self.index)
    }
}

pub(crate) enum Progress<'a> {
    Intent,
    Birth(&'a kernel::bootstrap::Child),
    Result(&'a kernel::bootstrap::Verified),
}
impl quarantine::Binding {
    pub(crate) fn verify_bootstrap_progress(
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
        if !matches!(n.continuation.as_ref().and_then(|c|c.quarantine_origin.as_ref()),Some(quarantine::ProgressOrigin::Bootstrap(r)) if Rc::ptr_eq(r,request))
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
            scope: request.scope(),
            namespace: request.namespace(),
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
            pins: request.identities(),
            result: None,
            verified_at: None,
        };
        let phase = match stage {
            Progress::Intent => {
                if p.bootstrap.len() != request.index() {
                    return Err(Error::OwnershipMismatch);
                }
                phase(request.index(), Stage::Intent)
            }
            Progress::Birth(c) => {
                if !Rc::ptr_eq(c.request(), request)
                    || p.bootstrap.get(request.index()) != Some(&h)
                    || p.bootstrap.len() != request.index() + 1
                {
                    return Err(Error::OwnershipMismatch);
                }
                c.bind_service(server)?;
                h.birth = Some(c.birth()?);
                phase(request.index(), Stage::Birth)
            }
            Progress::Result(v) => {
                if !Rc::ptr_eq(v.request(), request) || p.bootstrap.len() != request.index() + 1 {
                    return Err(Error::OwnershipMismatch);
                }
                v.bind_service(server)?;
                h.birth = Some(v.birth()?);
                if p.bootstrap.get(request.index()) != Some(&h) {
                    return Err(Error::OwnershipMismatch);
                }
                h.result = Some(v.result()?.clone());
                h.verified_at = Some(v.accepted_at()?);
                phase(request.index(), Stage::Result)
            }
        };
        if p.bootstrap.len() == request.index() {
            p.bootstrap.push(h);
        } else {
            *p.bootstrap
                .get_mut(request.index())
                .ok_or(Error::OwnershipMismatch)? = h;
        }
        n.verify_owned_progress(&expected, phase, request.requested_at())?;
        self.verify_retained()?;
        request.check()
    }
}

impl Server {
    pub(crate) fn verify_bootstrap_chain(
        &self,
        values: &[(
            Rc<kernel::docker_query::Accepted>,
            kernel::bootstrap::Verified,
        )],
    ) -> Result<()> {
        self.verify_preparation_idle()?;
        if values.len() != 3 {
            return Err(Error::OwnershipMismatch);
        }
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        let j = n.transaction.shared.journal.borrow();
        let e = j
            .record
            .entries
            .iter()
            .find(|e| e.exit_id == n.history.member)
            .ok_or(Error::OwnershipMismatch)?;
        let p = e.preparation.as_ref().ok_or(Error::OwnershipMismatch)?;
        if p.bootstrap.len() != values.len() {
            return Err(Error::OwnershipMismatch);
        }
        for (index, (query, v)) in values.iter().enumerate() {
            v.require_acknowledged_history()?;
            v.bind_service(self)?;
            v.request().require_query_origin(query)?;
            let mut expected = v.intent()?.history.clone();
            expected.birth = Some(v.birth()?);
            expected.result = Some(v.historical_result()?.clone());
            expected.verified_at = Some(v.historical_accepted_at()?);
            if v.request().index() != index || p.bootstrap.get(index) != Some(&expected) {
                return Err(Error::OwnershipMismatch);
            }
            expected.validate(&j.record, e, p, index)?;
        }
        Ok(())
    }
}

#[cfg(test)]
impl quarantine::Binding {
    pub(crate) fn lab_bootstrap_intent_negatives(
        self: &Rc<Self>,
        s: &Server,
        r: &Rc<Request>,
    ) -> Result<usize> {
        self.verify_bootstrap_progress(s, r, Progress::Intent)?;
        let refused = |v: Result<()>| matches!(v, Err(Error::OwnershipMismatch));
        let n = s.native.as_ref().ok_or(Error::Interrupted)?;
        let c = n.continuation.as_ref().ok_or(Error::Interrupted)?;
        let mut changed = c.proposed.clone();
        changed
            .entries
            .iter_mut()
            .find(|e| e.exit_id == n.history.member)
            .ok_or(Error::OwnershipMismatch)?
            .exit_id
            .push_str("-foreign");
        if !refused(self.verify(s))
            || !refused(n.verify_owned_progress(
                &c.proposed,
                phase(r.index(), Stage::Birth),
                c.started_at,
            ))
            || !refused(n.verify_owned_progress(&c.proposed, c.phase, c.started_at - 0.001))
            || !refused(n.verify_owned_progress(&changed, c.phase, c.started_at))
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(4)
    }
}
#[cfg(test)]
impl Server {
    pub(crate) fn lab_bootstrap_schema_checks(&self) -> Result<usize> {
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        n.require_creator()?;
        let j = n.transaction.shared.journal.borrow();
        let record = &j.record;
        let validate = |r: &Record| {
            r.bind_anchor(
                &r.allocation,
                &r.primary_exit_id,
                r.base_network,
                r.owner_network,
            )
        };
        validate(record)?;
        let original = serde_json::to_value(record).map_err(|_| Error::OwnershipMismatch)?;
        let index = record
            .entries
            .iter()
            .position(|e| e.exit_id == n.history.member)
            .ok_or(Error::OwnershipMismatch)?;
        let mut count = 0;
        for scope in 0..3 {
            for path in [
                "namespace/ino",
                "group/ino",
                "query/0",
                "policy/0",
                "pins/6/1",
                "pins/7/1",
                "creation/parent/ino",
                "result/policy/0",
                "result/group/ino",
                "result/pins/7/1",
            ] {
                let mut changed = original.clone();
                let ptr = format!("/entries/{index}/preparation/bootstrap/{scope}/{path}");
                let field = changed.pointer_mut(&ptr).ok_or(Error::OwnershipMismatch)?;
                *field = serde_json::json!(field.as_u64().ok_or(Error::OwnershipMismatch)? ^ 1);
                if serde_json::from_value::<Record>(changed).is_ok_and(|v| validate(&v).is_ok()) {
                    return Err(Error::OwnershipMismatch);
                }
                count += 1;
            }
            for path in ["birth", "result", "verified_at"] {
                let mut changed = original.clone();
                *changed
                    .pointer_mut(&format!(
                        "/entries/{index}/preparation/bootstrap/{scope}/{path}"
                    ))
                    .ok_or(Error::OwnershipMismatch)? = serde_json::Value::Null;
                if serde_json::from_value::<Record>(changed).is_ok_and(|v| validate(&v).is_ok()) {
                    return Err(Error::OwnershipMismatch);
                }
                count += 1;
            }
        }
        Ok(count)
    }
}
