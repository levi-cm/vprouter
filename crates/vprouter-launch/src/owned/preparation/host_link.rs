//! Original declaration-bound socket/pair/HOST addition journal sequence.
//! Parsed histories are evidence only; release requires the private live gate.
use super::super::super::attachment::host_addition::{Kind, Request};
use super::*;
use kernel::host_link::{Child, PublicResult, Verified};
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct History {
    kind: Kind,
    request: [u8; 32],
    namespace: Identity,
    host: Identity,
    declaration: [u8; 32],
    admission: [f64; 3],
    requested_at: f64,
    deadline: f64,
    addition: Option<([u8; 32], u32)>,
    birth: Option<ValidationBirth>,
    result: Option<PublicResult>,
    verified_at: Option<f64>,
}
impl History {
    pub(super) fn completed_host_addition_at(&self) -> Result<f64> {
        if self.kind != Kind::Move || self.birth.is_none() || self.result.is_none() {
            return Err(Error::OwnershipMismatch);
        }
        self.verified_at.ok_or(Error::OwnershipMismatch)
    }
    fn requested(r: &Request) -> Self {
        Self {
            kind: r.kind(),
            request: r.digest(),
            namespace: r.namespace(),
            host: r.binding().host(),
            declaration: r.declaration_digest(),
            admission: r.admission_window(),
            requested_at: r.requested_at(),
            deadline: r.deadline(),
            addition: r.addition(),
            birth: None,
            result: None,
            verified_at: None,
        }
    }
    pub(super) fn validate(
        &self,
        record: &Record,
        e: &Entry,
        p: &super::History,
        index: usize,
    ) -> Result<()> {
        let kinds = [
            Kind::TransportSockets,
            Kind::Pair,
            Kind::HostSockets,
            Kind::Move,
        ];
        let bound = p
            .producer_binding
            .as_ref()
            .ok_or(Error::OwnershipMismatch)?;
        if kinds.get(index) != Some(&self.kind)
            || !bound.matches_publication(e)
            || self.request == [0; 32]
            || self.declaration == [0; 32]
            || record.owner_network != Some(self.host)
            || Some(self.namespace)
                != if self.kind == Kind::HostSockets {
                    Some(self.host)
                } else {
                    e.transport
                }
            || self.admission.iter().any(|v| !v.is_finite())
            || self.admission[0] <= 0.
            || self.admission[1] != self.admission[0] + 2.
            || self.admission[2] < self.admission[0]
            || self.admission[2] >= self.admission[1]
            || self.admission[0] < bound.host_bound_at()?
            || !self.requested_at.is_finite()
            || self.requested_at < self.admission[2]
            || self.deadline != self.requested_at + 2.
            || (self.kind == Kind::Move) != self.addition.is_some()
        {
            return Err(Error::OwnershipMismatch);
        }
        if let Some((digest, planned)) = self.addition
            && (digest == [0; 32]
                || vprouter_network::planned_host_link_index(&record.allocation, &e.exit_id)
                    .map_err(|_| Error::OwnershipMismatch)?
                    != planned)
        {
            return Err(Error::OwnershipMismatch);
        }
        if index > 0 {
            let previous = &p.host_link[index - 1];
            if previous.result.is_none()
                || previous.verified_at.is_none_or(|at| at > self.requested_at)
                || previous.declaration != self.declaration
                || previous.admission != self.admission
                || previous.host != self.host
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
            (None, None) => (),
            (Some(r), Some(at)) => {
                if !at.is_finite()
                    || at >= self.deadline
                    || self.birth.as_ref().is_none_or(|b| at < b.born_at)
                    || r.namespace
                        != if self.kind == Kind::Move {
                            self.host
                        } else {
                            self.namespace
                        }
                {
                    return Err(Error::OwnershipMismatch);
                }
                match self.kind {
                    Kind::TransportSockets | Kind::HostSockets => {
                        if r.host.is_some() || r.peer.is_some() {
                            return Err(Error::OwnershipMismatch);
                        }
                    }
                    Kind::Pair => {
                        let (h, t) = r.pair()?;
                        let allocation = record
                            .allocation
                            .exits
                            .iter()
                            .find(|a| a.exit_id == e.exit_id)
                            .ok_or(Error::OwnershipMismatch)?;
                        let alias = format!(
                            "vprouter-v2:{}:{}:{}",
                            record.allocation.deployment_id,
                            record.allocation.generation,
                            e.exit_id
                        );
                        if h.name != allocation.host_interface
                            || t.name != allocation.data_interface
                            || h.up
                            || t.up
                            || h.kind != "veth"
                            || t.kind != "veth"
                            || h.index == 0
                            || t.index == 0
                            || h.index == t.index
                            || h.alias != alias
                            || t.alias != alias
                            || h.peer_index != Some(t.index)
                            || t.peer_index != Some(h.index)
                        {
                            return Err(Error::OwnershipMismatch);
                        }
                    }
                    Kind::Move => {
                        let (_, index) = self.addition.ok_or(Error::OwnershipMismatch)?;
                        let (old_h, old_t) = p
                            .host_link
                            .get(1)
                            .and_then(|h| h.result.as_ref())
                            .ok_or(Error::OwnershipMismatch)?
                            .pair()?;
                        let mut h = old_h.clone();
                        h.index = index;
                        let mut t = old_t.clone();
                        t.peer_index = Some(index);
                        if r.host.as_ref() != Some(&h) || r.peer.as_ref() != Some(&t) {
                            return Err(Error::OwnershipMismatch);
                        }
                    }
                }
            }
            _ => return Err(Error::OwnershipMismatch),
        }
        Ok(())
    }
    fn matches(&self, v: &Verified) -> Result<()> {
        if self.request != v.request().digest()
            || self.birth.as_ref() != Some(&v.birth()?)
            || self.result.as_ref() != Some(v.historical_result()?)
            || self.verified_at != Some(v.historical_accepted_at()?)
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
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
    pub(crate) fn verify_previous(&self, p: &Self, index: usize) -> Result<()> {
        if self.creator != std::process::id()
            || p.creator != self.creator
            || !Rc::ptr_eq(&self.shared, &p.shared)
            || !Rc::ptr_eq(&self.owner, &p.owner)
            || self.member != p.member
            || p.index != index
            || p.index >= self.index
            || self.history.declaration != p.history.declaration
            || self.history.admission != p.history.admission
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
    pub(crate) fn verify(&self, r: &Request) -> Result<()> {
        r.verify()?;
        r.binding()
            .verify_owner_origin(&self.shared, &self.owner, &self.member)?;
        if self.creator != std::process::id()
            || self.history != History::requested(r)
            || self.index != r.index()
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
        if p.host_link.get(self.index) != Some(&self.history)
            || j.record.owner_epoch.as_ref() != Some(&self.owner.record(&self.domains)?)
        {
            return Err(Error::OwnershipMismatch);
        }
        self.history.validate(&j.record, e, p, self.index)
    }
    pub(crate) fn prepare(&mut self, r: &Request) -> Result<()> {
        self.verify(r)?;
        self.lease
            .prepare_native_job(kernel::NativeJobKind::FixedVeth)
    }
    pub(crate) fn lease(&mut self) -> &mut MutatorLease {
        &mut self.lease
    }
    pub(crate) fn transfer_ticket(&self) -> Result<&kernel::NativeJobTicket> {
        if self.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        self.lease.transfer_ticket()
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
        if p.host_link.get(self.index) != Some(&self.history)
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
    gate: Gate,
}
impl Receipt {
    pub(crate) fn verify(&self, v: &Verified) -> Result<()> {
        v.verify()?;
        let g = &self.gate;
        let i = v.intent()?;
        if g.creator != std::process::id()
            || !Rc::ptr_eq(&g.shared, &i.shared)
            || g.member != i.member
            || g.index != i.index
            || g.history.request != v.request().digest()
            || g.history.birth.as_ref() != Some(&v.birth()?)
            || g.history.result.as_ref() != Some(v.result()?)
            || g.history.verified_at != Some(v.accepted_at()?)
            || g.shared.fenced.get()
            || g.shared.pending.borrow().is_some()
        {
            return Err(Error::OwnershipMismatch);
        }
        let j = g.shared.journal.borrow();
        let e = j
            .record
            .entries
            .iter()
            .find(|e| e.exit_id == g.member)
            .ok_or(Error::OwnershipMismatch)?;
        let p = e.preparation.as_ref().ok_or(Error::OwnershipMismatch)?;
        if p.host_link.get(g.index) != Some(&g.history) {
            return Err(Error::OwnershipMismatch);
        }
        g.history.validate(&j.record, e, p, g.index)
    }
}
impl Native {
    fn host_link_history(&self, index: usize) -> Result<History> {
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
            .and_then(|p| p.host_link.get(index))
            .cloned()
            .ok_or(Error::OwnershipMismatch)
    }
    fn queue_host_link(
        &mut self,
        r: &Rc<Request>,
        h: History,
        phase: &'static str,
        insert: bool,
    ) -> Result<()> {
        self.require_creator()?;
        r.verify()?;
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
        let p = proposed
            .entries
            .iter_mut()
            .find(|e| e.exit_id == self.history.member)
            .and_then(|e| e.preparation.as_mut())
            .ok_or(Error::OwnershipMismatch)?;
        if insert {
            if p.host_link.len() != r.index() {
                return Err(Error::OwnershipMismatch);
            }
            p.host_link.push(h);
        } else {
            if p.host_link.len() != r.index() + 1 {
                return Err(Error::OwnershipMismatch);
            }
            p.host_link[r.index()] = h;
        }
        proposed.bind_anchor(
            &proposed.allocation,
            &proposed.primary_exit_id,
            proposed.base_network,
            proposed.owner_network,
        )?;
        shared.queue.borrow_mut().push(&self.history.member)?;
        self.continuation = Some(Continuation {
            quarantine_origin: Some(quarantine::ProgressOrigin::HostLink(r.clone())),
            before,
            proposed,
            started_at: r.requested_at(),
            phase,
            publication: None,
            transport_publication: None,
        });
        self.queued_at = Some(vprouter_core::health::boot_seconds());
        Ok(())
    }
}
impl Server {
    pub(crate) fn verify_completed_host_links(&self, original: &[Verified]) -> Result<()> {
        self.verify_preparation_idle()?;
        self.verify_completed_host_custody(original)
    }
    /// Does not admit work while busy: the ongoing owner must also prove its
    /// exact typed continuation. All four original completed receipts remain
    /// historical, while their original descriptor custody is checked now.
    pub(crate) fn verify_completed_host_custody(&self, original: &[Verified]) -> Result<()> {
        if original.len() != 4 {
            return Err(Error::OwnershipMismatch);
        }
        original[0]
            .request()
            .binding()
            .verify_service_custody(self)?;
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
        if p.host_link.len() != 4 {
            return Err(Error::OwnershipMismatch);
        }
        for (h, v) in p.host_link.iter().zip(original) {
            v.bind_service(self)?;
            v.require_acknowledged()?;
            h.matches(v)?;
        }
        Ok(())
    }

    pub(crate) fn start_host_link(&mut self, r: &Rc<Request>, previous: &[Verified]) -> Result<()> {
        r.verify_service(self)?;
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        let j = n.transaction.shared.journal.borrow();
        let p = j
            .record
            .entries
            .iter()
            .find(|e| e.exit_id == n.history.member)
            .and_then(|e| e.preparation.as_ref())
            .ok_or(Error::OwnershipMismatch)?;
        if previous.len() != r.index() || p.host_link.len() != r.index() {
            return Err(Error::OwnershipMismatch);
        }
        for (h, v) in p.host_link.iter().zip(previous) {
            v.bind_service(self)?;
            v.require_acknowledged()?;
            h.matches(v)?;
        }
        drop(j);
        self.native
            .as_mut()
            .ok_or(Error::Interrupted)?
            .queue_host_link(r, History::requested(r), "host_link_intent", true)
    }
    pub(crate) fn poll_host_link_intent(&mut self, r: &Request) -> Result<Option<Intent>> {
        r.verify()?;
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        if !n.poll_inspection("host_link_intent")? {
            return Ok(None);
        }
        let i = Intent {
            creator: n.creator,
            shared: n.transaction.shared.clone(),
            member: n.history.member.clone(),
            history: n.host_link_history(r.index())?,
            index: r.index(),
            owner: n.owner.clone(),
            domains: n.domains.clone(),
            lease: n.transaction.retain_allocation_lease()?,
        };
        i.verify(r)?;
        Ok(Some(i))
    }
    pub(crate) fn start_host_link_birth(&mut self, c: &Child) -> Result<()> {
        c.bind_service(self)?;
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        let mut h = n.host_link_history(c.request().index())?;
        if h != History::requested(c.request()) {
            return Err(Error::OwnershipMismatch);
        }
        h.birth = Some(c.birth()?);
        n.queue_host_link(c.request(), h, "host_link_birth", false)
    }
    pub(crate) fn poll_host_link_birth(&mut self, c: &Child) -> Result<Option<Gate>> {
        c.bind_service(self)?;
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        if !n.poll_inspection("host_link_birth")? {
            return Ok(None);
        }
        let g = Gate {
            creator: n.creator,
            shared: n.transaction.shared.clone(),
            member: n.history.member.clone(),
            history: n.host_link_history(c.request().index())?,
            index: c.request().index(),
        };
        c.verify_gate(&g)?;
        Ok(Some(g))
    }
    pub(crate) fn start_host_link_result(&mut self, v: &Verified) -> Result<()> {
        v.bind_service(self)?;
        v.verify()?;
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        let mut h = n.host_link_history(v.request().index())?;
        if h.request != v.request().digest()
            || h.birth.as_ref() != Some(&v.birth()?)
            || h.result.is_some()
        {
            return Err(Error::OwnershipMismatch);
        }
        h.result = Some(v.result()?.clone());
        h.verified_at = Some(v.accepted_at()?);
        n.queue_host_link(v.request(), h, "host_link_result", false)
    }
    pub(crate) fn poll_host_link_result(&mut self, v: &Verified) -> Result<Option<Receipt>> {
        v.bind_service(self)?;
        v.verify()?;
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        if !n.poll_inspection("host_link_result")? {
            return Ok(None);
        }
        let r = Receipt {
            gate: Gate {
                creator: n.creator,
                shared: n.transaction.shared.clone(),
                member: n.history.member.clone(),
                history: n.host_link_history(v.request().index())?,
                index: v.request().index(),
            },
        };
        r.verify(v)?;
        Ok(Some(r))
    }
}
pub(crate) enum Progress<'a> {
    Intent,
    Birth(&'a Child),
    Result(&'a Verified),
}
impl quarantine::Binding {
    pub(crate) fn verify_host_link_progress(
        self: &Rc<Self>,
        s: &Server,
        r: &Rc<Request>,
        stage: Progress<'_>,
    ) -> Result<()> {
        self.verify_service_custody(s)?;
        r.verify()?;
        if !Rc::ptr_eq(self, r.binding()) {
            return Err(Error::OwnershipMismatch);
        }
        let n = s.native.as_ref().ok_or(Error::Interrupted)?;
        if !matches!(n.continuation.as_ref().and_then(|c|c.quarantine_origin.as_ref()),Some(quarantine::ProgressOrigin::HostLink(original)) if Rc::ptr_eq(original,r))
        {
            return Err(Error::OwnershipMismatch);
        }
        let mut expected = n.transaction.shared.journal.borrow().record.clone();
        let p = expected
            .entries
            .iter_mut()
            .find(|e| e.exit_id == n.history.member)
            .and_then(|e| e.preparation.as_mut())
            .ok_or(Error::OwnershipMismatch)?;
        let mut h = History::requested(r);
        let phase = match stage {
            Progress::Intent => {
                if p.host_link.len() != r.index() {
                    return Err(Error::OwnershipMismatch);
                }
                p.host_link.push(h);
                "host_link_intent"
            }
            Progress::Birth(c) => {
                if !Rc::ptr_eq(c.request(), r)
                    || p.host_link.len() != r.index() + 1
                    || p.host_link[r.index()] != h
                {
                    return Err(Error::OwnershipMismatch);
                }
                c.bind_service(s)?;
                h.birth = Some(c.birth()?);
                p.host_link[r.index()] = h;
                "host_link_birth"
            }
            Progress::Result(v) => {
                if !Rc::ptr_eq(v.request(), r) || p.host_link.len() != r.index() + 1 {
                    return Err(Error::OwnershipMismatch);
                }
                v.bind_service(s)?;
                h.birth = Some(v.birth()?);
                if p.host_link[r.index()] != h {
                    return Err(Error::OwnershipMismatch);
                }
                h.result = Some(v.result()?.clone());
                h.verified_at = Some(v.accepted_at()?);
                p.host_link[r.index()] = h;
                "host_link_result"
            }
        };
        n.verify_owned_progress(&expected, phase, r.requested_at())?;
        self.verify_retained()?;
        r.check()
    }
}

#[cfg(test)]
impl quarantine::Binding {
    pub(crate) fn lab_host_intent_negatives(
        self: &Rc<Self>,
        s: &Server,
        r: &Rc<Request>,
    ) -> Result<usize> {
        self.verify_host_link_progress(s, r, Progress::Intent)?;
        let other = Rc::new((**r).clone());
        let refused = |v: Result<()>| matches!(v, Err(Error::OwnershipMismatch));
        if !refused(self.verify(s))
            || !refused(self.verify_host_link_progress(s, &other, Progress::Intent))
            || !refused(self.verify_host_link_progress(s, &r.lab_changed_index(), Progress::Intent))
        {
            return Err(Error::OwnershipMismatch);
        }
        let n = s.native.as_ref().ok_or(Error::Interrupted)?;
        let c = n.continuation.as_ref().ok_or(Error::Interrupted)?;
        let mut changed = c.proposed.clone();
        changed.entries[0].exit_id.push_str("-foreign");
        if !refused(n.verify_owned_progress(&c.proposed, "host_link_birth", c.started_at))
            || !refused(n.verify_owned_progress(&c.proposed, c.phase, c.started_at - 0.001))
            || !refused(n.verify_owned_progress(&changed, c.phase, c.started_at))
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(6)
    }
}

#[cfg(test)]
impl Server {
    // Parsed copies exercise rejection only; none can mint original admission,
    // pair ownership, or an addition release capability.
    pub(crate) fn lab_host_schema_checks(&self) -> Result<usize> {
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        n.require_creator()?;
        let journal = n.transaction.shared.journal.borrow();
        let record = &journal.record;
        let validate = |r: &Record| {
            r.bind_anchor(
                &r.allocation,
                &r.primary_exit_id,
                r.base_network,
                r.owner_network,
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
        let mut count = 0;
        let original = serde_json::to_value(record).map_err(|_| Error::OwnershipMismatch)?;
        for path in [
            "0/namespace/ino",
            "0/host/ino",
            "0/declaration/0",
            "0/admission/2",
            "1/result/host/index",
            "1/result/peer/peer_index",
            "1/result/host/up",
            "2/namespace/ino",
            "2/admission/0",
            "2/deadline",
            "3/addition/1",
            "3/result/host/index",
            "3/result/peer/peer_index",
            "3/result/host/up",
            "3/verified_at",
            "3/birth/deadline",
        ] {
            let mut changed = original.clone();
            let pointer = format!("/entries/{selected}/preparation/host_link/{path}");
            let field = changed
                .pointer_mut(&pointer)
                .ok_or(Error::OwnershipMismatch)?;
            *field = if path == "3/verified_at" {
                original["entries"][selected]["preparation"]["host_link"][3]["deadline"].clone()
            } else if field.is_boolean() {
                serde_json::json!(!field.as_bool().unwrap())
            } else if let Some(v) = field.as_u64() {
                serde_json::json!(v ^ 1)
            } else {
                serde_json::json!(field.as_f64().ok_or(Error::OwnershipMismatch)? + 1.)
            };
            if serde_json::from_value::<Record>(changed).is_ok_and(|r| validate(&r).is_ok()) {
                return Err(Error::OwnershipMismatch);
            }
            count += 1;
        }
        for (path, value) in [
            ("3/kind", serde_json::json!("pair")),
            ("3/addition", serde_json::Value::Null),
            ("3/birth", serde_json::Value::Null),
            ("3/result", serde_json::Value::Null),
        ] {
            let mut changed = original.clone();
            *changed
                .pointer_mut(&format!("/entries/{selected}/preparation/host_link/{path}"))
                .ok_or(Error::OwnershipMismatch)? = value;
            if serde_json::from_value::<Record>(changed).is_ok_and(|r| validate(&r).is_ok()) {
                return Err(Error::OwnershipMismatch);
            }
            count += 1;
        }
        Ok(count)
    }
}
