//! Typed durable gates for the three fixed original transport operations.
use super::super::super::attachment::provision::{Kind, Request};
use super::*;
use kernel::wireguard_role::{Child, PublicResult, Verified};
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct History {
    kind: Kind,
    request: [u8; 32],
    namespace: Identity,
    configuration: [u8; 32],
    requested_at: f64,
    deadline: f64,
    birth: Option<ValidationBirth>,
    result: Option<PublicResult>,
    verified_at: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    destination: Option<Identity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    movement_query: Option<[u8; 32]>,
}
impl History {
    pub(super) fn matches_assembly_receipt(&self, v: &Verified) -> Result<()> {
        self.matches_receipt(v)?;
        if self.verified_at != Some(v.historical_accepted_at()?) {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }

    pub(super) fn matches_receipt(&self, v: &Verified) -> Result<()> {
        v.require_acknowledged()?;
        if self.request != v.request().digest()
            || self.birth.as_ref() != Some(&v.birth()?)
            || self.result.as_ref() != Some(v.historical_result()?)
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
    pub(super) fn completed_move_at(&self) -> Result<f64> {
        if self.kind != Kind::Move || self.result.is_none() {
            return Err(Error::OwnershipMismatch);
        }
        self.verified_at.ok_or(Error::OwnershipMismatch)
    }
    pub(super) fn completed_query_at(&self) -> Result<f64> {
        if self.kind != Kind::Query || self.result.is_none() {
            return Err(Error::OwnershipMismatch);
        }
        self.verified_at.ok_or(Error::OwnershipMismatch)
    }
    pub(super) fn completed_data_sockets_at(&self) -> Result<f64> {
        if self.kind != Kind::DataSockets || self.result.is_none() {
            return Err(Error::OwnershipMismatch);
        }
        self.verified_at.ok_or(Error::OwnershipMismatch)
    }

    pub(super) fn validate(
        &self,
        entry: &Entry,
        preparation: &super::History,
        index: usize,
    ) -> Result<()> {
        let expected = [
            Kind::Sockets,
            Kind::Provision,
            Kind::Query,
            Kind::DataSockets,
            Kind::Move,
        ]
        .get(index)
        .ok_or(Error::OwnershipMismatch)?;
        if &self.kind != expected
            || self.request == [0; 32]
            || (if self.kind == Kind::DataSockets {
                entry.data
            } else {
                entry.transport
            }) != Some(self.namespace)
            || self.namespace.ino == 0
            || self.configuration != preparation.configuration
            || !self.requested_at.is_finite()
            || self.deadline != self.requested_at + 2.
            || preparation
                .fresh_transport
                .as_ref()
                .and_then(|h| h.mount.as_ref())
                .and_then(|m| m.published_at)
                .is_none_or(|at| self.requested_at < at)
        {
            return Err(Error::OwnershipMismatch);
        }
        if self.kind == Kind::Move {
            let (query, start, end, verified) = preparation
                .movement_query
                .as_ref()
                .ok_or(Error::OwnershipMismatch)?
                .completed_movement()?;
            if self.destination != entry.data
                || self.destination == Some(self.namespace)
                || self.movement_query != Some(query)
                || self.requested_at != start
                || self.deadline != end
                || self.birth.as_ref().is_some_and(|b| b.born_at < verified)
            {
                return Err(Error::OwnershipMismatch);
            }
        } else if self.destination.is_some() || self.movement_query.is_some() {
            return Err(Error::OwnershipMismatch);
        }
        if index > 0 {
            let previous = &preparation.wireguard[index - 1];
            if previous.result.is_none()
                || previous.verified_at.is_none_or(|at| self.requested_at < at)
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
                if r.namespace != self.destination.unwrap_or(self.namespace)
                    || !at.is_finite()
                    || at >= self.deadline
                    || self.birth.as_ref().is_none_or(|b| at < b.born_at)
                    || matches!(self.kind, Kind::Sockets | Kind::DataSockets)
                        != (r.link.is_none() && r.wireguard.is_none())
                    || (!matches!(self.kind, Kind::Sockets | Kind::DataSockets)
                        && (r.link.is_none() || r.wireguard.is_none()))
                {
                    return Err(Error::OwnershipMismatch);
                }
            }
            _ => return Err(Error::OwnershipMismatch),
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
            || self.history.namespace != previous.history.namespace
            || self.history.configuration != previous.history.configuration
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
    pub(crate) fn verify_move_source(&self, previous: &Self, target: bool) -> Result<()> {
        if self.creator != std::process::id()
            || previous.creator != self.creator
            || !Rc::ptr_eq(&self.shared, &previous.shared)
            || !Rc::ptr_eq(&self.owner, &previous.owner)
            || self.member != previous.member
            || self.index != 4
            || self.history.kind != Kind::Move
            || previous.index != if target { 3 } else { 2 }
            || previous.history.kind
                != if target {
                    Kind::DataSockets
                } else {
                    Kind::Query
                }
            || self.history.configuration != previous.history.configuration
            || Some(previous.history.namespace)
                != if target {
                    self.history.destination
                } else {
                    Some(self.history.namespace)
                }
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
    pub(crate) fn verify(&self, r: &Request) -> Result<()> {
        r.verify()?;
        if self.creator != std::process::id()
            || self.member != r.member()
            || self.history.request != r.digest()
            || self.history.kind != r.kind()
            || self.history.namespace != r.source_identity()
            || self.history.configuration != r.configuration_digest()
            || self.history.destination != (r.kind() == Kind::Move).then(|| r.target_identity())
            || self.history.movement_query != r.movement_digest()
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
        if p.wireguard.get(self.index) != Some(&self.history)
            || p.inputs != r.identities()
            || j.record.owner_epoch.as_ref() != Some(&self.owner.record(&self.domains)?)
        {
            return Err(Error::OwnershipMismatch);
        }
        self.history.validate(e, p, self.index)
    }
    pub(crate) fn prepare(&mut self, r: &Request) -> Result<()> {
        self.verify(r)?;
        self.lease
            .prepare_native_job(kernel::NativeJobKind::WireguardSecret)
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
        if p.wireguard.get(self.index) != Some(&self.history)
            || j.record.owner_epoch.as_ref() != Some(&i.owner.record(&i.domains)?)
        {
            return Err(Error::OwnershipMismatch);
        }
        self.history.validate(e, p, self.index)?;
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
    history: History,
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
        if p.wireguard.get(self.index) != Some(&self.history) {
            return Err(Error::OwnershipMismatch);
        }
        self.history.validate(e, p, self.index)
    }
}
impl Native {
    fn wireguard_history(&self) -> Result<(usize, History)> {
        self.require_creator()?;
        let j = self.transaction.shared.journal.borrow();
        let list = &j
            .record
            .entries
            .iter()
            .find(|e| e.exit_id == self.history.member)
            .and_then(|e| e.preparation.as_ref())
            .ok_or(Error::OwnershipMismatch)?
            .wireguard;
        let index = list.len().checked_sub(1).ok_or(Error::OwnershipMismatch)?;
        Ok((index, list[index].clone()))
    }
    fn queue_wireguard(
        &mut self,
        h: History,
        index: usize,
        phase: &'static str,
        append: bool,
    ) -> Result<()> {
        self.require_creator()?;
        kernel::owner_admission_permitted()?;
        original_frame(h.requested_at, vprouter_core::health::boot_seconds())?;
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
        let list = &mut proposed
            .entries
            .iter_mut()
            .find(|e| e.exit_id == self.history.member)
            .and_then(|e| e.preparation.as_mut())
            .ok_or(Error::OwnershipMismatch)?
            .wireguard;
        let started_at = h.requested_at;
        if append {
            if list.len() != index || index >= 5 {
                return Err(Error::OwnershipMismatch);
            }
            list.push(h);
        } else {
            if list.len() != index + 1 {
                return Err(Error::OwnershipMismatch);
            }
            list[index] = h;
        }
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
    pub(crate) fn start_wireguard(&mut self, r: &Request, previous: &[Verified]) -> Result<()> {
        self.verify_transport_mounted(r.mounted())?;
        r.verify()?;
        r.verify_movement_service(self)?;
        for v in previous {
            v.bind_service(self)?;
            v.require_acknowledged()?;
        }
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        let shared = &n.transaction.shared;
        let j = shared.journal.borrow();
        let e = j
            .record
            .entries
            .iter()
            .find(|e| e.exit_id == n.history.member)
            .ok_or(Error::OwnershipMismatch)?;
        let p = e.preparation.as_ref().ok_or(Error::OwnershipMismatch)?;
        let index = p.wireguard.len();
        if r.member() != n.history.member
            || p.configuration != r.configuration_digest()
            || p.inputs != r.identities()
            || previous.len() != index
            || [
                Kind::Sockets,
                Kind::Provision,
                Kind::Query,
                Kind::DataSockets,
                Kind::Move,
            ]
            .get(index)
                != Some(&r.kind())
        {
            return Err(Error::OwnershipMismatch);
        }
        for (h, v) in p.wireguard.iter().zip(previous) {
            if h.request != v.request().digest()
                || h.birth.as_ref() != Some(&v.birth()?)
                || h.result.as_ref() != Some(v.historical_result()?)
            {
                return Err(Error::OwnershipMismatch);
            }
        }
        drop(j);
        let mut jobs = shared.native_jobs.borrow_mut();
        jobs.prune()?;
        let mut count = 0;
        for (member, receipt) in jobs.pending.values() {
            if member == r.member() {
                let mut known = r.mounted().matches_job(receipt)?
                    || r.mounted().request().original().matches_job(receipt)?
                    || r.mounted()
                        .request()
                        .original()
                        .request()
                        .data()
                        .matches_job(receipt)?;
                for v in previous {
                    known |= v.matches_job(receipt)?;
                }
                if !known {
                    return Err(Error::OwnershipMismatch);
                }
                count += 1;
            }
        }
        if count != 3 + index {
            return Err(Error::OwnershipMismatch);
        }
        drop(jobs);
        n.queue_wireguard(
            History {
                kind: r.kind(),
                request: r.digest(),
                namespace: r.source_identity(),
                configuration: r.configuration_digest(),
                requested_at: r.requested_at(),
                deadline: r.deadline(),
                birth: None,
                result: None,
                verified_at: None,
                destination: (r.kind() == Kind::Move).then(|| r.target_identity()),
                movement_query: r.movement_digest(),
            },
            index,
            "wireguard_intent",
            true,
        )
    }
    pub(crate) fn poll_wireguard_intent(&mut self, r: &Request) -> Result<Option<Intent>> {
        r.verify()?;
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        if !n.poll_inspection("wireguard_intent")? {
            return Ok(None);
        }
        let (index, history) = n.wireguard_history()?;
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
    pub(crate) fn start_wireguard_birth(&mut self, c: &Child) -> Result<()> {
        c.bind_service(self)?;
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        let (index, mut h) = n.wireguard_history()?;
        if h.birth.is_some() {
            return Err(Error::OwnershipMismatch);
        }
        h.birth = Some(c.birth()?);
        n.queue_wireguard(h, index, "wireguard_birth", false)
    }
    pub(crate) fn poll_wireguard_birth(&mut self, c: &Child) -> Result<Option<Gate>> {
        c.bind_service(self)?;
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        if !n.poll_inspection("wireguard_birth")? {
            return Ok(None);
        }
        let (index, history) = n.wireguard_history()?;
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
    pub(crate) fn start_wireguard_result(&mut self, v: &Verified) -> Result<()> {
        v.bind_service(self)?;
        v.verify()?;
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        let (index, mut h) = n.wireguard_history()?;
        if h.request != v.request().digest()
            || h.birth.as_ref() != Some(&v.birth()?)
            || h.result.is_some()
        {
            return Err(Error::OwnershipMismatch);
        }
        h.result = Some(v.result()?.clone());
        h.verified_at = Some(v.accepted_at()?);
        n.queue_wireguard(h, index, "wireguard_result", false)
    }
    pub(crate) fn poll_wireguard_result(&mut self, v: &Verified) -> Result<Option<Receipt>> {
        #[cfg(test)]
        let span = super::super::super::attachment::movement::trace::Span::new(
            "result_writer",
            "binding_verify",
        );
        v.bind_service(self)?;
        v.verify()?;
        #[cfg(test)]
        span.finish();
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        #[cfg(test)]
        let span = super::super::super::attachment::movement::trace::Span::new(
            "result_writer",
            "poll_ack_reap",
        );
        let done = n.poll_inspection("wireguard_result")?;
        #[cfg(test)]
        span.finish();
        if !done {
            return Ok(None);
        }
        let (index, history) = n.wireguard_history()?;
        let r = Receipt {
            creator: n.creator,
            shared: n.transaction.shared.clone(),
            member: n.history.member.clone(),
            history,
            index,
        };
        #[cfg(test)]
        let span = super::super::super::attachment::movement::trace::Span::new(
            "result_writer",
            "receipt_verify",
        );
        r.verify(v)?;
        #[cfg(test)]
        span.finish();
        Ok(Some(r))
    }
}
