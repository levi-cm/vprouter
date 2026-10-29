//! Distinct fresh TRANSPORT origin: serialized history is not a source permit.
use super::super::super::attachment::transport::Request;
use super::*;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct History {
    request: [u8; 32],
    pub(super) directory: Identity,
    pub(super) name: String,
    host: Identity,
    data: Identity,
    requested_at: f64,
    deadline: f64,
    pub(super) birth: Option<ValidationBirth>,
    pub(super) source: Option<Identity>,
    pub(super) verified_at: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) mount: Option<fresh_mount::History>,
}
impl History {
    pub(super) fn validate(
        &self,
        record: &Record,
        entry: &Entry,
        preparation: &super::History,
    ) -> Result<()> {
        let mounted = preparation.mount.as_ref().ok_or(Error::OwnershipMismatch)?;
        if self.request == [0; 32]
            || self.directory.ino == 0
            || self.host.ino == 0
            || self.data.ino == 0
            || self.name != entry.transport_name
            || record.base_network != Some(self.data)
            || entry.data != Some(self.data)
            || mounted
                .published_at
                .is_none_or(|at| !self.requested_at.is_finite() || self.requested_at < at)
            || self.deadline != self.requested_at + 2.
            || (self.mount.is_none() && entry.transport.is_some())
        {
            return Err(Error::OwnershipMismatch);
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
        match (self.source, self.verified_at) {
            (None, None) => (),
            (Some(source), Some(at))
                if source.ino > 0
                    && source != self.host
                    && source != self.data
                    && self.birth.as_ref().is_some_and(|b| {
                        at.is_finite() && at >= b.born_at && at < self.deadline
                    }) => {}
            _ => return Err(Error::OwnershipMismatch),
        }
        if let Some(mount) = &self.mount {
            mount.validate(entry, self)?;
        }
        Ok(())
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
        if self.creator != std::process::id()
            || self.history.request != request.digest()
            || self.history.directory != request.directory_identity()
            || self.history.name != request.name()
            || self.history.host != request.host_identity()
            || self.history.data != request.data_identity()
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
        if p.fresh_transport.as_ref() != Some(&self.history)
            || journal.record.owner_epoch.as_ref() != Some(&self.owner.record(&self.domains)?)
        {
            return Err(Error::OwnershipMismatch);
        }
        self.history.validate(&journal.record, entry, p)
    }
    pub(crate) fn prepare(&mut self, request: &Request) -> Result<()> {
        self.verify(request)?;
        self.lease
            .prepare_native_job(kernel::NativeJobKind::FreshTransport)
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
            || self.history.source.is_some()
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
        if p.fresh_transport.as_ref() != Some(&self.history)
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
    pub(super) fn fresh_transport_history(&self) -> Result<History> {
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
            .and_then(|p| p.fresh_transport.clone())
            .ok_or(Error::OwnershipMismatch)
    }
    fn queue_fresh_transport(&mut self, history: History, phase: &'static str) -> Result<()> {
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
            .fresh_transport = Some(history);
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
    pub(crate) fn fresh_transport_target(
        &self,
        data: &kernel::namespace_attachment::Mounted,
    ) -> Result<(OwnedFd, String)> {
        self.verify_attached(data)?;
        data.only_member_job(self)?;
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        let j = n.transaction.shared.journal.borrow();
        let e = j
            .record
            .entries
            .iter()
            .find(|e| e.exit_id == n.history.member)
            .ok_or(Error::OwnershipMismatch)?;
        if e.transport.is_some()
            || e.links.is_some()
            || e.producer.is_some()
            || e.attempt.is_some()
            || e.preparation
                .as_ref()
                .ok_or(Error::OwnershipMismatch)?
                .fresh_transport
                .is_some()
        {
            return Err(Error::OwnershipMismatch);
        }
        let directory =
            rustix::io::fcntl_dupfd_cloexec(&j.dir, 3).map_err(|_| Error::DescriptorDuplicate)?;
        Ok((directory, e.transport_name.clone()))
    }
    pub(crate) fn start_fresh_transport(&mut self, request: &Request) -> Result<()> {
        self.verify_attached(request.data())?;
        request.verify()?;
        request.data().only_member_job(self)?;
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        let j = n.transaction.shared.journal.borrow();
        let e = j
            .record
            .entries
            .iter()
            .find(|e| e.exit_id == n.history.member)
            .ok_or(Error::OwnershipMismatch)?;
        if Identity::of(&j.dir)? != request.directory_identity()
            || e.transport_name != request.name()
            || e.preparation
                .as_ref()
                .ok_or(Error::OwnershipMismatch)?
                .fresh_transport
                .is_some()
        {
            return Err(Error::OwnershipMismatch);
        }
        drop(j);
        n.queue_fresh_transport(
            History {
                request: request.digest(),
                directory: request.directory_identity(),
                name: request.name().into(),
                host: request.host_identity(),
                data: request.data_identity(),
                requested_at: request.requested_at(),
                deadline: request.deadline(),
                birth: None,
                source: None,
                verified_at: None,
                mount: None,
            },
            "transport_intent",
        )
    }
    pub(crate) fn poll_fresh_transport_intent(
        &mut self,
        request: &Request,
    ) -> Result<Option<Intent>> {
        request.verify()?;
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        if !n.poll_inspection("transport_intent")? {
            return Ok(None);
        }
        let intent = Intent {
            creator: n.creator,
            shared: n.transaction.shared.clone(),
            member: n.history.member.clone(),
            history: n.fresh_transport_history()?,
            owner: n.owner.clone(),
            domains: n.domains.clone(),
            lease: n.transaction.retain_allocation_lease()?,
        };
        intent.verify(request)?;
        Ok(Some(intent))
    }
    pub(crate) fn start_fresh_transport_birth(
        &mut self,
        child: &kernel::fresh_transport::Child,
    ) -> Result<()> {
        child.bind_service(self)?;
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        let mut h = n.fresh_transport_history()?;
        if h.birth.is_some() {
            return Err(Error::OwnershipMismatch);
        }
        h.birth = Some(child.birth()?);
        n.queue_fresh_transport(h, "transport_birth")
    }
    pub(crate) fn poll_fresh_transport_birth(
        &mut self,
        child: &kernel::fresh_transport::Child,
    ) -> Result<Option<Gate>> {
        child.bind_service(self)?;
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        if !n.poll_inspection("transport_birth")? {
            return Ok(None);
        }
        let gate = Gate {
            creator: n.creator,
            shared: n.transaction.shared.clone(),
            member: n.history.member.clone(),
            history: n.fresh_transport_history()?,
        };
        child.verify_gate(&gate)?;
        Ok(Some(gate))
    }
    pub(crate) fn start_fresh_transport_source(
        &mut self,
        source: &kernel::fresh_transport::Source,
    ) -> Result<()> {
        source.bind_service(self)?;
        source.verify()?;
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        let mut h = n.fresh_transport_history()?;
        if h.birth.as_ref() != Some(&source.birth()?) || h.source.is_some() {
            return Err(Error::OwnershipMismatch);
        }
        h.source = Some(source.identity()?);
        h.verified_at = Some(source.verified_at());
        n.queue_fresh_transport(h, "transport_source")
    }
    pub(crate) fn poll_fresh_transport_source(
        &mut self,
        source: &kernel::fresh_transport::Source,
    ) -> Result<bool> {
        source.bind_service(self)?;
        source.verify()?;
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        if !n.poll_inspection("transport_source")? {
            return Ok(false);
        }
        let h = n.fresh_transport_history()?;
        if h.birth.as_ref() != Some(&source.birth()?)
            || h.source != Some(source.identity()?)
            || h.verified_at != Some(source.verified_at())
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(true)
    }
}
