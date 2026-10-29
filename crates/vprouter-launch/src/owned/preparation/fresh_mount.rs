//! Fresh source mount is a separate operation with immutable creation history.
use super::super::super::attachment::transport::MountRequest as Request;
pub(crate) use super::mount::Placeholder;
use super::*;
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct History {
    request: [u8; 32],
    source: Identity,
    directory: Identity,
    name: String,
    requested_at: f64,
    deadline: f64,
    birth: Option<ValidationBirth>,
    placeholder: Option<Placeholder>,
    mounted_at: Option<f64>,
    pub(super) published_at: Option<f64>,
}
impl History {
    pub(super) fn validate(
        &self,
        entry: &Entry,
        creation: &fresh_transport::History,
    ) -> Result<()> {
        if self.request == [0; 32]
            || creation.source != Some(self.source)
            || self.directory != creation.directory
            || self.name != creation.name
            || creation
                .verified_at
                .is_none_or(|at| !self.requested_at.is_finite() || self.requested_at < at)
            || self.deadline != self.requested_at + 2.
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
        if let Some(p) = &self.placeholder
            && (self.birth.is_none()
                || p.identity.ino == 0
                || p.identity.dev != self.directory.dev
                || p.mode != 0o100600)
        {
            return Err(Error::OwnershipMismatch);
        }
        if let Some(at) = self.mounted_at
            && (self.placeholder.is_none()
                || !at.is_finite()
                || at >= self.deadline
                || self.birth.as_ref().is_none_or(|b| at < b.born_at))
        {
            return Err(Error::OwnershipMismatch);
        }
        match self.published_at {
            Some(at)
                if self
                    .mounted_at
                    .is_some_and(|m| at.is_finite() && at >= m && at < self.deadline)
                    && entry.transport == Some(self.source) => {}
            None if entry.transport.is_none() => (),
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
    pub(crate) fn verify(&self, r: &Request) -> Result<()> {
        r.verify_native()?;
        if self.creator != std::process::id()
            || self.history.request != r.digest()
            || self.history.source != r.source_identity()
            || self.history.directory != r.directory_identity()
            || self.history.name != r.name()
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
        let h = e
            .preparation
            .as_ref()
            .and_then(|p| p.fresh_transport.as_ref())
            .ok_or(Error::OwnershipMismatch)?;
        if h.mount.as_ref() != Some(&self.history)
            || j.record.owner_epoch.as_ref() != Some(&self.owner.record(&self.domains)?)
        {
            return Err(Error::OwnershipMismatch);
        }
        self.history.validate(e, h)
    }
    pub(crate) fn prepare(&mut self, r: &Request) -> Result<()> {
        self.verify(r)?;
        self.lease
            .prepare_native_job(kernel::NativeJobKind::FreshTransportMount)
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
    pub(crate) fn verify(
        &self,
        intent: &Intent,
        birth: &ValidationBirth,
        placeholder: Option<&Placeholder>,
    ) -> Result<()> {
        if self.creator != std::process::id()
            || self.creator != intent.creator
            || !Rc::ptr_eq(&self.shared, &intent.shared)
            || self.member != intent.member
            || self.history.request != intent.history.request
            || self.history.birth.as_ref() != Some(birth)
            || self.history.placeholder.as_ref() != placeholder
            || self.history.mounted_at.is_some()
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
        let h = e
            .preparation
            .as_ref()
            .and_then(|p| p.fresh_transport.as_ref())
            .ok_or(Error::OwnershipMismatch)?;
        if h.mount.as_ref() != Some(&self.history)
            || j.record.owner_epoch.as_ref() != Some(&intent.owner.record(&intent.domains)?)
        {
            return Err(Error::OwnershipMismatch);
        }
        self.history.validate(e, h)?;
        original_frame(
            self.history.requested_at,
            vprouter_core::health::boot_seconds(),
        )?;
        kernel::owner_admission_permitted()
    }
}
impl Native {
    fn fresh_mount_history(&self) -> Result<History> {
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
            .and_then(|p| p.fresh_transport.as_ref())
            .and_then(|h| h.mount.clone())
            .ok_or(Error::OwnershipMismatch)
    }
    fn queue_fresh_mount(
        &mut self,
        h: History,
        phase: &'static str,
        publication: Option<Rc<kernel::fresh_transport_mount::Mounted>>,
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
        let e = proposed
            .entries
            .iter_mut()
            .find(|e| e.exit_id == self.history.member)
            .ok_or(Error::OwnershipMismatch)?;
        if let Some(m) = &publication {
            m.verify_current()?;
            if e.transport.is_some()
                || m.request().digest() != h.request
                || h.published_at.is_none()
            {
                return Err(Error::OwnershipMismatch);
            }
            e.transport = Some(h.source);
        }
        let started_at = h.requested_at;
        e.preparation
            .as_mut()
            .and_then(|p| p.fresh_transport.as_mut())
            .ok_or(Error::OwnershipMismatch)?
            .mount = Some(h);
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
            transport_publication: publication,
        });
        self.queued_at = Some(vprouter_core::health::boot_seconds());
        Ok(())
    }
}
impl Server {
    pub(crate) fn verify_transport_mounted(
        &self,
        m: &kernel::fresh_transport_mount::Mounted,
    ) -> Result<()> {
        self.verify_preparation_idle()?;
        self.verify_transport_custody(m)
    }
    pub(super) fn verify_transport_custody(
        &self,
        m: &kernel::fresh_transport_mount::Mounted,
    ) -> Result<()> {
        m.bind_service(self)?;
        m.verify_retained()?;
        self.verify_attached_custody(m.request().original().request().data())?;
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        let h = n.fresh_mount_history()?;
        let j = n.transaction.shared.journal.borrow();
        let e = j
            .record
            .entries
            .iter()
            .find(|e| e.exit_id == n.history.member)
            .ok_or(Error::OwnershipMismatch)?;
        if h.published_at.is_none()
            || h.request != m.request().digest()
            || h.birth.as_ref() != Some(&m.birth()?)
            || h.placeholder.as_ref() != Some(&m.placeholder()?)
            || e.transport != Some(m.request().source_identity())
            || e.links.is_some()
            || (e.producer.is_some() && !e.preparation_bound_producer())
            || e.attempt.is_some()
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
    pub(crate) fn verify_transport_source(
        &self,
        source: &kernel::fresh_transport::Source,
    ) -> Result<()> {
        source.bind_service(self)?;
        source.verify_retained()?;
        self.verify_attached(source.request().data())?;
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        let h = n.fresh_transport_history()?;
        if h.birth.as_ref() != Some(&source.birth()?)
            || h.source != Some(source.identity()?)
            || h.verified_at != Some(source.verified_at())
            || h.mount.is_some()
        {
            return Err(Error::OwnershipMismatch);
        }
        let mut jobs = n.transaction.shared.native_jobs.borrow_mut();
        jobs.prune()?;
        let mut exact = 0;
        for (member, receipt) in jobs.pending.values() {
            if member == &n.history.member {
                if !source.matches_job(receipt)? && !source.request().data().matches_job(receipt)? {
                    return Err(Error::OwnershipMismatch);
                }
                exact += 1;
            }
        }
        if exact != 2 {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
    pub(crate) fn start_fresh_mount(&mut self, r: &Request) -> Result<()> {
        self.verify_transport_source(r.original())?;
        r.verify_native()?;
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        n.queue_fresh_mount(
            History {
                request: r.digest(),
                source: r.source_identity(),
                directory: r.directory_identity(),
                name: r.name().into(),
                requested_at: r.requested_at(),
                deadline: r.deadline(),
                birth: None,
                placeholder: None,
                mounted_at: None,
                published_at: None,
            },
            "transport_mount_intent",
            None,
        )
    }
    pub(crate) fn poll_fresh_mount_intent(&mut self, r: &Request) -> Result<Option<Intent>> {
        r.verify_native()?;
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        if !n.poll_inspection("transport_mount_intent")? {
            return Ok(None);
        }
        let intent = Intent {
            creator: n.creator,
            shared: n.transaction.shared.clone(),
            member: n.history.member.clone(),
            history: n.fresh_mount_history()?,
            owner: n.owner.clone(),
            domains: n.domains.clone(),
            lease: n.transaction.retain_allocation_lease()?,
        };
        intent.verify(r)?;
        Ok(Some(intent))
    }
    pub(crate) fn start_fresh_mount_birth(
        &mut self,
        child: &kernel::fresh_transport_mount::Child,
    ) -> Result<()> {
        child.bind_service(self)?;
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        let mut h = n.fresh_mount_history()?;
        if h.birth.is_some() {
            return Err(Error::OwnershipMismatch);
        }
        h.birth = Some(child.birth()?);
        n.queue_fresh_mount(h, "transport_mount_birth", None)
    }
    pub(crate) fn poll_fresh_mount_gate(
        &mut self,
        child: &kernel::fresh_transport_mount::Child,
        placeholder: bool,
    ) -> Result<Option<Gate>> {
        child.bind_service(self)?;
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        if !n.poll_inspection(if placeholder {
            "transport_mount_placeholder"
        } else {
            "transport_mount_birth"
        })? {
            return Ok(None);
        }
        let gate = Gate {
            creator: n.creator,
            shared: n.transaction.shared.clone(),
            member: n.history.member.clone(),
            history: n.fresh_mount_history()?,
        };
        child.verify_gate(&gate, placeholder)?;
        Ok(Some(gate))
    }
    pub(crate) fn start_fresh_mount_placeholder(
        &mut self,
        child: &kernel::fresh_transport_mount::Child,
    ) -> Result<()> {
        child.bind_service(self)?;
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        let mut h = n.fresh_mount_history()?;
        if h.birth.as_ref() != Some(&child.birth()?) || h.placeholder.is_some() {
            return Err(Error::OwnershipMismatch);
        }
        h.placeholder = Some(child.placeholder()?);
        n.queue_fresh_mount(h, "transport_mount_placeholder", None)
    }
    pub(crate) fn start_fresh_mounted(
        &mut self,
        m: Rc<kernel::fresh_transport_mount::Mounted>,
    ) -> Result<()> {
        m.bind_service(self)?;
        m.verify_current()?;
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        let mut h = n.fresh_mount_history()?;
        if h.birth.as_ref() != Some(&m.birth()?)
            || h.placeholder.as_ref() != Some(&m.placeholder()?)
            || h.mounted_at.is_some()
        {
            return Err(Error::OwnershipMismatch);
        }
        h.mounted_at = Some(m.verified_at());
        h.published_at = Some(vprouter_core::health::boot_seconds());
        n.queue_fresh_mount(h, "transport_mount_publication", Some(m))
    }
    pub(crate) fn poll_fresh_mounted(
        &mut self,
        m: &kernel::fresh_transport_mount::Mounted,
    ) -> Result<bool> {
        m.bind_service(self)?;
        m.verify_current()?;
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        if !n.poll_inspection("transport_mount_publication")? {
            return Ok(false);
        }
        let h = n.fresh_mount_history()?;
        let j = n.transaction.shared.journal.borrow();
        let e = j
            .record
            .entries
            .iter()
            .find(|e| e.exit_id == n.history.member)
            .ok_or(Error::OwnershipMismatch)?;
        if h.published_at.is_none()
            || h.request != m.request().digest()
            || e.transport != Some(m.request().source_identity())
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(true)
    }
}
