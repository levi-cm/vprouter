//! Owner-only attachment history and constructor-origin mount permits.
use super::super::super::attachment::{Origin, mount::Request};
use super::*;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Placeholder {
    pub(crate) identity: Identity,
    pub(crate) mode: u32,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct History {
    request: [u8; 32],
    origin: Origin,
    directory: Identity,
    name: String,
    source: Identity,
    requested_at: f64,
    deadline: f64,
    birth: Option<ValidationBirth>,
    placeholder: Option<Placeholder>,
    mounted_at: Option<f64>,
    pub(super) query: Option<inspection::History>,
    pub(super) published_at: Option<f64>,
}
impl History {
    pub(super) fn validate(
        &self,
        record: &Record,
        entry: &Entry,
        preparation: &super::History,
    ) -> Result<()> {
        self.origin.validate()?;
        let inspection = preparation
            .inspection
            .as_ref()
            .ok_or(Error::OwnershipMismatch)?;
        let (_, inspected_at) = inspection.completed_recheck()?;
        if self.request == [0; 32]
            || self.directory.ino == 0
            || self.source.ino == 0
            || self.name != entry.data_name
            || entry.exit_id != record.primary_exit_id
            || !self.requested_at.is_finite()
            || self.requested_at < inspected_at
            || self.deadline != self.requested_at + 2.
            || !matches!(&self.origin, Origin::ExistingAdmitted { network, public_result, process_start, .. }
                if *network == self.source && *process_start > 0 && preparation.result.as_ref().is_some_and(|r| r.report == *public_result))
        {
            return Err(Error::OwnershipMismatch);
        }
        if let Some(birth) = &self.birth
            && (birth.pid <= 1
                || birth.start == 0
                || !birth.born_at.is_finite()
                || birth.born_at < self.requested_at
                || birth.born_at >= self.deadline
                || birth.deadline != self.deadline)
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
                || at < self.birth.as_ref().ok_or(Error::OwnershipMismatch)?.born_at
                || at >= self.deadline)
        {
            return Err(Error::OwnershipMismatch);
        }
        if let Some(query) = &self.query {
            if self.mounted_at.is_none() {
                return Err(Error::OwnershipMismatch);
            }
            query.validate(preparation)?;
        }
        if let Some(at) = self.published_at {
            let (_, verified) = self
                .query
                .as_ref()
                .ok_or(Error::OwnershipMismatch)?
                .completed_mount_query()?;
            if !at.is_finite()
                || at < verified
                || at >= self.deadline
                || record.base_network != Some(self.source)
                || entry.data != Some(self.source)
            {
                return Err(Error::OwnershipMismatch);
            }
        } else if record.base_network.is_some() || entry.data.is_some() {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
    pub(super) fn query_binding(&self) -> ([u8; 32], f64, f64, Option<f64>) {
        (
            self.request,
            self.requested_at,
            self.deadline,
            self.mounted_at,
        )
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
    pub(crate) fn only_member_job(&self, server: &Server) -> Result<()> {
        self.same_service(server)?;
        let ticket = self
            .lease
            .native_job
            .as_ref()
            .ok_or(Error::OwnershipMismatch)?;
        let mut jobs = self.shared.native_jobs.borrow_mut();
        jobs.prune()?;
        let mut exact = 0;
        for (member, receipt) in jobs.pending.values() {
            if member == &self.member {
                if !receipt.matches_reaped(ticket)? {
                    return Err(Error::OwnershipMismatch);
                }
                exact += 1;
            }
        }
        if exact != 1 {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
    pub(crate) fn verify(&self, request: &Request) -> Result<()> {
        request.verify_native()?;
        if self.creator != std::process::id()
            || self.history.request != request.digest()
            || self.history.source != request.source_identity()
            || self.history.directory != request.directory_identity()
            || self.history.name != request.name()
            || self.history.requested_at != request.requested_at()
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
        let preparation = entry.preparation.as_ref().ok_or(Error::OwnershipMismatch)?;
        if preparation.mount.as_ref() != Some(&self.history)
            || self.history.birth.is_some()
            || journal.record.owner_epoch.as_ref() != Some(&self.owner.record(&self.domains)?)
        {
            return Err(Error::OwnershipMismatch);
        }
        self.history.validate(&journal.record, entry, preparation)
    }
    pub(crate) fn prepare(&mut self, request: &Request) -> Result<()> {
        self.verify(request)?;
        self.lease
            .prepare_native_job(kernel::NativeJobKind::NamespaceAttachment)
    }
    pub(crate) fn lease(&mut self) -> &mut MutatorLease {
        &mut self.lease
    }
    pub(crate) fn same_service(&self, server: &Server) -> Result<()> {
        let native = server.native.as_ref().ok_or(Error::Interrupted)?;
        native.require_creator()?;
        if self.creator != native.creator
            || !Rc::ptr_eq(&self.shared, &native.transaction.shared)
            || self.member != native.history.member
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
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
        let journal = self.shared.journal.borrow();
        let entry = journal
            .record
            .entries
            .iter()
            .find(|e| e.exit_id == self.member)
            .ok_or(Error::OwnershipMismatch)?;
        let preparation = entry.preparation.as_ref().ok_or(Error::OwnershipMismatch)?;
        if preparation.mount.as_ref() != Some(&self.history) {
            return Err(Error::OwnershipMismatch);
        }
        self.history.validate(&journal.record, entry, preparation)?;
        original_frame(
            self.history.requested_at,
            vprouter_core::health::boot_seconds(),
        )
    }
}
impl Native {
    fn mount_history(&self) -> Result<History> {
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
            .and_then(|p| p.mount.clone())
            .ok_or(Error::OwnershipMismatch)
    }
    fn queue_mount(
        &mut self,
        history: History,
        phase: &'static str,
        publication: Option<Rc<kernel::namespace_attachment::Mounted>>,
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
        let journal = shared.journal.borrow();
        let before = record_digest(&encode_record(&journal.record)?);
        let mut proposed = journal.record.clone();
        if let Some(mounted) = &publication {
            mounted.verify_current()?;
            if journal.record.base_network.is_some()
                || mounted.request().digest() != history.request
                || history.published_at.is_none()
            {
                return Err(Error::OwnershipMismatch);
            }
            proposed.base_network = Some(mounted.request().source_identity());
        }
        let entry = proposed
            .entries
            .iter_mut()
            .find(|e| e.exit_id == self.history.member)
            .ok_or(Error::OwnershipMismatch)?;
        if publication.is_some() {
            if entry.data.is_some() {
                return Err(Error::OwnershipMismatch);
            }
            entry.data = Some(history.source);
        }
        let started_at = history.requested_at;
        entry
            .preparation
            .as_mut()
            .ok_or(Error::OwnershipMismatch)?
            .mount = Some(history);
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
            publication,
            transport_publication: None,
        });
        self.queued_at = Some(vprouter_core::health::boot_seconds());
        Ok(())
    }
}
impl Server {
    /// Requires the original mounted capability and SAME retained service, not
    /// merely the serialized publication record.
    pub(crate) fn verify_attached(
        &self,
        mounted: &kernel::namespace_attachment::Mounted,
    ) -> Result<()> {
        self.verify_preparation_idle()?;
        self.verify_attached_custody(mounted)
    }
    pub(super) fn verify_preparation_idle(&self) -> Result<()> {
        let native = self.native.as_ref().ok_or(Error::Interrupted)?;
        native.require_creator()?;
        if native.pending.is_some()
            || native.queued_at.is_some()
            || native.continuation.is_some()
            || native.transaction.shared.pending.borrow().is_some()
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
    // Original resource/canonical proof only. This does not admit work: callers
    // must additionally require idle state or an exact typed ongoing mutation.
    pub(super) fn verify_attached_custody(
        &self,
        mounted: &kernel::namespace_attachment::Mounted,
    ) -> Result<()> {
        mounted.bind_service(self)?;
        mounted.verify_retained()?;
        let native = self.native.as_ref().ok_or(Error::Interrupted)?;
        native.require_creator()?;
        let shared = &native.transaction.shared;
        if native.failure.is_some()
            || shared.fenced.get()
            || !shared.services.borrow().contains(&native.history.member)
        {
            return Err(Error::OwnershipMismatch);
        }
        let journal = shared.journal.borrow();
        let entry = journal
            .record
            .entries
            .iter()
            .find(|e| e.exit_id == native.history.member)
            .ok_or(Error::OwnershipMismatch)?;
        let preparation = entry.preparation.as_ref().ok_or(Error::OwnershipMismatch)?;
        let history = preparation.mount.as_ref().ok_or(Error::OwnershipMismatch)?;
        history.validate(&journal.record, entry, preparation)?;
        if history.published_at.is_none()
            || history.request != mounted.request().digest()
            || history.birth.as_ref() != Some(&mounted.birth()?)
            || journal.record.base_network != Some(mounted.request().source_identity())
            || entry.data != journal.record.base_network
            || journal.record.owner_epoch.as_ref() != Some(&native.owner.record(&native.domains)?)
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
    pub(crate) fn mount_target(&self, spec: &LaunchSpec) -> Result<(OwnedFd, String)> {
        let native = self.native.as_ref().ok_or(Error::Interrupted)?;
        native.require_creator()?;
        let journal = native.transaction.shared.journal.borrow();
        if journal.record.primary_exit_id != spec.exit.exit_id
            || journal.record.base_network.is_some()
            || !same_allocation(&journal.record.allocation, &spec.allocation)?
        {
            return Err(Error::OwnershipMismatch);
        }
        let entry = journal
            .record
            .entries
            .iter()
            .find(|e| e.exit_id == spec.exit.exit_id)
            .ok_or(Error::OwnershipMismatch)?;
        if entry.data.is_some() || entry.transport.is_some() || entry.phase != Phase::Creating {
            return Err(Error::OwnershipMismatch);
        }
        let directory = rustix::io::fcntl_dupfd_cloexec(&journal.dir, 3)
            .map_err(|_| Error::DescriptorDuplicate)?;
        Ok((directory, entry.data_name.clone()))
    }
    pub(crate) fn start_mount(&mut self, request: &Request) -> Result<()> {
        request.binding().verify_initial(self, request.spec())?;
        request.verify_native()?;
        let native = self.native.as_mut().ok_or(Error::Interrupted)?;
        let journal = native.transaction.shared.journal.borrow();
        let p = journal
            .record
            .entries
            .iter()
            .find(|e| e.exit_id == native.history.member)
            .and_then(|e| e.preparation.as_ref())
            .ok_or(Error::OwnershipMismatch)?;
        if p.mount.is_some() || Identity::of(&journal.dir)? != request.directory_identity() {
            return Err(Error::OwnershipMismatch);
        }
        p.inspection
            .as_ref()
            .ok_or(Error::OwnershipMismatch)?
            .completed_recheck()?;
        drop(journal);
        native.queue_mount(
            History {
                request: request.digest(),
                origin: request.origin().clone(),
                directory: request.directory_identity(),
                name: request.name().into(),
                source: request.source_identity(),
                requested_at: request.requested_at(),
                deadline: request.deadline(),
                birth: None,
                placeholder: None,
                mounted_at: None,
                query: None,
                published_at: None,
            },
            "attachment_intent",
            None,
        )
    }
    pub(crate) fn poll_mount_intent(&mut self, request: &Request) -> Result<Option<Intent>> {
        request.check()?;
        let native = self.native.as_mut().ok_or(Error::Interrupted)?;
        if !native.poll_inspection("attachment_intent")? {
            return Ok(None);
        }
        let value = Intent {
            creator: native.creator,
            shared: native.transaction.shared.clone(),
            member: native.history.member.clone(),
            history: native.mount_history()?,
            owner: native.owner.clone(),
            domains: native.domains.clone(),
            lease: native.transaction.retain_allocation_lease()?,
        };
        value.verify(request)?;
        Ok(Some(value))
    }
    pub(crate) fn start_mount_birth(
        &mut self,
        child: &kernel::namespace_attachment::Child,
    ) -> Result<()> {
        child.bind_service(self)?;
        let native = self.native.as_mut().ok_or(Error::Interrupted)?;
        let mut history = native.mount_history()?;
        if history.birth.is_some() {
            return Err(Error::OwnershipMismatch);
        }
        history.birth = Some(child.birth()?);
        native.queue_mount(history, "attachment_birth", None)
    }
    pub(crate) fn poll_mount_gate(
        &mut self,
        child: &kernel::namespace_attachment::Child,
        placeholder: bool,
    ) -> Result<Option<Gate>> {
        child.bind_service(self)?;
        let native = self.native.as_mut().ok_or(Error::Interrupted)?;
        if !native.poll_inspection(if placeholder {
            "attachment_placeholder"
        } else {
            "attachment_birth"
        })? {
            return Ok(None);
        }
        let history = native.mount_history()?;
        let gate = Gate {
            creator: native.creator,
            shared: native.transaction.shared.clone(),
            member: native.history.member.clone(),
            history,
        };
        child.verify_gate(&gate, placeholder)?;
        Ok(Some(gate))
    }
    pub(crate) fn start_mount_placeholder(
        &mut self,
        child: &kernel::namespace_attachment::Child,
    ) -> Result<()> {
        child.bind_service(self)?;
        let native = self.native.as_mut().ok_or(Error::Interrupted)?;
        let mut history = native.mount_history()?;
        if history.birth.as_ref() != Some(&child.birth()?) || history.placeholder.is_some() {
            return Err(Error::OwnershipMismatch);
        }
        history.placeholder = Some(child.placeholder()?);
        native.queue_mount(history, "attachment_placeholder", None)
    }
    pub(crate) fn start_mounted(
        &mut self,
        mounted: &kernel::namespace_attachment::Mounted,
    ) -> Result<()> {
        mounted.bind_service(self)?;
        mounted.verify_current()?;
        let native = self.native.as_mut().ok_or(Error::Interrupted)?;
        let mut history = native.mount_history()?;
        if history.birth.as_ref() != Some(&mounted.birth()?)
            || history.placeholder.as_ref() != Some(&mounted.placeholder()?)
            || history.mounted_at.is_some()
        {
            return Err(Error::OwnershipMismatch);
        }
        history.mounted_at = Some(mounted.verified_at());
        native.queue_mount(history, "attachment_mounted", None)
    }
    pub(crate) fn poll_mounted(
        &mut self,
        mounted: &kernel::namespace_attachment::Mounted,
    ) -> Result<bool> {
        mounted.bind_service(self)?;
        mounted.verify_current()?;
        self.native
            .as_mut()
            .ok_or(Error::Interrupted)?
            .poll_inspection("attachment_mounted")
    }
    pub(crate) fn start_primary_publication(
        &mut self,
        mounted: Rc<kernel::namespace_attachment::Mounted>,
        query: &kernel::docker_query::Accepted,
    ) -> Result<()> {
        mounted.bind_service(self)?;
        mounted.verify_current()?;
        query.require()?;
        if !query.request().matches_mount(&mounted)? {
            return Err(Error::OwnershipMismatch);
        }
        let native = self.native.as_mut().ok_or(Error::Interrupted)?;
        let mut history = native.mount_history()?;
        let (facts, _) = history
            .query
            .as_ref()
            .ok_or(Error::OwnershipMismatch)?
            .completed_mount_query()?;
        if &facts != query.facts()
            || history.published_at.is_some()
            || history.request != mounted.request().digest()
        {
            return Err(Error::OwnershipMismatch);
        }
        history.published_at = Some(vprouter_core::health::boot_seconds());
        native.queue_mount(history, "attachment_primary", Some(mounted))
    }
    pub(crate) fn poll_primary_publication(
        &mut self,
        mounted: &kernel::namespace_attachment::Mounted,
    ) -> Result<bool> {
        mounted.bind_service(self)?;
        mounted.verify_current()?;
        let native = self.native.as_mut().ok_or(Error::Interrupted)?;
        if !native.poll_inspection("attachment_primary")? {
            return Ok(false);
        }
        let journal = native.transaction.shared.journal.borrow();
        let history = native.mount_history()?;
        if journal.record.base_network != Some(mounted.request().source_identity())
            || history.published_at.is_none()
            || history.request != mounted.request().digest()
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(true)
    }
}
