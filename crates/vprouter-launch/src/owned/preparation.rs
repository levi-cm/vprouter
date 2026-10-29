#![forbid(unsafe_code)]
//! Owner-only pre-resource journal service. It shares the canonical mutation
//! queue and read windows; a no-fork helper never receives journal authority.
use super::super::{
    secret::{InputIdentity, Inputs},
    supervision::{Domains, OwnerDomain, OwnerDomainRecord},
};
use super::*;
use std::{cell::RefCell, rc::Rc};
pub(crate) mod assembly;
pub(crate) mod bootstrap;
pub(crate) mod fresh_mount;
pub(crate) mod fresh_transport;
pub(crate) mod host_link;
pub(crate) mod inspection;
pub(crate) mod mount;
pub(crate) mod movement;
pub(crate) mod producer_binding;
pub(crate) mod producer_creation;
pub(crate) mod quarantine;
pub(crate) mod wireguard;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct History {
    member: String,
    allocation: String,
    configuration: [u8; 32],
    owner: OwnerDomainRecord,
    inputs: Vec<(String, InputIdentity)>,
    requested_at: f64,
    deadline: f64,
    birth: Option<ValidationBirth>,
    result: Option<PublicValidation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    inspection: Option<inspection::History>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mount: Option<mount::History>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    fresh_transport: Option<fresh_transport::History>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    wireguard: Vec<wireguard::History>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    movement_query: Option<inspection::History>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    quarantine_query: Option<inspection::History>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    producer_query: Option<inspection::History>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    producer_binding_query: Option<inspection::History>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    producer_creation: Option<producer_creation::History>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    producer_binding: Option<producer_binding::History>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    netfilter: Vec<quarantine::Operation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    host_link: Vec<host_link::History>,
    #[serde(default, skip_serializing_if = "no_bootstrap_queries")]
    bootstrap_queries: [Option<inspection::History>; 3],
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    bootstrap: Vec<bootstrap::History>,
}
fn no_bootstrap_queries(v: &[Option<inspection::History>; 3]) -> bool {
    v.iter().all(Option::is_none)
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicValidation {
    report: [u8; 32],
    selected: [u8; 32],
    device_key: Option<[u8; 32]>,
    verified_at: f64,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ValidationBirth {
    pub(crate) pid: u32,
    pub(crate) start: u64,
    pub(crate) born_at: f64,
    pub(crate) deadline: f64,
}
impl History {
    pub(super) fn matches_producer_publication(&self, entry: &Entry) -> bool {
        self.producer_binding
            .as_ref()
            .is_some_and(|h| h.matches_publication(entry))
    }
    pub(super) fn validate(&self, record: &Record, entry: &Entry) -> Result<()> {
        if self.member != entry.exit_id
            || self.allocation
                != vprouter_worker::bootstrap::digest(
                    &serde_json::to_vec(&record.allocation)
                        .map_err(|_| Error::AllocationMismatch)?,
                )
            || record.owner_epoch.as_ref() != Some(&self.owner)
            || self.configuration == [0; 32]
            || !self.requested_at.is_finite()
            || self.requested_at <= 0.
            || self.deadline != self.requested_at + 2.
            || self.inputs.len() > vprouter_core::config::MAX_EXITS
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
        if let Some(result) = &self.result {
            let birth = self.birth.as_ref().ok_or(Error::OwnershipMismatch)?;
            let mode = record
                .allocation
                .exits
                .iter()
                .find(|e| e.exit_id == self.member)
                .ok_or(Error::AllocationMismatch)?
                .mode;
            if result.report == [0; 32]
                || result.selected == [0; 32]
                || !result.verified_at.is_finite()
                || result.verified_at < birth.born_at
                || result.verified_at >= self.deadline
                || (mode == vprouter_core::config::ExitMode::Mullvad) != result.device_key.is_some()
                || result.device_key == Some([0; 32])
                || result.device_key.is_some_and(|key| {
                    record.entries.iter().any(|e| {
                        e.exit_id != self.member
                            && e.preparation
                                .as_ref()
                                .and_then(|h| h.result.as_ref())
                                .is_some_and(|r| r.device_key == Some(key))
                    })
                })
            {
                return Err(Error::OwnershipMismatch);
            }
        }
        if let Some(inspection) = &self.inspection {
            inspection.validate(self)?;
        }
        if let Some(mount) = &self.mount {
            mount.validate(record, entry, self)?;
        }
        if let Some(fresh) = &self.fresh_transport {
            fresh.validate(record, entry, self)?;
        }
        if self.wireguard.len() > 5 {
            return Err(Error::OwnershipMismatch);
        }
        for (index, history) in self.wireguard.iter().enumerate() {
            history.validate(entry, self, index)?;
        }
        if let Some(query) = &self.movement_query {
            query.validate_movement(self)?;
        }
        if let Some(query) = &self.quarantine_query {
            query.validate_quarantine(self)?;
        }
        if let Some(query) = &self.producer_query {
            query.validate_producer(self)?;
        }
        if let Some(query) = &self.producer_binding_query {
            query.validate_producer_binding(self)?;
        }
        if let Some(producer) = &self.producer_creation {
            producer.validate(record, entry, self)?;
        }
        if let Some(binding) = &self.producer_binding {
            binding.validate(record, entry, self)?;
        }
        if self.netfilter.len() > 6 {
            return Err(Error::OwnershipMismatch);
        }
        for (index, operation) in self.netfilter.iter().enumerate() {
            operation.validate(record, entry, self, index)?;
        }
        if self.host_link.len() > 4 {
            return Err(Error::OwnershipMismatch);
        }
        for (index, history) in self.host_link.iter().enumerate() {
            history.validate(record, entry, self, index)?;
        }
        if self.bootstrap.len() > 3 {
            return Err(Error::OwnershipMismatch);
        }
        for (index, operation) in self.bootstrap.iter().enumerate() {
            operation.validate(record, entry, self, index)?;
        }
        for (index, query) in self.bootstrap_queries.iter().enumerate() {
            if let Some(query) = query {
                query.validate_bootstrap(self, index)?;
            }
        }
        let mut seen = std::collections::HashSet::new();
        for (member, identity) in &self.inputs {
            if !seen.insert(member)
                || !record.allocation.exits.iter().any(|e| {
                    e.exit_id == *member && e.mode == vprouter_core::config::ExitMode::Mullvad
                })
            {
                return Err(Error::OwnershipMismatch);
            }
            identity.validate()?;
        }
        if seen.len()
            != record
                .allocation
                .exits
                .iter()
                .filter(|e| e.mode == vprouter_core::config::ExitMode::Mullvad)
                .count()
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
}

/// Constructor-only permit, issued after this exact intent's native writer
/// ACK/readback AND actual reap. Parsed History never constructs this type.
pub(crate) struct ValidationIntent {
    creator: u32,
    shared: Rc<SharedJournal>,
    member: String,
    history: History,
    owner: Rc<OwnerDomain>,
    domains: Domains,
    lease: MutatorLease,
}
impl ValidationIntent {
    pub(crate) fn prepare(&mut self, inputs: &Inputs) -> Result<()> {
        self.verify(inputs)?;
        self.lease
            .prepare_native_job(kernel::NativeJobKind::SecretValidation)
    }
    pub(crate) fn lease(&mut self) -> &mut MutatorLease {
        &mut self.lease
    }
    pub(crate) fn same_service(&self, service: &Server) -> Result<()> {
        let native = service.native.as_ref().ok_or(Error::Interrupted)?;
        native.require_creator()?;
        if self.creator != std::process::id()
            || !Rc::ptr_eq(&self.shared, &native.transaction.shared)
            || self.member != native.history.member
            || self.history.configuration != native.history.configuration
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
    pub(crate) fn verify(&self, inputs: &Inputs) -> Result<()> {
        kernel::owner_admission_permitted()?;
        inputs.verify_parent()?;
        if self.creator != std::process::id()
            || self.history.configuration != inputs.digest()
            || self.history.inputs != inputs.identities()
            || self.history.requested_at != inputs.started_at()
            || self.history.deadline != inputs.deadline()
            || vprouter_core::health::boot_seconds() >= self.history.deadline
            || self.shared.fenced.get()
            || self.shared.pending.borrow().is_some()
            || self.owner.record(&self.domains)? != self.history.owner
            || !self.shared.services.borrow().contains(&self.member)
        {
            return Err(Error::OwnershipMismatch);
        }
        let journal = self.shared.journal.borrow();
        let entry = journal
            .record
            .entries
            .iter()
            .find(|entry| entry.exit_id == self.member)
            .ok_or(Error::OwnershipMismatch)?;
        if entry.phase != Phase::Creating
            || entry.data.is_some()
            || entry.transport.is_some()
            || entry.preparation.as_ref() != Some(&self.history)
        {
            return Err(Error::OwnershipMismatch);
        }
        self.history.validate(&journal.record, entry)
    }
}
pub(crate) struct BirthReceipt {
    creator: u32,
    shared: Rc<SharedJournal>,
    member: String,
    birth: ValidationBirth,
}
pub(crate) struct ValidationReceipt {
    creator: u32,
    shared: Rc<SharedJournal>,
    member: String,
    birth: ValidationBirth,
    result: PublicValidation,
}
impl ValidationReceipt {
    pub(crate) fn verify(
        &self,
        intent: &ValidationIntent,
        birth: &ValidationBirth,
        report: [u8; 32],
    ) -> Result<()> {
        if self.creator != std::process::id()
            || self.creator != intent.creator
            || !Rc::ptr_eq(&self.shared, &intent.shared)
            || self.member != intent.member
            || &self.birth != birth
            || self.result.report != report
            || self.shared.fenced.get()
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
        let history = entry.preparation.as_ref().ok_or(Error::OwnershipMismatch)?;
        if history.result.as_ref() != Some(&self.result)
            || history.birth.as_ref() != Some(birth)
            || history.configuration != intent.history.configuration
            || history.owner != intent.history.owner
        {
            return Err(Error::OwnershipMismatch);
        }
        history.validate(&journal.record, entry)
    }
}
impl BirthReceipt {
    pub(crate) fn verify(&self, intent: &ValidationIntent, birth: &ValidationBirth) -> Result<()> {
        if self.creator != std::process::id()
            || self.creator != intent.creator
            || !Rc::ptr_eq(&self.shared, &intent.shared)
            || self.member != intent.member
            || &self.birth != birth
            || self.shared.fenced.get()
            || vprouter_core::health::boot_seconds() >= self.birth.deadline
        {
            return Err(Error::OwnershipMismatch);
        }
        let journal = self.shared.journal.borrow();
        let history = journal
            .record
            .entries
            .iter()
            .find(|e| e.exit_id == self.member)
            .and_then(|e| e.preparation.as_ref())
            .ok_or(Error::OwnershipMismatch)?;
        if history.birth.as_ref() != Some(birth)
            || history.configuration != intent.history.configuration
            || history.inputs != intent.history.inputs
            || history.owner != intent.history.owner
        {
            return Err(Error::OwnershipMismatch);
        }
        kernel::owner_admission_permitted()
    }
}

pub(crate) struct Server {
    native: Option<Native>,
}
struct Native {
    creator: u32,
    transaction: Transaction,
    owner: Rc<OwnerDomain>,
    domains: Domains,
    inputs: Option<Inputs>,
    history: History,
    queued_at: Option<f64>,
    pending: Option<JournalJob>,
    failure: Option<Error>,
    issued: bool,
    birth: Option<ValidationBirth>,
    result: Option<PublicValidation>,
    result_issued: bool,
    continuation: Option<Continuation>,
    #[cfg(test)]
    lab_writers: Vec<LabWriter>,
    #[cfg(test)]
    lab_hold: Option<&'static str>,
}
/// Owner-only serialized continuation, never a caller-supplied record or a
/// guard wire request. Exact before digest prevents stale queued proposals.
struct Continuation {
    quarantine_origin: Option<quarantine::ProgressOrigin>,
    before: [u8; 32],
    proposed: Record,
    started_at: f64,
    phase: &'static str,
    publication: Option<Rc<kernel::namespace_attachment::Mounted>>,
    transport_publication: Option<Rc<kernel::fresh_transport_mount::Mounted>>,
}
#[cfg(test)]
struct LabWriter {
    phase: &'static str,
    queued_at: f64,
    io_deadline: f64,
    parent_deadline: f64,
    original: kernel::Survivor,
    verified_at: Option<f64>,
}
thread_local! { static RETAINED: RefCell<Vec<Native>> = const { RefCell::new(Vec::new()) }; }
impl Drop for Server {
    fn drop(&mut self) {
        if let Some(mut native) = self.native.take() {
            if native.creator != std::process::id() {
                return;
            }
            native.fail(Error::Interrupted);
            // Keep the unique service, original input descriptors, canonical
            // journal and pending write even if cancellation/reap itself fails.
            RETAINED.with(|retained| retained.borrow_mut().push(native));
        }
    }
}
pub(crate) fn poll_retained() {
    RETAINED.with(|retained| {
        for native in retained.borrow_mut().iter_mut() {
            if native.creator == std::process::id() {
                native.collect();
            }
        }
    });
}
/// Actual native child drainage only. Failed canonical writes, service
/// reservations and their uncertainty fence stay retained after this is true.
pub(crate) fn retained_children_reaped() -> bool {
    RETAINED.with(|retained| {
        retained.borrow().iter().all(|native| {
            native.creator != std::process::id()
                || native
                    .pending
                    .as_ref()
                    .is_none_or(|job| job.child.drained())
        })
    })
}
impl Server {
    #[cfg(test)]
    pub(crate) fn lab_cached_quarantine_progress(&self) -> Option<serde_json::Value> {
        let n = self.native.as_ref()?;
        if n.creator != std::process::id() || n.lab_writers.len() > 112 {
            return None;
        }
        let shared = &n.transaction.shared;
        let journal = shared.journal.try_borrow().ok()?;
        let pending = shared.pending.try_borrow().ok()?;
        let current = journal
            .record
            .entries
            .iter()
            .find(|e| e.exit_id == n.history.member)?
            .preparation
            .as_ref()?;
        let proposed = pending
            .as_ref()
            .and_then(|r| r.entries.iter().find(|e| e.exit_id == n.history.member))
            .and_then(|e| e.preparation.as_ref());
        let writers: Vec<_> = n.lab_writers.iter().map(|w| {
            let identity=w.original.lab_birth_identity().ok();
            serde_json::json!({"phase":w.phase,"pid":identity.map(|i|i.0),"start":identity.map(|i|i.1),
                "queued_at":w.queued_at,"io_deadline":w.io_deadline,"parent_deadline":w.parent_deadline,
                "actual_wait_status":w.original.lab_terminal_status().ok().flatten(),"verified_at":w.verified_at})
        }).collect();
        Some(
            serde_json::json!({"schema":1,"member":n.history.member,"owner_epoch":journal.record.owner_epoch,
            "writers":writers,"netfilter":current.netfilter,"pending_netfilter":proposed.map(|p|&p.netfilter),
            "canonical_pending":pending.is_some(),"mutation_fenced":shared.fenced.get(),
            "checkpoint_waiting":n.pending.as_ref().and_then(|j|j.child.lab_cached_checkpoint_waiting())}),
        )
    }
    pub(crate) fn fail(&mut self, error: Error) {
        if let Some(native) = &mut self.native {
            native.fail(error);
        }
    }
    pub(crate) fn collect(&mut self) {
        if let Some(native) = &mut self.native
            && native.creator == std::process::id()
        {
            native.collect();
        }
    }
    pub(crate) fn children_reaped(&self) -> bool {
        self.native.as_ref().is_none_or(|native| {
            native.creator == std::process::id()
                && native
                    .pending
                    .as_ref()
                    .is_none_or(|job| job.child.drained())
        })
    }
    /// Startup only: no established neighbor exists yet. The native owner-host
    /// anchor is explicit, while the primary data namespace remains absent.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn initial(
        store: &AllocationStore,
        path: &Path,
        allocation: &AllocationRecord,
        member: &str,
        primary: &str,
        inputs: Inputs,
        owner: Rc<OwnerDomain>,
        domains: Domains,
    ) -> Result<(Transaction, Self)> {
        if domains.exit_id() != member {
            return Err(Error::AllocationMismatch);
        }
        let epoch = owner.record(&domains)?;
        let host = kernel::network()?;
        let _host_inventory = super::super::inventory::Registration::owned(&[host.as_fd()])?;
        let journal = Journal::open_context(
            store,
            path,
            allocation,
            member,
            primary,
            &host,
            Some(epoch),
            JournalOrigin::OwnerHost,
        )?;
        let transaction = Transaction::from_journal_member(journal, member)?;
        let server = Self::existing(&transaction, inputs, owner, domains)?;
        Ok((transaction, server))
    }
    /// Dynamic members reuse the SAME canonical Rc/OFD. No synchronous reopen,
    /// fsync, manager query or foreign-record adoption happens on this path.
    pub(crate) fn existing(
        transaction: &Transaction,
        inputs: Inputs,
        owner: Rc<OwnerDomain>,
        domains: Domains,
    ) -> Result<Self> {
        kernel::owner_admission_permitted()?;
        transaction.require_allocation_memory()?;
        inputs.verify_parent()?;
        let epoch = owner.record(&domains)?;
        let shared = &transaction.shared;
        let journal = shared.journal.borrow();
        if domains.exit_id() != transaction.exit_id
            || journal.record.owner_epoch.as_ref() != Some(&epoch)
            || domains.allocation()
                != vprouter_worker::bootstrap::digest(
                    &serde_json::to_vec(&journal.record.allocation)
                        .map_err(|_| Error::AllocationMismatch)?,
                )
            || !same_allocation(
                &inputs.allocation(journal.record.allocation.generation)?,
                &journal.record.allocation,
            )?
            || journal
                .record
                .entries
                .iter()
                .any(|entry| entry.exit_id == transaction.exit_id)
            || shared.fenced.get()
            || shared.services.borrow().contains(&transaction.exit_id)
        {
            return Err(Error::OwnershipMismatch);
        }
        if !shared
            .native_jobs
            .borrow_mut()
            .drained(&transaction.exit_id)?
        {
            return Err(Error::LockBusy);
        }
        let history = History {
            member: transaction.exit_id.clone(),
            allocation: domains.allocation().into(),
            configuration: inputs.digest(),
            owner: epoch,
            inputs: inputs.identities(),
            requested_at: inputs.started_at(),
            deadline: inputs.deadline(),
            birth: None,
            result: None,
            inspection: None,
            mount: None,
            fresh_transport: None,
            wireguard: Vec::new(),
            movement_query: None,
            quarantine_query: None,
            producer_query: None,
            producer_binding_query: None,
            producer_creation: None,
            producer_binding: None,
            netfilter: Vec::new(),
            host_link: Vec::new(),
            bootstrap_queries: [None, None, None],
            bootstrap: Vec::new(),
        };
        let entry = new_entry(&journal.record, &history)?;
        history.validate(&journal.record, &entry)?;
        shared.leases.borrow_mut().hold(&transaction.exit_id)?;
        shared
            .services
            .borrow_mut()
            .insert(transaction.exit_id.clone());
        journal.async_only.set(true);
        drop(journal);
        let view = Transaction {
            remote: None,
            owner_service: true,
            retirement_bookkeeping: false,
            shared: shared.clone(),
            exit_id: transaction.exit_id.clone(),
        };
        Ok(Self {
            native: Some(Native {
                creator: std::process::id(),
                transaction: view,
                owner,
                domains,
                inputs: Some(inputs),
                history,
                queued_at: None,
                pending: None,
                failure: None,
                issued: false,
                birth: None,
                result: None,
                result_issued: false,
                continuation: None,
                #[cfg(test)]
                lab_writers: Vec::new(),
                #[cfg(test)]
                lab_hold: None,
            }),
        })
    }
    pub(crate) fn start(&mut self) -> Result<()> {
        let native = self.native.as_mut().ok_or(Error::Interrupted)?;
        native.require_creator()?;
        kernel::owner_admission_permitted()?;
        if native.failure.is_some()
            || native.queued_at.is_some()
            || native.pending.is_some()
            || native.issued
        {
            return Err(Error::Interrupted);
        }
        let shared = &native.transaction.shared;
        mutation_slot_available(shared.pending.borrow().is_some(), shared.fenced.get())?;
        let now = vprouter_core::health::boot_seconds();
        original_frame(native.history.requested_at, now)?;
        shared.queue.borrow_mut().push(&native.history.member)?;
        native.queued_at = Some(now);
        Ok(())
    }
    pub(crate) fn poll(&mut self) -> Result<Option<(ValidationIntent, Inputs)>> {
        let native = self.native.as_mut().ok_or(Error::Interrupted)?;
        native.require_creator()?;
        if let Some(error) = native.failure {
            native.collect();
            return Err(error);
        }
        let result = (|| {
            if native.issued || native.birth.is_some() {
                return Err(Error::OwnershipMismatch);
            }
            if !native.advance()? {
                return Ok(None);
            }
            let permit = ValidationIntent {
                creator: native.creator,
                shared: native.transaction.shared.clone(),
                member: native.history.member.clone(),
                history: native.history.clone(),
                owner: native.owner.clone(),
                domains: native.domains.clone(),
                lease: native.transaction.retain_allocation_lease()?,
            };
            let inputs = native.inputs.take().ok_or(Error::Interrupted)?;
            permit.verify(&inputs)?;
            native.issued = true;
            Ok(Some((permit, inputs)))
        })();
        if let Err(error) = result {
            native.fail(error);
            native.collect();
        }
        result
    }
    pub(crate) fn start_birth(&mut self, child: &kernel::secret::ValidationChild) -> Result<()> {
        child.bind_service(self)?;
        let birth = child.birth()?;
        let native = self.native.as_mut().ok_or(Error::Interrupted)?;
        native.require_creator()?;
        kernel::owner_admission_permitted()?;
        if !native.issued
            || native.birth.is_some()
            || native.pending.is_some()
            || native.queued_at.is_some()
            || native.failure.is_some()
        {
            return Err(Error::OwnershipMismatch);
        }
        let mut history = native.history.clone();
        history.birth = Some(birth.clone());
        let journal = native.transaction.shared.journal.borrow();
        let entry = journal
            .record
            .entries
            .iter()
            .find(|e| e.exit_id == native.history.member)
            .ok_or(Error::OwnershipMismatch)?;
        history.validate(&journal.record, entry)?;
        drop(journal);
        native
            .transaction
            .shared
            .queue
            .borrow_mut()
            .push(&native.history.member)?;
        native.birth = Some(birth);
        native.queued_at = Some(vprouter_core::health::boot_seconds());
        Ok(())
    }
    pub(crate) fn poll_birth(
        &mut self,
        child: &kernel::secret::ValidationChild,
    ) -> Result<Option<BirthReceipt>> {
        child.bind_service(self)?;
        let native = self.native.as_mut().ok_or(Error::Interrupted)?;
        native.require_creator()?;
        if let Some(error) = native.failure {
            native.collect();
            return Err(error);
        }
        let result = (|| {
            if native.birth.as_ref() != Some(&child.birth()?) {
                return Err(Error::OwnershipMismatch);
            }
            if !native.advance()? {
                return Ok(None);
            }
            Ok(Some(BirthReceipt {
                creator: native.creator,
                shared: native.transaction.shared.clone(),
                member: native.history.member.clone(),
                birth: native.birth.clone().ok_or(Error::Interrupted)?,
            }))
        })();
        if let Err(error) = result {
            native.fail(error);
            native.collect();
        }
        result
    }
    pub(crate) fn start_result(&mut self, verified: &kernel::secret::Verified) -> Result<()> {
        verified.bind_service(self)?;
        let native = self.native.as_mut().ok_or(Error::Interrupted)?;
        native.require_creator()?;
        kernel::owner_admission_permitted()?;
        if native.birth.as_ref() != Some(&verified.birth()?)
            || native.result.is_some()
            || native.pending.is_some()
            || native.queued_at.is_some()
            || native.failure.is_some()
        {
            return Err(Error::OwnershipMismatch);
        }
        let (selected, device_key) = verified.member_fact(&native.history.member)?;
        let result = PublicValidation {
            report: verified.digest(),
            selected,
            device_key,
            verified_at: verified.verified_at(),
        };
        let journal = native.transaction.shared.journal.borrow();
        // A newly validated whole candidate must preserve every already-bound
        // neighbor's public profile/config facts; never adopt changed A data.
        for entry in &journal.record.entries {
            if let Some(old) = entry.preparation.as_ref().and_then(|h| h.result.as_ref())
                && verified.member_fact(&entry.exit_id)? != (old.selected, old.device_key)
            {
                return Err(Error::OwnershipMismatch);
            }
        }
        let mut proposed = journal.record.clone();
        let entry = proposed
            .entries
            .iter_mut()
            .find(|e| e.exit_id == native.history.member)
            .ok_or(Error::OwnershipMismatch)?;
        let history = entry.preparation.as_mut().ok_or(Error::OwnershipMismatch)?;
        if history.birth.as_ref() != native.birth.as_ref() || history.result.is_some() {
            return Err(Error::OwnershipMismatch);
        }
        history.result = Some(result.clone());
        proposed.bind_anchor(
            &proposed.allocation,
            &proposed.primary_exit_id,
            proposed.base_network,
            proposed.owner_network,
        )?;
        drop(journal);
        native
            .transaction
            .shared
            .queue
            .borrow_mut()
            .push(&native.history.member)?;
        native.result = Some(result);
        native.queued_at = Some(vprouter_core::health::boot_seconds());
        Ok(())
    }
    pub(crate) fn poll_result(
        &mut self,
        verified: &kernel::secret::Verified,
    ) -> Result<Option<ValidationReceipt>> {
        verified.bind_service(self)?;
        let native = self.native.as_mut().ok_or(Error::Interrupted)?;
        native.require_creator()?;
        if let Some(error) = native.failure {
            native.collect();
            return Err(error);
        }
        let result = (|| {
            if native.result_issued
                || native
                    .result
                    .as_ref()
                    .is_none_or(|r| r.report != verified.digest())
                || native.birth.as_ref() != Some(&verified.birth()?)
            {
                return Err(Error::OwnershipMismatch);
            }
            if !native.advance()? {
                return Ok(None);
            }
            native.result_issued = true;
            Ok(Some(ValidationReceipt {
                creator: native.creator,
                shared: native.transaction.shared.clone(),
                member: native.history.member.clone(),
                birth: verified.birth()?,
                result: native.result.clone().ok_or(Error::Interrupted)?,
            }))
        })();
        if let Err(error) = result {
            native.fail(error);
            native.collect();
        }
        result
    }
}
fn new_entry(record: &Record, history: &History) -> Result<Entry> {
    if record
        .entries
        .iter()
        .any(|entry| entry.exit_id == history.member)
    {
        return Err(Error::Interrupted);
    }
    let allocation = record
        .allocation
        .exits
        .iter()
        .find(|entry| entry.exit_id == history.member)
        .ok_or(Error::AllocationMismatch)?;
    Ok(Entry {
        exit_id: history.member.clone(),
        data_name: allocation.data_namespace.clone(),
        transport_name: allocation.transport_namespace.clone(),
        phase: Phase::Creating,
        data: None,
        transport: None,
        links: None,
        producer: None,
        terminal: None,
        attempt: None,
        preparation: Some(history.clone()),
    })
}
impl Native {
    fn require_creator(&self) -> Result<()> {
        if self.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        self.transaction.require_allocation_memory()
    }
    fn fail(&mut self, error: Error) {
        if self.creator != std::process::id() {
            return;
        }
        self.failure.get_or_insert(error);
        if self.queued_at.take().is_some() {
            self.transaction
                .shared
                .queue
                .borrow_mut()
                .remove(&self.history.member);
        }
        if let Some(job) = &mut self.pending {
            // Fence before any fallible cancellation; never erase a proposed
            // record or convert native death into durable-write certainty.
            self.transaction.shared.fenced.set(true);
            job.failed = true;
            let _ = job.child.cancel();
        }
    }
    fn collect(&mut self) {
        if let Some(job) = &mut self.pending
            && job.failed
            && !job.child.drained()
        {
            let _ = job.child.poll();
        }
    }
    fn advance(&mut self) -> Result<bool> {
        kernel::owner_admission_permitted()?;
        // Every preparation writer is a new fork, including continuations
        // between polls. A previously pristine constructor is not a waiver for
        // later sensitive ingress elsewhere in this same owner process.
        if !vprouter_core::secret_boundary::pristine() {
            return Err(Error::ConfinementPolicy);
        }
        let started_at = self
            .continuation
            .as_ref()
            .map_or(self.history.requested_at, |c| c.started_at);
        let deadline = started_at + 2.;
        #[cfg(test)]
        let phase = self.continuation.as_ref().map_or_else(
            || {
                if self.result.is_some() {
                    "result"
                } else if self.birth.is_some() {
                    "birth"
                } else {
                    "intent"
                }
            },
            |c| c.phase,
        );
        original_frame(started_at, vprouter_core::health::boot_seconds())?;
        let shared = &self.transaction.shared;
        if let Some(sent_at) = self.queued_at {
            original_frame(sent_at, vprouter_core::health::boot_seconds())?;
            if !mutation_slot_available(shared.pending.borrow().is_some(), shared.fenced.get())?
                || !shared.queue.borrow().first(&self.history.member)
                || shared
                    .reads
                    .borrow()
                    .0
                    .values()
                    .any(|window| window.generations.len() >= MAX_READ_GENERATIONS)
            {
                return Ok(false);
            }
            let before = shared.journal.borrow().record.clone();
            let mut proposed = before.clone();
            if let Some(continuation) = &self.continuation {
                if record_digest(&encode_record(&before)?) != continuation.before {
                    return Err(Error::OwnershipMismatch);
                }
                proposed = continuation.proposed.clone();
            } else if let Some(result) = &self.result {
                let history = proposed
                    .entries
                    .iter_mut()
                    .find(|e| e.exit_id == self.history.member)
                    .and_then(|e| e.preparation.as_mut())
                    .ok_or(Error::OwnershipMismatch)?;
                let mut expected = self.history.clone();
                expected.birth = self.birth.clone();
                if *history != expected || history.result.is_some() {
                    return Err(Error::OwnershipMismatch);
                }
                history.result = Some(result.clone());
            } else if let Some(birth) = &self.birth {
                let entry = proposed
                    .entries
                    .iter_mut()
                    .find(|e| e.exit_id == self.history.member)
                    .ok_or(Error::OwnershipMismatch)?;
                let history = entry.preparation.as_mut().ok_or(Error::OwnershipMismatch)?;
                if *history != self.history || history.birth.is_some() {
                    return Err(Error::OwnershipMismatch);
                }
                history.birth = Some(birth.clone());
            } else {
                proposed.entries.push(new_entry(&before, &self.history)?);
            }
            if let Some(mounted) = self
                .continuation
                .as_ref()
                .and_then(|c| c.transport_publication.as_ref())
            {
                mounted.verify_current()?;
                let old = before
                    .entries
                    .iter()
                    .find(|e| e.exit_id == self.history.member)
                    .ok_or(Error::OwnershipMismatch)?;
                let new = proposed
                    .entries
                    .iter()
                    .find(|e| e.exit_id == self.history.member)
                    .ok_or(Error::OwnershipMismatch)?;
                if old.transport.is_some()
                    || new.transport != Some(mounted.request().source_identity())
                    || before.base_network != proposed.base_network
                {
                    return Err(Error::OwnershipMismatch);
                }
            }
            let base = if let Some(mounted) = self
                .continuation
                .as_ref()
                .and_then(|c| c.publication.as_ref())
            {
                mounted.verify_current()?;
                if before.base_network.is_some()
                    || proposed.base_network != Some(mounted.request().source_identity())
                {
                    return Err(Error::OwnershipMismatch);
                }
                proposed.base_network
            } else {
                before.base_network
            };
            proposed.bind_anchor(
                &before.allocation,
                &before.primary_exit_id,
                base,
                before.owner_network,
            )?;
            if !shared.reads.borrow().can_publish(&proposed)? {
                return Ok(false);
            }
            let io = JournalIo {
                allocation: before.allocation.clone(),
                before: encode_record(&before)?,
                after: Some(encode_record(&proposed)?),
                deadline,
                #[cfg(test)]
                pause_before_sync: self.lab_hold == Some(phase),
                #[cfg(test)]
                pause_before_read: false,
                #[cfg(test)]
                lab_stage: std::cell::Cell::new(0),
            };
            let directory = rustix::io::fcntl_dupfd_cloexec(&shared.journal.borrow().dir, 3)
                .map_err(|_| Error::DescriptorDuplicate)?;
            let lease = self.transaction.retain_allocation_lease()?;
            let child = kernel::spawn_journal_io(directory, lease, &io)?;
            self.pending = Some(JournalJob {
                child,
                mutation: true,
                deadline,
                failed: false,
            });
            #[cfg(test)]
            {
                // Fixed connected path: 42 movement + 18 NFT + 3 DATA query
                // + 3 producer query + 3 producer writers; retain bounded fault headroom.
                if self.lab_writers.len() >= 112 {
                    return Err(Error::TooLarge);
                }
                let job = self.pending.as_ref().ok_or(Error::Interrupted)?;
                let original = job.child.lab_native_reap_handle()?;
                // Capture while this exact constructor child is still behind
                // its release gate; start_time brackets stat with original
                // pidfd liveness and binds the shared direct-child receipt.
                original.start_time()?;
                self.lab_writers.push(LabWriter {
                    phase,
                    queued_at: sent_at,
                    io_deadline: io.deadline,
                    parent_deadline: job.deadline,
                    original,
                    verified_at: None,
                });
            }
            // Install pending ownership before releasing the child. The exact
            // proposal participates in existing A read windows before mutation.
            *shared.pending.borrow_mut() = Some(proposed.clone());
            shared.reads.borrow_mut().publish(&proposed)?;
            shared.queue.borrow_mut().remove(&self.history.member);
            self.queued_at = None;
            self.pending
                .as_mut()
                .ok_or(Error::Interrupted)?
                .child
                .start()?;
            #[cfg(test)]
            if self.lab_hold == Some("attachment_placeholder") && phase == "attachment_birth"
                || self.lab_hold == Some("attachment_primary") && phase == "attachment_placeholder"
            {
                // Deterministic ACK-race fixture: yield after original native
                // ownership and release, before the FIRST normal ACK read.
                // No phase timestamp or writer deadline is renewed.
                return Ok(false);
            }
        }
        let job = self.pending.as_mut().ok_or(Error::Interrupted)?;
        if job.failed || vprouter_core::health::boot_seconds() >= job.deadline {
            return Err(Error::Deadline);
        }
        match job.child.poll()? {
            None => return Ok(false),
            Some(false) => return Err(Error::Interrupted),
            Some(true) => {}
        }
        original_frame(started_at, vprouter_core::health::boot_seconds())?;
        let proposed = shared
            .pending
            .borrow()
            .as_ref()
            .ok_or(Error::Interrupted)?
            .clone();
        if job.child.observed()? != record_digest(&encode_record(&proposed)?) {
            return Err(Error::OwnershipMismatch);
        }
        #[cfg(test)]
        {
            let proof = self
                .lab_writers
                .last_mut()
                .ok_or(Error::OwnershipMismatch)?;
            if proof.original.lab_terminal_status()? != Some(0)
                || proof.io_deadline != deadline
                || proof.parent_deadline != deadline
            {
                return Err(Error::OwnershipMismatch);
            }
            proof.verified_at = Some(vprouter_core::health::boot_seconds());
        }
        shared.journal.borrow_mut().record = proposed;
        shared.pending.borrow_mut().take();
        self.pending = None; // Actual reap preceded ACK acceptance; releases job ticket.
        if self.birth.is_none()
            && !shared
                .native_jobs
                .borrow_mut()
                .drained(&self.history.member)?
        {
            return Err(Error::LockBusy);
        }
        Ok(true)
    }
}

#[cfg(test)]
impl Server {
    pub(crate) fn lab_binding_result_charge(
        &self,
        failed: bool,
    ) -> Result<(kernel::LabJournalCharge, serde_json::Value)> {
        self.lab_result_charge(failed, 74, "producer_binding_result")
    }
    pub(crate) fn lab_host_result_charge(
        &self,
        failed: bool,
    ) -> Result<(kernel::LabJournalCharge, serde_json::Value)> {
        self.lab_result_charge(failed, 86, "host_link_result")
    }
    fn lab_result_charge(
        &self,
        failed: bool,
        expected_index: usize,
        expected_phase: &str,
    ) -> Result<(kernel::LabJournalCharge, serde_json::Value)> {
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        n.require_creator()?;
        let job = n.pending.as_ref().ok_or(Error::OwnershipMismatch)?;
        let continuation = n.continuation.as_ref().ok_or(Error::OwnershipMismatch)?;
        let index = n
            .lab_writers
            .len()
            .checked_sub(1)
            .ok_or(Error::OwnershipMismatch)?;
        let writer = &n.lab_writers[index];
        let shared = &n.transaction.shared;
        let pending = shared.pending.borrow();
        let proposed = pending.as_ref().ok_or(Error::OwnershipMismatch)?;
        let charge = job.child.lab_charge(&writer.original)?;
        let (pid, start, status) = charge.facts()?;
        if index != expected_index
            || writer.phase != expected_phase
            || continuation.phase != writer.phase
            || writer.verified_at.is_some()
            || writer.original.lab_birth_identity()? != (pid, start)
            || writer.original.lab_terminal_status()? != status
            || job.failed != failed
            || n.failure.is_some() != failed
            || shared.fenced.get() != failed
            || !job.mutation
            || job.child.drained() != failed
            || status != if failed { Some(9) } else { None }
            || !failed && job.child.lab_cached_checkpoint_waiting() != Some(true)
            || charge.before != continuation.before
            || charge.after != Some(record_digest(&encode_record(proposed)?))
            || encode_record(proposed)? != encode_record(&continuation.proposed)?
            || charge.deadline != continuation.started_at + 2.
            || charge.deadline != writer.io_deadline
            || charge.deadline != writer.parent_deadline
            || charge.deadline != job.deadline
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok((
            charge,
            serde_json::json!({"index":index,"pid":pid,"start":start,
            "actual_wait_status":status,"io_deadline":writer.io_deadline,"parent_deadline":writer.parent_deadline,
            "launch_charge":1,"original_reap_bound":true,"failed":failed,"mutation":true,
            "acknowledged":false,"canonical_pending":true,"mutation_fenced":failed}),
        ))
    }
    pub(crate) fn lab_hold(&mut self, phase: &'static str) -> Result<()> {
        let native = self.native.as_mut().ok_or(Error::Interrupted)?;
        native.require_creator()?;
        if native.pending.is_some()
            || !native.lab_writers.is_empty()
            || !["intent", "birth", "result"].contains(&phase)
        {
            return Err(Error::OwnershipMismatch);
        }
        native.lab_hold = Some(phase);
        Ok(())
    }
    pub(crate) fn lab_checkpoint(&mut self) -> Result<bool> {
        let native = self.native.as_mut().ok_or(Error::Interrupted)?;
        native.require_creator()?;
        let Some(job) = &mut native.pending else {
            return Ok(false);
        };
        job.child.lab_waiting_checkpoint()
    }
    pub(crate) fn lab_ack_ready(&mut self) -> Result<bool> {
        let native = self.native.as_mut().ok_or(Error::Interrupted)?;
        native.require_creator()?;
        match &native.pending {
            Some(job) => job.child.lab_ack_ready(),
            None => Ok(false),
        }
    }
    pub(crate) fn lab_pending_writer_identity(&self) -> Result<Option<(usize, u32, u64)>> {
        let native = self.native.as_ref().ok_or(Error::Interrupted)?;
        native.require_creator()?;
        if native.pending.is_none() {
            return Ok(None);
        }
        let index = native
            .lab_writers
            .len()
            .checked_sub(1)
            .ok_or(Error::OwnershipMismatch)?;
        let proof = &native.lab_writers[index];
        if proof.verified_at.is_some() {
            return Err(Error::OwnershipMismatch);
        }
        let (pid, start) = proof.original.lab_birth_identity()?;
        Ok(Some((index, pid, start)))
    }
    pub(crate) fn lab_hold_attachment(&mut self, phase: &'static str) -> Result<()> {
        let native = self.native.as_mut().ok_or(Error::Interrupted)?;
        native.require_creator()?;
        if native.pending.is_some()
            || native
                .continuation
                .as_ref()
                .is_some_and(|c| c.phase != "attachment_intent")
            || !matches!(phase, "attachment_placeholder" | "attachment_primary")
        {
            return Err(Error::OwnershipMismatch);
        }
        native.lab_hold = Some(phase);
        Ok(())
    }
    pub(crate) fn lab_hold_netfilter_intent(&mut self) -> Result<()> {
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        n.require_creator()?;
        if n.pending.is_some()
            || n.continuation.is_some()
            || n.lab_hold.is_some()
            || n.lab_writers.len() != 42
        {
            return Err(Error::OwnershipMismatch);
        }
        n.lab_hold = Some("netfilter_intent");
        Ok(())
    }
    pub(crate) fn lab_release_netfilter_intent(&mut self) -> Result<()> {
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        n.require_creator()?;
        if n.lab_hold != Some("netfilter_intent")
            || n.lab_writers.len() != 43
            || n.continuation
                .as_ref()
                .is_none_or(|c| c.phase != "netfilter_intent")
        {
            return Err(Error::OwnershipMismatch);
        }
        n.pending
            .as_mut()
            .ok_or(Error::Interrupted)?
            .child
            .lab_release_checkpoint()?;
        n.lab_hold = None;
        Ok(())
    }
    pub(crate) fn lab_hold_host_writer(&mut self, intent: bool) -> Result<()> {
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        n.require_creator()?;
        if n.pending.is_some()
            || n.lab_hold.is_some()
            || (intent && n.lab_writers.len() != 75)
            || (!intent && n.continuation.is_some())
        {
            return Err(Error::OwnershipMismatch);
        }
        n.lab_hold = Some(if intent {
            "host_link_intent"
        } else {
            "host_link_result"
        });
        Ok(())
    }
    pub(crate) fn lab_release_host_intent(&mut self) -> Result<()> {
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        n.require_creator()?;
        if n.lab_hold != Some("host_link_intent")
            || n.lab_writers.len() != 76
            || n.continuation
                .as_ref()
                .is_none_or(|c| c.phase != "host_link_intent")
        {
            return Err(Error::OwnershipMismatch);
        }
        n.pending
            .as_mut()
            .ok_or(Error::Interrupted)?
            .child
            .lab_release_checkpoint()?;
        n.lab_hold = None;
        Ok(())
    }
    pub(crate) fn lab_hold_producer_binding_result(&mut self) -> Result<()> {
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        n.require_creator()?;
        if n.pending.is_some() || n.continuation.is_some() || n.lab_hold.is_some() {
            return Err(Error::OwnershipMismatch);
        }
        n.lab_hold = Some("producer_binding_result");
        Ok(())
    }
    pub(crate) fn lab_hold_producer_result(&mut self) -> Result<()> {
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        n.require_creator()?;
        if n.pending.is_some() || n.continuation.is_some() || n.lab_hold.is_some() {
            return Err(Error::OwnershipMismatch);
        }
        n.lab_hold = Some("producer_result");
        Ok(())
    }
    pub(crate) fn lab_hold_provision_result(&mut self) -> Result<()> {
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        n.require_creator()?;
        if n.pending.is_some() || n.continuation.is_some() || n.lab_hold.is_some() {
            return Err(Error::OwnershipMismatch);
        }
        n.lab_hold = Some("wireguard_result");
        Ok(())
    }
    pub(crate) fn lab_release_expired_writer(&mut self) -> Result<i32> {
        let native = self.native.as_mut().ok_or(Error::Interrupted)?;
        native.require_creator()?;
        if vprouter_core::health::boot_seconds() < native.history.deadline {
            return Err(Error::OwnershipMismatch);
        }
        let job = native.pending.as_mut().ok_or(Error::Interrupted)?;
        if job.deadline != native.history.deadline || job.failed {
            return Err(Error::OwnershipMismatch);
        }
        job.child.lab_release_checkpoint()?;
        // Test-only drainage window, not an extension of this native operation.
        // The original child must refuse its expired canonical rename itself.
        let reap_end = vprouter_core::health::boot_seconds() + 2.;
        loop {
            match job.child.poll()? {
                Some(false) => break,
                Some(true) => return Err(Error::OwnershipMismatch),
                None => {}
            }
            if vprouter_core::health::boot_seconds() >= reap_end {
                return Err(Error::Deadline);
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        let proof = native.lab_writers.last().ok_or(Error::OwnershipMismatch)?;
        let status = proof
            .original
            .lab_terminal_status()?
            .ok_or(Error::OwnershipMismatch)?;
        if status != 122 << 8 {
            return Err(Error::OwnershipMismatch);
        }
        Ok(status)
    }
    pub(crate) fn lab_evidence(&self) -> Result<serde_json::Value> {
        let native = self.native.as_ref().ok_or(Error::Interrupted)?;
        native.require_creator()?;
        let shared = &native.transaction.shared;
        let journal = shared.journal.borrow();
        let entry = journal
            .record
            .entries
            .iter()
            .find(|entry| entry.exit_id == native.history.member);
        let writers = native.lab_writers.iter().map(|proof| {
            let (pid, start) = proof.original.lab_birth_identity()?;
            Ok(serde_json::json!({"phase": proof.phase, "pid": pid, "start": start,
                "queued_at": proof.queued_at, "io_deadline": proof.io_deadline,
                "parent_deadline": proof.parent_deadline, "actual_wait_status": proof.original.lab_terminal_status()?,
                "verified_at": proof.verified_at}))
        }).collect::<Result<Vec<_>>>()?;
        let pending_producer = shared.pending.borrow().as_ref().and_then(|record| {
            record
                .entries
                .iter()
                .find(|e| e.exit_id == native.history.member)
                .and_then(|e| e.preparation.as_ref())
                .and_then(|p| p.producer_creation.clone())
        });
        let pending_producer_binding = shared.pending.borrow().as_ref().and_then(|r|r.entries.iter().find(|e|e.exit_id==native.history.member)).map(|e|serde_json::json!({"producer":e.producer,"history":e.preparation.as_ref().and_then(|p|p.producer_binding.as_ref())}));
        let pending_host_link = shared
            .pending
            .borrow()
            .as_ref()
            .and_then(|r| {
                r.entries
                    .iter()
                    .find(|e| e.exit_id == native.history.member)
            })
            .and_then(|e| e.preparation.as_ref())
            .map(|p| p.host_link.clone());
        let pending_wireguard = shared.pending.borrow().as_ref().and_then(|record| {
            record
                .entries
                .iter()
                .find(|e| e.exit_id == native.history.member)
                .and_then(|e| e.preparation.as_ref())
                .map(|p| p.wireguard.clone())
        });
        let mut value = serde_json::json!({"member": native.history.member, "requested_at": native.history.requested_at,
            "deadline": native.history.deadline, "birth": native.birth,
            "base_network_absent": journal.record.base_network.is_none(),
            "base_network": journal.record.base_network,
            "data_network": entry.and_then(|e| e.data),
            "transport_network": entry.and_then(|e| e.transport),
            "inspection": entry.and_then(|e| e.preparation.as_ref()).and_then(|p| p.inspection.as_ref()),
            "attachment": entry.and_then(|e| e.preparation.as_ref()).and_then(|p| p.mount.as_ref()),
            "fresh_transport": entry.and_then(|e| e.preparation.as_ref()).and_then(|p| p.fresh_transport.as_ref()),
            "wireguard": entry.and_then(|e| e.preparation.as_ref()).map(|p| &p.wireguard),
            "host_link": entry.and_then(|e|e.preparation.as_ref()).map(|p|&p.host_link),
            "pending_host_link":pending_host_link,
            "producer_creation": entry.and_then(|e| e.preparation.as_ref()).and_then(|p| p.producer_creation.as_ref()),
            "entry_phase": entry.map(|e|e.phase),
            "entry_links_absent": entry.is_some_and(|e|e.links.is_none()),
            "entry_attempt_absent": entry.is_some_and(|e|e.attempt.is_none()),
            "entry_terminal_absent": entry.is_some_and(|e|e.terminal.is_none()),
            "entry_producer": entry.and_then(|e|e.producer.as_ref()),
            "pending_producer_binding": pending_producer_binding,
            "entry_producer_absent": entry.is_some_and(|e|e.producer.is_none()),
            "bootstrap": entry.and_then(|e|e.preparation.as_ref()).map(|p| &p.bootstrap),
            "bootstrap_queries": entry.and_then(|e|e.preparation.as_ref()).map(|p| &p.bootstrap_queries),
            "producer_binding_query": entry.and_then(|e| e.preparation.as_ref()).and_then(|p| p.producer_binding_query.as_ref()),
            "producer_binding": entry.and_then(|e| e.preparation.as_ref()).and_then(|p| p.producer_binding.as_ref()),
            "producer_query": entry.and_then(|e| e.preparation.as_ref()).and_then(|p| p.producer_query.as_ref()),
            "netfilter": entry.and_then(|e| e.preparation.as_ref()).map(|p| &p.netfilter),
            "quarantine_query": entry.and_then(|e| e.preparation.as_ref()).and_then(|p| p.quarantine_query.as_ref()),
            "movement_query": entry.and_then(|e| e.preparation.as_ref()).and_then(|p| p.movement_query.as_ref()),
            "pending_wireguard":pending_wireguard,"pending_producer_creation":pending_producer,
            "owner_host_anchor_present": journal.record.owner_network.is_some(),
            "canonical_owner_epoch": journal.record.owner_epoch,
            "canonical_result_present": entry.and_then(|e| e.preparation.as_ref()).is_some_and(|h| h.result.is_some()),
            "service_reserved": shared.services.borrow().contains(&native.history.member),
            "canonical_pending": shared.pending.borrow().is_some(), "mutation_fenced": shared.fenced.get(),
            "native_children_reaped": self.children_reaped(),
            "member_native_jobs_collected": shared.native_jobs.borrow_mut().drained(&native.history.member)?,
            "writers": writers});
        value["pending_bootstrap"] = serde_json::json!(
            shared
                .pending
                .borrow()
                .as_ref()
                .and_then(|r| r
                    .entries
                    .iter()
                    .find(|e| e.exit_id == native.history.member))
                .and_then(|e| e.preparation.as_ref())
                .map(|p| &p.bootstrap)
        );
        Ok(value)
    }
}

#[cfg(test)]
impl ValidationReceipt {
    pub(crate) fn lab_wrong_member(mut self) -> Self {
        self.member.push_str("-mismatch");
        self
    }
}

/// Retained, constructor-origin link between a verified public result and the
/// exact canonical preparation service. It is not a namespace/mount permit.
pub(crate) struct PublicBinding {
    creator: u32,
    shared: Rc<SharedJournal>,
    member: String,
    result: PublicValidation,
    owner: OwnerDomainRecord,
}
impl ValidationReceipt {
    pub(crate) fn bind_current(&self, server: &Server) -> Result<PublicBinding> {
        let native = server.native.as_ref().ok_or(Error::Interrupted)?;
        native.require_creator()?;
        if self.creator != native.creator
            || !Rc::ptr_eq(&self.shared, &native.transaction.shared)
            || self.member != native.history.member
            || !native.result_issued
            || native.failure.is_some()
            || native.pending.is_some()
            || native.queued_at.is_some()
            || self.shared.fenced.get()
            || !self.shared.services.borrow().contains(&self.member)
        {
            return Err(Error::OwnershipMismatch);
        }
        let journal = self.shared.journal.borrow();
        let entry = journal
            .record
            .entries
            .iter()
            .find(|entry| entry.exit_id == self.member)
            .ok_or(Error::OwnershipMismatch)?;
        let history = entry.preparation.as_ref().ok_or(Error::OwnershipMismatch)?;
        history.validate(&journal.record, entry)?;
        if history.result.as_ref() != Some(&self.result)
            || history.birth.as_ref() != Some(&self.birth)
            || native.owner.record(&native.domains)? != history.owner
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(PublicBinding {
            creator: self.creator,
            shared: self.shared.clone(),
            member: self.member.clone(),
            result: self.result.clone(),
            owner: history.owner.clone(),
        })
    }
}
impl PublicBinding {
    pub(crate) fn verify_initial(&self, server: &Server, spec: &LaunchSpec) -> Result<()> {
        self.verify_initial_native(server, spec, None)
    }
    pub(crate) fn verify_initial_except_mount(
        &self,
        server: &Server,
        spec: &LaunchSpec,
        mounted: &kernel::namespace_attachment::Mounted,
    ) -> Result<()> {
        mounted.verify_current()?;
        mounted.only_member_job(server)?;
        self.verify_initial_native(server, spec, Some(mounted))
    }
    fn verify_initial_native(
        &self,
        server: &Server,
        spec: &LaunchSpec,
        mounted: Option<&kernel::namespace_attachment::Mounted>,
    ) -> Result<()> {
        let native = server.native.as_ref().ok_or(Error::Interrupted)?;
        native.require_creator()?;
        let shared = &native.transaction.shared;
        let journal = shared.journal.borrow();
        spec.validate()?;
        if self.creator != std::process::id()
            || !Rc::ptr_eq(&self.shared, shared)
            || self.member != native.history.member
            || self.member != spec.exit.exit_id
            || !same_allocation(&spec.allocation, &journal.record.allocation)?
            || journal.record.primary_exit_id != self.member
            || journal.record.base_network.is_some()
            || journal.record.owner_network.is_none()
            || journal.record.entries.len() != 1
            || shared.services.borrow().len() != 1
            || !shared.services.borrow().contains(&self.member)
            || shared.pending.borrow().is_some()
            || shared.fenced.get()
            || native.failure.is_some()
            || native.pending.is_some()
            || native.queued_at.is_some()
            || native.owner.record(&native.domains)? != self.owner
        {
            return Err(Error::OwnershipMismatch);
        }
        let entry = &journal.record.entries[0];
        if entry.exit_id != self.member
            || entry.phase != Phase::Creating
            || entry.data.is_some()
            || entry.transport.is_some()
            || entry.links.is_some()
            || entry.producer.is_some()
            || entry.attempt.is_some()
            || entry.terminal.is_some()
            || entry
                .preparation
                .as_ref()
                .and_then(|history| history.result.as_ref())
                != Some(&self.result)
            || (mounted.is_none() && !shared.native_jobs.borrow_mut().drained(&self.member)?)
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
    pub(crate) fn public_result(&self) -> [u8; 32] {
        self.result.report
    }
}

#[cfg(test)]
impl Server {
    pub(crate) fn lab_hold_bootstrap_result(&mut self) -> Result<()> {
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        n.require_creator()?;
        if n.pending.is_some()
            || n.continuation
                .as_ref()
                .is_none_or(|c| c.phase != "bootstrap_data_intent")
            || n.lab_hold.is_some()
            || n.lab_writers.len() != 102
        {
            return Err(Error::OwnershipMismatch);
        }
        n.lab_hold = Some("bootstrap_data_result");
        Ok(())
    }
    pub(crate) fn lab_bootstrap_result_charge(
        &self,
        failed: bool,
    ) -> Result<(kernel::LabJournalCharge, serde_json::Value)> {
        self.lab_result_charge(failed, 104, "bootstrap_data_result")
    }
}

#[cfg(test)]
impl Server {
    pub(crate) fn lab_hold_bootstrap_intent(&mut self) -> Result<()> {
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        n.require_creator()?;
        if n.pending.is_some()
            || n.lab_hold.is_some()
            || n.lab_writers.len() != 90
            || n.continuation
                .as_ref()
                .is_none_or(|c| c.phase != "bootstrap_host_intent")
        {
            return Err(Error::OwnershipMismatch);
        }
        n.lab_hold = Some("bootstrap_host_intent");
        Ok(())
    }
    pub(crate) fn lab_release_bootstrap_intent(&mut self) -> Result<()> {
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        n.require_creator()?;
        if n.lab_hold != Some("bootstrap_host_intent")
            || n.lab_writers.len() != 91
            || n.continuation
                .as_ref()
                .is_none_or(|c| c.phase != "bootstrap_host_intent")
        {
            return Err(Error::OwnershipMismatch);
        }
        n.pending
            .as_mut()
            .ok_or(Error::Interrupted)?
            .child
            .lab_release_checkpoint()?;
        n.lab_hold = None;
        Ok(())
    }
}
