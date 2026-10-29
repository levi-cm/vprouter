//! Canonical intent/birth/result for the fixed no-fork Docker policy query.
//! These are owner-only continuations; no guard request can construct them.
use super::super::super::attachment::{InspectionRequest, QueryFacts, QueryKind};
use super::*;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct History {
    kind: QueryKind,
    initial: Option<Initial>,
    request: [u8; 32],
    requested_at: f64,
    deadline: f64,
    birth: Option<ValidationBirth>,
    facts: Option<QueryFacts>,
    verified_at: Option<f64>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Initial {
    request: [u8; 32],
    birth: ValidationBirth,
    facts: QueryFacts,
    verified_at: f64,
}
impl History {
    pub(super) fn validate_bootstrap(&self, p: &super::History, index: usize) -> Result<()> {
        if self.kind.bootstrap_index() != Some(index) || self.initial.is_some() {
            return Err(Error::OwnershipMismatch);
        }
        self.validate(p)
    }
    pub(super) fn completed_bootstrap(&self, index: usize) -> Result<([u8; 32], f64, f64)> {
        if self.kind.bootstrap_index() != Some(index)
            || self.initial.is_some()
            || self.birth.is_none()
            || self.facts.is_none()
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok((
            self.request,
            self.requested_at,
            self.verified_at.ok_or(Error::OwnershipMismatch)?,
        ))
    }
    pub(super) fn validate_quarantine(&self, preparation: &super::History) -> Result<()> {
        if self.kind != QueryKind::QuarantineRecheck || self.initial.is_some() {
            return Err(Error::OwnershipMismatch);
        }
        self.validate(preparation)
    }
    pub(super) fn completed_quarantine(&self) -> Result<([u8; 32], f64, f64)> {
        if self.kind != QueryKind::QuarantineRecheck
            || self.initial.is_some()
            || self.birth.is_none()
            || self.facts.is_none()
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok((
            self.request,
            self.requested_at,
            self.verified_at.ok_or(Error::OwnershipMismatch)?,
        ))
    }
    pub(super) fn validate_producer(&self, preparation: &super::History) -> Result<()> {
        if self.kind != QueryKind::ProducerRecheck || self.initial.is_some() {
            return Err(Error::OwnershipMismatch);
        }
        self.validate(preparation)
    }
    pub(super) fn completed_producer(&self) -> Result<([u8; 32], f64, f64)> {
        if self.kind != QueryKind::ProducerRecheck
            || self.initial.is_some()
            || self.birth.is_none()
            || self.facts.is_none()
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok((
            self.request,
            self.requested_at,
            self.verified_at.ok_or(Error::OwnershipMismatch)?,
        ))
    }
    pub(super) fn validate_producer_binding(&self, preparation: &super::History) -> Result<()> {
        if self.kind != QueryKind::ProducerBindingRecheck || self.initial.is_some() {
            return Err(Error::OwnershipMismatch);
        }
        self.validate(preparation)
    }
    pub(super) fn completed_producer_binding(&self) -> Result<([u8; 32], f64, f64)> {
        if self.kind != QueryKind::ProducerBindingRecheck
            || self.initial.is_some()
            || self.birth.is_none()
            || self.facts.is_none()
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok((
            self.request,
            self.requested_at,
            self.verified_at.ok_or(Error::OwnershipMismatch)?,
        ))
    }
    pub(super) fn completed_movement(&self) -> Result<([u8; 32], f64, f64, f64)> {
        if self.kind != QueryKind::MovementRecheck
            || self.initial.is_some()
            || self.facts.is_none()
            || self.birth.is_none()
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok((
            self.request,
            self.requested_at,
            self.deadline,
            self.verified_at.ok_or(Error::OwnershipMismatch)?,
        ))
    }

    pub(super) fn validate_movement(&self, preparation: &super::History) -> Result<()> {
        if self.kind != QueryKind::MovementRecheck || self.initial.is_some() {
            return Err(Error::OwnershipMismatch);
        }
        self.validate(preparation)
    }
    pub(super) fn validate(&self, preparation: &super::History) -> Result<()> {
        let public = preparation
            .result
            .as_ref()
            .ok_or(Error::OwnershipMismatch)?;
        if self.request == [0; 32]
            || !self.requested_at.is_finite()
            || self.requested_at < public.verified_at
            || self.deadline != self.requested_at + 2.
        {
            return Err(Error::OwnershipMismatch);
        }
        match (self.kind, &self.initial) {
            (QueryKind::Initial, None) => {}
            (QueryKind::Recheck, Some(initial)) => {
                if initial.request == [0; 32]
                    || initial.request == self.request
                    || initial.birth.pid <= 1
                    || initial.birth.start == 0
                    || initial.birth.deadline != self.deadline
                    || !initial.birth.born_at.is_finite()
                    || initial.birth.born_at < self.requested_at
                    || !initial.verified_at.is_finite()
                    || initial.verified_at < initial.birth.born_at
                    || initial.verified_at >= self.deadline
                    || initial.facts.pid <= 1
                    || initial.facts.pid > i32::MAX as u32
                    || self
                        .birth
                        .as_ref()
                        .is_some_and(|b| b.born_at < initial.verified_at)
                    || self
                        .facts
                        .as_ref()
                        .is_some_and(|facts| facts != &initial.facts)
                {
                    return Err(Error::OwnershipMismatch);
                }
            }
            (QueryKind::ProducerRecheck, None) => {
                if preparation.wireguard.len() != 5
                    || preparation.netfilter.len() != 6
                    || preparation
                        .netfilter
                        .iter()
                        .any(|op| op.completed_at().is_err())
                    || self.requested_at < preparation.netfilter[5].completed_at()?
                {
                    return Err(Error::OwnershipMismatch);
                }
                let (original, _) = preparation
                    .inspection
                    .as_ref()
                    .ok_or(Error::OwnershipMismatch)?
                    .completed_recheck()?;
                if self.facts.as_ref().is_some_and(|facts| facts != &original) {
                    return Err(Error::OwnershipMismatch);
                }
            }
            (QueryKind::ProducerBindingRecheck, None) => {
                if self.requested_at
                    < preparation
                        .producer_creation
                        .as_ref()
                        .ok_or(Error::OwnershipMismatch)?
                        .completed_at()?
                    || preparation.wireguard.len() != 5
                    || preparation.netfilter.len() != 6
                    || preparation
                        .netfilter
                        .iter()
                        .any(|op| op.completed_at().is_err())
                    || self.requested_at < preparation.netfilter[5].completed_at()?
                {
                    return Err(Error::OwnershipMismatch);
                }
                let (original, _) = preparation
                    .inspection
                    .as_ref()
                    .ok_or(Error::OwnershipMismatch)?
                    .completed_recheck()?;
                if self.facts.as_ref().is_some_and(|facts| facts != &original) {
                    return Err(Error::OwnershipMismatch);
                }
            }
            (kind, None) if kind.bootstrap_index().is_some() => {
                let index = kind.bootstrap_index().ok_or(Error::OwnershipMismatch)?;
                let prior = if index == 0 {
                    preparation
                        .host_link
                        .get(3)
                        .ok_or(Error::OwnershipMismatch)?
                        .completed_host_addition_at()?
                } else {
                    preparation
                        .bootstrap
                        .get(index - 1)
                        .ok_or(Error::OwnershipMismatch)?
                        .completed_at()?
                };
                if preparation.host_link.len() != 4 || self.requested_at < prior {
                    return Err(Error::OwnershipMismatch);
                }
                let (original, _) = preparation
                    .inspection
                    .as_ref()
                    .ok_or(Error::OwnershipMismatch)?
                    .completed_recheck()?;
                if self.facts.as_ref().is_some_and(|facts| facts != &original) {
                    return Err(Error::OwnershipMismatch);
                }
            }
            (QueryKind::QuarantineRecheck, None) => {
                if preparation.wireguard.len() != 5
                    || !(5..=6).contains(&preparation.netfilter.len())
                    || self.requested_at < preparation.wireguard[4].completed_move_at()?
                    || self.requested_at < preparation.netfilter[4].completed_data_sockets_at()?
                {
                    return Err(Error::OwnershipMismatch);
                }
                let (original, _) = preparation
                    .inspection
                    .as_ref()
                    .ok_or(Error::OwnershipMismatch)?
                    .completed_recheck()?;
                if self.facts.as_ref().is_some_and(|facts| facts != &original) {
                    return Err(Error::OwnershipMismatch);
                }
            }
            (QueryKind::MovementRecheck, None) => {
                if !(4..=5).contains(&preparation.wireguard.len())
                    || self.requested_at < preparation.wireguard[2].completed_query_at()?
                    || self.requested_at < preparation.wireguard[3].completed_data_sockets_at()?
                {
                    return Err(Error::OwnershipMismatch);
                }
                let (original, _) = preparation
                    .inspection
                    .as_ref()
                    .ok_or(Error::OwnershipMismatch)?
                    .completed_recheck()?;
                if self.facts.as_ref().is_some_and(|facts| facts != &original) {
                    return Err(Error::OwnershipMismatch);
                }
            }
            (QueryKind::AttachmentRecheck, None) => {
                let (mount_digest, requested, deadline, mounted_at) = preparation
                    .mount
                    .as_ref()
                    .ok_or(Error::OwnershipMismatch)?
                    .query_binding();
                let (original, _) = preparation
                    .inspection
                    .as_ref()
                    .ok_or(Error::OwnershipMismatch)?
                    .completed_recheck()?;
                if mount_digest == [0; 32]
                    || self.requested_at != requested
                    || self.deadline != deadline
                    || mounted_at.is_none()
                    || self
                        .birth
                        .as_ref()
                        .is_some_and(|b| b.born_at < mounted_at.unwrap_or(f64::INFINITY))
                    || self.facts.as_ref().is_some_and(|facts| facts != &original)
                {
                    return Err(Error::OwnershipMismatch);
                }
            }
            _ => return Err(Error::OwnershipMismatch),
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
        match (&self.facts, self.verified_at) {
            (None, None) => {}
            (Some(facts), Some(at)) => {
                let birth = self.birth.as_ref().ok_or(Error::OwnershipMismatch)?;
                if facts.pid <= 1
                    || facts.pid > i32::MAX as u32
                    || !at.is_finite()
                    || at < birth.born_at
                    || at >= self.deadline
                {
                    return Err(Error::OwnershipMismatch);
                }
            }
            _ => return Err(Error::OwnershipMismatch),
        }
        Ok(())
    }
}

impl History {
    pub(super) fn completed_recheck(&self) -> Result<(QueryFacts, f64)> {
        if self.kind != QueryKind::Recheck || self.initial.is_none() {
            return Err(Error::OwnershipMismatch);
        }
        Ok((
            self.facts.clone().ok_or(Error::OwnershipMismatch)?,
            self.verified_at.ok_or(Error::OwnershipMismatch)?,
        ))
    }
    pub(super) fn completed_mount_query(&self) -> Result<(QueryFacts, f64)> {
        if self.kind != QueryKind::AttachmentRecheck || self.initial.is_some() {
            return Err(Error::OwnershipMismatch);
        }
        Ok((
            self.facts.clone().ok_or(Error::OwnershipMismatch)?,
            self.verified_at.ok_or(Error::OwnershipMismatch)?,
        ))
    }
}
fn selected(preparation: &super::History, kind: QueryKind) -> Option<&History> {
    match kind {
        QueryKind::AttachmentRecheck => preparation.mount.as_ref().and_then(|m| m.query.as_ref()),
        QueryKind::MovementRecheck => preparation.movement_query.as_ref(),
        QueryKind::QuarantineRecheck => preparation.quarantine_query.as_ref(),
        QueryKind::ProducerRecheck => preparation.producer_query.as_ref(),
        QueryKind::ProducerBindingRecheck => preparation.producer_binding_query.as_ref(),
        kind if kind.bootstrap_index().is_some() => {
            preparation.bootstrap_queries[kind.bootstrap_index()?].as_ref()
        }
        _ => preparation.inspection.as_ref(),
    }
}
pub(crate) struct Intent {
    creator: u32,
    shared: Rc<SharedJournal>,
    member: String,
    owner: Rc<OwnerDomain>,
    domains: Domains,
    history: History,
    lease: MutatorLease,
}
impl Intent {
    pub(crate) fn verify(&self, request: &InspectionRequest) -> Result<()> {
        kernel::owner_admission_permitted()?;
        if self.creator != std::process::id()
            || !vprouter_core::secret_boundary::pristine()
            || request.digest() != self.history.request
            || request.requested_at() != self.history.requested_at
            || request.deadline() != self.history.deadline
            || self.shared.fenced.get()
            || self.shared.pending.borrow().is_some()
            || !self.shared.services.borrow().contains(&self.member)
        {
            return Err(Error::OwnershipMismatch);
        }
        request.check_deadline()?;
        let journal = self.shared.journal.borrow();
        if journal.record.owner_epoch.as_ref() != Some(&self.owner.record(&self.domains)?) {
            return Err(Error::OwnershipMismatch);
        }
        let entry = journal
            .record
            .entries
            .iter()
            .find(|e| e.exit_id == self.member)
            .ok_or(Error::OwnershipMismatch)?;
        let preparation = entry.preparation.as_ref().ok_or(Error::OwnershipMismatch)?;
        if entry.phase != Phase::Creating
            || match self.history.kind {
                QueryKind::MovementRecheck
                | QueryKind::QuarantineRecheck
                | QueryKind::ProducerRecheck
                | QueryKind::ProducerBindingRecheck
                | QueryKind::BootstrapHostRecheck
                | QueryKind::BootstrapTransportRecheck
                | QueryKind::BootstrapDataRecheck => {
                    entry.data.is_none() || entry.transport.is_none()
                }
                _ => entry.data.is_some() || entry.transport.is_some(),
            }
            || selected(preparation, self.history.kind) != Some(&self.history)
            || self.history.birth.is_some()
        {
            return Err(Error::OwnershipMismatch);
        }
        self.history.validate(preparation)
    }
    pub(crate) fn prepare(&mut self, request: &InspectionRequest) -> Result<()> {
        self.verify(request)?;
        self.lease
            .prepare_native_job(kernel::NativeJobKind::DockerInspection)
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
    birth: ValidationBirth,
    request: [u8; 32],
}
impl Gate {
    pub(crate) fn verify(&self, intent: &Intent, birth: &ValidationBirth) -> Result<()> {
        if self.creator != std::process::id()
            || self.creator != intent.creator
            || !Rc::ptr_eq(&self.shared, &intent.shared)
            || self.member != intent.member
            || self.request != intent.history.request
            || &self.birth != birth
            || self.shared.fenced.get()
            || self.shared.pending.borrow().is_some()
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
            .and_then(|p| selected(p, intent.history.kind))
            .ok_or(Error::OwnershipMismatch)?;
        if history.request != self.request
            || history.birth.as_ref() != Some(birth)
            || history.facts.is_some()
        {
            return Err(Error::OwnershipMismatch);
        }
        original_frame(history.requested_at, vprouter_core::health::boot_seconds())
    }
}
pub(crate) struct Receipt {
    creator: u32,
    shared: Rc<SharedJournal>,
    member: String,
    history: History,
}
impl Receipt {
    pub(crate) fn verify_movement(
        &self,
        accepted: &kernel::docker_query::Accepted,
        server: &Server,
    ) -> Result<()> {
        let n = server.native.as_ref().ok_or(Error::Interrupted)?;
        n.require_creator()?;
        accepted.require()?;
        if self.creator != n.creator
            || !Rc::ptr_eq(&self.shared, &n.transaction.shared)
            || self.member != n.history.member
            || self.history.kind != QueryKind::MovementRecheck
            || self.history.request != accepted.request().digest()
            || self.history.facts.as_ref() != Some(accepted.facts())
            || self.history.verified_at.is_none()
            || self.history.birth.is_none()
        {
            return Err(Error::OwnershipMismatch);
        }
        let j = self.shared.journal.borrow();
        let p = j
            .record
            .entries
            .iter()
            .find(|e| e.exit_id == self.member)
            .and_then(|e| e.preparation.as_ref())
            .ok_or(Error::OwnershipMismatch)?;
        if p.movement_query.as_ref() != Some(&self.history) {
            return Err(Error::OwnershipMismatch);
        }
        self.history.validate_movement(p)
    }
    pub(crate) fn verify_quarantine(
        &self,
        accepted: &kernel::docker_query::Accepted,
        server: &Server,
    ) -> Result<()> {
        let n = server.native.as_ref().ok_or(Error::Interrupted)?;
        n.require_creator()?;
        accepted.require()?;
        if self.creator != n.creator
            || !Rc::ptr_eq(&self.shared, &n.transaction.shared)
            || self.member != n.history.member
            || self.history.kind != QueryKind::QuarantineRecheck
            || self.history.request != accepted.request().digest()
            || self.history.facts.as_ref() != Some(accepted.facts())
            || self.history.verified_at.is_none()
            || self.history.birth.is_none()
        {
            return Err(Error::OwnershipMismatch);
        }
        let j = self.shared.journal.borrow();
        let p = j
            .record
            .entries
            .iter()
            .find(|e| e.exit_id == self.member)
            .and_then(|e| e.preparation.as_ref())
            .ok_or(Error::OwnershipMismatch)?;
        if p.quarantine_query.as_ref() != Some(&self.history) {
            return Err(Error::OwnershipMismatch);
        }
        self.history.validate_quarantine(p)
    }
    pub(crate) fn verify_producer(
        &self,
        accepted: &kernel::docker_query::Accepted,
        server: &Server,
    ) -> Result<()> {
        let n = server.native.as_ref().ok_or(Error::Interrupted)?;
        n.require_creator()?;
        accepted.require()?;
        if self.creator != n.creator
            || !Rc::ptr_eq(&self.shared, &n.transaction.shared)
            || self.member != n.history.member
            || self.history.kind != QueryKind::ProducerRecheck
            || self.history.request != accepted.request().digest()
            || self.history.facts.as_ref() != Some(accepted.facts())
            || self.history.verified_at.is_none()
            || self.history.birth.is_none()
        {
            return Err(Error::OwnershipMismatch);
        }
        let j = self.shared.journal.borrow();
        let p = j
            .record
            .entries
            .iter()
            .find(|e| e.exit_id == self.member)
            .and_then(|e| e.preparation.as_ref())
            .ok_or(Error::OwnershipMismatch)?;
        if p.producer_query.as_ref() != Some(&self.history) {
            return Err(Error::OwnershipMismatch);
        }
        self.history.validate_producer(p)
    }
    pub(crate) fn verify_producer_binding(
        &self,
        accepted: &kernel::docker_query::Accepted,
        server: &Server,
    ) -> Result<()> {
        let n = server.native.as_ref().ok_or(Error::Interrupted)?;
        n.require_creator()?;
        accepted.require()?;
        if self.creator != n.creator
            || !Rc::ptr_eq(&self.shared, &n.transaction.shared)
            || self.member != n.history.member
            || self.history.kind != QueryKind::ProducerBindingRecheck
            || self.history.request != accepted.request().digest()
            || self.history.facts.as_ref() != Some(accepted.facts())
            || self.history.verified_at.is_none()
            || self.history.birth.is_none()
        {
            return Err(Error::OwnershipMismatch);
        }
        let j = self.shared.journal.borrow();
        let p = j
            .record
            .entries
            .iter()
            .find(|e| e.exit_id == self.member)
            .and_then(|e| e.preparation.as_ref())
            .ok_or(Error::OwnershipMismatch)?;
        if p.producer_binding_query.as_ref() != Some(&self.history) {
            return Err(Error::OwnershipMismatch);
        }
        self.history.validate_producer_binding(p)
    }
    pub(crate) fn verify_bootstrap(
        &self,
        accepted: &kernel::docker_query::Accepted,
        server: &Server,
    ) -> Result<()> {
        let n = server.native.as_ref().ok_or(Error::Interrupted)?;
        n.require_creator()?;
        accepted.require()?;
        if self.creator != n.creator
            || !Rc::ptr_eq(&self.shared, &n.transaction.shared)
            || self.member != n.history.member
            || self.history.kind.bootstrap_index().is_none()
            || self.history.kind != accepted.request().kind()
            || self.history.request != accepted.request().digest()
            || self.history.facts.as_ref() != Some(accepted.facts())
            || self.history.verified_at.is_none()
            || self.history.birth.is_none()
        {
            return Err(Error::OwnershipMismatch);
        }
        let j = self.shared.journal.borrow();
        let p = j
            .record
            .entries
            .iter()
            .find(|e| e.exit_id == self.member)
            .and_then(|e| e.preparation.as_ref())
            .ok_or(Error::OwnershipMismatch)?;
        if selected(p, self.history.kind) != Some(&self.history) {
            return Err(Error::OwnershipMismatch);
        }
        self.history.validate_bootstrap(
            p,
            self.history
                .kind
                .bootstrap_index()
                .ok_or(Error::OwnershipMismatch)?,
        )
    }
    pub(crate) fn verify(
        &self,
        intent: &Intent,
        birth: &ValidationBirth,
        facts: &QueryFacts,
        at: f64,
    ) -> Result<()> {
        if self.creator != std::process::id()
            || self.creator != intent.creator
            || !Rc::ptr_eq(&self.shared, &intent.shared)
            || self.member != intent.member
            || self.history.request != intent.history.request
            || self.history.birth.as_ref() != Some(birth)
            || self.history.facts.as_ref() != Some(facts)
            || self.history.verified_at != Some(at)
            || self.shared.fenced.get()
            || self.shared.pending.borrow().is_some()
        {
            return Err(Error::OwnershipMismatch);
        }
        let journal = self.shared.journal.borrow();
        let preparation = journal
            .record
            .entries
            .iter()
            .find(|e| e.exit_id == self.member)
            .and_then(|e| e.preparation.as_ref())
            .ok_or(Error::OwnershipMismatch)?;
        if selected(preparation, self.history.kind) != Some(&self.history) {
            return Err(Error::OwnershipMismatch);
        }
        self.history.validate(preparation)?;
        original_frame(
            self.history.requested_at,
            vprouter_core::health::boot_seconds(),
        )
    }
}
fn phase(kind: QueryKind, part: &'static str) -> &'static str {
    match (kind, part) {
        (QueryKind::BootstrapHostRecheck, "inspection_intent") => "bootstrap_host_query_intent",
        (QueryKind::BootstrapHostRecheck, "inspection_birth") => "bootstrap_host_query_birth",
        (QueryKind::BootstrapHostRecheck, "inspection_result") => "bootstrap_host_query_result",
        (QueryKind::BootstrapTransportRecheck, "inspection_intent") => {
            "bootstrap_transport_query_intent"
        }
        (QueryKind::BootstrapTransportRecheck, "inspection_birth") => {
            "bootstrap_transport_query_birth"
        }
        (QueryKind::BootstrapTransportRecheck, "inspection_result") => {
            "bootstrap_transport_query_result"
        }
        (QueryKind::BootstrapDataRecheck, "inspection_intent") => "bootstrap_data_query_intent",
        (QueryKind::BootstrapDataRecheck, "inspection_birth") => "bootstrap_data_query_birth",
        (QueryKind::BootstrapDataRecheck, "inspection_result") => "bootstrap_data_query_result",
        (QueryKind::ProducerRecheck, "inspection_intent") => "producer_query_intent",
        (QueryKind::ProducerBindingRecheck, "inspection_intent") => "producer_binding_query_intent",
        (QueryKind::ProducerRecheck, "inspection_birth") => "producer_query_birth",
        (QueryKind::ProducerBindingRecheck, "inspection_birth") => "producer_binding_query_birth",
        (QueryKind::ProducerRecheck, "inspection_result") => "producer_query_result",
        (QueryKind::ProducerBindingRecheck, "inspection_result") => "producer_binding_query_result",
        (QueryKind::QuarantineRecheck, "inspection_intent") => "quarantine_query_intent",
        (QueryKind::QuarantineRecheck, "inspection_birth") => "quarantine_query_birth",
        (QueryKind::QuarantineRecheck, "inspection_result") => "quarantine_query_result",
        (QueryKind::MovementRecheck, "inspection_intent") => "movement_query_intent",
        (QueryKind::MovementRecheck, "inspection_birth") => "movement_query_birth",
        (QueryKind::MovementRecheck, "inspection_result") => "movement_query_result",
        (QueryKind::AttachmentRecheck, "inspection_intent") => "attachment_query_intent",
        (QueryKind::AttachmentRecheck, "inspection_birth") => "attachment_query_birth",
        (QueryKind::AttachmentRecheck, "inspection_result") => "attachment_query_result",
        _ => part,
    }
}
impl Native {
    fn inspection(&self, kind: QueryKind) -> Result<History> {
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
            .and_then(|p| selected(p, kind).cloned())
            .ok_or(Error::OwnershipMismatch)
    }
    fn queue_inspection(
        &mut self,
        history: History,
        phase: &'static str,
        request: Rc<InspectionRequest>,
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
        let preparation = proposed
            .entries
            .iter_mut()
            .find(|e| e.exit_id == self.history.member)
            .and_then(|e| e.preparation.as_mut())
            .ok_or(Error::OwnershipMismatch)?;
        history.validate(preparation)?;
        let started_at = history.requested_at;
        match history.kind {
            QueryKind::MovementRecheck => preparation.movement_query = Some(history),
            QueryKind::QuarantineRecheck => preparation.quarantine_query = Some(history),
            QueryKind::ProducerRecheck => preparation.producer_query = Some(history),
            QueryKind::ProducerBindingRecheck => preparation.producer_binding_query = Some(history),
            kind if kind.bootstrap_index().is_some() => {
                preparation.bootstrap_queries
                    [kind.bootstrap_index().ok_or(Error::OwnershipMismatch)?] = Some(history)
            }
            QueryKind::AttachmentRecheck => {
                preparation
                    .mount
                    .as_mut()
                    .ok_or(Error::OwnershipMismatch)?
                    .query = Some(history)
            }
            _ => preparation.inspection = Some(history),
        }
        proposed.bind_anchor(
            &proposed.allocation,
            &proposed.primary_exit_id,
            proposed.base_network,
            proposed.owner_network,
        )?;
        shared.queue.borrow_mut().push(&self.history.member)?;
        self.continuation = Some(Continuation {
            quarantine_origin: matches!(
                request.kind(),
                QueryKind::QuarantineRecheck
                    | QueryKind::ProducerBindingRecheck
                    | QueryKind::BootstrapHostRecheck
                    | QueryKind::BootstrapTransportRecheck
                    | QueryKind::BootstrapDataRecheck
            )
            .then_some(quarantine::ProgressOrigin::Query(request)),
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
    pub(super) fn poll_inspection(&mut self, phase: &'static str) -> Result<bool> {
        self.require_creator()?;
        if let Some(error) = self.failure {
            self.collect();
            return Err(error);
        }
        if self.continuation.as_ref().is_none_or(|c| c.phase != phase) {
            return Err(Error::OwnershipMismatch);
        }
        match self.advance() {
            Ok(true) => {
                self.continuation = None;
                Ok(true)
            }
            Ok(false) => Ok(false),
            Err(error) => {
                self.fail(error);
                self.collect();
                Err(error)
            }
        }
    }
}
impl Server {
    pub(crate) fn start_inspection(&mut self, request: &Rc<InspectionRequest>) -> Result<()> {
        request.verify_service(self)?;
        request.check_deadline()?;
        let native = self.native.as_mut().ok_or(Error::Interrupted)?;
        let previous = native
            .transaction
            .shared
            .journal
            .borrow()
            .record
            .entries
            .iter()
            .find(|e| e.exit_id == native.history.member)
            .and_then(|e| e.preparation.as_ref())
            .and_then(|p| selected(p, request.kind()).cloned());
        let initial = match (request.kind(), previous) {
            (QueryKind::Initial, None)
            | (QueryKind::AttachmentRecheck, None)
            | (QueryKind::MovementRecheck, None)
            | (QueryKind::QuarantineRecheck, None)
            | (QueryKind::ProducerRecheck, None)
            | (QueryKind::ProducerBindingRecheck, None)
            | (QueryKind::BootstrapHostRecheck, None)
            | (QueryKind::BootstrapTransportRecheck, None)
            | (QueryKind::BootstrapDataRecheck, None) => None,
            (QueryKind::Recheck, Some(previous))
                if previous.kind == QueryKind::Initial
                    && previous.initial.is_none()
                    && previous.requested_at == request.requested_at()
                    && previous.deadline == request.deadline() =>
            {
                Some(Initial {
                    request: previous.request,
                    birth: previous.birth.ok_or(Error::OwnershipMismatch)?,
                    facts: previous.facts.ok_or(Error::OwnershipMismatch)?,
                    verified_at: previous.verified_at.ok_or(Error::OwnershipMismatch)?,
                })
            }
            _ => return Err(Error::OwnershipMismatch),
        };
        native.queue_inspection(
            History {
                kind: request.kind(),
                initial,
                request: request.digest(),
                requested_at: request.requested_at(),
                deadline: request.deadline(),
                birth: None,
                facts: None,
                verified_at: None,
            },
            phase(request.kind(), "inspection_intent"),
            request.clone(),
        )
    }
    pub(crate) fn poll_inspection_intent(
        &mut self,
        request: &InspectionRequest,
    ) -> Result<Option<Intent>> {
        request.check_deadline()?;
        let native = self.native.as_mut().ok_or(Error::Interrupted)?;
        if !native.poll_inspection(phase(request.kind(), "inspection_intent"))? {
            return Ok(None);
        }
        let intent = Intent {
            creator: native.creator,
            shared: native.transaction.shared.clone(),
            member: native.history.member.clone(),
            owner: native.owner.clone(),
            domains: native.domains.clone(),
            history: native.inspection(request.kind())?,
            lease: native.transaction.retain_allocation_lease()?,
        };
        intent.verify(request)?;
        Ok(Some(intent))
    }
    pub(crate) fn start_inspection_birth(
        &mut self,
        child: &kernel::docker_query::Child,
    ) -> Result<()> {
        child.bind_service(self)?;
        let native = self.native.as_mut().ok_or(Error::Interrupted)?;
        let mut history = native.inspection(child.kind())?;
        if history.birth.is_some() {
            return Err(Error::OwnershipMismatch);
        }
        history.birth = Some(child.birth()?);
        native.queue_inspection(
            history,
            phase(child.kind(), "inspection_birth"),
            child.original_request()?.clone(),
        )
    }
    pub(crate) fn poll_inspection_birth(
        &mut self,
        child: &kernel::docker_query::Child,
    ) -> Result<Option<Gate>> {
        child.bind_service(self)?;
        let native = self.native.as_mut().ok_or(Error::Interrupted)?;
        if !native.poll_inspection(phase(child.kind(), "inspection_birth"))? {
            return Ok(None);
        }
        let history = native.inspection(child.kind())?;
        if history.birth.as_ref() != Some(&child.birth()?) {
            return Err(Error::OwnershipMismatch);
        }
        Ok(Some(Gate {
            creator: native.creator,
            shared: native.transaction.shared.clone(),
            member: native.history.member.clone(),
            birth: child.birth()?,
            request: history.request,
        }))
    }
    pub(crate) fn start_inspection_result(
        &mut self,
        verified: &kernel::docker_query::Verified,
    ) -> Result<()> {
        verified.bind_service(self)?;
        let native = self.native.as_mut().ok_or(Error::Interrupted)?;
        let mut history = native.inspection(verified.kind())?;
        if history.birth.as_ref() != Some(&verified.birth()?) || history.facts.is_some() {
            return Err(Error::OwnershipMismatch);
        }
        history.facts = Some(verified.facts().clone());
        history.verified_at = Some(verified.verified_at());
        native.queue_inspection(
            history,
            phase(verified.kind(), "inspection_result"),
            verified.original_request()?.clone(),
        )
    }
    pub(crate) fn poll_inspection_result(
        &mut self,
        verified: &kernel::docker_query::Verified,
    ) -> Result<Option<Receipt>> {
        verified.bind_service(self)?;
        let native = self.native.as_mut().ok_or(Error::Interrupted)?;
        if !native.poll_inspection(phase(verified.kind(), "inspection_result"))? {
            return Ok(None);
        }
        let receipt = Receipt {
            creator: native.creator,
            shared: native.transaction.shared.clone(),
            member: native.history.member.clone(),
            history: native.inspection(verified.kind())?,
        };
        verified.verify_receipt(&receipt)?;
        Ok(Some(receipt))
    }
}

// Restricted to the already admitted quarantine query under its original end.
pub(crate) enum QuarantineProgress<'a> {
    Intent,
    Birth(&'a kernel::docker_query::Child),
    Result(&'a kernel::docker_query::Verified),
}
pub(super) fn apply_quarantine_progress(
    p: &mut super::History,
    request: &Rc<InspectionRequest>,
    stage: QuarantineProgress<'_>,
    server: &Server,
) -> Result<&'static str> {
    if !matches!(
        request.kind(),
        QueryKind::QuarantineRecheck
            | QueryKind::ProducerBindingRecheck
            | QueryKind::BootstrapHostRecheck
            | QueryKind::BootstrapTransportRecheck
            | QueryKind::BootstrapDataRecheck
    ) {
        return Err(Error::OwnershipMismatch);
    }
    request.check_deadline()?;
    let slot = match request.kind() {
        QueryKind::QuarantineRecheck => &mut p.quarantine_query,
        QueryKind::ProducerBindingRecheck => &mut p.producer_binding_query,
        kind if kind.bootstrap_index().is_some() => {
            &mut p.bootstrap_queries[kind.bootstrap_index().ok_or(Error::OwnershipMismatch)?]
        }
        _ => return Err(Error::OwnershipMismatch),
    };
    let mut expected = History {
        kind: request.kind(),
        initial: None,
        request: request.digest(),
        requested_at: request.requested_at(),
        deadline: request.deadline(),
        birth: None,
        facts: None,
        verified_at: None,
    };
    let name = match stage {
        QuarantineProgress::Intent => {
            if slot.is_some() {
                return Err(Error::OwnershipMismatch);
            }
            phase(request.kind(), "inspection_intent")
        }
        QuarantineProgress::Birth(child) => {
            child.require_request(request)?;
            child.bind_service(server)?;
            if slot.as_ref() != Some(&expected) {
                return Err(Error::OwnershipMismatch);
            }
            expected.birth = Some(child.birth()?);
            phase(request.kind(), "inspection_birth")
        }
        QuarantineProgress::Result(verified) => {
            verified.require_request(request)?;
            verified.bind_service(server)?;
            expected.birth = Some(verified.birth()?);
            if slot.as_ref() != Some(&expected) {
                return Err(Error::OwnershipMismatch);
            }
            expected.facts = Some(verified.facts().clone());
            expected.verified_at = Some(verified.verified_at());
            phase(request.kind(), "inspection_result")
        }
    };
    *slot = Some(expected);
    Ok(name)
}

#[cfg(test)]
mod movement_history_tests {
    use super::*;

    // Parsed scalar history is never a native receipt. This fixture isolates
    // the discriminator enforced by the dedicated canonical movement slot.
    fn prior_public_history() -> super::super::History {
        super::super::History {
            member: "a".into(),
            allocation: "public-allocation".into(),
            configuration: [1; 32],
            owner: super::super::OwnerDomainRecord {
                boot: "public-boot".into(),
                unit: "public-unit".into(),
                invocation: "public-invocation".into(),
                pid: 42,
                start: 1,
                cgroup: Identity { dev: 1, ino: 2 },
            },
            inputs: Vec::new(),
            requested_at: 1.,
            deadline: 3.,
            birth: None,
            result: Some(super::super::PublicValidation {
                report: [2; 32],
                selected: [3; 32],
                device_key: Some([4; 32]),
                verified_at: 2.,
            }),
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
        }
    }
    #[test]
    fn bootstrap_queries_have_distinct_slots_without_changing_empty_history_encoding() {
        let mut p = prior_public_history();
        let value = serde_json::to_value(&p).unwrap();
        assert!(value.get("bootstrap_queries").is_none());
        assert!(value.get("bootstrap").is_none());
        for (index, kind) in [
            QueryKind::BootstrapHostRecheck,
            QueryKind::BootstrapTransportRecheck,
            QueryKind::BootstrapDataRecheck,
        ]
        .into_iter()
        .enumerate()
        {
            p.bootstrap_queries[index] = Some(History {
                kind,
                initial: None,
                request: [index as u8 + 1; 32],
                requested_at: 1.,
                deadline: 3.,
                birth: None,
                facts: None,
                verified_at: None,
            });
            assert_eq!(selected(&p, kind), p.bootstrap_queries[index].as_ref());
            assert!(selected(&p, QueryKind::ProducerBindingRecheck).is_none());
        }
        for index in 0..3 {
            let original = p.bootstrap_queries[index].as_ref().unwrap();
            assert_eq!(original.kind.bootstrap_index(), Some(index));
            for wrong in (0..3).filter(|wrong| *wrong != index) {
                assert_eq!(
                    original.validate_bootstrap(&p, wrong),
                    Err(Error::OwnershipMismatch)
                );
            }
            // These metadata-only pending records cannot assert completion.
            assert!(original.completed_bootstrap(index).is_err());
        }
    }
    #[test]
    fn movement_history_slot_rejects_initial_query_discriminator() {
        let history: History = serde_json::from_value(serde_json::json!({
            "kind": "Initial", "initial": null, "request": ([7u8; 32].to_vec()),
            "requested_at": 10., "deadline": 12., "birth": null,
            "facts": null, "verified_at": null,
        }))
        .unwrap();
        let prior = prior_public_history();
        assert!(history.validate(&prior).is_ok());
        assert!(history.validate_movement(&prior).is_err());
        assert!(history.validate_quarantine(&prior).is_err());
        assert!(history.validate_producer(&prior).is_err());
        assert!(history.validate_producer_binding(&prior).is_err());
        assert!(history.completed_producer_binding().is_err());
        assert!(history.completed_quarantine().is_err());
    }
}
