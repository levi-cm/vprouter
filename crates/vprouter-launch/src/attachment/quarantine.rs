//! Fixed original quarantine operation requests. A parsed public declaration
//! and historical movement receipt alone never release a native mutation gate.
pub(crate) mod producer;
use super::super::{
    kernel,
    owned::{
        Identity,
        preparation::{Server, quarantine::Binding},
    },
};
use super::{
    Error, InspectionRequest, QueryKind, Result,
    host_declaration::{PinnedDeclaration, VerifiedWan},
};
use serde::{Deserialize, Serialize};
use std::{os::fd::BorrowedFd, rc::Rc};
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Scope {
    Host,
    Transport,
    Data,
}
impl Scope {
    fn native(self) -> vprouter_netfilter::Scope {
        match self {
            Self::Host => vprouter_netfilter::Scope::Host,
            Self::Transport => vprouter_netfilter::Scope::Transport,
            Self::Data => vprouter_netfilter::Scope::Data,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Kind {
    Sockets,
    InitialQuarantine,
}
#[cfg_attr(test, derive(Clone))]
pub(crate) struct Request {
    creator: u32,
    binding: Rc<Binding>,
    declaration: Rc<PinnedDeclaration>,
    kind: Kind,
    scope: Scope,
    policy: vprouter_netfilter::Policy,
    policy_digest: [u8; 32],
    digest: [u8; 32],
    requested_at: f64,
    query: Option<Rc<kernel::docker_query::Accepted>>,
    wan: Option<Rc<VerifiedWan>>,
}
impl Request {
    // Private until the connected owner driver binds DATA's fresh policy query
    // and the host observation receipt. No parsed request enters this path.
    fn new(
        binding: Rc<Binding>,
        declaration: Rc<PinnedDeclaration>,
        kind: Kind,
        scope: Scope,
        requested_at: f64,
        query: Option<Rc<kernel::docker_query::Accepted>>,
        wan: Option<Rc<VerifiedWan>>,
    ) -> Result<Rc<Self>> {
        #[cfg(test)]
        lab_stage("request_seal");
        #[cfg(test)]
        lab_clock(Some(requested_at));
        kernel::secret::seal_parent()?;
        kernel::owner_admission_permitted()?;
        #[cfg(test)]
        lab_stage("request_binding");
        binding.verify_retained()?;
        let spec = binding.data().request().spec();
        #[cfg(test)]
        lab_stage("request_declaration");
        declaration.verify(&spec.allocation, &spec.exit.exit_id, binding.host())?;
        let public = binding
            .configuration()
            .exits()
            .iter()
            .find(|e| e.exit().id == spec.exit.exit_id)
            .and_then(|e| e.profile())
            .ok_or(Error::InvalidSpec)?;
        let endpoint = vprouter_netfilter::Endpoint::new(public.endpoint())
            .map_err(|_| Error::NetworkOperation)?;
        #[cfg(test)]
        lab_stage("request_policy");
        let policy = vprouter_netfilter::Policy::new(
            &spec.allocation,
            &spec.allocation.deployment_id,
            &spec.exit,
            endpoint,
            scope.native(),
            &declaration.wan().name,
            "wireguard",
        )
        .map_err(|_| Error::NetworkOperation)?;
        let policy_digest = policy
            .initial_digest()
            .map_err(|_| Error::NetworkOperation)?;
        use sha2::Digest;
        let digest = sha2::Sha256::digest(
            serde_json::to_vec(&(
                "original_exclusive_quarantine_v1",
                kind,
                scope,
                binding.configuration_digest(),
                binding.public_result(),
                binding.transport().request().digest(),
                binding.transport().birth()?,
                binding.data().request().digest(),
                binding.data().birth()?,
                binding.host(),
                declaration.digest(),
                policy_digest,
                query.as_ref().map(|q| q.request().digest()),
                requested_at,
            ))
            .map_err(|_| Error::InvalidSpec)?,
        )
        .into();
        let value = Rc::new(Self {
            creator: std::process::id(),
            binding,
            declaration,
            kind,
            scope,
            policy,
            policy_digest,
            digest,
            requested_at,
            query,
            wan,
        });
        #[cfg(test)]
        lab_stage("request_verify");
        value.verify()?;
        Ok(value)
    }
    pub(crate) fn verify(&self) -> Result<()> {
        self.check()?;
        self.verify_retained()?;
        self.check()
    }
    pub(crate) fn verify_retained(&self) -> Result<()> {
        self.binding.verify_retained()?;
        let spec = self.binding.data().request().spec();
        self.declaration
            .verify(&spec.allocation, &spec.exit.exit_id, self.binding.host())?;
        if self
            .policy
            .initial_digest()
            .map_err(|_| Error::NetworkOperation)?
            != self.policy_digest
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
    pub(crate) fn verify_service(&self, service: &Server) -> Result<()> {
        self.verify()?;
        self.binding.verify(service)?;
        if let Some(query) = &self.query {
            query.verify_quarantine_service(service)?;
        }
        Ok(())
    }
    pub(crate) fn check(&self) -> Result<()> {
        if self.creator != std::process::id() || !vprouter_core::secret_boundary::pristine() {
            return Err(Error::OwnershipMismatch);
        }
        match (&self.query, self.kind, self.scope) {
            (Some(query), Kind::InitialQuarantine, Scope::Data)
                if query.request().requested_at() == self.requested_at
                    && query
                        .request()
                        .quarantine
                        .as_ref()
                        .is_some_and(|b| Rc::ptr_eq(b, &self.binding)) =>
            {
                query.require()?;
                query.request().revalidate_quarantine_process_pins()?;
            }
            (None, kind, scope) if (kind, scope) != (Kind::InitialQuarantine, Scope::Data) => (),
            _ => return Err(Error::OwnershipMismatch),
        }
        match (&self.wan, self.kind, self.scope) {
            (Some(wan), Kind::InitialQuarantine, Scope::Host) => {
                wan.verify(&self.declaration, self.deadline())?
            }
            (None, kind, scope) if (kind, scope) != (Kind::InitialQuarantine, Scope::Host) => (),
            _ => return Err(Error::OwnershipMismatch),
        }
        let now = vprouter_core::health::boot_seconds();
        if !now.is_finite()
            || !self.requested_at.is_finite()
            || self.requested_at <= 0.
            || now < self.requested_at
            || now >= self.deadline()
        {
            return Err(Error::Deadline);
        }
        kernel::owner_admission_permitted()
    }
    pub(crate) fn query_digest(&self) -> Option<[u8; 32]> {
        self.query.as_ref().map(|q| q.request().digest())
    }
    pub(crate) fn binding(&self) -> &Rc<Binding> {
        &self.binding
    }
    pub(crate) fn source(&self) -> BorrowedFd<'_> {
        match self.scope {
            Scope::Host => self.binding.host_pin(),
            Scope::Transport => self.binding.transport().request().source(),
            Scope::Data => self.binding.data().request().source(),
        }
    }
    pub(crate) fn namespace(&self) -> Identity {
        match self.scope {
            Scope::Host => self.binding.host(),
            Scope::Transport => self.binding.transport().request().source_identity(),
            Scope::Data => self.binding.data().request().source_identity(),
        }
    }
    pub(crate) fn member(&self) -> &str {
        &self.binding.data().request().spec().exit.exit_id
    }
    pub(crate) fn requested_at(&self) -> f64 {
        self.requested_at
    }
    pub(crate) fn deadline(&self) -> f64 {
        self.requested_at + 2.
    }
    pub(crate) fn digest(&self) -> [u8; 32] {
        self.digest
    }
    pub(crate) fn configuration_digest(&self) -> [u8; 32] {
        self.binding.configuration_digest()
    }
    pub(crate) fn declaration_digest(&self) -> [u8; 32] {
        self.declaration.digest()
    }
    pub(crate) fn policy_digest(&self) -> [u8; 32] {
        self.policy_digest
    }
    pub(crate) fn policy(&self) -> &vprouter_netfilter::Policy {
        &self.policy
    }
    pub(crate) fn kind(&self) -> Kind {
        self.kind
    }
    pub(crate) fn scope(&self) -> Scope {
        self.scope
    }
}

impl InspectionRequest {
    fn for_quarantine(binding: Rc<Binding>, service: &Server) -> Result<Rc<Self>> {
        Self::for_owned_quarantine(binding, service, QueryKind::QuarantineRecheck)
    }
    pub(super) fn for_owned_quarantine(
        binding: Rc<Binding>,
        service: &Server,
        kind: QueryKind,
    ) -> Result<Rc<Self>> {
        if !matches!(
            kind,
            QueryKind::QuarantineRecheck
                | QueryKind::ProducerRecheck
                | QueryKind::ProducerBindingRecheck
        ) {
            return Err(Error::OwnershipMismatch);
        }
        Self::owned_policy_query(binding, service, kind)
    }
    pub(super) fn for_bootstrap(
        input: &super::operational::OperationalOwner,
        kind: QueryKind,
    ) -> Result<Rc<Self>> {
        if kind.bootstrap_index().is_none() {
            return Err(Error::OwnershipMismatch);
        }
        input.require_complete()?;
        let context = input.context()?;
        Self::owned_policy_query(context.binding, context.service, kind)
    }
    fn owned_policy_query(
        binding: Rc<Binding>,
        service: &Server,
        kind: QueryKind,
    ) -> Result<Rc<Self>> {
        let requested_at = Self::start_clock()?;
        binding.verify(service)?;
        let original = binding.data().request();
        original.revalidate_retained_process()?;
        let staging = serde_json::from_slice(
            &serde_json::to_vec(original.staging()).map_err(|_| Error::InvalidSpec)?,
        )
        .map_err(|_| Error::InvalidSpec)?;
        use sha2::Digest;
        let digest = sha2::Sha256::digest(
            serde_json::to_vec(&(
                "existing_admitted_data_initial_quarantine_v1",
                original.spec(),
                &staging,
                binding.public_result(),
                original.digest(),
                binding.data().birth()?,
                binding.transport().request().digest(),
                binding.transport().birth()?,
                kind,
                requested_at,
            ))
            .map_err(|_| Error::InvalidSpec)?,
        )
        .into();
        let request = Rc::new(Self {
            creator: std::process::id(),
            spec: original.spec().clone(),
            staging,
            binding: binding.query_public_binding(),
            requested_at,
            digest,
            kind,
            mounted: None,
            movement: None,
            quarantine: Some(binding),
        });
        request.verify_service(service)?;
        request.check_deadline()?;
        Ok(request)
    }
    pub(crate) fn revalidate_quarantine_process_pins(&self) -> Result<()> {
        if !matches!(
            self.kind,
            QueryKind::QuarantineRecheck
                | QueryKind::ProducerRecheck
                | QueryKind::ProducerBindingRecheck
                | QueryKind::BootstrapHostRecheck
                | QueryKind::BootstrapTransportRecheck
                | QueryKind::BootstrapDataRecheck
        ) {
            return Err(Error::OwnershipMismatch);
        }
        self.check_deadline()?;
        self.quarantine
            .as_ref()
            .ok_or(Error::OwnershipMismatch)?
            .data()
            .request()
            .revalidate_retained_process()?;
        self.check_deadline()
    }
}

use super::super::inventory;
use super::{host_declaration::PendingWan, movement::MovedPrimary};
use std::{cell::RefCell, path::Path};
/// This retained owner installs only the six original socket/quarantine steps.
/// It grants no producer exception, host link, UP, permit or cleanup authority.
pub(super) struct PendingQuarantine {
    native: Option<Box<Native>>,
}
pub(super) struct QuarantinedPrimary {
    native: Option<Box<Native>>,
}
struct Native {
    creator: u32,
    input: MovedPrimary,
    binding: Rc<Binding>,
    declaration: Rc<PinnedDeclaration>,
    observer: Option<vprouter_network::RouteObserver>,
    observer_token: Option<inventory::Registration>,
    wan: Option<PendingWan>,
    wan_started: Option<f64>,
    request: Option<Rc<Request>>,
    previous: Vec<kernel::netfilter_role::Verified>,
    child: Option<kernel::netfilter_role::Child>,
    verified: Option<kernel::netfilter_role::Verified>,
    query: Option<Rc<InspectionRequest>>,
    query_child: Option<kernel::docker_query::Child>,
    query_verified: Option<kernel::docker_query::Verified>,
    query_accepted: Option<Rc<kernel::docker_query::Accepted>>,
    step: Step,
    failure: Option<Error>,
    #[cfg(test)]
    anchor: Rc<()>,
}
#[derive(Clone, Copy)]
enum Step {
    Prepare,
    Wan,
    QueryIntent,
    QueryBirth,
    QueryReading,
    QueryResult,
    Intent,
    Birth,
    Executing,
    Result,
    Complete,
}
// Keep the same heap-owned bundle on retention; never move its pointee onto the stack.
thread_local! { #[allow(clippy::vec_box)] static RETAINED: RefCell<Vec<Box<Native>>> = const { RefCell::new(Vec::new()) }; }
// Bounded creator-bound cached scalars, armed only by the fixed fixture.
#[cfg(test)]
#[derive(Clone, Copy)]
struct LabStage {
    creator: u32,
    phase: &'static str,
    started: Option<f64>,
    queue: Option<[bool; 5]>,
    jobs: Option<[usize; 2]>,
    own_intent: Option<LabOwnIntent>,
}
#[cfg(test)]
#[derive(Clone, Copy)]
struct LabOwnIntent {
    queued: usize,
    held: usize,
    released: bool,
    writer: Option<(usize, u32, u64)>,
}
#[cfg(test)]
thread_local! { static LAB_STAGE: std::cell::Cell<LabStage> = const { std::cell::Cell::new(LabStage {creator:0,phase:"unarmed",started:None,queue:None,jobs:None,own_intent:None}) }; }
#[cfg(test)]
pub(crate) fn lab_stage(stage: &'static str) {
    LAB_STAGE.with(|slot| {
        let mut state = slot.get();
        if state.creator == std::process::id() {
            state.phase = stage;
            slot.set(state);
        }
    });
}
#[cfg(test)]
pub(crate) fn lab_queue(queue: [bool; 5]) {
    LAB_STAGE.with(|slot| {
        let mut state = slot.get();
        if state.creator == std::process::id() {
            state.queue = Some(queue);
            slot.set(state);
        }
    });
}
#[cfg(test)]
pub(crate) fn lab_jobs(total: usize, matched: usize) {
    LAB_STAGE.with(|slot| {
        let mut state = slot.get();
        if state.creator == std::process::id() {
            state.jobs = Some([total, matched]);
            slot.set(state);
        }
    });
}
#[cfg(test)]
fn lab_own_intent(queued: usize, held: usize, released: bool, writer: Option<(usize, u32, u64)>) {
    LAB_STAGE.with(|slot| {
        let mut state = slot.get();
        if state.creator == std::process::id() {
            state.own_intent = Some(LabOwnIntent {
                queued,
                held,
                released,
                writer,
            });
            slot.set(state);
        }
    });
}
#[cfg(test)]
fn lab_clock(started: Option<f64>) {
    LAB_STAGE.with(|slot| {
        let mut state = slot.get();
        if state.creator == std::process::id() {
            state.started = started;
            state.queue = None;
            state.jobs = None;
            slot.set(state);
        }
    });
}
#[cfg(test)]
fn lab_arm_stages() {
    LAB_STAGE.with(|slot| {
        slot.set(LabStage {
            creator: std::process::id(),
            phase: "construction",
            started: None,
            queue: None,
            jobs: None,
            own_intent: None,
        })
    });
}
#[cfg(test)]
impl Native {
    fn lab_failure(&self, error: Error) {
        if self.creator != std::process::id() {
            return;
        }
        let state = LAB_STAGE.with(|slot| slot.get());
        if state.creator != self.creator {
            return;
        }
        let started = state.started;
        eprintln!(
            "LAB_INITIAL_QUARANTINE_FAILURE {}",
            serde_json::json!({
                "schema":1,"phase":state.phase,"reason":format!("{error:?}"),
                "operation_index":self.previous.len(),
                "step":match self.step {Step::Prepare=>"prepare",Step::Wan=>"wan",Step::QueryIntent=>"query_intent",Step::QueryBirth=>"query_birth",Step::QueryReading=>"query_reading",Step::QueryResult=>"query_result",Step::Intent=>"intent",Step::Birth=>"birth",Step::Executing=>"executing",Step::Result=>"result",Step::Complete=>"complete"},
                "requested_at":started,"deadline":started.map(|t|t+2.),
                "queue_state":state.queue.map(|q|serde_json::json!({"failed":q[0],"pending":q[1],"queued":q[2],"continuation":q[3],"result_issued":q[4]})),
                "job_counts":state.jobs.map(|j|serde_json::json!({"total":j[0],"matched":j[1]})),
                "observed_at":vprouter_core::health::boot_seconds(),
                "child":self.child.as_ref().and_then(|c|c.lab_cached_failure_context()),
                "own_intent_fixture":state.own_intent.map(|LabOwnIntent{queued,held,released,writer}|serde_json::json!({
                    "queued_polls":queued,"held_pending_polls":held,"intent_released":released,
                    "original_writer":writer.map(|(index,pid,start)|serde_json::json!({"index":index,"pid":pid,"start":start}))})),
            })
        );
        // Failure identity is already emitted. This snapshot reads cached
        // canonical memory and original receipts only; it never polls IO.
        if let Ok(service) = self.input.service_ref()
            && let Some(progress) = service.lab_cached_quarantine_progress()
        {
            eprintln!("LAB_INITIAL_QUARANTINE_PROGRESS {progress}");
        }
    }
}

impl Native {
    fn fail(&mut self, error: Error) {
        if self.creator != std::process::id() {
            return;
        }
        self.failure.get_or_insert(error);
        self.input.fail(error);
        if let Some(child) = &mut self.child {
            child.cancel(error);
        }
        if let Some(child) = &mut self.query_child {
            child.cancel(error);
        }
    }
    fn collect(&mut self) {
        if self.creator != std::process::id() {
            return;
        }
        self.input.collect();
        if let Some(child) = &mut self.child {
            child.collect();
        }
        if let Some(child) = &mut self.query_child {
            child.collect();
        }
    }
    fn reaped(&self) -> bool {
        self.input.reaped()
            && self
                .child
                .as_ref()
                .is_none_or(kernel::netfilter_role::Child::reaped)
            && self
                .query_child
                .as_ref()
                .is_none_or(kernel::docker_query::Child::reaped)
    }
    fn start(&mut self, request: Rc<Request>) -> Result<()> {
        self.request = Some(request);
        #[cfg(test)]
        lab_stage("start_netfilter");
        self.input.start_netfilter(
            self.request.as_ref().ok_or(Error::Interrupted)?,
            &self.previous,
        )?;
        self.step = Step::Intent;
        Ok(())
    }
    fn advance(&mut self) -> Result<()> {
        #[cfg(test)]
        if matches!(self.step, Step::Prepare) {
            lab_clock(None);
        }
        #[cfg(test)]
        lab_stage("advance_owner");
        kernel::owner_admission_permitted()?;
        #[cfg(test)]
        lab_stage("advance_binding");
        use super::super::owned::preparation::inspection::QuarantineProgress;
        use super::super::owned::preparation::quarantine::{NetfilterProgress, Progress};
        let progress = match self.step {
            Step::Intent => Some(Progress::Netfilter(
                self.request.as_ref().ok_or(Error::Interrupted)?,
                self.previous.len(),
                NetfilterProgress::Intent,
            )),
            Step::Birth => Some(Progress::Netfilter(
                self.request.as_ref().ok_or(Error::Interrupted)?,
                self.previous.len(),
                NetfilterProgress::Birth(self.child.as_ref().ok_or(Error::Interrupted)?),
            )),
            Step::Result => Some(Progress::Netfilter(
                self.request.as_ref().ok_or(Error::Interrupted)?,
                self.previous.len(),
                NetfilterProgress::Result(self.verified.as_ref().ok_or(Error::Interrupted)?),
            )),
            Step::QueryIntent => Some(Progress::Query(
                self.query.as_ref().ok_or(Error::Interrupted)?,
                QuarantineProgress::Intent,
            )),
            Step::QueryBirth => Some(Progress::Query(
                self.query.as_ref().ok_or(Error::Interrupted)?,
                QuarantineProgress::Birth(self.query_child.as_ref().ok_or(Error::Interrupted)?),
            )),
            Step::QueryResult => Some(Progress::Query(
                self.query.as_ref().ok_or(Error::Interrupted)?,
                QuarantineProgress::Result(self.query_verified.as_ref().ok_or(Error::Interrupted)?),
            )),
            _ => None,
        };
        if let Some(progress) = progress {
            self.binding
                .verify_progress(self.input.service_ref()?, progress)?;
        } else {
            self.binding.verify(self.input.service_ref()?)?;
        }
        match self.step {
            Step::Prepare => {
                let index = self.previous.len();
                if index == 6 {
                    self.step = Step::Complete;
                    return Ok(());
                }
                let scope = match index {
                    0 | 1 => Scope::Host,
                    2 | 3 => Scope::Transport,
                    4 | 5 => Scope::Data,
                    _ => return Err(Error::OwnershipMismatch),
                };
                if index == 5 {
                    #[cfg(test)]
                    lab_stage("prepare_query");
                    let request = InspectionRequest::for_quarantine(
                        self.binding.clone(),
                        self.input.service_ref()?,
                    )?;
                    #[cfg(test)]
                    lab_clock(Some(request.requested_at()));
                    self.query = Some(request);
                    self.input
                        .service()?
                        .start_inspection(self.query.as_ref().ok_or(Error::Interrupted)?)?;
                    self.step = Step::QueryIntent;
                } else if index == 1 {
                    let started = InspectionRequest::start_clock()?;
                    #[cfg(test)]
                    lab_clock(Some(started));
                    #[cfg(test)]
                    lab_stage("wan_open");
                    self.wan_started = Some(started);
                    // Keep the original observer in the complete owner before
                    // fallible registration and creation of its retained read.
                    self.observer = Some(
                        vprouter_network::RouteObserver::open()
                            .map_err(|_| Error::NetworkOperation)?,
                    );
                    let observer = self.observer.as_mut().ok_or(Error::Interrupted)?;
                    self.observer_token =
                        Some(inventory::Registration::owned(&[observer.descriptor()])?);
                    self.wan = Some(self.declaration.begin_wan(observer, started + 2.)?);
                    self.step = Step::Wan;
                } else {
                    let started = InspectionRequest::start_clock()?;
                    let kind = if index.is_multiple_of(2) {
                        Kind::Sockets
                    } else {
                        Kind::InitialQuarantine
                    };
                    self.start(Request::new(
                        self.binding.clone(),
                        self.declaration.clone(),
                        kind,
                        scope,
                        started,
                        None,
                        None,
                    )?)?;
                }
            }
            Step::Wan => {
                #[cfg(test)]
                lab_stage("wan_poll");
                let observer = self.observer.as_mut().ok_or(Error::Interrupted)?;
                if !self
                    .observer_token
                    .as_ref()
                    .is_some_and(|t| t.contains(observer.descriptor()))
                {
                    return Err(Error::DescriptorInventory);
                }
                let wan = self.wan.as_mut().ok_or(Error::Interrupted)?;
                if wan.poll(observer)? {
                    let receipt = wan.accepted()?;
                    let started = self.wan_started.ok_or(Error::Interrupted)?;
                    self.start(Request::new(
                        self.binding.clone(),
                        self.declaration.clone(),
                        Kind::InitialQuarantine,
                        Scope::Host,
                        started,
                        None,
                        Some(receipt),
                    )?)?;
                }
            }
            Step::QueryIntent => {
                #[cfg(test)]
                lab_stage("query_intent");
                let request = self.query.as_ref().ok_or(Error::Interrupted)?;
                if let Some(intent) = self.input.service()?.poll_inspection_intent(request)? {
                    self.query_child = Some(kernel::docker_query::spawn(request.clone(), intent)?);
                    self.input.service()?.start_inspection_birth(
                        self.query_child.as_ref().ok_or(Error::Interrupted)?,
                    )?;
                    self.step = Step::QueryBirth;
                }
            }
            Step::QueryBirth => {
                #[cfg(test)]
                lab_stage("query_birth");
                let child = self.query_child.as_mut().ok_or(Error::Interrupted)?;
                if let Some(gate) = self.input.service()?.poll_inspection_birth(child)? {
                    child.release(gate)?;
                    self.step = Step::QueryReading;
                }
            }
            Step::QueryReading => {
                #[cfg(test)]
                lab_stage("query_reading");
                if let Some(verified) = self
                    .query_child
                    .as_mut()
                    .ok_or(Error::Interrupted)?
                    .poll()?
                {
                    self.query_verified = Some(verified);
                    self.input.service()?.start_inspection_result(
                        self.query_verified.as_ref().ok_or(Error::Interrupted)?,
                    )?;
                    self.step = Step::QueryResult;
                }
            }
            Step::QueryResult => {
                #[cfg(test)]
                lab_stage("query_result");
                let verified = self.query_verified.as_ref().ok_or(Error::Interrupted)?;
                if let Some(receipt) = self.input.service()?.poll_inspection_result(verified)? {
                    self.query_accepted = Some(Rc::new(kernel::docker_query::Verified::accept(
                        &mut self.query_verified,
                        receipt,
                    )?));
                    let accepted = self.query_accepted.as_ref().ok_or(Error::Interrupted)?;
                    accepted.verify_quarantine_service(self.input.service_ref()?)?;
                    accepted.request().revalidate_quarantine_process_pins()?;
                    self.start(Request::new(
                        self.binding.clone(),
                        self.declaration.clone(),
                        Kind::InitialQuarantine,
                        Scope::Data,
                        accepted.request().requested_at(),
                        Some(accepted.clone()),
                        None,
                    )?)?;
                }
            }
            Step::Intent => {
                let request = self.request.as_ref().ok_or(Error::Interrupted)?;
                #[cfg(test)]
                lab_stage("poll_intent");
                if let Some(intent) = self.input.service()?.poll_netfilter_intent(request)? {
                    #[cfg(test)]
                    lab_stage("spawn");
                    self.child = Some(kernel::netfilter_role::Child::spawn(
                        request.clone(),
                        intent,
                        &mut self.previous,
                    )?);
                    self.input
                        .service()?
                        .start_netfilter_birth(self.child.as_ref().ok_or(Error::Interrupted)?)?;
                    self.step = Step::Birth;
                }
            }
            Step::Birth => {
                let child = self.child.as_mut().ok_or(Error::Interrupted)?;
                #[cfg(test)]
                lab_stage("poll_birth");
                if let Some(gate) = self.input.service()?.poll_netfilter_birth(child)? {
                    #[cfg(test)]
                    lab_stage("release_gate");
                    child.release(gate)?;
                    self.step = Step::Executing;
                }
            }
            Step::Executing => {
                #[cfg(test)]
                lab_stage("poll_native");
                if let Some(verified) = self.child.as_mut().ok_or(Error::Interrupted)?.poll()? {
                    self.verified = Some(verified);
                    self.input.service()?.start_netfilter_result(
                        self.verified.as_ref().ok_or(Error::Interrupted)?,
                    )?;
                    self.step = Step::Result;
                }
            }
            Step::Result => {
                let verified = self.verified.as_mut().ok_or(Error::Interrupted)?;
                #[cfg(test)]
                lab_stage("poll_result");
                if let Some(receipt) = self.input.service()?.poll_netfilter_result(verified)? {
                    #[cfg(test)]
                    lab_stage("accept_result");
                    verified.accept(receipt)?;
                    self.request.as_ref().ok_or(Error::Interrupted)?.verify()?;
                    self.previous
                        .push(self.verified.take().ok_or(Error::Interrupted)?);
                    self.child = None;
                    self.step = Step::Prepare;
                }
            }
            Step::Complete => (),
        }
        Ok(())
    }
}
impl PendingQuarantine {
    pub(super) fn new(slot: &mut Option<MovedPrimary>, path: &Path) -> Result<Self> {
        kernel::secret::seal_parent()?;
        let input = slot.as_ref().ok_or(Error::Interrupted)?;
        let binding = input.quarantine_binding()?;
        let spec = binding.data().request().spec();
        let declaration = Rc::new(PinnedDeclaration::load(
            path,
            &spec.allocation,
            &spec.exit.exit_id,
            binding.host(),
        )?);
        binding.verify(input.service_ref()?)?;
        Ok(Self {
            native: Some(Box::new(Native {
                creator: std::process::id(),
                input: slot.take().ok_or(Error::Interrupted)?,
                binding,
                declaration,
                observer: None,
                observer_token: None,
                wan: None,
                wan_started: None,
                request: None,
                previous: Vec::new(),
                child: None,
                verified: None,
                query: None,
                query_child: None,
                query_verified: None,
                query_accepted: None,
                step: Step::Prepare,
                failure: None,
                #[cfg(test)]
                anchor: Rc::new(()),
            })),
        })
    }
    pub(super) fn poll(&mut self) -> Result<Option<QuarantinedPrimary>> {
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        if n.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        if let Some(error) = n.failure {
            n.collect();
            return Err(error);
        }
        if let Err(error) = n.advance() {
            #[cfg(test)]
            n.lab_failure(error);
            n.fail(error);
            n.collect();
            return Err(error);
        }
        if matches!(n.step, Step::Complete) {
            Ok(Some(QuarantinedPrimary {
                native: self.native.take(),
            }))
        } else {
            Ok(None)
        }
    }
}
fn retain(mut native: Box<Native>) {
    if native.creator != std::process::id() {
        std::mem::forget(native);
        return;
    }
    native.fail(Error::Interrupted);
    RETAINED.with(|r| r.borrow_mut().push(native));
}
impl Drop for PendingQuarantine {
    fn drop(&mut self) {
        if let Some(n) = self.native.take() {
            retain(n);
        }
    }
}
impl Drop for QuarantinedPrimary {
    fn drop(&mut self) {
        if let Some(n) = self.native.take() {
            retain(n);
        }
    }
}
pub(super) fn poll_retained() {
    producer::poll_retained();
    RETAINED.with(|r| {
        for n in r.borrow_mut().iter_mut() {
            n.collect();
        }
    });
}
pub(super) fn children_reaped() -> bool {
    producer::children_reaped()
        && RETAINED.with(|r| {
            r.borrow()
                .iter()
                .all(|n| n.creator != std::process::id() || n.reaped())
        })
}

impl QuarantinedPrimary {
    #[cfg(test)]
    fn lab_bootstrap_result_charge(
        &mut self,
        failed: bool,
    ) -> Result<(kernel::LabJournalCharge, serde_json::Value)> {
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        if n.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        n.input.lab_service()?.lab_bootstrap_result_charge(failed)
    }

    fn bootstrap_initial(&mut self, scope: Scope) -> Result<&mut kernel::netfilter_role::Verified> {
        self.binding_context()?;
        let index = match scope {
            Scope::Host => 1,
            Scope::Transport => 3,
            Scope::Data => return Err(Error::OwnershipMismatch),
        };
        self.native
            .as_mut()
            .ok_or(Error::Interrupted)?
            .previous
            .get_mut(index)
            .ok_or(Error::OwnershipMismatch)
    }
    fn assembly_plan(
        &self,
        source: &kernel::producer_creation::Source,
    ) -> Result<Vec<kernel::ResourceTransfer>> {
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        if n.creator != std::process::id()
            || n.failure.is_some()
            || !matches!(n.step, Step::Complete)
            || n.previous.len() != 6
            || n.child.is_some()
            || n.verified.is_some()
            || n.query_accepted.is_none()
        {
            return Err(Error::OwnershipMismatch);
        }
        n.input.service_ref()?.assembly_plan(
            &n.binding,
            n.input.assembly_operations()?,
            &n.previous,
            source,
        )
    }

    fn producer_binding(&self) -> Result<Rc<Binding>> {
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        if n.creator != std::process::id()
            || n.failure.is_some()
            || !matches!(n.step, Step::Complete)
            || n.previous.len() != 6
            || n.child.is_some()
            || n.verified.is_some()
        {
            return Err(Error::OwnershipMismatch);
        }
        n.input.verify_netfilter_prefix(&n.binding, &n.previous)?;
        Ok(n.binding.clone())
    }
    fn binding_context(&self) -> Result<Rc<Binding>> {
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        self.service_ref()?;
        if n.previous.len() != 6 || n.child.is_some() || n.verified.is_some() {
            return Err(Error::OwnershipMismatch);
        }
        for v in &n.previous {
            v.bind_service(n.input.service_ref()?)?;
            v.require_acknowledged()?;
        }
        n.binding.verify(n.input.service_ref()?)?;
        Ok(n.binding.clone())
    }
    fn binding_initial(&mut self) -> Result<&mut kernel::netfilter_role::Verified> {
        self.binding_context()?;
        self.native
            .as_mut()
            .ok_or(Error::Interrupted)?
            .previous
            .get_mut(5)
            .ok_or(Error::OwnershipMismatch)
    }
    fn service_ref(&self) -> Result<&Server> {
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        if n.creator != std::process::id()
            || n.failure.is_some()
            || !matches!(n.step, Step::Complete)
        {
            return Err(Error::OwnershipMismatch);
        }
        n.input.service_ref()
    }
    fn service(&mut self) -> Result<&mut Server> {
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        if n.creator != std::process::id()
            || n.failure.is_some()
            || !matches!(n.step, Step::Complete)
        {
            return Err(Error::OwnershipMismatch);
        }
        n.input.service()
    }
}

#[cfg(test)]
impl Native {
    fn lab_evidence(&mut self) -> Result<serde_json::Value> {
        if self.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        let mut operations = Vec::new();
        for v in &mut self.previous {
            operations.push(v.lab_evidence()?);
        }
        let query = self
            .query_accepted
            .as_ref()
            .ok_or(Error::OwnershipMismatch)?
            .lab_evidence()?;
        let wan = self
            .wan
            .as_ref()
            .ok_or(Error::OwnershipMismatch)?
            .lab_evidence(self.observer.as_ref().ok_or(Error::OwnershipMismatch)?)?;
        Ok(
            serde_json::json!({"preparation":self.input.lab_service()?.lab_evidence()?,"operations":operations,"quarantine_query":query,"wan":wan}),
        )
    }
}
#[cfg(test)]
pub(crate) fn lab_run(fault: u8) -> Result<()> {
    let label = match fault {
        0 => "actual_secret_free_parent_original_quarantine_and_producer",
        1 => "actual_producer_postbirth_failure_retains_quarantine_context",
        2 => "actual_producer_result_writer_failure_retains_original_group",
        3 => "actual_producer_registration_failure_retains_prepared_context",
        _ => return Err(Error::InvalidSpec),
    };
    let witness = producer::lab_build(fault)?;
    println!("{}", serde_json::json!({"case":label,"result":"PASS"}));
    println!("LAB_SECRET_QUARANTINE {witness}");
    Ok(())
}
