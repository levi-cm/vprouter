//! One-way binding of the original created producer group under unchanged
//! quarantine. No placement, permit, activation or producer exception grant.
use super::super::{
    inventory, kernel,
    owned::{
        Identity,
        preparation::{Server, quarantine::Binding},
    },
};
use super::{Error, InspectionRequest, QueryKind, Result, assembly::Assembly};
use rustix::fs::{self, Mode, OFlags, ResolveFlags};
use std::{
    os::fd::{AsFd, OwnedFd},
    rc::Rc,
};

pub(crate) struct Request {
    creator: u32,
    binding: Rc<Binding>,
    source: Rc<kernel::producer_creation::Source>,
    query: Rc<kernel::docker_query::Accepted>,
    fds: [OwnedFd; 6],
    tokens: inventory::Registration,
    pins: [(u64, u64, u32); 6],
    group: Identity,
    policy: [u8; 32],
    digest: [u8; 32],
}
impl Request {
    fn new(input: &Assembly, query: Rc<kernel::docker_query::Accepted>) -> Result<Rc<Self>> {
        kernel::secret::seal_parent()?;
        let binding = input.binding_context()?;
        let source = input.binding_source()?;
        query.verify_producer_binding_service(input.service_ref()?)?;
        if query
            .request()
            .quarantine
            .as_ref()
            .is_none_or(|b| !Rc::ptr_eq(b, &binding))
            || !Rc::ptr_eq(source.request().binding(), &binding)
        {
            return Err(Error::OwnershipMismatch);
        }
        query.request().revalidate_quarantine_process_pins()?;
        let group = source.identity()?;
        let parent = source
            .request()
            .parent()
            .try_clone_to_owned()
            .map_err(|_| Error::DescriptorDuplicate)?;
        let original_group = source.descriptor()?;
        let pin = original_group
            .try_clone_to_owned()
            .map_err(|_| Error::DescriptorDuplicate)?;
        let open = |name: &str| {
            fs::openat2(
                original_group,
                name,
                OFlags::RDONLY | OFlags::CLOEXEC,
                Mode::empty(),
                ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
            )
            .map_err(|_| Error::CgroupMismatch)
        };
        let fds = [
            parent,
            pin,
            open("cgroup.procs")?,
            open("cgroup.events")?,
            open("cgroup.type")?,
            open("cgroup.subtree_control")?,
        ];
        let tokens =
            inventory::Registration::owned(&fds.iter().map(AsFd::as_fd).collect::<Vec<_>>())?;
        let mut pins = [(0, 0, 0); 6];
        for (fd, pin) in fds.iter().zip(&mut pins) {
            let st = fs::fstat(fd).map_err(|_| Error::CgroupMismatch)?;
            *pin = (st.st_dev, st.st_ino, st.st_mode);
        }
        let policy = input.service_ref()?.producer_binding_policy(&source)?;
        use sha2::Digest;
        let digest = sha2::Sha256::digest(
            serde_json::to_vec(&(
                "original_created_producer_binding_v1",
                binding.configuration_digest(),
                binding.public_result(),
                source.request().digest(),
                source.birth()?,
                source.verified_at(),
                source.request().parent_identity(),
                group,
                source.request().name(),
                pins,
                policy,
                query.request().digest(),
                query.request().requested_at(),
            ))
            .map_err(|_| Error::InvalidSpec)?,
        )
        .into();
        let value = Rc::new(Self {
            creator: std::process::id(),
            binding,
            source,
            query,
            fds,
            tokens,
            pins,
            group,
            policy,
            digest,
        });
        value.verify()?;
        Ok(value)
    }
    pub(crate) fn verify_retained(&self) -> Result<()> {
        if self.creator != std::process::id() || !vprouter_core::secret_boundary::pristine() {
            return Err(Error::OwnershipMismatch);
        }
        self.source.require_acknowledged()?;
        self.binding.verify_retained()?;
        if self.source.identity()? != self.group
            || !Rc::ptr_eq(self.source.request().binding(), &self.binding)
        {
            return Err(Error::OwnershipMismatch);
        }
        for (fd, pin) in self.fds.iter().zip(self.pins) {
            let st = fs::fstat(fd).map_err(|_| Error::CgroupMismatch)?;
            if !self.tokens.contains(fd.as_fd())
                || (st.st_dev, st.st_ino, st.st_mode) != pin
                || st.st_uid != 0
                || st.st_gid != 0
                || fs::fstatfs(fd).map_err(|_| Error::CgroupMismatch)?.f_type as u64 != 0x63677270
            {
                return Err(Error::CgroupMismatch);
            }
        }
        Ok(())
    }
    pub(crate) fn verify(&self) -> Result<()> {
        self.check()?;
        self.verify_retained()?;
        self.query.request().revalidate_quarantine_process_pins()?;
        self.check()
    }
    pub(crate) fn verify_service(&self, s: &Server) -> Result<()> {
        self.verify()?;
        self.source.bind_service(s)?;
        self.binding.verify(s)?;
        self.query.verify_producer_binding_service(s)
    }
    pub(crate) fn check(&self) -> Result<()> {
        if self.creator != std::process::id()
            || self.query.request().kind() != QueryKind::ProducerBindingRecheck
            || self
                .query
                .request()
                .quarantine
                .as_ref()
                .is_none_or(|b| !Rc::ptr_eq(b, &self.binding))
        {
            return Err(Error::OwnershipMismatch);
        }
        kernel::owner_admission_permitted()?;
        self.query.require()
    }
    pub(crate) fn descriptors(&self) -> vprouter_native_role::ProducerDescriptors<'_> {
        let f = &self.fds;
        vprouter_native_role::ProducerDescriptors {
            parent: f[0].as_fd(),
            group: f[1].as_fd(),
            procs: f[2].as_fd(),
            events: f[3].as_fd(),
            kind: f[4].as_fd(),
            subtree: f[5].as_fd(),
        }
    }
    pub(crate) fn binding(&self) -> &Rc<Binding> {
        &self.binding
    }
    pub(crate) fn source(&self) -> &Rc<kernel::producer_creation::Source> {
        &self.source
    }
    pub(crate) fn digest(&self) -> [u8; 32] {
        self.digest
    }
    pub(crate) fn query_digest(&self) -> [u8; 32] {
        self.query.request().digest()
    }
    pub(crate) fn policy_digest(&self) -> [u8; 32] {
        self.policy
    }
    #[cfg(test)]
    pub(crate) fn lab_registered_slots(&self) -> Result<usize> {
        if self.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        self.tokens.lab_live_slots()
    }
    pub(crate) fn pins(&self) -> [(u64, u64, u32); 6] {
        self.pins
    }
    pub(crate) fn group(&self) -> Identity {
        self.group
    }
    pub(crate) fn parent(&self) -> Identity {
        self.source.request().parent_identity()
    }
    pub(crate) fn name(&self) -> &str {
        self.source.request().name()
    }
    pub(crate) fn requested_at(&self) -> f64 {
        self.query.request().requested_at()
    }
    pub(crate) fn deadline(&self) -> f64 {
        self.query.request().deadline()
    }
    pub(crate) fn data(&self) -> Identity {
        self.binding.data().request().source_identity()
    }
}

use super::super::owned::preparation::{
    inspection::QuarantineProgress, producer_binding::Progress,
    quarantine::Progress as QueryProgress,
};
use std::cell::RefCell;
#[derive(Clone, Copy)]
enum Step {
    QueryIntent,
    QueryBirth,
    QueryReading,
    QueryResult,
    Intent,
    Birth,
    Reading,
    Result,
    Complete,
}
struct Native {
    creator: u32,
    input: Assembly,
    binding: Rc<Binding>,
    query: Rc<InspectionRequest>,
    query_child: Option<kernel::docker_query::Child>,
    query_verified: Option<kernel::docker_query::Verified>,
    query_accepted: Option<Rc<kernel::docker_query::Accepted>>,
    request: Option<Rc<Request>>,
    child: Option<kernel::producer_binding::Child>,
    verified: Option<kernel::producer_binding::Verified>,
    step: Step,
    failure: Option<Error>,
    #[cfg(test)]
    anchor: Rc<()>,
    #[cfg(test)]
    final_verified_at: Option<f64>,
}
pub(crate) struct PendingBinding {
    native: Option<Box<Native>>,
}
pub(crate) struct ProducerBoundAssembly {
    native: Option<Box<Native>>,
}
impl ProducerBoundAssembly {
    pub(crate) fn bootstrap_previous(
        &mut self,
        scope: super::quarantine::Scope,
    ) -> Result<kernel::bootstrap::Previous<'_>> {
        self.host_custody()?;
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        match scope {
            super::quarantine::Scope::Data => Ok(kernel::bootstrap::Previous::Observed(
                n.verified.as_mut().ok_or(Error::OwnershipMismatch)?,
            )),
            _ => Ok(kernel::bootstrap::Previous::Initial(
                n.input.bootstrap_initial(scope)?,
            )),
        }
    }
    pub(super) fn operational_resource(&self) -> Result<kernel::ResourceTransfer> {
        let n = self.require_historical()?;
        n.verified
            .as_ref()
            .ok_or(Error::OwnershipMismatch)?
            .resource_transfer()
    }
    pub(super) fn reserve_operational_extension(
        &self,
        plan: &[kernel::ResourceTransfer],
    ) -> Result<super::super::owned::preparation::assembly::OperationalReservation> {
        self.require_historical()?
            .input
            .reserve_operational_extension(plan)
    }

    fn require_historical(&self) -> Result<&Native> {
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        if n.creator != std::process::id()
            || n.failure.is_some()
            || !matches!(n.step, Step::Complete)
        {
            return Err(Error::OwnershipMismatch);
        }
        n.input
            .service_ref()?
            .require_producer_bound_history(n.verified.as_ref().ok_or(Error::OwnershipMismatch)?)?;
        Ok(n)
    }
    pub(crate) fn host_custody(&self) -> Result<(&Rc<Binding>, &Server)> {
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        if n.creator != std::process::id()
            || n.failure.is_some()
            || !matches!(n.step, Step::Complete)
        {
            return Err(Error::OwnershipMismatch);
        }
        let service = n.input.service_ref()?;
        service
            .require_producer_bound_custody(n.verified.as_ref().ok_or(Error::OwnershipMismatch)?)?;
        Ok((&n.binding, service))
    }
    pub(crate) fn operational_source(&self) -> Result<Rc<kernel::producer_creation::Source>> {
        let (_, service) = self.host_custody()?;
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        let source = &n.request.as_ref().ok_or(Error::OwnershipMismatch)?.source;
        source.bind_service(service)?;
        source.verify_acknowledged_history()?;
        Ok(source.clone())
    }
    pub(crate) fn host_custody_mut(&mut self) -> Result<&mut Server> {
        self.host_custody()?;
        self.native
            .as_mut()
            .ok_or(Error::Interrupted)?
            .input
            .service()
    }
    pub(crate) fn host_context(&self) -> Result<Rc<Binding>> {
        Ok(self.require_historical()?.binding.clone())
    }
    pub(crate) fn host_service(&self) -> Result<&Server> {
        self.require_historical()?.input.service_ref()
    }
    pub(crate) fn host_service_mut(&mut self) -> Result<&mut Server> {
        self.require_historical()?;
        self.native
            .as_mut()
            .ok_or(Error::Interrupted)?
            .input
            .service()
    }
    pub(crate) fn fail(&mut self, error: Error) {
        if let Some(n) = &mut self.native {
            n.fail(error);
        }
    }
    pub(crate) fn collect(&mut self) {
        if let Some(n) = &mut self.native {
            n.collect();
        }
    }
    pub(crate) fn children_reaped(&self) -> bool {
        self.native
            .as_ref()
            .is_none_or(|n| n.creator == std::process::id() && n.reaped())
    }
}
// Keep the same heap-owned bundle on retention; never move its pointee onto the stack.
thread_local! {#[allow(clippy::vec_box)] static RETAINED:RefCell<Vec<Box<Native>>>=const{RefCell::new(Vec::new())};}
impl Native {
    fn fail(&mut self, e: Error) {
        if self.creator != std::process::id() {
            return;
        }
        self.failure.get_or_insert(e);
        self.input.fail(e);
        if let Some(c) = &mut self.query_child {
            c.cancel(e);
        }
        if let Some(c) = &mut self.child {
            c.cancel(e);
        }
    }
    fn collect(&mut self) {
        if self.creator != std::process::id() {
            return;
        }
        self.input.collect();
        if let Some(c) = &mut self.query_child {
            c.collect();
        }
        if let Some(c) = &mut self.child {
            c.collect();
        }
    }
    fn reaped(&self) -> bool {
        self.input.children_reaped()
            && self
                .query_child
                .as_ref()
                .is_none_or(kernel::docker_query::Child::reaped)
            && self
                .child
                .as_ref()
                .is_none_or(kernel::producer_binding::Child::reaped)
    }
    fn advance(&mut self) -> Result<()> {
        self.query.check_deadline()?;
        let service = self.input.service_ref()?;
        match self.step {
            Step::QueryIntent => self.binding.verify_progress(
                service,
                QueryProgress::Query(&self.query, QuarantineProgress::Intent),
            )?,
            Step::QueryBirth => self.binding.verify_progress(
                service,
                QueryProgress::Query(
                    &self.query,
                    QuarantineProgress::Birth(self.query_child.as_ref().ok_or(Error::Interrupted)?),
                ),
            )?,
            Step::QueryResult => self.binding.verify_progress(
                service,
                QueryProgress::Query(
                    &self.query,
                    QuarantineProgress::Result(
                        self.query_verified.as_ref().ok_or(Error::Interrupted)?,
                    ),
                ),
            )?,
            Step::Intent => self.binding.verify_producer_binding_progress(
                service,
                self.request.as_ref().ok_or(Error::Interrupted)?,
                Progress::Intent,
            )?,
            Step::Birth => self.binding.verify_producer_binding_progress(
                service,
                self.request.as_ref().ok_or(Error::Interrupted)?,
                Progress::Birth(self.child.as_ref().ok_or(Error::Interrupted)?),
            )?,
            Step::Result => self.binding.verify_producer_binding_progress(
                service,
                self.request.as_ref().ok_or(Error::Interrupted)?,
                Progress::Result(self.verified.as_ref().ok_or(Error::Interrupted)?),
            )?,
            _ => self.binding.verify(service)?,
        }
        match self.step {
            Step::QueryIntent => {
                if let Some(i) = self.input.service()?.poll_inspection_intent(&self.query)? {
                    self.query_child = Some(kernel::docker_query::spawn(self.query.clone(), i)?);
                    self.input.service()?.start_inspection_birth(
                        self.query_child.as_ref().ok_or(Error::Interrupted)?,
                    )?;
                    self.step = Step::QueryBirth;
                }
            }
            Step::QueryBirth => {
                let c = self.query_child.as_mut().ok_or(Error::Interrupted)?;
                if let Some(g) = self.input.service()?.poll_inspection_birth(c)? {
                    c.release(g)?;
                    self.step = Step::QueryReading;
                }
            }
            Step::QueryReading => {
                if let Some(v) = self
                    .query_child
                    .as_mut()
                    .ok_or(Error::Interrupted)?
                    .poll()?
                {
                    self.query_verified = Some(v);
                    self.input.service()?.start_inspection_result(
                        self.query_verified.as_ref().ok_or(Error::Interrupted)?,
                    )?;
                    self.step = Step::QueryResult;
                }
            }
            Step::QueryResult => {
                if let Some(r) = self.input.service()?.poll_inspection_result(
                    self.query_verified.as_ref().ok_or(Error::Interrupted)?,
                )? {
                    self.query_accepted = Some(Rc::new(kernel::docker_query::Verified::accept(
                        &mut self.query_verified,
                        r,
                    )?));
                    self.request = Some(Request::new(
                        &self.input,
                        self.query_accepted
                            .as_ref()
                            .ok_or(Error::Interrupted)?
                            .clone(),
                    )?);
                    self.input
                        .service()?
                        .start_producer_binding(self.request.as_ref().ok_or(Error::Interrupted)?)?;
                    self.step = Step::Intent;
                }
            }
            Step::Intent => {
                let r = self.request.as_ref().ok_or(Error::Interrupted)?;
                if let Some(i) = self.input.service()?.poll_producer_binding_intent(r)? {
                    self.child = Some(kernel::producer_binding::spawn(
                        r.clone(),
                        i,
                        self.input.binding_initial()?,
                    )?);
                    self.input.service()?.start_producer_binding_birth(
                        self.child.as_ref().ok_or(Error::Interrupted)?,
                    )?;
                    self.step = Step::Birth;
                }
            }
            Step::Birth => {
                let c = self.child.as_mut().ok_or(Error::Interrupted)?;
                if let Some(g) = self.input.service()?.poll_producer_binding_birth(c)? {
                    c.release(g)?;
                    self.step = Step::Reading;
                }
            }
            Step::Reading => {
                if let Some(v) = self.child.as_mut().ok_or(Error::Interrupted)?.poll()? {
                    self.verified = Some(v);
                    self.input.service()?.start_producer_binding_source(
                        self.verified.as_ref().ok_or(Error::Interrupted)?,
                    )?;
                    self.step = Step::Result;
                }
            }
            Step::Result => {
                let v = self.verified.as_mut().ok_or(Error::Interrupted)?;
                if let Some(r) = self.input.service()?.poll_producer_binding_source(v)? {
                    v.accept(r)?;
                    self.request.as_ref().ok_or(Error::Interrupted)?.verify()?;
                    self.query.revalidate_quarantine_process_pins()?;
                    self.query.check_deadline()?;
                    #[cfg(test)]
                    {
                        self.final_verified_at = Some(vprouter_core::health::boot_seconds());
                    }
                    self.step = Step::Complete;
                }
            }
            Step::Complete => (),
        }
        self.query.check_deadline()
    }
}
impl PendingBinding {
    pub(crate) fn new(slot: &mut Option<Assembly>) -> Result<Self> {
        let input = slot.as_ref().ok_or(Error::Interrupted)?;
        let binding = input.binding_context()?;
        let query = InspectionRequest::for_owned_quarantine(
            binding.clone(),
            input.service_ref()?,
            QueryKind::ProducerBindingRecheck,
        )?;
        let mut value = Self {
            native: Some(Box::new(Native {
                creator: std::process::id(),
                input: slot.take().ok_or(Error::Interrupted)?,
                binding,
                query,
                query_child: None,
                query_verified: None,
                query_accepted: None,
                request: None,
                child: None,
                verified: None,
                step: Step::QueryIntent,
                failure: None,
                #[cfg(test)]
                anchor: Rc::new(()),
                #[cfg(test)]
                final_verified_at: None,
            })),
        };
        let n = value.native.as_mut().ok_or(Error::Interrupted)?;
        if let Err(e) = n.input.service()?.start_inspection(&n.query) {
            n.fail(e);
            return Err(e);
        }
        Ok(value)
    }
    pub(crate) fn poll(&mut self) -> Result<Option<ProducerBoundAssembly>> {
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        if n.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        if let Some(e) = n.failure {
            n.collect();
            return Err(e);
        }
        match n.advance() {
            Ok(()) if matches!(n.step, Step::Complete) => Ok(Some(ProducerBoundAssembly {
                native: self.native.take(),
            })),
            Ok(()) => Ok(None),
            Err(e) => {
                n.fail(e);
                n.collect();
                Err(e)
            }
        }
    }
}
fn retain(mut n: Box<Native>) {
    if n.creator != std::process::id() {
        std::mem::forget(n);
        return;
    }
    n.fail(Error::Interrupted);
    RETAINED.with(|r| r.borrow_mut().push(n));
}
impl Drop for PendingBinding {
    fn drop(&mut self) {
        if let Some(n) = self.native.take() {
            retain(n);
        }
    }
}
impl Drop for ProducerBoundAssembly {
    fn drop(&mut self) {
        if let Some(n) = self.native.take() {
            retain(n);
        }
    }
}
pub(super) fn poll_retained() {
    RETAINED.with(|r| {
        for n in r.borrow_mut().iter_mut() {
            n.collect();
        }
    });
}
pub(super) fn children_reaped() -> bool {
    RETAINED.with(|r| {
        r.borrow()
            .iter()
            .all(|n| n.creator != std::process::id() || n.reaped())
    })
}

/// One failure-only diagnostic. Each boundary is selected before its existing
/// call/check; snapshots copy already-produced public evidence only. Drop does
/// not verify, poll, collect, cancel, or inspect any native descriptor.
#[cfg(test)]
struct LabPostfault {
    creator: u32,
    fault: u8,
    query: [u8; 32],
    requested_at: f64,
    deadline: f64,
    phase: &'static str,
    constructor: Option<serde_json::Value>,
    preparation: Option<serde_json::Value>,
    charges: Option<[usize; 2]>,
    finished: bool,
}
#[cfg(test)]
impl Drop for LabPostfault {
    fn drop(&mut self) {
        if self.creator == std::process::id() && self.fault != 0 && !self.finished {
            eprintln!(
                "LAB_PRODUCER_BINDING_POSTFAULT {}",
                serde_json::json!({"schema":1,"creator":self.creator,"fault":self.fault,
                    "query":self.query,"requested_at":self.requested_at,"deadline":self.deadline,
                    "phase":self.phase,"constructor":self.constructor,"preparation":self.preparation,
                    "charges":self.charges})
            );
        }
    }
}

#[cfg(test)]
pub(crate) fn lab_run(fault: u8) -> Result<()> {
    lab_build(fault, false).map(|_| ())
}
#[cfg(test)]
pub(super) fn lab_bound() -> Result<(ProducerBoundAssembly, serde_json::Value)> {
    let (owner, witness) = lab_build(0, true)?;
    Ok((owner.ok_or(Error::OwnershipMismatch)?, witness))
}
#[cfg(test)]
impl ProducerBoundAssembly {
    pub(super) fn lab_bootstrap_result_charge(
        &mut self,
        failed: bool,
    ) -> Result<(kernel::LabJournalCharge, serde_json::Value)> {
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        if n.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        n.input.lab_bootstrap_result_charge(failed)
    }
    pub(super) fn lab_preparation(&mut self) -> Result<serde_json::Value> {
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        if n.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        n.input.lab_preparation()
    }
    pub(super) fn lab_host_result_charge(
        &mut self,
        failed: bool,
    ) -> Result<(kernel::LabJournalCharge, serde_json::Value)> {
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        if n.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        n.input.lab_host_result_charge(failed)
    }
    pub(super) fn lab_anchors(&self) -> Result<Vec<std::rc::Weak<()>>> {
        let n = self.require_historical()?;
        let mut old = n.input.lab_anchors()?.to_vec();
        old.push(Rc::downgrade(&n.anchor));
        Ok(old)
    }
}
#[cfg(test)]
fn lab_build(
    fault: u8,
    continuation: bool,
) -> Result<(Option<ProducerBoundAssembly>, serde_json::Value)> {
    if continuation && fault != 0 {
        return Err(Error::OwnershipMismatch);
    }
    use std::time::Duration;
    let label = match fault {
        0 => "actual_original_producer_binding_published_under_quarantine",
        1 => "actual_producer_binding_postbirth_failure_retains_unpublished_group",
        2 => "actual_producer_binding_result_failure_retains_unacknowledged_publication",
        3 => "actual_producer_binding_registration_failure_retains_original_assembly",
        _ => return Err(Error::InvalidSpec),
    };
    let (assembly, assembly_witness) = super::assembly::lab_assembled()?;
    let old = assembly.lab_anchors()?;
    let original_source = assembly.binding_source()?;
    let original_group = original_source.identity()?;
    let before = [
        kernel::lab_live_child_capacity(),
        vprouter_native_role::lab_live_child_capacity(),
    ];
    if before != [0, 0]
        || assembly_witness["charges_after_drop"] != serde_json::Value::Null
        || assembly_witness["continued_original_context"] != true
    {
        return Err(Error::OwnershipMismatch);
    }
    let mut slot = Some(assembly);
    let mut pending = PendingBinding::new(&mut slot)?;
    let weak = Rc::downgrade(&pending.native.as_ref().ok_or(Error::Interrupted)?.anchor);
    let q = &pending.native.as_ref().ok_or(Error::Interrupted)?.query;
    let mut trace = LabPostfault {
        creator: std::process::id(),
        fault,
        query: q.digest(),
        requested_at: q.requested_at(),
        deadline: q.deadline(),
        phase: "driver_poll",
        constructor: None,
        preparation: None,
        charges: None,
        finished: false,
    };
    let mut armed = false;
    let mut held = false;
    let mut original_result_charge = None;
    let mut retained_result_writer = None;
    let outcome = loop {
        let n = pending.native.as_mut().ok_or(Error::Interrupted)?;
        if !armed {
            if matches!(fault, 1 | 3) && matches!(n.step, Step::Intent) {
                kernel::producer_binding::lab_arm(
                    n.request.as_ref().ok_or(Error::Interrupted)?,
                    fault,
                );
                armed = true;
            } else if fault == 2 && matches!(n.step, Step::Reading) {
                n.input.service()?.lab_hold_producer_binding_result()?;
                armed = true;
            }
        }
        if fault == 2
            && armed
            && matches!(n.step, Step::Result)
            && n.input.service()?.lab_checkpoint()?
        {
            if n.input.service_ref()?.children_reaped() {
                return Err(Error::OwnershipMismatch);
            }
            held = true;
            trace.phase = "capture_result_writer_charge";
            original_result_charge = Some(n.input.lab_binding_result_charge(false)?.0);
            n.fail(Error::ChildFailed);
        }
        match pending.poll() {
            Ok(Some(v)) => break Ok(v),
            Ok(None) => std::thread::sleep(Duration::from_millis(1)),
            Err(e) => break Err(e),
        }
    };
    let mut complete = None;
    let mut failed_constructor = None;
    let mut failure_retry = None;
    match outcome {
        Ok(v) if fault == 0 => complete = Some(v),
        Ok(_) => return Err(Error::OwnershipMismatch),
        Err(e) => {
            trace.phase = "expected_fault";
            let n = pending.native.as_mut().ok_or(Error::Interrupted)?;
            eprintln!(
                "LAB_SECRET_PRODUCER_BINDING_FAILURE reason={e:?} requested_at={} deadline={} now={}",
                n.query.requested_at(),
                n.query.deadline(),
                vprouter_core::health::boot_seconds()
            );
            if !armed
                || !(fault == 2 && held && e == Error::ChildFailed
                    || matches!(fault, 1 | 3) && e == Error::DescriptorInventory)
            {
                return Err(e);
            }
            let collect_end = vprouter_core::health::boot_seconds() + 2.;
            loop {
                trace.phase = "collect_original_context";
                n.collect();
                if matches!(fault, 1 | 3) {
                    trace.phase = "failed_constructor_evidence";
                    failed_constructor = kernel::producer_binding::lab_failed_context(
                        n.request.as_ref().ok_or(Error::Interrupted)?,
                    )?;
                    trace.constructor = failed_constructor.as_ref().map(|f| serde_json::json!({
                        "request":f["request"],"original_pid":f["original_pid"],
                        "original_start":f["original_start"],"actual_wait_status":f["actual_wait_status"],
                        "native_born":f["native_born"],"native_job_state":f["native_job_state"],
                        "registered_native_slots":f["registered_native_slots"],
                        "original_registration_slots_verified":f["original_registration_slots_verified"],
                        "borrowed_registration_count":f["borrowed_registration_count"],
                        "complete_native_registration":f["complete_native_registration"],
                        "durable_birth_released":f["durable_birth_released"]}));
                }
                trace.phase = "original_context_reaped";
                if n.reaped() && (fault == 2 || failed_constructor.is_some()) {
                    break;
                }
                if vprouter_core::health::boot_seconds() >= collect_end {
                    return Err(Error::Deadline);
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            // A failed original operation keeps its local owner and service
            // unavailable even when no journal writer is uncertain. That is
            // distinct from the shared canonical mutation fence below.
            trace.phase = "failed_owner_retry_refusal";
            if fault == 2 {
                trace.phase = "result_writer_charge_after_collection";
                let (current, mut evidence) = n.input.lab_binding_result_charge(true)?;
                original_result_charge
                    .as_ref()
                    .ok_or(Error::OwnershipMismatch)?
                    .same_original(&current)?;
                evidence["charge_retained_before_cancel"] = serde_json::json!(true);
                evidence["charge_retained_after_collection"] = serde_json::json!(true);
                evidence["charge_retained_after_retries"] = serde_json::json!(false);
                evidence["charge_retained_after_drop"] = serde_json::json!(false);
                retained_result_writer = Some(evidence);
            }
            trace.phase = "failed_owner_retry_refusal";
            if n.failure != Some(e)
                || !matches!(n.input.service_ref(), Err(Error::OwnershipMismatch))
            {
                return Err(Error::OwnershipMismatch);
            }
            let original_request = n.request.as_ref().ok_or(Error::Interrupted)?.clone();
            let original_step = std::mem::discriminant(&n.step);
            let births_before = kernel::lab_native_births();
            let charges_before = [
                kernel::lab_live_child_capacity(),
                vprouter_native_role::lab_live_child_capacity(),
            ];
            for _ in 0..2 {
                if !matches!(pending.poll(), Err(actual) if actual == e) {
                    return Err(Error::OwnershipMismatch);
                }
                let retained = pending.native.as_ref().ok_or(Error::Interrupted)?;
                if retained.failure != Some(e)
                    || std::mem::discriminant(&retained.step) != original_step
                    || !Rc::ptr_eq(
                        retained.request.as_ref().ok_or(Error::Interrupted)?,
                        &original_request,
                    )
                    || !matches!(retained.input.service_ref(), Err(Error::OwnershipMismatch))
                {
                    return Err(Error::OwnershipMismatch);
                }
            }
            let births_after = kernel::lab_native_births();
            let charges_after = [
                kernel::lab_live_child_capacity(),
                vprouter_native_role::lab_live_child_capacity(),
            ];
            if births_before != births_after || charges_before != charges_after {
                return Err(Error::OwnershipMismatch);
            }
            if fault == 2 {
                trace.phase = "result_writer_charge_after_retries";
                let n = pending.native.as_mut().ok_or(Error::Interrupted)?;
                let (current, _) = n.input.lab_binding_result_charge(true)?;
                original_result_charge
                    .as_ref()
                    .ok_or(Error::OwnershipMismatch)?
                    .same_original(&current)?;
                retained_result_writer
                    .as_mut()
                    .ok_or(Error::OwnershipMismatch)?["charge_retained_after_retries"] =
                    serde_json::json!(true);
            }
            failure_retry = Some(
                serde_json::json!({"polls":2,"native_births_before":births_before,
                "native_births_after":births_after,"charges_before":charges_before,"charges_after":charges_after,
                "same_original_request":true,"same_step":true,"original_error_retained":true,"assembly_reuse_refused":true}),
            );
        }
    }
    trace.phase = "retained_owner";
    let n = if let Some(v) = &mut complete {
        v.native.as_mut()
    } else {
        pending.native.as_mut()
    }
    .ok_or(Error::Interrupted)?;
    trace.phase = "observation_evidence";
    let observation = n
        .verified
        .as_mut()
        .map(kernel::producer_binding::Verified::lab_evidence)
        .transpose()?;
    trace.phase = "query_evidence";
    let query = n
        .query_accepted
        .as_ref()
        .ok_or(Error::OwnershipMismatch)?
        .lab_evidence()?;
    trace.phase = "preparation_evidence";
    let preparation = n.input.lab_preparation()?;
    trace.preparation = Some(serde_json::json!({
        "writer_count":preparation["writers"].as_array().map(Vec::len),
        "member_native_jobs_collected":preparation["member_native_jobs_collected"],
        "native_children_reaped":preparation["native_children_reaped"],
        "service_reserved":preparation["service_reserved"],"mutation_fenced":preparation["mutation_fenced"],
        "canonical_pending":preparation["canonical_pending"],"entry_phase":preparation["entry_phase"],
        "entry_producer_absent":preparation["entry_producer_absent"],
        "binding_birth_present":!preparation["producer_binding"]["birth"].is_null(),
        "binding_result_present":!preparation["producer_binding"]["result"].is_null()}));
    trace.phase = "writer_prefix_and_custody";
    let writers = preparation["writers"]
        .as_array()
        .ok_or(Error::OwnershipMismatch)?;
    let old_preparation = &assembly_witness["preparation"];
    let old_writers = old_preparation["writers"]
        .as_array()
        .ok_or(Error::OwnershipMismatch)?;
    let expected = if matches!(fault, 1 | 3) { 73 } else { 75 };
    if writers.len() != expected
        || old_writers.len() != 69
        || writers[..69] != old_writers[..]
        || preparation["member_native_jobs_collected"] != false
        || preparation["native_children_reaped"] != true
        || preparation["service_reserved"] != true
        || preparation["mutation_fenced"] != serde_json::json!(fault == 2)
        || preparation["canonical_pending"] != serde_json::json!(fault == 2)
    {
        return Err(Error::OwnershipMismatch);
    }
    for key in [
        "member",
        "requested_at",
        "deadline",
        "birth",
        "base_network_absent",
        "base_network",
        "data_network",
        "transport_network",
        "inspection",
        "attachment",
        "fresh_transport",
        "wireguard",
        "movement_query",
        "netfilter",
        "quarantine_query",
        "producer_query",
        "producer_creation",
    ] {
        trace.phase = key;
        if preparation[key] != old_preparation[key] {
            return Err(Error::OwnershipMismatch);
        }
    }
    let phases = [
        "producer_binding_query_intent",
        "producer_binding_query_birth",
        "producer_binding_query_result",
        "producer_binding_intent",
        "producer_binding_birth",
        "producer_binding_result",
    ];
    for (index, w) in writers[69..].iter().enumerate() {
        trace.phase = phases[index];
        if w["phase"] != phases[index]
            || w["io_deadline"] != serde_json::json!(n.query.deadline())
            || w["parent_deadline"] != w["io_deadline"]
        {
            return Err(Error::OwnershipMismatch);
        }
        if fault == 2 && index == 5 {
            if w["actual_wait_status"] != 9 || !w["verified_at"].is_null() {
                return Err(Error::OwnershipMismatch);
            }
        } else {
            let queued = w["queued_at"].as_f64().ok_or(Error::OwnershipMismatch)?;
            let at = w["verified_at"].as_f64().ok_or(Error::OwnershipMismatch)?;
            if w["actual_wait_status"] != 0
                || !queued.is_finite()
                || !at.is_finite()
                || queued < n.query.requested_at()
                || at < queued
                || at >= n.query.deadline()
            {
                return Err(Error::OwnershipMismatch);
            }
        }
    }
    let canonical = &preparation["producer_binding"];
    trace.phase = "original_source_binding";
    let source = n.request.as_ref().ok_or(Error::Interrupted)?;
    if !Rc::ptr_eq(source.source(), &original_source)
        || source.group() != original_group
        || canonical["request"] != serde_json::json!(source.digest())
        || canonical["query"] != serde_json::json!(n.query.digest())
        || canonical["creation"] != preparation["producer_creation"]
    {
        return Err(Error::OwnershipMismatch);
    }
    match fault {
        0 | 2 => {
            trace.phase = "observed_result";
            let o = observation.as_ref().ok_or(Error::OwnershipMismatch)?;
            if o["actual_wait_status"] != 0
                || o["eof"] != true
                || o["durable_birth_released"] != true
                || o["complete_native_registration"] != true
                || o["borrowed_registration_count"] != 2
                || o["acknowledged"] != serde_json::json!(fault == 0)
            {
                return Err(Error::OwnershipMismatch);
            }
            if fault == 0 {
                if canonical["result"] != o["result"]
                    || canonical["verified_at"] != o["accepted_at"]
                    || preparation["entry_producer_absent"] != false
                    || preparation["entry_producer"]["binding"]
                        != serde_json::json!(source.digest())
                    || n.final_verified_at.is_none_or(|at| {
                        at >= n.query.deadline()
                            || at < writers[74]["verified_at"].as_f64().unwrap_or(f64::INFINITY)
                    })
                {
                    return Err(Error::OwnershipMismatch);
                }
            } else if !canonical["result"].is_null()
                || !canonical["verified_at"].is_null()
                || preparation["entry_producer_absent"] != true
                || preparation["pending_producer_binding"]["history"]["result"] != o["result"]
                || preparation["pending_producer_binding"]["producer"]["group"]
                    != serde_json::json!(original_group)
            {
                return Err(Error::OwnershipMismatch);
            }
        }
        1 | 3 => {
            trace.phase = "failed_constructor_common";
            let f = failed_constructor
                .as_ref()
                .ok_or(Error::OwnershipMismatch)?;
            if !canonical["birth"].is_null()
                || !canonical["result"].is_null()
                || preparation["entry_producer_absent"] != true
                || observation.is_some()
                || f["durable_birth_released"] != false
                || f["original_registration_slots_verified"] != true
            {
                return Err(Error::OwnershipMismatch);
            }
            if fault == 1 {
                trace.phase = "failed_constructor_born_status";
                if f["native_born"] != true
                    || f["native_job_state"] != "born"
                    || f["actual_wait_status"] != 9
                    || !f["original_start"].is_null()
                {
                    return Err(Error::OwnershipMismatch);
                }
            } else {
                trace.phase = "failed_constructor_prepared_status";
                if f["native_born"] != false
                    || f["native_job_state"] != "prepared"
                    || !f["original_pid"].is_null()
                    || !f["actual_wait_status"].is_null()
                {
                    return Err(Error::OwnershipMismatch);
                }
            }
        }
        _ => return Err(Error::InvalidSpec),
    }
    trace.phase = "canonical_negative_checks";
    let canonical_negative_checks = if fault == 0 {
        n.input
            .service_ref()?
            .lab_producer_binding_schema_checks(n.request.as_ref().ok_or(Error::Interrupted)?)?
    } else {
        0
    };
    let final_process_verified_at = n.final_verified_at;
    let before_drop = [
        kernel::lab_live_child_capacity(),
        vprouter_native_role::lab_live_child_capacity(),
    ];
    trace.charges = Some(before_drop);
    trace.phase = "charge_and_creating_boundary";
    let expected_charges = match fault {
        2 => [2, 1],
        3 => [0, 0],
        _ => [1, 1],
    };
    if before_drop != expected_charges
        || preparation["entry_phase"] != "creating"
        || preparation["entry_links_absent"] != true
        || preparation["entry_attempt_absent"] != true
        || preparation["entry_terminal_absent"] != true
    {
        return Err(Error::OwnershipMismatch);
    }
    let mut witness = serde_json::json!({"schema":1,"fault":fault,"assembly":assembly_witness,"preparation":preparation,"query":query,"observation":observation,"failed_constructor":failed_constructor,
        "canonical_negative_checks":canonical_negative_checks,"original_group":original_group,"final_process_verified_at":final_process_verified_at,"charges_before":before,"charges_before_drop":before_drop,"failure_retry":failure_retry,"retained_result_writer":retained_result_writer,
        "canonical_producer_published":fault==0,"unacknowledged_observation_retained":fault==2,"result_writer_held":held,
        "whole_chain_retained_after_drop":false,"producer_binding_context_retained_after_drop":false,"assembly_context_retained_after_drop":false,"producer_context_retained_after_drop":false,"quarantine_context_retained_after_drop":false,"movement_context_retained_after_drop":false,"original_provision_context_retained_after_drop":false,
        "same_original_source":true,"parent_pristine":vprouter_core::secret_boundary::pristine(),"producer_exception_authorized":false,"placement_authorized":false,"health_ready_authorized":false,"up_authorized":false,"host_network_links_or_routes_created":false,"resource_cleanup_authorized":false,"multi_exit_runtime_proven":false,"requirement8_complete":false});
    if continuation {
        if fault != 0 || complete.is_none() {
            return Err(Error::OwnershipMismatch);
        }
        witness["continued_original_context"] = serde_json::json!(true);
        witness["charges_after_drop"] = serde_json::Value::Null;
        trace.finished = true;
        return Ok((complete.take(), witness));
    }
    drop(complete);
    drop(pending);
    drop(slot);
    drop(original_source);
    trace.phase = "whole_owner_after_drop";
    let after = [
        kernel::lab_live_child_capacity(),
        vprouter_native_role::lab_live_child_capacity(),
    ];
    if weak.upgrade().is_none() || old.iter().any(|w| w.upgrade().is_none()) || after != before_drop
    {
        return Err(Error::OwnershipMismatch);
    }
    if fault == 2 {
        trace.phase = "result_writer_charge_after_drop";
        let (pid, start, status) = original_result_charge
            .as_ref()
            .ok_or(Error::OwnershipMismatch)?
            .facts()?;
        let original = &witness["retained_result_writer"];
        if original["pid"] != pid
            || original["start"] != start
            || status != Some(9)
            || original["actual_wait_status"] != 9
        {
            return Err(Error::OwnershipMismatch);
        }
        witness["retained_result_writer"]["charge_retained_after_drop"] = serde_json::json!(true);
    }
    for key in [
        "whole_chain_retained_after_drop",
        "producer_binding_context_retained_after_drop",
        "assembly_context_retained_after_drop",
        "producer_context_retained_after_drop",
        "quarantine_context_retained_after_drop",
        "movement_context_retained_after_drop",
        "original_provision_context_retained_after_drop",
    ] {
        witness[key] = serde_json::Value::Bool(true);
    }
    witness["charges_after_drop"] = serde_json::json!(after);
    trace.finished = true;
    println!("{}", serde_json::json!({"case":label,"result":"PASS"}));
    println!("LAB_SECRET_PRODUCER_BINDING {witness}");
    Ok((None, witness))
}
