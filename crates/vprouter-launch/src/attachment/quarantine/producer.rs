//! Original, exclusive empty producer creation only. This receipt is not a
//! ProducerGroup, placement permission, nft exception, or activation grant.
use super::*;
use rustix::fs::{self, Mode, OFlags};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
pub(crate) struct Request {
    creator: u32,
    binding: Rc<Binding>,
    query: Rc<kernel::docker_query::Accepted>,
    parent: OwnedFd,
    parent_token: inventory::Registration,
    parent_identity: Identity,
    name: String,
    digest: [u8; 32],
}
impl Request {
    fn new(
        input: &QuarantinedPrimary,
        query: Rc<kernel::docker_query::Accepted>,
    ) -> Result<Rc<Self>> {
        let binding = input.producer_binding()?;
        query.verify_producer_service(input.service_ref()?)?;
        if query
            .request()
            .quarantine
            .as_ref()
            .is_none_or(|b| !Rc::ptr_eq(b, &binding))
        {
            return Err(Error::OwnershipMismatch);
        }
        query.request().revalidate_quarantine_process_pins()?;
        let original = binding.data().request();
        let parent = original
            .original_cgroup_parent()?
            .try_clone_to_owned()
            .map_err(|_| Error::DescriptorDuplicate)?;
        let parent_token = inventory::Registration::owned(&[parent.as_fd()])?;
        let parent_identity = parent_identity(parent.as_fd())?;
        let spec = original.spec();
        let name = vprouter_netfilter::SocketProducer::group_name(&spec.allocation, &spec.exit);
        use sha2::Digest;
        let digest = sha2::Sha256::digest(
            serde_json::to_vec(&(
                "original_exclusive_empty_producer_v1",
                binding.configuration_digest(),
                binding.public_result(),
                query.request().digest(),
                query.request().requested_at(),
                parent_identity,
                &name,
                binding.data().request().source_identity(),
                binding.transport().request().source_identity(),
            ))
            .map_err(|_| Error::InvalidSpec)?,
        )
        .into();
        let value = Rc::new(Self {
            creator: std::process::id(),
            binding,
            query,
            parent,
            parent_token,
            parent_identity,
            name,
            digest,
        });
        value.verify()?;
        Ok(value)
    }
    pub(crate) fn verify_retained(&self) -> Result<()> {
        if self.creator != std::process::id()
            || !vprouter_core::secret_boundary::pristine()
            || !self.parent_token.contains(self.parent.as_fd())
            || parent_identity(self.parent.as_fd())? != self.parent_identity
        {
            return Err(Error::OwnershipMismatch);
        }
        self.binding.verify_retained()
    }
    pub(crate) fn verify(&self) -> Result<()> {
        self.check()?;
        self.verify_retained()?;
        self.query.request().revalidate_quarantine_process_pins()?;
        if Identity::of(self.binding.data().request().original_cgroup_parent()?)?
            != self.parent_identity
        {
            return Err(Error::CgroupMismatch);
        }
        self.check()
    }
    pub(crate) fn verify_service(&self, s: &Server) -> Result<()> {
        self.verify()?;
        self.binding.verify(s)?;
        self.query.verify_producer_service(s)
    }
    pub(crate) fn check(&self) -> Result<()> {
        if self.creator != std::process::id()
            || self.query.request().kind() != QueryKind::ProducerRecheck
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
    pub(crate) fn binding(&self) -> &Rc<Binding> {
        &self.binding
    }
    pub(crate) fn digest(&self) -> [u8; 32] {
        self.digest
    }
    pub(crate) fn query_digest(&self) -> [u8; 32] {
        self.query.request().digest()
    }
    pub(crate) fn parent(&self) -> BorrowedFd<'_> {
        self.parent.as_fd()
    }
    pub(crate) fn parent_identity(&self) -> Identity {
        self.parent_identity
    }
    pub(crate) fn name(&self) -> &str {
        &self.name
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
pub(crate) fn parent_identity(fd: BorrowedFd<'_>) -> Result<Identity> {
    let st = fs::fstat(fd).map_err(|_| Error::CgroupMismatch)?;
    if fs::fstatfs(fd).map_err(|_| Error::CgroupMismatch)?.f_type as u64 != 0x63677270
        || fs::FileType::from_raw_mode(st.st_mode) != fs::FileType::Directory
        || st.st_uid != 0
        || st.st_gid != 0
        || st.st_mode & 0o022 != 0
    {
        return Err(Error::CgroupMismatch);
    }
    Ok(Identity {
        dev: st.st_dev,
        ino: st.st_ino,
    })
}
pub(crate) fn verify_created_group(request: &Request, group: BorrowedFd<'_>) -> Result<Identity> {
    request.verify_retained()?;
    #[cfg(test)]
    let _retained_cost = super::super::super::owned::preparation::lab_cost::RetainedTimer::new(
        super::super::super::owned::preparation::lab_cost::RetainedKey::CreatedGroupNative,
    );
    let id = parent_identity(group)?;
    let st = fs::fstat(group).map_err(|_| Error::CgroupMismatch)?;
    let named = fs::statat(
        request.parent(),
        request.name(),
        fs::AtFlags::SYMLINK_NOFOLLOW,
    )
    .map_err(|_| Error::CgroupMismatch)?;
    let parent = fs::openat(
        group,
        "..",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| Error::CgroupMismatch)?;
    if id == request.parent_identity()
        || id.dev != request.parent_identity().dev
        || parent_identity(parent.as_fd())? != request.parent_identity()
        || (
            named.st_dev,
            named.st_ino,
            named.st_mode,
            named.st_uid,
            named.st_gid,
        ) != (id.dev, id.ino, st.st_mode, 0, 0)
        || st.st_mode & 0o7777 != 0o700
    {
        return Err(Error::CgroupMismatch);
    }
    for (name, expected) in [
        ("cgroup.procs", ""),
        ("cgroup.type", "domain"),
        ("cgroup.subtree_control", ""),
    ] {
        if read(group, name)?.trim() != expected {
            return Err(Error::CgroupMismatch);
        }
    }
    let events = read(group, "cgroup.events")?;
    let lines: Vec<_> = events.lines().collect();
    if lines != ["populated 0", "frozen 0"] {
        return Err(Error::CgroupMismatch);
    }
    Ok(id)
}
fn read(fd: BorrowedFd<'_>, name: &str) -> Result<String> {
    use std::io::Read;
    let fd = fs::openat2(
        fd,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        fs::ResolveFlags::BENEATH | fs::ResolveFlags::NO_SYMLINKS,
    )
    .map_err(|_| Error::CgroupMismatch)?;
    let st = fs::fstat(&fd).map_err(|_| Error::CgroupMismatch)?;
    if fs::FileType::from_raw_mode(st.st_mode) != fs::FileType::RegularFile
        || st.st_uid != 0
        || st.st_gid != 0
        || fs::fstatfs(&fd).map_err(|_| Error::CgroupMismatch)?.f_type as u64 != 0x63677270
    {
        return Err(Error::CgroupMismatch);
    }
    let mut bytes = String::new();
    std::fs::File::from(fd)
        .take(4097)
        .read_to_string(&mut bytes)
        .map_err(|_| Error::CgroupMismatch)?;
    if bytes.len() > 4096 {
        return Err(Error::TooLarge);
    }
    Ok(bytes)
}

#[cfg(test)]
impl Request {
    pub(crate) fn lab_registered_slots(&self) -> Result<usize> {
        self.verify_retained()?;
        self.parent_token.lab_live_slots()
    }
}

pub(super) struct PendingProducer {
    native: Option<Box<Native>>,
}
pub(crate) struct PreparedProducer {
    native: Option<Box<Native>>,
}
struct Native {
    creator: u32,
    input: QuarantinedPrimary,
    query: Rc<InspectionRequest>,
    query_child: Option<kernel::docker_query::Child>,
    query_verified: Option<kernel::docker_query::Verified>,
    query_accepted: Option<Rc<kernel::docker_query::Accepted>>,
    request: Option<Rc<Request>>,
    child: Option<kernel::producer_creation::Child>,
    source: Option<Rc<kernel::producer_creation::Source>>,
    step: Step,
    failure: Option<Error>,
    #[cfg(test)]
    anchor: Rc<()>,
    #[cfg(test)]
    final_verified_at: Option<f64>,
}
#[derive(Clone, Copy)]
enum Step {
    QueryIntent,
    QueryBirth,
    QueryReading,
    QueryResult,
    Intent,
    Birth,
    Creating,
    Result,
    Complete,
}
// Keep the same heap-owned bundle on retention; never move its pointee onto the stack.
thread_local! { #[allow(clippy::vec_box)] static RETAINED:RefCell<Vec<Box<Native>>>=const{RefCell::new(Vec::new())}; }
impl Native {
    fn fail(&mut self, error: Error) {
        if self.creator != std::process::id() {
            return;
        }
        self.failure.get_or_insert(error);
        if let Some(n) = &mut self.input.native {
            n.fail(error);
        }
        if let Some(c) = &mut self.query_child {
            c.cancel(error);
        }
        if let Some(c) = &mut self.child {
            c.cancel(error);
        }
    }
    fn collect(&mut self) {
        if self.creator != std::process::id() {
            return;
        }
        if let Some(n) = &mut self.input.native {
            n.collect();
        }
        if let Some(c) = &mut self.query_child {
            c.collect();
        }
        if let Some(c) = &mut self.child {
            c.collect();
        }
    }
    fn reaped(&self) -> bool {
        self.input.native.as_ref().is_none_or(|n| n.reaped())
            && self
                .query_child
                .as_ref()
                .is_none_or(kernel::docker_query::Child::reaped)
            && self
                .child
                .as_ref()
                .is_none_or(kernel::producer_creation::Child::reaped)
    }
    fn advance(&mut self) -> Result<()> {
        self.query.check_deadline()?;
        match self.step {
            Step::QueryIntent => {
                if let Some(intent) = self.input.service()?.poll_inspection_intent(&self.query)? {
                    self.query_child =
                        Some(kernel::docker_query::spawn(self.query.clone(), intent)?);
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
                    self.input.service()?.start_producer_creation(
                        self.request.as_ref().ok_or(Error::Interrupted)?,
                    )?;
                    self.step = Step::Intent;
                }
            }
            Step::Intent => {
                let r = self.request.as_ref().ok_or(Error::Interrupted)?;
                if let Some(i) = self.input.service()?.poll_producer_creation_intent(r)? {
                    self.child = Some(kernel::producer_creation::spawn(r.clone(), i)?);
                    self.input.service()?.start_producer_creation_birth(
                        self.child.as_ref().ok_or(Error::Interrupted)?,
                    )?;
                    self.step = Step::Birth;
                }
            }
            Step::Birth => {
                let c = self.child.as_mut().ok_or(Error::Interrupted)?;
                if let Some(g) = self.input.service()?.poll_producer_creation_birth(c)? {
                    c.release(g)?;
                    self.step = Step::Creating;
                }
            }
            Step::Creating => {
                if let Some(s) = self.child.as_mut().ok_or(Error::Interrupted)?.poll()? {
                    self.source = Some(Rc::new(s));
                    self.input.service()?.start_producer_creation_source(
                        self.source.as_ref().ok_or(Error::Interrupted)?,
                    )?;
                    self.step = Step::Result;
                }
            }
            Step::Result => {
                let s = Rc::get_mut(self.source.as_mut().ok_or(Error::Interrupted)?)
                    .ok_or(Error::OwnershipMismatch)?;
                if let Some(r) = self.input.service()?.poll_producer_creation_source(s)? {
                    s.accept(r)?;
                    self.request.as_ref().ok_or(Error::Interrupted)?.verify()?;
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
impl PendingProducer {
    pub(super) fn new(slot: &mut Option<QuarantinedPrimary>) -> Result<Self> {
        let input = slot.as_ref().ok_or(Error::Interrupted)?;
        let binding = input.producer_binding()?;
        let query = InspectionRequest::for_owned_quarantine(
            binding,
            input.service_ref()?,
            QueryKind::ProducerRecheck,
        )?;
        let mut value = Self {
            native: Some(Box::new(Native {
                creator: std::process::id(),
                input: slot.take().ok_or(Error::Interrupted)?,
                query,
                query_child: None,
                query_verified: None,
                query_accepted: None,
                request: None,
                child: None,
                source: None,
                step: Step::QueryIntent,
                failure: None,
                #[cfg(test)]
                anchor: Rc::new(()),
                #[cfg(test)]
                final_verified_at: None,
            })),
        };
        let n = value.native.as_mut().ok_or(Error::Interrupted)?;
        n.input.service()?.start_inspection(&n.query)?;
        Ok(value)
    }
    pub(super) fn poll(&mut self) -> Result<Option<PreparedProducer>> {
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        if n.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        if let Some(e) = n.failure {
            n.collect();
            return Err(e);
        }
        if let Err(e) = n.advance() {
            n.fail(e);
            n.collect();
            return Err(e);
        }
        if matches!(n.step, Step::Complete) {
            Ok(Some(PreparedProducer {
                native: self.native.take(),
            }))
        } else {
            Ok(None)
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
impl Drop for PendingProducer {
    fn drop(&mut self) {
        if let Some(n) = self.native.take() {
            retain(n);
        }
    }
}
impl PreparedProducer {
    #[cfg(test)]
    pub(crate) fn lab_bootstrap_result_charge(
        &mut self,
        failed: bool,
    ) -> Result<(kernel::LabJournalCharge, serde_json::Value)> {
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        if n.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        n.input.lab_bootstrap_result_charge(failed)
    }

    pub(crate) fn bootstrap_initial(
        &mut self,
        scope: super::Scope,
    ) -> Result<&mut kernel::netfilter_role::Verified> {
        self.service_ref()?;
        self.native
            .as_mut()
            .ok_or(Error::Interrupted)?
            .input
            .bootstrap_initial(scope)
    }
    pub(crate) fn children_reaped(&self) -> bool {
        self.native
            .as_ref()
            .is_none_or(|n| n.creator == std::process::id() && n.reaped())
    }

    pub(crate) fn assembly_plan(&self) -> Result<Vec<kernel::ResourceTransfer>> {
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        if n.creator != std::process::id()
            || n.failure.is_some()
            || !matches!(n.step, Step::Complete)
            || n.query_accepted.is_none()
            || n.query_verified.is_some()
        {
            return Err(Error::OwnershipMismatch);
        }
        n.input
            .assembly_plan(n.source.as_ref().ok_or(Error::Interrupted)?)
    }
    pub(crate) fn service_ref(&self) -> Result<&Server> {
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        if n.creator != std::process::id()
            || n.failure.is_some()
            || !matches!(n.step, Step::Complete)
        {
            return Err(Error::OwnershipMismatch);
        }
        n.input.service_ref()
    }
    pub(crate) fn binding_source(&self) -> Result<Rc<kernel::producer_creation::Source>> {
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        self.service_ref()?;
        let source = n.source.as_ref().ok_or(Error::OwnershipMismatch)?;
        source.bind_service(n.input.service_ref()?)?;
        source.verify_acknowledged_history()?;
        Ok(source.clone())
    }
    pub(crate) fn binding_context(&self) -> Result<Rc<Binding>> {
        self.service_ref()?;
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        n.input.binding_context()
    }
    pub(crate) fn binding_initial(&mut self) -> Result<&mut kernel::netfilter_role::Verified> {
        self.service_ref()?;
        self.native
            .as_mut()
            .ok_or(Error::Interrupted)?
            .input
            .binding_initial()
    }
    pub(crate) fn service(&mut self) -> Result<&mut Server> {
        self.service_ref()?;
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
}
impl Drop for PreparedProducer {
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

#[cfg(test)]
pub(super) fn lab_build(fault: u8) -> Result<serde_json::Value> {
    lab_build_inner(fault, false).map(|(_, w)| w)
}
#[cfg(test)]
pub(crate) fn lab_prepared() -> Result<(PreparedProducer, serde_json::Value)> {
    let (owner, witness) = lab_build_inner(0, true)?;
    Ok((owner.ok_or(Error::OwnershipMismatch)?, witness))
}
#[cfg(test)]
fn lab_build_inner(
    fault: u8,
    continuation: bool,
) -> Result<(Option<PreparedProducer>, serde_json::Value)> {
    if continuation && fault != 0 {
        return Err(Error::InvalidSpec);
    }
    use std::time::Duration;
    let (moved, movement) = super::super::movement::lab_moved()?;
    let (movement_weak, provision_weak) = moved.lab_anchors()?;
    let mut moved = Some(moved);
    super::lab_arm_stages();
    let mut quarantine = PendingQuarantine::new(
        &mut moved,
        Path::new("/var/lib/vprouter-v2-lab/secret-quarantine-host.json"),
    )?;
    let quarantine_weak =
        Rc::downgrade(&quarantine.native.as_ref().ok_or(Error::Interrupted)?.anchor);
    quarantine
        .native
        .as_mut()
        .ok_or(Error::Interrupted)?
        .input
        .service()?
        .lab_hold_netfilter_intent()?;
    let mut queued_polls = 0usize;
    let mut held_pending_polls = 0usize;
    let mut progress_negative_checks = 0usize;
    let mut original_intent_writer = None;
    let mut original_intent_start = None;
    let mut intent_released = false;
    let q = loop {
        let mut held_this_poll = None;
        {
            let n = quarantine.native.as_mut().ok_or(Error::Interrupted)?;
            if matches!(n.step, super::Step::Intent) && n.previous.is_empty() && !intent_released {
                let request = n.request.as_ref().ok_or(Error::Interrupted)?;
                original_intent_start = Some(request.requested_at());
                let pending = n.input.service_ref()?.lab_pending_writer_identity()?;
                if pending.is_none() && queued_polls == 0 {
                    progress_negative_checks += n
                        .binding
                        .lab_own_intent_negatives(n.input.service_ref()?, request)?;
                    queued_polls += 1;
                }
                if let Some(identity) = pending
                    && n.input.service()?.lab_checkpoint()?
                {
                    if original_intent_writer.is_some_and(|old| old != identity) {
                        return Err(Error::OwnershipMismatch);
                    }
                    original_intent_writer = Some(identity);
                    if held_pending_polls == 0 {
                        progress_negative_checks += n.binding.lab_own_intent_negatives(
                            n.input.service_ref()?,
                            n.request.as_ref().ok_or(Error::Interrupted)?,
                        )?;
                    }
                    held_this_poll = Some(identity);
                }
            }
        }
        super::lab_own_intent(
            queued_polls,
            held_pending_polls,
            intent_released,
            original_intent_writer,
        );
        match quarantine.poll() {
            Ok(Some(v)) => break v,
            Ok(None) => {
                if let Some(identity) = held_this_poll {
                    let n = quarantine.native.as_mut().ok_or(Error::Interrupted)?;
                    if !matches!(n.step, super::Step::Intent)
                        || n.input.service_ref()?.lab_pending_writer_identity()? != Some(identity)
                    {
                        return Err(Error::OwnershipMismatch);
                    }
                    held_pending_polls += 1;
                    if held_pending_polls == 2 {
                        n.input.service()?.lab_release_netfilter_intent()?;
                        intent_released = true;
                    }
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(e) => {
                eprintln!("LAB_SECRET_QUARANTINE_FAILURE phase=initial_quarantine reason={e:?}");
                return Err(e);
            }
        }
    };
    let mut q = Some(q);
    let mut pending = PendingProducer::new(&mut q)?;
    let producer_weak = Rc::downgrade(&pending.native.as_ref().ok_or(Error::Interrupted)?.anchor);
    let mut armed = false;
    let mut held = false;
    let result = loop {
        let n = pending.native.as_mut().ok_or(Error::Interrupted)?;
        if !armed {
            if matches!(fault, 1 | 3) && matches!(n.step, Step::Intent) {
                kernel::producer_creation::lab_arm(
                    n.request.as_ref().ok_or(Error::Interrupted)?,
                    fault,
                );
                armed = true;
            } else if fault == 2 && matches!(n.step, Step::Creating) {
                n.input.service()?.lab_hold_producer_result()?;
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
    match result {
        Ok(v) if fault == 0 => complete = Some(v),
        Ok(_) => return Err(Error::OwnershipMismatch),
        Err(error) => {
            let n = pending.native.as_mut().ok_or(Error::Interrupted)?;
            eprintln!(
                "LAB_SECRET_QUARANTINE_FAILURE phase={} reason={error:?} requested_at={} deadline={} now={}",
                match n.step {
                    Step::QueryIntent => "producer_query_intent",
                    Step::QueryBirth => "producer_query_birth",
                    Step::QueryReading => "producer_query_reading",
                    Step::QueryResult => "producer_query_result",
                    Step::Intent => "producer_intent",
                    Step::Birth => "producer_birth",
                    Step::Creating => "producer_creating",
                    Step::Result => "producer_result",
                    Step::Complete => "complete",
                },
                n.query.requested_at(),
                n.query.deadline(),
                vprouter_core::health::boot_seconds()
            );
            if !armed
                || !(fault == 2 && held && error == Error::ChildFailed
                    || matches!(fault, 1 | 3) && error == Error::DescriptorInventory)
            {
                return Err(error);
            }
            let collect_end = vprouter_core::health::boot_seconds() + 2.;
            loop {
                n.collect();
                if matches!(fault, 1 | 3) {
                    failed_constructor = kernel::producer_creation::lab_failed_context(
                        n.request.as_ref().ok_or(Error::Interrupted)?,
                    )?;
                }
                if n.reaped() && (fault == 2 || failed_constructor.is_some()) {
                    break;
                }
                if vprouter_core::health::boot_seconds() >= collect_end {
                    return Err(Error::Deadline);
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    }
    let n = if let Some(v) = &mut complete {
        v.native.as_mut()
    } else {
        pending.native.as_mut()
    }
    .ok_or(Error::Interrupted)?;
    let producer = n
        .source
        .as_mut()
        .map(|s| {
            Rc::get_mut(s)
                .ok_or(Error::OwnershipMismatch)?
                .lab_evidence()
        })
        .transpose()?;
    let producer_query = n
        .query_accepted
        .as_ref()
        .ok_or(Error::OwnershipMismatch)?
        .lab_evidence()?;
    let q = n
        .input
        .native
        .as_mut()
        .ok_or(Error::Interrupted)?
        .lab_evidence()?;
    let preparation = &q["preparation"];
    let writers = preparation["writers"]
        .as_array()
        .ok_or(Error::OwnershipMismatch)?;
    let (intent_index, intent_pid, intent_start) =
        original_intent_writer.ok_or(Error::OwnershipMismatch)?;
    let intent_requested = original_intent_start.ok_or(Error::OwnershipMismatch)?;
    let intent_receipt = writers.get(intent_index).ok_or(Error::OwnershipMismatch)?;
    if queued_polls != 1
        || held_pending_polls < 2
        || progress_negative_checks != 12
        || !intent_released
        || intent_index != 42
        || intent_receipt["phase"] != "netfilter_intent"
        || intent_receipt["pid"] != intent_pid
        || intent_receipt["start"] != intent_start
        || intent_receipt["actual_wait_status"] != 0
        || intent_receipt["io_deadline"] != intent_requested + 2.
        || intent_receipt["parent_deadline"] != intent_requested + 2.
        || intent_receipt["verified_at"].as_f64().is_none_or(|at| {
            !at.is_finite() || at < intent_requested || at >= intent_requested + 2.
        })
    {
        return Err(Error::OwnershipMismatch);
    }
    let own_intent_polling = serde_json::json!({"queued_polls":queued_polls,"held_pending_polls":held_pending_polls,
        "negative_checks":progress_negative_checks,"original_writer":{"index":intent_index,"pid":intent_pid,"start":intent_start},
        "requested_at":intent_requested,"deadline":intent_requested+2.,"verified_at":intent_receipt["verified_at"],"actual_wait_status":0});
    let old = movement["preparation"]["writers"]
        .as_array()
        .ok_or(Error::OwnershipMismatch)?;
    if writers.len() != if matches!(fault, 1 | 3) { 67 } else { 69 }
        || writers.get(..42) != Some(old.as_slice())
        || movement["continued_original_context"] != true
        || movement["whole_chain_retained_after_drop"] != false
        || movement["movement_context_retained_after_drop"] != false
        || movement["original_provision_context_retained_after_drop"] != false
        || preparation["canonical_pending"] != (fault == 2)
        || preparation["mutation_fenced"] != (fault == 2)
        || preparation["service_reserved"] != true
        || preparation["native_children_reaped"] != true
        || preparation["member_native_jobs_collected"] != false
        || preparation["entry_producer_absent"] != true
        || !vprouter_core::secret_boundary::pristine()
    {
        return Err(Error::OwnershipMismatch);
    }
    for name in [
        "member",
        "canonical_owner_epoch",
        "inspection",
        "attachment",
        "fresh_transport",
        "wireguard",
        "movement_query",
        "base_network",
        "data_network",
        "transport_network",
    ] {
        if preparation[name] != movement["preparation"][name] {
            return Err(Error::OwnershipMismatch);
        }
    }
    let histories = preparation["netfilter"]
        .as_array()
        .ok_or(Error::OwnershipMismatch)?;
    let operations = q["operations"].as_array().ok_or(Error::OwnershipMismatch)?;
    if histories.len() != 6 || operations.len() != 6 {
        return Err(Error::OwnershipMismatch);
    }
    for (i, (h, o)) in histories.iter().zip(operations).enumerate() {
        if o["request"] != h["request"]
            || o["birth"] != h["birth"]
            || o["result"] != h["result"]
            || o["accepted_at"] != h["verified_at"]
            || o["actual_wait_status"] != 0
            || o["acknowledged"] != true
            || o["full_descriptor_registration"] != true
            || o["context_retained"] != true
            || o["borrowed_registration_count"] != if i % 2 == 0 { 0 } else { 2 }
        {
            return Err(Error::OwnershipMismatch);
        }
    }
    let ph = &preparation["producer_creation"];
    if producer_query["kind"] != "ProducerRecheck"
        || producer_query["actual_wait_status"] != 0
        || producer_query["birth"] != preparation["producer_query"]["birth"]
        || producer_query["facts"] != preparation["producer_query"]["facts"]
        || producer_query["verified_at"] != preparation["producer_query"]["verified_at"]
        || producer_query["requested_at"] != ph["requested_at"]
        || producer_query["deadline"] != ph["deadline"]
    {
        return Err(Error::OwnershipMismatch);
    }
    for (i, w) in writers.iter().enumerate().skip(42) {
        let (phase, end) = if i < 57 {
            (
                ["netfilter_intent", "netfilter_birth", "netfilter_result"][(i - 42) % 3],
                histories[(i - 42) / 3]["deadline"].as_f64(),
            )
        } else if i < 60 {
            (
                [
                    "quarantine_query_intent",
                    "quarantine_query_birth",
                    "quarantine_query_result",
                ][i - 57],
                q["quarantine_query"]["deadline"].as_f64(),
            )
        } else if i < 63 {
            (
                ["netfilter_intent", "netfilter_birth", "netfilter_result"][i - 60],
                histories[5]["deadline"].as_f64(),
            )
        } else if i < 66 {
            (
                [
                    "producer_query_intent",
                    "producer_query_birth",
                    "producer_query_result",
                ][i - 63],
                producer_query["deadline"].as_f64(),
            )
        } else {
            (
                ["producer_intent", "producer_birth", "producer_result"][i - 66],
                ph["deadline"].as_f64(),
            )
        };
        let end = end.ok_or(Error::OwnershipMismatch)?;
        let queued = w["queued_at"].as_f64().ok_or(Error::OwnershipMismatch)?;
        let failed = fault == 2 && i == 68;
        if w["phase"] != phase
            || !end.is_finite()
            || !queued.is_finite()
            || queued < end - 2.
            || queued >= end
            || w["io_deadline"] != end
            || w["parent_deadline"] != end
            || w["actual_wait_status"] != if failed { 9 } else { 0 }
            || if failed {
                !w["verified_at"].is_null()
            } else {
                w["verified_at"]
                    .as_f64()
                    .is_none_or(|at| !at.is_finite() || at < queued || at >= end)
            }
        {
            return Err(Error::OwnershipMismatch);
        }
    }
    if let Some(f) = &failed_constructor {
        if f["request"] != ph["request"]
            || f["full_descriptor_registration"] != true
            || f["native_born"] != (fault == 1)
            || f["native_job_state"] != if fault == 1 { "born" } else { "prepared" }
            || !f["birth"].is_null()
            || !f["original_start"].is_null()
            || !ph["birth"].is_null()
            || !ph["group"].is_null()
            || !ph["verified_at"].is_null()
            || if fault == 1 {
                f["actual_wait_status"] != 9 || f["original_pid"].as_u64().is_none_or(|p| p <= 1)
            } else {
                !f["actual_wait_status"].is_null() || !f["original_pid"].is_null()
            }
        {
            return Err(Error::OwnershipMismatch);
        }
    } else {
        let p = producer.as_ref().ok_or(Error::OwnershipMismatch)?;
        let bound = if fault == 2 {
            if !ph["group"].is_null() || !ph["verified_at"].is_null() {
                return Err(Error::OwnershipMismatch);
            }
            &preparation["pending_producer_creation"]
        } else {
            ph
        };
        if p["request"] != ph["request"]
            || p["birth"] != ph["birth"]
            || p["group"] != bound["group"]
            || p["verified_at"] != bound["verified_at"]
            || p["actual_wait_status"] != 0
            || p["eof"] != true
            || p["received_original_group"] != true
            || p["durable_birth_released"] != true
            || p["acknowledged"] != (fault == 0)
            || p["full_descriptor_registration"] != true
            || p["operational_publication"] != false
        {
            return Err(Error::OwnershipMismatch);
        }
    }
    if fault == 0 {
        let at = n.final_verified_at.ok_or(Error::OwnershipMismatch)?;
        if !at.is_finite()
            || at
                < writers[68]["verified_at"]
                    .as_f64()
                    .ok_or(Error::OwnershipMismatch)?
            || at >= n.query.deadline()
        {
            return Err(Error::OwnershipMismatch);
        }
    } else if n.final_verified_at.is_some() {
        return Err(Error::OwnershipMismatch);
    }
    let witness = serde_json::json!({"schema":1,"fault":fault,"movement":movement,"preparation":preparation,"operations":operations,
        "own_intent_polling":own_intent_polling,"quarantine_query":q["quarantine_query"],"wan":q["wan"],"producer_query":producer_query,"producer":producer,"failed_constructor":failed_constructor,
        "final_process_verified_at":n.final_verified_at,"held_real_result_writer":held,"unacknowledged_native_result_retained":fault==2,
        "whole_chain_retained_after_drop":!continuation,"quarantine_context_retained_after_drop":!continuation,"producer_context_retained_after_drop":!continuation,
        "movement_context_retained_after_drop":!continuation,"original_provision_context_retained_after_drop":!continuation,"continued_original_context":continuation,
        "parent_pristine":true,"same_service_retained":true,"initial_quarantine_only":true,"producer_operational_publication":false,
        "producer_exceptions_authorized":false,"host_network_links_or_routes_created":false,"initial_quarantine_installation_observed_all_scopes":true,"producer_group_creation_observed":matches!(fault,0|2),"up_authorized":false,"operational_reuse_authorized":false,"requirement8_complete":false});
    if continuation {
        return Ok((complete.take(), witness));
    }
    drop(complete);
    drop(pending);
    drop(quarantine);
    if producer_weak.upgrade().is_none()
        || quarantine_weak.upgrade().is_none()
        || movement_weak.upgrade().is_none()
        || provision_weak.upgrade().is_none()
    {
        return Err(Error::OwnershipMismatch);
    }
    Ok((None, witness))
}

#[cfg(test)]
impl PreparedProducer {
    pub(crate) fn lab_anchors(&self) -> Result<[std::rc::Weak<()>; 4]> {
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        if n.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        let q = n.input.native.as_ref().ok_or(Error::Interrupted)?;
        let (movement, provision) = q.input.lab_anchors()?;
        Ok([
            Rc::downgrade(&n.anchor),
            Rc::downgrade(&q.anchor),
            movement,
            provision,
        ])
    }
    pub(crate) fn lab_preparation(&mut self) -> Result<serde_json::Value> {
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        if n.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        n.input
            .native
            .as_mut()
            .ok_or(Error::Interrupted)?
            .input
            .lab_service()?
            .lab_evidence()
    }
    pub(crate) fn lab_binding_result_charge(
        &mut self,
        failed: bool,
    ) -> Result<(kernel::LabJournalCharge, serde_json::Value)> {
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        if n.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        n.input
            .native
            .as_mut()
            .ok_or(Error::Interrupted)?
            .input
            .lab_service()?
            .lab_binding_result_charge(failed)
    }
    pub(crate) fn lab_host_result_charge(
        &mut self,
        failed: bool,
    ) -> Result<(kernel::LabJournalCharge, serde_json::Value)> {
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        if n.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        n.input
            .native
            .as_mut()
            .ok_or(Error::Interrupted)?
            .input
            .lab_service()?
            .lab_host_result_charge(failed)
    }
}
