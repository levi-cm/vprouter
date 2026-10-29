//! Fresh TRANSPORT namespace origin. It is never the attached DATA namespace,
//! a parsed identity, or a namespace discovered by reopening a process path.
use super::super::{
    inventory, kernel,
    owned::{Identity, preparation::Server},
};
use super::{Error, Result, mount::AttachedPrimary};
use std::{
    cell::RefCell,
    os::fd::{AsFd, BorrowedFd, OwnedFd},
    rc::Rc,
};

pub(crate) struct Request {
    creator: u32,
    data: Rc<kernel::namespace_attachment::Mounted>,
    host: OwnedFd,
    host_identity: Identity,
    host_token: inventory::Registration,
    directory: OwnedFd,
    directory_identity: Identity,
    directory_token: inventory::Registration,
    name: String,
    requested_at: f64,
    digest: [u8; 32],
}
impl Request {
    fn new(input: &AttachedPrimary) -> Result<Rc<Self>> {
        kernel::secret::seal_parent()?;
        kernel::owner_admission_permitted()?;
        let requested_at = vprouter_core::health::boot_seconds();
        let data = input.retained_data()?;
        let (directory, name) = input.service_ref()?.fresh_transport_target(&data)?;
        let directory_token = inventory::Registration::owned(&[directory.as_fd()])?;
        let directory_identity = Identity::of(&directory)?;
        let host = kernel::network()?;
        let host_token = inventory::Registration::owned(&[host.as_fd()])?;
        let host_identity = Identity::network(&host)?;
        use sha2::Digest;
        let digest = sha2::Sha256::digest(
            serde_json::to_vec(&(
                "fresh_transport_v1",
                data.request().digest(),
                data.birth()?,
                data.request().source_identity(),
                host_identity,
                directory_identity,
                &name,
                requested_at,
            ))
            .map_err(|_| Error::InvalidSpec)?,
        )
        .into();
        let value = Rc::new(Self {
            creator: std::process::id(),
            data,
            host,
            host_identity,
            host_token,
            directory,
            directory_identity,
            directory_token,
            name,
            requested_at,
            digest,
        });
        value.verify()?;
        Ok(value)
    }
    pub(crate) fn verify(&self) -> Result<()> {
        self.check()?;
        self.data.verify_retained()?;
        let s = rustix::fs::fstat(&self.directory).map_err(|_| Error::OwnershipMismatch)?;
        if !self.host_token.contains(self.host.as_fd())
            || !self.directory_token.contains(self.directory.as_fd())
            || Identity::network(&self.host)? != self.host_identity
            || Identity::of(&self.directory)? != self.directory_identity
            || s.st_mode != 0o40700
            || s.st_uid != 0
            || s.st_gid != 0
        {
            return Err(Error::OwnershipMismatch);
        }
        self.check()
    }
    pub(crate) fn check(&self) -> Result<()> {
        if self.creator != std::process::id() || !vprouter_core::secret_boundary::pristine() {
            return Err(Error::OwnershipMismatch);
        }
        kernel::owner_admission_permitted()?;
        let now = vprouter_core::health::boot_seconds();
        if !now.is_finite()
            || !self.requested_at.is_finite()
            || now < self.requested_at
            || now >= self.deadline()
        {
            return Err(Error::Deadline);
        }
        Ok(())
    }
    pub(crate) fn data(&self) -> &Rc<kernel::namespace_attachment::Mounted> {
        &self.data
    }
    pub(crate) fn host_identity(&self) -> Identity {
        self.host_identity
    }
    pub(crate) fn data_identity(&self) -> Identity {
        self.data.request().source_identity()
    }
    pub(crate) fn directory(&self) -> BorrowedFd<'_> {
        self.directory.as_fd()
    }
    pub(crate) fn directory_identity(&self) -> Identity {
        self.directory_identity
    }
    pub(crate) fn name(&self) -> &str {
        &self.name
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
}

pub(super) struct PendingTransport {
    native: Option<Native>,
}
/// Original source custody and durable Source acknowledgement, not a mounted
/// namespace or permission to publish a transport resource/activate a link.
pub(super) struct CreatedTransport {
    native: Option<Native>,
}
struct Native {
    creator: u32,
    input: AttachedPrimary,
    request: Rc<Request>,
    child: Option<kernel::fresh_transport::Child>,
    source: Option<Rc<kernel::fresh_transport::Source>>,
    step: Step,
    failure: Option<Error>,
}
#[derive(Clone, Copy)]
enum Step {
    Intent,
    Birth,
    Creating,
    SourceWriting,
    Complete,
}
thread_local! { static RETAINED: RefCell<Vec<Native>> = const { RefCell::new(Vec::new()) }; }
impl Native {
    fn fail(&mut self, error: Error) {
        if self.creator != std::process::id() {
            return;
        }
        self.failure.get_or_insert(error);
        if let Ok(service) = self.input.service() {
            service.fail(error);
        }
        if let Some(child) = &mut self.child {
            child.cancel(error);
        }
    }
    fn collect(&mut self) {
        if self.creator != std::process::id() {
            return;
        }
        if let Ok(service) = self.input.service() {
            service.collect();
        }
        if let Some(child) = &mut self.child {
            child.collect();
        }
    }
    fn advance(&mut self) -> Result<()> {
        self.request.check()?;
        let service = self.input.service()?;
        match self.step {
            Step::Intent => {
                if let Some(intent) = service.poll_fresh_transport_intent(&self.request)? {
                    self.child = Some(kernel::fresh_transport::spawn(
                        self.request.clone(),
                        intent,
                    )?);
                    service.start_fresh_transport_birth(
                        self.child.as_ref().ok_or(Error::Interrupted)?,
                    )?;
                    self.step = Step::Birth;
                }
            }
            Step::Birth => {
                let child = self.child.as_mut().ok_or(Error::Interrupted)?;
                if let Some(gate) = service.poll_fresh_transport_birth(child)? {
                    child.release(gate)?;
                    self.step = Step::Creating;
                }
            }
            Step::Creating => {
                if let Some(source) = self.child.as_mut().ok_or(Error::Interrupted)?.poll()? {
                    self.source = Some(source);
                    service.start_fresh_transport_source(
                        self.source.as_ref().ok_or(Error::Interrupted)?,
                    )?;
                    self.step = Step::SourceWriting;
                }
            }
            Step::SourceWriting => {
                if service
                    .poll_fresh_transport_source(self.source.as_ref().ok_or(Error::Interrupted)?)?
                {
                    self.step = Step::Complete;
                }
            }
            Step::Complete => (),
        }
        self.request.check()
    }
}
fn retain(mut n: Native) {
    if n.creator != std::process::id() {
        std::mem::forget(n);
        return;
    }
    {
        n.fail(Error::Interrupted);
        RETAINED.with(|r| r.borrow_mut().push(n));
    }
}
impl Drop for PendingTransport {
    fn drop(&mut self) {
        if let Some(n) = self.native.take() {
            retain(n);
        }
    }
}
impl Drop for CreatedTransport {
    fn drop(&mut self) {
        if let Some(n) = self.native.take() {
            retain(n);
        }
    }
}
pub(super) fn poll_retained() {
    MOUNTS.with(|r| {
        for n in r.borrow_mut().iter_mut() {
            n.collect();
        }
    });
    RETAINED.with(|r| {
        for n in r.borrow_mut().iter_mut() {
            n.collect();
        }
    });
}
pub(super) fn children_reaped() -> bool {
    let mounts_reaped = MOUNTS.with(|r| {
        r.borrow().iter().all(|n| {
            n.creator != std::process::id()
                || n.input.service_ref().is_ok_and(Server::children_reaped)
                    && n.child
                        .as_ref()
                        .is_none_or(kernel::fresh_transport_mount::Child::reaped)
        })
    });
    mounts_reaped
        && RETAINED.with(|r| {
            r.borrow().iter().all(|n| {
                n.creator != std::process::id()
                    || n.input.service_ref().is_ok_and(Server::children_reaped)
                        && n.child
                            .as_ref()
                            .is_none_or(kernel::fresh_transport::Child::reaped)
            })
        })
}
impl PendingTransport {
    pub(super) fn new(slot: &mut Option<AttachedPrimary>) -> Result<Self> {
        let input = slot.as_ref().ok_or(Error::Interrupted)?;
        let request = Request::new(input)?;
        let mut pending = Self {
            native: Some(Native {
                creator: std::process::id(),
                input: slot.take().ok_or(Error::Interrupted)?,
                request,
                child: None,
                source: None,
                step: Step::Intent,
                failure: None,
            }),
        };
        let n = pending.native.as_mut().ok_or(Error::Interrupted)?;
        n.input.service()?.start_fresh_transport(&n.request)?;
        Ok(pending)
    }
    pub(super) fn poll(&mut self) -> Result<Option<CreatedTransport>> {
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        if n.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        if let Some(error) = n.failure {
            n.collect();
            return Err(error);
        }
        if let Err(error) = n.advance() {
            n.fail(error);
            n.collect();
            return Err(error);
        }
        if matches!(n.step, Step::Complete) {
            Ok(Some(CreatedTransport {
                native: self.native.take(),
            }))
        } else {
            Ok(None)
        }
    }
}

/// A separately anchored mount of the original fixed creator's namespace.
/// Its creation history stays immutable and is consumed while still timely.
pub(crate) struct MountRequest {
    creator: u32,
    original: Rc<kernel::fresh_transport::Source>,
    source: OwnedFd,
    source_token: inventory::Registration,
    source_identity: Identity,
    directory: OwnedFd,
    directory_token: inventory::Registration,
    directory_identity: Identity,
    name: String,
    requested_at: f64,
    digest: [u8; 32],
}
impl MountRequest {
    fn new(input: &CreatedTransport) -> Result<Rc<Self>> {
        let n = input.native.as_ref().ok_or(Error::Interrupted)?;
        if n.creator != std::process::id()
            || n.failure.is_some()
            || !matches!(n.step, Step::Complete)
        {
            return Err(Error::OwnershipMismatch);
        }
        kernel::secret::seal_parent()?;
        kernel::owner_admission_permitted()?;
        let requested_at = vprouter_core::health::boot_seconds();
        let original = n.source.as_ref().ok_or(Error::OwnershipMismatch)?.clone();
        original.verify()?;
        n.input.service_ref()?.verify_transport_source(&original)?;
        let source = rustix::io::fcntl_dupfd_cloexec(original.descriptor()?, 3)
            .map_err(|_| Error::DescriptorDuplicate)?;
        let source_token = inventory::Registration::owned(&[source.as_fd()])?;
        let source_identity = Identity::network(&source)?;
        let directory = rustix::io::fcntl_dupfd_cloexec(original.request().directory(), 3)
            .map_err(|_| Error::DescriptorDuplicate)?;
        let directory_token = inventory::Registration::owned(&[directory.as_fd()])?;
        let directory_identity = Identity::of(&directory)?;
        let name = original.request().name().to_owned();
        use sha2::Digest;
        let digest = sha2::Sha256::digest(
            serde_json::to_vec(&(
                "fresh_transport_mount_v1",
                original.request().digest(),
                original.birth()?,
                source_identity,
                directory_identity,
                &name,
                requested_at,
            ))
            .map_err(|_| Error::InvalidSpec)?,
        )
        .into();
        let request = Rc::new(Self {
            creator: std::process::id(),
            original,
            source,
            source_token,
            source_identity,
            directory,
            directory_token,
            directory_identity,
            name,
            requested_at,
            digest,
        });
        request.verify_native()?;
        // Last old-clock check, immediately before consuming CreatedTransport.
        request.original.verify()?;
        Ok(request)
    }
    pub(crate) fn check(&self) -> Result<()> {
        if self.creator != std::process::id() || !vprouter_core::secret_boundary::pristine() {
            return Err(Error::OwnershipMismatch);
        }
        kernel::owner_admission_permitted()?;
        let now = vprouter_core::health::boot_seconds();
        if !now.is_finite()
            || !self.requested_at.is_finite()
            || now < self.requested_at
            || now >= self.deadline()
        {
            return Err(Error::Deadline);
        }
        Ok(())
    }
    pub(crate) fn verify_native(&self) -> Result<()> {
        self.check()?;
        self.verify_retained_pins()?;
        self.check()
    }
    pub(crate) fn verify_retained_pins(&self) -> Result<()> {
        if self.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        self.original.verify_retained()?;
        let st = rustix::fs::fstat(&self.directory).map_err(|_| Error::OwnershipMismatch)?;
        if !self.source_token.contains(self.source.as_fd())
            || !self.directory_token.contains(self.directory.as_fd())
            || Identity::network(&self.source)? != self.source_identity
            || self.original.identity()? != self.source_identity
            || Identity::of(&self.directory)? != self.directory_identity
            || self.directory_identity != self.original.request().directory_identity()
            || st.st_mode != 0o40700
            || st.st_uid != 0
            || st.st_gid != 0
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
    pub(crate) fn original(&self) -> &kernel::fresh_transport::Source {
        &self.original
    }
    pub(crate) fn source(&self) -> BorrowedFd<'_> {
        self.source.as_fd()
    }
    pub(crate) fn source_identity(&self) -> Identity {
        self.source_identity
    }
    pub(crate) fn directory(&self) -> BorrowedFd<'_> {
        self.directory.as_fd()
    }
    pub(crate) fn directory_identity(&self) -> Identity {
        self.directory_identity
    }
    pub(crate) fn name(&self) -> &str {
        &self.name
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
}
pub(super) struct PendingTransportMount {
    native: Option<MountNative>,
}
pub(super) struct MountedTransport {
    native: Option<MountNative>,
}
struct MountNative {
    creator: u32,
    input: CreatedTransport,
    request: Rc<MountRequest>,
    child: Option<kernel::fresh_transport_mount::Child>,
    mounted: Option<Rc<kernel::fresh_transport_mount::Mounted>>,
    step: MountStep,
    failure: Option<Error>,
}
#[derive(Clone, Copy)]
enum MountStep {
    Intent,
    Birth,
    Placeholder,
    PlaceholderWriting,
    Mounting,
    Publishing,
    Complete,
}
thread_local! {static MOUNTS:RefCell<Vec<MountNative>>=const{RefCell::new(Vec::new())};}
impl CreatedTransport {
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
}
impl MountNative {
    fn fail(&mut self, e: Error) {
        if self.creator != std::process::id() {
            return;
        }
        self.failure.get_or_insert(e);
        if let Ok(s) = self.input.service() {
            s.fail(e);
        }
        if let Some(c) = &mut self.child {
            c.cancel(e);
        }
    }
    fn collect(&mut self) {
        if self.creator != std::process::id() {
            return;
        }
        if let Ok(s) = self.input.service() {
            s.collect();
        }
        if let Some(c) = &mut self.child {
            c.collect();
        }
    }
    fn advance(&mut self) -> Result<()> {
        self.request.check()?;
        let s = self.input.service()?;
        match self.step {
            MountStep::Intent => {
                if let Some(intent) = s.poll_fresh_mount_intent(&self.request)? {
                    self.child = Some(kernel::fresh_transport_mount::spawn(
                        self.request.clone(),
                        intent,
                    )?);
                    s.start_fresh_mount_birth(self.child.as_ref().ok_or(Error::Interrupted)?)?;
                    self.step = MountStep::Birth;
                }
            }
            MountStep::Birth => {
                let c = self.child.as_mut().ok_or(Error::Interrupted)?;
                if let Some(g) = s.poll_fresh_mount_gate(c, false)? {
                    c.release(g, false)?;
                    self.step = MountStep::Placeholder;
                }
            }
            MountStep::Placeholder => {
                let c = self.child.as_mut().ok_or(Error::Interrupted)?;
                if c.poll_placeholder()? {
                    s.start_fresh_mount_placeholder(c)?;
                    self.step = MountStep::PlaceholderWriting;
                }
            }
            MountStep::PlaceholderWriting => {
                let c = self.child.as_mut().ok_or(Error::Interrupted)?;
                if let Some(g) = s.poll_fresh_mount_gate(c, true)? {
                    c.release(g, true)?;
                    self.step = MountStep::Mounting;
                }
            }
            MountStep::Mounting => {
                if let Some(m) = self
                    .child
                    .as_mut()
                    .ok_or(Error::Interrupted)?
                    .poll_mounted()?
                {
                    self.mounted = Some(m.clone());
                    s.start_fresh_mounted(m)?;
                    self.step = MountStep::Publishing;
                }
            }
            MountStep::Publishing => {
                if s.poll_fresh_mounted(self.mounted.as_ref().ok_or(Error::Interrupted)?)? {
                    self.step = MountStep::Complete;
                }
            }
            MountStep::Complete => (),
        }
        self.request.check()
    }
}
fn retain_mount(mut n: MountNative) {
    if n.creator != std::process::id() {
        std::mem::forget(n);
        return;
    }
    n.fail(Error::Interrupted);
    MOUNTS.with(|r| r.borrow_mut().push(n));
}
impl Drop for PendingTransportMount {
    fn drop(&mut self) {
        if let Some(n) = self.native.take() {
            retain_mount(n);
        }
    }
}
impl Drop for MountedTransport {
    fn drop(&mut self) {
        if let Some(n) = self.native.take() {
            retain_mount(n);
        }
    }
}
impl PendingTransportMount {
    pub(super) fn new(slot: &mut Option<CreatedTransport>) -> Result<Self> {
        let request = MountRequest::new(slot.as_ref().ok_or(Error::Interrupted)?)?;
        let mut p = Self {
            native: Some(MountNative {
                creator: std::process::id(),
                input: slot.take().ok_or(Error::Interrupted)?,
                request,
                child: None,
                mounted: None,
                step: MountStep::Intent,
                failure: None,
            }),
        };
        let n = p.native.as_mut().ok_or(Error::Interrupted)?;
        n.input.service()?.start_fresh_mount(&n.request)?;
        Ok(p)
    }
    pub(super) fn poll(&mut self) -> Result<Option<MountedTransport>> {
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
        if matches!(n.step, MountStep::Complete) {
            Ok(Some(MountedTransport {
                native: self.native.take(),
            }))
        } else {
            Ok(None)
        }
    }
}
impl MountedTransport {
    fn original(&self) -> Result<&AttachedPrimary> {
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        if n.creator != std::process::id()
            || n.failure.is_some()
            || !matches!(n.step, MountStep::Complete)
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(&n.input.native.as_ref().ok_or(Error::Interrupted)?.input)
    }
    pub(super) fn service(&mut self) -> Result<&mut Server> {
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        if n.creator != std::process::id()
            || n.failure.is_some()
            || !matches!(n.step, MountStep::Complete)
        {
            return Err(Error::OwnershipMismatch);
        }
        n.input.service()
    }
    pub(super) fn service_ref(&self) -> Result<&Server> {
        self.original()?.service_ref()
    }
    pub(super) fn mounted(&self) -> Result<Rc<kernel::fresh_transport_mount::Mounted>> {
        self.original()?;
        let m = self
            .native
            .as_ref()
            .and_then(|n| n.mounted.as_ref())
            .ok_or(Error::OwnershipMismatch)?;
        self.service_ref()?.verify_transport_mounted(m)?;
        Ok(m.clone())
    }
    pub(super) fn configuration(&self) -> Result<&vprouter_core::config::PublicConfiguration> {
        self.original()?.configuration()
    }
    pub(super) fn provision_descriptors(&self) -> Result<Vec<(String, BorrowedFd<'_>)>> {
        self.original()?.provision_descriptors()
    }
}
