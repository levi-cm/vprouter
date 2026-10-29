//! Fixed exclusive empty cgroup creator. Original admitted parent and one gate
//! only; no profile/canonical/OFD, namespace, network or placement operation.
use super::super::{
    attachment::quarantine::producer::{Request, verify_created_group},
    owned::{
        Identity,
        preparation::{
            Server, ValidationBirth,
            producer_creation::{Gate, Intent},
        },
    },
};
use super::namespace_attachment::{Received, receive_packet, send_fd};
use super::*;
use rustix::net::{self, SendFlags};
use std::{cell::RefCell, rc::Rc};

pub(crate) struct Child {
    native: Option<Native>,
}
pub(crate) struct Source {
    native: Option<Native>,
    verified_at: f64,
    receipt: Option<super::super::owned::preparation::producer_creation::Receipt>,
}
struct Native {
    creator: u32,
    request: Rc<Request>,
    intent: Intent,
    _capacity: Option<ChildCapacity>,
    pid: Option<u32>,
    pidfd: Option<OwnedFd>,
    reap: Option<Rc<ParentReap>>,
    pid_token: Option<super::super::inventory::Registration>,
    channel: OwnedFd,
    _channel_token: Option<super::super::inventory::Registration>,
    child_channel: Option<OwnedFd>,
    child_token: Option<super::super::inventory::Registration>,
    birth: Option<ValidationBirth>,
    received: Vec<Received>,
    released: bool,
    packet: bool,
    eof: bool,
    failure: Option<Error>,
}
impl Native {
    fn creator(&self) -> Result<()> {
        if self.creator != std::process::id() {
            Err(Error::OwnershipMismatch)
        } else {
            Ok(())
        }
    }
    fn cancel(&mut self, error: Error) {
        if self.creator != std::process::id() {
            return;
        }
        self.failure.get_or_insert(error);
        let _ = net::shutdown(&self.channel, net::Shutdown::Both);
        if self.reap.as_ref().is_some_and(|r| r.status.get().is_none())
            && let Some(pidfd) = &self.pidfd
        {
            let _ = send_or_exited(pidfd.as_fd(), libc::SIGKILL);
        }
    }
    fn collect(&mut self) -> Result<Option<i32>> {
        self.creator()?;
        if self._channel_token.is_none() {
            self._channel_token = Some(super::super::inventory::Registration::owned(&[self
                .channel
                .as_fd()])?);
        }
        if self.child_token.is_none()
            && let Some(child) = &self.child_channel
        {
            self.child_token = Some(super::super::inventory::Registration::owned(&[
                child.as_fd()
            ])?);
        }
        let (Some(pid), Some(pidfd), Some(reap)) = (self.pid, &self.pidfd, &self.reap) else {
            return Ok(None);
        };
        if self.pid_token.is_none() {
            self.pid_token = Some(super::super::inventory::Registration::owned(&[
                pidfd.as_fd()
            ])?);
        }
        reap.poll(pid, pidfd.as_fd())
    }
    fn receive(&mut self) -> Result<()> {
        self.creator()?;
        for _ in 0..2 {
            match receive_packet(&self.channel, &mut self.received)? {
                None => return Ok(()),
                Some(0) => {
                    self.eof = true;
                    return Ok(());
                }
                Some(1) if self.released && !self.packet && self.received.len() == 1 => {
                    self.packet = true
                }
                _ => return Err(Error::DescriptorPolicy),
            }
        }
        Ok(())
    }
    fn source(&self) -> Result<&Received> {
        #[cfg(test)]
        super::super::owned::preparation::lab_cost::count_entry(
            super::super::owned::preparation::lab_cost::RetainedKey::NativeSourceEntries,
        );
        self.creator()?;
        if !self.packet || self.received.len() != 1 {
            return Err(Error::DescriptorPolicy);
        }
        let source = &self.received[0];
        if source
            .token
            .as_ref()
            .is_none_or(|t| !t.contains(source.fd.as_fd()))
        {
            return Err(Error::DescriptorInventory);
        }
        verify_created_group(&self.request, source.fd.as_fd())?;
        Ok(source)
    }
}
thread_local! {static RETAINED:RefCell<Vec<Native>>=const{RefCell::new(Vec::new())};}
fn retain(mut n: Native) {
    if n.creator != std::process::id() {
        std::mem::forget(n);
        return;
    }
    n.cancel(Error::Interrupted);
    RETAINED.with(|r| r.borrow_mut().push(n));
}
impl Drop for Child {
    fn drop(&mut self) {
        if let Some(n) = self.native.take() {
            retain(n);
        }
    }
}
impl Drop for Source {
    fn drop(&mut self) {
        if let Some(n) = self.native.take() {
            retain(n);
        }
    }
}
pub(super) fn poll_retained() {
    #[cfg(test)]
    LAB_RETAINED.with(|r| {
        for n in r.borrow_mut().iter_mut() {
            if n.creator == std::process::id() {
                let _ = n.reap.poll(n.pid, n.pidfd.as_fd());
            }
        }
    });
    RETAINED.with(|r| {
        for n in r.borrow_mut().iter_mut() {
            if n.creator == std::process::id() {
                let _ = n.collect();
            }
        }
    });
}
pub(super) fn children_reaped() -> bool {
    #[cfg(test)]
    if !LAB_RETAINED.with(|r| {
        r.borrow()
            .iter()
            .all(|n| n.creator != std::process::id() || n.reap.status.get().is_some())
    }) {
        return false;
    }
    RETAINED.with(|r| {
        r.borrow().iter().all(|n| {
            n.creator != std::process::id()
                || n.reap.as_ref().is_none_or(|r| r.status.get().is_some())
        })
    })
}
impl Child {
    pub(crate) fn bind_service(&self, s: &Server) -> Result<()> {
        self.native
            .as_ref()
            .ok_or(Error::Interrupted)?
            .intent
            .same_service(s)
    }
    pub(crate) fn birth(&self) -> Result<ValidationBirth> {
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        n.creator()?;
        n.birth.clone().ok_or(Error::OwnershipMismatch)
    }
    pub(crate) fn verify_gate(&self, gate: &Gate) -> Result<()> {
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        n.creator()?;
        gate.verify(&n.intent, &self.birth()?)
    }
    pub(crate) fn release(&mut self, gate: Gate) -> Result<()> {
        self.verify_gate(&gate)?;
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        n.request.verify()?;
        if n.failure.is_some() || n.released {
            return Err(Error::OwnershipMismatch);
        }
        n.released = true;
        let result = (|| {
            if net::send(&n.channel, &[1], SendFlags::DONTWAIT | SendFlags::NOSIGNAL)
                .map_err(|_| Error::ChildFailed)?
                != 1
            {
                return Err(Error::ChildFailed);
            }
            n.request.check()
        })();
        if let Err(e) = result {
            n.cancel(e);
        }
        result
    }
    pub(crate) fn poll(&mut self) -> Result<Option<Source>> {
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        n.creator()?;
        let result = (|| {
            n.request.check()?;
            if let Some(e) = n.failure {
                return Err(e);
            }
            if !n.released {
                return Err(Error::OwnershipMismatch);
            }
            n.receive()?;
            let Some(status) = n.collect()? else {
                return Ok(false);
            };
            // Actual reap can race the last packet after the first EAGAIN.
            n.receive()?;
            if status != 0 || !n.eof {
                return Err(Error::ChildFailed);
            }
            n.source()?;
            n.request.verify()?;
            Ok(true)
        })();
        match result {
            Ok(false) => Ok(None),
            Ok(true) => {
                let verified_at = vprouter_core::health::boot_seconds();
                n.request.check()?;
                Ok(Some(Source {
                    native: self.native.take(),
                    verified_at,
                    receipt: None,
                }))
            }
            Err(e) => {
                n.cancel(e);
                Err(e)
            }
        }
    }
    pub(crate) fn cancel(&mut self, e: Error) {
        if let Some(n) = &mut self.native {
            n.cancel(e);
        }
    }
    pub(crate) fn collect(&mut self) {
        if let Some(n) = &mut self.native {
            let _ = n.collect();
        }
    }
    pub(crate) fn reaped(&self) -> bool {
        self.native.as_ref().is_none_or(|n| {
            n.creator == std::process::id()
                && n.reap.as_ref().is_none_or(|r| r.status.get().is_some())
        })
    }
}
impl Source {
    pub(crate) fn resource_transfer(&self) -> Result<ResourceTransfer> {
        self.require_acknowledged()?;
        self.receipt
            .as_ref()
            .ok_or(Error::OwnershipMismatch)?
            .verify_history(self)?;
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        ResourceTransfer::local(
            n.intent.transfer_ticket()?,
            NativeJobKind::ProducerCreation,
            n.reap.as_ref().ok_or(Error::OwnershipMismatch)?,
            n._capacity.as_ref().ok_or(Error::OwnershipMismatch)?,
        )
    }
    pub(crate) fn verify_acknowledged_history(&self) -> Result<()> {
        self.require_acknowledged()?;
        self.receipt
            .as_ref()
            .ok_or(Error::OwnershipMismatch)?
            .verify_history(self)
    }
    pub(crate) fn verify_acknowledged_write(
        &self,
        proof: &super::super::owned::preparation::OriginalWrite<'_>,
    ) -> Result<()> {
        self.require_acknowledged()?;
        self.receipt
            .as_ref()
            .ok_or(Error::OwnershipMismatch)?
            .verify_write(self, proof)
    }

    pub(crate) fn accept(
        &mut self,
        receipt: super::super::owned::preparation::producer_creation::Receipt,
    ) -> Result<()> {
        if self.receipt.is_some() {
            return Err(Error::OwnershipMismatch);
        }
        receipt.verify(self)?;
        self.receipt = Some(receipt);
        Ok(())
    }
    pub(crate) fn require_acknowledged(&self) -> Result<()> {
        self.verify_retained()?;
        if self.receipt.is_none() {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }

    pub(crate) fn matches_job(&self, ticket: &NativeJobDrain) -> Result<bool> {
        self.verify_retained()?;
        self.native
            .as_ref()
            .ok_or(Error::Interrupted)?
            .intent
            .matches_job(ticket)
    }
    pub(crate) fn verify_retained(&self) -> Result<()> {
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        n.creator()?;
        if n.failure.is_some()
            || n.reap.as_ref().is_none_or(|r| r.status.get() != Some(0))
            || !n.eof
            || !self.verified_at.is_finite()
            || self.verified_at >= n.request.deadline()
        {
            return Err(Error::OwnershipMismatch);
        }
        n.source()?;
        Ok(())
    }
    pub(crate) fn verify(&self) -> Result<()> {
        self.verify_retained()?;
        self.request().verify()
    }
    pub(crate) fn bind_service(&self, s: &Server) -> Result<()> {
        self.native
            .as_ref()
            .ok_or(Error::Interrupted)?
            .intent
            .same_service(s)
    }
    pub(crate) fn birth(&self) -> Result<ValidationBirth> {
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        n.creator()?;
        n.birth.clone().ok_or(Error::OwnershipMismatch)
    }
    pub(crate) fn identity(&self) -> Result<Identity> {
        #[cfg(test)]
        super::super::owned::preparation::lab_cost::count_entry(
            super::super::owned::preparation::lab_cost::RetainedKey::SourceIdentityEntries,
        );
        self.verify_retained()?;
        Identity::of(&self.native.as_ref().ok_or(Error::Interrupted)?.source()?.fd)
    }
    pub(crate) fn descriptor(&self) -> Result<BorrowedFd<'_>> {
        self.verify_retained()?;
        Ok(self
            .native
            .as_ref()
            .ok_or(Error::Interrupted)?
            .source()?
            .fd
            .as_fd())
    }
    pub(crate) fn request(&self) -> &Rc<Request> {
        &self.native.as_ref().expect("live original source").request
    }
    pub(crate) fn verified_at(&self) -> f64 {
        self.verified_at
    }
}
fn child_run(request: &Request, channel: BorrowedFd<'_>, parent: i32) -> Result<()> {
    parent_death(parent)?;
    cv(unsafe { libc::clearenv() }, Error::ChildFailed)?;
    let null = fs::open(c"/dev/null", OFlags::RDWR | OFlags::CLOEXEC, Mode::empty())
        .map_err(|_| Error::DescriptorNull)?;
    let st = fs::fstat(&null).map_err(|_| Error::DescriptorNull)?;
    if fs::FileType::from_raw_mode(st.st_mode) != fs::FileType::CharacterDevice
        || fs::major(st.st_rdev) != 1
        || fs::minor(st.st_rdev) != 3
    {
        return Err(Error::DescriptorNull);
    }
    for fd in 0..3 {
        dup_fixed(&null, fd, false)?;
    }
    drop(null);
    let high_channel =
        rustix::io::fcntl_dupfd_cloexec(channel, 64).map_err(|_| Error::DescriptorDuplicate)?;
    let high_parent = rustix::io::fcntl_dupfd_cloexec(request.parent(), 64)
        .map_err(|_| Error::DescriptorDuplicate)?;
    dup_fixed(&high_channel, 3, true)?;
    dup_fixed(&high_parent, 4, true)?;
    drop(high_channel);
    drop(high_parent);
    close_except(&[3, 4])?;
    drop_identity(0)?;
    parent_death(parent)?;
    secret::non_dumpable()?;
    let name = c(request.name())?;
    let how = OpenHow {
        flags: (libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW) as u64,
        mode: 0,
        resolve: 0x08 | 0x04,
    };
    apply_filter(&creation_filter(
        name.as_ptr() as u64,
        &how as *const _ as u64,
    ))?;
    let channel = unsafe { BorrowedFd::borrow_raw(3) };
    let parent = unsafe { BorrowedFd::borrow_raw(4) };
    let end = request.deadline();
    secret::gate(channel, end)?;
    namespace_attachment::check(end)?;
    if super::super::attachment::quarantine::producer::parent_identity(parent)?
        != request.parent_identity()
    {
        return Err(Error::CgroupMismatch);
    }
    namespace_attachment::check(end)?;
    cv(
        unsafe { libc::mkdirat(4, name.as_ptr(), 0o700) },
        Error::CgroupMismatch,
    )?;
    namespace_attachment::check(end)?;
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            4,
            name.as_ptr(),
            &how,
            std::mem::size_of::<OpenHow>(),
        )
    };
    if fd < 0 {
        return Err(Error::CgroupMismatch);
    }
    let group = unsafe { OwnedFd::from_raw_fd(fd as i32) };
    if group.as_raw_fd() != 5
        || super::super::attachment::quarantine::producer::parent_identity(group.as_fd())?
            == request.parent_identity()
    {
        return Err(Error::CgroupMismatch);
    }
    namespace_attachment::check(end)?;
    send_fd(channel, &group, 1, end)?;
    namespace_attachment::check(end)
}
#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}
pub(super) fn creation_filter(name: u64, how: u64) -> Vec<libc::sock_filter> {
    let mut out = secret::fixed_runtime_filter();
    out.pop();
    out.extend(exact_args(
        libc::SYS_mkdirat,
        &[(0, 4), (1, name), (2, 0o700)],
    ));
    out.extend(exact_args(
        libc::SYS_openat2,
        &[
            (0, 4),
            (1, name),
            (2, how),
            (3, std::mem::size_of::<OpenHow>() as u64),
        ],
    ));
    for nr in [libc::SYS_fstat, libc::SYS_fstatfs] {
        secret::selected_fd_call(&mut out, nr, &[4, 5], None);
    }
    out.extend(exact_args(libc::SYS_close, &[(0, 5)]));
    out.extend(exact_args(
        libc::SYS_fcntl,
        &[(0, 5), (1, libc::F_GETFD as u64)],
    ));
    out.extend(exact_args(
        libc::SYS_sendmsg,
        &[
            (0, 3),
            (2, (libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL) as u64),
        ],
    ));
    out.extend(exact_args(
        libc::SYS_recvfrom,
        &[
            (0, 3),
            (3, (libc::MSG_DONTWAIT | libc::MSG_TRUNC) as u64),
            (4, 0),
            (5, 0),
        ],
    ));
    out.push(libc::sock_filter {
        code: 0x06,
        jt: 0,
        jf: 0,
        k: 0x00050001,
    });
    out
}
pub(crate) fn spawn(request: Rc<Request>, mut intent: Intent) -> Result<Child> {
    process::single_threaded()?;
    secret::seal_parent()?;
    intent.prepare(&request)?;
    let (parent_channel, child_channel) = net::socketpair(
        net::AddressFamily::UNIX,
        net::SocketType::SEQPACKET,
        net::SocketFlags::CLOEXEC,
        None,
    )
    .map_err(|_| Error::DescriptorPolicy)?;
    let mut value = Child {
        native: Some(Native {
            creator: std::process::id(),
            request,
            intent,
            _capacity: None,
            pid: None,
            pidfd: None,
            reap: None,
            pid_token: None,
            channel: parent_channel,
            _channel_token: None,
            child_channel: Some(child_channel),
            child_token: None,
            birth: None,
            received: Vec::new(),
            released: false,
            packet: false,
            eof: false,
            failure: None,
        }),
    };
    let n = value.native.as_mut().ok_or(Error::Interrupted)?;
    let result = (|| {
        n.child_token = Some(super::super::inventory::Registration::owned(&[n
            .child_channel
            .as_ref()
            .ok_or(Error::Interrupted)?
            .as_fd()])?);
        #[cfg(test)]
        lab_fault(&n.request, 3)?;
        n._channel_token = Some(super::super::inventory::Registration::owned(&[n
            .channel
            .as_fd()])?);
        super::super::inventory::verify()?;
        n.request.verify()?;
        owner_admission_permitted()?;
        require_child_capacity()?;
        let parent = std::process::id() as i32;
        let born_at = vprouter_core::health::boot_seconds();
        let (pid, pidfd) = fork_with_pidfd()?;
        if pid == 0 {
            let r = child_run(
                &n.request,
                n.child_channel.as_ref().expect("original endpoint").as_fd(),
                parent,
            );
            die(if r.is_ok() { 0 } else { 122 });
        }
        let reap = ParentReap::born(pid as u32).expect("atomic original constructor");
        n.intent
            .lease()
            .native_job_mut()
            .born(NativeJobKind::ProducerCreation, &Some(reap.clone()));
        n.pid = Some(pid as u32);
        n.pidfd = Some(pidfd.expect("atomic pidfd"));
        n.reap = Some(reap);
        n._capacity = Some(ChildCapacity::created());
        n.child_token.take();
        n.child_channel.take();
        #[cfg(test)]
        lab_fault(&n.request, 1)?;
        let pidfd = n.pidfd.as_ref().ok_or(Error::Interrupted)?;
        n.pid_token = Some(super::super::inventory::Registration::owned(&[
            pidfd.as_fd()
        ])?);
        if wait_ready(pidfd, Duration::ZERO)? {
            return Err(Error::ChildFailed);
        }
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .map_err(|_| Error::ProcessUnavailable)?;
        let start = process::stat_start(&stat, pid as u32)?;
        if wait_ready(pidfd, Duration::ZERO)? {
            return Err(Error::ChildFailed);
        }
        n.reap
            .as_ref()
            .ok_or(Error::Interrupted)?
            .start
            .set(Some(start));
        n.birth = Some(ValidationBirth {
            pid: pid as u32,
            start,
            born_at,
            deadline: n.request.deadline(),
        });
        n.request.check()
    })();
    if let Err(error) = result {
        n.cancel(error);
        return Err(error);
    }
    Ok(value)
}

impl Child {
    pub(crate) fn request_digest(&self) -> Result<[u8; 32]> {
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        n.creator()?;
        Ok(n.request.digest())
    }
}
impl Source {
    pub(crate) fn intent(&self) -> Result<&Intent> {
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        n.creator()?;
        Ok(&n.intent)
    }
}
#[cfg(test)]
thread_local! { static FAULT: std::cell::Cell<Option<(u32,[u8;32],u8)>>=const{std::cell::Cell::new(None)}; }
#[cfg(test)]
pub(crate) fn lab_arm(request: &Request, stage: u8) {
    FAULT.with(|f| f.set(Some((std::process::id(), request.digest(), stage))));
}
#[cfg(test)]
fn lab_fault(request: &Request, stage: u8) -> Result<()> {
    if FAULT.with(|f| {
        if f.get() == Some((std::process::id(), request.digest(), stage)) {
            f.set(None);
            true
        } else {
            false
        }
    }) {
        Err(Error::DescriptorInventory)
    } else {
        Ok(())
    }
}

#[cfg(test)]
impl Native {
    fn lab_evidence(
        &mut self,
        accepted: Option<f64>,
        acknowledged: bool,
    ) -> Result<serde_json::Value> {
        self.creator()?;
        let mut slots = self.request.lab_registered_slots()?;
        for token in self
            ._channel_token
            .iter()
            .chain(self.child_token.iter())
            .chain(self.pid_token.iter())
        {
            slots += token.lab_live_slots()?;
        }
        for fd in &self.received {
            slots += fd
                .token
                .as_ref()
                .ok_or(Error::DescriptorInventory)?
                .lab_live_slots()?;
        }
        let state = self.intent.lease().native_job_mut().state.get();
        let group = if self.packet {
            Some(verify_created_group(
                &self.request,
                self.source()?.fd.as_fd(),
            )?)
        } else {
            None
        };
        Ok(
            serde_json::json!({"request":self.request.digest(),"query":self.request.query_digest(),"requested_at":self.request.requested_at(),"deadline":self.request.deadline(),
            "parent":self.request.parent_identity(),"name":self.request.name(),"data":self.request.data(),"group":group,
            "birth":self.birth,"original_pid":self.pid,"original_start":self.reap.as_ref().and_then(|r|r.start.get()),
            "actual_wait_status":self.reap.as_ref().and_then(|r|r.status.get()),"native_born":self.pid.is_some(),
            "native_job_state":match state{NativeJobState::Prepared=>"prepared",NativeJobState::Born=>"born",NativeJobState::NoBirth=>"no_birth",NativeJobState::Collected=>"collected",NativeJobState::TransferredResources=>"transferred_resources"},
            "registered_native_slots":slots,"full_descriptor_registration":slots>=3,"received_original_group":self.packet&&self.received.len()==1,
            "eof":self.eof,"durable_birth_released":self.released,"verified_at":accepted,"acknowledged":acknowledged,
            "context_retained":true,"operational_publication":false,"parent_death_lock_survival_claimed":false}),
        )
    }
}
#[cfg(test)]
impl Source {
    pub(crate) fn lab_evidence(&mut self) -> Result<serde_json::Value> {
        self.verify_retained()?;
        self.native
            .as_mut()
            .ok_or(Error::Interrupted)?
            .lab_evidence(Some(self.verified_at), self.receipt.is_some())
    }
}
#[cfg(test)]
pub(crate) fn lab_failed_context(request: &Rc<Request>) -> Result<Option<serde_json::Value>> {
    RETAINED.with(|r| {
        let mut r = r.borrow_mut();
        let Some(n) = r
            .iter_mut()
            .find(|n| n.creator == std::process::id() && Rc::ptr_eq(&n.request, request))
        else {
            return Ok(None);
        };
        n.collect()?;
        if n.reap.as_ref().is_some_and(|r| r.status.get().is_none()) {
            return Ok(None);
        }
        n.lab_evidence(None, false).map(Some)
    })
}

#[cfg(test)]
struct LabHeld {
    creator: u32,
    directory: OwnedFd,
    channel: OwnedFd,
    registration: super::super::inventory::Registration,
    observer: vprouter_network::RouteObserver,
    read: vprouter_network::LabRouteRead,
    pid: u32,
    pidfd: OwnedFd,
    pid_token: Option<super::super::inventory::Registration>,
    reap: Rc<ParentReap>,
    received: Vec<Received>,
    _capacity: ChildCapacity,
}
#[cfg(test)]
thread_local! { static LAB_RETAINED:RefCell<Vec<LabHeld>>=const{RefCell::new(Vec::new())}; }
/// Same fixed syscall filter on private ordinary directories. This additionally
/// demonstrates independent original-child progress while a real kernel route
/// dump remains held after send; no A-owner RPC or cgroup mutation is claimed.
#[cfg(test)]
pub(super) fn lab_filter_selftest() -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    let path = std::env::temp_dir().join(format!("vpr-producer-filter-{}", std::process::id()));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&path)
        .map_err(|_| Error::OwnershipMismatch)?;
    let directory = fs::open(
        &path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| Error::OwnershipMismatch)?;
    let (channel, child_channel) = net::socketpair(
        net::AddressFamily::UNIX,
        net::SocketType::SEQPACKET,
        net::SocketFlags::CLOEXEC,
        None,
    )
    .map_err(|_| Error::DescriptorPolicy)?;
    let mut observer =
        vprouter_network::RouteObserver::open().map_err(|_| Error::NetworkOperation)?;
    let registration = super::super::inventory::Registration::owned(&[
        directory.as_fd(),
        channel.as_fd(),
        observer.descriptor(),
    ])?;
    let child_token = super::super::inventory::Registration::owned(&[child_channel.as_fd()])?;
    let started = vprouter_core::health::boot_seconds();
    let end = started + 2.;
    let mut read = observer
        .lab_start_pending_read(end)
        .map_err(|_| Error::NetworkOperation)?;
    while read.sent_sequence().is_none() {
        if observer
            .lab_poll_pending_read(&mut read)
            .map_err(|_| Error::NetworkOperation)?
            .is_some()
        {
            return Err(Error::OwnershipMismatch);
        }
    }
    let sequence = read.sent_sequence().ok_or(Error::OwnershipMismatch)?;
    require_child_capacity()?;
    let (pid, pidfd) = fork_with_pidfd()?;
    if pid == 0 {
        let stage = std::cell::Cell::new(0u8);
        let answer = (|| {
            let a = rustix::io::fcntl_dupfd_cloexec(&child_channel, 64)
                .map_err(|_| Error::DescriptorDuplicate)?;
            let b = rustix::io::fcntl_dupfd_cloexec(&directory, 64)
                .map_err(|_| Error::DescriptorDuplicate)?;
            dup_fixed(&a, 3, true)?;
            dup_fixed(&b, 4, true)?;
            drop(a);
            drop(b);
            close_except(&[3, 4])?;
            secret::non_dumpable()?;
            cv(
                unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) },
                Error::ConfinementPolicy,
            )?;
            let name = c"original";
            let other = c"foreign";
            let how = OpenHow {
                flags: (libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW)
                    as u64,
                mode: 0,
                resolve: 0x08 | 0x04,
            };
            apply_filter(&creation_filter(
                name.as_ptr() as u64,
                &how as *const _ as u64,
            ))?;
            stage.set(1);
            secret::lab_denials()?;
            let channel = unsafe { BorrowedFd::borrow_raw(3) };
            secret::gate(channel, end)?;
            stage.set(2);
            for (fd, pointer, mode) in [
                (4, other.as_ptr(), 0o700),
                ((1u64 << 32) | 4, name.as_ptr(), 0o700),
                (4, name.as_ptr(), 0o755),
            ] {
                if unsafe { libc::syscall(libc::SYS_mkdirat, fd, pointer, mode) } != -1
                    || std::io::Error::last_os_error().raw_os_error() != Some(libc::EPERM)
                {
                    return Err(Error::DescriptorPolicy);
                }
            }
            namespace_attachment::check(end)?;
            cv(
                unsafe { libc::mkdirat(4, name.as_ptr(), 0o700) },
                Error::OwnershipMismatch,
            )?;
            stage.set(3);
            if unsafe { libc::mkdirat(4, name.as_ptr(), 0o700) } != -1
                || std::io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST)
            {
                return Err(Error::OwnershipMismatch);
            }
            let raw = unsafe {
                libc::syscall(
                    libc::SYS_openat2,
                    4,
                    name.as_ptr(),
                    &how,
                    std::mem::size_of::<OpenHow>(),
                )
            };
            if raw != 5 {
                return Err(Error::DescriptorPolicy);
            }
            let group = unsafe { OwnedFd::from_raw_fd(raw as i32) };
            let st = fs::fstat(&group).map_err(|_| Error::DescriptorPolicy)?;
            fs::fstatfs(&group).map_err(|_| Error::DescriptorPolicy)?;
            if st.st_mode & 0o7777 != 0o700
                || !rustix::io::fcntl_getfd(&group)
                    .map_err(|_| Error::DescriptorPolicy)?
                    .contains(rustix::io::FdFlags::CLOEXEC)
            {
                return Err(Error::DescriptorPolicy);
            }
            for nr in [libc::SYS_unshare, libc::SYS_setns, libc::SYS_unlinkat] {
                if unsafe { libc::syscall(nr, 4, name.as_ptr(), libc::AT_REMOVEDIR) } != -1
                    || std::io::Error::last_os_error().raw_os_error() != Some(libc::EPERM)
                {
                    return Err(Error::DescriptorPolicy);
                }
            }
            stage.set(4);
            send_fd(channel, &group, 1, end)?;
            namespace_attachment::check(end)
        })();
        die(if answer.is_ok() {
            0
        } else {
            60 + stage.get() as i32
        });
    }
    let reap = ParentReap::born(pid as u32).expect("original mechanical child");
    drop(child_token);
    drop(child_channel);
    let mut n = LabHeld {
        creator: std::process::id(),
        directory,
        channel,
        registration,
        observer,
        read,
        pid: pid as u32,
        pidfd: pidfd.expect("original pidfd"),
        pid_token: None,
        reap,
        received: Vec::new(),
        _capacity: ChildCapacity::created(),
    };
    let result = (|| {
        n.pid_token = Some(super::super::inventory::Registration::owned(&[n
            .pidfd
            .as_fd()])?);
        if wait_ready(&n.pidfd, Duration::ZERO)? {
            return Err(Error::ChildFailed);
        }
        let start = process::stat_start(
            &std::fs::read_to_string(format!("/proc/{pid}/stat"))
                .map_err(|_| Error::ProcessUnavailable)?,
            pid as u32,
        )?;
        if wait_ready(&n.pidfd, Duration::ZERO)? {
            return Err(Error::ChildFailed);
        }
        n.reap.start.set(Some(start));
        let mut pending_polls = 0u32;
        for _ in 0..2 {
            if n.observer
                .lab_poll_pending_read(&mut n.read)
                .map_err(|_| Error::NetworkOperation)?
                .is_some()
            {
                return Err(Error::OwnershipMismatch);
            }
            pending_polls += 1;
        }
        if net::send(&n.channel, &[1], SendFlags::DONTWAIT | SendFlags::NOSIGNAL)
            .map_err(|_| Error::ChildFailed)?
            != 1
        {
            return Err(Error::ChildFailed);
        }
        let mut packet = false;
        let mut eof = false;
        loop {
            namespace_attachment::check(end)?;
            if n.observer
                .lab_poll_pending_read(&mut n.read)
                .map_err(|_| Error::NetworkOperation)?
                .is_some()
            {
                return Err(Error::OwnershipMismatch);
            }
            pending_polls = pending_polls.checked_add(1).ok_or(Error::TooLarge)?;
            if !eof {
                match receive_packet(&n.channel, &mut n.received)? {
                    None => (),
                    Some(1) if !packet && n.received.len() == 1 => packet = true,
                    Some(0) if packet => eof = true,
                    _ => return Err(Error::DescriptorPolicy),
                }
            }
            let status = n.reap.poll(n.pid, n.pidfd.as_fd())?;
            if status.is_some_and(|s| s != 0) {
                return Err(Error::ChildFailed);
            }
            if status == Some(0) && eof {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        if !n.registration.contains(n.directory.as_fd())
            || !n.registration.contains(n.observer.descriptor())
            || n.read.sent_sequence() != Some(sequence)
        {
            return Err(Error::DescriptorInventory);
        }
        let group = n.received.first().ok_or(Error::DescriptorPolicy)?;
        let id = Identity::of(&group.fd)?;
        let named = fs::statat(&n.directory, "original", fs::AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| Error::OwnershipMismatch)?;
        if (id.dev, id.ino) != (named.st_dev, named.st_ino)
            || named.st_mode & 0o7777 != 0o700
            || n.received.len() != 1
        {
            return Err(Error::OwnershipMismatch);
        }
        let independent_completed_at = vprouter_core::health::boot_seconds();
        n.read.release().map_err(|_| Error::NetworkOperation)?;
        let messages = loop {
            namespace_attachment::check(end)?;
            match n
                .observer
                .lab_poll_pending_read(&mut n.read)
                .map_err(|_| Error::NetworkOperation)?
            {
                Some(n) => break n,
                None => std::thread::yield_now(),
            }
        };
        let completed_at = vprouter_core::health::boot_seconds();
        if messages == 0
            || completed_at >= end
            || independent_completed_at < started
            || independent_completed_at > completed_at
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(
            serde_json::json!({"requested_at":started,"deadline":end,"sequence":sequence,"pending_parent_polls":pending_polls,
            "independent_pid":n.pid,"independent_start":start,"actual_wait_status":n.reap.status.get(),"independent_completed_at":independent_completed_at,
            "route_completed_at":completed_at,"reply_messages":messages,"original_kernel_dump_completed":true,"unrelated_owner_rpc_claimed":false}),
        )
    })();
    let witness = match result {
        Ok(v) => v,
        Err(error) => {
            eprintln!(
                "LAB_FIXED_PRODUCER_FAILURE actual_wait_status={:?} reason={error:?}",
                n.reap.status.get()
            );
            if n.reap.status.get().is_none() {
                let _ = send_or_exited(n.pidfd.as_fd(), libc::SIGKILL);
            }
            LAB_RETAINED.with(|r| r.borrow_mut().push(n));
            return Err(error);
        }
    };
    fs::unlinkat(&n.directory, "original", fs::AtFlags::REMOVEDIR)
        .map_err(|_| Error::OwnershipMismatch)?;
    std::fs::remove_dir(&path).map_err(|_| Error::OwnershipMismatch)?;
    println!(
        "LAB_FIXED_PRODUCER_FILTER {{\"actual_wait_zero\":true,\"eof_verified\":true,\"original_scm_descriptor_retained\":true,\"exclusive_mkdir_collision_refused\":true,\"foreign_pointer_mode_high_word_denied\":true,\"fork_exec_namespace_unlink_denied\":true,\"actual_cgroup_creation\":false}}"
    );
    println!("LAB_PENDING_ROUTE_PROGRESS {witness}");
    Ok(())
}
