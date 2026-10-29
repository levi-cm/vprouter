//! Fixed fresh namespace creator. No mount, profile, netlink or canonical FD is
//! inherited by the installed role; its only command is one durable Birth gate.
use super::super::{
    attachment::transport::Request,
    owned::{
        Identity,
        preparation::{
            Server, ValidationBirth,
            fresh_transport::{Gate, Intent},
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
}
struct Native {
    creator: u32,
    request: Rc<Request>,
    intent: Intent,
    _capacity: ChildCapacity,
    pid: u32,
    pidfd: OwnedFd,
    reap: Rc<ParentReap>,
    pid_token: Option<super::super::inventory::Registration>,
    channel: OwnedFd,
    _channel_token: super::super::inventory::Registration,
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
        if self.reap.status.get().is_none() {
            let _ = send_or_exited(self.pidfd.as_fd(), libc::SIGKILL);
        }
    }
    fn collect(&mut self) -> Result<Option<i32>> {
        self.creator()?;
        if self.pid_token.is_none() {
            self.pid_token = Some(super::super::inventory::Registration::owned(&[self
                .pidfd
                .as_fd()])?);
        }
        self.reap.poll(self.pid, self.pidfd.as_fd())
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
        let id = Identity::network(&source.fd)?;
        if id == self.request.host_identity() || id == self.request.data_identity() {
            return Err(Error::NamespaceMismatch);
        }
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
    RETAINED.with(|r| {
        for n in r.borrow_mut().iter_mut() {
            if n.creator == std::process::id() {
                let _ = n.collect();
            }
        }
    });
}
pub(super) fn children_reaped() -> bool {
    RETAINED.with(|r| {
        r.borrow()
            .iter()
            .all(|n| n.creator != std::process::id() || n.reap.status.get().is_some())
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
    pub(crate) fn poll(&mut self) -> Result<Option<Rc<Source>>> {
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
                Ok(Some(Rc::new(Source {
                    native: self.native.take(),
                    verified_at,
                })))
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
        self.native
            .as_ref()
            .is_none_or(|n| n.creator == std::process::id() && n.reap.status.get().is_some())
    }
}
impl Source {
    pub(crate) fn resource_transfer(&self) -> Result<ResourceTransfer> {
        self.verify_retained()?;
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        ResourceTransfer::local(
            n.intent.transfer_ticket()?,
            NativeJobKind::FreshTransport,
            &n.reap,
            &n._capacity,
        )
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
            || n.reap.status.get() != Some(0)
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
        self.verify_retained()?;
        Identity::network(&self.native.as_ref().ok_or(Error::Interrupted)?.source()?.fd)
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
    let high =
        rustix::io::fcntl_dupfd_cloexec(channel, 64).map_err(|_| Error::DescriptorDuplicate)?;
    dup_fixed(&high, 3, true)?;
    drop(high);
    close_except(&[3])?;
    namespace_attachment::mount_capabilities()?;
    parent_death(parent)?;
    secret::non_dumpable()?;
    let path = c"/proc/thread-self/ns/net";
    apply_filter(&creation_filter(path.as_ptr() as u64))?;
    let channel = unsafe { BorrowedFd::borrow_raw(3) };
    let end = request.deadline();
    secret::gate(channel, end)?;
    namespace_attachment::check(end)?;
    cv(
        unsafe { libc::unshare(libc::CLONE_NEWNET) },
        Error::NamespaceOperation,
    )?;
    namespace_attachment::check(end)?;
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat,
            libc::AT_FDCWD as libc::c_long,
            path.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC,
            0,
        )
    };
    if fd < 0 {
        return Err(Error::NamespaceOperation);
    }
    let source = unsafe { OwnedFd::from_raw_fd(fd as i32) };
    if source.as_raw_fd() != 4 {
        return Err(Error::DescriptorPolicy);
    }
    let id = Identity::network(&source)?;
    if id == request.host_identity() || id == request.data_identity() {
        return Err(Error::NamespaceMismatch);
    }
    send_fd(channel, &source, 1, end)?;
    namespace_attachment::check(end)
}
pub(super) fn creation_filter(path: u64) -> Vec<libc::sock_filter> {
    let mut out = secret::fixed_runtime_filter();
    out.pop();
    out.extend(exact_args(
        libc::SYS_unshare,
        &[(0, libc::CLONE_NEWNET as u64)],
    ));
    out.extend(exact_args(
        libc::SYS_openat,
        &[
            (0, libc::AT_FDCWD as i64 as u64),
            (1, path),
            (2, (libc::O_RDONLY | libc::O_CLOEXEC) as u64),
            (3, 0),
        ],
    ));
    for nr in [libc::SYS_fstat, libc::SYS_fstatfs, libc::SYS_close] {
        out.extend(exact_args(nr, &[(0, 4)]));
    }
    out.extend(exact_args(
        libc::SYS_fcntl,
        &[(0, 4), (1, libc::F_GETFD as u64)],
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
    let parent_token = super::super::inventory::Registration::owned(&[parent_channel.as_fd()])?;
    let child_token = super::super::inventory::Registration::owned(&[child_channel.as_fd()])?;
    super::super::inventory::verify()?;
    request.verify()?;
    owner_admission_permitted()?;
    let parent = std::process::id() as i32;
    let born_at = vprouter_core::health::boot_seconds();
    let (pid, pidfd) = fork_with_pidfd()?;
    if pid == 0 {
        let result = child_run(&request, child_channel.as_fd(), parent);
        die(if result.is_ok() { 0 } else { 122 });
    }
    let reap = ParentReap::born(pid as u32).expect("atomic native constructor");
    intent
        .lease()
        .native_job_mut()
        .born(NativeJobKind::FreshTransport, &Some(reap.clone()));
    drop(child_token);
    drop(child_channel);
    let mut n = Native {
        creator: std::process::id(),
        request,
        intent,
        _capacity: ChildCapacity::created(),
        pid: pid as u32,
        pidfd: pidfd.expect("atomic original pidfd"),
        reap,
        pid_token: None,
        channel: parent_channel,
        _channel_token: parent_token,
        birth: None,
        received: Vec::new(),
        released: false,
        packet: false,
        eof: false,
        failure: None,
    };
    let result = (|| {
        n.pid_token = Some(super::super::inventory::Registration::owned(&[n
            .pidfd
            .as_fd()])?);
        if wait_ready(&n.pidfd, Duration::ZERO)? {
            return Err(Error::ChildFailed);
        }
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .map_err(|_| Error::ProcessUnavailable)?;
        let start = process::stat_start(&stat, pid as u32)?;
        if wait_ready(&n.pidfd, Duration::ZERO)? {
            return Err(Error::ChildFailed);
        }
        n.reap.start.set(Some(start));
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
        retain(n);
        return Err(error);
    }
    Ok(Child { native: Some(n) })
}

#[cfg(test)]
impl Source {
    pub(crate) fn lab_evidence(&self) -> Result<serde_json::Value> {
        self.verify_retained()?;
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        Ok(
            serde_json::json!({"birth":self.birth()?,"actual_wait_status":n.reap.status.get(),
            "requested_at":n.request.requested_at(),"deadline":n.request.deadline(),"verified_at":self.verified_at,
            "request":n.request.digest(),"source":self.identity()?,"host":n.request.host_identity(),"data":n.request.data_identity(),
            "eof":n.eof,"original_source_retained":true,"durable_birth_released":n.released}),
        )
    }
}
