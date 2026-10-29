//! Fixed descriptor-bound namespace attachment. No profile/journal/command FD
//! survives in the child; no name or native target is received over the channel.
use super::super::{
    attachment::mount::Request,
    owned::{
        Identity,
        preparation::{
            Server, ValidationBirth,
            mount::{Gate, Intent, Placeholder},
        },
    },
};
use super::*;
use rustix::net::{self, RecvFlags, SendFlags};
use std::rc::Rc;

pub(crate) struct Child {
    native: Option<Native>,
}
pub(super) struct Received {
    pub(super) fd: OwnedFd,
    pub(super) token: Option<super::super::inventory::Registration>,
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
    placeholder: Option<Placeholder>,
    released: u8,
    packets: u8,
    failure: Option<Error>,
    eof: bool,
}
pub(crate) struct Mounted {
    native: Option<Native>,
    verified_at: f64,
}
thread_local! { static RETAINED: std::cell::RefCell<Vec<Native>> = const { std::cell::RefCell::new(Vec::new()) }; }
impl Native {
    fn creator(&self) -> Result<()> {
        if self.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
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
    fn placeholder_fd(&self) -> Result<&OwnedFd> {
        self.received
            .first()
            .map(|r| &r.fd)
            .ok_or(Error::OwnershipMismatch)
    }
    fn receive(&mut self) -> Result<bool> {
        self.creator()?;
        let Some(tag) = receive_packet(&self.channel, &mut self.received)? else {
            return Ok(false);
        };
        if tag == 0 {
            self.eof = true;
            return Ok(true);
        }
        if self.packets >= 2
            || tag != self.packets + 1
            || self.received.len() != self.packets as usize + 1
        {
            return Err(Error::DescriptorPolicy);
        }
        self.packets += 1;
        if self.packets == 1 {
            if self.released != 1 {
                return Err(Error::OwnershipMismatch);
            }
            self.placeholder = Some(placeholder(
                self.placeholder_fd()?,
                self.request.directory_identity(),
            )?);
            self.verify_placeholder_name()?;
        } else {
            if self.released != 2 {
                return Err(Error::OwnershipMismatch);
            }
            self.verify_mounted()?;
        }
        Ok(true)
    }
    fn verify_placeholder_name(&self) -> Result<()> {
        self.request.verify_native()?;
        if self.received.len() != 1
            || self.received[0]
                .token
                .as_ref()
                .is_none_or(|token| !token.contains(self.received[0].fd.as_fd()))
        {
            return Err(Error::DescriptorPolicy);
        }
        let proof = self.placeholder.as_ref().ok_or(Error::OwnershipMismatch)?;
        if placeholder(self.placeholder_fd()?, self.request.directory_identity())? != *proof {
            return Err(Error::OwnershipMismatch);
        }
        let named = fs::statat(
            self.request.directory(),
            self.request.name(),
            fs::AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(|_| Error::OwnershipMismatch)?;
        if (
            named.st_dev,
            named.st_ino,
            named.st_mode,
            named.st_uid,
            named.st_gid,
            named.st_nlink,
        ) != (proof.identity.dev, proof.identity.ino, proof.mode, 0, 0, 1)
        {
            return Err(Error::OwnershipMismatch);
        }
        self.request.check()
    }
    fn verify_mounted(&self) -> Result<()> {
        self.creator()?;
        self.request.verify_native()?;
        self.verify_mounted_pins()?;
        self.request.check()
    }
    fn verify_mounted_pins(&self) -> Result<()> {
        if self.received.len() != 2
            || self.packets != 2
            || self
                .received
                .iter()
                .any(|r| r.token.as_ref().is_none_or(|t| !t.contains(r.fd.as_fd())))
            || self.placeholder.as_ref()
                != Some(&placeholder(
                    self.placeholder_fd()?,
                    self.request.directory_identity(),
                )?)
            || Identity::network(&self.received[1].fd)? != self.request.source_identity()
        {
            return Err(Error::NamespaceMismatch);
        }
        let named = fs::openat2(
            self.request.directory(),
            self.request.name(),
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
            fs::ResolveFlags::BENEATH | fs::ResolveFlags::NO_SYMLINKS,
        )
        .map_err(|_| Error::NamespaceMismatch)?;
        if Identity::network(&named)? != self.request.source_identity() {
            return Err(Error::NamespaceMismatch);
        }
        Ok(())
    }
}
/// Decode only the fixed scalar tag; received native ownership is installed
/// first and stays with the caller even if framing or registration is rejected.
pub(super) fn receive_packet(
    channel: impl AsFd,
    received: &mut Vec<Received>,
) -> Result<Option<u8>> {
    let mut bytes = [0u8; 2];
    let mut buffer = [std::mem::MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(4))];
    let mut ancillary = net::RecvAncillaryBuffer::new(&mut buffer);
    let msg = match net::recvmsg(
        channel,
        &mut [std::io::IoSliceMut::new(&mut bytes)],
        &mut ancillary,
        RecvFlags::DONTWAIT | RecvFlags::CMSG_CLOEXEC,
    ) {
        Err(rustix::io::Errno::AGAIN) => return Ok(None),
        Ok(msg) => msg,
        Err(_) => return Err(Error::DescriptorPolicy),
    };
    let before = received.len();
    let mut messages = 0;
    let mut invalid = false;
    for item in ancillary.drain() {
        messages += 1;
        match item {
            net::RecvAncillaryMessage::ScmRights(rights) => {
                received.extend(rights.map(|fd| Received { fd, token: None }))
            }
            _ => invalid = true,
        }
    }
    for entry in &mut received[before..] {
        entry.token = Some(super::super::inventory::Registration::owned(&[entry
            .fd
            .as_fd()])?);
    }
    if msg.bytes == 0 && messages == 0 {
        return Ok(Some(0));
    }
    if invalid
        || msg.bytes != 1
        || messages != 1
        || received.len() != before + 1
        || msg
            .flags
            .intersects(net::ReturnFlags::TRUNC | net::ReturnFlags::CTRUNC)
        || !matches!(bytes[0], 1 | 2)
    {
        return Err(Error::DescriptorPolicy);
    }
    Ok(Some(bytes[0]))
}
fn retain(mut native: Native) {
    if native.creator != std::process::id() {
        std::mem::forget(native);
        return;
    }
    native.cancel(Error::Interrupted);
    RETAINED.with(|retained| retained.borrow_mut().push(native));
}
impl Drop for Child {
    fn drop(&mut self) {
        if let Some(native) = self.native.take() {
            retain(native);
        }
    }
}
impl Drop for Mounted {
    fn drop(&mut self) {
        if let Some(native) = self.native.take() {
            retain(native);
        }
    }
}
pub(super) fn poll_retained() {
    RETAINED.with(|retained| {
        for native in retained.borrow_mut().iter_mut() {
            if native.creator == std::process::id() {
                native.cancel(Error::Interrupted);
                let _ = native.collect();
            }
        }
    });
}
pub(super) fn children_reaped() -> bool {
    RETAINED.with(|retained| {
        retained
            .borrow()
            .iter()
            .all(|n| n.creator != std::process::id() || n.reap.status.get().is_some())
    })
}
impl Child {
    pub(crate) fn bind_service(&self, server: &Server) -> Result<()> {
        self.native
            .as_ref()
            .ok_or(Error::Interrupted)?
            .intent
            .same_service(server)
    }
    pub(crate) fn birth(&self) -> Result<ValidationBirth> {
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        n.creator()?;
        n.birth.clone().ok_or(Error::OwnershipMismatch)
    }
    pub(crate) fn placeholder(&self) -> Result<Placeholder> {
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        n.verify_placeholder_name()?;
        n.placeholder.clone().ok_or(Error::OwnershipMismatch)
    }
    pub(crate) fn verify_gate(&self, gate: &Gate, mounting: bool) -> Result<()> {
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        n.creator()?;
        gate.verify(
            &n.intent,
            &self.birth()?,
            if mounting {
                Some(n.placeholder.as_ref().ok_or(Error::OwnershipMismatch)?)
            } else {
                None
            },
        )
    }
    pub(crate) fn release(&mut self, gate: Gate, mounting: bool) -> Result<()> {
        self.verify_gate(&gate, mounting)?;
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        n.request.verify_native()?;
        if n.failure.is_some() || n.released != u8::from(mounting) {
            return Err(Error::OwnershipMismatch);
        }
        if mounting {
            n.verify_placeholder_name()?;
        }
        n.request.check()?;
        if net::send(&n.channel, &[1], SendFlags::DONTWAIT | SendFlags::NOSIGNAL)
            .map_err(|_| Error::ChildFailed)?
            != 1
        {
            return Err(Error::ChildFailed);
        }
        n.released += 1;
        Ok(())
    }
    pub(crate) fn poll_placeholder(&mut self) -> Result<bool> {
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        n.request.check()?;
        if n.released != 1 || n.failure.is_some() {
            return Err(Error::OwnershipMismatch);
        }
        n.receive()?;
        if n.eof {
            return Err(Error::ChildFailed);
        }
        if n.placeholder.is_some() {
            n.verify_placeholder_name()?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
    pub(crate) fn poll_mounted(&mut self) -> Result<Option<Rc<Mounted>>> {
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        n.request.check()?;
        if n.released != 2 || n.failure.is_some() {
            return Err(Error::OwnershipMismatch);
        }
        n.receive()?;
        let Some(status) = n.collect()? else {
            return Ok(None);
        };
        if status != 0 {
            return Err(Error::ChildFailed);
        }
        for _ in 0..2 {
            if n.eof {
                break;
            }
            if !n.receive()? {
                return Ok(None);
            }
        }
        if !n.eof || n.packets != 2 {
            return Err(Error::ChildFailed);
        }
        n.verify_mounted()?;
        let verified_at = vprouter_core::health::boot_seconds();
        n.request.check()?;
        Ok(Some(Rc::new(Mounted {
            native: self.native.take(),
            verified_at,
        })))
    }
    pub(crate) fn cancel(&mut self, error: Error) {
        if let Some(n) = &mut self.native {
            n.cancel(error);
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
impl Mounted {
    pub(crate) fn resource_transfer(&self) -> Result<ResourceTransfer> {
        self.verify_retained()?;
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        ResourceTransfer::local(
            n.intent.transfer_ticket()?,
            NativeJobKind::NamespaceAttachment,
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
    /// Historical actual receipt plus fresh original native custody; this does
    /// not extend the old admission query or attachment operation deadline.
    pub(crate) fn verify_retained(&self) -> Result<()> {
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        n.creator()?;
        if n.reap.status.get() != Some(0)
            || n.failure.is_some()
            || !n.eof
            || !self.verified_at.is_finite()
            || self.verified_at >= n.request.deadline()
        {
            return Err(Error::OwnershipMismatch);
        }
        n.request.verify_retained_pins()?;
        n.verify_mounted_pins()
    }
    pub(crate) fn only_member_job(&self, server: &Server) -> Result<()> {
        self.native
            .as_ref()
            .ok_or(Error::Interrupted)?
            .intent
            .only_member_job(server)
    }
    pub(crate) fn request(&self) -> &Rc<Request> {
        &self.native.as_ref().expect("live mounted proof").request
    }
    pub(crate) fn verify_current(&self) -> Result<()> {
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        n.creator()?;
        if n.reap.status.get() != Some(0) || n.failure.is_some() || !n.eof {
            return Err(Error::OwnershipMismatch);
        }
        n.verify_mounted()
    }
    pub(crate) fn bind_service(&self, server: &Server) -> Result<()> {
        self.native
            .as_ref()
            .ok_or(Error::Interrupted)?
            .intent
            .same_service(server)
    }
    pub(crate) fn birth(&self) -> Result<ValidationBirth> {
        self.native
            .as_ref()
            .ok_or(Error::Interrupted)?
            .birth
            .clone()
            .ok_or(Error::Interrupted)
    }
    pub(crate) fn placeholder(&self) -> Result<Placeholder> {
        self.native
            .as_ref()
            .ok_or(Error::Interrupted)?
            .placeholder
            .clone()
            .ok_or(Error::Interrupted)
    }
    pub(crate) fn verified_at(&self) -> f64 {
        self.verified_at
    }
}
fn placeholder(fd: impl AsFd, directory: Identity) -> Result<Placeholder> {
    let s = fs::fstat(&fd).map_err(|_| Error::OwnershipMismatch)?;
    if s.st_dev != directory.dev
        || s.st_uid != 0
        || s.st_gid != 0
        || s.st_nlink != 1
        || s.st_mode != 0o100600
        || s.st_size != 0
    {
        return Err(Error::OwnershipMismatch);
    }
    Ok(Placeholder {
        identity: Identity::of(fd)?,
        mode: s.st_mode,
    })
}
pub(super) fn check(end: f64) -> Result<()> {
    let now = vprouter_core::health::boot_seconds();
    if !end.is_finite() || !now.is_finite() || now >= end || end - now > 2. {
        return Err(Error::Deadline);
    }
    Ok(())
}
#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}
pub(super) fn send_fd(channel: impl AsFd, fd: impl AsFd, phase: u8, end: f64) -> Result<()> {
    check(end)?;
    let rights = [fd.as_fd()];
    let mut buffer = [std::mem::MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut ancillary = net::SendAncillaryBuffer::new(&mut buffer);
    if !ancillary.push(net::SendAncillaryMessage::ScmRights(&rights)) {
        return Err(Error::DescriptorPolicy);
    }
    if net::sendmsg(
        channel,
        &[std::io::IoSlice::new(&[phase])],
        &mut ancillary,
        SendFlags::DONTWAIT | SendFlags::NOSIGNAL,
    )
    .map_err(|_| Error::DescriptorPolicy)?
        != 1
    {
        return Err(Error::DescriptorPolicy);
    }
    check(end)
}
fn create_placeholder(name: &std::ffi::CStr) -> Result<OwnedFd> {
    // Exact fixed-role flags: rustix openat unconditionally adds O_LARGEFILE,
    // which is deliberately not part of this zero-length placeholder syscall.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat,
            4,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(Error::OwnershipMismatch);
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
}
fn child_run(request: &Request, channel: BorrowedFd<'_>, parent: i32) -> Result<()> {
    parent_death(parent)?;
    cv(unsafe { libc::clearenv() }, Error::ChildFailed)?;
    let null = fs::open(c"/dev/null", OFlags::RDWR | OFlags::CLOEXEC, Mode::empty())
        .map_err(|_| Error::DescriptorNull)?;
    for fd in 0..3 {
        dup_fixed(&null, fd, false)?;
    }
    drop(null);
    // Temporary high slots make fixed remapping safe even when original FDs
    // overlap 3/4/5. They are all closed before the fixed native role runs.
    let source = rustix::io::fcntl_dupfd_cloexec(request.source(), 64)
        .map_err(|_| Error::DescriptorDuplicate)?;
    let directory = rustix::io::fcntl_dupfd_cloexec(request.directory(), 64)
        .map_err(|_| Error::DescriptorDuplicate)?;
    let private =
        rustix::io::fcntl_dupfd_cloexec(channel, 64).map_err(|_| Error::DescriptorDuplicate)?;
    dup_fixed(&source, 3, true)?;
    dup_fixed(&directory, 4, true)?;
    dup_fixed(&private, 5, true)?;
    drop(source);
    drop(directory);
    drop(private);
    let name = CString::new(request.name()).map_err(|_| Error::InvalidSpec)?;
    let source_path = c"/proc/self/fd/3";
    let target_path = c"/proc/self/fd/6";
    let how = OpenHow {
        flags: (libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW) as u64,
        mode: 0,
        resolve: (fs::ResolveFlags::BENEATH | fs::ResolveFlags::NO_SYMLINKS).bits(),
    };
    close_except(&[3, 4, 5])?;
    mount_capabilities()?;
    parent_death(parent)?;
    secret::non_dumpable()?;
    apply_filter(&mount_filter(
        name.as_ptr() as u64,
        source_path.as_ptr() as u64,
        target_path.as_ptr() as u64,
        &how as *const OpenHow as u64,
    ))?;
    let source = unsafe { BorrowedFd::borrow_raw(3) };
    let directory = unsafe { BorrowedFd::borrow_raw(4) };
    let channel = unsafe { BorrowedFd::borrow_raw(5) };
    let end = request.deadline();
    secret::gate(channel, end)?;
    if Identity::network(source)? != request.source_identity()
        || Identity::of(directory)? != request.directory_identity()
    {
        return Err(Error::OwnershipMismatch);
    }
    check(end)?;
    let placeholder_fd = create_placeholder(&name)?;
    if placeholder_fd.as_raw_fd() != 6 {
        return Err(Error::DescriptorPolicy);
    }
    placeholder(&placeholder_fd, request.directory_identity())?;
    check(end)?;
    fs::fsync(directory).map_err(|_| Error::Interrupted)?;
    send_fd(channel, &placeholder_fd, 1, end)?;
    secret::gate(channel, end)?;
    placeholder(&placeholder_fd, request.directory_identity())?;
    if Identity::network(source)? != request.source_identity() {
        return Err(Error::NamespaceMismatch);
    }
    check(end)?;
    cv(
        unsafe {
            libc::mount(
                source_path.as_ptr(),
                target_path.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND,
                std::ptr::null(),
            )
        },
        Error::NamespaceOperation,
    )?;
    check(end)?;
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
        return Err(Error::NamespaceMismatch);
    }
    let mounted = unsafe { OwnedFd::from_raw_fd(fd as i32) };
    if mounted.as_raw_fd() != 7 || Identity::network(&mounted)? != request.source_identity() {
        return Err(Error::NamespaceMismatch);
    }
    send_fd(channel, &mounted, 2, end)?;
    check(end)
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
    request.verify_native()?;
    let parent = std::process::id() as i32;
    let born_at = vprouter_core::health::boot_seconds();
    let (pid, pidfd) = fork_with_pidfd()?;
    if pid == 0 {
        let result = child_run(&request, child_channel.as_fd(), parent);
        die(if result.is_ok() { 0 } else { 122 });
    }
    let reap = ParentReap::born(pid as u32).expect("atomic clone creates original child");
    intent
        .lease()
        .native_job_mut()
        .born(NativeJobKind::NamespaceAttachment, &Some(reap.clone()));
    drop(child_token);
    drop(child_channel);
    let mut native = Native {
        creator: std::process::id(),
        request,
        intent,
        _capacity: ChildCapacity::created(),
        pid: pid as u32,
        pidfd: pidfd.expect("atomic clone has pidfd"),
        reap,
        pid_token: None,
        channel: parent_channel,
        _channel_token: parent_token,
        birth: None,
        received: Vec::new(),
        placeholder: None,
        released: 0,
        packets: 0,
        failure: None,
        eof: false,
    };
    let result = (|| {
        native.pid_token = Some(super::super::inventory::Registration::owned(&[native
            .pidfd
            .as_fd()])?);
        if wait_ready(&native.pidfd, Duration::ZERO)? {
            return Err(Error::ChildFailed);
        }
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .map_err(|_| Error::ProcessUnavailable)?;
        let start = process::stat_start(&stat, pid as u32)?;
        if wait_ready(&native.pidfd, Duration::ZERO)? {
            return Err(Error::ChildFailed);
        }
        native.reap.start.set(Some(start));
        native.birth = Some(ValidationBirth {
            pid: pid as u32,
            start,
            born_at,
            deadline: native.request.deadline(),
        });
        native.request.check()
    })();
    match result {
        Ok(()) => Ok(Child {
            native: Some(native),
        }),
        Err(error) => {
            native.cancel(error);
            retain(native);
            Err(error)
        }
    }
}
pub(super) fn mount_capabilities() -> Result<()> {
    cv(
        unsafe { libc::prctl(libc::PR_SET_SECUREBITS, 0xef, 0, 0, 0) },
        Error::CapabilityPolicy,
    )?;
    for cap in 0..64 {
        if unsafe { libc::prctl(libc::PR_CAPBSET_READ, cap, 0, 0, 0) } < 0 {
            break;
        }
        if cap != 21 {
            cv(
                unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0) },
                Error::CapabilityPolicy,
            )?;
        }
    }
    cv(
        unsafe {
            libc::prctl(
                libc::PR_CAP_AMBIENT,
                libc::PR_CAP_AMBIENT_CLEAR_ALL,
                0,
                0,
                0,
            )
        },
        Error::CapabilityPolicy,
    )?;
    cv(
        unsafe { libc::setgroups(0, std::ptr::null()) },
        Error::CapabilityPolicy,
    )?;
    cv(unsafe { libc::setresgid(0, 0, 0) }, Error::CapabilityPolicy)?;
    cv(unsafe { libc::setresuid(0, 0, 0) }, Error::CapabilityPolicy)?;
    #[repr(C)]
    struct Header {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    struct Caps {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    let header = Header {
        version: 0x20080522,
        pid: 0,
    };
    let caps = [
        Caps {
            effective: 1 << 21,
            permitted: 1 << 21,
            inheritable: 0,
        },
        Caps {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
    ];
    cv(
        unsafe { libc::syscall(libc::SYS_capset, &header, caps.as_ptr()) as i32 },
        Error::CapabilityPolicy,
    )?;
    cv(
        unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) },
        Error::CapabilityPolicy,
    )
}
pub(super) fn mount_filter(
    name: u64,
    source: u64,
    target: u64,
    how: u64,
) -> Vec<libc::sock_filter> {
    let mut out = secret::fixed_read_filter(&[3, 4, 6, 7], &[]);
    out.pop();
    out.extend(exact_args(
        libc::SYS_openat,
        &[
            (0, 4),
            (1, name),
            (
                2,
                (libc::O_RDONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    as u64,
            ),
            (3, 0o600),
        ],
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
    out.extend(exact_args(
        libc::SYS_mount,
        &[(0, source), (1, target), (2, 0), (3, libc::MS_BIND), (4, 0)],
    ));
    out.extend(exact_args(libc::SYS_fsync, &[(0, 4)]));
    secret::selected_fd_call(&mut out, libc::SYS_fstatfs, &[3, 4, 6, 7], None);
    out.extend(exact_args(
        libc::SYS_sendmsg,
        &[
            (0, 5),
            (2, (libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL) as u64),
        ],
    ));
    out.extend(exact_args(
        libc::SYS_recvfrom,
        &[
            (0, 5),
            (3, (libc::MSG_DONTWAIT | libc::MSG_TRUNC) as u64),
            (4, 0),
            (5, 0),
        ],
    ));
    secret::selected_fd_call(&mut out, libc::SYS_close, &[6, 7], None);
    out.push(libc::sock_filter {
        code: 0x06,
        jt: 0,
        jf: 0,
        k: 0x00050001,
    });
    out
}

#[cfg(test)]
impl Native {
    fn lab_evidence(&self) -> Result<serde_json::Value> {
        self.creator()?;
        let birth = self.birth.as_ref().ok_or(Error::OwnershipMismatch)?;
        if self.reap.pid != birth.pid
            || self.reap.start.get() != Some(birth.start)
            || Identity::network(self.request.source())? != self.request.source_identity()
            || Identity::of(self.request.directory())? != self.request.directory_identity()
        {
            return Err(Error::OwnershipMismatch);
        }
        let original_placeholder = self
            .placeholder
            .as_ref()
            .map(|p| -> Result<bool> {
                let fd = self.placeholder_fd()?;
                Ok(placeholder(fd, self.request.directory_identity())? == *p
                    && self.received[0]
                        .token
                        .as_ref()
                        .is_some_and(|t| t.contains(fd.as_fd())))
            })
            .transpose()?
            .unwrap_or(false);
        let original_mounted = self
            .received
            .get(1)
            .map(|r| -> Result<bool> {
                Ok(Identity::network(&r.fd)? == self.request.source_identity()
                    && r.token.as_ref().is_some_and(|t| t.contains(r.fd.as_fd())))
            })
            .transpose()?
            .unwrap_or(false);
        Ok(
            serde_json::json!({"birth":birth,"actual_wait_status":self.reap.status.get(),
            "requested_at":self.request.requested_at(),"deadline":self.request.deadline(),
            "original_source":self.request.source_identity(),"original_directory":self.request.directory_identity(),
            "placeholder":self.placeholder,"original_placeholder_retained":original_placeholder,
            "original_mounted_namespace_retained":original_mounted,"released_gates":self.released,
            "received_packets":self.packets,"eof":self.eof}),
        )
    }
}
#[cfg(test)]
impl Child {
    pub(crate) fn lab_evidence(&self) -> Result<serde_json::Value> {
        self.native
            .as_ref()
            .ok_or(Error::Interrupted)?
            .lab_evidence()
    }
}
#[cfg(test)]
impl Mounted {
    pub(crate) fn lab_evidence(&self) -> Result<serde_json::Value> {
        self.native
            .as_ref()
            .ok_or(Error::Interrupted)?
            .lab_evidence()
    }
}
#[cfg(test)]
pub(super) fn lab_filter_selftest() -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    let path = std::env::temp_dir().join(format!("vpr-attachment-filter-{}", std::process::id()));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&path)
        .map_err(|_| Error::OwnershipMismatch)?;
    let directory = fs::open(
        &path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| Error::OwnershipMismatch)?;
    let source = fs::open(
        c"/proc/self/ns/net",
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| Error::NamespaceMismatch)?;
    let excluded =
        rustix::io::fcntl_dupfd_cloexec(&directory, 200).map_err(|_| Error::DescriptorDuplicate)?;
    let excluded_number = excluded.as_raw_fd();
    let (channel, child) = net::socketpair(
        net::AddressFamily::UNIX,
        net::SocketType::SEQPACKET,
        net::SocketFlags::CLOEXEC,
        None,
    )
    .map_err(|_| Error::DescriptorPolicy)?;
    let registration = super::super::inventory::Registration::owned(&[
        directory.as_fd(),
        source.as_fd(),
        excluded.as_fd(),
        channel.as_fd(),
        child.as_fd(),
    ])?;
    let end = vprouter_core::health::boot_seconds() + 2.;
    let parent = std::process::id() as i32;
    let (pid, pidfd) = fork_with_pidfd()?;
    if pid == 0 {
        let stage = std::cell::Cell::new(0u8);
        let result = (|| {
            parent_death(parent)?;
            let a = rustix::io::fcntl_dupfd_cloexec(&source, 64)
                .map_err(|_| Error::DescriptorDuplicate)?;
            let b = rustix::io::fcntl_dupfd_cloexec(&directory, 64)
                .map_err(|_| Error::DescriptorDuplicate)?;
            let c = rustix::io::fcntl_dupfd_cloexec(&child, 64)
                .map_err(|_| Error::DescriptorDuplicate)?;
            dup_fixed(&a, 3, true)?;
            dup_fixed(&b, 4, true)?;
            dup_fixed(&c, 5, true)?;
            drop(a);
            drop(b);
            drop(c);
            stage.set(1);
            close_except(&[3, 4, 5])?;
            if unsafe { libc::fcntl(excluded_number, libc::F_GETFD) } != -1
                || std::io::Error::last_os_error().raw_os_error() != Some(libc::EBADF)
            {
                return Err(Error::DescriptorPolicy);
            }
            let name = c"owned";
            let how = OpenHow {
                flags: (libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW) as u64,
                mode: 0,
                resolve: (fs::ResolveFlags::BENEATH | fs::ResolveFlags::NO_SYMLINKS).bits(),
            };
            secret::non_dumpable()?;
            cv(
                unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) },
                Error::ConfinementPolicy,
            )?;
            stage.set(2);
            apply_filter(&mount_filter(
                name.as_ptr() as u64,
                c"/proc/self/fd/3".as_ptr() as u64,
                c"/proc/self/fd/6".as_ptr() as u64,
                &how as *const OpenHow as u64,
            ))?;
            stage.set(3);
            secret::lab_denials()?;
            let channel = unsafe { BorrowedFd::borrow_raw(5) };
            let directory = unsafe { BorrowedFd::borrow_raw(4) };
            stage.set(4);
            secret::gate(channel, end)?;
            stage.set(5);
            let fd = create_placeholder(name)?;
            if fd.as_raw_fd() != 6 {
                return Err(Error::DescriptorPolicy);
            }
            stage.set(6);
            fs::fstat(&fd).map_err(|_| Error::DescriptorPolicy)?;
            fs::fstatfs(&fd).map_err(|_| Error::DescriptorPolicy)?;
            stage.set(7);
            fs::fsync(directory).map_err(|_| Error::Interrupted)?;
            stage.set(8);
            send_fd(channel, &fd, 1, end)?;
            secret::gate(channel, end)?;
            stage.set(9);
            let opened = unsafe {
                libc::syscall(
                    libc::SYS_openat2,
                    4,
                    name.as_ptr(),
                    &how,
                    std::mem::size_of::<OpenHow>(),
                )
            };
            if opened < 0 {
                return Err(Error::DescriptorPolicy);
            }
            stage.set(10);
            let reopened = unsafe { OwnedFd::from_raw_fd(opened as i32) };
            if reopened.as_raw_fd() != 7 || Identity::of(&reopened)? != Identity::of(&fd)? {
                return Err(Error::DescriptorPolicy);
            }
            if create_placeholder(c"foreign").err() != Some(Error::OwnershipMismatch)
                || std::io::Error::last_os_error().raw_os_error() != Some(libc::EPERM)
            {
                return Err(Error::DescriptorPolicy);
            }
            stage.set(11);
            send_fd(channel, &reopened, 2, end)?;
            secret::lab_denials()?;
            Ok(())
        })();
        die(if result.is_ok() {
            0
        } else {
            40 + stage.get() as i32
        });
    }
    let original = ParentReap::born(pid as u32).ok_or(Error::ChildFailed)?;
    let pidfd = pidfd.expect("atomic clone pidfd");
    let mut pid_token = None;
    let mut received = Vec::new();
    let result = (|| {
        pid_token = Some(super::super::inventory::Registration::owned(&[
            pidfd.as_fd()
        ])?);
        if wait_ready(&pidfd, Duration::ZERO)? {
            return Err(Error::ChildFailed);
        }
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .map_err(|_| Error::ProcessUnavailable)?;
        let start = process::stat_start(&stat, pid as u32)?;
        if wait_ready(&pidfd, Duration::ZERO)? {
            return Err(Error::ChildFailed);
        }
        original.start.set(Some(start));
        for phase in [1, 2] {
            net::send(&channel, &[1], SendFlags::DONTWAIT | SendFlags::NOSIGNAL)
                .map_err(|_| Error::DescriptorPolicy)?;
            loop {
                check(end)?;
                if let Some(tag) = receive_packet(&channel, &mut received)? {
                    if tag != phase || received.len() != phase as usize {
                        return Err(Error::DescriptorPolicy);
                    }
                    break;
                }
                if wait_ready(&pidfd, Duration::ZERO)?
                    && original.poll(pid as u32, pidfd.as_fd())? != Some(0)
                {
                    return Err(Error::ChildFailed);
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        if Identity::of(&received[0].fd)? != Identity::of(&received[1].fd)? {
            return Err(Error::OwnershipMismatch);
        }
        if !wait_ready(&pidfd, Duration::from_secs(2))?
            || original.poll(pid as u32, pidfd.as_fd())? != Some(0)
        {
            return Err(Error::ChildFailed);
        }
        Ok(())
    })();
    if let Err(error) = result {
        eprintln!(
            "LAB_NAMESPACE_FILTER_FAILURE status={:?} phase_packets={} reason={error:?}",
            original.status.get(),
            received.len()
        );
        let mut tokens = vec![registration];
        tokens.extend(pid_token);
        let mut fds = vec![directory, source, excluded, child];
        for r in received {
            tokens.extend(r.token);
            fds.push(r.fd);
        }
        retain_fork_bundle_with_reap(
            pid,
            pidfd,
            channel,
            None,
            tokens,
            fds,
            None,
            None,
            None,
            Some(original),
            None,
        );
        return Err(error);
    }
    fs::unlinkat(&directory, c"owned", fs::AtFlags::empty()).map_err(|_| Error::Interrupted)?;
    std::fs::remove_dir(&path).map_err(|_| Error::Interrupted)?;
    println!(
        "LAB_NAMESPACE_ATTACHMENT_FILTER {{\"native_exit_zero\":true,\"original_two_gates\":true,\"exact_create_fsync_openat2\":true,\"scm_rights_cloexec\":true,\"private_descriptor_excluded\":true,\"fork_exec_dumpability_denied\":true,\"actual_namespace_mount\":false}}"
    );
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn real_scm_packets_preserve_every_received_fd_on_rejection() {
        for (payload, count, valid) in [
            (&[1u8][..], 1, true),
            (&[7u8][..], 1, false),
            (&[1u8][..], 2, false),
            (&[1u8, 2, 3][..], 1, false),
            (&[1u8][..], 8, false),
        ] {
            let (parent, child) = net::socketpair(
                net::AddressFamily::UNIX,
                net::SocketType::SEQPACKET,
                net::SocketFlags::CLOEXEC,
                None,
            )
            .unwrap();
            let fd = fs::open(
                c"/dev/null",
                OFlags::RDONLY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .unwrap();
            let _tokens = super::super::super::inventory::Registration::owned(&[
                parent.as_fd(),
                child.as_fd(),
                fd.as_fd(),
            ])
            .unwrap();
            let rights: Vec<_> = (0..count).map(|_| fd.as_fd()).collect();
            let mut buffer = [std::mem::MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(8))];
            let mut ancillary = net::SendAncillaryBuffer::new(&mut buffer);
            assert!(ancillary.push(net::SendAncillaryMessage::ScmRights(&rights)));
            net::sendmsg(
                &child,
                &[std::io::IoSlice::new(payload)],
                &mut ancillary,
                SendFlags::NOSIGNAL,
            )
            .unwrap();
            let mut received = Vec::new();
            let result = receive_packet(&parent, &mut received);
            if valid {
                assert_eq!(result, Ok(Some(1)));
            } else {
                assert_eq!(result, Err(Error::DescriptorPolicy));
            }
            if count <= 2 {
                assert_eq!(received.len(), count);
            } else {
                // Ancillary-buffer alignment padding can fit more than the
                // nominal four rights. Retain ALL actually delivered slots;
                // CTRUNC still rejects the frame and grants nothing.
                assert!(!received.is_empty() && received.len() < count);
            }
            for entry in received {
                assert!(entry.token.as_ref().unwrap().contains(entry.fd.as_fd()));
                assert!(descriptor_cloexec(entry.fd.as_raw_fd()).unwrap());
                assert_eq!(Identity::of(&entry.fd).unwrap(), Identity::of(&fd).unwrap());
            }
        }
    }
}
