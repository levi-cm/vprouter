//! Fixed one-shot stop of an ORIGINAL guard pidfd and producer cgroup.kill.
//! No namespace/expiry target, path, PID, signal or command arrives over IPC.
use super::*;
use rustix::net::{self, RecvFlags, SendFlags};

pub(crate) struct StopChild {
    native: Option<StopNative>,
}
struct StopNative {
    creator: u32,
    context: super::super::owned::StopContext,
    child: Survivor,
    channel: OwnedFd,
    _channel_inventory: super::super::inventory::Registration,
    _capacity: ChildCapacity,
    _lease: super::super::owned::MutatorLease,
    target: super::super::producer::StopTarget,
    guard: OwnedFd,
    _guard_inventory: super::super::inventory::Registration,
    deadline: f64,
    reaped: bool,
    failed: bool,
}
/// Emitted only after this exact fixed job's ACK and actual native exit0,
/// within its one original operation deadline. It is not quiescence authority.
#[derive(Clone)]
pub(crate) struct StopReceipt {
    context: super::super::owned::StopContext,
    finished_at: f64,
}
impl StopReceipt {
    pub(crate) fn verify(
        &self,
        binding: &super::super::owned::RetirementBinding,
        authority: [u8; 32],
    ) -> Result<()> {
        self.context.verify(binding, authority)?;
        if !self.finished_at.is_finite()
            || self.finished_at >= self.context.deadline()
            || self.finished_at < self.context.deadline() - 2.
        {
            return Err(Error::Deadline);
        }
        Ok(())
    }
}
thread_local! { static RETIRED: std::cell::RefCell<Vec<StopNative>> = const { std::cell::RefCell::new(Vec::new()) }; }
impl Drop for StopChild {
    fn drop(&mut self) {
        if let Some(native) = self.native.take() {
            if native.creator != std::process::id() || native.reaped {
                return;
            }
            let _ = send_or_exited(native.child.pidfd(), libc::SIGKILL);
            RETIRED.with(|retired| retired.borrow_mut().push(native));
        }
    }
}
pub(super) fn poll_retired() {
    RETIRED.with(|retired| {
        retired.borrow_mut().retain_mut(|native| {
            if native.creator != std::process::id() {
                return true;
            }
            let _ = send_or_exited(native.child.pidfd(), libc::SIGKILL);
            native.child.reap_exited() != Ok(true)
        })
    });
}
pub(crate) fn retired_drained() -> bool {
    RETIRED.with(|retired| {
        retired
            .borrow()
            .iter()
            .all(|n| n.creator != std::process::id())
    })
}
impl StopChild {
    fn native(&mut self) -> Result<&mut StopNative> {
        let n = self.native.as_mut().ok_or(Error::OwnershipMismatch)?;
        if n.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        Ok(n)
    }
    pub(crate) fn cancel(&mut self) -> Result<()> {
        let n = self.native()?;
        n.failed = true;
        send_or_exited(n.child.pidfd(), libc::SIGKILL)
    }
    /// Native collection continues after an error, without converting late ACKs
    /// or observed exit into an accepted stop result.
    pub(crate) fn drain(&mut self) -> Result<bool> {
        let n = self.native()?;
        if !n.reaped {
            n.reaped = n.child.reap_exited()?;
        }
        Ok(n.reaped)
    }
    pub(crate) fn poll(&mut self) -> Result<Option<StopReceipt>> {
        let n = self.native()?;
        if n.failed || n.reaped {
            return Err(Error::Interrupted);
        }
        let result = (|| {
            deadline(n.deadline)?;
            let Some(status) = n.child.reap_status()? else {
                return Ok(None);
            };
            n.reaped = true;
            if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
                return Err(Error::ChildFailed);
            }
            let mut ack = [0; 2];
            if net::recv(&n.channel, &mut ack, RecvFlags::DONTWAIT | RecvFlags::TRUNC)
                .map_err(|_| Error::DescriptorPolicy)?
                != (1, 1)
                || ack[0] != 128
            {
                return Err(Error::ChildFailed);
            }
            deadline(n.deadline)?;
            Ok(Some(StopReceipt {
                context: n.context.clone(),
                finished_at: vprouter_core::health::boot_seconds(),
            }))
        })();
        if result.is_err() {
            n.failed = true;
            let _ = send_or_exited(n.child.pidfd(), libc::SIGKILL);
        }
        result
    }
}
fn deadline(end: f64) -> Result<()> {
    let now = vprouter_core::health::boot_seconds();
    if !end.is_finite() || !now.is_finite() || now >= end || end - now > 2. {
        return Err(Error::Deadline);
    }
    Ok(())
}
pub(crate) fn spawn(authorization: super::super::owned::StopAuthorization) -> Result<StopChild> {
    let (context, target, guard, guard_inventory, mut lease) = authorization.into_native();
    let end = context.deadline();
    process::single_threaded()?;
    owner_admission_permitted()?;
    deadline(end)?;
    target.verify()?;
    if !guard_inventory.contains(guard.as_fd()) {
        return Err(Error::DescriptorPolicy);
    }
    lease.prepare_native_job(NativeJobKind::RetirementStop)?;
    super::super::inventory::verify()?;
    let (channel, child_channel) = net::socketpair(
        net::AddressFamily::UNIX,
        net::SocketType::SEQPACKET,
        net::SocketFlags::CLOEXEC,
        None,
    )
    .map_err(|_| Error::DescriptorPolicy)?;
    let channel_inventory = super::super::inventory::Registration::owned(&[channel.as_fd()])?;
    let child_inventory = super::super::inventory::Registration::owned(&[child_channel.as_fd()])?;
    let parent = std::process::id() as i32;
    let (pid, pinned) = fork_with_pidfd()?;
    if pid == 0 {
        let result = (|| {
            parent_death(parent)?;
            deadline(end)?;
            cv(unsafe { libc::clearenv() }, Error::ChildFailed)?;
            let control = std::mem::ManuallyDrop::new(
                rustix::io::fcntl_dupfd_cloexec(&child_channel, 110)
                    .map_err(|_| Error::DescriptorDuplicate)?,
            );
            let root = std::mem::ManuallyDrop::new(
                rustix::io::fcntl_dupfd_cloexec(&guard, 110)
                    .map_err(|_| Error::DescriptorDuplicate)?,
            );
            let kill = std::mem::ManuallyDrop::new(
                rustix::io::fcntl_dupfd_cloexec(target.descriptor(), 110)
                    .map_err(|_| Error::DescriptorDuplicate)?,
            );
            let allocation = std::mem::ManuallyDrop::new(
                rustix::io::fcntl_dupfd_cloexec(lease.fd(), 110)
                    .map_err(|_| Error::DescriptorDuplicate)?,
            );
            let null = std::mem::ManuallyDrop::new(
                fs::open(c"/dev/null", OFlags::RDWR | OFlags::CLOEXEC, Mode::empty())
                    .map_err(|_| Error::DescriptorNull)?,
            );
            for number in 0..3 {
                dup_fixed(&*null, number, false)?;
            }
            dup_fixed(&*control, 3, true)?;
            dup_fixed(&*root, 4, true)?;
            dup_fixed(&*kill, 5, true)?;
            dup_fixed(&*allocation, 6, true)?;
            close_except(&[3, 4, 5, 6])?;
            // Same UID as the exact owned guard; no capabilities or regain path.
            drop_identity(0)?;
            parent_death(parent)?;
            apply_filter(&stop_filter())?;
            deadline(end)?;
            let control = unsafe { BorrowedFd::borrow_raw(3) };
            let remaining = end - vprouter_core::health::boot_seconds();
            if remaining <= 0. || !ready(control, Duration::from_secs_f64(remaining))? {
                return Err(Error::Deadline);
            }
            let mut byte = [0u8; 2];
            if net::recv(control, &mut byte, RecvFlags::DONTWAIT | RecvFlags::TRUNC)
                .map_err(|_| Error::DescriptorPolicy)?
                != (1, 1)
                || byte[0] != 1
            {
                return Err(Error::DescriptorPolicy);
            }
            deadline(end)?;
            // Fixed descriptors only. ESRCH for this original pidfd means already
            // exited; it does not mint a parent's waitpid or cleanup receipt.
            stop_guard(unsafe { BorrowedFd::borrow_raw(4) })?;
            if rustix::io::write(unsafe { BorrowedFd::borrow_raw(5) }, b"1")
                .map_err(|_| Error::CgroupMismatch)?
                != 1
            {
                return Err(Error::CgroupMismatch);
            }
            deadline(end)?;
            if net::send(control, &[128], SendFlags::DONTWAIT | SendFlags::NOSIGNAL)
                .map_err(|_| Error::DescriptorPolicy)?
                != 1
            {
                return Err(Error::DescriptorPolicy);
            }
            deadline(end)
        })();
        die(if result.is_ok() { 0 } else { 122 });
    }
    let reap = ParentReap::born(pid as u32);
    lease
        .native_job_mut()
        .born(NativeJobKind::RetirementStop, &reap);
    drop(child_inventory);
    drop(child_channel);
    let pinned = pinned.ok_or(Error::ChildFailed)?;
    let registration = match super::super::inventory::Registration::owned(&[pinned.as_fd()]) {
        Ok(value) => value,
        Err(error) => {
            let (mut pins, target_inventory) = target.into_retained();
            pins.push(guard);
            retain_fork_bundle_with_reap(
                pid,
                pinned,
                channel,
                None,
                vec![channel_inventory, guard_inventory, target_inventory],
                pins,
                None,
                None,
                Some(lease),
                reap,
                None,
            );
            return Err(error);
        }
    };
    let mut result = StopChild {
        native: Some(StopNative {
            creator: std::process::id(),
            context,
            child: Survivor {
                pid: pid as u32,
                pinned,
                _inventory: registration,
                reap,
            },
            channel,
            _channel_inventory: channel_inventory,
            _capacity: ChildCapacity::created(),
            _lease: lease,
            target,
            guard,
            _guard_inventory: guard_inventory,
            deadline: end,
            reaped: false,
            failed: false,
        }),
    };
    let release = (|| {
        let n = result.native()?;
        owner_admission_permitted()?;
        deadline(end)?;
        n.target.verify()?;
        if !n._guard_inventory.contains(n.guard.as_fd()) {
            return Err(Error::DescriptorPolicy);
        }
        if net::send(&n.channel, &[1], SendFlags::DONTWAIT | SendFlags::NOSIGNAL)
            .map_err(|_| Error::DescriptorPolicy)?
            != 1
        {
            return Err(Error::DescriptorPolicy);
        }
        Ok(())
    })();
    if let Err(error) = release {
        let _ = result.cancel();
        return Err(error);
    }
    Ok(result)
}
// Fixed-role ppoll on both architectures; generic libc poll is intentionally
// not admitted. This same path handles an already-exited ORIGINAL pidfd.
fn ready(fd: BorrowedFd<'_>, timeout: Duration) -> Result<bool> {
    let mut fds = [rustix::event::PollFd::new(
        &fd,
        rustix::event::PollFlags::IN,
    )];
    let timeout = rustix::event::Timespec {
        tv_sec: timeout.as_secs() as i64,
        tv_nsec: timeout.subsec_nanos() as i64,
    };
    rustix::event::poll(&mut fds, Some(&timeout)).map_err(|_| Error::ChildFailed)?;
    let events = fds[0].revents();
    if events.intersects(rustix::event::PollFlags::ERR | rustix::event::PollFlags::NVAL) {
        return Err(Error::ChildFailed);
    }
    Ok(events.intersects(rustix::event::PollFlags::IN | rustix::event::PollFlags::HUP))
}
fn stop_guard(fd: BorrowedFd<'_>) -> Result<()> {
    match send(fd, libc::SIGKILL) {
        Ok(()) => Ok(()),
        Err(error) if std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) => {
            if ready(fd, Duration::ZERO)? {
                Ok(())
            } else {
                Err(error)
            }
        }
        Err(error) => Err(error),
    }
}
pub(super) fn stop_filter() -> Vec<libc::sock_filter> {
    let mut out = filter()[..4].to_vec();
    out.extend(exact_args(
        libc::SYS_prctl,
        &[
            (0, libc::PR_GET_SECCOMP as u64),
            (1, 0),
            (2, 0),
            (3, 0),
            (4, 0),
        ],
    ));
    out.extend(exact_args(
        libc::SYS_pidfd_send_signal,
        &[(0, 4), (1, libc::SIGKILL as u64), (2, 0), (3, 0)],
    ));
    out.extend(exact_args(libc::SYS_write, &[(0, 5), (2, 1)]));
    out.extend(exact_args(
        libc::SYS_sendto,
        &[
            (0, 3),
            (2, 1),
            (3, (libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL) as u64),
            (4, 0),
            (5, 0),
        ],
    ));
    out.extend(exact_args(
        libc::SYS_recvfrom,
        &[
            (0, 3),
            (2, 2),
            (3, (libc::MSG_DONTWAIT | libc::MSG_TRUNC) as u64),
            (4, 0),
            (5, 0),
        ],
    ));
    for nr in [
        libc::SYS_ppoll,
        libc::SYS_clock_gettime,
        libc::SYS_exit,
        libc::SYS_exit_group,
        libc::SYS_rt_sigreturn,
    ] {
        allow_syscall(&mut out, nr);
    }
    out.push(libc::sock_filter {
        code: 0x06,
        jt: 0,
        jf: 0,
        k: 0x00050001,
    });
    out
}

#[cfg(test)]
pub(super) fn lab_filter_selftest() -> Result<()> {
    // Real original child and its original pidfd. No cgroup mutation here: FD5
    // is a pipe proving only the fixed write syscall and output shape.
    let mut target = lab_idle_child()?;
    for already_reaped in [false, true] {
        let (parent, channel) = net::socketpair(
            net::AddressFamily::UNIX,
            net::SocketType::SEQPACKET,
            net::SocketFlags::CLOEXEC,
            None,
        )
        .map_err(|_| Error::DescriptorPolicy)?;
        let (read, write) = pipe()?;
        let (pid, pinned) = fork_with_pidfd()?;
        if pid == 0 {
            let result = (|| {
                let channel = std::mem::ManuallyDrop::new(
                    rustix::io::fcntl_dupfd_cloexec(&channel, 110)
                        .map_err(|_| Error::DescriptorDuplicate)?,
                );
                let root = std::mem::ManuallyDrop::new(
                    rustix::io::fcntl_dupfd_cloexec(&target.pidfd, 110)
                        .map_err(|_| Error::DescriptorDuplicate)?,
                );
                let write = std::mem::ManuallyDrop::new(
                    rustix::io::fcntl_dupfd_cloexec(&write, 110)
                        .map_err(|_| Error::DescriptorDuplicate)?,
                );
                dup_fixed(&*channel, 3, true)?;
                dup_fixed(&*root, 4, true)?;
                dup_fixed(&*write, 5, true)?;
                close_except(&[3, 4, 5])?;
                cv(
                    unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) },
                    Error::CapabilityPolicy,
                )?;
                apply_filter(&stop_filter())?;
                let control = unsafe { BorrowedFd::borrow_raw(3) };
                if !ready(control, Duration::from_secs(1))? {
                    return Err(Error::Deadline);
                }
                let mut request = [0; 2];
                if net::recv(
                    control,
                    &mut request,
                    RecvFlags::DONTWAIT | RecvFlags::TRUNC,
                )
                .map_err(|_| Error::DescriptorPolicy)?
                    != (1, 1)
                    || request[0] != 1
                {
                    return Err(Error::DescriptorPolicy);
                }
                stop_guard(unsafe { BorrowedFd::borrow_raw(4) })?;
                if rustix::io::write(unsafe { BorrowedFd::borrow_raw(5) }, b"1")
                    .map_err(|_| Error::DescriptorPolicy)?
                    != 1
                {
                    return Err(Error::DescriptorPolicy);
                }
                if net::send(control, &[128], SendFlags::DONTWAIT | SendFlags::NOSIGNAL)
                    .map_err(|_| Error::DescriptorPolicy)?
                    != 1
                {
                    return Err(Error::DescriptorPolicy);
                }
                Ok(())
            })();
            die(if result.is_ok() { 0 } else { 122 });
        }
        drop(channel);
        drop(write);
        let pinned = pinned.ok_or(Error::ChildFailed)?;
        let result = (|| {
            std::thread::sleep(Duration::from_millis(25));
            net::send(&parent, &[1], SendFlags::DONTWAIT | SendFlags::NOSIGNAL)
                .map_err(|_| Error::DescriptorPolicy)?;
            if !wait_ready(&pinned, Duration::from_secs(2))? {
                return Err(Error::Deadline);
            }
            let mut ack = [0; 2];
            if net::recv(&parent, &mut ack, RecvFlags::DONTWAIT | RecvFlags::TRUNC)
                .map_err(|_| Error::DescriptorPolicy)?
                != (1, 1)
                || ack[0] != 128
            {
                return Err(Error::ChildFailed);
            }
            let mut byte = [0; 2];
            if rustix::io::read(&read, &mut byte).map_err(|_| Error::DescriptorPolicy)? != 1
                || byte[0] != b'1'
            {
                return Err(Error::DescriptorPolicy);
            }
            Ok(())
        })();
        if result.is_err() {
            let _ = send_or_exited(pinned.as_fd(), libc::SIGKILL);
        }
        if !wait_ready(&pinned, Duration::from_secs(1))? {
            retain_fork_bundle(pid, pinned, parent, None, vec![], vec![read], None);
            let _ = target.signal(libc::SIGKILL);
            let _ = target.reap();
            return Err(Error::Deadline);
        }
        let mut status = 0;
        let reaped = unsafe { libc::waitpid(pid, &mut status, 0) } == pid
            && libc::WIFEXITED(status)
            && libc::WEXITSTATUS(status) == 0;
        if !target.reaped {
            let _ = target.signal(libc::SIGKILL);
            if !wait_ready(&target.pidfd, Duration::from_secs(1))? {
                return Err(Error::Deadline);
            }
            let mut target_status = 0;
            if unsafe { libc::waitpid(target.pid as i32, &mut target_status, 0) }
                != target.pid as i32
            {
                return Err(Error::ChildFailed);
            }
            target.reaped = true;
            if !libc::WIFSIGNALED(target_status) || libc::WTERMSIG(target_status) != libc::SIGKILL {
                return Err(Error::ChildFailed);
            }
        }
        result?;
        if !reaped {
            return Err(Error::ChildFailed);
        }
        eprintln!(
            "LAB_RETIREMENT_STOP_FILTER original_target_already_reaped={already_reaped} gated_ppoll=true fixed_write=true actual_helper_exit0=true original_target_wait_sigkill=true"
        );
    }
    Ok(())
}
