//! Fixed native half of one durable, already-quiescent member retirement.
//! No journal/model mutation, target, command or program is supplied over IPC.
use super::*;
use rustix::net::{self, RecvFlags, SendFlags};
use std::{cell::RefCell, rc::Rc};

type Transport = Rc<RefCell<super::super::transport::RetirementTransport>>;
pub(crate) struct CleanupChild {
    native: Option<CleanupNative>,
}
struct CleanupNative {
    creator: u32,
    context: super::super::owned::CleanupContext,
    transport: Transport,
    target: super::super::producer::CleanupTarget,
    pid: u32,
    pidfd: OwnedFd,
    reap: Option<Rc<ParentReap>>,
    pid_inventory: Option<super::super::inventory::Registration>,
    channel: OwnedFd,
    _channel_inventory: super::super::inventory::Registration,
    _capacity: ChildCapacity,
    _lease: super::super::owned::MutatorLease,
    _timer: std::sync::Arc<OwnedFd>,
    _timer_inventory: super::super::inventory::Registration,
    reaped: bool,
    failed: bool,
}
pub(crate) struct CleanupReceipt {
    context: super::super::owned::CleanupContext,
    finished_at: f64,
    host: Option<vprouter_network::HostObservation>,
}
impl CleanupReceipt {
    pub(crate) fn verify_unlinked(
        &self,
        binding: &super::super::owned::RetirementBinding,
        transition: &str,
    ) -> Result<()> {
        self.context.verify_unlinked(binding, transition)?;
        if self.host.is_some()
            || !self.finished_at.is_finite()
            || self.finished_at < self.context.deadline() - 2.
            || self.finished_at >= self.context.deadline()
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
    pub(crate) fn verify_authority(
        &self,
        binding: &super::super::owned::RetirementBinding,
        authority: [u8; 32],
        transition: &str,
        stage: super::super::owned::CleanupStage,
    ) -> Result<()> {
        self.context
            .verify_authority(binding, authority, transition, stage)?;
        if self.context.producer_operation() != self.host.is_none() {
            return Err(Error::OwnershipMismatch);
        }
        if !self.finished_at.is_finite()
            || self.finished_at < self.context.deadline() - 2.
            || self.finished_at >= self.context.deadline()
        {
            return Err(Error::Deadline);
        }
        Ok(())
    }
    pub(crate) fn verify(
        &self,
        permit: &super::super::owned::CleanupPermit,
    ) -> Result<&vprouter_network::HostObservation> {
        self.context.verify(permit)?;
        if !self.finished_at.is_finite()
            || self.finished_at < self.context.deadline() - 2.
            || self.finished_at >= self.context.deadline()
        {
            return Err(Error::Deadline);
        }
        self.host.as_ref().ok_or(Error::OwnershipMismatch)
    }
}
thread_local! { static RETIRED: RefCell<Vec<CleanupNative>> = const { RefCell::new(Vec::new()) }; }
impl CleanupNative {
    fn collect(&mut self) -> Result<Option<i32>> {
        if self.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        // Only this exact atomic constructor can own a missing postclone token.
        // Retry registering its still-owned original fd; never inspect/adopt a PID.
        if self.pid_inventory.is_none() {
            self.pid_inventory =
                super::super::inventory::Registration::owned(&[self.pidfd.as_fd()]).ok();
        }
        let status = self
            .reap
            .as_ref()
            .ok_or(Error::OwnershipMismatch)?
            .poll(self.pid, self.pidfd.as_fd())?;
        self.reaped = status.is_some();
        Ok(status)
    }
}
impl Drop for CleanupChild {
    fn drop(&mut self) {
        if let Some(native) = self.native.take() {
            if native.creator != std::process::id() || native.reaped {
                return;
            }
            let _ = send_or_exited(native.pidfd.as_fd(), libc::SIGKILL);
            RETIRED.with(|jobs| jobs.borrow_mut().push(native));
        }
    }
}
pub(super) fn poll_retired() {
    RETIRED.with(|jobs| {
        jobs.borrow_mut().retain_mut(|job| {
            if job.creator != std::process::id() {
                return true;
            }
            let _ = send_or_exited(job.pidfd.as_fd(), libc::SIGKILL);
            !matches!(job.collect(), Ok(Some(_)))
        })
    });
}
pub(super) fn retired_drained() -> bool {
    RETIRED.with(|jobs| {
        jobs.borrow()
            .iter()
            .all(|job| job.creator != std::process::id())
    })
}
#[cfg(test)]
thread_local! {
    static NATIVE_SUBPHASE: std::cell::Cell<u8> = const { std::cell::Cell::new(0) };
    static NATIVE_PHASE: std::cell::Cell<u8> = const { std::cell::Cell::new(0) };
    static HOLD_LINKS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FENCE_GATE: std::cell::Cell<Option<(i32, f64, u8)>> = const { std::cell::Cell::new(None) };
}
#[cfg(test)]
pub(crate) fn lab_native_subphase(value: u8) {
    NATIVE_SUBPHASE.with(|phase| phase.set(value));
}
#[cfg(test)]
pub(crate) fn lab_hold_next_links() {
    HOLD_LINKS.with(|flag| flag.set(true));
}
#[cfg(test)]
pub(crate) fn lab_native_fence() -> Result<()> {
    NATIVE_PHASE.with(|phase| phase.set(phase.get().saturating_add(1)));
    let Some((fd, end, count)) = FENCE_GATE.with(|state| state.get()) else {
        return Ok(());
    };
    FENCE_GATE.with(|state| state.set(Some((fd, end, count.saturating_add(1)))));
    // Third exact native fence follows actual WG deletion and precedes host-veth
    // deletion. Keep the SAME original two-second operation deadline while A runs.
    if count != 2 {
        return Ok(());
    }
    deadline(end)?;
    let channel = unsafe { BorrowedFd::borrow_raw(fd) };
    if net::send(channel, &[9], SendFlags::DONTWAIT | SendFlags::NOSIGNAL)
        .map_err(|_| Error::DescriptorPolicy)?
        != 1
    {
        return Err(Error::DescriptorPolicy);
    }
    let remaining = end - vprouter_core::health::boot_seconds();
    if remaining <= 0. {
        return Err(Error::Deadline);
    }
    let mut polls = [rustix::event::PollFd::new(
        &channel,
        rustix::event::PollFlags::IN,
    )];
    if rustix::event::poll(
        &mut polls,
        Some(
            &rustix::event::Timespec::try_from(Duration::from_secs_f64(remaining))
                .map_err(|_| Error::Deadline)?,
        ),
    )
    .map_err(|_| Error::DescriptorPolicy)?
        == 0
    {
        return Err(Error::Deadline);
    }
    let mut byte = [0; 2];
    if net::recv(channel, &mut byte, RecvFlags::DONTWAIT | RecvFlags::TRUNC)
        .map_err(|_| Error::DescriptorPolicy)?
        != (1, 1)
        || byte[0] != 2
    {
        return Err(Error::DescriptorPolicy);
    }
    deadline(end)
}
impl CleanupChild {
    #[cfg(test)]
    pub(crate) fn lab_snapshot(&self) -> Result<serde_json::Value> {
        let native = self.native.as_ref().ok_or(Error::OwnershipMismatch)?;
        let reap = native.reap.as_ref().ok_or(Error::OwnershipMismatch)?;
        if native.creator != std::process::id()
            || reap.creator != native.creator
            || reap.pid != native.pid
        {
            return Err(Error::OwnershipMismatch);
        }
        // Diagnostic only: read the original constructor's cached facts, never
        // reap or infer death from a new observation while reporting failure.
        Ok(serde_json::json!({
            "pid": native.pid, "start": reap.start.get(),
            "original_started_at": native.context.deadline() - 2.,
            "original_deadline": native.context.deadline(),
            "actual_wait_status": reap.status.get(),
            "native_reaped": native.reaped, "failed": native.failed,
        }))
    }
    #[cfg(test)]
    pub(crate) fn lab_checkpoint(&mut self) -> Result<bool> {
        let native = self.native()?;
        deadline(native.context.deadline())?;
        let mut byte = [0; 2];
        match net::recv(
            &native.channel,
            &mut byte,
            RecvFlags::DONTWAIT | RecvFlags::PEEK | RecvFlags::TRUNC,
        ) {
            Ok((1, 1)) if byte[0] == 9 => Ok(true),
            Err(rustix::io::Errno::AGAIN) => Ok(false),
            Ok(_) => Ok(false),
            Err(_) => Err(Error::DescriptorPolicy),
        }
    }
    #[cfg(test)]
    pub(crate) fn lab_release(&mut self) -> Result<()> {
        if !self.lab_checkpoint()? {
            return Err(Error::OwnershipMismatch);
        }
        let native = self.native()?;
        let mut byte = [0; 2];
        if net::recv(
            &native.channel,
            &mut byte,
            RecvFlags::DONTWAIT | RecvFlags::TRUNC,
        )
        .map_err(|_| Error::DescriptorPolicy)?
            != (1, 1)
            || byte[0] != 9
        {
            return Err(Error::DescriptorPolicy);
        }
        deadline(native.context.deadline())?;
        write_byte(&native.channel, 2)
    }
    fn native(&mut self) -> Result<&mut CleanupNative> {
        let native = self.native.as_mut().ok_or(Error::OwnershipMismatch)?;
        if native.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        Ok(native)
    }
    pub(crate) fn cancel(&mut self) -> Result<()> {
        let native = self.native()?;
        native.failed = true;
        send_or_exited(native.pidfd.as_fd(), libc::SIGKILL)
    }
    pub(crate) fn drain(&mut self) -> Result<bool> {
        Ok(self.native()?.collect()?.is_some())
    }
    pub(crate) fn poll(&mut self) -> Result<Option<CleanupReceipt>> {
        let native = self.native()?;
        if native.failed || native.reaped {
            return Err(Error::Interrupted);
        }
        let result = (|| {
            deadline(native.context.deadline())?;
            let Some(status) = native.collect()? else {
                return Ok(None);
            };
            if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
                #[cfg(test)]
                {
                    let mut failure = [0; 4];
                    let bound = net::recv(
                        &native.channel,
                        &mut failure,
                        RecvFlags::DONTWAIT | RecvFlags::TRUNC,
                    ) == Ok((4, 4))
                        && failure[0] == 254;
                    eprintln!(
                        "LAB_CLEANUP_CHILD_FAILURE producer={} pid={} start={:?} wait_status={status} diagnostic_bound={bound} phase={} reason_code={} subphase={}",
                        native.context.producer_operation(),
                        native.pid,
                        native.reap.as_ref().and_then(|reap| reap.start.get()),
                        if bound { failure[1] } else { 0 },
                        if bound { failure[2] } else { 0 },
                        if bound { failure[3] } else { 0 }
                    );
                }
                return Err(Error::ChildFailed);
            }
            let mut bytes = vec![0u8; vprouter_network::HOST_OBSERVATION_BYTES + 9];
            let (n, full) = net::recv(
                &native.channel,
                &mut bytes,
                RecvFlags::DONTWAIT | RecvFlags::TRUNC,
            )
            .map_err(|_| Error::DescriptorPolicy)?;
            if n != full || n <= 8 || n > vprouter_network::HOST_OBSERVATION_BYTES + 8 {
                return Err(Error::TooLarge);
            }
            let finished_at =
                f64::from_le_bytes(bytes[..8].try_into().map_err(|_| Error::DescriptorPolicy)?);
            let now = vprouter_core::health::boot_seconds();
            if !finished_at.is_finite()
                || finished_at < native.context.deadline() - 2.
                || finished_at >= native.context.deadline()
                || finished_at > now
            {
                return Err(Error::Deadline);
            }
            let host = if native.context.producer_operation() {
                if n != 9 || bytes[8] != 128 {
                    return Err(Error::DescriptorPolicy);
                }
                None
            } else {
                Some(
                    vprouter_network::HostObservation::decode(&bytes[8..n])
                        .map_err(|_| Error::NetworkOperation)?,
                )
            };
            deadline(native.context.deadline())?;
            Ok(Some(CleanupReceipt {
                context: native.context.clone(),
                finished_at,
                host,
            }))
        })();
        if result.is_err() {
            native.failed = true;
            let _ = send_or_exited(native.pidfd.as_fd(), libc::SIGKILL);
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
pub(crate) fn spawn(
    authorization: super::super::owned::CleanupAuthorization,
) -> Result<CleanupChild> {
    let (context, target, transport, plan, mut lease) = authorization.into_native();
    let end = context.deadline();
    process::single_threaded()?;
    owner_admission_permitted()?;
    deadline(end)?;
    target.verify_parent()?;
    lease.prepare_native_job(NativeJobKind::RetirementCleanup)?;
    let producer = context.producer_operation();
    if producer != plan.is_none() {
        return Err(Error::OwnershipMismatch);
    }
    let sockets: Vec<_> = if producer {
        Vec::new()
    } else {
        transport
            .try_borrow()
            .map_err(|_| Error::LockBusy)?
            .cleanup_descriptors()?
            .into_iter()
            .map(|fd| fd.as_raw_fd())
            .collect()
    };
    let target_fds: Vec<_> = target
        .descriptors()
        .into_iter()
        .map(|fd| fd.as_raw_fd())
        .collect();
    let timer = std::sync::Arc::new(
        rustix::time::timerfd_create(
            rustix::time::TimerfdClockId::Boottime,
            rustix::time::TimerfdFlags::CLOEXEC | rustix::time::TimerfdFlags::NONBLOCK,
        )
        .map_err(|_| Error::DescriptorPolicy)?,
    );
    let timer_inventory = super::super::inventory::Registration::owned(&[timer.as_fd()])?;
    let at = Duration::try_from_secs_f64(end)
        .map_err(|_| Error::Deadline)?
        .checked_sub(Duration::from_nanos(1))
        .ok_or(Error::Deadline)?;
    rustix::time::timerfd_settime(
        &timer,
        rustix::time::TimerfdTimerFlags::ABSTIME,
        &rustix::time::Itimerspec {
            it_interval: rustix::time::Timespec {
                tv_sec: 0,
                tv_nsec: 0,
            },
            it_value: rustix::time::Timespec::try_from(at).map_err(|_| Error::Deadline)?,
        },
    )
    .map_err(|_| Error::DescriptorPolicy)?;
    let (channel, child_channel) = net::socketpair(
        net::AddressFamily::UNIX,
        net::SocketType::SEQPACKET,
        net::SocketFlags::CLOEXEC,
        None,
    )
    .map_err(|_| Error::DescriptorPolicy)?;
    let channel_inventory = super::super::inventory::Registration::owned(&[channel.as_fd()])?;
    let child_inventory = super::super::inventory::Registration::owned(&[child_channel.as_fd()])?;
    let mut kept = sockets.clone();
    kept.extend(&target_fds);
    kept.push(child_channel.as_raw_fd());
    kept.push(lease.fd().as_raw_fd());
    kept.push(timer.as_raw_fd());
    let unique: std::collections::BTreeSet<_> = kept.iter().copied().collect();
    if kept.len() != if producer { 7 } else { 19 }
        || unique.len() != kept.len()
        || kept.iter().any(|fd| *fd < 3)
    {
        return Err(Error::DescriptorInventory);
    }
    super::super::inventory::verify()?;
    #[cfg(test)]
    let hold = !producer && HOLD_LINKS.with(|flag| flag.replace(false));
    let parent = std::process::id() as i32;
    let (pid, pinned) = fork_with_pidfd()?;
    if pid == 0 {
        #[cfg(test)]
        NATIVE_PHASE.with(|phase| phase.set(1));
        let result = (|| {
            parent_death(parent)?;
            deadline(end)?;
            cv(unsafe { libc::clearenv() }, Error::ChildFailed)?;
            let null = std::mem::ManuallyDrop::new(
                fs::open(c"/dev/null", OFlags::RDWR | OFlags::CLOEXEC, Mode::empty())
                    .map_err(|_| Error::DescriptorNull)?,
            );
            for fd in 0..3 {
                dup_fixed(&*null, fd, false)?;
            }
            close_except(&kept)?;
            if producer {
                drop_identity(0)?;
            } else {
                terminal_capabilities()?;
            }
            parent_death(parent)?;
            #[cfg(test)]
            if hold {
                FENCE_GATE.with(|state| state.set(Some((child_channel.as_raw_fd(), end, 0))));
            }
            #[cfg(test)]
            NATIVE_PHASE.with(|phase| phase.set(2));
            let filter = cleanup_filter(&sockets, &target_fds, child_channel.as_raw_fd(), producer);
            apply_filter(&filter)?;
            #[cfg(test)]
            NATIVE_PHASE.with(|phase| phase.set(3));
            if !producer {
                transport
                    .try_borrow_mut()
                    .map_err(|_| Error::LockBusy)?
                    .bind_cleanup_deadline(end, timer.clone())?;
            }
            // Only the fixed gate byte is accepted. No target or mutable plan
            // arrives here. All raw WG readback occurs after the no-fork filter.
            let remaining = end - vprouter_core::health::boot_seconds();
            let mut polls = [rustix::event::PollFd::new(
                &child_channel,
                rustix::event::PollFlags::IN,
            )];
            if remaining <= 0.
                || rustix::event::poll(
                    &mut polls,
                    Some(
                        &rustix::event::Timespec::try_from(Duration::from_secs_f64(remaining))
                            .map_err(|_| Error::Deadline)?,
                    ),
                )
                .map_err(|_| Error::DescriptorPolicy)?
                    == 0
            {
                return Err(Error::Deadline);
            }
            let mut gate = [0; 2];
            if net::recv(
                &child_channel,
                &mut gate,
                RecvFlags::DONTWAIT | RecvFlags::TRUNC,
            )
            .map_err(|_| Error::DescriptorPolicy)?
                != (1, 1)
                || gate[0] != 1
            {
                return Err(Error::DescriptorPolicy);
            }
            deadline(end)?;
            #[cfg(test)]
            NATIVE_PHASE.with(|phase| phase.set(16));
            let bytes = if let Some(plan) = &plan {
                let observed = transport
                    .try_borrow_mut()
                    .map_err(|_| Error::LockBusy)?
                    .cleanup_links_native(plan, &target, end)?;
                deadline(end)?;
                observed.encode().map_err(|_| Error::TooLarge)?
            } else {
                target.unlink_native(end)?;
                vec![128]
            };
            deadline(end)?;
            let mut reply = vprouter_core::health::boot_seconds().to_le_bytes().to_vec();
            reply.extend(bytes);
            if net::send(
                &child_channel,
                &reply,
                SendFlags::DONTWAIT | SendFlags::NOSIGNAL,
            )
            .map_err(|_| Error::DescriptorPolicy)?
                != reply.len()
            {
                return Err(Error::DescriptorPolicy);
            }
            deadline(end)
        })();
        #[cfg(test)]
        if let Err(error) = result {
            let phase = NATIVE_PHASE.with(|phase| phase.get());
            let reason = match error {
                Error::Deadline => 1,
                Error::DescriptorPolicy => 2,
                Error::NetworkOperation => 3,
                Error::OwnershipMismatch => 4,
                _ => 5,
            };
            let _ = net::send(
                &child_channel,
                &[
                    254,
                    phase,
                    reason,
                    NATIVE_SUBPHASE.with(|phase| phase.get()),
                ],
                SendFlags::DONTWAIT | SendFlags::NOSIGNAL,
            );
        }
        die(if result.is_ok() { 0 } else { 122 });
    }
    let reap = ParentReap::born(pid as u32);
    lease
        .native_job_mut()
        .born(NativeJobKind::RetirementCleanup, &reap);
    let mut result = CleanupChild {
        native: Some(CleanupNative {
            creator: std::process::id(),
            context,
            transport,
            target,
            pid: pid as u32,
            pidfd: pinned.expect("atomic constructor returns original parent pidfd"),
            reap,
            pid_inventory: None,
            channel,
            _channel_inventory: channel_inventory,
            _capacity: ChildCapacity::created(),
            _lease: lease,
            _timer: timer,
            _timer_inventory: timer_inventory,
            reaped: false,
            failed: false,
        }),
    };
    drop(child_inventory);
    drop(child_channel);
    // The complete native bundle is owned before the first fallible postclone
    // operation. Err drops into its own collector, preserving every original.
    let native = result.native()?;
    native.pid_inventory = Some(super::super::inventory::Registration::owned(&[native
        .pidfd
        .as_fd()])?);
    #[cfg(test)]
    if hold {
        // The exact original child is still behind its birth gate. Capture only
        // the held fixture's public start identity; no observed PID mints reap.
        if wait_ready(&native.pidfd, Duration::ZERO)? {
            return Err(Error::ChildFailed);
        }
        let bytes = read_fixed(&format!("/proc/{}/stat", native.pid), 65536)
            .map_err(|_| Error::ProcessUnavailable)?;
        let start = process::stat_start(
            std::str::from_utf8(&bytes).map_err(|_| Error::ProcessChanged)?,
            native.pid,
        )?;
        if wait_ready(&native.pidfd, Duration::ZERO)? {
            return Err(Error::ChildFailed);
        }
        native
            .reap
            .as_ref()
            .ok_or(Error::OwnershipMismatch)?
            .start
            .set(Some(start));
    }
    native.target.verify_parent()?;
    if !producer {
        native
            .transport
            .try_borrow()
            .map_err(|_| Error::LockBusy)?
            .cleanup_descriptors()?;
    }
    owner_admission_permitted()?;
    deadline(end)?;
    write_byte(&native.channel, 1)?;
    Ok(result)
}
pub(super) fn cleanup_filter(
    sockets: &[i32],
    target: &[i32],
    control: i32,
    producer: bool,
) -> Vec<libc::sock_filter> {
    let mut out = filter()[..4].to_vec();
    let mut socket_fds: Vec<u32> = sockets.iter().map(|fd| *fd as u32).collect();
    socket_fds.push(control as u32);
    for nr in [libc::SYS_sendto, libc::SYS_recvfrom] {
        allow_fixed_args(&mut out, nr, 0, &socket_fds);
    }
    let target_fds: Vec<u32> = target.iter().map(|fd| *fd as u32).collect();
    for nr in [libc::SYS_fstat, libc::SYS_fstatfs] {
        allow_fixed_args(&mut out, nr, 0, &target_fds);
    }
    allow_fixed_args(&mut out, libc::SYS_pread64, 0, &target_fds[2..]);
    allow_fixed_args(&mut out, libc::SYS_newfstatat, 0, &target_fds[..2]);
    if producer {
        out.extend(exact_args(
            libc::SYS_unlinkat,
            &[(0, target[0] as u64), (2, libc::AT_REMOVEDIR as u64)],
        ));
    }
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
    for nr in [
        libc::SYS_ppoll,
        libc::SYS_brk,
        libc::SYS_munmap,
        libc::SYS_madvise,
        libc::SYS_futex,
        libc::SYS_clock_gettime,
        libc::SYS_rt_sigreturn,
        libc::SYS_exit,
        libc::SYS_exit_group,
    ] {
        allow_syscall(&mut out, nr);
    }
    out.push(libc::sock_filter {
        code: 0x15,
        jt: 0,
        jf: 13,
        k: libc::SYS_mmap as u32,
    });
    for (offset, expected) in [
        (52, u32::MAX),
        (48, u32::MAX),
        (44, 0),
        (40, (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as u32),
    ] {
        out.extend([
            libc::sock_filter {
                code: 0x20,
                jt: 0,
                jf: 0,
                k: offset,
            },
            libc::sock_filter {
                code: 0x15,
                jt: 1,
                jf: 0,
                k: expected,
            },
            libc::sock_filter {
                code: 0x06,
                jt: 0,
                jf: 0,
                k: 0x00050001,
            },
        ]);
    }
    out.push(libc::sock_filter {
        code: 0x20,
        jt: 0,
        jf: 0,
        k: 0,
    });
    for nr in [libc::SYS_mmap, libc::SYS_mprotect] {
        out.extend([
            libc::sock_filter {
                code: 0x15,
                jt: 0,
                jf: 5,
                k: nr as u32,
            },
            libc::sock_filter {
                code: 0x20,
                jt: 0,
                jf: 0,
                k: 32,
            },
            libc::sock_filter {
                code: 0x45,
                jt: 0,
                jf: 1,
                k: !(libc::PROT_READ | libc::PROT_WRITE) as u32,
            },
            libc::sock_filter {
                code: 0x06,
                jt: 0,
                jf: 0,
                k: 0x00050001,
            },
            libc::sock_filter {
                code: 0x06,
                jt: 0,
                jf: 0,
                k: 0x7fff0000,
            },
            libc::sock_filter {
                code: 0x20,
                jt: 0,
                jf: 0,
                k: 0,
            },
        ]);
    }
    out.push(libc::sock_filter {
        code: 0x06,
        jt: 0,
        jf: 0,
        k: 0x00050001,
    });
    out
}

/// Real fixed-filter syscall/gate proof with only freshly created rootless files.
/// This does not claim cgroup authority or native network cleanup.
#[cfg(test)]
pub(super) fn lab_filter_selftest() -> Result<()> {
    for producer in [false, true] {
        let directory = std::env::temp_dir().join(format!(
            "vpr-cleanup-filter-{}-{}",
            std::process::id(),
            u8::from(producer)
        ));
        std::fs::create_dir(&directory).map_err(|_| Error::OwnershipMismatch)?;
        std::fs::create_dir(directory.join("owned")).map_err(|_| Error::OwnershipMismatch)?;
        std::fs::write(directory.join("public"), b"public-filter-fixture")
            .map_err(|_| Error::Interrupted)?;
        let parent = fs::open(
            &directory,
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| Error::OwnershipMismatch)?;
        let group = fs::openat(
            &parent,
            c"owned",
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| Error::OwnershipMismatch)?;
        let events = fs::openat(
            &parent,
            c"public",
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| Error::OwnershipMismatch)?;
        let procs =
            rustix::io::fcntl_dupfd_cloexec(&events, 3).map_err(|_| Error::DescriptorDuplicate)?;
        let (channel, child) = net::socketpair(
            net::AddressFamily::UNIX,
            net::SocketType::SEQPACKET,
            net::SocketFlags::CLOEXEC,
            None,
        )
        .map_err(|_| Error::DescriptorPolicy)?;
        let registrations = super::super::inventory::Registration::owned(&[
            parent.as_fd(),
            group.as_fd(),
            events.as_fd(),
            procs.as_fd(),
            channel.as_fd(),
            child.as_fd(),
        ])?;
        let target = [
            parent.as_raw_fd(),
            group.as_raw_fd(),
            events.as_raw_fd(),
            procs.as_raw_fd(),
        ];
        let (pid, pinned) = fork_with_pidfd()?;
        if pid == 0 {
            let result = (|| {
                let mut keep = target.to_vec();
                keep.push(child.as_raw_fd());
                close_except(&keep)?;
                cv(
                    unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) },
                    Error::CapabilityPolicy,
                )?;
                apply_filter(&cleanup_filter(&[], &target, child.as_raw_fd(), producer))?;
                let mut poll = [rustix::event::PollFd::new(
                    &child,
                    rustix::event::PollFlags::IN,
                )];
                if rustix::event::poll(
                    &mut poll,
                    Some(&rustix::event::Timespec {
                        tv_sec: 1,
                        tv_nsec: 0,
                    }),
                )
                .map_err(|_| Error::DescriptorPolicy)?
                    != 1
                {
                    return Err(Error::Deadline);
                }
                let mut byte = [0; 2];
                if net::recv(&child, &mut byte, RecvFlags::DONTWAIT | RecvFlags::TRUNC)
                    .map_err(|_| Error::DescriptorPolicy)?
                    != (1, 1)
                    || byte[0] != 1
                {
                    return Err(Error::DescriptorPolicy);
                }
                fs::fstat(&parent).map_err(|_| Error::DescriptorPolicy)?;
                fs::fstatfs(&group).map_err(|_| Error::DescriptorPolicy)?;
                fs::statat(&parent, c"owned", fs::AtFlags::SYMLINK_NOFOLLOW)
                    .map_err(|_| Error::DescriptorPolicy)?;
                let mut content = [0; 32];
                if rustix::io::pread(&events, &mut content, 0)
                    .map_err(|_| Error::DescriptorPolicy)?
                    != 21
                {
                    return Err(Error::DescriptorPolicy);
                }
                if fs::openat(&parent, c"public", OFlags::RDONLY, Mode::empty()).err()
                    != Some(rustix::io::Errno::PERM)
                {
                    return Err(Error::DescriptorPolicy);
                }
                if unsafe { libc::syscall(libc::SYS_clone3, std::ptr::null::<u8>(), 0) } != -1
                    || std::io::Error::last_os_error().raw_os_error() != Some(libc::EPERM)
                {
                    return Err(Error::DescriptorPolicy);
                }
                let removed = fs::unlinkat(&parent, c"owned", fs::AtFlags::REMOVEDIR);
                if producer {
                    removed.map_err(|_| Error::DescriptorPolicy)?;
                    if fs::statat(&parent, c"owned", fs::AtFlags::SYMLINK_NOFOLLOW).err()
                        != Some(rustix::io::Errno::NOENT)
                    {
                        return Err(Error::DescriptorPolicy);
                    }
                    fs::fstat(&group).map_err(|_| Error::DescriptorPolicy)?;
                } else if removed.err() != Some(rustix::io::Errno::PERM) {
                    return Err(Error::DescriptorPolicy);
                }
                if net::send(&child, &[128], SendFlags::DONTWAIT | SendFlags::NOSIGNAL)
                    .map_err(|_| Error::DescriptorPolicy)?
                    != 1
                {
                    return Err(Error::DescriptorPolicy);
                }
                Ok(())
            })();
            die(if result.is_ok() { 0 } else { 122 });
        }
        let pinned = pinned.ok_or(Error::ChildFailed)?;
        // Every original fixture/context remains owned until this exact child is reaped.
        let result = (|| {
            net::send(&channel, &[1], SendFlags::DONTWAIT | SendFlags::NOSIGNAL)
                .map_err(|_| Error::DescriptorPolicy)?;
            if !wait_ready(&pinned, Duration::from_secs(2))? {
                return Err(Error::Deadline);
            }
            let mut byte = [0; 2];
            if net::recv(&channel, &mut byte, RecvFlags::DONTWAIT | RecvFlags::TRUNC)
                .map_err(|_| Error::DescriptorPolicy)?
                != (1, 1)
                || byte[0] != 128
            {
                return Err(Error::ChildFailed);
            }
            Ok(())
        })();
        if result.is_err() {
            let _ = send_or_exited(pinned.as_fd(), libc::SIGKILL);
        }
        if !wait_ready(&pinned, Duration::from_secs(1))? {
            retain_fork_bundle(
                pid,
                pinned,
                channel,
                None,
                vec![registrations],
                vec![parent, group, events, procs, child],
                None,
            );
            return Err(Error::Deadline);
        }
        let mut status = 0;
        if unsafe { libc::waitpid(pid, &mut status, 0) } != pid {
            retain_fork_bundle(
                pid,
                pinned,
                channel,
                None,
                vec![registrations],
                vec![parent, group, events, procs, child],
                None,
            );
            return Err(Error::ChildFailed);
        }
        result?;
        if status != 0 {
            return Err(Error::ChildFailed);
        }
        drop(registrations);
        if !producer {
            std::fs::remove_dir(directory.join("owned")).map_err(|_| Error::Interrupted)?;
        }
        std::fs::remove_file(directory.join("public")).map_err(|_| Error::Interrupted)?;
        std::fs::remove_dir(directory).map_err(|_| Error::Interrupted)?;
        eprintln!(
            "LAB_RETIREMENT_CLEANUP_FILTER producer={producer} original_gate_ppoll=true native_stat_pread=true exact_unlink_policy=true no_fork_open=true actual_helper_exit0=true rootless_only=true"
        );
    }
    Ok(())
}
