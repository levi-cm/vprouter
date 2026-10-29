//! Fixed read-only persistent inspector. No callback, path, executable or peer
//! assertion crosses this boundary; only the closed command enum is accepted.
use super::super::inspection::{Failure, FailureKind, Inspector, Job, Policy, Receipt};
use super::*;
use rustix::net::{self, RecvFlags, SendFlags};
const FRAME: usize = 1024;
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
enum Notice {
    Receipt {
        receipt: Receipt,
    },
    Failure {
        failure: Failure,
    },
    #[cfg(test)]
    Checkpoint {
        sequence: u64,
        sent_at: f64,
    },
}
#[cfg(test)]
pub(crate) fn lab_failure_fits_frame(failure: &Failure) -> bool {
    serde_json::to_vec(&Notice::Failure {
        failure: failure.clone(),
    })
    .is_ok_and(|bytes| bytes.len() <= FRAME)
}
fn failure_diagnostic(stage: u8, reason: &str) {
    // Fixed enum-only errors. Malformed text never reaches diagnostics.
    if reason.len() <= 64 && reason.bytes().all(|b| b.is_ascii_lowercase() || b == b'_') {
        #[cfg(test)]
        eprintln!("LAB_INSPECTION_FAILURE stage={stage} reason={reason}");
    }
    #[cfg(not(test))]
    let _ = stage;
}
fn inspection_wait(channel: impl AsFd, duration: Duration) -> Result<bool> {
    let mut fds = [rustix::event::PollFd::new(
        &channel,
        rustix::event::PollFlags::IN,
    )];
    rustix::event::poll(
        &mut fds,
        Some(&rustix::event::Timespec::try_from(duration).map_err(|_| Error::Deadline)?),
    )
    .map(|n| n != 0)
    .map_err(|_| Error::DescriptorPolicy)
}

pub(crate) struct Actor {
    creator: u32,
    child: Option<Survivor>,
    identity: Option<super::super::daemon::Process>,
    channel: Option<OwnedFd>,
    _inventory: Option<super::super::inventory::Registration>,
    killed: bool,
    reaped: bool,
    failure: std::cell::RefCell<Option<Failure>>,
    #[cfg(test)]
    checkpoint: std::cell::Cell<Option<(u64, f64)>>,
    #[cfg(test)]
    stopped: bool,
}
fn send_frame<T: serde::Serialize>(channel: impl AsFd, value: &T) -> Result<()> {
    let bytes = serde_json::to_vec(value).map_err(|_| Error::DescriptorPolicy)?;
    if bytes.len() > FRAME
        || net::send(channel, &bytes, SendFlags::DONTWAIT | SendFlags::NOSIGNAL)
            .map_err(|_| Error::DescriptorPolicy)?
            != bytes.len()
    {
        return Err(Error::DescriptorPolicy);
    }
    Ok(())
}
fn receive_frame<T: serde::de::DeserializeOwned>(channel: impl AsFd) -> Result<Option<T>> {
    let mut bytes = [0; FRAME + 1];
    let (n, full) = match net::recv(channel, &mut bytes, RecvFlags::DONTWAIT | RecvFlags::TRUNC) {
        Err(rustix::io::Errno::AGAIN) => return Ok(None),
        result => result.map_err(|_| Error::DescriptorPolicy)?,
    };
    if n == 0 || n != full || n > FRAME {
        return Err(Error::DescriptorPolicy);
    }
    serde_json::from_slice(&bytes[..n])
        .map(Some)
        .map_err(|_| Error::DescriptorPolicy)
}
impl Actor {
    #[cfg(test)]
    pub(crate) fn lab_require_foreign_inert(&self) -> Result<()> {
        if self.creator == std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        self.child()?._inventory.lab_require_inert()?;
        self._inventory
            .as_ref()
            .ok_or(Error::DescriptorInventory)?
            .lab_require_inert()?;
        if net::send(self.channel()?, b"excluded", SendFlags::NOSIGNAL)
            != Err(rustix::io::Errno::NOTSOCK)
        {
            return Err(Error::DescriptorPolicy);
        }
        Ok(())
    }
    fn identity(&self) -> Result<&super::super::daemon::Process> {
        self.identity.as_ref().ok_or(Error::Interrupted)
    }
    fn child(&self) -> Result<&Survivor> {
        self.child.as_ref().ok_or(Error::Interrupted)
    }
    fn channel(&self) -> Result<&OwnedFd> {
        self.channel.as_ref().ok_or(Error::Interrupted)
    }

    fn live(&self) -> Result<()> {
        if self.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        if self.killed || self.reaped {
            return Err(Error::Interrupted);
        }
        self.child()?.require_live()?;
        self.identity()?.verify()
    }
    pub(crate) fn require_quiet(&self) -> Result<()> {
        self.live()?;
        // An unsolicited or duplicate frame revokes this actor; never consume it
        // as a later operation's completion.
        if wait_ready(self.channel()?, Duration::ZERO)? {
            return Err(Error::DescriptorPolicy);
        }
        Ok(())
    }
    pub(crate) fn send(&self, job: &Job) -> Result<()> {
        self.require_quiet()?;
        send_frame(self.channel()?, job)
    }
    pub(crate) fn receive(&self) -> Result<Option<Receipt>> {
        // A dead actor may leave a bounded failure notice, never an approval.
        let live = self.live();
        let receipt = match receive_frame::<Notice>(self.channel()?)? {
            None => {
                live?;
                return Ok(None);
            }
            Some(Notice::Receipt { receipt }) => {
                live?;
                Some(receipt)
            }
            Some(Notice::Failure { failure }) => {
                self.retain_failure(failure);
                return Err(Error::ChildFailed);
            }
            #[cfg(test)]
            Some(Notice::Checkpoint { sequence, sent_at }) => {
                live?;
                if self.checkpoint.replace(Some((sequence, sent_at))).is_some() {
                    return Err(Error::DescriptorPolicy);
                }
                return Ok(None);
            }
        };
        if receipt.is_some() {
            self.identity()?.inspector_role()?;
            self.live()?;
            if wait_ready(self.channel()?, Duration::ZERO)? {
                return Err(Error::DescriptorPolicy);
            }
        }
        Ok(receipt)
    }
    pub(crate) fn cancel(&mut self) -> Result<()> {
        if self.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        if !self.reaped && !self.killed {
            send_or_exited(self.child()?.pidfd(), libc::SIGKILL)?;
            self.killed = true;
        }
        Ok(())
    }
    pub(crate) fn drain(&mut self) -> Result<bool> {
        if self.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        if self.reaped {
            return Ok(true);
        }
        if self.child()?.reap_status()?.is_none() {
            return Ok(false);
        }
        self.reaped = true;
        // Post-exit diagnostics are never receipts or proof; actual reaping above
        // remains independent of malformed/absent failure output.
        if let Ok(Some(Notice::Failure { failure })) = receive_frame::<Notice>(self.channel()?) {
            self.retain_failure(failure);
        }
        #[cfg(test)]
        eprintln!(
            "LAB_INSPECTION_DRAIN pid={} start={} actual_reaped=true killed={}",
            self.child()?.pid(),
            self.identity()?.start(),
            self.killed
        );
        Ok(true)
    }
    fn retain_failure(&self, failure: Failure) {
        failure_diagnostic(failure.stage, &failure.reason);
        if self.failure.borrow().is_none() {
            *self.failure.borrow_mut() = Some(failure);
        }
    }
    #[cfg(test)]
    pub(crate) fn lab_current_creator(&self) -> bool {
        self.creator == std::process::id()
    }
    pub(crate) fn failure(&self) -> Option<Failure> {
        self.failure.borrow().clone()
    }
    pub(crate) fn drained(&self) -> bool {
        self.reaped
    }
    #[cfg(test)]
    pub(crate) fn lab_identity(&self) -> Result<(u32, u64)> {
        Ok((self.identity()?.pid(), self.identity()?.start()))
    }
    #[cfg(test)]
    pub(crate) fn lab_checkpoint(&mut self, job: &Job) -> Result<Option<(u32, u64, f64)>> {
        let Some((sequence, sent_at)) = self.checkpoint.get() else {
            return Ok(None);
        };
        if !job.hold || job.sequence != sequence || job.sent_at != sent_at {
            return Err(Error::DescriptorPolicy);
        }
        self.identity()?.inspector_role()?;
        let start = self.identity()?.start();
        if !self.stopped {
            self.child()?.lab_signal(libc::SIGSTOP)?;
            self.stopped = true;
            return Ok(None);
        }
        // One zero-wait observation per deployment turn; the original pending
        // request deadline still governs, and neighbors/expiry are serviced.
        if self.child()?.lab_require_stopped(start).is_err() {
            self.identity()?.verify()?;
            return Ok(None);
        }
        eprintln!(
            "LAB_INSPECTION_HELD pid={} start={start} sequence={sequence} original_sent_at={sent_at} original_deadline={}",
            self.child()?.pid(),
            sent_at + 2.
        );
        Ok(Some((self.child()?.pid(), start, sent_at + 2.)))
    }
}
impl Drop for Actor {
    fn drop(&mut self) {
        if self.creator != std::process::id() {
            return;
        }
        if !self.reaped
            && let (Some(child), Some(channel)) = (self.child.take(), self.channel.take())
        {
            let inventory = self._inventory.take().into_iter().collect();
            retain_survivor(child, channel, self.identity.take(), inventory, Vec::new());
        }
    }
}
pub(crate) fn spawn(policy: Policy<'_>, guard: &Survivor, incarnation: [u8; 32]) -> Result<Actor> {
    process::single_threaded()?;
    super::super::inventory::verify()?;
    guard.require_live()?;
    let guard_identity = super::super::daemon::Process::open(guard.pid())?;
    if guard_identity.start() != guard.start_time()? {
        return Err(Error::ProcessChanged);
    }
    guard.require_live()?;
    let (parent_socket, child_socket) = net::socketpair(
        net::AddressFamily::UNIX,
        net::SocketType::SEQPACKET,
        net::SocketFlags::CLOEXEC,
        None,
    )
    .map_err(|_| Error::DescriptorPolicy)?;
    let parent = std::process::id() as i32;
    let (pid, pinned) = fork_with_pidfd()?;
    if pid == 0 {
        let diagnostic_stage = std::cell::Cell::new(1u8);
        #[cfg(test)]
        let diagnostic_substage = std::cell::Cell::new(0u8);
        let failure_kind = std::cell::Cell::new(FailureKind::Rejected);
        let pending = std::cell::RefCell::new(None);
        let result: Result<()> = (|| {
            parent_death(parent)?;
            cv(unsafe { libc::clearenv() }, Error::ChildFailed)?;
            let null = std::mem::ManuallyDrop::new(
                fs::open(c"/dev/null", OFlags::RDWR | OFlags::CLOEXEC, Mode::empty())
                    .map_err(|_| Error::DescriptorNull)?,
            );
            for fd in 0..3 {
                dup_fixed(&*null, fd, false)?;
            }
            #[cfg(test)]
            let idle = rustix::event::eventfd(
                0,
                rustix::event::EventfdFlags::CLOEXEC | rustix::event::EventfdFlags::NONBLOCK,
            )
            .map_err(|_| Error::DescriptorPolicy)?;
            let mut fds = policy.fds();
            fds.extend(guard_identity.fds());
            fds.push(child_socket.as_fd());
            #[cfg(test)]
            fds.push(idle.as_fd());
            let keep: Vec<_> = fds.iter().map(AsRawFd::as_raw_fd).collect();
            diagnostic_stage.set(2);
            close_except(&keep)?;
            // Clear stale inherited RAII inventory only after exact kernel closure.
            let _inventory = super::super::inventory::inspection_role(&fds)?;
            diagnostic_stage.set(3);
            inspection_capabilities()?;
            parent_death(parent)?;
            diagnostic_stage.set(4);
            apply_filter(&inspection_filter(child_socket.as_raw_fd()))?;
            diagnostic_stage.set(5);
            #[cfg(test)]
            lab_filter(&idle, child_socket.as_raw_fd())?;
            let mut inspector = Inspector::new(policy, guard_identity, incarnation);
            loop {
                diagnostic_stage.set(10);
                #[cfg(test)]
                diagnostic_substage.set(0);
                *pending.borrow_mut() = None;
                failure_kind.set(FailureKind::Rejected);
                let Some(job) = receive_frame::<Job>(&child_socket)? else {
                    if !inspection_wait(&child_socket, Duration::from_secs(1))? {
                        continue;
                    }
                    continue;
                };
                *pending.borrow_mut() = Some(job.clone());
                #[cfg(test)]
                if job.hold {
                    send_frame(
                        &child_socket,
                        &Notice::Checkpoint {
                            sequence: job.sequence,
                            sent_at: job.sent_at,
                        },
                    )?;
                    // Private checkpoint has no resume command. Root freezes this
                    // exact actor, and original request expiry kills/reaps it.
                    loop {
                        inspection_wait(&child_socket, Duration::from_secs(1))?;
                    }
                }
                let receipt = inspector.execute(
                    job,
                    &diagnostic_stage,
                    &failure_kind,
                    #[cfg(test)]
                    &diagnostic_substage,
                )?;
                super::super::inspection::deadline(
                    receipt.job.sent_at,
                    vprouter_core::health::boot_seconds(),
                )?;
                send_frame(&child_socket, &Notice::Receipt { receipt })?;
            }
            #[allow(unreachable_code)]
            Ok::<(), Error>(())
        })();
        if let Err(error) = result {
            let _ = send_frame(
                &child_socket,
                &Notice::Failure {
                    failure: Failure {
                        job: pending.borrow().clone(),
                        stage: diagnostic_stage.get(),
                        #[cfg(test)]
                        substage: diagnostic_substage.get(),
                        reason: error.to_string(),
                        kind: failure_kind.get(),
                        finished_at: vprouter_core::health::boot_seconds(),
                    },
                },
            );
        }
        die(if result.is_ok() { 0 } else { 122 });
    }
    drop(child_socket);
    bind_actor(pid, pinned.ok_or(Error::ChildFailed)?, parent_socket)
}
fn bind_actor(pid: i32, pinned: OwnedFd, parent_socket: OwnedFd) -> Result<Actor> {
    let inventory = match super::super::inventory::Registration::owned(&[pinned.as_fd()]) {
        Ok(inventory) => inventory,
        Err(error) => {
            retain_early_fork(pid, pinned, parent_socket);
            return Err(error);
        }
    };
    let child = Survivor {
        pid: pid as u32,
        reap: ParentReap::born(pid as u32),
        pinned,
        _inventory: inventory,
    };
    let identity = match super::super::daemon::Process::open(pid as u32) {
        Ok(identity) => identity,
        Err(error) => {
            retain_survivor(child, parent_socket, None, Vec::new(), Vec::new());
            return Err(error);
        }
    };
    let mut fds = vec![parent_socket.as_fd()];
    fds.extend(identity.fds());
    let inventory = match super::super::inventory::Registration::owned(&fds) {
        Ok(inventory) => inventory,
        Err(error) => {
            retain_survivor(child, parent_socket, Some(identity), Vec::new(), Vec::new());
            return Err(error);
        }
    };
    #[cfg(test)]
    eprintln!(
        "LAB_INSPECTION_ACTOR pid={} start={} role=fixed_readonly_inspector private_post_guard_endpoint=true",
        child.pid(),
        identity.start()
    );
    Ok(Actor {
        creator: std::process::id(),
        child: Some(child),
        identity: Some(identity),
        channel: Some(parent_socket),
        _inventory: Some(inventory),
        killed: false,
        reaped: false,
        failure: std::cell::RefCell::new(None),
        #[cfg(test)]
        checkpoint: std::cell::Cell::new(None),
        #[cfg(test)]
        stopped: false,
    })
}
fn inspection_capabilities() -> Result<()> {
    // Read-only proc traversal uses DAC_READ_SEARCH and SYS_PTRACE. The filter
    // prohibits every ptrace/fd-steal/write primitive, including writable opens.
    cv(
        unsafe { libc::prctl(libc::PR_SET_SECUREBITS, 0xef, 0, 0, 0) },
        Error::CapabilityPolicy,
    )?;
    for cap in 0..64 {
        if unsafe { libc::prctl(libc::PR_CAPBSET_READ, cap, 0, 0, 0) } < 0 {
            break;
        }
        if !matches!(cap, 2 | 19) {
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
            effective: (1 << 2) | (1 << 19),
            permitted: (1 << 2) | (1 << 19),
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
    )?;
    cv(
        unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) },
        Error::CapabilityPolicy,
    )
}
fn allowed(out: &mut Vec<libc::sock_filter>, nr: libc::c_long) {
    out.extend([
        libc::sock_filter {
            code: 0x15,
            jt: 0,
            jf: 1,
            k: nr as u32,
        },
        libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0x7fff0000,
        },
    ]);
}
/// Scalar-only read opens; pointed open_how is never accepted. No generic output,
/// mutation, fd stealing, exec, namespace, socket, signal or tracing syscall.
pub(super) fn inspection_filter(channel: i32) -> Vec<libc::sock_filter> {
    let mut out = filter()[..4].to_vec();
    // Rust's native OwnedFd debug validity check is a getter, never duplication
    // or descriptor flag mutation. All other fcntl commands remain denied.
    out.extend(exact_args(libc::SYS_fcntl, &[(1, libc::F_GETFD as u64)]));
    out.extend(exact_args(
        libc::SYS_prctl,
        &[(0, libc::PR_GET_SECCOMP as u64)],
    ));
    out.extend(exact_args(
        libc::SYS_sendto,
        &[
            (0, channel as u64),
            (3, (libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL) as u64),
            (4, 0),
            (5, 0),
        ],
    ));
    out.extend(exact_args(
        libc::SYS_recvfrom,
        &[
            (0, channel as u64),
            (3, (libc::MSG_DONTWAIT | libc::MSG_TRUNC) as u64),
            (4, 0),
            (5, 0),
        ],
    ));
    let mask = libc::O_CLOEXEC
        | libc::O_NOFOLLOW
        | libc::O_DIRECTORY
        | libc::O_NONBLOCK
        | if cfg!(target_arch = "aarch64") {
            0x20000
        } else {
            0x8000
        };
    // openat flags must have zero upper bits and contain only read-only flags.
    out.extend([
        libc::sock_filter {
            code: 0x15,
            jt: 0,
            jf: 8,
            k: libc::SYS_openat as u32,
        },
        libc::sock_filter {
            code: 0x20,
            jt: 0,
            jf: 0,
            k: 36,
        },
        libc::sock_filter {
            code: 0x15,
            jt: 0,
            jf: 4,
            k: 0,
        },
        libc::sock_filter {
            code: 0x20,
            jt: 0,
            jf: 0,
            k: 32,
        },
        libc::sock_filter {
            code: 0x45,
            jt: 2,
            jf: 0,
            k: !mask as u32,
        },
        libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0x7fff0000,
        },
        libc::sock_filter {
            code: 0x05,
            jt: 0,
            jf: 0,
            k: 0,
        },
        libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0x00050001,
        },
        libc::sock_filter {
            code: 0x20,
            jt: 0,
            jf: 0,
            k: 0,
        },
    ]);
    // Anonymous/private heap only: no writable shared mapping of a retained file.
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
                code: 0x05,
                jt: 0,
                jf: 0,
                k: 1,
            },
            libc::sock_filter {
                code: 0x20,
                jt: 0,
                jf: 0,
                k: 0,
            },
        ]);
        // Restore syscall before the next rule, including the accepted branch.
        out.push(libc::sock_filter {
            code: 0x20,
            jt: 0,
            jf: 0,
            k: 0,
        });
    }
    out.extend(exact_args(
        libc::SYS_mmap,
        &[(3, (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as u64)],
    ));
    allowed(&mut out, libc::SYS_mprotect);
    for nr in [
        libc::SYS_read,
        libc::SYS_pread64,
        libc::SYS_close,
        libc::SYS_fstat,
        libc::SYS_fstatfs,
        libc::SYS_statx,
        libc::SYS_newfstatat,
        libc::SYS_lseek,
        libc::SYS_getdents64,
        libc::SYS_readlinkat,
        libc::SYS_pidfd_open,
        libc::SYS_ppoll,
        libc::SYS_brk,
        libc::SYS_munmap,
        libc::SYS_madvise,
        libc::SYS_futex,
        libc::SYS_clock_gettime,
        libc::SYS_getpid,
        libc::SYS_gettid,
        libc::SYS_rt_sigprocmask,
        libc::SYS_rt_sigreturn,
        libc::SYS_exit,
        libc::SYS_exit_group,
    ] {
        allowed(&mut out, nr);
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
fn lab_filter(idle: impl AsFd, channel: i32) -> Result<()> {
    let current = super::super::daemon::Process::open(std::process::id())?;
    current.verify()?;
    let _inventory = super::super::inventory::Registration::owned(&current.fds())?;
    if inspection_wait(&idle, Duration::from_millis(1))? {
        return Err(Error::DescriptorPolicy);
    }
    // Every operation uses a harmless fixed target. A wrongly allowed open is
    // closed and reported, never written or used as authority.
    let denied = |fd: i64| -> Result<()> {
        if fd >= 0 {
            unsafe {
                libc::close(fd as i32);
            }
            return Err(Error::DescriptorPolicy);
        }
        if std::io::Error::last_os_error().raw_os_error() != Some(libc::EPERM) {
            return Err(Error::DescriptorPolicy);
        }
        Ok(())
    };
    for flags in [
        libc::O_WRONLY,
        libc::O_RDWR,
        libc::O_RDONLY | libc::O_TRUNC,
        libc::O_RDONLY | libc::O_CREAT,
    ] {
        denied(unsafe {
            libc::syscall(
                libc::SYS_openat,
                libc::AT_FDCWD,
                c"/dev/null".as_ptr(),
                flags,
                0,
            )
        })?;
    }
    let how = [libc::O_RDONLY as u64, 0, 0];
    denied(unsafe {
        libc::syscall(
            libc::SYS_openat2,
            libc::AT_FDCWD,
            c"/dev/null".as_ptr(),
            how.as_ptr(),
            std::mem::size_of_val(&how),
        )
    })?;
    denied(unsafe { libc::syscall(libc::SYS_pidfd_getfd, -1, channel, 0) })?;
    denied(unsafe { libc::syscall(libc::SYS_socket, libc::AF_UNIX, libc::SOCK_STREAM, 0) })?;
    // Native callees must report via the fixed private Notice channel. Ordinary
    // stdio (including test-only timing/error logging) remains forbidden.
    for fd in [channel, libc::STDOUT_FILENO, libc::STDERR_FILENO] {
        denied(unsafe { libc::syscall(libc::SYS_write, fd, c"x".as_ptr(), 1) })?;
        let iov = libc::iovec {
            iov_base: c"x".as_ptr().cast_mut().cast(),
            iov_len: 1,
        };
        denied(unsafe { libc::syscall(libc::SYS_writev, fd, &iov, 1) })?;
    }
    if inspection_wait(&idle, Duration::from_millis(1))? {
        return Err(Error::DescriptorPolicy);
    }
    Ok(())
}

/// Unprivileged exact-filter cycle, run by the dedicated single-task lab binary.
#[cfg(test)]
pub(crate) fn lab_selftest() -> Result<()> {
    super::lab_owner_signal_poll()?;
    super::lab_child_drop_retention()?;
    super::lab_reap_error_isolation()?;
    super::lab_child_creator_isolation()?;
    super::lab_guard_private_boundary()?;
    super::super::owned::lab_journal_drop_retention()?;
    lab_filter_selftest()?;
    super::retirement::lab_filter_selftest()?;
    super::cleanup::lab_filter_selftest()?;
    super::secret::lab_filter_selftest()?;
    super::docker_query::lab_filter_selftest()?;
    super::namespace_attachment::lab_filter_selftest()?;
    super::wireguard_role::lab_filter_selftest()?;
    super::capacity_lab::failed_selftest()?;
    super::producer_creation::lab_filter_selftest()?;
    lab_retention_selftest()?;
    lab_metadata_measurement()?;
    super::super::daemon::lab_local_guard_inventory()?;
    super::lab_publisher_startup_retention()
}
#[cfg(test)]
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct MetadataMeasurement {
    fd_count: usize,
    iterations: u32,
    warmup_rounds: u32,
    samples_ns: [u64; 16],
}
#[cfg(test)]
fn lab_metadata_measurement() -> Result<()> {
    use super::super::inventory;
    process::single_threaded()?;
    inventory::verify()?;
    let (read, write) = pipe()?;
    let (socket_a, socket_b) = net::socketpair(
        net::AddressFamily::UNIX,
        net::SocketType::SEQPACKET,
        net::SocketFlags::CLOEXEC,
        None,
    )
    .map_err(|_| Error::DescriptorPolicy)?;
    let mut fixtures = vec![
        fs::openat(
            fs::CWD,
            "/",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| Error::DescriptorPolicy)?,
        fs::memfd_create(c"vprouter-metadata-pair", fs::MemfdFlags::CLOEXEC)
            .map_err(|_| Error::DescriptorPolicy)?,
        read,
        write,
        socket_a,
        socket_b,
        rustix::event::eventfd(0, rustix::event::EventfdFlags::CLOEXEC)
            .map_err(|_| Error::DescriptorPolicy)?,
        pidfd(std::process::id() as i32)?,
        fs::openat(
            fs::CWD,
            "/proc/self",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| Error::DescriptorPolicy)?,
        network()?,
        fs::openat(
            fs::CWD,
            "/dev/null",
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| Error::DescriptorPolicy)?,
    ];
    let half = fixtures.len();
    for index in 0..half {
        fixtures.push(
            rustix::io::fcntl_dupfd_cloexec(&fixtures[index], 3)
                .map_err(|_| Error::DescriptorDuplicate)?,
        );
    }
    let fixture_inventory =
        inventory::Registration::owned(&fixtures.iter().map(AsFd::as_fd).collect::<Vec<_>>())?;
    inventory::lab_metadata_drift(&fixtures, &fixture_inventory)?;
    // Keep an ordinary slot occupied through endpoint allocation and atomic
    // fork. No assumption about a high RLIMIT_NOFILE is needed. Each process
    // drops its exact owner before checking the now-closed slot; later fdinfo
    // temporaries may reuse it but close again before the negative check.
    let closed =
        rustix::io::fcntl_dupfd_cloexec(&fixtures[0], 3).map_err(|_| Error::DescriptorDuplicate)?;
    let closed_number = closed.as_raw_fd();
    let closed_inventory = inventory::Registration::owned(&[closed.as_fd()])?;
    let numbers: Vec<_> = fixtures.iter().map(AsRawFd::as_raw_fd).collect();
    let (parent, child) = net::socketpair(
        net::AddressFamily::UNIX,
        net::SocketType::SEQPACKET,
        net::SocketFlags::CLOEXEC,
        None,
    )
    .map_err(|_| Error::DescriptorPolicy)?;
    let parent_inventory = inventory::Registration::owned(&[parent.as_fd()])?;
    let child_inventory = inventory::Registration::owned(&[child.as_fd()])?;
    let creator = std::process::id() as i32;
    let (pid, pinned) = fork_with_pidfd()?;
    if pid == 0 {
        drop(closed_inventory);
        drop(closed);
        let result: Result<()> = (|| {
            parent_death(creator)?;
            // Flag mutation is outside the installed fixed inspector filter.
            for fd in &fixtures[half..] {
                rustix::io::fcntl_setfd(fd, rustix::io::FdFlags::empty())
                    .map_err(|_| Error::DescriptorPolicy)?;
            }
            let mut keep = numbers.clone();
            keep.push(child.as_raw_fd());
            close_except(&keep)?;
            cv(
                unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) },
                Error::CapabilityPolicy,
            )?;
            apply_filter(&inspection_filter(child.as_raw_fd()))?;
            inventory::lab_metadata_equal(&numbers, closed_number)?;
            let expected = inventory::lab_metadata_sample(&numbers, false)?;
            for _ in 0..4 {
                for direct in [false, true] {
                    if inventory::lab_metadata_sample(&numbers, direct)? != expected {
                        return Err(Error::DescriptorPolicy);
                    }
                }
            }
            let mut samples_ns = [0; 16];
            for (sample, slot) in samples_ns.iter_mut().enumerate() {
                let direct = matches!(sample % 4, 1 | 2);
                let started = Instant::now();
                for _ in 0..16 {
                    if inventory::lab_metadata_sample(&numbers, direct)? != expected {
                        return Err(Error::DescriptorPolicy);
                    }
                }
                *slot = u64::try_from(started.elapsed().as_nanos()).map_err(|_| Error::TooLarge)?;
            }
            inventory::lab_metadata_equal(&numbers, closed_number)?;
            send_frame(
                &child,
                &MetadataMeasurement {
                    fd_count: numbers.len(),
                    iterations: 16,
                    warmup_rounds: 4,
                    samples_ns,
                },
            )
        })();
        die(if result.is_ok() { 0 } else { 122 });
    }
    drop(closed_inventory);
    drop(closed);
    drop(child_inventory);
    drop(child);
    let pinned = pinned.ok_or(Error::ChildFailed)?;
    let pinned_inventory = match inventory::Registration::owned(&[pinned.as_fd()]) {
        Ok(value) => value,
        Err(error) => {
            retain_registered_fork_with_pins(
                pid,
                pinned,
                parent,
                None,
                vec![fixture_inventory, parent_inventory],
                fixtures,
            );
            return Err(error);
        }
    };
    let result: Result<MetadataMeasurement> = (|| {
        if !wait_ready(&parent, Duration::from_secs(10))? {
            return Err(Error::Deadline);
        }
        receive_frame(&parent)?.ok_or(Error::DescriptorPolicy)
    })();
    if result.is_err() {
        let _ = send_or_exited(pinned.as_fd(), libc::SIGKILL);
    }
    let exited = wait_ready(&pinned, Duration::from_secs(2));
    if !matches!(exited, Ok(true)) {
        retain_registered_fork_with_pins(
            pid,
            pinned,
            parent,
            None,
            vec![fixture_inventory, parent_inventory, pinned_inventory],
            fixtures,
        );
        return Err(exited.err().unwrap_or(Error::Deadline));
    }
    let mut status = 0;
    if unsafe { libc::waitpid(pid, &mut status, 0) } != pid {
        retain_registered_fork_with_pins(
            pid,
            pinned,
            parent,
            None,
            vec![fixture_inventory, parent_inventory, pinned_inventory],
            fixtures,
        );
        return Err(Error::ChildFailed);
    }
    if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
        return Err(Error::ChildFailed);
    }
    let measurement = result?;
    if measurement.fd_count != fixtures.len()
        || measurement.iterations != 16
        || measurement.warmup_rounds != 4
        || measurement.samples_ns.contains(&0)
    {
        return Err(Error::DescriptorPolicy);
    }
    inventory::verify()?;
    let observations = measurement.fd_count as u64 * 16 * 8;
    println!(
        "LAB_METADATA_PAIR {}",
        serde_json::json!({
            "fd_count":measurement.fd_count,"iterations":16,"warmup_rounds":4,
            "order":"ABBA_ABBA_ABBA_ABBA","a":"statat_fdinfo","b":"statat_getfd",
            "samples_ns":measurement.samples_ns,"timed_observations_per_path":observations,
            "timed_statat_calls_per_path":observations,"timed_a_fdinfo_opens":observations,
            "timed_a_read_calls_lower_bound":observations,"timed_a_fdinfo_closes":observations,
            "timed_b_fcntl_getfd_calls":observations,"both_cloexec_states_equal":true,
            "closed_fd_rejected":true,"registered_flag_drift_rejected":true,
            "unchanged_inspector_filter":true,"actual_waitpid_exit0":true,
            "production_path_unchanged":false,"production_path":"statat_getfd"
        })
    );
    Ok(())
}
#[cfg(test)]
fn lab_filter_selftest() -> Result<()> {
    process::single_threaded()?;
    let (parent, child) = net::socketpair(
        net::AddressFamily::UNIX,
        net::SocketType::SEQPACKET,
        net::SocketFlags::CLOEXEC,
        None,
    )
    .map_err(|_| Error::DescriptorPolicy)?;
    let idle = rustix::event::eventfd(
        0,
        rustix::event::EventfdFlags::CLOEXEC | rustix::event::EventfdFlags::NONBLOCK,
    )
    .map_err(|_| Error::DescriptorPolicy)?;
    let (pid, pinned) = fork_with_pidfd()?;
    if pid == 0 {
        let result: Result<()> = (|| {
            close_except(&[child.as_raw_fd(), idle.as_raw_fd()])?;
            cv(
                unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) },
                Error::CapabilityPolicy,
            )?;
            apply_filter(&inspection_filter(child.as_raw_fd()))?;
            lab_filter(&idle, child.as_raw_fd())?;
            for _ in 0..2 {
                loop {
                    if let Some(value) = receive_frame::<Receipt>(&child)? {
                        send_frame(&child, &value)?;
                        break;
                    }
                    inspection_wait(&child, Duration::from_millis(50))?;
                }
                lab_filter(&idle, child.as_raw_fd())?;
            }
            Ok(())
        })();
        die(if result.is_ok() { 0 } else { 122 });
    }
    drop(child);
    drop(idle);
    let pinned = pinned.ok_or(Error::ChildFailed)?;
    let result: Result<()> = (|| {
        for sequence in 1..=2 {
            std::thread::sleep(Duration::from_millis(25));
            let receipt = super::super::inspection::lab_receipt(sequence);
            send_frame(&parent, &receipt)?;
            if !wait_ready(&parent, Duration::from_secs(1))? {
                return Err(Error::Deadline);
            }
            if receive_frame::<Receipt>(&parent)? != Some(receipt) {
                return Err(Error::DescriptorPolicy);
            }
        }
        if !wait_ready(&pinned, Duration::from_secs(1))? {
            return Err(Error::Deadline);
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = send_or_exited(pinned.as_fd(), libc::SIGKILL);
    }
    if !wait_ready(&pinned, Duration::from_secs(1))? {
        retain_early_fork(pid, pinned, parent);
        return Err(Error::Deadline);
    }
    let mut status = 0;
    if unsafe { libc::waitpid(pid, &mut status, 0) } != pid
        || !libc::WIFEXITED(status)
        || libc::WEXITSTATUS(status) != 0
    {
        return Err(Error::ChildFailed);
    }
    result
}

/// Actual persistent inspector actor used to exercise its custom Drop across a
/// later guard fork. This uses the fixed native inspector filter, not a mock FD.
#[cfg(test)]
pub(super) fn lab_idle_actor() -> Result<Actor> {
    let (parent, child) = net::socketpair(
        net::AddressFamily::UNIX,
        net::SocketType::SEQPACKET,
        net::SocketFlags::CLOEXEC,
        None,
    )
    .map_err(|_| Error::DescriptorPolicy)?;
    let creator = std::process::id() as i32;
    let (pid, pinned) = fork_with_pidfd()?;
    if pid == 0 {
        // Same fixed idle inspector role; only parent can retire it.
        let result: Result<()> = (|| {
            parent_death(creator)?;
            close_except(&[child.as_raw_fd()])?;
            cv(
                unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) },
                Error::CapabilityPolicy,
            )?;
            apply_filter(&inspection_filter(child.as_raw_fd()))?;
            loop {
                inspection_wait(&child, Duration::from_secs(1))?;
            }
        })();
        die(if result.is_ok() { 0 } else { 122 });
    }
    drop(child);
    bind_actor(pid, pinned.ok_or(Error::ChildFailed)?, parent)
}

/// Real atomic-fork actor, complete registration transfer, native waitpid reap,
/// then reuse of released descriptor slots. No harness-global descriptor mocks.
#[cfg(test)]
fn lab_retention_selftest() -> Result<()> {
    use super::super::inventory;
    process::single_threaded()?;
    inventory::verify()?;
    if !early_forks_drained() {
        return Err(Error::Interrupted);
    }
    let actor = lab_idle_actor()?;
    let pid = actor.child()?.pid() as i32;
    let (_, start) = actor.lab_identity()?;
    let reused_number = actor.channel()?.as_raw_fd();
    let reap_witness = actor.child()?.lab_clone_native()?;
    let observed_pin = actor
        .child()?
        .pinned
        .try_clone()
        .map_err(|_| Error::DescriptorDuplicate)?;
    let observed_inventory = inventory::Registration::owned(&[observed_pin.as_fd()])?;
    let observed = Survivor {
        pid: pid as u32,
        pinned: observed_pin,
        _inventory: observed_inventory,
        reap: None,
    };
    if observed.reap_status() != Err(Error::OwnershipMismatch) {
        return Err(Error::OwnershipMismatch);
    }
    drop(observed);
    inventory::verify()?;
    drop(actor);
    if early_forks_drained()
        || lab_early_reap((pid as u32, start))?.is_some()
        || lab_early_reap((pid as u32, start + 1)) != Err(Error::OwnershipMismatch)
    {
        return Err(Error::ChildFailed);
    }
    // Original124 failure: socket/pidfd still open while their tokens were gone.
    inventory::verify()?;
    let end = std::time::Instant::now() + Duration::from_secs(2);
    // A legitimate same-parent clone reaps first. The transferred original
    // must consume that exact receipt, not lose its bundle to ECHILD or infer
    // reaping from pidfd readability. Observed handles cannot do this above.
    while reap_witness.reap_status()?.is_none() {
        if std::time::Instant::now() >= end {
            return Err(Error::Deadline);
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    if early_forks_drained() {
        return Err(Error::ChildFailed);
    }
    while !early_forks_drained() {
        poll_early_forks()?;
        if std::time::Instant::now() >= end {
            return Err(Error::Deadline);
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    inventory::verify()?;
    let status = lab_early_reap((pid as u32, start))?.ok_or(Error::ChildFailed)?;
    if !libc::WIFSIGNALED(status) || libc::WTERMSIG(status) != libc::SIGKILL {
        return Err(Error::ChildFailed);
    }
    // Further admission/collector turns must not erase this exact receipt.
    poll_early_forks()?;
    if lab_early_reap((pid as u32, start))? != Some(status) {
        return Err(Error::ChildFailed);
    }
    if reap_witness.reap_status()? != Some(status) {
        return Err(Error::ChildFailed);
    }
    drop(reap_witness);
    if super::super::daemon::Process::open(pid as u32).is_ok_and(|p| p.start() == start) {
        return Err(Error::ChildFailed);
    }
    let reuse = rustix::event::eventfd(0, rustix::event::EventfdFlags::CLOEXEC)
        .map_err(|_| Error::DescriptorPolicy)?;
    // Lowest released slot was the parent endpoint; the fixed single-task
    // selftest opens no descriptor in between. Prove exact numeric reuse too.
    if reuse.as_raw_fd() != reused_number {
        return Err(Error::DescriptorPolicy);
    }
    let registration = inventory::Registration::owned(&[reuse.as_fd()])?;
    inventory::verify()?;
    drop(registration);
    drop(reuse);
    inventory::verify()
}
