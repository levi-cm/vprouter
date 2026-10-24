//! The ONLY unsafe module. No public API, raw descriptors or arbitrary exec.
//!
//! Safety contracts: each fork/namespace operation requires verified one-task
//! execution and no live async runtime. All passed FDs borrow owned admission
//! handles, outlive setup, and are never closed through those owners. Children
//! terminate with _exit after any setup/FD error; they never unwind into owners
//! whose descriptors were closed. All C pointers below borrow live fixed strings
//! or initialized buffers across synchronous syscalls only. No signal handlers
//! access Rust state: blocked signals are synchronously consumed by PID1.
use super::{Error, Result, process};
use rustix::fs::{self, Mode, OFlags};
use std::{
    ffi::{CStr, CString},
    os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd},
    time::{Duration, Instant},
};
// ---- Fixed diagnostics and checked syscall primitives ----
fn cv(r: i32, e: Error) -> Result<()> {
    if r < 0 { Err(e) } else { Ok(()) }
}
fn c(s: &str) -> Result<CString> {
    CString::new(s).map_err(|_| Error::MountIsolation)
}
fn fdpath(fd: impl AsFd) -> Result<CString> {
    c(&format!("/proc/self/fd/{}", fd.as_fd().as_raw_fd()))
}
fn stage_byte(e: Error) -> u8 {
    match e {
        Error::NamespaceOperation => 201,
        Error::MountIsolation => 202,
        Error::MountContainerRoot => 210,
        Error::MountPrivate => 211,
        Error::MountTmp => 212,
        Error::MountExecutable => 213,
        Error::MountExecutableClone => 220,
        Error::MountStateClone => 221,
        Error::MountExecutableBind => 218,
        Error::MountExecutableReadonly => 219,
        Error::MountState => 214,
        Error::MountPivot => 215,
        Error::MountProc => 216,
        Error::MountReadonly => 217,
        Error::DescriptorPolicy => 203,
        Error::DescriptorNull => 230,
        Error::DescriptorDuplicate => 231,
        Error::DescriptorClose => 232,
        Error::DescriptorFlags => 233,
        Error::DescriptorStdio => 234,
        Error::DescriptorHealth => 235,
        Error::DescriptorExecutable => 236,
        Error::DescriptorInventory => 237,
        Error::DescriptorReadlink => 238,
        Error::DescriptorScanOpen => 239,
        Error::DescriptorScanDenied => 240,
        Error::DescriptorScanCount => 241,
        Error::WaitLsmTransition => 242,
        Error::WaitLsmRead => 243,
        Error::WaitLsmLabel => 244,
        Error::WaitFilter => 245,
        Error::ProbeProcHiddenInit => 246,
        Error::ProbeProcSet => 247,
        Error::ProbeProcRoot => 248,
        Error::ProbeResolver => 249,
        Error::ProbeStateWrite => 250,
        Error::ProbeReadonly => 251,
        Error::ProbeForbiddenRoot => 252,
        Error::CapabilityPolicy => 204,
        Error::ConfinementPolicy => 205,
        _ => 206,
    }
}
fn report_failure(fd: impl AsFd, e: Error) {
    let _ = write_byte(fd, stage_byte(e));
}
fn die(code: i32) -> ! {
    // SAFETY: terminates only current child, never Rust unwinding.
    unsafe { libc::_exit(code) }
}
fn enter(fd: BorrowedFd<'_>, kind: i32) -> Result<()> {
    process::single_threaded()?;
    use rustix::thread::LinkNameSpaceType as T;
    let t = match kind {
        libc::CLONE_NEWNET => T::Network,
        libc::CLONE_NEWNS => T::Mount,
        libc::CLONE_NEWPID => T::ProcessID,
        libc::CLONE_NEWIPC => T::InterProcessCommunication,
        libc::CLONE_NEWUTS => T::HostNameAndNISDomainName,
        libc::CLONE_NEWCGROUP => T::ControlGroup,
        _ => return Err(Error::NamespaceOperation),
    };
    rustix::thread::move_into_link_name_space(fd, Some(t)).map_err(|_| Error::NamespaceOperation)
}
// ---- Owned network namespace entry and exclusive pinning ----
fn unshare(flags: i32) -> Result<()> {
    process::single_threaded()?; // SAFETY: dedicated one-task helper, no async runtime or shared descriptor owners in another thread.
    cv(unsafe { libc::unshare(flags) }, Error::NamespaceOperation)
}
fn network() -> Result<OwnedFd> {
    fs::open(
        "/proc/thread-self/ns/net",
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| Error::NamespaceMismatch)
}
pub(super) fn direct_network(handle: impl AsFd) -> Result<OwnedFd> {
    process::single_threaded()?;
    let old = network()?;
    enter(handle.as_fd(), libc::CLONE_NEWNET)?;
    let result = network();
    if enter(old.as_fd(), libc::CLONE_NEWNET).is_err() {
        die(122);
    }
    let fd = result?;
    if super::owned::Identity::network(&fd)? != super::owned::Identity::network(handle)? {
        return Err(Error::NamespaceMismatch);
    }
    Ok(fd)
}
pub(super) fn pin_network(target: impl AsFd, source: Option<BorrowedFd<'_>>) -> Result<()> {
    process::single_threaded()?;
    let old = network()?;
    let result = (|| {
        match source {
            Some(s) => enter(s, libc::CLONE_NEWNET)?,
            None => unshare(libc::CLONE_NEWNET)?,
        };
        let new = network()?;
        let a = fdpath(&new)?;
        let b = fdpath(target.as_fd())?;
        // SAFETY: fixed proc-fd paths resolve retained owned FDs; target was O_EXCL
        // created inside the locked root0700 ownership directory.
        cv(
            unsafe {
                libc::mount(
                    a.as_ptr(),
                    b.as_ptr(),
                    std::ptr::null(),
                    libc::MS_BIND,
                    std::ptr::null(),
                )
            },
            Error::NamespaceOperation,
        )
    })();
    if enter(old.as_fd(), libc::CLONE_NEWNET).is_err() {
        die(122);
    }
    result
}
pub(super) struct ContainerFds<'a> {
    pub mount: BorrowedFd<'a>,
    pub pid: BorrowedFd<'a>,
    pub network: BorrowedFd<'a>,
    pub ipc: BorrowedFd<'a>,
    pub uts: BorrowedFd<'a>,
    pub cgroup_ns: BorrowedFd<'a>,
    pub root: BorrowedFd<'a>,
    pub executable: BorrowedFd<'a>,
}
// ---- Gated child ownership, readiness and parent-death lifecycle ----
fn pipe() -> Result<(OwnedFd, OwnedFd)> {
    let mut fds = [-1; 2]; // SAFETY: two initialized integers, ownership transferred once on successful pipe2.
    cv(
        unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) },
        Error::DescriptorPolicy,
    )?;
    // SAFETY: successful pipe2 returns two distinct new descriptors.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}
fn pidfd(pid: i32) -> Result<OwnedFd> {
    // SAFETY: scalar syscall; success creates one owned pidfd.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if fd < 0 {
        return Err(Error::ChildFailed);
    } // SAFETY: nonnegative new pidfd, transferred exactly once.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
}
fn send(fd: impl AsFd, sig: i32) -> Result<()> {
    // SAFETY: scalar pidfd_send_signal, no user siginfo pointer, never PID-number signaling outside private PID namespace.
    cv(
        unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                fd.as_fd().as_raw_fd(),
                sig,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            ) as i32
        },
        Error::ChildFailed,
    )
}
fn wait_ready(fd: impl AsFd, timeout: Duration) -> Result<bool> {
    let mut p = libc::pollfd {
        fd: fd.as_fd().as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    }; // SAFETY: one initialized pollfd, bounded timeout.
    let r = unsafe { libc::poll(&mut p, 1, timeout.as_millis().min(i32::MAX as u128) as i32) };
    if r < 0 {
        return Err(Error::ChildFailed);
    }
    if p.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
        return Err(Error::ChildFailed);
    }
    Ok(r > 0)
}
fn write_byte(fd: impl AsFd, byte: u8) -> Result<()> {
    // SAFETY: one-byte live buffer; no raw external payload emitted.
    if unsafe { libc::write(fd.as_fd().as_raw_fd(), (&byte as *const u8).cast(), 1) } != 1 {
        return Err(Error::ChildFailed);
    }
    Ok(())
}
fn read_byte(fd: impl AsFd) -> Result<u8> {
    let mut byte = 0; // SAFETY: initialized one-byte writable buffer.
    if unsafe { libc::read(fd.as_fd().as_raw_fd(), (&mut byte as *mut u8).cast(), 1) } != 1 {
        return Err(Error::ChildFailed);
    }
    Ok(byte)
}
pub(super) struct Child {
    pid: u32,
    pidfd: OwnedFd,
    release: Option<OwnedFd>,
    health: OwnedFd,
    _inventory: super::inventory::Registration,
    release_inventory: Option<super::inventory::Registration>,
    reaped: bool,
}
impl Child {
    pub fn pid(&self) -> u32 {
        self.pid
    }
    pub fn release(&mut self) -> Result<()> {
        let f = self.release.take().ok_or(Error::ChildFailed)?;
        drop(self.release_inventory.take());
        write_byte(&f, 1)
    }
    pub fn ready(&mut self) -> Result<()> {
        let end = Instant::now() + Duration::from_secs(5);
        let mut worker = false;
        let mut init = false;
        let mut outer = false;
        let mut intermediate = false;
        while !worker || !init || !outer || !intermediate {
            let remaining = end.saturating_duration_since(Instant::now());
            if remaining.is_zero() || !wait_ready(&self.health, remaining)? {
                return Err(Error::Deadline);
            }
            match read_byte(&self.health)? {
                1 => worker = true,
                2 => init = true,
                4 => outer = true,
                8 => intermediate = true,
                253 => {
                    let role = read_byte(&self.health)?;
                    let stage = read_byte(&self.health)?;
                    let error = match stage {
                        201 => Error::NamespaceOperation,
                        204 => Error::CapabilityPolicy,
                        211 => Error::MountPrivate,
                        212 => Error::MountTmp,
                        215 => Error::MountPivot,
                        217 => Error::MountReadonly,
                        242 => Error::WaitLsmTransition,
                        243 => Error::WaitLsmRead,
                        244 => Error::WaitLsmLabel,
                        245 => Error::WaitFilter,
                        _ => Error::ChildFailed,
                    };
                    #[cfg(test)]
                    eprintln!(
                        "LAB_WAIT_ROLE {} {error}",
                        match role {
                            4 => "outer",
                            8 => "intermediate",
                            _ => "invalid",
                        }
                    );
                    #[cfg(not(test))]
                    let _ = role;
                    return Err(error);
                }
                254 => {
                    let role = read_byte(&self.health)?;
                    let field = read_byte(&self.health)?;
                    #[cfg(test)]
                    eprintln!(
                        "LAB_CREDENTIAL_ROLE {} {}",
                        match role {
                            4 => "outer",
                            8 => "intermediate",
                            16 => "init",
                            32 => "worker_before_exec",
                            64 => "probe_after_exec",
                            _ => "invalid",
                        },
                        match field {
                            0 => "uid",
                            1 => "gid",
                            2 => "groups",
                            3 => "nnp_status",
                            4 => "cap_inh",
                            5 => "cap_prm",
                            6 => "cap_eff",
                            7 => "cap_bnd",
                            8 => "cap_amb",
                            9 => "nnp_query",
                            10 => "securebits_query",
                            11 => "status_read",
                            12 => "status_utf8",
                            13 => "status_denied",
                            14 => "status_missing",
                            _ => "invalid",
                        }
                    );
                    #[cfg(not(test))]
                    let _ = (role, field);
                    return Err(Error::CapabilityPolicy);
                }
                201 => return Err(Error::NamespaceOperation),
                202 => return Err(Error::MountIsolation),
                203 => return Err(Error::DescriptorPolicy),
                230 => return Err(Error::DescriptorNull),
                231 => return Err(Error::DescriptorDuplicate),
                232 => return Err(Error::DescriptorClose),
                233 => return Err(Error::DescriptorFlags),
                234 => return Err(Error::DescriptorStdio),
                235 => return Err(Error::DescriptorHealth),
                236 => return Err(Error::DescriptorExecutable),
                237 => return Err(Error::DescriptorInventory),
                238 => return Err(Error::DescriptorReadlink),
                239 => return Err(Error::DescriptorScanOpen),
                240 => return Err(Error::DescriptorScanDenied),
                241 => return Err(Error::DescriptorScanCount),
                242 => return Err(Error::WaitLsmTransition),
                243 => return Err(Error::WaitLsmRead),
                244 => return Err(Error::WaitLsmLabel),
                245 => return Err(Error::WaitFilter),
                246 => return Err(Error::ProbeProcHiddenInit),
                247 => return Err(Error::ProbeProcSet),
                248 => return Err(Error::ProbeProcRoot),
                249 => return Err(Error::ProbeResolver),
                250 => return Err(Error::ProbeStateWrite),
                251 => return Err(Error::ProbeReadonly),
                252 => return Err(Error::ProbeForbiddenRoot),
                204 => return Err(Error::CapabilityPolicy),
                205 => return Err(Error::ConfinementPolicy),
                210 => return Err(Error::MountContainerRoot),
                211 => return Err(Error::MountPrivate),
                212 => return Err(Error::MountTmp),
                213 => return Err(Error::MountExecutable),
                214 => return Err(Error::MountState),
                215 => return Err(Error::MountPivot),
                216 => return Err(Error::MountProc),
                217 => return Err(Error::MountReadonly),
                218 => return Err(Error::MountExecutableBind),
                219 => return Err(Error::MountExecutableReadonly),
                220 => return Err(Error::MountExecutableClone),
                221 => return Err(Error::MountStateClone),
                _ => return Err(Error::ChildFailed),
            }
        }
        Ok(())
    }
    pub fn signal(&self, sig: i32) -> Result<()> {
        send(&self.pidfd, sig)
    }
    #[cfg(test)]
    pub fn try_wait_success(&mut self) -> Result<bool> {
        if self.reaped {
            return Ok(true);
        }
        if !wait_ready(&self.pidfd, Duration::ZERO)? {
            return Ok(false);
        }
        let mut status = 0;
        // SAFETY: exact unreaped direct child, with identity retained by pidfd.
        if unsafe { libc::waitpid(self.pid as i32, &mut status, 0) } != self.pid as i32 {
            return Err(Error::ChildFailed);
        }
        self.reaped = true;
        if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 {
            Ok(true)
        } else {
            Err(Error::ChildFailed)
        }
    }
    #[cfg(test)]
    pub fn kill_gated(&mut self) -> Result<()> {
        send(&self.pidfd, libc::SIGKILL)?;
        // Leave the dead child unreaped until normal failed-placement cleanup;
        // its numeric PID cannot be reused before the cgroup write is attempted.
        if wait_ready(&self.pidfd, Duration::from_secs(3))? {
            Ok(())
        } else {
            Err(Error::Deadline)
        }
    }
    fn reap(&mut self) -> Result<()> {
        if self.reaped {
            return Ok(());
        }
        if !wait_ready(&self.pidfd, Duration::from_secs(3))? {
            return Err(Error::Deadline);
        }
        let mut status = 0; // SAFETY: child remains our unreaped direct child; pidfd pins its identity until waitpid.
        if unsafe { libc::waitpid(self.pid as i32, &mut status, 0) } != self.pid as i32 {
            return Err(Error::ChildFailed);
        }
        self.reaped = true;
        Ok(())
    }
    pub fn terminate(mut self) -> Result<()> {
        let _ = send(&self.pidfd, libc::SIGKILL);
        self.reap()
    }
}
impl Drop for Child {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = send(&self.pidfd, libc::SIGKILL);
            let _ = self.reap();
        }
    }
}
fn parent_death(expected: i32) -> Result<()> {
    // SAFETY: scalar prctl and getppid; parent PID checked immediately after installing death signal to close setup race.
    cv(
        unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) },
        Error::ChildFailed,
    )?;
    if unsafe { libc::getppid() } != expected {
        return Err(Error::ChildFailed);
    }
    Ok(())
}
pub(super) fn spawn(
    container: ContainerFds<'_>,
    data: BorrowedFd<'_>,
    state: BorrowedFd<'_>,
) -> Result<Child> {
    process::single_threaded()?;
    let state_tree = rustix::mount::open_tree(
        state,
        "",
        rustix::mount::OpenTreeFlags::OPEN_TREE_CLONE
            | rustix::mount::OpenTreeFlags::OPEN_TREE_CLOEXEC
            | rustix::mount::OpenTreeFlags::AT_EMPTY_PATH,
    )
    .map_err(|_| Error::MountStateClone)?;
    let (release_r, release_w) = pipe()?;
    let (health_r, health_w) = pipe()?;
    let parent = std::process::id() as i32;
    // SAFETY: one task and no async runtime; child follows fixed setup only and
    // always _exits, so no duplicated Rust descriptor owners are dropped.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(Error::ChildFailed);
    }
    if pid == 0 {
        // SAFETY: child-only closure of pipe ends; never returns to Rust owners.
        unsafe {
            libc::close(release_w.as_raw_fd());
            libc::close(health_r.as_raw_fd());
        }
        let result = (|| {
            // SAFETY: one-task fork child; clear only its inherited environment.
            cv(unsafe { libc::clearenv() }, Error::ChildFailed)?;
            parent_death(parent)?;
            if !wait_ready(&release_r, Duration::from_secs(5))? || read_byte(&release_r)? != 1 {
                return Err(Error::PlacementFailed);
            }
            container_stage(container, data, state_tree.as_fd(), health_w.as_fd())
        })();
        die(if result.is_ok() { 0 } else { 121 });
    }
    drop(release_r);
    drop(health_w);
    let pinned = match pidfd(pid) {
        Ok(p) => p,
        Err(e) => {
            // SAFETY: forked child not reaped/reused and blocked at placement gate.
            unsafe {
                libc::kill(pid, libc::SIGKILL);
                libc::waitpid(pid, std::ptr::null_mut(), 0);
            }
            return Err(e);
        }
    };
    let inventory = super::inventory::Registration::owned(&[pinned.as_fd(), health_r.as_fd()])?;
    let release_inventory = super::inventory::Registration::owned(&[release_w.as_fd()])?;
    Ok(Child {
        _inventory: inventory,
        release_inventory: Some(release_inventory),
        pid: pid as u32,
        pidfd: pinned,
        release: Some(release_w),
        health: health_r,
        reaped: false,
    })
}
// ---- Container namespace entry and isolated mount-root construction ----
fn mount(
    source: Option<&CStr>,
    target: &CStr,
    kind: Option<&CStr>,
    flags: libc::c_ulong,
    data: Option<&CStr>,
) -> Result<()> {
    // SAFETY: all optional C strings live across synchronous mount; no borrowed kernel buffers retained.
    let result = cv(
        unsafe {
            libc::mount(
                source.map_or(std::ptr::null(), CStr::as_ptr),
                target.as_ptr(),
                kind.map_or(std::ptr::null(), CStr::as_ptr),
                flags,
                data.map_or(std::ptr::null(), |x| x.as_ptr().cast()),
            )
        },
        Error::MountIsolation,
    );
    #[cfg(test)]
    if result.is_err() {
        let category = match std::io::Error::last_os_error().raw_os_error() {
            Some(libc::EPERM | libc::EACCES) => "denied",
            Some(libc::ENOENT) => "missing",
            Some(libc::EINVAL) => "invalid",
            Some(libc::EBUSY) => "busy",
            Some(libc::EROFS) => "readonly",
            _ => "other",
        };
        eprintln!("LAB_NATIVE_MOUNT_REASON {category}");
    }
    result
}
fn attach_tree(tree: BorrowedFd<'_>, target: &str) -> Result<()> {
    let destination = fs::open(
        target,
        OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| Error::MountIsolation)?;
    rustix::mount::move_mount(
        tree,
        "",
        &destination,
        "",
        rustix::mount::MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH
            | rustix::mount::MoveMountFlags::MOVE_MOUNT_T_EMPTY_PATH,
    )
    .map_err(|_| Error::MountIsolation)
}
fn container_stage(
    container: ContainerFds<'_>,
    data: BorrowedFd<'_>,
    state: BorrowedFd<'_>,
    health: BorrowedFd<'_>,
) -> Result<()> {
    let signals = blocked_signals()?;
    // Pin the real parent before crossing the PID-for-children boundary.
    let parent = pidfd(unsafe { libc::getppid() })?;
    let outer_parent = pidfd(std::process::id() as i32)?;
    enter(container.pid, libc::CLONE_NEWPID)?;
    process::single_threaded()?;
    // SAFETY: single-task child, no runtime; setns PID-for-children becomes the
    // active container PID namespace only in this next intermediate child.
    let inner = unsafe { libc::fork() };
    if inner < 0 {
        return Err(Error::ChildFailed);
    }
    if inner == 0 {
        let r = (|| {
            parent_death(0)?;
            setup(container, data, state, health, outer_parent.as_fd())
        })();
        if let Err(e) = r {
            report_failure(health, e);
            die(118);
        }
        die(0);
    }
    let fd = pidfd(inner)?;
    wait_role(inner, fd.as_fd(), &signals, parent.as_fd(), health, 4)
}
fn setup(
    container: ContainerFds<'_>,
    data: BorrowedFd<'_>,
    state: BorrowedFd<'_>,
    health: BorrowedFd<'_>,
    parent: BorrowedFd<'_>,
) -> Result<()> {
    for (fd, kind) in [
        (container.ipc, libc::CLONE_NEWIPC),
        (container.uts, libc::CLONE_NEWUTS),
        (container.cgroup_ns, libc::CLONE_NEWCGROUP),
        (container.mount, libc::CLONE_NEWNS),
        (data, libc::CLONE_NEWNET),
    ] {
        enter(fd, kind)?;
    }
    let executable_tree = rustix::mount::open_tree(
        container.executable,
        "",
        rustix::mount::OpenTreeFlags::OPEN_TREE_CLONE
            | rustix::mount::OpenTreeFlags::OPEN_TREE_CLOEXEC
            | rustix::mount::OpenTreeFlags::AT_EMPTY_PATH,
    )
    .map_err(|_| Error::MountExecutableClone)?;
    // Bind root provenance after entering admitted container mount namespace.
    // SAFETY: pinned admitted root fd is a directory. chroot/fchdir affect this child only.
    cv(
        unsafe { libc::fchdir(container.root.as_raw_fd()) },
        Error::MountContainerRoot,
    )?;
    cv(
        unsafe { libc::chroot(c".".as_ptr()) },
        Error::MountContainerRoot,
    )?;
    cv(
        unsafe { libc::chdir(c"/".as_ptr()) },
        Error::MountContainerRoot,
    )?;
    unshare(libc::CLONE_NEWNS | libc::CLONE_NEWPID)?;
    mount(None, c"/", None, libc::MS_REC | libc::MS_PRIVATE, None)
        .map_err(|_| Error::MountPrivate)?;
    // Original readonly container root remains provenance source only; new root
    // contains fixed executable + selected state + fixed private resolver/proc.
    mount(
        Some(c"tmpfs"),
        c"/tmp",
        Some(c"tmpfs"),
        libc::MS_NOSUID | libc::MS_NODEV,
        Some(c"mode=0755,size=8m"),
    )
    .map_err(|_| Error::MountTmp)?;
    std::fs::create_dir("/tmp/root").map_err(|_| Error::MountPivot)?;
    mount(
        Some(c"tmpfs"),
        c"/tmp/root",
        Some(c"tmpfs"),
        libc::MS_NOSUID | libc::MS_NODEV,
        Some(c"mode=0755,size=8m"),
    )
    .map_err(|_| Error::MountTmp)?;
    for d in ["bin", "proc", "state", "etc", "old"] {
        std::fs::create_dir(format!("/tmp/root/{d}")).map_err(|_| Error::MountPivot)?;
    }
    std::fs::File::create("/tmp/root/bin/vprouter-worker").map_err(|_| Error::MountPivot)?;
    attach_tree(executable_tree.as_fd(), "/tmp/root/bin/vprouter-worker")
        .map_err(|_| Error::MountExecutableBind)?;
    mount(
        None,
        c"/tmp/root/bin/vprouter-worker",
        None,
        libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV,
        None,
    )
    .map_err(|_| Error::MountExecutableReadonly)?;
    attach_tree(state, "/tmp/root/state").map_err(|_| Error::MountState)?;
    std::fs::write(
        "/tmp/root/etc/resolv.conf",
        b"nameserver 192.0.2.53\noptions attempts:1 timeout:1\n",
    )
    .map_err(|_| Error::MountPivot)?;
    let null = fs::open("/dev/null", OFlags::RDWR | OFlags::CLOEXEC, Mode::empty())
        .map_err(|_| Error::DescriptorNull)?;
    let null_identity = approved_null(null.as_fd())?;
    for fd in 0..3 {
        dup_fixed(&null, fd, false)?;
    }
    let signals = blocked_signals()?;
    let init_parent = pidfd(std::process::id() as i32)?;
    process::single_threaded()?;
    // SAFETY: one task, no signal handler/thread; fixed PID1 child always _exits.
    let init = unsafe { libc::fork() };
    if init < 0 {
        return Err(Error::ChildFailed);
    }
    if init == 0 {
        // PID1's parent is outside the new namespace, so getppid is always0.
        // PDEATHSIG installed before readiness; intermediate checks pinned parent
        // survival and dies/kills PID1 as one unit on parent/container loss.
        let result = (|| {
            parent_death(0)?;
            // fork copied the mount-namespace reference. PID1 must unshare before
            // pivot/detach so it cannot disconnect its intermediate parent's root.
            unshare(libc::CLONE_NEWNS).map_err(|_| Error::MountPrivate)?;
            init_root()?;
            supervise(health, &signals, init_parent.as_fd(), null_identity)
        })();
        if let Err(e) = result {
            report_failure(health, e);
            die(120);
        }
        die(0);
    }
    let initfd = pidfd(init)?;
    // The intermediate has no purpose beyond preserving parent-death linkage;
    // forward signals to private PID1, boundedly kill even if frozen.
    wait_role(init, initfd.as_fd(), &signals, parent, health, 8)
}
fn init_root() -> Result<()> {
    // SAFETY: fixed prepared root is a mountpoint in this child's private view;
    // pivot_root puts old root solely at /old which is immediately detached.
    cv(
        unsafe {
            libc::syscall(
                libc::SYS_pivot_root,
                c"/tmp/root".as_ptr(),
                c"/tmp/root/old".as_ptr(),
            ) as i32
        },
        Error::MountPivot,
    )?;
    cv(unsafe { libc::chdir(c"/".as_ptr()) }, Error::MountPivot)?;
    cv(
        unsafe { libc::umount2(c"/old".as_ptr(), libc::MNT_DETACH) },
        Error::MountPivot,
    )?;
    std::fs::remove_dir("/old").map_err(|_| Error::MountPivot)?;
    mount(
        Some(c"proc"),
        c"/proc",
        Some(c"proc"),
        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        Some(c"hidepid=2"),
    )
    .map_err(|_| Error::MountProc)?;
    mount(
        None,
        c"/",
        None,
        libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV,
        None,
    )
    .map_err(|_| Error::MountReadonly)
}
// ---- Synchronous signal forwarding, bounded escalation and PID1 reaping ----
fn blocked_signals() -> Result<libc::sigset_t> {
    // SAFETY: zero is initialized storage subsequently initialized by sigemptyset; libc consumes exact sigset size.
    let mut set = unsafe { std::mem::zeroed() };
    unsafe {
        libc::sigemptyset(&mut set);
        for sig in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP, libc::SIGCHLD] {
            libc::sigaddset(&mut set, sig);
        }
    }
    cv(
        unsafe { libc::sigprocmask(libc::SIG_BLOCK, &set, std::ptr::null_mut()) },
        Error::ChildFailed,
    )?;
    Ok(set)
}
fn pending(set: &libc::sigset_t) -> Result<Option<i32>> {
    let t = libc::timespec {
        tv_sec: 0,
        tv_nsec: 50_000_000,
    }; // SAFETY: initialized fixed sigset and bounded timespec, no handlers.
    let signal = unsafe { libc::sigtimedwait(set, std::ptr::null_mut(), &t) };
    if signal >= 0 {
        return Ok(Some(signal));
    }
    match std::io::Error::last_os_error().raw_os_error() {
        Some(libc::EAGAIN | libc::EINTR) => Ok(None),
        _ => Err(Error::ChildFailed),
    }
}
fn earliest_deadline(deadline: &mut Option<Instant>, candidate: Instant) {
    *deadline = Some(deadline.map_or(candidate, |old| old.min(candidate)));
}
fn send_or_exited(fd: BorrowedFd<'_>, signal: i32) -> Result<()> {
    match send(fd, signal) {
        Ok(()) => Ok(()),
        Err(error) => {
            // A pinned child may exit between wait and signal. No numeric PID
            // fallback; only actual pidfd readiness makes that race harmless.
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
                && wait_ready(fd, Duration::ZERO)?
            {
                Ok(())
            } else {
                Err(error)
            }
        }
    }
}
fn forward_and_wait(
    pid: i32,
    fd: BorrowedFd<'_>,
    set: &libc::sigset_t,
    grace: Duration,
) -> Result<()> {
    let mut deadline = None;
    let mut escalation = None;
    loop {
        if let Some(sig @ (libc::SIGTERM | libc::SIGINT | libc::SIGHUP)) = pending(set)? {
            send_or_exited(fd, sig)?;
            earliest_deadline(&mut deadline, Instant::now() + grace);
        }
        if escalation.is_none() && deadline.is_some_and(|d| Instant::now() >= d) {
            send_or_exited(fd, libc::SIGKILL)?;
            escalation = Some(Instant::now() + Duration::from_secs(1));
        }
        if wait_ready(fd, Duration::ZERO)? {
            let mut status = 0; // SAFETY: our unreaped direct child, pinned by fd.
            if unsafe { libc::waitpid(pid, &mut status, 0) } != pid {
                return Err(Error::ChildFailed);
            }
            return if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 {
                Ok(())
            } else {
                Err(Error::ChildFailed)
            };
        }
        if escalation.is_some_and(|d| Instant::now() >= d) {
            return Err(Error::Deadline);
        }
    }
}
fn wait_role(
    pid: i32,
    child: BorrowedFd<'_>,
    set: &libc::sigset_t,
    parent: BorrowedFd<'_>,
    health: BorrowedFd<'_>,
    ready: u8,
) -> Result<()> {
    let mut report_fd = health.as_raw_fd();
    let result: Result<()> = (|| {
        let null = fs::open("/dev/null", OFlags::RDWR | OFlags::CLOEXEC, Mode::empty())
            .map_err(|_| Error::DescriptorNull)?;
        let expected_null = approved_null(null.as_fd())?;
        for n in 0..3 {
            dup_fixed(&null, n, false)?;
        }
        // Preserve source identities above fixed targets before either dup.
        let saved =
            rustix::io::fcntl_dupfd_cloexec(child, 110).map_err(|_| Error::DescriptorDuplicate)?;
        let saved_health =
            rustix::io::fcntl_dupfd_cloexec(health, 110).map_err(|_| Error::DescriptorDuplicate)?;
        let saved_parent =
            rustix::io::fcntl_dupfd_cloexec(parent, 110).map_err(|_| Error::DescriptorDuplicate)?;
        let status = fs::open(
            "/proc/self/status",
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| Error::CapabilityPolicy)?;
        let saved_status = rustix::io::fcntl_dupfd_cloexec(&status, 110)
            .map_err(|_| Error::DescriptorDuplicate)?;
        let lsm_read = fs::open(
            "/proc/self/attr/current",
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| Error::ConfinementPolicy)?;
        let lsm_write = fs::open(
            "/proc/self/attr/current",
            OFlags::WRONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| Error::ConfinementPolicy)?;
        let lsm_read = rustix::io::fcntl_dupfd_cloexec(lsm_read, 110)
            .map_err(|_| Error::DescriptorDuplicate)?;
        let lsm_write = rustix::io::fcntl_dupfd_cloexec(lsm_write, 110)
            .map_err(|_| Error::DescriptorDuplicate)?;
        dup_fixed(&saved, 3, true)?;
        dup_fixed(&saved_health, 4, true)?;
        report_fd = 4;
        dup_fixed(&saved_parent, 5, true)?;
        dup_fixed(&saved_status, 6, true)?;
        wait_root()?;
        rustix::io::write(&lsm_write, b"changeprofile docker-default")
            .map_err(|_| Error::WaitLsmTransition)?;
        let mut label = [0u8; 128];
        let count = rustix::io::read(&lsm_read, &mut label).map_err(|_| Error::WaitLsmRead)?;
        if label[..count]
            .strip_suffix(b"\n")
            .unwrap_or(&label[..count])
            != b"docker-default (enforce)"
        {
            return Err(Error::WaitLsmLabel);
        }
        // SAFETY: fixed0..6 now hold only validated null, child/health/parent and
        // current status. All other inherited FD owners stay inert until _exit.
        cv(
            unsafe { libc::syscall(libc::SYS_close_range, 7u32, u32::MAX, 0u32) as i32 },
            Error::DescriptorClose,
        )?;
        drop_privileges()?;
        let mut bytes = [0u8; 16384];
        let size = rustix::io::read(unsafe { BorrowedFd::borrow_raw(6) }, &mut bytes)
            .map_err(|_| Error::CapabilityPolicy)?;
        verify_credentials_text(
            std::str::from_utf8(&bytes[..size]).map_err(|_| Error::CapabilityPolicy)?,
            ready,
            unsafe { BorrowedFd::borrow_raw(4) },
        )?;
        // reduce_privileges re-arms PDEATHSIG after setresuid/setresgid cleared it.
        // The pidfd check closes the interval where the parent could have died.
        if wait_ready(unsafe { BorrowedFd::borrow_raw(5) }, Duration::ZERO)? {
            return Err(Error::ChildFailed);
        }
        unsafe {
            libc::close(5);
            libc::close(6);
        }
        // SAFETY: fixed descriptors were duplicated above and exclusively owned
        // by this child; no inherited Rust FD owner is dropped after closure.
        let child = unsafe { BorrowedFd::borrow_raw(3) };
        let health = unsafe { BorrowedFd::borrow_raw(4) };
        for n in 0..3 {
            if approved_null(unsafe { BorrowedFd::borrow_raw(n) })? != expected_null {
                return Err(Error::DescriptorStdio);
            }
        }
        apply_filter(&wait_filter()).map_err(|_| Error::WaitFilter)?;
        write_byte(health, ready)?;
        unsafe {
            libc::close(4);
        }
        // PID1 gets 500ms; its immediate wrapper gets 1000ms, the outer 1500ms.
        // These fixed bounds permit inner escalation and actual reaping first.
        let grace = Duration::from_millis(if ready == 8 { 1000 } else { 1500 });
        let result = forward_and_wait(pid, child, set, grace);
        die(if result.is_ok() { 0 } else { 112 });
    })();
    if let Err(e) = result {
        // One atomic pipe write keeps role+stage together amid other readiness.
        let bytes = [253u8, ready, stage_byte(e)];
        unsafe {
            libc::write(report_fd, bytes.as_ptr().cast(), bytes.len());
        }
    }
    die(111)
}
fn wait_root() -> Result<()> {
    // The wrapper gets a new mount namespace so neither host nor confined init
    // sees this empty root. No directory/state/proc survives the pivot.
    unshare(libc::CLONE_NEWNS)?;
    mount(None, c"/", None, libc::MS_REC | libc::MS_PRIVATE, None)
        .map_err(|_| Error::MountPrivate)?;
    mount(
        Some(c"tmpfs"),
        c"/tmp",
        Some(c"tmpfs"),
        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        Some(c"mode=0755,size=64k"),
    )
    .map_err(|_| Error::MountTmp)?;
    std::fs::create_dir("/tmp/old").map_err(|_| Error::MountPivot)?;
    cv(
        unsafe {
            libc::syscall(libc::SYS_pivot_root, c"/tmp".as_ptr(), c"/tmp/old".as_ptr()) as i32
        },
        Error::MountPivot,
    )?;
    cv(unsafe { libc::chdir(c"/".as_ptr()) }, Error::MountPivot)?;
    cv(
        unsafe { libc::umount2(c"/old".as_ptr(), libc::MNT_DETACH) },
        Error::MountPivot,
    )?;
    std::fs::remove_dir("/old").map_err(|_| Error::MountPivot)?;
    mount(
        None,
        c"/",
        None,
        libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        None,
    )
    .map_err(|_| Error::MountReadonly)
}
fn supervise(
    health: BorrowedFd<'_>,
    set: &libc::sigset_t,
    parent: BorrowedFd<'_>,
    null_identity: StdioIdentity,
) -> Result<()> {
    cv(
        unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) },
        Error::CapabilityPolicy,
    )?;
    let executable = fs::open(
        "/bin/vprouter-worker",
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| Error::ExecutableMismatch)?;
    process::single_threaded()?;
    // SAFETY: PID1 is single-task, fixed child exec path or _exit only.
    let worker = unsafe { libc::fork() };
    if worker < 0 {
        return Err(Error::ChildFailed);
    }
    if worker == 0 {
        let result = worker_exec(executable.as_fd(), health, null_identity);
        let _ = result;
        die(119);
    }
    // Close ALL inherited host handles in PID1 too; Rust FD owners are never
    // dropped here. Namespace init must not remain a privileged escape target.
    lsm_supervisor()?;
    reduce_privileges(16, health)?;
    if wait_ready(parent, Duration::ZERO)? {
        return Err(Error::ChildFailed);
    }
    let confined: Result<()> = (|| {
        close_except(&[health.as_raw_fd()])?;
        supervisor_fds(health, null_identity)?;
        seccomp()?;
        supervisor_fds(health, null_identity)
    })();
    if let Err(e) = confined {
        report_failure(health, e);
        die(115);
    }
    if write_byte(health, 2).is_err() {
        die(114);
    }
    // SAFETY: supervisor consumes its health descriptor and never unwinds these
    // inherited FD owners. The signal/reap loop exits via _exit only.
    if checked_close(health.as_raw_fd()).is_err() {
        die(114);
    }
    let result = supervisor_loop(set, worker);
    die(if result.is_ok() { 0 } else { 113 });
}
fn supervisor_loop(set: &libc::sigset_t, worker: i32) -> Result<()> {
    let mut deadline = None;
    let mut escalation = None;
    let mut main_exited = false;
    loop {
        if let Some(sig @ (libc::SIGTERM | libc::SIGINT | libc::SIGHUP)) = pending(set)? {
            signal_descendants(sig)?;
            earliest_deadline(&mut deadline, Instant::now() + Duration::from_millis(500));
        }
        if escalation.is_none() && deadline.is_some_and(|d| Instant::now() >= d) {
            signal_descendants(libc::SIGKILL)?;
            escalation = Some(Instant::now() + Duration::from_millis(400));
        }
        loop {
            let mut status = 0; // SAFETY: wait only any direct/adopted children in this private PID namespace.
            let p = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
            if p == worker {
                main_exited = true;
                earliest_deadline(&mut deadline, Instant::now());
            } else if p > 0 {
                #[cfg(test)]
                write_test_state("/state/reaped-descendant", b"reaped")?;
            }
            if p == 0 {
                break;
            }
            if p < 0 {
                match std::io::Error::last_os_error().raw_os_error() {
                    Some(libc::EINTR) => continue,
                    Some(libc::ECHILD) if main_exited => return Ok(()),
                    _ => return Err(Error::ChildFailed),
                }
            }
        }
        if escalation.is_some_and(|d| Instant::now() >= d) {
            return Err(Error::Deadline);
        }
    }
}
fn signal_descendants(signal: i32) -> Result<()> {
    // SAFETY: private PID1; -1 addresses only descendants of this namespace.
    if unsafe { libc::kill(-1, signal) } == 0 {
        return Ok(());
    }
    match std::io::Error::last_os_error().raw_os_error() {
        // No remaining signal targets is benign; waitpid must still establish
        // ECHILD before successful supervision completion.
        Some(libc::ESRCH) => Ok(()),
        _ => Err(Error::ChildFailed),
    }
}
// ---- Descriptor closure and independently verified final inventories ----
fn dup_fixed(fd: impl AsFd, to: i32, cloexec: bool) -> Result<()> {
    // SAFETY: fixed child-only targets, duplicate first to avoid source/target collisions.
    let saved = unsafe { libc::fcntl(fd.as_fd().as_raw_fd(), libc::F_DUPFD_CLOEXEC, 100) };
    if saved < 0 {
        return Err(Error::DescriptorDuplicate);
    }
    let result = cv(
        unsafe { libc::dup3(saved, to, if cloexec { libc::O_CLOEXEC } else { 0 }) },
        Error::DescriptorDuplicate,
    );
    unsafe {
        libc::close(saved);
    }
    result
}
fn close_except(keep: &[i32]) -> Result<()> {
    // CLOEXEC is not enough: remove host dirs, sockets, roots and namespace FDs
    // before untrusted code. Enumeration closes only numeric descriptors; owners
    // remain inert until this child execs/_exits, never Rust unwinding.
    close_numbers(descriptor_inventory()?, keep, checked_close)
}
fn close_numbers(
    fds: std::collections::BTreeSet<i32>,
    keep: &[i32],
    mut close: impl FnMut(i32) -> Result<()>,
) -> Result<()> {
    for fd in fds {
        if fd > 2 && !keep.contains(&fd) {
            close(fd)?;
        }
    }
    Ok(())
}
fn checked_close(fd: i32) -> Result<()> {
    // SAFETY: caller exclusively owns this child's descriptor table; inherited
    // Rust owners never run after closure. On Linux close consumes the FD even
    // on EINTR; report failure without a potentially dangerous retry.
    cv(unsafe { libc::close(fd) }, Error::DescriptorClose)
}
fn descriptor_numbers(
    entries: impl IntoIterator<Item = Result<Vec<u8>>>,
    scan_fd: i32,
) -> Result<std::collections::BTreeSet<i32>> {
    let mut numbers = std::collections::BTreeSet::new();
    for entry in entries {
        let name = entry?;
        if name == b"." || name == b".." {
            continue;
        }
        if name.is_empty() || !name.iter().all(u8::is_ascii_digit) {
            return Err(Error::DescriptorInventory);
        }
        let fd = std::str::from_utf8(&name)
            .ok()
            .and_then(|name| name.parse::<i32>().ok())
            .ok_or(Error::DescriptorInventory)?;
        if !numbers.insert(fd) {
            return Err(Error::DescriptorInventory);
        }
    }
    if !numbers.remove(&scan_fd) {
        return Err(Error::DescriptorInventory);
    }
    Ok(numbers)
}
fn descriptor_inventory() -> Result<std::collections::BTreeSet<i32>> {
    let directory = fs::openat(
        fs::CWD,
        "/proc/self/fd",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| Error::DescriptorScanOpen)?;
    let mut scan = fs::Dir::new(directory).map_err(|_| Error::DescriptorInventory)?;
    let scan_fd = scan
        .fd()
        .map_err(|_| Error::DescriptorInventory)?
        .as_raw_fd();
    descriptor_numbers(
        (&mut scan).map(|entry| {
            entry
                .map(|entry| entry.file_name().to_bytes().to_vec())
                .map_err(|_| Error::DescriptorInventory)
        }),
        scan_fd,
    )
}
fn supervisor_fds(health: BorrowedFd<'_>, expected_null: StdioIdentity) -> Result<()> {
    let health_fd = health.as_raw_fd();
    supervisor_inventory(descriptor_inventory()?, health_fd)?;
    for fd in 0..3 {
        // SAFETY: exact final child stdio is borrowed only for identity checks.
        if approved_null(unsafe { BorrowedFd::borrow_raw(fd) })? != expected_null
            || unsafe { libc::fcntl(fd, libc::F_GETFD) } != 0
        {
            return Err(Error::DescriptorStdio);
        }
    }
    let stat = fs::fstat(health).map_err(|_| Error::DescriptorHealth)?;
    if fs::FileType::from_raw_mode(stat.st_mode) != fs::FileType::Fifo
        || unsafe { libc::fcntl(health_fd, libc::F_GETFD) } != libc::FD_CLOEXEC
    {
        return Err(Error::DescriptorHealth);
    }
    Ok(())
}
fn supervisor_inventory(fds: std::collections::BTreeSet<i32>, health_fd: i32) -> Result<()> {
    if health_fd <= 2 || fds != [0, 1, 2, health_fd].into() {
        return Err(Error::DescriptorInventory);
    }
    Ok(())
}
// ---- Capability, identity and LSM confinement ----
fn reduce_privileges(role: u8, health: BorrowedFd<'_>) -> Result<()> {
    drop_privileges()?;
    verify_credentials(role, health)
}
fn drop_privileges() -> Result<()> {
    // SAFETY: scalar prctl calls on current child only. Securebits lock all
    // root/setuid/ambient regain paths; every supported bounding capability drops.
    cv(
        unsafe { libc::prctl(libc::PR_SET_SECUREBITS, 0xef, 0, 0, 0) },
        Error::CapabilityPolicy,
    )?;
    for cap in 0..64 {
        let value = unsafe { libc::prctl(libc::PR_CAPBSET_READ, cap, 0, 0, 0) };
        if value < 0 {
            break;
        }
        cv(
            unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0) },
            Error::CapabilityPolicy,
        )?;
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
    cv(
        unsafe { libc::setresgid(65534, 65534, 65534) },
        Error::CapabilityPolicy,
    )?;
    cv(
        unsafe { libc::setresuid(65534, 65534, 65534) },
        Error::CapabilityPolicy,
    )?;
    #[repr(C)]
    struct CapHeader {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    struct CapData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    let header = CapHeader {
        version: 0x20080522,
        pid: 0,
    };
    let data = [
        CapData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
        CapData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
    ];
    // SAFETY: Linux v3 capset expects this exact header and two initialized data
    // words. NO_SETUID_FIXUP requires explicit capset after dropping IDs.
    cv(
        unsafe { libc::syscall(libc::SYS_capset, &header, data.as_ptr()) as i32 },
        Error::CapabilityPolicy,
    )?;
    cv(
        unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) },
        Error::CapabilityPolicy,
    )?;
    cv(
        unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) },
        Error::ChildFailed,
    )?;
    Ok(())
}
fn credential_failure(health: BorrowedFd<'_>, role: u8, field: u8) -> Error {
    let bytes = [254u8, role, field];
    // SAFETY: fixed three-byte diagnostic is atomically written to owned pipe;
    // no process contents or variable external data is emitted.
    unsafe {
        libc::write(health.as_raw_fd(), bytes.as_ptr().cast(), bytes.len());
    }
    Error::CapabilityPolicy
}
fn verify_credentials(role: u8, health: BorrowedFd<'_>) -> Result<()> {
    let s = read_fixed("/proc/self/status", 16384).map_err(|error| {
        credential_failure(
            health,
            role,
            match error.kind() {
                std::io::ErrorKind::PermissionDenied => 13,
                std::io::ErrorKind::NotFound => 14,
                _ => 11,
            },
        )
    })?;
    let s = std::str::from_utf8(&s).map_err(|_| credential_failure(health, role, 12))?;
    verify_credentials_text(s, role, health)
}
fn read_fixed(path: &str, limit: usize) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    // Explicit openat is part of the fixed profile on both architectures;
    // std File::open would call denied musl SYS_open on x86_64.
    let fd = fs::openat(
        fs::CWD,
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )?;
    let mut bytes = Vec::new();
    std::fs::File::from(fd)
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(std::io::ErrorKind::InvalidData.into());
    }
    Ok(bytes)
}
#[cfg(test)]
fn write_test_state(path: &'static str, value: &[u8]) -> Result<()> {
    use std::io::Write;
    let fd = fs::openat(
        fs::CWD,
        path,
        OFlags::WRONLY | OFlags::CREATE | OFlags::TRUNC | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|_| Error::ProbeStateWrite)?;
    std::fs::File::from(fd)
        .write_all(value)
        .map_err(|_| Error::ProbeStateWrite)
}
fn verify_credentials_text(s: &str, role: u8, health: BorrowedFd<'_>) -> Result<()> {
    for (field, (key, expected)) in [
        ("Uid:", vec!["65534"; 4]),
        ("Gid:", vec!["65534"; 4]),
        ("Groups:", vec![]),
        ("NoNewPrivs:", vec!["1"]),
    ]
    .into_iter()
    .enumerate()
    {
        let parts = s
            .lines()
            .find_map(|l| l.strip_prefix(key))
            .ok_or_else(|| credential_failure(health, role, field as u8))?
            .split_whitespace()
            .collect::<Vec<_>>();
        if parts != expected {
            return Err(credential_failure(health, role, field as u8));
        }
    }
    for (field, key) in ["CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:"]
        .into_iter()
        .enumerate()
    {
        let v = s
            .lines()
            .find_map(|l| l.strip_prefix(key))
            .ok_or_else(|| credential_failure(health, role, field as u8 + 4))?
            .trim();
        if u64::from_str_radix(v, 16).ok() != Some(0) {
            return Err(credential_failure(health, role, field as u8 + 4));
        }
    }
    // SAFETY: GET operations have scalar results and no pointer parameters.
    if unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) } != 1 {
        return Err(credential_failure(health, role, 9));
    }
    if unsafe { libc::prctl(libc::PR_GET_SECUREBITS, 0, 0, 0, 0) } != 0xef {
        return Err(credential_failure(health, role, 10));
    }
    Ok(())
}
fn lsm_current() -> Result<()> {
    let s = read_fixed("/proc/self/attr/current", 128).map_err(|_| Error::ConfinementPolicy)?;
    if std::str::from_utf8(&s)
        .map_err(|_| Error::ConfinementPolicy)?
        .trim()
        != "docker-default (enforce)"
    {
        return Err(Error::ConfinementPolicy);
    }
    Ok(())
}
fn lsm_exec() -> Result<()> {
    // Explicit transition required: host-launched tasks inherit no Docker LSM.
    // Exact profile is fixed by the test-program policy, never caller-supplied.
    std::fs::write("/proc/self/attr/exec", b"exec docker-default")
        .map_err(|_| Error::ConfinementPolicy)
}
fn lsm_supervisor() -> Result<()> {
    std::fs::write("/proc/self/attr/current", b"changeprofile docker-default")
        .map_err(|_| Error::ConfinementPolicy)?;
    lsm_current()
}
// ---- Manifest-bound probe and reduced wait-role seccomp programs ----
fn filter() -> Vec<libc::sock_filter> {
    let mut out = vec![
        libc::sock_filter {
            code: 0x20,
            jt: 0,
            jf: 0,
            k: 4,
        }, // seccomp_data.arch
        libc::sock_filter {
            code: 0x15,
            jt: 1,
            jf: 0,
            k: if cfg!(target_arch = "x86_64") {
                0xc000003e
            } else {
                0xc00000b7
            },
        },
        libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0x80000000,
        }, // KILL_PROCESS arch mismatch
        libc::sock_filter {
            code: 0x20,
            jt: 0,
            jf: 0,
            k: 0,
        }, // syscall nr, x32 unlisted
    ];
    out.extend([
        libc::sock_filter {
            code: 0x15,
            jt: 0,
            jf: 8,
            k: libc::SYS_clone as u32,
        },
        libc::sock_filter {
            code: 0x20,
            jt: 0,
            jf: 0,
            k: 20,
        },
        libc::sock_filter {
            code: 0x15,
            jt: 1,
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
            k: 16,
        },
        libc::sock_filter {
            code: 0x15,
            jt: 2,
            jf: 0,
            k: libc::SIGCHLD as u32,
        },
        libc::sock_filter {
            code: 0x15,
            jt: 1,
            jf: 0,
            k: (libc::CLONE_CHILD_SETTID | libc::CLONE_CHILD_CLEARTID | libc::SIGCHLD) as u32,
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
    let syscalls = [
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_readv,
        libc::SYS_writev,
        libc::SYS_close,
        libc::SYS_openat,
        libc::SYS_newfstatat,
        libc::SYS_fstat,
        libc::SYS_statx,
        libc::SYS_lseek,
        libc::SYS_pread64,
        libc::SYS_getdents64,
        libc::SYS_readlinkat,
        libc::SYS_fcntl,
        libc::SYS_brk,
        libc::SYS_mmap,
        libc::SYS_mprotect,
        libc::SYS_munmap,
        libc::SYS_madvise,
        libc::SYS_rt_sigaction,
        libc::SYS_rt_sigprocmask,
        libc::SYS_rt_sigreturn,
        libc::SYS_rt_sigtimedwait,
        libc::SYS_set_tid_address,
        libc::SYS_set_robust_list,
        libc::SYS_futex,
        libc::SYS_getrandom,
        libc::SYS_clock_gettime,
        libc::SYS_clock_nanosleep,
        libc::SYS_nanosleep,
        libc::SYS_getpid,
        libc::SYS_getppid,
        libc::SYS_gettid,
        libc::SYS_getuid,
        libc::SYS_geteuid,
        libc::SYS_getgid,
        libc::SYS_getegid,
        libc::SYS_prctl,
        libc::SYS_exit,
        libc::SYS_exit_group,
        libc::SYS_execveat,
        libc::SYS_wait4,
        libc::SYS_kill,
        libc::SYS_sched_yield,
    ];
    for nr in syscalls {
        out.push(libc::sock_filter {
            code: 0x15,
            jt: 0,
            jf: 1,
            k: nr as u32,
        });
        out.push(libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0x7fff0000,
        });
    }
    #[cfg(target_arch = "x86_64")]
    for nr in [
        libc::SYS_arch_prctl,
        libc::SYS_readlink,
        libc::SYS_poll,
        libc::SYS_access,
        libc::SYS_stat,
        libc::SYS_lstat,
    ] {
        out.push(libc::sock_filter {
            code: 0x15,
            jt: 0,
            jf: 1,
            k: nr as u32,
        });
        out.push(libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0x7fff0000,
        });
    }
    out.push(libc::sock_filter {
        code: 0x06,
        jt: 0,
        jf: 0,
        k: 0x00050001,
    }); // EPERM default
    out
}
fn wait_filter() -> Vec<libc::sock_filter> {
    // Exact fixed wait role, no paths, sockets, namespaces, exec or fork.
    let mut out = filter()[..4].to_vec();
    // The install routine verifies its post-install state. Permit only the
    // scalar read-only PR_GET_SECCOMP query, never a state-changing prctl.
    out.extend([
        libc::sock_filter {
            code: 0x15,
            jt: 0,
            jf: 7,
            k: libc::SYS_prctl as u32,
        },
        libc::sock_filter {
            code: 0x20,
            jt: 0,
            jf: 0,
            k: 20,
        },
        libc::sock_filter {
            code: 0x15,
            jt: 1,
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
            k: 16,
        },
        libc::sock_filter {
            code: 0x15,
            jt: 0,
            jf: 1,
            k: libc::PR_GET_SECCOMP as u32,
        },
        libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0x7fff0000,
        },
        libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0x00050001,
        },
    ]);
    let calls = [
        libc::SYS_ppoll,
        libc::SYS_rt_sigtimedwait,
        libc::SYS_pidfd_send_signal,
        libc::SYS_wait4,
        libc::SYS_clock_gettime,
        libc::SYS_write,
        libc::SYS_close,
        libc::SYS_brk,
        libc::SYS_mmap,
        libc::SYS_munmap,
        libc::SYS_mprotect,
        libc::SYS_madvise,
        libc::SYS_exit,
        libc::SYS_exit_group,
        libc::SYS_rt_sigreturn,
        #[cfg(target_arch = "x86_64")]
        libc::SYS_poll,
    ];
    for nr in calls {
        out.push(libc::sock_filter {
            code: 0x15,
            jt: 0,
            jf: 1,
            k: nr as u32,
        });
        out.push(libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0x7fff0000,
        });
    }
    out.push(libc::sock_filter {
        code: 0x06,
        jt: 0,
        jf: 0,
        k: 0x00050001,
    });
    out
}
pub(super) fn policy_digest() -> String {
    let mut bytes = super::execution::POLICY.as_bytes().to_vec();
    for instruction in filter().into_iter().chain(wait_filter()) {
        bytes.extend_from_slice(&instruction.code.to_le_bytes());
        bytes.push(instruction.jt);
        bytes.push(instruction.jf);
        bytes.extend_from_slice(&instruction.k.to_le_bytes());
    }
    vprouter_linux::sha256(&bytes)
}
fn seccomp() -> Result<()> {
    apply_filter(&filter())
}
fn apply_filter(f: &[libc::sock_filter]) -> Result<()> {
    let p = libc::sock_fprog {
        len: f.len() as u16,
        filter: f.as_ptr().cast_mut(),
    }; // SAFETY: initialized BPF slice lives across synchronous prctl, kernel copies complete program before return.
    cv(
        unsafe { libc::prctl(libc::PR_SET_SECCOMP, 2, &p, 0, 0) },
        Error::ConfinementPolicy,
    )?;
    if unsafe { libc::prctl(libc::PR_GET_SECCOMP, 0, 0, 0, 0) } != 2 {
        return Err(Error::ConfinementPolicy);
    }
    Ok(())
}
// ---- Fixed worker exec and post-exec descriptor checks ----
fn worker_exec(
    executable: BorrowedFd<'_>,
    health: BorrowedFd<'_>,
    null_identity: StdioIdentity,
) -> Result<()> {
    process::single_threaded()?;
    parent_death(1)?;
    // Duplicate both sources above fixed targets before replacing either one.
    // SAFETY: creates new child-owned CLOEXEC descriptors; never transferred to Rust owners after final closure.
    let ex = unsafe { libc::fcntl(executable.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 110) };
    let he = unsafe { libc::fcntl(health.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 110) };
    if ex < 0 || he < 0 {
        return Err(Error::DescriptorPolicy);
    }
    // SAFETY: valid new FDs remain live until exec/_exit.
    let ex = unsafe { BorrowedFd::borrow_raw(ex) };
    let he = unsafe { BorrowedFd::borrow_raw(he) };
    dup_fixed(he, 3, false)?;
    dup_fixed(ex, 4, true)?;
    let result = (|| -> Result<()> {
        close_except(&[3, 4])?;
        lsm_exec()?;
        reduce_privileges(32, unsafe { BorrowedFd::borrow_raw(3) })?;
        if unsafe { libc::getppid() } != 1 {
            return Err(Error::ChildFailed);
        }
        seccomp()?;
        // Final inventory exact0..4; executable4 is CLOEXEC, health3 explicitly not.
        final_fds(true, Some(null_identity))?;
        // SAFETY: empty initialized set unblocks inherited blocked signals only in
        // the worker, not PID1. Fixed argv/env are null-terminated pointer arrays.
        let mut empty = unsafe { std::mem::zeroed() };
        unsafe {
            libc::sigemptyset(&mut empty);
        }
        cv(
            unsafe { libc::sigprocmask(libc::SIG_SETMASK, &empty, std::ptr::null_mut()) },
            Error::ChildFailed,
        )?;
        let args = [
            c"vprouter-worker".as_ptr(),
            c"--isolated-probe".as_ptr(),
            std::ptr::null(),
        ];
        let env = [c"LANG=C".as_ptr(), c"PATH=/bin".as_ptr(), std::ptr::null()];
        // SAFETY: FD4 is retained manifest-verified executable, CLOEXEC intentionally
        // consumed by execveat AT_EMPTY_PATH. No pathname/argv/env comes from caller.
        unsafe {
            libc::syscall(
                libc::SYS_execveat,
                4,
                c"".as_ptr(),
                args.as_ptr(),
                env.as_ptr(),
                libc::AT_EMPTY_PATH,
            );
        }
        Err(Error::ChildFailed)
    })();
    if let Err(e) = result {
        let health = unsafe { BorrowedFd::borrow_raw(3) };
        report_failure(health, e);
    }
    die(119)
}
#[derive(Clone, Copy, PartialEq, Eq)]
struct StdioIdentity {
    dev: u64,
    ino: u64,
    rdev: u64,
}
fn approved_null(fd: BorrowedFd<'_>) -> Result<StdioIdentity> {
    let stat = fs::fstat(fd).map_err(|_| Error::DescriptorStdio)?;
    if fs::FileType::from_raw_mode(stat.st_mode) != fs::FileType::CharacterDevice
        || fs::major(stat.st_rdev) != 1
        || fs::minor(stat.st_rdev) != 3
    {
        return Err(Error::DescriptorStdio);
    }
    Ok(StdioIdentity {
        dev: stat.st_dev,
        ino: stat.st_ino,
        rdev: stat.st_rdev,
    })
}
fn final_fds(before_exec: bool, expected_null: Option<StdioIdentity>) -> Result<()> {
    // SAFETY: FD0 belongs to current isolated child and is only borrowed here.
    let null = approved_null(unsafe { BorrowedFd::borrow_raw(0) })?;
    if expected_null.is_some_and(|expected| expected != null) {
        return Err(Error::DescriptorStdio);
    }
    let expected = if before_exec { 5 } else { 4 };
    for fd in 0..expected {
        // SAFETY: scalar descriptor flags queries.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags < 0 || flags & libc::FD_CLOEXEC != if fd == 4 { libc::FD_CLOEXEC } else { 0 } {
            return Err(Error::DescriptorFlags);
        }
        if fd <= 2 {
            // SAFETY: exact fixed stdio descriptor is borrowed only for fstat;
            // kernel character-device identity survives old-root detachment.
            if approved_null(unsafe { BorrowedFd::borrow_raw(fd) })? != null {
                return Err(Error::DescriptorStdio);
            }
            continue;
        }
        let target = std::fs::read_link(format!("/proc/self/fd/{fd}"))
            .map_err(|_| Error::DescriptorReadlink)?;
        let name = target.as_os_str().as_encoded_bytes();
        if fd == 3 && !name.starts_with(b"pipe:[") {
            return Err(Error::DescriptorHealth);
        }
        if fd == 4 && name != b"/bin/vprouter-worker" {
            return Err(Error::DescriptorExecutable);
        }
    }
    // Native openat+getdents avoids musl opendir's legacy SYS_open, which the
    // manifest-bound probe policy deliberately does not permit.
    let directory = fs::openat(
        fs::CWD,
        "/proc/self/fd",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| {
        if error == rustix::io::Errno::PERM || error == rustix::io::Errno::ACCESS {
            Error::DescriptorScanDenied
        } else {
            Error::DescriptorScanOpen
        }
    })?;
    let mut scan = fs::Dir::new(directory).map_err(|_| Error::DescriptorInventory)?;
    let mut entries = std::collections::BTreeSet::new();
    for entry in &mut scan {
        let entry = entry.map_err(|_| Error::DescriptorInventory)?;
        let name = entry.file_name().to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        let number = std::str::from_utf8(name)
            .ok()
            .and_then(|s| s.parse::<i32>().ok())
            .ok_or(Error::DescriptorInventory)?;
        entries.insert(number);
    }
    // The one temporary directory FD must be exactly the next available slot;
    // require the complete numeric set, not merely an equal descriptor count.
    if scan
        .fd()
        .map_err(|_| Error::DescriptorInventory)?
        .as_raw_fd()
        != expected
        || entries != (0..=expected).collect()
    {
        return Err(Error::DescriptorScanCount);
    }
    Ok(())
}
// ---- Test-only post-exec adversarial probe and isolated guest helpers ----
#[cfg(test)]
pub(super) fn probe_verify() -> Result<()> {
    verify_credentials(64, unsafe { BorrowedFd::borrow_raw(3) })?;
    lsm_current()?;
    final_fds(false, None)?;
    let bytes = read_fixed("/proc/self/status", 16384).map_err(|_| Error::ConfinementPolicy)?;
    let s = std::str::from_utf8(&bytes).map_err(|_| Error::ConfinementPolicy)?;
    if !s.lines().any(|l| l == "Seccomp:\t2") {
        return Err(Error::ConfinementPolicy);
    }
    // Actual denied syscall proves new filter enforcement after exec.
    // SAFETY: scalar socket call, closed immediately if unexpectedly permitted.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    if fd >= 0 {
        unsafe {
            libc::close(fd);
        }
        return Err(Error::ConfinementPolicy);
    }
    if std::io::Error::last_os_error().raw_os_error() != Some(libc::EPERM) {
        return Err(Error::ConfinementPolicy);
    }
    if std::env::vars_os().collect::<std::collections::BTreeMap<_, _>>()
        != [("LANG".into(), "C".into()), ("PATH".into(), "/bin".into())].into()
    {
        return Err(Error::ConfinementPolicy);
    }
    if read_fixed("/etc/resolv.conf", 128).map_err(|_| Error::ProbeResolver)?
        != b"nameserver 192.0.2.53\noptions attempts:1 timeout:1\n"
    {
        return Err(Error::ProbeResolver);
    }
    for path in [
        "/old",
        "/run/netns",
        "/var/run/docker.sock",
        "/sys/fs/cgroup",
    ] {
        if std::fs::metadata(path).is_ok() {
            return Err(Error::ProbeForbiddenRoot);
        }
    }
    write_test_state("/state/probe", b"selected-exit-only")?;
    if fs::openat(
        fs::CWD,
        "/etc/forbidden",
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::RUSR | Mode::WUSR,
    )
    .is_ok()
    {
        return Err(Error::ProbeReadonly);
    }
    // Before creating descendants private procfs may expose only self, or init
    // and self. hidepid=2 deliberately hides nondumpable PID1 even at the same
    // UID; the host oracle separately proves its exact root/mount/PID identity.
    use std::os::unix::fs::MetadataExt;
    let own_root = std::fs::metadata("/").map_err(|_| Error::ProbeProcRoot)?;
    let mut visible = std::collections::BTreeSet::new();
    let proc = fs::openat(
        fs::CWD,
        "/proc",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| Error::ProbeProcSet)?;
    for entry in fs::Dir::new(proc).map_err(|_| Error::ProbeProcSet)? {
        let e = entry.map_err(|_| Error::ProbeProcSet)?;
        if e.file_name().to_bytes().iter().all(u8::is_ascii_digit) {
            let pid = e
                .file_name()
                .to_str()
                .ok()
                .and_then(|s| s.parse::<u32>().ok())
                .ok_or(Error::ProbeProcSet)?;
            visible.insert(pid);
            match std::fs::metadata(format!("/proc/{pid}/root")) {
                Ok(root) if (root.dev(), root.ino()) == (own_root.dev(), own_root.ino()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {}
                _ => return Err(Error::ProbeProcRoot),
            }
        }
    }
    if (visible != [2].into() && visible != [1, 2].into()) || std::process::id() != 2 {
        return Err(Error::ProbeProcSet);
    }
    Ok(())
}
#[cfg(test)]
pub(super) fn probe_descendant() -> Result<()> {
    // Install synchronous handling before clone/readiness. The frozen descendant
    // inherits blocked shutdown signals and can only be removed by escalation.
    blocked_signals()?;
    // SAFETY: one-task post-exec test probe; SIGCHLD alone copies address space
    // and current stack, never CLONE_VM. x86_64/ARM64 order the ancillary tid/tls
    // arguments differently, but every such argument is the same null value.
    // Child only freezes then _exits; no libc atfork state is used after clone.
    let p = unsafe {
        libc::syscall(
            libc::SYS_clone,
            libc::SIGCHLD,
            0usize,
            0usize,
            0usize,
            0usize,
        )
    };
    if p < 0 {
        return Err(Error::ChildFailed);
    }
    if p == 0 {
        unsafe {
            libc::kill(libc::getpid(), libc::SIGSTOP);
        }
        die(0);
    }
    Ok(())
}
#[cfg(test)]
pub(super) fn probe_signal_loop() -> Result<()> {
    let set = blocked_signals()?;
    let mut witnessed = false;
    loop {
        if let Some(signal @ (libc::SIGTERM | libc::SIGINT | libc::SIGHUP)) = pending(&set)?
            && !witnessed
        {
            let value: &[u8] = match signal {
                libc::SIGTERM => b"TERM",
                libc::SIGINT => b"INT",
                _ => b"HUP",
            };
            write_test_state("/state/forwarded-signal", value)?;
            witnessed = true;
            // Remain alive so repeated signals cannot hide a moved PID1 deadline
            // behind ordinary worker exit. Actual SIGKILL must reap both roles.
        }
    }
}
#[cfg(test)]
pub(super) fn probe_ready() -> Result<()> {
    // SAFETY: fixed health descriptor was verified pipe after exec.
    let fd = unsafe { BorrowedFd::borrow_raw(3) };
    write_byte(fd, 1)
}
#[cfg(test)]
pub(super) fn verify_pid_parent(pid: u32, expected: BorrowedFd<'_>) -> Result<()> {
    let fd = fs::open(
        format!("/proc/{pid}/ns/pid"),
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| Error::NamespaceMismatch)?;
    // SAFETY: NS_GET_PARENT takes no pointer, returns a new owned nsfs FD.
    let parent = unsafe { libc::ioctl(fd.as_raw_fd(), 0xb702) };
    if parent < 0 {
        return Err(Error::NamespaceMismatch);
    }
    let parent = unsafe { OwnedFd::from_raw_fd(parent) };
    if super::owned::Identity::of(parent)? != super::owned::Identity::of(expected)? {
        return Err(Error::NamespaceMismatch);
    }
    Ok(())
}
#[cfg(test)]
fn cleanup_error(stage: &'static str, errno: Option<i32>) -> Error {
    eprintln!(
        "LAB_UNPIN_FAILURE {stage} {}",
        match errno {
            Some(libc::ENOENT) => "missing",
            Some(libc::ESRCH) => "vanished",
            Some(libc::EBUSY) => "busy",
            Some(libc::EPERM | libc::EACCES) => "denied",
            Some(libc::EINVAL) => "invalid",
            None => "identity",
            _ => "other",
        }
    );
    Error::OwnershipMismatch
}
#[cfg(test)]
pub(super) fn lab_unpin(dir: BorrowedFd<'_>, name: &str, id: super::owned::Identity) -> Result<()> {
    let fd = fs::openat(
        dir,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|error| cleanup_error("pin_open", Some(error.raw_os_error())))?;
    if super::owned::Identity::network(&fd)? != id {
        return Err(cleanup_error("pin_identity", None));
    }
    for e in std::fs::read_dir("/proc").map_err(|_| Error::OwnershipMismatch)? {
        let e = e.map_err(|_| Error::OwnershipMismatch)?;
        if !e
            .file_name()
            .to_str()
            .is_some_and(|s| s.bytes().all(|b| b.is_ascii_digit()))
        {
            continue;
        }
        match std::fs::metadata(e.path().join("ns/net")) {
            Ok(m) => {
                use std::os::unix::fs::MetadataExt;
                if (m.dev(), m.ino()) == (id.dev, id.ino) {
                    return Err(cleanup_error("active_namespace_user", None));
                }
            }
            Err(e) if matches!(e.raw_os_error(), Some(libc::ENOENT | libc::ESRCH)) => {}
            Err(error) => {
                return Err(cleanup_error(
                    "proc_namespace_metadata",
                    error.raw_os_error(),
                ));
            }
        }
    }
    // The validated bind-mount FD itself holds a mount reference. Release only
    // this local proof handle after identity and zero-user checks, before normal
    // unmount. The locked root0700 directory/name remain retained and protected;
    // never lazy-detach, force-unmount or fall back to another path.
    drop(fd);
    let target = c(&format!("/proc/self/fd/{}/{}", dir.as_raw_fd(), name))?;
    // SAFETY: descriptor-relative exact retained record name verified as nsfs;
    // no process uses this namespace. Test-only, not generic production cleanup.
    if unsafe { libc::umount2(target.as_ptr(), 0) } < 0 {
        return Err(cleanup_error(
            "unmount",
            std::io::Error::last_os_error().raw_os_error(),
        ));
    }
    fs::unlinkat(dir, name, fs::AtFlags::empty())
        .map_err(|error| cleanup_error("unlink_exact_pin", Some(error.raw_os_error())))
}
#[cfg(test)]
pub(super) fn lab_parent_loss(
    a: &super::Admission,
    tx: &super::owned::Transaction<'_>,
    ns: &super::owned::OwnedNamespaces,
) -> Result<Child> {
    process::single_threaded()?;
    let (r, w) = pipe()?;
    // SAFETY: test-only fixed launch, one task and no runtime; child never returns
    // or runs destructors for borrowed parent admission/ownership descriptors.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(Error::ChildFailed);
    }
    if pid == 0 {
        unsafe {
            libc::close(r.as_raw_fd());
        }
        let _control_inventory = super::inventory::Registration::owned(&[w.as_fd()]);
        let result = super::execution::VerifiedProgram::probe(a)
            .and_then(|p| super::execution::launch(a, tx, ns, p));
        match result {
            Ok(_running) => {
                let _ = write_byte(&w, 1);
                let _ = write_byte(&w, 2);
                let _ = write_byte(&w, 4);
                let _ = write_byte(&w, 8);
                loop {
                    std::thread::sleep(Duration::from_secs(1));
                }
            }
            Err(e) => {
                report_failure(&w, e);
                die(116);
            }
        }
    }
    drop(w);
    let pinned = pidfd(pid)?;
    let inventory = super::inventory::Registration::owned(&[pinned.as_fd(), r.as_fd()])?;
    let mut child = Child {
        _inventory: inventory,
        release_inventory: None,
        pid: pid as u32,
        pidfd: pinned,
        release: None,
        health: r,
        reaped: false,
    };
    child.ready()?;
    Ok(child)
}
#[cfg(test)]
pub(super) fn probe_container_reap() {
    loop {
        // SAFETY: test container PID1 reaps only direct/adopted children, never host tasks.
        let p = unsafe { libc::waitpid(-1, std::ptr::null_mut(), libc::WNOHANG) };
        if p <= 0 {
            break;
        }
    }
}
#[cfg(test)]
pub(super) fn probe_failure(error: Error) {
    // SAFETY: post-exec probe owns fixed health FD3; only fixed enum byte emitted.
    let fd = unsafe { BorrowedFd::borrow_raw(3) };
    report_failure(fd, error);
}
// ---- Offline policy, descriptor-fault and monotonic-deadline regressions ----
#[cfg(test)]
mod policy_tests {
    use super::*;
    #[test]
    fn descriptor_scan_errors_and_malformed_names_are_fatal() {
        assert_eq!(
            descriptor_numbers(
                [
                    Ok(b"0".to_vec()),
                    Err(Error::DescriptorInventory),
                    Ok(b"9".to_vec())
                ],
                9
            ),
            Err(Error::DescriptorInventory)
        );
        for invalid in [b"x".as_slice(), b"-1", b"", b"2147483648", b"\xff"] {
            assert_eq!(
                descriptor_numbers([Ok(b"9".to_vec()), Ok(invalid.to_vec())], 9),
                Err(Error::DescriptorInventory)
            );
        }
        // Scan FD must itself be present exactly once, never an arbitrary entry
        // silently ignored because it disappeared or failed to parse.
        assert_eq!(
            descriptor_numbers([Ok(b"0".to_vec())], 9),
            Err(Error::DescriptorInventory)
        );
        assert_eq!(
            descriptor_numbers([Ok(b"9".to_vec()), Ok(b"9".to_vec())], 9),
            Err(Error::DescriptorInventory)
        );
        assert_eq!(
            descriptor_numbers(
                [
                    Ok(b".".to_vec()),
                    Ok(b"..".to_vec()),
                    Ok(b"0".to_vec()),
                    Ok(b"9".to_vec())
                ],
                9
            ),
            Ok([0].into())
        );
    }
    #[test]
    fn descriptor_close_failure_cannot_reach_success_and_final_inventory_is_exact() {
        let mut visited = Vec::new();
        assert_eq!(
            close_numbers([0, 1, 2, 3, 40, 41].into(), &[3], |fd| {
                visited.push(fd);
                Err(Error::DescriptorClose)
            }),
            Err(Error::DescriptorClose)
        );
        assert_eq!(visited, [40]);
        assert_eq!(checked_close(-1), Err(Error::DescriptorClose));
        assert_eq!(supervisor_inventory([0, 1, 2, 3].into(), 3), Ok(()));
        for fds in [vec![0, 1, 2, 3, 40], vec![0, 1, 3], vec![0, 1, 2]] {
            assert_eq!(
                supervisor_inventory(fds.into_iter().collect(), 3),
                Err(Error::DescriptorInventory)
            );
        }
        assert_eq!(
            supervisor_inventory([0, 1, 2].into(), 2),
            Err(Error::DescriptorInventory)
        );
    }
    #[test]
    fn repeated_signals_never_extend_shutdown_or_worker_exit_deadline() {
        let now = Instant::now();
        let first = now + Duration::from_millis(500);
        let mut deadline = None;
        earliest_deadline(&mut deadline, first);
        for later in 1..100 {
            earliest_deadline(&mut deadline, first + Duration::from_millis(later * 50));
            assert_eq!(deadline, Some(first));
        }
        earliest_deadline(&mut deadline, now);
        earliest_deadline(&mut deadline, first);
        assert_eq!(deadline, Some(now));
    }
    fn verdict(arch: u32, nr: u32, arg: u64) -> u32 {
        verdict_program(&filter(), arch, nr, arg)
    }
    fn verdict_program(instructions: &[libc::sock_filter], arch: u32, nr: u32, arg: u64) -> u32 {
        let mut pc = 0;
        let mut accumulator = 0;
        for _ in 0..2048 {
            let i = &instructions[pc];
            match i.code {
                0x20 => {
                    accumulator = match i.k {
                        0 => nr,
                        4 => arch,
                        16 => arg as u32,
                        20 => (arg >> 32) as u32,
                        _ => panic!("unexpected load"),
                    };
                    pc += 1;
                }
                0x15 => {
                    pc += 1 + if accumulator == i.k {
                        i.jt as usize
                    } else {
                        i.jf as usize
                    }
                }
                0x06 => return i.k,
                _ => panic!("unexpected instruction"),
            }
        }
        panic!("unbounded filter")
    }
    #[test]
    fn wait_role_has_no_path_network_exec_or_fork_authority() {
        let arch = if cfg!(target_arch = "x86_64") {
            0xc000003e
        } else {
            0xc00000b7
        };
        for nr in [
            libc::SYS_openat,
            libc::SYS_newfstatat,
            libc::SYS_readlinkat,
            libc::SYS_socket,
            libc::SYS_clone,
            libc::SYS_execveat,
            libc::SYS_mount,
            libc::SYS_unshare,
            libc::SYS_setns,
            libc::SYS_capset,
            libc::SYS_prctl,
        ] {
            assert_eq!(
                verdict_program(&wait_filter(), arch, nr as u32, 0),
                0x00050001
            );
        }
        // Actual post-install wait-role sequence: verify, announce readiness,
        // close health, poll/reap/forward, then _exit.
        assert_eq!(
            verdict_program(
                &wait_filter(),
                arch,
                libc::SYS_prctl as u32,
                libc::PR_GET_SECCOMP as u64
            ),
            0x7fff0000
        );
        for option in [
            libc::PR_SET_SECCOMP,
            libc::PR_SET_NO_NEW_PRIVS,
            libc::PR_SET_DUMPABLE,
            libc::PR_SET_SECUREBITS,
        ] {
            assert_eq!(
                verdict_program(&wait_filter(), arch, libc::SYS_prctl as u32, option as u64),
                0x00050001
            );
        }
        assert_eq!(
            verdict_program(
                &wait_filter(),
                arch,
                libc::SYS_prctl as u32,
                (1u64 << 32) | libc::PR_GET_SECCOMP as u64
            ),
            0x00050001
        );
        for nr in [
            libc::SYS_write,
            libc::SYS_close,
            libc::SYS_ppoll,
            libc::SYS_clock_gettime,
            libc::SYS_exit_group,
        ] {
            assert_eq!(
                verdict_program(&wait_filter(), arch, nr as u32, 0),
                0x7fff0000
            );
        }
        for nr in [
            libc::SYS_wait4,
            libc::SYS_rt_sigtimedwait,
            libc::SYS_pidfd_send_signal,
        ] {
            assert_eq!(
                verdict_program(&wait_filter(), arch, nr as u32, 0),
                0x7fff0000
            );
        }
    }
    #[test]
    fn profile_denies_network_namespaces_privilege_and_exec_path_syscalls() {
        let arch = if cfg!(target_arch = "x86_64") {
            0xc000003e
        } else {
            0xc00000b7
        };
        // Actual post-filter FD/proc scan uses explicit openat + Dir::new
        // getdents64, fstat/fcntl/readlink and close; legacy open is not admitted.
        for nr in [
            libc::SYS_openat,
            libc::SYS_getdents64,
            libc::SYS_fstat,
            libc::SYS_fcntl,
            libc::SYS_readlinkat,
            libc::SYS_close,
            libc::SYS_execveat,
            libc::SYS_rt_sigprocmask,
            libc::SYS_clock_nanosleep,
        ] {
            assert_eq!(verdict(arch, nr as u32, 0), 0x7fff0000);
        }
        #[cfg(target_arch = "x86_64")]
        assert_eq!(verdict(arch, libc::SYS_open as u32, 0), 0x00050001);
        for nr in [
            libc::SYS_socket,
            libc::SYS_connect,
            libc::SYS_mount,
            libc::SYS_setns,
            libc::SYS_unshare,
            libc::SYS_capset,
            libc::SYS_ptrace,
            libc::SYS_bpf,
            libc::SYS_open_by_handle_at,
            libc::SYS_execve,
            libc::SYS_io_uring_setup,
            libc::SYS_userfaultfd,
        ] {
            assert_eq!(verdict(arch, nr as u32, 0), 0x00050001);
        }
        assert_eq!(verdict(arch, libc::SYS_execveat as u32, 0), 0x7fff0000);
        assert_eq!(
            verdict(arch, libc::SYS_clone as u32, libc::SIGCHLD as u64),
            0x7fff0000
        );
        for flags in [
            libc::CLONE_NEWUSER | libc::SIGCHLD,
            libc::CLONE_NEWNET | libc::SIGCHLD,
            libc::CLONE_VM | libc::SIGCHLD,
            libc::CLONE_PTRACE | libc::SIGCHLD,
        ] {
            assert_eq!(
                verdict(arch, libc::SYS_clone as u32, flags as u64),
                0x00050001
            );
        }
        assert_eq!(
            verdict(
                arch,
                libc::SYS_clone as u32,
                (1u64 << 32) | libc::SIGCHLD as u64
            ),
            0x00050001
        );
        assert_eq!(verdict(arch ^ 1, libc::SYS_read as u32, 0), 0x80000000);
        assert_eq!(
            verdict(arch, 0x40000000 | libc::SYS_read as u32, 0),
            0x00050001
        );
    }
}
