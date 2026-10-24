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
        if !wait_ready(&self.health, Duration::from_secs(5))? {
            return Err(Error::Deadline);
        }
        match read_byte(&self.health)? {
            1 => Ok(()),
            201 => Err(Error::NamespaceOperation),
            202 => Err(Error::MountIsolation),
            210 => Err(Error::MountContainerRoot),
            211 => Err(Error::MountPrivate),
            212 => Err(Error::MountTmp),
            213 => Err(Error::MountExecutable),
            220 => Err(Error::MountExecutableClone),
            221 => Err(Error::MountStateClone),
            218 => Err(Error::MountExecutableBind),
            219 => Err(Error::MountExecutableReadonly),
            214 => Err(Error::MountState),
            215 => Err(Error::MountPivot),
            216 => Err(Error::MountProc),
            217 => Err(Error::MountReadonly),
            203 => Err(Error::DescriptorPolicy),
            204 => Err(Error::CapabilityPolicy),
            205 => Err(Error::ConfinementPolicy),
            _ => Err(Error::ChildFailed),
        }
    }
    pub fn signal(&self, sig: i32) -> Result<()> {
        send(&self.pidfd, sig)
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
    let executable_tree = rustix::mount::open_tree(
        container.executable,
        "",
        rustix::mount::OpenTreeFlags::OPEN_TREE_CLONE
            | rustix::mount::OpenTreeFlags::OPEN_TREE_CLOEXEC
            | rustix::mount::OpenTreeFlags::AT_EMPTY_PATH,
    )
    .map_err(|_| Error::MountExecutableClone)?;
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
            parent_death(parent)?;
            if !wait_ready(&release_r, Duration::from_secs(5))? || read_byte(&release_r)? != 1 {
                return Err(Error::PlacementFailed);
            }
            container_stage(
                container,
                data,
                executable_tree.as_fd(),
                state_tree.as_fd(),
                health_w.as_fd(),
            )
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
    executable_tree: BorrowedFd<'_>,
    state: BorrowedFd<'_>,
    health: BorrowedFd<'_>,
) -> Result<()> {
    let signals = blocked_signals()?;
    enter(container.pid, libc::CLONE_NEWPID)?;
    // SAFETY: single-task child, no runtime; setns PID-for-children becomes the
    // active container PID namespace only in this next intermediate child.
    let inner = unsafe { libc::fork() };
    if inner < 0 {
        return Err(Error::ChildFailed);
    }
    if inner == 0 {
        let r = (|| {
            parent_death(0)?;
            setup(container, data, executable_tree, state, health)
        })();
        if let Err(e) = r {
            report_failure(health, e);
            die(118);
        }
        die(0);
    }
    let fd = pidfd(inner)?;
    forward_and_wait(inner, &fd, &signals)
}
fn setup(
    container: ContainerFds<'_>,
    data: BorrowedFd<'_>,
    executable_tree: BorrowedFd<'_>,
    state: BorrowedFd<'_>,
    health: BorrowedFd<'_>,
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
    attach_tree(executable_tree, "/tmp/root/bin/vprouter-worker")
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
        .map_err(|_| Error::DescriptorPolicy)?;
    for fd in 0..3 {
        dup_fixed(&null, fd, false)?;
    }
    let signals = blocked_signals()?;
    let init_parent = pidfd(std::process::id() as i32)?;
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
            init_root()?;
            supervise(health, &signals, init_parent.as_fd())
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
    forward_and_wait(init, &initfd, &signals)
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
fn pending(set: &libc::sigset_t) -> i32 {
    let t = libc::timespec {
        tv_sec: 0,
        tv_nsec: 50_000_000,
    }; // SAFETY: initialized fixed sigset and bounded timespec, no handlers.
    unsafe { libc::sigtimedwait(set, std::ptr::null_mut(), &t) }
}
fn forward_and_wait(pid: i32, fd: &OwnedFd, set: &libc::sigset_t) -> Result<()> {
    let mut deadline = None;
    loop {
        let sig = pending(set);
        if matches!(sig, libc::SIGTERM | libc::SIGINT | libc::SIGHUP) {
            let _ = send(fd, sig);
            deadline = Some(Instant::now() + Duration::from_millis(700));
        }
        if deadline.is_some_and(|d| Instant::now() >= d) {
            let _ = send(fd, libc::SIGKILL);
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
    }
}
fn supervise(health: BorrowedFd<'_>, set: &libc::sigset_t, parent: BorrowedFd<'_>) -> Result<()> {
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
    // SAFETY: PID1 is single-task, fixed child exec path or _exit only.
    let worker = unsafe { libc::fork() };
    if worker < 0 {
        return Err(Error::ChildFailed);
    }
    if worker == 0 {
        let result = worker_exec(executable.as_fd(), health);
        let _ = result;
        die(119);
    }
    // Close ALL inherited host handles in PID1 too; Rust FD owners are never
    // dropped here. Namespace init must not remain a privileged escape target.
    lsm_supervisor()?;
    reduce_privileges()?;
    if wait_ready(parent, Duration::ZERO)? {
        return Err(Error::ChildFailed);
    }
    close_except(&[])?;
    seccomp()?;
    let mut deadline = None;
    let mut main_exited = false;
    loop {
        let sig = pending(set);
        if matches!(sig, libc::SIGTERM | libc::SIGINT | libc::SIGHUP) {
            // SAFETY: PID1 private namespace; -1 can only address its own descendants.
            unsafe {
                libc::kill(-1, sig);
            }
            deadline = Some(Instant::now() + Duration::from_millis(500));
        }
        if deadline.is_some_and(|d| Instant::now() >= d) {
            unsafe {
                libc::kill(-1, libc::SIGKILL);
            }
        }
        loop {
            let mut status = 0; // SAFETY: wait only any direct/adopted children in this private PID namespace.
            let p = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
            if p == worker {
                main_exited = true;
                deadline = Some(Instant::now());
            }
            if p == 0 {
                break;
            }
            if p < 0 {
                return if main_exited {
                    Ok(())
                } else {
                    Err(Error::ChildFailed)
                };
            }
        }
    }
}
fn dup_fixed(fd: impl AsFd, to: i32, cloexec: bool) -> Result<()> {
    // SAFETY: fixed child-only targets, duplicate first to avoid source/target collisions.
    let saved = unsafe { libc::fcntl(fd.as_fd().as_raw_fd(), libc::F_DUPFD_CLOEXEC, 100) };
    if saved < 0 {
        return Err(Error::DescriptorPolicy);
    }
    let result = cv(
        unsafe { libc::dup3(saved, to, if cloexec { libc::O_CLOEXEC } else { 0 }) },
        Error::DescriptorPolicy,
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
    let fds: Vec<_> = std::fs::read_dir("/proc/self/fd")
        .map_err(|_| Error::DescriptorPolicy)?
        .filter_map(|e| e.ok()?.file_name().to_str()?.parse::<i32>().ok())
        .collect();
    for fd in fds {
        if fd > 2 && !keep.contains(&fd) {
            // SAFETY: child owns its descriptor table exclusively and will never drop inherited owners.
            unsafe {
                libc::close(fd);
            }
        }
    }
    Ok(())
}
fn reduce_privileges() -> Result<()> {
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
    verify_credentials()
}
pub(super) fn verify_credentials() -> Result<()> {
    let s = std::fs::read_to_string("/proc/self/status").map_err(|_| Error::CapabilityPolicy)?;
    for (key, expected) in [
        ("Uid:", vec!["65534"; 4]),
        ("Gid:", vec!["65534"; 4]),
        ("Groups:", vec![]),
        ("NoNewPrivs:", vec!["1"]),
    ] {
        let parts = s
            .lines()
            .find_map(|l| l.strip_prefix(key))
            .ok_or(Error::CapabilityPolicy)?
            .split_whitespace()
            .collect::<Vec<_>>();
        if parts != expected {
            return Err(Error::CapabilityPolicy);
        }
    }
    for key in ["CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:"] {
        let v = s
            .lines()
            .find_map(|l| l.strip_prefix(key))
            .ok_or(Error::CapabilityPolicy)?
            .trim();
        if u64::from_str_radix(v, 16).ok() != Some(0) {
            return Err(Error::CapabilityPolicy);
        }
    }
    // SAFETY: GET operations have scalar results and no pointer parameters.
    if unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) } != 1
        || unsafe { libc::prctl(libc::PR_GET_SECUREBITS, 0, 0, 0, 0) } != 0xef
    {
        return Err(Error::CapabilityPolicy);
    }
    Ok(())
}
fn lsm_current() -> Result<()> {
    let s =
        std::fs::read_to_string("/proc/self/attr/current").map_err(|_| Error::ConfinementPolicy)?;
    if s.trim() != "docker-default (enforce)" {
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
pub(super) fn policy_digest() -> String {
    let mut bytes = super::execution::POLICY.as_bytes().to_vec();
    for instruction in filter() {
        bytes.extend_from_slice(&instruction.code.to_le_bytes());
        bytes.push(instruction.jt);
        bytes.push(instruction.jf);
        bytes.extend_from_slice(&instruction.k.to_le_bytes());
    }
    vprouter_linux::sha256(&bytes)
}
fn seccomp() -> Result<()> {
    let f = filter();
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
fn worker_exec(executable: BorrowedFd<'_>, health: BorrowedFd<'_>) -> Result<()> {
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
    close_except(&[3, 4])?;
    lsm_exec()?;
    reduce_privileges()?;
    if unsafe { libc::getppid() } != 1 {
        return Err(Error::ChildFailed);
    }
    seccomp()?;
    // Final inventory exact0..4; executable4 is CLOEXEC, health3 explicitly not.
    final_fds(true)?;
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
}
fn final_fds(before_exec: bool) -> Result<()> {
    let expected = if before_exec { 5 } else { 4 };
    for fd in 0..expected {
        // SAFETY: scalar descriptor flags queries.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags < 0 || flags & libc::FD_CLOEXEC != if fd == 4 { libc::FD_CLOEXEC } else { 0 } {
            return Err(Error::DescriptorPolicy);
        }
        let target = std::fs::read_link(format!("/proc/self/fd/{fd}"))
            .map_err(|_| Error::DescriptorPolicy)?;
        let name = target.as_os_str().as_encoded_bytes();
        if fd <= 2 && name != b"/dev/null"
            || fd == 3 && !name.starts_with(b"pipe:[")
            || fd == 4 && name != b"/bin/vprouter-worker"
        {
            return Err(Error::DescriptorPolicy);
        }
    }
    let entries: Vec<_> = std::fs::read_dir("/proc/self/fd")
        .map_err(|_| Error::DescriptorPolicy)?
        .collect();
    // read_dir temporarily opens one extra fd; no gap/external fd is permitted.
    if entries.len() != expected as usize + 1 {
        return Err(Error::DescriptorPolicy);
    }
    Ok(())
}
#[cfg(test)]
pub(super) fn probe_verify() -> Result<()> {
    verify_credentials()?;
    lsm_current()?;
    final_fds(false)?;
    let s = std::fs::read_to_string("/proc/self/status").map_err(|_| Error::ConfinementPolicy)?;
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
    if std::fs::read_to_string("/etc/resolv.conf").map_err(|_| Error::MountIsolation)?
        != "nameserver 192.0.2.53\noptions attempts:1 timeout:1\n"
    {
        return Err(Error::MountIsolation);
    }
    for path in [
        "/old",
        "/run/netns",
        "/var/run/docker.sock",
        "/sys/fs/cgroup",
    ] {
        if std::fs::metadata(path).is_ok() {
            return Err(Error::MountIsolation);
        }
    }
    std::fs::write("/state/probe", b"selected-exit-only").map_err(|_| Error::MountIsolation)?;
    if std::fs::write("/etc/forbidden", b"x").is_ok() {
        return Err(Error::MountIsolation);
    }
    // Adversarial proc-root discovery sees only PID1 and own descendants, never
    // host/container/peer roots. Every visible numeric process has this root.
    for entry in std::fs::read_dir("/proc").map_err(|_| Error::MountIsolation)? {
        let e = entry.map_err(|_| Error::MountIsolation)?;
        if e.file_name()
            .to_str()
            .is_some_and(|s| s.bytes().all(|b| b.is_ascii_digit()))
        {
            if let Ok(root) = std::fs::read_link(e.path().join("root"))
                && root != std::path::Path::new("/")
            {
                return Err(Error::MountIsolation);
            }
            if e.path().join("root/run/netns").exists() {
                return Err(Error::MountIsolation);
            }
        }
    }
    Ok(())
}
#[cfg(test)]
pub(super) fn probe_descendant() -> Result<()> {
    // SAFETY: one-task post-exec test probe, child only freezes then _exits.
    let p = unsafe { libc::fork() };
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
pub(super) fn lab_unpin(dir: BorrowedFd<'_>, name: &str, id: super::owned::Identity) -> Result<()> {
    let fd = fs::openat(
        dir,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| Error::OwnershipMismatch)?;
    if super::owned::Identity::network(&fd)? != id {
        return Err(Error::OwnershipMismatch);
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
                    return Err(Error::OwnershipMismatch);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(Error::OwnershipMismatch),
        }
    }
    let target = c(&format!("/proc/self/fd/{}/{}", dir.as_raw_fd(), name))?;
    // SAFETY: descriptor-relative exact retained record name verified as nsfs;
    // no process uses this namespace. Test-only, not generic production cleanup.
    cv(
        unsafe { libc::umount2(target.as_ptr(), 0) },
        Error::OwnershipMismatch,
    )?;
    fs::unlinkat(dir, name, fs::AtFlags::empty()).map_err(|_| Error::OwnershipMismatch)
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
mod policy_tests {
    use super::*;
    fn verdict(arch: u32, nr: u32, arg: u64) -> u32 {
        let instructions = filter();
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
    fn profile_denies_network_namespaces_privilege_and_exec_path_syscalls() {
        let arch = if cfg!(target_arch = "x86_64") {
            0xc000003e
        } else {
            0xc00000b7
        };
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
