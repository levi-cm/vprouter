//! Reviewed unsafe Linux boundary, with shared primitives in kernel_base.rs.
//! No public API, raw descriptors or arbitrary exec.
//!
//! Safety contracts: each fork/namespace operation requires verified one-task
//! execution and no live async runtime. All passed FDs borrow owned admission
//! handles, outlive setup, and are never closed through those owners. Children
//! terminate with _exit after any setup/FD error; they never unwind into owners
//! whose descriptors were closed. All C pointers below borrow live fixed strings
//! or initialized buffers across synchronous syscalls only. No signal handlers
//! access Rust state: blocked signals are synchronously consumed by PID1.
pub(crate) mod bootstrap;
#[cfg(test)]
mod capacity_lab;
pub(super) mod cleanup;
pub(super) mod docker_query;
pub(super) mod fresh_transport;
pub(super) mod fresh_transport_mount;
pub(super) mod host_audit;
pub(crate) mod host_link;
pub(super) mod inspection;
pub(super) mod namespace_attachment;
pub(crate) mod netfilter_role;
pub(crate) mod producer_binding;
pub(super) mod producer_creation;
pub(super) mod retirement;
pub(super) mod secret;
pub(super) mod wireguard_role;
use super::kernel_base::*;
use super::{Error, Result, process};
use rustix::fs::{self, Mode, OFlags};
use std::{
    ffi::{CStr, CString},
    os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd},
    time::{Duration, Instant},
};
// ---- Fixed diagnostics and checked syscall primitives ----

pub(super) fn descriptor_cloexec(fd: i32) -> Result<bool> {
    // Read only. This borrows no Rust owner and never adopts or duplicates the
    // observed self descriptor. EBADF and every other error fail closed.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(Error::DescriptorPolicy);
    }
    Ok(flags & libc::FD_CLOEXEC != 0)
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
        Error::NetworkOperation => 207,
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
pub(super) fn network() -> Result<OwnedFd> {
    fs::open(
        "/proc/thread-self/ns/net",
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| Error::NamespaceMismatch)
}
/// Open retained native descriptors synchronously in the intended namespace.
/// No async runtime/task exists; the caller never keeps SYS_ADMIN in a worker.
pub(super) fn network_scope<T>(handle: impl AsFd, f: impl FnOnce() -> Result<T>) -> Result<T> {
    process::single_threaded()?;
    let old = network()?;
    enter(handle.as_fd(), libc::CLONE_NEWNET)?;
    struct Restore(OwnedFd);
    impl Drop for Restore {
        fn drop(&mut self) {
            if enter(self.0.as_fd(), libc::CLONE_NEWNET).is_err() {
                die(122);
            }
        }
    }
    let restore = Restore(old);
    if super::owned::Identity::network(network()?)? != super::owned::Identity::network(&handle)? {
        return Err(Error::NamespaceMismatch);
    }
    let result = f();
    process::single_threaded()?;
    drop(restore);
    result
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
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ActualRole {
    Observer,
    Monitor,
    OperationalMonitor,
    Daemon,
}
#[derive(Clone, Copy)]
pub(super) struct Actual<'a> {
    pub role: ActualRole,
    pub daemon_configuration: DaemonConfiguration,
    pub executable: BorrowedFd<'a>,
    pub ca: BorrowedFd<'a>,
    pub placement: Option<BorrowedFd<'a>>,
    pub localapi: Option<BorrowedFd<'a>>,
    pub tun: Option<BorrowedFd<'a>>,
    pub resolver: std::net::Ipv4Addr,
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
    native: Option<ChildNative>,
}
pub(super) struct ChildNative {
    _capacity: ChildCapacity,
    pid: u32,
    pidfd: OwnedFd,
    release: Option<OwnedFd>,
    health: OwnedFd,
    _inventory: super::inventory::Registration,
    release_inventory: Option<super::inventory::Registration>,
    reaped: bool,
    control: Option<OwnedFd>,
    retained_pins: Vec<OwnedFd>,
    retained_inventory: Vec<super::inventory::Registration>,
    producer: Option<super::producer::Drain>,
    drain_error: Option<Error>,
    descendants: bool,
    lease: Option<super::owned::MutatorLease>,
    #[cfg(test)]
    actual_negative: Option<ActualRole>,
}
struct ChildCapacity {
    charge: std::rc::Rc<ChildCharge>,
}
struct ChildCharge {
    creator: u32,
    retired: std::cell::Cell<bool>,
}
thread_local! { static LIVE_CHILDREN: std::cell::Cell<(u32, usize)> = const { std::cell::Cell::new((0, 0)) }; }
fn live_child_count() -> usize {
    LIVE_CHILDREN.with(|count| {
        let (creator, n) = count.get();
        if creator == std::process::id() { n } else { 0 }
    })
}
#[cfg(test)]
pub(crate) fn lab_live_child_capacity() -> usize {
    live_child_count()
}
impl ChildCapacity {
    fn created() -> Self {
        let creator = std::process::id();
        let count = live_child_count();
        LIVE_CHILDREN.with(|value| value.set((creator, count + 1)));
        Self {
            charge: std::rc::Rc::new(ChildCharge {
                creator,
                retired: std::cell::Cell::new(false),
            }),
        }
    }
}
impl ChildCharge {
    fn require_live_charge(&self) -> Result<()> {
        if self.creator != std::process::id() || self.retired.get() {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
    fn retire(&self) -> Result<()> {
        self.require_live_charge()?;
        self.retired.set(true);
        LIVE_CHILDREN.with(|count| {
            let (creator, n) = count.get();
            debug_assert_eq!(creator, self.creator);
            debug_assert!(n > 0);
            count.set((creator, n - 1));
        });
        Ok(())
    }
}
impl Drop for ChildCharge {
    fn drop(&mut self) {
        if self.creator == std::process::id() && !self.retired.get() {
            let _ = self.retire();
        }
    }
}
impl std::ops::Deref for Child {
    type Target = ChildNative;
    fn deref(&self) -> &ChildNative {
        self.native.as_ref().expect("live child owner")
    }
}
impl std::ops::DerefMut for Child {
    fn deref_mut(&mut self) -> &mut ChildNative {
        self.native.as_mut().expect("live child owner")
    }
}
impl Child {
    fn from_native(native: ChildNative) -> Self {
        Self {
            native: Some(native),
        }
    }
    pub(super) fn publisher_socket(&self) -> Result<&OwnedFd> {
        self.control.as_ref().ok_or(Error::DescriptorPolicy)
    }
    pub(super) fn bind_producer_drain(&mut self, drain: super::producer::Drain) -> Result<()> {
        if self.release.is_none() || self.producer.is_some() {
            return Err(Error::OwnershipMismatch);
        }
        self.producer = Some(drain);
        Ok(())
    }
    pub(super) fn retain_lease(&mut self, lease: super::owned::MutatorLease) -> Result<()> {
        self.require_placement_gate()?;
        if self.lease.is_some() {
            return Err(Error::OwnershipMismatch);
        }
        self.lease = Some(lease);
        Ok(())
    }
    pub fn pid(&self) -> u32 {
        self.pid
    }
    pub fn require_live(&self) -> Result<()> {
        if self._capacity.charge.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        if self.reaped || wait_ready(&self.pidfd, Duration::ZERO)? {
            return Err(Error::PlacementFailed);
        }
        Ok(())
    }
    /// Placement can move only this still-unreleased, live, unreaped child.
    /// The retained pidfd pins identity; no PID-only or caller proof is accepted.
    pub fn require_placement_gate(&self) -> Result<()> {
        if self._capacity.charge.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        if self.release.is_none() || self.reaped || wait_ready(&self.pidfd, Duration::ZERO)? {
            return Err(Error::PlacementFailed);
        }
        Ok(())
    }
    pub fn release(&mut self) -> Result<()> {
        self.require_placement_gate()?;
        let f = self.release.take().ok_or(Error::ChildFailed)?;
        drop(self.release_inventory.take());
        self.descendants = true;
        write_byte(&f, 1)
    }
    pub fn ready(&mut self) -> Result<()> {
        self.require_live()?;
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
                #[cfg(test)]
                60 => self.actual_negative = Some(ActualRole::Daemon),
                #[cfg(test)]
                61 => self.actual_negative = Some(ActualRole::Observer),
                #[cfg(test)]
                62 => self.actual_negative = Some(ActualRole::Monitor),
                #[cfg(test)]
                63 => self.actual_negative = Some(ActualRole::OperationalMonitor),
                #[cfg(test)]
                255 => {
                    let role = read_byte(&self.health)?;
                    let operation = read_byte(&self.health)?;
                    let errno = read_byte(&self.health)?;
                    eprintln!(
                        "LAB_LSM_OPERATION_FAILURE role={} operation={} reason={}",
                        match role {
                            1 => "daemon_supervisor",
                            2 => "observer_supervisor",
                            3 => "monitor_supervisor",
                            _ => "probe_supervisor",
                        },
                        match operation {
                            1 => "changeprofile_write",
                            _ => "current_label_verify",
                        },
                        match errno {
                            1 => "readonly",
                            2 => "permission",
                            3 => "access",
                            4 => "missing",
                            _ => "other",
                        }
                    );
                    return Err(Error::ConfinementPolicy);
                }
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
                207 => return Err(Error::NetworkOperation),
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
    /// Setup completion is not daemon health or guard readiness.
    pub fn setup_complete(&mut self) -> Result<()> {
        self.ready()
    }
    #[cfg(test)]
    pub fn require_actual_negative(&self, role: ActualRole) -> Result<()> {
        if self.actual_negative != Some(role) {
            return Err(Error::ConfinementPolicy);
        }
        Ok(())
    }
    pub fn signal(&self, sig: i32) -> Result<()> {
        if self._capacity.charge.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        send(&self.pidfd, sig)
    }
    #[cfg(test)]
    pub fn try_wait_success(&mut self) -> Result<bool> {
        if self._capacity.charge.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
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
    pub fn try_wait_terminal(&mut self) -> Result<bool> {
        if self._capacity.charge.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        if self.reaped {
            return Ok(true);
        }
        if !wait_ready(&self.pidfd, Duration::ZERO)? {
            return Ok(false);
        }
        let mut status = 0;
        // SAFETY: exact retained unreaped direct child. No signal or fallback
        // is sent; a container-death test observes the natural terminal status.
        if unsafe { libc::waitpid(self.pid as i32, &mut status, 0) } != self.pid as i32 {
            return Err(Error::ChildFailed);
        }
        self.reaped = true;
        if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
            Ok(true)
        } else {
            Err(Error::ChildFailed)
        }
    }
    #[cfg(test)]
    pub fn kill_gated(&mut self) -> Result<()> {
        self.signal(libc::SIGKILL)?;
        // Leave the dead child unreaped until normal failed-placement cleanup;
        // its numeric PID cannot be reused before the cgroup write is attempted.
        if wait_ready(&self.pidfd, Duration::from_secs(3))? {
            Ok(())
        } else {
            Err(Error::Deadline)
        }
    }
    fn reap(&mut self) -> Result<()> {
        if self._capacity.charge.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
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
        if self._capacity.charge.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        let _ = send(&self.pidfd, libc::SIGKILL);
        self.reap()
    }
}
impl Drop for Child {
    fn drop(&mut self) {
        let Some(native) = self.native.take() else {
            return;
        };
        if native._capacity.charge.creator != std::process::id() {
            // Only fork-copied handles leave here; the creator retains originals.
            return;
        }
        // No bounded timeout, signal success or direct-root exit can release a
        // producer's descendant ownership. Poll every retained bundle separately.
        if native.reaped && native.producer.is_none() && !native.descendants {
            return;
        }
        if !native.reaped {
            let _ = send_or_exited(native.pidfd.as_fd(), libc::SIGKILL);
        }
        RETIRED_CHILDREN.with(|children| children.borrow_mut().push(native));
    }
}
thread_local! {
    static RETIRED_CHILDREN: std::cell::RefCell<Vec<ChildNative>> = const { std::cell::RefCell::new(Vec::new()) };
}
fn poll_retired_children() -> Result<()> {
    RETIRED_CHILDREN.with(|children| {
        let mut children = children.borrow_mut();
        let mut index = 0;
        while index < children.len() {
            let child = &mut children[index];
            if child._capacity.charge.creator != std::process::id() {
                index += 1;
                continue;
            }
            let result = (|| {
                if !child.reaped {
                    if !wait_ready(&child.pidfd, Duration::ZERO)? {
                        return Ok(false);
                    }
                    let mut status = 0;
                    // SAFETY: exact original direct child, still pinned/unreaped.
                    if unsafe { libc::waitpid(child.pid as i32, &mut status, libc::WNOHANG) }
                        != child.pid as i32
                    {
                        return Err(Error::ChildFailed);
                    }
                    child.reaped = true;
                }
                child
                    .producer
                    .as_ref()
                    .map_or(Ok(!child.descendants), super::producer::Drain::empty)
            })();
            match result {
                Ok(true) => {
                    children.remove(index);
                }
                Ok(false) => index += 1,
                Err(error) => {
                    children[index].drain_error.get_or_insert(error);
                    index += 1;
                }
            }
        }
        Ok(())
    })
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
    spawn_inner(container, data, state, None)
}
pub(super) fn spawn_actual(
    container: ContainerFds<'_>,
    data: BorrowedFd<'_>,
    state: BorrowedFd<'_>,
    actual: Actual<'_>,
) -> Result<Child> {
    spawn_inner(container, data, state, Some(actual))
}
fn spawn_inner(
    container: ContainerFds<'_>,
    data: BorrowedFd<'_>,
    state: BorrowedFd<'_>,
    actual: Option<Actual<'_>>,
) -> Result<Child> {
    process::single_threaded()?;
    // These two fixed sources belong to the host guard's mount namespace.
    // Clone them before setns(container.mount); open_tree cannot clone a source
    // mount that is outside the current mount namespace. Detached trees may be
    // transferred into the new private root without exposing their parents.
    let placement_tree = actual
        .and_then(|a| a.placement)
        .map(clone_tree)
        .transpose()?;
    let localapi_tree = actual
        .and_then(|a| a.localapi)
        .map(clone_tree)
        .transpose()?;
    let actual = actual.map(|a| Actual {
        placement: placement_tree.as_ref().map(AsFd::as_fd),
        localapi: localapi_tree.as_ref().map(AsFd::as_fd),
        ..a
    });
    let state_tree = rustix::mount::open_tree(
        state,
        "",
        rustix::mount::OpenTreeFlags::OPEN_TREE_CLONE
            | rustix::mount::OpenTreeFlags::OPEN_TREE_CLOEXEC
            | rustix::mount::OpenTreeFlags::AT_EMPTY_PATH,
    )
    .map_err(|_| Error::MountStateClone)?;
    let mut tree_fds = vec![state_tree.as_fd()];
    tree_fds.extend(placement_tree.iter().map(AsFd::as_fd));
    tree_fds.extend(localapi_tree.iter().map(AsFd::as_fd));
    let _trees_inventory = super::inventory::Registration::owned(&tree_fds)?;
    let (release_r, release_w) = pipe()?;
    let (health_r, health_w) = pipe()?;
    let health_inventory = super::inventory::Registration::owned(&[health_r.as_fd()])?;
    let release_inventory = super::inventory::Registration::owned(&[release_w.as_fd()])?;
    let parent = std::process::id() as i32;
    // SAFETY: one task and no async runtime; child follows fixed setup only and
    // always _exits, so no duplicated Rust descriptor owners are dropped.
    let (pid, pinned) = fork_with_pidfd()?;
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
            container_stage(
                container,
                data,
                state_tree.as_fd(),
                health_w.as_fd(),
                actual,
            )
        })();
        if let Err(error) = result {
            report_failure(health_w.as_fd(), error);
            die(121);
        }
        die(0);
    }
    drop(release_r);
    drop(health_w);
    let pinned = pinned.ok_or(Error::ChildFailed)?;
    let inventory = match super::inventory::Registration::owned(&[pinned.as_fd()]) {
        Ok(inventory) => inventory,
        Err(error) => {
            retain_registered_fork_with_pins(
                pid,
                pinned,
                health_r,
                None,
                vec![health_inventory, release_inventory],
                vec![release_w],
            );
            return Err(error);
        }
    };
    Ok(Child::from_native(ChildNative {
        _capacity: ChildCapacity::created(),
        _inventory: inventory,
        release_inventory: Some(release_inventory),
        pid: pid as u32,
        pidfd: pinned,
        release: Some(release_w),
        health: health_r,
        reaped: false,
        control: None,
        retained_pins: Vec::new(),
        retained_inventory: vec![health_inventory],
        producer: None,
        drain_error: None,
        descendants: false,
        lease: None,
        #[cfg(test)]
        actual_negative: None,
    }))
}
/// The ready byte precedes the child closing its startup-only descriptor. EOF
/// from this exclusive pipe is the closure witness, within the same deadline.
fn publisher_pipe() -> Result<(OwnedFd, OwnedFd)> {
    let (read, write) = pipe()?;
    fs::fcntl_setfl(&read, OFlags::NONBLOCK).map_err(|_| Error::DescriptorPolicy)?;
    Ok((read, write))
}
fn publisher_ready(ack: impl AsFd, end: Instant) -> Result<()> {
    for expected in [Some(128), None] {
        let remaining = end.saturating_duration_since(Instant::now());
        if remaining.is_zero() || !wait_ready(&ack, remaining)? {
            return Err(Error::Deadline);
        }
        let mut byte = [0];
        let n = rustix::io::read(&ack, &mut byte).map_err(|_| Error::ChildFailed)?;
        if !matches!((expected, n), (Some(value), 1) if byte[0] == value)
            && !(expected.is_none() && n == 0)
        {
            return Err(Error::ChildFailed);
        }
        if Instant::now() >= end {
            return Err(Error::Deadline);
        }
    }
    Ok(())
}
/// Rootless ownership/barrier test, not a claim about the privileged writer role.
#[cfg(test)]
fn lab_idle_child() -> Result<Child> {
    let (read, write) = pipe()?;
    let creator = std::process::id() as i32;
    let (pid, pinned) = fork_with_pidfd()?;
    if pid == 0 {
        let result: Result<()> = (|| {
            parent_death(creator)?;
            close_except(&[write.as_raw_fd()])?;
            write_byte(&write, 1)?;
            loop {
                unsafe { libc::pause() };
            }
        })();
        die(if result.is_ok() { 0 } else { 122 });
    }
    drop(write);
    let pinned = pinned.ok_or(Error::ChildFailed)?;
    let inventory = super::inventory::Registration::owned(&[pinned.as_fd(), read.as_fd()])?;
    let child = Child::from_native(ChildNative {
        _capacity: ChildCapacity::created(),
        pid: pid as u32,
        pidfd: pinned,
        release: None,
        health: read,
        _inventory: inventory,
        release_inventory: None,
        reaped: false,
        control: None,
        retained_pins: Vec::new(),
        retained_inventory: Vec::new(),
        producer: None,
        drain_error: None,
        descendants: false,
        lease: None,
        actual_negative: None,
    });
    if !wait_ready(&child.health, Duration::from_secs(1))? {
        return Err(Error::Deadline);
    }
    Ok(child)
}

#[cfg(test)]
fn lab_child_drop_retention() -> Result<()> {
    process::single_threaded()?;
    super::inventory::verify()?;
    if !early_forks_drained() {
        return Err(Error::Interrupted);
    }
    let child = lab_idle_child()?;
    let reused = child.health.as_raw_fd();
    let sibling = lab_idle_child()?;
    if live_child_count() != 2 {
        return Err(Error::ChildFailed);
    }
    let start = Instant::now();
    drop(child);
    drop(sibling);
    if live_child_count() != 2 {
        return Err(Error::ChildFailed);
    }
    if early_forks_drained() || start.elapsed() > Duration::from_millis(100) {
        return Err(Error::ChildFailed);
    }
    super::inventory::verify()?;
    let end = Instant::now() + Duration::from_secs(2);
    while !early_forks_drained() {
        poll_early_forks()?;
        if Instant::now() >= end {
            return Err(Error::Deadline);
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    super::inventory::verify()?;
    if live_child_count() != 0 {
        return Err(Error::ChildFailed);
    }
    let reuse = rustix::event::eventfd(0, rustix::event::EventfdFlags::CLOEXEC)
        .map_err(|_| Error::DescriptorPolicy)?;
    if reuse.as_raw_fd() != reused {
        return Err(Error::DescriptorPolicy);
    }
    let registration = super::inventory::Registration::owned(&[reuse.as_fd()])?;
    super::inventory::verify()?;
    drop(registration);
    drop(reuse);
    super::inventory::verify()
}
#[cfg(test)]
fn lab_reap_error_isolation() -> Result<()> {
    process::single_threaded()?;
    if !early_forks_drained() || live_child_count() != 0 {
        return Err(Error::Interrupted);
    }
    let (read, write) = pipe()?;
    let creator = std::process::id() as i32;
    let (pid, pinned) = fork_with_pidfd()?;
    if pid == 0 {
        let outcome: Result<()> = (|| {
            parent_death(creator)?;
            drop(read);
            let _notice = super::inventory::Registration::owned(&[write.as_fd()])?;
            let lost_witness = lab_idle_child()?;
            let sibling = lab_idle_child()?;
            lost_witness.signal(libc::SIGKILL)?;
            if !wait_ready(&lost_witness.pidfd, Duration::from_secs(1))? {
                return Err(Error::Deadline);
            }
            let mut status = 0;
            // Deliberately consume the real waitpid receipt outside the owner.
            // Its collector must retain uncertainty on ECHILD, never guess that
            // another actor's successful reap repairs this missing witness.
            if unsafe { libc::waitpid(lost_witness.pid as i32, &mut status, 0) }
                != lost_witness.pid as i32
            {
                return Err(Error::ChildFailed);
            }
            drop(lost_witness);
            drop(sibling);
            let end = Instant::now() + Duration::from_secs(2);
            loop {
                poll_early_forks()?;
                let isolated = RETIRED_CHILDREN.with(|children| {
                    let children = children.borrow();
                    children.len() == 1
                        && children[0].drain_error == Some(Error::ChildFailed)
                        && !children[0].reaped
                });
                if isolated {
                    break;
                }
                if Instant::now() >= end {
                    return Err(Error::Deadline);
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            if early_forks_drained() || live_child_count() != 1 {
                return Err(Error::ChildFailed);
            }
            super::inventory::verify()?;
            write_byte(&write, 1)
        })();
        // This isolated test process has actually reaped both children. Its
        // deliberately lost receipt remains unresolved until process exit; no
        // production clearance, fake reap result or ownership reset is used.
        die(if outcome.is_ok() { 0 } else { 122 });
    }
    drop(write);
    let pinned = pinned.ok_or(Error::ChildFailed)?;
    let result = (|| {
        if !wait_ready(&read, Duration::from_secs(3))?
            || read_byte(&read)? != 1
            || !wait_ready(&pinned, Duration::from_secs(1))?
        {
            return Err(Error::Deadline);
        }
        let mut status = 0;
        if unsafe { libc::waitpid(pid, &mut status, 0) } != pid
            || !libc::WIFEXITED(status)
            || libc::WEXITSTATUS(status) != 0
        {
            return Err(Error::ChildFailed);
        }
        Ok(())
    })();
    if result.is_err() {
        retain_early_fork(pid, pinned, read);
    }
    result
}
/// Actual hot-add: live A socket and OFD exist before B is born.
#[cfg(test)]
fn lab_guard_private_boundary() -> Result<()> {
    use rustix::net::{self, RecvFlags, SendFlags};
    process::single_threaded()?;
    super::inventory::verify()?;
    let (a, peer) = net::socketpair(
        net::AddressFamily::UNIX,
        net::SocketType::SEQPACKET,
        net::SocketFlags::CLOEXEC | net::SocketFlags::NONBLOCK,
        None,
    )
    .map_err(|_| Error::DescriptorPolicy)?;
    // Same immutable native-handle sharing used by the owned StoreCore. Fork
    // copies its refcount, not a new descriptor or authority registration.
    let a = std::sync::Arc::new(a);
    let a_alias = a.clone();
    let a_registration = super::inventory::Registration::owned(&[a.as_fd()])?;
    let peer_registration = super::inventory::Registration::owned(&[peer.as_fd()])?;
    let lease = fs::memfd_create(c"guard-boundary-lease", fs::MemfdFlags::CLOEXEC)
        .map_err(|_| Error::DescriptorPolicy)?;
    fs::flock(&lease, fs::FlockOperation::NonBlockingLockExclusive).map_err(|_| Error::LockBusy)?;
    let lease_registration = super::inventory::Registration::owned(&[lease.as_fd()])?;
    let lease_id = fs::fstat(&lease).map_err(|_| Error::DescriptorPolicy)?;
    let observer = fs::open(
        format!("/proc/self/fd/{}", lease.as_raw_fd()),
        OFlags::RDWR | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| Error::DescriptorPolicy)?;
    let observer_registration = super::inventory::Registration::owned(&[observer.as_fd()])?;
    let a_actor = inspection::lab_idle_actor()?;
    let a_child = lab_idle_child()?;
    let (read, write) = pipe()?;
    let read_registration = super::inventory::Registration::owned(&[read.as_fd()])?;
    let write_registration = super::inventory::Registration::owned(&[write.as_fd()])?;
    let mut inputs = super::inventory::GuardInputs::empty();
    inputs.include(&write_registration, super::inventory::GuardAuthority::Gate)?;
    let boundary = inputs.seal()?;
    let creator = std::process::id() as i32;
    let (pid, pinned) = fork_with_pidfd()?;
    if pid == 0 {
        let outcome: Result<()> = (|| {
            parent_death(creator)?;
            boundary.enter()?;
            if net::send(&a, b"foreign", SendFlags::DONTWAIT | SendFlags::NOSIGNAL)
                != Err(rustix::io::Errno::NOTSOCK)
            {
                return Err(Error::DescriptorPolicy);
            }
            let inert = fs::fstat(&lease).map_err(|_| Error::DescriptorPolicy)?;
            if (inert.st_dev, inert.st_ino) == (lease_id.st_dev, lease_id.st_ino) {
                return Err(Error::OwnershipMismatch);
            }
            // Even an explicit flock unlock of the excluded slot cannot unlock A.
            let _ = fs::flock(&lease, fs::FlockOperation::Unlock);
            if a_registration.contains(a.as_fd()) {
                return Err(Error::DescriptorPolicy);
            }
            let stale = a_registration.lab_stale_copy();
            let number = a.as_raw_fd();
            drop(a);
            // One copied owner must leave the excluded slot occupied until the
            // final copied Arc drops; only then may B reuse that exact number.
            let still_inert = fs::fstat(&a_alias).map_err(|_| Error::DescriptorPolicy)?;
            if still_inert.st_dev != inert.st_dev || still_inert.st_ino != inert.st_ino {
                return Err(Error::OwnershipMismatch);
            }
            drop(a_alias);
            drop(a_registration);
            let reused = rustix::event::eventfd(0, rustix::event::EventfdFlags::CLOEXEC)
                .map_err(|_| Error::DescriptorPolicy)?;
            if reused.as_raw_fd() != number {
                return Err(Error::DescriptorPolicy);
            }
            let current = super::inventory::Registration::owned(&[reused.as_fd()])?;
            drop(stale);
            drop(a_actor); // Must not enqueue A's placeholder pidfd as a B actor.
            drop(a_child);
            if !early_forks_drained() || live_child_count() != 0 {
                return Err(Error::ChildFailed);
            }
            let own = lab_idle_child()?;
            drop(own);
            let end = Instant::now() + Duration::from_secs(2);
            while !early_forks_drained() {
                poll_early_forks()?;
                if Instant::now() >= end {
                    return Err(Error::Deadline);
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            if !current.contains(reused.as_fd()) {
                return Err(Error::DescriptorPolicy);
            }
            rustix::io::write(&reused, &7u64.to_ne_bytes()).map_err(|_| Error::DescriptorPolicy)?;
            let mut count = [0; 8];
            rustix::io::read(&reused, &mut count).map_err(|_| Error::DescriptorPolicy)?;
            if u64::from_ne_bytes(count) != 7 {
                return Err(Error::DescriptorPolicy);
            }
            drop(current);
            drop(reused);
            drop(peer);
            drop(peer_registration);
            drop(lease);
            drop(lease_registration);
            drop(observer);
            drop(observer_registration);
            drop(read);
            drop(read_registration);
            super::inventory::verify()?;
            write_byte(&write, 1)
        })();
        die(if outcome.is_ok() { 0 } else { 122 });
    }
    drop(write);
    drop(write_registration);
    let pinned = pinned.ok_or(Error::ChildFailed)?;
    let result = (|| {
        if !wait_ready(&read, Duration::from_secs(3))?
            || read_byte(&read)? != 1
            || !wait_ready(&pinned, Duration::from_secs(1))?
        {
            return Err(Error::ChildFailed);
        }
        let mut status = 0;
        if unsafe { libc::waitpid(pid, &mut status, 0) } != pid
            || !libc::WIFEXITED(status)
            || libc::WEXITSTATUS(status) != 0
        {
            return Err(Error::ChildFailed);
        }
        if fs::flock(&observer, fs::FlockOperation::NonBlockingLockExclusive)
            != Err(rustix::io::Errno::WOULDBLOCK)
        {
            return Err(Error::LockBusy);
        }
        a_actor.require_quiet()?;
        a_child.require_live()?;
        net::send(&a, b"parent", SendFlags::NOSIGNAL).map_err(|_| Error::DescriptorPolicy)?;
        let mut bytes = [0; 16];
        let (n, full) = net::recv(&peer, &mut bytes, RecvFlags::DONTWAIT)
            .map_err(|_| Error::DescriptorPolicy)?;
        if n != 6 || full != 6 || &bytes[..6] != b"parent" {
            return Err(Error::DescriptorPolicy);
        }
        Ok(())
    })();
    if result.is_err() {
        retain_early_fork(pid, pinned, read);
    }
    drop(a_actor);
    drop(a_child);
    let end = Instant::now() + Duration::from_secs(2);
    while !early_forks_drained() {
        poll_early_forks()?;
        if Instant::now() >= end {
            return Err(Error::Deadline);
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    if result.is_ok() {
        eprintln!(
            "LAB_SHARED_NATIVE_ARC_BOUNDARY foreign_aliases_inert=true last_copy_drop_before_exact_reuse=true new_token_survives_stale_drop=true parent_original_functional=true actual_child_waitpid_exit0=true"
        );
    }
    result
}
#[cfg(test)]
fn lab_child_creator_isolation() -> Result<()> {
    process::single_threaded()?;
    let live_parent = lab_idle_child()?;
    let pending_parent = lab_idle_child()?;
    drop(pending_parent);
    let (read, write) = pipe()?;
    let creator = std::process::id() as i32;
    let (pid, pinned) = fork_with_pidfd()?;
    if pid == 0 {
        let result: Result<()> = (|| {
            parent_death(creator)?;
            drop(read);
            let _notice = super::inventory::Registration::owned(&[write.as_fd()])?;
            if live_parent.require_live() != Err(Error::OwnershipMismatch)
                || live_parent.signal(libc::SIGKILL) != Err(Error::OwnershipMismatch)
            {
                return Err(Error::OwnershipMismatch);
            }
            drop(live_parent);
            if !early_forks_drained() || live_child_count() != 0 {
                return Err(Error::ChildFailed);
            }
            let own = lab_idle_child()?;
            drop(own);
            let end = Instant::now() + Duration::from_secs(2);
            while !early_forks_drained() {
                poll_early_forks()?;
                if Instant::now() >= end {
                    return Err(Error::Deadline);
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            if live_child_count() != 0 {
                return Err(Error::ChildFailed);
            }
            super::inventory::verify()?;
            write_byte(&write, 1)
        })();
        die(if result.is_ok() { 0 } else { 122 });
    }
    drop(write);
    let pinned = pinned.ok_or(Error::ChildFailed)?;
    if !wait_ready(&read, Duration::from_secs(3))?
        || read_byte(&read)? != 1
        || !wait_ready(&pinned, Duration::from_secs(1))?
    {
        retain_early_fork(pid, pinned, read);
        return Err(Error::ChildFailed);
    }
    let mut status = 0;
    if unsafe { libc::waitpid(pid, &mut status, 0) } != pid
        || !libc::WIFEXITED(status)
        || libc::WEXITSTATUS(status) != 0
    {
        return Err(Error::ChildFailed);
    }
    live_parent.require_live()?;
    drop(live_parent);
    let end = Instant::now() + Duration::from_secs(2);
    while !early_forks_drained() {
        poll_early_forks()?;
        if Instant::now() >= end {
            return Err(Error::Deadline);
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    drop(read);
    drop(pinned);
    super::inventory::verify()
}
#[cfg(test)]
fn lab_publisher_startup_retention() -> Result<()> {
    process::single_threaded()?;
    super::inventory::verify()?;
    if !early_forks_drained() {
        return Err(Error::Interrupted);
    }
    let cache = fs::open(
        c"/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| Error::DescriptorPolicy)?;
    let reused = cache.as_raw_fd();
    let cache_inventory = super::inventory::Registration::owned(&[cache.as_fd()])?;
    let (socket, other) = rustix::net::socketpair(
        rustix::net::AddressFamily::UNIX,
        rustix::net::SocketType::SEQPACKET,
        rustix::net::SocketFlags::CLOEXEC,
        None,
    )
    .map_err(|_| Error::DescriptorPolicy)?;
    let socket_inventory = super::inventory::Registration::owned(&[socket.as_fd()])?;
    let (read, write) = publisher_pipe()?;
    let creator = std::process::id() as i32;
    let (pid, pinned) = fork_with_pidfd()?;
    if pid == 0 {
        let result: Result<()> = (|| {
            parent_death(creator)?;
            close_except(&[write.as_raw_fd()])?;
            write_byte(&write, 128)?;
            loop {
                // Deliberately retain the ACK writer after Ready; parent alone
                // kills this exact direct child following the original timeout.
                unsafe {
                    libc::pause();
                }
            }
        })();
        die(if result.is_ok() { 0 } else { 122 });
    }
    drop(other);
    drop(write);
    // Observe data without consuming it, so the production finish constructor
    // receives exactly the held-close case, not just a slow startup timeout.
    let ack_available = wait_ready(&read, Duration::from_secs(1));
    let result = finish_publisher(
        pid,
        pinned.ok_or(Error::ChildFailed)?,
        read,
        socket,
        cache,
        cache_inventory,
        socket_inventory,
        Instant::now() + Duration::from_millis(10),
    );
    if ack_available != Ok(true) || !matches!(result, Err(Error::Deadline)) || early_forks_drained()
    {
        return Err(Error::DescriptorPolicy);
    }
    super::inventory::verify()?;
    let end = Instant::now() + Duration::from_secs(2);
    while !early_forks_drained() {
        poll_early_forks()?;
        if Instant::now() >= end {
            return Err(Error::Deadline);
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    super::inventory::verify()?;
    let reuse = rustix::event::eventfd(0, rustix::event::EventfdFlags::CLOEXEC)
        .map_err(|_| Error::DescriptorPolicy)?;
    if reuse.as_raw_fd() != reused {
        return Err(Error::DescriptorPolicy);
    }
    let inventory = super::inventory::Registration::owned(&[reuse.as_fd()])?;
    super::inventory::verify()?;
    drop(inventory);
    drop(reuse);
    super::inventory::verify()
}
/// Fixed directory-confined cache publisher; no caller program/argv/callback.
/// Parent remains single threaded. Only inherited pathless IPC3, directory4 and
/// initial acknowledgement5 survive setup; every host/network/control FD closes.
pub(super) fn spawn_publisher(
    directory: impl AsFd,
    binding: &vprouter_core::health::Binding,
) -> Result<Child> {
    process::publisher_preflight()?;
    binding.validate().map_err(|_| Error::InvalidSpec)?;
    let _directory = super::inventory::Registration::owned(&[directory.as_fd()])?;
    #[cfg(test)]
    eprintln!("spawn_publisher: before_inventory");
    super::inventory::verify()?;
    #[cfg(test)]
    eprintln!("spawn_publisher: inventory_verified");
    let cache = directory
        .as_fd()
        .try_clone_to_owned()
        .map_err(|_| Error::DescriptorDuplicate)?;
    let cache_inventory = super::inventory::Registration::owned(&[cache.as_fd()])?;
    let (parent_socket, child_socket) = rustix::net::socketpair(
        rustix::net::AddressFamily::UNIX,
        rustix::net::SocketType::SEQPACKET,
        rustix::net::SocketFlags::CLOEXEC,
        None,
    )
    .map_err(|_| Error::DescriptorPolicy)?;
    let socket_inventory = super::inventory::Registration::owned(&[parent_socket.as_fd()])?;
    let (health_r, health_w) = publisher_pipe()?;
    let parent = std::process::id() as i32;
    let (pid, pinned) = fork_with_pidfd()?;
    if pid == 0 {
        let result = (|| {
            parent_death(parent)?;
            cv(unsafe { libc::clearenv() }, Error::ChildFailed)?;
            let directory = std::mem::ManuallyDrop::new(
                rustix::io::fcntl_dupfd_cloexec(&cache, 110)
                    .map_err(|_| Error::DescriptorDuplicate)?,
            );
            let channel = std::mem::ManuallyDrop::new(
                rustix::io::fcntl_dupfd_cloexec(&child_socket, 110)
                    .map_err(|_| Error::DescriptorDuplicate)?,
            );
            let ack = std::mem::ManuallyDrop::new(
                rustix::io::fcntl_dupfd_cloexec(&health_w, 110)
                    .map_err(|_| Error::DescriptorDuplicate)?,
            );
            let null = std::mem::ManuallyDrop::new(
                fs::open(c"/dev/null", OFlags::RDWR | OFlags::CLOEXEC, Mode::empty())
                    .map_err(|_| Error::DescriptorNull)?,
            );
            for number in 0..3 {
                dup_fixed(&*null, number, false)?;
            }
            dup_fixed(&*channel, 3, true)?;
            dup_fixed(&*directory, 4, true)?;
            dup_fixed(&*ack, 5, true)?;
            close_except(&[3, 4, 5])?;
            if descriptor_inventory()? != [0, 1, 2, 3, 4, 5].into() {
                return Err(Error::DescriptorInventory);
            }
            // SAFETY: private fork descriptor table and fs context. No directory
            // above this root survives, and capabilities/exec regain are removed.
            cv(unsafe { libc::fchdir(4) }, Error::MountIsolation)?;
            cv(
                unsafe { libc::chroot(c".".as_ptr()) },
                Error::MountIsolation,
            )?;
            cv(unsafe { libc::chdir(c"/".as_ptr()) }, Error::MountIsolation)?;
            drop_identity(0)?;
            parent_death(parent)?;
            apply_filter(&publisher_filter())?;
            let ack = unsafe { BorrowedFd::borrow_raw(5) };
            write_byte(ack, 128)?;
            checked_close(5)?;
            super::publisher::run_child(
                unsafe { BorrowedFd::borrow_raw(4) },
                unsafe { BorrowedFd::borrow_raw(3) },
                binding,
            )
        })();
        // No strings, paths, kernel payloads or caller data cross the error lane.
        if result.is_err() {
            die(122);
        }
        die(0);
    }
    drop(child_socket);
    drop(health_w);
    finish_publisher(
        pid,
        pinned.ok_or(Error::ChildFailed)?,
        health_r,
        parent_socket,
        cache,
        cache_inventory,
        socket_inventory,
        Instant::now() + Duration::from_secs(2),
    )
}
#[allow(clippy::too_many_arguments)]
fn finish_publisher(
    pid: i32,
    pinned: OwnedFd,
    health: OwnedFd,
    socket: OwnedFd,
    cache: OwnedFd,
    cache_inventory: super::inventory::Registration,
    socket_inventory: super::inventory::Registration,
    end: Instant,
) -> Result<Child> {
    let inventory = match super::inventory::Registration::owned(&[pinned.as_fd(), health.as_fd()]) {
        Ok(inventory) => inventory,
        Err(error) => {
            retain_registered_fork_with_pins(
                pid,
                pinned,
                socket,
                None,
                vec![cache_inventory, socket_inventory],
                vec![health, cache],
            );
            return Err(error);
        }
    };
    #[cfg(test)]
    eprintln!("spawn_publisher: parent_registered");
    let native = Survivor {
        pid: pid as u32,
        reap: ParentReap::born(pid as u32),
        pinned,
        _inventory: inventory,
    };
    let ready = publisher_ready(&health, end).and_then(|()| {
        native.require_live()?;
        if Instant::now() >= end {
            Err(Error::Deadline)
        } else {
            Ok(())
        }
    });
    if let Err(error) = ready {
        retain_survivor(
            native,
            socket,
            None,
            vec![cache_inventory, socket_inventory],
            vec![health, cache],
        );
        return Err(error);
    }
    let child = Child::from_native(ChildNative {
        _capacity: ChildCapacity::created(),
        pid: pid as u32,
        pidfd: native.pinned,
        release: None,
        health,
        _inventory: native._inventory,
        release_inventory: None,
        reaped: false,
        control: Some(socket),
        retained_pins: vec![cache],
        retained_inventory: vec![cache_inventory, socket_inventory],
        producer: None,
        drain_error: None,
        descendants: false,
        lease: None,
        #[cfg(test)]
        actual_negative: None,
    });
    #[cfg(test)]
    eprintln!("spawn_publisher: ready");
    Ok(child)
}
/// One fixed directory-confined journal IO job. No arbitrary callback, exec or
/// caller path. The allocation OFD lease remains in FD5 until actual child exit.
pub(super) struct JournalChild {
    native: Option<JournalNative>,
}
pub(super) struct JournalNative {
    creator: u32,
    io_before: [u8; 32],
    io_after: Option<[u8; 32]>,
    io_deadline: f64,
    _capacity: ChildCapacity,
    _lease: super::owned::MutatorLease,
    _directory: OwnedFd,
    _directory_inventory: super::inventory::Registration,
    release: Option<OwnedFd>,
    release_inventory: Option<super::inventory::Registration>,
    child: Survivor,
    ack: OwnedFd,
    _inventory: super::inventory::Registration,
    reaped: bool,
    killed: bool,
    observed: Option<[u8; 32]>,
    #[cfg(test)]
    checkpoint_waiting: bool,
}
impl std::ops::Deref for JournalChild {
    type Target = JournalNative;
    fn deref(&self) -> &JournalNative {
        self.native.as_ref().expect("retained journal child")
    }
}
impl std::ops::DerefMut for JournalChild {
    fn deref_mut(&mut self) -> &mut JournalNative {
        self.native.as_mut().expect("retained journal child")
    }
}
thread_local! { static RETIRED_JOURNAL_IO: std::cell::RefCell<Vec<JournalNative>> = const { std::cell::RefCell::new(Vec::new()) }; }
impl Drop for JournalChild {
    fn drop(&mut self) {
        if let Some(native) = self.native.take() {
            if native.creator != std::process::id() || native.reaped {
                return;
            }
            let _ = send_or_exited(native.child.pidfd(), libc::SIGKILL);
            RETIRED_JOURNAL_IO.with(|pending| pending.borrow_mut().push(native));
        }
    }
}
fn poll_retired_journal_io() {
    RETIRED_JOURNAL_IO.with(|pending| {
        pending.borrow_mut().retain_mut(|native| {
            if native.creator != std::process::id() {
                return true;
            }
            let _ = send_or_exited(native.child.pidfd(), libc::SIGKILL);
            native.child.reap_exited() != Ok(true)
        })
    });
}
impl JournalChild {
    pub(super) fn matches_owned_mutation_io(
        &self,
        jobs: &std::rc::Rc<std::cell::RefCell<super::owned::NativeJobs>>,
        member: &str,
        before: [u8; 32],
        after: [u8; 32],
        deadline: f64,
    ) -> Result<bool> {
        self.creator()?;
        Ok(self._lease.matches_writer_owner(jobs, member)?
            && self.matches_mutation_io(before, after, deadline)?)
    }
    // Immutable constructor input binding, never a parsed completion or ACK.
    pub(super) fn matches_mutation_io(
        &self,
        before: [u8; 32],
        after: [u8; 32],
        deadline: f64,
    ) -> Result<bool> {
        self.creator()?;
        Ok(!self.killed
            && self.io_before == before
            && self.io_after == Some(after)
            && self.io_deadline == deadline)
    }
    #[cfg(test)]
    pub(super) fn lab_native_reap_handle(&self) -> Result<Survivor> {
        self.creator()?;
        self.child.lab_clone_native()
    }
    fn creator(&self) -> Result<()> {
        if self.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
    pub fn start(&mut self) -> Result<()> {
        self.creator()?;
        write_byte(self.release.as_ref().ok_or(Error::Interrupted)?, 1)?;
        self.release.take();
        self.release_inventory.take();
        Ok(())
    }
    pub fn drained(&self) -> bool {
        self.reaped
    }
    pub fn observed(&self) -> Result<[u8; 32]> {
        self.observed.ok_or(Error::OwnershipMismatch)
    }
    pub fn cancel(&mut self) -> Result<()> {
        self.creator()?;
        if !self.killed {
            send_or_exited(self.child.pidfd(), libc::SIGKILL)?;
            self.killed = true;
        }
        Ok(())
    }
    pub fn poll(&mut self) -> Result<Option<bool>> {
        self.creator()?;
        if self.reaped {
            return Err(Error::Interrupted);
        }
        let Some(status) = self.child.reap_status()? else {
            return Ok(None);
        };
        self.reaped = true;
        #[cfg(test)]
        if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
            let mut diagnostic = [0u8; 2];
            let length = if wait_ready(&self.ack, Duration::ZERO)? {
                rustix::io::read(&self.ack, &mut diagnostic).unwrap_or(0)
            } else {
                0
            };
            eprintln!(
                "LAB_JOURNAL_CHILD_FAILURE wait_status={status} diagnostic_length={length} stage={} error_code={}",
                diagnostic[0], diagnostic[1]
            );
        }
        if self.killed
            || !libc::WIFEXITED(status)
            || libc::WEXITSTATUS(status) != 0
            || !wait_ready(&self.ack, Duration::ZERO)?
        {
            return Ok(Some(false));
        }
        let mut ack = [0u8; 34];
        let count = rustix::io::read(&self.ack, &mut ack).map_err(|_| Error::ChildFailed)?;
        if count != 33 || ack[0] != 128 {
            return Ok(Some(false));
        }
        self.observed = Some(ack[1..33].try_into().map_err(|_| Error::ChildFailed)?);
        Ok(Some(true))
    }
}
#[cfg(test)]
thread_local! { static LAB_FAIL_JOURNAL_PARENT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }
#[cfg(test)]
pub(super) fn lab_fail_next_journal_parent() -> Result<()> {
    if LAB_FAIL_JOURNAL_PARENT.with(|flag| flag.replace(true)) {
        return Err(Error::Interrupted);
    }
    Ok(())
}
pub(super) fn spawn_journal_io(
    directory: OwnedFd,
    mut lease: super::owned::MutatorLease,
    job: &super::owned::JournalIo,
) -> Result<JournalChild> {
    process::single_threaded()?;
    // Stamp the exact immutable IO used below, before native birth.
    let (io_before, io_after, io_deadline) = job.constructor_binding();
    lease.prepare_native_job(NativeJobKind::Journal)?;
    let directory_inventory = super::inventory::Registration::owned(&[directory.as_fd()])?;
    #[cfg(test)]
    eprintln!("LAB_JOURNAL_STAGE stage=io_inventory");
    super::inventory::verify()?;
    #[cfg(test)]
    eprintln!("LAB_JOURNAL_STAGE stage=io_inventory_verified");
    let (ack_r, ack_w) = rustix::net::socketpair(
        rustix::net::AddressFamily::UNIX,
        rustix::net::SocketType::SEQPACKET,
        rustix::net::SocketFlags::CLOEXEC,
        None,
    )
    .map_err(|_| Error::DescriptorPolicy)?;
    let (release_r, release_w) = pipe()?;
    let inventory = super::inventory::Registration::owned(&[ack_r.as_fd()])?;
    let release_inventory = super::inventory::Registration::owned(&[release_w.as_fd()])?;
    let child_ends = super::inventory::Registration::owned(&[ack_w.as_fd(), release_r.as_fd()])?;
    let parent = std::process::id() as i32;
    // Atomic native child identity; no unpinned post-fork failure window.
    let (pid, pinned) = fork_with_pidfd()?;
    if pid == 0 {
        #[cfg(test)]
        let diagnostic = std::cell::Cell::new(1u8);
        #[cfg(test)]
        let diagnostic_fd = std::cell::Cell::new(ack_w.as_raw_fd());
        let result = (|| {
            parent_death(parent)?;
            if !wait_ready(&release_r, Duration::from_secs(2))? || read_byte(&release_r)? != 1 {
                return Err(Error::Deadline);
            }

            #[cfg(test)]
            diagnostic.set(2);
            cv(unsafe { libc::clearenv() }, Error::ChildFailed)?;
            let directory = std::mem::ManuallyDrop::new(
                rustix::io::fcntl_dupfd_cloexec(&directory, 110)
                    .map_err(|_| Error::DescriptorDuplicate)?,
            );
            let lease = std::mem::ManuallyDrop::new(
                rustix::io::fcntl_dupfd_cloexec(lease.fd(), 110)
                    .map_err(|_| Error::DescriptorDuplicate)?,
            );
            let ack = std::mem::ManuallyDrop::new(
                rustix::io::fcntl_dupfd_cloexec(&ack_w, 110)
                    .map_err(|_| Error::DescriptorDuplicate)?,
            );
            let null = std::mem::ManuallyDrop::new(
                fs::open(c"/dev/null", OFlags::RDWR | OFlags::CLOEXEC, Mode::empty())
                    .map_err(|_| Error::DescriptorNull)?,
            );
            for number in 0..3 {
                dup_fixed(&*null, number, false)?;
            }
            dup_fixed(&*ack, 3, true)?;
            #[cfg(test)]
            diagnostic_fd.set(3);
            #[cfg(test)]
            diagnostic.set(3);
            dup_fixed(&*directory, 4, true)?;
            dup_fixed(&*lease, 5, true)?;
            close_except(&[3, 4, 5])?;
            if descriptor_inventory()? != [0, 1, 2, 3, 4, 5].into() {
                return Err(Error::DescriptorInventory);
            }
            #[cfg(test)]
            diagnostic.set(4);
            cv(unsafe { libc::fchdir(4) }, Error::MountIsolation)?;
            cv(
                unsafe { libc::chroot(c".".as_ptr()) },
                Error::MountIsolation,
            )?;
            cv(unsafe { libc::chdir(c"/".as_ptr()) }, Error::MountIsolation)?;
            #[cfg(test)]
            diagnostic.set(5);
            drop_identity(0)?;
            #[cfg(test)]
            diagnostic.set(6);
            parent_death(parent)?;
            let mut filter = publisher_filter();
            filter.pop();
            allow_syscall(&mut filter, libc::SYS_read);
            filter.push(libc::sock_filter {
                code: 0x06,
                jt: 0,
                jf: 0,
                k: 0x00050001,
            });
            #[cfg(test)]
            diagnostic.set(7);
            apply_filter(&filter)?;
            let observed = job.run(unsafe { BorrowedFd::borrow_raw(4) })?;
            let mut ack = [0u8; 33];
            ack[0] = 128;
            ack[1..].copy_from_slice(&observed);
            if rustix::io::write(unsafe { BorrowedFd::borrow_raw(3) }, &ack)
                .map_err(|_| Error::ChildFailed)?
                != ack.len()
            {
                return Err(Error::ChildFailed);
            }
            Ok(())
        })();
        #[cfg(test)]
        if let Err(error) = result {
            let stage = if job.lab_stage.get() == 0 {
                diagnostic.get()
            } else {
                job.lab_stage.get()
            };
            // Fixed identity-free diagnostic only; no path, record or key bytes.
            let _ = rustix::io::write(
                unsafe { BorrowedFd::borrow_raw(diagnostic_fd.get()) },
                &[stage, stage_byte(error)],
            );
        }
        die(if result.is_ok() { 0 } else { 122 });
    }
    let reap = ParentReap::born(pid as u32);
    lease.native_job_mut().born(NativeJobKind::Journal, &reap);
    drop(child_ends);
    drop(ack_w);
    drop(release_r);
    let pinned = pinned.ok_or(Error::ChildFailed)?;
    let register = || super::inventory::Registration::owned(&[pinned.as_fd()]);
    #[cfg(test)]
    let registration = if LAB_FAIL_JOURNAL_PARENT.with(|flag| flag.replace(false)) {
        Err(Error::DescriptorInventory)
    } else {
        register()
    };
    #[cfg(not(test))]
    let registration = register();
    let child_inventory = match registration {
        Ok(inventory) => inventory,
        Err(error) => {
            retain_fork_bundle_with_reap(
                pid,
                pinned,
                ack_r,
                None,
                vec![inventory, release_inventory, directory_inventory],
                vec![release_w, directory],
                None,
                None,
                Some(lease),
                reap,
                None,
            );
            return Err(error);
        }
    };
    Ok(JournalChild {
        native: Some(JournalNative {
            creator: std::process::id(),
            io_before,
            io_after,
            io_deadline,
            _capacity: ChildCapacity::created(),
            _lease: lease,
            _directory: directory,
            _directory_inventory: directory_inventory,
            release: Some(release_w),
            release_inventory: Some(release_inventory),
            child: Survivor {
                pid: pid as u32,
                reap,
                pinned,
                _inventory: child_inventory,
            },
            ack: ack_r,
            _inventory: inventory,
            reaped: false,
            killed: false,
            observed: None,
            #[cfg(test)]
            checkpoint_waiting: false,
        }),
    })
}
#[cfg(test)]
pub(super) fn lab_journal_pause() -> Result<()> {
    // Fixed checkpoint after temp write. Parent stops the pinned child; the
    // confined child performs only already permitted read/write, never signals.
    write_byte(unsafe { BorrowedFd::borrow_raw(3) }, 127)?;
    if read_byte(unsafe { BorrowedFd::borrow_raw(3) })? != 1 {
        return Err(Error::ChildFailed);
    }
    Ok(())
}
#[cfg(test)]
pub(crate) struct LabJournalCharge {
    creator: u32,
    charge: std::rc::Weak<ChildCharge>,
    reap: std::rc::Weak<ParentReap>,
    pub(crate) before: [u8; 32],
    pub(crate) after: Option<[u8; 32]>,
    pub(crate) deadline: f64,
}
#[cfg(test)]
impl LabJournalCharge {
    pub(crate) fn facts(&self) -> Result<(u32, u64, Option<i32>)> {
        if self.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        self.charge
            .upgrade()
            .ok_or(Error::OwnershipMismatch)?
            .require_live_charge()?;
        let reap = self.reap.upgrade().ok_or(Error::OwnershipMismatch)?;
        if reap.creator != self.creator {
            return Err(Error::OwnershipMismatch);
        }
        Ok((
            reap.pid,
            reap.start.get().ok_or(Error::OwnershipMismatch)?,
            reap.status.get(),
        ))
    }
    pub(crate) fn same_original(&self, other: &Self) -> Result<()> {
        self.facts()?;
        other.facts()?;
        if self.creator != other.creator
            || !std::rc::Weak::ptr_eq(&self.charge, &other.charge)
            || !std::rc::Weak::ptr_eq(&self.reap, &other.reap)
            || self.before != other.before
            || self.after != other.after
            || self.deadline != other.deadline
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
}
#[cfg(test)]
impl JournalChild {
    /// Weak-only original constructor evidence: this cannot keep either the
    /// charge or native receipt alive after the retained owner is dropped.
    pub(crate) fn lab_charge(&self, original: &Survivor) -> Result<LabJournalCharge> {
        self.creator()?;
        let reap = self.child.reap.as_ref().ok_or(Error::OwnershipMismatch)?;
        let expected = original.reap.as_ref().ok_or(Error::OwnershipMismatch)?;
        if !std::rc::Rc::ptr_eq(reap, expected)
            || self.child.pid != original.pid
            || reap.pid != self.child.pid
        {
            return Err(Error::OwnershipMismatch);
        }
        let result = LabJournalCharge {
            creator: self.creator,
            charge: std::rc::Rc::downgrade(&self._capacity.charge),
            reap: std::rc::Rc::downgrade(reap),
            before: self.io_before,
            after: self.io_after,
            deadline: self.io_deadline,
        };
        result.facts()?;
        Ok(result)
    }
    pub(crate) fn lab_cached_checkpoint_waiting(&self) -> Option<bool> {
        let native = self.native.as_ref()?;
        (native.creator == std::process::id()).then_some(self.checkpoint_waiting)
    }
    pub fn lab_ack_ready(&self) -> Result<bool> {
        if self.native.as_ref().ok_or(Error::Interrupted)?.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        wait_ready(&self.ack, Duration::ZERO)
    }
    pub fn lab_waiting_checkpoint(&mut self) -> Result<bool> {
        if self.checkpoint_waiting {
            return Ok(true);
        }
        if !wait_ready(&self.ack, Duration::ZERO)? {
            return Ok(false);
        }
        if read_byte(&self.ack)? != 127 {
            return Err(Error::ChildFailed);
        }
        self.child.require_live()?;
        self.checkpoint_waiting = true;
        Ok(true)
    }
    pub fn lab_release_checkpoint(&mut self) -> Result<()> {
        if !self.checkpoint_waiting {
            return Err(Error::Interrupted);
        }
        self.child.require_live()?;
        write_byte(&self.ack, 1)?;
        self.checkpoint_waiting = false;
        Ok(())
    }
    pub fn lab_stop_at_checkpoint(&self) -> Result<Option<(u32, u64)>> {
        if !wait_ready(&self.ack, Duration::ZERO)? {
            return Ok(None);
        }
        if read_byte(&self.ack)? != 127 {
            return Err(Error::ChildFailed);
        }
        let start = self.child.lab_stop_and_witness()?;
        Ok(Some((self.child.pid(), start)))
    }
    pub fn lab_require_stopped(&self) -> Result<(u32, u64)> {
        let start = self.child.start_time()?;
        self.child.lab_require_stopped(start)?;
        Ok((self.child.pid(), start))
    }
}
fn publisher_filter() -> Vec<libc::sock_filter> {
    let mut out = filter()[..4].to_vec();
    // Full64-bit arg0 checks; no inherited dir/socket is usable under anotherFD.
    for (nr, fd) in [
        (libc::SYS_openat, 4),
        (libc::SYS_renameat, 4),
        (libc::SYS_recvfrom, 3),
        (libc::SYS_sendto, 3),
        (libc::SYS_prctl, libc::PR_GET_SECCOMP as u32),
    ] {
        out.extend([
            libc::sock_filter {
                code: 0x15,
                jt: 0,
                jf: 7,
                k: nr as u32,
            },
            libc::sock_filter {
                code: 0x20,
                jt: 0,
                jf: 0,
                k: 20,
            },
            libc::sock_filter {
                code: 0x15,
                jt: 0,
                jf: 3,
                k: 0,
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
                k: fd,
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
            libc::sock_filter {
                code: 0x20,
                jt: 0,
                jf: 0,
                k: 0,
            },
        ]);
    }
    // No executable mappings; allocator mappings/protection are at mostRW.
    for (nr, offset) in [(libc::SYS_mmap, 32), (libc::SYS_mprotect, 32)] {
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
                k: offset,
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
    for nr in [
        libc::SYS_write,
        libc::SYS_writev,
        libc::SYS_close,
        libc::SYS_fstat,
        libc::SYS_newfstatat,
        libc::SYS_statx,
        libc::SYS_fsync,
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
        code: 0x06,
        jt: 0,
        jf: 0,
        k: 0x00050001,
    });
    out
}

/// Unlike ordinary launch Child, this authority NEVER kills on Drop or parent
/// death. Private IPC closure causes terminal containment; the inherited flock
/// remains held by that process until _exit, even when its guard has disappeared.
pub(super) struct Survivor {
    pid: u32,
    pinned: OwnedFd,
    _inventory: super::inventory::Registration,
    // Only a native direct-child constructor creates this authority. Received
    // or observed pidfds can inspect/signal their target, never mint a reap.
    reap: Option<std::rc::Rc<ParentReap>>,
}
/// A creator-local receipt for ONE fixed, non-spawning native IO role. This is
/// not the process's signal/reap authority and cannot be minted from a pidfd.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum NativeJobKind {
    Journal,
    HostAudit,
    RetirementStop,
    RetirementCleanup,
    SecretValidation,
    DockerInspection,
    NamespaceAttachment,
    FreshTransport,
    FreshTransportMount,
    WireguardSecret,
    FixedNetfilter,
    FixedVeth,
    ProducerCreation,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum NativeJobState {
    Prepared,
    Born,
    NoBirth,
    Collected,
    // Native child capacity may be retired, but original resources remain
    // owned by the typed assembly and MUST NOT make member cleanup quiet.
    TransferredResources,
}
#[derive(Clone)]
pub(super) struct NativeJobDrain {
    creator: u32,
    state: std::rc::Rc<std::cell::Cell<NativeJobState>>,
}
pub(super) struct NativeJobTicket {
    creator: u32,
    kind: NativeJobKind,
    state: std::rc::Rc<std::cell::Cell<NativeJobState>>,
    reap: Option<NativeJobReap>,
}
#[derive(Clone)]
enum NativeJobReap {
    Local(std::rc::Rc<ParentReap>),
    Wireguard(vprouter_native_role::ReapWitness),
}
impl NativeJobReap {
    fn status(&self, creator: u32) -> Option<i32> {
        if creator != std::process::id() {
            return None;
        }
        match self {
            Self::Local(receipt) if receipt.creator == creator => receipt.status.get(),
            Self::Wireguard(receipt) => receipt.actual_status().ok().flatten(),
            _ => None,
        }
    }
}
impl NativeJobTicket {
    pub(super) fn prepare(kind: NativeJobKind) -> (Self, NativeJobDrain) {
        let creator = std::process::id();
        let state = std::rc::Rc::new(std::cell::Cell::new(NativeJobState::Prepared));
        (
            Self {
                creator,
                kind,
                state: state.clone(),
                reap: None,
            },
            NativeJobDrain { creator, state },
        )
    }
    // Called only immediately after positive atomic native clone, BEFORE any
    // fallible parent operation. The shared receipt is the constructor's own.
    fn born(&mut self, kind: NativeJobKind, reap: &Option<std::rc::Rc<ParentReap>>) {
        self.state.set(NativeJobState::Born);
        if self.creator == std::process::id() && self.kind == kind {
            self.reap = reap
                .as_ref()
                .map(|receipt| NativeJobReap::Local(receipt.clone()));
        }
    }
    fn born_wireguard(&mut self, receipt: vprouter_native_role::ReapWitness) {
        self.state.set(NativeJobState::Born);
        if self.creator == std::process::id()
            && self.kind == NativeJobKind::WireguardSecret
            && receipt.original().is_ok()
        {
            self.reap = Some(NativeJobReap::Wireguard(receipt));
        }
    }
    fn born_veth(&mut self, receipt: vprouter_native_role::ReapWitness) {
        self.state.set(NativeJobState::Born);
        if self.creator == std::process::id()
            && self.kind == NativeJobKind::FixedVeth
            && receipt.original().is_ok()
        {
            self.reap = Some(NativeJobReap::Wireguard(receipt));
        }
    }
    fn born_netfilter(&mut self, receipt: vprouter_native_role::ReapWitness) {
        self.state.set(NativeJobState::Born);
        if self.creator == std::process::id()
            && self.kind == NativeJobKind::FixedNetfilter
            && receipt.original().is_ok()
        {
            self.reap = Some(NativeJobReap::Wireguard(receipt));
        }
    }
}
impl Drop for NativeJobTicket {
    fn drop(&mut self) {
        if self.creator != std::process::id() {
            return;
        }
        match self.state.get() {
            NativeJobState::Prepared => self.state.set(NativeJobState::NoBirth),
            NativeJobState::Born
                if self
                    .reap
                    .as_ref()
                    .is_some_and(|r| r.status(self.creator).is_some()) =>
            {
                self.state.set(NativeJobState::Collected)
            }
            _ => {} // Unknown/live post-birth owner loss stays fenced forever.
        }
    }
}
impl NativeJobDrain {
    pub(super) fn matches_original_writer(&self, ticket: &NativeJobTicket) -> bool {
        self.creator == std::process::id()
            && ticket.creator == self.creator
            && ticket.kind == NativeJobKind::Journal
            && std::rc::Rc::ptr_eq(&self.state, &ticket.state)
            && self.state.get() == NativeJobState::Born
    }
    pub(super) fn matches_reaped(&self, ticket: &NativeJobTicket) -> Result<bool> {
        if self.creator != std::process::id() || ticket.creator != self.creator {
            return Err(Error::OwnershipMismatch);
        }
        Ok(std::rc::Rc::ptr_eq(&self.state, &ticket.state)
            && self.state.get() == NativeJobState::Born
            && ticket
                .reap
                .as_ref()
                .is_some_and(|r| r.status(self.creator) == Some(0)))
    }
    #[cfg(test)]
    pub(super) fn lab_collected(&self) -> Result<bool> {
        self.complete()?;
        Ok(self.state.get() == NativeJobState::Collected)
    }
    pub(super) fn resources_transferred(&self) -> Result<bool> {
        if self.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        Ok(self.state.get() == NativeJobState::TransferredResources)
    }
    pub(super) fn complete(&self) -> Result<bool> {
        if self.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        Ok(matches!(
            self.state.get(),
            NativeJobState::NoBirth | NativeJobState::Collected
        ))
    }
}
/// Private consuming capacity handoff. It does not release a descriptor,
/// journal lease, resource reservation, or grant current native authority.
pub(crate) struct ResourceTransfer {
    creator: u32,
    kind: NativeJobKind,
    state: std::rc::Rc<std::cell::Cell<NativeJobState>>,
    reap: NativeJobReap,
    charge: std::rc::Rc<ChildCharge>,
    lower: Option<vprouter_native_role::ReapWitness>,
    retired: bool,
    lower_done: bool,
}
impl ResourceTransfer {
    fn local(
        ticket: &NativeJobTicket,
        kind: NativeJobKind,
        reap: &std::rc::Rc<ParentReap>,
        capacity: &ChildCapacity,
    ) -> Result<Self> {
        if ticket.kind != kind
            || !matches!(&ticket.reap,Some(NativeJobReap::Local(r)) if std::rc::Rc::ptr_eq(r,reap))
        {
            return Err(Error::OwnershipMismatch);
        }
        Self::new(ticket, capacity, None)
    }
    fn lower(
        ticket: &NativeJobTicket,
        kind: NativeJobKind,
        reap: &vprouter_native_role::ReapWitness,
        capacity: &ChildCapacity,
    ) -> Result<Self> {
        if ticket.kind != kind
            || !matches!(&ticket.reap,Some(NativeJobReap::Wireguard(r)) if r.same_constructor(reap).unwrap_or(false))
        {
            return Err(Error::OwnershipMismatch);
        }
        Self::new(ticket, capacity, Some(reap.clone()))
    }
    fn new(
        ticket: &NativeJobTicket,
        capacity: &ChildCapacity,
        lower: Option<vprouter_native_role::ReapWitness>,
    ) -> Result<Self> {
        let value = Self {
            creator: ticket.creator,
            kind: ticket.kind,
            state: ticket.state.clone(),
            reap: ticket.reap.clone().ok_or(Error::OwnershipMismatch)?,
            charge: capacity.charge.clone(),
            lower_done: lower.is_none(),
            lower,
            retired: false,
        };
        value.verify()?;
        Ok(value)
    }
    pub(super) fn verify(&self) -> Result<()> {
        if self.creator != std::process::id()
            || self.retired
            || self.state.get() != NativeJobState::Born
            || self.reap.status(self.creator) != Some(0)
        {
            return Err(Error::OwnershipMismatch);
        }
        self.charge.require_live_charge()?;
        if let Some(lower) = &self.lower {
            lower
                .require_completed_capacity()
                .map_err(|_| Error::OwnershipMismatch)?;
        }
        Ok(())
    }
    pub(super) fn matches(&self, drain: &NativeJobDrain) -> bool {
        self.creator == std::process::id()
            && drain.creator == self.creator
            && std::rc::Rc::ptr_eq(&self.state, &drain.state)
    }
    pub(super) fn kind(&self) -> NativeJobKind {
        self.kind
    }
    pub(super) fn same_charge(&self, other: &Self) -> bool {
        std::rc::Rc::ptr_eq(&self.charge, &other.charge)
    }
    pub(super) fn fully_retired(&self) -> bool {
        self.creator == std::process::id()
            && self.retired
            && self.lower_done
            && self.charge.retired.get()
            && self.state.get() == NativeJobState::TransferredResources
            && self.reap.status(self.creator) == Some(0)
    }
    #[cfg(test)]
    pub(crate) fn lab_refuse_repeated_lower_retirement(&self) -> Result<()> {
        let lower = self.lower.as_ref().ok_or(Error::OwnershipMismatch)?;
        if !self.fully_retired()
            || lower.require_completed_capacity() != Err(vprouter_native_role::Error::Native)
            || lower.retire_completed_capacity() != Err(vprouter_native_role::Error::Native)
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
    #[cfg(test)]
    pub(crate) fn lab_eligible_foreign_refusal(&self) -> Result<serde_json::Value> {
        self.verify()?;
        capacity_lab::eligible_foreign(self.lower.as_ref().ok_or(Error::OwnershipMismatch)?)
    }
    #[cfg(test)]
    pub(crate) fn lab_evidence(&self) -> Result<serde_json::Value> {
        if self.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        let (pid, start) = match &self.reap {
            NativeJobReap::Local(r) => (r.pid, r.start.get()),
            NativeJobReap::Wireguard(r) => r.original().map_err(|_| Error::OwnershipMismatch)?,
        };
        let gated = self
            .lower
            .as_ref()
            .map(|r| {
                r.lab_gated_capacity_refused()
                    .map_err(|_| Error::OwnershipMismatch)
            })
            .transpose()?;
        if gated == Some(false) {
            return Err(Error::OwnershipMismatch);
        }
        Ok(
            serde_json::json!({"kind":format!("{:?}",self.kind),"original_pid":pid,"original_start":start,
            "actual_wait_status":self.reap.status(self.creator),"transfer_started":self.retired,
            "launch_charge_retired":self.charge.retired.get(),"lower_charge_required":self.lower.is_some(),
            "lower_charge_retired":self.lower.as_ref().map(|_|self.lower_done),"lower_gated_retirement_refused":gated,"fully_retired":self.fully_retired(),
            "native_job_state":match self.state.get(){NativeJobState::Born=>"born",NativeJobState::TransferredResources=>"transferred_resources",_=>"invalid"}}),
        )
    }
    /// Call only from the retained assembly after complete registry reservation.
    /// The state changes first so every partial error remains permanently nonquiet.
    pub(super) fn retire_capacity(&mut self) -> Result<()> {
        self.verify()?;
        self.state.set(NativeJobState::TransferredResources);
        self.retired = true;
        if let Some(lower) = &self.lower {
            lower
                .retire_completed_capacity()
                .map_err(|_| Error::OwnershipMismatch)?;
            self.lower_done = true;
        }
        self.charge.retire()
    }
}
/// Constructor-derived actual parent waitpid evidence. Deserialized identities,
/// received pidfds and process absence cannot construct this capability.
#[derive(Clone)]
pub(super) struct NativeReapProof {
    creator: u32,
    pid: u32,
    start: u64,
    status: i32,
    original: std::rc::Rc<ParentReap>,
}
impl NativeReapProof {
    pub(super) fn identity(&self) -> Result<(u32, u64, i32)> {
        if self.creator != std::process::id()
            || self.original.creator != self.creator
            || self.original.pid != self.pid
            || self.original.start.get() != Some(self.start)
            || self.original.status.get() != Some(self.status)
            || self.start == 0
            || (!libc::WIFEXITED(self.status) && !libc::WIFSIGNALED(self.status))
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok((self.pid, self.start, self.status))
    }
}
struct ParentReap {
    creator: u32,
    pid: u32,
    start: std::cell::Cell<Option<u64>>,
    status: std::cell::Cell<Option<i32>>,
}
impl ParentReap {
    fn born(pid: u32) -> Option<std::rc::Rc<Self>> {
        Some(std::rc::Rc::new(Self {
            creator: std::process::id(),
            pid,
            start: std::cell::Cell::new(None),
            status: std::cell::Cell::new(None),
        }))
    }
    fn poll(&self, pid: u32, pidfd: BorrowedFd<'_>) -> Result<Option<i32>> {
        if self.creator != std::process::id() || self.pid != pid {
            return Err(Error::OwnershipMismatch);
        }
        if let Some(status) = self.status.get() {
            return Ok(Some(status));
        }
        if !wait_ready(pidfd, Duration::ZERO)? {
            return Ok(None);
        }
        let mut status = 0;
        // SAFETY: creator-bound original native direct child, retained by its
        // exact registered pidfd. ECHILD/absence is never a successful receipt.
        if unsafe { libc::waitpid(self.pid as i32, &mut status, libc::WNOHANG) } != self.pid as i32
        {
            return Err(Error::ChildFailed);
        }
        if !libc::WIFEXITED(status) && !libc::WIFSIGNALED(status) {
            return Err(Error::ChildFailed);
        }
        self.status.set(Some(status));
        Ok(Some(status))
    }
}

/// A real external-owner child. Guard/service kill targets never include the
/// separately placed expiry scopes. No Drop path resumes or kills the guard.
pub(super) struct RemovedGuard {
    proof: GuardQuiescence,
}
impl RemovedGuard {
    pub(super) fn verify(
        &self,
        birth: &super::owned::GuardBirth,
        group: super::owned::Identity,
    ) -> Result<()> {
        self.proof.verify(birth, group)
    }
}
pub(super) struct ManagedGuard {
    native: Option<ManagedGuardNative>,
}
pub(super) struct ManagedGuardNative {
    creator: u32,
    pub child: Survivor,
    pub channel: OwnedFd,
    _channel_inventory: super::inventory::Registration,
    _scope: super::supervision::Scope,
    birth: super::owned::GuardBirth,
    #[cfg(test)]
    lab_removed_scope: Option<std::rc::Rc<std::cell::Cell<bool>>>,
    _attempt: Option<super::owned::PlannedAttempt>,
    _capacity: ChildCapacity,
    producer: Option<super::producer::Drain>,
    drain_error: Option<Error>,
    drained: std::rc::Rc<std::cell::Cell<bool>>,
}
impl std::ops::Deref for ManagedGuard {
    type Target = ManagedGuardNative;
    fn deref(&self) -> &Self::Target {
        self.native.as_ref().expect("retained managed guard")
    }
}
impl std::ops::DerefMut for ManagedGuard {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.native.as_mut().expect("retained managed guard")
    }
}
thread_local! { static RETIRED_GUARDS: std::cell::RefCell<Vec<ManagedGuardNative>> = const { std::cell::RefCell::new(Vec::new()) }; }
impl Drop for ManagedGuard {
    fn drop(&mut self) {
        if let Some(mut native) = self.native.take() {
            if native.creator != std::process::id() {
                return;
            }
            if rustix::net::shutdown(&native.channel, rustix::net::Shutdown::Both).is_err() {
                native.drain_error.get_or_insert(Error::DescriptorPolicy);
            }
            if let Err(error) = send_or_exited(native.child.pidfd(), libc::SIGSTOP) {
                native.drain_error.get_or_insert(error);
            }
            RETIRED_GUARDS.with(|guards| guards.borrow_mut().push(native));
        }
    }
}
fn poll_retired_guards() {
    RETIRED_GUARDS.with(|guards| {
        guards.borrow_mut().retain_mut(|native| {
            if native.creator != std::process::id() {
                return true;
            }
            let _ = rustix::net::shutdown(&native.channel, rustix::net::Shutdown::Both);
            if let Err(error) = send_or_exited(native.child.pidfd(), libc::SIGSTOP) {
                native.drain_error.get_or_insert(error);
            }
            let result = (|| {
                if !native.child.reap_exited()? {
                    return Ok(false);
                }
                #[cfg(test)]
                if let Some(witness) = &native.lab_removed_scope {
                    if native._scope.population()?
                        != super::supervision::ScopePopulation::RemovedOriginal
                    {
                        return Ok(false);
                    }
                    witness.set(true);
                }
                if !native._scope.quiescent()? {
                    return Ok(false);
                }
                if let Some(producer) = &native.producer
                    && !producer.empty()?
                {
                    return Ok(false);
                }
                Ok(true)
            })();
            match result {
                Ok(true) => {
                    native.drained.set(true);
                    false
                }
                Ok(false) => true,
                Err(error) => {
                    native.drain_error.get_or_insert(error);
                    true
                }
            }
        })
    });
}
/// Original root waitpid and original Scope no-live observation. This does not
/// include other member jobs, expiry, producer or canonical cleanup authority.
#[derive(Clone)]
pub(super) struct GuardQuiescence {
    creator: u32,
    birth: super::owned::GuardBirth,
    group: super::owned::Identity,
    reap: NativeReapProof,
}
impl GuardQuiescence {
    pub(super) fn verify(
        &self,
        birth: &super::owned::GuardBirth,
        group: super::owned::Identity,
    ) -> Result<()> {
        let (pid, start, _) = self.reap.identity()?;
        if self.creator != std::process::id()
            || &self.birth != birth
            || self.group != group
            || (pid, start) != (birth.pid, birth.start)
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
}
impl ManagedGuard {
    #[cfg(test)]
    pub(super) fn lab_require_removed_scope(
        &mut self,
    ) -> Result<std::rc::Rc<std::cell::Cell<bool>>> {
        if self.creator != std::process::id() || self.lab_removed_scope.is_some() {
            return Err(Error::OwnershipMismatch);
        }
        let witness = std::rc::Rc::new(std::cell::Cell::new(false));
        self.lab_removed_scope = Some(witness.clone());
        Ok(witness)
    }
    #[cfg(test)]
    pub(super) fn lab_drain_receipt(&self) -> Result<GuardDrain> {
        if self.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        Ok(GuardDrain {
            creator: self.creator,
            complete: self.drained.clone(),
            root: self
                .child
                .reap
                .as_ref()
                .ok_or(Error::OwnershipMismatch)?
                .clone(),
        })
    }
    #[cfg(test)]
    pub(super) fn lab_native_handle(&self) -> Result<Survivor> {
        if self.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        self.child.lab_clone_native()
    }
    #[cfg(test)]
    pub(super) fn lab_require_foreign_inert(&self) -> Result<()> {
        self.child._inventory.lab_require_inert()?;
        self._channel_inventory.lab_require_inert()?;
        self._scope.lab_require_inert()?;
        if rustix::net::send(&self.channel, b"excluded", rustix::net::SendFlags::NOSIGNAL)
            != Err(rustix::io::Errno::NOTSOCK)
        {
            return Err(Error::DescriptorPolicy);
        }
        Ok(())
    }
    pub(super) fn original_creator(&self) -> u32 {
        self.creator
    }
    pub(super) fn retirement_pidfd(&self) -> Result<(OwnedFd, super::inventory::Registration)> {
        self.original_birth()?;
        if !self.child._inventory.contains(self.child.pinned.as_fd()) {
            return Err(Error::DescriptorPolicy);
        }
        let fd = self
            .child
            .pinned
            .try_clone()
            .map_err(|_| Error::DescriptorDuplicate)?;
        let registration = super::inventory::Registration::owned(&[fd.as_fd()])?;
        Ok((fd, registration))
    }
    pub(super) fn retire_bookkeeping(
        &mut self,
        permit: &super::owned::QuiescentPermit,
        service: &super::owned::JournalServer,
    ) -> Result<()> {
        permit.verify_guard(service, self)?;
        self._attempt
            .as_mut()
            .ok_or(Error::OwnershipMismatch)?
            .retire_bookkeeping(permit, service)?;
        self.producer
            .as_mut()
            .ok_or(Error::OwnershipMismatch)?
            .retire_bookkeeping(permit, service)
    }
    pub(super) fn retirement_quiescence(&self) -> Result<Option<GuardQuiescence>> {
        if !self.retirement_drained()? {
            return Ok(None);
        }
        let birth = self.original_birth()?;
        let reap = self
            .child
            .retirement_reap(birth.start)?
            .ok_or(Error::OwnershipMismatch)?;
        Ok(Some(GuardQuiescence {
            creator: self.creator,
            birth,
            group: self._scope.retained_identity()?,
            reap,
        }))
    }
    pub(super) fn retirement_drained(&self) -> Result<bool> {
        self.original_birth()?;
        if !self.child.reap_exited()? || !self._scope.quiescent()? {
            return Ok(false);
        }
        if let Some(producer) = &self.producer {
            return producer.empty();
        }
        Err(Error::OwnershipMismatch)
    }
    pub(super) fn removed_root_proof(&self) -> Result<RemovedGuard> {
        if !self.retirement_root_removed()? {
            return Err(Error::OwnershipMismatch);
        }
        let birth = self.original_birth()?;
        let reap = self
            .child
            .retirement_reap(birth.start)?
            .ok_or(Error::OwnershipMismatch)?;
        Ok(RemovedGuard {
            proof: GuardQuiescence {
                creator: self.creator,
                birth,
                group: self._scope.retained_identity()?,
                reap,
            },
        })
    }
    pub(super) fn release_retired(
        &mut self,
        permit: &super::owned::RetiredPermit,
        service: &super::owned::JournalServer,
    ) -> Result<()> {
        permit.verify_guard_release(service, self)?;
        let native = self.native.take().ok_or(Error::OwnershipMismatch)?;
        native.drained.set(true);
        drop(native);
        Ok(())
    }
    pub(super) fn retirement_root_removed(&self) -> Result<bool> {
        self.original_birth()?;
        Ok(self.child.reap_exited()?
            && self._scope.population()? == super::supervision::ScopePopulation::RemovedOriginal)
    }
    pub(super) fn retirement_removed(&self) -> Result<bool> {
        if !self.retirement_root_removed()? {
            return Ok(false);
        }
        self.producer
            .as_ref()
            .ok_or(Error::OwnershipMismatch)?
            .empty()
    }
    pub(super) fn retirement_group(&self) -> Result<super::owned::Identity> {
        self.original_birth()?;
        self._scope.retained_identity()
    }
    pub(super) fn revoke_owner_channel(&self) -> Result<()> {
        self.original_birth()?;
        rustix::net::shutdown(&self.channel, rustix::net::Shutdown::Both)
            .map_err(|_| Error::DescriptorPolicy)
    }
    pub(super) fn original_birth(&self) -> Result<super::owned::GuardBirth> {
        if self.creator != std::process::id()
            || self._attempt.is_none()
            || self.child.pid != self.birth.pid
            || self.child.reap.as_ref().is_none_or(|r| {
                r.creator != self.creator
                    || r.pid != self.birth.pid
                    || r.start.get() != Some(self.birth.start)
            })
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(self.birth.clone())
    }
    pub fn freeze(&self) -> Result<()> {
        if self.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        send_or_exited(self.child.pidfd(), libc::SIGSTOP)
    }
}
#[cfg(test)]
pub(super) fn lab_retained_guard(witness: &Survivor) -> Result<()> {
    let receipt = witness.reap.as_ref().ok_or(Error::OwnershipMismatch)?;
    if receipt.creator != std::process::id() {
        return Err(Error::OwnershipMismatch);
    }
    RETIRED_GUARDS.with(|guards| {
        let guards = guards.borrow();
        let native = guards
            .iter()
            .find(|native| {
                native.creator == std::process::id()
                    && native
                        .child
                        .reap
                        .as_ref()
                        .is_some_and(|r| std::rc::Rc::ptr_eq(r, receipt))
            })
            .ok_or(Error::OwnershipMismatch)?;
        if !native
            .child
            ._inventory
            .contains(native.child.pinned.as_fd())
            || !native._channel_inventory.contains(native.channel.as_fd())
            || native.producer.is_none()
            || native._attempt.is_none()
            || !native._scope.registered()
        {
            return Err(Error::DescriptorInventory);
        }
        // Local shutdown has revoked this exact original owner endpoint.
        let mut byte = [0u8; 1];
        if rustix::net::recv(&native.channel, &mut byte, rustix::net::RecvFlags::DONTWAIT)
            != Ok((0, 0))
        {
            return Err(Error::DescriptorPolicy);
        }
        Ok(())
    })
}
pub(super) struct OwnerSignals {
    creator: u32,
    set: libc::sigset_t,
}
thread_local! { static OWNER_STOP: std::cell::Cell<(u32, Option<Error>)> = const { std::cell::Cell::new((0, None)) }; }
impl OwnerSignals {
    pub fn new() -> Result<Self> {
        Ok(Self {
            creator: std::process::id(),
            set: blocked_signals()?,
        })
    }
    pub(super) fn fence(&self, reason: Error) -> Result<()> {
        if self.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        OWNER_STOP.with(|slot| {
            let (creator, existing) = slot.get();
            slot.set((
                self.creator,
                if creator == self.creator {
                    existing.or(Some(reason))
                } else {
                    Some(reason)
                },
            ));
        });
        Ok(())
    }
    pub fn stop_requested(&self) -> Result<bool> {
        if self.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        let reason = OWNER_STOP.with(|slot| {
            let (creator, reason) = slot.get();
            if creator == self.creator {
                reason
            } else {
                None
            }
        });
        if let Some(reason) = reason {
            return if reason == Error::Interrupted {
                Ok(true)
            } else {
                Err(reason)
            };
        }
        match pending_now(&self.set) {
            Ok(Some(libc::SIGTERM | libc::SIGINT | libc::SIGHUP)) => {
                self.fence(Error::Interrupted)?;
                Ok(true)
            }
            Ok(_) => Ok(false),
            Err(error) => {
                self.fence(error)?;
                Err(error)
            }
        }
    }
}
pub(super) fn owner_admission_permitted() -> Result<()> {
    if OwnerSignals::new()?.stop_requested()? {
        return Err(Error::Interrupted);
    }
    Ok(())
}
#[cfg(test)]
pub(super) fn lab_queue_owner_stop() -> Result<()> {
    OwnerSignals::new()?;
    cv(
        unsafe { libc::kill(libc::getpid(), libc::SIGTERM) },
        Error::ChildFailed,
    )?;
    Ok(())
}
/// Isolated original children: never queue a stop or change the permanent latch
/// in the selftest parent. Signal timing is not a router performance claim.
#[cfg(test)]
fn lab_owner_signal_poll() -> Result<()> {
    use rustix::net::{self, RecvFlags, SendFlags};
    process::single_threaded()?;
    let foreign = OwnerSignals::new()?;
    let creator = std::process::id();
    for case in 0..6 {
        let (parent, child) = net::socketpair(
            net::AddressFamily::UNIX,
            net::SocketType::SEQPACKET,
            net::SocketFlags::CLOEXEC,
            None,
        )
        .map_err(|_| Error::DescriptorPolicy)?;
        let parent_token = super::inventory::Registration::owned(&[parent.as_fd()])?;
        let child_token = super::inventory::Registration::owned(&[child.as_fd()])?;
        let (pid, pinned) = fork_with_pidfd()?;
        if pid == 0 {
            let result = (|| {
                parent_death(creator as i32)?;
                close_except(&[child.as_raw_fd()])?;
                if foreign.stop_requested() != Err(Error::OwnershipMismatch)
                    || foreign.fence(Error::Interrupted) != Err(Error::OwnershipMismatch)
                {
                    return Err(Error::OwnershipMismatch);
                }
                let signals = OwnerSignals::new()?;
                let mut times = [0u64; 3];
                if case == 0 {
                    // SIGCHLD alone is consumed without becoming stop authority.
                    cv(
                        unsafe { libc::kill(libc::getpid(), libc::SIGCHLD) },
                        Error::ChildFailed,
                    )?;
                    if signals.stop_requested()? || pending_now(&signals.set)?.is_some() {
                        return Err(Error::OwnershipMismatch);
                    }
                    // Warm both actual syscall paths, then four ABBA rounds.
                    if pending(&signals.set)?.is_some() || pending_now(&signals.set)?.is_some() {
                        return Err(Error::ChildFailed);
                    }
                    for _ in 0..4 {
                        for timed in [true, false, false, true] {
                            let at = Instant::now();
                            let signal = if timed {
                                pending(&signals.set)?
                            } else {
                                pending_now(&signals.set)?
                            };
                            if signal.is_some() {
                                return Err(Error::ChildFailed);
                            }
                            times[usize::from(!timed)] += u64::try_from(at.elapsed().as_nanos())
                                .map_err(|_| Error::TooLarge)?;
                        }
                    }
                    let at = Instant::now();
                    for _ in 0..8 {
                        if signals.stop_requested()? {
                            return Err(Error::OwnershipMismatch);
                        }
                    }
                    times[2] =
                        u64::try_from(at.elapsed().as_nanos()).map_err(|_| Error::TooLarge)?;
                } else if case <= 3 {
                    let stop = [libc::SIGTERM, libc::SIGINT, libc::SIGHUP][case - 1];
                    cv(
                        unsafe { libc::kill(libc::getpid(), libc::SIGCHLD) },
                        Error::ChildFailed,
                    )?;
                    cv(
                        unsafe { libc::kill(libc::getpid(), stop) },
                        Error::ChildFailed,
                    )?;
                    if !signals.stop_requested()?
                        || !OwnerSignals::new()?.stop_requested()?
                        || owner_admission_permitted() != Err(Error::Interrupted)
                    {
                        return Err(Error::OwnershipMismatch);
                    }
                    // Native consumption, not a pending-stop observation, set
                    // the latch. Only CHLD may remain after the exact stop.
                    for _ in 0..2 {
                        if pending_now(&signals.set)?.is_some_and(|s| s != libc::SIGCHLD) {
                            return Err(Error::OwnershipMismatch);
                        }
                    }
                    if !OwnerSignals::new()?.stop_requested()? {
                        return Err(Error::OwnershipMismatch);
                    }
                } else if case == 4 {
                    signals.fence(Error::DescriptorInventory)?;
                    if signals.stop_requested() != Err(Error::DescriptorInventory)
                        || OwnerSignals::new()?.stop_requested() != Err(Error::DescriptorInventory)
                        || owner_admission_permitted() != Err(Error::DescriptorInventory)
                    {
                        return Err(Error::OwnershipMismatch);
                    }
                }
                if case == 5 {
                    // Real isolated native syscall error, not an injected bool.
                    // This test-only filter denies only the signal read; it is
                    // not a role confinement profile or any production policy.
                    cv(
                        unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) },
                        Error::ConfinementPolicy,
                    )?;
                    let mut denied_read = filter()[..4].to_vec();
                    denied_read.extend([
                        libc::sock_filter {
                            code: 0x15,
                            jt: 0,
                            jf: 1,
                            k: libc::SYS_rt_sigtimedwait as u32,
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
                    ]);
                    apply_filter(&denied_read)?;
                    if pending_now(&signals.set) != Err(Error::ChildFailed)
                        || signals.stop_requested() != Err(Error::ChildFailed)
                        || OwnerSignals::new()?.stop_requested() != Err(Error::ChildFailed)
                        || owner_admission_permitted() != Err(Error::ChildFailed)
                    {
                        return Err(Error::OwnershipMismatch);
                    }
                }
                let mut bytes = [0u8; 24];
                for (slot, value) in bytes.chunks_exact_mut(8).zip(times) {
                    slot.copy_from_slice(&value.to_le_bytes());
                }
                if net::send(&child, &bytes, SendFlags::DONTWAIT | SendFlags::NOSIGNAL)
                    .map_err(|_| Error::ChildFailed)?
                    != bytes.len()
                {
                    return Err(Error::ChildFailed);
                }
                Ok(())
            })();
            die(if result.is_ok() { 0 } else { 122 });
        }
        let reap = ParentReap::born(pid as u32);
        drop(child_token);
        drop(child);
        let pinned = pinned.expect("atomic original child pidfd");
        let registration = match super::inventory::Registration::owned(&[pinned.as_fd()]) {
            Ok(value) => value,
            Err(error) => {
                retain_fork_bundle_with_reap(
                    pid,
                    pinned,
                    parent,
                    None,
                    vec![parent_token],
                    Vec::new(),
                    None,
                    None,
                    None,
                    reap,
                    None,
                );
                return Err(error);
            }
        };
        let original = Survivor {
            pid: pid as u32,
            pinned,
            _inventory: registration,
            reap,
        };
        let result = (|| {
            if !wait_ready(&original.pinned, Duration::from_secs(2))?
                || original.reap_status()? != Some(0)
            {
                return Err(Error::ChildFailed);
            }
            let mut bytes = [0u8; 24];
            if net::recv(&parent, &mut bytes, RecvFlags::DONTWAIT | RecvFlags::TRUNC)
                .map_err(|_| Error::ChildFailed)?
                != (24, 24)
            {
                return Err(Error::ChildFailed);
            }
            let mut times = [0u64; 3];
            for (value, slot) in times.iter_mut().zip(bytes.chunks_exact(8)) {
                *value = u64::from_le_bytes(slot.try_into().map_err(|_| Error::ChildFailed)?);
            }
            if case == 0 {
                let nonblocking = times[2] < times[0] / 4;
                println!(
                    "LAB_OWNER_SIGNAL_POLL {}",
                    serde_json::json!({
                    "warmup_per_path":1,"abba_rounds":4,"samples_per_path":8,
                    "timed_total_ns":times[0],"nonblocking_total_ns":times[1],
                    "owner_poll_total_ns":times[2],"owner_nonblocking_contract":nonblocking,
                    "actual_native_wait_status":0,"router_performance_claim":false})
                );
                if !nonblocking {
                    return Err(Error::Deadline);
                }
            }
            Ok(())
        })();
        if let Err(error) = result {
            let Survivor {
                pid,
                pinned,
                _inventory,
                reap,
            } = original;
            retain_fork_bundle_with_reap(
                pid as i32,
                pinned,
                parent,
                None,
                vec![parent_token, _inventory],
                Vec::new(),
                None,
                None,
                None,
                reap,
                None,
            );
            return Err(error);
        }
    }
    println!(
        "LAB_OWNER_SIGNAL_SEMANTICS {{\"native_children_actual_wait_zero\":6,\"term_int_hup_with_sigchld_consumed_and_latched\":true,\"sigchld_alone_not_stop\":true,\"foreign_creator_refused\":true,\"permanent_error_preserved\":true,\"native_signal_error_latched\":true}}"
    );
    Ok(())
}

fn guard_no_ptrace() -> Result<()> {
    #[repr(C)]
    struct Header {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Data {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    let header = Header {
        version: 0x20080522,
        pid: 0,
    };
    let mut data = [Data {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    cv(
        unsafe { libc::syscall(libc::SYS_capget, &header, data.as_mut_ptr()) as i32 },
        Error::ChildFailed,
    )?;
    cv(
        unsafe { libc::prctl(libc::PR_CAPBSET_DROP, 19, 0, 0, 0) },
        Error::ChildFailed,
    )?;
    data[0].effective &= !(1 << 19);
    data[0].permitted &= !(1 << 19);
    data[0].inheritable &= !(1 << 19);
    cv(
        unsafe { libc::syscall(libc::SYS_capset, &header, data.as_ptr()) as i32 },
        Error::ChildFailed,
    )?;
    cv(
        unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) },
        Error::ChildFailed,
    )?;
    let mut actual = [Data {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    cv(
        unsafe { libc::syscall(libc::SYS_capget, &header, actual.as_mut_ptr()) as i32 },
        Error::ChildFailed,
    )?;
    if (actual[0].effective | actual[0].permitted | actual[0].inheritable) & (1 << 19) != 0
        || unsafe { libc::prctl(libc::PR_CAPBSET_READ, 19, 0, 0, 0) } != 0
    {
        return Err(Error::ChildFailed);
    }
    Ok(())
}
#[cfg(test)]
pub(super) fn terminal_after_containment() -> Result<()> {
    send(unsafe { BorrowedFd::borrow_raw(12) }, libc::SIGSTOP)
}
/// Only the verified child inventory boundary calls this replacement. Keeping
/// the old numeric slot occupied prevents copied OwnedFd destructors from closing
/// a subsequently reused descriptor. Source is a distinct retained /dev/null FD.
pub(super) fn inert_guard_slot(source: &OwnedFd, destination: i32) -> Result<()> {
    if destination < 3 || source.as_raw_fd() == destination {
        return Err(Error::DescriptorPolicy);
    }
    // SAFETY: both exact live slots were verified by GuardBoundary; single task,
    // child only, source remains retained, no Rust owner is created or forgotten.
    cv(
        unsafe { libc::dup3(source.as_raw_fd(), destination, libc::O_CLOEXEC) },
        Error::DescriptorPolicy,
    )?;
    Ok(())
}
fn gate_remaining(deadline: f64, now: f64) -> Result<Duration> {
    if !deadline.is_finite() || !now.is_finite() || now < 0. || now >= deadline {
        return Err(Error::Deadline);
    }
    Duration::try_from_secs_f64(deadline - now).map_err(|_| Error::Deadline)
}
pub(super) struct PendingGuard {
    native: Option<PendingGuardNative>,
}
pub(super) struct GuardDrain {
    creator: u32,
    complete: std::rc::Rc<std::cell::Cell<bool>>,
    #[cfg(test)]
    root: std::rc::Rc<ParentReap>,
}
impl GuardDrain {
    #[cfg(test)]
    pub(super) fn lab_status(&self) -> Result<Option<i32>> {
        self.drained()?;
        Ok(self.root.status.get())
    }
    pub(super) fn drained(&self) -> Result<bool> {
        if self.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        Ok(self.complete.get())
    }
}
struct PendingGuardNative {
    creator: u32,
    domains: super::supervision::Domains,
    child: Survivor,
    channel: OwnedFd,
    inventory: super::inventory::Registration,
    scope: Option<super::supervision::Scope>,
    placement: Option<PlacementChild>,
    born_at: f64,
    gate_deadline: f64,
    attempt: Option<super::owned::PlannedAttempt>,
    reaped: bool,
    failure: Option<Error>,
    capacity: ChildCapacity,
    producer: Option<super::producer::Drain>,
    drained: std::rc::Rc<std::cell::Cell<bool>>,
}
thread_local! { static FAILED_GUARDS: std::cell::RefCell<Vec<PendingGuardNative>> = const { std::cell::RefCell::new(Vec::new()) }; }
impl PendingGuard {
    pub(super) fn drain_receipt(&self) -> Result<GuardDrain> {
        let native = self.native.as_ref().ok_or(Error::Interrupted)?;
        if native.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        Ok(GuardDrain {
            creator: native.creator,
            complete: native.drained.clone(),
            #[cfg(test)]
            root: native
                .child
                .reap
                .as_ref()
                .ok_or(Error::OwnershipMismatch)?
                .clone(),
        })
    }
    pub(super) fn spawn(
        domains: &super::supervision::Domains,
        owner: &super::supervision::OwnerDomain,
        inputs: super::inventory::GuardInputs,
        attempt: super::owned::PlannedAttempt,
        run: impl FnOnce(BorrowedFd<'_>) -> Result<()>,
    ) -> Result<Self> {
        attempt.verify(domains, owner, &inputs)?;
        fork_owned_guard(domains, inputs, Some(attempt), run)
    }
    fn native(&self) -> Result<&PendingGuardNative> {
        owner_admission_permitted()?;
        let native = self.native.as_ref().ok_or(Error::Interrupted)?;
        if native.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        if let Some(error) = native.failure {
            return Err(error);
        }
        gate_remaining(native.gate_deadline, vprouter_core::health::boot_seconds())?;
        native.child.require_live()?;
        Ok(native)
    }
    pub(super) fn child(&self) -> Result<&Survivor> {
        Ok(&self.native()?.child)
    }
    pub(super) fn birth(&self) -> Result<super::owned::GuardBirth> {
        let native = self.native()?;
        Ok(super::owned::GuardBirth {
            pid: native.child.pid(),
            start: native.child.start_time()?,
            born_at: native.born_at,
            gate_deadline: native.gate_deadline,
        })
    }
    pub(super) fn domains(&self) -> Result<&super::supervision::Domains> {
        Ok(&self.native()?.domains)
    }
    pub(super) fn start_placement(&mut self, receipt: &super::owned::BornAttempt) -> Result<()> {
        receipt.verify(self)?;
        self.native()?;
        let native = self.native.as_mut().ok_or(Error::Interrupted)?;
        if native.placement.is_some() || native.scope.is_some() {
            return Err(Error::Interrupted);
        }
        let plan = native.attempt.as_ref().ok_or(Error::OwnershipMismatch)?;
        native.placement = Some(spawn_placement(
            &native.domains,
            &native.child,
            super::supervision::Role::Guard,
            plan.lease(),
            native.gate_deadline,
            #[cfg(test)]
            false,
        )?);
        Ok(())
    }
    pub(super) fn poll_placement(&mut self) -> Result<bool> {
        self.native()?;
        let native = self.native.as_mut().ok_or(Error::Interrupted)?;
        if native.scope.is_some() {
            return Ok(true);
        }
        let placement = native.placement.as_mut().ok_or(Error::Interrupted)?;
        let Some(receipt) = placement.poll()? else {
            return Ok(false);
        };
        native.domains.complete_placement_retained(
            &native.child,
            super::supervision::Role::Guard,
            receipt,
            &mut native.scope,
        )?;
        native.placement = None;
        Ok(true)
    }
    pub(super) fn group_identity(&self) -> Result<super::owned::Identity> {
        let native = self.native()?;
        let scope = native.scope.as_ref().ok_or(Error::CgroupMismatch)?;
        scope.verify(&native.child)?;
        super::owned::Identity::of(scope.retained_fd())
    }
    pub(super) fn release(mut self, receipt: super::owned::ReleaseAttempt) -> Result<ManagedGuard> {
        receipt.verify(&self)?;
        self.native()?;
        self.finish()
    }
    fn finish(&mut self) -> Result<ManagedGuard> {
        let birth = self.birth()?;
        let native = self.native()?;
        native
            .scope
            .as_ref()
            .ok_or(Error::CgroupMismatch)?
            .verify(&native.child)?;
        write_byte(&native.channel, 1)?;
        let native = self.native.take().ok_or(Error::Interrupted)?;
        Ok(ManagedGuard {
            native: Some(ManagedGuardNative {
                creator: native.creator,
                child: native.child,
                channel: native.channel,
                _channel_inventory: native.inventory,
                _scope: native.scope.ok_or(Error::CgroupMismatch)?,
                birth,
                #[cfg(test)]
                lab_removed_scope: None,
                _attempt: native.attempt,
                _capacity: native.capacity,
                producer: native.producer,
                drain_error: None,
                drained: native.drained,
            }),
        })
    }
}
impl Drop for PendingGuard {
    fn drop(&mut self) {
        if let Some(mut native) = self.native.take() {
            if native.creator != std::process::id() {
                return;
            }
            native.failure.get_or_insert(Error::Interrupted);
            let _ = send_or_exited(native.child.pidfd(), libc::SIGKILL);
            if let Some(placement) = &mut native.placement {
                let _ = placement.cancel();
            }
            FAILED_GUARDS.with(|guards| guards.borrow_mut().push(native));
        }
    }
}
fn poll_failed_guards() {
    FAILED_GUARDS.with(|guards| {
        guards.borrow_mut().retain_mut(|native| {
            if native.creator != std::process::id() {
                return true;
            }
            let _ = send_or_exited(native.child.pidfd(), libc::SIGKILL);
            if let Some(placement) = &mut native.placement {
                let _ = placement.cancel();
                if !placement.drained() {
                    let _ = placement.poll();
                }
            }
            if !native.reaped {
                match native.child.reap_exited() {
                    Ok(true) => native.reaped = true,
                    Ok(false) => {}
                    Err(error) => {
                        native.failure.get_or_insert(error);
                    }
                }
            }
            let drained = native.reaped
                && native.placement.as_ref().is_none_or(|p| p.drained())
                && native
                    .producer
                    .as_ref()
                    .is_none_or(|p| p.empty() == Ok(true));
            if drained {
                // Only this native collector publishes completion, after both
                // exact root waitpid and any placement helper's actual reap.
                native.drained.set(true);
            }
            !drained
        })
    });
}
/// Legacy fixed fixtures are kept while the operational owner uses PendingGuard.
#[cfg(test)]
pub(super) fn spawn_owned_guard(
    domains: &super::supervision::Domains,
    inputs: super::inventory::GuardInputs,
    run: impl FnOnce(BorrowedFd<'_>) -> Result<()>,
) -> Result<ManagedGuard> {
    domains.verify_owner()?;
    let mut pending = fork_owned_guard(domains, inputs, None, run)?;
    let native = pending.native.as_mut().ok_or(Error::Interrupted)?;
    domains.place_retained(
        &native.child,
        super::supervision::Role::Guard,
        &mut native.scope,
    )?;
    pending.finish()
}
fn fork_owned_guard(
    domains: &super::supervision::Domains,
    mut inputs: super::inventory::GuardInputs,
    attempt: Option<super::owned::PlannedAttempt>,
    run: impl FnOnce(BorrowedFd<'_>) -> Result<()>,
) -> Result<PendingGuard> {
    inputs.binds(domains)?;
    let producer = inputs.take_producer()?;
    super::inventory::verify()?;
    // Descendant guards must not recover private owner/executor endpoints via
    // procfs, ptrace or pidfd_getfd. This owner is never dumpable.
    cv(
        unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) },
        Error::ChildFailed,
    )?;
    let parent_pid = std::process::id() as i32;
    let (parent, child) = rustix::net::socketpair(
        rustix::net::AddressFamily::UNIX,
        rustix::net::SocketType::SEQPACKET,
        rustix::net::SocketFlags::CLOEXEC | rustix::net::SocketFlags::NONBLOCK,
        None,
    )
    .map_err(|_| Error::DescriptorPolicy)?;
    let parent_inventory = super::inventory::Registration::owned(&[parent.as_fd()])?;
    let child_inventory = super::inventory::Registration::owned(&[child.as_fd()])?;
    inputs.include(&child_inventory, super::inventory::GuardAuthority::Gate)?;
    let boundary = inputs.seal()?;
    // SAFETY: host one-task preflight, no live async runtime, inherited exact
    // owners only; this fixed child never unwinds or returns to the parent.
    owner_admission_permitted()?;
    super::producer::begin_guard(domains)?;
    let born_at = vprouter_core::health::boot_seconds();
    let gate_deadline = born_at + 3.;
    let (pid, pinned) = fork_with_pidfd()?;
    if pid == 0 {
        let result = (|| {
            // Owner death freezes the guard. It must NEVER be continued; the
            // independent writers retain their own original terminal deadlines.
            cv(
                unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGSTOP, 0, 0, 0) },
                Error::ChildFailed,
            )?;
            if unsafe { libc::getppid() } != parent_pid {
                return Err(Error::ChildFailed);
            }
            // Remove private authority before placement wait or any role code.
            // On partial failure exit immediately; do not unwind foreign owners.
            if boundary.enter().is_err() {
                die(122);
            }
            drop(parent_inventory);
            drop(parent);
            if !wait_ready(
                &child,
                gate_remaining(gate_deadline, vprouter_core::health::boot_seconds())?,
            )? || read_byte(&child)? != 1
                || vprouter_core::health::boot_seconds() >= gate_deadline
            {
                return Err(Error::Deadline);
            }
            process::single_threaded()?;
            guard_no_ptrace()?;
            super::inventory::verify()?;
            run(child.as_fd())
        })();
        #[cfg(test)]
        if let Err(error) = result {
            eprintln!("LAB_OWNED_GUARD_FAILURE phase=before_retained_drain reason={error}");
        }
        // Child Drop runs in this process. The parent's TLS collector cannot
        // see these bundles. Retain/collect here even if the closure failed;
        // uncertainty leaves the owner available for freeze/containment, never
        // releases a lease or pretends a direct-root reap drained descendants.
        while !early_forks_drained() {
            let _ = poll_early_forks();
            std::thread::sleep(Duration::from_millis(1));
        }
        if let Err(error) = result {
            #[cfg(test)]
            eprintln!("LAB_OWNED_GUARD_FAILURE reason={error}");
            #[cfg(not(test))]
            let _ = error;
            die(122);
        }
        die(0);
    }
    drop(child_inventory);
    drop(child);
    let pinned = pinned.ok_or(Error::ChildFailed)?;
    let inventory = match super::inventory::Registration::owned(&[pinned.as_fd()]) {
        Ok(inventory) => inventory,
        Err(error) => {
            retain_fork_bundle_with_reap(
                pid,
                pinned,
                parent,
                None,
                vec![parent_inventory],
                Vec::new(),
                None,
                attempt,
                None,
                ParentReap::born(pid as u32),
                producer,
            );
            return Err(error);
        }
    };
    let child = Survivor {
        pid: pid as u32,
        reap: ParentReap::born(pid as u32),
        pinned,
        _inventory: inventory,
    };
    let pending = PendingGuard {
        native: Some(PendingGuardNative {
            creator: std::process::id(),
            domains: domains.clone(),
            child,
            channel: parent,
            inventory: parent_inventory,
            scope: None,
            placement: None,
            born_at,
            gate_deadline,
            attempt,
            reaped: false,
            failure: None,
            capacity: ChildCapacity::created(),
            producer,
            drained: std::rc::Rc::new(std::cell::Cell::new(false)),
        }),
    };
    super::producer::bind_guard(domains, pending.child()?)?;
    Ok(pending)
}
impl Survivor {
    pub(super) fn retirement_reap(&self, original_start: u64) -> Result<Option<NativeReapProof>> {
        if original_start == 0
            || self
                .reap
                .as_ref()
                .is_none_or(|r| r.start.get() != Some(original_start))
        {
            return Err(Error::OwnershipMismatch);
        }
        let Some(status) = self.reap_status()? else {
            return Ok(None);
        };
        Ok(Some(NativeReapProof {
            creator: std::process::id(),
            pid: self.pid,
            start: original_start,
            status,
            original: self.reap.as_ref().ok_or(Error::OwnershipMismatch)?.clone(),
        }))
    }
    fn reap_status(&self) -> Result<Option<i32>> {
        let receipt = self.reap.as_ref().ok_or(Error::OwnershipMismatch)?;
        if receipt.creator != std::process::id()
            || receipt.pid != self.pid
            || !self._inventory.contains(self.pinned.as_fd())
        {
            return Err(Error::OwnershipMismatch);
        }
        receipt.poll(self.pid, self.pidfd())
    }
    pub fn reap_exited(&self) -> Result<bool> {
        Ok(self.reap_status()?.is_some())
    }
    pub fn pid(&self) -> u32 {
        self.pid
    }
    pub fn start_time(&self) -> Result<u64> {
        self.require_live()?;
        let bytes = read_fixed(&format!("/proc/{}/stat", self.pid), 65536)
            .map_err(|_| Error::ProcessUnavailable)?;
        let start = process::stat_start(
            std::str::from_utf8(&bytes).map_err(|_| Error::ProcessChanged)?,
            self.pid,
        )?;
        self.require_live()?;
        if let Some(receipt) = &self.reap
            && receipt.creator == std::process::id()
        {
            if receipt.pid != self.pid || receipt.start.get().is_some_and(|old| old != start) {
                return Err(Error::ProcessChanged);
            }
            receipt.start.set(Some(start));
        }
        Ok(start)
    }
    pub fn pidfd(&self) -> BorrowedFd<'_> {
        self.pinned.as_fd()
    }
    pub fn require_live(&self) -> Result<()> {
        if wait_ready(&self.pinned, Duration::ZERO)? {
            Err(Error::ChildFailed)
        } else {
            Ok(())
        }
    }
    pub fn identity(
        &self,
        scope: u8,
        namespace: super::owned::Identity,
    ) -> Result<super::owned::ExecutorIdentity> {
        let start_time = self.start_time()?;
        Ok(super::owned::ExecutorIdentity {
            scope,
            pid: self.pid,
            start_time,
            namespace,
        })
    }
}
pub(super) fn current_process_identity() -> Result<(u32, u64)> {
    let pid = std::process::id();
    let bytes = read_fixed("/proc/self/stat", 65536).map_err(|_| Error::ProcessUnavailable)?;
    Ok((
        pid,
        process::stat_start(
            std::str::from_utf8(&bytes).map_err(|_| Error::ProcessChanged)?,
            pid,
        )?,
    ))
}
pub(super) struct TerminalGuardIdentity {
    pid: u32,
    start: u64,
}
fn terminal_guard_dead(guard: impl AsFd) -> Result<bool> {
    // Use the fixed role's permitted ppoll syscall on BOTH architectures. The
    // generic libc poll helper uses SYS_poll on x86 and is deliberately denied.
    let mut descriptors = [rustix::event::PollFd::new(
        &guard,
        rustix::event::PollFlags::IN,
    )];
    rustix::event::poll(
        &mut descriptors,
        Some(&rustix::event::Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        }),
    )
    .map_err(|_| Error::ChildFailed)?;
    let events = descriptors[0].revents();
    if events.intersects(rustix::event::PollFlags::ERR | rustix::event::PollFlags::NVAL) {
        return Err(Error::ChildFailed);
    }
    Ok(events.intersects(rustix::event::PollFlags::IN | rustix::event::PollFlags::HUP))
}
pub(super) fn stop_terminal_guard(
    guard: impl AsFd,
    identity: &TerminalGuardIdentity,
    deadline: f64,
) -> Result<()> {
    if terminal_guard_dead(&guard)? {
        return Ok(());
    }
    if let Err(error) = send(&guard, libc::SIGSTOP) {
        // The original pidfd may report death between the initial check and
        // signal; only actual readiness makes that race harmless.
        if terminal_guard_dead(&guard)? {
            return Ok(());
        }
        return Err(error);
    }
    loop {
        if terminal_guard_dead(&guard)? {
            return Ok(());
        }
        if vprouter_core::health::boot_seconds() >= deadline {
            return Err(Error::Deadline);
        }
        let mut bytes = [0u8; 4096];
        let n = rustix::io::pread(unsafe { BorrowedFd::borrow_raw(13) }, &mut bytes, 0)
            .map_err(|_| Error::ProcessChanged)?;
        let text = std::str::from_utf8(&bytes[..n]).map_err(|_| Error::ProcessChanged)?;
        if process::stat_start(text, identity.pid)? != identity.start {
            return Err(Error::ProcessChanged);
        }
        if process::stat_stopped(text, identity.pid, identity.start).is_ok() {
            return Ok(());
        }
        let mut descriptors = [rustix::event::PollFd::new(
            &guard,
            rustix::event::PollFlags::IN,
        )];
        let delay = rustix::event::Timespec::try_from(Duration::from_millis(1))
            .map_err(|_| Error::Deadline)?;
        rustix::event::poll(&mut descriptors, Some(&delay)).map_err(|_| Error::Deadline)?;
    }
}
/// Every endpoint is created here, while single threaded, and inherited by one
/// fixed child. SO_PEERCRED from a pre-fork socketpair is NOT child identity.
/// Parent binds the returned fork pidfd and exact endpoint inventory instead.
struct EarlyFork {
    creator: u32,
    producer: Option<super::producer::Drain>,
    #[cfg(test)]
    receipt_recorded: bool,
    reap: Option<std::rc::Rc<ParentReap>>,
    _attempt: Option<super::owned::PlannedAttempt>,
    _lease: Option<super::owned::MutatorLease>,
    _scope: Option<super::supervision::Scope>,
    pid: i32,
    pidfd: OwnedFd,
    _control: OwnedFd,
    _identity: Option<super::daemon::Process>,
    _retained_pins: Vec<OwnedFd>,
    _inventory: Vec<super::inventory::Registration>,
    inventory_error: Option<Error>,
    drain_error: Option<Error>,
}
thread_local! { static EARLY_FORKS: std::cell::RefCell<Vec<EarlyFork>> = const { std::cell::RefCell::new(Vec::new()) }; }
// Test evidence survives collection while asynchronous admission continues.
// Only the successful native waitpid path below records these receipts.
#[cfg(test)]
struct LabEarlyReaps {
    receipts: std::collections::BTreeMap<(u32, u32, u64), i32>,
    failed: bool,
}
#[cfg(test)]
impl LabEarlyReaps {
    const fn new() -> Self {
        Self {
            receipts: std::collections::BTreeMap::new(),
            failed: false,
        }
    }
    fn record(&mut self, key: (u32, u32, u64), status: i32) {
        if self.failed || self.receipts.len() >= 64 || self.receipts.contains_key(&key) {
            self.failed = true;
            return;
        }
        self.receipts.insert(key, status);
    }
    fn get(&self, key: (u32, u32, u64)) -> Result<Option<i32>> {
        if self.failed {
            return Err(Error::TooLarge);
        }
        Ok(self.receipts.get(&key).copied())
    }
}
#[cfg(test)]
thread_local! { static LAB_EARLY_REAPS: std::cell::RefCell<LabEarlyReaps> = const { std::cell::RefCell::new(LabEarlyReaps::new()) }; }
#[cfg(test)]
pub(super) fn lab_early_reap(identity: (u32, u64)) -> Result<Option<i32>> {
    let creator = std::process::id();
    let pending = EARLY_FORKS.with(|actors| {
        actors.borrow().iter().any(|actor| {
            actor.creator == creator
                && !actor.receipt_recorded
                && actor.pid == identity.0 as i32
                && actor
                    ._identity
                    .as_ref()
                    .is_some_and(|process| (process.pid(), process.start()) == identity)
        })
    });
    let receipt = LAB_EARLY_REAPS
        .with(|receipts| receipts.borrow().get((creator, identity.0, identity.1)))?;
    match (pending, receipt) {
        (true, None) => Ok(None),
        (false, Some(status)) => Ok(Some(status)),
        _ => Err(Error::OwnershipMismatch),
    }
}
#[cfg(test)]
thread_local! { static NATIVE_BIRTHS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) }; }
#[cfg(test)]
pub(super) fn lab_native_births() -> u64 {
    NATIVE_BIRTHS
        .with(std::cell::Cell::get)
        .saturating_add(vprouter_native_role::native_birth_count())
}
fn fork_with_pidfd() -> Result<(i32, Option<OwnedFd>)> {
    require_child_capacity()?;
    fork_with_pidfd_capacity_checked()
}
fn require_child_capacity() -> Result<()> {
    if EARLY_FORKS.with(|actors| {
        actors
            .borrow()
            .iter()
            .filter(|actor| actor.creator == std::process::id())
            .count()
    }) + live_child_count()
        >= 64
    {
        return Err(Error::LockBusy);
    }
    Ok(())
}
fn fork_with_pidfd_capacity_checked() -> Result<(i32, Option<OwnedFd>)> {
    #[repr(C)]
    #[derive(Default)]
    struct CloneArgs {
        flags: u64,
        pidfd: u64,
        child_tid: u64,
        parent_tid: u64,
        exit_signal: u64,
        stack: u64,
        stack_size: u64,
        tls: u64,
        set_tid: u64,
        set_tid_size: u64,
        cgroup: u64,
    }
    let mut descriptor = -1i32;
    let args = CloneArgs {
        flags: libc::CLONE_PIDFD as u64,
        pidfd: (&mut descriptor as *mut i32) as u64,
        exit_signal: libc::SIGCHLD as u64,
        ..CloneArgs::default()
    };
    // SAFETY: single-threaded fork semantics, no shared VM/stack; Linux atomically
    // returns the exact child pidfd, so fd exhaustion cannot orphan an unpinned child.
    let pid =
        unsafe { libc::syscall(libc::SYS_clone3, &args, std::mem::size_of::<CloneArgs>()) } as i32;
    if pid < 0 {
        return Err(Error::ChildFailed);
    }
    #[cfg(test)]
    if pid > 0 {
        NATIVE_BIRTHS.with(|count| count.set(count.get() + 1));
    }
    Ok((
        pid,
        if pid > 0 {
            Some(unsafe { OwnedFd::from_raw_fd(descriptor) })
        } else {
            None
        },
    ))
}
fn retain_survivor(
    child: Survivor,
    control: OwnedFd,
    identity: Option<super::daemon::Process>,
    mut inventory: Vec<super::inventory::Registration>,
    retained_pins: Vec<OwnedFd>,
) {
    inventory.push(child._inventory);
    retain_fork_bundle_with_reap(
        child.pid as i32,
        child.pinned,
        control,
        identity,
        inventory,
        retained_pins,
        None,
        None,
        None,
        child.reap,
        None,
    );
}
fn retain_early_fork(pid: i32, pidfd: OwnedFd, control: OwnedFd) {
    retain_registered_fork(pid, pidfd, control, None, Vec::new());
}
fn retain_registered_fork(
    pid: i32,
    pidfd: OwnedFd,
    control: OwnedFd,
    identity: Option<super::daemon::Process>,
    inventory: Vec<super::inventory::Registration>,
) {
    retain_registered_fork_with_pins(pid, pidfd, control, identity, inventory, Vec::new());
}
fn retain_registered_fork_with_pins(
    pid: i32,
    pidfd: OwnedFd,
    control: OwnedFd,
    identity: Option<super::daemon::Process>,
    inventory: Vec<super::inventory::Registration>,
    retained_pins: Vec<OwnedFd>,
) {
    retain_fork_bundle(
        pid,
        pidfd,
        control,
        identity,
        inventory,
        retained_pins,
        None,
    );
}
fn retain_fork_bundle(
    pid: i32,
    pidfd: OwnedFd,
    control: OwnedFd,
    identity: Option<super::daemon::Process>,
    inventory: Vec<super::inventory::Registration>,
    retained_pins: Vec<OwnedFd>,
    scope: Option<super::supervision::Scope>,
) {
    retain_fork_bundle_with_attempt(
        pid,
        pidfd,
        control,
        identity,
        inventory,
        retained_pins,
        scope,
        None,
    );
}
#[allow(clippy::too_many_arguments)]
fn retain_fork_bundle_with_attempt(
    pid: i32,
    pidfd: OwnedFd,
    control: OwnedFd,
    identity: Option<super::daemon::Process>,
    inventory: Vec<super::inventory::Registration>,
    retained_pins: Vec<OwnedFd>,
    scope: Option<super::supervision::Scope>,
    attempt: Option<super::owned::PlannedAttempt>,
) {
    retain_fork_bundle_with_holds(
        pid,
        pidfd,
        control,
        identity,
        inventory,
        retained_pins,
        scope,
        attempt,
        None,
    );
}
#[allow(clippy::too_many_arguments)]
fn retain_fork_bundle_with_holds(
    pid: i32,
    pidfd: OwnedFd,
    control: OwnedFd,
    identity: Option<super::daemon::Process>,
    inventory: Vec<super::inventory::Registration>,
    retained_pins: Vec<OwnedFd>,
    scope: Option<super::supervision::Scope>,
    attempt: Option<super::owned::PlannedAttempt>,
    lease: Option<super::owned::MutatorLease>,
) {
    retain_fork_bundle_with_reap(
        pid,
        pidfd,
        control,
        identity,
        inventory,
        retained_pins,
        scope,
        attempt,
        lease,
        ParentReap::born(pid as u32),
        None,
    );
}
#[allow(clippy::too_many_arguments)]
fn retain_fork_bundle_with_reap(
    pid: i32,
    pidfd: OwnedFd,
    control: OwnedFd,
    identity: Option<super::daemon::Process>,
    mut inventory: Vec<super::inventory::Registration>,
    retained_pins: Vec<OwnedFd>,
    scope: Option<super::supervision::Scope>,
    attempt: Option<super::owned::PlannedAttempt>,
    lease: Option<super::owned::MutatorLease>,
    reap: Option<std::rc::Rc<ParentReap>>,
    producer: Option<super::producer::Drain>,
) {
    // Move existing registration owners with their complete native bundle. Never
    // unregister/re-register live handles or leave a token covering closed pins.
    let mut fds = vec![pidfd.as_fd(), control.as_fd()];
    fds.extend(retained_pins.iter().map(AsFd::as_fd));
    if let Some(scope) = &scope
        && !scope.registered()
    {
        fds.push(scope.retained_fd());
    }
    if let Some(identity) = &identity {
        fds.extend(identity.fds());
    }
    let missing: Vec<_> = fds
        .into_iter()
        .filter(|fd| !inventory.iter().any(|owned| owned.contains(*fd)))
        .collect();
    let inventory_error = if missing.is_empty() {
        None
    } else {
        match super::inventory::Registration::owned(&missing) {
            Ok(registered) => {
                inventory.push(registered);
                None
            }
            Err(error) => Some(error),
        }
    };
    // Even registration or signal failure cannot discard native ownership.
    // The collector still reaps; unresolved registration remains a fail-closed error.
    let _ = send_or_exited(pidfd.as_fd(), libc::SIGKILL);
    EARLY_FORKS.with(|actors| {
        actors.borrow_mut().push(EarlyFork {
            creator: std::process::id(),
            reap,
            producer,
            #[cfg(test)]
            receipt_recorded: false,
            _attempt: attempt,
            _lease: lease,
            _scope: scope,
            pid,
            pidfd,
            _control: control,
            _identity: identity,
            _retained_pins: retained_pins,
            _inventory: inventory,
            inventory_error,
            drain_error: None,
        })
    });
}
pub(super) fn early_forks_drained() -> bool {
    #[cfg(test)]
    if !capacity_lab::children_reaped() {
        return false;
    }

    TERMINAL_BIRTHS.with(|births| {
        births
            .borrow()
            .iter()
            .all(|birth| birth.creator != std::process::id())
    }) && super::expiry::retired_owners_drained()
        && RETIRED_GUARDS.with(|guards| {
            guards
                .borrow()
                .iter()
                .all(|native| native.creator != std::process::id())
        })
        && host_audit::retired_drained()
        && retirement::retired_drained()
        && cleanup::retired_drained()
        && secret::retired_drained()
        && docker_query::retired_drained()
        && namespace_attachment::children_reaped()
        && fresh_transport::children_reaped()
        && fresh_transport_mount::children_reaped()
        && wireguard_role::children_reaped()
        && host_link::children_reaped()
        && netfilter_role::children_reaped()
        && producer_creation::children_reaped()
        && producer_binding::children_reaped()
        && bootstrap::children_reaped()
        && vprouter_netfilter::retained_native_children_reaped()
        && vprouter_network::retained_secret_children_reaped()
        && super::owned::preparation::retained_children_reaped()
        && super::secret::retained_children_reaped()
        && super::attachment::retained_children_reaped()
        && RETIRED_JOURNAL_IO.with(|pending| {
            pending
                .borrow()
                .iter()
                .all(|p| p.creator != std::process::id())
        })
        && FAILED_GUARDS.with(|guards| {
            guards
                .borrow()
                .iter()
                .all(|g| g.creator != std::process::id())
        })
        && EARLY_FORKS.with(|actors| {
            actors
                .borrow()
                .iter()
                .all(|actor| actor.creator != std::process::id())
        })
        && RETIRED_CHILDREN.with(|children| {
            children
                .borrow()
                .iter()
                .all(|child| child._capacity.charge.creator != std::process::id())
        })
        && super::producer::retired_drained()
}
pub(super) fn poll_early_forks() -> Result<()> {
    #[cfg(test)]
    capacity_lab::poll_retained();

    super::expiry::poll_retired_owners();
    poll_terminal_births();
    poll_retired_guards();
    poll_failed_guards();
    poll_retired_journal_io();
    host_audit::poll_retired();
    secret::poll_retired();
    docker_query::poll_retired();
    namespace_attachment::poll_retained();
    fresh_transport::poll_retained();
    fresh_transport_mount::poll_retained();
    wireguard_role::poll_retained();
    host_link::poll_retained();
    netfilter_role::poll_retained();
    producer_creation::poll_retained();
    producer_binding::poll_retained();
    bootstrap::poll_retained();
    vprouter_netfilter::poll_retained_native();
    vprouter_network::poll_retained_secret_roles();
    super::owned::preparation::poll_retained();
    super::secret::poll_retained();
    super::attachment::poll_retained();
    retirement::poll_retired();
    cleanup::poll_retired();
    super::producer::poll_retired();
    let retired = poll_retired_children();
    let early = EARLY_FORKS.with(|actors| {
        let mut actors = actors.borrow_mut();
        let mut index = 0;
        let mut failure = None;
        while index < actors.len() {
            if actors[index].creator != std::process::id() {
                index += 1;
                continue;
            }
            if let Some(error) = actors[index].inventory_error {
                failure.get_or_insert(error);
            }
            let status = match actors[index].reap.as_ref().ok_or(Error::OwnershipMismatch)
                .and_then(|receipt| receipt.poll(actors[index].pid as u32, actors[index].pidfd.as_fd()))
            {
                Ok(Some(status)) => status,
                Ok(None) => { index += 1; continue; }
                Err(error) => {
                    actors[index].drain_error.get_or_insert(error);
                    index += 1;
                    continue;
                }
            };
            #[cfg(not(test))]
            let _ = status;
            #[cfg(test)]
            if !actors[index].receipt_recorded
                && let Some(identity) = &actors[index]._identity
                && identity.pid() == actors[index].pid as u32
                && (libc::WIFEXITED(status) || libc::WIFSIGNALED(status))
            {
                LAB_EARLY_REAPS.with(|receipts| {
                    receipts.borrow_mut().record(
                        (actors[index].creator, identity.pid(), identity.start()),
                        status,
                    );
                });
                eprintln!(
                    "LAB_EARLY_FORK_REAP creator={} pid={} start={} status={status} actual_waitpid=true",
                    actors[index].creator, identity.pid(), identity.start()
                );
                actors[index].receipt_recorded = true;
            }
            if actors[index].producer.as_ref().is_some_and(|producer| producer.empty() != Ok(true)) {
                index += 1;
                continue;
            }
            // Native handles AND exact registration owners leave together only
            // after actual waitpid, so later descriptor reuse has no stale token.
            actors.remove(index);
        }
        failure.map_or(Ok(()), Err)
    });
    retired.and(early)
}
// Independent terminal writers never enter the kill-on-error EarlyFork collector.
// One constructor-owned record remains even if its caller fails before receiving
// a Survivor. It owns the capacity charge and original parent reap capability.
struct TerminalBirth {
    creator: u32,
    pid: u32,
    pinned: OwnedFd,
    reap: std::rc::Rc<ParentReap>,
    _capacity: ChildCapacity,
    control: OwnedFd,
    _namespace: OwnedFd,
    _lease: OwnedFd,
    _guard: OwnedFd,
    _guard_stat: OwnedFd,
    _completion_reader: Option<OwnedFd>,
    _inventory: Vec<super::inventory::Registration>,
    scope: Option<super::supervision::Scope>,
    domains: Option<super::supervision::Domains>,
    _policy: vprouter_netfilter::Policy,
    _binding: vprouter_core::health::Binding,
    scope_index: u8,
    started_at: f64,
    error: Option<Error>,
}
#[cfg(test)]
thread_local! { static LAB_FAIL_TERMINAL_PARENT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }
#[cfg(test)]
pub(super) fn lab_fail_next_terminal_parent() {
    LAB_FAIL_TERMINAL_PARENT.with(|flag| flag.set(true));
}
thread_local! { static TERMINAL_BIRTHS: std::cell::RefCell<Vec<TerminalBirth>> = const { std::cell::RefCell::new(Vec::new()) }; }
fn poll_terminal_births() {
    TERMINAL_BIRTHS.with(|births| {
        births.borrow_mut().retain_mut(|birth| {
            if birth.creator != std::process::id() {
                return true;
            }
            match birth.reap.poll(birth.pid, birth.pinned.as_fd()) {
                Ok(Some(_)) => {
                    // A failed constructor may be the sole owner of unread
                    // completion evidence. Reconciliation consumes that owner;
                    // native reap alone must not discard its context.
                    if birth.error.is_some() {
                        return true;
                    }
                    if let Some(scope) = &birth.scope {
                        match scope.quiescent() {
                            Ok(true) => {}
                            Ok(false) => return true,
                            Err(error) => {
                                birth.error.get_or_insert(error);
                                return true;
                            }
                        }
                    }
                    false
                }
                Ok(None) => true,
                Err(error) => {
                    birth.error.get_or_insert(error);
                    true
                }
            }
        });
    });
}
pub(super) fn terminal_births_drained(allocation: &str, exit: &str, lifecycle: &str) -> bool {
    TERMINAL_BIRTHS.with(|births| {
        births.borrow().iter().all(|birth| {
            birth.creator != std::process::id()
                || birth.domains.as_ref().is_some_and(|domains| {
                    domains.allocation() != allocation
                        || domains.exit_id() != exit
                        || domains.lifecycle() != lifecycle
                })
        })
    })
}
impl Survivor {
    pub(super) fn revoke_terminal_control(&self) -> Result<()> {
        let original = self.reap.as_ref().ok_or(Error::OwnershipMismatch)?;
        if original.creator != std::process::id()
            || original.pid != self.pid
            || !self._inventory.contains(self.pinned.as_fd())
        {
            return Err(Error::OwnershipMismatch);
        }
        TERMINAL_BIRTHS.with(|births| {
            let births = births.borrow();
            let birth = births.iter().find(|birth| {
                birth.creator == std::process::id()
                    && birth.pid == self.pid
                    && std::rc::Rc::ptr_eq(&birth.reap, original)
            });
            match birth {
                Some(birth) => rustix::net::shutdown(&birth.control, rustix::net::Shutdown::Both)
                    .map_err(|_| Error::DescriptorPolicy),
                None if original.status.get().is_some() => Ok(()),
                None => Err(Error::OwnershipMismatch),
            }
        })
    }
}
#[cfg(test)]
pub(super) fn lab_terminal_birth(
    domains: &super::supervision::Domains,
    scope: u8,
) -> Result<(Survivor, f64, bool)> {
    TERMINAL_BIRTHS.with(|births| {
        let births = births.borrow();
        let mut matches = births.iter().filter(|birth| {
            birth.creator == std::process::id()
                && birth.scope_index == scope
                && birth.domains.as_ref().is_some_and(|actual| {
                    actual.allocation() == domains.allocation()
                        && actual.exit_id() == domains.exit_id()
                        && actual.lifecycle() == domains.lifecycle()
                })
        });
        let birth = matches.next().ok_or(Error::OwnershipMismatch)?;
        if matches.next().is_some() || birth.reap.start.get().is_none() {
            return Err(Error::OwnershipMismatch);
        }
        let mut retained = vec![
            birth.pinned.as_fd(),
            birth.control.as_fd(),
            birth._namespace.as_fd(),
            birth._lease.as_fd(),
            birth._guard.as_fd(),
            birth._guard_stat.as_fd(),
        ];
        if let Some(reader) = &birth._completion_reader {
            retained.push(reader.as_fd());
        }
        if retained.iter().any(|fd| {
            !birth
                ._inventory
                .iter()
                .any(|registration| registration.contains(*fd))
        }) {
            return Err(Error::DescriptorInventory);
        }
        let pinned = birth
            .pinned
            .try_clone()
            .map_err(|_| Error::DescriptorDuplicate)?;
        let inventory = super::inventory::Registration::owned(&[pinned.as_fd()])?;
        Ok((
            Survivor {
                pid: birth.pid,
                pinned,
                reap: Some(birth.reap.clone()),
                _inventory: inventory,
            },
            birth.started_at,
            birth.error.is_some(),
        ))
    })
}
pub(super) struct OwnerTerminal<'a> {
    pub guard: &'a Survivor,
    pub completion: BorrowedFd<'a>,
    pub completion_reader: BorrowedFd<'a>,
    #[cfg(test)]
    pub stop_after_containment: bool,
}
pub(super) fn spawn_terminal(
    namespace: impl AsFd,
    lease: impl AsFd,
    policy: &vprouter_netfilter::Policy,
    init: super::expiry::ChildBinding<'_>,
    domains: Option<&super::supervision::Domains>,
    owner: Option<OwnerTerminal<'_>>,
) -> Result<(Survivor, OwnedFd)> {
    let super::expiry::ChildBinding {
        binding,
        lifecycle,
        scope,
        started_at,
    } = init;
    process::host_preflight()?;
    if let Some(domains) = domains
        && owner.is_none()
    {
        domains.verify_guard()?;
    }
    super::inventory::verify()?;
    let namespace_id = super::owned::Identity::network(&namespace)?;
    let guard = if let Some(owner) = &owner {
        owner.guard.require_live()?;
        rustix::io::fcntl_dupfd_cloexec(owner.guard.pidfd(), 3)
            .map_err(|_| Error::DescriptorDuplicate)?
    } else {
        pidfd(std::process::id() as i32)?
    };
    let _guard_inventory = super::inventory::Registration::owned(&[guard.as_fd()])?;
    let (guard_pid, guard_start) = if let Some(owner) = &owner {
        (owner.guard.pid(), owner.guard.start_time()?)
    } else {
        current_process_identity()?
    };
    let guard_identity = TerminalGuardIdentity {
        pid: guard_pid,
        start: guard_start,
    };
    let guard_stat = fs::open(
        format!("/proc/{guard_pid}/stat"),
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| Error::ProcessChanged)?;
    let _stat_inventory = super::inventory::Registration::owned(&[guard_stat.as_fd()])?;
    let (parent_socket, child_socket) = rustix::net::socketpair(
        rustix::net::AddressFamily::UNIX,
        rustix::net::SocketType::SEQPACKET,
        rustix::net::SocketFlags::CLOEXEC | rustix::net::SocketFlags::NONBLOCK,
        None,
    )
    .map_err(|_| Error::DescriptorPolicy)?;
    // All original parent context is pinned and registered before native birth.
    // The reader is intentionally distinct from the child's private writer.
    let held_namespace = namespace
        .as_fd()
        .try_clone_to_owned()
        .map_err(|_| Error::DescriptorDuplicate)?;
    let held_lease = lease
        .as_fd()
        .try_clone_to_owned()
        .map_err(|_| Error::DescriptorDuplicate)?;
    let held_control = parent_socket
        .try_clone()
        .map_err(|_| Error::DescriptorDuplicate)?;
    let held_reader = owner
        .as_ref()
        .map(|owner| {
            owner
                .completion_reader
                .try_clone_to_owned()
                .map_err(|_| Error::DescriptorDuplicate)
        })
        .transpose()?;
    let mut parent_fds = vec![
        held_namespace.as_fd(),
        held_lease.as_fd(),
        held_control.as_fd(),
    ];
    if let Some(reader) = &held_reader {
        parent_fds.push(reader.as_fd());
    }
    let parent_inventory = super::inventory::Registration::owned(&parent_fds)?;
    let _channel_inventory = super::inventory::Registration::owned(&[parent_socket.as_fd()])?;
    let child_inventory = super::inventory::Registration::owned(&[child_socket.as_fd()])?;
    // SAFETY: verified single thread, fixed role, no unwind, no parent-death kill.
    let (pid, pinned) = fork_with_pidfd()?;
    if pid == 0 {
        let mut channel_ready = false;
        let result = (|| {
            // Operational writers cannot begin until PID1 placed the exact child
            // in a sibling scope and the parent independently read it back.
            drop(parent_socket);
            // Namespace identity is established while the actor is still gated;
            // no network sockets or mutation exist before durable registration.
            enter(namespace.as_fd(), libc::CLONE_NEWNET)?;
            if domains.is_some()
                && (!wait_ready(&child_socket, Duration::from_secs(3))?
                    || read_byte(&child_socket)? != 1)
            {
                return Err(Error::Deadline);
            }
            cv(
                unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, 0, 0, 0, 0) },
                Error::ChildFailed,
            )?;
            cv(unsafe { libc::clearenv() }, Error::ChildFailed)?;
            let channel = std::mem::ManuallyDrop::new(
                rustix::io::fcntl_dupfd_cloexec(&child_socket, 110)
                    .map_err(|_| Error::DescriptorDuplicate)?,
            );
            let guard = std::mem::ManuallyDrop::new(
                rustix::io::fcntl_dupfd_cloexec(&guard, 110)
                    .map_err(|_| Error::DescriptorDuplicate)?,
            );
            let lease = std::mem::ManuallyDrop::new(
                rustix::io::fcntl_dupfd_cloexec(&lease, 110)
                    .map_err(|_| Error::DescriptorDuplicate)?,
            );
            let null = std::mem::ManuallyDrop::new(
                fs::open(c"/dev/null", OFlags::RDWR | OFlags::CLOEXEC, Mode::empty())
                    .map_err(|_| Error::DescriptorNull)?,
            );
            for number in 0..3 {
                dup_fixed(&*null, number, false)?;
            }
            dup_fixed(&*channel, 3, true)?;
            channel_ready = true;
            dup_fixed(&*guard, 4, true)?;
            dup_fixed(&*lease, 5, true)?;
            let stat = rustix::io::fcntl_dupfd_cloexec(&guard_stat, 110)
                .map_err(|_| Error::DescriptorDuplicate)?;
            dup_fixed(&stat, 13, true)?;
            drop(stat);
            let has_completion = owner.is_some();
            if let Some(owner) = &owner {
                let completion = rustix::io::fcntl_dupfd_cloexec(owner.completion, 110)
                    .map_err(|_| Error::DescriptorDuplicate)?;
                dup_fixed(&completion, 11, true)?;
            }
            #[cfg(test)]
            let checkpoint = owner.as_ref().is_some_and(|o| o.stop_after_containment);
            #[cfg(test)]
            if checkpoint {
                let self_pid = pidfd(std::process::id() as i32)?;
                dup_fixed(&self_pid, 12, true)?;
                std::mem::forget(self_pid);
            }
            let mut keep = vec![3, 4, 5, 13];
            if has_completion {
                keep.push(11);
            }
            #[cfg(test)]
            if checkpoint {
                keep.push(12);
            }
            close_except(&keep)?;
            cv(
                unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) },
                Error::ChildFailed,
            )?;
            // New sockets are opened INSIDE the exact namespace. Neither is
            // inherited/duplicated from a guard's active netlink channel.
            let writer = vprouter_netfilter::TerminalQuarantine::open(
                policy,
                lifecycle,
                (namespace_id.dev, namespace_id.ino),
            )
            .map_err(|_| Error::NetworkPolicy)?;
            let recovery = vprouter_netfilter::TerminalQuarantine::open(
                policy,
                lifecycle,
                (namespace_id.dev, namespace_id.ino),
            )
            .map_err(|_| Error::NetworkPolicy)?;
            let timer = rustix::time::timerfd_create(
                rustix::time::TimerfdClockId::Boottime,
                rustix::time::TimerfdFlags::CLOEXEC | rustix::time::TimerfdFlags::NONBLOCK,
            )
            .map_err(|_| Error::Deadline)?;
            let fds = writer.descriptors();
            let backup = recovery.descriptors();
            if [
                fds[0].as_raw_fd(),
                fds[1].as_raw_fd(),
                backup[0].as_raw_fd(),
                backup[1].as_raw_fd(),
                timer.as_raw_fd(),
            ] != [6, 7, 8, 9, 10]
                || descriptor_inventory()? != {
                    let mut expected: std::collections::BTreeSet<_> = (0..=10).collect();
                    expected.insert(13);
                    if has_completion {
                        expected.insert(11);
                    }
                    #[cfg(test)]
                    if checkpoint {
                        expected.insert(12);
                    }
                    expected
                }
            {
                return Err(Error::DescriptorInventory);
            }
            terminal_capabilities()?;
            // Prove same-UID pidfd signal permission after dropping every cap
            // except NET_ADMIN; do not stop the healthy guard at registration.
            send(unsafe { BorrowedFd::borrow_raw(4) }, 0)?;
            apply_filter(&terminal_filter(
                #[cfg(test)]
                checkpoint,
            ))?;
            // Native positive under the installed exact role filter. A future
            // syscall mismatch must refuse registration/Ready, not fail at expiry.
            if terminal_guard_dead(unsafe { BorrowedFd::borrow_raw(4) })? {
                return Err(Error::ChildFailed);
            }
            super::expiry::run_child(
                unsafe { BorrowedFd::borrow_raw(3) },
                unsafe { BorrowedFd::borrow_raw(4) },
                &timer,
                &guard_identity,
                has_completion.then(|| unsafe { BorrowedFd::borrow_raw(11) }),
                #[cfg(test)]
                checkpoint,
                writer,
                recovery,
                super::expiry::ChildBinding {
                    binding,
                    lifecycle,
                    scope,
                    started_at,
                },
            )
        })();
        if let Err(error) = result {
            if channel_ready {
                super::expiry::child_failure(unsafe { BorrowedFd::borrow_raw(3) }, error);
            }
            die(122);
        }
        die(0);
    }
    drop(child_inventory);
    drop(child_socket);
    let pinned = pinned.ok_or(Error::ChildFailed)?;
    let reap = ParentReap::born(pid as u32).expect("positive native terminal birth");
    let mut birth = TerminalBirth {
        creator: std::process::id(),
        pid: pid as u32,
        pinned,
        reap: reap.clone(),
        _capacity: ChildCapacity::created(),
        control: held_control,
        _namespace: held_namespace,
        _lease: held_lease,
        _guard: guard,
        _guard_stat: guard_stat,
        _completion_reader: held_reader,
        _inventory: vec![parent_inventory, _guard_inventory, _stat_inventory],
        scope: None,
        domains: domains.cloned(),
        _policy: policy.clone(),
        _binding: binding.clone(),
        scope_index: scope,
        started_at,
        error: None,
    };
    // No fallible postclone operation can escape this retained birth owner.
    let result = (|| {
        birth
            ._inventory
            .push(super::inventory::Registration::owned(&[birth
                .pinned
                .as_fd()])?);
        let pinned = birth
            .pinned
            .try_clone()
            .map_err(|_| Error::DescriptorDuplicate)?;
        let inventory = super::inventory::Registration::owned(&[pinned.as_fd()])?;
        let child = Survivor {
            pid: pid as u32,
            reap: Some(reap),
            pinned,
            _inventory: inventory,
        };
        child.start_time()?;
        #[cfg(test)]
        if LAB_FAIL_TERMINAL_PARENT.with(|flag| flag.replace(false)) {
            return Err(Error::Interrupted);
        }
        if owner.is_none()
            && let Some(domains) = domains
        {
            let role = match scope {
                0 => super::supervision::Role::ExpiryHost,
                1 => super::supervision::Role::ExpiryTransport,
                2 => super::supervision::Role::ExpiryData,
                _ => return Err(Error::InvalidSpec),
            };
            domains.place_retained(&child, role, &mut birth.scope)?;
            birth
                .scope
                .as_ref()
                .ok_or(Error::CgroupMismatch)?
                .verify(&child)?;
            write_byte(&parent_socket, 1)?;
        }
        Ok(child)
    })();
    if let Err(error) = result {
        birth.error = Some(error);
        // Closing just one alias would suppress EOF because the retained parent
        // endpoint is still open. Shutdown triggers the existing terminal path;
        // it neither kills nor resumes this independent writer.
        let _ = rustix::net::shutdown(&birth.control, rustix::net::Shutdown::Both);
    }
    TERMINAL_BIRTHS.with(|births| births.borrow_mut().push(birth));
    result.map(|child| (child, parent_socket))
}

pub(super) fn release_terminal(socket: impl AsFd) -> Result<()> {
    write_byte(socket, 1)
}

pub(super) struct PlacementChild {
    #[cfg(test)]
    checkpoint_start: Option<u64>,
    child: Survivor,
    channel: OwnedFd,
    _inventory: super::inventory::Registration,
    deadline: f64,
    reaped: bool,
    cancelled: bool,
}
impl PlacementChild {
    pub fn cancel(&mut self) -> Result<()> {
        self.cancelled = true;
        if !self.reaped {
            send_or_exited(self.child.pidfd(), libc::SIGKILL)?;
        }
        Ok(())
    }
    pub fn drained(&self) -> bool {
        self.reaped
    }
    pub fn poll(&mut self) -> Result<Option<super::supervision::PlacementReceipt>> {
        if self.reaped {
            return Err(Error::Interrupted);
        }
        let Some(status) = self.child.reap_status()? else {
            return Ok(None);
        };
        self.reaped = true;
        if self.cancelled || !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
            return Err(Error::ChildFailed);
        }
        if vprouter_core::health::boot_seconds() >= self.deadline {
            return Err(Error::Deadline);
        }
        let mut bytes = [0; 2049];
        let (n, full) = rustix::net::recv(
            &self.channel,
            &mut bytes,
            rustix::net::RecvFlags::DONTWAIT | rustix::net::RecvFlags::TRUNC,
        )
        .map_err(|_| Error::DescriptorPolicy)?;
        if n == 0 || n != full || n > 2048 {
            return Err(Error::DescriptorPolicy);
        }
        serde_json::from_slice(&bytes[..n])
            .map(Some)
            .map_err(|_| Error::DescriptorPolicy)
    }
}
#[cfg(test)]
impl PlacementChild {
    pub fn lab_checkpoint(&mut self) -> Result<Option<(u32, u64, f64)>> {
        if self.checkpoint_start.is_none() {
            if !wait_ready(&self.channel, Duration::ZERO)? {
                return Ok(None);
            }
            if read_byte(&self.channel)? != 127 {
                return Err(Error::ChildFailed);
            }
            let start = self.child.start_time()?;
            self.child.lab_signal(libc::SIGSTOP)?;
            self.checkpoint_start = Some(start);
        }
        let start = self.checkpoint_start.ok_or(Error::ProcessChanged)?;
        if self.child.lab_require_stopped(start).is_err() {
            return Ok(None);
        }
        Ok(Some((self.child.pid(), start, self.deadline)))
    }
}
pub(super) fn spawn_placement(
    domains: &super::supervision::Domains,
    target: &Survivor,
    role: super::supervision::Role,
    lease: impl AsFd,
    deadline: f64,
    #[cfg(test)] pause_before_place: bool,
) -> Result<PlacementChild> {
    process::single_threaded()?;
    super::inventory::verify()?;
    target.require_live()?;
    let target_pid = target.pid();
    let target_start = target.start_time()?;
    #[cfg(test)]
    eprintln!(
        "LAB_GUARD_SCOPE_INTENT {}",
        serde_json::json!({"unit":domains.unit(role),"lifecycle":domains.lifecycle(),"exit_id":domains.exit_id(),"role":match role { super::supervision::Role::ExpiryHost=>"expiry-host",super::supervision::Role::ExpiryTransport=>"expiry-transport",super::supervision::Role::ExpiryData=>"expiry-data",super::supervision::Role::Guard=>"guard" },"allocation_digest":domains.allocation(),"pid":target_pid,"start_time":target_start})
    );
    let (parent, child) = rustix::net::socketpair(
        rustix::net::AddressFamily::UNIX,
        rustix::net::SocketType::SEQPACKET,
        rustix::net::SocketFlags::CLOEXEC | rustix::net::SocketFlags::NONBLOCK,
        None,
    )
    .map_err(|_| Error::DescriptorPolicy)?;
    // SAFETY: fixed single-thread child, no callback/input frame; exact retained target only.
    let (pid, pinned) = fork_with_pidfd()?;
    if pid == 0 {
        let result = (|| {
            let channel = std::mem::ManuallyDrop::new(
                rustix::io::fcntl_dupfd_cloexec(&child, 110)
                    .map_err(|_| Error::DescriptorDuplicate)?,
            );
            let pinned = std::mem::ManuallyDrop::new(
                rustix::io::fcntl_dupfd_cloexec(target.pidfd(), 110)
                    .map_err(|_| Error::DescriptorDuplicate)?,
            );
            let held = std::mem::ManuallyDrop::new(
                rustix::io::fcntl_dupfd_cloexec(&lease, 110)
                    .map_err(|_| Error::DescriptorDuplicate)?,
            );
            let null = std::mem::ManuallyDrop::new(
                fs::open(c"/dev/null", OFlags::RDWR | OFlags::CLOEXEC, Mode::empty())
                    .map_err(|_| Error::DescriptorNull)?,
            );
            for n in 0..3 {
                dup_fixed(&*null, n, false)?;
            }
            dup_fixed(&*channel, 3, true)?;
            dup_fixed(&*pinned, 4, true)?;
            dup_fixed(&*held, 5, true)?;
            close_except(&[3, 4, 5])?;
            let fixed_inventory = super::inventory::placement_role()?;
            // SAFETY: fixed pidfd4 was duplicated above; role never unwinds.
            let target = std::mem::ManuallyDrop::new(Survivor {
                pid: target_pid,
                reap: None,
                pinned: unsafe { OwnedFd::from_raw_fd(4) },
                _inventory: fixed_inventory,
            });
            if target.start_time()? != target_start
                || vprouter_core::health::boot_seconds() >= deadline
            {
                return Err(Error::ProcessChanged);
            }
            #[cfg(test)]
            if pause_before_place {
                // Fixed pre-send checkpoint: no PID1 mutation has been issued.
                // There is deliberately no release command or SIGCONT path.
                write_byte(unsafe { BorrowedFd::borrow_raw(3) }, 127)?;
                loop {
                    std::thread::sleep(Duration::from_secs(1));
                }
            }
            let scope = domains.place(&target, role)?;
            scope.verify(&target)?;
            if vprouter_core::health::boot_seconds() >= deadline {
                return Err(Error::Deadline);
            }
            let bytes =
                serde_json::to_vec(&scope.receipt()).map_err(|_| Error::DescriptorPolicy)?;
            if bytes.len() > 2048 {
                return Err(Error::TooLarge);
            }
            let n = rustix::net::send(
                unsafe { BorrowedFd::borrow_raw(3) },
                &bytes,
                rustix::net::SendFlags::DONTWAIT | rustix::net::SendFlags::NOSIGNAL,
            )
            .map_err(|_| Error::DescriptorPolicy)?;
            if n != bytes.len() {
                return Err(Error::DescriptorPolicy);
            }
            Ok(())
        })();
        die(if result.is_ok() { 0 } else { 122 });
    }
    drop(child);
    let pinned = pinned.ok_or(Error::ChildFailed)?;
    let child_inventory = match super::inventory::Registration::owned(&[pinned.as_fd()]) {
        Ok(inventory) => inventory,
        Err(error) => {
            retain_early_fork(pid, pinned, parent);
            return Err(error);
        }
    };
    let inventory = match super::inventory::Registration::owned(&[parent.as_fd()]) {
        Ok(inventory) => inventory,
        Err(error) => {
            retain_registered_fork(pid, pinned, parent, None, vec![child_inventory]);
            return Err(error);
        }
    };
    Ok(PlacementChild {
        #[cfg(test)]
        checkpoint_start: None,
        child: Survivor {
            pid: pid as u32,
            reap: ParentReap::born(pid as u32),
            pinned,
            _inventory: child_inventory,
        },
        channel: parent,
        _inventory: inventory,
        deadline,
        reaped: false,
        cancelled: false,
    })
}
#[cfg(test)]
pub(super) fn lab_terminal_guard(
    run: impl FnOnce(BorrowedFd<'_>) -> Result<()>,
) -> Result<Survivor> {
    process::host_preflight()?;
    let (r, w) = pipe()?;
    let _pipes = super::inventory::Registration::owned(&[r.as_fd(), w.as_fd()])?;
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(Error::ChildFailed);
    }
    if pid == 0 {
        if let Err(error) = run(w.as_fd()) {
            eprintln!("LAB_TERMINAL_GUARD_FAILURE reason={error}");
            die(122);
        }
        die(0);
    }
    let pinned = pidfd(pid)?;
    let inventory = super::inventory::Registration::owned(&[pinned.as_fd()])?;
    let child = Survivor {
        pid: pid as u32,
        reap: ParentReap::born(pid as u32),
        pinned,
        _inventory: inventory,
    };
    if !wait_ready(&r, Duration::from_secs(5))? || read_byte(&r)? != 1 {
        return Err(Error::Deadline);
    }
    child.require_live()?;
    Ok(child)
}
#[cfg(test)]
pub(super) fn executor_private_boundary(child: &Survivor) -> Result<()> {
    // Exact private completion FD11 must not be obtainable by the real guard.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_getfd, child.pidfd().as_raw_fd(), 11, 0) };
    if fd >= 0 {
        unsafe {
            libc::close(fd as i32);
        }
        return Err(Error::DescriptorPolicy);
    }
    if std::io::Error::last_os_error().raw_os_error() != Some(libc::EPERM) {
        return Err(Error::DescriptorPolicy);
    }
    for suffix in ["fd/11", "mem"] {
        if fs::open(
            format!("/proc/{}/{suffix}", child.pid()),
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .is_ok()
        {
            return Err(Error::DescriptorPolicy);
        }
    }
    Ok(())
}
pub(super) fn received_executor(
    pinned: OwnedFd,
    identity: &super::owned::ExecutorIdentity,
) -> Result<Survivor> {
    let info = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", pinned.as_raw_fd()))
        .map_err(|_| Error::DescriptorPolicy)?;
    if info
        .lines()
        .find_map(|line| line.strip_prefix("Pid:\t"))
        .and_then(|p| p.parse::<u32>().ok())
        != Some(identity.pid)
    {
        return Err(Error::ProcessChanged);
    }
    let inventory = super::inventory::Registration::owned(&[pinned.as_fd()])?;
    let child = Survivor {
        pid: identity.pid,
        reap: None,
        pinned,
        _inventory: inventory,
    };
    if child.start_time()? != identity.start_time {
        return Err(Error::ProcessChanged);
    }
    Ok(child)
}
pub(super) fn pin_recorded_executor(identity: &super::owned::ExecutorIdentity) -> Result<Survivor> {
    let pinned = pidfd(identity.pid as i32)?;
    let inventory = super::inventory::Registration::owned(&[pinned.as_fd()])?;
    let child = Survivor {
        pid: identity.pid,
        reap: None,
        pinned,
        _inventory: inventory,
    };
    if child.identity(identity.scope, identity.namespace)? != *identity {
        return Err(Error::ProcessChanged);
    }
    Ok(child)
}
#[cfg(test)]
pub(super) fn lab_terminal_checkpoint(fd: impl AsFd) -> Result<()> {
    write_byte(fd, 1)
}
#[cfg(test)]
impl Survivor {
    pub(super) fn lab_birth_identity(&self) -> Result<(u32, u64)> {
        let original = self.reap.as_ref().ok_or(Error::OwnershipMismatch)?;
        if original.creator != std::process::id() || original.pid != self.pid {
            return Err(Error::OwnershipMismatch);
        }
        Ok((self.pid, original.start.get().ok_or(Error::ProcessChanged)?))
    }
    pub(super) fn lab_terminal_status(&self) -> Result<Option<i32>> {
        let receipt = self.reap.as_ref().ok_or(Error::OwnershipMismatch)?;
        if receipt.creator != std::process::id() || receipt.pid != self.pid {
            return Err(Error::OwnershipMismatch);
        }
        Ok(receipt.status.get())
    }
    pub(super) fn lab_clone_native(&self) -> Result<Self> {
        let reap = self.reap.as_ref().ok_or(Error::OwnershipMismatch)?;
        if reap.creator != std::process::id()
            || reap.pid != self.pid
            || !self._inventory.contains(self.pinned.as_fd())
        {
            return Err(Error::OwnershipMismatch);
        }
        let pinned = self
            .pinned
            .try_clone()
            .map_err(|_| Error::DescriptorDuplicate)?;
        let inventory = super::inventory::Registration::owned(&[pinned.as_fd()])?;
        Ok(Self {
            pid: self.pid,
            pinned,
            _inventory: inventory,
            reap: Some(reap.clone()),
        })
    }
    pub fn lab_signal(&self, signal: i32) -> Result<()> {
        send(&self.pinned, signal)
    }
    pub fn lab_stop_and_witness(&self) -> Result<u64> {
        self.require_live()?;
        let bytes = read_fixed(&format!("/proc/{}/stat", self.pid), 65536)
            .map_err(|_| Error::ProcessUnavailable)?;
        let start = process::stat_start(
            std::str::from_utf8(&bytes).map_err(|_| Error::ProcessChanged)?,
            self.pid,
        )?;
        self.lab_signal(libc::SIGSTOP)?;
        let end = Instant::now() + Duration::from_secs(1);
        loop {
            if self.lab_require_stopped(start).is_ok() {
                return Ok(start);
            }
            if Instant::now() >= end {
                return Err(Error::Deadline);
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    pub fn lab_require_stopped(&self, start: u64) -> Result<()> {
        self.require_live()?;
        let bytes = read_fixed(&format!("/proc/{}/stat", self.pid), 65536)
            .map_err(|_| Error::ProcessUnavailable)?;
        process::stat_stopped(
            std::str::from_utf8(&bytes).map_err(|_| Error::ProcessChanged)?,
            self.pid,
            start,
        )?;
        self.require_live()
    }
    pub fn lab_is_dead(&self) -> Result<bool> {
        wait_ready(&self.pinned, Duration::ZERO)
    }
    pub fn lab_wait_killed(&self) -> Result<()> {
        if !wait_ready(&self.pinned, Duration::from_secs(5))? {
            return Err(Error::Deadline);
        }
        let status = self.reap_status()?.ok_or(Error::ChildFailed)?;
        if !libc::WIFSIGNALED(status) || libc::WTERMSIG(status) != libc::SIGKILL {
            return Err(Error::ChildFailed);
        }
        Ok(())
    }
    pub fn lab_wait_dead(&self) -> Result<()> {
        if !wait_ready(&self.pinned, Duration::from_secs(5))? {
            return Err(Error::Deadline);
        }
        let status = self.reap_status()?.ok_or(Error::ChildFailed)?;
        if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
            return Err(Error::ChildFailed);
        }
        Ok(())
    }
}
fn terminal_capabilities() -> Result<()> {
    cv(
        unsafe { libc::prctl(libc::PR_SET_SECUREBITS, 0xef, 0, 0, 0) },
        Error::CapabilityPolicy,
    )?;
    for cap in 0..64 {
        if unsafe { libc::prctl(libc::PR_CAPBSET_READ, cap, 0, 0, 0) } < 0 {
            break;
        }
        if cap != 12 {
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
            effective: 1 << 12,
            permitted: 1 << 12,
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
    )?;
    let bytes = read_fixed("/proc/self/status", 16384).map_err(|_| Error::CapabilityPolicy)?;
    let status = std::str::from_utf8(&bytes).map_err(|_| Error::CapabilityPolicy)?;
    for (key, expected) in [
        ("CapInh:", 0),
        ("CapPrm:", 1 << 12),
        ("CapEff:", 1 << 12),
        ("CapBnd:", 1 << 12),
        ("CapAmb:", 0),
    ] {
        if status
            .lines()
            .find_map(|l| l.strip_prefix(key))
            .and_then(|v| u64::from_str_radix(v.trim(), 16).ok())
            != Some(expected)
        {
            return Err(Error::CapabilityPolicy);
        }
    }
    for key in ["Uid:", "Gid:"] {
        if status
            .lines()
            .find_map(|l| l.strip_prefix(key))
            .map(|s| s.split_whitespace().collect::<Vec<_>>())
            != Some(vec!["0"; 4])
        {
            return Err(Error::CapabilityPolicy);
        }
    }
    Ok(())
}
/// Restricted FD arguments use full64-bit comparisons. In particular FD5
/// cannot be closed, written, flock-unlocked, duplicated or passed elsewhere.
fn terminal_filter(#[cfg(test)] checkpoint: bool) -> Vec<libc::sock_filter> {
    let mut out = filter()[..4].to_vec();
    for (nr, values) in [
        (libc::SYS_sendto, vec![3, 6, 8, 11]),
        (libc::SYS_pread64, vec![13]),
        (libc::SYS_recvfrom, vec![3, 6, 8]),
        (libc::SYS_timerfd_settime, vec![7, 9, 10]),
        (libc::SYS_close, vec![6, 7, 8, 9, 10]),
    ] {
        allow_fixed_args(&mut out, nr, 0, &values);
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
    // The test-only survivor checkpoint is an alternative exact match. A
    // mismatch must reload the syscall and continue into the unchanged guard
    // rule below; concatenating two rejecting exact_args blocks denies fd12.
    #[cfg(test)]
    if checkpoint {
        let mut checkpoint_block = exact_args(
            libc::SYS_pidfd_send_signal,
            &[(0, 12), (1, libc::SIGSTOP as u64), (2, 0), (3, 0)],
        );
        let reload = checkpoint_block.len() - 1;
        for (index, instruction) in checkpoint_block.iter_mut().enumerate() {
            if instruction.code == 0x06 && instruction.k == 0x00050001 {
                *instruction = libc::sock_filter {
                    code: 0x05,
                    jt: 0,
                    jf: 0,
                    k: (reload - index - 1) as u32,
                };
            }
        }
        out.extend(checkpoint_block);
    }
    // Exact pidfd, SIGSTOP only, null siginfo and flags0. No PID-number kill.
    let block = exact_args(
        libc::SYS_pidfd_send_signal,
        &[(0, 4), (1, libc::SIGSTOP as u64), (2, 0), (3, 0)],
    );
    out.extend(block);
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
    // Anonymous private allocator mappings only. A writable MAP_SHARED mapping
    // must not turn the inherited flock descriptor into write authority.
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
fn allow_fixed_args(out: &mut Vec<libc::sock_filter>, nr: libc::c_long, arg: u32, values: &[u32]) {
    let count = 5 + values.len() * 2;
    out.push(libc::sock_filter {
        code: 0x15,
        jt: 0,
        jf: count as u8,
        k: nr as u32,
    });
    out.push(libc::sock_filter {
        code: 0x20,
        jt: 0,
        jf: 0,
        k: 20 + arg * 8,
    });
    out.push(libc::sock_filter {
        code: 0x15,
        jt: 1,
        jf: 0,
        k: 0,
    });
    out.push(libc::sock_filter {
        code: 0x06,
        jt: 0,
        jf: 0,
        k: 0x00050001,
    });
    out.push(libc::sock_filter {
        code: 0x20,
        jt: 0,
        jf: 0,
        k: 16 + arg * 8,
    });
    for value in values {
        out.push(libc::sock_filter {
            code: 0x15,
            jt: 0,
            jf: 1,
            k: *value,
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
    out.push(libc::sock_filter {
        code: 0x20,
        jt: 0,
        jf: 0,
        k: 0,
    });
}
fn exact_args(nr: libc::c_long, args: &[(u32, u64)]) -> Vec<libc::sock_filter> {
    let length = args.len() * 6 + 2;
    let mut out = vec![libc::sock_filter {
        code: 0x15,
        jt: 0,
        jf: length as u8,
        k: nr as u32,
    }];
    for (arg, value) in args {
        for (offset, part) in [
            (20 + arg * 8, (value >> 32) as u32),
            (16 + arg * 8, *value as u32),
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
                    k: part,
                },
                libc::sock_filter {
                    code: 0x06,
                    jt: 0,
                    jf: 0,
                    k: 0x00050001,
                },
            ]);
        }
    }
    out.push(libc::sock_filter {
        code: 0x06,
        jt: 0,
        jf: 0,
        k: 0x7fff0000,
    });
    out.push(libc::sock_filter {
        code: 0x20,
        jt: 0,
        jf: 0,
        k: 0,
    });
    out
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
    actual: Option<Actual<'_>>,
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
            setup(container, data, state, health, outer_parent.as_fd(), actual)
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
    actual: Option<Actual<'_>>,
) -> Result<()> {
    for (fd, kind) in [
        (container.ipc, libc::CLONE_NEWIPC),
        (container.uts, libc::CLONE_NEWUTS),
        (container.cgroup_ns, libc::CLONE_NEWCGROUP),
        (data, libc::CLONE_NEWNET),
    ] {
        enter(fd, kind)?;
    }
    if actual.is_some() {
        // Root-relative cgroup identity is minted only after host producer join.
        unshare(libc::CLONE_NEWCGROUP)?;
        if super::owned::Identity::network(network()?)? != super::owned::Identity::network(data)? {
            return Err(Error::NamespaceMismatch);
        }
        // Suppression is established under three-scope Offline quarantine
        // before native activation captures its baseline. Exec only verifies;
        // it must never invalidate a retained baseline after activation.
        data_ipv6_disabled()?;
    }
    enter(container.mount, libc::CLONE_NEWNS)?;
    let executable_tree = rustix::mount::open_tree(
        actual.map_or(container.executable, |a| a.executable),
        "",
        rustix::mount::OpenTreeFlags::OPEN_TREE_CLONE
            | rustix::mount::OpenTreeFlags::OPEN_TREE_CLOEXEC
            | rustix::mount::OpenTreeFlags::AT_EMPTY_PATH,
    )
    .map_err(|_| Error::MountExecutableClone)?;
    let extra_trees = actual.map(ActualTrees::clone).transpose()?;
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
    if let Some(a) = actual {
        actual_root(a, extra_trees.as_ref().ok_or(Error::MountIsolation)?)?;
    } else {
        std::fs::write(
            "/tmp/root/etc/resolv.conf",
            b"nameserver 192.0.2.53\noptions attempts:1 timeout:1\n",
        )
        .map_err(|_| Error::MountPivot)?;
    }
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
            supervise(
                health,
                &signals,
                init_parent.as_fd(),
                null_identity,
                actual.map(|a| a.role),
            )
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
    actual: Option<ActualRole>,
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
    #[cfg(test)]
    let proc_ready = if actual.is_some() {
        Some(pipe()?)
    } else {
        None
    };
    // SAFETY: PID1 is single-task, fixed child exec path or _exit only.
    let worker = unsafe { libc::fork() };
    if worker < 0 {
        return Err(Error::ChildFailed);
    }
    if worker == 0 {
        let result = if let Some(role) = actual {
            actual_exec(
                executable.as_fd(),
                health,
                null_identity,
                role,
                #[cfg(test)]
                proc_ready.as_ref().map(|(_, write)| write.as_fd()),
            )
        } else {
            worker_exec(executable.as_fd(), health, null_identity)
        };
        let _ = result;
        die(119);
    }
    // Close ALL inherited host handles in PID1 too; Rust FD owners are never
    // dropped here. Namespace init must not remain a privileged escape target.
    #[cfg(test)]
    if let Some((read, write)) = proc_ready {
        drop(write);
        // Deterministic regression: child's proc mount is already readonly when
        // PID1 must still write its own LSM transition on the sibling mount.
        if !wait_ready(&read, Duration::from_secs(5))? || read_byte(&read)? != 129 {
            return Err(Error::MountReadonly);
        }
    }
    lsm_supervisor(health, actual)?;
    reduce_privileges(16, health)?;
    if wait_ready(parent, Duration::ZERO)? {
        return Err(Error::ChildFailed);
    }
    let confined: Result<()> = (|| {
        close_except(&[health.as_raw_fd()])?;
        supervisor_fds(health, null_identity)?;
        if actual.is_some() {
            // Exact inventory was verified immediately above. Installing the
            // reduced wait filter creates no descriptors, and that filter
            // deliberately denies every path open; do not reopen proc after it.
            apply_filter(&init_filter())
        } else {
            seccomp()?;
            supervisor_fds(health, null_identity)
        }
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
    let result = supervisor_loop(set, worker, actual.is_some());
    die(if result.is_ok() { 0 } else { 113 });
}
fn supervisor_loop(set: &libc::sigset_t, worker: i32, actual: bool) -> Result<()> {
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
                if actual && (!libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0) {
                    return Err(Error::ChildFailed);
                }
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
    drop_identity(65534)
}
fn drop_identity(uid: u32) -> Result<()> {
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
        unsafe { libc::setresgid(uid, uid, uid) },
        Error::CapabilityPolicy,
    )?;
    cv(
        unsafe { libc::setresuid(uid, uid, uid) },
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

fn lsm_exec() -> Result<()> {
    // Explicit transition required: host-launched tasks inherit no Docker LSM.
    // Exact profile is fixed by the test-program policy, never caller-supplied.
    std::fs::write("/proc/self/attr/exec", b"exec docker-default")
        .map_err(|_| Error::ConfinementPolicy)
}
fn lsm_supervisor(_health: BorrowedFd<'_>, _role: Option<ActualRole>) -> Result<()> {
    std::fs::write("/proc/self/attr/current", b"changeprofile docker-default").map_err(
        |error| {
            #[cfg(test)]
            lsm_diagnostic(_health, _role, 1, error.raw_os_error());
            #[cfg(not(test))]
            let _ = error;
            Error::ConfinementPolicy
        },
    )?;
    lsm_current().inspect_err(|_| {
        #[cfg(test)]
        lsm_diagnostic(_health, _role, 2, None);
    })
}
#[cfg(test)]
fn lsm_diagnostic(
    health: BorrowedFd<'_>,
    role: Option<ActualRole>,
    operation: u8,
    errno: Option<i32>,
) {
    let role = match role {
        Some(ActualRole::Daemon) => 1,
        Some(ActualRole::Observer) => 2,
        Some(ActualRole::Monitor) => 3,
        Some(ActualRole::OperationalMonitor) => 4,
        None => 0,
    };
    let errno = match errno {
        Some(libc::EROFS) => 1,
        Some(libc::EPERM) => 2,
        Some(libc::EACCES) => 3,
        Some(libc::ENOENT) => 4,
        _ => 0,
    };
    let bytes = [255u8, role, operation, errno];
    // SAFETY: one atomic fixed diagnostic packet on the owned pipe; no source
    // strings, paths, syscall buffers or dynamic errno text are emitted.
    unsafe {
        libc::write(health.as_raw_fd(), bytes.as_ptr().cast(), bytes.len());
    }
}
// ---- Manifest-bound probe and reduced wait-role seccomp programs ----

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
    tx: &super::owned::Transaction,
    ns: &super::owned::OwnedNamespaces,
) -> Result<Child> {
    process::single_threaded()?;
    let lease = tx.retain_mutator_lease(&a.spec)?;
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
    let mut child = Child::from_native(ChildNative {
        _capacity: ChildCapacity::created(),
        _inventory: inventory,
        release_inventory: None,
        pid: pid as u32,
        pidfd: pinned,
        release: None,
        health: r,
        reaped: false,
        control: None,
        retained_pins: Vec::new(),
        retained_inventory: Vec::new(),
        producer: None,
        drain_error: None,
        descendants: true,
        lease: Some(lease),
        #[cfg(test)]
        actual_negative: None,
    });
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
// Test-only socket-origin oracle; single-task process temporarily joins only
// the retained owned subgroup, restores its EXACT original group before return.
#[cfg(test)]
pub(super) fn producer_socket_scope<T>(
    group: impl AsFd,
    f: impl FnOnce() -> Result<T>,
) -> Result<T> {
    use std::io::Write;
    process::single_threaded()?;
    let content =
        std::fs::read_to_string("/proc/self/cgroup").map_err(|_| Error::CgroupMismatch)?;
    let path = content
        .strip_prefix("0::/")
        .and_then(|s| s.strip_suffix('\n'))
        .filter(|s| !s.contains('\n') && !s.split('/').any(|v| v == ".." || v == "."))
        .ok_or(Error::CgroupMismatch)?;
    let old = fs::open(
        format!("/sys/fs/cgroup/{path}"),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| Error::CgroupMismatch)?;
    fn place(fd: impl AsFd) -> Result<()> {
        let f = fs::openat(
            fd,
            "cgroup.procs",
            OFlags::WRONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|_| Error::CgroupMismatch)?;
        std::fs::File::from(f)
            .write_all(std::process::id().to_string().as_bytes())
            .map_err(|_| Error::CgroupMismatch)
    }
    place(group)?;
    let r = f();
    if place(old).is_err() {
        die(122);
    }
    r
}

// ---- Fixed actual Rust / Go private root and execution policy ----
const DAEMON_CONFIG: &[u8] = br#"{"version":"alpha0","locked":true,"enabled":false,"acceptDNS":false,"acceptRoutes":false,"advertiseRoutes":[],"advertiseExitNode":false,"disableSNAT":true,"netfilterMode":"off","noStatefulFiltering":true,"runSSHServer":false,"runWebClient":false,"remoteConfig":false,"autoUpdate":{"Check":false,"Apply":false}}"#;
const OPERATIONAL_DAEMON_CONFIG: &[u8] = br#"{"version":"alpha0","locked":false,"enabled":true,"acceptDNS":false,"acceptRoutes":false,"advertiseRoutes":[],"advertiseExitNode":false,"disableSNAT":true,"netfilterMode":"off","noStatefulFiltering":true,"runSSHServer":false,"runWebClient":false,"remoteConfig":false,"autoUpdate":{"Check":false,"Apply":false}}"#;
#[derive(Clone, Copy)]
pub(super) enum DaemonConfiguration {
    Unenrolled,
    PreservedEnrollment,
}
impl DaemonConfiguration {
    pub fn bytes(self) -> &'static [u8] {
        match self {
            Self::Unenrolled => DAEMON_CONFIG,
            Self::PreservedEnrollment => OPERATIONAL_DAEMON_CONFIG,
        }
    }
}
pub(super) fn daemon_configuration() -> &'static [u8] {
    DAEMON_CONFIG
}
struct ActualTrees {
    ca: OwnedFd,
    placement: Option<OwnedFd>,
    localapi: Option<OwnedFd>,
    tun: Option<OwnedFd>,
    null: OwnedFd,
}
fn clone_tree(fd: impl AsFd) -> Result<OwnedFd> {
    rustix::mount::open_tree(
        fd,
        "",
        rustix::mount::OpenTreeFlags::OPEN_TREE_CLONE
            | rustix::mount::OpenTreeFlags::OPEN_TREE_CLOEXEC
            | rustix::mount::OpenTreeFlags::AT_EMPTY_PATH,
    )
    .map_err(|_| Error::MountIsolation)
}
impl ActualTrees {
    fn clone(a: Actual<'_>) -> Result<Self> {
        let null = fs::open("/dev/null", OFlags::PATH | OFlags::CLOEXEC, Mode::empty())
            .map_err(|_| Error::DescriptorNull)?;
        approved_null(null.as_fd())?;
        Ok(Self {
            ca: clone_tree(a.ca)?,
            // Host sources were cloned before namespace entry. Retain only a
            // CLOEXEC duplicate of each exact detached mount for move_mount.
            placement: a
                .placement
                .map(|fd| fd.try_clone_to_owned().map_err(|_| Error::MountIsolation))
                .transpose()?,
            localapi: a
                .localapi
                .map(|fd| fd.try_clone_to_owned().map_err(|_| Error::MountIsolation))
                .transpose()?,
            tun: a.tun.map(clone_tree).transpose()?,
            null: clone_tree(null)?,
        })
    }
}
fn readonly_bind(path: &str, noexec: bool) -> Result<()> {
    mount(
        None,
        &c(path)?,
        None,
        libc::MS_BIND
            | libc::MS_REMOUNT
            | libc::MS_RDONLY
            | libc::MS_NOSUID
            | if noexec { libc::MS_NOEXEC } else { 0 },
        None,
    )
}
fn actual_file(tree: &OwnedFd, path: &str) -> Result<()> {
    std::fs::File::create(path).map_err(|_| Error::MountIsolation)?;
    attach_tree(tree.as_fd(), path)?;
    readonly_bind(path, true)
}
fn disable_data_ipv6() -> Result<()> {
    for path in [
        "/proc/sys/net/ipv6/conf/all/disable_ipv6",
        "/proc/sys/net/ipv6/conf/default/disable_ipv6",
    ] {
        std::fs::write(path, b"1\n").map_err(|_| Error::NetworkOperation)?;
    }
    data_ipv6_disabled()
}
fn data_ipv6_disabled() -> Result<()> {
    for path in [
        "/proc/sys/net/ipv6/conf/all/disable_ipv6",
        "/proc/sys/net/ipv6/conf/default/disable_ipv6",
    ] {
        if std::fs::read(path).map_err(|_| Error::NetworkOperation)? != b"1\n" {
            return Err(Error::NetworkOperation);
        }
    }
    Ok(())
}
pub(super) fn prepare_owned_data_ipv6(
    namespaces: &super::owned::OwnedNamespaces,
    spec: &super::LaunchSpec,
) -> Result<()> {
    namespaces.bind(spec)?;
    network_scope(&namespaces.data, disable_data_ipv6)?;
    namespaces.bind(spec)
}
fn actual_root(a: Actual<'_>, trees: &ActualTrees) -> Result<()> {
    for d in [
        "dev",
        "dev/net",
        "run",
        "run/vprouter",
        "run/tailscale",
        "etc/ssl",
        "etc/ssl/certs",
    ] {
        std::fs::create_dir(format!("/tmp/root/{d}")).map_err(|_| Error::MountIsolation)?;
    }
    std::fs::write(
        "/tmp/root/etc/resolv.conf",
        format!("nameserver {}\noptions attempts:1 timeout:1\n", a.resolver),
    )
    .map_err(|_| Error::MountIsolation)?;
    std::fs::write(
        "/tmp/root/etc/tailscale.json",
        a.daemon_configuration.bytes(),
    )
    .map_err(|_| Error::MountIsolation)?;
    actual_file(&trees.ca, "/tmp/root/etc/ssl/certs/ca-certificates.crt")?;
    actual_file(&trees.null, "/tmp/root/dev/null")?;
    // Selected writable state cannot provide executable/setuid/device payloads.
    mount(
        None,
        c"/tmp/root/state",
        None,
        libc::MS_BIND | libc::MS_REMOUNT | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        None,
    )?;
    match a.role {
        ActualRole::Observer | ActualRole::Monitor | ActualRole::OperationalMonitor => {
            let placement = trees.placement.as_ref().ok_or(Error::DescriptorPolicy)?;
            attach_tree(placement.as_fd(), "/tmp/root/run/vprouter")?;
            readonly_bind("/tmp/root/run/vprouter", true)?;
            actual_file(
                trees.localapi.as_ref().ok_or(Error::DescriptorPolicy)?,
                "/tmp/root/run/tailscale/tailscaled.sock",
            )?;
            if trees.tun.is_some() {
                return Err(Error::DescriptorPolicy);
            }
        }
        ActualRole::Daemon => {
            if trees.placement.is_some() || trees.localapi.is_some() {
                return Err(Error::DescriptorPolicy);
            }
            actual_file(
                trees.tun.as_ref().ok_or(Error::DescriptorPolicy)?,
                "/tmp/root/dev/net/tun",
            )?;
        }
    }
    Ok(())
}
fn actual_capabilities(role: ActualRole, health: BorrowedFd<'_>) -> Result<()> {
    if role != ActualRole::Daemon {
        return reduce_privileges(32, health);
    }
    // Keep only NET_ADMIN for TUN/link/route/mark; never SYS_ADMIN, NET_RAW,
    // SETUID/SETGID/SETPCAP, DAC override, ptrace or a device capability.
    cv(
        unsafe { libc::prctl(libc::PR_SET_SECUREBITS, 0x2f, 0, 0, 0) },
        Error::CapabilityPolicy,
    )?;
    for cap in 0..64 {
        if unsafe { libc::prctl(libc::PR_CAPBSET_READ, cap, 0, 0, 0) } < 0 {
            break;
        }
        if cap != 12 {
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
    cv(
        unsafe { libc::setresgid(65534, 65534, 65534) },
        Error::CapabilityPolicy,
    )?;
    cv(
        unsafe { libc::setresuid(65534, 65534, 65534) },
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
    let h = Header {
        version: 0x20080522,
        pid: 0,
    };
    let caps = [
        Caps {
            effective: 1 << 12,
            permitted: 1 << 12,
            inheritable: 1 << 12,
        },
        Caps {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
    ];
    // SAFETY: Linux v3 capset exact header and two initialized words, child only.
    cv(
        unsafe { libc::syscall(libc::SYS_capset, &h, caps.as_ptr()) as i32 },
        Error::CapabilityPolicy,
    )?;
    cv(
        unsafe { libc::prctl(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_RAISE, 12, 0, 0) },
        Error::CapabilityPolicy,
    )?;
    // Ambient grant is fixed; lock further ambient raises and root/setuid paths.
    // SETPCAP has been removed, so securebits cannot now change. 0x2f already
    // locks NOROOT/NO_SETUID_FIXUP and KEEP_CAPS off; ambient bounding=NET_ADMIN.
    cv(
        unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) },
        Error::CapabilityPolicy,
    )?;
    cv(
        unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) },
        Error::ChildFailed,
    )?;
    let status = read_fixed("/proc/self/status", 16384).map_err(|_| Error::CapabilityPolicy)?;
    let status = std::str::from_utf8(&status).map_err(|_| Error::CapabilityPolicy)?;
    for key in ["CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:"] {
        if status
            .lines()
            .find_map(|s| s.strip_prefix(key))
            .and_then(|s| u64::from_str_radix(s.trim(), 16).ok())
            != Some(1 << 12)
        {
            return Err(Error::CapabilityPolicy);
        }
    }
    if !status.lines().any(|s| s == "NoNewPrivs:\t1")
        || unsafe { libc::getuid() } != 65534
        || unsafe { libc::getgid() } != 65534
        || unsafe { libc::getgroups(0, std::ptr::null_mut()) } != 0
    {
        return Err(Error::CapabilityPolicy);
    }
    Ok(())
}
fn allow_syscall(out: &mut Vec<libc::sock_filter>, nr: libc::c_long) {
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
fn operational_sockets(out: &mut Vec<libc::sock_filter>) {
    // Only this separately authorized zero-cap role needs provider TCP/DNS UDP.
    // Check all64 bits of each argument; ordinary observation roles retain their
    // original no-AF_INET profile. No raw/netlink/IPv6/socketpair escape is added.
    let mut socket = Vec::new();
    for (family, kind, protocol) in [
        (libc::AF_UNIX, libc::SOCK_STREAM, 0),
        (libc::AF_INET, libc::SOCK_STREAM, 0),
        (libc::AF_INET, libc::SOCK_STREAM, libc::IPPROTO_TCP),
        (libc::AF_INET, libc::SOCK_DGRAM, 0),
        (libc::AF_INET, libc::SOCK_DGRAM, libc::IPPROTO_UDP),
    ] {
        for flags in [
            0,
            libc::SOCK_CLOEXEC,
            libc::SOCK_NONBLOCK,
            libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
        ] {
            let expected = [
                (20, 0),
                (16, family),
                (28, 0),
                (24, kind | flags),
                (36, 0),
                (32, protocol),
            ];
            for (index, (offset, value)) in expected.into_iter().enumerate() {
                socket.push(libc::sock_filter {
                    code: 0x20,
                    jt: 0,
                    jf: 0,
                    k: offset,
                });
                socket.push(libc::sock_filter {
                    code: 0x15,
                    jt: 0,
                    jf: (11 - index * 2) as u8,
                    k: value as u32,
                });
            }
            socket.push(libc::sock_filter {
                code: 0x06,
                jt: 0,
                jf: 0,
                k: 0x7fff0000,
            });
        }
    }
    socket.push(libc::sock_filter {
        code: 0x06,
        jt: 0,
        jf: 0,
        k: 0x00050001,
    });
    out.push(libc::sock_filter {
        code: 0x15,
        jt: 1,
        jf: 0,
        k: libc::SYS_socket as u32,
    });
    out.push(libc::sock_filter {
        code: 0x05,
        jt: 0,
        jf: 0,
        k: socket.len() as u32,
    });
    out.extend(socket);
    out.push(libc::sock_filter {
        code: 0x20,
        jt: 0,
        jf: 0,
        k: 0,
    });
}
fn runtime_filter(role: ActualRole) -> Vec<libc::sock_filter> {
    let mut out = filter()[..4].to_vec();
    if role == ActualRole::OperationalMonitor {
        operational_sockets(&mut out);
    }
    if role == ActualRole::Daemon {
        // Pinned Go TUN construction uses only pipe2(O_CLOEXEC). Do not admit
        // inheritable pipes, packet/direct mode, or any extra upper-word bits.
        out.extend([
            libc::sock_filter {
                code: 0x15,
                jt: 0,
                jf: 6,
                k: libc::SYS_pipe2 as u32,
            },
            libc::sock_filter {
                code: 0x20,
                jt: 0,
                jf: 0,
                k: 28,
            },
            libc::sock_filter {
                code: 0x15,
                jt: 0,
                jf: 3,
                k: 0,
            },
            libc::sock_filter {
                code: 0x20,
                jt: 0,
                jf: 0,
                k: 24,
            },
            libc::sock_filter {
                code: 0x15,
                jt: 0,
                jf: 1,
                k: libc::O_CLOEXEC as u32,
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
            libc::sock_filter {
                code: 0x20,
                jt: 0,
                jf: 0,
                k: 0,
            },
        ]);
    }
    // clone3 must report ENOSYS so libc may use the constrained clone fallback.
    out.extend([
        libc::sock_filter {
            code: 0x15,
            jt: 0,
            jf: 1,
            k: libc::SYS_clone3 as u32,
        },
        libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0x00050026,
        },
    ]);
    // Go creates threads only. Fork/vfork and namespace-bearing clones refuse.
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
            jt: 0,
            jf: 5,
            k: 0,
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
            k: 0x50f00,
        },
        libc::sock_filter {
            code: 0x15,
            jt: 1,
            jf: 0,
            k: 0x3d0f00,
        },
        libc::sock_filter {
            code: 0x15,
            jt: 0,
            jf: 1,
            k: 0xd0f00,
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
        libc::sock_filter {
            code: 0x20,
            jt: 0,
            jf: 0,
            k: 0,
        },
    ]);
    // Only pinned descriptor4 plus exact AT_EMPTY_PATH may be executed. Both
    // the executable and health descriptors close atomically on that exec.
    out.extend([
        libc::sock_filter {
            code: 0x15,
            jt: 0,
            jf: 8,
            k: libc::SYS_execveat as u32,
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
            jf: 5,
            k: 4,
        },
        libc::sock_filter {
            code: 0x20,
            jt: 0,
            jf: 0,
            k: 48,
        },
        libc::sock_filter {
            code: 0x15,
            jt: 0,
            jf: 3,
            k: libc::AT_EMPTY_PATH as u32,
        },
        libc::sock_filter {
            code: 0x20,
            jt: 0,
            jf: 0,
            k: 52,
        },
        libc::sock_filter {
            code: 0x15,
            jt: 0,
            jf: 1,
            k: 0,
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
        libc::sock_filter {
            code: 0x20,
            jt: 0,
            jf: 0,
            k: 0,
        },
    ]);
    // IPv6 and AF_PACKET/raw WAN creation never receive a permit. Restrict
    // socket families before the general syscall list.
    out.extend([
        libc::sock_filter {
            code: 0x15,
            jt: 0,
            jf: 6,
            k: libc::SYS_socket as u32,
        },
        libc::sock_filter {
            code: 0x20,
            jt: 0,
            jf: 0,
            k: 16,
        },
        libc::sock_filter {
            code: 0x15,
            jt: 3,
            jf: 0,
            k: libc::AF_UNIX as u32,
        },
        libc::sock_filter {
            code: 0x15,
            jt: 2,
            jf: 0,
            k: libc::AF_NETLINK as u32,
        },
        libc::sock_filter {
            code: 0x15,
            jt: 1,
            jf: 0,
            k: if role == ActualRole::Daemon {
                libc::AF_INET as u32
            } else {
                u32::MAX
            },
        },
        libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0x00050061,
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
    // Neither fixed Rust nor Go needs JIT or executable writable mappings.
    // Deny PROT_EXEC in mmap/mprotect, including anonymous/state-backed code.
    for nr in [libc::SYS_mmap, libc::SYS_mprotect] {
        out.extend([
            libc::sock_filter {
                code: 0x15,
                jt: 0,
                jf: 4,
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
                k: libc::PROT_EXEC as u32,
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
    let calls = [
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
        libc::SYS_sigaltstack,
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
        libc::SYS_getgroups,
        libc::SYS_prctl,
        libc::SYS_exit,
        libc::SYS_exit_group,
        libc::SYS_sched_yield,
        libc::SYS_sched_getaffinity,
        libc::SYS_prlimit64,
        libc::SYS_uname,
        libc::SYS_fstatfs,
        libc::SYS_epoll_create1,
        libc::SYS_epoll_ctl,
        libc::SYS_epoll_pwait,
        libc::SYS_eventfd2,
        libc::SYS_ppoll,
        libc::SYS_bind,
        libc::SYS_connect,
        libc::SYS_getsockname,
        libc::SYS_getpeername,
        libc::SYS_getsockopt,
        libc::SYS_setsockopt,
        libc::SYS_sendmsg,
        libc::SYS_recvmsg,
        libc::SYS_sendto,
        libc::SYS_recvfrom,
    ];
    for nr in calls {
        allow_syscall(&mut out, nr);
    }
    if role == ActualRole::OperationalMonitor {
        // Tokio HTTP transports perform a write-half shutdown before EOF.
        allow_syscall(&mut out, libc::SYS_shutdown);
    }
    if role == ActualRole::Daemon {
        for nr in [
            libc::SYS_ioctl,
            libc::SYS_bind,
            libc::SYS_listen,
            libc::SYS_accept4,
            libc::SYS_fsync,
            libc::SYS_fdatasync,
            libc::SYS_renameat,
            libc::SYS_unlinkat,
            libc::SYS_mkdirat,
            libc::SYS_fchmod,
            libc::SYS_fchmodat,
            libc::SYS_tgkill,
        ] {
            allow_syscall(&mut out, nr);
        }
    }
    #[cfg(target_arch = "x86_64")]
    for nr in [
        libc::SYS_arch_prctl,
        libc::SYS_poll,
        libc::SYS_epoll_wait,
        libc::SYS_readlink,
        libc::SYS_access,
        libc::SYS_stat,
        libc::SYS_lstat,
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
fn actual_environment(role: ActualRole) -> &'static [&'static CStr] {
    match role {
        ActualRole::Observer | ActualRole::Monitor | ActualRole::OperationalMonitor => {
            &[c"LANG=C", c"PATH=/bin"]
        }
        ActualRole::Daemon => &[
            c"LANG=C",
            c"PATH=/bin",
            // Pinned linuxfw.New otherwise defaults to an iptables CLI runner
            // even with netfilterMode off. Never admit a secondary executable.
            c"TS_DEBUG_FIREWALL_MODE=nftables",
            // Pinned logpolicy ignores --statedir when choosing log state and
            // panics if /var/lib, HOME and /tmp are unavailable. Keep every
            // writable file in the same selected daemon-only noexec state view.
            c"TS_LOGS_DIR=/state",
        ],
    }
}
/// Test-only syscall exercise. The caller has already admitted the exact lab
/// executable in an owned guest. A fresh network namespace has only loopback;
/// no enrollment, placement token, provider endpoint or production release exists.
#[cfg(test)]
pub(super) fn operational_profile_lab() -> Result<()> {
    process::single_threaded()?;
    let old = network()?;
    unshare(libc::CLONE_NEWNET)?;
    let empty = network();
    if enter(old.as_fd(), libc::CLONE_NEWNET).is_err() {
        die(122);
    }
    network_scope(empty?, operational_profile_in_empty_namespace)
}
#[cfg(test)]
fn operational_profile_in_empty_namespace() -> Result<()> {
    use std::{
        io::{Read, Write},
        net::{TcpListener, UdpSocket},
        os::unix::net::UnixStream,
    };
    // SAFETY: this is a newly unshared, empty test namespace. The initialized
    // ifreq contains only the fixed loopback name and kernel-returned flags.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(Error::NetworkOperation);
    }
    let control = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut req: libc::ifreq = unsafe { std::mem::zeroed() };
    req.ifr_name[0] = b'l' as libc::c_char;
    req.ifr_name[1] = b'o' as libc::c_char;
    cv(
        unsafe { libc::ioctl(control.as_raw_fd(), libc::SIOCGIFFLAGS as _, &mut req) },
        Error::NetworkOperation,
    )?;
    req.ifr_ifru.ifru_flags = unsafe { req.ifr_ifru.ifru_flags } | libc::IFF_UP as i16;
    cv(
        unsafe { libc::ioctl(control.as_raw_fd(), libc::SIOCSIFFLAGS as _, &req) },
        Error::NetworkOperation,
    )?;
    drop(control);
    let io = |_| Error::NetworkOperation;
    let udp = UdpSocket::bind("127.0.0.1:0").map_err(io)?;
    let tcp = TcpListener::bind("127.0.0.1:0").map_err(io)?;
    // Retain a bound but non-listening TCP port so a refused connection really
    // exercises SO_ERROR, without a race for a guessed unused port.
    let refused = rustix::net::socket(
        rustix::net::AddressFamily::INET,
        rustix::net::SocketType::STREAM,
        None,
    )
    .map_err(|_| Error::NetworkOperation)?;
    rustix::net::bind(
        &refused,
        &std::net::SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, 0),
    )
    .map_err(|_| Error::NetworkOperation)?;
    let refused_addr = std::net::SocketAddrV4::try_from(
        rustix::net::getsockname(&refused).map_err(|_| Error::NetworkOperation)?,
    )
    .map_err(|_| Error::NetworkOperation)?;
    let udp_addr = udp.local_addr().map_err(io)?;
    let tcp_addr = tcp.local_addr().map_err(io)?;
    let (mut server, client) = UnixStream::pair().map_err(io)?;
    let (health_read, health_write) = pipe()?;
    let parent = std::process::id();
    process::single_threaded()?;
    // SAFETY: dedicated synchronous lab entry; no Tokio runtime or thread exists
    // yet. Child closes all inherited descriptors except its private IPC and
    // diagnostics, then always _exits without unwinding inherited Rust owners.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(Error::ChildFailed);
    }
    if pid == 0 {
        let result = (|| {
            close_except(&[client.as_raw_fd(), health_write.as_raw_fd()])?;
            actual_capabilities(ActualRole::OperationalMonitor, health_write.as_fd())?;
            if unsafe { libc::getppid() } != parent as i32 {
                return Err(Error::ChildFailed);
            }
            apply_filter(&runtime_filter(ActualRole::OperationalMonitor))?;
            verify_credentials(32, health_write.as_fd())?;
            super::lab::stage("operational_profile_exact_caps_filter_applied");
            operational_profile_client(client, udp_addr, tcp_addr, refused_addr.into())
        })();
        if let Err(error) = result {
            report_failure(&health_write, error);
            die(1);
        }
        let _ = write_byte(&health_write, 1);
        die(0);
    }
    drop(client);
    drop(health_write);
    // Direct unreaped child ownership prevents PID reuse even if pidfd_open fails.
    struct ProbeChild {
        pid: i32,
        handle: Option<OwnedFd>,
        reaped: bool,
    }
    impl Drop for ProbeChild {
        fn drop(&mut self) {
            if self.reaped {
                return;
            }
            if let Some(handle) = &self.handle {
                let _ = send(handle, libc::SIGKILL);
            } else {
                unsafe {
                    libc::kill(self.pid, libc::SIGKILL);
                }
            }
            let end = Instant::now() + Duration::from_secs(3);
            loop {
                let r = unsafe { libc::waitpid(self.pid, std::ptr::null_mut(), libc::WNOHANG) };
                if r == self.pid || Instant::now() >= end {
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
    let mut child = ProbeChild {
        pid,
        handle: None,
        reaped: false,
    };
    child.handle = Some(pidfd(pid)?);
    let end = Instant::now() + Duration::from_secs(6);
    let left = || end.saturating_duration_since(Instant::now());
    let message: bool = vprouter_worker::bootstrap::read_message_before(&mut server, end)
        .map_err(|_| Error::ChildFailed)?;
    if !message {
        return Err(Error::ChildFailed);
    }
    vprouter_worker::bootstrap::write_message_before(&mut server, &true, end)
        .map_err(|_| Error::ChildFailed)?;
    // Bootstrap uses fcntl, then both peers register the same nonblocking Unix
    // stream with their respective I/O paths. Parent uses bounded readiness.
    if !wait_ready(&server, left())? {
        return Err(Error::Deadline);
    }
    let mut byte = [0];
    server.read_exact(&mut byte).map_err(io)?;
    if byte != [42] {
        return Err(Error::ChildFailed);
    }
    server.write_all(&byte).map_err(io)?;
    for _ in 0..2 {
        if !wait_ready(&udp, left())? {
            return Err(Error::Deadline);
        }
        let (n, source) = udp.recv_from(&mut byte).map_err(io)?;
        if n != 1 || byte != [42] {
            return Err(Error::ChildFailed);
        }
        udp.send_to(&byte, source).map_err(io)?;
    }
    if !wait_ready(&tcp, left())? {
        return Err(Error::Deadline);
    }
    let (mut stream, _) = tcp.accept().map_err(io)?;
    stream.set_read_timeout(Some(left())).map_err(io)?;
    stream.set_write_timeout(Some(left())).map_err(io)?;
    stream.read_exact(&mut byte).map_err(io)?;
    if byte != [42] {
        return Err(Error::ChildFailed);
    }
    stream.write_all(&byte).map_err(io)?;
    if stream.read(&mut byte).map_err(io)? != 0 {
        return Err(Error::ChildFailed);
    }
    drop(stream);
    if !wait_ready(&health_read, left())? || read_byte(&health_read)? != 1 {
        return Err(Error::ChildFailed);
    }
    if !wait_ready(child.handle.as_ref().ok_or(Error::ChildFailed)?, left())? {
        return Err(Error::Deadline);
    }
    let mut status = 0;
    if unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) } != pid {
        return Err(Error::ChildFailed);
    }
    child.reaped = true;
    if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
        return Err(Error::ChildFailed);
    }
    Ok(())
}
#[cfg(test)]
fn operational_profile_client(
    mut unix: std::os::unix::net::UnixStream,
    udp_addr: std::net::SocketAddr,
    tcp_addr: std::net::SocketAddr,
    refused_addr: std::net::SocketAddr,
) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    // FIONBIO must remain denied. Production Channel uses the same fcntl helper
    // as these public framing functions; no broad ioctl permission is added.
    if unix
        .set_nonblocking(true)
        .err()
        .and_then(|e| e.raw_os_error())
        != Some(libc::EPERM)
    {
        return Err(Error::ConfinementPolicy);
    }
    vprouter_worker::bootstrap::write_message(&mut unix, &true).map_err(|_| Error::ChildFailed)?;
    if !vprouter_worker::bootstrap::read_message::<bool>(&mut unix)
        .map_err(|_| Error::ChildFailed)?
    {
        return Err(Error::ChildFailed);
    }
    for (family, kind, protocol) in [
        (libc::AF_INET6, libc::SOCK_STREAM, 0),
        (libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE),
        (libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_ICMP),
        (libc::AF_PACKET, libc::SOCK_RAW, 0),
        (libc::AF_UNIX, libc::SOCK_DGRAM, 0),
    ] {
        let fd = unsafe { libc::socket(family, kind, protocol) };
        if fd >= 0 {
            unsafe {
                libc::close(fd);
            }
            return Err(Error::ConfinementPolicy);
        }
        if std::io::Error::last_os_error().raw_os_error() != Some(libc::EPERM) {
            return Err(Error::ConfinementPolicy);
        }
    }
    // Check errno immediately after each syscall, not after an array of calls.
    if unsafe { libc::listen(unix.as_raw_fd(), 1) } != -1
        || std::io::Error::last_os_error().raw_os_error() != Some(libc::EPERM)
    {
        return Err(Error::ConfinementPolicy);
    }
    if unsafe {
        libc::accept4(
            unix.as_raw_fd(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            libc::SOCK_CLOEXEC,
        )
    } != -1
        || std::io::Error::last_os_error().raw_os_error() != Some(libc::EPERM)
    {
        return Err(Error::ConfinementPolicy);
    }
    super::lab::stage("operational_profile_fcntl_bootstrap_and_negative_syscalls_passed");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| Error::ChildFailed)?;
    rt.block_on(async {
        tokio::time::timeout(Duration::from_secs(4), async {
            let mut unix = tokio::net::UnixStream::from_std(unix)?;
            unix.write_all(&[42]).await?;
            let mut byte = [0];
            unix.read_exact(&mut byte).await?;
            if byte != [42] {
                return Err(std::io::ErrorKind::InvalidData.into());
            }
            unix.shutdown().await?;
            super::lab::stage("operational_profile_tokio_unix_passed");
            let udp = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
            let _ = udp.local_addr()?;
            udp.send_to(&[42], udp_addr).await?;
            let (n, source) = udp.recv_from(&mut byte).await?;
            if n != 1 || source != udp_addr || byte != [42] {
                return Err(std::io::ErrorKind::InvalidData.into());
            }
            udp.connect(udp_addr).await?;
            if udp.peer_addr()? != udp_addr {
                return Err(std::io::ErrorKind::InvalidData.into());
            }
            udp.send(&[42]).await?;
            if udp.recv(&mut byte).await? != 1 || byte != [42] {
                return Err(std::io::ErrorKind::InvalidData.into());
            }
            super::lab::stage("operational_profile_tokio_udp_passed");
            let mut tcp = tokio::net::TcpStream::connect(tcp_addr).await?;
            tcp.set_nodelay(true)?;
            if tcp.peer_addr()? != tcp_addr
                || !tcp.local_addr()?.ip().is_loopback()
                || tcp.take_error()?.is_some()
            {
                return Err(std::io::ErrorKind::InvalidData.into());
            }
            tcp.write_all(&[42]).await?;
            tcp.read_exact(&mut byte).await?;
            if byte != [42] {
                return Err(std::io::ErrorKind::InvalidData.into());
            }
            tcp.shutdown().await?;
            if tcp.read(&mut byte).await? != 0 {
                return Err(std::io::ErrorKind::InvalidData.into());
            }
            match tokio::net::TcpStream::connect(refused_addr).await {
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => (),
                _ => return Err(std::io::ErrorKind::InvalidData.into()),
            }
            super::lab::stage("operational_profile_tokio_tcp_shutdown_so_error_passed");
            // Exercise timer wakeup separately from successful immediate I/O.
            tokio::time::sleep(Duration::from_millis(10)).await;
            Ok::<_, std::io::Error>(())
        })
        .await
        .map_err(|_| Error::Deadline)?
        .map_err(|_| Error::NetworkOperation)
    })
}
#[cfg(test)]
fn actual_state_mount_negative(executable: BorrowedFd<'_>) -> Result<()> {
    use std::io::Write;
    let state = fs::open(
        c"/state",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| Error::ProbeStateWrite)?;
    let flags = fs::fstatvfs(&state)
        .map_err(|_| Error::ProbeStateWrite)?
        .f_flag;
    if !flags.contains(
        fs::StatVfsMountFlags::NOEXEC
            | fs::StatVfsMountFlags::NOSUID
            | fs::StatVfsMountFlags::NODEV,
    ) {
        return Err(Error::ProbeReadonly);
    }
    let size = fs::fstat(executable)
        .map_err(|_| Error::DescriptorExecutable)?
        .st_size;
    if !(1..=64 * 1024 * 1024).contains(&size) {
        return Err(Error::DescriptorExecutable);
    }
    let fd = fs::openat(
        &state,
        "noexec-probe",
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::RUSR | Mode::WUSR | Mode::XUSR,
    )
    .map_err(|_| Error::ProbeStateWrite)?;
    let mut file = std::fs::File::from(fd);
    let mut bytes = vec![0; 65536];
    let mut offset = 0;
    while offset < size as u64 {
        let n = rustix::io::pread(executable, &mut bytes, offset)
            .map_err(|_| Error::ProbeStateWrite)?;
        if n == 0 {
            return Err(Error::ProbeStateWrite);
        }
        file.write_all(&bytes[..n])
            .map_err(|_| Error::ProbeStateWrite)?;
        offset += n as u64;
    }
    if offset != size as u64
        || fs::fstat(&file)
            .map_err(|_| Error::ProbeStateWrite)?
            .st_size
            != size
    {
        return Err(Error::ProbeStateWrite);
    }
    drop(file);
    // Independent mount denial BEFORE installing the runtime seccomp filter.
    // A regression can run only this exact public program with fixed --version.
    let args = [
        c"fixed-state-probe".as_ptr(),
        c"--version".as_ptr(),
        std::ptr::null(),
    ];
    let env = [std::ptr::null()];
    unsafe {
        libc::execve(c"/state/noexec-probe".as_ptr(), args.as_ptr(), env.as_ptr());
    }
    if std::io::Error::last_os_error().raw_os_error() != Some(libc::EACCES) {
        return Err(Error::ProbeReadonly);
    }
    fs::unlinkat(&state, "noexec-probe", fs::AtFlags::empty()).map_err(|_| Error::ProbeStateWrite)
}
#[cfg(test)]
fn hidden_init_denial(
    result: std::result::Result<(), rustix::io::Errno>,
    magic: u64,
    mounts: &str,
    parent: i32,
    mount_id: u64,
) -> Result<()> {
    let proc: Vec<_> = mounts
        .lines()
        .filter_map(|line| line.split_once(" - "))
        .filter(|(left, _)| {
            left.split_whitespace()
                .next()
                .and_then(|id| id.parse::<u64>().ok())
                == Some(mount_id)
        })
        .collect();
    if magic != 0x9fa0
        || parent != 1
        || mount_id == 0
        || proc.len() != 1
        || proc[0].0.split_whitespace().nth(3) != Some("/")
        || proc[0].0.split_whitespace().nth(4) != Some("/proc")
        || !proc[0].0.split_whitespace().nth(5).is_some_and(|flags| {
            ["ro", "nosuid", "nodev", "noexec"]
                .iter()
                .all(|flag| flags.split(',').any(|present| present == *flag))
        })
        || proc[0].1.split_whitespace().next() != Some("proc")
        || !proc[0].1.split_whitespace().nth(2).is_some_and(|s| {
            let values: Vec<_> = s
                .split(',')
                .filter_map(|v| v.strip_prefix("hidepid="))
                .collect();
            matches!(values.as_slice(), ["2"] | ["invisible"])
        })
        || !result.is_err_and(|e| {
            matches!(
                e,
                rustix::io::Errno::ACCESS | rustix::io::Errno::PERM | rustix::io::Errno::NOENT
            )
        })
    {
        return Err(Error::ProbeProcHiddenInit);
    }
    Ok(())
}
#[cfg(test)]
fn actual_profile_negative() -> Result<()> {
    // Positive predicates precede negative probes: absent/broken procfs or a
    // dead/missing namespace parent must never make ENOENT count as isolation.
    use std::io::Read;
    let read = |path: &str| -> Result<String> {
        let mut text = String::new();
        let descriptor = fs::openat(
            fs::CWD,
            path,
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| Error::ProbeProcHiddenInit)?;
        std::fs::File::from(descriptor)
            .take(262145)
            .read_to_string(&mut text)
            .map_err(|_| Error::ProbeProcHiddenInit)?;
        if text.len() > 262144 {
            return Err(Error::ProbeProcHiddenInit);
        }
        Ok(text)
    };
    let own_pid = unsafe { libc::getpid() } as u32;
    super::process::stat_start(&read("/proc/self/stat")?, own_pid)
        .map_err(|_| Error::ProbeProcHiddenInit)?;
    let mounts = read("/proc/self/mountinfo")?;
    let proc = fs::openat(
        fs::CWD,
        "/proc",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| Error::ProbeProcHiddenInit)?;
    let magic = fs::fstatfs(&proc)
        .map_err(|_| Error::ProbeProcHiddenInit)?
        .f_type as u64;
    let selected = fs::statx(&proc, "", fs::AtFlags::EMPTY_PATH, fs::StatxFlags::MNT_ID)
        .map_err(|_| Error::ProbeProcHiddenInit)?;
    if selected.stx_mask & fs::StatxFlags::MNT_ID.bits() == 0 || selected.stx_mnt_id == 0 {
        return Err(Error::ProbeProcHiddenInit);
    }
    let parent = unsafe { libc::getppid() };
    for path in ["/proc/1/root", "/proc/1/mem", "/proc/1/fd"] {
        hidden_init_denial(
            fs::openat(
                fs::CWD,
                path,
                OFlags::RDONLY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map(|_| ()),
            magic,
            &mounts,
            parent,
            selected.stx_mnt_id,
        )?;
    }
    let args = [
        c"fixed-state-probe".as_ptr(),
        c"--version".as_ptr(),
        std::ptr::null(),
    ];
    let env = [std::ptr::null()];
    unsafe {
        libc::execve(c"/state/noexec-probe".as_ptr(), args.as_ptr(), env.as_ptr());
    }
    if std::io::Error::last_os_error().raw_os_error() != Some(libc::EPERM) {
        return Err(Error::ConfinementPolicy);
    }
    Ok(())
}
fn actual_exec(
    executable: BorrowedFd<'_>,
    health: BorrowedFd<'_>,
    null: StdioIdentity,
    role: ActualRole,
    #[cfg(test)] proc_ready: Option<BorrowedFd<'_>>,
) -> Result<()> {
    parent_death(1)?;
    let ex =
        rustix::io::fcntl_dupfd_cloexec(executable, 110).map_err(|_| Error::DescriptorDuplicate)?;
    let he =
        rustix::io::fcntl_dupfd_cloexec(health, 110).map_err(|_| Error::DescriptorDuplicate)?;
    #[cfg(test)]
    let proc_ready = proc_ready
        .map(|fd| {
            rustix::io::fcntl_dupfd_cloexec(fd, 110)
                .map(std::mem::ManuallyDrop::new)
                .map_err(|_| Error::DescriptorDuplicate)
        })
        .transpose()?;
    dup_fixed(&he, 3, true)?;
    dup_fixed(&ex, 4, true)?;
    let result: Result<()> = (|| {
        // The supervisor still needs to write its own LSM transition after
        // fork. Isolate this mount view before making proc readonly; otherwise
        // the child's remount races that fixed supervisor transition with
        // EROFS. Setup SYS_ADMIN is dropped below before the fixed exec.
        unshare(libc::CLONE_NEWNS).map_err(|_| Error::MountPrivate)?;
        #[cfg(test)]
        if let Some(gate) = &proc_ready {
            dup_fixed(&**gate, 5, true)?;
        }
        #[cfg(test)]
        close_except(if proc_ready.is_some() {
            &[3, 4, 5]
        } else {
            &[3, 4]
        })?;
        #[cfg(not(test))]
        close_except(&[3, 4])?;
        lsm_exec()?;
        // Restrict this mount only. A plain MS_REMOUNT changes the shared proc
        // superblock despite unshare(CLONE_NEWNS), racing PID1's LSM write.
        // The child retains readonly/nosuid/nodev/noexec after setup caps drop.
        mount(
            None,
            c"/proc",
            None,
            libc::MS_REMOUNT
                | libc::MS_BIND
                | libc::MS_RDONLY
                | libc::MS_NOSUID
                | libc::MS_NODEV
                | libc::MS_NOEXEC,
            None,
        )?;
        #[cfg(test)]
        if proc_ready.is_some() {
            write_byte(unsafe { BorrowedFd::borrow_raw(5) }, 129)?;
            checked_close(5)?;
        }
        actual_capabilities(role, unsafe { BorrowedFd::borrow_raw(3) })?;
        #[cfg(test)]
        actual_state_mount_negative(unsafe { BorrowedFd::borrow_raw(4) })?;
        if unsafe { libc::getppid() } != 1 {
            return Err(Error::ChildFailed);
        }
        for n in 0..3 {
            if approved_null(unsafe { BorrowedFd::borrow_raw(n) })? != null {
                return Err(Error::DescriptorStdio);
            }
        }
        let mut empty = unsafe { std::mem::zeroed() };
        unsafe {
            libc::sigemptyset(&mut empty);
        }
        cv(
            unsafe { libc::sigprocmask(libc::SIG_SETMASK, &empty, std::ptr::null_mut()) },
            Error::ChildFailed,
        )?;
        if descriptor_inventory()? != [0, 1, 2, 3, 4].into_iter().collect() {
            return Err(Error::DescriptorInventory);
        }
        for fd in [3, 4] {
            if unsafe { libc::fcntl(fd, libc::F_GETFD) } != libc::FD_CLOEXEC {
                return Err(Error::DescriptorFlags);
            }
        }
        if fs::FileType::from_raw_mode(
            fs::fstat(unsafe { BorrowedFd::borrow_raw(3) })
                .map_err(|_| Error::DescriptorHealth)?
                .st_mode,
        ) != fs::FileType::Fifo
            || fs::FileType::from_raw_mode(
                fs::fstat(unsafe { BorrowedFd::borrow_raw(4) })
                    .map_err(|_| Error::DescriptorExecutable)?
                    .st_mode,
            ) != fs::FileType::RegularFile
        {
            return Err(Error::DescriptorPolicy);
        }
        let mut env: Vec<_> = actual_environment(role)
            .iter()
            .map(|value| value.as_ptr())
            .collect();
        env.push(std::ptr::null());
        apply_filter(&runtime_filter(role))?;
        #[cfg(test)]
        {
            actual_profile_negative()?;
            if descriptor_inventory()? != [0, 1, 2, 3, 4].into_iter().collect() {
                return Err(Error::DescriptorInventory);
            }
            write_byte(
                unsafe { BorrowedFd::borrow_raw(3) },
                match role {
                    ActualRole::Daemon => 60,
                    ActualRole::Observer => 61,
                    ActualRole::Monitor => 62,
                    ActualRole::OperationalMonitor => 63,
                },
            )?;
        }
        // Setup acknowledgement ONLY. It is never daemon health, ObserveOnce or
        // advertisement/readiness. Both control/executable FDs are CLOEXEC.
        write_byte(unsafe { BorrowedFd::borrow_raw(3) }, 1)?;
        let worker = [c"vprouter-worker-observe".as_ptr(), std::ptr::null()];
        let monitor = [c"vprouter-worker-monitor".as_ptr(), std::ptr::null()];
        let daemon = [
            c"tailscaled".as_ptr(),
            c"--tun=tailscale0".as_ptr(),
            c"--port=41641".as_ptr(),
            c"--state=/state/tailscaled.state".as_ptr(),
            c"--statedir=/state".as_ptr(),
            c"--socket=/state/tailscaled.sock".as_ptr(),
            c"--no-logs-no-support".as_ptr(),
            c"--config=/etc/tailscale.json".as_ptr(),
            std::ptr::null(),
        ];
        let args = match role {
            ActualRole::Observer => worker.as_ptr(),
            ActualRole::Monitor | ActualRole::OperationalMonitor => monitor.as_ptr(),
            ActualRole::Daemon => daemon.as_ptr(),
        };
        // SAFETY: fixed immutable bytes and constant argv/env; exact FD4 closes
        // on exec along with health3. No namespace/root/control FD survives.
        unsafe {
            libc::syscall(
                libc::SYS_execveat,
                4,
                c"".as_ptr(),
                args,
                env.as_ptr(),
                libc::AT_EMPTY_PATH,
            );
        }
        Err(Error::ChildFailed)
    })();
    if let Err(e) = result {
        report_failure(unsafe { BorrowedFd::borrow_raw(3) }, e);
    }
    die(119)
}

/// Validate the exact socket observed immediately after a trusted synchronous
/// constructor, including its actual construction network namespace cookie.
pub(super) fn control_socket(number: i32) -> Result<i32> {
    if number < 3 {
        return Err(Error::DescriptorPolicy);
    }
    // SAFETY: inventory scanned a currently live descriptor on this sole thread;
    // borrowed only synchronously, never transferred or closed here.
    let fd = unsafe { BorrowedFd::borrow_raw(number) };
    use rustix::net::{self, AddressFamily, SocketFlags, SocketType, netlink::SocketAddrNetlink};
    if net::sockopt::socket_domain(fd).map_err(|_| Error::DescriptorPolicy)?
        != AddressFamily::NETLINK
        || net::sockopt::socket_type(fd).map_err(|_| Error::DescriptorPolicy)? != SocketType::RAW
    {
        return Err(Error::DescriptorPolicy);
    }
    let protocol = net::sockopt::socket_protocol(fd)
        .map_err(|_| Error::DescriptorPolicy)?
        .map_or(0, |p| p.as_raw().get());
    let address =
        SocketAddrNetlink::try_from(net::getsockname(fd).map_err(|_| Error::DescriptorPolicy)?)
            .map_err(|_| Error::DescriptorPolicy)?;
    if address.pid() == 0 || address.groups() != 0 {
        return Err(Error::DescriptorPolicy);
    }
    fn net_cookie(fd: BorrowedFd<'_>) -> Result<u64> {
        let mut cookie = 0u64;
        let mut size = std::mem::size_of::<u64>() as libc::socklen_t;
        // SAFETY: exact initialized u64 output and socklen storage; kernel only
        // writes within the declared length. SO_NETNS_COOKIE is Linux option71.
        cv(
            unsafe {
                libc::getsockopt(
                    fd.as_raw_fd(),
                    libc::SOL_SOCKET,
                    71,
                    (&mut cookie as *mut u64).cast(),
                    &mut size,
                )
            },
            Error::DescriptorPolicy,
        )?;
        if size as usize != std::mem::size_of::<u64>() || cookie == 0 {
            return Err(Error::DescriptorPolicy);
        }
        Ok(cookie)
    }
    let local = net::socket_with(
        AddressFamily::NETLINK,
        SocketType::RAW,
        SocketFlags::CLOEXEC,
        None,
    )
    .map_err(|_| Error::DescriptorPolicy)?;
    if net_cookie(fd)? != net_cookie(local.as_fd())? {
        return Err(Error::NamespaceMismatch);
    }
    Ok(protocol as i32)
}

fn init_filter() -> Vec<libc::sock_filter> {
    let mut out = wait_filter();
    out.pop();
    out.extend([
        libc::sock_filter {
            code: 0x15,
            jt: 0,
            jf: 3,
            k: libc::SYS_kill as u32,
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
            k: u32::MAX,
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
    out
}

#[cfg(test)]
mod policy_tests {
    use super::*;
    #[test]
    fn native_reap_test_history_overflow_fails_without_evicting_evidence() {
        let mut history = LabEarlyReaps::new();
        for pid in 1..=64 {
            history.record((1, pid, 123), libc::SIGKILL);
        }
        assert_eq!(history.get((1, 1, 123)), Ok(Some(libc::SIGKILL)));
        let before = history.receipts.clone();
        history.record((1, 65, 123), libc::SIGKILL);
        assert_eq!(history.receipts, before);
        assert_eq!(history.get((1, 1, 123)), Err(Error::TooLarge));
        let mut duplicate = LabEarlyReaps::new();
        duplicate.record((1, 1, 123), libc::SIGKILL);
        duplicate.record((1, 1, 123), 0);
        assert_eq!(duplicate.receipts.get(&(1, 1, 123)), Some(&libc::SIGKILL));
        assert_eq!(duplicate.get((1, 1, 123)), Err(Error::TooLarge));
    }
    #[test]
    fn live_child_capacity_refuses_before_creating_another_native_process() {
        assert_eq!(live_child_count(), 0);
        let held: Vec<_> = (0..64).map(|_| ChildCapacity::created()).collect();
        assert!(matches!(fork_with_pidfd(), Err(Error::LockBusy)));
        drop(held);
        assert_eq!(live_child_count(), 0);
    }
    #[test]
    fn publisher_ready_requires_exact_byte_and_writer_close() {
        let (read, write) = publisher_pipe().unwrap();
        write_byte(&write, 128).unwrap();
        // The child has sent Ready but still owns startup FD5. This must fail,
        // even though reading the ready byte itself succeeds immediately.
        assert_eq!(
            publisher_ready(&read, Instant::now() + Duration::from_millis(10)),
            Err(Error::Deadline)
        );
        drop(write);
        for bytes in [vec![], vec![127], vec![128, 1], vec![128, 128]] {
            let (read, write) = publisher_pipe().unwrap();
            for byte in bytes {
                write_byte(&write, byte).unwrap();
            }
            drop(write);
            assert_eq!(
                publisher_ready(&read, Instant::now() + Duration::from_secs(1)),
                Err(Error::ChildFailed)
            );
        }
        let (read, write) = publisher_pipe().unwrap();
        write_byte(&write, 128).unwrap();
        drop(write);
        publisher_ready(&read, Instant::now() + Duration::from_secs(1)).unwrap();
    }
    #[test]
    fn publisher_ready_preserves_original_deadline_and_rejects_read_error() {
        let (read, write) = publisher_pipe().unwrap();
        write_byte(&write, 128).unwrap();
        drop(write);
        assert_eq!(publisher_ready(&read, Instant::now()), Err(Error::Deadline));
        let invalid = fs::open(
            c"/dev/null",
            OFlags::WRONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        assert_eq!(
            publisher_ready(&invalid, Instant::now() + Duration::from_secs(1)),
            Err(Error::ChildFailed)
        );
    }
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
    #[test]
    fn proc_positive_probe_uses_admitted_native_syscalls_not_legacy_open() {
        let arch = if cfg!(target_arch = "x86_64") {
            0xc000003e
        } else {
            0xc00000b7
        };
        for role in [
            ActualRole::Observer,
            ActualRole::Monitor,
            ActualRole::Daemon,
        ] {
            let filter = runtime_filter(role);
            for syscall in [
                libc::SYS_openat,
                libc::SYS_read,
                libc::SYS_fstatfs,
                libc::SYS_statx,
                libc::SYS_getpid,
                libc::SYS_getppid,
            ] {
                assert_eq!(
                    verdict_program(&filter, arch, syscall as u32, 0),
                    0x7fff0000
                );
            }
            #[cfg(target_arch = "x86_64")]
            assert_ne!(
                verdict_program(&filter, arch, libc::SYS_open as u32, 0),
                0x7fff0000
            );
        }
    }
    #[test]
    fn hidden_init_binds_selected_proc_mount_id_and_exact_invisible_semantics() {
        let old = "11 10 0:7 / /proc rw,nosuid,nodev,noexec - proc proc rw\n";
        for mode in ["2", "invisible"] {
            let selected =
                format!("12 11 0:8 / /proc ro,nosuid,nodev,noexec - proc proc rw,hidepid={mode}\n");
            let mounts = format!("{old}{selected}");
            assert!(
                hidden_init_denial(Err(rustix::io::Errno::NOENT), 0x9fa0, &mounts, 1, 12).is_ok()
            );
            assert!(
                hidden_init_denial(Err(rustix::io::Errno::NOENT), 0x9fa0, &mounts, 1, 11).is_err()
            );
            assert!(
                hidden_init_denial(Err(rustix::io::Errno::NOENT), 0x9fa0, &mounts, 1, 13).is_err()
            );
            let duplicate = format!("{mounts}{selected}");
            assert!(
                hidden_init_denial(Err(rustix::io::Errno::NOENT), 0x9fa0, &duplicate, 1, 12)
                    .is_err()
            );
        }
        for mode in ["0", "1", "4", "noaccess", "ptraceable", "invisible-extra"] {
            let mount =
                format!("12 11 0:8 / /proc ro,nosuid,nodev,noexec - proc proc rw,hidepid={mode}\n");
            assert!(
                hidden_init_denial(Err(rustix::io::Errno::NOENT), 0x9fa0, &mount, 1, 12).is_err()
            );
        }
    }
    #[test]
    fn hidden_init_enoent_requires_positive_private_proc_and_live_self() {
        let mount = "12 11 0:8 / /proc ro,nosuid,nodev,noexec - proc proc rw,hidepid=2\n";
        for errno in [
            rustix::io::Errno::ACCESS,
            rustix::io::Errno::PERM,
            rustix::io::Errno::NOENT,
        ] {
            assert!(hidden_init_denial(Err(errno), 0x9fa0, mount, 1, 12).is_ok());
        }
        assert!(hidden_init_denial(Ok(()), 0x9fa0, mount, 1, 12).is_err());
        for (magic, mount, parent) in [
            (0, mount, 1),
            (0x9fa0, "", 1),
            (0x9fa0, mount, 0),
            (0x9fa0, "12 11 0:8 / /proc ro - proc proc rw\n", 1),
        ] {
            assert!(
                hidden_init_denial(Err(rustix::io::Errno::NOENT), magic, mount, parent, 12)
                    .is_err()
            );
        }
        assert!(hidden_init_denial(Err(rustix::io::Errno::IO), 0x9fa0, mount, 1, 12).is_err());
    }
    #[test]
    fn terminal_guard_observation_uses_permitted_ppoll_without_widening_filter() {
        let f = terminal_filter(false);
        let arch = if cfg!(target_arch = "x86_64") {
            0xc000003e
        } else {
            0xc00000b7
        };
        assert_eq!(
            verdict_program(&f, arch, libc::SYS_ppoll as u32, 0),
            0x7fff0000
        );
        #[cfg(target_arch = "x86_64")]
        assert_ne!(
            verdict_program(&f, arch, libc::SYS_poll as u32, 0),
            0x7fff0000
        );
        assert_eq!(
            verdict_program(&f, arch, libc::SYS_pread64 as u32, 13),
            0x7fff0000
        );
        for fd in [3, 4, 5, 11] {
            assert_ne!(
                verdict_program(&f, arch, libc::SYS_pread64 as u32, fd),
                0x7fff0000
            );
        }
    }
    #[test]
    fn terminal_checkpoint_allows_only_exact_self_stop_and_preserves_guard_policy() {
        let arch = if cfg!(target_arch = "x86_64") {
            0xc000003e
        } else {
            0xc00000b7
        };
        for checkpoint in [false, true] {
            let filter = terminal_filter(checkpoint);
            for fd in [4, 12] {
                let args = [fd, libc::SIGSTOP as u64, 0, 0, 0, 0];
                assert_eq!(
                    verdict_args(&filter, arch, libc::SYS_pidfd_send_signal as u32, args)
                        == 0x7fff0000,
                    fd == 4 || checkpoint,
                    "checkpoint={checkpoint} fd={fd}",
                );
                for altered in [
                    [fd, libc::SIGCONT as u64, 0, 0, 0, 0],
                    [fd, libc::SIGKILL as u64, 0, 0, 0, 0],
                    [fd, libc::SIGSTOP as u64, 1, 0, 0, 0],
                    [fd, libc::SIGSTOP as u64, 0, 1, 0, 0],
                    [fd | (1 << 32), libc::SIGSTOP as u64, 0, 0, 0, 0],
                    [fd, (libc::SIGSTOP as u64) | (1 << 32), 0, 0, 0, 0],
                    [fd, libc::SIGSTOP as u64, 1 << 32, 0, 0, 0],
                    [fd, libc::SIGSTOP as u64, 0, 1 << 32, 0, 0],
                ] {
                    assert_ne!(
                        verdict_args(&filter, arch, libc::SYS_pidfd_send_signal as u32, altered),
                        0x7fff0000
                    );
                }
            }
            for fd in [0, 3, 5, 11, 13] {
                assert_ne!(
                    verdict_args(
                        &filter,
                        arch,
                        libc::SYS_pidfd_send_signal as u32,
                        [fd, libc::SIGSTOP as u64, 0, 0, 0, 0]
                    ),
                    0x7fff0000
                );
            }
        }
    }
    #[test]
    fn terminal_executor_filter_cannot_unlock_close_write_or_duplicate_lease() {
        let f = terminal_filter(false);
        let arch = if cfg!(target_arch = "x86_64") {
            0xc000003e
        } else {
            0xc00000b7
        };
        assert_eq!(
            verdict_args(
                &f,
                arch,
                libc::SYS_prctl as u32,
                [libc::PR_GET_SECCOMP as u64, 0, 0, 0, 0, 0]
            ),
            0x7fff0000
        );
        for nr in [
            libc::SYS_write,
            libc::SYS_writev,
            libc::SYS_close,
            libc::SYS_fcntl,
            libc::SYS_flock,
            libc::SYS_dup,
            libc::SYS_sendmsg,
            libc::SYS_openat,
            libc::SYS_socket,
            libc::SYS_clone,
            libc::SYS_execveat,
            libc::SYS_kill,
            libc::SYS_setns,
        ] {
            assert_ne!(verdict_program(&f, arch, nr as u32, 5), 0x7fff0000, "{nr}");
        }
        assert_ne!(
            verdict_args(
                &f,
                arch,
                libc::SYS_mmap as u32,
                [
                    0,
                    4096,
                    (libc::PROT_READ | libc::PROT_WRITE) as u64,
                    libc::MAP_SHARED as u64,
                    5,
                    0
                ]
            ),
            0x7fff0000
        );
        for fd in [3, 6, 8] {
            assert_eq!(
                verdict_program(&f, arch, libc::SYS_sendto as u32, fd),
                0x7fff0000
            );
        }
        for fd in [4, 5, 7, 9, 10, (1u64 << 32) | 3] {
            assert_ne!(
                verdict_program(&f, arch, libc::SYS_sendto as u32, fd),
                0x7fff0000
            );
        }
        assert_eq!(
            verdict_args(
                &f,
                arch,
                libc::SYS_pidfd_send_signal as u32,
                [4, libc::SIGSTOP as u64, 0, 0, 0, 0]
            ),
            0x7fff0000
        );
        for args in [
            [5, libc::SIGSTOP as u64, 0, 0, 0, 0],
            [4, libc::SIGCONT as u64, 0, 0, 0, 0],
            [4, libc::SIGSTOP as u64, 1, 0, 0, 0],
            [4, libc::SIGSTOP as u64, 0, 1, 0, 0],
        ] {
            assert_ne!(
                verdict_args(&f, arch, libc::SYS_pidfd_send_signal as u32, args),
                0x7fff0000
            );
        }
    }
    #[test]
    fn inspector_filter_allows_readonly_scalar_paths_and_only_private_receipt_output() {
        let f = inspection::inspection_filter(71);
        let arch = if cfg!(target_arch = "x86_64") {
            0xc000003e
        } else {
            0xc00000b7
        };
        let allow = 0x7fff0000;
        let mut args = [0u64; 6];
        args[0] = u64::MAX - 99;
        args[2] = (libc::O_CLOEXEC | libc::O_NOFOLLOW) as u64;
        assert_eq!(verdict_args(&f, arch, libc::SYS_openat as u32, args), allow);
        for bits in [
            libc::O_WRONLY as u64,
            libc::O_RDWR as u64,
            libc::O_CREAT as u64,
            libc::O_TRUNC as u64,
            libc::O_APPEND as u64,
            libc::O_TMPFILE as u64,
            1u64 << 32,
        ] {
            let mut bad = args;
            bad[2] |= bits;
            assert_ne!(verdict_args(&f, arch, libc::SYS_openat as u32, bad), allow);
        }
        let getter = [71, libc::F_GETFD as u64, 0, 0, 0, 0];
        assert_eq!(
            verdict_args(&f, arch, libc::SYS_fcntl as u32, getter),
            allow
        );
        for command in [
            libc::F_SETFD,
            libc::F_SETFL,
            libc::F_DUPFD,
            libc::F_DUPFD_CLOEXEC,
        ] {
            let mut bad = getter;
            bad[1] = command as u64;
            assert_ne!(verdict_args(&f, arch, libc::SYS_fcntl as u32, bad), allow);
        }
        #[cfg(target_arch = "x86_64")]
        assert_ne!(verdict_args(&f, arch, libc::SYS_open as u32, [0; 6]), allow);
        let send = [
            71,
            0,
            1,
            (libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL) as u64,
            0,
            0,
        ];
        assert_eq!(verdict_args(&f, arch, libc::SYS_sendto as u32, send), allow);
        for index in [0, 3, 4, 5] {
            let mut bad = send;
            bad[index] += 1;
            assert_ne!(verdict_args(&f, arch, libc::SYS_sendto as u32, bad), allow);
        }
        let mmap = [
            0,
            4096,
            (libc::PROT_READ | libc::PROT_WRITE) as u64,
            (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as u64,
            u64::MAX,
            0,
        ];
        assert_eq!(verdict_args(&f, arch, libc::SYS_mmap as u32, mmap), allow);
        for (index, bits) in [(2, libc::PROT_EXEC), (3, libc::MAP_SHARED)] {
            let mut bad = mmap;
            bad[index] |= bits as u64;
            assert_ne!(verdict_args(&f, arch, libc::SYS_mmap as u32, bad), allow);
        }
        for nr in [
            libc::SYS_openat2,
            libc::SYS_write,
            libc::SYS_writev,
            libc::SYS_pwrite64,
            libc::SYS_pidfd_getfd,
            libc::SYS_ptrace,
            libc::SYS_process_vm_writev,
            libc::SYS_process_vm_readv,
            libc::SYS_socket,
            libc::SYS_sendmsg,
            libc::SYS_execve,
            libc::SYS_execveat,
            libc::SYS_setns,
            libc::SYS_unshare,
            libc::SYS_ftruncate,
            libc::SYS_fchmod,
            libc::SYS_unlinkat,
            libc::SYS_mkdirat,
            libc::SYS_renameat,
            libc::SYS_pidfd_send_signal,
        ] {
            assert_ne!(
                verdict_args(&f, arch, nr as u32, [0; 6]),
                allow,
                "syscall {nr}"
            );
        }
        assert_eq!(
            verdict_args(&f, arch, libc::SYS_ppoll as u32, [0; 6]),
            allow
        );
        #[cfg(target_arch = "x86_64")]
        assert_ne!(verdict_args(&f, arch, libc::SYS_poll as u32, [0; 6]), allow);
    }
    #[test]
    fn host_audit_filter_binds_two_sockets_and_denies_mutation_capability_paths() {
        let f = host_audit::host_filter();
        let arch = if cfg!(target_arch = "x86_64") {
            0xc000003e
        } else {
            0xc00000b7
        };
        assert_eq!(
            verdict_program(
                &f,
                arch,
                libc::SYS_prctl as u32,
                libc::PR_GET_SECCOMP as u64
            ),
            0x7fff0000
        );
        for command in [
            libc::PR_SET_SECCOMP as u64,
            libc::PR_SET_NO_NEW_PRIVS as u64,
            libc::PR_CAP_AMBIENT as u64,
            (1u64 << 32) | libc::PR_GET_SECCOMP as u64,
        ] {
            assert_ne!(
                verdict_program(&f, arch, libc::SYS_prctl as u32, command),
                0x7fff0000
            );
        }
        for nr in [
            libc::SYS_socket,
            libc::SYS_openat,
            libc::SYS_connect,
            libc::SYS_execveat,
            libc::SYS_clone,
            libc::SYS_unshare,
            libc::SYS_setns,
            libc::SYS_chroot,
            libc::SYS_capset,
            libc::SYS_renameat,
            libc::SYS_write,
            libc::SYS_read,
        ] {
            assert_ne!(verdict_program(&f, arch, nr as u32, 0), 0x7fff0000);
        }
        for nr in [libc::SYS_sendto, libc::SYS_recvfrom] {
            for fd in [3, 6] {
                assert_eq!(verdict_program(&f, arch, nr as u32, fd), 0x7fff0000);
            }
            for fd in [0, 1, 2, 4, 5, 7, (1u64 << 32) | 3, (1u64 << 32) | 6] {
                assert_ne!(verdict_program(&f, arch, nr as u32, fd), 0x7fff0000);
            }
        }
        for nr in [libc::SYS_mmap, libc::SYS_mprotect] {
            assert_ne!(
                verdict_args(&f, arch, nr as u32, [0, 0, libc::PROT_EXEC as u64, 0, 0, 0]),
                0x7fff0000
            );
        }
    }
    #[test]
    fn retirement_cleanup_filter_binds_native_targets_and_denies_escape() {
        let arch = if cfg!(target_arch = "x86_64") {
            0xc000003e
        } else {
            0xc00000b7
        };
        for producer in [false, true] {
            let sockets: &[i32] = if producer { &[] } else { &[11, 12] };
            let f = cleanup::cleanup_filter(sockets, &[20, 21, 22, 23], 30, producer);
            let allow = 0x7fff0000;
            for nr in [
                libc::SYS_clone,
                libc::SYS_clone3,
                libc::SYS_execve,
                libc::SYS_execveat,
                libc::SYS_socket,
                libc::SYS_openat,
                libc::SYS_setns,
                libc::SYS_close,
                libc::SYS_flock,
                libc::SYS_dup3,
                libc::SYS_kill,
                libc::SYS_pidfd_send_signal,
                libc::SYS_timerfd_settime,
                libc::SYS_write,
            ] {
                assert_ne!(verdict_args(&f, arch, nr as u32, [0; 6]), allow);
            }
            for nr in [libc::SYS_sendto, libc::SYS_recvfrom] {
                for fd in [0, 1, 2, 10, 20, 21, 22, 23, (1u64 << 32) | 30] {
                    assert_ne!(
                        verdict_args(&f, arch, nr as u32, [fd, 0, 0, 0, 0, 0]),
                        allow
                    );
                }
                assert_eq!(
                    verdict_args(&f, arch, nr as u32, [30, 0, 0, 0, 0, 0]),
                    allow
                );
                assert_eq!(
                    verdict_args(&f, arch, nr as u32, [11, 0, 0, 0, 0, 0]) == allow,
                    !producer
                );
            }
            for fd in [20, 21, 30, (1u64 << 32) | 22] {
                assert_ne!(
                    verdict_args(&f, arch, libc::SYS_pread64 as u32, [fd, 0, 0, 0, 0, 0]),
                    allow
                );
            }
            assert_eq!(
                verdict_args(&f, arch, libc::SYS_pread64 as u32, [22, 0, 0, 0, 0, 0]),
                allow
            );
            for fd in [21, 22, 30, (1u64 << 32) | 20] {
                assert_ne!(
                    verdict_args(
                        &f,
                        arch,
                        libc::SYS_unlinkat as u32,
                        [fd, 0, libc::AT_REMOVEDIR as u64, 0, 0, 0]
                    ),
                    allow
                );
            }
            assert_eq!(
                verdict_args(
                    &f,
                    arch,
                    libc::SYS_unlinkat as u32,
                    [20, 0, libc::AT_REMOVEDIR as u64, 0, 0, 0]
                ) == allow,
                producer
            );
            assert_ne!(
                verdict_args(&f, arch, libc::SYS_unlinkat as u32, [20, 0, 0, 0, 0, 0]),
                allow
            );
            assert_eq!(
                verdict_args(&f, arch, libc::SYS_ppoll as u32, [0; 6]),
                allow
            );
            #[cfg(target_arch = "x86_64")]
            assert_ne!(verdict_args(&f, arch, libc::SYS_poll as u32, [0; 6]), allow);
        }
    }
    #[test]
    fn retirement_stop_filter_has_only_exact_original_stop_and_private_receipt_syscalls() {
        let f = retirement::stop_filter();
        let arch = if cfg!(target_arch = "x86_64") {
            0xc000003e
        } else {
            0xc00000b7
        };
        let allow = 0x7fff0000;
        let valid = [4, libc::SIGKILL as u64, 0, 0, 0, 0];
        assert_eq!(
            verdict_args(&f, arch, libc::SYS_pidfd_send_signal as u32, valid),
            allow
        );
        for (arg, value) in [
            (0, 3),
            (0, 5),
            (0, (1u64 << 32) | 4),
            (1, libc::SIGCONT as u64),
            (1, libc::SIGSTOP as u64),
            (2, 1),
            (3, 1),
        ] {
            let mut args = valid;
            args[arg] = value;
            assert_ne!(
                verdict_args(&f, arch, libc::SYS_pidfd_send_signal as u32, args),
                allow
            );
        }
        assert_eq!(
            verdict_args(&f, arch, libc::SYS_write as u32, [5, 0, 1, 0, 0, 0]),
            allow
        );
        for fd in [0, 1, 2, 3, 4, 6, (1u64 << 32) | 5] {
            assert_ne!(
                verdict_args(&f, arch, libc::SYS_write as u32, [fd, 0, 1, 0, 0, 0]),
                allow
            );
        }
        for count in [0, 2, 4096] {
            assert_ne!(
                verdict_args(&f, arch, libc::SYS_write as u32, [5, 0, count, 0, 0, 0]),
                allow
            );
        }
        for nr in [
            libc::SYS_clone,
            libc::SYS_clone3,
            libc::SYS_execve,
            libc::SYS_execveat,
            libc::SYS_socket,
            libc::SYS_openat,
            libc::SYS_setns,
            libc::SYS_read,
            libc::SYS_close,
            libc::SYS_flock,
            libc::SYS_dup3,
            libc::SYS_kill,
        ] {
            assert_ne!(verdict_args(&f, arch, nr as u32, [0; 6]), allow);
        }
        assert_eq!(
            verdict_args(&f, arch, libc::SYS_ppoll as u32, [0; 6]),
            allow
        );
        #[cfg(target_arch = "x86_64")]
        assert_ne!(verdict_args(&f, arch, libc::SYS_poll as u32, [0; 6]), allow);
    }
    #[test]
    fn fixed_publisher_filter_has_no_exec_network_or_fork_and_binds_directory() {
        let f = publisher_filter();
        let arch = if cfg!(target_arch = "x86_64") {
            0xc000003e
        } else {
            0xc00000b7
        };
        for nr in [
            libc::SYS_socket,
            libc::SYS_connect,
            libc::SYS_execveat,
            libc::SYS_clone,
            libc::SYS_unshare,
            libc::SYS_chroot,
        ] {
            assert_ne!(verdict_program(&f, arch, nr as u32, 0), 0x7fff0000);
        }
        assert_eq!(
            verdict_program(&f, arch, libc::SYS_openat as u32, 4),
            0x7fff0000
        );
        assert_ne!(
            verdict_program(&f, arch, libc::SYS_openat as u32, 5),
            0x7fff0000
        );
        assert_ne!(
            verdict_program(&f, arch, libc::SYS_openat as u32, (1u64 << 32) | 4),
            0x7fff0000
        );
        assert_eq!(
            verdict_program(&f, arch, libc::SYS_recvfrom as u32, 3),
            0x7fff0000
        );
        assert_ne!(
            verdict_program(&f, arch, libc::SYS_recvfrom as u32, 4),
            0x7fff0000
        );
    }
    #[test]
    fn fresh_transport_creation_filter_allows_original_ns_metadata_not_profile_reads() {
        let f = fresh_transport::creation_filter(0x1000);
        let arch = if cfg!(target_arch = "x86_64") {
            0xc000003e
        } else {
            0xc00000b7
        };
        let allow = 0x7fff0000;
        for (nr, args) in [
            (libc::SYS_fstat, [4, 0, 0, 0, 0, 0]),
            (libc::SYS_fstatfs, [4, 0, 0, 0, 0, 0]),
            (libc::SYS_fcntl, [4, libc::F_GETFD as u64, 0, 0, 0, 0]),
            (
                libc::SYS_unshare,
                [libc::CLONE_NEWNET as u64, 0, 0, 0, 0, 0],
            ),
            (
                libc::SYS_openat,
                [
                    libc::AT_FDCWD as i64 as u64,
                    0x1000,
                    (libc::O_RDONLY | libc::O_CLOEXEC) as u64,
                    0,
                    0,
                    0,
                ],
            ),
        ] {
            assert_eq!(
                verdict_args(&f, arch, nr as u32, args),
                allow,
                "original syscall {nr}"
            );
            let mut foreign = args;
            foreign[0] ^= 1;
            assert_ne!(verdict_args(&f, arch, nr as u32, foreign), allow);
            let mut aliased = args;
            aliased[0] ^= 1 << 32;
            assert_ne!(verdict_args(&f, arch, nr as u32, aliased), allow);
        }
        for nr in [
            libc::SYS_pread64,
            libc::SYS_read,
            libc::SYS_fork,
            libc::SYS_clone,
            libc::SYS_clone3,
            libc::SYS_execve,
            libc::SYS_mount,
            libc::SYS_setns,
        ] {
            assert_ne!(verdict_args(&f, arch, nr as u32, [4, 0, 0, 0, 0, 0]), allow);
        }
        assert_ne!(
            verdict_args(
                &f,
                arch,
                libc::SYS_unshare as u32,
                [
                    (libc::CLONE_NEWNET | libc::CLONE_NEWNS) as u64,
                    0,
                    0,
                    0,
                    0,
                    0
                ]
            ),
            allow
        );
    }
    #[test]
    fn fixed_namespace_attachment_filter_binds_original_paths_slots_and_flags() {
        let f = namespace_attachment::mount_filter(0x1000, 0x2000, 0x3000, 0x4000);
        let arch = if cfg!(target_arch = "x86_64") {
            0xc000003e
        } else {
            0xc00000b7
        };
        let allow = 0x7fff0000;
        for (nr, args, checked) in [
            (
                libc::SYS_openat,
                [
                    4,
                    0x1000,
                    (libc::O_RDONLY
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_CLOEXEC
                        | libc::O_NOFOLLOW) as u64,
                    0o600,
                    0,
                    0,
                ],
                4,
            ),
            (libc::SYS_openat2, [4, 0x1000, 0x4000, 24, 0, 0], 4),
            (libc::SYS_mount, [0x2000, 0x3000, 0, libc::MS_BIND, 0, 0], 5),
            (libc::SYS_fsync, [4, 0, 0, 0, 0, 0], 1),
            (
                libc::SYS_sendmsg,
                [
                    5,
                    0,
                    (libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL) as u64,
                    0,
                    0,
                    0,
                ],
                0,
            ),
            (
                libc::SYS_recvfrom,
                [5, 0, 0, (libc::MSG_DONTWAIT | libc::MSG_TRUNC) as u64, 0, 0],
                0,
            ),
        ] {
            assert_eq!(
                verdict_args(&f, arch, nr as u32, args),
                allow,
                "allowed syscall {nr}"
            );
            for index in 0..checked {
                for changed in [args[index] ^ 1, args[index] ^ (1u64 << 32)] {
                    let mut bad = args;
                    bad[index] = changed;
                    assert_ne!(
                        verdict_args(&f, arch, nr as u32, bad),
                        allow,
                        "syscall {nr} arg {index}"
                    );
                }
            }
        }
        for (nr, flags) in [
            (libc::SYS_recvfrom, libc::MSG_DONTWAIT | libc::MSG_TRUNC),
            (libc::SYS_sendmsg, libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL),
        ] {
            let flag_index = if nr == libc::SYS_sendmsg { 2 } else { 3 };
            for fd in [0, 1, 2, 3, 4, 6, 7, 1u64 << 32 | 5] {
                let mut args = [0; 6];
                args[0] = fd;
                args[flag_index] = flags as u64;
                assert_ne!(verdict_args(&f, arch, nr as u32, args), allow);
            }
        }
        for nr in [
            libc::SYS_clone,
            libc::SYS_clone3,
            libc::SYS_execve,
            libc::SYS_execveat,
            libc::SYS_setns,
            libc::SYS_unshare,
            libc::SYS_socket,
            libc::SYS_connect,
            libc::SYS_umount2,
            libc::SYS_unlinkat,
            libc::SYS_dup,
            libc::SYS_dup3,
        ] {
            assert_ne!(verdict_args(&f, arch, nr as u32, [0; 6]), allow);
        }
        assert_ne!(
            verdict_args(
                &f,
                arch,
                libc::SYS_prctl as u32,
                [libc::PR_SET_DUMPABLE as u64, 1, 0, 0, 0, 0]
            ),
            allow
        );
    }
    #[test]
    fn fixed_docker_query_filter_all_selected_sockets_are_reachable() {
        let sockets = [10, 11, 12, 13];
        let f = docker_query::query_filter(&sockets, 3);
        let arch = if cfg!(target_arch = "x86_64") {
            0xc000003e
        } else {
            0xc00000b7
        };
        for fd in sockets {
            for (nr, flags) in [
                (libc::SYS_sendto, libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL),
                (libc::SYS_recvfrom, libc::MSG_DONTWAIT),
                (libc::SYS_close, 0),
            ] {
                assert_eq!(
                    verdict_args(&f, arch, nr as u32, [fd as u64, 0, 0, flags as u64, 0, 0]),
                    0x7fff0000,
                    "fd={fd} syscall={nr}"
                );
            }
            assert_ne!(
                verdict_args(
                    &f,
                    arch,
                    libc::SYS_sendto as u32,
                    [fd as u64, 0, 0, libc::MSG_DONTWAIT as u64, 0, 0]
                ),
                0x7fff0000
            );
            assert_ne!(
                verdict_args(
                    &f,
                    arch,
                    libc::SYS_recvfrom as u32,
                    [
                        fd as u64,
                        0,
                        0,
                        (libc::MSG_DONTWAIT | libc::MSG_TRUNC) as u64,
                        0,
                        0
                    ]
                ),
                0x7fff0000
            );
            assert_ne!(
                verdict_args(
                    &f,
                    arch,
                    libc::SYS_sendto as u32,
                    [
                        fd as u64,
                        0,
                        0,
                        (libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL) as u64,
                        1,
                        0
                    ]
                ),
                0x7fff0000
            );
        }
        assert_eq!(
            verdict_args(
                &f,
                arch,
                libc::SYS_recvfrom as u32,
                [3, 0, 0, (libc::MSG_DONTWAIT | libc::MSG_TRUNC) as u64, 0, 0]
            ),
            0x7fff0000
        );
        assert_ne!(
            verdict_args(
                &f,
                arch,
                libc::SYS_recvfrom as u32,
                [3, 0, 0, libc::MSG_DONTWAIT as u64, 0, 0]
            ),
            0x7fff0000
        );
        assert_ne!(
            verdict_args(&f, arch, libc::SYS_close as u32, [3, 0, 0, 0, 0, 0]),
            0x7fff0000
        );
        for fd in [0, 1, 2, 4, 14, (1 << 32) | 10] {
            for (nr, flags) in [
                (libc::SYS_sendto, libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL),
                (libc::SYS_recvfrom, libc::MSG_DONTWAIT),
                (libc::SYS_close, 0),
            ] {
                assert_ne!(
                    verdict_args(&f, arch, nr as u32, [fd, 0, 0, flags as u64, 0, 0]),
                    0x7fff0000
                );
            }
        }
        for nr in [
            libc::SYS_socket,
            libc::SYS_connect,
            libc::SYS_openat,
            libc::SYS_clone,
            libc::SYS_clone3,
            libc::SYS_execve,
            libc::SYS_execveat,
            libc::SYS_sendmsg,
        ] {
            assert_ne!(verdict_args(&f, arch, nr as u32, [0; 6]), 0x7fff0000);
        }
    }
    #[test]
    fn fixed_secret_filter_covers_all_inputs_without_fork_exec_or_descriptor_aliases() {
        let inputs: Vec<_> = (10..138).collect();
        let program = secret::secret_filter(&inputs, 3);
        assert!(program.len() < 4096);
        let arch = if cfg!(target_arch = "x86_64") {
            0xc000003e
        } else {
            0xc00000b7
        };
        for fd in &inputs {
            for nr in [libc::SYS_fstat, libc::SYS_pread64] {
                assert_eq!(
                    verdict_args(&program, arch, nr as u32, [*fd as u64, 0, 0, 0, 0, 0]),
                    0x7fff0000
                );
                assert_ne!(
                    verdict_args(
                        &program,
                        arch,
                        nr as u32,
                        [(*fd as u64) | (1 << 32), 0, 0, 0, 0, 0]
                    ),
                    0x7fff0000
                );
            }
            assert_eq!(
                verdict_args(
                    &program,
                    arch,
                    libc::SYS_fcntl as u32,
                    [*fd as u64, libc::F_GETFD as u64, 0, 0, 0, 0]
                ),
                0x7fff0000
            );
            for command in [
                libc::F_SETFD as u64,
                libc::F_DUPFD_CLOEXEC as u64,
                (libc::F_GETFD as u64) | (1 << 32),
            ] {
                assert_ne!(
                    verdict_args(
                        &program,
                        arch,
                        libc::SYS_fcntl as u32,
                        [*fd as u64, command, 0, 0, 0, 0]
                    ),
                    0x7fff0000
                );
            }
        }
        for fd in [0, 1, 2, 3, 9, 138] {
            assert_ne!(
                verdict_args(
                    &program,
                    arch,
                    libc::SYS_pread64 as u32,
                    [fd, 0, 0, 0, 0, 0]
                ),
                0x7fff0000
            );
        }
        for nr in [
            libc::SYS_clone,
            libc::SYS_clone3,
            libc::SYS_execve,
            libc::SYS_execveat,
            libc::SYS_openat,
            libc::SYS_socket,
            libc::SYS_setns,
            libc::SYS_write,
        ] {
            assert_ne!(verdict_args(&program, arch, nr as u32, [0; 6]), 0x7fff0000);
        }
        #[cfg(target_arch = "x86_64")]
        for nr in [libc::SYS_fork, libc::SYS_vfork] {
            assert_ne!(verdict_args(&program, arch, nr as u32, [0; 6]), 0x7fff0000);
        }
    }
    fn verdict(arch: u32, nr: u32, arg: u64) -> u32 {
        verdict_program(&filter(), arch, nr, arg)
    }
    fn verdict_program(instructions: &[libc::sock_filter], arch: u32, nr: u32, arg: u64) -> u32 {
        verdict_args(instructions, arch, nr, [arg, 0, 0, 0, 0, 0])
    }
    fn verdict_args(instructions: &[libc::sock_filter], arch: u32, nr: u32, args: [u64; 6]) -> u32 {
        let mut pc = 0;
        let mut accumulator = 0;
        for _ in 0..2048 {
            let i = &instructions[pc];
            match i.code {
                0x20 => {
                    accumulator = match i.k {
                        0 => nr,
                        4 => arch,
                        offset if (16..64).contains(&offset) && offset % 4 == 0 => {
                            let value = args[((offset - 16) / 8) as usize];
                            if offset % 8 == 0 {
                                value as u32
                            } else {
                                (value >> 32) as u32
                            }
                        }
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
                0x45 => {
                    pc += 1 + if accumulator & i.k != 0 {
                        i.jt as usize
                    } else {
                        i.jf as usize
                    };
                }
                0x05 => pc += 1 + i.k as usize,
                0x06 => return i.k,
                _ => panic!("unexpected instruction"),
            }
        }
        panic!("unbounded filter")
    }
    #[test]
    fn fixed_actual_environments_have_no_inherited_resolver_home_or_program_overrides() {
        let values = |role| {
            actual_environment(role)
                .iter()
                .map(|value| value.to_bytes())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            values(ActualRole::Observer),
            [b"LANG=C".as_slice(), b"PATH=/bin"]
        );
        assert_eq!(
            values(ActualRole::Daemon),
            [
                b"LANG=C".as_slice(),
                b"PATH=/bin",
                b"TS_DEBUG_FIREWALL_MODE=nftables",
                b"TS_LOGS_DIR=/state"
            ]
        );
    }
    #[test]
    fn operational_monitor_has_only_unix_stream_and_ipv4_provider_tcp_dns_udp_sockets() {
        let arch = if cfg!(target_arch = "x86_64") {
            0xc000003e
        } else {
            0xc00000b7
        };
        let policy = runtime_filter(ActualRole::OperationalMonitor);
        assert_eq!(
            verdict_args(&policy, arch, libc::SYS_shutdown as u32, [0; 6]),
            0x7fff0000,
            "Tokio AsyncWrite shutdown requires shutdown"
        );
        assert_eq!(
            verdict_args(&policy, arch, libc::SYS_bind as u32, [0; 6]),
            0x7fff0000,
            "namespace-local DNS requires UDP bind"
        );
        for nr in [libc::SYS_ioctl, libc::SYS_listen, libc::SYS_accept4] {
            assert_ne!(verdict_args(&policy, arch, nr as u32, [0; 6]), 0x7fff0000);
        }

        for family in [
            libc::AF_UNIX,
            libc::AF_INET,
            libc::AF_INET6,
            libc::AF_NETLINK,
            libc::AF_PACKET,
        ] {
            for kind in [
                libc::SOCK_STREAM,
                libc::SOCK_DGRAM,
                libc::SOCK_RAW,
                libc::SOCK_SEQPACKET,
            ] {
                for protocol in [
                    0,
                    libc::IPPROTO_TCP,
                    libc::IPPROTO_UDP,
                    libc::NETLINK_GENERIC,
                ] {
                    for flags in [
                        0,
                        libc::SOCK_CLOEXEC,
                        libc::SOCK_NONBLOCK,
                        libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                    ] {
                        let expected =
                            family == libc::AF_UNIX && kind == libc::SOCK_STREAM && protocol == 0
                                || family == libc::AF_INET
                                    && ((kind == libc::SOCK_STREAM
                                        && matches!(protocol, 0 | libc::IPPROTO_TCP))
                                        || (kind == libc::SOCK_DGRAM
                                            && matches!(protocol, 0 | libc::IPPROTO_UDP)));
                        let args = [
                            family as u64,
                            (kind | flags) as u64,
                            protocol as u64,
                            0,
                            0,
                            0,
                        ];
                        assert_eq!(
                            verdict_args(&policy, arch, libc::SYS_socket as u32, args)
                                == 0x7fff0000,
                            expected,
                            "family={family} kind={kind} protocol={protocol}"
                        );
                        for arg in 0..3 {
                            let mut wide = args;
                            wide[arg] |= 1u64 << 32;
                            assert_ne!(
                                verdict_args(&policy, arch, libc::SYS_socket as u32, wide),
                                0x7fff0000
                            );
                        }
                    }
                }
            }
        }
    }
    #[test]
    fn actual_profiles_bind_exec_thread_memory_and_network_authority() {
        let arch = if cfg!(target_arch = "x86_64") {
            0xc000003e
        } else {
            0xc00000b7
        };
        for role in [
            ActualRole::Observer,
            ActualRole::Monitor,
            ActualRole::Daemon,
        ] {
            let policy = runtime_filter(role);
            for flags in [
                0,
                libc::O_CLOEXEC as u64,
                (libc::O_CLOEXEC | libc::O_NONBLOCK) as u64,
                (libc::O_CLOEXEC | libc::O_DIRECT) as u64,
                (1u64 << 32) | libc::O_CLOEXEC as u64,
            ] {
                assert_eq!(
                    verdict_args(
                        &policy,
                        arch,
                        libc::SYS_pipe2 as u32,
                        [0, flags, 0, 0, 0, 0]
                    ) == 0x7fff0000,
                    role == ActualRole::Daemon && flags == libc::O_CLOEXEC as u64
                );
            }
            assert_eq!(
                verdict_args(&policy, arch, libc::SYS_clone3 as u32, [0; 6]),
                0x00050026
            );
            assert_eq!(
                verdict_args(&policy, arch ^ 1, libc::SYS_read as u32, [0; 6]),
                0x80000000
            );
            for nr in [
                libc::SYS_setns,
                libc::SYS_unshare,
                libc::SYS_mount,
                libc::SYS_capset,
                libc::SYS_ptrace,
                libc::SYS_bpf,
                libc::SYS_execve,
                libc::SYS_memfd_create,
                libc::SYS_open_by_handle_at,
            ] {
                assert_eq!(verdict_args(&policy, arch, nr as u32, [0; 6]), 0x00050001);
            }
            for (fd, flags, allowed) in [
                (4, libc::AT_EMPTY_PATH as u64, true),
                (3, libc::AT_EMPTY_PATH as u64, false),
                (4, 0, false),
                (4, (1u64 << 32) | libc::AT_EMPTY_PATH as u64, false),
            ] {
                assert_eq!(
                    verdict_args(
                        &policy,
                        arch,
                        libc::SYS_execveat as u32,
                        [fd, 0, 0, 0, flags, 0]
                    ) == 0x7fff0000,
                    allowed
                );
            }
            for nr in [libc::SYS_mmap, libc::SYS_mprotect] {
                assert_eq!(
                    verdict_args(
                        &policy,
                        arch,
                        nr as u32,
                        [0, 4096, libc::PROT_READ as u64, 0, 0, 0]
                    ),
                    0x7fff0000
                );
                assert_eq!(
                    verdict_args(
                        &policy,
                        arch,
                        nr as u32,
                        [0, 4096, (libc::PROT_READ | libc::PROT_EXEC) as u64, 0, 0, 0]
                    ),
                    0x00050001
                );
            }
            for family in [libc::AF_INET6, libc::AF_PACKET] {
                assert_ne!(
                    verdict_args(
                        &policy,
                        arch,
                        libc::SYS_socket as u32,
                        [family as u64, 0, 0, 0, 0, 0]
                    ),
                    0x7fff0000
                );
            }
            for flags in [
                libc::SIGCHLD,
                libc::CLONE_NEWNET | libc::SIGCHLD,
                libc::CLONE_NEWUSER | libc::SIGCHLD,
            ] {
                assert_eq!(
                    verdict_args(
                        &policy,
                        arch,
                        libc::SYS_clone as u32,
                        [flags as u64, 0, 0, 0, 0, 0]
                    ),
                    0x00050001
                );
            }
            for flags in [0x50f00, 0x3d0f00, 0xd0f00] {
                assert_eq!(
                    verdict_args(
                        &policy,
                        arch,
                        libc::SYS_clone as u32,
                        [flags, 0, 0, 0, 0, 0]
                    ),
                    0x7fff0000
                );
                for extra in [
                    1u64 << 32,
                    libc::CLONE_NEWNET as u64,
                    libc::CLONE_NEWUSER as u64,
                    libc::SIGCHLD as u64,
                ] {
                    assert_eq!(
                        verdict_args(
                            &policy,
                            arch,
                            libc::SYS_clone as u32,
                            [flags | extra, 0, 0, 0, 0, 0]
                        ),
                        0x00050001
                    );
                }
            }
            assert_eq!(
                verdict_args(
                    &policy,
                    arch,
                    libc::SYS_socket as u32,
                    [libc::AF_INET as u64, 0, 0, 0, 0, 0]
                ) == 0x7fff0000,
                role == ActualRole::Daemon
            );
        }
        for nr in [
            libc::SYS_socket,
            libc::SYS_execveat,
            libc::SYS_clone,
            libc::SYS_openat,
            libc::SYS_setns,
        ] {
            assert_eq!(
                verdict_args(&init_filter(), arch, nr as u32, [0; 6]),
                0x00050001
            );
        }
        assert_eq!(
            verdict_args(
                &init_filter(),
                arch,
                libc::SYS_kill as u32,
                [u32::MAX as u64, libc::SIGTERM as u64, 0, 0, 0, 0]
            ),
            0x7fff0000
        );
        assert_eq!(
            verdict_args(
                &init_filter(),
                arch,
                libc::SYS_kill as u32,
                [1, libc::SIGTERM as u64, 0, 0, 0, 0]
            ),
            0x00050001
        );
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

#[cfg(test)]
mod assembly_capacity_tests {
    use super::*;

    #[test]
    fn original_charge_survives_proxy_drop_and_retires_exactly_once() {
        let before = live_child_count();
        let original = ChildCapacity::created();
        let retained = original.charge.clone();
        assert_eq!(live_child_count(), before + 1);
        drop(original);
        assert_eq!(live_child_count(), before + 1);
        retained.retire().unwrap();
        assert_eq!(live_child_count(), before);
        assert!(matches!(retained.retire(), Err(Error::OwnershipMismatch)));
        drop(retained);
        assert_eq!(live_child_count(), before);
        let ordinary = ChildCapacity::created();
        assert_eq!(live_child_count(), before + 1);
        drop(ordinary);
        assert_eq!(live_child_count(), before);
    }

    #[test]
    fn foreign_charge_cannot_retire_or_decrement_current_creator() {
        let before = live_child_count();
        let foreign = ChildCharge {
            creator: std::process::id().wrapping_add(1),
            retired: std::cell::Cell::new(false),
        };
        assert!(matches!(foreign.retire(), Err(Error::OwnershipMismatch)));
        assert!(!foreign.retired.get());
        drop(foreign);
        assert_eq!(live_child_count(), before);
    }

    #[test]
    fn no_birth_ticket_cannot_transfer_and_transferred_resources_stay_nonquiet() {
        let before = live_child_count();
        let charge = ChildCapacity::created();
        let (ticket, drain) = NativeJobTicket::prepare(NativeJobKind::FreshTransport);
        assert!(matches!(
            ResourceTransfer::new(&ticket, &charge, None),
            Err(Error::OwnershipMismatch)
        ));
        assert_eq!(live_child_count(), before + 1);
        // This tests state/drain semantics only; it mints no native receipt,
        // Completed, resource owner or successful ResourceTransfer.
        ticket.state.set(NativeJobState::TransferredResources);
        assert!(!drain.complete().unwrap());
        drop(ticket);
        assert!(!drain.complete().unwrap());
        assert!(drain.resources_transferred().unwrap());
        drop(charge);
        assert_eq!(live_child_count(), before);
    }
}
