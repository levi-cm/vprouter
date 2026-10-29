//! All raw operations in this crate are confined to this reviewed boundary.
use crate::{Error, Result};
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
thread_local! { static BIRTHS: std::cell::Cell<(u32,u64)> = const { std::cell::Cell::new((0,0)) }; }
pub(crate) fn native_birth_count() -> u64 {
    BIRTHS.with(|births| {
        let (creator, count) = births.get();
        if creator == std::process::id() {
            count
        } else {
            0
        }
    })
}

pub(crate) fn deadline(end: f64) -> Result<()> {
    let now = vprouter_core::health::boot_seconds();
    if !end.is_finite() || !now.is_finite() || now >= end || end - now > 2. {
        return Err(Error::Deadline);
    }
    Ok(())
}
fn cv(value: i32) -> Result<()> {
    if value < 0 {
        Err(Error::Native)
    } else {
        Ok(())
    }
}
pub(crate) fn non_dumpable() -> Result<()> {
    // SAFETY: scalar prctl operations, no pointer argument.
    cv(unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) })?;
    if unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        return Err(Error::Confinement);
    }
    Ok(())
}
pub(crate) fn preflight() -> Result<()> {
    if !vprouter_core::secret_boundary::pristine() {
        return Err(Error::Confinement);
    }
    // Fixed child stdio replacement must never overwrite a selected endpoint
    // allocated into a previously vacant standard descriptor slot.
    for descriptor in 0..3 {
        if unsafe { libc::fcntl(descriptor, libc::F_GETFD) } < 0 {
            return Err(Error::Descriptor);
        }
    }
    let proc = rustix::fs::open(
        "/proc",
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )
    .map_err(|_| Error::Confinement)?;
    if rustix::fs::fstatfs(&proc)
        .map_err(|_| Error::Confinement)?
        .f_type as u64
        != 0x9fa0
    {
        return Err(Error::Confinement);
    }
    let task = rustix::fs::openat(
        &proc,
        "self/task",
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|_| Error::Confinement)?;
    let mut count = 0;
    for entry in rustix::fs::Dir::read_from(&task).map_err(|_| Error::Confinement)? {
        let entry = entry.map_err(|_| Error::Confinement)?;
        let name = entry.file_name().to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        if !name.iter().all(u8::is_ascii_digit) {
            return Err(Error::Confinement);
        }
        count += 1;
        if count > 1 {
            return Err(Error::Confinement);
        }
    }
    if count != 1 {
        return Err(Error::Confinement);
    }
    non_dumpable()
}
pub(crate) fn duplicate(fd: BorrowedFd<'_>) -> Result<OwnedFd> {
    // SAFETY: fd is borrowed live; successful fcntl returns a new owned CLOEXEC fd.
    let raw = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 64) };
    if raw < 0 {
        return Err(Error::Descriptor);
    }
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}
pub(crate) fn atomic_fork() -> Result<(i32, Option<OwnedFd>)> {
    #[repr(C)]
    #[derive(Default)]
    struct Args {
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
    let args = Args {
        flags: libc::CLONE_PIDFD as u64,
        pidfd: (&mut descriptor as *mut i32) as u64,
        exit_signal: libc::SIGCHLD as u64,
        ..Args::default()
    };
    // SAFETY: preflight has established a pristine single-threaded parent.
    // No shared VM/stack; CLONE_PIDFD returns the exact original child's pin.
    let pid = unsafe { libc::syscall(libc::SYS_clone3, &args, std::mem::size_of::<Args>()) };
    if pid < 0 {
        return Err(Error::Native);
    }
    if pid > 0 {
        BIRTHS.with(|births| {
            births.set((std::process::id(), native_birth_count().saturating_add(1)))
        });
    }
    Ok((
        pid as i32,
        if pid > 0 {
            Some(unsafe { OwnedFd::from_raw_fd(descriptor) })
        } else {
            None
        },
    ))
}
pub(crate) fn reap(pid: u32) -> Result<Option<i32>> {
    let mut status = 0;
    // SAFETY: only the creator-bound constructor receipt invokes this with its
    // exact original PID. ECHILD is an error, never successful collection.
    let result = unsafe { libc::waitpid(pid as i32, &mut status, libc::WNOHANG) };
    if result == 0 {
        return Ok(None);
    }
    if result != pid as i32 || !(libc::WIFEXITED(status) || libc::WIFSIGNALED(status)) {
        return Err(Error::Native);
    }
    Ok(Some(status))
}
pub(crate) fn ready(fd: BorrowedFd<'_>) -> Result<bool> {
    let mut fds = [rustix::event::PollFd::new(
        &fd,
        rustix::event::PollFlags::IN,
    )];
    rustix::event::poll(
        &mut fds,
        Some(&rustix::event::Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        }),
    )
    .map_err(|_| Error::Native)?;
    if fds[0].revents().intersects(rustix::event::PollFlags::NVAL) {
        return Err(Error::Descriptor);
    }
    Ok(!fds[0].revents().is_empty())
}
pub(crate) fn kill(fd: BorrowedFd<'_>) -> Result<()> {
    // SAFETY: original atomic pidfd, exact fixed signal, no numeric fallback.
    let result = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            fd.as_raw_fd(),
            libc::SIGKILL,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    if result == 0 {
        return Ok(());
    }
    if std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) && ready(fd)? {
        return Ok(());
    }
    Err(Error::Native)
}
pub(crate) fn start(pid: u32, pin: BorrowedFd<'_>) -> Result<u64> {
    if ready(pin)? {
        return Err(Error::Native);
    }
    let text = std::fs::read_to_string(format!("/proc/{pid}/stat")).map_err(|_| Error::Native)?;
    let (head, tail) = text.rsplit_once(") ").ok_or(Error::Native)?;
    let fields: Vec<_> = tail.split_whitespace().collect();
    if !head.starts_with(&format!("{pid} ("))
        || fields.len() < 20
        || fields[0].len() != 1
        || matches!(fields[0], "Z" | "X" | "x")
    {
        return Err(Error::Native);
    }
    let start = fields[19].parse::<u64>().map_err(|_| Error::Native)?;
    if start == 0 || ready(pin)? {
        return Err(Error::Native);
    }
    Ok(start)
}
fn parent_death(parent: u32) -> Result<()> {
    cv(unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) })?;
    if unsafe { libc::getppid() } != parent as i32 {
        return Err(Error::Creator);
    }
    Ok(())
}
pub(crate) fn child_setup(keep: &[i32], namespace: BorrowedFd<'_>, parent: u32) -> Result<()> {
    // Namespace entry occurs before the filter and before ANY sensitive read.
    if !vprouter_core::secret_boundary::pristine() {
        return Err(Error::Confinement);
    }
    parent_death(parent)?;
    cv(unsafe { libc::clearenv() })?;
    cv(unsafe { libc::setns(namespace.as_raw_fd(), libc::CLONE_NEWNET) })?;
    let expected = rustix::fs::fstat(namespace).map_err(|_| Error::Descriptor)?;
    let current = rustix::fs::stat("/proc/thread-self/ns/net").map_err(|_| Error::Descriptor)?;
    if (expected.st_dev, expected.st_ino) != (current.st_dev, current.st_ino)
        || rustix::fs::fstatfs(namespace)
            .map_err(|_| Error::Descriptor)?
            .f_type as u64
            != 0x6e736673
    {
        return Err(Error::Confinement);
    }
    let original_null = rustix::fs::open(
        "/dev/null",
        rustix::fs::OFlags::RDWR | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|_| Error::Descriptor)?;
    let null_stat = rustix::fs::fstat(&original_null).map_err(|_| Error::Descriptor)?;
    if rustix::fs::FileType::from_raw_mode(null_stat.st_mode)
        != rustix::fs::FileType::CharacterDevice
        || rustix::fs::major(null_stat.st_rdev) != 1
        || rustix::fs::minor(null_stat.st_rdev) != 3
    {
        return Err(Error::Descriptor);
    }
    use std::os::fd::AsFd;
    let null = duplicate(original_null.as_fd())?;
    drop(original_null);
    for fd in 0..3 {
        cv(unsafe { libc::dup2(null.as_raw_fd(), fd) })?;
    }
    drop(null);
    // Keep the exact enumeration descriptor live until all OTHER closes finish.
    let mut descriptors = Vec::new();
    let directory = rustix::fs::open(
        "/proc/self/fd",
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|_| Error::Descriptor)?;
    let mut entries = rustix::fs::Dir::new(directory).map_err(|_| Error::Descriptor)?;
    let enumerator = entries.fd().map_err(|_| Error::Descriptor)?.as_raw_fd();
    for entry in &mut entries {
        let entry = entry.map_err(|_| Error::Descriptor)?;
        let name = entry.file_name().to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        let raw = std::str::from_utf8(name)
            .map_err(|_| Error::Descriptor)?
            .parse::<i32>()
            .map_err(|_| Error::Descriptor)?;
        if raw > 2 && raw != enumerator && !keep.contains(&raw) {
            descriptors.push(raw);
        }
    }
    for fd in descriptors {
        if unsafe { libc::close(fd) } < 0 {
            return Err(Error::Descriptor);
        }
    }
    drop(entries);
    capabilities()?;
    parent_death(parent)?;
    non_dumpable()?;
    cv(unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) })
}
fn capabilities() -> Result<()> {
    cv(unsafe { libc::prctl(libc::PR_SET_SECUREBITS, 0xef, 0, 0, 0) })?;
    for cap in 0..64 {
        if unsafe { libc::prctl(libc::PR_CAPBSET_READ, cap, 0, 0, 0) } < 0 {
            break;
        }
        if cap != 12 {
            cv(unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0) })?;
        }
    }
    cv(unsafe {
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL,
            0,
            0,
            0,
        )
    })?;
    cv(unsafe { libc::setgroups(0, std::ptr::null()) })?;
    cv(unsafe { libc::setresgid(0, 0, 0) })?;
    cv(unsafe { libc::setresuid(0, 0, 0) })?;
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
    cv(unsafe { libc::syscall(libc::SYS_capset, &header, caps.as_ptr()) as i32 })
}
pub(crate) fn install(program: &[libc::sock_filter]) -> Result<()> {
    let program = libc::sock_fprog {
        len: program.len().try_into().map_err(|_| Error::Confinement)?,
        filter: program.as_ptr().cast_mut(),
    };
    cv(unsafe { libc::prctl(libc::PR_SET_SECCOMP, 2, &program, 0, 0) })?;
    if unsafe { libc::prctl(libc::PR_GET_SECCOMP, 0, 0, 0, 0) } != 2 {
        return Err(Error::Confinement);
    }
    Ok(())
}
pub(crate) fn die(code: i32) -> ! {
    // No unwinding or inherited parent-owner destructors after descriptor closure.
    unsafe { libc::_exit(code) }
}
