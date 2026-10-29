//! Manifest-independent reviewed Linux boundary shared by inert image PID1 and
//! host launch. Keep all pointer/syscall safety contracts here; no host runtime,
//! reviewed program manifest, Docker, D-Bus, or credential input is linked by PID1.
use super::{Error, Result};
use rustix::fs::{self, Mode, OFlags, open, openat};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
const DIR: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::CLOEXEC)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::NONBLOCK);
pub(super) fn single_threaded() -> Result<()> {
    let proc = open("/proc", DIR, Mode::empty()).map_err(|_| Error::UnsupportedPlatform)?;
    if fs::fstatfs(&proc)
        .map_err(|_| Error::UnsupportedPlatform)?
        .f_type as i64
        != 0x9fa0
    {
        return Err(Error::UnsupportedPlatform);
    }
    // Deliberate kernel procfs self link remains valid across PID namespaces;
    // procfs was validated, and no caller path component is accepted.
    let own = openat(
        &proc,
        "self",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| Error::ProcessUnavailable)?;
    let task = openat(&own, "task", DIR, Mode::empty()).map_err(|_| Error::ProcessUnavailable)?;
    let mut entries = fs::Dir::read_from(&task).map_err(|_| Error::ProcessUnavailable)?;
    let mut count = 0;
    for entry in &mut entries {
        let entry = entry.map_err(|_| Error::ProcessUnavailable)?;
        let name = entry.file_name().to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        if !name.iter().all(u8::is_ascii_digit) {
            return Err(Error::ProcessChanged);
        }
        count += 1;
        if count > 1 {
            return Err(Error::NotSingleThreaded);
        }
    }
    if count != 1 {
        return Err(Error::NotSingleThreaded);
    }
    Ok(())
}

pub(super) fn cv(r: i32, e: Error) -> Result<()> {
    if r < 0 { Err(e) } else { Ok(()) }
}

pub(super) fn read_fixed(path: &str, limit: usize) -> std::io::Result<Vec<u8>> {
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

pub(super) fn lsm_current() -> Result<()> {
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

pub(super) fn blocked_signals() -> Result<libc::sigset_t> {
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

pub(super) fn pending(set: &libc::sigset_t) -> Result<Option<i32>> {
    pending_for(set, 50_000_000)
}
/// Consume only a signal already pending. Owner admission/service polls must not
/// spend 50ms waiting for a future signal before each otherwise-ready operation.
pub(super) fn pending_now(set: &libc::sigset_t) -> Result<Option<i32>> {
    pending_for(set, 0)
}
fn pending_for(set: &libc::sigset_t, nanoseconds: libc::c_long) -> Result<Option<i32>> {
    let t = libc::timespec {
        tv_sec: 0,
        tv_nsec: nanoseconds,
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

pub(super) fn dup_fixed(fd: impl AsFd, to: i32, cloexec: bool) -> Result<()> {
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

pub(super) fn close_except(keep: &[i32]) -> Result<()> {
    // CLOEXEC is not enough: remove host dirs, sockets, roots and namespace FDs
    // before untrusted code. Enumeration closes only numeric descriptors; owners
    // remain inert until this child execs/_exits, never Rust unwinding.
    close_numbers(descriptor_inventory()?, keep, checked_close)
}

pub(super) fn close_numbers(
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

pub(super) fn checked_close(fd: i32) -> Result<()> {
    // SAFETY: caller exclusively owns this child's descriptor table; inherited
    // Rust owners never run after closure. On Linux close consumes the FD even
    // on EINTR; report failure without a potentially dangerous retry.
    cv(unsafe { libc::close(fd) }, Error::DescriptorClose)
}

pub(super) fn descriptor_numbers(
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

pub(super) fn descriptor_inventory() -> Result<std::collections::BTreeSet<i32>> {
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

pub(super) fn filter() -> Vec<libc::sock_filter> {
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

pub(super) fn wait_filter() -> Vec<libc::sock_filter> {
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

pub(super) fn apply_filter(f: &[libc::sock_filter]) -> Result<()> {
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

pub(super) fn approved_null(fd: BorrowedFd<'_>) -> Result<StdioIdentity> {
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

/// Immutable image's inert base PID1. Docker supplies capdropALL and NNP; unlike
/// the host placement helper this role never needs namespace/cgroup authority.
pub(super) fn gateway_init() -> Result<()> {
    single_threaded()?;
    if std::process::id() != 1 {
        return Err(Error::ConfinementPolicy);
    }
    let status = read_fixed("/proc/self/status", 16384).map_err(|_| Error::CapabilityPolicy)?;
    let status = std::str::from_utf8(&status).map_err(|_| Error::CapabilityPolicy)?;
    for key in ["CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:"] {
        if status
            .lines()
            .find_map(|l| l.strip_prefix(key))
            .and_then(|s| u64::from_str_radix(s.trim(), 16).ok())
            != Some(0)
        {
            return Err(Error::CapabilityPolicy);
        }
    }
    if unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) } != 1 {
        return Err(Error::CapabilityPolicy);
    }
    lsm_current()?;
    let signals = blocked_signals()?;
    let null = fs::open("/dev/null", OFlags::RDWR | OFlags::CLOEXEC, Mode::empty())
        .map_err(|_| Error::DescriptorNull)?;
    approved_null(null.as_fd())?;
    for n in 0..3 {
        dup_fixed(&null, n, false)?;
    }
    close_except(&[])?;
    apply_filter(&wait_filter())?;
    loop {
        match pending(&signals)? {
            Some(libc::SIGTERM | libc::SIGINT | libc::SIGHUP) => return Ok(()),
            Some(libc::SIGCHLD) => {
                loop {
                    // SAFETY: PID1 reaps only its own adopted children, bounded nonblocking calls.
                    let p = unsafe { libc::waitpid(-1, std::ptr::null_mut(), libc::WNOHANG) };
                    if p <= 0 {
                        break;
                    }
                }
            }
            _ => (),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct StdioIdentity {
    dev: u64,
    ino: u64,
    rdev: u64,
}
