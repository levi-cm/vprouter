#![forbid(unsafe_code)]
//! Private one-thread RAII inventory of exact owned host descriptors. No caller
//! allowlist or assertion constructor. Fork children never unwind these owners.
use super::{Error, Result};
use rustix::fs;
use std::{
    cell::RefCell,
    collections::BTreeMap,
    os::fd::{AsRawFd, BorrowedFd, OwnedFd},
};
#[derive(Clone, Copy, PartialEq, Eq)]
struct Identity {
    dev: u64,
    ino: u64,
    mode: u32,
    cloexec: bool,
}
thread_local! {static OWNED:RefCell<BTreeMap<i32,Identity>>=const{RefCell::new(BTreeMap::new())};}
fn observed(fd: i32) -> Result<Identity> {
    use std::os::unix::fs::MetadataExt;
    let m =
        std::fs::metadata(format!("/proc/self/fd/{fd}")).map_err(|_| Error::DescriptorPolicy)?;
    let info = std::fs::read_to_string(format!("/proc/self/fdinfo/{fd}"))
        .map_err(|_| Error::DescriptorPolicy)?;
    let flags = info
        .lines()
        .find_map(|l| l.strip_prefix("flags:\t"))
        .and_then(|s| u32::from_str_radix(s.trim(), 8).ok())
        .ok_or(Error::DescriptorPolicy)?;
    Ok(Identity {
        dev: m.dev(),
        ino: m.ino(),
        mode: m.mode() & libc::S_IFMT,
        cloexec: flags & libc::O_CLOEXEC as u32 != 0,
    })
}
pub(super) struct Registration {
    fds: Vec<i32>,
}
impl Registration {
    pub fn owned(fds: &[BorrowedFd<'_>]) -> Result<Self> {
        Self::numbers(fds.iter().map(AsRawFd::as_raw_fd).collect())
    }
    fn numbers(fds: Vec<i32>) -> Result<Self> {
        let mut identities = Vec::new();
        for fd in &fds {
            let id = observed(*fd)?;
            if *fd < 3 || !id.cloexec {
                return Err(Error::DescriptorPolicy);
            }
            identities.push((*fd, id));
        }
        OWNED.with(|owned| {
            let mut owned = owned.borrow_mut();
            if identities.iter().any(|(fd, _)| owned.contains_key(fd)) {
                return Err(Error::DescriptorPolicy);
            }
            for (fd, id) in identities {
                owned.insert(fd, id);
            }
            Ok(Self { fds })
        })
    }
    /// Producer owns one extra parent FD and exactly two matching subgroup FDs
    /// (local + private netfilter authority). Existing admitted descriptors are
    /// already registered. No raw authority FD getter or caller numeric list.
    pub fn producer(parent: BorrowedFd<'_>, group: BorrowedFd<'_>) -> Result<Self> {
        let parent = fs::fstat(parent).map_err(|_| Error::DescriptorPolicy)?;
        let group = fs::fstat(group).map_err(|_| Error::DescriptorPolicy)?;
        let registered = OWNED.with(|o| o.borrow().clone());
        let mut parents = Vec::new();
        let mut groups = Vec::new();
        for fd in numbers()? {
            if fd <= 2 || registered.contains_key(&fd) {
                continue;
            }
            let id = observed(fd)?;
            if (id.dev, id.ino) == (parent.st_dev, parent.st_ino) {
                parents.push(fd);
            }
            if (id.dev, id.ino) == (group.st_dev, group.st_ino) {
                groups.push(fd);
            }
        }
        if parents.len() != 1 || groups.len() != 2 {
            return Err(Error::DescriptorPolicy);
        }
        parents.extend(groups);
        Self::numbers(parents)
    }
    /// AllocationStore deliberately exposes no FD. After verify_directory, two
    /// exact directory handles (store + transaction) and one lock handle must
    /// exist. This observation is one-task bounded and checked by count/identity;
    /// extra duplicates are ambiguous and refused rather than adopted.
    pub fn allocation(dir: BorrowedFd<'_>) -> Result<Self> {
        let d = fs::fstat(dir).map_err(|_| Error::DescriptorPolicy)?;
        let lock = fs::openat(
            dir,
            ".allocations.lock",
            fs::OFlags::RDONLY | fs::OFlags::NOFOLLOW | fs::OFlags::CLOEXEC,
            fs::Mode::empty(),
        )
        .map_err(|_| Error::DescriptorPolicy)?;
        let l = fs::fstat(&lock).map_err(|_| Error::DescriptorPolicy)?;
        let mut dirs = Vec::new();
        let mut locks = Vec::new();
        let numbers = numbers()?;
        for fd in numbers {
            if fd == lock.as_raw_fd() {
                continue;
            }
            if let Ok(id) = observed(fd) {
                if (id.dev, id.ino) == (d.st_dev, d.st_ino) {
                    dirs.push(fd);
                }
                if (id.dev, id.ino) == (l.st_dev, l.st_ino) {
                    locks.push(fd);
                }
            }
        }
        if dirs.len() != 2 || locks.len() != 1 {
            return Err(Error::DescriptorPolicy);
        }
        dirs.extend(locks);
        Self::numbers(dirs)
    }
}
impl Drop for Registration {
    fn drop(&mut self) {
        OWNED.with(|o| {
            let mut o = o.borrow_mut();
            for fd in &self.fds {
                o.remove(fd);
            }
        });
    }
}
fn numbers() -> Result<Vec<i32>> {
    let fd = fs::openat(
        fs::CWD,
        "/proc/self/fd",
        fs::OFlags::RDONLY | fs::OFlags::DIRECTORY | fs::OFlags::CLOEXEC,
        fs::Mode::empty(),
    )
    .map_err(|_| Error::DescriptorPolicy)?;
    scan_numbers(fd)
}
fn scan_numbers(fd: OwnedFd) -> Result<Vec<i32>> {
    let scan_fd = fd.as_raw_fd();
    let mut numbers = Vec::new();
    for entry in fs::Dir::new(fd).map_err(|_| Error::DescriptorPolicy)? {
        let entry = entry.map_err(|_| Error::DescriptorPolicy)?;
        let name = entry.file_name().to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        let number = std::str::from_utf8(name)
            .ok()
            .and_then(|s| s.parse().ok())
            .ok_or(Error::DescriptorPolicy)?;
        // Exclude only our exact owned scan descriptor, never a failed lookup.
        if number != scan_fd {
            numbers.push(number);
        }
    }
    Ok(numbers)
}
pub(super) fn verify() -> Result<()> {
    let expected = OWNED.with(|o| o.borrow().clone());
    let mut seen = std::collections::BTreeSet::new();
    for fd in numbers()? {
        let id = observed(fd)?;
        if fd <= 2 {
            if id.mode == libc::S_IFSOCK {
                return Err(Error::DescriptorPolicy);
            }
            continue;
        }
        if expected.get(&fd) != Some(&id) {
            return Err(Error::DescriptorPolicy);
        }
        seen.insert(fd);
    }
    if expected
        .keys()
        .copied()
        .collect::<std::collections::BTreeSet<_>>()
        != seen
    {
        return Err(Error::DescriptorPolicy);
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;
    #[test]
    fn exact_scan_fd_is_excluded_but_disappeared_real_fd_is_an_error() {
        let real = fs::openat(
            fs::CWD,
            "/",
            fs::OFlags::RDONLY | fs::OFlags::DIRECTORY | fs::OFlags::CLOEXEC,
            fs::Mode::empty(),
        )
        .unwrap();
        // A deliberately high FD avoids reuse by other ordinary libtest tasks.
        let real = rustix::io::fcntl_dupfd_cloexec(real, 10000).unwrap();
        let real_number = real.as_raw_fd();
        let scan = fs::openat(
            fs::CWD,
            "/proc/self/fd",
            fs::OFlags::RDONLY | fs::OFlags::DIRECTORY | fs::OFlags::CLOEXEC,
            fs::Mode::empty(),
        )
        .unwrap();
        let scan_number = scan.as_raw_fd();
        let numbers = scan_numbers(scan).unwrap();
        assert!(numbers.contains(&real_number));
        assert!(!numbers.contains(&scan_number));
        drop(real);
        assert_eq!(observed(real_number).err(), Some(Error::DescriptorPolicy));
    }
    #[test]
    fn unregistered_directory_and_namespace_are_not_owned() {
        let directory = fs::open(
            "/",
            fs::OFlags::RDONLY | fs::OFlags::DIRECTORY | fs::OFlags::CLOEXEC,
            fs::Mode::empty(),
        )
        .unwrap();
        assert!(OWNED.with(|o| !o.borrow().contains_key(&directory.as_raw_fd())));
        let registration = Registration::owned(&[directory.as_fd()]).unwrap();
        assert!(OWNED.with(|o| o.borrow().contains_key(&directory.as_raw_fd())));
        drop(registration);
        assert!(OWNED.with(|o| !o.borrow().contains_key(&directory.as_raw_fd())));
    }
}
