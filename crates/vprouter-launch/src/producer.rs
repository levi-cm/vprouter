#![forbid(unsafe_code)]
//! One owned health/control subgroup. No controller/limit/parent mutation.
use super::{
    Admission, Error, Result,
    owned::{Identity, OwnedNamespaces, Transaction},
    spec::LaunchSpec,
};
use rustix::fs::{self, Mode, OFlags, ResolveFlags};
use std::{
    fs::File,
    io::Read,
    os::fd::{AsFd, OwnedFd},
    sync::Arc,
};
use vprouter_netfilter::SocketProducer;
pub(super) struct ProducerGroup {
    _inventory: super::inventory::Registration,
    parent: OwnedFd,
    group: OwnedFd,
    parent_id: Identity,
    group_id: Identity,
    name: String,
    authority: Arc<SocketProducer>,
}
impl ProducerGroup {
    pub fn create(a: &Admission, ns: &OwnedNamespaces, tx: &mut Transaction<'_>) -> Result<Self> {
        a.process.revalidate(&a.spec, &a.staging)?;
        ns.bind(&a.spec)?;
        let parent = a
            .process
            .cgroup_parent()
            .try_clone_to_owned()
            .map_err(|_| Error::CgroupMismatch)?;
        let parent_id = Identity::of(&parent)?;
        let name = SocketProducer::group_name(&a.spec.allocation, &a.spec.exit);
        // Exclusive mkdir; never adopt/reconcile a pre-existing same-name group.
        fs::mkdirat(&parent, name.as_str(), Mode::RUSR | Mode::WUSR | Mode::XUSR)
            .map_err(|_| Error::OwnershipMismatch)?;
        let group = fs::openat2(
            &parent,
            name.as_str(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
        )
        .map_err(|_| Error::CgroupMismatch)?;
        let group_id = Identity::of(&group)?;
        tx.bind_producer(&a.spec, parent_id, group_id)?;
        let authority = SocketProducer::from_owned_group(
            &a.spec.allocation,
            &a.spec.exit,
            &a.spec.container_id,
            group.as_fd(),
            ns.data.as_fd(),
        )
        .map_err(|_| Error::CgroupMismatch)?;
        let inventory = super::inventory::Registration::producer(parent.as_fd(), group.as_fd())?;
        let result = Self {
            _inventory: inventory,
            parent,
            group,
            parent_id,
            group_id,
            name,
            authority,
        };
        result.verify(tx, &a.spec)?;
        Ok(result)
    }
    pub fn authority(&self) -> Arc<SocketProducer> {
        self.authority.clone()
    }
    pub fn verify(&self, tx: &Transaction<'_>, s: &LaunchSpec) -> Result<()> {
        tx.verify_producer(s, self.parent_id, self.group_id)?;
        if Identity::of(&self.parent)? != self.parent_id
            || Identity::of(&self.group)? != self.group_id
        {
            return Err(Error::CgroupMismatch);
        }
        let current = fs::openat2(
            &self.parent,
            self.name.as_str(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
        )
        .map_err(|_| Error::CgroupMismatch)?;
        if Identity::of(current)? != self.group_id {
            return Err(Error::CgroupMismatch);
        }
        Ok(())
    }
    pub fn cleanup(self, tx: &Transaction<'_>, s: &LaunchSpec) -> Result<()> {
        self.verify(tx, s)?;
        let fd = fs::openat(
            &self.group,
            "cgroup.procs",
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| Error::CgroupMismatch)?;
        let mut b = String::new();
        File::from(fd)
            .take(65537)
            .read_to_string(&mut b)
            .map_err(|_| Error::CgroupMismatch)?;
        if !b.trim().is_empty() {
            return Err(Error::CgroupMismatch);
        }
        // rmdir is atomic and fails if populated or children have appeared.
        fs::unlinkat(&self.parent, self.name.as_str(), fs::AtFlags::REMOVEDIR)
            .map_err(|_| Error::CgroupMismatch)
    }
    #[cfg(test)]
    pub fn socket_scope<T>(&self, f: impl FnOnce() -> Result<T>) -> Result<T> {
        super::kernel::producer_socket_scope(&self.group, f)
    }
}

/// Retained host process identity for a single accepted observation peer. Not a
/// readiness/producer constructor and never exposed outside the launch crate.
pub(super) struct Sender {
    proc: OwnedFd,
    pidfd: OwnedFd,
    pid: u32,
    start: u64,
}
fn read(fd: impl AsFd, name: &str, limit: u64) -> Result<String> {
    let f = fs::openat(
        fd,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| Error::PlacementFailed)?;
    let mut s = String::new();
    File::from(f)
        .take(limit + 1)
        .read_to_string(&mut s)
        .map_err(|_| Error::PlacementFailed)?;
    if s.len() as u64 > limit {
        return Err(Error::PlacementFailed);
    }
    Ok(s)
}
fn alive(fd: impl AsFd) -> Result<()> {
    let mut p = [rustix::event::PollFd::new(
        &fd,
        rustix::event::PollFlags::IN,
    )];
    if rustix::event::poll(
        &mut p,
        Some(&rustix::event::Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        }),
    )
    .map_err(|_| Error::PlacementFailed)?
        != 0
    {
        return Err(Error::PlacementFailed);
    }
    Ok(())
}
impl ProducerGroup {
    fn path(&self, spec: &LaunchSpec) -> String {
        format!(
            "0::/system.slice/docker-{}.scope/{}\n",
            spec.container_id, self.name
        )
    }
    pub(super) fn membership(&self, pid: u32, proc: impl AsFd, spec: &LaunchSpec) -> Result<()> {
        if read(proc, "cgroup", 4096)? != self.path(spec)
            || read(&self.group, "cgroup.procs", 65536)?
                .lines()
                .filter(|line| line.parse::<u32>().ok() == Some(pid))
                .count()
                != 1
        {
            return Err(Error::PlacementFailed);
        }
        Ok(())
    }
    pub fn verify_child(&self, pid: u32, tx: &Transaction<'_>, spec: &LaunchSpec) -> Result<()> {
        self.verify(tx, spec)?;
        let proc = fs::open(
            format!("/proc/{pid}"),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| Error::PlacementFailed)?;
        self.membership(pid, proc, spec)
    }
    /// Host-side placement gate: child stays blocked at its inherited release
    /// pipe until all cgroup/parent/allocation/namespace checks have succeeded.
    /// No PID-number-only release API and no caller-supplied proof boolean.
    pub fn release_child(
        &self,
        child: &mut super::kernel::Child,
        admission: &Admission,
        tx: &Transaction<'_>,
        ns: &OwnedNamespaces,
    ) -> Result<()> {
        child.require_placement_gate()?;
        super::process::single_threaded()?;
        self.verify(tx, &admission.spec)?;
        ns.bind(&admission.spec)?;
        admission
            .process
            .revalidate(&admission.spec, &admission.staging)?;
        let pid = child.pid();
        let dir = fs::open(
            format!("/proc/{pid}"),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| Error::PlacementFailed)?;
        if fs::fstatfs(&dir)
            .map_err(|_| Error::PlacementFailed)?
            .f_type as u64
            != 0x9fa0
        {
            return Err(Error::PlacementFailed);
        }
        let start = super::process::stat_start(&read(&dir, "stat", 65536)?, pid)?;
        let f = fs::openat(
            &self.group,
            "cgroup.procs",
            OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| Error::PlacementFailed)?;
        use std::io::Write;
        File::from(f)
            .write_all(pid.to_string().as_bytes())
            .map_err(|_| Error::PlacementFailed)?;
        self.verify(tx, &admission.spec)?;
        self.membership(pid, &dir, &admission.spec)?;
        admission
            .process
            .revalidate(&admission.spec, &admission.staging)?;
        if start != super::process::stat_start(&read(&dir, "stat", 65536)?, pid)? {
            return Err(Error::PlacementFailed);
        }
        // Child owns a retained pidfd and has not been reaped, preventing PID
        // reuse between this verification and release. Errors do not release.
        child.release()
    }
    pub fn pin_sender(
        &self,
        pid: u32,
        tx: &Transaction<'_>,
        spec: &LaunchSpec,
        ns: &OwnedNamespaces,
        bundle: &super::programs::ReviewedBundle,
    ) -> Result<Sender> {
        self.verify(tx, spec)?;
        ns.bind(spec)?;
        let pidfd = rustix::process::pidfd_open(
            rustix::process::Pid::from_raw(pid as i32).ok_or(Error::PlacementFailed)?,
            rustix::process::PidfdFlags::NONBLOCK,
        )
        .map_err(|_| Error::PlacementFailed)?;
        alive(&pidfd)?;
        let proc = fs::open(
            format!("/proc/{pid}"),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|_| Error::PlacementFailed)?;
        if fs::fstatfs(&proc)
            .map_err(|_| Error::PlacementFailed)?
            .f_type as u64
            != 0x9fa0
        {
            return Err(Error::PlacementFailed);
        }
        let start = super::process::stat_start(&read(&proc, "stat", 65536)?, pid)?;
        let sender = Sender {
            proc,
            pidfd,
            pid,
            start,
        };
        sender.verify(self, tx, spec, ns, bundle)?;
        Ok(sender)
    }
}
impl Sender {
    pub fn verify(
        &self,
        group: &ProducerGroup,
        tx: &Transaction<'_>,
        spec: &LaunchSpec,
        ns: &OwnedNamespaces,
        bundle: &super::programs::ReviewedBundle,
    ) -> Result<()> {
        alive(&self.pidfd)?;
        group.verify(tx, spec)?;
        ns.bind(spec)?;
        if self.start != super::process::stat_start(&read(&self.proc, "stat", 65536)?, self.pid)?
            || !super::process::initial_map(&read(&self.proc, "uid_map", 4096)?)
            || !super::process::initial_map(&read(&self.proc, "gid_map", 4096)?)
        {
            return Err(Error::PlacementFailed);
        }
        group.membership(self.pid, &self.proc, spec)?;
        let net = fs::openat(
            &self.proc,
            "ns/net",
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| Error::NamespaceMismatch)?;
        if Identity::network(net)? != Identity::network(&ns.data)? {
            return Err(Error::NamespaceMismatch);
        }
        let exe = fs::openat(
            &self.proc,
            "exe",
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| Error::ExecutableMismatch)?;
        bundle.verify(exe, super::programs::Role::WorkerObserver)?;
        group.membership(self.pid, &self.proc, spec)?;
        if self.start != super::process::stat_start(&read(&self.proc, "stat", 65536)?, self.pid)? {
            return Err(Error::PlacementFailed);
        }
        alive(&self.pidfd)
    }
}
#[cfg(test)]
mod placement_tests {
    #[test]
    fn exact_host_producer_path_is_not_namespace_relative_membership() {
        let id = "a".repeat(64);
        let name = "vpr-test";
        let exact = format!("0::/system.slice/docker-{id}.scope/{name}\n");
        for other in [
            "0::/\n".to_string(),
            format!("0::/system.slice/docker-{id}.scope\n"),
            format!("0::/system.slice/docker-{id}.scope/{name}-foreign\n"),
        ] {
            assert_ne!(exact, other);
        }
    }
}
