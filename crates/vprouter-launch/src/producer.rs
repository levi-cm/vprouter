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
        let result = Self {
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
