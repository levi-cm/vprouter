//! Fixed producer Bootstrap mechanics. No producer placement,
//! UP, READY, or original cgroup creation authority is returned.
use crate::wireguard::{
    Completed, ConfinedWireguard, ForkOutcome, PreparedWireguard, WireguardChild,
    WireguardDescriptors,
};
use crate::{Birth, Error, ReapWitness, Result, WireguardChildGate};
use std::{
    os::fd::{BorrowedFd, OwnedFd},
    sync::Arc,
};
pub struct ProducerBootstrapDescriptors<'a> {
    pub main: BorrowedFd<'a>,
    pub emergency: BorrowedFd<'a>,
    pub namespace: BorrowedFd<'a>,
    pub producer: crate::wireguard::ProducerDescriptors<'a>,
    pub ancestry: ProducerAncestryDescriptors<'a>,
}
pub struct PreparedProducerBootstrap {
    inner: PreparedWireguard,
}
pub enum ProducerBootstrapFork {
    Parent(ProducerBootstrapChild, ReapWitness),
    Child(ConfinedProducerBootstrap),
}
pub struct ConfinedProducerBootstrap {
    inner: ConfinedWireguard,
}
pub struct ProducerBootstrapChild {
    inner: WireguardChild,
}
pub struct ProducerBootstrapCompleted {
    inner: Completed,
}
impl PreparedProducerBootstrap {
    pub fn new(
        fds: ProducerBootstrapDescriptors<'_>,
        digest: [u8; 32],
        end: f64,
        gate: WireguardChildGate,
    ) -> Result<Self> {
        Ok(Self {
            inner: PreparedWireguard::for_producer_bootstrap(
                WireguardDescriptors {
                    profiles: &[],
                    route: fds.main,
                    generic: fds.emergency,
                    namespace: fds.namespace,
                },
                fds.producer,
                fds.ancestry,
                digest,
                end,
                gate,
            )?,
        })
    }
    pub fn descriptors(&self) -> Result<Vec<BorrowedFd<'_>>> {
        self.inner.descriptors()
    }
    pub fn child_endpoints(&self) -> Result<[BorrowedFd<'_>; 2]> {
        Ok([self.inner.child_channel()?, self.inner.child_gate()?])
    }
    pub fn timer_owner(&self) -> Result<Arc<OwnedFd>> {
        self.inner.timer_owner()
    }
    pub fn birth(self) -> Result<ProducerBootstrapFork> {
        Ok(match self.inner.birth()? {
            ForkOutcome::Parent(inner, original) => {
                ProducerBootstrapFork::Parent(ProducerBootstrapChild { inner }, original)
            }
            ForkOutcome::Child(inner) => {
                ProducerBootstrapFork::Child(ConfinedProducerBootstrap { inner })
            }
        })
    }
}
impl ConfinedProducerBootstrap {
    pub fn require(&self) -> Result<()> {
        if !self.inner.is_producer_bootstrap() {
            return Err(Error::Protocol);
        }
        self.inner.require()
    }
    pub fn namespace_identity(&self) -> Result<(u64, u64)> {
        self.require()?;
        self.inner.selected_namespace()
    }
    pub fn producer_owners(&self) -> Result<[Arc<OwnedFd>; 6]> {
        self.require()?;
        self.inner.producer_owners()
    }
    pub fn producer_group(&self) -> Result<ConfinedProducerGroup> {
        self.require()?;
        self.inner.bootstrap_group()
    }
    pub fn require_ancestry(&self) -> Result<()> {
        self.require()?;
        self.inner.require_producer_ancestry()
    }
    pub fn deadline(&self) -> f64 {
        self.inner.deadline()
    }
    pub fn socket_descriptors(&self) -> Result<[BorrowedFd<'_>; 2]> {
        self.require()?;
        self.inner.socket_descriptors()
    }
    pub fn socket_owners(&self) -> Result<[Arc<OwnedFd>; 2]> {
        self.require()?;
        self.inner.socket_owners()
    }
    pub fn timer_owner(&self) -> Result<Arc<OwnedFd>> {
        self.require()?;
        self.inner.timer_owner()
    }
    pub fn finish(self, bytes: &[u8]) -> ! {
        self.inner.finish(bytes)
    }
    pub fn fail(self) -> ! {
        self.inner.fail()
    }
}
impl ProducerBootstrapChild {
    pub fn descriptors(&self) -> Result<Vec<BorrowedFd<'_>>> {
        self.inner.descriptors()
    }
    pub fn pidfd(&self) -> Result<BorrowedFd<'_>> {
        self.inner.pidfd()
    }
    pub fn identify(&mut self) -> Result<Birth> {
        self.inner.identify()
    }
    pub fn original_child(&self) -> Result<ReapWitness> {
        self.inner.reap_witness()
    }
    pub fn collect(&mut self) -> Result<Option<i32>> {
        self.inner.collect()
    }
    pub fn cancel(&mut self, e: Error) {
        self.inner.cancel(e)
    }
    pub fn poll(&mut self) -> Result<Option<ProducerBootstrapCompleted>> {
        match self.inner.poll()? {
            None => Ok(None),
            Some(inner) => {
                if !inner.is_producer_bootstrap() {
                    return Err(Error::Protocol);
                }
                Ok(Some(ProducerBootstrapCompleted { inner }))
            }
        }
    }
}
impl ProducerBootstrapCompleted {
    pub fn descriptors(&self) -> Result<Vec<BorrowedFd<'_>>> {
        self.require_retained()?;
        self.inner.descriptors()
    }
    pub fn require_current(&self) -> Result<()> {
        if !self.inner.is_producer_bootstrap() {
            return Err(Error::Protocol);
        }
        self.inner.require_current()
    }
    pub fn public_report(&self) -> Result<&[u8]> {
        self.require_current()?;
        self.inner.public_report()
    }
    pub fn timer_owner(&self) -> Result<Arc<OwnedFd>> {
        self.require_current()?;
        self.inner.timer_owner()
    }
    pub fn original_child(&self) -> Result<ReapWitness> {
        self.inner.reap_witness()
    }
    pub fn accepted_at(&self) -> Result<f64> {
        self.inner.accepted_at()
    }
    pub fn child_reported_at(&self) -> Result<f64> {
        self.inner.child_reported_at()
    }
    pub fn birth(&self) -> Result<Birth> {
        self.inner.birth()
    }
    /// Historical original completion custody, not renewed table validity.
    pub fn require_retained(&self) -> Result<()> {
        if !self.inner.is_producer_bootstrap() {
            return Err(Error::Protocol);
        }
        self.inner.retained_timer_owner()?;
        Ok(())
    }
}

/// Explicit original cgroup hierarchy. Launch supplies these only from its
/// retained admitted process/root and original Source, never a public report.
pub struct ProducerAncestryDescriptors<'a> {
    pub root: BorrowedFd<'a>,
    pub system_slice: BorrowedFd<'a>,
    pub container_id: &'a str,
    pub group_name: &'a str,
}
static ROOT_PARENT: &std::ffi::CStr = c"..";
static SYSTEM_SLICE: &std::ffi::CStr = c"system.slice";
pub(crate) struct Ancestry {
    pub(crate) root: Arc<OwnedFd>,
    pub(crate) system_slice: Arc<OwnedFd>,
    container: std::ffi::CString,
    group: std::ffi::CString,
}
impl Ancestry {
    pub(crate) fn prepare(input: ProducerAncestryDescriptors<'_>) -> Result<Self> {
        if input.container_id.len() != 64
            || !input
                .container_id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || input.group_name.is_empty()
            || input.group_name.len() > 255
            || !input
                .group_name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
            || matches!(input.group_name, "." | "..")
        {
            return Err(Error::Protocol);
        }
        Ok(Self {
            root: Arc::new(crate::linux::duplicate(input.root)?),
            system_slice: Arc::new(crate::linux::duplicate(input.system_slice)?),
            container: std::ffi::CString::new(format!("docker-{}.scope", input.container_id))
                .map_err(|_| Error::Protocol)?,
            group: std::ffi::CString::new(input.group_name).map_err(|_| Error::Protocol)?,
        })
    }
    pub(crate) fn rules(&self, parent: BorrowedFd<'_>) -> [(i32, u64); 4] {
        use std::os::fd::AsRawFd;
        [
            (self.root.as_raw_fd(), ROOT_PARENT.as_ptr() as u64),
            (self.root.as_raw_fd(), SYSTEM_SLICE.as_ptr() as u64),
            (
                self.system_slice.as_raw_fd(),
                self.container.as_ptr() as u64,
            ),
            (parent.as_raw_fd(), self.group.as_ptr() as u64),
        ]
    }
    pub(crate) fn verify(&self, parent: BorrowedFd<'_>, group: BorrowedFd<'_>) -> Result<()> {
        use std::os::fd::AsFd;
        for fd in [self.root.as_fd(), self.system_slice.as_fd(), parent, group] {
            let s = rustix::fs::fstat(fd).map_err(|_| Error::Descriptor)?;
            if s.st_uid != 0
                || s.st_gid != 0
                || s.st_mode & 0o022 != 0
                || rustix::fs::FileType::from_raw_mode(s.st_mode) != rustix::fs::FileType::Directory
                || rustix::fs::fstatfs(fd)
                    .map_err(|_| Error::Descriptor)?
                    .f_type as u64
                    != 0x63677270
            {
                return Err(Error::Descriptor);
            }
        }
        verify_link(self.root.as_fd(), ROOT_PARENT, self.root.as_fd())?;
        verify_link(self.root.as_fd(), SYSTEM_SLICE, self.system_slice.as_fd())?;
        verify_link(self.system_slice.as_fd(), &self.container, parent)?;
        verify_link(parent, &self.group, group)
    }
}
fn verify_link(parent: BorrowedFd<'_>, name: &std::ffi::CStr, child: BorrowedFd<'_>) -> Result<()> {
    let s = rustix::fs::fstat(child).map_err(|_| Error::Descriptor)?;
    let at = rustix::fs::statat(parent, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| Error::Descriptor)?;
    if (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid)
        != (at.st_dev, at.st_ino, at.st_mode, at.st_uid, at.st_gid)
    {
        return Err(Error::Descriptor);
    }
    Ok(())
}

/// Child-local ancestry observation. Only an installed Bootstrap role can mint
/// this; it is not original Source/creation or parent-side policy authority.
pub struct ConfinedProducerGroup {
    creator: u32,
    ancestry: Arc<Ancestry>,
    parent: Arc<OwnedFd>,
    group: Arc<OwnedFd>,
    namespace: (u64, u64),
    end: f64,
}
impl ConfinedProducerGroup {
    pub(crate) fn new(
        ancestry: Arc<Ancestry>,
        parent: Arc<OwnedFd>,
        group: Arc<OwnedFd>,
        namespace: (u64, u64),
        end: f64,
    ) -> Self {
        Self {
            creator: std::process::id(),
            ancestry,
            parent,
            group,
            namespace,
            end,
        }
    }
    pub fn verify(&self) -> Result<()> {
        use std::os::fd::AsFd;
        if self.creator != std::process::id() {
            return Err(Error::Creator);
        }
        crate::linux::deadline(self.end)?;
        self.ancestry
            .verify(self.parent.as_fd(), self.group.as_fd())?;
        crate::linux::deadline(self.end)
    }
    pub fn identity(&self) -> Result<(u64, u64)> {
        self.verify()?;
        let s = rustix::fs::fstat(&self.group).map_err(|_| Error::Descriptor)?;
        Ok((s.st_dev, s.st_ino))
    }
    pub fn namespace_identity(&self) -> Result<(u64, u64)> {
        self.verify()?;
        Ok(self.namespace)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;
    #[test]
    fn retained_directory_inode_does_not_authorize_renamed_ancestry() {
        // Real filesystem relation test, not cgroup or confined-child proof.
        let path = std::env::temp_dir().join(format!(
            "vprouter-bootstrap-ancestry-{}",
            std::process::id()
        ));
        std::fs::create_dir(&path).unwrap();
        struct Remove(std::path::PathBuf);
        impl Drop for Remove {
            fn drop(&mut self) {
                std::fs::remove_dir_all(&self.0).unwrap();
            }
        }
        let _remove = Remove(path.clone());
        std::fs::create_dir(path.join("system.slice")).unwrap();
        std::fs::create_dir(path.join("system.slice/container")).unwrap();
        std::fs::create_dir(path.join("system.slice/container/group")).unwrap();
        let root = std::fs::File::open(&path).unwrap();
        let system = std::fs::File::open(path.join("system.slice")).unwrap();
        let parent = std::fs::File::open(path.join("system.slice/container")).unwrap();
        let group = std::fs::File::open(path.join("system.slice/container/group")).unwrap();
        verify_link(root.as_fd(), SYSTEM_SLICE, system.as_fd()).unwrap();
        verify_link(system.as_fd(), c"container", parent.as_fd()).unwrap();
        verify_link(parent.as_fd(), c"group", group.as_fd()).unwrap();
        std::fs::rename(path.join("system.slice"), path.join("old.slice")).unwrap();
        // The old parent/subgroup check still succeeds, so it is insufficient.
        verify_link(parent.as_fd(), c"group", group.as_fd()).unwrap();
        assert_eq!(
            verify_link(root.as_fd(), SYSTEM_SLICE, system.as_fd()),
            Err(Error::Descriptor)
        );
        std::fs::create_dir(path.join("system.slice")).unwrap();
        assert_eq!(
            verify_link(root.as_fd(), SYSTEM_SLICE, system.as_fd()),
            Err(Error::Descriptor)
        );
        std::fs::remove_dir(path.join("system.slice")).unwrap();
        std::os::unix::fs::symlink("old.slice", path.join("system.slice")).unwrap();
        assert_eq!(
            verify_link(root.as_fd(), SYSTEM_SLICE, system.as_fd()),
            Err(Error::Descriptor)
        );
    }
}
