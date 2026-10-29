//! Read-only original producer/ancestry pins for one fresh Bootstrap window.
//! This owner cannot publish, place a process, or manufacture SocketProducer.
use super::super::super::{inventory, kernel};
use super::super::{Error, Result};
use rustix::fs::{self, Mode, OFlags, ResolveFlags};
use std::{
    os::fd::{AsFd, BorrowedFd, OwnedFd},
    rc::Rc,
};

pub(super) struct Pins {
    creator: u32,
    source: Rc<kernel::producer_creation::Source>,
    started: f64,
    fds: Vec<OwnedFd>,
    tokens: Vec<inventory::Registration>,
    identities: Vec<(u64, u64, u32)>,
}
impl Pins {
    #[cfg(test)]
    pub(super) fn lab_registered_slots(&self) -> Result<usize> {
        self.verify_retained()?;
        self.tokens
            .iter()
            .try_fold(0, |sum, t| Ok(sum + t.lab_live_slots()?))
    }

    pub(super) fn new(source: Rc<kernel::producer_creation::Source>, started: f64) -> Result<Self> {
        // Retain the exact original Source before acquiring any additional read
        // pin. The consuming operational owner remains responsible for it.
        let mut value = Self {
            creator: std::process::id(),
            source,
            started,
            fds: Vec::with_capacity(8),
            tokens: Vec::with_capacity(8),
            identities: Vec::with_capacity(8),
        };
        value.check()?;
        value.source.verify_acknowledged_history()?;
        let original = value.source.request().binding().data().request();
        let ancestry = original.original_producer_ancestry()?;
        let parent = value
            .source
            .request()
            .parent()
            .try_clone_to_owned()
            .map_err(|_| Error::DescriptorDuplicate)?;
        value.add(parent)?;
        let group = value
            .source
            .descriptor()?
            .try_clone_to_owned()
            .map_err(|_| Error::DescriptorDuplicate)?;
        value.add(group)?;
        for name in [
            "cgroup.procs",
            "cgroup.events",
            "cgroup.type",
            "cgroup.subtree_control",
        ] {
            let fd = fs::openat2(
                value.fds[1].as_fd(),
                name,
                OFlags::RDONLY | OFlags::CLOEXEC,
                Mode::empty(),
                ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
            )
            .map_err(|_| Error::CgroupMismatch)?;
            value.add(fd)?;
        }
        for fd in ancestry {
            value.add(fd)?;
        }
        value.verify()?;
        Ok(value)
    }
    fn add(&mut self, fd: OwnedFd) -> Result<()> {
        self.check()?;
        self.fds.push(fd);
        let fd = self.fds.last().ok_or(Error::DescriptorInventory)?.as_fd();
        self.tokens.push(inventory::Registration::owned(&[fd])?);
        let st = fs::fstat(fd).map_err(|_| Error::CgroupMismatch)?;
        self.identities.push((st.st_dev, st.st_ino, st.st_mode));
        self.check()
    }
    fn check(&self) -> Result<()> {
        if self.creator != std::process::id() || !vprouter_core::secret_boundary::pristine() {
            return Err(Error::OwnershipMismatch);
        }
        let now = vprouter_core::health::boot_seconds();
        if !self.started.is_finite()
            || self.started < 0.
            || !now.is_finite()
            || now < self.started
            || now >= self.started + 2.
        {
            return Err(Error::Deadline);
        }
        Ok(())
    }
    pub(super) fn verify(&self) -> Result<()> {
        self.check()?;
        self.verify_retained()?;
        self.check()
    }
    pub(super) fn matches_source(&self, source: &Rc<kernel::producer_creation::Source>) -> bool {
        Rc::ptr_eq(&self.source, source)
    }
    pub(super) fn identities(&self) -> Result<[(u64, u64, u32); 8]> {
        // Immutable constructor metadata only; every use for native work also
        // passes the complete current Request/registration check.
        self.check()?;
        self.identities
            .clone()
            .try_into()
            .map_err(|_| Error::DescriptorInventory)
    }
    pub(super) fn verify_retained(&self) -> Result<()> {
        if self.creator != std::process::id() || !vprouter_core::secret_boundary::pristine() {
            return Err(Error::OwnershipMismatch);
        }
        self.source.verify_acknowledged_history()?;
        if self.fds.len() != 8 || self.tokens.len() != 8 || self.identities.len() != 8 {
            return Err(Error::DescriptorInventory);
        }
        for (index, ((fd, token), expected)) in self
            .fds
            .iter()
            .zip(&self.tokens)
            .zip(&self.identities)
            .enumerate()
        {
            token.retained_slots()?;
            let st = fs::fstat(fd).map_err(|_| Error::CgroupMismatch)?;
            let kind = if (2..6).contains(&index) {
                fs::FileType::RegularFile
            } else {
                fs::FileType::Directory
            };
            if !token.contains(fd.as_fd())
                || (st.st_dev, st.st_ino, st.st_mode) != *expected
                || st.st_uid != 0
                || st.st_gid != 0
                || st.st_mode & 0o022 != 0
                || fs::FileType::from_raw_mode(st.st_mode) != kind
                || fs::fstatfs(fd).map_err(|_| Error::CgroupMismatch)?.f_type as u64 != 0x63677270
                || fs::fcntl_getfl(fd)
                    .map_err(|_| Error::DescriptorInventory)?
                    .intersects(OFlags::WRONLY | OFlags::RDWR)
            {
                return Err(Error::CgroupMismatch);
            }
        }
        let group = self.source.identity()?;
        if self.identities[0].0 != self.source.request().parent_identity().dev
            || self.identities[0].1 != self.source.request().parent_identity().ino
            || self.identities[1].0 != group.dev
            || self.identities[1].1 != group.ino
        {
            return Err(Error::CgroupMismatch);
        }
        self.source
            .request()
            .binding()
            .data()
            .request()
            .verify_producer_ancestry(self.fds[6].as_fd(), self.fds[7].as_fd())
    }
    pub(super) fn selected(&self) -> Result<vprouter_native_role::ProducerDescriptors<'_>> {
        self.verify()?;
        Ok(vprouter_native_role::ProducerDescriptors {
            parent: self.fds[0].as_fd(),
            group: self.fds[1].as_fd(),
            procs: self.fds[2].as_fd(),
            events: self.fds[3].as_fd(),
            kind: self.fds[4].as_fd(),
            subtree: self.fds[5].as_fd(),
        })
    }
    pub(super) fn ancestry(&self) -> Result<vprouter_native_role::ProducerAncestryDescriptors<'_>> {
        self.verify()?;
        Ok(vprouter_native_role::ProducerAncestryDescriptors {
            root: self.fds[6].as_fd(),
            system_slice: self.fds[7].as_fd(),
            container_id: &self
                .source
                .request()
                .binding()
                .data()
                .request()
                .spec()
                .container_id,
            group_name: self.source.request().name(),
        })
    }
    pub(super) fn descriptors(&self) -> Result<Vec<BorrowedFd<'_>>> {
        self.verify()?;
        Ok(self.fds.iter().map(AsFd::as_fd).collect())
    }
}

impl Drop for Pins {
    fn drop(&mut self) {
        if self.creator != std::process::id() {
            std::mem::forget(std::mem::take(&mut self.fds));
            std::mem::forget(std::mem::take(&mut self.tokens));
        }
    }
}
