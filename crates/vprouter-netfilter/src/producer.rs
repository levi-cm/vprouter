//! Descriptor-backed cgroupv2 socket-origin authority for one protected namespace.
use crate::{Error, Result};
use rustix::fs::{self, FileType, Mode, OFlags};
use std::{
    os::fd::{AsRawFd, BorrowedFd, OwnedFd},
    sync::Arc,
};
use vprouter_core::allocation::{AllocationRecord, ExitAllocation};
pub struct SocketProducer {
    fd: Option<OwnedFd>,
    confined: Option<vprouter_native_role::ConfinedProducerGroup>,
    dev: u64,
    id: u64,
    namespace: (u64, u64),
    alias: String,
    path: String,
}
impl SocketProducer {
    pub fn group_name(record: &AllocationRecord, exit: &ExitAllocation) -> String {
        format!("{}-g{}-health", exit.nft_table, record.generation)
    }
    /// This constructor derives cgroup ID/level from an actual pinned, root-owned
    /// subgroup in the exact admitted Docker container parent; never caller IDs.
    pub fn from_owned_group(
        record: &AllocationRecord,
        exit: &ExitAllocation,
        container_id: &str,
        group: BorrowedFd<'_>,
        namespace: BorrowedFd<'_>,
    ) -> Result<Arc<Self>> {
        record
            .validate(&record.deployment_id, &[])
            .map_err(|_| Error::InvalidAllocation)?;
        if !record.exits.contains(exit)
            || container_id.len() != 64
            || !container_id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Error::InvalidInput);
        }
        let path = format!(
            "/sys/fs/cgroup/system.slice/docker-{container_id}.scope/{}",
            Self::group_name(record, exit)
        );
        let fd = group.try_clone_to_owned().map_err(|_| Error::Io)?;
        let st = fs::fstat(&fd).map_err(|_| Error::InvalidInput)?;
        if fs::fstatfs(&fd).map_err(|_| Error::InvalidInput)?.f_type as u64 != 0x63677270
            || st.st_uid != 0
            || st.st_gid != 0
            || st.st_mode & 0o022 != 0
            || FileType::from_raw_mode(st.st_mode) != FileType::Directory
            || std::fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd()))
                .map_err(|_| Error::InvalidInput)?
                .as_os_str()
                != path.as_str()
        {
            return Err(Error::InvalidInput);
        }
        let ns = fs::fstat(namespace).map_err(|_| Error::InvalidInput)?;
        if fs::fstatfs(namespace)
            .map_err(|_| Error::InvalidInput)?
            .f_type as u64
            != 0x6e736673
        {
            return Err(Error::InvalidInput);
        }
        let result = Arc::new(Self {
            fd: Some(fd),
            confined: None,
            dev: st.st_dev,
            id: st.st_ino,
            namespace: (ns.st_dev, ns.st_ino),
            alias: format!(
                "vprouter-v2:{}:{}:{}",
                record.deployment_id, record.generation, exit.exit_id
            ),
            path,
        });
        result.verify()?;
        Ok(result)
    }
    pub(crate) fn from_confined_bootstrap(
        role: &vprouter_native_role::ConfinedProducerBootstrap,
        alias: String,
    ) -> Result<Arc<Self>> {
        let confined = role.producer_group().map_err(|_| Error::Foreign)?;
        let (dev, id) = confined.identity().map_err(|_| Error::Foreign)?;
        let namespace = confined.namespace_identity().map_err(|_| Error::Foreign)?;
        Ok(Arc::new(Self {
            fd: None,
            confined: Some(confined),
            dev,
            id,
            namespace,
            alias,
            path: String::new(),
        }))
    }
    pub(crate) fn verify(&self) -> Result<()> {
        if let Some(confined) = &self.confined {
            if self.fd.is_some()
                || !self.path.is_empty()
                || confined.identity().map_err(|_| Error::Drifted)? != (self.dev, self.id)
                || confined.namespace_identity().map_err(|_| Error::Drifted)? != self.namespace
            {
                return Err(Error::Drifted);
            }
            return Ok(());
        }
        let fd = self.fd.as_ref().ok_or(Error::Drifted)?;
        let st = fs::fstat(fd).map_err(|_| Error::Drifted)?;
        if (st.st_dev, st.st_ino) != (self.dev, self.id)
            || st.st_uid != 0
            || st.st_gid != 0
            || st.st_mode & 0o022 != 0
        {
            return Err(Error::Drifted);
        }
        let reopened = fs::open(
            &self.path,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
            Mode::empty(),
        )
        .map_err(|_| Error::Drifted)?;
        let r = fs::fstat(reopened).map_err(|_| Error::Drifted)?;
        if (r.st_dev, r.st_ino) != (self.dev, self.id) {
            return Err(Error::Drifted);
        }
        Ok(())
    }
    pub(crate) fn matches(&self, alias: &str, namespace: (u64, u64)) -> bool {
        self.alias == alias && self.namespace == namespace
    }
    pub(crate) fn id(&self) -> u64 {
        self.id
    }
    pub(crate) fn level(&self) -> u32 {
        3
    } // exact system.slice/container/owned subgroup
}

#[cfg(test)]
pub(crate) fn fixture(id: u64) -> Arc<SocketProducer> {
    Arc::new(SocketProducer {
        fd: Some(std::fs::File::open("/dev/null").unwrap().into()),
        confined: None,
        dev: 0,
        id,
        namespace: (0, 0),
        alias: String::new(),
        path: String::new(),
    })
}

impl std::fmt::Debug for SocketProducer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SocketProducer")
            .field("dev", &self.dev)
            .field("id", &self.id)
            .field("namespace", &self.namespace)
            .field("alias", &self.alias)
            .finish_non_exhaustive()
    }
}
