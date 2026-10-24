#![forbid(unsafe_code)]
//! Locked generation-bound ownership. Failed creation is deliberately retained.
use super::{Error, Result, kernel, process, spec::LaunchSpec};
use rustix::fs::{self, FileType, Mode, OFlags, ResolveFlags};
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::{Read, Write},
    os::fd::{AsFd, OwnedFd},
    path::Path,
};
use vprouter_core::allocation::{AllocationRecord, AllocationStore, AllocationTransaction};
const RD: OFlags = OFlags::RDONLY
    .union(OFlags::CLOEXEC)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::NONBLOCK);
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Identity {
    pub dev: u64,
    pub ino: u64,
}
impl Identity {
    pub fn of(fd: impl AsFd) -> Result<Self> {
        let s = fs::fstat(fd).map_err(|_| Error::OwnershipMismatch)?;
        Ok(Self {
            dev: s.st_dev,
            ino: s.st_ino,
        })
    }
    pub fn network(fd: impl AsFd) -> Result<Self> {
        if fs::fstatfs(&fd)
            .map_err(|_| Error::NamespaceMismatch)?
            .f_type as u64
            != 0x6e736673
        {
            return Err(Error::NamespaceMismatch);
        }
        Self::of(fd)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Phase {
    Creating,
    Offline,
    Activating,
    Bootstrap,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    exit_id: String,
    data_name: String,
    transport_name: String,
    phase: Phase,
    data: Option<Identity>,
    transport: Option<Identity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    links: Option<LinkOwnership>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    producer: Option<ProducerOwnership>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProducerOwnership {
    parent: Identity,
    group: Identity,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LinkOwnership {
    host_namespace: Identity,
    host_index: u32,
    transport_index: u32,
    wireguard_index: u32,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    schema_version: u32,
    allocation: AllocationRecord,
    primary_exit_id: String,
    base_network: Identity,
    entries: Vec<Entry>,
}
fn same_allocation(a: &AllocationRecord, b: &AllocationRecord) -> Result<bool> {
    Ok(serde_json::to_vec(a).map_err(|_| Error::OwnershipMismatch)?
        == serde_json::to_vec(b).map_err(|_| Error::OwnershipMismatch)?)
}
impl Record {
    fn new(s: &LaunchSpec, primary: &str, base: Identity) -> Result<Self> {
        if !s.allocation.exits.iter().any(|e| e.exit_id == primary) {
            return Err(Error::AllocationMismatch);
        }
        let allocation = serde_json::from_slice(
            &serde_json::to_vec(&s.allocation).map_err(|_| Error::AllocationMismatch)?,
        )
        .map_err(|_| Error::AllocationMismatch)?;
        Ok(Self {
            schema_version: 1,
            allocation,
            primary_exit_id: primary.into(),
            base_network: base,
            entries: Vec::new(),
        })
    }
    fn bind(&self, s: &LaunchSpec, primary: &str, base: Identity) -> Result<()> {
        s.validate()?;
        if self.schema_version != 1
            || !same_allocation(&self.allocation, &s.allocation)?
            || self.primary_exit_id != primary
            || self.base_network != base
            || !self.allocation.exits.iter().any(|e| e.exit_id == primary)
        {
            return Err(Error::OwnershipMismatch);
        }
        let mut seen = std::collections::HashSet::new();
        let mut identities = std::collections::HashSet::new();
        for e in &self.entries {
            let a = self
                .allocation
                .exits
                .iter()
                .find(|a| a.exit_id == e.exit_id)
                .ok_or(Error::OwnershipMismatch)?;
            if !seen.insert(&e.exit_id)
                || a.data_namespace != e.data_name
                || a.transport_namespace != e.transport_name
            {
                return Err(Error::OwnershipMismatch);
            }
            if e.phase != Phase::Creating && (e.data.is_none() || e.transport.is_none()) {
                return Err(Error::OwnershipMismatch);
            }
            if let Some(p) = &e.producer {
                if !matches!(e.phase, Phase::Activating | Phase::Bootstrap)
                    || p.parent.dev != p.group.dev
                    || p.parent == p.group
                    || p.parent.ino == 0
                    || p.group.ino == 0
                {
                    return Err(Error::OwnershipMismatch);
                }
            } else if e.phase == Phase::Bootstrap {
                return Err(Error::OwnershipMismatch);
            }
            if let Some(l) = &e.links {
                if !matches!(e.phase, Phase::Activating | Phase::Bootstrap)
                    || l.host_namespace.ino == 0
                    || l.host_namespace == e.data.unwrap_or(l.host_namespace)
                    || l.host_namespace == e.transport.unwrap_or(l.host_namespace)
                    || [l.host_index, l.transport_index, l.wireguard_index].contains(&0)
                {
                    return Err(Error::OwnershipMismatch);
                }
            } else if e.phase == Phase::Bootstrap {
                return Err(Error::OwnershipMismatch);
            }
            for id in [e.data, e.transport].into_iter().flatten() {
                if id.ino == 0 || !identities.insert((id.dev, id.ino)) {
                    return Err(Error::OwnershipMismatch);
                }
            }
            if e.exit_id == primary && e.data.is_some_and(|id| id != base) {
                return Err(Error::OwnershipMismatch);
            }
            if e.exit_id != primary && e.data == Some(base) || e.transport == Some(base) {
                return Err(Error::OwnershipMismatch);
            }
        }
        Ok(())
    }
}
pub(super) struct OwnedNamespaces {
    pub data: OwnedFd,
    pub transport: OwnedFd,
    exit_id: String,
    allocation_digest: String,
    data_identity: Identity,
    transport_identity: Identity,
    _inventory: super::inventory::Registration,
}
impl OwnedNamespaces {
    fn new(s: &LaunchSpec, data: OwnedFd, transport: OwnedFd) -> Result<Self> {
        let data_identity = Identity::network(&data)?;
        let transport_identity = Identity::network(&transport)?;
        let inventory = super::inventory::Registration::owned(&[data.as_fd(), transport.as_fd()])?;
        Ok(Self {
            data,
            transport,
            exit_id: s.exit.exit_id.clone(),
            allocation_digest: vprouter_linux::sha256(
                &serde_json::to_vec(&s.allocation).map_err(|_| Error::AllocationMismatch)?,
            ),
            data_identity,
            transport_identity,
            _inventory: inventory,
        })
    }
    pub fn bind(&self, s: &LaunchSpec) -> Result<()> {
        if self.exit_id != s.exit.exit_id
            || self.allocation_digest
                != vprouter_linux::sha256(
                    &serde_json::to_vec(&s.allocation).map_err(|_| Error::AllocationMismatch)?,
                )
            || Identity::network(&self.data)? != self.data_identity
            || Identity::network(&self.transport)? != self.transport_identity
        {
            return Err(Error::NamespaceMismatch);
        }
        Ok(())
    }
}
/// Allocation lock is shared with AllocationStore; it remains held through
/// namespace acquisition and execution admission. No caller evidence booleans.
pub(super) struct Transaction<'a> {
    dir: OwnedFd,
    allocation: AllocationTransaction<'a>,
    record: Record,
    _inventory: super::inventory::Registration,
}
fn file_check(fd: impl AsFd) -> Result<()> {
    let s = fs::fstat(fd).map_err(|_| Error::OwnershipMismatch)?;
    if s.st_uid != 0
        || s.st_gid != 0
        || s.st_mode & 0o7777 != 0o600
        || s.st_nlink != 1
        || FileType::from_raw_mode(s.st_mode) != FileType::RegularFile
    {
        return Err(Error::OwnershipMismatch);
    }
    Ok(())
}
pub(super) fn directory(path: &Path) -> Result<OwnedFd> {
    if !super::spec::safe_absolute(path) {
        return Err(Error::UnsafeInput);
    }
    let mut d =
        fs::open("/", RD | OFlags::DIRECTORY, Mode::empty()).map_err(|_| Error::UnsafeInput)?;
    for p in path.components().skip(1) {
        let s = fs::fstat(&d).map_err(|_| Error::UnsafeInput)?;
        if s.st_uid != 0 || s.st_gid != 0 || s.st_mode & 0o022 != 0 {
            return Err(Error::UnsafeInput);
        }
        d = fs::openat(&d, p.as_os_str(), RD | OFlags::DIRECTORY, Mode::empty())
            .map_err(|_| Error::UnsafeInput)?;
    }
    let s = fs::fstat(&d).map_err(|_| Error::UnsafeInput)?;
    if s.st_uid != 0 || s.st_gid != 0 || s.st_mode & 0o7777 != 0o700 {
        return Err(Error::UnsafeInput);
    }
    Ok(d)
}
impl<'a> Transaction<'a> {
    pub fn open(
        store: &'a AllocationStore,
        path: &Path,
        s: &LaunchSpec,
        primary: &str,
        base: impl AsFd,
    ) -> Result<Self> {
        process::single_threaded()?;
        let allocation = store.lock().map_err(|_| Error::LockBusy)?;
        let a = allocation
            .read()
            .map_err(|_| Error::AllocationMismatch)?
            .ok_or(Error::AllocationMismatch)?;
        if !same_allocation(&a, &s.allocation)? {
            return Err(Error::AllocationMismatch);
        }
        let dir = directory(path)?;
        allocation
            .verify_directory(dir.as_fd())
            .map_err(|_| Error::OwnershipMismatch)?;
        let inventory = super::inventory::Registration::allocation(dir.as_fd())?;
        let base = Identity::network(base)?;
        let record = match fs::openat(&dir, "namespaces.json", RD, Mode::empty()) {
            Ok(fd) => {
                file_check(&fd)?;
                let mut b = Vec::new();
                File::from(fd)
                    .take(262145)
                    .read_to_end(&mut b)
                    .map_err(|_| Error::OwnershipMismatch)?;
                if b.len() > 262144 {
                    return Err(Error::TooLarge);
                }
                serde_json::from_slice(&b).map_err(|_| Error::OwnershipMismatch)?
            }
            Err(rustix::io::Errno::NOENT) => Record::new(s, primary, base)?,
            Err(_) => return Err(Error::OwnershipMismatch),
        };
        record.bind(s, primary, base)?;
        let tx = Self {
            dir,
            allocation,
            record,
            _inventory: inventory,
        };
        tx.persist()?;
        Ok(tx)
    }
    fn persist(&self) -> Result<()> {
        let bytes = serde_json::to_vec(&self.record).map_err(|_| Error::OwnershipMismatch)?;
        if bytes.len() > 262144 {
            return Err(Error::TooLarge);
        }
        let name = format!(".namespaces-{}", std::process::id());
        // An interrupted temp is never overwritten or silently deleted.
        let fd = fs::openat(
            &self.dir,
            &name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|_| Error::Interrupted)?;
        let mut f = File::from(fd);
        f.write_all(&bytes)
            .and_then(|()| f.sync_all())
            .map_err(|_| Error::Interrupted)?;
        fs::renameat(&self.dir, &name, &self.dir, "namespaces.json")
            .map_err(|_| Error::Interrupted)?;
        fs::fsync(&self.dir).map_err(|_| Error::Interrupted)
    }
    pub fn revalidate(&self, s: &LaunchSpec) -> Result<()> {
        let current = self
            .allocation
            .read()
            .map_err(|_| Error::AllocationMismatch)?
            .ok_or(Error::AllocationMismatch)?;
        if !same_allocation(&current, &s.allocation)? {
            return Err(Error::AllocationMismatch);
        }
        self.record
            .bind(s, &self.record.primary_exit_id, self.record.base_network)
    }
    pub fn acquire(&mut self, s: &LaunchSpec, base: impl AsFd) -> Result<OwnedNamespaces> {
        self.revalidate(s)?;
        if Identity::network(&base)? != self.record.base_network {
            return Err(Error::NamespaceMismatch);
        }
        if let Some(e) = self
            .record
            .entries
            .iter()
            .find(|e| e.exit_id == s.exit.exit_id)
        {
            if e.phase != Phase::Offline {
                return Err(Error::Interrupted);
            }
            return OwnedNamespaces::new(
                s,
                self.reopen(&e.data_name, e.data.ok_or(Error::Interrupted)?)?,
                self.reopen(&e.transport_name, e.transport.ok_or(Error::Interrupted)?)?,
            );
        }
        // Exclusivity checked before durable intent, but O_EXCL below remains
        // decisive. Foreign paths and ambiguous partial entries are never adopted.
        for name in [&s.exit.data_namespace, &s.exit.transport_namespace] {
            match fs::statat(&self.dir, name, fs::AtFlags::SYMLINK_NOFOLLOW) {
                Err(rustix::io::Errno::NOENT) => {}
                _ => return Err(Error::OwnershipMismatch),
            }
        }
        self.record.entries.push(Entry {
            exit_id: s.exit.exit_id.clone(),
            data_name: s.exit.data_namespace.clone(),
            transport_name: s.exit.transport_namespace.clone(),
            phase: Phase::Creating,
            data: None,
            transport: None,
            links: None,
            producer: None,
        });
        self.persist()?;
        let data = self.create(
            &s.exit.data_namespace,
            if s.exit.exit_id == self.record.primary_exit_id {
                Some(base.as_fd())
            } else {
                None
            },
        )?;
        let id = Identity::network(&data)?;
        self.record
            .entries
            .last_mut()
            .ok_or(Error::Interrupted)?
            .data = Some(id);
        self.persist()?;
        let transport = self.create(&s.exit.transport_namespace, None)?;
        let id = Identity::network(&transport)?;
        let e = self.record.entries.last_mut().ok_or(Error::Interrupted)?;
        e.transport = Some(id);
        e.phase = Phase::Offline;
        self.record
            .bind(s, &self.record.primary_exit_id, self.record.base_network)?;
        self.persist()?;
        OwnedNamespaces::new(s, data, transport)
    }
    /// Persist activation intent before any link creation/UP operation. A crash
    /// in this phase is never silently adopted by acquire().
    pub fn begin_transport(&mut self, s: &LaunchSpec, ns: &OwnedNamespaces) -> Result<()> {
        self.revalidate(s)?;
        ns.bind(s)?;
        let e = self
            .record
            .entries
            .iter_mut()
            .find(|e| e.exit_id == s.exit.exit_id)
            .ok_or(Error::OwnershipMismatch)?;
        if e.phase != Phase::Offline || e.links.is_some() {
            return Err(Error::Interrupted);
        }
        e.phase = Phase::Activating;
        self.persist()
    }
    pub fn bind_producer(
        &mut self,
        s: &LaunchSpec,
        parent: Identity,
        group: Identity,
    ) -> Result<()> {
        self.revalidate(s)?;
        let e = self
            .record
            .entries
            .iter_mut()
            .find(|e| e.exit_id == s.exit.exit_id)
            .ok_or(Error::OwnershipMismatch)?;
        if e.phase != Phase::Activating
            || e.producer.is_some()
            || parent.dev != group.dev
            || parent == group
            || parent.ino == 0
            || group.ino == 0
        {
            return Err(Error::OwnershipMismatch);
        }
        e.producer = Some(ProducerOwnership { parent, group });
        self.persist()
    }
    pub fn verify_producer(&self, s: &LaunchSpec, parent: Identity, group: Identity) -> Result<()> {
        self.revalidate(s)?;
        let e = self
            .record
            .entries
            .iter()
            .find(|e| e.exit_id == s.exit.exit_id)
            .ok_or(Error::OwnershipMismatch)?;
        let p = e.producer.as_ref().ok_or(Error::OwnershipMismatch)?;
        if p.parent != parent || p.group != group {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
    pub fn bind_links(
        &mut self,
        s: &LaunchSpec,
        ns: &OwnedNamespaces,
        host: Identity,
        indices: (u32, u32, u32),
    ) -> Result<()> {
        self.revalidate(s)?;
        ns.bind(s)?;
        let e = self
            .record
            .entries
            .iter_mut()
            .find(|e| e.exit_id == s.exit.exit_id)
            .ok_or(Error::OwnershipMismatch)?;
        if e.phase != Phase::Activating
            || e.links.is_some()
            || [indices.0, indices.1, indices.2].contains(&0)
            || host.ino == 0
            || Some(host) == e.data
            || Some(host) == e.transport
        {
            return Err(Error::OwnershipMismatch);
        }
        e.links = Some(LinkOwnership {
            host_namespace: host,
            host_index: indices.0,
            transport_index: indices.1,
            wireguard_index: indices.2,
        });
        self.persist()
    }
    pub fn bootstrap(
        &mut self,
        s: &LaunchSpec,
        ns: &OwnedNamespaces,
        host: Identity,
        indices: (u32, u32, u32),
    ) -> Result<()> {
        self.verify_links(s, ns, host, indices)?;
        let e = self
            .record
            .entries
            .iter_mut()
            .find(|e| e.exit_id == s.exit.exit_id)
            .ok_or(Error::OwnershipMismatch)?;
        if e.phase != Phase::Activating {
            return Err(Error::Interrupted);
        }
        e.phase = Phase::Bootstrap;
        self.persist()
    }
    pub fn verify_links(
        &self,
        s: &LaunchSpec,
        ns: &OwnedNamespaces,
        host: Identity,
        indices: (u32, u32, u32),
    ) -> Result<()> {
        self.revalidate(s)?;
        ns.bind(s)?;
        let e = self
            .record
            .entries
            .iter()
            .find(|e| e.exit_id == s.exit.exit_id)
            .ok_or(Error::OwnershipMismatch)?;
        let l = e.links.as_ref().ok_or(Error::OwnershipMismatch)?;
        if !matches!(e.phase, Phase::Activating | Phase::Bootstrap)
            || l.host_namespace != host
            || (l.host_index, l.transport_index, l.wireguard_index) != indices
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
    pub fn transport_cleaned(&mut self, s: &LaunchSpec) -> Result<()> {
        self.revalidate(s)?;
        let e = self
            .record
            .entries
            .iter_mut()
            .find(|e| e.exit_id == s.exit.exit_id)
            .ok_or(Error::OwnershipMismatch)?;
        if !matches!(e.phase, Phase::Activating | Phase::Bootstrap) {
            return Err(Error::Interrupted);
        }
        e.phase = Phase::Offline;
        e.links = None;
        e.producer = None;
        self.persist()
    }
    fn create(&self, name: &str, source: Option<std::os::fd::BorrowedFd<'_>>) -> Result<OwnedFd> {
        let placeholder = fs::openat(
            &self.dir,
            name,
            OFlags::CREATE | OFlags::EXCL | OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|_| Error::OwnershipMismatch)?;
        file_check(&placeholder)?;
        fs::fsync(&self.dir).map_err(|_| Error::Interrupted)?;
        kernel::pin_network(&placeholder, source)?;
        let handle = fs::openat2(
            &self.dir,
            name,
            RD,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
        )
        .map_err(|_| Error::NamespaceMismatch)?;
        let id = Identity::network(&handle)?;
        self.reopen(name, id)
    }
    #[cfg(test)]
    pub fn lab_unpin(&self) -> Result<()> {
        for (index, e) in self.record.entries.iter().enumerate() {
            if e.phase != Phase::Offline {
                return Err(Error::Interrupted);
            }
            eprintln!("LAB_UNPIN_RECORD exit_index={index} kind=data");
            kernel::lab_unpin(
                self.dir.as_fd(),
                &e.data_name,
                e.data.ok_or(Error::Interrupted)?,
            )?;
            eprintln!("LAB_UNPIN_RECORD exit_index={index} kind=transport");
            kernel::lab_unpin(
                self.dir.as_fd(),
                &e.transport_name,
                e.transport.ok_or(Error::Interrupted)?,
            )?;
        }
        fs::fsync(&self.dir).map_err(|_| Error::Interrupted)
    }
    fn reopen(&self, name: &str, expected: Identity) -> Result<OwnedFd> {
        let handle = fs::openat2(
            &self.dir,
            name,
            RD,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
        )
        .map_err(|_| Error::NamespaceMismatch)?;
        if Identity::network(&handle)? != expected {
            return Err(Error::NamespaceMismatch);
        }
        // setns+direct proc reopening is mandatory for native NamespaceTarget.
        kernel::direct_network(&handle)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn durable_activation_and_bootstrap_require_exact_live_authorities() {
        let (s, _) = super::super::tests::fixture();
        let base = Identity { dev: 4, ino: 10 };
        let mut r = Record::new(&s, "one", base).unwrap();
        r.entries.push(Entry {
            exit_id: "one".into(),
            data_name: s.exit.data_namespace.clone(),
            transport_name: s.exit.transport_namespace.clone(),
            phase: Phase::Activating,
            data: Some(base),
            transport: Some(Identity { dev: 4, ino: 11 }),
            producer: None,
            links: None,
        });
        // Partial intent remains readable, but acquire refuses this phase.
        assert!(r.bind(&s, "one", base).is_ok());
        r.entries[0].phase = Phase::Bootstrap;
        assert!(r.bind(&s, "one", base).is_err());
        r.entries[0].producer = Some(ProducerOwnership {
            parent: Identity { dev: 5, ino: 20 },
            group: Identity { dev: 5, ino: 21 },
        });
        r.entries[0].links = Some(LinkOwnership {
            host_namespace: Identity { dev: 4, ino: 12 },
            host_index: 2,
            transport_index: 3,
            wireguard_index: 4,
        });
        assert!(r.bind(&s, "one", base).is_ok());
        r.entries[0].links.as_mut().unwrap().host_namespace = base;
        assert!(r.bind(&s, "one", base).is_err());
        r.entries[0].links.as_mut().unwrap().host_namespace = Identity { dev: 4, ino: 12 };
        r.entries[0].producer.as_mut().unwrap().group.dev = 6;
        assert!(r.bind(&s, "one", base).is_err());
    }
    #[test]
    fn exact_members_generation_primary_and_interruption_are_bound() {
        let (mut s, _) = super::super::tests::fixture();
        let base = Identity { dev: 4, ino: 10 };
        let mut r = Record::new(&s, "one", base).unwrap();
        assert!(r.bind(&s, "one", base).is_ok());
        assert!(r.bind(&s, "wrong", base).is_err());
        assert!(r.bind(&s, "one", Identity { dev: 4, ino: 11 }).is_err());
        s.generation += 1;
        assert!(r.bind(&s, "one", base).is_err());
        s.generation -= 1;
        r.entries.push(Entry {
            exit_id: "one".into(),
            data_name: s.exit.data_namespace.clone(),
            transport_name: s.exit.transport_namespace.clone(),
            phase: Phase::Creating,
            data: None,
            transport: None,
            links: None,
            producer: None,
        });
        assert!(r.bind(&s, "one", base).is_ok());
        r.entries[0].phase = Phase::Offline;
        assert!(r.bind(&s, "one", base).is_err());
        r.entries[0].data = Some(base);
        r.entries[0].transport = Some(base);
        assert!(r.bind(&s, "one", base).is_err());
        r.entries[0].transport = Some(Identity { dev: 4, ino: 12 });
        assert!(r.bind(&s, "one", base).is_ok());
        r.entries[0].transport_name = "foreign".into();
        assert!(r.bind(&s, "one", base).is_err());
    }
}
