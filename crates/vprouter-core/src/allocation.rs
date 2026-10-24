//! Deterministic, scoped resource reservations and root-owned atomic storage.
use crate::{
    config::{ExitMode, MAX_EXITS, ValidatedConfiguration, absolute_path, label},
    reason::{Reason, Result, err},
};
use rustix::{
    fs::{FileType, FlockOperation, Mode, OFlags, flock, fstat, fsync, open, openat, renameat},
    io::Errno,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    fs::File,
    io::{Read, Write},
    net::Ipv4Addr,
    os::fd::{AsFd, OwnedFd},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

const MAX_RECORD_BYTES: usize = 256 * 1024;
const RECORD_NAME: &str = "allocations.json";
const LOCK_NAME: &str = ".allocations.lock";
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExitAllocation {
    pub exit_id: String,
    pub mode: ExitMode,
    pub state_dir: PathBuf,
    pub data_namespace: String,
    pub transport_namespace: String,
    pub nft_table: String,
    pub host_interface: String,
    pub data_interface: String,
    pub wireguard_interface: Option<String>,
    pub transport_subnet: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllocationRecord {
    pub schema_version: u32,
    pub deployment_id: String,
    pub generation: u64,
    pub exits: Vec<ExitAllocation>,
}
#[derive(Clone, Debug)]
pub enum ResourceClaim {
    Namespace(String),
    Interface(String),
    NftTable(String),
    Subnet(String),
}
impl AllocationRecord {
    pub fn from_configuration(
        configuration: &ValidatedConfiguration,
        generation: u64,
    ) -> Result<Self> {
        let deployment = &configuration.configuration().deployment_id;
        let exits = configuration
            .exits()
            .iter()
            .map(|e| {
                allocation(
                    deployment,
                    &e.exit().id,
                    e.exit().mode.kind(),
                    e.exit().state_dir.clone(),
                )
            })
            .collect();
        let record = Self {
            schema_version: 2,
            deployment_id: deployment.clone(),
            generation,
            exits,
        };
        record.validate(deployment, &[])?;
        Ok(record)
    }
    pub fn parse(bytes: &[u8], deployment: &str, foreign: &[ResourceClaim]) -> Result<Self> {
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(err(Reason::InvalidAllocation));
        }
        let record: Self =
            serde_json::from_slice(bytes).map_err(|_| err(Reason::InvalidAllocation))?;
        record.validate(deployment, foreign)?;
        Ok(record)
    }
    pub fn validate(&self, deployment: &str, foreign: &[ResourceClaim]) -> Result<()> {
        label(deployment, 32)?;
        if self.deployment_id != deployment {
            return Err(err(Reason::ForeignAllocation));
        }
        if self.schema_version != 2
            || self.generation == 0
            || self.exits.is_empty()
            || self.exits.len() > MAX_EXITS
        {
            return Err(err(Reason::InvalidAllocation));
        }
        let mut ids = HashSet::new();
        let mut namespaces = HashSet::new();
        let mut interfaces = HashSet::new();
        let mut tables = HashSet::new();
        let mut states: Vec<&Path> = Vec::new();
        let mut subnets = Vec::new();
        for e in &self.exits {
            label(&e.exit_id, 32)?;
            absolute_path(&e.state_dir)?;
            if e.state_dir == Path::new("/")
                || states
                    .iter()
                    .any(|p| p.starts_with(&e.state_dir) || e.state_dir.starts_with(p))
            {
                return Err(err(Reason::StateConflict));
            }
            states.push(&e.state_dir);
            if !ids.insert(&e.exit_id) {
                return Err(err(Reason::AllocationConflict));
            }
            if *e != allocation(deployment, &e.exit_id, e.mode, e.state_dir.clone()) {
                return Err(err(Reason::InvalidAllocation));
            }
            for n in [&e.data_namespace, &e.transport_namespace] {
                if !namespaces.insert(n.as_str()) {
                    return Err(err(Reason::AllocationConflict));
                }
            }
            for n in [&e.host_interface, &e.data_interface]
                .into_iter()
                .chain(e.wireguard_interface.iter())
            {
                if n.len() > 15 || !interfaces.insert(n.as_str()) {
                    return Err(err(Reason::AllocationConflict));
                }
            }
            if !tables.insert(e.nft_table.as_str()) {
                return Err(err(Reason::AllocationConflict));
            }
            let subnet = subnet_range(&e.transport_subnet)?;
            if subnets.iter().any(|s| overlaps(*s, subnet)) {
                return Err(err(Reason::AllocationConflict));
            }
            subnets.push(subnet);
        }
        for claim in foreign {
            let conflict = match claim {
                ResourceClaim::Namespace(n) => namespaces.contains(n.as_str()),
                ResourceClaim::Interface(n) => interfaces.contains(n.as_str()),
                ResourceClaim::NftTable(n) => tables.contains(n.as_str()),
                ResourceClaim::Subnet(n) => {
                    let foreign = subnet_range(n)?;
                    subnets.iter().any(|s| overlaps(*s, foreign))
                }
            };
            if conflict {
                return Err(err(Reason::AllocationConflict));
            }
        }
        Ok(())
    }
    /// Mode/state changes require an explicitly stopped reconfiguration by later layers.
    pub fn matches_configuration(&self, cfg: &ValidatedConfiguration) -> Result<()> {
        let next = Self::from_configuration(cfg, self.generation)?;
        if self.deployment_id != next.deployment_id
            || self.exits.len() != next.exits.len()
            || self.exits.iter().any(|e| !next.exits.contains(e))
        {
            return Err(err(Reason::AllocationConflict));
        }
        Ok(())
    }
}
fn allocation(deployment: &str, id: &str, mode: ExitMode, state_dir: PathBuf) -> ExitAllocation {
    let hash = stable_hash(deployment, id);
    let short = format!("{:012x}", hash & 0xffffffffffff);
    let full = format!("{hash:016x}");
    let slot = (hash & 0xffff) as u32;
    ExitAllocation {
        exit_id: id.to_owned(),
        mode,
        state_dir,
        data_namespace: format!("vr-data-{full}"),
        transport_namespace: format!("vr-trans-{full}"),
        nft_table: format!("vr_{full}"),
        host_interface: format!("vh{short}"),
        data_interface: format!("vd{short}"),
        wireguard_interface: if mode == ExitMode::Mullvad {
            Some(format!("wg{short}"))
        } else {
            None
        },
        transport_subnet: format!(
            "10.{}.{}.{}/30",
            200 + (slot >> 14),
            (slot >> 6) & 255,
            (slot & 63) * 4
        ),
    }
}
fn subnet_range(s: &str) -> Result<(u32, u32)> {
    let invalid = || err(Reason::InvalidAllocation);
    let (ip, prefix) = s.split_once('/').ok_or_else(invalid)?;
    let ip = u32::from(ip.parse::<Ipv4Addr>().map_err(|_| invalid())?);
    let prefix = prefix.parse::<u8>().map_err(|_| invalid())?;
    if prefix > 32 {
        return Err(invalid());
    }
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    if ip & mask != ip {
        return Err(invalid());
    }
    Ok((ip, ip | !mask))
}
fn overlaps(a: (u32, u32), b: (u32, u32)) -> bool {
    a.0 <= b.1 && b.0 <= a.1
}
pub(crate) fn stable_hash(deployment: &str, id: &str) -> u64 {
    // Stable identity only; not cryptographic authentication. Collisions fail closed.
    deployment
        .bytes()
        .chain([0])
        .chain(id.bytes())
        .fold(0xcbf29ce484222325, |h, b| {
            (h ^ u64::from(b)).wrapping_mul(0x100000001b3)
        })
}

fn open_directory(path: &Path) -> Result<OwnedFd> {
    absolute_path(path)?;
    let mut dir = open(
        "/",
        OFlags::DIRECTORY | OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| err(Reason::StorageUnsafe))?;
    for component in path.components().skip(1) {
        dir = openat(
            &dir,
            component.as_os_str(),
            OFlags::DIRECTORY | OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|_| err(Reason::StorageUnsafe))?;
    }
    Ok(dir)
}
pub(crate) fn secure_open_read(path: &Path) -> Result<File> {
    absolute_path(path)?;
    let parent = path.parent().ok_or_else(|| err(Reason::InvalidPath))?;
    let name = path.file_name().ok_or_else(|| err(Reason::InvalidPath))?;
    let dir = open_directory(parent)?;
    let fd = openat(
        dir,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| err(Reason::StorageUnsafe))?;
    let file = File::from(fd);
    if !file
        .metadata()
        .map_err(|_| err(Reason::StorageUnavailable))?
        .is_file()
    {
        return Err(err(Reason::StorageUnsafe));
    }
    Ok(file)
}

pub struct AllocationStore {
    dir: OwnedFd,
    deployment: String,
    owner: u32,
}
/// flock remains held until this guard is dropped. The lock file is never unlinked.
pub struct AllocationTransaction<'a> {
    store: &'a AllocationStore,
    _lock: File,
}
impl AllocationStore {
    /// Root-owned 0700 existing directory; root-owned non-writable ancestors only.
    pub fn open(path: &Path, deployment: &str) -> Result<Self> {
        Self::open_owned(path, deployment, 0, false)
    }
    #[cfg(test)]
    fn open_for_test(path: &Path, deployment: &str) -> Result<Self> {
        Self::open_owned(path, deployment, rustix::process::getuid().as_raw(), true)
    }
    fn open_owned(path: &Path, deployment: &str, owner: u32, test_temp: bool) -> Result<Self> {
        absolute_path(path)?;
        label(deployment, 32)?;
        let mut dir = open(
            "/",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| err(Reason::StorageUnsafe))?;
        for component in path.components().skip(1) {
            let ancestor = fstat(&dir).map_err(|_| err(Reason::StorageUnsafe))?;
            let owner_ok = ancestor.st_uid == 0 || test_temp && ancestor.st_uid == owner;
            let mode_ok = ancestor.st_mode & 0o022 == 0
                || test_temp && ancestor.st_uid == 0 && ancestor.st_mode & 0o1000 != 0;
            if !owner_ok || !mode_ok {
                return Err(err(Reason::StorageUnsafe));
            }
            dir = openat(
                &dir,
                component.as_os_str(),
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| err(Reason::StorageUnsafe))?;
        }
        let stat = fstat(&dir).map_err(|_| err(Reason::StorageUnsafe))?;
        if stat.st_uid != owner || stat.st_mode & 0o7777 != 0o700 {
            return Err(err(Reason::StorageUnsafe));
        }
        Ok(Self {
            dir,
            deployment: deployment.to_owned(),
            owner,
        })
    }
    fn check_directory(&self) -> Result<()> {
        let stat = fstat(&self.dir).map_err(|_| err(Reason::StorageUnsafe))?;
        if stat.st_uid != self.owner || stat.st_mode & 0o7777 != 0o700 {
            return Err(err(Reason::StorageUnsafe));
        }
        Ok(())
    }
    pub fn lock(&self) -> Result<AllocationTransaction<'_>> {
        self.check_directory()?;
        let fd = openat(
            &self.dir,
            LOCK_NAME,
            OFlags::CREATE | OFlags::RDWR | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|_| err(Reason::StorageUnsafe))?;
        check_file(&fd, self.owner)?;
        flock(&fd, FlockOperation::NonBlockingLockExclusive).map_err(|error| {
            err(if error == Errno::WOULDBLOCK {
                Reason::LockBusy
            } else {
                Reason::StorageUnavailable
            })
        })?;
        Ok(AllocationTransaction {
            store: self,
            _lock: File::from(fd),
        })
    }
    pub fn read(&self) -> Result<Option<AllocationRecord>> {
        self.lock()?.read()
    }
}
impl AllocationTransaction<'_> {
    pub fn read(&self) -> Result<Option<AllocationRecord>> {
        self.store.check_directory()?;
        let fd = match openat(
            &self.store.dir,
            RECORD_NAME,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(Errno::NOENT) => return Ok(None),
            Err(_) => return Err(err(Reason::StorageUnsafe)),
        };
        check_file(&fd, self.store.owner)?;
        let mut bytes = Vec::new();
        File::from(fd)
            .take((MAX_RECORD_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| err(Reason::StorageUnavailable))?;
        AllocationRecord::parse(&bytes, &self.store.deployment, &[]).map(Some)
    }
    /// None creates generation 1; Some(g) commits precisely g+1. A parent-fsync
    /// failure after rename returns DurabilityUncertain: re-inspect before retrying.
    /// Shared references cannot commit: a single flock guard must not allow
    /// concurrent compare-and-swap operations through the same transaction.
    ///
    /// ```compile_fail
    /// use vprouter_core::allocation::{AllocationRecord,AllocationTransaction};
    /// fn concurrent_commit(tx: &AllocationTransaction<'_>, record: &AllocationRecord) {
    ///     std::thread::scope(|scope| {
    ///         scope.spawn(|| tx.commit(None,record));
    ///         scope.spawn(|| tx.commit(None,record));
    ///     });
    /// }
    /// ```
    pub fn commit(&mut self, expected: Option<u64>, record: &AllocationRecord) -> Result<()> {
        record.validate(&self.store.deployment, &[])?;
        let previous = self.read()?;
        if previous.as_ref().map(|r| r.generation) != expected
            || Some(record.generation) != expected.unwrap_or(0).checked_add(1)
        {
            return Err(err(Reason::GenerationConflict));
        }
        let bytes = serde_json::to_vec(record).map_err(|_| err(Reason::InvalidAllocation))?;
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(err(Reason::InvalidAllocation));
        }
        let (name, fd) = self.create_temp()?;
        let mut file = File::from(fd);
        file.write_all(&bytes)
            .map_err(|_| err(Reason::StorageUnavailable))?;
        file.sync_all()
            .map_err(|_| err(Reason::StorageUnavailable))?;
        renameat(&self.store.dir, &name, &self.store.dir, RECORD_NAME)
            .map_err(|_| err(Reason::StorageUnavailable))?;
        fsync(&self.store.dir).map_err(|_| err(Reason::DurabilityUncertain))?;
        Ok(())
    }
    fn create_temp(&self) -> Result<(String, OwnedFd)> {
        for _ in 0..16 {
            let seq = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let name = format!(".allocations.tmp-{}-{seq}", std::process::id());
            match openat(
                &self.store.dir,
                &name,
                OFlags::CREATE | OFlags::EXCL | OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            ) {
                Ok(fd) => {
                    check_file(&fd, self.store.owner)?;
                    return Ok((name, fd));
                }
                Err(Errno::EXIST) => continue,
                Err(_) => return Err(err(Reason::StorageUnavailable)),
            }
        }
        Err(err(Reason::StorageUnavailable))
    }
}
fn check_file(fd: impl AsFd, owner: u32) -> Result<()> {
    let stat = fstat(fd).map_err(|_| err(Reason::StorageUnsafe))?;
    if stat.st_uid != owner
        || stat.st_mode & 0o7777 != 0o600
        || stat.st_nlink != 1
        || FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
    {
        return Err(err(Reason::StorageUnsafe));
    }
    Ok(())
}

#[cfg(test)]
mod storage_tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink},
        sync::{Arc, Barrier},
    };
    struct TempRoot(PathBuf);
    impl TempRoot {
        fn new() -> Self {
            let n = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let p =
                std::env::temp_dir().join(format!("vprouter-core-test-{}-{n}", std::process::id()));
            fs::create_dir(&p).unwrap();
            fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
            Self(p)
        }
        fn store(&self) -> AllocationStore {
            AllocationStore::open_for_test(&self.0, "fleet").unwrap()
        }
    }
    impl Drop for TempRoot {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }
    fn record(generation: u64) -> AllocationRecord {
        AllocationRecord {
            schema_version: 2,
            deployment_id: "fleet".into(),
            generation,
            exits: vec![allocation(
                "fleet",
                "primary",
                ExitMode::Direct,
                "/state/primary".into(),
            )],
        }
    }
    fn private_file(path: &Path, bytes: &[u8]) {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        f.write_all(bytes).unwrap();
    }
    #[test]
    fn flock_excludes_an_independent_concurrent_open() {
        let root = TempRoot::new();
        let store = root.store();
        let _lock = store.lock().unwrap();
        std::thread::scope(|s| {
            let p = &root.0;
            s.spawn(move || {
                let other = AllocationStore::open_for_test(p, "fleet").unwrap();
                assert!(other.lock().is_err_and(|e| e.reason() == Reason::LockBusy));
            })
            .join()
            .unwrap();
        });
    }
    #[test]
    fn two_writers_cannot_commit_the_same_generation() {
        let root = TempRoot::new();
        let barrier = Arc::new(Barrier::new(2));
        let results = std::thread::scope(|s| {
            let mut threads = Vec::new();
            for _ in 0..2 {
                let p = &root.0;
                let b = barrier.clone();
                threads.push(s.spawn(move || {
                    let store = AllocationStore::open_for_test(p, "fleet").unwrap();
                    b.wait();
                    for _ in 0..10000 {
                        match store.lock() {
                            Ok(mut tx) => return tx.commit(None, &record(1)),
                            Err(e) if e.reason() == Reason::LockBusy => std::thread::yield_now(),
                            Err(e) => return Err(e),
                        }
                    }
                    panic!("lock did not become available");
                }));
            }
            threads
                .into_iter()
                .map(|t| t.join().unwrap())
                .collect::<Vec<_>>()
        });
        assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|r| r
                    .as_ref()
                    .is_err_and(|e| e.reason() == Reason::GenerationConflict))
                .count(),
            1
        );
        assert_eq!(root.store().read().unwrap().unwrap().generation, 1);
    }
    #[test]
    fn shared_transaction_writers_must_serialize_and_cannot_lose_an_update() {
        use std::sync::Mutex;
        let root = TempRoot::new();
        let store = root.store();
        let shared = Mutex::new(store.lock().unwrap());
        let barrier = Barrier::new(2);
        let results = std::thread::scope(|scope| {
            let mut threads = Vec::new();
            for id in ["alpha", "beta"] {
                let shared = &shared;
                let barrier = &barrier;
                threads.push(scope.spawn(move || {
                    let candidate = AllocationRecord {
                        schema_version: 2,
                        deployment_id: "fleet".into(),
                        generation: 1,
                        exits: vec![allocation(
                            "fleet",
                            id,
                            ExitMode::Direct,
                            format!("/state/{id}").into(),
                        )],
                    };
                    barrier.wait();
                    (id, shared.lock().unwrap().commit(None, &candidate))
                }));
            }
            threads
                .into_iter()
                .map(|t| t.join().unwrap())
                .collect::<Vec<_>>()
        });
        assert_eq!(results.iter().filter(|(_, r)| r.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|(_, r)| r
                    .as_ref()
                    .is_err_and(|e| e.reason() == Reason::GenerationConflict))
                .count(),
            1
        );
        let winner = results.iter().find(|(_, r)| r.is_ok()).unwrap().0;
        assert_eq!(
            shared.lock().unwrap().read().unwrap().unwrap().exits[0].exit_id,
            winner
        );
    }
    #[test]
    fn cas_and_interrupted_temp_preserve_last_commit() {
        let root = TempRoot::new();
        let store = root.store();
        {
            let mut tx = store.lock().unwrap();
            tx.commit(None, &record(1)).unwrap();
            assert!(tx.commit(None, &record(1)).is_err());
            assert!(tx.commit(Some(1), &record(3)).is_err());
        }
        let temp = root.0.join(".allocations.tmp-orphan");
        private_file(&temp, b"{incomplete");
        assert_eq!(store.read().unwrap().unwrap().generation, 1);
        store.lock().unwrap().commit(Some(1), &record(2)).unwrap();
        assert_eq!(store.read().unwrap().unwrap().generation, 2);
        assert!(temp.exists());
        let raw = fs::read(root.0.join(RECORD_NAME)).unwrap();
        assert!(AllocationRecord::parse(&raw, "fleet", &[]).is_ok());
        assert_eq!(
            fs::metadata(root.0.join(RECORD_NAME))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    #[test]
    fn symlink_components_and_record_lock_substitution_are_rejected() {
        let root = TempRoot::new();
        let target = TempRoot::new();
        symlink(&target.0, root.0.join("alias")).unwrap();
        assert!(AllocationStore::open_for_test(&root.0.join("alias"), "fleet").is_err());
        let secret = target.0.join("profile");
        private_file(&secret, b"secret");
        symlink(&secret, root.0.join("secret-alias")).unwrap();
        assert!(secure_open_read(&root.0.join("secret-alias")).is_err());
        assert!(secure_open_read(&root.0.join("alias/profile")).is_err());
        symlink(&secret, root.0.join(LOCK_NAME)).unwrap();
        assert!(root.store().lock().is_err());
        fs::remove_file(root.0.join(LOCK_NAME)).unwrap();
        symlink(&secret, root.0.join(RECORD_NAME)).unwrap();
        assert!(root.store().read().is_err());
    }
    #[test]
    fn malformed_record_and_unprivate_storage_are_rejected() {
        let root = TempRoot::new();
        private_file(&root.0.join(RECORD_NAME), b"{incomplete");
        assert!(root.store().read().is_err());
        fs::set_permissions(&root.0, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(AllocationStore::open_for_test(&root.0, "fleet").is_err());
    }
    #[test]
    fn permissions_changed_after_open_revoke_storage_access() {
        let root = TempRoot::new();
        let store = root.store();
        let mut tx = store.lock().unwrap();
        fs::set_permissions(&root.0, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(tx.commit(None, &record(1)).is_err());
        drop(tx);
        assert!(store.read().is_err());
        assert!(AllocationStore::open(&root.0, "fleet").is_err());
    }
    #[test]
    fn hardlinked_or_permissive_files_are_rejected() {
        let root = TempRoot::new();
        let store = root.store();
        store.lock().unwrap().commit(None, &record(1)).unwrap();
        fs::hard_link(root.0.join(RECORD_NAME), root.0.join("copy")).unwrap();
        assert!(store.read().is_err());
        fs::remove_file(root.0.join("copy")).unwrap();
        fs::set_permissions(root.0.join(RECORD_NAME), fs::Permissions::from_mode(0o640)).unwrap();
        assert!(store.read().is_err());
    }
}
