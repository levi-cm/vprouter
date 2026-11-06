//! Local synthetic tree only. All names are descriptor-relative and closed-set.
use super::{
    contract::{FixtureDriver, Operation},
    *,
};
use crate::allocation::{AllocationStore, AllocationTransaction};
use rustix::{
    fs::{self, AtFlags, FileType, Mode, OFlags, RenameFlags},
    io::Errno,
};
use std::{
    fs::File,
    io::{Read, Write},
    os::fd::{AsFd, OwnedFd},
    path::{Path, PathBuf},
};
const MARKER: &str = "offline-migration.fixture";
const JOURNAL: &str = "journal.json";
const PENDING: &str = ".journal.pending";
const DIR_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);
const FILE_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::NOFOLLOW)
    .union(OFlags::NONBLOCK)
    .union(OFlags::CLOEXEC);
pub struct FixtureTree {
    store: AllocationStore,
    path: PathBuf,
    // Admission custody survives lock/reinspection. O_PATH descriptors prevent
    // inode reuse; no opaque file is ever opened for data access.
    opaque: BTreeMap<String, Pin>,
    _custody: Vec<OwnedFd>,
}
struct Locked<'a> {
    tree: &'a FixtureTree,
    lease: AllocationTransaction,
    device: u64,
    head: Option<String>,
    protected: Vec<Pin>,
    expected_opaque: Option<BTreeMap<String, Pin>>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    schema: u32,
    generation: u64,
    plan: Plan,
    direction: Direction,
    completed: usize,
    terminal: Option<Outcome>,
    cleanup: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    journal: Journal,
    checksum: String,
}
// A plan must fit every future envelope, not just its standalone encoding.
// Reserve actual serialized widths for the largest counter/cursor and terminal
// fields. This is a size bound only, never a loadable or published journal.
pub(super) fn check_journal_capacity(plan: &Plan) -> Result<()> {
    Locked::journal_bytes(&Journal {
        schema: 1,
        generation: u64::MAX,
        plan: plan.clone(),
        direction: Direction::Reverse,
        completed: usize::MAX,
        terminal: Some(Outcome::RolledBackFixture),
        cleanup: false,
    })?;
    Ok(())
}
type RawBundle = (BTreeMap<String, Vec<u8>>, BTreeMap<String, Pin>);
struct Metadata {
    owner: u32,
    device: u64,
}
impl Metadata {
    fn safe(&self, fd: impl AsFd, directory: bool) -> Result<Pin> {
        let st = fs::fstat(fd).map_err(|_| Error::UnsafeTree)?;
        let kind = FileType::from_raw_mode(st.st_mode);
        if st.st_dev != self.device
            || st.st_uid != self.owner
            || st.st_mode & 0o7777 != if directory { 0o700 } else { 0o600 }
            || (if directory {
                kind != FileType::Directory
            } else {
                kind != FileType::RegularFile || st.st_nlink != 1
            })
        {
            return Err(Error::UnsafeTree);
        }
        Ok(Pin {
            device: st.st_dev,
            inode: st.st_ino,
            size: st.st_size.try_into().map_err(|_| Error::UnsafeTree)?,
            mode: st.st_mode & 0o7777,
            owner: st.st_uid,
            group: st.st_gid,
            links: st.st_nlink,
            kind: if directory {
                PinKind::Directory
            } else {
                PinKind::File
            },
        })
    }
    fn entries(&self, fd: impl AsFd) -> Result<Vec<String>> {
        self.safe(&fd, true)?;
        let mut entries = Vec::new();
        let dir = fs::Dir::read_from(fd).map_err(|_| Error::UnsafeTree)?;
        for entry in dir {
            let e = entry.map_err(|_| Error::UnsafeTree)?;
            let n = e.file_name().to_str().map_err(|_| Error::UnsafeTree)?;
            if n == "." || n == ".." {
                continue;
            }
            if entries.len() >= 32 {
                return Err(Error::UnsafeTree);
            }
            entries.push(n.into());
        }
        entries.sort();
        Ok(entries)
    }
    fn capture_opaque(&self, root: impl AsFd) -> Result<(BTreeMap<String, Pin>, Vec<OwnedFd>)> {
        let mut pins = BTreeMap::new();
        let mut held = Vec::new();
        self.opaque_entry(root, "opaque", "/", 0, &mut pins, &mut held)?;
        Ok((pins, held))
    }
    fn opaque_entry(
        &self,
        parent: impl AsFd,
        name: &str,
        path: &str,
        depth: usize,
        pins: &mut BTreeMap<String, Pin>,
        held: &mut Vec<OwnedFd>,
    ) -> Result<()> {
        if depth > MAX_OPAQUE_DEPTH || pins.len() >= MAX_OPAQUE || path.len() > 256 {
            return Err(Error::UnsafeTree);
        }
        let fd = fs::openat(
            &parent,
            name,
            OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| Error::UnsafeTree)?;
        let st = fs::fstat(&fd).map_err(|_| Error::UnsafeTree)?;
        let directory = FileType::from_raw_mode(st.st_mode) == FileType::Directory;
        let pin = self.safe(&fd, directory)?;
        if (path == "/" || path == "state") && !directory
            || path == "profile.wg" && directory
            || pins
                .values()
                .any(|p: &Pin| (p.device, p.inode) == (pin.device, pin.inode))
        {
            return Err(Error::UnsafeTree);
        }
        pins.insert(path.into(), pin.clone());
        if directory {
            // Only directories get a readable descriptor, solely for getdents.
            // All file leaves retain metadata-only O_PATH custody.
            let dir = fs::openat(&parent, name, DIR_FLAGS, Mode::empty())
                .map_err(|_| Error::UnsafeTree)?;
            if self.safe(&dir, true)? != pin {
                return Err(Error::UnsafeTree);
            }
            let entries = self.entries(&dir)?;
            if path == "/" && entries != ["profile.wg", "state"] {
                return Err(Error::UnsafeTree);
            }
            for child in &entries {
                super::path(&format!("/{child}"))?;
                if child.len() > 63 {
                    return Err(Error::UnsafeTree);
                }
                let next = if path == "/" {
                    child.clone()
                } else {
                    format!("{path}/{child}")
                };
                self.opaque_entry(&dir, child, &next, depth + 1, pins, held)?;
            }
            if self.entries(&dir)? != entries || self.safe(&dir, true)? != pin {
                return Err(Error::Drift);
            }
        }
        let named = fs::openat(
            &parent,
            name,
            OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| Error::UnsafeTree)?;
        if self.safe(&named, directory)? != pin || self.safe(&fd, directory)? != pin {
            return Err(Error::Drift);
        }
        held.push(fd);
        Ok(())
    }
}
impl FixtureTree {
    pub fn open(path: &Path) -> Result<Self> {
        super::path(path.to_str().ok_or(Error::Invalid)?)?;
        // Same private directory, ancestor checks and flock as allocation preparation.
        let store = AllocationStore::open_owned(
            path,
            "migration-fixture",
            rustix::process::geteuid().as_raw(),
            true,
        )
        .map_err(|_| Error::UnsafeTree)?;
        let metadata = Metadata {
            owner: rustix::process::geteuid().as_raw(),
            device: fs::fstat(store.directory())
                .map_err(|_| Error::UnsafeTree)?
                .st_dev,
        };
        let (opaque, custody) = metadata.capture_opaque(store.directory())?;
        for name in [MARKER, ".allocations.lock"] {
            let fd = fs::openat(
                store.directory(),
                name,
                OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| Error::UnsafeTree)?;
            let pin = metadata.safe(fd, false)?;
            if opaque
                .values()
                .any(|p| (p.device, p.inode) == (pin.device, pin.inode))
            {
                return Err(Error::UnsafeTree);
            }
        }
        Ok(Self {
            store,
            path: path.into(),
            opaque,
            _custody: custody,
        })
    }
    fn lock(&self, original: Option<&BTreeMap<String, Pin>>) -> Result<Locked<'_>> {
        let protected: Vec<Pin> = self
            .opaque
            .values()
            .chain(original.into_iter().flat_map(|pins| pins.values()))
            .cloned()
            .collect();
        let excluded = protected
            .iter()
            .map(|pin| (pin.device, pin.inode))
            .collect::<Vec<_>>();
        let lease = self.store.lock_existing(&excluded).map_err(|e| {
            if e.reason() == crate::reason::Reason::LockBusy {
                Error::Busy
            } else {
                Error::UnsafeTree
            }
        })?;
        let device = fs::fstat(lease.directory())
            .map_err(|_| Error::UnsafeTree)?
            .st_dev;
        let locked = Locked {
            tree: self,
            lease,
            device,
            head: None,
            protected,
            expected_opaque: Some(self.opaque.clone()),
        };
        // Repeat admission after taking the lock; a pre-lock snapshot grants no
        // mutation authority. Recovery also excludes original plan pins above.
        locked.check()?;
        locked.metadata_at(locked.root(), MARKER, false)?;
        for forbidden in ["allocations.json", "fleet-preparation.json"] {
            if locked.exists(locked.root(), forbidden)? {
                return Err(Error::UnsafeTree);
            }
        }
        Ok(locked)
    }
    pub fn inspect(&self) -> Result<Inspection> {
        self.lock(None)?.inspection()
    }
    pub fn apply(
        &self,
        plan: &Plan,
        driver: &mut impl FixtureDriver,
        fault: &mut impl Fault,
    ) -> Result<Outcome> {
        plan.validate()?;
        let mut locked = self.lock(Some(&plan.inspection.opaque))?;
        locked.bind_opaque(plan)?;
        locked.marker()?;
        if let Some(j) = locked.load(plan)? {
            return match j.terminal {
                Some(Outcome::CommittedFixture) => {
                    locked.verify_terminal(plan, Outcome::CommittedFixture)?;
                    Ok(Outcome::CommittedFixture)
                }
                _ => Err(Error::Terminal),
            };
        }
        if locked.exists(locked.root(), PENDING)? || locked.exists(locked.root(), "staged")? {
            return Err(Error::Terminal);
        }
        if locked.inspection()?.fingerprint != plan.inspection.fingerprint {
            return Err(Error::Drift);
        }
        let mut journal = Journal {
            schema: 1,
            generation: 0,
            plan: plan.clone(),
            direction: Direction::Forward,
            completed: 0,
            terminal: None,
            cleanup: false,
        };
        locked.save(&mut journal, fault)?;
        locked.run(journal, driver, fault)
    }
    pub fn resume(
        &self,
        plan: &Plan,
        driver: &mut impl FixtureDriver,
        fault: &mut impl Fault,
    ) -> Result<Outcome> {
        self.recover(plan, Direction::Forward, driver, fault)
    }
    pub fn rollback(
        &self,
        plan: &Plan,
        driver: &mut impl FixtureDriver,
        fault: &mut impl Fault,
    ) -> Result<Outcome> {
        self.recover(plan, Direction::Reverse, driver, fault)
    }
    fn recover(
        &self,
        plan: &Plan,
        direction: Direction,
        driver: &mut impl FixtureDriver,
        fault: &mut impl Fault,
    ) -> Result<Outcome> {
        plan.validate()?;
        let mut locked = self.lock(Some(&plan.inspection.opaque))?;
        locked.bind_opaque(plan)?;
        locked.marker()?;
        let stored = locked.load(plan)?;
        if let Some(j) = &stored
            && let Some(outcome) = j.terminal
            && (outcome == Outcome::Offline
                || outcome == Outcome::RolledBackFixture
                || direction == Direction::Forward)
        {
            locked.verify_terminal(plan, outcome)?;
            return Ok(outcome);
        }
        locked.remove_pending(plan, stored.as_ref(), fault)?;
        let mut journal = match stored {
            Some(j) => j,
            None => {
                if locked.inspection()?.fingerprint != plan.inspection.fingerprint {
                    return Err(Error::Drift);
                }
                Journal {
                    schema: 1,
                    generation: 0,
                    plan: plan.clone(),
                    direction,
                    completed: 0,
                    terminal: None,
                    cleanup: false,
                }
            }
        };
        if journal.cleanup {
            return locked.offline(&mut journal, driver, fault);
        }
        if direction == Direction::Reverse && journal.direction == Direction::Forward {
            journal.direction = Direction::Reverse;
            journal.completed = 0;
            journal.terminal = None;
        }
        locked.save(&mut journal, fault)?;
        locked.run(journal, driver, fault)
    }
}
impl Locked<'_> {
    fn root(&self) -> &OwnedFd {
        self.lease.directory()
    }
    fn check(&self) -> Result<()> {
        self.lease.check_lock().map_err(|_| Error::UnsafeTree)?;
        let named = AllocationStore::open_owned(
            &self.tree.path,
            "migration-fixture",
            self.lease.owner(),
            true,
        )
        .map_err(|_| Error::UnsafeTree)?;
        let a = fs::fstat(self.root()).map_err(|_| Error::UnsafeTree)?;
        let b = fs::fstat(named.directory()).map_err(|_| Error::UnsafeTree)?;
        if (a.st_dev, a.st_ino) != (b.st_dev, b.st_ino) {
            return Err(Error::UnsafeTree);
        }
        if let Some(expected) = &self.expected_opaque
            && self.opaque()?.ne(expected)
        {
            return Err(Error::Drift);
        }
        Ok(())
    }
    fn bind_opaque(&mut self, plan: &Plan) -> Result<()> {
        self.protected
            .extend(plan.inspection.opaque.values().cloned());
        self.expected_opaque = Some(plan.inspection.opaque.clone());
        self.check()
    }
    fn public_pin(&self, fd: impl AsFd, directory: bool) -> Result<Pin> {
        let pin = self.safe(fd, directory)?;
        if self
            .protected
            .iter()
            .any(|p| (p.device, p.inode) == (pin.device, pin.inode))
        {
            return Err(Error::UnsafeTree);
        }
        Ok(pin)
    }
    fn safe(&self, fd: impl AsFd, directory: bool) -> Result<Pin> {
        self.metadata().safe(fd, directory)
    }
    fn metadata(&self) -> Metadata {
        Metadata {
            owner: self.lease.owner(),
            device: self.device,
        }
    }
    fn exists(&self, dir: impl AsFd, name: &str) -> Result<bool> {
        match fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(_) => Ok(true),
            Err(Errno::NOENT) => Ok(false),
            Err(_) => Err(Error::UnsafeTree),
        }
    }
    fn metadata_at(&self, parent: impl AsFd, name: &str, directory: bool) -> Result<Pin> {
        let fd = fs::openat(
            parent,
            name,
            OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| Error::UnsafeTree)?;
        self.public_pin(fd, directory)
    }
    fn public_open(&self, parent: impl AsFd, name: &str, directory: bool) -> Result<OwnedFd> {
        // Exclude protected identities BEFORE opening data, then recheck the
        // actual NOFOLLOW descriptor. Metadata alone is never a read license.
        let before = self.metadata_at(&parent, name, directory)?;
        let fd = fs::openat(
            &parent,
            name,
            if directory { DIR_FLAGS } else { FILE_FLAGS },
            Mode::empty(),
        )
        .map_err(|_| Error::UnsafeTree)?;
        if self.public_pin(&fd, directory)? != before {
            return Err(Error::UnsafeTree);
        }
        self.named(&parent, name, &fd, directory)?;
        Ok(fd)
    }
    fn named(&self, parent: impl AsFd, name: &str, fd: impl AsFd, directory: bool) -> Result<()> {
        if self.metadata_at(parent, name, directory)? != self.public_pin(fd, directory)? {
            return Err(Error::UnsafeTree);
        }
        Ok(())
    }
    fn dir(&self, parent: impl AsFd, name: &str) -> Result<OwnedFd> {
        self.public_open(parent, name, true)
    }
    fn entries(&self, fd: impl AsFd) -> Result<Vec<String>> {
        self.metadata().entries(fd)
    }
    fn read_at(&self, dir: impl AsFd, name: &str, limit: usize) -> Result<Option<Vec<u8>>> {
        self.read_public(dir, name, limit)
            .map(|v| v.map(|(bytes, _)| bytes))
    }
    fn read_public(
        &self,
        dir: impl AsFd,
        name: &str,
        limit: usize,
    ) -> Result<Option<(Vec<u8>, Pin)>> {
        if !self.exists(&dir, name)? {
            return Ok(None);
        }
        let fd = self.public_open(&dir, name, false)?;
        self.check()?;
        let before = self.public_pin(&fd, false)?;
        if before.size > limit as u64 {
            return Err(Error::UnsafeTree);
        }
        let mut bytes = Vec::new();
        let mut file = File::from(fd);
        (&mut file)
            .take(limit as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| Error::UnsafeTree)?;
        let after = self.public_pin(&file, false)?;
        let named = self.public_open(dir, name, false)?;
        if before != after
            || before != self.public_pin(named, false)?
            || bytes.len() > limit
            || bytes.len() as u64 != before.size
        {
            return Err(Error::UnsafeTree);
        }
        Ok(Some((bytes, before)))
    }
    fn read_root(&self, name: &str) -> Result<Option<Vec<u8>>> {
        self.read_at(self.root(), name, MAX_JSON)
    }
    fn marker(&self) -> Result<()> {
        if self.read_root(MARKER)?.as_deref() != Some(b"synthetic-only-v1\n") {
            return Err(Error::UnsafeTree);
        }
        Ok(())
    }
    fn opaque(&self) -> Result<BTreeMap<String, Pin>> {
        self.metadata()
            .capture_opaque(self.root())
            .map(|(pins, _)| pins)
    }
    fn bundle(&self, slot: &str, inventory: &Inventory) -> Result<(Bundle, BTreeMap<String, Pin>)> {
        let (raw, pins) = self.raw_bundle(slot, inventory)?;
        let files = raw
            .into_iter()
            .map(|(name, bytes)| Ok((name, String::from_utf8(bytes).map_err(|_| Error::Invalid)?)))
            .collect::<Result<_>>()?;
        Ok((Bundle { files }, pins))
    }
    fn raw_bundle(&self, slot: &str, inventory: &Inventory) -> Result<RawBundle> {
        let dir = self.dir(self.root(), slot)?;
        let mut pins = BTreeMap::from([("/".into(), self.safe(&dir, true)?)]);
        let mut files = BTreeMap::new();
        let allowed: std::collections::BTreeSet<&str> = ASSETS
            .iter()
            .copied()
            .chain(["config.json", "allocations.json", "wrappers.json"])
            .chain(inventory.dependencies.iter().map(|d| d.hook.as_str()))
            .collect();
        for n in self.entries(&dir)? {
            if n == "host" {
                let host = self.dir(&dir, "host")?;
                pins.insert("host/".into(), self.safe(&host, true)?);
                for child in self.entries(&host)? {
                    let p = format!("host/{child}");
                    if !allowed.contains(p.as_str()) {
                        return Err(Error::UnsafeTree);
                    }
                    let (data, pin) = self
                        .read_public(&host, &child, MAX_FILE)?
                        .ok_or(Error::UnsafeTree)?;
                    pins.insert(p.clone(), pin);
                    files.insert(p, data);
                }
            } else {
                if !allowed.contains(n.as_str()) {
                    return Err(Error::UnsafeTree);
                }
                let (data, pin) = self
                    .read_public(&dir, &n, MAX_FILE)?
                    .ok_or(Error::UnsafeTree)?;
                pins.insert(n.clone(), pin);
                files.insert(n, data);
            }
        }
        if files.values().map(Vec::len).sum::<usize>() > MAX_BUNDLE {
            return Err(Error::Invalid);
        }
        Ok((files, pins))
    }
    fn inspection(&self) -> Result<Inspection> {
        self.check()?;
        self.marker()?;
        let opaque = self.opaque()?;
        let raw = self.read_root("inventory.json")?.ok_or(Error::UnsafeTree)?;
        let inventory = Inventory::parse(&raw)?;
        let (bundle, mut public_pins) = self.bundle("current", &inventory)?;
        let fd = self.public_open(self.root(), "inventory.json", false)?;
        public_pins.insert("inventory.json".into(), self.safe(fd, false)?);
        let mut i = Inspection {
            inventory,
            inventory_bytes: String::from_utf8(raw).map_err(|_| Error::Invalid)?,
            bundle,
            public_pins,
            opaque,
            fingerprint: String::new(),
        };
        i.fingerprint = i.digest()?;
        self.check()?;
        Ok(i)
    }
    fn io<T>(
        &self,
        fault: &mut impl Fault,
        step: IoStep,
        op: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        fault.boundary(step, Edge::Before)?;
        self.check()?;
        let result = op()?;
        fault.boundary(step, Edge::After)?;
        self.check()?;
        Ok(result)
    }
    fn sync(&self, fd: impl AsFd, directory: bool, fault: &mut impl Fault) -> Result<()> {
        self.io(
            fault,
            if directory {
                IoStep::SyncDirectory
            } else {
                IoStep::SyncFile
            },
            || {
                self.public_pin(&fd, directory)?;
                fs::fsync(fd).map_err(|_| Error::Interrupted)
            },
        )
    }
    fn create_dir(&self, parent: impl AsFd, name: &str, fault: &mut impl Fault) -> Result<()> {
        self.io(fault, IoStep::CreateDirectory, || {
            fs::mkdirat(parent, name, Mode::RWXU).map_err(|_| Error::Interrupted)
        })
    }
    fn write(
        &self,
        parent: impl AsFd,
        name: &str,
        bytes: &[u8],
        fault: &mut impl Fault,
    ) -> Result<()> {
        let fd = self.io(fault, IoStep::CreateFile, || {
            fs::openat(
                &parent,
                name,
                OFlags::CREATE | OFlags::EXCL | OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            )
            .map_err(|_| Error::Interrupted)
        })?;
        let mut file = File::from(fd);
        for chunk in bytes.chunks(4096) {
            self.io(fault, IoStep::Write, || {
                self.public_pin(&file, false)?;
                let named = fs::statat(&parent, name, AtFlags::SYMLINK_NOFOLLOW)
                    .map_err(|_| Error::UnsafeTree)?;
                let opened = fs::fstat(&file).map_err(|_| Error::UnsafeTree)?;
                if (named.st_dev, named.st_ino) != (opened.st_dev, opened.st_ino) {
                    return Err(Error::UnsafeTree);
                }
                // One bounded write per boundary, so a short write leaves a prefix and
                // cannot be hidden by write_all's internal retries.
                if file.write(chunk).map_err(|_| Error::Interrupted)? != chunk.len() {
                    return Err(Error::Interrupted);
                }
                Ok(())
            })?;
        }
        self.sync(&file, false, fault)
    }
    fn remove_file(
        &self,
        parent: impl AsFd,
        name: &str,
        expected: &[u8],
        fault: &mut impl Fault,
    ) -> Result<()> {
        self.io(fault, IoStep::RemoveFile, || {
            let (bytes, pin) = self
                .read_public(&parent, name, MAX_JSON)?
                .ok_or(Error::UnsafeTree)?;
            if bytes != expected {
                return Err(Error::Drift);
            }
            let fd = self.public_open(&parent, name, false)?;
            if self.public_pin(&fd, false)? != pin {
                return Err(Error::UnsafeTree);
            }
            self.named(&parent, name, &fd, false)?;
            fs::unlinkat(&parent, name, AtFlags::empty()).map_err(|_| Error::Interrupted)
        })
    }
    fn journal_bytes(j: &Journal) -> Result<Vec<u8>> {
        encode(&Envelope {
            checksum: hash(encode(j)?),
            journal: j.clone(),
        })
    }
    fn pending_prefix(&self, bytes: &[u8], plan: &Plan, stored: Option<&Journal>) -> Result<bool> {
        let base = stored.cloned().unwrap_or(Journal {
            schema: 1,
            generation: 0,
            plan: plan.clone(),
            direction: Direction::Forward,
            completed: 0,
            terminal: None,
            cleanup: false,
        });
        let mut candidates = vec![base.clone()];
        if stored.is_some() && base.terminal.is_none() {
            if !base.cleanup && base.completed < plan.operations(base.direction).len() {
                let mut next = base.clone();
                next.completed += 1;
                candidates.push(next);
            }
            let mut cleanup = base.clone();
            cleanup.cleanup = true;
            candidates.push(cleanup.clone());
            cleanup.terminal = Some(Outcome::Offline);
            candidates.push(cleanup);
            if base.completed == plan.operations(base.direction).len() {
                let mut terminal = base.clone();
                terminal.terminal = Some(if base.direction == Direction::Forward {
                    Outcome::CommittedFixture
                } else {
                    Outcome::RolledBackFixture
                });
                candidates.push(terminal);
            }
        }
        if !base.cleanup && base.direction == Direction::Forward {
            let mut reverse = base.clone();
            reverse.direction = Direction::Reverse;
            reverse.completed = 0;
            reverse.terminal = None;
            candidates.push(reverse);
        }
        for mut j in candidates {
            j.generation = base.generation.checked_add(1).ok_or(Error::Invalid)?;
            if Self::journal_bytes(&j)?.starts_with(bytes) {
                return Ok(true);
            }
        }
        Ok(false)
    }
    fn remove_pending(
        &self,
        plan: &Plan,
        stored: Option<&Journal>,
        fault: &mut impl Fault,
    ) -> Result<()> {
        if let Some(bytes) = self.read_root(PENDING)? {
            if !self.pending_prefix(&bytes, plan, stored)? {
                return Err(Error::Drift);
            }
            self.remove_file(self.root(), PENDING, &bytes, fault)?;
            self.sync(self.root(), true, fault)?;
        }
        Ok(())
    }
    fn load(&mut self, plan: &Plan) -> Result<Option<Journal>> {
        let Some(bytes) = self.read_root(JOURNAL)? else {
            return Ok(None);
        };
        let e: Envelope = decode(&bytes)?;
        if e.checksum != hash(encode(&e.journal)?)
            || e.journal.schema != 1
            || e.journal.generation == 0
            || e.journal.plan.fingerprint != plan.fingerprint
            || encode(&e.journal.plan)? != plan.encode()?
        {
            return Err(Error::Invalid);
        }
        let j = e.journal;
        let n = plan.operations(j.direction).len();
        if j.completed > n
            || match j.terminal {
                Some(Outcome::CommittedFixture) => {
                    j.cleanup || j.direction != Direction::Forward || j.completed != n
                }
                Some(Outcome::RolledBackFixture) => {
                    j.cleanup || j.direction != Direction::Reverse || j.completed != n
                }
                Some(Outcome::Offline) => !j.cleanup,
                None => false,
            }
        {
            return Err(Error::Invalid);
        }
        self.head = Some(hash(bytes));
        Ok(Some(j))
    }
    fn head_matches(&self) -> Result<()> {
        if self.read_root(JOURNAL)?.map(hash) != self.head {
            return Err(Error::Drift);
        }
        Ok(())
    }
    fn save(&mut self, j: &mut Journal, fault: &mut impl Fault) -> Result<()> {
        self.head_matches()?;
        j.generation = j.generation.checked_add(1).ok_or(Error::Invalid)?;
        let bytes = Self::journal_bytes(j)?;
        self.write(self.root(), PENDING, &bytes, fault)?;
        self.io(fault, IoStep::PublishJournal, || {
            self.head_matches()?;
            let named = self.read_root(PENDING)?.ok_or(Error::UnsafeTree)?;
            if named != bytes {
                return Err(Error::Drift);
            }
            if let Some(outcome) = j.terminal {
                // A last-boundary public change must not first be committed
                // and only then rejected by the post-publication check.
                self.verify_terminal(&j.plan, outcome)?;
            }
            fs::renameat_with(
                self.root(),
                PENDING,
                self.root(),
                JOURNAL,
                if self.head.is_none() {
                    RenameFlags::NOREPLACE
                } else {
                    RenameFlags::empty()
                },
            )
            .map_err(|_| Error::Interrupted)
        })?;
        self.sync(self.root(), true, fault)?;
        self.head = Some(hash(bytes));
        Ok(())
    }
    fn clear_stage(&self, plan: &Plan, fault: &mut impl Fault) -> Result<()> {
        // Every surviving byte must be an engine-planned prefix. Interrupted
        // UTF-8 is raw bytes here, never a reason to strand a valid transaction.
        let (raw, _) = self.raw_bundle("staged", &plan.inspection.inventory)?;
        for (name, bytes) in &raw {
            if !plan
                .new
                .files
                .get(name)
                .is_some_and(|s| s.as_bytes().starts_with(bytes))
            {
                return Err(Error::Drift);
            }
        }
        let dir = self.dir(self.root(), "staged")?;
        for name in self.entries(&dir)? {
            if name == "host" {
                let host = self.dir(&dir, "host")?;
                for child in self.entries(&host)? {
                    let expected = raw.get(&format!("host/{child}")).ok_or(Error::Drift)?;
                    self.remove_file(&host, &child, expected, fault)?;
                }
                self.sync(&host, true, fault)?;
                self.io(fault, IoStep::RemoveDirectory, || {
                    self.named(&dir, "host", &host, true)?;
                    fs::unlinkat(&dir, "host", AtFlags::REMOVEDIR).map_err(|_| Error::Interrupted)
                })?;
            } else {
                self.remove_file(&dir, &name, raw.get(&name).ok_or(Error::Drift)?, fault)?;
            }
        }
        self.sync(&dir, true, fault)?;
        self.io(fault, IoStep::RemoveDirectory, || {
            self.named(self.root(), "staged", &dir, true)?;
            fs::unlinkat(self.root(), "staged", AtFlags::REMOVEDIR).map_err(|_| Error::Interrupted)
        })?;
        self.sync(self.root(), true, fault)
    }
    fn sync_stage(&self, inventory: &Inventory, fault: &mut impl Fault) -> Result<()> {
        let dir = self.dir(self.root(), "staged")?;
        for n in self.entries(&dir)? {
            if n == "host" {
                let host = self.dir(&dir, "host")?;
                for child in self.entries(&host)? {
                    let fd = self.public_open(&host, &child, false)?;
                    self.sync(fd, false, fault)?;
                }
                self.sync(host, true, fault)?;
            } else {
                let fd = self.public_open(&dir, &n, false)?;
                self.sync(fd, false, fault)?;
            }
        }
        self.bundle("staged", inventory)?;
        self.sync(dir, true, fault)?;
        self.sync(self.root(), true, fault)
    }
    fn stage(&self, plan: &Plan, fault: &mut impl Fault) -> Result<()> {
        if self.exists(self.root(), "staged")? {
            let (raw, _) = self.raw_bundle("staged", &plan.inspection.inventory)?;
            if raw.len() == plan.new.files.len()
                && raw.iter().all(|(name, bytes)| {
                    plan.new
                        .files
                        .get(name)
                        .is_some_and(|text| text.as_bytes() == bytes)
                })
            {
                return self.sync_stage(&plan.inspection.inventory, fault);
            }
            self.clear_stage(plan, fault)?;
        }
        self.create_dir(self.root(), "staged", fault)?;
        let dir = self.dir(self.root(), "staged")?;
        self.create_dir(&dir, "host", fault)?;
        let host = self.dir(&dir, "host")?;
        for (name, content) in &plan.new.files {
            if let Some(child) = name.strip_prefix("host/") {
                self.write(&host, child, content.as_bytes(), fault)?;
            } else {
                self.write(&dir, name, content.as_bytes(), fault)?;
            }
        }
        self.sync_stage(&plan.inspection.inventory, fault)
    }
    fn check_inputs(&self, plan: &Plan) -> Result<Bundle> {
        let observed = self.inspection()?;
        if observed.inventory_bytes != plan.inspection.inventory_bytes
            || observed.public_pins.get("inventory.json")
                != plan.inspection.public_pins.get("inventory.json")
            || observed.opaque != plan.inspection.opaque
        {
            return Err(Error::Drift);
        }
        if observed.bundle == plan.inspection.bundle {
            if observed.public_pins != plan.inspection.public_pins {
                return Err(Error::Drift);
            }
        } else if observed.bundle != plan.new {
            return Err(Error::Drift);
        }
        Ok(observed.bundle)
    }
    fn exchange(&self, plan: &Plan, direction: Direction, fault: &mut impl Fault) -> Result<()> {
        let current = self.check_inputs(plan)?;
        let desired = if direction == Direction::Forward {
            &plan.new
        } else {
            &plan.inspection.bundle
        };
        if &current != desired {
            if self.bundle("staged", &plan.inspection.inventory)?.0 != *desired {
                return Err(Error::Drift);
            }
            // One syscall exchanges REAL directories, never a two-rename gap.
            self.io(fault, IoStep::ExchangeRelease, || {
                if self.check_inputs(plan)? != current
                    || self.bundle("staged", &plan.inspection.inventory)?.0 != *desired
                {
                    return Err(Error::Drift);
                }
                fs::renameat_with(
                    self.root(),
                    "current",
                    self.root(),
                    "staged",
                    RenameFlags::EXCHANGE,
                )
                .map_err(|_| Error::Interrupted)
            })?;
        }
        // Repeat parent fsync even if death occurred after exchange but before sync.
        self.sync(self.root(), true, fault)
    }
    fn verify_terminal(&self, plan: &Plan, outcome: Outcome) -> Result<()> {
        if outcome == Outcome::Offline {
            return Ok(());
        }
        let actual = self.check_inputs(plan).map_err(|_| Error::Drift)?;
        let expected = if outcome == Outcome::CommittedFixture {
            &plan.new
        } else {
            &plan.inspection.bundle
        };
        if &actual != expected {
            return Err(Error::Drift);
        }
        Ok(())
    }
    fn offline(
        &mut self,
        j: &mut Journal,
        driver: &mut impl FixtureDriver,
        fault: &mut impl Fault,
    ) -> Result<Outcome> {
        // Persist retry-only intent before cleanup. No subsequent recovery may
        // start a service while any cleanup obligation remains unresolved.
        if !j.cleanup {
            j.cleanup = true;
            self.save(j, fault)?;
        }
        let obligations = j.plan.obligations(j.direction);
        let quarantine = &obligations[0];
        let quarantined = self
            .io(fault, IoStep::Lifecycle, || Ok(driver.perform(quarantine)))?
            .is_ok_and(|r| j.plan.accepts(quarantine, &r));
        if !quarantined {
            return Err(Error::Offline);
        }
        let mut complete = true;
        for obligation in obligations.iter().skip(1) {
            if matches!(obligation.action, contract::Action::StoppedStateRetained {}) {
                break;
            }
            // Adapter failures must not suppress scoped stop or all-user checks.
            let accepted = self
                .io(fault, IoStep::Lifecycle, || Ok(driver.perform(obligation)))?
                .is_ok_and(|r| j.plan.accepts(obligation, &r));
            complete &= accepted;
        }
        if !complete {
            return Err(Error::Offline);
        }
        j.terminal = Some(Outcome::Offline);
        self.save(j, fault)?;
        Ok(Outcome::Offline)
    }
    fn run(
        &mut self,
        mut j: Journal,
        driver: &mut impl FixtureDriver,
        fault: &mut impl Fault,
    ) -> Result<Outcome> {
        let operations = j.plan.operations(j.direction);
        // Every resume repeats the entire lifecycle contract. A completed journal
        // step is a durability cursor, never permission to skip current stop,
        // identity/server verification, rename, or restart obligations.
        for (index, operation) in operations.iter().enumerate() {
            if self.check_inputs(&j.plan).is_err() {
                return self.offline(&mut j, driver, fault);
            }
            match operation {
                Operation::Observe(o) => {
                    match self.io(fault, IoStep::Lifecycle, || Ok(driver.perform(o)))? {
                        Ok(r) if j.plan.accepts(o, &r) => {}
                        _ => return self.offline(&mut j, driver, fault),
                    }
                }
                Operation::Stage => {
                    if self.check_inputs(&j.plan)? == j.plan.new {
                        if self.bundle("staged", &j.plan.inspection.inventory)?.0
                            != j.plan.inspection.bundle
                        {
                            return self.offline(&mut j, driver, fault);
                        }
                    } else {
                        self.stage(&j.plan, fault)?;
                    }
                }
                Operation::Exchange => self.exchange(&j.plan, j.direction, fault)?,
            }
            if index >= j.completed {
                j.completed = index + 1;
                self.save(&mut j, fault)?;
            }
        }
        if self.check_inputs(&j.plan).is_err() {
            return self.offline(&mut j, driver, fault);
        }
        j.terminal = Some(if j.direction == Direction::Forward {
            Outcome::CommittedFixture
        } else {
            Outcome::RolledBackFixture
        });
        self.save(&mut j, fault)?;
        let outcome = j.terminal.expect("assigned terminal outcome");
        self.verify_terminal(&j.plan, outcome)?;
        Ok(outcome)
    }
}
impl FixtureTree {
    pub fn execute_json(
        &self,
        bytes: &[u8],
        driver: &mut impl FixtureDriver,
        fault: &mut impl Fault,
    ) -> Result<Vec<u8>> {
        let data = match Command::parse(bytes)? {
            Command::Inspect {} => {
                serde_json::to_value(self.inspect()?).map_err(|_| Error::Invalid)?
            }
            Command::Plan { request } => {
                serde_json::to_value(self.inspect()?.plan(request)?).map_err(|_| Error::Invalid)?
            }
            Command::Apply { plan } => serde_json::to_value(self.apply(&plan, driver, fault)?)
                .map_err(|_| Error::Invalid)?,
            Command::Resume { plan } => serde_json::to_value(self.resume(&plan, driver, fault)?)
                .map_err(|_| Error::Invalid)?,
            Command::Rollback { plan } => {
                serde_json::to_value(self.rollback(&plan, driver, fault)?)
                    .map_err(|_| Error::Invalid)?
            }
        };
        encode(
            &serde_json::json!({"scope":"synthetic_fixture_only","client_coverage":"unverified","quarantine":"required","data":data}),
        )
    }
}
