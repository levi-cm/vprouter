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
    retirement: Option<Drain>,
}
/// An original-object stop target. Only a durable Retiring permit can request
/// this handle; it contains no path-based or caller-PID signal authority.
pub(super) struct StopTarget {
    creator: u32,
    inventory: super::inventory::Registration,
    parent: OwnedFd,
    group: OwnedFd,
    kill: OwnedFd,
    parent_id: Identity,
    group_id: Identity,
    kill_id: Identity,
    name: String,
}
impl StopTarget {
    pub(super) fn verify(&self) -> Result<()> {
        if self.creator != std::process::id()
            || ![&self.parent, &self.group, &self.kill]
                .iter()
                .all(|fd| self.inventory.contains(fd.as_fd()))
            || Identity::of(&self.parent)? != self.parent_id
            || Identity::of(&self.group)? != self.group_id
            || Identity::of(&self.kill)? != self.kill_id
        {
            return Err(Error::CgroupMismatch);
        }
        let group = fs::statat(
            &self.parent,
            self.name.as_str(),
            fs::AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(|_| Error::CgroupMismatch)?;
        let kill = fs::statat(&self.group, "cgroup.kill", fs::AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| Error::CgroupMismatch)?;
        if (group.st_dev, group.st_ino) != (self.group_id.dev, self.group_id.ino)
            || (kill.st_dev, kill.st_ino) != (self.kill_id.dev, self.kill_id.ino)
            || kill.st_mode & libc::S_IFMT != libc::S_IFREG
            || fs::fstatfs(&self.kill)
                .map_err(|_| Error::CgroupMismatch)?
                .f_type as u64
                != 0x63677270
            || fs::fstatfs(&self.group)
                .map_err(|_| Error::CgroupMismatch)?
                .f_type as u64
                != 0x63677270
        {
            return Err(Error::CgroupMismatch);
        }
        Ok(())
    }
    pub(super) fn descriptor(&self) -> std::os::fd::BorrowedFd<'_> {
        self.kill.as_fd()
    }
    pub(super) fn into_retained(self) -> (Vec<OwnedFd>, super::inventory::Registration) {
        (vec![self.parent, self.group, self.kill], self.inventory)
    }
}
/// Original producer pins and preopened read handles for the fixed retirement
/// cleanup actor. No pathname or descriptor supplied over IPC can construct it.
pub(super) struct CleanupTarget {
    creator: u32,
    inventory: super::inventory::Registration,
    parent: OwnedFd,
    group: OwnedFd,
    events: OwnedFd,
    procs: OwnedFd,
    identities: [Identity; 4],
    modes: [u32; 4],
    name: String,
}
impl CleanupTarget {
    pub(super) fn descriptors(&self) -> [std::os::fd::BorrowedFd<'_>; 4] {
        [
            self.parent.as_fd(),
            self.group.as_fd(),
            self.events.as_fd(),
            self.procs.as_fd(),
        ]
    }
    pub(super) fn verify_parent(&self) -> Result<()> {
        if self.creator != std::process::id()
            || !self
                .descriptors()
                .iter()
                .all(|fd| self.inventory.contains(*fd))
        {
            return Err(Error::OwnershipMismatch);
        }
        self.verify_empty_native()
    }
    pub(super) fn unlink_native(&self, deadline: f64) -> Result<()> {
        self.verify_empty_native()?;
        let now = vprouter_core::health::boot_seconds();
        if !now.is_finite() || now >= deadline || deadline - now > 2. {
            return Err(Error::Deadline);
        }
        fs::unlinkat(&self.parent, self.name.as_str(), fs::AtFlags::REMOVEDIR)
            .map_err(|_| Error::CgroupMismatch)?;
        let now = vprouter_core::health::boot_seconds();
        if !now.is_finite() || now >= deadline {
            return Err(Error::Deadline);
        }
        if !matches!(
            fs::statat(
                &self.parent,
                self.name.as_str(),
                fs::AtFlags::SYMLINK_NOFOLLOW,
            ),
            Err(rustix::io::Errno::NOENT)
        ) || Identity::of(&self.parent)? != self.identities[0]
            || Identity::of(&self.group)? != self.identities[1]
            || fs::fstatfs(&self.group)
                .map_err(|_| Error::CgroupMismatch)?
                .f_type as u64
                != 0x63677270
        {
            return Err(Error::CgroupMismatch);
        }
        let mut byte = [0u8; 1];
        for fd in [&self.events, &self.procs] {
            if rustix::io::pread(fd, &mut byte, 0) != Err(rustix::io::Errno::NODEV) {
                return Err(Error::CgroupMismatch);
            }
        }
        Ok(())
    }
    /// Only the fixed actor uses this after parent authorization/FD isolation.
    /// Original objects, hierarchy and current population are checked anew.
    pub(super) fn verify_empty_native(&self) -> Result<()> {
        for ((fd, id), mode) in self
            .descriptors()
            .into_iter()
            .zip(self.identities)
            .zip(self.modes)
        {
            let stat = fs::fstat(fd).map_err(|_| Error::CgroupMismatch)?;
            if stat.st_mode != mode
                || stat.st_uid != 0
                || stat.st_gid != 0
                || stat.st_mode & 0o022 != 0
                || Identity::of(fd)? != id
                || fs::fstatfs(fd).map_err(|_| Error::CgroupMismatch)?.f_type as u64 != 0x63677270
            {
                return Err(Error::CgroupMismatch);
            }
        }
        for (dir, name, id) in [
            (self.parent.as_fd(), self.name.as_str(), self.identities[1]),
            (self.group.as_fd(), "cgroup.events", self.identities[2]),
            (self.group.as_fd(), "cgroup.procs", self.identities[3]),
        ] {
            let stat = fs::statat(dir, name, fs::AtFlags::SYMLINK_NOFOLLOW)
                .map_err(|_| Error::CgroupMismatch)?;
            if (stat.st_dev, stat.st_ino) != (id.dev, id.ino) {
                return Err(Error::CgroupMismatch);
            }
        }
        let mut bytes = [0u8; 4097];
        let n =
            rustix::io::pread(&self.events, &mut bytes, 0).map_err(|_| Error::CgroupMismatch)?;
        if n == 0 || n > 4096 {
            return Err(Error::CgroupMismatch);
        }
        let events = std::str::from_utf8(&bytes[..n]).map_err(|_| Error::CgroupMismatch)?;
        if events
            .lines()
            .filter_map(|l| l.strip_prefix("populated "))
            .collect::<Vec<_>>()
            != ["0"]
        {
            return Err(Error::CgroupMismatch);
        }
        let mut byte = [0u8; 1];
        if rustix::io::pread(&self.procs, &mut byte, 0).map_err(|_| Error::CgroupMismatch)? != 0 {
            return Err(Error::CgroupMismatch);
        }
        Ok(())
    }
}
/// Read-only native retention of the exact producer. Root waitpid is deliberately
/// insufficient: every task/descendant in the retained cgroup must be gone.
pub(super) struct Drain {
    creator: u32,
    guard: std::rc::Rc<std::cell::RefCell<GuardLifetimeState>>,
    _inventory: super::inventory::Registration,
    parent: OwnedFd,
    group: OwnedFd,
    parent_id: Identity,
    group_id: Identity,
    name: String,
    _lease: super::owned::MutatorLease,
}
enum GuardLifetimeState {
    Unstarted,
    Pending,
    Pinned(GuardLifetime),
}
struct GuardLifetime {
    _inventory: super::inventory::Registration,
    pidfd: OwnedFd,
}
type GuardHold = std::rc::Weak<std::cell::RefCell<GuardLifetimeState>>;
thread_local! {
    static GUARD_HOLDS: std::cell::RefCell<std::collections::BTreeMap<(u32, String, String), GuardHold>> = const { std::cell::RefCell::new(std::collections::BTreeMap::new()) };
}
/// Reserve the parent's retirement fence BEFORE any native guard fork. A failed
/// partial constructor stays Pending until explicit native reconciliation; an
/// empty producer alone can never clear a placement-capable guard attempt.
pub(super) fn begin_guard(domains: &super::supervision::Domains) -> Result<()> {
    let key = (
        std::process::id(),
        domains.allocation().to_owned(),
        domains.exit_id().to_owned(),
    );
    let hold = GUARD_HOLDS.with(|holds| holds.borrow().get(&key).and_then(std::rc::Weak::upgrade));
    if let Some(hold) = hold {
        let mut hold = hold.try_borrow_mut().map_err(|_| Error::LockBusy)?;
        if !matches!(*hold, GuardLifetimeState::Unstarted) {
            return Err(Error::OwnershipMismatch);
        }
        *hold = GuardLifetimeState::Pending;
    }
    Ok(())
}
/// Canonical parent binds its actual still-gated guard; an IPC PID is insufficient.
pub(super) fn bind_guard(
    domains: &super::supervision::Domains,
    child: &super::kernel::Survivor,
) -> Result<()> {
    let key = (
        std::process::id(),
        domains.allocation().to_owned(),
        domains.exit_id().to_owned(),
    );
    let hold = GUARD_HOLDS.with(|holds| holds.borrow().get(&key).and_then(std::rc::Weak::upgrade));
    if let Some(hold) = hold {
        let mut hold = hold.try_borrow_mut().map_err(|_| Error::LockBusy)?;
        if !matches!(*hold, GuardLifetimeState::Pending) {
            return Err(Error::OwnershipMismatch);
        }
        child.require_live()?;
        let pidfd = child
            .pidfd()
            .try_clone_to_owned()
            .map_err(|_| Error::DescriptorDuplicate)?;
        let inventory = super::inventory::Registration::owned(&[pidfd.as_fd()])?;
        *hold = GuardLifetimeState::Pinned(GuardLifetime {
            _inventory: inventory,
            pidfd,
        });
    }
    Ok(())
}
impl Drain {
    fn retain(&self) -> Result<Self> {
        let parent = self
            .parent
            .try_clone()
            .map_err(|_| Error::DescriptorDuplicate)?;
        let group = self
            .group
            .try_clone()
            .map_err(|_| Error::DescriptorDuplicate)?;
        let inventory = super::inventory::Registration::owned(&[parent.as_fd(), group.as_fd()])?;
        Ok(Self {
            creator: std::process::id(),
            // A selected guard retains its own descendant drain, not the
            // canonical parent's guard-death fence copied Pending at fork.
            guard: if self.creator == std::process::id() {
                self.guard.clone()
            } else {
                std::rc::Rc::new(std::cell::RefCell::new(GuardLifetimeState::Unstarted))
            },
            _inventory: inventory,
            parent,
            group,
            parent_id: self.parent_id,
            group_id: self.group_id,
            name: self.name.clone(),
            _lease: self._lease.retain()?,
        })
    }
    pub(super) fn retire_bookkeeping(
        &mut self,
        permit: &super::owned::QuiescentPermit,
        service: &super::owned::JournalServer,
    ) -> Result<()> {
        if !self.empty()? {
            return Err(Error::CgroupMismatch);
        }
        permit.retire_bookkeeping(service, &mut self._lease)
    }
    pub(super) fn empty(&self) -> Result<bool> {
        if self.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        let state = self.guard.try_borrow().map_err(|_| Error::LockBusy)?;
        if matches!(*state, GuardLifetimeState::Pending) {
            return Ok(false);
        }
        if let GuardLifetimeState::Pinned(guard) = &*state {
            let mut fds = [rustix::event::PollFd::new(
                &guard.pidfd,
                rustix::event::PollFlags::IN,
            )];
            rustix::event::poll(
                &mut fds,
                Some(&rustix::event::Timespec {
                    tv_sec: 0,
                    tv_nsec: 0,
                }),
            )
            .map_err(|_| Error::ProcessUnavailable)?;
            if fds[0]
                .revents()
                .intersects(rustix::event::PollFlags::ERR | rustix::event::PollFlags::NVAL)
            {
                return Err(Error::ProcessUnavailable);
            }
            if !fds[0].revents().contains(rustix::event::PollFlags::IN) {
                return Ok(false);
            }
        }
        if Identity::of(&self.parent)? != self.parent_id
            || Identity::of(&self.group)? != self.group_id
        {
            return Err(Error::CgroupMismatch);
        }
        let current = fs::openat(
            &self.parent,
            self.name.as_str(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|_| Error::CgroupMismatch)?;
        if Identity::of(current)? != self.group_id {
            return Err(Error::CgroupMismatch);
        }
        let events = read(&self.group, "cgroup.events", 4096)?;
        let values: Vec<_> = events
            .lines()
            .filter_map(|l| l.strip_prefix("populated "))
            .collect();
        match values.as_slice() {
            ["0"] => Ok(read(&self.group, "cgroup.procs", 65536)?.is_empty()),
            ["1"] => Ok(false),
            _ => Err(Error::CgroupMismatch),
        }
    }
}
thread_local! {
    static RETIRED_PRODUCERS: std::cell::RefCell<Vec<Drain>> = const { std::cell::RefCell::new(Vec::new()) };
}
impl Drop for ProducerGroup {
    fn drop(&mut self) {
        if let Some(drain) = self.retirement.take() {
            if drain.creator != std::process::id() {
                return;
            }
            // The canonical parent owns this separate hold before guard birth.
            // Guard death cannot close it, release the exit reservation or make
            // the exact producer's remaining mutators disappear from accounting.
            RETIRED_PRODUCERS.with(|pending| pending.borrow_mut().push(drain));
        }
    }
}
pub(super) fn retired_drained() -> bool {
    RETIRED_PRODUCERS.with(|pending| {
        pending
            .borrow()
            .iter()
            .all(|drain| drain.creator != std::process::id())
    })
}
pub(super) fn poll_retired() {
    RETIRED_PRODUCERS.with(|pending| {
        // Unknown/changed objects remain retained; one failed group never blocks
        // independently quiescent groups from releasing their own holds.
        pending
            .borrow_mut()
            .retain(|drain| drain.creator != std::process::id() || drain.empty() != Ok(true));
    });
}
impl ProducerGroup {
    pub(super) fn select_guard(&self, inputs: &mut super::inventory::GuardInputs) -> Result<()> {
        inputs.include(
            &self._inventory,
            super::inventory::GuardAuthority::SelectedMember,
        )?;
        let retirement = self.retirement.as_ref().ok_or(Error::OwnershipMismatch)?;
        inputs.include(
            &retirement._inventory,
            super::inventory::GuardAuthority::SelectedMember,
        )?;
        retirement._lease.select_guard(inputs)?;
        // Separate parent-private aliases, default-excluded by the guard fork
        // boundary, keep native descendant proof alive with the guard owner.
        inputs.retain_producer(self.retain_drain()?)
    }
    pub(super) fn retain_drain(&self) -> Result<Drain> {
        self.verify_native()?;
        self.retirement
            .as_ref()
            .ok_or(Error::OwnershipMismatch)?
            .retain()
    }
    pub fn create(a: &Admission, ns: &OwnedNamespaces, tx: &mut Transaction) -> Result<Self> {
        let lease = tx.retain_mutator_lease(&a.spec)?;
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
        let retained_parent = parent.try_clone().map_err(|_| Error::DescriptorDuplicate)?;
        let retained_group = group.try_clone().map_err(|_| Error::DescriptorDuplicate)?;
        let retained_inventory = super::inventory::Registration::owned(&[
            retained_parent.as_fd(),
            retained_group.as_fd(),
        ])?;
        let guard = std::rc::Rc::new(std::cell::RefCell::new(GuardLifetimeState::Unstarted));
        let key = (
            std::process::id(),
            vprouter_worker::bootstrap::digest(
                &serde_json::to_vec(&a.spec.allocation).map_err(|_| Error::InvalidSpec)?,
            ),
            a.spec.exit.exit_id.clone(),
        );
        GUARD_HOLDS.with(|holds| {
            let mut holds = holds.borrow_mut();
            if holds.get(&key).and_then(std::rc::Weak::upgrade).is_some() {
                return Err(Error::OwnershipMismatch);
            }
            holds.insert(key, std::rc::Rc::downgrade(&guard));
            Ok(())
        })?;
        let retirement = Drain {
            creator: std::process::id(),
            guard,
            _inventory: retained_inventory,
            parent: retained_parent,
            group: retained_group,
            parent_id,
            group_id,
            name: name.clone(),
            _lease: lease,
        };
        let result = Self {
            _inventory: inventory,
            parent,
            group,
            parent_id,
            group_id,
            name,
            authority,
            retirement: Some(retirement),
        };
        result.verify(tx, &a.spec)?;
        Ok(result)
    }
    /// Private read-inspector snapshot: preserves exact validated objects and
    /// immutable names. It never creates a producer or journal authority.
    pub(super) fn inspection_copy(&self) -> Result<Self> {
        self.verify_native()?;
        let parent = self
            .parent
            .try_clone()
            .map_err(|_| Error::DescriptorDuplicate)?;
        let group = self
            .group
            .try_clone()
            .map_err(|_| Error::DescriptorDuplicate)?;
        let inventory = super::inventory::Registration::owned(&[parent.as_fd(), group.as_fd()])?;
        Ok(Self {
            _inventory: inventory,
            parent,
            group,
            parent_id: self.parent_id,
            group_id: self.group_id,
            name: self.name.clone(),
            authority: self.authority.clone(),
            retirement: None,
        })
    }
    pub fn authority(&self) -> Arc<SocketProducer> {
        self.authority.clone()
    }
    pub fn verify(&self, tx: &Transaction, s: &LaunchSpec) -> Result<()> {
        tx.verify_producer(s, self.parent_id, self.group_id)?;
        self.verify_native()
    }
    pub(super) fn stop_target(
        &self,
        permit: &super::owned::RetiringPermit,
        journal: &super::owned::JournalServer,
        guard: &super::kernel::ManagedGuard,
    ) -> Result<StopTarget> {
        permit.verify_stop(journal, guard, self.original_identities()?)?;
        if self
            .retirement
            .as_ref()
            .is_none_or(|d| d.creator != std::process::id())
        {
            return Err(Error::OwnershipMismatch);
        }
        let parent = self
            .parent
            .try_clone()
            .map_err(|_| Error::DescriptorDuplicate)?;
        let group = self
            .group
            .try_clone()
            .map_err(|_| Error::DescriptorDuplicate)?;
        let kill = fs::openat(
            &group,
            "cgroup.kill",
            OFlags::WRONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|_| Error::CgroupMismatch)?;
        let inventory =
            super::inventory::Registration::owned(&[parent.as_fd(), group.as_fd(), kill.as_fd()])?;
        let target = StopTarget {
            creator: std::process::id(),
            parent_id: self.parent_id,
            group_id: self.group_id,
            kill_id: Identity::of(&kill)?,
            parent,
            group,
            kill,
            inventory,
            name: self.name.clone(),
        };
        target.verify()?;
        Ok(target)
    }
    pub(super) fn release_retired(
        &mut self,
        permit: &super::owned::RetiredPermit,
        service: &super::owned::JournalServer,
    ) -> Result<()> {
        permit.verify_producer_release(
            service,
            Identity::of(&self.parent)?,
            Identity::of(&self.group)?,
        )?;
        let drain = self.retirement.as_ref().ok_or(Error::OwnershipMismatch)?;
        if drain.creator != std::process::id()
            || !drain._lease.sole_producer()?
            || !self._inventory.contains(self.parent.as_fd())
            || !self._inventory.contains(self.group.as_fd())
        {
            return Err(Error::OwnershipMismatch);
        }
        drop(self.retirement.take());
        Ok(())
    }
    pub(super) fn cleanup_target(
        &self,
        permit: &super::owned::CleanupPermit,
    ) -> Result<CleanupTarget> {
        permit.verify_producer_target(self.original_identities()?)?;
        let drain = self.retirement.as_ref().ok_or(Error::OwnershipMismatch)?;
        if !drain._lease.sole_producer()? {
            return Err(Error::LockBusy);
        }
        if !drain.empty()? {
            return Err(Error::CgroupMismatch);
        }
        let parent = self
            .parent
            .try_clone()
            .map_err(|_| Error::DescriptorDuplicate)?;
        let group = self
            .group
            .try_clone()
            .map_err(|_| Error::DescriptorDuplicate)?;
        let events = fs::openat(
            &group,
            "cgroup.events",
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|_| Error::CgroupMismatch)?;
        let procs = fs::openat(
            &group,
            "cgroup.procs",
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|_| Error::CgroupMismatch)?;
        let inventory = super::inventory::Registration::owned(&[
            parent.as_fd(),
            group.as_fd(),
            events.as_fd(),
            procs.as_fd(),
        ])?;
        let identities = [
            self.parent_id,
            self.group_id,
            Identity::of(&events)?,
            Identity::of(&procs)?,
        ];
        let mut modes = [0; 4];
        for (i, fd) in [parent.as_fd(), group.as_fd(), events.as_fd(), procs.as_fd()]
            .into_iter()
            .enumerate()
        {
            let stat = fs::fstat(fd).map_err(|_| Error::CgroupMismatch)?;
            let kind = if i < 2 { libc::S_IFDIR } else { libc::S_IFREG };
            if stat.st_mode & libc::S_IFMT != kind
                || stat.st_uid != 0
                || stat.st_gid != 0
                || stat.st_mode & 0o022 != 0
            {
                return Err(Error::CgroupMismatch);
            }
            modes[i] = stat.st_mode;
        }
        let target = CleanupTarget {
            creator: std::process::id(),
            inventory,
            parent,
            group,
            events,
            procs,
            identities,
            modes,
            name: self.name.clone(),
        };
        target.verify_parent()?;
        Ok(target)
    }
    pub(super) fn original_identities(&self) -> Result<(Identity, Identity)> {
        self.verify_native()?;
        Ok((self.parent_id, self.group_id))
    }
    pub(super) fn inspection_fds(&self) -> [std::os::fd::BorrowedFd<'_>; 2] {
        [self.parent.as_fd(), self.group.as_fd()]
    }
    pub(super) fn verify_native(&self) -> Result<()> {
        if Identity::of(&self.parent)? != self.parent_id
            || Identity::of(&self.group)? != self.group_id
        {
            return Err(Error::CgroupMismatch);
        }
        let current = fs::openat(
            &self.parent,
            self.name.as_str(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|_| Error::CgroupMismatch)?;
        if Identity::of(current)? != self.group_id {
            return Err(Error::CgroupMismatch);
        }
        Ok(())
    }
    pub(super) fn require_cleanup(&self, tx: &Transaction, s: &LaunchSpec) -> Result<()> {
        // Legacy non-terminal cleanup cannot gain authority merely because a
        // consuming retirement has released proven-idle bookkeeping counts.
        tx.require_no_executors(s)?;
        super::kernel::poll_early_forks()?;
        self.verify(tx, s)?;
        if !self
            .retirement
            .as_ref()
            .ok_or(Error::OwnershipMismatch)?
            ._lease
            .sole_producer()?
        {
            return Err(Error::LockBusy);
        }
        if !self
            .retirement
            .as_ref()
            .ok_or(Error::OwnershipMismatch)?
            .empty()?
        {
            return Err(Error::CgroupMismatch);
        }
        Ok(())
    }
    pub fn cleanup(mut self, tx: &Transaction, s: &LaunchSpec) -> Result<()> {
        self.require_cleanup(tx, s)?;
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
            .map_err(|_| Error::CgroupMismatch)?;
        // Atomic rmdir succeeded only for this exact empty group. No deferred
        // object-path lookup after unlink can strengthen that native proof.
        self.retirement.take();
        Ok(())
    }
    #[cfg(test)]
    pub fn socket_scope<T>(&self, f: impl FnOnce() -> Result<T>) -> Result<T> {
        super::kernel::producer_socket_scope(&self.group, f)
    }
}

/// Retained host process identity for a single accepted observation peer. Not a
/// readiness/producer constructor and never exposed outside the launch crate.
pub(super) struct Sender {
    state: SenderState,
    bundle_digest: String,
    revoked: std::cell::Cell<bool>,
}
enum SenderState {
    Local(NativeSender),
    Remote {
        token: super::inspection::Token,
        client: super::owner::JournalClient,
    },
}
pub(super) struct NativeSender {
    proc: OwnedFd,
    pidfd: OwnedFd,
    pid: u32,
    start: u64,
    role: super::programs::Role,
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
    pub fn verify_child(&self, pid: u32, tx: &Transaction, spec: &LaunchSpec) -> Result<()> {
        self.verify(tx, spec)?;
        let proc = fs::openat(
            fs::CWD,
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
        tx: &Transaction,
        ns: &OwnedNamespaces,
        role: Option<super::inspection::PeerRole>,
    ) -> Result<()> {
        child.require_placement_gate()?;
        // Retain descendant-drain ownership BEFORE any placement mutation.
        child.bind_producer_drain(self.retain_drain()?)?;
        super::process::single_threaded()?;
        self.verify(tx, &admission.spec)?;
        ns.bind(&admission.spec)?;
        tx.inspect_container(admission)?;
        let pid = child.pid();
        let dir = fs::openat(
            fs::CWD,
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
        tx.inspect_container(admission)?;
        if start != super::process::stat_start(&read(&dir, "stat", 65536)?, pid)? {
            return Err(Error::PlacementFailed);
        }
        if let Some(client) = tx.inspection_client(&admission.spec)? {
            client.inspect(super::inspection::Request::RegisterChild {
                pid,
                role: role.ok_or(Error::DescriptorPolicy)?,
            })?;
            child.require_placement_gate()?;
            if start != super::process::stat_start(&read(&dir, "stat", 65536)?, pid)? {
                return Err(Error::PlacementFailed);
            }
            self.membership(pid, &dir, &admission.spec)?;
        }
        // Child owns a retained pidfd and has not been reaped, preventing PID
        // reuse between this verification and release. Errors do not release.
        child.release()
    }
    pub fn pin_sender(
        &self,
        pid: u32,
        tx: &Transaction,
        spec: &LaunchSpec,
        ns: &OwnedNamespaces,
        bundle: &super::programs::ReviewedBundle,
    ) -> Result<Sender> {
        self.pin_sender_role(
            pid,
            tx,
            spec,
            ns,
            bundle,
            super::programs::Role::WorkerObserver,
        )
    }
    pub fn pin_monitor_sender(
        &self,
        pid: u32,
        tx: &Transaction,
        spec: &LaunchSpec,
        ns: &OwnedNamespaces,
        bundle: &super::programs::ReviewedBundle,
    ) -> Result<Sender> {
        self.pin_sender_role(
            pid,
            tx,
            spec,
            ns,
            bundle,
            super::programs::Role::WorkerMonitor,
        )
    }
    fn pin_sender_role(
        &self,
        pid: u32,
        tx: &Transaction,
        spec: &LaunchSpec,
        ns: &OwnedNamespaces,
        bundle: &super::programs::ReviewedBundle,
        role: super::programs::Role,
    ) -> Result<Sender> {
        self.verify(tx, spec)?;
        ns.bind(spec)?;
        let state = match tx.inspection_client(spec)? {
            Some(client) => {
                let role = match role {
                    super::programs::Role::WorkerObserver => super::inspection::PeerRole::Observer,
                    super::programs::Role::WorkerMonitor => super::inspection::PeerRole::Monitor,
                    _ => return Err(Error::ExecutableMismatch),
                };
                let token = client.inspect(super::inspection::Request::PinSender { pid, role })?;
                SenderState::Remote { token, client }
            }
            None => SenderState::Local(NativeSender::pin(pid, self, spec, ns, bundle, role)?),
        };
        let sender = Sender {
            state,
            bundle_digest: bundle.digest().into(),
            revoked: std::cell::Cell::new(false),
        };
        Ok(sender)
    }
}
fn sender_credentials(status: &str, lsm: &str) -> Result<()> {
    let field = |key: &str| -> Result<&str> {
        let mut values = status.lines().filter_map(|line| line.strip_prefix(key));
        let value = values.next().ok_or(Error::CapabilityPolicy)?.trim();
        if values.next().is_some() {
            return Err(Error::CapabilityPolicy);
        }
        Ok(value)
    };
    for key in ["Uid:", "Gid:"] {
        if field(key)?.split_whitespace().collect::<Vec<_>>() != ["65534"; 4] {
            return Err(Error::CapabilityPolicy);
        }
    }
    if !field("Groups:")?.is_empty()
        || field("NoNewPrivs:")? != "1"
        || field("Seccomp:")? != "2"
        || lsm.trim() != "docker-default (enforce)"
    {
        return Err(Error::ConfinementPolicy);
    }
    for key in ["CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:"] {
        if u64::from_str_radix(field(key)?, 16).ok() != Some(0) {
            return Err(Error::CapabilityPolicy);
        }
    }
    Ok(())
}
impl Sender {
    pub fn verify(
        &self,
        group: &ProducerGroup,
        tx: &Transaction,
        spec: &LaunchSpec,
        ns: &OwnedNamespaces,
        bundle: &super::programs::ReviewedBundle,
    ) -> Result<()> {
        if self.revoked.get() {
            return Err(Error::PlacementFailed);
        }
        let result = (|| {
            group.verify(tx, spec)?;
            ns.bind(spec)?;
            if bundle.digest() != self.bundle_digest {
                return Err(Error::ExecutableMismatch);
            }
            match &self.state {
                SenderState::Local(native) => native.verify(group, spec, ns, bundle),
                SenderState::Remote { token, client } => {
                    client.binds(spec)?;
                    client
                        .inspect(super::inspection::Request::Reinspect { token: *token })
                        .map(|_| ())
                }
            }
        })();
        if result.is_err() {
            self.revoked.set(true);
        }
        result
    }
}
impl NativeSender {
    pub(super) fn target_exited(&self) -> Result<bool> {
        let mut fds = [rustix::event::PollFd::new(
            &self.pidfd,
            rustix::event::PollFlags::IN,
        )];
        rustix::event::poll(
            &mut fds,
            Some(&rustix::event::Timespec {
                tv_sec: 0,
                tv_nsec: 0,
            }),
        )
        .map_err(|_| Error::ProcessUnavailable)?;
        Ok(fds[0].revents().intersects(rustix::event::PollFlags::IN))
    }
    pub(super) fn pin(
        pid: u32,
        group: &ProducerGroup,
        spec: &LaunchSpec,
        ns: &OwnedNamespaces,
        bundle: &super::programs::ReviewedBundle,
        role: super::programs::Role,
    ) -> Result<Self> {
        let pidfd = rustix::process::pidfd_open(
            rustix::process::Pid::from_raw(pid as i32).ok_or(Error::PlacementFailed)?,
            rustix::process::PidfdFlags::NONBLOCK,
        )
        .map_err(|_| Error::PlacementFailed)?;
        alive(&pidfd)?;
        let proc = fs::openat(
            fs::CWD,
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
        let sender = Self {
            proc,
            pidfd,
            pid,
            start,
            role,
        };
        sender.verify(group, spec, ns, bundle)?;
        Ok(sender)
    }
    pub(super) fn pid(&self) -> u32 {
        self.pid
    }
    pub(super) fn start(&self) -> u64 {
        self.start
    }
}
#[cfg(test)]
fn sender_substage(trace: Option<&std::cell::Cell<u8>>, value: u8) {
    if let Some(trace) = trace {
        trace.set(value);
    }
}
impl NativeSender {
    pub(super) fn verify(
        &self,
        group: &ProducerGroup,
        spec: &LaunchSpec,
        ns: &OwnedNamespaces,
        bundle: &super::programs::ReviewedBundle,
    ) -> Result<()> {
        self.verify_inner(
            group,
            spec,
            ns,
            bundle,
            #[cfg(test)]
            None,
        )
    }
    #[cfg(test)]
    pub(super) fn verify_diagnostic(
        &self,
        group: &ProducerGroup,
        spec: &LaunchSpec,
        ns: &OwnedNamespaces,
        bundle: &super::programs::ReviewedBundle,
        trace: &std::cell::Cell<u8>,
    ) -> Result<()> {
        self.verify_inner(group, spec, ns, bundle, Some(trace))
    }
    fn verify_inner(
        &self,
        group: &ProducerGroup,
        spec: &LaunchSpec,
        ns: &OwnedNamespaces,
        bundle: &super::programs::ReviewedBundle,
        #[cfg(test)] trace: Option<&std::cell::Cell<u8>>,
    ) -> Result<()> {
        #[cfg(test)]
        sender_substage(trace, 10);
        alive(&self.pidfd)?;
        #[cfg(test)]
        sender_substage(trace, 11);
        group.verify_native()?;
        #[cfg(test)]
        sender_substage(trace, 12);
        ns.bind(spec)?;
        #[cfg(test)]
        sender_substage(trace, 13);
        let stat = read(&self.proc, "stat", 65536)?;
        let start = super::process::stat_start(&stat, self.pid)?;
        if self.start != start {
            return Err(Error::PlacementFailed);
        }
        for name in ["uid_map", "gid_map"] {
            #[cfg(test)]
            sender_substage(trace, if name == "uid_map" { 14 } else { 15 });
            if !super::process::initial_map(&read(&self.proc, name, 4096)?) {
                return Err(Error::PlacementFailed);
            }
        }
        #[cfg(test)]
        sender_substage(trace, 16);
        group.membership(self.pid, &self.proc, spec)?;
        #[cfg(test)]
        sender_substage(trace, 17);
        sender_credentials(
            &read(&self.proc, "status", 16384)?,
            &read(&self.proc, "attr/current", 128)?,
        )?;
        #[cfg(test)]
        sender_substage(trace, 18);
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
        #[cfg(test)]
        sender_substage(trace, 19);
        let exe = fs::openat(
            &self.proc,
            "exe",
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| Error::ExecutableMismatch)?;
        // Pure native verification also runs inside the fixed inspector.
        // Diagnostics belong to its private bounded failure channel, never stdio.
        #[cfg(test)]
        sender_substage(trace, 20);
        bundle.verify(exe, self.role)?;
        #[cfg(test)]
        sender_substage(trace, 21);
        group.membership(self.pid, &self.proc, spec)?;
        #[cfg(test)]
        sender_substage(trace, 22);
        if self.start != super::process::stat_start(&read(&self.proc, "stat", 65536)?, self.pid)? {
            return Err(Error::PlacementFailed);
        }
        #[cfg(test)]
        sender_substage(trace, 23);
        alive(&self.pidfd)
    }
}
#[cfg(test)]
mod placement_tests {
    #[test]
    fn sender_fixed_role_requires_zero_caps_unprivileged_ids_nnp_seccomp_and_lsm() {
        let good = "Uid: 65534 65534 65534 65534\nGid: 65534 65534 65534 65534\nGroups:\nNoNewPrivs: 1\nSeccomp: 2\nCapInh: 0\nCapPrm: 0\nCapEff: 0\nCapBnd: 0\nCapAmb: 0\n";
        assert!(super::sender_credentials(good, "docker-default (enforce)").is_ok());
        for (before, after) in [
            ("CapEff: 0", "CapEff: 1000"),
            ("Uid: 65534", "Uid: 0"),
            ("Groups:", "Groups: 65534"),
            ("NoNewPrivs: 1", "NoNewPrivs: 0"),
            ("Seccomp: 2", "Seccomp: 0"),
        ] {
            assert!(
                super::sender_credentials(&good.replace(before, after), "docker-default (enforce)")
                    .is_err()
            );
        }
        assert!(super::sender_credentials(good, "unconfined").is_err());
        assert!(
            super::sender_credentials(&format!("{good}CapEff: 0\n"), "docker-default (enforce)")
                .is_err()
        );
    }
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
