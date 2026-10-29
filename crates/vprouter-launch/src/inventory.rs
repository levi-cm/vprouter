#![forbid(unsafe_code)]
//! Private one-thread RAII inventory of exact owned host descriptors. No caller
//! allowlist or assertion constructor. Guard forks retain numeric ownership of
//! excluded handles using inert slots until each copied owner is destroyed.
use super::{Error, Result};
use rustix::fs;
#[cfg(test)]
use std::os::fd::AsFd;
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
#[derive(Clone, Copy, PartialEq, Eq)]
struct Token {
    creator: u32,
    epoch: u64,
}
#[derive(Clone, Copy, PartialEq, Eq)]
struct Entry {
    token: Token,
    identity: Identity,
    inert: bool,
}
#[derive(Clone, Copy)]
struct Slot {
    fd: i32,
    token: Token,
    identity: Identity,
}
thread_local! {
    static OWNED:RefCell<BTreeMap<i32,Entry>>=const{RefCell::new(BTreeMap::new())};
    static EPOCH:std::cell::Cell<u64>=const{std::cell::Cell::new(0)};
}
fn next_token() -> Result<Token> {
    EPOCH.with(|epoch| {
        let next = epoch
            .get()
            .checked_add(1)
            .ok_or(Error::DescriptorInventory)?;
        epoch.set(next);
        Ok(Token {
            creator: std::process::id(),
            epoch: next,
        })
    })
}
#[cfg(test)]
fn lab_observed_fdinfo(fd: i32) -> Result<Identity> {
    use std::io::Read;
    // Explicit native syscalls on both libc ABIs; musl metadata/open wrappers
    // may select legacy stat/open which the fixed inspector intentionally denies.
    let m = fs::statat(fs::CWD, format!("/proc/self/fd/{fd}"), fs::AtFlags::empty())
        .map_err(|_| Error::DescriptorPolicy)?;
    let source = fs::openat(
        fs::CWD,
        format!("/proc/self/fdinfo/{fd}"),
        fs::OFlags::RDONLY | fs::OFlags::NOFOLLOW | fs::OFlags::CLOEXEC,
        fs::Mode::empty(),
    )
    .map_err(|_| Error::DescriptorPolicy)?;
    let mut info = String::new();
    std::fs::File::from(source)
        .take(65537)
        .read_to_string(&mut info)
        .map_err(|_| Error::DescriptorPolicy)?;
    if info.len() > 65536 {
        return Err(Error::DescriptorPolicy);
    }
    let flags = info
        .lines()
        .find_map(|l| l.strip_prefix("flags:\t"))
        .and_then(|s| u32::from_str_radix(s.trim(), 8).ok())
        .ok_or(Error::DescriptorPolicy)?;
    Ok(Identity {
        dev: m.st_dev,
        ino: m.st_ino,
        mode: m.st_mode & libc::S_IFMT,
        cloexec: flags & libc::O_CLOEXEC as u32 != 0,
    })
}
fn observed(fd: i32) -> Result<Identity> {
    // Keep the fresh native statat identity/type read on both libc ABIs. Read
    // descriptor flags directly without opening a second procfs descriptor.
    let m = fs::statat(fs::CWD, format!("/proc/self/fd/{fd}"), fs::AtFlags::empty())
        .map_err(|_| Error::DescriptorPolicy)?;
    Ok(Identity {
        dev: m.st_dev,
        ino: m.st_ino,
        mode: m.st_mode & libc::S_IFMT,
        cloexec: super::kernel::descriptor_cloexec(fd)?,
    })
}
#[cfg(test)]
pub(super) fn lab_metadata_equal(fds: &[i32], closed: i32) -> Result<()> {
    for fd in fds {
        if lab_observed_fdinfo(*fd)? != observed(*fd)? {
            return Err(Error::DescriptorPolicy);
        }
    }
    if lab_observed_fdinfo(closed) != Err(Error::DescriptorPolicy)
        || observed(closed) != Err(Error::DescriptorPolicy)
        || super::kernel::descriptor_cloexec(closed) != Err(Error::DescriptorPolicy)
    {
        return Err(Error::DescriptorPolicy);
    }
    Ok(())
}
#[cfg(test)]
pub(super) fn lab_metadata_sample(fds: &[i32], direct: bool) -> Result<u64> {
    let mut witness = 0;
    for fd in fds {
        let value = if direct {
            observed(*fd)?
        } else {
            lab_observed_fdinfo(*fd)?
        };
        witness ^= value.dev ^ value.ino ^ value.mode as u64 ^ value.cloexec as u64;
    }
    Ok(witness)
}
#[cfg(test)]
pub(super) fn lab_metadata_drift(fds: &[OwnedFd], registration: &Registration) -> Result<()> {
    verify()?;
    for fd in fds {
        rustix::io::fcntl_setfd(fd, rustix::io::FdFlags::empty())
            .map_err(|_| Error::DescriptorPolicy)?;
        let result = (|| {
            if lab_observed_fdinfo(fd.as_raw_fd())? != observed(fd.as_raw_fd())?
                || registration.contains(fd.as_fd())
                || registration.retained_slots() != Err(Error::DescriptorInventory)
                || verify() != Err(Error::DescriptorPolicy)
            {
                return Err(Error::DescriptorPolicy);
            }
            Ok(())
        })();
        // Restore even on comparison failure; never register/adopt the drift.
        rustix::io::fcntl_setfd(fd, rustix::io::FdFlags::CLOEXEC)
            .map_err(|_| Error::DescriptorPolicy)?;
        result?;
        if !registration.contains(fd.as_fd()) || registration.retained_slots()? != fds.len() {
            return Err(Error::DescriptorPolicy);
        }
        verify()?;
    }
    Ok(())
}
enum Channels {
    Control,
    Network,
}
pub(super) struct Registration {
    slots: Vec<Slot>,
}
impl Registration {
    /// Existing exact RAII ownership only; this never authorizes a new fd.
    pub(super) fn contains(&self, fd: BorrowedFd<'_>) -> bool {
        self.slots
            .iter()
            .any(|slot| slot.fd == fd.as_raw_fd() && live_slot(*slot))
    }
    /// Fresh custody of the SAME registered slots; no descriptor adoption.
    pub(super) fn retained_slots(&self) -> Result<usize> {
        if self.slots.is_empty() || self.slots.iter().any(|slot| !live_slot(*slot)) {
            return Err(Error::DescriptorInventory);
        }
        Ok(self.slots.len())
    }
    #[cfg(test)]
    pub(super) fn lab_live_slots(&self) -> Result<usize> {
        self.retained_slots()
    }
    #[cfg(test)]
    pub(super) fn lab_require_inert(&self) -> Result<()> {
        for slot in &self.slots {
            let entry = OWNED
                .with(|owned| owned.borrow().get(&slot.fd).copied())
                .ok_or(Error::DescriptorInventory)?;
            if entry.token != slot.token
                || !entry.inert
                || observed(slot.fd)? != entry.identity
                || self.contains_number(*slot)
            {
                return Err(Error::DescriptorPolicy);
            }
        }
        Ok(())
    }
    #[cfg(test)]
    fn contains_number(&self, slot: Slot) -> bool {
        live_slot(slot)
    }
    #[cfg(test)]
    pub(super) fn lab_stale_copy(&self) -> Self {
        Self {
            slots: self.slots.clone(),
        }
    }
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
        let token = next_token()?;
        OWNED.with(|owned| {
            let mut owned = owned.borrow_mut();
            let distinct: std::collections::BTreeSet<_> = fds.iter().copied().collect();
            if distinct.len() != fds.len()
                || identities.iter().any(|(fd, _)| owned.contains_key(fd))
            {
                return Err(Error::DescriptorPolicy);
            }
            let slots = identities
                .into_iter()
                .map(|(fd, identity)| {
                    // Trusted registrations are private to their creator by default.
                    // Only a fixed typed guard input may select them across a fork.
                    owned.insert(
                        fd,
                        Entry {
                            token,
                            identity,
                            inert: false,
                        },
                    );
                    Slot {
                        fd,
                        token,
                        identity,
                    }
                })
                .collect();
            Ok(Self { slots })
        })
    }
    /// Exact descriptor delta around one trusted synchronous native constructor.
    /// No runtime/thread/caller supplied descriptor exists during this scope.
    /// Only the expected number of new CLOEXEC sockets may be registered.
    pub fn control<T>(construct: impl FnOnce() -> Result<T>) -> Result<(T, Self)> {
        Self::construct_channels(construct, Channels::Control)
    }
    /// Exactly one native network observer: route and generic-netlink only.
    /// The constructor is fixed here; callers cannot provide a descriptor list
    /// or widen the independent four-channel netfilter-control registration.
    pub fn network(
        plan: vprouter_network::Plan,
    ) -> Result<(vprouter_network::NativeNetwork, Self)> {
        Self::construct_channels(
            || vprouter_network::NativeNetwork::open(plan).map_err(|_| Error::NetworkOperation),
            Channels::Network,
        )
    }
    fn construct_channels<T>(
        construct: impl FnOnce() -> Result<T>,
        channels: Channels,
    ) -> Result<(T, Self)> {
        super::process::single_threaded()?;
        let before: std::collections::BTreeSet<_> = numbers()?.into_iter().collect();
        let value = construct()?;
        super::process::single_threaded()?;
        let after: std::collections::BTreeSet<_> = numbers()?.into_iter().collect();
        if !before.is_subset(&after) {
            return Err(Error::DescriptorPolicy);
        }
        let added: Vec<_> = after.difference(&before).copied().collect();
        let mut protocols = Vec::new();
        for fd in &added {
            let id = observed(*fd)?;
            if id.mode != libc::S_IFSOCK || !id.cloexec {
                return Err(Error::DescriptorPolicy);
            }
            protocols.push(super::kernel::control_socket(*fd)?);
        }
        match channels {
            Channels::Control => control_protocols(&mut protocols)?,
            Channels::Network => network_protocols(&mut protocols)?,
        }
        Ok((value, Self::numbers(added)?))
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
            for slot in &self.slots {
                // Foreign placeholder owners must retire their original token.
                // A stale owner never removes a later registration of this number.
                if o.get(&slot.fd)
                    .is_some_and(|entry| entry.token == slot.token)
                {
                    o.remove(&slot.fd);
                }
            }
        });
    }
}
fn live_slot(slot: Slot) -> bool {
    OWNED
        .with(|owned| owned.borrow().get(&slot.fd).copied())
        .is_some_and(|entry| {
            entry.token == slot.token
                && !entry.inert
                && entry.identity == slot.identity
                && observed(slot.fd) == Ok(entry.identity)
        })
}
/// Closed authority classes. No observed-number adoption or caller allowlist.
#[derive(Clone, Copy)]
pub(super) enum GuardAuthority {
    SelectedMember,
    DeploymentHold,
    Gate,
}
/// Constructed only from existing typed owners. Everything not explicitly selected
/// is creator-private, including every duplicate in owner factories/collectors.
pub(super) struct GuardInputs {
    creator: u32,
    selected: BTreeMap<i32, (Slot, GuardAuthority)>,
    binding: Option<(String, String)>,
    attempt: Option<super::owned::AttemptBinding>,
    producer: Option<super::producer::Drain>,
}
impl GuardInputs {
    pub(super) fn empty() -> Self {
        Self {
            creator: std::process::id(),
            selected: BTreeMap::new(),
            binding: None,
            attempt: None,
            producer: None,
        }
    }
    pub(super) fn for_owner(
        domains: &super::supervision::Domains,
        owner: &super::supervision::OwnerDomain,
    ) -> Result<Self> {
        owner.verify(domains)?;
        let mut inputs = Self::empty();
        inputs.binding = Some((domains.allocation().into(), domains.exit_id().into()));
        Ok(inputs)
    }
    pub(super) fn for_domains(domains: &super::supervision::Domains) -> Result<Self> {
        domains.verify_owner()?;
        let mut inputs = Self::empty();
        inputs.binding = Some((
            domains.allocation().to_owned(),
            domains.exit_id().to_owned(),
        ));
        Ok(inputs)
    }
    pub(super) fn bind_attempt(&mut self, binding: super::owned::AttemptBinding) -> Result<()> {
        if self.creator != std::process::id() || self.attempt.is_some() {
            return Err(Error::OwnershipMismatch);
        }
        self.attempt = Some(binding);
        Ok(())
    }
    pub(super) fn attempt_binding(&self) -> Result<&super::owned::AttemptBinding> {
        if self.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        self.attempt.as_ref().ok_or(Error::OwnershipMismatch)
    }
    pub(super) fn binds(&self, domains: &super::supervision::Domains) -> Result<()> {
        if self.creator != std::process::id()
            || self.binding.as_ref()
                != Some(&(
                    domains.allocation().to_owned(),
                    domains.exit_id().to_owned(),
                ))
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
    pub(super) fn retain_producer(&mut self, producer: super::producer::Drain) -> Result<()> {
        if self.creator != std::process::id() || self.producer.is_some() {
            return Err(Error::OwnershipMismatch);
        }
        self.producer = Some(producer);
        Ok(())
    }
    pub(super) fn take_producer(&mut self) -> Result<Option<super::producer::Drain>> {
        if self.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        Ok(self.producer.take())
    }
    pub(super) fn include(
        &mut self,
        registration: &Registration,
        authority: GuardAuthority,
    ) -> Result<()> {
        if self.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        for slot in &registration.slots {
            if !live_slot(*slot) || self.selected.contains_key(&slot.fd) {
                return Err(Error::DescriptorPolicy);
            }
            self.selected.insert(slot.fd, (*slot, authority));
        }
        Ok(())
    }
    #[cfg(test)]
    pub(super) fn lab_checkpoint(&mut self, registration: &Registration) -> Result<()> {
        self.include(registration, GuardAuthority::Gate)
    }
    pub(super) fn seal(self) -> Result<GuardBoundary> {
        if self.creator != std::process::id() || self.producer.is_some() {
            return Err(Error::OwnershipMismatch);
        }
        verify()?;
        if self.selected.values().any(|(slot, _)| !live_slot(*slot)) {
            return Err(Error::DescriptorPolicy);
        }
        Ok(GuardBoundary {
            creator: self.creator,
            selected: self.selected,
            inherited: OWNED.with(|owned| owned.borrow().clone()),
        })
    }
}
pub(super) struct GuardBoundary {
    creator: u32,
    selected: BTreeMap<i32, (Slot, GuardAuthority)>,
    inherited: BTreeMap<i32, Entry>,
}
impl GuardBoundary {
    /// Child only. Failure, including partial substitution, must _exit before any
    /// role runs. Parent never mutates. Copied OwnedFd owners keep occupied slots.
    pub(super) fn enter(self) -> Result<()> {
        if self.creator == std::process::id()
            || OWNED.with(|owned| *owned.borrow() != self.inherited)
        {
            return Err(Error::DescriptorInventory);
        }
        verify()?;
        let inert = fs::openat(
            fs::CWD,
            "/dev/null",
            fs::OFlags::RDWR | fs::OFlags::CLOEXEC | fs::OFlags::NOFOLLOW,
            fs::Mode::empty(),
        )
        .map_err(|_| Error::DescriptorPolicy)?;
        let inert_id = observed(inert.as_raw_fd())?;
        let metadata = fs::fstat(&inert).map_err(|_| Error::DescriptorPolicy)?;
        if self.inherited.contains_key(&inert.as_raw_fd())
            || inert_id.mode != libc::S_IFCHR
            || fs::major(metadata.st_rdev) != 1
            || fs::minor(metadata.st_rdev) != 3
            || metadata.st_uid != 0
            || metadata.st_gid != 0
            || metadata.st_nlink != 1
        {
            return Err(Error::DescriptorPolicy);
        }
        for (fd, entry) in &self.inherited {
            if observed(*fd)? != entry.identity {
                return Err(Error::DescriptorPolicy);
            }
            if let Some((slot, _)) = self.selected.get(fd) {
                if !live_slot(*slot) {
                    return Err(Error::DescriptorPolicy);
                }
                continue;
            }
            super::kernel::inert_guard_slot(&inert, *fd)?;
            if observed(*fd)? != inert_id {
                return Err(Error::DescriptorPolicy);
            }
            OWNED.with(|owned| {
                let mut owned = owned.borrow_mut();
                let current = owned.get_mut(fd).ok_or(Error::DescriptorInventory)?;
                if *current != *entry {
                    return Err(Error::DescriptorInventory);
                }
                current.identity = inert_id;
                current.inert = true;
                Ok(())
            })?;
        }
        drop(inert);
        verify()
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
fn network_protocols(protocols: &mut [i32]) -> Result<()> {
    protocols.sort_unstable();
    if protocols != [0, 16] {
        return Err(Error::DescriptorPolicy);
    }
    Ok(())
}
fn control_protocols(protocols: &mut [i32]) -> Result<()> {
    protocols.sort_unstable();
    // Exactly route + generic + independent nft normal/emergency channels.
    if protocols != [0, 12, 12, 16] {
        return Err(Error::DescriptorPolicy);
    }
    Ok(())
}
pub(super) fn verify() -> Result<()> {
    let expected = OWNED.with(|o| o.borrow().clone());
    let mut seen = std::collections::BTreeSet::new();
    for fd in numbers()? {
        let id = observed(fd)?;
        if fd <= 2 {
            if id.mode == libc::S_IFSOCK {
                #[cfg(test)]
                eprintln!("inventory: rejected_stdio_fd={fd}");
                return Err(Error::DescriptorPolicy);
            }
            continue;
        }
        if expected.get(&fd).map(|entry| entry.identity) != Some(id) {
            #[cfg(test)]
            eprintln!(
                "inventory: mismatched_fd={fd}, registered={}, mode={:o}, cloexec={}, target={:?}",
                expected.contains_key(&fd),
                id.mode,
                id.cloexec,
                std::fs::read_link(format!("/proc/self/fd/{fd}"))
            );
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
        #[cfg(test)]
        eprintln!(
            "inventory: expected_fds={:?}, seen_fds={seen:?}",
            expected.keys().collect::<Vec<_>>()
        );
        return Err(Error::DescriptorPolicy);
    }
    Ok(())
}
/// Fixed isolated placement role, after the kernel boundary has closed everything
/// except its private reply, original target pidfd and native allocation lease.
pub(super) fn placement_role() -> Result<Registration> {
    if numbers()? != [0, 1, 2, 3, 4, 5] {
        return Err(Error::DescriptorInventory);
    }
    OWNED.with(|owned| owned.borrow_mut().clear());
    Registration::numbers(vec![3, 4, 5])
}

/// Kernel-only fixed inspector boundary, after every unrelated inherited handle
/// is closed. Policy and exact guard pins supply this list, never wire requests.
pub(super) fn inspection_role(fds: &[BorrowedFd<'_>]) -> Result<Registration> {
    let mut expected: std::collections::BTreeSet<_> = fds.iter().map(AsRawFd::as_raw_fd).collect();
    expected.extend([0, 1, 2]);
    if numbers()?
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>()
        != expected
    {
        return Err(Error::DescriptorInventory);
    }
    OWNED.with(|owned| owned.borrow_mut().clear());
    Registration::owned(fds)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;
    #[test]
    fn dropped_native_io_runtime_leaves_no_global_descriptors() {
        // A fresh process is essential: another Tokio test can already have
        // initialized a persistent global signal socket and hide the leak.
        const CHILD: &str = "VPROUTER_RUNTIME_FD_PROBE";
        if std::env::var_os(CHILD).is_none() {
            let name = std::thread::current().name().unwrap().to_owned();
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &name, "--nocapture"])
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        let before: std::collections::BTreeSet<_> = numbers().unwrap().into_iter().collect();
        {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .build()
                .unwrap();
            runtime.block_on(tokio::task::yield_now());
        }
        let after: std::collections::BTreeSet<_> = numbers().unwrap().into_iter().collect();
        assert_eq!(
            after, before,
            "native runtime must close every descriptor before fork"
        );
    }
    #[test]
    fn static_host_dependency_graph_excludes_global_signal_and_process_drivers() {
        for platform in ["x86_64-unknown-linux-musl", "aarch64-unknown-linux-musl"] {
            for (package, forbidden) in [
                ("tokio", &["process", "signal", "rt-multi-thread", "fs"][..]),
                (
                    "zbus",
                    &[
                        "default",
                        "default-rt",
                        "unixexec",
                        "ibus",
                        "tokio-multithread",
                        "p2p",
                    ][..],
                ),
            ] {
                // `metadata` includes optional-feature edges which are not in
                // the resolved build. `tree` reports the target build graph.
                let output = std::process::Command::new("cargo")
                    .current_dir(env!("CARGO_MANIFEST_DIR"))
                    .args([
                        "tree", "--locked", "--target", platform, "--invert", package, "--depth",
                        "0", "--format", "{f}",
                    ])
                    .output()
                    .unwrap();
                assert!(
                    output.status.success(),
                    "{}",
                    String::from_utf8_lossy(&output.stderr)
                );
                let text = String::from_utf8(output.stdout).unwrap();
                assert!(!text.trim().is_empty());
                let features: Vec<_> = text.trim().split(',').collect();
                assert!(
                    forbidden.iter().all(|feature| !features.contains(feature)),
                    "{platform}: {package} features {features:?}"
                );
            }
        }
    }
    #[test]
    fn network_observer_registration_allows_only_route_and_generic_channels() {
        network_protocols(&mut [16, 0]).unwrap();
        for mut protocols in [
            vec![0],
            vec![16],
            vec![0, 0],
            vec![0, 12],
            vec![0, 12, 12, 16],
            vec![0, 16, 16],
        ] {
            assert_eq!(
                network_protocols(&mut protocols),
                Err(Error::DescriptorPolicy)
            );
        }
        assert_eq!(
            control_protocols(&mut [0, 16]),
            Err(Error::DescriptorPolicy)
        );
    }
    #[test]
    fn native_control_registration_rejects_wrong_protocol_kind_and_count() {
        control_protocols(&mut [16, 12, 0, 12]).unwrap();
        for mut values in [
            vec![0, 12, 16],
            vec![0, 12, 12, 16, 16],
            vec![0, 0, 12, 16],
            vec![0, 12, 12, 6],
        ] {
            assert_eq!(control_protocols(&mut values), Err(Error::DescriptorPolicy));
        }
        let (socket, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
        assert_eq!(
            super::super::kernel::control_socket(socket.as_raw_fd()),
            Err(Error::DescriptorPolicy)
        );
        let file = std::fs::File::open("/dev/null").unwrap();
        assert_eq!(
            super::super::kernel::control_socket(file.as_raw_fd()),
            Err(Error::DescriptorPolicy)
        );
    }
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
