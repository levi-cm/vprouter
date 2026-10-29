#![forbid(unsafe_code)]
//! Private, revocable actual-daemon identity. Setup acknowledgements, arbitrary
//! snapshots and PID numbers cannot construct this authority or readiness.
use super::{
    Admission, Error, Result, inventory, kernel,
    owned::{Identity, OwnedNamespaces, Transaction},
    producer::ProducerGroup,
    programs::{ReviewedBundle, Role},
};
use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    fs::{self, Mode, OFlags},
    process::{Pid, PidfdFlags, pidfd_open},
};
use std::{
    fs::File,
    io::Read,
    os::fd::{AsFd, OwnedFd},
};
const RD: OFlags = OFlags::RDONLY
    .union(OFlags::CLOEXEC)
    .union(OFlags::NOFOLLOW);
fn read(root: impl AsFd, path: &str, limit: usize) -> Result<String> {
    let fd = fs::openat(root, path, RD, Mode::empty()).map_err(|_| Error::PlacementFailed)?;
    let mut bytes = Vec::new();
    File::from(fd)
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::PlacementFailed)?;
    if bytes.len() > limit {
        return Err(Error::TooLarge);
    }
    String::from_utf8(bytes).map_err(|_| Error::PlacementFailed)
}
fn alive(fd: impl AsFd) -> Result<()> {
    let mut descriptors = [PollFd::new(&fd, PollFlags::IN)];
    if poll(
        &mut descriptors,
        Some(&Timespec {
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
fn parent(status: &str) -> Result<u32> {
    let mut fields = status.lines().filter_map(|line| line.strip_prefix("PPid:"));
    let value = fields
        .next()
        .and_then(|v| v.trim().parse::<u32>().ok())
        .filter(|p| *p > 0)
        .ok_or(Error::PlacementFailed)?;
    if fields.next().is_some() {
        return Err(Error::PlacementFailed);
    }
    Ok(value)
}
fn daemon_credentials(status: &str) -> Result<()> {
    let field = |key: &str| {
        let mut fields = status.lines().filter_map(|line| line.strip_prefix(key));
        let value = fields.next().ok_or(Error::CapabilityPolicy)?.trim();
        if fields.next().is_some() {
            return Err(Error::CapabilityPolicy);
        }
        Ok(value)
    };
    for key in ["Uid:", "Gid:"] {
        if field(key)?.split_whitespace().collect::<Vec<_>>() != ["65534"; 4] {
            return Err(Error::CapabilityPolicy);
        }
    }
    if !field("Groups:")?.is_empty() || field("NoNewPrivs:")? != "1" || field("Seccomp:")? != "2" {
        return Err(Error::CapabilityPolicy);
    }
    for key in ["CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:"] {
        if u64::from_str_radix(field(key)?, 16).ok() != Some(1 << 12) {
            return Err(Error::CapabilityPolicy);
        }
    }
    Ok(())
}
pub(super) struct Process {
    proc: OwnedFd,
    pidfd: OwnedFd,
    pid: u32,
    start: u64,
    parent: u32,
}
impl Process {
    pub(super) fn open(pid: u32) -> Result<Self> {
        let pidfd = pidfd_open(
            Pid::from_raw(pid as i32).ok_or(Error::PlacementFailed)?,
            PidfdFlags::NONBLOCK,
        )
        .map_err(|_| Error::PlacementFailed)?;
        alive(&pidfd)?;
        let proc = fs::openat(
            fs::CWD,
            format!("/proc/{pid}"),
            RD | OFlags::DIRECTORY,
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
        let result = Self {
            parent: parent(&read(&proc, "status", 16384)?)?,
            proc,
            pidfd,
            pid,
            start,
        };
        result.verify()?;
        Ok(result)
    }
    pub(super) fn exited(&self) -> Result<bool> {
        let mut fds = [PollFd::new(&self.pidfd, PollFlags::IN)];
        poll(
            &mut fds,
            Some(&Timespec {
                tv_sec: 0,
                tv_nsec: 0,
            }),
        )
        .map_err(|_| Error::ProcessUnavailable)?;
        Ok(fds[0].revents().intersects(PollFlags::IN))
    }
    pub(super) fn verify(&self) -> Result<()> {
        alive(&self.pidfd)?;
        if super::process::stat_start(&read(&self.proc, "stat", 65536)?, self.pid)? != self.start
            || parent(&read(&self.proc, "status", 16384)?)? != self.parent
            || !super::process::initial_map(&read(&self.proc, "uid_map", 4096)?)
            || !super::process::initial_map(&read(&self.proc, "gid_map", 4096)?)
        {
            return Err(Error::PlacementFailed);
        }
        alive(&self.pidfd)
    }
    pub(super) fn pid(&self) -> u32 {
        self.pid
    }
    pub(super) fn start(&self) -> u64 {
        self.start
    }
    pub(super) fn parent(&self) -> u32 {
        self.parent
    }
    pub(super) fn proc(&self) -> std::os::fd::BorrowedFd<'_> {
        self.proc.as_fd()
    }
    pub(super) fn fds(&self) -> [std::os::fd::BorrowedFd<'_>; 2] {
        [self.proc.as_fd(), self.pidfd.as_fd()]
    }
    pub(super) fn inspector_role(&self) -> Result<()> {
        self.verify()?;
        let status = read(&self.proc, "status", 16384)?;
        for key in ["Uid:", "Gid:"] {
            let values: Vec<_> = status
                .lines()
                .filter_map(|line| line.strip_prefix(key))
                .collect();
            if values.len() != 1 || values[0].split_whitespace().collect::<Vec<_>>() != ["0"; 4] {
                return Err(Error::CapabilityPolicy);
            }
        }
        let groups: Vec<_> = status
            .lines()
            .filter_map(|line| line.strip_prefix("Groups:"))
            .collect();
        if groups.len() != 1
            || !groups[0].trim().is_empty()
            || read(&self.proc, "attr/current", 128)?.trim() != "unconfined"
        {
            return Err(Error::CapabilityPolicy);
        }
        for (key, expected) in [
            ("CapInh:", 0),
            ("CapPrm:", (1 << 2) | (1 << 19)),
            ("CapEff:", (1 << 2) | (1 << 19)),
            ("CapBnd:", (1 << 2) | (1 << 19)),
            ("CapAmb:", 0),
        ] {
            let values: Vec<_> = status
                .lines()
                .filter_map(|line| line.strip_prefix(key))
                .collect();
            if values.len() != 1 || u64::from_str_radix(values[0].trim(), 16).ok() != Some(expected)
            {
                return Err(Error::CapabilityPolicy);
            }
        }
        for (key, expected) in [("NoNewPrivs:", "1"), ("Seccomp:", "2"), ("Threads:", "1")] {
            if status
                .lines()
                .filter_map(|line| line.strip_prefix(key))
                .collect::<Vec<_>>()
                .as_slice()
                != [format!("\t{expected}")]
            {
                return Err(Error::CapabilityPolicy);
            }
        }
        self.verify()
    }
    pub(super) fn same(&self, other: &Self) -> Result<()> {
        self.verify()?;
        other.verify()?;
        if self.pid != other.pid || self.start != other.start {
            return Err(Error::ProcessChanged);
        }
        Ok(())
    }
    fn namespace(&self, name: &str) -> Result<OwnedFd> {
        fs::openat(
            &self.proc,
            format!("ns/{name}"),
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| Error::NamespaceMismatch)
    }
}
/// Explicit local or opaque owner peer authority. A remote token never carries
/// a cached native verdict: every verification sends a fresh authenticated job.
pub(super) struct LiveDaemon<'g> {
    state: DaemonState,
    pid: u32,
    bootstrap_digest: String,
    bundle_digest: String,
    admission: &'g Admission,
    transaction: &'g Transaction,
    owned: &'g OwnedNamespaces,
    producer: &'g ProducerGroup,
    shape: Option<vprouter_network::DaemonLinks>,
    revoked: bool,
}
enum DaemonState {
    Local {
        native: NativeDaemon,
        guard: LocalGuard,
    },
    Remote {
        token: super::inspection::Token,
        client: super::owner::JournalClient,
    },
}
/// The local verifier retains its creator independently of the daemon chain.
/// Keep the exact registration with both native pins until this owner drops.
struct LocalGuard {
    _inventory: inventory::Registration,
    process: Process,
}
impl LocalGuard {
    fn current() -> Result<Self> {
        let process = Process::open(std::process::id())?;
        let inventory = inventory::Registration::owned(&process.fds())?;
        Ok(Self {
            _inventory: inventory,
            process,
        })
    }
}

#[cfg(test)]
pub(super) fn lab_local_guard_inventory() -> Result<()> {
    use std::os::fd::AsRawFd;
    super::process::single_threaded()?;
    inventory::verify()?;
    let guard = LocalGuard::current()?;
    let reused_number = guard.process.pidfd.as_raw_fd();
    guard.process.verify()?;
    inventory::verify()?;
    drop(guard);
    inventory::verify()?;
    let reuse = rustix::event::eventfd(0, rustix::event::EventfdFlags::CLOEXEC)
        .map_err(|_| Error::DescriptorPolicy)?;
    if reuse.as_raw_fd() != reused_number {
        return Err(Error::DescriptorPolicy);
    }
    let registration = inventory::Registration::owned(&[reuse.as_fd()])?;
    inventory::verify()?;
    drop(registration);
    drop(reuse);
    inventory::verify()
}
impl<'g> LiveDaemon<'g> {
    #[cfg(test)]
    pub(super) fn lab_remote_token(&self) -> Result<super::inspection::Token> {
        match &self.state {
            DaemonState::Remote { token, .. } => Ok(*token),
            _ => Err(Error::OwnershipMismatch),
        }
    }
    pub(super) fn revoke(&mut self) {
        self.revoked = true;
    }
    #[allow(clippy::too_many_arguments)]
    pub(super) fn pin(
        admission: &'g Admission,
        transaction: &'g Transaction,
        owned: &'g OwnedNamespaces,
        producer: &'g ProducerGroup,
        bundle: &ReviewedBundle,
        child: &kernel::Child,
        pid: u32,
        bootstrap_digest: &str,
        configuration_kind: kernel::DaemonConfiguration,
    ) -> Result<Self> {
        child.require_live()?;
        transaction.revalidate(&admission.spec)?;
        producer.verify(transaction, &admission.spec)?;
        let state = match transaction.inspection_client(&admission.spec)? {
            Some(client) => {
                let token = client.inspect(super::inspection::Request::PinDaemon {
                    pid,
                    child: child.pid(),
                    bootstrap: bootstrap_digest.into(),
                })?;
                DaemonState::Remote { token, client }
            }
            None => {
                let guard = LocalGuard::current()?;
                let root = Process::open(child.pid())?;
                let native = NativeDaemon::pin(
                    admission,
                    owned,
                    producer,
                    bundle,
                    &root,
                    &guard.process,
                    pid,
                    bootstrap_digest,
                    configuration_kind,
                )?;
                DaemonState::Local { native, guard }
            }
        };
        child.require_live()?;
        Ok(Self {
            state,
            pid,
            bootstrap_digest: bootstrap_digest.into(),
            bundle_digest: bundle.digest().into(),
            admission,
            transaction,
            owned,
            producer,
            shape: None,
            revoked: false,
        })
    }
    pub(super) fn pid(&self) -> u32 {
        self.pid
    }
    pub(super) fn bind_shape(&mut self, shape: vprouter_network::DaemonLinks) -> Result<()> {
        if self.revoked || self.shape.is_some() {
            self.revoke();
            return Err(Error::PlacementFailed);
        }
        self.shape = Some(shape);
        Ok(())
    }
    pub(super) fn shape(&self) -> Result<&vprouter_network::DaemonLinks> {
        if self.revoked {
            return Err(Error::PlacementFailed);
        }
        self.shape.as_ref().ok_or(Error::PlacementFailed)
    }
    pub(super) fn revalidate(&mut self, bundle: &ReviewedBundle) -> Result<()> {
        self.verify(bundle, &self.bootstrap_digest.clone())
    }
    pub(super) fn verify(&mut self, bundle: &ReviewedBundle, bootstrap_digest: &str) -> Result<()> {
        if self.revoked {
            return Err(Error::PlacementFailed);
        }
        let result = (|| {
            self.transaction.revalidate(&self.admission.spec)?;
            self.producer
                .verify(self.transaction, &self.admission.spec)?;
            self.owned.bind(&self.admission.spec)?;
            if bundle.digest() != self.bundle_digest || bootstrap_digest != self.bootstrap_digest {
                return Err(Error::ExecutableMismatch);
            }
            match &self.state {
                DaemonState::Local { native, guard } => native.verify(
                    self.admission,
                    self.owned,
                    self.producer,
                    bundle,
                    bootstrap_digest,
                    &guard.process,
                ),
                DaemonState::Remote { token, client } => client
                    .inspect(super::inspection::Request::Reinspect { token: *token })
                    .map(|_| ()),
            }
        })();
        if result.is_err() {
            self.revoked = true;
        }
        result
    }
}
/// Pure native verifier; it has no Transaction or Journal reference.
pub(super) struct NativeDaemon {
    _inventory: inventory::Registration,
    chain: Vec<Process>,
    namespaces: Vec<(&'static str, OwnedFd)>,
    executable: OwnedFd,
    root: OwnedFd,
    root_id: Identity,
    configuration: OwnedFd,
    configuration_id: Identity,
    configuration_kind: kernel::DaemonConfiguration,
    bundle_digest: String,
    bootstrap_digest: String,
    guard_pid: u32,
    guard_start: u64,
}
impl NativeDaemon {
    pub(super) fn target_exited(&self) -> Result<bool> {
        self.chain[0].exited()
    }
    pub(super) fn bootstrap_digest(&self) -> &str {
        &self.bootstrap_digest
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn pin(
        admission: &Admission,
        owned: &OwnedNamespaces,
        producer: &ProducerGroup,
        bundle: &ReviewedBundle,
        child: &Process,
        guard: &Process,
        pid: u32,
        bootstrap_digest: &str,
        configuration_kind: kernel::DaemonConfiguration,
    ) -> Result<Self> {
        child.verify()?;
        if !super::spec::digest(bootstrap_digest) {
            return Err(Error::DescriptorPolicy);
        }
        let mut chain = vec![Process::open(pid)?];
        for _ in 0..3 {
            chain.push(Process::open(
                chain.last().ok_or(Error::PlacementFailed)?.parent,
            )?);
        }
        if chain[3].pid != child.pid
            || chain[3].parent != guard.pid
            || chain
                .iter()
                .map(|p| p.pid)
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != 4
        {
            return Err(Error::PlacementFailed);
        }
        chain[3].same(child)?;
        guard.verify()?;
        for process in &chain {
            producer.membership(process.pid, &process.proc, &admission.spec)?;
        }
        let main = &chain[0];
        let executable = fs::openat(
            &main.proc,
            "exe",
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| Error::ExecutableMismatch)?;
        bundle.verify(&executable, Role::Tailscaled)?;
        let root = fs::openat(
            &main.proc,
            "root",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| Error::MountIsolation)?;
        let configuration = super::process::readonly_path(&root, "etc/tailscale.json")
            .map_err(|_| Error::MountIsolation)?;
        let root_id = Identity::of(&root)?;
        let configuration_id = Identity::of(&configuration)?;
        let namespaces = ["net", "pid", "mnt", "cgroup", "user"]
            .into_iter()
            .map(|name| Ok((name, main.namespace(name)?)))
            .collect::<Result<Vec<_>>>()?;
        let mut fds = vec![executable.as_fd(), configuration.as_fd(), root.as_fd()];
        for p in &chain {
            fds.extend([p.proc.as_fd(), p.pidfd.as_fd()]);
        }
        fds.extend(namespaces.iter().map(|(_, fd)| fd.as_fd()));
        let inventory = inventory::Registration::owned(&fds)?;
        let result = Self {
            _inventory: inventory,
            chain,
            namespaces,
            executable,
            root,
            root_id,
            configuration,
            configuration_id,
            configuration_kind,
            bundle_digest: bundle.digest().to_owned(),
            bootstrap_digest: bootstrap_digest.to_owned(),
            guard_pid: guard.pid,
            guard_start: guard.start,
        };
        result.verify(admission, owned, producer, bundle, bootstrap_digest, guard)?;
        child.verify()?;
        Ok(result)
    }
    pub(super) fn verify(
        &self,
        a: &Admission,
        owned: &OwnedNamespaces,
        producer: &ProducerGroup,
        bundle: &ReviewedBundle,
        bootstrap_digest: &str,
        guard: &Process,
    ) -> Result<()> {
        if bundle.digest() != self.bundle_digest || bootstrap_digest != self.bootstrap_digest {
            return Err(Error::ExecutableMismatch);
        }
        a.process.revalidate(&a.spec, &a.staging)?;
        owned.bind(&a.spec)?;
        producer.verify_native()?;
        guard.verify()?;
        if guard.pid != self.guard_pid
            || guard.start != self.guard_start
            || self.chain[3].parent != guard.pid
        {
            return Err(Error::PlacementFailed);
        }
        for p in &self.chain {
            p.verify()?;
            producer.membership(p.pid, &p.proc, &a.spec)?;
        }
        for pair in self.chain.windows(2) {
            if pair[0].parent != pair[1].pid {
                return Err(Error::PlacementFailed);
            }
        }
        let main = &self.chain[0];
        daemon_credentials(&read(&main.proc, "status", 16384)?)?;
        if read(&main.proc, "attr/current", 128)?.trim() != "docker-default (enforce)" {
            return Err(Error::ConfinementPolicy);
        }
        for (name, fd) in &self.namespaces {
            if Identity::network(fd)? != Identity::network(main.namespace(name)?)? {
                return Err(Error::NamespaceMismatch);
            }
        }
        if Identity::network(&self.namespaces[0].1)? != Identity::network(&owned.data)?
            || Identity::network(&self.namespaces[1].1)?
                != Identity::network(self.chain[1].namespace("pid")?)?
            || Identity::network(&self.namespaces[1].1)?
                == Identity::network(a.process.launch_fds().pid)?
            || Identity::network(self.chain[2].namespace("pid")?)?
                != Identity::network(a.process.launch_fds().pid)?
            || Identity::network(&self.namespaces[2].1)?
                == Identity::network(self.chain[1].namespace("mnt")?)?
        {
            return Err(Error::NamespaceMismatch);
        }
        let exe = fs::openat(
            &main.proc,
            "exe",
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| Error::ExecutableMismatch)?;
        bundle.verify_pinned(&exe, &self.executable, Role::Tailscaled)?;
        let root = fs::openat(
            &main.proc,
            "root",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| Error::MountIsolation)?;
        if Identity::of(&root)? != self.root_id || Identity::of(&self.root)? != self.root_id {
            return Err(Error::MountIsolation);
        }
        let current = super::process::readonly_path(&root, "etc/tailscale.json")
            .map_err(|_| Error::MountIsolation)?;
        if Identity::of(&current)? != self.configuration_id
            || Identity::of(&self.configuration)? != self.configuration_id
        {
            return Err(Error::MountIsolation);
        }
        let stat = fs::fstat(&current).map_err(|_| Error::MountIsolation)?;
        let expected = self.configuration_kind.bytes();
        if stat.st_uid != 0
            || stat.st_gid != 0
            || stat.st_mode & 0o022 != 0
            || fs::FileType::from_raw_mode(stat.st_mode) != fs::FileType::RegularFile
            || stat.st_size != expected.len() as i64
        {
            return Err(Error::MountIsolation);
        }
        let mut bytes = vec![0; expected.len() + 1];
        let n = rustix::io::pread(&current, &mut bytes, 0).map_err(|_| Error::MountIsolation)?;
        if n != expected.len() || &bytes[..n] != expected {
            return Err(Error::MountIsolation);
        }
        for p in &self.chain {
            p.verify()?;
            producer.membership(p.pid, &p.proc, &a.spec)?;
        }
        guard.verify()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn process_parent_binding_rejects_missing_duplicate_zero_and_malformed_fields() {
        assert_eq!(parent("Name:	comm (unsafe)\nPPid:	123\n"), Ok(123));
        for value in [
            "",
            "PPid: 0\n",
            "PPid: -1\n",
            "PPid: 12 13\n",
            "PPid: 1\nPPid: 1\n",
        ] {
            assert!(parent(value).is_err());
        }
    }
    #[test]
    fn live_daemon_requires_post_exec_uid_groups_capabilities_nnp_and_seccomp() {
        let status = "Uid: 65534 65534 65534 65534\nGid: 65534 65534 65534 65534\nGroups:\nNoNewPrivs: 1\nSeccomp: 2\nCapInh: 1000\nCapPrm: 1000\nCapEff: 1000\nCapBnd: 1000\nCapAmb: 1000\n";
        assert!(daemon_credentials(status).is_ok());
        for (old, new) in [
            ("Uid: 65534", "Uid: 0"),
            ("Gid: 65534", "Gid: 0"),
            ("Groups:", "Groups: 65534"),
            ("NoNewPrivs: 1", "NoNewPrivs: 0"),
            ("Seccomp: 2", "Seccomp: 0"),
            ("CapEff: 1000", "CapEff: 201000"),
            ("CapAmb: 1000", "CapAmb: 0"),
            ("CapBnd: 1000", "CapBnd: ffffffff"),
        ] {
            assert!(
                daemon_credentials(&status.replacen(old, new, 1)).is_err(),
                "{old}"
            );
        }
        assert!(daemon_credentials(&format!("{status}Uid: 65534 65534 65534 65534\n")).is_err());
    }
}
