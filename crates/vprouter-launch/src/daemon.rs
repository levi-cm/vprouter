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
    fs::{self, Mode, OFlags, ResolveFlags},
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
struct Process {
    proc: OwnedFd,
    pidfd: OwnedFd,
    pid: u32,
    start: u64,
    parent: u32,
}
impl Process {
    fn open(pid: u32) -> Result<Self> {
        let pidfd = pidfd_open(
            Pid::from_raw(pid as i32).ok_or(Error::PlacementFailed)?,
            PidfdFlags::NONBLOCK,
        )
        .map_err(|_| Error::PlacementFailed)?;
        alive(&pidfd)?;
        let proc = fs::open(
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
    fn verify(&self) -> Result<()> {
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
/// Contains retained executable, process ancestry, namespace and fixed config
/// objects. Every verification error permanently revokes the object.
pub(super) struct LiveDaemon<'g, 'a> {
    _inventory: inventory::Registration,
    chain: Vec<Process>,
    namespaces: Vec<(&'static str, OwnedFd)>,
    executable: OwnedFd,
    configuration: OwnedFd,
    configuration_id: Identity,
    bundle_digest: String,
    bootstrap_digest: String,
    admission: &'g Admission,
    transaction: &'g Transaction<'a>,
    owned: &'g OwnedNamespaces,
    producer: &'g ProducerGroup,
    revoked: bool,
}
impl<'g, 'a> LiveDaemon<'g, 'a> {
    pub(super) fn revoke(&mut self) {
        self.revoked = true;
    }
    #[allow(clippy::too_many_arguments)]
    pub(super) fn pin(
        admission: &'g Admission,
        transaction: &'g Transaction<'a>,
        owned: &'g OwnedNamespaces,
        producer: &'g ProducerGroup,
        bundle: &ReviewedBundle,
        child: &kernel::Child,
        pid: u32,
        bootstrap_digest: &str,
    ) -> Result<Self> {
        child.require_live()?;
        if !super::spec::digest(bootstrap_digest) {
            return Err(Error::DescriptorPolicy);
        }
        let mut chain = vec![Process::open(pid)?];
        for _ in 0..3 {
            chain.push(Process::open(
                chain.last().ok_or(Error::PlacementFailed)?.parent,
            )?);
        }
        if chain[3].pid != child.pid()
            || chain[3].parent != std::process::id()
            || chain
                .iter()
                .map(|p| p.pid)
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != 4
        {
            return Err(Error::PlacementFailed);
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
        let configuration = fs::openat2(
            &root,
            "etc/tailscale.json",
            RD,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
        )
        .map_err(|_| Error::MountIsolation)?;
        let configuration_id = Identity::of(&configuration)?;
        let namespaces = ["net", "pid", "mnt", "cgroup", "user"]
            .into_iter()
            .map(|name| Ok((name, main.namespace(name)?)))
            .collect::<Result<Vec<_>>>()?;
        let mut fds = vec![executable.as_fd(), configuration.as_fd()];
        for p in &chain {
            fds.extend([p.proc.as_fd(), p.pidfd.as_fd()]);
        }
        fds.extend(namespaces.iter().map(|(_, fd)| fd.as_fd()));
        let inventory = inventory::Registration::owned(&fds)?;
        let mut result = Self {
            _inventory: inventory,
            chain,
            namespaces,
            executable,
            configuration,
            configuration_id,
            bundle_digest: bundle.digest().to_owned(),
            bootstrap_digest: bootstrap_digest.to_owned(),
            admission,
            transaction,
            owned,
            producer,
            revoked: false,
        };
        result.verify(bundle, bootstrap_digest)?;
        child.require_live()?;
        Ok(result)
    }
    pub(super) fn pid(&self) -> u32 {
        self.chain[0].pid
    }
    pub(super) fn revalidate(&mut self, bundle: &ReviewedBundle) -> Result<()> {
        self.verify(bundle, &self.bootstrap_digest.clone())
    }
    pub(super) fn verify(&mut self, bundle: &ReviewedBundle, bootstrap_digest: &str) -> Result<()> {
        if self.revoked {
            return Err(Error::PlacementFailed);
        }
        let result = self.verify_current(bundle, bootstrap_digest);
        if result.is_err() {
            self.revoked = true;
        }
        result
    }
    fn verify_current(&self, bundle: &ReviewedBundle, bootstrap_digest: &str) -> Result<()> {
        if bundle.digest() != self.bundle_digest || bootstrap_digest != self.bootstrap_digest {
            return Err(Error::ExecutableMismatch);
        }
        let a = self.admission;
        a.process.revalidate(&a.spec, &a.staging)?;
        self.transaction.revalidate(&a.spec)?;
        self.owned.bind(&a.spec)?;
        self.producer.verify(self.transaction, &a.spec)?;
        for p in &self.chain {
            p.verify()?;
            self.producer.membership(p.pid, &p.proc, &a.spec)?;
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
        if Identity::network(&self.namespaces[0].1)? != Identity::network(&self.owned.data)?
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
        bundle.verify(&exe, Role::Tailscaled)?;
        bundle.verify(&self.executable, Role::Tailscaled)?;
        if Identity::of(exe)? != Identity::of(&self.executable)? {
            return Err(Error::ExecutableMismatch);
        }
        let current = fs::openat(&main.proc, "root/etc/tailscale.json", RD, Mode::empty())
            .map_err(|_| Error::MountIsolation)?;
        if Identity::of(&current)? != self.configuration_id
            || Identity::of(&self.configuration)? != self.configuration_id
        {
            return Err(Error::MountIsolation);
        }
        let stat = fs::fstat(&current).map_err(|_| Error::MountIsolation)?;
        let expected = kernel::daemon_configuration();
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
        }
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
